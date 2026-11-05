//! 鉴权及目标解码完成后才调用统一目标访问口；载体、逻辑流和 UDP flow 分别计费。
use crate::{
    config::{self, Limits, NodeOptions, Transport},
    protocol,
};
use bytes::Bytes;
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Destination, Error,
    InboundContext, InboundProtocol, IngressBinding, NodeEvent, Result,
};
use kerlico_http_carrier::{BodyIo, Reader, Writer};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncWriteExt, task::JoinSet};
pub struct TrustTunnelNodeFactory;
#[derive(Clone)]
struct Node {
    tls: Arc<rustls::ServerConfig>,
    users: CredentialSet<config::Auth>,
    transport: Transport,
    udp: bool,
    limits: Limits,
    #[cfg(test)]
    rejection_gate: Option<Arc<RejectionGate>>,
}
impl NodeFactory for TrustTunnelNodeFactory {
    fn kind(&self) -> &'static str {
        "trusttunnel"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: NodeOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| crate::invalid())?;
        let limits = options.limits.into_limits()?;
        if input.native_credentials().is_empty() || input.native_credentials().len() > 256 {
            return Err(crate::invalid());
        }
        let mut seen = BTreeSet::new();
        let mut passwords = BTreeSet::new();
        let mut users = Vec::new();
        for value in input.native_credentials() {
            let user: config::Auth =
                serde_json::from_value(value.clone()).map_err(|_| crate::invalid())?;
            user.validate()?;
            let auth = user.hash();
            let secret = user.isolation();
            if !seen.insert(auth) || !passwords.insert(secret) {
                return Err(crate::invalid());
            }
            users.push(user);
        }
        Ok(Arc::new(Node {
            tls: config::server_tls(options.tls, options.transport)?,
            users: input.credentials(users)?,
            transport: options.transport,
            udp: options.udp,
            limits,
            #[cfg(test)]
            rejection_gate: None,
        }))
    }
}
enum Reply {
    H1(BoxStream),
    H2(h2::server::SendResponse<Bytes>, h2::RecvStream),
    H3(Box<kerlico_http_carrier::H3Server>),
}
enum RequestExit {
    Finished,
    Rejected,
    OwnerFailed(Error),
}
enum RequestFailure {
    AuthenticationRejected,
    Operation(Error),
}
impl RequestFailure {
    fn into_error(self) -> Error {
        match self {
            Self::AuthenticationRejected => Error::Rejected,
            Self::Operation(error) => error,
        }
    }
}
impl From<Error> for RequestFailure {
    fn from(error: Error) -> Self {
        Self::Operation(error)
    }
}
impl From<std::io::Error> for RequestFailure {
    fn from(error: std::io::Error) -> Self {
        Self::Operation(error.into())
    }
}
#[cfg(test)]
struct RejectionGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    send_failed: std::sync::atomic::AtomicBool,
}
fn request_result(result: std::result::Result<RequestExit, tokio::task::JoinError>) -> Result<()> {
    match result {
        Ok(RequestExit::Finished) => Ok(()),
        Ok(RequestExit::Rejected) => Err(Error::Rejected),
        Ok(RequestExit::OwnerFailed(error)) => Err(error),
        Err(_) => Err(protocol()),
    }
}
#[derive(Clone, Copy)]
struct DrainWindow {
    cleanup_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
}
impl DrainWindow {
    fn new(budget: Duration) -> Self {
        let started = tokio::time::Instant::now();
        Self {
            cleanup_at: started + budget - budget / 5,
            deadline: started + budget,
        }
    }
}
#[derive(Default)]
struct QuicDrain {
    state: Mutex<QuicDrainState>,
}
#[derive(Default)]
struct QuicDrainState {
    phase: QuicDrainPhase,
    flows: Vec<Weak<crate::flow::FlowSet>>,
}
#[derive(Clone, Copy, Default)]
enum QuicDrainPhase {
    #[default]
    Running,
    Draining(DrainWindow),
    Expired(DrainWindow),
}
impl QuicDrain {
    fn window(&self, context: &InboundContext) -> Option<DrainWindow> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if context.stream_budget.is_closed() && matches!(state.phase, QuicDrainPhase::Running) {
            state.phase = QuicDrainPhase::Draining(DrainWindow::new(context.drain_timeout));
        }
        match state.phase {
            QuicDrainPhase::Running => None,
            QuicDrainPhase::Draining(window) | QuicDrainPhase::Expired(window) => Some(window),
        }
    }
    fn expired(&self) -> bool {
        matches!(
            self.state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .phase,
            QuicDrainPhase::Expired(_)
        )
    }
    fn expire(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let QuicDrainPhase::Draining(window) = state.phase {
            state.phase = QuicDrainPhase::Expired(window);
        }
        drop(state);
        self.close(crate::flow::outcome(&Err(Error::Timeout)));
    }
    fn register(&self, flows: &Arc<crate::flow::FlowSet>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.flows.retain(|flows| flows.strong_count() != 0);
        state.flows.push(Arc::downgrade(flows));
        let expired = matches!(state.phase, QuicDrainPhase::Expired(_));
        drop(state);
        if expired {
            flows.close(crate::flow::outcome(&Err(Error::Timeout)));
        }
    }
    fn close(&self, reason: kerlico_core::FlowOutcome) {
        let flows: Vec<_> = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .flows
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for flows in flows {
            flows.close(reason);
        }
    }
}
impl Reply {
    async fn send(self, status: u16) -> Result<BoxStream> {
        match self {
            Self::H1(mut io) => {
                crate::http1::respond(&mut io, status).await?;
                Ok(io)
            }
            Self::H2(mut reply, receive) => {
                let response = response(status)?;
                let send = reply
                    .send_response(response, status != 200)
                    .map_err(|_| protocol())?;
                Ok(BodyIo::boxed(Writer::H2(send), Reader::H2(receive)))
            }
            Self::H3(mut stream) => {
                stream
                    .send_response(response(status)?)
                    .await
                    .map_err(|_| protocol())?;
                if status != 200 {
                    stream.finish().await.map_err(|_| protocol())?;
                }
                let (send, receive) = (*stream).split();
                Ok(BodyIo::boxed(Writer::Server(send), Reader::Server(receive)))
            }
        }
    }
}
fn response(status: u16) -> Result<http::Response<()>> {
    let mut builder = http::Response::builder().status(status);
    if status != 200 {
        builder = builder.header("content-length", "0");
    }
    if status == 407 {
        builder = builder.header("proxy-authenticate", "Basic realm=\"TrustTunnel\"");
    }
    builder.body(()).map_err(|_| protocol())
}
fn authority(request: &http::Request<()>) -> Result<&str> {
    if request.method() != http::Method::CONNECT
        || request.extensions().get::<h3::ext::Protocol>().is_some()
        || request.extensions().get::<h2::ext::Protocol>().is_some()
        || request.headers().get_all("user-agent").iter().count() != 1
        || request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .get("content-length")
            .is_some_and(|v| v != "0")
    {
        return Err(protocol());
    }
    request
        .uri()
        .authority()
        .map(|v| v.as_str())
        .ok_or_else(protocol)
}
fn target(authority: &str) -> Result<Destination> {
    let authority = authority
        .parse::<http::uri::Authority>()
        .map_err(|_| protocol())?;
    let port = authority.port_u16().ok_or_else(protocol)?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    Destination::new(host, port)
}
impl Node {
    async fn request(
        &self,
        flows: Arc<crate::flow::FlowSet>,
        request: http::Request<()>,
        reply: Reply,
        access: IngressBinding,
        context: InboundContext,
    ) -> std::result::Result<(), RequestFailure> {
        let verified = config::authentication_hash(request.headers()).and_then(|hash| {
            self.users.verify(&hash, |user, hash| {
                Ok(bool::from(user.hash().ct_eq(hash)).then_some(()))
            })
        });
        let verified = match verified {
            Ok(verified) => verified,
            Err(_) => {
                #[cfg(test)]
                if let Some(gate) = &self.rejection_gate {
                    gate.entered.add_permits(1);
                    let _permit = gate.release.acquire().await;
                }
                let response = reply.send(407).await;
                #[cfg(test)]
                if let Some(gate) = &self.rejection_gate {
                    gate.send_failed
                        .store(response.is_err(), std::sync::atomic::Ordering::Release);
                }
                let _ = response;
                return Err(RequestFailure::AuthenticationRejected);
            }
        };
        let (access, ()) = access.authenticated(verified, &context)?;
        let authority = match authority(&request) {
            Ok(v) => v,
            Err(error) => {
                let _ = reply.send(400).await?;
                return Err(error.into());
            }
        };
        if context.stream_budget.is_closed() {
            let _ = reply.send(503).await?;
            return Err(Error::ResourceLimit.into());
        }
        if authority == "_icmp" {
            let _ = reply.send(501).await?;
            return Err(Error::Unsupported("TrustTunnel ICMP 尚无统一目标访问契约").into());
        }
        if authority == "_check" {
            let mut io = reply.send(200).await?;
            io.shutdown().await?;
            return Ok(());
        }
        if authority == "_udp2" {
            if !self.udp {
                let _ = reply.send(501).await?;
                return Err(Error::Unsupported("TrustTunnel UDP 已关闭").into());
            }
            let io = reply.send(200).await?;
            return crate::udp::serve(io, access, context, self.limits.max_udp_flows, flows)
                .await
                .map_err(RequestFailure::Operation);
        }
        let target = match target(authority) {
            Ok(v) => v,
            Err(error) => {
                let _ = reply.send(400).await?;
                return Err(error.into());
            }
        };
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let remote = match connect.run(access.connect_tcp(&target, &connect)).await {
            Ok(v) => v,
            Err(error) => {
                let _ = reply.send(502).await?;
                return Err(error.into());
            }
        };
        let remote = flows.tcp(remote)?;
        let io = match connect.run(reply.send(200)).await {
            Ok(io) => io,
            Err(error) => {
                remote.finish(kerlico_core::FlowOutcome::Failed(
                    kerlico_core::FlowFailure::from_error(&error),
                ));
                return Err(error.into());
            }
        };
        remote
            .relay(io, context.idle_timeout, context.cancel)
            .await
            .map_err(RequestFailure::Operation)
    }
    async fn tcp(
        &self,
        stream: BoxStream,
        access: IngressBinding,
        mut context: InboundContext,
    ) -> Result<()> {
        context.idle_timeout = context.idle_timeout.min(self.limits.idle());
        let flows = crate::flow::FlowSet::new(context.max_streams, context.cancel.clone());
        let _flows_guard = flows.guard();
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let stream = connect
            .run(async {
                let stream = tokio_rustls::TlsAcceptor::from(self.tls.clone())
                    .accept(stream)
                    .await?;
                if stream.get_ref().1.alpn_protocol() != Some(self.transport.alpn()[0].as_slice())
                    && !(self.transport == Transport::H1
                        && stream.get_ref().1.alpn_protocol().is_none())
                {
                    return Err(protocol());
                }
                Ok(Box::new(stream) as BoxStream)
            })
            .await?;
        if self.transport == Transport::H1 {
            let mut stream = stream;
            let request = connect.run(crate::http1::request(&mut stream)).await?;
            return self
                .request(flows, request, Reply::H1(stream), access, context)
                .await
                .map_err(RequestFailure::into_error);
        }
        let mut connection = connect
            .run(async {
                h2::server::Builder::new()
                    .initial_window_size(16 * 1024 * 1024)
                    .initial_connection_window_size(64 * 1024 * 1024)
                    .max_frame_size(65536)
                    .max_send_buffer_size(4 * 1024 * 1024)
                    .max_header_list_size(16384)
                    .max_concurrent_streams(self.limits.max_streams.min(context.max_streams) as u32)
                    .handshake(stream)
                    .await
                    .map_err(|_| protocol())
            })
            .await?;
        let mut tasks = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        let mut draining = None;
        let mut last = tokio::time::Instant::now();
        let result = async {
            loop {
                if context.cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                while let Some(result) = tasks.try_join_next() {
                    request_result(result)?;
                    last = tokio::time::Instant::now();
                }
                if draining.is_some() && tasks.is_empty() {
                    #[cfg(test)]
                    eprintln!("TrustTunnel H2 已无业务任务，底层仍有流：{}", connection.has_streams());
                    break;
                }
                tokio::select! { biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(result) = result { request_result(result)?; }
                        last = tokio::time::Instant::now();
                    },
                    _ = tokio::time::sleep_until(draining.map_or_else(tokio::time::Instant::now, |window: DrainWindow| window.cleanup_at)), if draining.is_some() => return Err(Error::Timeout),
                    _ = tick.tick() => {
                        if context.stream_budget.is_closed() && draining.is_none() {
                            draining = Some(DrainWindow::new(context.drain_timeout));
                            connection.graceful_shutdown();
                        }
                        if tasks.is_empty() && last.elapsed() >= context.idle_timeout { break; }
                    },
                    request = connection.accept() => {
                        let Some(request) = request else {
                            #[cfg(test)]
                            eprintln!("TrustTunnel H2 接纳驱动已正常关闭");
                            break;
                        };
                        let (request, reply) = request.map_err(|_error| {
                            #[cfg(test)]
                            eprintln!("TrustTunnel H2 接纳驱动失败：{_error:?}");
                            protocol()
                        })?;
                        last = tokio::time::Instant::now();
                        let lease = match context.stream_budget.try_acquire() {
                            Ok(lease) => lease,
                            Err(_) => {
                                let _ = Reply::H2(reply, request.into_body()).send(503).await;
                                context.events.record(NodeEvent::Dropped);
                                continue;
                            }
                        };
                        let (request, body) = request.into_parts();
                        let node = self.clone();
                        let access = access.clone();
                        let context = context.clone();
                        let flows = flows.clone();
                        kerlico_http_carrier::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move {
                            let _lease = lease;
                            let result = node.request(flows, http::Request::from_parts(request, ()), Reply::H2(reply, body), access, context.clone()).await;
                            context.events.record(if result.is_ok() { NodeEvent::Completed } else { NodeEvent::Failed });
                            if matches!(result, Err(RequestFailure::AuthenticationRejected)) { RequestExit::Rejected } else { RequestExit::Finished }
                        }, RequestExit::OwnerFailed)?;
                    }
                }
            }
            Ok(())
        }.await;
        #[cfg(test)]
        if result.is_err() {
            eprintln!("TrustTunnel H2 请求循环退出：{result:?}");
        }
        flows.close(crate::flow::outcome(&result));
        if matches!(&result, Err(Error::Rejected)) {
            connection.abrupt_shutdown(h2::Reason::from(0x1f));
        } else if result.is_err() {
            connection.abrupt_shutdown(h2::Reason::CANCEL);
        }
        tasks.abort_all();
        let deadline = draining
            .unwrap_or_else(|| DrainWindow::new(context.drain_timeout))
            .deadline;
        tokio::time::timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
            if draining.is_some() || result.is_err() {
                let closed = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
                if result.is_ok() {
                    closed.map_err(|_error| {
                        #[cfg(test)]
                        eprintln!("TrustTunnel H2 排空关闭失败：{_error:?}");
                        protocol()
                    })?;
                }
            }
            Ok::<(), Error>(())
        })
        .await
        .map_err(|_| Error::Protocol("TrustTunnel H2 请求清理未在期限内完成"))??;
        result
    }
    async fn quic(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        mut context: InboundContext,
    ) -> Result<()> {
        context.idle_timeout = context.idle_timeout.min(self.limits.idle());
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*self.tls).clone())
            .map_err(|_| crate::invalid())?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(
            self.limits
                .quic(context.max_streams.min(self.limits.max_streams))?,
        );
        let fd = socket2::SockRef::from(socket.as_ref()).try_clone()?;
        let standard: std::net::UdpSocket = fd.into();
        standard.set_nonblocking(true)?;
        let mut config = quinn::EndpointConfig::default();
        config.supported_versions(vec![1]);
        let (socket, _socket_close) = kerlico_http_carrier::socket::wrap(standard)?;
        let runtime =
            kerlico_http_carrier::runtime::NodeRuntime::new(&context.cancel, context.tasks.clone());
        let _runtime_guard = runtime.guard();
        let mut context = context;
        context.cancel = runtime.cancel();
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            config,
            Some(server),
            socket,
            runtime.clone(),
        )?;
        let mut tasks = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        let drain = Arc::new(QuicDrain::default());
        let result = loop {
            if context.cancel.is_cancelled() {
                break Ok(());
            }
            while let Some(result) = tasks.try_join_next() {
                runtime.observe(&Some(result));
            }
            let window = drain.window(&context);
            if drain.expired() {
                break Err(Error::Timeout);
            }
            if window.is_some() && tasks.is_empty() {
                break Ok(());
            }
            tokio::select! { biased;
                _ = context.cancel.cancelled() => break Ok(()),
                result = tasks.join_next(), if !tasks.is_empty() => runtime.observe(&result),
                _ = tokio::time::sleep_until(window.map_or_else(tokio::time::Instant::now, |window| window.cleanup_at)), if window.is_some() => {
                    drain.expire();
                    break Err(Error::Timeout);
                },
                _ = tick.tick() => {},
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break Ok(()); };
                    if context.stream_budget.is_closed() { incoming.refuse(); continue; }
                    let Ok(lease) = context.stream_budget.try_acquire() else {
                        incoming.refuse();
                        context.events.record(NodeEvent::Dropped);
                        continue;
                    };
                    let node = self.clone();
                    let access = access.clone();
                    let context = context.clone();
                    let drain = drain.clone();
                    kerlico_http_carrier::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move {
                        let _lease = lease;
                        context.events.record(NodeEvent::Accepted);
                        let connect = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
                        let result = async {
                            let connection = connect.run(async { incoming.await.map_err(|_| protocol()) }).await?;
                            node.h3(connection, access, context.clone(), drain).await
                        }.await;
                        context.events.record(if result.is_ok() { NodeEvent::Completed } else { NodeEvent::Failed });
                    }, |_| ())?;
                }
            }
        };
        if context.cancel.is_cancelled() {
            drain.close(crate::flow::outcome(&Err(Error::Cancelled)));
        } else if result.is_err() {
            drain.close(crate::flow::outcome(&result));
        }
        let deadline = drain
            .window(&context)
            .unwrap_or_else(|| DrainWindow::new(context.drain_timeout))
            .deadline;
        if runtime.shutdown_at(endpoint, &mut tasks, deadline).await?
            == kerlico_http_carrier::runtime::NodeDrain::Forced
        {
            context.events.record(NodeEvent::ForcedCleanup);
        }
        result
    }
    async fn h3(
        &self,
        connection: quinn::Connection,
        access: IngressBinding,
        context: InboundContext,
        drain: Arc<QuicDrain>,
    ) -> Result<()> {
        let mut context = context;
        context.peer_addr = Some(connection.remote_address());
        let flows = crate::flow::FlowSet::new(context.max_streams, context.cancel.clone());
        let _flows_guard = flows.guard();
        drain.register(&flows);
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let mut server = connect
            .run(async {
                h3::server::builder()
                    .max_field_section_size(16384)
                    .build(h3_quinn::Connection::new(connection.clone()))
                    .await
                    .map_err(|_| protocol())
            })
            .await?;
        let mut tasks = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        let mut draining: Option<DrainWindow> = None;
        let mut accepting = true;
        let result = async {
            loop {
                if context.cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                while let Some(result) = tasks.try_join_next() {
                    request_result(result)?;
                }
                if let Some(window) = drain.window(&context) {
                    if draining.is_none() {
                        draining = Some(window);
                        tokio::select! { biased;
                            _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                            result = tokio::time::timeout_at(window.cleanup_at, server.shutdown(0)) => {
                                match result {
                                    Ok(result) => result.map_err(|_| protocol())?,
                                    Err(_) => { drain.expire(); return Err(Error::Timeout); }
                                }
                            }
                        }
                    } else if draining.is_some_and(|local| window.deadline < local.deadline) {
                        draining = Some(window);
                    }
                }
                if draining.is_some() && tasks.is_empty() {
                    break;
                }
                tokio::select! { biased;
                    _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                    _ = connection.closed() => return Err(protocol()),
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(result) = result { request_result(result)?; }
                    },
                    _ = tokio::time::sleep_until(draining.map_or_else(tokio::time::Instant::now, |window| window.cleanup_at)), if draining.is_some() => {
                        if drain.window(&context).is_some_and(|window| tokio::time::Instant::now() >= window.cleanup_at) {
                            drain.expire();
                        }
                        return Err(Error::Timeout);
                    },
                    _ = tick.tick() => {},
                    resolver = server.accept(), if accepting => {
                        let mut resolver = match resolver {
                            Ok(Some(resolver)) => resolver,
                            Ok(None) => {
                                accepting = false;
                                draining.get_or_insert_with(|| DrainWindow::new(context.drain_timeout));
                                continue;
                            }
                            Err(_) => return Err(protocol()),
                        };
                        let lease = match context.stream_budget.try_acquire() {
                            Ok(lease) => lease,
                            Err(_) => {
                                let code = h3::error::Code::H3_REQUEST_REJECTED.value();
                                h3::quic::SendStream::reset(&mut resolver.frame_stream, code);
                                h3::quic::RecvStream::stop_sending(&mut resolver.frame_stream.stream, code);
                                context.events.record(NodeEvent::Dropped);
                                continue;
                            }
                        };
                        let node = self.clone();
                        let access = access.clone();
                        let context = context.clone();
                        let flows = flows.clone();
                        kerlico_http_carrier::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move {
                            let _lease = lease;
                            let connect = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
                            let result = async {
                                let (request, stream) = connect.run(async { resolver.resolve_request().await.map_err(|_| protocol()) }).await?;
                                node.request(flows, request, Reply::H3(Box::new(stream)), access, context.clone()).await
                            }.await;
                            context.events.record(if result.is_ok() { NodeEvent::Completed } else { NodeEvent::Failed });
                            if matches!(result, Err(RequestFailure::AuthenticationRejected)) { RequestExit::Rejected } else { RequestExit::Finished }
                        }, RequestExit::OwnerFailed)?;
                    }
                }
            }
            Ok(())
        }.await;
        flows.close(crate::flow::outcome(&result));
        connection.close(
            if matches!(&result, Err(Error::Rejected)) {
                0x1fu32
            } else {
                0x100u32
            }
            .into(),
            b"",
        );
        tasks.abort_all();
        let deadline = draining
            .or_else(|| drain.window(&context))
            .unwrap_or_else(|| DrainWindow::new(context.drain_timeout))
            .deadline;
        tokio::time::timeout_at(deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .map_err(|_| Error::Protocol("TrustTunnel H3 请求清理未在期限内完成"))?;
        result
    }
}
impl InboundProtocol for Node {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, user)) in self.users.rows().enumerate() {
            manifest.authentication("trusttunnel", index, user.hash());
            manifest.authentication("http", index, user.http_hash());
            manifest.protection("trusttunnel-password", user.isolation());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn supports_tcp(&self) -> bool {
        self.transport != Transport::H3
    }
    fn supports_udp(&self) -> bool {
        self.transport == Transport::H3
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.transport == Transport::H3 {
                return Err(Error::Unsupported("TrustTunnel H3 使用 UDP 物理监听"));
            }
            self.tcp(stream, access, context).await
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.transport != Transport::H3 {
                return Err(Error::Unsupported("TrustTunnel H1/H2 使用 TCP 物理监听"));
            }
            self.quic(socket, access, context).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_domain_and_special_authorities_are_separate() {
        assert_eq!(
            target("[::1]:443").unwrap(),
            Destination::new("::1", 443).unwrap()
        );
        assert_eq!(
            target("EXAMPLE.INVALID:80").unwrap().host(),
            "example.invalid"
        );
        for value in ["_udp2", "example.invalid", "a:0", "x/y:443"] {
            assert!(target(value).is_err());
        }
    }
}

#[cfg(test)]
#[path = "server_rejection_tests.rs"]
mod rejection_tests;
