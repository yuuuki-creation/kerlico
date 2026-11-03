use crate::{
    config::{self, Limits, MasqueradePlan, NodeOptions},
    dispatch, invalid, udp, wire,
};
use bytes::Bytes;
use http::Response;
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, NodeEvent, PeerSession, Result,
};
use rand::Rng;

use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::Component,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Notify, mpsc},
    task::JoinSet,
};

pub struct Hysteria2Node {
    auth: CredentialSet<[u8; 32]>,
    tls: Arc<rustls::ServerConfig>,
    salamander: Option<Arc<String>>,
    udp: bool,
    up_bps: Option<u64>,
    masquerade: Arc<MasqueradePlan>,
    limits: Limits,
}
impl Hysteria2Node {
    pub fn from_options(input: &NodeBuildContext) -> Result<Self> {
        let options: NodeOptions = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("Hysteria2 节点字段不合法".into()))?;
        options.limits.validate()?;
        if let Some(down) = &options.down {
            down.to_bps()?;
        }
        let up_bps = options
            .up
            .as_ref()
            .map(|up| up.to_bps())
            .transpose()?
            .filter(|bps| *bps > 0);
        let masquerade = Arc::new(options.masquerade_plan()?);
        Ok(Self {
            auth: input.credentials(
                input
                    .native_credentials()
                    .iter()
                    .map(|value| {
                        let auth: config::Auth = serde_json::from_value(value.clone())
                            .map_err(|_| Error::Config("Hysteria2 用户凭据字段不合法".into()))?;
                        config::auth(&auth.auth)
                    })
                    .collect::<Result<Vec<_>>>()?,
            )?,
            tls: config::server_tls(options.tls)?,
            salamander: config::obfs(options.salamander_password)?,
            udp: options.udp,
            up_bps,
            masquerade,
            limits: options.limits,
        })
    }
    pub async fn serve_udp(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        mut context: InboundContext,
    ) -> Result<()> {
        if self.udp && !access.supports_udp_association() {
            return Err(Error::Unsupported(
                "Hysteria2 UDP 节点需要多目标目标访问服务",
            ));
        }
        context.local_addr = socket.local_addr().ok();
        context.idle_timeout = context.idle_timeout.min(std::time::Duration::from_millis(
            self.limits.idle_timeout_ms,
        ));
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*self.tls).clone())
            .map_err(|_| invalid())?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(
            self.limits
                .transport(context.max_streams, self.salamander.is_some())?,
        );
        let duplicated = socket2::SockRef::from(socket.as_ref()).try_clone()?;
        let standard: std::net::UdpSocket = duplicated.into();
        let runtime = crate::runtime::NodeRuntime::new(&context.cancel, context.tasks.clone());
        let _runtime_guard = runtime.guard();
        let mut context = context;
        context.cancel = runtime.cancel();
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(config),
            crate::socket::wrap(standard, self.salamander.clone())?,
            runtime.clone(),
        )?;
        let mut connections = JoinSet::new();
        let mut maintenance = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled()=>break,
                _ = maintenance.tick()=>{if context.stream_budget.is_closed()&&connections.is_empty(){break;}},
                result=connections.join_next(),if !connections.is_empty()=>{runtime.observe(&result);if result.is_some_and(|result|result.is_err()){context.events.record(NodeEvent::Failed);}},
                incoming=endpoint.accept()=>{
                    let Some(incoming)=incoming else{break};let Ok(lease)=context.stream_budget.try_acquire() else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};
                    let mut context=context.clone();let access=access.clone();let limits=self.limits.clone();let auth=self.auth.clone();let udp=self.udp;
                    let up_bps=self.up_bps;let masquerade=self.masquerade.clone();
                    crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut connections, async move{
                        let _lease=lease;context.events.record(NodeEvent::Accepted);
                        let result=async {
                            let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|invalid())?;
                            context.peer_addr=Some(connection.remote_address());connection_loop(connection,access,context.clone(),limits,auth,udp,up_bps,masquerade).await
                        }.await;
                        context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});
                    }, |_| ())?;
                }
            }
        }
        if runtime
            .shutdown(endpoint, &mut connections, context.drain_timeout)
            .await?
            == crate::runtime::NodeDrain::Forced
        {
            context.events.record(NodeEvent::ForcedCleanup);
        }
        Ok(())
    }
}
impl InboundProtocol for Hysteria2Node {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, auth)) in self.auth.rows().enumerate() {
            manifest.authentication("hysteria2", index, *auth);
        }
        if let Some(password) = &self.salamander {
            manifest.protection(
                "hysteria2-salamander",
                Sha256::digest(password.as_bytes()).into(),
            );
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn requires_udp_association(&self) -> bool {
        self.udp
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _stream: BoxStream,
        _access: IngressBinding,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("Hysteria2 物理监听仅使用 QUIC/UDP")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve_udp(socket, access, context))
    }
}
struct ConnectionGuard(quinn::Connection);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(0x100u32.into(), b"");
    }
}
enum ControlEvent {
    Request(Box<h3::server::RequestResolver<dispatch::Connection, Bytes>>),
    Goaway,
    NativeProgress,
}
struct H3Control(h3::server::Connection<dispatch::Connection, Bytes>);
impl H3Control {
    fn has_pending_native(&self) -> bool {
        self.0.inner.conn.pending_sniffers() != 0
    }
    async fn next(&mut self, draining: bool) -> Result<ControlEvent> {
        if draining {
            return std::future::poll_fn(|cx| {
                let pending = self.0.inner.conn.pending_sniffers();
                let result = {
                    let mut accept = std::pin::pin!(self.0.accept());
                    accept.as_mut().poll(cx)
                };
                match result {
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(invalid())),
                    Poll::Ready(Ok(Some(mut request))) => {
                        let code = h3::error::Code::H3_REQUEST_REJECTED.value();
                        h3::quic::SendStream::reset(&mut request.frame_stream.stream, code);
                        h3::quic::RecvStream::stop_sending(&mut request.frame_stream.stream, code);
                    }
                    Poll::Ready(Ok(None)) | Poll::Pending => {}
                }
                if self.0.inner.conn.pending_sniffers() < pending {
                    Poll::Ready(Ok(ControlEvent::NativeProgress))
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        match self.0.accept().await.map_err(|_| invalid())? {
            Some(request) => Ok(ControlEvent::Request(Box::new(request))),
            None => {
                self.0.inner.conn.stop_admission();
                Ok(ControlEvent::Goaway)
            }
        }
    }
}
fn resolve_masquerade(
    plan: &MasqueradePlan,
    request_path: &str,
) -> (
    http::StatusCode,
    Vec<(http::HeaderName, http::HeaderValue)>,
    Bytes,
) {
    match plan {
        MasqueradePlan::Default404 => (
            http::StatusCode::NOT_FOUND,
            vec![(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            Bytes::from_static("资源不存在".as_bytes()),
        ),
        MasqueradePlan::String {
            status_code,
            headers,
            content,
        } => (*status_code, headers.clone(), content.clone()),
        MasqueradePlan::File { directory, headers } => {
            let trimmed = request_path.trim_start_matches('/');
            let relative = if trimmed.is_empty() {
                "index.html"
            } else {
                trimmed
            };
            let rel_path = std::path::Path::new(relative);
            if rel_path
                .components()
                .any(|comp| !matches!(comp, Component::Normal(_)))
            {
                return (
                    http::StatusCode::NOT_FOUND,
                    headers.clone(),
                    Bytes::from_static(b"Not Found"),
                );
            }
            let full_path = directory.join(rel_path);
            let final_path = if full_path.is_dir() {
                full_path.join("index.html")
            } else {
                full_path
            };
            match std::fs::read(&final_path) {
                Ok(bytes) if bytes.len() <= 4 * 1024 * 1024 => {
                    (http::StatusCode::OK, headers.clone(), Bytes::from(bytes))
                }
                _ => (
                    http::StatusCode::NOT_FOUND,
                    headers.clone(),
                    Bytes::from_static(b"Not Found"),
                ),
            }
        }
        MasqueradePlan::Proxy {
            url,
            rewrite_host,
            headers,
        } => {
            let mut resp_headers = headers.clone();
            if *rewrite_host
                && let Ok(parsed) = url.parse::<http::Uri>()
                && let Some(host) = parsed.authority()
                && let Ok(val) = http::HeaderValue::from_str(host.as_str())
            {
                resp_headers.push((http::header::HOST, val));
            }
            if let Ok(loc) = http::HeaderValue::from_str(url) {
                resp_headers.push((http::header::LOCATION, loc));
            }
            (http::StatusCode::OK, resp_headers, Bytes::new())
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn connection_loop(
    connection: quinn::Connection,
    access: IngressBinding,
    context: InboundContext,
    limits: Limits,
    auth: CredentialSet<[u8; 32]>,
    udp_enabled: bool,
    up_bps: Option<u64>,
    masquerade: Arc<MasqueradePlan>,
) -> Result<()> {
    let _guard = ConnectionGuard(connection.clone());
    let authenticated = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Notify::new());
    let peer = Arc::new(Mutex::new(None::<([u8; 32], PeerSession)>));
    let (proxy, mut streams) = mpsc::channel(limits.max_streams);
    let carrier = dispatch::Connection::new(
        connection.clone(),
        proxy,
        authenticated.clone(),
        context.clone(),
    );
    let h3: h3::server::Connection<_, Bytes> = h3::server::builder()
        .max_field_section_size(8192)
        .build(carrier)
        .await
        .map_err(|_| invalid())?;
    let mut h3 = H3Control(h3);
    let flows = crate::flow::FlowSet::new(context.max_streams, context.cancel.clone());
    let _flows_guard = flows.guard();
    let mut tasks = JoinSet::new();
    if udp_enabled {
        crate::runtime::spawn_owned(
            context.tasks.clone(),
            context.events.clone(),
            &mut tasks,
            udp::server(
                connection.clone(),
                peer.clone(),
                context.clone(),
                limits,
                ready.clone(),
                flows.clone(),
            ),
            Err,
        )?;
    }
    let mut draining = None;
    let mut native_open = true;
    let result = async {
    loop {
        if let Some(deadline) = draining {
            if context.cancel.is_cancelled() { return Err(Error::Cancelled); }
            if connection.close_reason().is_some() { return Err(Error::Protocol("Hysteria2载体已关闭")); }
            if tokio::time::Instant::now() >= deadline { return Err(Error::Timeout); }
            let native_pending = h3.has_pending_native();
            if !native_pending { streams.close(); }
            if tasks.is_empty() && streams.is_empty() && !native_pending { return Ok(()); }
        }
        tokio::select! {
            biased;
            _ = context.cancel.cancelled()=>return Err(Error::Cancelled),
            _ = connection.closed()=>return Err(Error::Protocol("Hysteria2载体已关闭")),
            _ = tokio::time::sleep_until(draining.unwrap_or_else(tokio::time::Instant::now)), if draining.is_some()=>return Err(Error::Timeout),
            result=tasks.join_next(),if !tasks.is_empty()=>{if result.is_some_and(|result|result.is_err()){context.events.record(NodeEvent::Failed);}},
            stream=streams.recv(),if native_open=>{
                let Some(stream)=stream else{native_open=false;continue;};let access=peer.lock().map_err(|_|invalid())?.as_ref().map(|(_,peer)|peer.clone()).ok_or(Error::Rejected)?;let context=context.clone();let flows=flows.clone();context.events.record(NodeEvent::Accepted);
                crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move{let result=proxy_tcp(stream,access,context.clone(),flows).await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});result}, Err)?;
            },
            request=h3.next(draining.is_some())=>{
                let resolver=match request? {
                    ControlEvent::Request(resolver)=>*resolver,
                    ControlEvent::Goaway=>{
                        flows.stop_admission();
                        draining=Some(tokio::time::Instant::now()+context.drain_timeout);
                        continue;
                    },
                    ControlEvent::NativeProgress=>continue,
                };
                let authenticated=authenticated.clone();let ready=ready.clone();let context=context.clone();let auth=auth.clone();let ingress=access.clone();let peer=peer.clone();
                let masquerade=masquerade.clone();
                crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move{
                    let operation=async {
                        let (request,mut stream)=resolver.resolve_request().await.map_err(|_|invalid())?;
                        let one=|name:&str|{let mut values=request.headers().get_all(name).iter();let first=values.next();if values.next().is_some(){None}else{first}};
                        let credential=one("hysteria-auth");let bandwidth=one("hysteria-cc-rx").and_then(|value|value.to_str().ok());
                        let valid_bandwidth=bandwidth.is_some_and(|value|!value.is_empty()&&value.bytes().all(|byte|byte.is_ascii_digit())&&value.parse::<u64>().is_ok());
                        let verified=credential.ok_or(Error::Rejected).and_then(|value|{let actual:[u8;32]=Sha256::digest(value.as_bytes()).into();auth.verify(&actual,|expected,actual|Ok(bool::from(actual.ct_eq(expected)).then_some(*expected)))});
                        let is_auth=request.method()==http::Method::POST&&request.uri().path()=="/auth"&&request.uri().authority().is_some_and(|authority|authority.as_str()=="hysteria")&&valid_bandwidth&&verified.is_ok();
                        if is_auth {
                            let (authenticated_peer, identity) = ingress.authenticated(verified?, &context)?;
                            {
                                let mut current = peer.lock().map_err(|_|invalid())?;
                                if current.as_ref().is_some_and(|(previous,_)|previous != &identity) {
                                    return Err(Error::Rejected);
                                }
                                if current.is_none() { *current = Some((identity, authenticated_peer)); }
                            }
                            authenticated.store(true,Ordering::Release);if udp_enabled{ready.notify_one();}
                            let padding:String=rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(256).map(char::from).collect();
                            let cc_rx = match up_bps {
                                Some(bps) => bps.to_string(),
                                None => "auto".into(),
                            };
                            let response=Response::builder().status(233).header("hysteria-udp",if udp_enabled{"true"}else{"false"}).header("hysteria-cc-rx",cc_rx).header("hysteria-padding",padding).body(()).map_err(|_|invalid())?;
                            stream.send_response(response).await.map_err(|_|invalid())?;
                        } else {
                            let (status, headers, body) = resolve_masquerade(&masquerade, request.uri().path());
                            let mut builder = Response::builder().status(status);
                            for (name, val) in headers {
                                builder = builder.header(name, val);
                            }
                            let response = builder.body(()).map_err(|_|invalid())?;
                            stream.send_response(response).await.map_err(|_|invalid())?;
                            if !body.is_empty() {
                                stream.send_data(body).await.map_err(|_|invalid())?;
                            }
                        }
                        stream.finish().await.map_err(|_|invalid())?;Ok(())
                    };
                    crate::budget(&context).run(operation).await
                }, Err)?;
            }
        }
    }
    }.await;
    flows.close(crate::flow::outcome(&result));
    connection.close(0x100u32.into(), b"");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn proxy_tcp(
    mut stream: dispatch::Bi,
    access: PeerSession,
    context: InboundContext,
    flows: Arc<crate::flow::FlowSet>,
) -> Result<()> {
    let establish = crate::budget(&context);
    let address = establish.run(wire::request(&mut stream)).await?;
    let target = crate::target(&address)?;
    let remote = match access.connect_tcp(&target, &establish).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = wire::send_response(&mut stream, false).await;
            return Err(error);
        }
    };
    let remote = flows.tcp(remote)?;
    if let Err(error) = establish.run(wire::send_response(&mut stream, true)).await {
        remote.finish(kerlico_core::FlowOutcome::Failed(
            kerlico_core::FlowFailure::from_error(&error),
        ));
        return Err(error);
    }
    remote
        .relay(Box::new(stream), context.idle_timeout, context.cancel)
        .await
}
pub struct Hysteria2NodeFactory;
impl NodeFactory for Hysteria2NodeFactory {
    fn kind(&self) -> &'static str {
        "hysteria2"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(Hysteria2Node::from_options(input)?))
    }
}

#[cfg(test)]
#[path = "inbound_goaway_tests.rs"]
mod goaway_tests;
