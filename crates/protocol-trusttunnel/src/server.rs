//! 鉴权及目标解码完成后才调用统一 AccessService；载体、逻辑流和 UDP flow 分别计费。
use crate::{
    config::{self, Limits, NodeOptions, Transport},
    io::{BodyIo, Reader, Writer},
    protocol,
};
use bytes::Bytes;
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Destination, Error, InboundContext,
    InboundProtocol, NodeEvent, Result, ScopedCredentialFingerprint,
};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, task::JoinSet};
pub struct TrustTunnelNodeFactory;
#[derive(Clone)]
struct Node {
    tls: Arc<rustls::ServerConfig>,
    users: Arc<Vec<[u8; 32]>>,
    http_users: Arc<Vec<[u8; 32]>>,
    isolation: Arc<Vec<ScopedCredentialFingerprint>>,
    transport: Transport,
    udp: bool,
    limits: Limits,
}
impl NodeFactory for TrustTunnelNodeFactory {
    fn kind(&self) -> &'static str {
        "trusttunnel"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options: NodeOptions =
            serde_json::from_value(value.clone()).map_err(|_| crate::invalid())?;
        let limits = options.limits.into_limits()?;
        if options.users.is_empty() || options.users.len() > 256 {
            return Err(crate::invalid());
        }
        let mut seen = BTreeSet::new();
        let mut passwords = BTreeSet::new();
        let mut users = Vec::new();
        let mut http_users = Vec::new();
        let mut isolation = Vec::new();
        for user in options.users {
            user.validate()?;
            let auth = user.hash();
            let secret = user.isolation();
            if !seen.insert(auth) || !passwords.insert(secret.fingerprint) {
                return Err(crate::invalid());
            }
            users.push(auth);
            http_users.push(user.http_hash());
            isolation.push(secret);
        }
        Ok(Arc::new(Node {
            tls: config::server_tls(options.tls, options.transport)?,
            users: Arc::new(users),
            http_users: Arc::new(http_users),
            isolation: Arc::new(isolation),
            transport: options.transport,
            udp: options.udp,
            limits,
        }))
    }
}
enum Reply {
    H1(BoxStream),
    H2(h2::server::SendResponse<Bytes>, h2::RecvStream),
    H3(Box<crate::io::H3Server>),
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
        request: http::Request<()>,
        reply: Reply,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        if !config::authenticate(request.headers(), &self.users) {
            let _ = reply.send(407).await?;
            return Err(Error::Rejected);
        }
        let authority = match authority(&request) {
            Ok(v) => v,
            Err(error) => {
                let _ = reply.send(400).await?;
                return Err(error);
            }
        };
        if context.stream_budget.is_closed() {
            let _ = reply.send(503).await?;
            return Err(Error::ResourceLimit);
        }
        if authority == "_icmp" {
            let _ = reply.send(501).await?;
            return Err(Error::Unsupported("TrustTunnel ICMP 尚无统一目标访问契约"));
        }
        if authority == "_check" {
            let mut io = reply.send(200).await?;
            io.shutdown().await?;
            return Ok(());
        }
        if authority == "_udp2" {
            if !self.udp {
                let _ = reply.send(501).await?;
                return Err(Error::Unsupported("TrustTunnel UDP 已关闭"));
            }
            let io = reply.send(200).await?;
            return crate::udp::serve(io, access, context, self.limits.max_udp_flows).await;
        }
        let target = match target(authority) {
            Ok(v) => v,
            Err(error) => {
                let _ = reply.send(400).await?;
                return Err(error);
            }
        };
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let remote = match connect.run(access.connect_tcp(&target, &connect)).await {
            Ok(v) => v,
            Err(error) => {
                let _ = reply.send(502).await?;
                return Err(error);
            }
        };
        let io = reply.send(200).await?;
        kerlico_core::relay_tcp(io, remote, context.idle_timeout, context.cancel).await
    }
    async fn tcp(
        &self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        mut context: InboundContext,
    ) -> Result<()> {
        context.idle_timeout = context.idle_timeout.min(self.limits.idle());
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
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
                .request(request, Reply::H1(stream), access, context)
                .await;
        }
        let mut connection = connect
            .run(async {
                h2::server::Builder::new()
                    .initial_window_size(131072)
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
        loop {
            tokio::select! {biased;
                _=context.cancel.cancelled()=>break,
                _=tick.tick()=>{
                    if context.stream_budget.is_closed()&&draining.is_none(){connection.graceful_shutdown();draining=Some(tokio::time::Instant::now()+context.drain_timeout);}
                    if draining.is_some_and(|deadline|tokio::time::Instant::now()>=deadline)||(tasks.is_empty()&&last.elapsed()>=context.idle_timeout){break;}
                },
                result=tasks.join_next(),if !tasks.is_empty()=>{last=tokio::time::Instant::now();if matches!(result,Some(Ok(true))){connection.abrupt_shutdown(h2::Reason::from(0x1f));draining=Some(tokio::time::Instant::now()+context.drain_timeout);}},
                request=connection.accept()=>{let Some(request)=request else{break;};let(request,reply)=request.map_err(|_|protocol())?;last=tokio::time::Instant::now();
                    let lease=match context.stream_budget.try_acquire(){Ok(v)=>v,Err(_)=>{let _=Reply::H2(reply,request.into_body()).send(503).await;context.events.record(NodeEvent::Dropped);continue;}};
                    let(request,body)=request.into_parts();let node=self.clone();let access=access.clone();let context=context.clone();tasks.spawn(async move{let _lease=lease;let result=node.request(http::Request::from_parts(request,()),Reply::H2(reply,body),access,context.clone()).await;let rejected=matches!(&result,Err(Error::Rejected));context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});rejected});
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
    async fn quic(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
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
        let (socket, _socket_close) = crate::socket::wrap(standard)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            config,
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let mut tasks = JoinSet::new();
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        let mut draining = None;
        loop {
            tokio::select! {biased;_=context.cancel.cancelled()=>break,
                            _=tick.tick()=>{if context.stream_budget.is_closed()&&draining.is_none(){draining=Some(tokio::time::Instant::now()+context.drain_timeout);}
            if draining.is_some_and(|v|tokio::time::Instant::now()>=v){break;}},
                            _=tasks.join_next(),if !tasks.is_empty()=>{},
                            incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};if context.stream_budget.is_closed(){incoming.refuse();continue;}let Ok(lease)=context.stream_budget.try_acquire()else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};let node=self.clone();let access=access.clone();let context=context.clone();tasks.spawn(async move{let _lease=lease;context.events.record(NodeEvent::Accepted);let connect=ConnectContext{cancel:context.cancel.clone(),timeout:context.connect_timeout};let result=async{let connection=connect.run(async{incoming.await.map_err(|_|protocol())}).await?;node.h3(connection,access,context.clone()).await}.await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});}
                        }
        }
        endpoint.close(0x100u32.into(), b"");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let _ = tokio::time::timeout(context.drain_timeout, endpoint.wait_idle()).await;
        Ok(())
    }
    async fn h3(
        &self,
        connection: quinn::Connection,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
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
        let mut draining = None;
        loop {
            tokio::select! {biased;_=context.cancel.cancelled()=>break,
                            _=tick.tick()=>{if context.stream_budget.is_closed()&&draining.is_none(){let _=server.shutdown(0).await;draining=Some(tokio::time::Instant::now()+context.drain_timeout);}
            if draining.is_some_and(|v|tokio::time::Instant::now()>=v){break;}},
                            result=tasks.join_next(),if !tasks.is_empty()=>{if matches!(result,Some(Ok(true))){connection.close(0x1fu32.into(),b"");break;}},
                            resolver=server.accept()=>{let resolver=match resolver{Ok(Some(v))=>v,Ok(None)=>break,Err(_)=>return Err(protocol())};let lease=match context.stream_budget.try_acquire(){Ok(v)=>v,Err(_)=>{context.events.record(NodeEvent::Dropped);continue;}};let node=self.clone();let access=access.clone();let context=context.clone();tasks.spawn(async move{let _lease=lease;let connect=ConnectContext{cancel:context.cancel.clone(),timeout:context.connect_timeout};let result=async{let(request,stream)=connect.run(async{resolver.resolve_request().await.map_err(|_|protocol())}).await?;node.request(request,Reply::H3(Box::new(stream)),access,context.clone()).await}.await;let rejected=matches!(&result,Err(Error::Rejected));context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});rejected});}
                        }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        connection.close(0x100u32.into(), b"");
        Ok(())
    }
}
impl InboundProtocol for Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.users.as_ref().clone()
    }
    fn scoped_credential_fingerprints(&self, _: &str) -> Vec<ScopedCredentialFingerprint> {
        self.users
            .iter()
            .map(|fingerprint| ScopedCredentialFingerprint {
                protocol: "trusttunnel".into(),
                fingerprint: *fingerprint,
            })
            .chain(
                self.http_users
                    .iter()
                    .map(|fingerprint| ScopedCredentialFingerprint {
                        protocol: "http".into(),
                        fingerprint: *fingerprint,
                    }),
            )
            .collect()
    }
    fn credential_isolation_fingerprints(
        &self,
        default_protocol: &str,
    ) -> Vec<ScopedCredentialFingerprint> {
        let mut values = self.scoped_credential_fingerprints(default_protocol);
        values.extend(self.isolation.iter().cloned());
        values
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
        access: Arc<dyn AccessService>,
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
        access: Arc<dyn AccessService>,
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
