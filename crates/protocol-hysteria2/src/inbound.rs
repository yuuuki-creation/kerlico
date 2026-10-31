use crate::{
    config::{self, Limits, NodeOptions},
    dispatch, invalid, udp, wire,
};
use bytes::Bytes;
use http::Response;
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, Error, InboundContext, InboundProtocol, NodeEvent, Result,
};
use rand::Rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Notify, mpsc},
    task::JoinSet,
};

pub struct Hysteria2Node {
    auth: [u8; 32],
    tls: Arc<rustls::ServerConfig>,
    salamander: Option<Arc<String>>,
    udp: bool,
    limits: Limits,
}
impl Hysteria2Node {
    pub fn from_options(options: &Value) -> Result<Self> {
        let options: NodeOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Hysteria2 节点字段不合法".into()))?;
        options.limits.validate()?;
        Ok(Self {
            auth: config::auth(&options.auth)?,
            tls: config::server_tls(options.tls)?,
            salamander: config::obfs(options.salamander_password)?,
            udp: options.udp,
            limits: options.limits,
        })
    }
    pub async fn serve_udp(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
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
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(config),
            crate::socket::wrap(standard, self.salamander.clone())?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let mut connections = JoinSet::new();
        let mut maintenance = tokio::time::interval(std::time::Duration::from_millis(100));
        loop {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled()=>break,
                _ = maintenance.tick()=>{if context.stream_budget.is_closed()&&connections.is_empty(){break;}},
                result=connections.join_next(),if !connections.is_empty()=>{if result.is_some_and(|result|result.is_err()){context.events.record(NodeEvent::Failed);}},
                incoming=endpoint.accept()=>{
                    let Some(incoming)=incoming else{break};let Ok(lease)=context.stream_budget.try_acquire() else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};
                    let mut context=context.clone();let access=access.clone();let limits=self.limits.clone();let auth=self.auth;let udp=self.udp;
                    connections.spawn(async move{
                        let _lease=lease;context.events.record(NodeEvent::Accepted);
                        let result=async {
                            let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|invalid())?;
                            context.peer_addr=Some(connection.remote_address());connection_loop(connection,access,context.clone(),limits,auth,udp).await
                        }.await;
                        context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});
                    });
                }
            }
        }
        endpoint.close(0x100u32.into(), b"");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        let _ = tokio::time::timeout(context.drain_timeout, endpoint.wait_idle()).await;
        Ok(())
    }
}
impl InboundProtocol for Hysteria2Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        vec![self.auth]
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
        _access: Arc<dyn AccessService>,
        _context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("Hysteria2 物理监听仅使用 QUIC/UDP")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
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
async fn connection_loop(
    connection: quinn::Connection,
    access: Arc<dyn AccessService>,
    context: InboundContext,
    limits: Limits,
    auth: [u8; 32],
    udp_enabled: bool,
) -> Result<()> {
    let _guard = ConnectionGuard(connection.clone());
    let authenticated = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Notify::new());
    let (proxy, mut streams) = mpsc::channel(limits.max_streams);
    let carrier = dispatch::Connection::new(
        connection.clone(),
        proxy,
        authenticated.clone(),
        context.clone(),
    );
    let mut h3: h3::server::Connection<_, Bytes> = h3::server::builder()
        .max_field_section_size(8192)
        .build(carrier)
        .await
        .map_err(|_| invalid())?;
    let mut tasks = JoinSet::new();
    if udp_enabled {
        tasks.spawn(udp::server(
            connection.clone(),
            access.clone(),
            context.clone(),
            limits,
            ready.clone(),
        ));
    }
    loop {
        tokio::select! {
            biased;
            _ = context.cancel.cancelled()=>break,
            _ = connection.closed()=>break,
            result=tasks.join_next(),if !tasks.is_empty()=>{if result.is_some_and(|result|result.is_err()){context.events.record(NodeEvent::Failed);}},
            stream=streams.recv()=>{
                let Some(stream)=stream else{break};let access=access.clone();let context=context.clone();context.events.record(NodeEvent::Accepted);
                tasks.spawn(async move{let result=proxy_tcp(stream,access,context.clone()).await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});result});
            },
            request=h3.accept()=>{
                let resolver=match request {Ok(Some(resolver))=>resolver,Ok(None)=>break,Err(_)=>{if connection.close_reason().is_some(){break;}return Err(invalid());}};
                let authenticated=authenticated.clone();let ready=ready.clone();let context=context.clone();
                tasks.spawn(async move{
                    let operation=async {
                        let (request,mut stream)=resolver.resolve_request().await.map_err(|_|invalid())?;
                        let one=|name:&str|{let mut values=request.headers().get_all(name).iter();let first=values.next();if values.next().is_some(){None}else{first}};
                        let credential=one("hysteria-auth");let bandwidth=one("hysteria-cc-rx").and_then(|value|value.to_str().ok());
                        let valid_bandwidth=bandwidth.is_some_and(|value|!value.is_empty()&&value.bytes().all(|byte|byte.is_ascii_digit())&&value.parse::<u64>().is_ok());
                        let valid_auth=credential.is_some_and(|value|{let actual:[u8;32]=Sha256::digest(value.as_bytes()).into();bool::from(actual.ct_eq(&auth))});
                        let is_auth=request.method()==http::Method::POST&&request.uri().path()=="/auth"&&request.uri().authority().is_some_and(|authority|authority.as_str()=="hysteria")&&valid_bandwidth&&valid_auth;
                        if is_auth {
                            authenticated.store(true,Ordering::Release);if udp_enabled{ready.notify_one();}
                            let padding:String=rand::thread_rng().sample_iter(rand::distributions::Alphanumeric).take(256).map(char::from).collect();
                            let response=Response::builder().status(233).header("hysteria-udp",if udp_enabled{"true"}else{"false"}).header("hysteria-cc-rx","auto").header("hysteria-padding",padding).body(()).map_err(|_|invalid())?;
                            stream.send_response(response).await.map_err(|_|invalid())?;
                        } else {
                            let response=Response::builder().status(404).header("content-type","text/plain; charset=utf-8").body(()).map_err(|_|invalid())?;stream.send_response(response).await.map_err(|_|invalid())?;stream.send_data(Bytes::from_static("资源不存在".as_bytes())).await.map_err(|_|invalid())?;
                        }
                        stream.finish().await.map_err(|_|invalid())?;Ok(())
                    };
                    crate::budget(&context).run(operation).await
                });
            }
        }
    }
    connection.close(0x100u32.into(), b"");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn proxy_tcp(
    mut stream: dispatch::Bi,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let establish = crate::budget(&context);
    let remote = establish
        .run(async {
            let address = wire::request(&mut stream).await?;
            let target = crate::target(&address)?;
            match access.connect_tcp(&target, &establish).await {
                Ok(remote) => {
                    wire::send_response(&mut stream, true).await?;
                    Ok(remote)
                }
                Err(error) => {
                    let _ = wire::send_response(&mut stream, false).await;
                    Err(error)
                }
            }
        })
        .await?;
    kerlico_core::relay_tcp(
        Box::new(stream),
        remote,
        context.idle_timeout,
        context.cancel,
    )
    .await
}
pub struct Hysteria2NodeFactory;
impl NodeFactory for Hysteria2NodeFactory {
    fn kind(&self) -> &'static str {
        "hysteria2"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(Hysteria2Node::from_options(options)?))
    }
}
