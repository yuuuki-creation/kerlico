//! 节点认证完成后只调用统一目标访问接口；TCP/H3监听均受节点预算限制。
use crate::{
    config::{self, ServerOptions, Transport, User},
    http, padding, tls, transport, uot,
};
use ::http::{Request, Response, StatusCode};
use bytes::Bytes;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    NodeEvent, Result, ScopedCredentialFingerprint, StreamLease,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
pub(crate) struct Node {
    users: Vec<Arc<User>>,
    tls: Arc<rustls::ServerConfig>,
    transports: Vec<Transport>,
    uot: bool,
    congestion: String,
}
struct RequestBudget {
    primary: Arc<Semaphore>,
    streams: Arc<Semaphore>,
}
enum IdentityLease {
    Primary { _lease: OwnedSemaphorePermit },
    Additional { _lease: StreamLease },
}
struct RequestLease {
    _identity: IdentityLease,
    _stream: OwnedSemaphorePermit,
}
impl RequestBudget {
    fn new(limit: usize) -> Self {
        Self {
            primary: Arc::new(Semaphore::new(1)),
            streams: Arc::new(Semaphore::new(limit)),
        }
    }
    fn acquire(&self, context: &InboundContext) -> Result<RequestLease> {
        if context.stream_budget.is_closed() {
            return Err(Error::ResourceLimit);
        }
        let stream = self
            .streams
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let identity = if let Ok(lease) = self.primary.clone().try_acquire_owned() {
            IdentityLease::Primary { _lease: lease }
        } else {
            IdentityLease::Additional {
                _lease: context.stream_budget.try_acquire()?,
            }
        };
        Ok(RequestLease {
            _identity: identity,
            _stream: stream,
        })
    }
}
fn status(error: &Error) -> StatusCode {
    match error {
        Error::Rejected => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        Error::ResourceLimit => StatusCode::SERVICE_UNAVAILABLE,
        Error::Protocol(_) | Error::InvalidAddress => StatusCode::BAD_REQUEST,
        _ => StatusCode::BAD_GATEWAY,
    }
}
fn failed_response(error: &Error) -> Response<()> {
    let mut response = Response::new(());
    *response.status_mut() = status(error);
    response
}
impl Node {
    pub(crate) fn new(options: ServerOptions) -> Result<Self> {
        if options.transports.is_empty()
            || options.transports.len() > 3
            || options
                .transports
                .iter()
                .enumerate()
                .any(|(i, p)| options.transports[..i].contains(p))
            || !matches!(options.congestion_control.as_str(), "cubic" | "reno")
            || !options.transports.contains(&Transport::H3) && options.congestion_control != "cubic"
        {
            return Err(config::invalid());
        }
        Ok(Self {
            users: config::users(options.users)?,
            tls: tls::server(options.tls, &options.transports)?,
            transports: options.transports,
            uot: options.udp_over_tcp,
            congestion: options.congestion_control,
        })
    }
    async fn destination<T>(
        &self,
        request: &Request<T>,
        access: &Arc<dyn AccessService>,
        context: &InboundContext,
    ) -> Result<(kerlico_core::Destination, Option<BoxStream>)> {
        let target = http::check_request(request, &self.users)?;
        let upstream = if uot::version(&target).is_some() {
            if !self.uot {
                return Err(Error::Rejected);
            }
            None
        } else {
            Some(
                access
                    .connect_tcp(
                        &target,
                        &ConnectContext {
                            cancel: context.cancel.clone(),
                            timeout: context.connect_timeout,
                        },
                    )
                    .await?,
            )
        };
        Ok((target, upstream))
    }
    async fn route(
        &self,
        stream: BoxStream,
        target: kerlico_core::Destination,
        upstream: Option<BoxStream>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let stream = padding::wrap(stream, context.cancel.clone());
        if let Some(version) = uot::version(&target) {
            uot::serve(stream, version, access, context).await
        } else {
            kerlico_core::relay_tcp(
                stream,
                upstream.ok_or_else(config::malformed)?,
                context.idle_timeout,
                context.cancel,
            )
            .await
        }
    }
    async fn h1(
        &self,
        mut stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let connection = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let prepare = connection
            .run(async {
                let request = http::read_request(&mut stream).await?;
                self.destination(&request, &access, &context).await
            })
            .await;
        let (target, upstream) = match prepare {
            Ok(value) => value,
            Err(error) => {
                let _ = http::write_response(&mut stream, &failed_response(&error)).await;
                return Err(error);
            }
        };
        connection
            .run(http::write_response(&mut stream, &http::response()))
            .await?;
        self.route(stream, target, upstream, access, context).await
    }
    async fn h2(
        &self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let mut builder = h2::server::Builder::new();
        builder
            .max_concurrent_streams(context.max_streams as u32)
            .initial_window_size(256 * 1024)
            .initial_connection_window_size(4 * 1024 * 1024)
            .max_header_list_size(config::HEADER_LIMIT as u32)
            .max_send_buffer_size(config::BUFFER * 2);
        let mut connection = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        }
        .run(async {
            builder
                .handshake::<_, Bytes>(stream)
                .await
                .map_err(|_| config::malformed())
        })
        .await?;
        let budget = RequestBudget::new(context.max_streams);
        let mut tasks = JoinSet::new();
        let timer = tokio::time::sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                biased;_=context.cancel.cancelled()=>break,
                joined=tasks.join_next(),if !tasks.is_empty()=>{if joined.is_some_and(|r|r.is_err()){context.events.record(NodeEvent::Failed);}timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);},
                _=&mut timer,if tasks.is_empty()=>{connection.graceful_shutdown();break;},
                incoming=connection.accept()=>{
                    let Some(incoming)=incoming else{break};let (request,mut response)=incoming.map_err(|_|config::malformed())?;
                    let lease=match budget.acquire(&context){Ok(lease)=>lease,Err(error)=>{let _=response.send_response(failed_response(&error),true);context.events.record(NodeEvent::Dropped);continue;}};
                    let node=self.clone_owned();let access=access.clone();let context=context.clone();
                    tasks.spawn(async move {let _lease=lease;let control=ConnectContext{cancel:context.cancel.clone(),timeout:context.connect_timeout};
                        let prepared=control.run(node.destination(&request,&access,&context)).await;
                        let (target,upstream)=match prepared{Ok(value)=>value,Err(error)=>{let _=response.send_response(failed_response(&error),true);context.events.record(NodeEvent::Failed);return;}};
                        let writer=match response.send_response(http::response(),false){Ok(writer)=>writer,Err(_)=>return};
                        let stream=transport::h2(request.into_body(),writer,context.cancel.clone(),None);let result=node.route(stream,target,upstream,access,context.clone()).await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});
                    });
                }
            }
        }
        drain(&mut tasks, context.drain_timeout).await;
        Ok(())
    }
    fn clone_owned(&self) -> Arc<Self> {
        Arc::new(Self {
            users: self.users.clone(),
            tls: self.tls.clone(),
            transports: self.transports.clone(),
            uot: self.uot,
            congestion: self.congestion.clone(),
        })
    }
    async fn h3_connection(
        self: Arc<Self>,
        connection: quinn::Connection,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let mut server = h3::server::builder()
            .max_field_section_size(config::HEADER_LIMIT as u64)
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|_| config::malformed())?;
        let budget = RequestBudget::new(context.max_streams);
        let mut tasks = JoinSet::new();
        let timer = tokio::time::sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                biased;_=context.cancel.cancelled()=>break,
                joined=tasks.join_next(),if !tasks.is_empty()=>{if joined.is_some_and(|r|r.is_err()){context.events.record(NodeEvent::Failed);}timer.as_mut().reset(tokio::time::Instant::now()+context.idle_timeout);},
                _=&mut timer,if tasks.is_empty()=>break,
                incoming=server.accept()=>{
                    let resolver=match incoming{Ok(Some(resolver))=>resolver,Ok(None)=>break,Err(_)=>return Err(config::malformed())};
                    let lease=match budget.acquire(&context){Ok(lease)=>lease,Err(_)=>{drop(resolver);context.events.record(NodeEvent::Dropped);continue;}};
                    let node=self.clone();let access=access.clone();let context=context.clone();
                    tasks.spawn(async move {let _lease=lease;let control=ConnectContext{cancel:context.cancel.clone(),timeout:context.connect_timeout};
                        let resolved=control.run(async {resolver.resolve_request().await.map_err(|_|config::malformed())}).await;let Ok((request,mut stream))=resolved else{return};
                        let prepared=control.run(node.destination(&request,&access,&context)).await;let (target,upstream)=match prepared {Ok(value)=>value,Err(error)=>{let _=stream.send_response(failed_response(&error)).await;let _=stream.finish().await;context.events.record(NodeEvent::Failed);return;}};
                        if stream.send_response(http::response()).await.is_err(){return;}let stream=transport::h3_server(stream,context.cancel.clone());let result=node.route(stream,target,upstream,access,context.clone()).await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});
                    });
                }
            }
        }
        drain(&mut tasks, context.drain_timeout).await;
        connection.close(0u32.into(), b"session closed");
        Ok(())
    }
}
async fn drain(tasks: &mut JoinSet<()>, timeout: Duration) {
    if tokio::time::timeout(timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
impl InboundProtocol for Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.users.iter().map(|u| u.fingerprint()).collect()
    }
    fn scoped_credential_fingerprints(&self, _: &str) -> Vec<ScopedCredentialFingerprint> {
        config::credentials(&self.users)
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn requires_udp_association(&self) -> bool {
        self.uot
    }
    fn supports_tcp(&self) -> bool {
        self.transports.iter().any(|p| *p != Transport::H3)
    }
    fn supports_udp(&self) -> bool {
        self.transports.contains(&Transport::H3)
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_tcp() {
                return Err(Error::Unsupported("该Naive节点只启用H3监听"));
            }
            let stream = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            }
            .run(async {
                tokio_rustls::TlsAcceptor::from(self.tls.clone())
                    .accept(stream)
                    .await
                    .map_err(Error::Io)
            })
            .await?;
            let alpn = stream.get_ref().1.alpn_protocol();
            if alpn == Some(b"h2".as_slice()) && self.transports.contains(&Transport::H2) {
                self.h2(Box::new(stream), access, context).await
            } else if (alpn == Some(b"http/1.1".as_slice()) || alpn.is_none())
                && self.transports.contains(&Transport::H1)
            {
                self.h1(Box::new(stream), access, context).await
            } else {
                Err(config::malformed())
            }
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if !self.supports_udp() {
                return Err(Error::Unsupported("该Naive节点未启用H3监听"));
            }
            let fd = socket2::SockRef::from(socket.as_ref()).try_clone()?;
            let standard: std::net::UdpSocket = fd.into();
            let mut endpoint_config = quinn::EndpointConfig::default();
            endpoint_config.supported_versions(vec![1]);
            let server = tls::quic_server(
                self.tls.clone(),
                tls::quic_transport(context.idle_timeout, context.max_streams, &self.congestion)?,
            )?;
            let endpoint = quinn::Endpoint::new(
                endpoint_config,
                Some(server),
                standard,
                Arc::new(quinn::TokioRuntime),
            )?;
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {biased;_=context.cancel.cancelled()=>break,joined=tasks.join_next(),if !tasks.is_empty()=>{if joined.is_some_and(|r|r.is_err()){context.events.record(NodeEvent::Failed);}},incoming=endpoint.accept()=>{
                    let Some(incoming)=incoming else{break};let lease=match context.stream_budget.try_acquire(){Ok(lease)=>lease,Err(_)=>{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;}};
                    let node=self.clone_owned();let access=access.clone();let context=context.clone();tasks.spawn(async move {let _lease=lease;context.events.record(NodeEvent::Accepted);let connection=ConnectContext{cancel:context.cancel.clone(),timeout:context.connect_timeout}.run(async {incoming.await.map_err(|_|config::malformed())}).await;
                        match connection {Ok(connection)=>{let result=node.h3_connection(connection,access,context.clone()).await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});},Err(_)=>context.events.record(NodeEvent::Failed)}
                    });
                }}
            }
            endpoint.close(0u32.into(), b"node stopping");
            drain(&mut tasks, context.drain_timeout).await;
            let _ = tokio::time::timeout(context.drain_timeout, endpoint.wait_idle()).await;
            Ok(())
        })
    }
}
