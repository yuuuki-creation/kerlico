use crate::{
    carrier::{
        http::{
            body::Body,
            server::{self, Handler},
        },
        tls,
    },
    classify::{self, Classified},
    codec::record::Method,
    config::{NodeConfig, NodeOptions},
    handshake,
    io::{CancelIo, CancelOnDrop, SharedIo},
    service::Runtime,
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    NodeEvent, Result, ScopedCredentialFingerprint,
};
use serde_json::Value;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, watch},
    time::Instant,
};

pub struct SudokuNodeFactory;
struct Node {
    config: Arc<NodeConfig>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    ready: watch::Sender<Option<Arc<Runtime>>>,
    running: tokio::sync::Mutex<()>,
}
impl NodeFactory for SudokuNodeFactory {
    fn kind(&self) -> &'static str {
        "sudoku"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options: NodeOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Sudoku节点字段不合法".into()))?;
        let config = Arc::new(options.prepare()?);
        let tls = config.mask.tls.as_ref().map(tls::server).transpose()?;
        let (ready, _) = watch::channel(None);
        Ok(Arc::new(Node {
            config,
            tls,
            ready,
            running: tokio::sync::Mutex::new(()),
        }))
    }
}
struct ReadyGuard<'a> {
    ready: &'a watch::Sender<Option<Arc<Runtime>>>,
    cancel: kerlico_core::CancellationToken,
}
impl Drop for ReadyGuard<'_> {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.ready.send_replace(None);
    }
}
impl Node {
    async fn runtime(&self, context: &InboundContext) -> Result<Arc<Runtime>> {
        let mut ready = self.ready.subscribe();
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        connect
            .run(async {
                loop {
                    if let Some(runtime) = ready.borrow_and_update().clone() {
                        return Ok(runtime);
                    }
                    ready.changed().await.map_err(|_| Error::Cancelled)?;
                }
            })
            .await
    }
    async fn http(
        &self,
        stream: BoxStream,
        h2: bool,
        runtime: Arc<Runtime>,
        context: InboundContext,
    ) -> Result<()> {
        let (stream, compat) = if !h2 && self.config.mask.mode.split() {
            let (stream, handle) =
                crate::carrier::http::h1_compat::wrap(stream, &self.config.mask.path_root);
            (stream, Some(handle))
        } else {
            (stream, None)
        };
        let upgraded_runtime = runtime.clone();
        let mut upgraded_context = context.clone();
        upgraded_context.connect_timeout = runtime.context.connect_timeout;
        let upgraded: server::UpgradedHandler = Arc::new(move |stream, early, lease| {
            if let Some(compat) = compat.as_ref() {
                compat.accepted();
            }
            let runtime = upgraded_runtime.clone();
            let mut context = upgraded_context.clone();
            context.cancel = runtime.scope.cancel.child_token();
            Box::pin(async move {
                let _lease = lease;
                context.events.record(NodeEvent::Accepted);
                let result = runtime.accept(stream, early, context.clone()).await;
                context.events.record(if result.is_ok() {
                    NodeEvent::Completed
                } else {
                    NodeEvent::Failed
                });
            })
        });
        let cover = runtime.cover.clone().map(|client| {
            Arc::new(move |method| {
                let client = client.clone();
                Box::pin(crate::cover::http(client, method))
                    as BoxFuture<'static, http::Response<Body>>
            }) as server::CoverHandler
        });
        let handler = Arc::new(Handler {
            registry: runtime.registry.clone(),
            mode: self.config.mask.mode,
            root: self.config.mask.path_root.clone(),
            upgraded,
            cover,
        });
        let active = Arc::new(Semaphore::new(64));
        let last = Arc::new(Mutex::new(Instant::now()));
        let service_active = active.clone();
        let service_last = last.clone();
        let service = service_fn(move |request: http::Request<Incoming>| {
            let handler = handler.clone();
            let active = service_active.clone();
            let last = service_last.clone();
            async move {
                *last.lock().unwrap() = Instant::now();
                let response = match active.try_acquire_owned() {
                    Ok(permit) => {
                        let mut response = handler.handle(request).await;
                        response.body_mut()._physical = Some(permit);
                        response
                    }
                    Err(_) => {
                        server::response(http::StatusCode::SERVICE_UNAVAILABLE, bytes::Bytes::new())
                    }
                };
                Ok::<_, Infallible>(response)
            }
        });
        let mut builder = Builder::new(TokioExecutor::new());
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(runtime.context.connect_timeout)
            .max_buf_size(32 * 1024)
            .keep_alive(true);
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(64)
            .max_header_list_size(32 * 1024)
            .max_send_buf_size(128 * 1024);
        let builder = if h2 {
            builder.http2_only()
        } else {
            builder.http1_only()
        };
        let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
        tokio::pin!(connection);
        let mut tick = tokio::time::interval(Duration::from_millis(25));
        let mut draining = None;
        loop {
            tokio::select! {biased;
                _=context.cancel.cancelled()=>return Err(Error::Cancelled),
                _=runtime.scope.cancel.cancelled()=>return Err(Error::Cancelled),
                result=&mut connection=>return result.map_err(|_|Error::Protocol("Sudoku HTTP载体连接失败")),
                _=tick.tick()=>{
                    if context.stream_budget.is_closed() && draining.is_none(){connection.as_mut().graceful_shutdown();draining=Some(Instant::now()+context.drain_timeout);}
                    if draining.is_some_and(|until|Instant::now()>=until){return Ok(());}
                    if draining.is_none() && active.available_permits()==64 && last.lock().unwrap().elapsed()>=context.idle_timeout{return Ok(());}
                }
            }
        }
    }
    async fn physical(&self, stream: BoxStream, mut context: InboundContext) -> Result<()> {
        let deadline = Instant::now() + context.connect_timeout;
        let runtime = self.runtime(&context).await?;
        if self.config.protocol.method == Method::None
            && !context
                .local_addr
                .is_some_and(|address| address.ip().is_loopback())
        {
            return Err(Error::Rejected);
        }
        context.connect_timeout = deadline.saturating_duration_since(Instant::now());
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let stream = Box::new(CancelIo::new(
            CancelIo::new(stream, &runtime.scope.cancel),
            &context.cancel,
        )) as BoxStream;
        let (stream, h2) = connect
            .run(async {
                if let Some(tls) = self.tls.as_ref() {
                    let stream = tls.accept(stream).await?;
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    Ok((Box::new(stream) as BoxStream, h2))
                } else {
                    Ok((stream, false))
                }
            })
            .await?;
        let classified = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: deadline.saturating_duration_since(Instant::now()),
        }
        .run(classify::read(
            stream,
            &self.config.protocol,
            self.config.mask.mode,
                    &self.config.mask.path_root,
            runtime.cover.is_some(),
            h2,
        ))
        .await?;
        context.connect_timeout = deadline.saturating_duration_since(Instant::now());
        match classified {
            Classified::Http { stream, h2 }
                if self.config.mask.mode.http() || runtime.cover.is_some() =>
            {
                self.http(stream, h2, runtime, context).await
            }
            Classified::Http { .. } => Err(Error::Rejected),
            Classified::Raw(stream) => runtime.accept(stream, None, context).await,
            Classified::Legacy {
                stream,
                cover_method,
            } => {
                if let (Some(client), Some(method)) = (runtime.cover.as_ref(), cover_method) {
                    let shared = SharedIo::new(stream);
                    let connect = ConnectContext {
                        cancel: context.cancel.clone(),
                        timeout: context.connect_timeout,
                    };
                    let start = Instant::now();
                    let negotiated = connect
                        .run(handshake::server(
                            Box::new(shared.clone()),
                            &self.config.protocol,
                        ))
                        .await;
                    match negotiated {
                        Ok(negotiated) => {
                            drop(shared);
                            context.connect_timeout =
                                context.connect_timeout.saturating_sub(start.elapsed());
                            runtime.process(negotiated, context).await
                        }
                        Err(Error::Cancelled) => Err(Error::Cancelled),
                        Err(_) => {
                            ConnectContext {
                                cancel: context.cancel,
                                timeout: Duration::from_secs(4),
                            }
                            .run(crate::cover::raw(client, method, shared))
                            .await
                        }
                    }
                } else {
                    runtime.accept(stream, None, context).await
                }
            }
        }
    }
}
impl InboundProtocol for Node {
    fn requires_udp_association(&self) -> bool {
        self.config.protocol.udp_enabled
    }
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        if self.config.protocol.method == Method::None {
            Vec::new()
        } else {
            vec![self.config.protocol.material.fingerprint]
        }
    }
    fn credential_isolation_fingerprints(
        &self,
        _default: &str,
    ) -> Vec<ScopedCredentialFingerprint> {
        vec![ScopedCredentialFingerprint {
            protocol: "sudoku".to_owned(),
            fingerprint: self.config.protocol.material.fingerprint,
        }]
    }
    fn requires_loopback(&self) -> bool {
        self.config.protocol.method == Method::None
    }
    fn supports_virtual(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        _access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.physical(stream, context))
    }
    fn handle_virtual<'a>(
        &'a self,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let _running = self
                .running
                .try_lock()
                .map_err(|_| Error::Config("Sudoku同一节点不能重复启动".into()))?;
            let (runtime, mut backends) =
                Runtime::start(self.config.clone(), access, context.clone())?;
            let _ready = ReadyGuard {
                ready: &self.ready,
                cancel: runtime.scope.cancel.clone(),
            };
            let _cancel = CancelOnDrop(runtime.scope.cancel.clone());
            self.ready.send_replace(Some(runtime.clone()));
            let mut tick = tokio::time::interval(Duration::from_millis(25));
            let mut draining = None;
            loop {
                tokio::select! {biased;
                    _=context.cancel.cancelled()=>break,
                    _=tick.tick()=>{
                        if context.stream_budget.is_closed() && draining.is_none(){
                            draining=Some(Instant::now()+context.drain_timeout);
                        }
                        if draining.is_some_and(|until|Instant::now()>=until){break;}
                    },
                    backend=backends.recv()=>{let Some(backend)=backend else{break;};let runtime=runtime.clone();let mut logical=context.clone();logical.cancel=backend.token.cancel.clone();logical.events.record(NodeEvent::Accepted);
                        runtime.clone().scope.spawn(async move {let token=backend.token;let result=runtime.accept(backend.stream,backend.early,logical.clone()).await;logical.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});if result.is_err(){token.failed.store(true,std::sync::atomic::Ordering::Release);runtime.registry.remove(&token.value);}});
                    }
                }
            }
            runtime.registry.shutdown();
            runtime.scope.shutdown().await;
            Ok(())
        })
    }
}
