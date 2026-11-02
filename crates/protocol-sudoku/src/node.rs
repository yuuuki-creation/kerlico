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
    io::{CancelIo, CancelOnDrop, SharedIo},
    members::Members,
    scope::ScopeExecutor,
    service::Runtime,
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, Error, InboundContext,
    InboundProtocol, IngressBinding, NodeEvent, Result,
};
use serde::Deserialize;
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
    members: Arc<Members>,
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
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NativeKey {
            key: String,
        }
        let mut value = input.options().clone();
        let mut protocols = Vec::new();
        if !input.is_local() {
            if !value
                .get("protocol")
                .is_some_and(serde_json::Value::is_object)
            {
                return Err(Error::Config("Sudoku节点protocol必须是对象".into()));
            }
            if value.get("protocol").and_then(|p| p.get("key")).is_some()
                || input.native_credentials().is_empty()
                || input.native_credentials().len() > 256
            {
                return Err(Error::Config("Sudoku节点密钥须来自成员凭据".into()));
            }
            let mut seen = std::collections::HashSet::new();
            for native in input.native_credentials() {
                let native: NativeKey = serde_json::from_value(native.clone())
                    .map_err(|_| Error::Config("Sudoku成员凭据不合法".into()))?;
                value["protocol"]["key"] = serde_json::Value::String(native.key);
                let protocol: crate::config::ProtocolOptions =
                    serde_json::from_value(value["protocol"].clone())
                        .map_err(|_| crate::invalid())?;
                let protocol = protocol.prepare()?;
                if protocol.method == Method::None || !seen.insert(protocol.material.fingerprint) {
                    return Err(Error::Rejected);
                }
                protocols.push(protocol);
            }
        }
        let options: NodeOptions = serde_json::from_value(value)
            .map_err(|_| Error::Config("Sudoku节点字段不合法".into()))?;
        let mut config = options.prepare()?;
        if let Some(protocol) = protocols.first() {
            config.protocol = protocol.clone();
        }
        let config = Arc::new(config);
        if input.is_local() && config.protocol.method != Method::None {
            return Err(Error::Config("Sudoku Local只允许显式none编码".into()));
        }
        let members = Arc::new(Members {
            credentials: input.credentials(protocols)?,
            local: config.protocol.clone(),
        });
        let tls = config.mask.tls.as_ref().map(tls::server).transpose()?;
        let (ready, _) = watch::channel(None);
        Ok(Arc::new(Node {
            config,
            members,
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
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
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
            let context = upgraded_context.clone();
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
        let mut builder = Builder::new(ScopeExecutor(runtime.scope.clone()));
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
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
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
        let classified = ConnectContext::new(deadline.saturating_duration_since(Instant::now()))
            .with_cancel(context.cancel.clone())
            .run(classify::read(
                stream,
                &self.members.protocols(),
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
                    let connect = ConnectContext::new(context.connect_timeout)
                        .with_cancel(context.cancel.clone());
                    let start = Instant::now();
                    let negotiated = connect
                        .run(runtime.negotiate(Box::new(shared.clone()), None, &context))
                        .await;
                    match negotiated {
                        Ok((negotiated, peer)) => {
                            drop(shared);
                            context.connect_timeout =
                                context.connect_timeout.saturating_sub(start.elapsed());
                            runtime.process(negotiated, peer, context).await
                        }
                        Err(Error::Cancelled) => Err(Error::Cancelled),
                        Err(_) => {
                            ConnectContext::new(Duration::from_secs(4))
                                .with_cancel(context.cancel)
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
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        if self.members.credentials.is_empty() {
            manifest.protection("sudoku", self.config.protocol.material.fingerprint);
        } else {
            for (index, (_, protocol)) in self.members.credentials.rows().enumerate() {
                manifest.authentication("sudoku", index, protocol.material.fingerprint);
            }
        }
        manifest
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
        _access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.physical(stream, context))
    }
    fn handle_virtual<'a>(
        &'a self,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let _running = self
                .running
                .try_lock()
                .map_err(|_| Error::Config("Sudoku同一节点不能重复启动".into()))?;
            let (runtime, mut backends) = Runtime::start(
                self.config.clone(),
                self.members.clone(),
                access,
                context.clone(),
            )?;
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
