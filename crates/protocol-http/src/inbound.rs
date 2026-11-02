mod flush;
use crate::config::{self, Auth, ServerTls};
use bytes::Bytes;
use flush::FlushReceipts;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Destination, Error,
    FlowCompletion, FlowFailure, FlowOutcome, InboundContext, InboundProtocol, IngressBinding,
    Result, TcpFlow,
};
use serde::Deserialize;
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{oneshot, watch},
    task::JoinSet,
    time::Instant,
};

type BodyError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BodyError>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    tls: Option<ServerTls>,
}
struct HttpNode {
    auth: CredentialSet<Auth>,
    tls: Option<tokio_rustls::TlsAcceptor>,
}
fn connect(context: &InboundContext) -> ConnectContext {
    ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone())
}
fn simple(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::new())
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    response
}
fn strip(headers: &mut HeaderMap) {
    let nominated: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| http::header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
fn target(authority: &http::uri::Authority, require_port: bool) -> Result<Destination> {
    if authority.as_str().contains('@') || (require_port && authority.port_u16().is_none()) {
        return Err(config::invalid());
    }
    Destination::new(
        authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']'),
        authority.port_u16().unwrap_or(80),
    )
}
struct Tasks(Arc<Mutex<JoinSet<()>>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.0.lock() {
            tasks.abort_all();
        }
    }
}
fn spawn(
    tasks: &Arc<Mutex<JoinSet<()>>>,
    context: &InboundContext,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let mut tasks = tasks.lock().map_err(|_| config::invalid())?;
    while tasks.try_join_next().is_some() {}
    if tasks.len() >= context.max_streams {
        return Err(Error::ResourceLimit);
    }
    let task = context.tasks.spawn_tracked(future)?;
    tasks.spawn(async move {
        let _ = task.await;
    });
    Ok(())
}

struct PendingFlow {
    flow: Option<TcpFlow>,
    peer: kerlico_core::CancellationToken,
    node: kerlico_core::CancellationToken,
}
impl PendingFlow {
    fn take(&mut self) -> TcpFlow {
        self.flow.take().expect("任务接纳后移交流")
    }
}
impl Drop for PendingFlow {
    fn drop(&mut self) {
        if let Some(flow) = self.flow.take() {
            flow.finish(FlowOutcome::Failed(
                if self.peer.is_cancelled() || self.node.is_cancelled() {
                    FlowFailure::Cancelled
                } else {
                    FlowFailure::Failed
                },
            ));
        }
    }
}
struct PendingCompletion {
    completion: Option<FlowCompletion>,
    peer: kerlico_core::CancellationToken,
    node: kerlico_core::CancellationToken,
}
impl PendingCompletion {
    fn take(&mut self) -> FlowCompletion {
        self.completion.take().expect("任务接纳后移交完成权")
    }
}
impl Drop for PendingCompletion {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            completion.finish(FlowOutcome::Failed(
                if self.peer.is_cancelled() || self.node.is_cancelled() {
                    FlowFailure::Cancelled
                } else {
                    FlowFailure::Failed
                },
            ));
        }
    }
}
struct ApplicationEnd(Option<oneshot::Sender<FlowOutcome>>);
impl ApplicationEnd {
    fn finish(&mut self, outcome: FlowOutcome) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(outcome);
        }
    }
}
impl Drop for ApplicationEnd {
    fn drop(&mut self) {
        self.finish(FlowOutcome::ClosedByCaller);
    }
}
struct ResponseBody {
    body: Incoming,
    end: Mutex<ApplicationEnd>,
    flushed: FlushReceipts,
}
impl ResponseBody {
    fn pending_flush(&self) {
        let sender = self
            .end
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .0
            .take();
        if let Some(sender) = sender {
            self.flushed.register(sender);
        }
    }
}
impl hyper::body::Body for ResponseBody {
    type Data = Bytes;
    type Error = BodyError;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.body).poll_frame(cx) {
            Poll::Ready(None) => {
                this.pending_flush();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.end
                    .get_mut()
                    .unwrap_or_else(|error| error.into_inner())
                    .finish(FlowOutcome::Failed(FlowFailure::Failed));
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_trailers() || this.body.is_end_stream() {
                    this.pending_flush();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        let ended = self.body.is_end_stream();
        if ended {
            self.pending_flush();
        }
        ended
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
async fn parent_end(receiver: &mut watch::Receiver<Option<FlowOutcome>>) -> FlowOutcome {
    loop {
        if let Some(outcome) = *receiver.borrow_and_update() {
            return outcome;
        }
        if receiver.changed().await.is_err() {
            return FlowOutcome::ClosedByCaller;
        }
    }
}

impl HttpNode {
    async fn request(
        auth: CredentialSet<Auth>,
        mut request: Request<Incoming>,
        ingress: IngressBinding,
        context: InboundContext,
        tasks: Arc<Mutex<JoinSet<()>>>,
        mut parent: watch::Receiver<Option<FlowOutcome>>,
        flushed: FlushReceipts,
    ) -> Result<Response<Body>> {
        let access = if auth.is_empty() {
            ingress.local(&context)?
        } else {
            let header = (request
                .headers()
                .get_all("proxy-authorization")
                .iter()
                .count()
                == 1)
                .then(|| {
                    request
                        .headers()
                        .get("proxy-authorization")
                        .and_then(|value| value.to_str().ok())
                })
                .flatten();
            let verified = header.ok_or(Error::Rejected).and_then(|header| {
                auth.verify(&header, |auth, value| Ok(auth.matches(value).then_some(())))
            });
            let Ok(verified) = verified else {
                let mut response = simple(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                response.headers_mut().insert(
                    "proxy-authenticate",
                    http::HeaderValue::from_static("Basic realm=\"kerlico\", charset=\"UTF-8\""),
                );
                response
                    .headers_mut()
                    .insert("connection", http::HeaderValue::from_static("close"));
                return Ok(response);
            };
            ingress.authenticated(verified, &context)?.0
        };
        if request.method() == Method::CONNECT {
            if request.uri().scheme().is_some()
                || request.uri().path_and_query().is_some()
                || request.headers().contains_key("transfer-encoding")
                || request
                    .headers()
                    .get("content-length")
                    .is_some_and(|value| value.as_bytes() != b"0")
            {
                return Ok(simple(StatusCode::BAD_REQUEST));
            }
            let authority = request.uri().authority().ok_or_else(config::invalid)?;
            let target = target(authority, true)?;
            let budget = connect(&context);
            let remote = budget.run(access.connect_tcp(&target, &budget)).await?;
            let upgrade = hyper::upgrade::on(&mut request);
            let mut pending = PendingFlow {
                flow: Some(remote),
                peer: context.cancel.clone(),
                node: context.tasks.cancel(),
            };
            let task_context = context.clone();
            spawn(&tasks, &context, async move {
                let remote = pending.take();
                let upgraded = tokio::select! {
                    biased;
                    _=task_context.cancel.cancelled()=>Err(Error::Cancelled),
                    outcome=parent_end(&mut parent)=>{ remote.finish(outcome); return; },
                    result=tokio::time::timeout(task_context.connect_timeout,upgrade)=>match result {
                        Ok(Ok(upgraded))=>Ok(upgraded), Ok(Err(_))=>Err(config::invalid()), Err(_)=>Err(Error::Timeout),
                    }
                };
                match upgraded {
                    Ok(upgraded) => {
                        let _ = kerlico_core::relay_tcp(
                            Box::new(TokioIo::new(upgraded)),
                            remote,
                            task_context.idle_timeout,
                            task_context.cancel,
                        )
                        .await;
                    }
                    Err(error) => {
                        remote.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)))
                    }
                }
            })?;
            return Ok(simple(StatusCode::OK));
        }
        if request.uri().scheme_str() != Some("http") || request.headers().contains_key("upgrade") {
            return Ok(simple(StatusCode::BAD_REQUEST));
        }
        let authority = request
            .uri()
            .authority()
            .ok_or_else(config::invalid)?
            .clone();
        let destination = target(&authority, false)?;
        if request.headers().get_all("host").iter().count() != 1 {
            return Ok(simple(StatusCode::BAD_REQUEST));
        }
        let host = request
            .headers()
            .get("host")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(config::invalid)?
            .parse::<http::uri::Authority>()
            .map_err(|_| config::invalid())?;
        if target(&host, false)? != destination {
            return Ok(simple(StatusCode::BAD_REQUEST));
        }
        let uri = request
            .uri()
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/")
            .parse::<http::Uri>()
            .map_err(|_| config::invalid())?;
        let budget = connect(&context);
        let remote = budget
            .run(access.connect_tcp(&destination, &budget))
            .await?;
        let (io, completion) = remote.into_parts();
        let handshake = budget
            .run(async {
                hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(io))
                    .await
                    .map_err(|_| config::invalid())
            })
            .await;
        let (mut sender, connection) = match handshake {
            Ok(value) => value,
            Err(error) => {
                completion.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
                return Err(error);
            }
        };
        let (application, mut application_done) = oneshot::channel();
        let mut application = ApplicationEnd(Some(application));
        let mut pending = PendingCompletion {
            completion: Some(completion),
            peer: context.cancel.clone(),
            node: context.tasks.cancel(),
        };
        let token = context.cancel.clone();
        spawn(&tasks, &context, async move {
            let completion = pending.take();
            tokio::pin!(connection);
            let mut driver_done = false;
            let mut driver_failure = None;
            let mut application_outcome = None;
            let outcome = loop {
                if application_outcome.is_none() {
                    match application_done.try_recv() {
                        Ok(outcome) if outcome != FlowOutcome::ProtocolEnd => {
                            break driver_failure.unwrap_or(outcome);
                        }
                        Ok(outcome) => application_outcome = Some(outcome),
                        Err(oneshot::error::TryRecvError::Closed) => {
                            break driver_failure.unwrap_or(FlowOutcome::ClosedByCaller);
                        }
                        Err(oneshot::error::TryRecvError::Empty) => {}
                    }
                }
                if driver_done && let Some(outcome) = application_outcome {
                    break driver_failure.unwrap_or(outcome);
                }
                tokio::select! {
                    biased;
                    _=token.cancelled()=>break driver_failure.unwrap_or(FlowOutcome::Failed(FlowFailure::Cancelled)),
                    outcome=parent_end(&mut parent)=>break driver_failure.unwrap_or(outcome),
                    result=&mut connection,if !driver_done=>{
                        driver_done = true;
                        if result.is_err() { driver_failure = Some(FlowOutcome::Failed(FlowFailure::Failed)); }
                    },
                    result=&mut application_done,if application_outcome.is_none()=>{
                        let outcome=result.unwrap_or(FlowOutcome::ClosedByCaller);
                        if outcome!=FlowOutcome::ProtocolEnd {break driver_failure.unwrap_or(outcome);}
                        application_outcome=Some(outcome);
                    },
                }
            };
            completion.finish(outcome);
        })?;
        *request.uri_mut() = uri;
        strip(request.headers_mut());
        let host = match http::HeaderValue::from_str(authority.as_str()) {
            Ok(host) => host,
            Err(_) => {
                application.finish(FlowOutcome::Failed(FlowFailure::Failed));
                return Err(config::invalid());
            }
        };
        request.headers_mut().insert("host", host);
        let response = budget
            .run(async {
                sender
                    .send_request(request)
                    .await
                    .map_err(|_| config::invalid())
            })
            .await;
        drop(sender);
        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                application.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
                return Err(error);
            }
        };
        strip(response.headers_mut());
        Ok(response.map(|body| {
            ResponseBody {
                body,
                end: Mutex::new(application),
                flushed,
            }
            .boxed()
        }))
    }
}

impl InboundProtocol for HttpNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, auth)) in self.auth.rows().enumerate() {
            manifest.authentication("http", index, auth.fingerprint());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.auth.is_empty()
    }
    fn handle<'a>(
        &'a self,
        mut stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(tls) = &self.tls {
                stream = Box::new(
                    connect(&context)
                        .run(async { Ok(tls.accept(stream).await?) })
                        .await?,
                );
            }
            let tasks = Tasks(Arc::new(Mutex::new(JoinSet::new())));
            let tracked = tasks.0.clone();
            let (parent, ended) = watch::channel(None);
            let flushed = FlushReceipts::new(context.max_streams);
            let response_flush = flushed.clone();
            let auth = self.auth.clone();
            let request_context = context.clone();
            let service = service_fn(move |request| {
                let auth = auth.clone();
                let ingress = ingress.clone();
                let context = request_context.clone();
                let tasks = tracked.clone();
                let ended = ended.clone();
                let flushed = response_flush.clone();
                async move {
                    let response =
                        match Self::request(auth, request, ingress, context, tasks, ended, flushed)
                            .await
                        {
                            Ok(response) => response,
                            Err(Error::InvalidAddress | Error::Protocol(_)) => {
                                simple(StatusCode::BAD_REQUEST)
                            }
                            Err(Error::Timeout) => simple(StatusCode::GATEWAY_TIMEOUT),
                            Err(_) => simple(StatusCode::BAD_GATEWAY),
                        };
                    Ok::<_, Infallible>(response)
                }
            });
            let (activity, mut observed) = watch::channel(Instant::now());
            let stream = ActiveIo {
                inner: stream,
                activity,
                flushed: flushed.clone(),
            };
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(context.connect_timeout)
                .pipeline_flush(false)
                .max_buf_size(16_384);
            let connection = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::pin!(connection);
            let timer = tokio::time::sleep(context.idle_timeout);
            tokio::pin!(timer);
            let mut result = loop {
                tokio::select! {
                    biased;
                    _=context.cancel.cancelled()=>break Err(Error::Cancelled),
                    result=&mut connection=>break result.map_err(|_|config::invalid()),
                    changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout);}},
                    _=&mut timer=>break Err(Error::Timeout),
                }
            };
            if let Err(error) = &result {
                let outcome = FlowOutcome::Failed(FlowFailure::from_error(error));
                flushed.failed(outcome);
                parent.send_replace(Some(outcome));
            }
            let mut pending = {
                let mut lock = tasks.0.lock().map_err(|_| config::invalid())?;
                std::mem::take(&mut *lock)
            };
            if result.is_ok() {
                while !pending.is_empty() {
                    tokio::select! {
                        biased;
                        _=context.cancel.cancelled()=>{result=Err(Error::Cancelled);parent.send_replace(Some(FlowOutcome::Failed(FlowFailure::Cancelled)));break;},
                        joined=pending.join_next()=>{if joined.is_some_and(|joined|joined.is_err()){result=Err(config::invalid());parent.send_replace(Some(FlowOutcome::Failed(FlowFailure::Failed)));break;}},
                    }
                }
            }
            let deadline = Instant::now() + context.drain_timeout;
            while !pending.is_empty() {
                match tokio::time::timeout_at(deadline, pending.join_next()).await {
                    Ok(Some(Err(_))) => return Err(config::invalid()),
                    Ok(_) => {}
                    Err(_) => {
                        pending.abort_all();
                        return result.and(Err(Error::Timeout));
                    }
                }
            }
            result
        })
    }
}

struct ActiveIo {
    inner: BoxStream,
    activity: watch::Sender<Instant>,
    flushed: FlushReceipts,
}
impl Drop for ActiveIo {
    fn drop(&mut self) {
        self.flushed.failed(FlowOutcome::ClosedByCaller);
    }
}
impl AsyncRead for ActiveIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let previous = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > previous {
            this.activity.send_replace(Instant::now());
        }
        result
    }
}
impl AsyncWrite for ActiveIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if matches!(result,Poll::Ready(Ok(count)) if count>0) {
            this.activity.send_replace(Instant::now());
        }
        if matches!(result, Poll::Ready(Err(_)) | Poll::Ready(Ok(0))) && !bytes.is_empty() {
            this.flushed
                .failed(FlowOutcome::Failed(FlowFailure::Failed));
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        match &result {
            Poll::Ready(Ok(())) => this.flushed.succeeded(),
            Poll::Ready(Err(_)) => this
                .flushed
                .failed(FlowOutcome::Failed(FlowFailure::Failed)),
            Poll::Pending => {}
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct HttpNodeFactory;
impl NodeFactory for HttpNodeFactory {
    fn kind(&self) -> &'static str {
        "http"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("HTTP 节点字段不合法".into()))?;
        let rows = input
            .native_credentials()
            .iter()
            .map(|value| {
                let auth: Auth = serde_json::from_value(value.clone())
                    .map_err(|_| Error::Config("HTTP 用户凭据字段不合法".into()))?;
                auth.validate()?;
                Ok(auth)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(HttpNode {
            auth: input.credentials(rows)?,
            tls: options.tls.map(config::server_tls).transpose()?,
        }))
    }
}
