use crate::config::{self, Auth, ServerTls};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Destination, Error, InboundContext,
    InboundProtocol, Result,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    task::JoinSet,
    time::Instant,
};

type BodyError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BodyError>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    auth: Option<Auth>,
    tls: Option<ServerTls>,
}
struct HttpNode {
    auth: Option<Auth>,
    tls: Option<tokio_rustls::TlsAcceptor>,
}
fn connect(context: &InboundContext) -> ConnectContext {
    ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    }
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
    max: usize,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let mut tasks = tasks.lock().map_err(|_| config::invalid())?;
    while tasks.try_join_next().is_some() {}
    if tasks.len() >= max {
        return Err(Error::ResourceLimit);
    }
    tasks.spawn(future);
    Ok(())
}

impl HttpNode {
    async fn request(
        auth: Option<Auth>,
        mut request: Request<Incoming>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
        tasks: Arc<Mutex<JoinSet<()>>>,
    ) -> Result<Response<Body>> {
        if let Some(auth) = auth {
            let valid = request
                .headers()
                .get_all("proxy-authorization")
                .iter()
                .count()
                == 1
                && request
                    .headers()
                    .get("proxy-authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| auth.matches(value));
            if !valid {
                let mut response = simple(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                response.headers_mut().insert(
                    "proxy-authenticate",
                    http::HeaderValue::from_static("Basic realm=\"kerlico\", charset=\"UTF-8\""),
                );
                response
                    .headers_mut()
                    .insert("connection", http::HeaderValue::from_static("close"));
                return Ok(response);
            }
        }
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
            spawn(&tasks, context.max_streams, async move {
                let upgraded = tokio::select! {biased;_=context.cancel.cancelled()=>return,result=tokio::time::timeout(context.connect_timeout,upgrade)=>match result{Ok(Ok(upgraded))=>upgraded,_=>return}};
                let _ = kerlico_core::relay_tcp(
                    Box::new(TokioIo::new(upgraded)),
                    remote,
                    context.idle_timeout,
                    context.cancel,
                )
                .await;
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
        let (mut sender, connection) = budget
            .run(async {
                hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(remote))
                    .await
                    .map_err(|_| config::invalid())
            })
            .await?;
        let token = context.cancel.clone();
        spawn(&tasks, context.max_streams, async move {
            tokio::select! {_=token.cancelled()=>{},_=connection=>{}}
        })?;
        *request.uri_mut() = uri;
        strip(request.headers_mut());
        request.headers_mut().insert(
            "host",
            http::HeaderValue::from_str(authority.as_str()).map_err(|_| config::invalid())?,
        );
        let mut response = budget
            .run(async {
                sender
                    .send_request(request)
                    .await
                    .map_err(|_| config::invalid())
            })
            .await?;
        strip(response.headers_mut());
        Ok(response.map(|body| body.map_err(|error| Box::new(error) as BodyError).boxed()))
    }
}

impl InboundProtocol for HttpNode {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.auth
            .as_ref()
            .map(|auth| vec![auth.fingerprint()])
            .unwrap_or_default()
    }
    fn requires_loopback(&self) -> bool {
        self.auth.is_none()
    }
    fn handle<'a>(
        &'a self,
        mut stream: BoxStream,
        access: Arc<dyn AccessService>,
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
            let auth = self.auth.clone();
            let request_context = context.clone();
            let service = service_fn(move |request| {
                let auth = auth.clone();
                let access = access.clone();
                let context = request_context.clone();
                let tasks = tracked.clone();
                async move {
                    let response = match Self::request(auth, request, access, context, tasks).await
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
            };
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(context.connect_timeout)
                .max_buf_size(16_384);
            let connection = builder
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            tokio::pin!(connection);
            let timer = tokio::time::sleep(context.idle_timeout);
            tokio::pin!(timer);
            loop {
                tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=&mut connection=>{result.map_err(|_|config::invalid())?;break;},changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout);}},_=&mut timer=>return Err(Error::Timeout)}
            }
            let mut pending = {
                let mut lock = tasks.0.lock().map_err(|_| config::invalid())?;
                std::mem::take(&mut *lock)
            };
            while !pending.is_empty() {
                tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=pending.join_next()=>{if result.is_some_and(|result|result.is_err()){return Err(config::invalid());}}}
            }
            Ok(())
        })
    }
}

struct ActiveIo {
    inner: BoxStream,
    activity: watch::Sender<Instant>,
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
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
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
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("HTTP 节点字段不合法".into()))?;
        if let Some(auth) = &options.auth {
            auth.validate()?;
        }
        Ok(Arc::new(HttpNode {
            auth: options.auth,
            tls: options.tls.map(config::server_tls).transpose()?,
        }))
    }
}
