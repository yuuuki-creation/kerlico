//! HTTP 载体只提供受限字节通道，认证与目标连接仍由 VLESS 和统一访问服务完成。
use super::{inbound::Payload, server_io::Plain};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::Frame;
use hyper_util::rt::TokioIo;
use kerlico_core::{BoxStream, Error, InboundContext, IngressBinding, Result};
use rust_xhttp::session::{OpenDownload, PushResult, SessionConfig, SessionConn, SessionTable};
use serde::Deserialize;
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
type Body = UnsyncBoxBody<Bytes, io::Error>;

#[cfg(test)]
mod task_tests;

#[derive(Clone)]
struct NodeExecutor(kerlico_core::NodeTasks);
impl<F> hyper::rt::Executor<F> for NodeExecutor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        let _ = self.0.spawn(future);
    }
}

#[derive(Deserialize, Default)]
#[serde(untagged)]
pub(crate) enum Input {
    #[default]
    Default,
    Name(String),
    Options(Box<Transport>),
}
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Transport {
    #[serde(alias = "raw")]
    Tcp,
    Ws {
        #[serde(default = "path")]
        path: String,
        #[serde(default)]
        early_data_bytes: usize,
    },
    Httpupgrade {
        #[serde(default = "path")]
        path: String,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
    },
    Xhttp {
        settings: XhttpSettings,
    },
    Xdrive {
        settings: crate::xdrive::Settings,
    },
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct XhttpSettings {
    #[serde(default = "path")]
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default = "auto")]
    pub mode: String,
    #[serde(default = "auto")]
    pub http_version: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub no_grpc_header: bool,
    #[serde(default, alias = "sc_max_each_post_bytes")]
    pub max_post_bytes: Option<u32>,
    #[serde(default, alias = "sc_min_posts_interval_ms")]
    pub min_post_interval_ms: Option<u32>,
    #[serde(default, alias = "sc_max_buffered_posts")]
    pub max_buffered_posts: Option<u32>,
    #[serde(default)]
    pub sc_stream_up_server_secs: Option<[u32; 2]>,
    #[serde(default, alias = "x_padding_bytes")]
    pub padding_bytes: Option<[u32; 2]>,
    #[serde(default)]
    pub x_padding_obfs_mode: bool,
    #[serde(default)]
    pub x_padding_key: Option<String>,
    #[serde(default)]
    pub x_padding_header: Option<String>,
    #[serde(default)]
    pub x_padding_placement: Option<String>,
    #[serde(default)]
    pub x_padding_method: Option<String>,
    #[serde(default)]
    pub uplink_http_method: Option<String>,
    #[serde(default)]
    pub session_placement: Option<String>,
    #[serde(default)]
    pub session_key: Option<String>,
    #[serde(default)]
    pub seq_placement: Option<String>,
    #[serde(default)]
    pub seq_key: Option<String>,
    #[serde(default)]
    pub uplink_data_placement: Option<String>,
    #[serde(default)]
    pub uplink_data_key: Option<String>,
    #[serde(default)]
    pub uplink_chunk_size: Option<u32>,
    #[serde(default, alias = "reuse_settings")]
    pub xmux: Option<serde_json::Value>,
}
fn path() -> String {
    "/".into()
}
fn auto() -> String {
    "auto".into()
}
impl Input {
    pub fn normalize(self) -> Result<Transport> {
        match self {
            Self::Default => Ok(Transport::Tcp),
            Self::Name(name) if matches!(name.as_str(), "tcp" | "raw") => Ok(Transport::Tcp),
            Self::Options(value) => {
                value.validate()?;
                Ok(*value)
            }
            _ => Err(Error::Config("节点非 TCP 载体须提供选项对象".into())),
        }
    }
}
impl Transport {
    fn validate(&self) -> Result<()> {
        let value = match self {
            Self::Tcp | Self::Xdrive { .. } => return Ok(()),
            Self::Ws { path, .. } | Self::Httpupgrade { path } => path,
            Self::Grpc { service_name } => {
                if service_name.len() > 1024 || service_name.chars().any(char::is_control) {
                    return Err(Error::Config("gRPC service_name 不合法".into()));
                }
                return Ok(());
            }
            Self::Xhttp { settings } => {
                if !matches!(
                    settings.mode.as_str(),
                    "auto" | "packet-up" | "stream-up" | "stream-one"
                ) || !matches!(settings.http_version.as_str(), "auto" | "h1" | "h2" | "h3")
                {
                    return Err(Error::Config("XHTTP 节点模式或版本不合法".into()));
                }
                &settings.path
            }
        };
        if !value.starts_with('/') || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(Error::Config("HTTP 节点路径不合法".into()));
        }
        Ok(())
    }
    pub fn raw(&self) -> bool {
        matches!(self, Self::Tcp)
    }
    pub fn tcp(&self) -> bool {
        !matches!(self, Self::Xdrive { .. })
            && !matches!(self,Self::Xhttp{settings} if settings.http_version=="h3")
    }
    pub fn udp(&self) -> bool {
        matches!(self,Self::Xhttp{settings} if matches!(settings.http_version.as_str(),"auto"|"h3"))
    }
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        match self {
            Self::Tcp | Self::Xdrive { .. } => vec![],
            Self::Grpc { .. } => vec![b"h2".to_vec()],
            Self::Ws { .. } | Self::Httpupgrade { .. } => vec![b"http/1.1".to_vec()],
            Self::Xhttp { settings } => match settings.http_version.as_str() {
                "h1" => vec![b"http/1.1".to_vec()],
                "h3" => vec![b"h3".to_vec()],
                _ => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            },
        }
    }
}

#[derive(Clone)]
struct Physical(Arc<PhysicalState>);
struct PhysicalState {
    count: watch::Sender<usize>,
    failed: AtomicBool,
}
struct PhysicalLease(Physical);
impl Physical {
    fn new() -> Self {
        let (count, _) = watch::channel(0);
        Self(Arc::new(PhysicalState {
            count,
            failed: AtomicBool::new(false),
        }))
    }
    fn lease(&self) -> PhysicalLease {
        self.0.count.send_modify(|count| *count += 1);
        PhysicalLease(self.clone())
    }
    fn fail(&self) {
        self.0.failed.store(true, Ordering::Release);
    }
    async fn drained(&self) -> Result<()> {
        let mut count = self.0.count.subscribe();
        loop {
            let active = *count.borrow_and_update();
            if active == 0 {
                break;
            }
            if count.changed().await.is_err() {
                break;
            }
        }
        if self.0.failed.load(Ordering::Acquire) {
            Err(Error::Protocol("HTTP 升级会话失败"))
        } else {
            Ok(())
        }
    }
}
impl Drop for PhysicalLease {
    fn drop(&mut self) {
        self.0
            .0
            .count
            .send_modify(|count| *count = count.saturating_sub(1));
    }
}
struct ObservedIo {
    inner: BoxStream,
    activity: watch::Sender<tokio::time::Instant>,
}
impl AsyncRead for ObservedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, out);
        if matches!(result, Poll::Ready(Ok(()))) && out.filled().len() > before {
            this.activity.send_replace(tokio::time::Instant::now());
        }
        result
    }
}
impl AsyncWrite for ObservedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if matches!(result,Poll::Ready(Ok(count)) if count>0) {
            this.activity.send_replace(tokio::time::Instant::now());
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(crate) struct State {
    transport: Transport,
    table: OnceLock<Arc<SessionTable>>,
    ids: Mutex<HashMap<String, Option<tokio::time::Instant>>>,
    tasks: Mutex<JoinSet<()>>,
    input_budget: Arc<Semaphore>,
}
impl State {
    pub fn new(transport: Transport) -> Arc<Self> {
        Arc::new(Self {
            transport,
            table: OnceLock::new(),
            ids: Mutex::new(HashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
            input_budget: Arc::new(Semaphore::new(16 * 1024 * 1024)),
        })
    }
    fn spawn(
        &self,
        owner: &kerlico_core::NodeTasks,
        task: impl Future<Output = ()> + Send + 'static,
    ) {
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            if let Ok(task) = owner.spawn_tracked(task) {
                tasks.spawn(async move {
                    let _ = task.await;
                });
            }
        }
    }
    fn remove(&self, id: &str) {
        if let Some(table) = self.table.get() {
            table.remove(id);
        }
        if let Ok(mut ids) = self.ids.lock() {
            ids.remove(id);
        }
    }
    fn table(
        self: &Arc<Self>,
        payload: Arc<Payload>,
        access: IngressBinding,
        mut context: InboundContext,
    ) -> Arc<SessionTable> {
        context.peer_lease = None;
        context.peer_addr = None;
        context.local_addr = None;
        context.cancel = context.tasks.cancel().child_token();
        self.table.get_or_init(||{let limits=context.clone();let weak=Arc::downgrade(self);let handler:rust_xhttp::session::Handler=Arc::new(move |connection|{
            let Some(state)=weak.upgrade() else{return};let Ok(lease)=context.stream_budget.try_acquire() else{return};let payload=payload.clone();let access=access.clone();let mut context=context.clone();context.cancel=context.cancel.child_token();
            state.spawn(&context.tasks.clone(),async move {let _lease=lease;let stream=SessionIo::new(connection);let _=tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=payload.serve(Box::new(Plain(Box::new(stream))),access,context.clone())=>result};});
        });SessionTable::new(SessionConfig {max_sessions:limits.max_streams,max_pending_packets:32,max_pending_bytes:1024*1024,downlink_capacity:16,grace:limits.connect_timeout,..Default::default()},handler,Arc::new(rust_xhttp::metrics::Metrics::default()))}).clone()
    }
    pub async fn serve(
        self: Arc<Self>,
        stream: BoxStream,
        payload: Arc<Payload>,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let idle = context.idle_timeout;
        let cancel = context.cancel.clone();
        let executor = NodeExecutor(context.tasks.clone());
        let physical = Physical::new();
        let request_physical = physical.clone();
        let (activity, mut changes) = watch::channel(tokio::time::Instant::now());
        let stream = ObservedIo {
            inner: stream,
            activity,
        };
        let service =
            hyper::service::service_fn(move |mut request: Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(request_physical.clone());
                let state = self.clone();
                let payload = payload.clone();
                let access = access.clone();
                let context = context.clone();
                async move {
                    Ok::<_, Infallible>(state.request(request, payload, access, context).await)
                }
            });
        let builder = hyper_util::server::conn::auto::Builder::new(executor);
        let serving = async {
            builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
                .map_err(|_| Error::Protocol("HTTP 节点连接失败"))?;
            physical.drained().await
        };
        tokio::pin!(serving);
        let timer = tokio::time::sleep(idle);
        tokio::pin!(timer);
        loop {
            tokio::select! {_=cancel.cancelled()=>return Err(Error::Cancelled),r=&mut serving=>return r,_=&mut timer=>return Err(Error::Timeout),r=changes.changed()=>{if r.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+idle);}}}
        }
    }

    pub(crate) async fn request<B>(
        self: Arc<Self>,
        mut request: Request<B>,
        payload: Arc<Payload>,
        access: IngressBinding,
        context: InboundContext,
    ) -> Response<Body>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: Send,
    {
        let header_bytes: usize = request
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
            .sum();
        if header_bytes > 65536 {
            return empty(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        if context.stream_budget.is_closed() {
            return empty(StatusCode::SERVICE_UNAVAILABLE);
        }
        match &self.transport {
            Transport::Ws {
                path,
                early_data_bytes,
            } if request.uri().path() == path => {
                if request.method() != http::Method::GET
                    || !upgrade_header(&request)
                    || request
                        .headers()
                        .get("sec-websocket-version")
                        .and_then(|v| v.to_str().ok())
                        != Some("13")
                {
                    return empty(StatusCode::BAD_REQUEST);
                }
                let Some(key) = request
                    .headers()
                    .get("sec-websocket-key")
                    .and_then(|v| v.to_str().ok())
                else {
                    return empty(StatusCode::BAD_REQUEST);
                };
                use base64::Engine;
                if base64::engine::general_purpose::STANDARD
                    .decode(key)
                    .map_or(true, |bytes| bytes.len() != 16)
                {
                    return empty(StatusCode::BAD_REQUEST);
                }
                let accept = xray_transport::stream::accept_key_for(key);
                let early = match request
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|v| v.to_str().ok())
                {
                    Some(value) => {
                        use base64::Engine;
                        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value) {
                            Ok(bytes) if bytes.len() <= *early_data_bytes => bytes,
                            _ => return empty(StatusCode::BAD_REQUEST),
                        }
                    }
                    None => Vec::new(),
                };
                let Ok(lease) = context.stream_budget.try_acquire() else {
                    return empty(StatusCode::TOO_MANY_REQUESTS);
                };
                let physical = request.extensions().get::<Physical>().cloned();
                let tracked = physical.as_ref().map(Physical::lease);
                let upgrade = hyper::upgrade::on(&mut request);
                self.spawn(&context.tasks.clone(), async move {let _lease=lease;let _tracked=tracked;if let Ok(io)=upgrade.await {
                    let mut config=tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();config.max_message_size=Some(1024*1024);config.max_frame_size=Some(1024*1024);config.write_buffer_size=8192;config.max_write_buffer_size=65536;
                    let websocket=tokio_tungstenite::WebSocketStream::from_raw_socket(TokioIo::new(io),tokio_tungstenite::tungstenite::protocol::Role::Server,Some(config)).await;
                    let (local,peer)=tokio::io::duplex(64*1024);let running=payload.serve(Box::new(Plain(Box::new(local))),access,context.clone());let bridge=websocket_bridge(websocket,peer,early,context.clone());let result=tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=async{tokio::try_join!(running,bridge).map(|_|())}=>result};if result.is_err()&&let Some(physical)=&physical{physical.fail();}
                }else if let Some(physical)=&physical{physical.fail();}});
                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .header("sec-websocket-accept", accept)
                    .body(empty_body())
                    .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
            }
            Transport::Httpupgrade { path } if request.uri().path() == path => {
                if !upgrade_header(&request) {
                    return empty(StatusCode::BAD_REQUEST);
                }
                let Ok(lease) = context.stream_budget.try_acquire() else {
                    return empty(StatusCode::TOO_MANY_REQUESTS);
                };
                let physical = request.extensions().get::<Physical>().cloned();
                let tracked = physical.as_ref().map(Physical::lease);
                let upgrade = hyper::upgrade::on(&mut request);
                self.spawn(&context.tasks.clone(), async move {
                    let _lease = lease;
                    let _tracked = tracked;
                    let result = match upgrade.await {
                        Ok(io) => {
                            payload
                                .serve(Box::new(Plain(Box::new(TokioIo::new(io)))), access, context)
                                .await
                        }
                        Err(_) => Err(Error::Protocol("HTTPUpgrade 升级失败")),
                    };
                    if result.is_err()
                        && let Some(physical) = physical
                    {
                        physical.fail();
                    }
                });
                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header("upgrade", "websocket")
                    .header("connection", "upgrade")
                    .body(empty_body())
                    .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
            }
            Transport::Grpc { service_name } => {
                let single = format!("/{service_name}/Tun");
                let multi = format!("/{service_name}/TunMulti");
                if request.method() != http::Method::POST
                    || !matches!(request.uri().path(),value if value==single||value==multi)
                {
                    return empty(StatusCode::NOT_FOUND);
                }
                let multi = request.uri().path() == multi;
                self.direct(request.into_body(), payload, access, context, Some(multi))
            }
            Transport::Xhttp { settings } => {
                let base = settings.path.trim_end_matches('/');
                let Some(rest) = request.uri().path().strip_prefix(base) else {
                    return empty(StatusCode::NOT_FOUND);
                };
                if !rest.is_empty() && !rest.starts_with('/') {
                    return empty(StatusCode::NOT_FOUND);
                }
                let mut parts: Vec<String> = rest
                    .trim_matches('/')
                    .split('/')
                    .filter(|p| !p.is_empty())
                    .map(str::to_owned)
                    .collect();
                if parts.is_empty()
                    && let Some(meta_id) = extract_metadata(
                        &request,
                        settings.session_placement.as_deref(),
                        settings.session_key.as_deref(),
                        "X-Session",
                        "x_session",
                    )
                {
                    parts.push(meta_id);
                }
                if parts.len() == 1
                    && let Some(meta_seq) = extract_metadata(
                        &request,
                        settings.seq_placement.as_deref(),
                        settings.seq_key.as_deref(),
                        "X-Seq",
                        "x_seq",
                    )
                {
                    parts.push(meta_seq);
                }
                let uplink_method = settings.uplink_http_method.as_deref().unwrap_or("POST");
                let is_uplink_method = request.method() == http::Method::POST
                    || request
                        .method()
                        .as_str()
                        .eq_ignore_ascii_case(uplink_method);
                if parts.is_empty() && is_uplink_method {
                    if !matches!(settings.mode.as_str(), "auto" | "stream-one") {
                        return empty(StatusCode::METHOD_NOT_ALLOWED);
                    }
                    return self.direct(request.into_body(), payload, access, context, None);
                }
                let Some(id) = parts.first().map(String::as_str) else {
                    return empty(StatusCode::NOT_FOUND);
                };
                if id.len() > 128
                    || id.is_empty()
                    || !id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
                {
                    return empty(StatusCode::BAD_REQUEST);
                }
                if settings.mode == "stream-one" {
                    return empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                let is_download_get = request.method() == http::Method::GET && parts.len() == 1;
                if is_uplink_method
                    && !is_download_get
                    && ((parts.len() == 2 && settings.mode == "stream-up")
                        || (parts.len() == 1 && settings.mode == "packet-up"))
                {
                    return empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                if (!is_download_get && !is_uplink_method) || parts.len() > 2 {
                    return empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                let id = id.to_owned();
                let max = context.max_streams;
                let table = self.table(payload, access, context.clone());
                {
                    let Ok(mut ids) = self.ids.lock() else {
                        return empty(StatusCode::INTERNAL_SERVER_ERROR);
                    };
                    ids.retain(|key, time| {
                        let expired =
                            time.is_some_and(|time| time.elapsed() > context.connect_timeout);
                        if expired {
                            table.remove(key);
                        }
                        !expired
                    });
                    if !ids.contains_key(&id) && ids.len() >= max {
                        return empty(StatusCode::TOO_MANY_REQUESTS);
                    }
                    let time = ids
                        .entry(id.clone())
                        .or_insert_with(|| Some(tokio::time::Instant::now()));
                    if is_download_get {
                        *time = None;
                    }
                }

                if is_download_get {
                    let mut reader = match table.open_download(&id) {
                        OpenDownload::Opened(reader) => reader,
                        _ => return empty(StatusCode::CONFLICT),
                    };
                    let (sender, body) = body_channel();
                    let weak = Arc::downgrade(&self);
                    self.spawn(&context.tasks.clone(), async move {
                        let _cleanup = SessionGuard { state: weak, id };
                        while let Some(bytes) = reader.recv().await {
                            if sender.send(Ok(Frame::data(bytes))).await.is_err() {
                                break;
                            }
                        }
                    });
                    return response(body, false);
                }
                if !is_uplink_method {
                    return empty(StatusCode::METHOD_NOT_ALLOWED);
                }
                if parts.len() == 2 {
                    let Ok(sequence) = parts[1].parse::<u64>() else {
                        return empty(StatusCode::BAD_REQUEST);
                    };
                    let meta_payload = extract_uplink_data_from_headers(
                        &request,
                        settings.uplink_data_placement.as_deref(),
                        settings.uplink_data_key.as_deref(),
                    );
                    let mut bytes =
                        match collect(request.into_body(), self.input_budget.clone()).await {
                            Ok(bytes) => bytes,
                            Err(_) => return empty(StatusCode::PAYLOAD_TOO_LARGE),
                        };
                    if bytes.is_empty()
                        && let Some(decoded) = meta_payload
                    {
                        bytes = Bytes::from(decoded);
                    }
                    return match table.push_uplink(&id, sequence, bytes).await {
                        Some(PushResult::Accepted | PushResult::Duplicate) => empty(StatusCode::OK),
                        _ => empty(StatusCode::TOO_MANY_REQUESTS),
                    };
                }
                if parts.len() == 1 {
                    let (hold, response_body) = body_channel();
                    let mut body = request.into_body();
                    let table = table.clone();
                    let context = context.clone();
                    self.spawn(&context.tasks.clone(), async move {
                        let _hold = hold;
                        let mut sequence = 0u64;
                        while let Some(frame) = body.frame().await {
                            let Ok(frame) = frame else { break };
                            if let Ok(bytes) = frame.into_data() {
                                if bytes.is_empty() {
                                    continue;
                                }
                                if !matches!(
                                    table.push_uplink(&id, sequence, bytes).await,
                                    Some(PushResult::Accepted)
                                ) {
                                    break;
                                }
                                sequence = match sequence.checked_add(1) {
                                    Some(n) => n,
                                    None => break,
                                };
                            }
                            if context.cancel.is_cancelled() {
                                break;
                            }
                        }
                    });
                    return response(response_body, false);
                }
                empty(StatusCode::NOT_FOUND)
            }
            _ => empty(StatusCode::NOT_FOUND),
        }
    }
    fn direct<B>(
        self: &Arc<Self>,
        body: B,
        payload: Arc<Payload>,
        access: IngressBinding,
        context: InboundContext,
        grpc: Option<bool>,
    ) -> Response<Body>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: Send,
    {
        let Ok(lease) = context.stream_budget.try_acquire() else {
            return empty(StatusCode::TOO_MANY_REQUESTS);
        };
        let (sender, response_body) = body_channel();
        let (local, peer) = tokio::io::duplex(64 * 1024);
        self.spawn(&context.tasks.clone(), async move {let _lease=lease;let running=payload.serve(Box::new(Plain(Box::new(local))),access,context.clone());let bridge=http_bridge(body,peer,sender,grpc);let _=tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),r=async {tokio::try_join!(running,bridge).map(|_|())}=>r};});
        response(response_body, grpc.is_some())
    }
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(table) = self.table.get()
            && let Ok(ids) = self.ids.get_mut()
        {
            for (id, _) in ids.drain() {
                table.remove(&id);
            }
        }
        if let Ok(tasks) = self.tasks.get_mut() {
            tasks.abort_all();
        }
    }
}
struct SessionGuard {
    state: std::sync::Weak<State>,
    id: String,
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state.remove(&self.id);
        }
    }
}
fn upgrade_header<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
        && request
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}
fn empty_body() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}
fn empty(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(empty_body())
        .unwrap_or_else(|_| Response::new(empty_body()))
}
fn body_channel() -> (mpsc::Sender<io::Result<Frame<Bytes>>>, Body) {
    let (sender, receiver) = mpsc::channel(16);
    (
        sender,
        StreamBody::new(ReceiverStream::new(receiver)).boxed_unsync(),
    )
}
fn response(body: Body, grpc: bool) -> Response<Body> {
    Response::builder()
        .status(200)
        .header(
            "content-type",
            if grpc {
                "application/grpc"
            } else {
                "text/event-stream"
            },
        )
        .header("cache-control", "no-cache")
        .header("x-padding", padding())
        .body(body)
        .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
}
fn padding() -> String {
    use rand::Rng;
    let length = rand::thread_rng().gen_range(100..=1000);
    std::iter::repeat_n('X', length).collect()
}

fn extract_metadata<B>(
    request: &Request<B>,
    placement: Option<&str>,
    key: Option<&str>,
    default_header: &str,
    default_param: &str,
) -> Option<String> {
    match placement {
        Some("header") => {
            let k = key.filter(|s| !s.is_empty()).unwrap_or(default_header);
            request
                .headers()
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_owned())
        }
        Some("cookie") => {
            let k = key.filter(|s| !s.is_empty()).unwrap_or(default_param);
            request
                .headers()
                .get_all(http::header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(';'))
                .find_map(|pair| {
                    let (ck, cv) = pair.trim().split_once('=')?;
                    (ck.trim() == k).then(|| cv.trim().to_owned())
                })
        }
        Some("query") => {
            let k = key.filter(|s| !s.is_empty()).unwrap_or(default_param);
            let q = request.uri().query()?;
            q.split('&').find_map(|pair| {
                let (qk, qv) = pair.split_once('=')?;
                (qk == k).then(|| qv.to_owned())
            })
        }
        _ => None,
    }
}

fn extract_uplink_data_from_headers<B>(
    request: &Request<B>,
    placement: Option<&str>,
    key: Option<&str>,
) -> Option<Vec<u8>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let k = key.filter(|s| !s.is_empty()).unwrap_or("X-Data");
    match placement {
        Some("header") => {
            let mut combined = String::new();
            for val in request.headers().get_all(k) {
                if let Ok(s) = val.to_str() {
                    combined.push_str(s.trim());
                }
            }
            if combined.is_empty() {
                None
            } else {
                URL_SAFE_NO_PAD
                    .decode(combined.as_bytes())
                    .or_else(|_| base64::engine::general_purpose::STANDARD.decode(combined))
                    .ok()
            }
        }
        Some("cookie") => {
            let mut combined = String::new();
            for val in request.headers().get_all(http::header::COOKIE) {
                if let Ok(s) = val.to_str() {
                    for pair in s.split(';') {
                        if let Some((ck, cv)) = pair.trim().split_once('=')
                            && (ck.trim() == k || ck.trim().starts_with(k))
                        {
                            combined.push_str(cv.trim());
                        }
                    }
                }
            }
            if combined.is_empty() {
                None
            } else {
                URL_SAFE_NO_PAD
                    .decode(combined.as_bytes())
                    .or_else(|_| base64::engine::general_purpose::STANDARD.decode(combined))
                    .ok()
            }
        }
        _ => None,
    }
}
async fn collect<B>(mut body: B, budget: Arc<Semaphore>) -> Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Send,
{
    let mut bytes = Vec::new();
    let mut permits = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Error::Protocol("HTTP 上传帧不合法"))?;
        if let Ok(data) = frame.into_data() {
            if bytes.len() + data.len() > 1024 * 1024 {
                return Err(Error::ResourceLimit);
            }
            if !data.is_empty() {
                permits.push(
                    budget
                        .clone()
                        .acquire_many_owned(data.len() as u32)
                        .await
                        .map_err(|_| Error::Cancelled)?,
                );
                bytes.extend_from_slice(&data);
            }
        }
    }
    Ok(Bytes::from(bytes))
}

struct SessionIo {
    reader: rust_xhttp::session::UplinkReader,
    writer: Option<rust_xhttp::session::DownlinkSink>,
    pending: Option<kerlico_core::BoxFuture<'static, io::Result<usize>>>,
    closed: bool,
}
impl SessionIo {
    fn new(connection: SessionConn) -> Self {
        Self {
            reader: connection.reader,
            writer: Some(connection.writer),
            pending: None,
            closed: false,
        }
    }
    fn send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if let Some(future) = &mut self.pending {
            let result = future.as_mut().poll(cx);
            if result.is_ready() {
                self.pending = None;
            }
            result
        } else {
            Poll::Ready(Ok(0))
        }
    }
}
impl AsyncRead for SessionIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, out)
    }
}
impl AsyncWrite for SessionIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP 写端已关闭",
            )));
        }
        if this.pending.is_some() {
            return this.send(cx);
        }
        let bytes = Bytes::copy_from_slice(&bytes[..bytes.len().min(8192)]);
        let count = bytes.len();
        let Some(writer) = this.writer.clone() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP 下载已关闭",
            )));
        };
        this.pending = Some(Box::pin(async move {
            writer
                .send(bytes)
                .await
                .map(|_| count)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "XHTTP 下载已结束"))
        }));
        this.send(cx)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().send(cx).map_ok(|_| ())
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.as_mut().poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.closed = true;
            self.writer.take();
        }
        result
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct Hunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}
async fn http_bridge<B>(
    mut incoming: B,
    peer: tokio::io::DuplexStream,
    sender: mpsc::Sender<io::Result<Frame<Bytes>>>,
    grpc: Option<bool>,
) -> Result<()>
where
    B: hyper::body::Body<Data = Bytes> + Unpin + Send,
    B::Error: Send,
{
    let (mut reader, mut writer) = tokio::io::split(peer);
    let upload = async {
        let mut pending = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| Error::Protocol("HTTP 请求体读取失败"))?;
            if let Ok(data) = frame.into_data() {
                if grpc.is_none() {
                    writer.write_all(&data).await?;
                } else {
                    pending.extend_from_slice(&data);
                    if pending.len() > 2 * 1024 * 1024 {
                        return Err(Error::ResourceLimit);
                    }
                    while pending.len() >= 5 {
                        if pending[0] != 0 {
                            return Err(Error::Protocol("不支持压缩 gRPC 帧"));
                        }
                        let length = u32::from_be_bytes(
                            pending[1..5]
                                .try_into()
                                .map_err(|_| Error::Protocol("gRPC 长度不合法"))?,
                        ) as usize;
                        if length > 1024 * 1024 {
                            return Err(Error::ResourceLimit);
                        }
                        if pending.len() < 5 + length {
                            break;
                        }
                        use prost::Message;
                        let hunk = Hunk::decode(&pending[5..5 + length])
                            .map_err(|_| Error::Protocol("gRPC Hunk 不合法"))?;
                        for data in hunk.data {
                            writer.write_all(&data).await?;
                        }
                        pending.drain(..5 + length);
                    }
                }
            }
        }
        if !pending.is_empty() {
            return Err(Error::Protocol("gRPC 帧被截断"));
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let download = async move {
        let mut bytes = vec![0; 8192];
        loop {
            let n = reader.read(&mut bytes).await?;
            if n == 0 {
                break;
            }
            let data = if grpc.is_some() {
                use prost::Message;
                let data = Hunk {
                    data: vec![bytes[..n].to_vec()],
                }
                .encode_to_vec();
                let mut frame = vec![0];
                frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
                frame.extend_from_slice(&data);
                Bytes::from(frame)
            } else {
                Bytes::copy_from_slice(&bytes[..n])
            };
            sender
                .send(Ok(Frame::data(data)))
                .await
                .map_err(|_| Error::Cancelled)?;
        }
        if grpc.is_some() {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
            let _ = sender.send(Ok(Frame::trailers(trailers))).await;
        }
        Ok::<_, Error>(())
    };
    tokio::try_join!(upload, download).map(|_| ())
}
async fn websocket_bridge<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    peer: tokio::io::DuplexStream,
    early: Vec<u8>,
    context: InboundContext,
) -> Result<()> {
    let (mut sink, mut stream) = websocket.split();
    let (mut reader, mut writer) = tokio::io::split(peer);
    let upload = async {
        writer.write_all(&early).await?;
        while let Some(message) = stream.next().await {
            match message.map_err(|_| Error::Protocol("WebSocket 帧不合法"))? {
                tokio_tungstenite::tungstenite::Message::Binary(data) => {
                    writer.write_all(&data).await?
                }
                tokio_tungstenite::tungstenite::Message::Text(data) => {
                    writer.write_all(data.as_bytes()).await?
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => {}
            }
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let download = async move {
        let mut bytes = vec![0; 8192];
        loop {
            let n = reader.read(&mut bytes).await?;
            if n == 0 {
                break;
            }
            sink.send(tokio_tungstenite::tungstenite::Message::Binary(
                Bytes::copy_from_slice(&bytes[..n]),
            ))
            .await
            .map_err(|_| Error::Protocol("WebSocket 写入失败"))?;
        }
        let _ = sink.close().await;
        Ok::<_, Error>(())
    };
    tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=async{tokio::try_join!(upload,download).map(|_|())}=>result}
}
