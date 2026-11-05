//! HTTP 载体的会话任务归属当前物理连接，并受取消和资源预算约束。
use crate::{carrier::Transport, inbound::Payload};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::Frame;
use hyper_util::rt::TokioIo;
use kerlico_core::{BoxStream, Error, InboundContext, IngressBinding, Result};
use std::{
    convert::Infallible,
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
type Body = UnsyncBoxBody<Bytes, io::Error>;
type Tasks = Arc<Mutex<JoinSet<Result<()>>>>;
#[derive(Clone)]
struct NodeExecutor(kerlico_core::NodeTasks);
impl<F> hyper::rt::Executor<F> for NodeExecutor
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    fn execute(&self, future: F) {
        let _ = self.0.spawn(future);
    }
}
fn empty_body() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}
fn empty(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(empty_body());
    *response.status_mut() = status;
    response
}
fn upgrade(request: &Request<hyper::body::Incoming>) -> bool {
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
                    .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))
            })
}
fn spawn(
    tasks: &Tasks,
    owner: &kerlico_core::NodeTasks,
    future: impl std::future::Future<Output = Result<()>> + Send + 'static,
) -> bool {
    let Ok(mut tasks) = tasks.lock() else {
        return false;
    };
    while tasks.try_join_next().is_some() {}
    let Ok(task) = owner.spawn_tracked(future) else {
        return false;
    };
    tasks.spawn(async move {
        task.await
            .unwrap_or(Err(Error::Protocol("VMess HTTP 任务异常退出")))
    });
    true
}
struct TaskGuard(Tasks);
impl Drop for TaskGuard {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.0.lock() {
            tasks.abort_all();
        }
    }
}
pub(crate) async fn serve(
    inner: BoxStream,
    transport: Transport,
    payload: Arc<Payload>,
    access: IngressBinding,
    context: InboundContext,
) -> Result<()> {
    let tasks = Arc::new(Mutex::new(JoinSet::new()));
    let _guard = TaskGuard(tasks.clone());
    let all = tasks.clone();
    let cancel = context.cancel.clone();
    let executor = NodeExecutor(context.tasks.clone());
    let idle = context.idle_timeout;
    let now = tokio::time::Instant::now();
    let (activity, mut changed) = tokio::sync::watch::channel(now);
    let inner = ActiveIo {
        inner,
        activity,
        last: now,
    };
    let service = hyper::service::service_fn(move |request| {
        let transport = transport.clone();
        let payload = payload.clone();
        let access = access.clone();
        let context = context.clone();
        let tasks = tasks.clone();
        async move {
            Ok::<_, Infallible>(handle(request, transport, payload, access, context, tasks).await)
        }
    });
    let serving = async {
        let mut builder = hyper_util::server::conn::auto::Builder::new(executor);
        builder
            .http2()
            .initial_stream_window_size(16 * 1024 * 1024)
            .initial_connection_window_size(64 * 1024 * 1024)
            .adaptive_window(true);
        builder
            .serve_connection_with_upgrades(TokioIo::new(inner), service)
            .await
            .map_err(|_| Error::Protocol("VMess HTTP 载体失败"))?;
        let mut tasks = std::mem::take(&mut *all.lock().map_err(|_| Error::Cancelled)?);
        while let Some(result) = tasks.join_next().await {
            result.map_err(|_| Error::Protocol("VMess HTTP 会话任务失败"))??;
        }
        Ok(())
    };
    tokio::pin!(serving);
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    loop {
        tokio::select! {_=cancel.cancelled()=>return Err(Error::Cancelled),result=&mut serving=>return result,_=&mut timer=>return Err(Error::Timeout),r=changed.changed()=>{if r.is_ok(){timer.as_mut().reset(*changed.borrow_and_update()+idle);}}}
    }
}
async fn handle(
    mut request: Request<hyper::body::Incoming>,
    transport: Transport,
    payload: Arc<Payload>,
    access: IngressBinding,
    context: InboundContext,
    tasks: Tasks,
) -> Response<Body> {
    if context.stream_budget.is_closed() {
        return empty(StatusCode::SERVICE_UNAVAILABLE);
    }
    if request
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
        .sum::<usize>()
        > 65536
    {
        return empty(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }
    let Ok(lease) = context.stream_budget.try_acquire() else {
        return empty(StatusCode::TOO_MANY_REQUESTS);
    };
    match transport {
        Transport::Ws { path, .. }
            if request
                .uri()
                .path_and_query()
                .is_some_and(|value| value.as_str() == path) =>
        {
            if request.method() != http::Method::GET
                || !upgrade(&request)
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
                .map_or(true, |v| v.len() != 16)
                || request.headers().contains_key("sec-websocket-protocol")
            {
                return empty(StatusCode::BAD_REQUEST);
            }
            let accept = xray_transport::stream::accept_key_for(key);
            let upgraded = hyper::upgrade::on(&mut request);
            if !spawn(&tasks, &context.tasks.clone(), async move {
                let _lease = lease;
                let socket = upgraded
                    .await
                    .map_err(|_| Error::Protocol("VMess WebSocket 升级失败"))?;
                let mut config =
                    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
                config.max_message_size = Some(1024 * 1024);
                config.max_frame_size = Some(1024 * 1024);
                config.write_buffer_size = 65536;
                config.max_write_buffer_size = 256 * 1024;
                let websocket = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    TokioIo::new(socket),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    Some(config),
                )
                .await;
                let (local, peer) = tokio::io::duplex(256 * 1024);
                let run = payload.serve(Box::new(local), access, context.clone());
                let bridge = ws_bridge(websocket, peer);
                tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=async{tokio::try_join!(run,bridge).map(|_|())}=>result}
            }) {
                return empty(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Response::builder()
                .status(101)
                .header("upgrade", "websocket")
                .header("connection", "Upgrade")
                .header("sec-websocket-accept", accept)
                .body(empty_body())
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
        Transport::Httpupgrade { path, .. }
            if request
                .uri()
                .path_and_query()
                .is_some_and(|value| value.as_str() == path) =>
        {
            if request.method() != http::Method::GET || !upgrade(&request) {
                return empty(StatusCode::BAD_REQUEST);
            }
            let upgraded = hyper::upgrade::on(&mut request);
            if !spawn(&tasks, &context.tasks.clone(), async move {
                let _lease = lease;
                let socket = upgraded
                    .await
                    .map_err(|_| Error::Protocol("VMess HTTPUpgrade 失败"))?;
                payload
                    .serve(Box::new(TokioIo::new(socket)), access, context)
                    .await
            }) {
                return empty(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Response::builder()
                .status(101)
                .header("upgrade", "websocket")
                .header("connection", "upgrade")
                .body(empty_body())
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
        Transport::Grpc { service_name, .. } => {
            if request.version() != http::Version::HTTP_2
                || request.method() != http::Method::POST
                || !matches!(request.uri().path(),value if value==format!("/{service_name}/Tun")||value==format!("/{service_name}/TunMulti"))
                || !request
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/grpc"))
            {
                return empty(StatusCode::NOT_FOUND);
            }
            let (sender, receiver) = mpsc::channel(128);
            let body = StreamBody::new(ReceiverStream::new(receiver)).boxed_unsync();
            let (local, peer) = tokio::io::duplex(256 * 1024);
            if !spawn(&tasks, &context.tasks.clone(), async move {
                let _lease = lease;
                let run = payload.serve(Box::new(local), access, context.clone());
                let bridge = grpc_bridge(request.into_body(), peer, sender);
                tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=async{tokio::try_join!(run,bridge).map(|_|())}=>result}
            }) {
                return empty(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(body)
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
        _ => empty(StatusCode::NOT_FOUND),
    }
}
#[derive(Clone, PartialEq, prost::Message)]
struct Hunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}
async fn grpc_bridge(
    mut incoming: hyper::body::Incoming,
    peer: tokio::io::DuplexStream,
    sender: mpsc::Sender<io::Result<Frame<Bytes>>>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(peer);
    let upload = async {
        let mut pending = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| Error::Protocol("VMess gRPC 请求体失败"))?;
            if let Ok(bytes) = frame.into_data() {
                if pending.len() + bytes.len() > 2 * 1024 * 1024 {
                    return Err(Error::ResourceLimit);
                }
                pending.extend_from_slice(&bytes);
                while pending.len() >= 5 {
                    if pending[0] != 0 {
                        return Err(Error::Protocol("VMess gRPC 不支持压缩"));
                    }
                    let n = u32::from_be_bytes(pending[1..5].try_into().unwrap()) as usize;
                    if n > 1024 * 1024 {
                        return Err(Error::ResourceLimit);
                    }
                    if pending.len() < 5 + n {
                        break;
                    }
                    use prost::Message;
                    let hunk = Hunk::decode(&pending[5..5 + n])
                        .map_err(|_| Error::Protocol("VMess gRPC 消息不合法"))?;
                    for data in hunk.data {
                        writer.write_all(&data).await?;
                    }
                    pending.drain(..5 + n);
                }
            }
        }
        if !pending.is_empty() {
            return Err(Error::Protocol("VMess gRPC 消息截断"));
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let download = async move {
        let mut bytes = vec![0; 65536];
        loop {
            let n = reader.read(&mut bytes).await?;
            if n == 0 {
                break;
            }
            use prost::Message;
            let hunk = Hunk {
                data: vec![bytes[..n].to_vec()],
            }
            .encode_to_vec();
            let mut frame = vec![0];
            frame.extend_from_slice(&(hunk.len() as u32).to_be_bytes());
            frame.extend(hunk);
            sender
                .send(Ok(Frame::data(Bytes::from(frame))))
                .await
                .map_err(|_| Error::Cancelled)?;
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        sender
            .send(Ok(Frame::trailers(trailers)))
            .await
            .map_err(|_| Error::Cancelled)?;
        Ok::<_, Error>(())
    };
    tokio::try_join!(upload, download).map(|_| ())
}
async fn ws_bridge<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    peer: tokio::io::DuplexStream,
) -> Result<()> {
    let (mut sink, mut stream) = websocket.split();
    let (mut reader, mut writer) = tokio::io::split(peer);
    let upload = async {
        while let Some(message) = stream.next().await {
            match message.map_err(|_| Error::Protocol("VMess WebSocket 帧错误"))? {
                tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                    writer.write_all(&bytes).await?
                }
                tokio_tungstenite::tungstenite::Message::Text(bytes) => {
                    writer.write_all(bytes.as_bytes()).await?
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => {}
            }
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let download = async move {
        let mut bytes = vec![0; 65536];
        loop {
            let n = reader.read(&mut bytes).await?;
            if n == 0 {
                break;
            }
            sink.send(tokio_tungstenite::tungstenite::Message::Binary(
                Bytes::copy_from_slice(&bytes[..n]),
            ))
            .await
            .map_err(|_| Error::Protocol("VMess WebSocket 写入失败"))?;
        }
        let _ = sink.close().await;
        Ok::<_, Error>(())
    };
    tokio::try_join!(upload, download).map(|_| ())
}

struct ActiveIo {
    inner: BoxStream,
    activity: tokio::sync::watch::Sender<tokio::time::Instant>,
    last: tokio::time::Instant,
}
impl AsyncRead for ActiveIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, out);
        if matches!(result, std::task::Poll::Ready(Ok(()))) && out.filled().len() > before {
            let now = tokio::time::Instant::now();
            if now.duration_since(this.last) >= std::time::Duration::from_secs(1) {
                this.last = now;
                this.activity.send_replace(now);
            }
        }
        result
    }
}
impl AsyncWrite for ActiveIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, bytes);
        if matches!(result,std::task::Poll::Ready(Ok(n)) if n>0) {
            let now = tokio::time::Instant::now();
            if now.duration_since(this.last) >= std::time::Duration::from_secs(1) {
                this.last = now;
                this.activity.send_replace(now);
            }
        }
        result
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
