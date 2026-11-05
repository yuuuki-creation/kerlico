//! HTTP 升级及 gRPC 逻辑流由物理连接持有并排空。
use crate::{config::Transport, inbound::Payload};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Frame, Incoming};
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
use tokio_tungstenite::tungstenite::{
    Message,
    protocol::{Role, WebSocketConfig},
};
type Body = UnsyncBoxBody<Bytes, io::Error>;
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
struct Jobs(Mutex<JoinSet<()>>, kerlico_core::NodeTasks);
impl Jobs {
    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Ok(mut tasks) = self.0.lock() {
            while tasks.try_join_next().is_some() {}
            if let Ok(task) = self.1.spawn_tracked(task) {
                tasks.spawn(async move {
                    let _ = task.await;
                });
            }
        }
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        if let Ok(tasks) = self.0.get_mut() {
            tasks.abort_all();
        }
    }
}
pub(crate) async fn serve(
    stream: BoxStream,
    transport: Transport,
    payload: Arc<Payload>,
    access: IngressBinding,
    context: InboundContext,
) -> Result<()> {
    if let Transport::Httpupgrade { path, .. } = &transport {
        return serve_httpupgrade(stream, path, payload, access, context).await;
    }
    let jobs = Arc::new(Jobs(Mutex::new(JoinSet::new()), context.tasks.clone()));
    let tasks = jobs.clone();
    let cancel = context.cancel.clone();
    let executor = NodeExecutor(context.tasks.clone());
    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
        let jobs = tasks.clone();
        let transport = transport.clone();
        let payload = payload.clone();
        let access = access.clone();
        let context = context.clone();
        async move {
            Ok::<_, Infallible>(
                request_handler(request, transport, payload, access, context, jobs).await,
            )
        }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(executor);
    builder
        .http2()
        .initial_stream_window_size(16 * 1024 * 1024)
        .initial_connection_window_size(64 * 1024 * 1024)
        .adaptive_window(true);
    builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await
        .map_err(|_| Error::Protocol("Trojan HTTP 载体失败"))?;
    let mut tasks = {
        let mut locked = jobs
            .0
            .lock()
            .map_err(|_| Error::Protocol("Trojan HTTP 任务状态失败"))?;
        std::mem::replace(&mut *locked, JoinSet::new())
    };
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            task = tasks.join_next() => match task {None=>return Ok(()),Some(Err(_))=>return Err(Error::Protocol("Trojan HTTP 逻辑流退出失败")),_=>{}},
        }
    }
}
async fn request_handler(
    mut request: Request<Incoming>,
    transport: Transport,
    payload: Arc<Payload>,
    access: IngressBinding,
    context: InboundContext,
    jobs: Arc<Jobs>,
) -> Response<Body> {
    if context.stream_budget.is_closed() {
        return empty(StatusCode::SERVICE_UNAVAILABLE);
    }
    let size: usize = request
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
        .sum();
    if size > 65536 {
        return empty(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }
    match transport {
        Transport::Ws {
            path,
            early_data_bytes,
            ..
        } if request.uri().path() == path => {
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
                Some(value) => match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value)
                {
                    Ok(bytes) if bytes.len() <= early_data_bytes as usize => bytes,
                    _ => return empty(StatusCode::BAD_REQUEST),
                },
                None => Vec::new(),
            };
            let Ok(lease) = context.stream_budget.try_acquire() else {
                return empty(StatusCode::TOO_MANY_REQUESTS);
            };
            let upgraded = hyper::upgrade::on(&mut request);
            jobs.spawn(async move {
                let _lease = lease;
                let running = async {
                    let upgraded = upgraded.await.map_err(|_| Error::Protocol("Trojan WS 升级失败"))?;
                    let mut config = WebSocketConfig::default();config.max_message_size=Some(1024*1024);config.max_frame_size=Some(1024*1024);config.write_buffer_size=65536;config.max_write_buffer_size=256*1024;
                    let websocket = tokio_tungstenite::WebSocketStream::from_raw_socket(TokioIo::new(upgraded),Role::Server,Some(config)).await;
                    let (local, peer) = tokio::io::duplex(256*1024);
                    let serving = serve_payload(payload,Box::new(local),access,context.clone());
                    tokio::try_join!(serving, websocket_bridge(websocket,peer,early)).map(|_|())
                };
                let _ = tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=running=>result};
            });
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("upgrade", "websocket")
                .header("connection", "Upgrade")
                .header("sec-websocket-accept", accept)
                .body(empty_body())
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
        Transport::Httpupgrade { path, .. } if request.uri().path() == path => {
            if request.method() != http::Method::GET || !upgrade(&request) {
                return empty(StatusCode::BAD_REQUEST);
            }
            let Ok(lease) = context.stream_budget.try_acquire() else {
                return empty(StatusCode::TOO_MANY_REQUESTS);
            };
            let upgraded = hyper::upgrade::on(&mut request);
            jobs.spawn(async move {let _lease=lease;let running=async {let stream=upgraded.await.map_err(|_|Error::Protocol("Trojan HTTPUpgrade 失败"))?;serve_payload(payload,Box::new(TokioIo::new(stream)),access,context.clone()).await};let _=tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=running=>result};});
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("upgrade", "websocket")
                .header("connection", "upgrade")
                .body(empty_body())
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
        Transport::Grpc { service_name, .. } => {
            if request.method() != http::Method::POST
                || request.version() != http::Version::HTTP_2
                || !matches!(request.uri().path(),value if value==format!("/{service_name}/Tun") || value==format!("/{service_name}/TunMulti"))
                || !request
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.starts_with("application/grpc"))
            {
                return empty(StatusCode::NOT_FOUND);
            }
            let Ok(lease) = context.stream_budget.try_acquire() else {
                return empty(StatusCode::TOO_MANY_REQUESTS);
            };
            let (sender, receiver) = mpsc::channel(128);
            let (local, peer) = tokio::io::duplex(256 * 1024);
            jobs.spawn(async move {let _lease=lease;let serving=serve_payload(payload,Box::new(local),access,context.clone());let bridge=grpc_bridge(request.into_body(),peer,sender);let _=tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),result=async{tokio::try_join!(serving,bridge).map(|_|())}=>result};});
            Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(StreamBody::new(ReceiverStream::new(receiver)).boxed_unsync())
                .unwrap_or_else(|_| empty(StatusCode::INTERNAL_SERVER_ERROR))
        }
        _ => empty(StatusCode::NOT_FOUND),
    }
}
async fn serve_payload(
    payload: Arc<Payload>,
    stream: BoxStream,
    access: IngressBinding,
    context: InboundContext,
) -> Result<()> {
    payload.serve(stream, access, context).await
}
struct PrefixedIo {
    inner: BoxStream,
    prefix: Vec<u8>,
    pos: usize,
}
impl AsyncRead for PrefixedIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let rem = &this.prefix[this.pos..];
            let take = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..take]);
            this.pos += take;
            if this.pos == this.prefix.len() {
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for PrefixedIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
async fn serve_httpupgrade(
    mut stream: BoxStream,
    expected_path: &str,
    payload: Arc<Payload>,
    access: IngressBinding,
    context: InboundContext,
) -> Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let n = tokio::select! {
            _ = context.cancel.cancelled() => return Err(Error::Cancelled),
            r = stream.read(&mut chunk) => r?,
        };
        if n == 0 {
            if buf.is_empty() {
                return Ok(());
            }
            return Err(Error::Protocol("Trojan HTTP 载体失败"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 72 * 1024 {
            let _ = stream
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    if context.stream_budget.is_closed() {
        let _ = stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    let Ok(head) = std::str::from_utf8(&buf[..header_end]) else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    let mut lines = head.split("\r\n");
    let Some(req_line) = lines.next() else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    let mut parts = req_line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    if !version.starts_with("HTTP/1.") {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    }
    let mut header_bytes = 0usize;
    let mut has_upgrade_ws = false;
    let mut has_conn_upgrade = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        };
        let name = name.trim();
        let value = value.trim();
        header_bytes = header_bytes.saturating_add(name.len() + value.len());
        if name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket") {
            has_upgrade_ws = true;
        }
        if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
        {
            has_conn_upgrade = true;
        }
    }
    if header_bytes > 65536 {
        let _ = stream
            .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    let Ok(uri) = target.parse::<http::Uri>() else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    if uri.path() != expected_path {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    if method != "GET" || !has_upgrade_ws || !has_conn_upgrade {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    }
    let Ok(_lease) = context.stream_budget.try_acquire() else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    stream
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: upgrade\r\n\r\n")
        .await?;
    stream.flush().await?;
    let leftover = &buf[header_end + 4..];
    let upgraded: BoxStream = if leftover.is_empty() {
        stream
    } else {
        Box::new(PrefixedIo {
            inner: stream,
            prefix: leftover.to_vec(),
            pos: 0,
        })
    };
    tokio::select! {
        _ = context.cancel.cancelled() => Err(Error::Cancelled),
        result = serve_payload(payload, upgraded, access, context.clone()) => result,
    }
}
fn upgrade(request: &Request<Incoming>) -> bool {
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
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
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
#[derive(Clone, PartialEq, prost::Message)]
struct Hunk {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}
async fn grpc_bridge(
    mut incoming: Incoming,
    peer: tokio::io::DuplexStream,
    sender: mpsc::Sender<io::Result<Frame<Bytes>>>,
) -> Result<()> {
    use prost::Message;
    let (mut reader, mut writer) = tokio::io::split(peer);
    let upload = async {
        let mut pending = Vec::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| Error::Protocol("Trojan gRPC 请求体失败"))?;
            if let Ok(data) = frame.into_data() {
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
                            .map_err(|_| Error::Protocol("gRPC 长度失败"))?,
                    ) as usize;
                    if length > 1024 * 1024 {
                        return Err(Error::ResourceLimit);
                    }
                    if pending.len() < 5 + length {
                        break;
                    }
                    let hunk = Hunk::decode(&pending[5..5 + length])
                        .map_err(|_| Error::Protocol("Trojan gRPC Hunk 失败"))?;
                    for data in hunk.data {
                        writer.write_all(&data).await?;
                    }
                    pending.drain(..5 + length);
                }
            }
        }
        if !pending.is_empty() {
            return Err(Error::Protocol("Trojan gRPC 帧截断"));
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
            let data = Hunk {
                data: vec![bytes[..n].to_vec()],
            }
            .encode_to_vec();
            let mut frame = vec![0];
            frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
            frame.extend_from_slice(&data);
            sender
                .send(Ok(Frame::data(Bytes::from(frame))))
                .await
                .map_err(|_| Error::Cancelled)?;
        }
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        let _ = sender.send(Ok(Frame::trailers(trailers))).await;
        Ok::<_, Error>(())
    };
    tokio::try_join!(upload, download).map(|_| ())
}
async fn websocket_bridge<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    websocket: tokio_tungstenite::WebSocketStream<S>,
    peer: tokio::io::DuplexStream,
    early: Vec<u8>,
) -> Result<()> {
    let (mut sink, mut stream) = websocket.split();
    let (mut reader, mut writer) = tokio::io::split(peer);
    let (control, mut events) = mpsc::channel(8);
    let upload = async {
        writer.write_all(&early).await?;
        while let Some(message) = stream.next().await {
            match message.map_err(|_| Error::Protocol("Trojan WS 帧失败"))? {
                Message::Binary(data) => writer.write_all(&data).await?,
                Message::Text(data) => writer.write_all(data.as_bytes()).await?,
                Message::Close(_) => break,
                Message::Ping(data) => {
                    control.send(data).await.map_err(|_| Error::Cancelled)?;
                }
                _ => {}
            }
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let download = async move {
        let mut bytes = vec![0; 65536];
        let mut controls_open = true;
        loop {
            tokio::select! {
                event=events.recv(),if controls_open=>match event {Some(data)=>sink.send(Message::Pong(data)).await.map_err(|_|Error::Protocol("Trojan WS pong 失败"))?,None=>controls_open=false},
                result=reader.read(&mut bytes)=>{let n=result?;if n==0 {break;}sink.send(Message::Binary(Bytes::copy_from_slice(&bytes[..n]))).await.map_err(|_|Error::Protocol("Trojan WS 写入失败"))?;},
            }
        }
        let _ = sink.close().await;
        Ok::<_, Error>(())
    };
    tokio::try_join!(upload, download).map(|_| ())
}
