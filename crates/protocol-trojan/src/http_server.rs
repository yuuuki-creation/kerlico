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
    if let Transport::Ws {
        path,
        early_data_bytes,
        ..
    } = &transport
    {
        return serve_ws(
            stream,
            path,
            *early_data_bytes as usize,
            payload,
            access,
            context,
        )
        .await;
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
        .initial_stream_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(8 * 1024 * 1024)
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
            let (sender, receiver) = mpsc::channel(32);
            let (local, peer) = tokio::io::duplex(64 * 1024);
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
async fn serve_ws(
    mut stream: BoxStream,
    expected_path: &str,
    early_data_bytes: usize,
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
    let mut ws_version_ok = false;
    let mut ws_key: Option<&str> = None;
    let mut ws_proto: Option<&str> = None;
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
        } else if name.eq_ignore_ascii_case("connection")
            && value
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
        {
            has_conn_upgrade = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-version") && value == "13" {
            ws_version_ok = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-key") && ws_key.is_none() {
            ws_key = Some(value);
        } else if name.eq_ignore_ascii_case("sec-websocket-protocol") && ws_proto.is_none() {
            ws_proto = Some(value);
        }
    }
    if header_bytes > 65536 {
        let _ = stream
            .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    if context.stream_budget.is_closed() {
        let _ = stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
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
    use base64::Engine;
    let Some(key) = ws_key.filter(|k| {
        base64::engine::general_purpose::STANDARD
            .decode(k)
            .is_ok_and(|bytes| bytes.len() == 16)
    }) else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    if method != "GET" || !has_upgrade_ws || !has_conn_upgrade || !ws_version_ok {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    }
    let early = match ws_proto {
        Some(value) => match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value) {
            Ok(bytes) if bytes.len() <= early_data_bytes => bytes,
            _ => {
                let _ = stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                return Ok(());
            }
        },
        None => Vec::new(),
    };
    let Ok(_lease) = context.stream_budget.try_acquire() else {
        let _ = stream
            .write_all(
                b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    let accept = xray_transport::stream::accept_key_for(key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {accept}\r\n\r\n"
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await?;
    let ws = ServerWsStream::new(stream, early, &buf[header_end + 4..]);
    let result = tokio::select! {
        _ = context.cancel.cancelled() => Err(Error::Cancelled),
        r = serve_payload(payload, Box::new(ws), access, context.clone()) => r,
    };
    if result.is_err() {
        return Err(Error::Protocol("Trojan HTTP 逻辑流退出失败"));
    }
    Ok(())
}
enum ServerWsEvent {
    Payload(std::ops::Range<usize>),
    Ping(std::ops::Range<usize>),
    Close,
}
struct ServerWsStream {
    inner: BoxStream,
    rx_buf: Vec<u8>,
    rx_consumed: usize,
    pending: std::ops::Range<usize>,
    tx_buf: Vec<u8>,
    tx_pos: usize,
    scratch: Vec<u8>,
    peer_closed: bool,
    close_queued: bool,
}
impl ServerWsStream {
    fn new(inner: BoxStream, early: Vec<u8>, leftover: &[u8]) -> Self {
        let early_len = early.len();
        let mut rx_buf = Vec::with_capacity((early_len + leftover.len()).max(65536 + 32));
        rx_buf.extend_from_slice(&early);
        rx_buf.extend_from_slice(leftover);
        Self {
            inner,
            rx_buf,
            rx_consumed: early_len,
            pending: 0..early_len,
            tx_buf: Vec::with_capacity(65536 + 32),
            tx_pos: 0,
            scratch: vec![0u8; 65536],
            peer_closed: false,
            close_queued: false,
        }
    }
    fn deliver(&mut self, output: &mut tokio::io::ReadBuf<'_>) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let remaining = &self.rx_buf[self.pending.clone()];
        let take = remaining.len().min(output.remaining());
        if take == 0 {
            return false;
        }
        output.put_slice(&remaining[..take]);
        self.pending.start += take;
        if self.pending.is_empty() {
            self.pending = 0..0;
        }
        true
    }
    fn compact(&mut self) {
        if self.rx_consumed == 0 {
            return;
        }
        if self.rx_consumed == self.rx_buf.len() {
            self.rx_buf.clear();
        } else {
            self.rx_buf.drain(..self.rx_consumed);
        }
        self.rx_consumed = 0;
    }
    fn next_frame(&mut self) -> io::Result<Option<ServerWsEvent>> {
        loop {
            let bytes = &mut self.rx_buf[self.rx_consumed..];
            if bytes.len() < 2 {
                self.compact();
                return Ok(None);
            }
            if bytes[0] & 0x70 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket 帧不合法",
                ));
            }
            let opcode = bytes[0] & 0x0f;
            let is_control = opcode & 0x8 != 0;
            let masked = (bytes[1] & 0x80) != 0;
            let short_len = (bytes[1] & 0x7f) as usize;
            let (payload_len, mut hdr) = match short_len {
                126 => {
                    if bytes.len() < 4 {
                        self.compact();
                        return Ok(None);
                    }
                    (u16::from_be_bytes([bytes[2], bytes[3]]) as usize, 4)
                }
                127 => {
                    if bytes.len() < 10 {
                        self.compact();
                        return Ok(None);
                    }
                    let mut len_bytes = [0u8; 8];
                    len_bytes.copy_from_slice(&bytes[2..10]);
                    (u64::from_be_bytes(len_bytes) as usize, 10)
                }
                len => (len, 2),
            };
            if (is_control && (payload_len > 125 || bytes[0] & 0x80 == 0))
                || payload_len > 16 * 1024 * 1024
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket 帧不合法",
                ));
            }
            let mask_key = if masked {
                if bytes.len() < hdr + 4 {
                    self.compact();
                    return Ok(None);
                }
                let k = [bytes[hdr], bytes[hdr + 1], bytes[hdr + 2], bytes[hdr + 3]];
                hdr += 4;
                Some(k)
            } else {
                None
            };
            let total = hdr + payload_len;
            if bytes.len() < total {
                self.compact();
                return Ok(None);
            }
            if let Some(key) = mask_key {
                let payload = &mut bytes[hdr..total];
                let key64 = u64::from_ne_bytes([
                    key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3],
                ]);
                let (chunks, tail) = payload.as_chunks_mut::<8>();
                for chunk in chunks {
                    let v = u64::from_ne_bytes(*chunk) ^ key64;
                    *chunk = v.to_ne_bytes();
                }
                for (i, b) in tail.iter_mut().enumerate() {
                    *b ^= key[i & 3];
                }
            }
            let start = self.rx_consumed + hdr;
            let end = self.rx_consumed + total;
            self.rx_consumed += total;
            match opcode {
                0x8 => return Ok(Some(ServerWsEvent::Close)),
                0x9 => return Ok(Some(ServerWsEvent::Ping(start..end))),
                0xa => continue,
                0x0..=0x2 => {
                    if start == end {
                        continue;
                    }
                    return Ok(Some(ServerWsEvent::Payload(start..end)));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WebSocket 帧不合法",
                    ));
                }
            }
        }
    }
    fn encode_frame(out: &mut Vec<u8>, opcode: u8, payload: &[u8]) {
        out.reserve(payload.len() + 10);
        out.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            out.push(len as u8);
        } else if let Ok(len16) = u16::try_from(len) {
            out.push(126);
            out.extend_from_slice(&len16.to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
    }
    fn poll_flush_tx(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        while self.tx_pos < self.tx_buf.len() {
            let written = match std::pin::Pin::new(&mut self.inner)
                .poll_write(cx, &self.tx_buf[self.tx_pos..])
            {
                std::task::Poll::Ready(Ok(n)) => n,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };
            if written == 0 {
                return std::task::Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.tx_pos += written;
        }
        self.tx_buf.clear();
        self.tx_pos = 0;
        std::task::Poll::Ready(Ok(()))
    }
}
impl AsyncRead for ServerWsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let initial_rem = output.remaining();
        if initial_rem == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        if let std::task::Poll::Ready(Err(e)) = this.poll_flush_tx(cx) {
            return std::task::Poll::Ready(Err(e));
        }
        loop {
            if this.deliver(output) && output.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            if this.peer_closed {
                return std::task::Poll::Ready(Ok(()));
            }
            match this.next_frame()? {
                Some(ServerWsEvent::Payload(range)) => {
                    this.pending = range;
                    continue;
                }
                Some(ServerWsEvent::Ping(range)) => {
                    Self::encode_frame(&mut this.tx_buf, 0xa, &this.rx_buf[range]);
                    if let std::task::Poll::Ready(Err(e)) = this.poll_flush_tx(cx) {
                        return std::task::Poll::Ready(Err(e));
                    }
                    continue;
                }
                Some(ServerWsEvent::Close) => {
                    this.peer_closed = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                None => {}
            }
            if output.remaining() < initial_rem {
                return std::task::Poll::Ready(Ok(()));
            }
            let filled = {
                let mut buffer = tokio::io::ReadBuf::new(&mut this.scratch);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                    std::task::Poll::Ready(Ok(())) => buffer.filled().len(),
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            };
            if filled == 0 {
                this.peer_closed = true;
                return std::task::Poll::Ready(Ok(()));
            }
            this.rx_buf.extend_from_slice(&this.scratch[..filled]);
        }
    }
}
impl AsyncWrite for ServerWsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_flush_tx(cx) {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
        if input.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        Self::encode_frame(&mut this.tx_buf, 0x2, input);
        this.tx_pos = 0;
        if let std::task::Poll::Ready(Err(e)) = this.poll_flush_tx(cx) {
            return std::task::Poll::Ready(Err(e));
        }
        std::task::Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_tx(cx) {
            std::task::Poll::Ready(Ok(())) => std::pin::Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_queued {
            Self::encode_frame(&mut this.tx_buf, 0x8, &1000u16.to_be_bytes());
            this.close_queued = true;
        }
        match this.poll_flush_tx(cx) {
            std::task::Poll::Ready(Ok(())) => std::pin::Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
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
        use bytes::Buf;
        let mut pending = bytes::BytesMut::new();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|_| Error::Protocol("Trojan gRPC 请求体失败"))?;
            if let Ok(data) = frame.into_data() {
                if pending.len() + data.len() > 2 * 1024 * 1024 {
                    return Err(Error::ResourceLimit);
                }
                pending.extend_from_slice(&data);
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
                    pending.advance(5 + length);
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
        use bytes::BufMut;
        let mut bytes = vec![0; 65536];
        loop {
            let n = reader.read(&mut bytes).await?;
            if n == 0 {
                break;
            }
            let mut v = n;
            let mut varint = [0u8; 5];
            let mut vlen = 0;
            while v >= 0x80 {
                varint[vlen] = (v as u8) | 0x80;
                v >>= 7;
                vlen += 1;
            }
            varint[vlen] = v as u8;
            vlen += 1;
            let msg_len = (1 + vlen + n) as u32;
            let mut frame = bytes::BytesMut::with_capacity(6 + vlen + n);
            frame.put_u8(0);
            frame.put_slice(&msg_len.to_be_bytes());
            frame.put_u8(0x0a);
            frame.put_slice(&varint[..vlen]);
            frame.put_slice(&bytes[..n]);
            sender
                .send(Ok(Frame::data(frame.freeze())))
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
