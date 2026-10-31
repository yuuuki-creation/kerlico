//! 固定原生peer不声明TE仍读取Sudoku EOF trailer；只向Hyper补充该内部能力标记。
//! 不处理响应、不改变正文；H2必须由调用方跳过本适配器。

use kerlico_core::BoxStream;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_HEAD: usize = 32 * 1024;
const MAX_FIELDS: usize = 64;
const MAX_CHUNK_LINE: usize = 8 * 1024;
const INTERNAL_TE: &[u8] = b"TE: trailers\r\n";

/// 只在Hyper OnUpgrade成功后、升级载体第一次读取前调用accepted。
#[derive(Clone)]
pub(crate) struct UpgradeHandle(Arc<AtomicBool>);
impl UpgradeHandle {
    pub fn accepted(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// path_root须已由NodeOptions规范化；支持同一H1连接的后续请求和pipeline。
/// 原有TE字段始终保留；仅精确匹配本节点stream下载且没有TE时增加一行。
pub(crate) fn wrap(inner: BoxStream, path_root: &str) -> (BoxStream, UpgradeHandle) {
    let accepted = Arc::new(AtomicBool::new(false));
    let handle = UpgradeHandle(accepted.clone());
    let stream = Compat {
        inner,
        path: format!("{path_root}/stream"),
        accepted,
        input: Vec::new(),
        consumed: 0,
        output: Vec::new(),
        emitted: 0,
        framing: Framing::Head,
        failed: false,
        eof: false,
    };
    (Box::new(stream), handle)
}

#[derive(Clone, Copy)]
enum Framing {
    Head,
    Fixed(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailers,
    Raw,
}
struct Compat {
    inner: BoxStream,
    path: String,
    accepted: Arc<AtomicBool>,
    input: Vec<u8>,
    consumed: usize,
    output: Vec<u8>,
    emitted: usize,
    framing: Framing,
    failed: bool,
    eof: bool,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Sudoku H1请求边界不合法或超过预算",
    )
}
fn trim(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|&b| matches!(b, b' ' | b'\t')) {
        value = &value[1..];
    }
    while value.last().is_some_and(|&b| matches!(b, b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}
fn crlf(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().all(|(i, &b)| {
        (b != b'\n' || i > 0 && bytes[i - 1] == b'\r')
            && (b != b'\r' || bytes.get(i + 1) == Some(&b'\n'))
    })
}
fn decimal(bytes: &[u8]) -> io::Result<u64> {
    let bytes = trim(bytes);
    if bytes.is_empty() {
        return Err(invalid());
    }
    bytes.iter().try_fold(0u64, |value, &b| {
        if !b.is_ascii_digit() {
            return Err(invalid());
        }
        value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or_else(invalid)
    })
}

impl Compat {
    fn remaining(&self) -> &[u8] {
        &self.input[self.consumed..]
    }
    fn forward(&mut self, count: usize) {
        self.output
            .extend_from_slice(&self.input[self.consumed..self.consumed + count]);
        self.consumed += count;
    }
    fn compact(&mut self) {
        if self.consumed != 0 {
            self.input.drain(..self.consumed);
            self.consumed = 0;
        }
    }
    fn head(&mut self) -> io::Result<bool> {
        let mut fields = [httparse::EMPTY_HEADER; MAX_FIELDS];
        let mut request = httparse::Request::new(&mut fields);
        let parsed = request.parse(self.remaining()).map_err(|_| invalid())?;
        let httparse::Status::Complete(length) = parsed else {
            if self.remaining().len() >= MAX_HEAD {
                return Err(invalid());
            }
            return Ok(false);
        };
        if length > MAX_HEAD || !crlf(&self.remaining()[..length]) {
            return Err(invalid());
        }
        let mut content_length = None;
        let mut chunked = false;
        let mut has_te = false;
        let mut tunnel = None;
        let mut tunnel_count = 0usize;
        for field in request.headers.iter() {
            if field.name.eq_ignore_ascii_case("content-length") {
                // 同值重复也不接受，避免与Hyper版本的合并规则产生不同边界。
                if content_length.is_some() {
                    return Err(invalid());
                }
                content_length = Some(decimal(field.value)?);
            } else if field.name.eq_ignore_ascii_case("transfer-encoding") {
                // 这里只需要Sudoku原生上传的chunked；其他编码链不猜测正文边界。
                if chunked || !trim(field.value).eq_ignore_ascii_case(b"chunked") {
                    return Err(invalid());
                }
                chunked = true;
            } else if field.name.eq_ignore_ascii_case("te") {
                has_te = true;
            } else if field.name.eq_ignore_ascii_case("x-sudoku-tunnel") {
                tunnel_count += 1;
                tunnel = Some(trim(field.value));
            }
        }
        if chunked && content_length.is_some() {
            return Err(invalid());
        }
        let target = request.path.unwrap_or("");
        let path = target.split('?').next().unwrap_or("");
        let inject = request.version == Some(1)
            && request.method == Some("GET")
            && target.starts_with('/')
            && path == self.path
            && !has_te
            && tunnel_count == 1
            && tunnel.is_some_and(|mode| matches!(mode, b"stream" | b"poll"));
        if inject && length > MAX_HEAD - INTERNAL_TE.len() {
            return Err(invalid());
        }
        self.framing = if chunked {
            Framing::ChunkSize
        } else {
            match content_length {
                Some(size) if size != 0 => Framing::Fixed(size),
                _ => Framing::Head,
            }
        };
        if inject {
            // 首部以CRLF CRLF结束，在最后一个空行前插入，不重排或重写原字段。
            self.forward(length - 2);
            self.output.extend_from_slice(INTERNAL_TE);
            self.forward(2);
        } else {
            self.forward(length);
        }
        Ok(true)
    }
    fn trailers(&mut self) -> io::Result<bool> {
        let bytes = self.remaining();
        let length = if bytes.starts_with(b"\r\n") {
            Some(2)
        } else {
            bytes
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| i + 4)
        };
        let Some(length) = length else {
            if bytes.len() >= MAX_HEAD {
                return Err(invalid());
            }
            return Ok(false);
        };
        if length > MAX_HEAD || !crlf(&bytes[..length]) {
            return Err(invalid());
        }
        let mut fields = [httparse::EMPTY_HEADER; MAX_FIELDS];
        let parsed =
            httparse::parse_headers(&bytes[..length], &mut fields).map_err(|_| invalid())?;
        let httparse::Status::Complete((used, fields)) = parsed else {
            return Err(invalid());
        };
        if used != length
            || fields.iter().any(|field| {
                field.name.eq_ignore_ascii_case("content-length")
                    || field.name.eq_ignore_ascii_case("transfer-encoding")
            })
        {
            return Err(invalid());
        }
        self.forward(length);
        self.framing = Framing::Head;
        Ok(true)
    }
    /// 每次只准备一个有界片段；正文计数和部分行始终保存在对象内。
    fn prepare(&mut self) -> io::Result<bool> {
        match self.framing {
            Framing::Head => self.head(),
            Framing::Fixed(remaining) | Framing::ChunkData(remaining) => {
                let count = self.remaining().len().min(remaining.min(4096) as usize);
                if count == 0 {
                    return Ok(false);
                }
                let next = remaining - count as u64;
                self.framing = match self.framing {
                    Framing::Fixed(_) if next == 0 => Framing::Head,
                    Framing::Fixed(_) => Framing::Fixed(next),
                    _ if next == 0 => Framing::ChunkEnd,
                    _ => Framing::ChunkData(next),
                };
                self.forward(count);
                Ok(true)
            }
            Framing::ChunkSize => {
                let parsed = httparse::parse_chunk_size(self.remaining()).map_err(|_| invalid())?;
                let httparse::Status::Complete((length, size)) = parsed else {
                    if self.remaining().len() >= MAX_CHUNK_LINE {
                        return Err(invalid());
                    }
                    return Ok(false);
                };
                if length > MAX_CHUNK_LINE || !crlf(&self.remaining()[..length]) {
                    return Err(invalid());
                }
                self.forward(length);
                self.framing = if size == 0 {
                    Framing::Trailers
                } else {
                    Framing::ChunkData(size)
                };
                Ok(true)
            }
            Framing::ChunkEnd => {
                if self.remaining().len() < 2 {
                    return Ok(false);
                }
                if !self.remaining().starts_with(b"\r\n") {
                    return Err(invalid());
                }
                self.forward(2);
                self.framing = Framing::ChunkSize;
                Ok(true)
            }
            Framing::Trailers => self.trailers(),
            Framing::Raw => {
                let count = self.remaining().len().min(4096);
                if count == 0 {
                    return Ok(false);
                }
                self.forward(count);
                Ok(true)
            }
        }
    }
}

impl AsyncRead for Compat {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if target.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(invalid()));
        }
        for _ in 0..64 {
            if this.emitted < this.output.len() {
                let count = target.remaining().min(this.output.len() - this.emitted);
                target.put_slice(&this.output[this.emitted..this.emitted + count]);
                this.emitted += count;
                return Poll::Ready(Ok(()));
            }
            this.output.clear();
            this.emitted = 0;
            if this.accepted.load(Ordering::Acquire) {
                this.framing = Framing::Raw;
            }
            match this.prepare() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
            if this.eof {
                if this.remaining().is_empty()
                    && matches!(this.framing, Framing::Head | Framing::Raw)
                {
                    return Poll::Ready(Ok(()));
                }
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Sudoku H1请求在首部或正文边界前截断",
                )));
            }
            this.compact();
            let limit = match this.framing {
                Framing::Head | Framing::Trailers => MAX_HEAD.saturating_sub(this.input.len()),
                Framing::ChunkSize => MAX_CHUNK_LINE.saturating_sub(this.input.len()),
                _ => 4096,
            }
            .min(4096);
            if limit == 0 {
                this.failed = true;
                return Poll::Ready(Err(invalid()));
            }
            let mut bytes = [0; 4096];
            let mut buffer = ReadBuf::new(&mut bytes[..limit]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) => {
                    if buffer.filled().is_empty() {
                        this.eof = true;
                    }
                    this.input.extend_from_slice(buffer.filled());
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Compat {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{Empty, StreamBody};
    use hyper::{body::Frame, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::{
        convert::Infallible,
        future::{Future, poll_fn},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const GET: &[u8] = b"GET /gate/stream?token=synthetic HTTP/1.1\r\nHost: localhost\r\nX-Sudoku-Tunnel: stream\r\n\r\n";
    fn injected(bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes[..bytes.len() - 2].to_vec();
        out.extend_from_slice(INTERNAL_TE);
        out.extend_from_slice(b"\r\n");
        out
    }
    async fn transform(wire: Vec<u8>, root: &str, capacity: usize) -> io::Result<Vec<u8>> {
        let (mut writer, reader) = tokio::io::duplex(capacity);
        let (mut wrapped, _) = wrap(Box::new(reader), root);
        let sender = tokio::spawn(async move {
            let _ = writer.write_all(&wire).await;
            let _ = writer.shutdown().await;
        });
        let mut out = Vec::new();
        let result = wrapped.read_to_end(&mut out).await;
        drop(wrapped);
        sender.await.unwrap();
        result.map(|_| out)
    }
    async fn head(reader: &mut (impl AsyncRead + Unpin)) -> Vec<u8> {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            reader.read_exact(&mut byte).await.unwrap();
            header.push(byte[0]);
            assert!(header.len() < 4096);
        }
        header
    }

    #[tokio::test]
    async fn exact_endpoint_only_preserves_existing_te_and_rejected_upgrade_keepalive() {
        for (request,changed) in [
            (GET.to_vec(),true),
            (b"GET /gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: poll\r\n\r\n".to_vec(),true),
            (b"GET /gate/stream HTTP/1.0\r\nX-Sudoku-Tunnel: stream\r\n\r\n".to_vec(),false),
            (b"GET /other/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\n\r\n".to_vec(),false),
            (b"GET /gate/stream-other HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\n\r\n".to_vec(),false),
            (b"GET http://localhost/gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\n\r\n".to_vec(),false),
            (b"POST /gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\nContent-Length: 0\r\n\r\n".to_vec(),false),
            (b"GET /gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\nte: gzip\r\n\r\n".to_vec(),false),
            (b"GET /gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\nTE: trailers\r\n\r\n".to_vec(),false),
            (b"GET /gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\nX-Sudoku-Tunnel: poll\r\n\r\n".to_vec(),false),
        ] {
            let expected=if changed{injected(&request)}else{request.clone()};assert_eq!(transform(request,"/gate",1).await.unwrap(),expected);
        }
        let upgrade = b"GET /gate/ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut pipeline = upgrade.to_vec();
        pipeline.extend_from_slice(GET);
        let mut expected = upgrade.to_vec();
        expected.extend(injected(GET));
        assert_eq!(transform(pipeline, "/gate", 1).await.unwrap(), expected);
        let default = b"GET /stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\n\r\n";
        assert_eq!(
            transform(default.to_vec(), "", 1).await.unwrap(),
            injected(default)
        );
    }

    #[tokio::test]
    async fn content_length_chunked_trailers_and_pipeline_are_byte_exact() {
        let fake = GET;
        let fixed = format!(
            "POST /gate/api/v1/upload HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            fake.len()
        );
        let mut chunked =
            b"POST /gate/api/v1/upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x};opaque=example\r\n", fake.len()).as_bytes());
        chunked.extend_from_slice(fake);
        chunked.extend_from_slice(b"\r\n1\r\nx\r\n0\r\nX-Test: trailer\r\n\r\n");
        let mut wire = GET.to_vec();
        wire.extend_from_slice(fixed.as_bytes());
        wire.extend_from_slice(fake);
        wire.extend_from_slice(&chunked);
        wire.extend_from_slice(GET);
        let mut expected = injected(GET);
        expected.extend_from_slice(fixed.as_bytes());
        expected.extend_from_slice(fake);
        expected.extend_from_slice(&chunked);
        expected.extend(injected(GET));
        for capacity in [1, 7, 4096] {
            assert_eq!(
                transform(wire.clone(), "/gate", capacity).await.unwrap(),
                expected
            );
        }
        let mut empty = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec();
        let mut expected = empty.clone();
        empty.extend_from_slice(GET);
        expected.extend(injected(GET));
        assert_eq!(transform(empty, "/gate", 1).await.unwrap(), expected);
    }

    #[tokio::test]
    async fn suspended_read_retains_partial_head_and_chunk_size() {
        let (mut writer, reader) = tokio::io::duplex(256);
        let (mut wrapped, _) = wrap(Box::new(reader), "/gate");
        writer.write_all(&GET[..17]).await.unwrap();
        let mut byte = [0; 1];
        let mut first = Box::pin(wrapped.read(&mut byte));
        assert!(poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx).is_pending())).await);
        drop(first);
        writer.write_all(&GET[17..]).await.unwrap();
        writer.shutdown().await.unwrap();
        let mut received = Vec::new();
        wrapped.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, injected(GET));
        let (mut writer, reader) = tokio::io::duplex(256);
        let (mut wrapped, _) = wrap(Box::new(reader), "/gate");
        let prefix = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        writer.write_all(prefix).await.unwrap();
        let mut header = vec![0; prefix.len()];
        wrapped.read_exact(&mut header).await.unwrap();
        assert_eq!(header, prefix);
        writer.write_all(b"3;ext").await.unwrap();
        let mut first = Box::pin(wrapped.read(&mut byte));
        assert!(poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx).is_pending())).await);
        drop(first);
        writer.write_all(b"=v\r\nabc\r\n0\r\n\r\n").await.unwrap();
        writer.shutdown().await.unwrap();
        let mut received = Vec::new();
        wrapped.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"3;ext=v\r\nabc\r\n0\r\n\r\n");
    }

    #[tokio::test]
    async fn ambiguous_framing_limits_bare_lf_and_truncation_fail_closed() {
        for wire in [
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx".to_vec(),
            b"POST / HTTP/1.1\r\nContent-Length: 1,1\r\n\r\nx".to_vec(),
            b"POST / HTTP/1.1\r\nContent-Length: 18446744073709551616\r\n\r\n".to_vec(),
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\nHost: localhost\n\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: local".to_vec(),
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab".to_vec(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab".to_vec(),
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 1\r\n\r\n"
                .to_vec(),
            format!("GET / HTTP/1.1\r\nX-Fill: {}\r\n\r\n", "a".repeat(MAX_HEAD)).into_bytes(),
            format!(
                "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\na\r\n0\r\n\r\n",
                "a".repeat(MAX_CHUNK_LINE)
            )
            .into_bytes(),
        ] {
            assert!(transform(wire, "/gate", 17).await.is_err());
        }
    }

    #[tokio::test]
    async fn successful_upgrade_preserves_buffered_opaque_bytes_and_writes() {
        let (mut peer, inner) = tokio::io::duplex(4096);
        let (mut wrapped, upgrade) = wrap(Box::new(inner), "/gate");
        let clone = upgrade.clone();
        let request = b"GET /gate/ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let raw = b"\x82\x04\0\r\n\xffGET /gate/stream HTTP/1.1\r\nX-Sudoku-Tunnel: stream\r\n\r\n";
        let mut all = request.to_vec();
        all.extend_from_slice(raw);
        peer.write_all(&all).await.unwrap();
        peer.shutdown().await.unwrap();
        let mut header = vec![0; request.len()];
        wrapped.read_exact(&mut header).await.unwrap();
        assert_eq!(header, request);
        clone.accepted();
        let mut received = Vec::new();
        wrapped.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, raw);
        wrapped.write_all(b"opaque-response").await.unwrap();
        wrapped.shutdown().await.unwrap();
        let mut response = Vec::new();
        peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"opaque-response");
    }

    #[tokio::test]
    async fn hyper_keepalive_sends_real_eof_trailer_to_native_h1_without_te() {
        let (mut peer, inner) = tokio::io::duplex(4096);
        let (wrapped, _) = wrap(Box::new(inner), "/gate");
        let server = tokio::spawn(async move {
            let service = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                assert_eq!(request.headers().get(http::header::TE).unwrap(), "trailers");
                let mut trailers = http::HeaderMap::new();
                trailers.insert("x-sudoku-stream-eof", http::HeaderValue::from_static("1"));
                let frames = tokio_stream::iter(vec![
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"data"))),
                    Ok(Frame::trailers(trailers)),
                ]);
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .header(http::header::TRAILER, "x-sudoku-stream-eof")
                        .body(StreamBody::new(frames))
                        .unwrap(),
                )
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(wrapped), service)
                .await
                .unwrap();
        });
        for close in [false, true] {
            let mut request = GET[..GET.len() - 2].to_vec();
            if close {
                request.extend_from_slice(b"Connection: close\r\n");
            }
            request.extend_from_slice(b"\r\n");
            peer.write_all(&request).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !response.ends_with(b"0\r\nx-sudoku-stream-eof: 1\r\n\r\n") {
                    let mut byte = [0; 1];
                    peer.read_exact(&mut byte).await.unwrap();
                    response.push(byte[0]);
                    assert!(response.len() < 4096);
                }
            })
            .await
            .unwrap();
            assert!(response.windows(4).any(|w| w == b"data"));
        }
        let mut end = [0; 1];
        assert_eq!(peer.read(&mut end).await.unwrap(), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hyper_on_upgrade_marks_raw_before_upgraded_reader_runs() {
        let (mut peer, inner) = tokio::io::duplex(4096);
        let (wrapped, upgrade) = wrap(Box::new(inner), "/gate");
        let (done, finished) = tokio::sync::oneshot::channel();
        let done = Arc::new(std::sync::Mutex::new(Some(done)));
        let service = service_fn(move |mut request: http::Request<hyper::body::Incoming>| {
            let upgrade = upgrade.clone();
            let done = done.clone();
            async move {
                let upgraded = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    let upgraded = upgraded.await.unwrap();
                    upgrade.accepted();
                    let mut stream = TokioIo::new(upgraded);
                    let mut bytes = [0; 4];
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"\0\xff\r\n");
                    stream.write_all(&bytes).await.unwrap();
                    stream.shutdown().await.unwrap();
                    done.lock().unwrap().take().unwrap().send(()).unwrap();
                });
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .status(101)
                        .header("connection", "upgrade")
                        .header("upgrade", "websocket")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
            }
        });
        let server = tokio::spawn(async move {
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(wrapped), service)
                .with_upgrades()
                .await
                .unwrap();
        });
        peer.write_all(b"GET /gate/ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
        let response = head(&mut peer).await;
        assert!(response.starts_with(b"HTTP/1.1 101"));
        peer.write_all(b"\0\xff\r\n").await.unwrap();
        let mut echoed = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), peer.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"\0\xff\r\n");
        finished.await.unwrap();
        server.await.unwrap();
    }
}
