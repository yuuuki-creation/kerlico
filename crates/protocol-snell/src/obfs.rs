//! HTTP obfs 只剥离一次头部；它不是 TLS，也不承载 WebSocket 帧。
use crate::{
    config::{Obfs, Settings},
    io_protocol,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::BoxStream;
use rand::RngCore;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
struct Head {
    inner: BoxStream,
    pending: bool,
    matched: usize,
    length: usize,
}
impl AsyncRead for Head {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while this.pending {
            let mut byte = [0];
            let mut buffer = ReadBuf::new(&mut byte);
            match Pin::new(&mut this.inner).poll_read(cx, &mut buffer) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if buffer.filled().is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.length += 1;
                    if this.length > 16384 {
                        return Poll::Ready(Err(io_protocol()));
                    }
                    let value = byte[0];
                    if value == b"\r\n\r\n"[this.matched] {
                        this.matched += 1;
                    } else {
                        this.matched = usize::from(value == b'\r');
                    }
                    if this.matched == 4 {
                        this.pending = false;
                    }
                }
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}
impl AsyncWrite for Head {
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
}
pub(crate) async fn wrap(
    mut stream: BoxStream,
    settings: &Settings,
    server: bool,
) -> io::Result<BoxStream> {
    if settings.obfs == Obfs::None {
        return Ok(stream);
    }
    let mut random = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let key = STANDARD.encode(random);
    let header = if server {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {key}\r\n\r\n"
        )
    } else {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
            settings.uri, settings.host
        )
    };
    stream.write_all(header.as_bytes()).await?;
    stream.flush().await?;
    Ok(Box::new(Head {
        inner: stream,
        pending: true,
        matched: 0,
        length: 0,
    }))
}
