//! 写入不等待、首次读取时才解析的流响应头。
//!
//! sing-quic 与 sing-mux 服务端（Mihomo、sing-box）在目标第一次回写数据时才发送流响应头。
//! 客户端若先等响应再转发数据，HTTP 这类客户端先发的协议会与服务端互相等待。

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 解析缓冲区开头的响应头：完整时返回头长度，不完整时返回 `None`，拒绝或格式错误时返回错误。
pub type Parse = fn(&[u8]) -> io::Result<Option<usize>>;

pub struct LazyResponse<S> {
    inner: S,
    parse: Option<Parse>,
    buffer: Vec<u8>,
    position: usize,
}

impl<S> LazyResponse<S> {
    pub fn new(inner: S, parse: Parse) -> Self {
        Self {
            inner,
            parse: Some(parse),
            buffer: Vec::new(),
            position: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LazyResponse<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while let Some(parse) = this.parse {
            let mut chunk = [0u8; 2048];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "对端在流响应头之前关闭",
                )));
            }
            this.buffer.extend_from_slice(read.filled());
            if let Some(length) = parse(&this.buffer)? {
                this.parse = None;
                this.position = length;
            }
        }
        if this.position < this.buffer.len() {
            let count = output.remaining().min(this.buffer.len() - this.position);
            output.put_slice(&this.buffer[this.position..this.position + count]);
            this.position += count;
            if this.position == this.buffer.len() {
                this.buffer = Vec::new();
                this.position = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, output)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for LazyResponse<S> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn two_byte_header(input: &[u8]) -> io::Result<Option<usize>> {
        match input {
            [] | [_] => Ok(None),
            [0, _, ..] => Ok(Some(2)),
            _ => Err(io::Error::new(io::ErrorKind::ConnectionRefused, "拒绝")),
        }
    }

    #[tokio::test]
    async fn writes_before_response_and_strips_split_header() {
        let (client, mut server) = duplex(64);
        let mut stream = LazyResponse::new(client, two_byte_header);
        stream.write_all(b"GET").await.unwrap();
        let mut request = [0u8; 3];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");
        server.write_all(&[0]).await.unwrap();
        server.write_all(&[9, b'o', b'k']).await.unwrap();
        drop(server);
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn rejected_header_fails_first_read() {
        let (client, mut server) = duplex(64);
        let mut stream = LazyResponse::new(client, two_byte_header);
        server.write_all(&[1, 0]).await.unwrap();
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[tokio::test]
    async fn eof_before_header_is_an_error() {
        let (client, server) = duplex(64);
        drop(server);
        let mut stream = LazyResponse::new(client, two_byte_header);
        let error = stream.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
}
