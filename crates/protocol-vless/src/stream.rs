use crate::codec::{VERSION, validate_addons};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 请求头发送后使用的流：首次读取时才处理响应头，写入不等待响应。
pub struct VlessStream<S> {
    inner: S,
    header: [u8; 257],
    received: usize,
    required: usize,
    ready: bool,
    failed: bool,
    write_closed: bool,
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 257],
            received: 0,
            required: 2,
            ready: false,
            failed: false,
            write_closed: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS 响应头已失败",
            )));
        }
        while !this.ready {
            if this.received < this.required {
                let mut target = ReadBuf::new(&mut this.header[this.received..this.required]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut target) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.failed = true;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => {
                        let count = target.filled().len();
                        if count == 0 {
                            this.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "VLESS 响应头被截断",
                            )));
                        }
                        this.received += count;
                    }
                }
                continue;
            }
            if this.header[0] != VERSION {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS 响应版本不匹配",
                )));
            }
            let total = 2 + this.header[1] as usize;
            if this.required != total {
                this.required = total;
                continue;
            }
            if validate_addons(&this.header[2..total]).is_err() {
                this.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "VLESS 响应附加信息不支持",
                )));
            }
            this.ready = true;
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS 响应头已失败",
            )));
        }
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "VLESS 写端已关闭",
            )));
        }
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS 响应头已失败",
            )));
        }
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VLESS 响应头已失败",
            )));
        }
        // 普通 VLESS 没有独立的请求 EOF 帧；保留载体等待反向响应。
        this.write_closed = true;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}
