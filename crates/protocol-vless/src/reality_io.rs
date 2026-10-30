//! 将固定 REALITY 记录原语适配为核心异步流，并按方向保留 Direct 转换。
use kerlico_core::{BoxFuture, BoxStream};
use rust_reality::protocol::reality::tls13::{
    TlsApplicationIo, TlsApplicationIoError, TlsApplicationReader, TlsApplicationWriter,
    TlsRecordReadErrorKind,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use xray_transport::TransportStream;
type Reader = TlsApplicationReader<ReadHalf<BoxStream>>;
type Writer = TlsApplicationWriter<WriteHalf<BoxStream>>;
enum Reading {
    Ready(Option<Reader>),
    Busy(BoxFuture<'static, (Reader, io::Result<Vec<u8>>)>),
    Raw {
        prefix: Vec<u8>,
        position: usize,
        inner: ReadHalf<BoxStream>,
    },
    Failed,
}
enum Writing {
    Ready(Option<Writer>),
    Busy(BoxFuture<'static, (Writer, io::Result<usize>)>),
    Raw(WriteHalf<BoxStream>),
    Failed,
}
pub(crate) struct RealityIo {
    read: Reading,
    write: Writing,
    pending: Vec<u8>,
    position: usize,
    timeout: Duration,
    direct_read: bool,
    direct_write: bool,
    closing: bool,
    closed: bool,
    eof: bool,
}
fn failure() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "REALITY 记录处理失败")
}
impl RealityIo {
    pub fn new(io: TlsApplicationIo<BoxStream>, timeout: Duration) -> Self {
        let (reader, writer) = io.into_split();
        Self {
            read: Reading::Ready(Some(reader)),
            write: Writing::Ready(Some(writer)),
            pending: Vec::new(),
            position: 0,
            timeout,
            direct_read: false,
            direct_write: false,
            closing: false,
            closed: false,
            eof: false,
        }
    }
    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if let Writing::Busy(future) = &mut self.write {
            match future.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready((writer, result)) => {
                    self.write = Writing::Ready(Some(writer));
                    if result.is_err() {
                        self.write = Writing::Failed;
                    }
                    Poll::Ready(result)
                }
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }
}
impl AsyncRead for RealityIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.position < this.pending.len() {
                let n = (this.pending.len() - this.position).min(out.remaining());
                out.put_slice(&this.pending[this.position..this.position + n]);
                this.position += n;
                return Poll::Ready(Ok(()));
            }
            match &mut this.read {
                Reading::Ready(slot) => {
                    let Some(reader) = slot.take() else {
                        return Poll::Ready(Err(failure()));
                    };
                    if this.direct_read {
                        let (prefix, inner) = reader.into_inner_with_pending();
                        this.read = Reading::Raw {
                            prefix,
                            position: 0,
                            inner,
                        };
                        continue;
                    }
                    let timeout = this.timeout;
                    this.read = Reading::Busy(Box::pin(async move {
                        let mut reader = reader;
                        let result = match reader.read_application(timeout).await {
                            Ok(record) => Ok(record.plaintext().to_vec()),
                            Err(TlsApplicationIoError::PeerAlert { description: 0, .. }) => {
                                Ok(Vec::new())
                            }
                            Err(TlsApplicationIoError::Read(error))
                                if matches!(
                                    error.kind(),
                                    TlsRecordReadErrorKind::UnexpectedEof
                                ) && error.wire_prefix().is_empty() =>
                            {
                                Ok(Vec::new())
                            }
                            Err(_) => Err(failure()),
                        };
                        (reader, result)
                    }));
                }
                Reading::Busy(future) => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready((reader, Ok(bytes))) => {
                        this.read = Reading::Ready(Some(reader));
                        if bytes.is_empty() {
                            this.eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        this.pending = bytes;
                        this.position = 0;
                    }
                    Poll::Ready((_, Err(error))) => {
                        this.read = Reading::Failed;
                        return Poll::Ready(Err(error));
                    }
                },
                Reading::Raw {
                    prefix,
                    position,
                    inner,
                } => {
                    if *position < prefix.len() {
                        let n = (prefix.len() - *position).min(out.remaining());
                        out.put_slice(&prefix[*position..*position + n]);
                        *position += n;
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(inner).poll_read(cx, out);
                }
                Reading::Failed => return Poll::Ready(Err(failure())),
            }
        }
    }
}
impl AsyncWrite for RealityIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.closing {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "REALITY 写端已关闭",
            )));
        }
        if matches!(this.write, Writing::Busy(_)) {
            return this.poll_write_pending(cx);
        }
        if let Writing::Raw(inner) = &mut this.write {
            return Pin::new(inner).poll_write(cx, input);
        }
        let state = std::mem::replace(&mut this.write, Writing::Failed);
        let writer = match state {
            Writing::Ready(Some(writer)) => writer,
            _ => return Poll::Ready(Err(failure())),
        };
        if this.direct_write {
            this.write = Writing::Raw(writer.into_inner());
            if let Writing::Raw(inner) = &mut this.write {
                return Pin::new(inner).poll_write(cx, input);
            }
            return Poll::Ready(Err(failure()));
        }
        let bytes = input[..input.len().min(16 * 1024)].to_vec();
        let size = bytes.len();
        if size == 0 {
            this.write = Writing::Ready(Some(writer));
            return Poll::Ready(Ok(0));
        }
        let timeout = this.timeout;
        this.write = Writing::Busy(Box::pin(async move {
            let mut writer = writer;
            let result = writer
                .write_application(&bytes, timeout)
                .await
                .map(|_| size)
                .map_err(|_| failure());
            (writer, result)
        }));
        this.poll_write_pending(cx)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_write_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            _ => match &mut this.write {
                Writing::Raw(inner) => Pin::new(inner).poll_flush(cx),
                Writing::Failed => Poll::Ready(Err(failure())),
                _ => Poll::Ready(Ok(())),
            },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        if !this.closing {
            match this.poll_write_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                _ => {}
            }
            match &mut this.write {
                Writing::Ready(slot) => {
                    let Some(mut writer) = slot.take() else {
                        return Poll::Ready(Err(failure()));
                    };
                    let timeout = this.timeout;
                    this.write = Writing::Busy(Box::pin(async move {
                        let result = writer
                            .shutdown(timeout)
                            .await
                            .map(|_| 0)
                            .map_err(|_| failure());
                        (writer, result)
                    }));
                }
                Writing::Raw(_) => {}
                _ => return Poll::Ready(Err(failure())),
            }
            this.closing = true;
        }
        let result = if let Writing::Raw(inner) = &mut this.write {
            Pin::new(inner).poll_shutdown(cx)
        } else {
            this.poll_write_pending(cx).map_ok(|_| ())
        };
        if matches!(result, Poll::Ready(Ok(()))) {
            this.closed = true;
        }
        result
    }
}
impl TransportStream for RealityIo {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.direct_read = true;
        AsyncRead::poll_read(Pin::new(this), cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.direct_write = true;
        AsyncWrite::poll_write(Pin::new(this), cx, input)
    }
    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}
