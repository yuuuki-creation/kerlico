//! 将固定 REALITY 记录原语适配为核心异步流，并按方向保留 Direct 转换。
use kerlico_core::{BoxFuture, BoxStream};
use rust_reality::protocol::reality::tls13::{
    ApplicationRead, TlsApplicationIo, TlsApplicationIoError, TlsApplicationReader,
    TlsApplicationWriter, TlsRecordReadErrorKind,
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
    Tls(Reader),
    Raw {
        prefix: Vec<u8>,
        position: usize,
        inner: ReadHalf<BoxStream>,
    },
    Failed,
}
enum Writing {
    Tls(Writer),
    Shutting(BoxFuture<'static, io::Result<()>>),
    Raw(WriteHalf<BoxStream>),
    Failed,
}
pub(crate) struct RealityIo {
    read: Reading,
    write: Writing,
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
fn clean_eof(error: &TlsApplicationIoError) -> bool {
    match error {
        TlsApplicationIoError::PeerAlert { description: 0, .. } => true,
        TlsApplicationIoError::Read(error)
            if matches!(error.kind(), TlsRecordReadErrorKind::UnexpectedEof)
                && error.wire_prefix().is_empty() =>
        {
            true
        }
        _ => false,
    }
}
impl RealityIo {
    pub fn new(io: TlsApplicationIo<BoxStream>, timeout: Duration) -> Self {
        let (reader, writer) = io.into_split();
        Self {
            read: Reading::Tls(reader),
            write: Writing::Tls(writer),
            timeout,
            direct_read: false,
            direct_write: false,
            closing: false,
            closed: false,
            eof: false,
        }
    }
    fn take_reader(&mut self) -> io::Result<Reader> {
        match std::mem::replace(&mut self.read, Reading::Failed) {
            Reading::Tls(reader) => Ok(reader),
            _ => Err(failure()),
        }
    }
    fn take_writer(&mut self) -> io::Result<Writer> {
        match std::mem::replace(&mut self.write, Writing::Failed) {
            Writing::Tls(writer) => Ok(writer),
            _ => Err(failure()),
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
        let started = out.filled().len();
        loop {
            if this.direct_read
                && matches!(&this.read, Reading::Tls(reader) if !reader.has_pending_plain())
            {
                let reader = match this.take_reader() {
                    Ok(reader) => reader,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                let (prefix, inner) = reader.into_inner_with_pending();
                this.read = Reading::Raw {
                    prefix,
                    position: 0,
                    inner,
                };
                continue;
            }
            match &mut this.read {
                Reading::Tls(reader) => {
                    let before = out.filled().len();
                    match reader.poll_copy_application(cx, out, this.timeout) {
                        Poll::Pending => {
                            if out.filled().len() > started {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(ApplicationRead::Eof)) => {
                            this.eof = true;
                            if out.filled().len() > started {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Ok(ApplicationRead::Bytes(_))) => {
                            if out.filled().len() == before || out.remaining() == 0 {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Poll::Ready(Err(error)) if clean_eof(&error) => {
                            this.eof = true;
                            if out.filled().len() > started {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(_)) => {
                            this.read = Reading::Failed;
                            if out.filled().len() > started {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(failure()));
                        }
                    }
                }
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
                    if out.filled().len() > started {
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
        if let Writing::Raw(inner) = &mut this.write {
            return Pin::new(inner).poll_write(cx, input);
        }
        if this.direct_write
            && matches!(&this.write, Writing::Tls(writer) if writer.is_write_idle())
        {
            let writer = match this.take_writer() {
                Ok(writer) => writer,
                Err(error) => return Poll::Ready(Err(error)),
            };
            this.write = Writing::Raw(writer.into_inner());
            if let Writing::Raw(inner) = &mut this.write {
                return Pin::new(inner).poll_write(cx, input);
            }
            return Poll::Ready(Err(failure()));
        }
        let Writing::Tls(writer) = &mut this.write else {
            return Poll::Ready(Err(failure()));
        };
        match writer.poll_write_application(cx, input, this.timeout) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(_)) => {
                this.write = Writing::Failed;
                Poll::Ready(Err(failure()))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.write {
            Writing::Raw(inner) => Pin::new(inner).poll_flush(cx),
            Writing::Failed => Poll::Ready(Err(failure())),
            Writing::Tls(_) | Writing::Shutting(_) => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        if !this.closing {
            match &this.write {
                Writing::Tls(writer) if writer.is_write_idle() => {
                    let mut writer = match this.take_writer() {
                        Ok(writer) => writer,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    let timeout = this.timeout;
                    this.write = Writing::Shutting(Box::pin(async move {
                        writer.shutdown(timeout).await.map_err(|_| failure())
                    }));
                }
                Writing::Raw(_) => {}
                _ => return Poll::Ready(Err(failure())),
            }
            this.closing = true;
        }
        let result = match &mut this.write {
            Writing::Raw(inner) => Pin::new(inner).poll_shutdown(cx),
            Writing::Shutting(future) => future.as_mut().poll(cx),
            _ => Poll::Ready(Err(failure())),
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
