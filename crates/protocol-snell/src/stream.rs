//! 记录流保留半关闭，只有双向排空的载体才进入本节点复用池。
use crate::{
    config::Settings,
    io_protocol,
    record::{Reader, Writer},
    wire,
};
use kerlico_core::{BoxFuture, BoxStream};
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, WriteHalf};
pub(crate) struct Session {
    pub reader: Reader,
    pub writer: Writer,
    pub output: WriteHalf<BoxStream>,
}
impl Session {
    pub fn new(stream: BoxStream, settings: Arc<Settings>) -> io::Result<Self> {
        let (reader, output) = tokio::io::split(stream);
        Ok(Self {
            reader: Reader::new(reader, settings.clone()),
            writer: Writer::new(settings)?,
            output,
        })
    }
    pub async fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        self.writer.packet_limit();
        let frame = self.writer.frame(payload)?;
        self.output.write_all(&frame).await?;
        self.output.flush().await
    }
}
pub(crate) struct Pool {
    entries: Mutex<VecDeque<(Instant, Session)>>,
    maximum: usize,
    reaper: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Pool {
    pub fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(VecDeque::new()),
            maximum,
            reaper: Mutex::new(None),
        })
    }
    pub fn start(self: &Arc<Self>) {
        let Ok(mut running) = self.reaper.lock() else {
            return;
        };
        if running.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        *running = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                let Some(pool) = weak.upgrade() else {
                    break;
                };
                pool.expire();
            }
        }));
    }
    fn expire(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|(time, _)| time.elapsed() < Duration::from_secs(180));
        }
    }
    pub fn take(&self) -> Option<Session> {
        self.expire();
        self.entries
            .lock()
            .ok()?
            .pop_back()
            .map(|(_, session)| session)
    }
    pub fn put(&self, session: Session) {
        self.expire();
        if let Ok(mut entries) = self.entries.lock()
            && entries.len() < self.maximum
        {
            entries.push_back((Instant::now(), session));
        }
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        if let Ok(handle) = self.reaper.get_mut()
            && let Some(handle) = handle.take()
        {
            handle.abort();
        }
    }
}
type Reading = BoxFuture<'static, (Reader, io::Result<Option<Vec<u8>>>)>;
pub(crate) struct Stream {
    reader: Option<Reader>,
    reading: Option<Reading>,
    writer: Option<Writer>,
    output: Option<WriteHalf<BoxStream>>,
    cached: Vec<u8>,
    position: usize,
    pending: Vec<u8>,
    sent: usize,
    accepted: Option<usize>,
    read_closed: bool,
    write_closed: bool,
    closing: bool,
    failed: bool,
    expect_reply: bool,
    pool: Option<Arc<Pool>>,
    reuse: bool,
}
impl Stream {
    pub fn new(
        session: Session,
        expect_reply: bool,
        cached: Vec<u8>,
        pool: Option<Arc<Pool>>,
        reuse: bool,
    ) -> Self {
        Self {
            reader: Some(session.reader),
            reading: None,
            writer: Some(session.writer),
            output: Some(session.output),
            cached,
            position: 0,
            pending: Vec::new(),
            sent: 0,
            accepted: None,
            read_closed: false,
            write_closed: false,
            closing: false,
            failed: false,
            expect_reply,
            pool,
            reuse,
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(output) = self.output.as_mut() else {
            return Poll::Ready(Err(io_protocol()));
        };
        while self.sent < self.pending.len() {
            match Pin::new(&mut *output).poll_write(cx, &self.pending[self.sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => self.sent += n,
                Poll::Ready(Err(e)) => {
                    self.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.position < this.cached.len() {
                let n = (this.cached.len() - this.position).min(out.remaining());
                out.put_slice(&this.cached[this.position..this.position + n]);
                this.position += n;
                return Poll::Ready(Ok(()));
            }
            this.cached.clear();
            this.position = 0;
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            if this.reading.is_none() {
                let Some(mut reader) = this.reader.take() else {
                    this.failed = true;
                    return Poll::Ready(Err(io_protocol()));
                };
                this.reading = Some(Box::pin(async move {
                    let result = reader.next().await;
                    (reader, result)
                }));
            }
            let Some(future) = this.reading.as_mut() else {
                return Poll::Ready(Err(io_protocol()));
            };
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready((reader, result)) => {
                    this.reader = Some(reader);
                    this.reading = None;
                    match result {
                        Err(error) => {
                            this.failed = true;
                            return Poll::Ready(Err(error));
                        }
                        Ok(None) => {
                            this.read_closed = true;
                            if this.expect_reply {
                                this.failed = true;
                                return Poll::Ready(Err(io_protocol()));
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Ok(Some(bytes)) => {
                            this.cached = if this.expect_reply {
                                this.expect_reply = false;
                                match wire::reply(bytes) {
                                    Ok(bytes) => bytes,
                                    Err(error) => {
                                        this.failed = true;
                                        return Poll::Ready(Err(error));
                                    }
                                }
                            } else {
                                bytes
                            };
                        }
                    }
                }
            }
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing || this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        loop {
            match this.drain(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                _ => {}
            }
            if let Some(n) = this.accepted.take() {
                return Poll::Ready(Ok(n));
            }
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let Some(writer) = this.writer.as_mut() else {
                return Poll::Ready(Err(io_protocol()));
            };
            let n = bytes.len().min(writer.stream_limit()).min(16 * 1024);
            writer.consume(n);
            match writer.frame(&bytes[..n]) {
                Ok(frame) => {
                    this.pending = frame;
                    this.accepted = Some(n);
                }
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        let Some(output) = this.output.as_mut() else {
            return Poll::Ready(Err(io_protocol()));
        };
        let result = Pin::new(output).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed = true;
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        match this.drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        if !this.closing {
            let Some(writer) = this.writer.as_mut() else {
                return Poll::Ready(Err(io_protocol()));
            };
            writer.stream_limit();
            match writer.frame(&[]) {
                Ok(frame) => this.pending = frame,
                Err(error) => {
                    this.failed = true;
                    return Poll::Ready(Err(error));
                }
            }
            this.closing = true;
        }
        match this.drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        let Some(output) = this.output.as_mut() else {
            return Poll::Ready(Err(io_protocol()));
        };
        let result = if this.reuse {
            Pin::new(output).poll_flush(cx)
        } else {
            Pin::new(output).poll_shutdown(cx)
        };
        match &result {
            Poll::Ready(Ok(())) => this.write_closed = true,
            Poll::Ready(Err(_)) => this.failed = true,
            _ => {}
        }
        result
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        if self.failed
            || !self.reuse
            || !self.read_closed
            || !self.write_closed
            || self.reading.is_some()
            || !self.pending.is_empty()
            || self.position < self.cached.len()
            || self
                .reader
                .as_ref()
                .is_some_and(|reader| reader.physical_closed)
        {
            return;
        }
        if let (Some(pool), Some(reader), Some(writer), Some(output)) = (
            &self.pool,
            self.reader.take(),
            self.writer.take(),
            self.output.take(),
        ) {
            pool.put(Session {
                reader,
                writer,
                output,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mode, Obfs};
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn boundary_tcp_eof_finishes_data_but_never_returns_closed_carrier_to_pool() {
        let settings = Arc::new(
            Settings::new(
                6,
                "snell-close-test-key".into(),
                Some(Mode::Unshaped),
                Obfs::None,
                None,
                None,
                false,
            )
            .unwrap(),
        );
        let (a, b) = tokio::io::duplex(65536);
        let session = Session::new(Box::new(a), settings.clone()).unwrap();
        let mut peer = Session::new(Box::new(b), settings).unwrap();
        peer.send(b"\0payload").await.unwrap();
        peer.output.shutdown().await.unwrap();
        let pool = Pool::new(10);
        let mut stream = Stream::new(session, true, Vec::new(), Some(pool.clone()), true);
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"payload");
        drop(stream);
        assert!(pool.take().is_none());
    }
}
