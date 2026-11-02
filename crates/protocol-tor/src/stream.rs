use crate::{error::{cancelled, sanitized_io}, runtime::TaskOwner, storage::StateLease};
use kerlico_core::{BoxFuture, ConnectContext, Error};
use std::{io, pin::Pin, sync::Arc, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Cancellation {
    waiting: BoxFuture<'static, ()>,
    stopped: bool,
}
impl Cancellation {
    fn new(owner: &TaskOwner, context: &ConnectContext) -> Self {
        let service = owner.cancel();
        let request = context.cancel.clone();
        let node = context.node_cancel();
        let peer = context.peer_cancel();
        let context_service = context.service_cancel();
        Self {
            stopped: false,
            waiting: Box::pin(async move {
                tokio::select! {
                    biased;
                    _ = service.cancelled() => {}
                    _ = request.cancelled() => {}
                    _ = node.cancelled() => {}
                    _ = peer.cancelled() => {}
                    _ = context_service.cancelled() => {}
                }
            }),
        }
    }
    fn poll(&mut self, owner: &TaskOwner, cx: &mut Context<'_>) -> io::Result<()> {
        owner.check().map_err(|error| io::Error::new(io::ErrorKind::ConnectionAborted, error))?;
        if self.stopped || self.waiting.as_mut().poll(cx).is_ready() {
            self.stopped = true;
            match owner.check() {
                Err(Error::Cancelled) | Ok(()) => Err(cancelled()),
                Err(error) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, error)),
            }
        } else {
            Ok(())
        }
    }
}

pub(crate) struct TorStream<S> {
    stream: S,
    owner: TaskOwner,
    _storage: Arc<StateLease>,
    read_cancel: Cancellation,
    write_cancel: Cancellation,
}
impl<S> TorStream<S> {
    pub fn new(stream: S, owner: TaskOwner, storage: Arc<StateLease>, context: &ConnectContext) -> Self {
        Self {
            stream,
            read_cancel: Cancellation::new(&owner, context),
            write_cancel: Cancellation::new(&owner, context),
            owner,
            _storage: storage,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for TorStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.read_cancel.poll(&this.owner, cx)?;
        Pin::new(&mut this.stream).poll_read(cx, bytes).map_err(sanitized_io)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for TorStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_cancel.poll(&this.owner, cx)?;
        Pin::new(&mut this.stream).poll_write(cx, bytes).map_err(sanitized_io)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_cancel.poll(&this.owner, cx)?;
        Pin::new(&mut this.stream).poll_flush(cx).map_err(sanitized_io)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_cancel.poll(&this.owner, cx)?;
        Pin::new(&mut this.stream).poll_shutdown(cx).map_err(sanitized_io)
    }
}
