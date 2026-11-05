use crate::telemetry::FlowLease;
use kerlico_core::{
    AddressedDatagram, BoxFuture, BoxStream, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, DatagramChannel, DatagramReceiver, DatagramSender, Destination,
    Result,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) fn stream(inner: BoxStream, lease: FlowLease) -> BoxStream {
    kerlico_core::SpliceBox::boxed(MeteredStream {
        inner,
        lease,
        read_cancel: None,
        write_cancel: None,
    })
}
struct MeteredStream {
    inner: BoxStream,
    lease: FlowLease,
    read_cancel: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    write_cancel: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}
impl MeteredStream {
    fn aborted(lease: &FlowLease) -> io::Error {
        let error = lease.cancellation_error();
        lease.failed(&error);
        io::Error::new(io::ErrorKind::ConnectionAborted, error)
    }
    fn poll_cancel(
        cancel: &mut Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
        lease: &FlowLease,
        cx: &mut Context<'_>,
    ) -> io::Result<()> {
        let fut = cancel.get_or_insert_with(|| {
            let lease = lease.clone();
            Box::pin(async move { lease.cancelled().await })
        });
        if fut.as_mut().poll(cx).is_ready() {
            *cancel = None;
            Err(Self::aborted(lease))
        } else {
            Ok(())
        }
    }
}
impl AsyncRead for MeteredStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&this.lease)));
        }
        let before = buffer.filled().len();
        let had_capacity = buffer.remaining() > 0;
        match Pin::new(&mut this.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                let read = buffer.filled().len() - before;
                this.lease.ledger().download(read, false);
                if read == 0 && had_capacity {
                    this.lease.download_closed();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut this.read_cancel, &this.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
}
impl AsyncWrite for MeteredStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&this.lease)));
        }
        match Pin::new(&mut this.inner).poll_write(cx, bytes) {
            Poll::Ready(Ok(count)) => {
                this.lease.ledger().upload(count, false);
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => {
                this.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut this.write_cancel, &this.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&this.lease)));
        }
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(count)) => {
                this.lease.ledger().upload(count, false);
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => {
                this.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut this.write_cancel, &this.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&this.lease)));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                this.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut this.write_cancel, &this.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&this.lease)));
        }
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.lease.upload_closed();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut this.write_cancel, &this.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
}
impl kerlico_core::SpliceIo for MeteredStream {
    fn supports_splice(&self) -> bool {
        kerlico_core::stream_supports_splice(self.inner.as_ref())
    }
    #[cfg(target_os = "linux")]
    fn poll_splice_to_pipe(
        &mut self,
        cx: &mut Context<'_>,
        pipe_wr: std::os::fd::BorrowedFd<'_>,
        max_len: usize,
    ) -> Poll<io::Result<usize>> {
        if self.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&self.lease)));
        }
        let Some(inner) = kerlico_core::as_splice_io(self.inner.as_mut()) else {
            return Poll::Ready(Err(io::ErrorKind::Unsupported.into()));
        };
        match inner.poll_splice_to_pipe(cx, pipe_wr, max_len) {
            Poll::Ready(Ok(read)) => {
                self.lease.ledger().download(read, false);
                if read == 0 && max_len > 0 {
                    self.lease.download_closed();
                }
                Poll::Ready(Ok(read))
            }
            Poll::Ready(Err(error)) => {
                self.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut self.read_cancel, &self.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
    #[cfg(target_os = "linux")]
    fn poll_splice_from_pipe(
        &mut self,
        cx: &mut Context<'_>,
        pipe_rd: std::os::fd::BorrowedFd<'_>,
        max_len: usize,
    ) -> Poll<io::Result<usize>> {
        if self.lease.is_cancelled() {
            return Poll::Ready(Err(Self::aborted(&self.lease)));
        }
        let Some(inner) = kerlico_core::as_splice_io(self.inner.as_mut()) else {
            return Poll::Ready(Err(io::ErrorKind::Unsupported.into()));
        };
        match inner.poll_splice_from_pipe(cx, pipe_rd, max_len) {
            Poll::Ready(Ok(count)) => {
                self.lease.ledger().upload(count, false);
                Poll::Ready(Ok(count))
            }
            Poll::Ready(Err(error)) => {
                self.lease.io_failed(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => match Self::poll_cancel(&mut self.write_cancel, &self.lease, cx) {
                Ok(()) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
        }
    }
}

pub(crate) fn fixed(channel: DatagramChannel, lease: FlowLease) -> DatagramChannel {
    DatagramChannel {
        sender: Box::new(FixedSender {
            inner: channel.sender,
            lease: lease.clone(),
        }),
        receiver: Box::new(FixedReceiver {
            inner: channel.receiver,
            lease,
        }),
    }
}
struct FixedSender {
    inner: Box<dyn DatagramSender>,
    lease: FlowLease,
}
struct FixedReceiver {
    inner: Box<dyn DatagramReceiver>,
    lease: FlowLease,
}
impl DatagramSender for FixedSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let result = tokio::select! {biased;_=self.lease.cancelled()=>Err(self.lease.cancellation_error()),result=self.inner.send(packet)=>result};
            match &result {
                Ok(()) => self.lease.ledger().upload(packet.len(), true),
                Err(error) => self.lease.failed(error),
            }
            result
        })
    }
}
impl DatagramReceiver for FixedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        self.inner.peer_addr()
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let result = tokio::select! {biased;_=self.lease.cancelled()=>Err(self.lease.cancellation_error()),result=self.inner.recv()=>result};
            match &result {
                Ok(Some(packet)) => self.lease.ledger().download(packet.len(), true),
                Ok(None) => self.lease.download_closed(),
                Err(error) => self.lease.failed(error),
            }
            result
        })
    }
}

pub(crate) fn association(channel: DatagramAssociation, lease: FlowLease) -> DatagramAssociation {
    DatagramAssociation {
        sender: Box::new(AssociationSender {
            inner: channel.sender,
            lease: lease.clone(),
        }),
        receiver: Box::new(AssociationReceiver {
            inner: channel.receiver,
            lease,
        }),
    }
}
struct AssociationSender {
    inner: Box<dyn DatagramAssociationSender>,
    lease: FlowLease,
}
struct AssociationReceiver {
    inner: Box<dyn DatagramAssociationReceiver>,
    lease: FlowLease,
}
impl DatagramAssociationSender for AssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let result = tokio::select! {biased;_=self.lease.cancelled()=>Err(self.lease.cancellation_error()),result=self.inner.send_to(packet,target)=>result};
            self.lease.ledger().datagram_target(
                target,
                None,
                result.as_ref().ok().map(|_| packet.len()),
            );
            match &result {
                Ok(()) => self.lease.ledger().upload(packet.len(), true),
                Err(error) => self.lease.failed(error),
            }
            result
        })
    }
}
impl DatagramAssociationReceiver for AssociationReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            let result = tokio::select! {biased;_=self.lease.cancelled()=>Err(self.lease.cancellation_error()),result=self.inner.recv_from()=>result};
            match &result {
                Ok(Some((_, packet))) => self.lease.ledger().download(packet.len(), true),
                Ok(None) => self.lease.download_closed(),
                Err(error) => self.lease.failed(error),
            }
            result
        })
    }
}
