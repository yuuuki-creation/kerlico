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
    let read_cancel = lease.clone();
    let write_cancel = lease.clone();
    Box::new(MeteredStream {
        inner,
        lease,
        read_cancel: Some(Box::pin(async move { read_cancel.cancelled().await })),
        write_cancel: Some(Box::pin(async move { write_cancel.cancelled().await })),
    })
}
struct MeteredStream {
    inner: BoxStream,
    lease: FlowLease,
    read_cancel: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    write_cancel: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}
impl MeteredStream {
    fn check(
        cancel: &mut Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
        lease: &FlowLease,
        cx: &mut Context<'_>,
    ) -> io::Result<()> {
        if cancel
            .as_mut()
            .is_some_and(|cancel| cancel.as_mut().poll(cx).is_ready())
        {
            *cancel = None;
        }
        if cancel.is_none() {
            let error = lease.cancellation_error();
            lease.failed(&error);
            Err(io::Error::new(io::ErrorKind::ConnectionAborted, error))
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
        if let Err(error) = Self::check(&mut this.read_cancel, &this.lease, cx) {
            return Poll::Ready(Err(error));
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
            Poll::Pending => Poll::Pending,
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
        if let Err(error) = Self::check(&mut this.write_cancel, &this.lease, cx) {
            return Poll::Ready(Err(error));
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
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = Self::check(&mut this.write_cancel, &this.lease, cx) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if let Poll::Ready(Err(error)) = &result {
            this.lease.io_failed(error);
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = Self::check(&mut this.write_cancel, &this.lease, cx) {
            return Poll::Ready(Err(error));
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
            Poll::Pending => Poll::Pending,
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
