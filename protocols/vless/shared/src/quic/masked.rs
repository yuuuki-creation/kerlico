use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::finalmask::PacketIo;

struct Packet { bytes: Vec<u8>, peer: SocketAddr }

pub(super) struct MaskedSocket {
    local: SocketAddr,
    outgoing: mpsc::Sender<Packet>,
    incoming: Mutex<mpsc::Receiver<io::Result<Packet>>>,
    closed: Arc<AtomicBool>,
}

impl MaskedSocket {
    pub(super) fn new(socket: Arc<dyn PacketIo>) -> io::Result<Arc<Self>> {
        let local = socket.local_addr()?;
        let (outgoing, mut send) = mpsc::channel::<Packet>(256);
        let (received, incoming) = mpsc::channel(256);
        let closed = Arc::new(AtomicBool::new(false));
        let writer = socket.clone();
        let write_closed = closed.clone();
        let errors = received.clone();
        std::thread::spawn(move || {
            while let Some(packet) = send.blocking_recv() {
                loop {
                    if write_closed.load(Ordering::Acquire) { return; }
                    let result = writer.send_to(&packet.bytes, packet.peer);
                    match result {
                        Ok(n) if n == packet.bytes.len() => break,
                        Err(error) if retryable(&error) => std::thread::sleep(Duration::from_millis(1)),
                        result => {
                            let error = result.err().unwrap_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "short masked datagram"));
                            let _ = errors.blocking_send(Err(error));
                            write_closed.store(true, Ordering::Release);
                            return;
                        }
                    }
                }
            }
        });
        let read_closed = closed.clone();
        std::thread::spawn(move || {
            let mut bytes = vec![0; u16::MAX as usize];
            while !read_closed.load(Ordering::Acquire) {
                match socket.recv_from(&mut bytes) {
                    Ok((n, peer)) => {
                        if received.blocking_send(Ok(Packet { bytes: bytes[..n].to_vec(), peer })).is_err() { return; }
                    }
                    Err(error) if retryable(&error) => {},
                    Err(error) => {
                        let _ = received.blocking_send(Err(error));
                        read_closed.store(true, Ordering::Release);
                        return;
                    }
                }
            }
        });
        Ok(Arc::new(Self { local, outgoing, incoming: Mutex::new(incoming), closed }))
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted)
}

impl fmt::Debug for MaskedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("MaskedSocket").field("local", &self.local).finish_non_exhaustive() }
}

impl Drop for MaskedSocket {
    fn drop(&mut self) { self.closed.store(true, Ordering::Release); }
}

impl AsyncUdpSocket for MaskedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable { socket: self, waiting: Mutex::new(None) })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) { return Err(io::ErrorKind::BrokenPipe.into()); }
        if transmit.segment_size.is_some_and(|size| size < transmit.contents.len()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "masked UDP requires individual datagrams"));
        }
        self.outgoing.try_send(Packet { bytes: transmit.contents.to_vec(), peer: transmit.destination }).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock.into(),
            mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
        })
    }

    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() { return Poll::Ready(Ok(0)); }
        match self.incoming.lock().expect("masked UDP").poll_recv(cx) {
            Poll::Ready(Some(Ok(packet))) => {
                if packet.bytes.len() > bufs[0].len() { return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "masked datagram exceeds receive buffer"))); }
                bufs[0][..packet.bytes.len()].copy_from_slice(&packet.bytes);
                meta[0] = RecvMeta { addr: packet.peer, len: packet.bytes.len(), stride: packet.bytes.len(), ecn: None, dst_ip: (!self.local.ip().is_unspecified()).then_some(self.local.ip()) };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> { Ok(self.local) }
}

type Wait = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
struct Writable { socket: Arc<MaskedSocket>, waiting: Mutex<Option<Wait>> }

impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("MaskedWritable").finish_non_exhaustive() }
}

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.socket.closed.load(Ordering::Acquire) { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        let waiting = this.waiting.get_mut().expect("masked UDP writable");
        if waiting.is_none() {
            let sender = this.socket.outgoing.clone();
            *waiting = Some(Box::pin(async move { let _permit = sender.reserve().await.map_err(|_| io::ErrorKind::BrokenPipe)?; Ok(()) }));
        }
        let result = waiting.as_mut().expect("masked UDP wait").as_mut().poll(cx);
        if result.is_ready() { *waiting = None; }
        result
    }
}
