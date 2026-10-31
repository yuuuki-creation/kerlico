//! 显式释放原生 QUIC socket；保留原生 ECN/分段能力，不等后台排空期占住监听端口。
use quinn::{AsyncUdpSocket, Runtime, UdpPoller, udp};
use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
};
struct PollState {
    inner: Option<Pin<Box<dyn UdpPoller>>>,
    wake: Option<Waker>,
}
struct Socket {
    inner: Mutex<Option<Arc<dyn AsyncUdpSocket>>>,
    pollers: Mutex<Vec<Weak<Mutex<PollState>>>>,
    reader: Mutex<Option<Waker>>,
    address: SocketAddr,
    segments: (usize, usize),
    fragment: bool,
}
impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustTunnelUdpSocket")
    }
}
impl Socket {
    fn close(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.take();
        }
        let mut wakes = Vec::new();
        if let Ok(mut pollers) = self.pollers.lock() {
            for weak in pollers.drain(..) {
                if let Some(state) = weak.upgrade()
                    && let Ok(mut state) = state.lock()
                {
                    state.inner.take();
                    if let Some(wake) = state.wake.take() {
                        wakes.push(wake);
                    }
                }
            }
        }
        if let Ok(mut reader) = self.reader.lock()
            && let Some(wake) = reader.take()
        {
            wakes.push(wake);
        }
        for wake in wakes {
            wake.wake();
        }
    }
}
pub(crate) struct Close(Arc<Socket>);
impl Close {
    pub fn close(&self) {
        self.0.close();
    }
}
impl Drop for Close {
    fn drop(&mut self) {
        self.close();
    }
}
struct Poller(Arc<Mutex<PollState>>);
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustTunnelUdpPoller")
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("TrustTunnel UDP 状态不可用"))?;
        state.wake = Some(cx.waker().clone());
        match state.inner.as_mut() {
            Some(inner) => inner.as_mut().poll_writable(cx),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let inner = self.inner.lock().expect("UDP 状态锁未中毒");
        let state = Arc::new(Mutex::new(PollState {
            inner: inner.as_ref().map(|inner| inner.clone().create_io_poller()),
            wake: None,
        }));
        if let Ok(mut pollers) = self.pollers.lock() {
            pollers.retain(|p| p.strong_count() > 0);
            pollers.push(Arc::downgrade(&state));
        }
        Box::pin(Poller(state))
    }
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("TrustTunnel UDP 状态不可用"))?;
        guard
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Ok(mut reader) = self.reader.lock() {
            *reader = Some(cx.waker().clone());
        }
        let guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("TrustTunnel UDP 状态不可用"))?;
        match guard.as_ref() {
            Some(inner) => inner.poll_recv(cx, buffers, metadata),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.address)
    }
    fn max_transmit_segments(&self) -> usize {
        self.segments.0
    }
    fn max_receive_segments(&self) -> usize {
        self.segments.1
    }
    fn may_fragment(&self) -> bool {
        self.fragment
    }
}
pub(crate) fn wrap(socket: UdpSocket) -> io::Result<(Arc<dyn AsyncUdpSocket>, Close)> {
    let inner = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    let socket = Arc::new(Socket {
        address: inner.local_addr()?,
        segments: (inner.max_transmit_segments(), inner.max_receive_segments()),
        fragment: inner.may_fragment(),
        inner: Mutex::new(Some(inner)),
        pollers: Mutex::new(Vec::new()),
        reader: Mutex::new(None),
    });
    let close = Close(socket.clone());
    Ok((socket, close))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn closing_quic_socket_releases_bind_even_when_native_pollers_are_still_owned() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        socket.set_nonblocking(true).unwrap();
        let (socket, close) = wrap(socket).unwrap();
        let poller = socket.clone().create_io_poller();
        assert!(UdpSocket::bind(address).is_err());
        close.close();
        let rebound = UdpSocket::bind(address).unwrap();
        drop(poller);
        drop(socket);
        drop(close);
        drop(rebound);
    }
}
