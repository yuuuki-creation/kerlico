//! 所有 QUIC 后台任务归属节点/连接；回退 socket 不启用 GRO，保留完整 UDP 包。
use jls_quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpSender};
use kerlico_core::CancellationToken;
use std::{
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{io::ReadBuf, net::UdpSocket, task::JoinSet};
pub(crate) struct ScopedRuntime {
    inner: jls_quinn::TokioRuntime,
    cancel: CancellationToken,
    tasks: Mutex<JoinSet<()>>,
    main: AtomicBool,
}
impl ScopedRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: jls_quinn::TokioRuntime,
            cancel: CancellationToken::new(),
            tasks: Mutex::new(JoinSet::new()),
            main: AtomicBool::new(true),
        })
    }
    pub fn stop(&self) {
        self.cancel.cancel();
        if let Ok(mut tasks) = self.tasks.lock() {
            tasks.abort_all();
        }
    }
    pub async fn shutdown(&self) {
        self.stop();
        let mut tasks = if let Ok(mut tasks) = self.tasks.lock() {
            std::mem::take(&mut *tasks)
        } else {
            return;
        };
        while tasks.join_next().await.is_some() {}
    }
}
impl fmt::Debug for ScopedRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopedRuntime")
    }
}
impl Runtime for ScopedRuntime {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(instant)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        if self.cancel.is_cancelled() {
            return;
        }
        let cancel = self.cancel.clone();
        if let Ok(mut tasks) = self.tasks.lock() {
            while tasks.try_join_next().is_some() {}
            tasks.spawn(async move {
                tokio::select! {biased;_=cancel.cancelled()=>{},_=future=>{}}
            });
        }
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        if self.main.swap(false, Ordering::AcqRel) {
            return self.inner.wrap_udp_socket(socket);
        }
        socket.set_nonblocking(true)?;
        Ok(Box::new(PlainSocket(Arc::new(UdpSocket::from_std(
            socket,
        )?))))
    }
}
pub(crate) struct RuntimeGuard {
    runtime: Arc<ScopedRuntime>,
    armed: bool,
}
impl RuntimeGuard {
    pub fn new(runtime: Arc<ScopedRuntime>) -> Self {
        Self {
            runtime,
            armed: true,
        }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for RuntimeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.runtime.stop();
        }
    }
}
struct PlainSocket(Arc<UdpSocket>);
impl fmt::Debug for PlainSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JlsForwardSocket")
    }
}
impl AsyncUdpSocket for PlainSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(PlainSender {
            socket: self.0.clone(),
            position: 0,
            writable: None,
        })
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [jls_quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let mut buffer = ReadBuf::new(&mut buffers[0]);
        let source = ready!(self.0.poll_recv_from(cx, &mut buffer))?;
        let count = buffer.filled().len();
        meta[0] = jls_quinn::udp::RecvMeta::default();
        meta[0].addr = source;
        meta[0].len = count;
        meta[0].stride = count.max(1);
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }
}
struct PlainSender {
    socket: Arc<UdpSocket>,
    position: usize,
    writable: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}
impl fmt::Debug for PlainSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JlsForwardSender")
    }
}
impl UdpSender for PlainSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &jls_quinn::udp::Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let size = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        while this.position < transmit.contents.len() {
            if this.writable.is_none() {
                let socket = this.socket.clone();
                this.writable = Some(Box::pin(async move { socket.writable().await }));
            }
            ready!(
                this.writable
                    .as_mut()
                    .expect("发送就绪状态存在")
                    .as_mut()
                    .poll(cx)
            )?;
            this.writable = None;
            let end = (this.position + size).min(transmit.contents.len());
            match this
                .socket
                .try_send_to(&transmit.contents[this.position..end], transmit.destination)
            {
                Ok(count) if count == end - this.position => this.position = end,
                Ok(_) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        this.position = 0;
        Poll::Ready(Ok(()))
    }
}
