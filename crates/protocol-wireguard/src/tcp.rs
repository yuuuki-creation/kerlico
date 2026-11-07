use crate::{
    packet::{FlowTuple, rewrite_tcp},
    stack::{FlowScope, SharedStack, TcpEntry, TcpOwner, endpoint},
};
use kerlico_core::{ConnectContext, Error, Result};
use smoltcp::socket::tcp;
use std::{
    future::poll_fn,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct TcpStream {
    stack: Arc<SharedStack>,
    id: u64,
    local: SocketAddr,
    pending: kerlico_core::CancellationToken,
}
impl TcpStream {
    fn allocate(
        stack: Arc<SharedStack>,
        local: SocketAddr,
        remote: SocketAddr,
        scope: FlowScope,
        inbound: Option<(FlowTuple, Vec<u8>)>,
    ) -> Result<Self> {
        let (wire, syn) = inbound.unzip();
        // 入站 SYN 与监听 socket 同在一次加锁内入队：另一任务的轮询若先看到没收到 SYN 的
        // 监听 socket，会把它当作握手失败取消，客户端收到 RST。
        let syn = syn
            .map(|syn| {
                stack
                    .budget
                    .packet(rewrite_tcp(&syn, remote, local)?, false)
            })
            .transpose()?;
        let mut state = stack.lock()?;
        if state.tcp.len() + state.udp.len() >= stack.limits.max_flows {
            return Err(Error::ResourceLimit);
        }
        let tuple = FlowTuple {
            source: local,
            target: remote,
        };
        if state.tuples.contains_key(&tuple)
            || wire.is_some_and(|wire| state.inbound_tcp.contains_key(&wire))
        {
            return Err(Error::Rejected);
        }
        let mut buf_bytes = stack.limits.tcp_buffer_bytes;
        if buf_bytes >= 65536 && buf_bytes.is_power_of_two() {
            buf_bytes -= 1;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; buf_bytes]),
            tcp::SocketBuffer::new(vec![0; buf_bytes]),
        );
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        socket.set_congestion_control(tcp::CongestionControl::None);
        if wire.is_some() {
            socket
                .listen(endpoint(local))
                .map_err(|_| Error::InvalidAddress)?;
            socket.pause_synack(true);
        } else {
            socket
                .connect(state.interface.context(), endpoint(remote), endpoint(local))
                .map_err(|_| Error::InvalidAddress)?;
        }
        let id = state.next_id;
        state.next_id = state.next_id.checked_add(1).ok_or(Error::ResourceLimit)?;
        let handle = state.sockets.add(socket);
        let pending = kerlico_core::CancellationToken::new();
        state.tuples.insert(tuple, id);
        if let Some(wire) = wire {
            state.inbound_tcp.insert(wire, id);
        }
        if let Some(syn) = syn {
            state.push_incoming(syn);
        }
        state.tcp.insert(
            id,
            TcpEntry {
                handle,
                scope,
                established: false,
                saw_fin: false,
                owner: TcpOwner::Attached,
                write_closed: false,
                pending: pending.clone(),
                reader: None,
                writer: None,
                tuple,
                wire,
            },
        );
        drop(state);
        stack.notify.notify_one();
        Ok(Self {
            stack,
            id,
            local,
            pending,
        })
    }
    /// `syn` 是客户端发来的、四元组为 `wire` 的 SYN，与监听 socket 一起入队。
    pub fn accept(
        stack: Arc<SharedStack>,
        wire: FlowTuple,
        syn: Vec<u8>,
        cancel: kerlico_core::CancellationToken,
    ) -> Result<Self> {
        let local = next_local(&stack, wire.target.ip())?;
        Self::allocate(
            stack,
            local,
            wire.source,
            FlowScope::inbound(cancel),
            Some((wire, syn)),
        )
    }
    pub async fn connect(
        stack: Arc<SharedStack>,
        target: SocketAddr,
        context: &ConnectContext,
    ) -> Result<Self> {
        let local = next_local(&stack, target.ip())?;
        let stream = Self::allocate(stack, local, target, FlowScope::from_context(context), None)?;
        context.run(stream.established()).await?;
        Ok(stream)
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn pending_cancel(&self) -> kerlico_core::CancellationToken {
        self.pending.clone()
    }
    pub fn resume_accept(&self) -> Result<()> {
        let mut state = self.stack.lock()?;
        let handle = state.tcp.get(&self.id).ok_or(Error::Cancelled)?.handle;
        state
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .pause_synack(false);
        drop(state);
        self.stack.notify.notify_one();
        Ok(())
    }
    pub async fn established(&self) -> Result<()> {
        poll_fn(|cx| {
            self.stack.tcp_poll(self.id, cx, |socket, entry, cx| {
                if entry.established {
                    return Poll::Ready(Ok(()));
                }
                if socket.state() == tcp::State::Closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "WireGuard目标TCP拒绝连接",
                    )));
                }
                entry.writer = Some(cx.waker().clone());
                socket.register_send_waker(cx.waker());
                Poll::Pending
            })
        })
        .await
        .map_err(Error::Io)
    }
}
impl Drop for TcpStream {
    fn drop(&mut self) {
        self.pending.cancel();
        if let Ok(mut state) = self.stack.lock()
            && let Some(entry) = state.tcp.get_mut(&self.id)
        {
            entry.owner = if entry.write_closed {
                TcpOwner::Draining(Instant::now() + Duration::from_secs(60))
            } else {
                TcpOwner::Aborting(Instant::now() + Duration::from_secs(1))
            };
        }
        self.stack.notify.notify_one();
    }
}
impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.stack.tcp_poll(self.id, cx, |socket, entry, cx| {
            if socket.can_recv() {
                let size = socket
                    .recv_slice(buffer.initialize_unfilled())
                    .map_err(|_| io::Error::other("WireGuard TCP读取状态不合法"))?;
                buffer.advance(size);
                return Poll::Ready(Ok(()));
            }
            if !socket.may_recv() {
                return Poll::Ready(if entry.saw_fin {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "WireGuard TCP连接已重置",
                    ))
                });
            }
            entry.reader = Some(cx.waker().clone());
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        })
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.stack.tcp_poll(self.id, cx, |socket, entry, cx| {
            if socket.can_send() {
                return Poll::Ready(socket.send_slice(bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard TCP写端已关闭")
                }));
            }
            if !socket.may_send() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WireGuard TCP写端已关闭",
                )));
            }
            entry.writer = Some(cx.waker().clone());
            socket.register_send_waker(cx.waker());
            Poll::Pending
        })
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stack.tcp_poll(self.id, cx, |socket, entry, cx| {
            if socket.send_queue() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !socket.is_active() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WireGuard TCP刷新前连接已关闭",
                )));
            }
            entry.writer = Some(cx.waker().clone());
            socket.register_send_waker(cx.waker());
            Poll::Pending
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stack.tcp_poll(self.id, cx, |socket, entry, cx| {
            entry.write_closed = true;
            socket.close();
            if socket.send_queue() == 0
                && matches!(
                    socket.state(),
                    tcp::State::FinWait2 | tcp::State::TimeWait | tcp::State::Closed
                )
            {
                return Poll::Ready(Ok(()));
            }
            entry.writer = Some(cx.waker().clone());
            socket.register_send_waker(cx.waker());
            Poll::Pending
        })
    }
}

fn next_local(stack: &SharedStack, family: std::net::IpAddr) -> Result<SocketAddr> {
    let address = stack.addresses.for_target(family)?;
    let mut state = stack.lock()?;
    for _ in 0..16384 {
        let port = state.next_port;
        state.next_port = if port == u16::MAX { 49152 } else { port + 1 };
        let local = SocketAddr::new(address, port);
        if !state.tuples.keys().any(|tuple| tuple.source == local) {
            return Ok(local);
        }
    }
    Err(Error::ResourceLimit)
}
