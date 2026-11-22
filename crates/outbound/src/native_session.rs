//! Native UDP carriers shared by all destinations in an inbound session.

use std::collections::HashMap;
use std::future::pending;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use kerlico_shared::{
    DatagramReply, DatagramSession, DatagramUplink, InboundStream, OpenError, PlaneFault,
    TrafficCounters,
};

use crate::copy::{self, PipeWrite};
use crate::DialTarget;

use crate::datagram_mux::{DirectSink, Mux, Route, IO_WAIT};

const SESSION_CHECK: Duration = Duration::from_secs(1);

#[derive(Default)]
pub(crate) struct Sessions {
    entries: Mutex<HashMap<usize, Weak<Carrier>>>,
    pending: Arc<AtomicUsize>,
}

struct Carrier {
    session: Weak<DatagramSession>,
    socket: UdpSocket,
    family_v6: bool,
    mux: Arc<Mux<SocketAddr>>,
    receiving: AtomicBool,
}

impl Sessions {
    pub(crate) fn dial(
        &self,
        session: Arc<DatagramSession>,
        target: &DialTarget,
        stream: &dyn InboundStream,
        flow: copy::Flow<'_>,
        detached: bool,
    ) -> Result<(), OpenError> {
        let (address, carrier) = copy::report_connect(
            stream,
            (|| {
                let address = target
                    .addresses
                    .iter()
                    .copied()
                    .find(|addr| addr.is_ipv4() == flow.exit.is_v4())
                    .ok_or(OpenError::Transport)?;
                let carrier = self.carrier(&session).map_err(|_| OpenError::Transport)?;
                if !carrier.family_v6 && address.is_ipv6() {
                    return Err(OpenError::Transport);
                }
                Ok((address, carrier))
            })(),
        )?;
        if detached {
            if let (Some(executor), Some(direct)) = (session.executor(), stream.direct_datagram()) {
                let state = Arc::new(DirectState {
                    pace: copy::Pace::new(),
                    counters: flow.traffic.bind(flow.user, flow.node, flow.exit.tag()),
                });
                let install = move || {
                    if !carrier.receiving.load(Ordering::Acquire) {
                        return Err(OpenError::Transport);
                    }
                    let route = carrier.mux.register_direct(
                        address,
                        Box::new(DirectRead {
                            address,
                            reply: direct.reply,
                            state: state.clone(),
                        }),
                    );
                    let write = Write::new(address, carrier, route.id);
                    (direct.install)(Box::new(DirectWrite {
                        write,
                        _route: route,
                        state,
                    }))
                    .map_err(|_| OpenError::Transport)
                };
                if tokio::runtime::Handle::try_current().is_ok_and(|current| current.id() == executor.id()) {
                    return install();
                }
                let (done, result) = mpsc::sync_channel(1);
                executor.spawn(async move {
                    let _ = done.send(install());
                });
                return result.recv().unwrap_or(Err(OpenError::Transport));
            }
        }
        let (id, read) = carrier.mux.register(address);
        let write = Write::new(address, carrier, id);
        drop(session);
        copy::bridge(stream, write, read, flow)
    }

    fn carrier(&self, session: &Arc<DatagramSession>) -> io::Result<Arc<Carrier>> {
        let owner = Arc::downgrade(session);
        let key = Arc::as_ptr(session) as usize;
        let mut entries = self.entries.lock().expect("UDP sessions");
        entries.retain(|_, carrier| carrier.strong_count() != 0);
        if let Some(carrier) = entries
            .get(&key)
            .and_then(Weak::upgrade)
            .filter(|item| item.session.ptr_eq(&owner) && item.receiving.load(Ordering::Acquire))
        {
            return Ok(carrier);
        }
        let (socket, family_v6) = match dual_socket() {
            Ok(socket) => (socket, true),
            Err(_) => (UdpSocket::bind("0.0.0.0:0")?, false),
        };
        if session.executor().is_some() {
            #[cfg(target_os = "linux")]
            kerlico_shared::grow_udp_carrier_receive_buffer(&socket);
            #[cfg(not(target_os = "linux"))]
            let _ = socket2::SockRef::from(&socket).set_recv_buffer_size(256 * 1024);
        }
        socket.set_write_timeout(Some(IO_WAIT))?;
        let incoming = socket.try_clone()?;
        incoming.set_nonblocking(true)?;
        let runtime = match session.executor() {
            Some(executor) => executor,
            None => runtime()?,
        };
        let incoming = {
            let _guard = runtime.enter();
            tokio::net::UdpSocket::from_std(incoming)?
        };
        let carrier = Arc::new(Carrier {
            session: owner,
            socket,
            family_v6,
            mux: Mux::new(session.allows_other_sources(), self.pending.clone()),
            receiving: AtomicBool::new(true),
        });
        entries.insert(key, Arc::downgrade(&carrier));
        runtime.spawn(dispatch(incoming, carrier.clone()));
        Ok(carrier)
    }
}

fn dual_socket() -> io::Result<UdpSocket> {
    let socket = crate::network::dual_stack_udp_socket()?;
    let address = SocketAddr::from(([0; 8], 0));
    socket.bind(&address.into())?;
    Ok(socket.into())
}

fn runtime() -> io::Result<&'static tokio::runtime::Handle> {
    static RUNTIME: OnceLock<io::Result<tokio::runtime::Handle>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()?;
            let handle = runtime.handle().clone();
            std::thread::Builder::new()
                .name("kerlico-udp-sessions".into())
                .spawn(move || runtime.block_on(pending::<()>()))?;
            Ok(handle)
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

async fn dispatch(socket: tokio::net::UdpSocket, carrier: Arc<Carrier>) {
    // Receivers on the same thread share scratch space. Only queued routes
    // need a separate payload buffer.
    thread_local! {
        static BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 65_536]);
    }
    let mut maintenance = tokio::time::interval(SESSION_CHECK);
    'session: while carrier.session.strong_count() != 0 {
        tokio::select! {
            biased;
            _ = maintenance.tick() => {
                carrier.mux.prune_idle();
                continue;
            },
            ready = socket.readable() => if ready.is_err() { break },
        }
        for _ in 0..32 {
            let result = BUFFER.with(|buffer| {
                let mut buffer = buffer.borrow_mut();
                socket.try_recv_from(&mut buffer).map(|(n, address)| {
                    let address = match address {
                        SocketAddr::V6(v6) => v6
                            .ip()
                            .to_ipv4_mapped()
                            .map_or(address, |ip| SocketAddr::from((ip, v6.port()))),
                        SocketAddr::V4(_) => address,
                    };
                    carrier.mux.deliver(&address, Some(address), &buffer[..n]);
                })
            });
            if let Err(error) = result {
                match error.kind() {
                    io::ErrorKind::WouldBlock => continue 'session,
                    io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused => {}
                    _ => break 'session,
                }
            }
        }
        tokio::task::yield_now().await;
    }
    carrier.receiving.store(false, Ordering::Release);
    carrier.mux.close();
}

struct Write {
    address: SocketAddr,
    carrier: Arc<Carrier>,
    id: u64,
}

impl Write {
    fn new(address: SocketAddr, carrier: Arc<Carrier>, id: u64) -> Self {
        let address = match address {
            SocketAddr::V4(ip) if carrier.family_v6 => {
                SocketAddr::from((ip.ip().to_ipv6_mapped(), ip.port()))
            }
            address => address,
        };
        Self {
            address,
            carrier,
            id,
        }
    }

    fn send(&self, data: &[u8]) -> io::Result<()> {
        self.carrier.mux.mark_sent(self.id);
        let size = self.carrier.socket.send_to(data, self.address)?;
        if size != data.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
}

impl PipeWrite for Write {
    fn write_pipe(&mut self, data: &[u8]) -> Result<(), OpenError> {
        let deadline = std::time::Instant::now() + IO_WAIT;
        loop {
            match self.send(data) {
                Ok(()) => return Ok(()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                _ => return Err(OpenError::Transport),
            }
        }
    }
}

struct DirectState {
    pace: copy::Pace,
    counters: TrafficCounters,
}

struct DirectRead {
    address: SocketAddr,
    reply: DatagramReply,
    state: Arc<DirectState>,
}

impl DirectSink for DirectRead {
    fn is_live(&self) -> bool {
        !self.state.pace.idle()
    }

    fn deliver(&self, source: Option<SocketAddr>, payload: &[u8]) {
        if (self.reply)(source.unwrap_or(self.address), payload).is_ok() {
            self.state.counters.add_downlink(payload.len() as u64);
            self.state.pace.mark();
        }
    }
}

struct DirectWrite {
    write: Write,
    _route: Route<SocketAddr>,
    state: Arc<DirectState>,
}

impl DatagramUplink for DirectWrite {
    fn send(&self, payload: &[u8]) -> Result<(), PlaneFault> {
        if !self.is_live() {
            return Err(PlaneFault::Closed);
        }
        match self.write.send(payload) {
            Ok(()) => {
                self.state.pace.mark();
                self.state.counters.add_uplink(payload.len() as u64);
                Ok(())
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Err(PlaneFault::Again)
            }
            Err(_) => Err(PlaneFault::Transport),
        }
    }

    fn is_live(&self) -> bool {
        self.write.carrier.receiving.load(Ordering::Acquire) && !self.state.pace.idle()
    }
}
