//! Native UDP carriers shared by all destinations in an inbound session.

use std::collections::HashMap;
use std::future::pending;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use kerlico_shared::{DatagramSession, InboundStream, OpenError};

use crate::copy::{self, PipeWrite};
use crate::DialTarget;

use crate::datagram_mux::{Mux, IO_WAIT};

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
}

impl Sessions {
    pub(crate) fn dial(
        &self,
        session: Arc<DatagramSession>,
        target: &DialTarget,
        stream: &dyn InboundStream,
        flow: copy::Flow<'_>,
    ) -> Result<(), OpenError> {
        let (read, write) = copy::report_connect(
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
                let (id, read) = carrier.mux.register(address);
                Ok((
                    read,
                    Write {
                        address,
                        carrier,
                        id,
                    },
                ))
            })(),
        )?;
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
            .filter(|item| item.session.ptr_eq(&owner))
        {
            return Ok(carrier);
        }
        let (socket, family_v6) = match dual_socket() {
            Ok(socket) => (socket, true),
            Err(_) => (UdpSocket::bind("0.0.0.0:0")?, false),
        };
        socket.set_write_timeout(Some(IO_WAIT))?;
        let incoming = socket.try_clone()?;
        incoming.set_nonblocking(true)?;
        let runtime = runtime()?;
        let incoming = {
            let _guard = runtime.enter();
            tokio::net::UdpSocket::from_std(incoming)?
        };
        let carrier = Arc::new(Carrier {
            session: owner,
            socket,
            family_v6,
            mux: Mux::new(session.allows_other_sources(), self.pending.clone()),
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
    // All carriers run on one reactor thread. Only the datagram delivered to a
    // registered destination needs its own buffer.
    thread_local! {
        static BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; 65_536]);
    }
    while carrier.session.strong_count() != 0 {
        match tokio::time::timeout(SESSION_CHECK, socket.readable()).await {
            Err(_) => continue,
            Ok(Err(_)) => break,
            Ok(Ok(())) => {}
        }
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
        if result.is_err_and(|error| {
            !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused
            )
        }) {
            break;
        }
    }
    carrier.mux.close();
}

struct Write {
    address: SocketAddr,
    carrier: Arc<Carrier>,
    id: u64,
}

impl PipeWrite for Write {
    fn write_pipe(&mut self, data: &[u8]) -> Result<(), OpenError> {
        let address = match self.address {
            SocketAddr::V4(ip) if self.carrier.family_v6 => {
                SocketAddr::from((ip.ip().to_ipv6_mapped(), ip.port()))
            }
            address => address,
        };
        let deadline = std::time::Instant::now() + IO_WAIT;
        self.carrier.mux.mark_sent(self.id);
        loop {
            match self.carrier.socket.send_to(data, address) {
                Ok(sent) if sent == data.len() => return Ok(()),
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
