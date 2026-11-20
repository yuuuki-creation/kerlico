use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use ipnet::Ipv4Net;
use kerlico_openvpn::{Carrier, Session, TcpCarrier, Tunnel, FRAME_BATCH, POLL};
#[cfg(target_os = "linux")]
use kerlico_openvpn::SocketRegistration;
use kerlico_shared::dispatch;
use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault,
    Settings, Transport, UserEmail,
};
use kerlico_wg::{Incoming, PeerId, Pipe, Protocol, Stack};
use socket2::{Domain, Socket, Type};

mod udp;

const MAX_SESSIONS: usize = 64;
const MAX_FLOWS: usize = 128;

struct Config {
    tag: NodeTag,
    tls: Arc<rustls::ServerConfig>,
    subnet: Ipv4Net,
    mtu: u16,
    users: Mutex<HashMap<UserEmail, Arc<User>>>,
    stopped: AtomicBool,
    next_peer: AtomicU32,
    ready: dispatch::SyncSender<Handoff>,
}

struct User {
    email: UserEmail,
    fingerprint: [u8; 32],
    address: Ipv4Addr,
    revoked: AtomicBool,
    generation: AtomicU64,
}

struct Node {
    config: Arc<Config>,
    ready: mpsc::Receiver<Handoff>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.config.stopped.store(true, Ordering::Release);
    }
}

impl Accept for Node {
    fn add_user(&mut self, email: &UserEmail, settings: &Settings) -> Result<(), OpenError> {
        if settings
            .keys()
            .any(|key| !matches!(key, "certificateSha256" | "address"))
        {
            return Err(OpenError::Settings);
        }
        let mut fingerprint = [0; 32];
        hex::decode_to_slice(settings.text("certificateSha256")?, &mut fingerprint)
            .map_err(|_| OpenError::Settings)?;
        let address: Ipv4Addr = settings
            .text("address")?
            .parse()
            .map_err(|_| OpenError::Settings)?;
        let net = self.config.subnet;
        if !net.contains(&address)
            || [net.addr(), net.network(), net.broadcast()].contains(&address)
        {
            return Err(OpenError::Settings);
        }
        let mut users = self.config.users.lock().expect("OpenVPN users");
        if users.contains_key(email)
            || users
                .values()
                .any(|user| user.address == address || user.fingerprint == fingerprint)
        {
            return Err(OpenError::Settings);
        }
        users.insert(
            email.clone(),
            Arc::new(User {
                email: email.clone(),
                fingerprint,
                address,
                revoked: AtomicBool::new(false),
                generation: AtomicU64::new(0),
            }),
        );
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let mut users = self.config.users.lock().expect("OpenVPN users");
        let user = users.remove(email).ok_or(OpenError::Settings)?;
        user.revoked.store(true, Ordering::Release);
        Ok(())
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        self.ready.try_recv().map_err(|error| match error {
            mpsc::TryRecvError::Empty => OpenError::Again,
            mpsc::TryRecvError::Disconnected => OpenError::Transport,
        })
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    if settings.keys().any(|key| {
        !matches!(
            key,
            "ca" | "certificate" | "privateKey" | "subnet" | "transport" | "mtu"
        )
    }) {
        return Err(OpenError::Settings);
    }
    let tls = kerlico_openvpn::server_tls(
        settings.text("ca")?,
        settings.text("certificate")?,
        settings.text("privateKey")?,
    )
    .map_err(|_| OpenError::Settings)?;
    let subnet: Ipv4Net = settings
        .text("subnet")?
        .parse()
        .map_err(|_| OpenError::Settings)?;
    if !(1..=30).contains(&subnet.prefix_len())
        || subnet.addr().is_multicast()
        || subnet.addr() == subnet.network()
        || subnet.addr() == subnet.broadcast()
    {
        return Err(OpenError::Settings);
    }
    let mtu: u16 = settings
        .optional_text("mtu")?
        .unwrap_or("1400")
        .parse()
        .map_err(|_| OpenError::Settings)?;
    if !(576..=1500).contains(&mtu) {
        return Err(OpenError::Settings);
    }
    let (ready, receive) = dispatch::sync_channel(256, settings.dispatch_wake());
    let config = Arc::new(Config {
        tag: tag.clone(),
        tls: Arc::new(tls),
        subnet,
        mtu,
        users: Mutex::new(HashMap::new()),
        stopped: AtomicBool::new(false),
        next_peer: AtomicU32::new(0),
        ready,
    });
    let addr = bind.socket_addr();
    let job: Box<dyn FnOnce() + Send> = match settings.optional_text("transport")?.unwrap_or("udp")
    {
        "tcp" => {
            let socket = bind_socket(addr, Type::STREAM).map_err(|_| OpenError::Transport)?;
            socket.listen(128).map_err(|_| OpenError::Transport)?;
            socket
                .set_nonblocking(true)
                .map_err(|_| OpenError::Transport)?;
            let config = config.clone();
            Box::new(move || tcp_node(socket.into(), config))
        }
        "udp" => {
            let socket: UdpSocket = bind_socket(addr, Type::DGRAM)
                .map_err(|_| OpenError::Transport)?
                .into();
            socket
                .set_read_timeout(Some(POLL))
                .map_err(|_| OpenError::Transport)?;
            socket
                .set_write_timeout(Some(POLL))
                .map_err(|_| OpenError::Transport)?;
            let (wait, wake) = udp::DatagramWait::new(&socket).map_err(|_| OpenError::Transport)?;
            let config = config.clone();
            Box::new(move || udp::run(Arc::new(socket), config, wait, wake))
        }
        _ => return Err(OpenError::Settings),
    };
    std::thread::Builder::new()
        .name("openvpn-listener".into())
        .spawn(job)
        .map_err(|_| OpenError::Transport)?;
    Ok(Box::new(Node {
        config,
        ready: receive,
    }))
}

fn bind_socket(addr: SocketAddr, kind: Type) -> io::Result<Socket> {
    let protocol = if kind == Type::STREAM {
        socket2::Protocol::TCP
    } else {
        socket2::Protocol::UDP
    };
    let socket = Socket::new(Domain::for_address(addr), kind, Some(protocol))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    if kind == Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn tcp_node(listener: TcpListener, config: Arc<Config>) {
    let mut workers = Vec::<std::thread::JoinHandle<()>>::new();
    while !config.stopped.load(Ordering::Acquire) {
        workers.retain(|worker| !worker.is_finished());
        match listener.accept() {
            Ok((socket, addr)) => {
                if workers.len() >= MAX_SESSIONS {
                    drop(socket);
                    std::thread::sleep(POLL);
                    continue;
                }
                let Ok(mut carrier) = socket
                    .set_nonblocking(false)
                    .and_then(|_| TcpCarrier::new(socket))
                else {
                    continue;
                };
                let Ok(wake) = carrier.enable_wake() else {
                    continue;
                };
                #[cfg(target_os = "linux")]
                let registration = carrier.registration();
                let config = config.clone();
                if let Ok(worker) = std::thread::Builder::new()
                    .name("openvpn-peer".into())
                    .spawn(move || {
                        if let Ok(mut peer) =
                            Peer::establish(
                                Box::new(carrier), addr, &config, wake,
                                #[cfg(target_os = "linux")]
                                registration,
                            )
                        {
                            while peer.live() && peer.drive(&config, None, false).is_ok() {}
                        }
                    })
                {
                    workers.push(worker);
                }
            }
            Err(error) if kerlico_openvpn::retry(&error) => std::thread::sleep(POLL),
            Err(_) => break,
        }
    }
}

struct NodeCarrier {
    inner: Box<dyn Carrier>,
    config: Arc<Config>,
}

impl Carrier for NodeCarrier {
    fn datagrams(&self) -> bool {
        self.inner.datagrams()
    }
    fn ipv6(&self) -> bool {
        self.inner.ipv6()
    }
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.inner.send(frame)
    }
    fn send_batch(&mut self, frames: &[Vec<u8>]) -> io::Result<()> {
        self.inner.send_batch(frames)
    }
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.config.stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.inner.receive()
    }

    fn receive_ready(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.inner.receive_ready()
    }
}

struct Peer {
    session: Session,
    stack: Stack,
    user: Arc<User>,
    generation: u64,
    addr: SocketAddr,
    packets: Vec<Vec<u8>>,
    #[cfg(target_os = "linux")]
    registration: Option<SocketRegistration>,
    #[cfg(target_os = "linux")]
    ready_peers: Vec<SocketAddr>,
}

impl Peer {
    fn establish(
        carrier: Box<dyn Carrier>,
        addr: SocketAddr,
        config: &Arc<Config>,
        wake: impl Fn() + Send + Sync + 'static,
        #[cfg(target_os = "linux")] registration: Option<SocketRegistration>,
    ) -> io::Result<Self> {
        let carrier = Box::new(NodeCarrier {
            inner: carrier,
            config: config.clone(),
        });
        let mut user = None;
        let session = kerlico_openvpn::server(carrier, config.tls.clone(), |certificate| {
            let fingerprint = kerlico_openvpn::fingerprint(certificate);
            let users = config.users.lock().expect("OpenVPN users");
            let account = users
                .values()
                .find(|user| user.fingerprint == fingerprint)
                .ok_or(io::ErrorKind::PermissionDenied)?;
            let generation = account.generation.fetch_add(1, Ordering::AcqRel) + 1;
            let peer_id = config.next_peer.fetch_add(1, Ordering::Relaxed) % 0xff_ffff;
            user = Some((account.clone(), generation));
            Ok(Tunnel {
                address: account.address,
                netmask: config.subnet.netmask(),
                gateway: Some(config.subnet.addr()),
                mtu: config.mtu,
                peer_id,
            })
        })?;
        let (user, generation) = user.expect("authenticated OpenVPN account");
        let mut stack = Stack::with_limits(usize::from(config.mtu), MAX_FLOWS, MAX_FLOWS)?;
        stack.enable_tcp_nodelay();
        stack.set_wake(wake);
        Ok(Self {
            session,
            stack,
            user,
            generation,
            addr,
            packets: Vec::with_capacity(FRAME_BATCH),
            #[cfg(target_os = "linux")]
            registration,
            #[cfg(target_os = "linux")]
            ready_peers: Vec::new(),
        })
    }

    fn live(&self) -> bool {
        !self.user.revoked.load(Ordering::Acquire)
            && self.user.generation.load(Ordering::Acquire) == self.generation
    }

    fn drive(
        &mut self,
        config: &Config,
        datagrams: Option<(&[udp::Datagram<'_>], bool)>,
        native_event: bool,
    ) -> io::Result<()> {
        let Self {
            session,
            stack,
            user,
            addr,
            packets,
            #[cfg(target_os = "linux")]
            registration,
            #[cfg(target_os = "linux")]
            ready_peers,
            ..
        } = self;
        let source = user.address.octets();
        let offer = |incoming: Incoming| {
            let transport = match incoming.protocol {
                Protocol::Tcp => Transport::Tcp,
                Protocol::Udp => Transport::Udp,
            };
            let Ok(destination) = Destination::new(
                incoming.target.ip().to_string(),
                incoming.target.port(),
                transport,
            ) else {
                return;
            };
            let mut handoff = Handoff::new(
                config.tag.clone(),
                user.email.clone(),
                destination,
                Box::new(Flow {
                    pipe: incoming.pipe,
                    #[cfg(target_os = "linux")]
                    native: registration
                        .as_ref()
                        .filter(|_| transport == Transport::Udp)
                        .map(|registry| (registry.clone(), *addr)),
                }),
            );
            handoff.set_peer(*addr);
            let _ = config.ready.try_send(handoff);
        };
        let receive = |packet: Vec<u8>| {
            if packet.first().is_some_and(|byte| byte >> 4 == 4)
                && packet.get(12..16) == Some(&source)
            {
                if let Some(incoming) = stack.receive_owned(PeerId::SINGLE, *addr, packet) {
                    offer(incoming);
                }
            }
        };
        #[cfg(target_os = "linux")]
        let tcp_carrier = datagrams.is_none();
        if !native_event {
            match datagrams {
                Some((batch, handshake)) => {
                    session.receive_datagrams(
                        batch.iter().map(|(_, frame)| *frame),
                        handshake,
                        receive,
                    )?;
                }
                None => session.receive_batch(FRAME_BATCH, receive)?,
            }
        }
        #[cfg(target_os = "linux")]
        let native_ready = native_event
            || (tcp_carrier
                && registration.as_ref().is_some_and(|registry| {
                    registry.take_datagram_peers(ready_peers);
                    !ready_peers.is_empty()
                }));
        #[cfg(not(target_os = "linux"))]
        let native_ready = false;
        let mut sent = Ok(());
        let emit = |_, packet| {
            if sent.is_ok() {
                packets.push(packet);
                if packets.len() == FRAME_BATCH {
                    sent = session.send_batch(packets);
                    packets.clear();
                }
            }
        };
        if native_event {
            stack.poll_udp(true, emit);
        } else {
            stack.poll_with_udp(native_ready, offer, emit);
        }
        sent?;
        session.send_batch(packets)?;
        packets.clear();
        Ok(())
    }
}

struct Flow {
    pipe: Pipe,
    #[cfg(target_os = "linux")]
    native: Option<(SocketRegistration, SocketAddr)>,
}

impl InboundStream for Flow {
    #[cfg(target_os = "linux")]
    fn connected_datagrams(&self) -> bool {
        self.native.is_some()
    }

    #[cfg(target_os = "linux")]
    fn attach_datagrams(
        &self,
        mut relay: Box<dyn kerlico_shared::ConnectedDatagrams>,
    ) -> Result<(), PlaneFault> {
        let (registration, peer) = self.native.as_ref().ok_or(PlaneFault::Transport)?;
        let interest = registration
            .add_datagram(relay.descriptor(), *peer)
            .map_err(fault)?;
        self.pipe
            .install_udp_driver(Box::new(move |packets, receive, reply| {
                if !packets.is_empty() {
                    interest.note_datagram_requests(packets.len());
                }
                let mut replies = 0;
                let result = relay.drive(
                    packets,
                    receive.filter(|_| interest.take_ready()),
                    &mut |packet| {
                        replies += 1;
                        reply(packet)
                    },
                );
                if replies != 0 {
                    interest.note_datagram_replies(replies);
                }
                result
            }))
            .map_err(fault)
    }

    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.pipe.read_for(buf, POLL).map_err(fault)
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.pipe.write_for(buf, POLL).map_err(fault)
    }
    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        Ok(self.pipe.finish())
    }
    fn report_connect(&self, connected: Result<(), OpenError>) -> Result<(), PlaneFault> {
        if connected.is_err() {
            self.pipe.abort();
        }
        Ok(())
    }
}

fn fault(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => PlaneFault::Again,
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}
