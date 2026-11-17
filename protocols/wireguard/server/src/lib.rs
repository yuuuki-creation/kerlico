use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::Duration;

use kerlico_shared::dispatch;
use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault,
    Settings, Transport, UserEmail,
};
use kerlico_wg::{Hub, HubEvent, Incoming, IpNet, PeerId, Pipe, Protocol, Stack};

const POLL: Duration = Duration::from_millis(5);

struct Node {
    command: SyncSender<Command>,
    ready: Receiver<Handoff>,
    ipv4: bool,
}

struct Config {
    email: UserEmail,
    key: [u8; 32],
    preshared: Option<[u8; 32]>,
    keepalive: u16,
    allowed: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
}

enum Command {
    Add(Config, SyncSender<Result<(), OpenError>>),
    Remove(UserEmail, SyncSender<Result<(), OpenError>>),
}

impl Node {
    fn change(
        &self,
        command: impl FnOnce(SyncSender<Result<(), OpenError>>) -> Command,
    ) -> Result<(), OpenError> {
        let (reply, result) = mpsc::sync_channel(1);
        self.command
            .send(command(reply))
            .map_err(|_| OpenError::Transport)?;
        result
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| OpenError::Transport)?
    }
}

impl Accept for Node {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        if account.keys().any(|item| {
            !matches!(
                item,
                "publicKey" | "presharedKey" | "allowedIPs" | "persistentKeepalive" | "endpoint"
            )
        }) {
            return Err(OpenError::Settings);
        }
        let key =
            kerlico_wireguard::key(account.text("publicKey")?).map_err(|_| OpenError::Settings)?;
        let preshared = account
            .optional_text("presharedKey")?
            .map(kerlico_wireguard::key)
            .transpose()
            .map_err(|_| OpenError::Settings)?;
        let allowed: Vec<String> =
            serde_json::from_str(account.text("allowedIPs")?).map_err(|_| OpenError::Settings)?;
        let allowed = kerlico_wireguard::prefixes(&allowed).map_err(|_| OpenError::Settings)?;
        let keepalive = account
            .optional_text("persistentKeepalive")?
            .unwrap_or("0")
            .parse()
            .map_err(|_| OpenError::Settings)?;
        let endpoint: Option<SocketAddr> = account
            .optional_text("endpoint")?
            .map(kerlico_wg::parse_endpoint)
            .transpose()
            .map_err(|_| OpenError::Settings)?;
        if endpoint.is_some_and(|endpoint| endpoint.port() == 0 || endpoint.is_ipv4() != self.ipv4)
        {
            return Err(OpenError::Settings);
        }
        self.change(|reply| {
            Command::Add(
                Config {
                    email: email.clone(),
                    key,
                    preshared,
                    keepalive,
                    allowed,
                    endpoint,
                },
                reply,
            )
        })
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        self.change(|reply| Command::Remove(email.clone(), reply))
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        self.ready.recv().map_err(|_| OpenError::Transport)
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    if settings
        .keys()
        .any(|item| !matches!(item, "privateKey" | "mtu"))
    {
        return Err(OpenError::Settings);
    }
    let key =
        kerlico_wireguard::key(settings.text("privateKey")?).map_err(|_| OpenError::Settings)?;
    let mtu = settings
        .optional_text("mtu")?
        .unwrap_or("1420")
        .parse()
        .map_err(|_| OpenError::Settings)?;
    let hub = Hub::with_mtu(key, mtu).map_err(|_| OpenError::Settings)?;
    let stack = Stack::new(mtu).map_err(|_| OpenError::Settings)?;
    let address = bind.socket_addr();
    let socket = open_socket(address).map_err(|_| OpenError::Transport)?;
    let (tx, command) = mpsc::sync_channel(64);
    let (ready, rx) = dispatch::sync_channel(256, settings.dispatch_wake());
    let tag = tag.clone();
    std::thread::Builder::new()
        .name("kerlico-wireguard-node".into())
        .spawn(move || run(socket, tag, hub, stack, command, ready))
        .map_err(|_| OpenError::Transport)?;
    Ok(Box::new(Node {
        command: tx,
        ready: rx,
        ipv4: address.is_ipv4(),
    }))
}

fn open_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(POLL))?;
    socket.set_write_timeout(Some(POLL))?;
    Ok(socket)
}

fn run(
    socket: UdpSocket,
    tag: NodeTag,
    mut hub: Hub,
    mut stack: Stack,
    command: Receiver<Command>,
    ready: dispatch::SyncSender<Handoff>,
) {
    let mut accounts: HashMap<UserEmail, PeerId> = HashMap::new();
    let mut peers: HashMap<PeerId, UserEmail> = HashMap::new();
    let mut wire = vec![0; 65_535];
    loop {
        for _ in 0..64 {
            match command.try_recv() {
                Ok(Command::Add(config, reply)) => {
                    let result = if accounts.contains_key(&config.email) {
                        Err(OpenError::Settings)
                    } else {
                        hub.add(
                            config.key,
                            config.preshared,
                            config.keepalive,
                            config.allowed,
                            config.endpoint,
                        )
                        .map(|id| {
                            accounts.insert(config.email.clone(), id);
                            peers.insert(id, config.email);
                        })
                        .map_err(|_| OpenError::Settings)
                    };
                    let _ = reply.send(result);
                }
                Ok(Command::Remove(email, reply)) => {
                    let result = accounts
                        .remove(&email)
                        .ok_or(OpenError::Settings)
                        .map(|id| {
                            peers.remove(&id);
                            hub.remove(id);
                            stack.remove_peer(id);
                        });
                    let _ = reply.send(result);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        let offer = |incoming: Incoming| {
            let Some(email) = peers.get(&incoming.peer) else {
                return;
            };
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
                tag.clone(),
                email.clone(),
                destination,
                Box::new(Flow(incoming.pipe)),
            );
            handoff.set_peer(incoming.endpoint);
            let _ = ready.try_send(handoff);
        };
        match socket.recv_from(&mut wire) {
            Ok((len, from)) => hub.receive(from, &wire[..len], |event| match event {
                HubEvent::Datagram(peer, data) => {
                    let _ = socket.send_to(&data, peer);
                }
                HubEvent::Packet(peer, source, data) => {
                    if let Some(incoming) = stack.receive(peer, source, &data) {
                        offer(incoming);
                    }
                }
            }),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionRefused
                ) => {}
            Err(_) => return,
        }
        stack.poll(offer, |peer, packet| {
            if let Some(HubEvent::Datagram(remote, wire)) = hub.send_to(peer, &packet) {
                let _ = socket.send_to(&wire, remote);
            }
        });
        hub.tick(|event| {
            if let HubEvent::Datagram(remote, wire) = event {
                let _ = socket.send_to(&wire, remote);
            }
        });
    }
}

struct Flow(Pipe);

impl InboundStream for Flow {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        match self.0.read(buf).map_err(fault) {
            Err(PlaneFault::Again) => {
                std::thread::sleep(POLL);
                self.0.read(buf).map_err(fault)
            }
            result => result,
        }
    }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.write(buf).map_err(fault)
    }
    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        Ok(self.0.finish())
    }
    fn report_connect(&self, connected: Result<(), OpenError>) -> Result<(), PlaneFault> {
        if connected.is_err() {
            self.0.abort();
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
