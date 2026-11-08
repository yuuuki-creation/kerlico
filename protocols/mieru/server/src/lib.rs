use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_mieru::{serve_tcp, serve_udp, Account, Conn, Ready};
use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault,
    Settings, Transport, UserEmail,
};
use socket2::{Domain, Protocol, Socket, Type};

struct User {
    email: UserEmail,
    account: Account,
}

enum Underlay {
    Tcp,
    Udp,
}

struct Plan {
    underlay: Underlay,
    ports: Vec<u16>,
    mtu: u16,
}

pub struct MieruInbound {
    tag: NodeTag,
    users: BTreeMap<String, User>,
    accounts: Arc<Mutex<Vec<Account>>>,
    /// Kept so the session queue stays open after the worker threads are the other senders.
    #[allow(dead_code)]
    ready_tx: Sender<Ready>,
    ready_rx: Receiver<Ready>,
}

impl Accept for MieruInbound {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let username = account
            .text("username")
            .unwrap_or(email.as_str())
            .to_string();
        let password = account.text("password")?.to_string();
        self.users.insert(
            username.clone(),
            User {
                email: email.clone(),
                account: Account { username, password },
            },
        );
        self.publish();
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let key = self
            .users
            .iter()
            .find(|(_, user)| &user.email == email)
            .map(|(key, _)| key.clone());
        let Some(key) = key else {
            return Err(OpenError::Settings);
        };
        self.users.remove(&key);
        self.publish();
        Ok(())
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        match self.ready_rx.try_recv() {
            Ok(ready) => self.handoff(ready),
            Err(TryRecvError::Empty) => Err(OpenError::Again),
            Err(TryRecvError::Disconnected) => Err(OpenError::Transport),
        }
    }
}

impl MieruInbound {
    fn publish(&self) {
        let accounts = self
            .users
            .values()
            .map(|user| user.account.clone())
            .collect();
        *self.accounts.lock().expect("accounts") = accounts;
    }

    fn handoff(&self, ready: Ready) -> Result<Handoff, OpenError> {
        let email = self
            .users
            .get(&ready.username)
            .map(|user| user.email.clone())
            .ok_or(OpenError::Settings)?;
        let transport = if ready.udp { Transport::Udp } else { Transport::Tcp };
        let destination = Destination::new(ready.target.host, ready.target.port, transport)
            .map_err(|_| OpenError::Settings)?;
        let mut handoff = Handoff::new(self.tag.clone(), email, destination, Box::new(Stream(ready.conn)));
        if ready.udp {
            handoff.set_peer(ready.peer);
        }
        Ok(handoff)
    }
}

struct Stream(Conn);

impl InboundStream for Stream {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.0
            .read_for(buf, std::time::Duration::from_millis(200))
            .map_err(map_io)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.write_user(buf).map_err(map_io)?;
        Ok(buf.len())
    }
}

fn map_io(error: std::io::Error) -> PlaneFault {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => PlaneFault::Again,
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    let plan = plan(bind, settings)?;
    let accounts = Arc::new(Mutex::new(Vec::new()));
    let (ready_tx, ready_rx) = mpsc::channel();
    for port in plan.ports {
        let addr = with_port(*bind, port);
        match plan.underlay {
            Underlay::Tcp => {
                let listener = bind_tcp(addr).map_err(|_| OpenError::Transport)?;
                let accounts = Arc::clone(&accounts);
                let ready = ready_tx.clone();
                thread::spawn(move || accept_loop(listener, accounts, ready, plan.mtu));
            }
            Underlay::Udp => {
                let socket = bind_udp(addr).map_err(|_| OpenError::Transport)?;
                serve_udp(socket, Arc::clone(&accounts), plan.mtu, ready_tx.clone())
                    .map_err(|_| OpenError::Transport)?;
            }
        }
    }
    Ok(Box::new(MieruInbound {
        tag: tag.clone(),
        users: BTreeMap::new(),
        accounts,
        ready_tx,
        ready_rx,
    }))
}

fn accept_loop(listener: TcpListener, accounts: Arc<Mutex<Vec<Account>>>, ready: Sender<Ready>, mtu: u16) {
    loop {
        match listener.accept() {
            Ok((tcp, peer)) => {
                let _ = serve_tcp(tcp, peer, Arc::clone(&accounts), mtu, ready.clone());
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn plan(bind: &ListenAddr, settings: &Settings) -> Result<Plan, OpenError> {
    let port = bind.socket_addr().port();
    if port < 1025 {
        return Err(OpenError::Settings);
    }
    let underlay = match settings.text("transport") {
        Err(_) => Underlay::Tcp,
        Ok("TCP") => Underlay::Tcp,
        Ok("UDP") => Underlay::Udp,
        Ok(_) => return Err(OpenError::Settings),
    };
    let ports = match settings.text("portRange") {
        Err(_) => vec![port],
        Ok(text) => parse_range(text, port)?,
    };
    let mtu = match settings.text("mtu") {
        Err(_) => 1400,
        Ok(text) => {
            let mtu = text.parse::<u16>().map_err(|_| OpenError::Settings)?;
            if !(1280..=1400).contains(&mtu) {
                return Err(OpenError::Settings);
            }
            mtu
        }
    };
    Ok(Plan { underlay, ports, mtu })
}

fn parse_range(text: &str, port: u16) -> Result<Vec<u16>, OpenError> {
    let (start, end) = text.split_once('-').ok_or(OpenError::Settings)?;
    if start.is_empty() || end.is_empty() || !start.bytes().all(|byte| byte.is_ascii_digit()) || !end.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OpenError::Settings);
    }
    let start = start.parse::<u16>().map_err(|_| OpenError::Settings)?;
    let end = end.parse::<u16>().map_err(|_| OpenError::Settings)?;
    if start < 1025 || end < start || port < start || port > end {
        return Err(OpenError::Settings);
    }
    Ok((start..=end).collect())
}

fn with_port(bind: ListenAddr, port: u16) -> SocketAddr {
    let mut addr = bind.socket_addr();
    addr.set_port(port);
    addr
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = stream_socket(addr)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from(socket))
}

fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = match addr {
        SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?,
        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            socket.set_only_v6(true)?;
            socket
        }
    };
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from(socket))
}

fn stream_socket(addr: SocketAddr) -> std::io::Result<Socket> {
    match addr {
        SocketAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)),
        SocketAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_only_v6(true)?;
            Ok(socket)
        }
    }
}
