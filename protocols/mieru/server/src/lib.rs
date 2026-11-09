use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_mieru::{serve_tcp, serve_udp, Account, Conn, Ready, ServerHandle};
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
    control: Arc<Control>,
    listeners: Vec<thread::JoinHandle<()>>,
}

struct Control {
    closed: AtomicBool,
    connections: Mutex<Vec<ServerHandle>>,
}

impl Control {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for connection in self.connections.lock().expect("连接句柄").drain(..) {
            connection.close();
        }
    }
}

impl Drop for MieruInbound {
    fn drop(&mut self) {
        self.control.close();
        for task in self.listeners.drain(..) {
            let _ = task.join();
        }
    }
}

impl Accept for MieruInbound {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let username = account
            .optional_text("username")?
            .unwrap_or(email.as_str())
            .to_string();
        let password = account.text("password")?.to_string();
        if username.is_empty()
            || password.is_empty()
            || self
                .users
                .get(&username)
                .is_some_and(|user| &user.email != email)
        {
            return Err(OpenError::Settings);
        }
        self.users.retain(|_, user| &user.email != email);
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
        let transport = if ready.udp {
            Transport::Udp
        } else {
            Transport::Tcp
        };
        let destination = Destination::new(ready.target.host, ready.target.port, transport)
            .map_err(|_| OpenError::Settings)?;
        let mut handoff = Handoff::new(
            self.tag.clone(),
            email,
            destination,
            Box::new(Stream(ready.conn)),
        );
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
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => {
            PlaneFault::Closed
        }
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
    let control = Arc::new(Control {
        closed: AtomicBool::new(false),
        connections: Mutex::new(Vec::new()),
    });
    let mut listeners = Vec::new();
    enum Bound {
        Tcp(TcpListener),
        Udp(UdpSocket),
    }
    let mut bound = Vec::new();
    // 完整绑定成功后才启动；后续端口失败不会遗留已启动的监听器。
    for port in plan.ports {
        let addr = with_port(*bind, port);
        match plan.underlay {
            Underlay::Tcp => {
                let listener = bind_tcp(addr).map_err(|_| OpenError::Transport)?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| OpenError::Transport)?;
                bound.push(Bound::Tcp(listener));
            }
            Underlay::Udp => {
                let socket = bind_udp(addr).map_err(|_| OpenError::Transport)?;
                bound.push(Bound::Udp(socket));
            }
        }
    }
    for socket in bound {
        match socket {
            Bound::Tcp(listener) => {
                let accounts = Arc::clone(&accounts);
                let ready = ready_tx.clone();
                let control = Arc::clone(&control);
                listeners.push(thread::spawn(move || {
                    accept_loop(listener, accounts, ready, plan.mtu, control)
                }));
            }
            Bound::Udp(socket) => {
                match serve_udp(socket, Arc::clone(&accounts), plan.mtu, ready_tx.clone()) {
                    Ok(handle) => control.connections.lock().expect("连接句柄").push(handle),
                    Err(_) => {
                        control.close();
                        for task in listeners {
                            let _ = task.join();
                        }
                        return Err(OpenError::Transport);
                    }
                }
            }
        }
    }
    Ok(Box::new(MieruInbound {
        tag: tag.clone(),
        users: BTreeMap::new(),
        accounts,
        ready_tx,
        ready_rx,
        control,
        listeners,
    }))
}

fn accept_loop(
    listener: TcpListener,
    accounts: Arc<Mutex<Vec<Account>>>,
    ready: Sender<Ready>,
    mtu: u16,
    control: Arc<Control>,
) {
    while !control.closed.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((tcp, peer)) => {
                let mut connections = control.connections.lock().expect("连接句柄");
                if control.closed.load(Ordering::Acquire) {
                    break;
                }
                connections.retain(|connection| !connection.is_closed());
                if connections.len() >= 1024 {
                    continue;
                }
                if let Ok(handle) = serve_tcp(tcp, peer, Arc::clone(&accounts), mtu, ready.clone())
                {
                    connections.push(handle);
                }
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
    let underlay = match settings.optional_text("transport")? {
        None | Some("TCP") => Underlay::Tcp,
        Some("UDP") => Underlay::Udp,
        Some(_) => return Err(OpenError::Settings),
    };
    let ports = match settings.optional_text("portRange")? {
        None => vec![port],
        Some(text) => parse_range(text, port)?,
    };
    let mtu = match settings.optional_text("mtu")? {
        None => 1400,
        Some(text) => {
            let mtu = text.parse::<u16>().map_err(|_| OpenError::Settings)?;
            if !(1280..=1400).contains(&mtu) {
                return Err(OpenError::Settings);
            }
            mtu
        }
    };
    Ok(Plan {
        underlay,
        ports,
        mtu,
    })
}

fn parse_range(text: &str, port: u16) -> Result<Vec<u16>, OpenError> {
    let (start, end) = text.split_once('-').ok_or(OpenError::Settings)?;
    if start.is_empty()
        || end.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || !end.bytes().all(|byte| byte.is_ascii_digit())
    {
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
