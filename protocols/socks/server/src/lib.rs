//! SOCKS5 inbound. The server dispatcher owns DNS, target connections and relaying.

use kerlico_shared::{
    dispatch, Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError,
    PlaneFault, Settings, Transport, UserEmail,
};
use kerlico_socks::{encode_ip, invalid, read_address, Address};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, RwLock,
};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

mod udp;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FLOW_WAIT: Duration = Duration::from_millis(200);

struct Account {
    email: UserEmail,
    password: Vec<u8>,
}

struct State {
    tag: NodeTag,
    auth: u8,
    anonymous: UserEmail,
    udp: bool,
    advertised_ip: Option<IpAddr>,
    users: RwLock<HashMap<String, Account>>,
    ready: dispatch::SyncSender<Handoff>,
    queued: Arc<AtomicUsize>,
    associations: Semaphore,
}

struct Node {
    state: Arc<State>,
    flows: mpsc::Receiver<Handoff>,
    stop: Option<watch::Sender<()>>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

impl Accept for Node {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        if account.keys().any(|key| !matches!(key, "user" | "pass")) {
            return Err(OpenError::Settings);
        }
        add_account(
            &self.state,
            email.clone(),
            account.text("user")?,
            account.text("pass")?,
        )
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let mut users = self.state.users.write().expect("SOCKS5 users");
        let before = users.len();
        users.retain(|_, user| &user.email != email);
        if before == users.len() {
            Err(OpenError::Settings)
        } else {
            Ok(())
        }
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        self.flows.try_recv().map_err(|error| match error {
            mpsc::TryRecvError::Empty => OpenError::Again,
            mpsc::TryRecvError::Disconnected => OpenError::Transport,
        })
    }
}

fn add_account(state: &State, email: UserEmail, user: &str, pass: &str) -> Result<(), OpenError> {
    if !(1..=255).contains(&user.len()) || !(1..=255).contains(&pass.len()) {
        return Err(OpenError::Settings);
    }
    let mut users = state.users.write().expect("SOCKS5 users");
    if users.contains_key(user) || users.values().any(|account| account.email == email) {
        return Err(OpenError::Settings);
    }
    users.insert(
        user.to_owned(),
        Account {
            email,
            password: pass.as_bytes().to_vec(),
        },
    );
    Ok(())
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    if settings
        .keys()
        .any(|key| !matches!(key, "auth" | "udp" | "ip" | "userLevel"))
    {
        return Err(OpenError::Settings);
    }
    let auth = match settings.optional_text("auth")? {
        None | Some("noauth") => 0,
        Some("password") => 2,
        _ => return Err(OpenError::Settings),
    };
    let udp = match settings.optional_text("udp")? {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err(OpenError::Settings),
    };
    let ip = settings
        .optional_text("ip")?
        .map(str::parse::<IpAddr>)
        .transpose()
        .map_err(|_| OpenError::Settings)?;
    if settings
        .optional_text("userLevel")?
        .is_some_and(|value| value != "0")
    {
        return Err(OpenError::Settings);
    }
    let bind = bind.socket_addr();
    if ip.is_some_and(|ip| ip.is_ipv4() != bind.is_ipv4()) {
        return Err(OpenError::Settings);
    }
    let (ready, flows) = dispatch::sync_channel(256, settings.dispatch_wake());
    let state = Arc::new(State {
        tag: tag.clone(),
        auth,
        anonymous: UserEmail::parse("socks").expect("static user"),
        udp,
        advertised_ip: ip.filter(|ip| !ip.is_unspecified()),
        users: RwLock::default(),
        ready,
        queued: Arc::new(AtomicUsize::new(0)),
        associations: Semaphore::new(1024),
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| OpenError::Transport)?;
    let listener = {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(bind),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|_| OpenError::Transport)?;
        #[cfg(unix)]
        socket
            .set_reuse_address(true)
            .map_err(|_| OpenError::Transport)?;
        if bind.is_ipv6() {
            socket.set_only_v6(true).map_err(|_| OpenError::Transport)?;
        }
        socket
            .set_nonblocking(true)
            .and_then(|()| socket.bind(&bind.into()))
            .and_then(|()| socket.listen(1024))
            .map_err(|_| OpenError::Transport)?;
        let _enter = runtime.enter();
        TcpListener::from_std(socket.into()).map_err(|_| OpenError::Transport)?
    };
    let (stop, stopped) = watch::channel(());
    let task = {
        let state = state.clone();
        std::thread::Builder::new()
            .name("socks-accept".into())
            .spawn(move || runtime.block_on(accept_loop(listener, state, stopped)))
            .map_err(|_| OpenError::Transport)?
    };
    Ok(Box::new(Node {
        state,
        flows,
        stop: Some(stop),
        task: Some(task),
    }))
}

async fn accept_loop(listener: TcpListener, state: Arc<State>, mut stopped: watch::Receiver<()>) {
    let permits = Arc::new(Semaphore::new(256));
    loop {
        tokio::select! {
            _ = stopped.changed() => return,
            result = listener.accept() => {
                let Ok((stream, peer)) = result else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, peer, state, permit).await;
                });
            }
        }
    }
}

async fn authenticate(stream: &mut tokio::net::TcpStream, state: &State) -> io::Result<UserEmail> {
    let mut header = [0; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[1] == 0 {
        return Err(invalid());
    }
    let mut methods = [0; 255];
    let methods = &mut methods[..usize::from(header[1])];
    stream.read_exact(methods).await?;
    if !methods.contains(&state.auth) {
        stream.write_all(&[5, 255]).await?;
        return Err(invalid());
    }
    stream.write_all(&[5, state.auth]).await?;
    if state.auth == 0 {
        return Ok(state.anonymous.clone());
    }
    stream.read_exact(&mut header).await?;
    if header[0] != 1 || header[1] == 0 {
        stream.write_all(&[1, 1]).await?;
        return Err(invalid());
    }
    let mut username = [0; 255];
    let username = &mut username[..usize::from(header[1])];
    stream.read_exact(username).await?;
    let mut password = [0; 255];
    let length = stream.read_u8().await?;
    let password = &mut password[..usize::from(length)];
    stream.read_exact(password).await?;
    let email = std::str::from_utf8(username).ok().and_then(|name| {
        let users = state.users.read().expect("SOCKS5 users");
        let user = users.get(name)?;
        bool::from(user.password.ct_eq(password)).then(|| user.email.clone())
    });
    stream.write_all(&[1, u8::from(email.is_none())]).await?;
    email.ok_or_else(invalid)
}

async fn serve(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: Arc<State>,
    handshake: OwnedSemaphorePermit,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let (user, command, address) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let user = authenticate(&mut stream, &state).await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        if request[0] != 5 || request[2] != 0 {
            return Err(invalid());
        }
        let address = match read_address(&mut stream, request[3]).await {
            Ok(address) => address,
            Err(error) => {
                stream.write_all(&reply(8, unspecified(peer))).await?;
                return Err(error);
            }
        };
        Ok((user, request[1], address))
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)??;
    drop(handshake);
    match command {
        1 if address.port != 0 => {
            let dest = Destination::new(address.host, address.port, Transport::Tcp)
                .map_err(|_| invalid())?;
            let socket = stream.into_std()?;
            socket.set_nonblocking(false)?;
            socket.set_read_timeout(Some(FLOW_WAIT))?;
            socket.set_write_timeout(Some(FLOW_WAIT))?;
            let stream = TcpFlow {
                socket,
                peer,
                acknowledged: AtomicBool::new(false),
            };
            let mut handoff = Handoff::new(state.tag.clone(), user, dest, Box::new(stream));
            handoff.set_peer(peer);
            if let Err(error) = state.ready.try_send(handoff) {
                let handoff = match error {
                    mpsc::TrySendError::Full(handoff)
                    | mpsc::TrySendError::Disconnected(handoff) => handoff,
                };
                let _ = handoff.report_connect(Err(OpenError::Transport));
            }
            Ok(())
        }
        1 => stream.write_all(&reply(8, unspecified(peer))).await,
        3 if state.udp => match state.associations.try_acquire() {
            Ok(_permit) => udp::associate(stream, peer, user, address, &state).await,
            Err(_) => stream.write_all(&reply(1, unspecified(peer))).await,
        },
        _ => stream.write_all(&reply(7, unspecified(peer))).await,
    }
}

fn unspecified(peer: SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        ([0; 4], 0).into()
    } else {
        ([0; 8], 0).into()
    }
}

fn reply(status: u8, address: SocketAddr) -> Vec<u8> {
    let mut wire = Vec::with_capacity(22);
    wire.extend([5, status, 0]);
    encode_ip(&mut wire, address);
    wire
}

fn map_io(error: io::Error) -> PlaneFault {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
            PlaneFault::Again
        }
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::UnexpectedEof => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

struct TcpFlow {
    socket: TcpStream,
    peer: SocketAddr,
    acknowledged: AtomicBool,
}

impl InboundStream for TcpFlow {
    #[cfg(target_os = "linux")]
    fn take_splice_socket(&mut self) -> Option<TcpStream> {
        self.raw_read()
    }

    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        (&self.socket).read(buf).map_err(map_io)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        (&self.socket).write(buf).map_err(map_io)
    }

    fn report_connect(&self, result: Result<(), OpenError>) -> Result<(), PlaneFault> {
        if self.acknowledged.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let code = match result {
            Ok(()) => 0,
            Err(OpenError::Settings) => 2,
            Err(_) => 5,
        };
        let bound = if code == 0 {
            self.socket.local_addr().map_err(map_io)?
        } else {
            unspecified(self.peer)
        };
        (&self.socket)
            .write_all(&reply(code, bound))
            .map_err(map_io)
    }

    fn finish_to_user(&self) -> Result<bool, PlaneFault> {
        self.socket.shutdown(Shutdown::Write).map_err(map_io)?;
        Ok(true)
    }

    fn raw_read(&self) -> Option<TcpStream> {
        self.socket.try_clone().ok()
    }

    fn raw_write(&self) -> Option<TcpStream> {
        self.socket.try_clone().ok()
    }

    #[cfg(target_os = "linux")]
    fn can_splice(&self) -> bool {
        true
    }

    #[cfg(target_os = "linux")]
    fn coalesce_splice_reads(&self) -> bool {
        false
    }
}
