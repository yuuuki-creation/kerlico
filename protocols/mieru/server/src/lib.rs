use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::sync::Mutex;

use kerlico_mieru::{accept, Account, Conn};
use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault,
    Settings, Transport, UserEmail,
};
use socket2::{Domain, Protocol, Socket, Type};

struct User {
    email: UserEmail,
    account: Account,
}

pub struct MieruInbound {
    tag: NodeTag,
    listener: TcpListener,
    users: Mutex<BTreeMap<String, User>>,
}

impl Accept for MieruInbound {
    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let username = account
            .text("username")
            .unwrap_or(email.as_str())
            .to_string();
        let password = account.text("password")?.to_string();
        self.users.lock().expect("users").insert(
            username.clone(),
            User {
                email: email.clone(),
                account: Account { username, password },
            },
        );
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let mut users = self.users.lock().expect("users");
        let key = users
            .iter()
            .find(|(_, user)| &user.email == email)
            .map(|(key, _)| key.clone());
        let Some(key) = key else {
            return Err(OpenError::Settings);
        };
        users.remove(&key);
        Ok(())
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        let (tcp, _) = self.listener.accept().map_err(|error| {
            if error.kind() == ErrorKind::WouldBlock {
                OpenError::Again
            } else {
                OpenError::Transport
            }
        })?;
        tcp.set_nonblocking(false).map_err(|_| OpenError::Transport)?;
        let accounts: Vec<Account> = self
            .users
            .lock()
            .expect("users")
            .values()
            .map(|user| Account {
                username: user.account.username.clone(),
                password: user.account.password.clone(),
            })
            .collect();
        let (conn, target, username) = accept(tcp, &accounts).map_err(|error| {
            eprintln!("mieru {error}");
            OpenError::Transport
        })?;
        let email = self
            .users
            .lock()
            .expect("users")
            .get(&username)
            .map(|user| user.email.clone())
            .ok_or(OpenError::Settings)?;
        let destination = Destination::new(target.host, target.port, Transport::Tcp)
            .map_err(|_| OpenError::Settings)?;
        Ok(Handoff::new(
            self.tag.clone(),
            email,
            destination,
            Box::new(Stream(conn)),
        ))
    }
}

struct Stream(Conn);

impl InboundStream for Stream {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        self.0.read_user(buf).map_err(map_io)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.0.write_user(buf).map_err(map_io)?;
        Ok(buf.len())
    }
}

fn map_io(error: std::io::Error) -> PlaneFault {
    match error.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => PlaneFault::Again,
        ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    _settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    let listener = bind_listener(*bind).map_err(|_| OpenError::Transport)?;
    Ok(Box::new(MieruInbound {
        tag: tag.clone(),
        listener,
        users: Mutex::new(BTreeMap::new()),
    }))
}

fn bind_listener(addr: ListenAddr) -> std::io::Result<TcpListener> {
    let socket = match addr {
        ListenAddr::V4(_) => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?,
        ListenAddr::V6(_) => {
            let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_only_v6(true)?;
            socket
        }
    };
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.socket_addr().into())?;
    socket.listen(128)?;
    Ok(TcpListener::from(socket))
}
