use std::sync::Arc;
use std::{io, net::{IpAddr, SocketAddr}, sync::atomic::{AtomicBool, Ordering}, time::Duration};

use kerlico_outbound::{BytePipe, PacketDevice};
use kerlico_shared::{Association, OpenError};
use kerlico_wg::{Datagrams, Pipe, Tunnel};

pub struct WarpDevice(pub Arc<Tunnel>);

impl PacketDevice for WarpDevice {
    fn connect_tcp(&self, addr: std::net::SocketAddr) -> Result<Box<dyn BytePipe + Send>, OpenError> {
        let pipe = self.0.connect_tcp(addr).map_err(|_| OpenError::Transport)?;
        Ok(Box::new(WarpPipe(pipe)))
    }

    fn connect_udp(&self, addr: std::net::SocketAddr) -> Result<Box<dyn BytePipe + Send>, OpenError> {
        let pipe = self.0.connect_udp(addr).map_err(|_| OpenError::Transport)?;
        Ok(Box::new(WarpPipe(pipe)))
    }

    fn supports_udp_associations(&self) -> bool { true }

    fn associate_udp(&self, ipv4: bool) -> Result<Box<dyn Association>, OpenError> {
        let port = self.0.associate_udp(ipv4).map_err(map_io)?;
        Ok(Box::new(WarpAssociation { port, closed: AtomicBool::new(false), _tunnel: self.0.clone() }))
    }
}

struct WarpAssociation { port: Datagrams, closed: AtomicBool, _tunnel: Arc<Tunnel> }

impl Association for WarpAssociation {
    fn send_to(&self, _: SocketAddr, host: &str, port: u16, payload: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) { return Err(io::ErrorKind::BrokenPipe.into()); }
        let ip: IpAddr = host.parse().map_err(|_| io::ErrorKind::InvalidInput)?;
        match self.port.send_to(SocketAddr::new(ip, port), payload) {
            Err(error) if matches!(error.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::WouldBlock) => Ok(()),
            result => result,
        }
    }

    fn recv_for(&self, wait: Duration) -> io::Result<(String, u16, Vec<u8>)> {
        if self.closed.load(Ordering::Acquire) { return Err(io::ErrorKind::BrokenPipe.into()); }
        let (source, data) = self.port.recv_for(wait)?;
        Ok((source.ip().to_string(), source.port(), data))
    }

    fn close(&self) { self.closed.store(true, Ordering::Release); }
}

struct WarpPipe(Pipe);

impl BytePipe for WarpPipe {
    fn read_pipe(&self, buf: &mut [u8]) -> Result<usize, OpenError> {
        self.0.read(buf).map_err(map_io)
    }

    fn write_pipe(&self, buf: &[u8]) -> Result<usize, OpenError> {
        self.0.write(buf).map_err(map_io)
    }
}

fn map_io(error: std::io::Error) -> OpenError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => OpenError::Again,
        _ => OpenError::Transport,
    }
}

pub fn attach(server: &crate::Server, explicit: Option<&str>, dir: &std::path::Path) {
    let Ok(profile) = kerlico_wg::load_profile(explicit, dir) else {
        return;
    };
    let Ok(socket) = kerlico_outbound::open_system_datagram(profile.endpoint, std::time::Duration::from_secs(10)) else {
        return;
    };
    let Ok(tunnel) = Tunnel::spawn(profile, socket) else {
        return;
    };
    server.install_warp_device(Arc::new(WarpDevice(Arc::new(tunnel))));
}
