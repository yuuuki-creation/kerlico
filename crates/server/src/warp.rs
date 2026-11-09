use std::sync::Arc;

use kerlico_outbound::{BytePipe, PacketDevice};
use kerlico_shared::OpenError;
use kerlico_wg::{Pipe, Tunnel};

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
    let Ok(tunnel) = Tunnel::spawn(profile) else {
        return;
    };
    server.install_warp_device(Arc::new(WarpDevice(Arc::new(tunnel))));
}
