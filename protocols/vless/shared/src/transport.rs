use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use kerlico_shared::runtime::{NetworkConnection, NetworkRead, NetworkWrite};

use crate::finalmask::{FinalMask, Side};

pub struct MaskedRead {
    reader: Box<dyn Read + Send>,
    control: ReadControl,
}

pub struct MaskedWrite {
    writer: Box<dyn Write + Send>,
    control: WriteControl,
}

enum ReadControl { Tcp(TcpStream), Stream(Arc<Mutex<Box<dyn NetworkRead>>>) }
enum WriteControl { Tcp(TcpStream), Stream(Arc<Mutex<Box<dyn NetworkWrite>>>) }

struct NetworkReader(Arc<Mutex<Box<dyn NetworkRead>>>);
struct NetworkWriter(Arc<Mutex<Box<dyn NetworkWrite>>>);
impl Read for NetworkReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { self.0.lock().expect("carrier reader").read(bytes) }
}
impl Write for NetworkWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.0.lock().expect("carrier writer").write(bytes) }
    fn flush(&mut self) -> io::Result<()> { self.0.lock().expect("carrier writer").flush() }
}

pub fn mask_network(connection: NetworkConnection, masks: &FinalMask, peer: std::net::SocketAddr) -> io::Result<(MaskedRead, MaskedWrite)> {
    match connection {
        NetworkConnection::Tcp(socket) => mask_tcp(socket, masks, Side::Client),
        NetworkConnection::Udp(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "TCP carrier requires a byte stream")),
        connection => {
            masks.validate(Side::Client)?;
            let (read, write) = connection.split()?;
            let read = Arc::new(Mutex::new(read));
            let write = Arc::new(Mutex::new(write));
            let local = std::net::SocketAddr::new(if peer.is_ipv4() { std::net::Ipv4Addr::UNSPECIFIED.into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() }, 0);
            let (reader, writer) = masks.wrap_tcp((Box::new(NetworkReader(read.clone())), Box::new(NetworkWriter(write.clone()))), local, peer, Side::Client)?;
            Ok((MaskedRead { reader, control: ReadControl::Stream(read) }, MaskedWrite { writer, control: WriteControl::Stream(write) }))
        }
    }
}

pub fn mask_tcp(socket: TcpStream, masks: &FinalMask, side: Side) -> io::Result<(MaskedRead, MaskedWrite)> {
    let local = socket.local_addr()?;
    let peer = socket.peer_addr()?;
    mask_tcp_at(socket, masks, side, local, peer)
}

pub fn mask_tcp_at(socket: TcpStream, masks: &FinalMask, side: Side, local: std::net::SocketAddr, peer: std::net::SocketAddr) -> io::Result<(MaskedRead, MaskedWrite)> {
    masks.validate(side)?;
    let read_control = socket.try_clone()?;
    let write_control = socket.try_clone()?;
    let pair = (Box::new(socket.try_clone()?) as Box<dyn Read + Send>, Box::new(socket) as Box<dyn Write + Send>);
    let (reader, writer) = masks.wrap_tcp(pair, local, peer, side)?;
    Ok((MaskedRead { reader, control: ReadControl::Tcp(read_control) }, MaskedWrite { writer, control: WriteControl::Tcp(write_control) }))
}

impl MaskedRead {
    pub fn set_timeout(&self, timeout: Duration) {
        match &self.control {
            ReadControl::Tcp(socket) => { socket.set_read_timeout(Some(timeout)).ok(); }
            ReadControl::Stream(read) => { read.lock().expect("carrier reader").set_timeout(timeout).ok(); }
        }
    }
}

impl MaskedWrite {
    pub fn set_timeout(&self, timeout: Duration) {
        match &self.control {
            WriteControl::Tcp(socket) => { socket.set_write_timeout(Some(timeout)).ok(); }
            WriteControl::Stream(write) => { write.lock().expect("carrier writer").set_timeout(timeout).ok(); }
        }
    }
}

impl Read for MaskedRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.reader.read(buf) }
}

impl Write for MaskedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.writer.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.writer.flush() }
}
