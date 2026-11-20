use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::thread;
use std::time::Duration;

use crate::{now, pattern, wait_until, STREAMS};

const PAYLOAD: usize = 1200;
const HEADER: usize = 10;
const PACKET: usize = HEADER + PAYLOAD;
const SECOND: u64 = 1_000_000_000;
const READ_WAIT: Duration = Duration::from_millis(25);

#[cfg(target_os = "linux")]
fn receive_buffer(socket: &UdpSocket, capacity: i32) -> io::Result<()> {
    use std::ffi::c_void;
    extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, data: *const c_void, len: u32) -> i32;
    }
    const SOL_SOCKET: i32 = 1;
    const SO_RCVBUFFORCE: i32 = 33;
    // SAFETY: The socket is held open, and data points to a complete int for
    // the duration of the syscall. The veth fixture runs inside a private namespace.
    let result = unsafe {
        setsockopt(
            socket.as_raw_fd(),
            SOL_SOCKET,
            SO_RCVBUFFORCE,
            (&capacity as *const i32).cast(),
            std::mem::size_of_val(&capacity) as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn receive_buffer(_: &UdpSocket, _: i32) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

pub(super) fn echo(address: &str, buffer_size: i32) -> io::Result<()> {
    let socket = UdpSocket::bind(address)?;
    if buffer_size != 0 {
        receive_buffer(&socket, buffer_size)?;
    }
    println!("listening");
    let mut bytes = [0; PAYLOAD + 1];
    loop {
        let (size, source) = socket.recv_from(&mut bytes)?;
        if size != PAYLOAD {
            return Err(invalid("unexpected UDP payload length"));
        }
        socket.send_to(&bytes[..size], source)?;
    }
}

fn associate(proxy: &str, buffer_size: i32) -> io::Result<(TcpStream, UdpSocket)> {
    let mut control = TcpStream::connect(proxy)?;
    control.set_read_timeout(Some(Duration::from_secs(3)))?;
    control.set_write_timeout(Some(Duration::from_secs(3)))?;
    control.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    control.read_exact(&mut method)?;
    if method != [5, 0] {
        return Err(invalid("unexpected SOCKS5 authentication method"));
    }
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let mut reply = [0; HEADER];
    control.read_exact(&mut reply)?;
    if reply[..4] != [5, 0, 0, 1] {
        return Err(invalid("expected an IPv4 SOCKS5 relay"));
    }
    let mut relay = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    if relay.is_unspecified() {
        let std::net::SocketAddr::V4(peer) = control.peer_addr()? else {
            return Err(invalid("expected an IPv4 SOCKS5 proxy"));
        };
        relay = *peer.ip();
    }
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    if buffer_size != 0 {
        receive_buffer(&socket, buffer_size)?;
    }
    socket.connect((relay, port))?;
    socket.set_read_timeout(Some(READ_WAIT))?;
    Ok((control, socket))
}

pub(super) fn roundtrip(
    proxy: &str,
    target: &str,
    warmup: u64,
    duration: u64,
    packets_per_second: u64,
    buffer_size: i32,
) -> io::Result<()> {
    let target: SocketAddrV4 = target.parse().map_err(|_| invalid("invalid UDP target"))?;
    let mut sockets = Vec::with_capacity(STREAMS);
    let mut packets = Vec::with_capacity(STREAMS);
    for index in 0..STREAMS {
        sockets.push(associate(proxy, buffer_size)?);
        let mut wire = [0; PACKET];
        wire[3] = 1;
        wire[4..8].copy_from_slice(&target.ip().octets());
        wire[8..HEADER].copy_from_slice(&target.port().to_be_bytes());
        wire[HEADER..].copy_from_slice(&pattern(index)[..PAYLOAD]);
        packets.push(wire);
    }
    let start = now() + SECOND / 2;
    let first = warmup * packets_per_second;
    let sent = duration * packets_per_second;
    let total = first + sent;
    let stop = start + (warmup + duration) * SECOND;
    let drain = stop + SECOND / 5;
    let min_batch_spacing = (STREAMS as u64 * SECOND / packets_per_second) / 2;
    let (verified, duplicates, max_late, tail_late) = thread::scope(|scope| -> io::Result<_> {
        let readers: Vec<_> = sockets
            .iter()
            .zip(&packets)
            .enumerate()
            .map(|(index, ((_, socket), expected))| {
                scope.spawn(move || receive(socket, expected, index as u64, first, total, drain))
            })
            .collect();
        println!("start {start}");
        let mut max_late = 0;
        let mut previous_batch = 0;
        for record in (0..total).step_by(STREAMS) {
            let deadline = start + record * SECOND / packets_per_second;
            // Keep the same packet count at the target rate without sending
            // all overdue batches at once after a scheduling pause.
            wait_until(deadline.max(previous_batch + min_batch_spacing));
            previous_batch = now();
            for (index, ((_, socket), packet)) in sockets.iter().zip(&packets).enumerate() {
                let sequence = record + index as u64;
                if sequence >= total {
                    break;
                }
                let mut wire = *packet;
                wire[HEADER..HEADER + 8].copy_from_slice(&sequence.to_be_bytes());
                socket.send(&wire)?;
            }
            max_late = max_late.max(now().saturating_sub(deadline));
        }
        let tail_late = now().saturating_sub(stop);
        let (mut verified, mut duplicates) = (0, 0);
        for reader in readers {
            let (received, repeated) = reader.join().expect("UDP reader panicked")?;
            verified += received;
            duplicates += repeated;
        }
        Ok((verified, duplicates, max_late, tail_late))
    })?;
    assert!(verified <= sent);
    println!("udp_result {sent} {verified} {duplicates} {max_late} {tail_late}");
    Ok(())
}

fn receive(
    socket: &UdpSocket,
    expected: &[u8; PACKET],
    flow: u64,
    first: u64,
    total: u64,
    drain: u64,
) -> io::Result<(u64, u64)> {
    let stride = STREAMS as u64;
    let mut seen = vec![false; total.div_ceil(stride) as usize];
    let mut bytes = [0; PACKET + 1];
    let (mut verified, mut duplicates) = (0, 0);
    while now() < drain {
        match socket.recv(&mut bytes) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
            Ok(PACKET)
                if bytes[..HEADER] == expected[..HEADER]
                    && bytes[HEADER + 8..PACKET] == expected[HEADER + 8..] => {}
            Ok(_) => return Err(invalid("SOCKS5 UDP reply mismatch")),
            Err(error) => return Err(error),
        }
        let sequence = u64::from_be_bytes(bytes[HEADER..HEADER + 8].try_into().unwrap());
        if sequence % stride != flow || sequence >= total {
            return Err(invalid("SOCKS5 UDP reply sequence mismatch"));
        }
        if sequence >= first {
            if std::mem::replace(&mut seen[(sequence / stride) as usize], true) {
                duplicates += 1;
            } else {
                verified += 1;
            }
        }
    }
    Ok((verified, duplicates))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
