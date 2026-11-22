use std::ffi::{c_int, c_short};
#[cfg(target_os = "linux")]
use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

#[cfg(target_os = "linux")]
use crate::Timespec;
use crate::{now, pattern, STREAMS};

const PAYLOAD: usize = 1200;
const HEADER: usize = 10;
const PACKET: usize = HEADER + PAYLOAD;
const SECOND: u64 = 1_000_000_000;
const POLLIN: c_short = 1;
const READ_BATCH: usize = 4;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[cfg(target_os = "linux")]
extern "C" {
    fn ppoll(fds: *mut PollFd, len: usize, timeout: *const Timespec, sigmask: *const c_void) -> c_int;
}

#[cfg(not(target_os = "linux"))]
extern "C" {
    fn poll(fds: *mut PollFd, len: std::ffi::c_uint, timeout: c_int) -> c_int;
}

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
    socket.set_nonblocking(true)?;
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
    let mut poll_fds: Vec<_> = sockets
        .iter()
        .map(|(_, socket)| PollFd { fd: socket.as_raw_fd(), events: POLLIN, revents: 0 })
        .collect();
    let stride = STREAMS as u64;
    let mut seen = vec![false; total as usize];
    let (mut verified, mut duplicates) = (0, 0);
    let (mut max_late, mut tail_late) = (0, 0);
    let mut previous_batch = 0;
    let mut record = 0;
    let mut bytes = [0; PACKET + 1];
    println!("start {start}");
    loop {
        let current = now();
        let deadline = start + record * SECOND / packets_per_second;
        // Keep a minimum spacing between batches when catching up after a pause.
        let send_at = deadline.max(previous_batch + min_batch_spacing);
        if record < total && current >= send_at {
            previous_batch = current;
            for (index, ((_, socket), packet)) in sockets.iter().zip(&packets).enumerate() {
                let sequence = record + index as u64;
                if sequence >= total {
                    break;
                }
                let mut wire = *packet;
                wire[HEADER..HEADER + 8].copy_from_slice(&sequence.to_be_bytes());
                socket.send(&wire)?;
            }
            let finished = now();
            max_late = max_late.max(finished.saturating_sub(deadline));
            record += stride;
            if record >= total {
                tail_late = finished.saturating_sub(stop);
            }
            continue;
        }
        if current >= drain {
            if record >= total {
                break;
            }
            // Complete the offered count even when the send schedule already failed.
            crate::wait_until(send_at);
            continue;
        }
        let until = if record < total { send_at.min(drain) } else { drain };
        if !wait_readable(&mut poll_fds, until - current)? {
            continue;
        }
        for (flow, ((_, socket), expected)) in sockets.iter().zip(&packets).enumerate() {
            if poll_fds[flow].revents == 0 {
                continue;
            }
            // Bound each read so one loaded association cannot starve sends or other readers.
            for _ in 0..READ_BATCH {
                if now() >= drain {
                    break;
                }
                let Some(sequence) = receive(socket, expected, &mut bytes)? else { break };
                if sequence % stride != flow as u64 || sequence >= total {
                    return Err(invalid("SOCKS5 UDP reply sequence mismatch"));
                }
                if sequence >= first {
                    if std::mem::replace(&mut seen[sequence as usize], true) {
                        duplicates += 1;
                    } else {
                        verified += 1;
                    }
                }
            }
        }
    }
    assert!(verified <= sent);
    println!("udp_result {sent} {verified} {duplicates} {max_late} {tail_late}");
    Ok(())
}

fn wait_readable(fds: &mut [PollFd], nanos: u64) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    let result = {
        let timeout = Timespec { sec: (nanos / SECOND) as i64, nanos: (nanos % SECOND) as i64 };
        // SAFETY: ppoll borrows the complete fd array and the timeout for the call.
        unsafe { ppoll(fds.as_mut_ptr(), fds.len(), &timeout, std::ptr::null()) }
    };
    #[cfg(not(target_os = "linux"))]
    let result = {
        let millis = (nanos / 1_000_000) as c_int;
        // SAFETY: poll borrows the complete fd array for the call.
        let ready = unsafe { poll(fds.as_mut_ptr(), fds.len() as std::ffi::c_uint, millis) };
        if ready == 0 && millis == 0 {
            std::thread::sleep(Duration::from_nanos(nanos));
        }
        ready
    };
    if result >= 0 {
        return Ok(result != 0);
    }
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::Interrupted => Ok(false),
        _ => Err(error),
    }
}

fn receive(socket: &UdpSocket, expected: &[u8; PACKET], bytes: &mut [u8]) -> io::Result<Option<u64>> {
    match socket.recv(bytes) {
        Ok(PACKET)
            if bytes[..HEADER] == expected[..HEADER]
                && bytes[HEADER + 8..PACKET] == expected[HEADER + 8..] =>
        {
            Ok(Some(u64::from_be_bytes(bytes[HEADER..HEADER + 8].try_into().unwrap())))
        }
        Ok(_) => Err(invalid("SOCKS5 UDP reply mismatch")),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
