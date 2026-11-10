use super::{invalid, read_exact, timed_out, Client, State};
use kerlico_shared::Stream;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(200);
const IDLE: Duration = Duration::from_secs(300);

fn address(stream: &mut TcpStream, state: &State, atyp: u8) -> io::Result<(String, u16)> {
    let host = match atyp {
        1 => {
            let mut b = [0; 4];
            read_exact(stream, &mut b, state)?;
            Ipv4Addr::from(b).to_string()
        }
        4 => {
            let mut b = [0; 16];
            read_exact(stream, &mut b, state)?;
            Ipv6Addr::from(b).to_string()
        }
        3 => {
            let mut n = [0];
            read_exact(stream, &mut n, state)?;
            if n[0] == 0 {
                return Err(invalid());
            }
            let mut b = vec![0; n[0] as usize];
            read_exact(stream, &mut b, state)?;
            String::from_utf8(b).map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    let mut p = [0; 2];
    read_exact(stream, &mut p, state)?;
    Ok((host, u16::from_be_bytes(p)))
}
fn encode_address(out: &mut Vec<u8>, host: &str, port: u16) -> io::Result<()> {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) if !host.is_empty() && host.len() <= 255 => {
            out.push(3);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
        _ => return Err(invalid()),
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}
fn reply(stream: &mut TcpStream, status: u8, addr: SocketAddr) -> io::Result<()> {
    let mut b = vec![5, status, 0];
    encode_address(&mut b, &addr.ip().to_string(), addr.port())?;
    stream.write_all(&b)
}
pub(super) fn serve(mut stream: TcpStream, client: Client, state: Arc<State>) -> io::Result<()> {
    let mut h = [0; 2];
    read_exact(&mut stream, &mut h, &state)?;
    if h[0] != 5 || h[1] == 0 {
        return Err(invalid());
    }
    let mut methods = vec![0; h[1] as usize];
    read_exact(&mut stream, &mut methods, &state)?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255])?;
        return Err(invalid());
    }
    stream.write_all(&[5, 0])?;
    let mut req = [0; 4];
    read_exact(&mut stream, &mut req, &state)?;
    if req[0] != 5 || req[2] != 0 {
        return Err(invalid());
    }
    let destination = match address(&mut stream, &state, req[3]) {
        Ok(addr) => addr,
        Err(e) => {
            let addr = stream_addr(&stream);
            let _ = reply(&mut stream, 8, addr);
            return Err(e);
        }
    };
    match req[1] {
        1 if destination.1 != 0 => match client.open_stream(&destination.0, destination.1) {
            Ok(conn) => {
                let addr = stream.local_addr()?;
                reply(&mut stream, 0, addr)?;
                relay(stream, conn, Vec::new(), state)
            }
            Err(e) => {
                let addr = stream_addr(&stream);
                let _ = reply(&mut stream, 5, addr);
                Err(e)
            }
        },
        3 => associate(stream, client, state, destination),
        _ => {
            let addr = stream_addr(&stream);
            reply(&mut stream, 7, addr)?;
            Err(invalid())
        }
    }
}
fn stream_addr(stream: &TcpStream) -> SocketAddr {
    stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

pub(super) fn relay(
    mut local: TcpStream,
    conn: Box<dyn Stream>,
    initial: Vec<u8>,
    state: Arc<State>,
) -> io::Result<()> {
    if !initial.is_empty() {
        conn.write_all(&initial)?;
    }
    let mut writer = local.try_clone()?;
    let conn: Arc<dyn Stream> = Arc::from(conn);
    let done = Arc::new(AtomicBool::new(false));
    let activity = Arc::new(Mutex::new(Instant::now()));
    thread::scope(|scope| {
        let conn2 = conn.clone();
        let done2 = done.clone();
        let state2 = state.clone();
        let activity2 = activity.clone();
        scope.spawn(move || {
            let mut buf = [0u8; 16384];
            while !state2.stopped()
                && !done2.load(Ordering::Acquire)
                && activity2.lock().unwrap().elapsed() < IDLE
            {
                match local.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        *activity2.lock().unwrap() = Instant::now();
                        if conn2.write_all(&buf[..n]).is_err() {
                            done2.store(true, Ordering::Release);
                            break;
                        }
                    }
                    Err(e) if timed_out(&e) => continue,
                    Err(_) => {
                        done2.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            // 底层协议没有半关闭消息；等待对端响应或空闲超时。
        });
        let mut buf = [0u8; 16384];
        while !state.stopped()
            && !done.load(Ordering::Acquire)
            && activity.lock().unwrap().elapsed() < IDLE
        {
            match conn.read_for(&mut buf, POLL) {
                Ok(0) => break,
                Ok(n) => {
                    *activity.lock().unwrap() = Instant::now();
                    if writer.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if timed_out(&e) => continue,
                Err(_) => break,
            }
        }
        done.store(true, Ordering::Release);
        conn.close();
    });
    Ok(())
}

fn parse_udp(packet: &[u8]) -> io::Result<(String, u16, &[u8])> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return Err(invalid());
    }
    let (host, end) = match packet[3] {
        1 if packet.len() >= 10 => (
            Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]).to_string(),
            8,
        ),
        4 if packet.len() >= 22 => {
            let octets: [u8; 16] = packet[4..20].try_into().unwrap();
            (Ipv6Addr::from(octets).to_string(), 20)
        }
        3 if packet.len() >= 5 && packet[4] > 0 && packet.len() >= 7 + packet[4] as usize => {
            let end = 5 + packet[4] as usize;
            (
                std::str::from_utf8(&packet[5..end])
                    .map_err(|_| invalid())?
                    .to_owned(),
                end,
            )
        }
        _ => return Err(invalid()),
    };
    let port = u16::from_be_bytes([packet[end], packet[end + 1]]);
    if port == 0 {
        return Err(invalid());
    }
    Ok((host, port, &packet[end + 2..]))
}
fn associate(
    mut control: TcpStream,
    client: Client,
    state: Arc<State>,
    requested: (String, u16),
) -> io::Result<()> {
    let peer = control.peer_addr()?;
    let requested_ip = requested.0.parse::<IpAddr>().map_err(|_| invalid())?;
    if !requested_ip.is_unspecified() && requested_ip != peer.ip() {
        return Err(invalid());
    }
    let local = control.local_addr()?;
    let mut bind = local;
    bind.set_port(0);
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(POLL))?;
    let assoc: Arc<dyn kerlico_shared::Association> = Arc::from(client.associate()?);
    reply(&mut control, 0, socket.local_addr()?)?;
    let destination = Arc::new(Mutex::new(None::<SocketAddr>));
    let running = Arc::new(AtomicBool::new(true));
    let activity = Arc::new(Mutex::new(Instant::now()));
    thread::scope(|scope| {
        let socket2 = socket.try_clone().unwrap();
        let assoc2 = assoc.clone();
        let state2 = state.clone();
        let destination2 = destination.clone();
        let running2 = running.clone();
        let activity2 = activity.clone();
        scope.spawn(move || {
            let mut packet = vec![0; 65535];
            while running2.load(Ordering::Acquire) && !state2.stopped() {
                match socket2.recv_from(&mut packet) {
                    Ok((n, src)) => {
                        if src.ip() != peer.ip() || (requested.1 != 0 && src.port() != requested.1)
                        {
                            continue;
                        }
                        let Ok((host, port, payload)) = parse_udp(&packet[..n]) else {
                            continue;
                        };
                        let mut fixed = destination2.lock().unwrap();
                        if fixed.is_some_and(|a| a != src) {
                            continue;
                        }
                        *fixed = Some(src);
                        drop(fixed);
                        *activity2.lock().unwrap() = Instant::now();
                        if assoc2.send_to(src, &host, port, payload).is_err() {
                            running2.store(false, Ordering::Release);
                            break;
                        }
                    }
                    Err(e) if timed_out(&e) => continue,
                    Err(_) => break,
                }
            }
        });
        let socket3 = socket.try_clone().unwrap();
        let assoc3 = assoc.clone();
        let state3 = state.clone();
        let destination3 = destination.clone();
        let running3 = running.clone();
        let activity3 = activity.clone();
        scope.spawn(move || {
            while running3.load(Ordering::Acquire) && !state3.stopped() {
                match assoc3.recv_for(POLL) {
                    Ok((host, port, payload)) => {
                        let mut packet = vec![0, 0, 0];
                        if encode_address(&mut packet, &host, port).is_err() {
                            continue;
                        }
                        packet.extend_from_slice(&payload);
                        if let Some(dst) = *destination3.lock().unwrap() {
                            let _ = socket3.send_to(&packet, dst);
                        }
                        *activity3.lock().unwrap() = Instant::now();
                    }
                    Err(e) if timed_out(&e) => continue,
                    Err(_) => {
                        running3.store(false, Ordering::Release);
                        break;
                    }
                }
            }
        });
        let mut byte = [0; 1];
        while running.load(Ordering::Acquire)
            && !state.stopped()
            && activity.lock().unwrap().elapsed() < IDLE
        {
            match control.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) if timed_out(&e) => continue,
                Err(_) => break,
            }
        }
        running.store(false, Ordering::Release);
        assoc.close();
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 数据报保留目标和空载荷() {
        let mut packet = vec![0, 0, 0];
        encode_address(&mut packet, "test.example", 5353).unwrap();
        let (host, port, payload) = parse_udp(&packet).unwrap();
        assert_eq!(
            (host.as_str(), port, payload),
            ("test.example", 5353, &[][..])
        );
        packet.extend_from_slice(&[1, 2, 0]);
        assert_eq!(parse_udp(&packet).unwrap().2, &[1, 2, 0]);
        packet[2] = 1;
        assert!(parse_udp(&packet).is_err());
    }
    #[test]
    fn 数据报地址截断时拒绝() {
        let packet = [0, 0, 0, 4, 1, 2];
        assert!(parse_udp(&packet).is_err());
    }
}
