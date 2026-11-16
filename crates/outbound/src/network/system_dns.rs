use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use kerlico_shared::runtime::{NetworkDial, NetworkRoute};
use kerlico_shared::Transport;

use super::{exchange_dns, open_native};

/// Send a wire query to the standalone client's configured OS resolvers.
pub fn exchange_system_dns(message: &[u8]) -> io::Result<Vec<u8>> {
    let (config, _) = hickory_resolver::system_conf::read_system_conf().map_err(io::Error::other)?;
    let mut tried = HashSet::new();
    let mut error = io::Error::new(io::ErrorKind::NotFound, "no system DNS servers");
    for server in config.name_servers() {
        let peer = server.socket_addr;
        if tried.insert(peer) {
            match exchange(peer, message) {
                Ok(answer) => return Ok(answer),
                Err(fault) => error = fault,
            }
        }
    }
    Err(error)
}

fn exchange(peer: SocketAddr, message: &[u8]) -> io::Result<Vec<u8>> {
    let mut request = NetworkDial {
        host: peer.ip().to_string(),
        port: peer.port(),
        transport: Transport::Udp,
        addresses: vec![peer],
        route: NetworkRoute::Direct,
        timeout: Duration::from_secs(3),
        socket_factory: None,
        race: None,
    };
    let mut answer = exchange_dns(request.transport, message, || open_native(&request, peer))?;
    check_reply(&answer, message)?;
    if answer[2] & 2 != 0 {
        request.transport = Transport::Tcp;
        answer = exchange_dns(request.transport, message, || open_native(&request, peer))?;
        check_reply(&answer, message)?;
    }
    Ok(answer)
}

fn check_reply(answer: &[u8], message: &[u8]) -> io::Result<()> {
    if answer.len() < 12 || answer.get(..2) != message.get(..2) || answer[2] & 0x80 == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid system DNS response"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};

    #[test]
    fn retries_a_truncated_system_dns_reply_over_tcp_on_the_same_port() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(peer).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let message = [0x34, 0x56, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut answer = message;
        answer[2] |= 0x80;
        let stub = std::thread::spawn(move || {
            let mut request = [0; 12];
            let (length, source) = udp.recv_from(&mut request).unwrap();
            assert_eq!(length, request.len());
            assert_eq!(request, message);
            let mut truncated = answer;
            truncated[2] |= 2;
            udp.send_to(&truncated, source).unwrap();
            let (mut socket, _) = tcp.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tcp_query = [0; 14];
            socket.read_exact(&mut tcp_query).unwrap();
            assert_eq!(&tcp_query[..2], &[0, 12]);
            assert_eq!(&tcp_query[2..], &message);
            socket.write_all(&[0, 12]).unwrap();
            socket.write_all(&answer).unwrap();
        });
        assert_eq!(exchange(peer, &message).unwrap(), answer);
        stub.join().unwrap();
    }
}
