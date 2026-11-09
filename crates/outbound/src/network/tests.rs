use super::*;
use crate::OutboundChoice;
use std::sync::{Arc, Mutex};

#[test]
fn selected_default_uses_warp_without_native_and_never_redials_native() {
    struct Device(Arc<Mutex<Vec<SocketAddr>>>);
    impl crate::PacketDevice for Device {
        fn connect_tcp(&self, peer: SocketAddr) -> Result<Box<dyn BytePipe + Send>, OpenError> {
            self.0.lock().unwrap().push(peer);
            Err(OpenError::Transport)
        }
        fn connect_udp(&self, peer: SocketAddr) -> Result<Box<dyn BytePipe + Send>, OpenError> {
            self.connect_tcp(peer)
        }
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let outbound = Outbound::new();
    outbound.install_warp(Arc::new(Device(calls.clone())));
    let peer = "203.0.113.4:443".parse().unwrap();
    let mut dial = NetworkDial::direct(peer, Transport::Tcp);
    dial.route = NetworkRoute::Selected(OutboundChoice::Default);
    assert!(outbound
        .connect_transport(
            &dial,
            Native {
                v4: false,
                v6: false
            }
        )
        .is_err());
    assert_eq!(*calls.lock().unwrap(), [peer]);
}

#[test]
fn landing_preserves_hostname_and_rejects_recursive_carrier() {
    let outbound = Outbound::new();
    let weak = outbound.downgrade();
    outbound.install_reverse_landing(Arc::new(move |destination| {
        assert_eq!(destination.host(), "unresolved.invalid");
        let request = NetworkDial {
            host: destination.host().into(),
            addresses: Vec::new(),
            route: NetworkRoute::Selected(OutboundChoice::Manual(Exit::Landing)),
            ..NetworkDial::direct("127.0.0.1:443".parse().unwrap(), Transport::Tcp)
        };
        assert_eq!(
            weak.upgrade()
                .unwrap()
                .connect_transport(&request, Native { v4: true, v6: true })
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Err(OpenError::Transport)
    }));
    let request = NetworkDial {
        host: "unresolved.invalid".into(),
        addresses: Vec::new(),
        route: NetworkRoute::Selected(OutboundChoice::Manual(Exit::Landing)),
        ..NetworkDial::direct("127.0.0.1:443".parse().unwrap(), Transport::Tcp)
    };
    assert!(outbound
        .connect_transport(&request, Native { v4: true, v6: true })
        .is_err());
    let weak = outbound.downgrade();
    drop(outbound);
    assert!(weak.upgrade().is_none());
}

#[test]
fn dns_tcp_and_udp_exchange_preserve_the_entire_message() {
    for tcp in [false, true] {
        let payload: Vec<u8> = (0..5000).map(|n| n as u8).collect();
        let (peer, thread) = if tcp {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let peer = listener.local_addr().unwrap();
            (
                peer,
                std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut length = [0; 2];
                    stream.read_exact(&mut length).unwrap();
                    let mut message = vec![0; u16::from_be_bytes(length) as usize];
                    stream.read_exact(&mut message).unwrap();
                    stream.write_all(&length).unwrap();
                    stream.write_all(&message).unwrap();
                }),
            )
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let peer = socket.local_addr().unwrap();
            (
                peer,
                std::thread::spawn(move || {
                    let mut message = vec![0; 65535];
                    let (n, from) = socket.recv_from(&mut message).unwrap();
                    socket.send_to(&message[..n], from).unwrap();
                }),
            )
        };
        let request = NetworkDial::direct(peer, if tcp { Transport::Tcp } else { Transport::Udp });
        let response = Outbound::new()
            .exchange_dns_transport(&request, &payload, Native { v4: true, v6: true })
            .unwrap();
        assert_eq!(response, payload);
        thread.join().unwrap();
    }
}

#[test]
fn landing_split_can_write_while_the_other_half_is_reading() {
    struct Duplex {
        received: std::sync::Condvar,
        bytes: Mutex<Vec<u8>>,
        reading: std::sync::mpsc::Sender<()>,
    }
    impl InboundStream for Duplex {
        fn read_from_user(&self, output: &mut [u8]) -> Result<usize, PlaneFault> {
            let _ = self.reading.send(());
            let mut bytes = self.bytes.lock().unwrap();
            while bytes.is_empty() {
                bytes = self
                    .received
                    .wait_timeout(bytes, Duration::from_secs(2))
                    .unwrap()
                    .0;
                if bytes.is_empty() {
                    return Err(PlaneFault::Again);
                }
            }
            output[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
        fn write_to_user(&self, bytes: &[u8]) -> Result<usize, PlaneFault> {
            self.bytes.lock().unwrap().extend(bytes);
            self.received.notify_all();
            Ok(bytes.len())
        }
    }
    let (started, ready) = std::sync::mpsc::channel();
    let connection = NetworkConnection::Stream(Box::new(LandingStream {
        stream: Arc::new(Duplex {
            received: std::sync::Condvar::new(),
            bytes: Mutex::new(Vec::new()),
            reading: started,
        }),
        timeout: Duration::from_secs(3),
    }));
    let (mut read, mut write) = connection.split().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = [0; 16];
        let n = read.read(&mut bytes).unwrap();
        bytes[..n].to_vec()
    });
    ready.recv_timeout(Duration::from_secs(1)).unwrap();
    write.write_all(b"duplex").unwrap();
    assert_eq!(reader.join().unwrap(), b"duplex");
}

#[test]
fn racing_native_candidates_returns_a_live_connection() {
    let refused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let first = refused.local_addr().unwrap();
    drop(refused);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"winner").unwrap();
    });
    let mut request = NetworkDial::direct(first, Transport::Tcp);
    request.addresses.push(second);
    request.race = Some(kerlico_shared::runtime::ConnectRace {
        delay: Duration::from_millis(5),
        max_concurrent: 2,
    });
    let mut connection = Outbound::new()
        .connect_transport(&request, Native { v4: true, v6: true })
        .unwrap();
    let mut response = [0; 6];
    connection.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"winner");
    server.join().unwrap();
}

#[test]
fn native_datagram_factory_keeps_the_socket_unconnected() {
    let first = UdpSocket::bind("127.0.0.1:0").unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").unwrap();
    let request = NetworkDial::direct(first.local_addr().unwrap(), Transport::Udp);
    let connection = Outbound::new().open_datagram_transport(&request, Native { v4: true, v6: true }).unwrap();
    let NetworkConnection::Udp(socket) = connection else { panic!("native datagram descriptor") };
    assert!(socket.peer_addr().is_err());
    socket.send_to(b"first", first.local_addr().unwrap()).unwrap();
    socket.send_to(b"second", second.local_addr().unwrap()).unwrap();
    let mut bytes = [0; 16];
    assert_eq!(first.recv_from(&mut bytes).unwrap().0, 5);
    assert_eq!(second.recv_from(&mut bytes).unwrap().0, 6);
}
