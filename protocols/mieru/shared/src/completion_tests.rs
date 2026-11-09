use super::*;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};

struct Server {
    peer: SocketAddr,
    ready: Receiver<Ready>,
    handles: Arc<Mutex<Vec<ServerHandle>>>,
    stop: Arc<AtomicBool>,
    acceptor: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new(transport: Transport, mtu: u16) -> Self {
        let accounts = Arc::new(Mutex::new(vec![account()]));
        let (tx, ready) = mpsc::channel();
        let handles = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        if transport == Transport::Udp {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let peer = socket.local_addr().unwrap();
            handles
                .lock()
                .unwrap()
                .push(serve_udp(socket, accounts, mtu, tx).unwrap());
            Self {
                peer,
                ready,
                handles,
                stop,
                acceptor: None,
            }
        } else {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let peer = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let stopping = Arc::clone(&stop);
            let connections = Arc::clone(&handles);
            let acceptor = thread::spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((tcp, peer)) => connections.lock().unwrap().push(
                            serve_tcp(tcp, peer, Arc::clone(&accounts), mtu, tx.clone()).unwrap(),
                        ),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                }
            });
            Self {
                peer,
                ready,
                handles,
                stop,
                acceptor: Some(acceptor),
            }
        }
    }

    fn next(&self) -> Ready {
        self.ready.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn client(&self, options: ClientOptions) -> Client {
        Client::new(vec![self.peer], account(), options).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(acceptor) = self.acceptor.take() {
            acceptor.join().unwrap();
        }
        for handle in self.handles.lock().unwrap().iter() {
            handle.close();
        }
    }
}

fn account() -> Account {
    Account {
        username: "completion".into(),
        password: "local-test".into(),
    }
}
fn target() -> Target {
    Target {
        host: "example.test".into(),
        port: 443,
    }
}

fn read_bytes(conn: &Conn, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    let mut offset = 0;
    while offset < size {
        offset += conn
            .read_for(&mut bytes[offset..], Duration::from_secs(5))
            .unwrap();
    }
    bytes
}

#[test]
fn no_wait_is_lazy_and_hides_the_reply() {
    let server = Server::new(Transport::Tcp, 1400);
    let client = server.client(ClientOptions {
        handshake: HandshakeMode::NoWait,
        ..ClientOptions::default()
    });
    let conn = client.open(&target()).unwrap();
    assert!(matches!(
        server.ready.recv_timeout(Duration::from_millis(30)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert_eq!(
        conn.read_for(&mut [0; 16], Duration::from_millis(30))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    conn.write_user(b"first application bytes").unwrap();
    let ready = server.next();
    assert_eq!(ready.target.host, "example.test");
    assert_eq!(read_bytes(&ready.conn, 23), b"first application bytes");
    ready.conn.write_user(b"answer").unwrap();
    assert_eq!(read_bytes(&conn, 6), b"answer");
    conn.close();
    assert_eq!(client.active_sessions(), 0);
    let unwritten = client.open(&target()).unwrap();
    unwritten.close();
    assert!(matches!(
        server.ready.recv_timeout(Duration::from_millis(30)),
        Err(RecvTimeoutError::Timeout)
    ));
}

#[test]
fn off_uses_one_underlay_per_session_and_client_drop_keeps_live_streams() {
    let server = Server::new(Transport::Tcp, 1400);
    let client = server.client(ClientOptions {
        multiplexing: Multiplexing::Off,
        ..ClientOptions::default()
    });
    let clone = client.clone();
    let first = client.open(&target()).unwrap();
    let remote = server.next();
    let second = clone.open(&target()).unwrap();
    let _second_remote = server.next();
    assert_eq!(client.active_connections(), 2);
    assert_eq!(clone.active_sessions(), 2);
    second.close();
    assert_eq!(client.active_connections(), 1);
    drop(client);
    drop(clone);
    first.write_user(b"live").unwrap();
    assert_eq!(read_bytes(&remote.conn, 4), b"live");
    remote.conn.write_user(b"back").unwrap();
    assert_eq!(read_bytes(&first, 4), b"back");
}

#[test]
fn all_low_entropy_modes_carry_max_pdu_over_both_transports() {
    for transport in [Transport::Tcp, Transport::Udp] {
        for mode in 0..=4 {
            let server = Server::new(transport, 1280);
            let client = server.client(ClientOptions {
                transport,
                mtu: 1280,
                low_entropy: mode,
                ..ClientOptions::default()
            });
            let conn = client.open(&target()).unwrap();
            let remote = server.next();
            let payload: Vec<u8> = (0..32768).map(|n| (n % 251) as u8).collect();
            conn.write_user(&payload).unwrap();
            assert_eq!(read_bytes(&remote.conn, payload.len()), payload);
            remote.conn.write_user(&payload).unwrap();
            assert_eq!(read_bytes(&conn, payload.len()), payload);
            client.close();
        }
    }
}

#[test]
fn udp_messages_keep_empty_packets_boundaries_and_reopen_targets() {
    for transport in [Transport::Tcp, Transport::Udp] {
        let server = Server::new(transport, 1400);
        let client = server.client(ClientOptions {
            transport,
            ..ClientOptions::default()
        });
        let assoc = client.associate().unwrap();
        assoc.send_to("example.test", 53, &[]).unwrap();
        let first = server.next();
        assert!(first.udp);
        assert_eq!(
            first
                .conn
                .read_for(&mut [0; 128], Duration::from_secs(2))
                .unwrap(),
            0
        );
        first.conn.write_user(&[]).unwrap();
        assert_eq!(
            assoc.recv_for(Duration::from_secs(2)).unwrap(),
            ("example.test".into(), 53, vec![])
        );
        assoc.send_to("example.test", 53, &[9; 100]).unwrap();
        let error = first
            .conn
            .read_for(&mut [0; 16], Duration::from_secs(2))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let mut packet = [0; 128];
        assert_eq!(
            first
                .conn
                .read_for(&mut packet, Duration::from_secs(2))
                .unwrap(),
            100
        );
        assert_eq!(packet[..100], [9; 100]);
        drop(first);
        assoc.send_to("example.test", 53, b"new").unwrap();
        let reopened = server.next();
        assert_eq!(
            reopened
                .conn
                .read_for(&mut packet, Duration::from_secs(2))
                .unwrap(),
            3
        );
        assert_eq!(&packet[..3], b"new");
        assoc.close();
        assert_eq!(client.active_sessions(), 0);
    }
}

#[test]
fn timed_udp_receive_retains_a_partial_frame() {
    let server = Server::new(Transport::Tcp, 1400);
    let client = server.client(ClientOptions::default());
    let assoc = client.associate().unwrap();
    assoc.send_to("example.test", 53, b"start").unwrap();
    let remote = server.next();
    let ConnKind::Leg(leg) = &remote.conn.kind else {
        panic!("UDP leg");
    };
    let packet = udp_datagram("example.test", 53, b"whole").unwrap();
    let mut frame = vec![0];
    frame.extend((packet.len() as u16).to_be_bytes());
    frame.extend(packet);
    frame.push(0xff);
    leg.sess.write_client(&frame[..2]).unwrap();
    assert_eq!(
        assoc
            .recv_for(Duration::from_millis(40))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    leg.sess.write_client(&frame[2..]).unwrap();
    assert_eq!(
        assoc.recv_for(Duration::from_secs(2)).unwrap(),
        ("example.test".into(), 53, b"whole".to_vec())
    );
}

#[test]
fn concurrent_sessions_preserve_the_tcp_cipher_sequence() {
    let server = Server::new(Transport::Tcp, 1400);
    let link = dial(server.peer, &account(), true).unwrap();
    let first = open_connect(&link, &target(), &[]).unwrap();
    let first_remote = server.next();
    let second = open_connect(&link, &target(), &[]).unwrap();
    let second_remote = server.next();
    thread::scope(|scope| {
        let first_writer = scope.spawn(|| {
            for _ in 0..64 {
                first.write_user(&[1; 8192]).unwrap();
            }
        });
        let second_writer = scope.spawn(|| {
            for _ in 0..64 {
                second.write_user(&[2; 8192]).unwrap();
            }
        });
        let first_reader = scope.spawn(|| {
            assert_eq!(
                read_bytes(&first_remote.conn, 64 * 8192),
                vec![1; 64 * 8192]
            )
        });
        assert_eq!(
            read_bytes(&second_remote.conn, 64 * 8192),
            vec![2; 64 * 8192]
        );
        first_writer.join().unwrap();
        second_writer.join().unwrap();
        first_reader.join().unwrap();
    });
    first.close();
    second.close();
    assert_eq!(link.session_count(), 0);
}

#[test]
fn closing_a_client_wakes_a_blocked_reader() {
    let server = Server::new(Transport::Tcp, 1400);
    let client = server.client(ClientOptions::default());
    let conn = client.open(&target()).unwrap();
    let _remote = server.next();
    thread::scope(|scope| {
        let reader = scope.spawn(|| conn.read_user(&mut [0; 1]));
        client.close();
        assert_eq!(
            reader.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    });
    assert_eq!(client.active_connections(), 0);
}

#[test]
fn slow_tcp_payload_can_arrive_after_the_socket_poll_timeout() {
    for allow_idle in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (started, ready) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut tcp = TcpStream::connect(addr).unwrap();
            tcp.write_all(b"a").unwrap();
            started.send(()).unwrap();
            thread::sleep(Duration::from_millis(80));
            tcp.write_all(b"bcdefgh").unwrap();
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        ready.recv().unwrap();
        let mut tcp = BufReader::with_capacity(8, tcp);
        assert_eq!(take(&mut tcp, 3, allow_idle).unwrap(), b"abc");
        skip_padding(&mut tcp, 2).unwrap();
        assert_eq!(take(&mut tcp, 3, false).unwrap(), b"fgh");
        writer.join().unwrap();
    }
}

#[test]
fn each_multiplexing_level_keeps_independent_live_sessions() {
    for level in [
        Multiplexing::Off,
        Multiplexing::Low,
        Multiplexing::Middle,
        Multiplexing::High,
    ] {
        let server = Server::new(Transport::Tcp, 1400);
        let client = server.client(ClientOptions {
            multiplexing: level,
            ..ClientOptions::default()
        });
        let mut streams = Vec::new();
        for index in 0..32 {
            let conn = client.open(&target()).unwrap();
            let remote = server.next();
            conn.write_user(&[index]).unwrap();
            assert_eq!(read_bytes(&remote.conn, 1), [index]);
            streams.push((conn, remote.conn));
        }
        assert_eq!(client.active_sessions(), 32);
        if level == Multiplexing::Off {
            assert_eq!(client.active_connections(), 32);
        } else {
            // 复用系数至少为 1 时，连续 32 个会话都不复用的概率至多为 1/32!。
            assert!(client.active_connections() < 32);
        }
        drop(streams);
        assert_eq!(client.active_sessions(), 0);
        client.close();
    }
}

struct LossyRelay {
    peer: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl LossyRelay {
    fn new(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = socket.local_addr().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(5)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut client = None;
            let mut dropped_first = false;
            let mut buf = [0; 65535];
            while !stopping.load(Ordering::Acquire) {
                match socket.recv_from(&mut buf) {
                    Ok((n, source)) if source == server => {
                        if let Some(client) = client {
                            socket.send_to(&buf[..n], client).unwrap();
                        }
                    }
                    Ok((n, source)) => {
                        client = Some(source);
                        if dropped_first {
                            socket.send_to(&buf[..n], server).unwrap();
                        } else {
                            dropped_first = true;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("relay: {error}"),
                }
                if let Some(client) = client {
                    socket.send_to(&[0], client).unwrap();
                }
            }
        });
        Self {
            peer,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for LossyRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn udp_retransmits_even_when_packets_keep_the_reader_busy() {
    let server = Server::new(Transport::Udp, 1280);
    let relay = LossyRelay::new(server.peer);
    let client = Client::new(
        vec![relay.peer],
        account(),
        ClientOptions {
            transport: Transport::Udp,
            mtu: 1280,
            ..ClientOptions::default()
        },
    )
    .unwrap();
    let conn = client.open(&target()).unwrap();
    let remote = server.next();
    conn.write_user(b"retried").unwrap();
    assert_eq!(read_bytes(&remote.conn, 7), b"retried");
    client.close();
}

#[test]
fn udp_no_wait_defers_data_until_open_response_and_can_be_cancelled() {
    for respond in [true, false] {
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let credentials = account();
        let client = Client::new(
            vec![peer.local_addr().unwrap()],
            credentials.clone(),
            ClientOptions {
                transport: Transport::Udp,
                handshake: HandshakeMode::NoWait,
                low_entropy: 3,
                ..ClientOptions::default()
            },
        )
        .unwrap();
        let conn = Arc::new(client.open(&target()).unwrap());
        let writing = Arc::clone(&conn);
        let (done, finished) = mpsc::channel();
        let writer = thread::spawn(move || {
            let _ = done.send(writing.write_user(b"payload"));
        });
        let mut wire = [0; 2048];
        let (n, source) = peer.recv_from(&mut wire).unwrap();
        let opened = crypto::open_first(
            &credentials.username,
            &credentials.password,
            &wire[..72.min(n)],
            meta::unix_now(),
        )
        .unwrap();
        let request = meta::parse(&opened.plain).unwrap();
        assert_eq!(request.kind, OPEN_REQUEST);
        let key = opened.direction.key_bytes();
        let reply = |plain: [u8; 32]| {
            let nonce = crypto::nonce_with_hint(&credentials.username);
            let mut packet = nonce.to_vec();
            packet.extend(Direction::from_key(key).seal_at(&nonce, &plain));
            peer.send_to(&packet, source).unwrap();
        };
        reply(meta::data(&Meta {
            kind: ACK_S2C,
            session: request.session,
            seq: 0,
            unack: 1,
            window: 16,
            fragment: 0,
            prefix: 0,
            payload_len: 0,
            suffix: 0,
            low_mode: 0,
            low_mask: 0,
            extracted: 0,
            rotation: 0,
        }));
        peer.set_read_timeout(Some(Duration::from_millis(120)))
            .unwrap();
        let early = match peer.recv_from(&mut wire) {
            Ok((n, _)) => {
                let opened = crypto::open_first(
                    &credentials.username,
                    &credentials.password,
                    &wire[..72.min(n)],
                    meta::unix_now(),
                )
                .unwrap();
                Some(meta::parse(&opened.plain).unwrap().kind)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(error) => panic!("receive: {error}"),
        };
        if respond {
            reply(meta::session(OPEN_RESPONSE, request.session, 0, 0, 0));
        } else {
            client.close();
        }
        let result = finished.recv_timeout(Duration::from_secs(2));
        client.close();
        writer.join().unwrap();
        assert_eq!(early, None, "client emitted a segment before OPEN_RESPONSE");
        let result = result.expect("open wait must finish or cancel");
        if respond {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        }
    }
}

#[test]
fn close_after_data_preserves_buffered_bytes_and_a_pending_socks_reply() {
    for handshake in [HandshakeMode::Standard, HandshakeMode::NoWait] {
        let server = Server::new(Transport::Tcp, 1400);
        let client = server.client(ClientOptions {
            handshake,
            ..ClientOptions::default()
        });
        let conn = client.open(&target()).unwrap();
        if handshake == HandshakeMode::NoWait {
            conn.write_user(b"start").unwrap();
        }
        let remote = server.next();
        remote.conn.write_user(b"final bytes").unwrap();
        remote.conn.close();
        // 等待对端关闭，保留队列中的应答和载荷，随后验证它们仍可读出。
        let ConnKind::Stream(sess) = &conn.kind else {
            unreachable!()
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !sess.closed.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(sess.closed.load(Ordering::Acquire));
        assert_eq!(read_bytes(&conn, 11), b"final bytes");
        assert_eq!(
            conn.read_for(&mut [0; 1], Duration::from_millis(50))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
