#![cfg(all(feature = "vless", feature = "landing-vless"))]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use kerlico_shared::{Accept, Destination, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault, Settings, Transport, UserEmail};

fn settings(network: &str, security: &str, mode: &str) -> (Settings, Settings) {
    let mut server = Settings::default();
    let mut client = Settings::default();
    for cfg in [&mut server, &mut client] {
        cfg.insert_text("network", network);
        cfg.insert_text("security", security);
        cfg.insert_text("path", "/vless");
        cfg.insert_text("serviceName", "vless");
        cfg.insert_text("mode", mode);
    }
    server.insert_text("decryption", "none");
    client.insert_text("encryption", "none");
    client.insert_text("id", "test-user");
    if security == "tls" {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        server.insert_text("certificate", cert.cert.pem());
        server.insert_text("key", cert.key_pair.serialize_pem());
        client.insert_text("serverName", "localhost");
        client.insert_text("allowInsecure", "true");
    }
    if security == "reality" {
        let (secret, public) = kerlico_vless::reality_pair();
        server.insert_text("privateKey", kerlico_vless::encode_reality_key(&secret));
        client.insert_text("publicKey", kerlico_vless::encode_reality_key(&public));
        client.insert_text("serverName", "localhost");
    }
    (server, client)
}

fn inbound(settings: &Settings) -> (Box<dyn Accept>, u16) {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let mut inbound = vless::listen(&NodeTag::parse("vless-test").unwrap(), &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(), settings).unwrap();
    let mut account = Settings::default();
    account.insert_text("id", "test-user");
    inbound.add_user(&UserEmail::parse("test-user").unwrap(), &account).unwrap();
    (inbound, port)
}

fn wait_handoff(inbound: &mut dyn Accept) -> kerlico_shared::Handoff {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match inbound.accept() {
            Ok(flow) => return flow,
            Err(OpenError::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            error => panic!("no VLESS handoff: {:?}", error.err()),
        }
    }
}

fn send(stream: &dyn InboundStream, mut bytes: &[u8], udp: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !bytes.is_empty() {
        match stream.write_to_user(bytes) {
            Ok(n) if n > 0 => {
                if udp { assert_eq!(n, bytes.len(), "partial datagram write"); }
                bytes = &bytes[n..];
            }
            Err(PlaneFault::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            other => panic!("VLESS write: {other:?}"),
        }
    }
}

fn receive(stream: &dyn InboundStream, expected: &[u8], udp: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut received = Vec::new();
    let mut buf = vec![0; 1024 * 1024];
    while received.len() < expected.len() {
        match stream.read_from_user(&mut buf) {
            Ok(n) if n > 0 => {
                if udp { assert_eq!(n, expected.len(), "datagram boundary changed"); }
                received.extend_from_slice(&buf[..n]);
            }
            Err(PlaneFault::Again) if Instant::now() < deadline => {}
            other => panic!("VLESS read after {} bytes: {other:?}", received.len()),
        }
    }
    assert_eq!(received, expected);
}

fn exchange(server: Settings, client: Settings, udp: bool) {
    exchange_host(server, client, udp, "127.0.0.1")
}

fn exchange_host(server: Settings, client: Settings, udp: bool, host: &str) {
    let (mut inbound, port) = inbound(&server);
    let transport = if udp { Transport::Udp } else { Transport::Tcp };
    let payloads: Vec<Vec<u8>> = if udp {
        [1, 511, 8193, 32769, 65507].into_iter().map(|len| (0..len).map(|i| (i % 251) as u8).collect()).collect()
    } else {
        [19, 196613].into_iter().map(|len| (0..len).map(|i| (i % 251) as u8).collect()).collect()
    };
    let sent = payloads.clone();
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let flow = wait_handoff(&mut *inbound);
        assert_eq!(flow.destination().transport(), transport);
        let stream = flow.stream();
        for payload in sent {
            receive(stream.as_ref(), &payload, udp);
            send(stream.as_ref(), &payload, udp);
        }
        done_tx.send(()).unwrap();
    });
    let destination = Destination::new("example.test", 80, transport).unwrap();
    let stream = landing_vless::land(host, port, &client, &destination).unwrap();
    for payload in payloads {
        send(stream.as_ref(), &payload, udp);
        receive(stream.as_ref(), &payload, udp);
    }
    done_rx.recv_timeout(Duration::from_secs(10)).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn every_native_carrier_uses_the_owned_resolver_and_socket_settings() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use kerlico_shared::runtime::*;

    struct OwnedNetwork { outbound: kerlico_outbound::Outbound, lookups: AtomicUsize, dials: AtomicUsize }
    impl std::fmt::Debug for OwnedNetwork {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("fixture network") }
    }
    impl Network for OwnedNetwork {
        fn lookup_ip(&self, host: &str, port: u16, _: Option<AddressFamily>, source: ResolutionSource) -> std::io::Result<Vec<std::net::SocketAddr>> {
            assert_eq!(host, "carrier.fixture.invalid");
            assert_eq!(source, ResolutionSource::Configured);
            self.lookups.fetch_add(1, Ordering::Relaxed);
            Ok(vec![(Ipv4Addr::LOCALHOST, port).into()])
        }
        fn connect(&self, request: &NetworkDial) -> std::io::Result<NetworkConnection> {
            assert_eq!(request.route, NetworkRoute::Direct);
            let conn = self.outbound.connect_transport(request, kerlico_outbound::Native { v4: true, v6: false })?;
            let NetworkConnection::Tcp(socket) = &conn else { panic!("TCP carrier"); };
            assert_eq!(socket.ttl()?, 43);
            self.dials.fetch_add(1, Ordering::Relaxed);
            Ok(conn)
        }
        fn open_datagram(&self, request: &NetworkDial) -> std::io::Result<NetworkConnection> {
            assert_eq!(request.route, NetworkRoute::Direct);
            let conn = self.outbound.open_datagram_transport(request, kerlico_outbound::Native { v4: true, v6: false })?;
            let NetworkConnection::Udp(socket) = &conn else { panic!("UDP carrier"); };
            assert_eq!(socket.ttl()?, 43);
            self.dials.fetch_add(1, Ordering::Relaxed);
            Ok(conn)
        }
    }
    #[derive(Debug)]
    struct Catalog;
    impl GeoIpCatalog for Catalog {
        fn load(&self, _: &str, _: &str) -> std::io::Result<GeoIpSet> { Ok(GeoIpSet::new(true, false, |ip| ip.is_loopback())) }
    }
    let network = Arc::new(OwnedNetwork { outbound: kerlico_outbound::Outbound::new(), lookups: AtomicUsize::new(0), dials: AtomicUsize::new(0) });
    let context = Arc::new(RuntimeContext { network: network.clone(), geoip: Arc::new(Catalog) });
    for (carrier, h3) in [("raw", false), ("ws", false), ("grpc", false), ("xhttp", false), ("mkcp", false), ("xhttp", true), ("hysteria", true)] {
        eprintln!("runtime carrier {carrier} h3={h3}");
        let (mut server, mut client) = settings(carrier, "tls", "stream-one");
        if h3 { server.insert_text("alpn", "h3"); client.insert_text("alpn", "h3"); }
        if carrier == "hysteria" { server.insert_text("auth", "fixture"); client.insert_text("auth", "fixture"); }
        let udp = h3 || carrier == "mkcp";
        let mask = if udp { r#"{"udp":[{"type":"salamander","settings":{"password":"runtime-fixture"}}]}"# } else { "{}" };
        server.insert_text("finalmask", mask);
        client.insert_text("finalmask", mask);
        client.insert_text("sockopt", r#"{"domainStrategy":"ForceIPv4","customSockopt":[{"system":"linux","network":"","level":"0","opt":"2","value":"43","type":"int"}]}"#);
        client.set_runtime(context.clone());
        let before = network.dials.load(Ordering::Relaxed);
        exchange_host(server, client, false, "carrier.fixture.invalid");
        assert!(network.dials.load(Ordering::Relaxed) > before);
    }
    assert!(network.lookups.load(Ordering::Relaxed) >= 7);
}

#[test]
fn raw_udp_retains_large_datagrams() {
    let (server, client) = settings("raw", "none", "auto");
    exchange(server, client, true);
}

#[test]
fn mux_udp_retains_large_datagrams() {
    let (server, mut client) = settings("raw", "none", "auto");
    client.insert_text("mux", "true");
    exchange(server, client, true);
}

#[test]
fn xudp_session_reaches_each_destination() {
    let (server, client) = settings("raw", "none", "auto");
    let (mut inbound, port) = inbound(&server);
    let targets = [5301, 5302].map(|port| Destination::new("example.test", port, Transport::Udp).unwrap());
    let session = landing_vless::land_udp("127.0.0.1", port, &client, &targets[0]).unwrap();
    let mut streams = Vec::new();
    let mut buf = [0; 64];
    for target in &targets {
        session.send_to(target, target.port().to_string().as_bytes()).unwrap();
        let flow = wait_handoff(inbound.as_mut());
        assert_eq!(flow.destination(), target, "one handoff per XUDP destination");
        let stream = flow.stream();
        receive(stream.as_ref(), target.port().to_string().as_bytes(), true);
        send(stream.as_ref(), b"reply", true);
        let deadline = Instant::now() + Duration::from_secs(10);
        let (n, source) = loop {
            match session.recv_from(&mut buf) {
                Err(PlaneFault::Again) if Instant::now() < deadline => {}
                received => break received.unwrap(),
            }
        };
        assert_eq!((&buf[..n], &source), (&b"reply"[..], target));
        streams.push(stream);
    }
}

#[test]
fn mux_tcp_transfers_more_than_one_frame() {
    let (server, mut client) = settings("raw", "none", "auto");
    client.insert_text("mux", "true");
    exchange(server, client, false);
}

#[test]
fn uuid_route_bytes_preserve_account_identity() {
    let (server, _) = settings("raw", "none", "auto");
    let (mut inbound, port) = inbound(&server);
    let mut id = kerlico_vless::parse_id("test-user").unwrap();
    id[6..8].copy_from_slice(&[0xab, 0xcd]);
    let request = kerlico_vless::encode_request(&kerlico_vless::Request {
        id, flow: String::new(), seed: Vec::new(), command: kerlico_vless::Command::Tcp,
        port: 80, address: kerlico_vless::Addr::Domain("example.test".into()),
    }).unwrap();
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    socket.write_all(&request).unwrap();
    socket.write_all(b"route bytes").unwrap();
    let flow = wait_handoff(inbound.as_mut());
    assert_eq!(flow.user().as_str(), "test-user");
    receive(flow.stream().as_ref(), b"route bytes", false);
}

#[test]
fn vision_rejects_plaintext_and_tls12_carriers() {
    for security in ["none", "tls"] {
        let (mut server, mut client) = settings("raw", security, "auto");
        server.insert_text("flow", "xtls-rprx-vision");
        client.insert_text("flow", "xtls-rprx-vision");
        if security == "tls" {
            server.insert_text("maxVersion", "1.2");
            client.insert_text("maxVersion", "1.2");
        }
        let (mut inbound, port) = inbound(&server);
        let target = Destination::new("example.test", 80, Transport::Tcp).unwrap();
        assert!(landing_vless::land("127.0.0.1", port, &client, &target).is_err());
        assert!(matches!(inbound.accept(), Err(OpenError::Again)));
        if security == "none" {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = kerlico_vless::encode_request(&kerlico_vless::Request {
                id: kerlico_vless::parse_id("test-user").unwrap(), flow: "xtls-rprx-vision".into(),
                seed: Vec::new(), command: kerlico_vless::Command::Tcp, port: 80,
                address: kerlico_vless::Addr::Domain("example.test".into()),
            }).unwrap();
            socket.write_all(&request).unwrap();
            assert!(matches!(socket.read(&mut [0; 2]), Ok(0)));
            assert!(matches!(inbound.accept(), Err(OpenError::Again)));
        }
    }
}

#[test]
fn removing_or_replacing_reverse_user_revokes_the_portal() {
    for replace in [false, true] {
        let (server, client) = settings("raw", "none", "auto");
        let (mut inbound, port) = inbound(&server);
        let tag = format!("revoke-{port}");
        let email = UserEmail::parse("test-user").unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "test-user");
        account.insert_text("reverse", &tag);
        inbound.add_user(&email, &account).unwrap();
        let bridge = landing_vless::reverse_bridge("127.0.0.1", port, &client).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let _session = loop {
            match vless::open_reverse(&tag, "example.test", 80, true, b"before revoke") {
                Ok(stream) => break stream,
                Err(OpenError::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                error => panic!("reverse registration: {:?}", error.err()),
            }
        };
        let flow = loop {
            match bridge.accept() {
                Ok(flow) => break flow,
                Err(OpenError::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                error => panic!("reverse flow: {:?}", error.err()),
            }
        };
        receive(flow.stream(), b"before revoke", false);
        if replace {
            account.insert_text("id", "replacement-user");
            inbound.add_user(&email, &account).unwrap();
        } else {
            inbound.remove_user(&email).unwrap();
        }
        assert!(matches!(vless::open_reverse(&tag, "example.test", 80, true, b"after revoke"), Err(OpenError::Again)));
    }
}

#[test]
fn proxy_header_preserves_vless_payload_and_datagram_peer() {
    let (mut server, _) = settings("raw", "none", "auto");
    server.insert_text("acceptProxyProtocol", "true");
    let (mut inbound, port) = inbound(&server);
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let request = kerlico_vless::encode_request(&kerlico_vless::Request {
        id: kerlico_vless::parse_id("test-user").unwrap(), flow: String::new(), seed: Vec::new(),
        command: kerlico_vless::Command::Udp, port: 53, address: kerlico_vless::Addr::Domain("example.test".into()),
    }).unwrap();
    let mut wire = b"PROXY TCP4 203.0.113.1 192.0.2.1 1234 443\r\n".to_vec();
    wire.extend(request);
    wire.extend(kerlico_vless::encode_udp(b"datagram").unwrap());
    socket.write_all(&wire).unwrap();
    let flow = wait_handoff(inbound.as_mut());
    assert_eq!(flow.peer(), Some("203.0.113.1:1234".parse().unwrap()));
    receive(flow.stream().as_ref(), b"datagram", true);
}

#[test]
fn outbound_landing_uses_the_nodes_reverse_portal() {
    struct Counters;
    impl kerlico_shared::Traffic for Counters {
        fn bind(&self, _: &UserEmail, _: &NodeTag, _: &str) -> kerlico_shared::TrafficCounters {
            kerlico_shared::TrafficCounters::new(Default::default(), Default::default())
        }
    }
    let (server, client) = settings("raw", "none", "auto");
    let (mut inbound, port) = inbound(&server);
    let tag = format!("landing-{port}");
    let mut account = Settings::default();
    account.insert_text("id", "reverse-user");
    account.insert_text("reverse", &tag);
    inbound.add_user(&UserEmail::parse("reverse-user").unwrap(), &account).unwrap();
    let dial = inbound.reverse_landing(&tag).unwrap();
    let mut bridge_settings = client.clone();
    bridge_settings.insert_text("id", "reverse-user");
    let bridge = landing_vless::reverse_bridge("127.0.0.1", port, &bridge_settings).unwrap();
    let target = Destination::new("example.test", 80, Transport::Tcp).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let probe = loop {
        match dial(&target) {
            Ok(stream) => break stream,
            Err(OpenError::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            error => panic!("reverse landing registration: {:?}", error.err()),
        }
    };
    drop(probe);
    loop {
        match bridge.accept() {
            Ok(flow) => { drop(flow); break; }
            Err(OpenError::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            error => panic!("reverse probe: {:?}", error.err()),
        }
    }
    let outbound = kerlico_outbound::Outbound::new();
    outbound.install_reverse_landing(dial);
    let (done_tx, done_rx) = mpsc::channel();
    thread::spawn(move || {
        let handoff = wait_handoff(inbound.as_mut());
        let target = kerlico_outbound::DialTarget::from_destination(handoff.destination(), Vec::new());
        let result = outbound.dispatch(handoff, kerlico_outbound::Exit::Landing, target, &Counters);
        done_tx.send(result).unwrap();
    });
    let forward = landing_vless::land("127.0.0.1", port, &client, &target).unwrap();
    send(forward.as_ref(), b"ping over reverse landing", false);
    let remote = loop {
        match bridge.accept() {
            Ok(flow) => break flow,
            Err(OpenError::Again) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            error => panic!("reverse landing flow: {:?}", error.err()),
        }
    };
    assert_eq!(remote.destination(), &target);
    receive(remote.stream(), b"ping over reverse landing", false);
    send(remote.stream(), b"pong", false);
    receive(forward.as_ref(), b"pong", false);
    drop(forward);
    drop(remote);
    drop(bridge);
    assert!(done_rx.recv_timeout(Duration::from_secs(5)).is_ok());
}

#[test]
fn xhttp_tls_modes_transfer_large_streams() {
    for mode in ["packet-up", "stream-up", "stream-one"] {
        eprintln!("XHTTP TLS {mode}");
        let (server, client) = settings("xhttp", "tls", mode);
        exchange(server, client, false);
    }
}

#[test]
fn tcp_masks_remain_below_security_and_transports() {
    let masks = r#"{"tcp":[{"type":"sudoku","settings":{"password":"mask-flow-test","paddingMin":5,"paddingMax":15}}]}"#;
    for (network, security) in [("raw", "none"), ("raw", "tls"), ("raw", "reality"), ("ws", "tls"), ("grpc", "tls"), ("xhttp", "tls"), ("xhttp", "reality")] {
        eprintln!("masked {network}/{security}");
        let (mut server, mut client) = settings(network, security, "stream-one");
        server.insert_text("finalmask", masks);
        client.insert_text("finalmask", masks);
        exchange(server, client, false);
    }
}

#[test]
fn udp_masks_wrap_kcp_before_its_tls_and_vless_layers() {
    let masks = r#"{"udp":[{"type":"mkcp-legacy","settings":{"value":"mask-seed"}},{"type":"salamander","settings":{"password":"mask-pass"}},{"type":"sudoku","settings":{"password":"mask-table"}}]}"#;
    for (security, udp) in [("none", false), ("tls", false), ("tls", true)] {
        let (mut server, mut client) = settings("mkcp", security, "auto");
        server.insert_text("finalmask", masks);
        client.insert_text("finalmask", masks);
        exchange(server, client, udp);
    }
}

#[test]
fn udp_masks_wrap_h3_and_hysteria_datagrams() {
    let masks = r#"{"udp":[{"type":"salamander","settings":{"password":"quic-mask-pass"}},{"type":"sudoku","settings":{"password":"quic-mask-table"}}]}"#;
    for (network, mode) in [("xhttp", "packet-up"), ("xhttp", "stream-one"), ("hysteria", "auto")] {
        eprintln!("masked {network}/{mode} h3");
        let (mut server, mut client) = settings(network, "tls", mode);
        for config in [&mut server, &mut client] {
            config.insert_text("alpn", "h3");
            config.insert_text("auth", "quic-mask-auth");
            config.insert_text("finalmask", masks);
        }
        exchange(server, client, false);
    }
}

#[test]
fn changed_and_removed_uuid_cannot_authenticate() {
    let (settings, _) = settings("raw", "none", "auto");
    let (mut inbound, port) = inbound(&settings);
    let email = UserEmail::parse("test-user").unwrap();
    let mut replacement = Settings::default();
    replacement.insert_text("id", "replacement");
    inbound.add_user(&email, &replacement).unwrap();
    inbound.remove_user(&email).unwrap();
    for id in ["test-user", "replacement"] {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let header = kerlico_vless::encode_request(&kerlico_vless::Request {
            id: kerlico_vless::parse_id(id).unwrap(), flow: String::new(), seed: vec![],
            command: kerlico_vless::Command::Tcp, port: 80,
            address: kerlico_vless::Addr::Domain("example.test".into()),
        }).unwrap();
        socket.write_all(&header).unwrap();
        let mut response = [0; 2];
        match socket.read(&mut response) {
            Ok(0) => {}
            Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {}
            other => panic!("removed account replied: {other:?}"),
        }
    }
    assert!(matches!(inbound.accept(), Err(OpenError::Again)));
}

#[test]
fn xudp_keep_routes_each_datagram_to_its_own_target() {
    use kerlico_vless::{Addr, Command, MuxFrame, Request, DATA, NEW};
    let (settings, _) = settings("raw", "none", "auto");
    let (mut inbound, port) = inbound(&settings);
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(&kerlico_vless::encode_request(&Request {
        id: kerlico_vless::parse_id("test-user").unwrap(), flow: String::new(), seed: Vec::new(),
        command: Command::Mux, port: 0, address: Addr::Domain(String::new()),
    }).unwrap()).unwrap();
    let mut response = [0; 2];
    socket.read_exact(&mut response).unwrap();
    assert_eq!(response, [0, 0]);
    socket.write_all(&kerlico_vless::encode_mux(&MuxFrame {
        id: 0, status: NEW, option: DATA, network: 2, port: 80,
        address: Some(Addr::V4(Ipv4Addr::LOCALHOST)), payload: b"A".to_vec(),
    })).unwrap();
    let first = wait_handoff(&mut *inbound);
    assert_eq!(first.destination().host(), "127.0.0.1");
    assert_eq!(first.destination().port(), 80);
    // Xray XUDP KEEP includes network + destination after the four fixed metadata bytes.
    socket.write_all(&[0, 12, 0, 0, 2, 1, 2, 0, 81, 1, 127, 0, 0, 2, 0, 1, b'B']).unwrap();
    let second = wait_handoff(&mut *inbound);
    assert_eq!(second.destination().host(), "127.0.0.2");
    assert_eq!(second.destination().port(), 81);
    let first = first.stream();
    let second = second.stream();
    receive(first.as_ref(), b"A", true);
    receive(second.as_ref(), b"B", true);
    send(first.as_ref(), b"one", true);
    send(second.as_ref(), b"two", true);
    let mut wire = Vec::new();
    for (port, ip, payload) in [(80, Ipv4Addr::LOCALHOST, b"one"), (81, Ipv4Addr::new(127, 0, 0, 2), b"two")] {
        let frame = loop {
            if let Ok((frame, used)) = kerlico_vless::decode_mux(&wire) {
                wire.drain(..used);
                break frame;
            }
            let mut buf = [0; 256];
            let n = socket.read(&mut buf).unwrap();
            assert!(n > 0);
            wire.extend_from_slice(&buf[..n]);
        };
        assert_eq!(frame.port, port);
        assert_eq!(frame.address, Some(Addr::V4(ip)));
        assert_eq!(frame.payload, payload);
    }
}
