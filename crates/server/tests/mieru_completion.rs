#![cfg(feature = "mieru")]

use kerlico_shared::{ListenAddr, NodeTag, Settings, UserEmail};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
use std::time::Duration;

fn tag() -> NodeTag {
    NodeTag::parse("test-node").unwrap()
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn dropping_a_node_releases_tcp_and_udp_listeners() {
    for transport in ["TCP", "UDP"] {
        let p = port();
        let mut settings = Settings::default();
        settings.insert_text("transport", transport);
        let bind = ListenAddr::v4(Ipv4Addr::LOCALHOST, p).unwrap();
        let node = mieru::listen(&tag(), &bind, &settings).unwrap();
        drop(node);
        if transport == "TCP" {
            assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, p)).is_ok());
        } else {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                if UdpSocket::bind((Ipv4Addr::LOCALHOST, p)).is_ok() {
                    break;
                }
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

#[test]
fn a_failed_range_bind_rolls_back_earlier_ports() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = occupied.local_addr().unwrap().port();
    assert!(p > 1025);
    let available = TcpListener::bind((Ipv4Addr::LOCALHOST, p - 1)).unwrap();
    drop(available);
    let mut settings = Settings::default();
    settings.insert_text("portRange", format!("{}-{p}", p - 1));
    assert!(mieru::listen(
        &tag(),
        &ListenAddr::v4(Ipv4Addr::LOCALHOST, p - 1).unwrap(),
        &settings
    )
    .is_err());
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, p - 1)).is_ok());
}

#[test]
fn an_ipv6_node_does_not_accept_ipv4() {
    let p = port();
    let node = mieru::listen(
        &tag(),
        &ListenAddr::v6(Ipv6Addr::UNSPECIFIED, p).unwrap(),
        &Settings::default(),
    )
    .unwrap();
    assert!(TcpStream::connect_timeout(
        &format!("127.0.0.1:{p}").parse().unwrap(),
        Duration::from_millis(200)
    )
    .is_err());
    assert!(TcpStream::connect_timeout(
        &format!("[::1]:{p}").parse().unwrap(),
        Duration::from_secs(1)
    )
    .is_ok());
    drop(node);
}

#[test]
fn a_username_cannot_replace_another_users_credentials() {
    let p = port();
    let mut node = mieru::listen(
        &tag(),
        &ListenAddr::v4(Ipv4Addr::LOCALHOST, p).unwrap(),
        &Settings::default(),
    )
    .unwrap();
    let mut account = Settings::default();
    account.insert_text("username", "test-account");
    account.insert_text("password", "test-password");
    node.add_user(&UserEmail::parse("first-user").unwrap(), &account)
        .unwrap();
    assert!(node
        .add_user(&UserEmail::parse("second-user").unwrap(), &account)
        .is_err());
    node.remove_user(&UserEmail::parse("first-user").unwrap())
        .unwrap();
    node.add_user(&UserEmail::parse("second-user").unwrap(), &account)
        .unwrap();
}

#[cfg(feature = "landing-mieru")]
#[test]
fn udp_landing_preserves_empty_and_large_datagrams() {
    use kerlico_outbound::{DialTarget, Exit, Outbound};
    use kerlico_shared::{Destination, Handoff, InboundStream, PlaneFault, Transport};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    struct State {
        packets: VecDeque<Vec<u8>>,
        replies: Vec<Vec<u8>>,
        done: bool,
    }
    struct Packets(Arc<Mutex<State>>);
    impl InboundStream for Packets {
        fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
            let mut state = self.0.lock().unwrap();
            if state.done {
                return Err(PlaneFault::Closed);
            }
            if let Some(packet) = state.packets.pop_front() {
                buf[..packet.len()].copy_from_slice(&packet);
                return Ok(packet.len());
            }
            drop(state);
            std::thread::sleep(Duration::from_millis(10));
            Err(PlaneFault::Again)
        }
        fn write_to_user(&self, data: &[u8]) -> Result<usize, PlaneFault> {
            let mut state = self.0.lock().unwrap();
            state.replies.push(data.to_vec());
            state.done = state.replies.len() == 2;
            Ok(data.len())
        }
    }
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    echo.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let target = echo.local_addr().unwrap();
    let echo_task = std::thread::spawn(move || {
        let mut buf = vec![0; 65535];
        for _ in 0..2 {
            let (n, peer) = echo.recv_from(&mut buf).unwrap();
            echo.send_to(&buf[..n], peer).unwrap();
        }
    });
    let p = port();
    let document = format!(
        r#"{{"inbounds":[{{"tag":"fixture","protocol":"mieru","listen":"127.0.0.1","port":{p},"outbound":"native-v4","settings":{{"users":[{{"email":"test-user","username":"test-user","password":"test-password"}}]}}}}]}}"#
    );
    let mut loaded = kerlico_server::Server::from_config(&document).unwrap();
    std::thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
    let outbound = Outbound::new();
    let mut settings = Settings::default();
    settings.insert_text("username", "test-user");
    settings.insert_text("password", "test-password");
    settings.insert_text("multiplexing", "MULTIPLEXING_HIGH");
    outbound.install_landing(landing_mieru::land, "127.0.0.1".into(), p, settings);
    let large: Vec<u8> = (0..32768).map(|n| (n % 251) as u8).collect();
    let state = Arc::new(Mutex::new(State {
        packets: VecDeque::from([Vec::new(), large.clone()]),
        replies: Vec::new(),
        done: false,
    }));
    let handoff = Handoff::new(
        tag(),
        UserEmail::parse("test-user").unwrap(),
        Destination::new("127.0.0.1", target.port(), Transport::Udp).unwrap(),
        Box::new(Packets(state.clone())),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(outbound.dispatch(
            handoff,
            Exit::Landing,
            DialTarget {
                host: "127.0.0.1".into(),
                port: target.port(),
                transport: Transport::Udp,
                addresses: Vec::new(),
            },
            &kerlico_server::Stats::new(),
        ))
        .unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_secs(15)).unwrap().is_ok());
    assert_eq!(state.lock().unwrap().replies, vec![Vec::<u8>::new(), large]);
    echo_task.join().unwrap();
}
