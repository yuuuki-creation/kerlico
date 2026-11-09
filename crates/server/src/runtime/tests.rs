use super::*;
use std::io::{Read, Write};

#[test]
fn configured_hosts_and_system_dns_remain_distinct_and_scope_outlives_server_safely() {
    let outbound = Outbound::new();
    let mut config = dns::Config::default();
    config.hosts.insert(
        "localhost".into(),
        vec![
            "203.0.113.9".parse().unwrap(),
            "2001:db8::9".parse().unwrap(),
        ],
    );
    let context = context(
        &outbound,
        Arc::new(RwLock::new(config)),
        geodata::Catalog::empty(),
        true,
    );
    let addresses = context
        .network
        .lookup_ip(
            "localhost",
            443,
            Some(AddressFamily::V4),
            ResolutionSource::Configured,
        )
        .unwrap();
    assert_eq!(addresses, ["203.0.113.9:443".parse().unwrap()]);
    let system = context
        .network
        .lookup_ip("localhost", 443, None, ResolutionSource::System)
        .unwrap();
    assert!(system.iter().all(|peer| peer.ip().is_loopback()));
    drop(outbound);
    assert_eq!(
        context
            .network
            .connect(&NetworkDial::direct(
                "127.0.0.1:443".parse().unwrap(),
                kerlico_shared::Transport::Tcp
            ))
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotConnected
    );
}

#[test]
fn loading_config_prepares_dns_before_returning_settings_owner() {
    let loaded = crate::Server::from_config(
        r#"{"inbounds":[],"dns":{"hosts":{"metadata.test":"203.0.113.8"}}}"#,
    )
    .unwrap();
    assert_eq!(
        loaded
            .server
            .runtime()
            .network
            .lookup_ip("metadata.test", 443, None, ResolutionSource::Configured)
            .unwrap(),
        ["203.0.113.8:443".parse().unwrap()]
    );
}

#[test]
fn landing_scope_rejects_self_reference_before_resolving() {
    let outbound = Outbound::new();
    let context = context(
        &outbound,
        Arc::new(RwLock::new(dns::Config::default())),
        geodata::Catalog::empty(),
        false,
    );
    let mut request = NetworkDial::direct(
        "127.0.0.1:443".parse().unwrap(),
        kerlico_shared::Transport::Tcp,
    );
    request.route = NetworkRoute::Selected(OutboundChoice::Manual(Exit::Landing));
    request.addresses.clear();
    request.host = "never-resolve.invalid".into();
    assert_eq!(
        context.network.connect(&request).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn dns_srv_and_txt_follow_the_configured_upstream() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for kind in [33u16, 16] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let mut message = vec![0; u16::from_be_bytes(length) as usize];
            stream.read_exact(&mut message).unwrap();
            assert_eq!(
                &message[message.len() - 4..message.len() - 2],
                &kind.to_be_bytes()
            );
            message[2] = 0x81;
            message[3] = 0x80;
            message[7] = 1;
            let body = if kind == 33 {
                vec![
                    0, 3, 0, 7, 0x20, 0xfb, 6, b't', b'a', b'r', b'g', b'e', b't', 4, b't', b'e',
                    b's', b't', 0,
                ]
            } else {
                let text = b"target.test:8443";
                let mut body = vec![text.len() as u8];
                body.extend(text);
                body
            };
            message.extend([0xc0, 0x0c]);
            message.extend(kind.to_be_bytes());
            message.extend([0, 1, 0, 0, 0, 30]);
            message.extend((body.len() as u16).to_be_bytes());
            message.extend(body);
            stream
                .write_all(&(message.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&message).unwrap();
        }
    });
    let outbound = Outbound::new();
    let config = dns::Config {
        upstreams: vec![dns::Upstream {
            address: peer.ip(),
            port: peer.port(),
            tcp: true,
            choice: OutboundChoice::Manual(Exit::NativeV4),
        }],
        ..dns::Config::default()
    };
    let context = context(
        &outbound,
        Arc::new(RwLock::new(config)),
        geodata::Catalog::empty(),
        true,
    );
    let srv = context
        .network
        .lookup_srv("_test._tcp.service.test")
        .unwrap();
    assert_eq!(
        srv,
        [SrvRecord {
            target: "target.test".into(),
            port: 8443,
            priority: 3,
            weight: 7
        }]
    );
    assert_eq!(
        context.network.lookup_txt("service.test").unwrap(),
        ["target.test:8443"]
    );
    server.join().unwrap();
}
