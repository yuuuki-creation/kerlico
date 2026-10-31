use kerlico_config::{NodeFactory, OutboundFactory, Registry, parse};
use kerlico_core::{CancellationToken, ConnectContext, Destination};
use kerlico_engine::Engine;
use kerlico_net::DirectFactory;
use kerlico_socks::{SocksFactory, SocksNodeFactory};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
};

async fn node(
    options: Value,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<kerlico_core::Result<()>>,
) {
    node_on(options, "127.0.0.1:0").await
}

async fn node_on(
    options: Value,
    listen: &str,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<kerlico_core::Result<()>>,
) {
    node_limits(
        options,
        listen,
        json!({"connect_timeout_ms":500,"idle_timeout_ms":1000,"drain_timeout_ms":30}),
    )
    .await
}

async fn node_limits(
    options: Value,
    listen: &str,
    limits: Value,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<kerlico_core::Result<()>>,
) {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(SocksNodeFactory).unwrap();
    let config = json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[],"local_inbounds":[{"tag":"node","type":"socks","listen":listen,"outbound":"exit","options":options}],"limits":limits});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(engine.run(cancel.clone()));
    (address, cancel, task)
}

#[tokio::test]
async fn all_versions_tcp_keep_half_close_and_remote_domain() {
    for version in ["4", "4a", "5"] {
        for domain in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = listener.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
            });
            let auth = json!({"username":"test-node","password":"synthetic-secret"});
            let options = if version == "5" {
                json!({"version":version,"auth":auth})
            } else {
                json!({"version":version,"userid":"local-test"})
            };
            let (address, cancel, task) = node(options.clone()).await;
            let mut outbound = options;
            outbound["server"] = json!({"host":address.ip().to_string(),"port":address.port()});
            let outbound = SocksFactory.build(&outbound).unwrap();
            let target = Destination::new(
                if domain { "localhost" } else { "127.0.0.1" },
                target.port(),
            )
            .unwrap();
            let mut stream = outbound
                .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
                .await
                .unwrap();
            let payload = vec![0x51; 8193];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, payload);
            echo.await.unwrap();
            cancel.cancel();
            task.await.unwrap().unwrap();
        }
    }
}

#[tokio::test]
async fn socks5_udp_preserves_empty_large_and_control_lifetime() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", echo.local_addr().unwrap().port()).unwrap();
    let peer = tokio::spawn(async move {
        let mut bytes = vec![0; 65_535];
        for _ in 0..3 {
            let (count, from) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..count], from).await.unwrap();
        }
    });
    let (address, cancel, task) = node(json!({})).await;
    let outbound = SocksFactory
        .build(&json!({"server":{"host":address.ip().to_string(),"port":address.port()}}))
        .unwrap();
    let mut channel = outbound
        .connect_udp(&target, &ConnectContext::new(Duration::from_secs(2)))
        .await
        .unwrap();
    for payload in [vec![], vec![1; 17], vec![2; 12_000]] {
        channel.sender.send(&payload).await.unwrap();
        let response = timeout(Duration::from_secs(2), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response, payload);
    }
    peer.await.unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
    assert!(
        timeout(Duration::from_secs(2), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn wrong_auth_and_forbidden_command_are_rejected() {
    let (address, cancel, task) = node(json!({"auth":{"username":"a","password":"b"}})).await;
    let outbound=SocksFactory.build(&json!({"server":{"host":"127.0.0.1","port":address.port()},"auth":{"username":"a","password":"wrong"}})).unwrap();
    assert!(
        outbound
            .connect_tcp(
                &Destination::new("127.0.0.1", 9).unwrap(),
                &ConnectContext::new(Duration::from_secs(2))
            )
            .await
            .is_err()
    );
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 255]);
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (address, cancel, task) = node(json!({})).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 9])
        .await
        .unwrap();
    let mut response = [0; 12];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response[3], 7);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn udp_drops_fragments_wrong_source_and_tracks_multiple_targets() {
    let (address, cancel, task) = node(json!({})).await;
    let mut control = TcpStream::connect(address).await.unwrap();
    control
        .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 12];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..2], &[5, 0]);
    assert_eq!(reply[3], 0);
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[10], reply[11]])));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wrong = UdpSocket::bind("127.0.0.2:0").await.unwrap();
    let mut peers = Vec::new();
    for marker in [11u8, 22] {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut bytes = [0; 32];
            let (count, from) = echo.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], &[marker]);
            echo.send_to(&bytes[..count], from).await.unwrap();
        });
        let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
        packet.extend(port.to_be_bytes());
        packet.push(marker);
        wrong.send_to(&packet, relay).await.unwrap();
        let mut fragmented = packet.clone();
        fragmented[2] = 1;
        socket.send_to(&fragmented, relay).await.unwrap();
        socket.send_to(&packet, relay).await.unwrap();
        let mut response = [0; 64];
        let (count, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..count], packet.as_slice());
        peers.push(task);
    }
    for task in peers {
        task.await.unwrap();
    }
    drop(control);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn socks5_node_and_udp_target_families_are_independent() {
    for (listen, target_host) in [("[::1]:0", "127.0.0.1"), ("127.0.0.1:0", "::1")] {
        let echo = UdpSocket::bind((target_host, 0)).await.unwrap();
        let target = Destination::new(target_host, echo.local_addr().unwrap().port()).unwrap();
        let peer = tokio::spawn(async move {
            let mut bytes = [0; 128];
            let (count, from) = echo.recv_from(&mut bytes).await.unwrap();
            echo.send_to(&bytes[..count], from).await.unwrap();
        });
        let (address, cancel, task) = node_on(json!({}), listen).await;
        let out = SocksFactory
            .build(&json!({"server":{"host":address.ip().to_string(),"port":address.port()}}))
            .unwrap();
        let mut channel = out
            .connect_udp(&target, &ConnectContext::new(Duration::from_secs(2)))
            .await
            .unwrap();
        channel.sender.send(b"cross-family").await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), channel.receiver.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            b"cross-family"
        );
        peer.await.unwrap();
        drop(channel);
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}

#[test]
fn rejects_unsupported_and_conflicting_configurations() {
    for options in [
        json!({"version":"6"}),
        json!({"version":"4","auth":{"username":"a","password":"b"}}),
        json!({"auth":{"username":"","password":"b"}}),
        json!({"userid":"unexpected"}),
        json!({"unknown":true}),
    ] {
        assert!(SocksNodeFactory.build(&options).is_err());
    }
    for version in ["4", "4a"] {
        let out = SocksFactory
            .build(&json!({"server":{"host":"127.0.0.1","port":1080},"version":version}))
            .unwrap();
        assert!(!out.capabilities().udp);
    }
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(SocksNodeFactory).unwrap();
    let mut config = json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[],"nodes":[{"tag":"node4","type":"socks","listen":"127.0.0.1:0","outbound":"exit","options":{"auth":{"username":"a","password":"b"}}},{"tag":"node6","type":"socks","listen":"[::1]:0","outbound":"exit","options":{"auth":{"username":"a","password":"b"}}}]});
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_err()
    );
    let mut local = json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[],"local_inbounds":[{"tag":"local","type":"socks","listen":"127.0.0.1:0","outbound":"exit","options":{}}]});
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&local).unwrap()).unwrap())
            .is_ok()
    );
    local["local_inbounds"][0]["listen"] = json!("0.0.0.0:1080");
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&local).unwrap()).unwrap())
            .is_err()
    );
    local["local_inbounds"][0]["listen"] = json!("127.0.0.1:0");
    local["local_inbounds"][0]["type"] = json!("direct");
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&local).unwrap()).unwrap())
            .is_err()
    );
    config["nodes"] = json!([{"tag":"node","type":"socks","listen":"0.0.0.0:1080","outbound":"exit","options":{}}]);
    assert!(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .is_err()
    );
}

async fn association(address: SocketAddr) -> (TcpStream, UdpSocket, SocketAddr) {
    let mut control = TcpStream::connect(address).await.unwrap();
    control
        .write_all(&[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 12];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..6], &[5, 0, 5, 0, 0, 1]);
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[10], reply[11]])));
    (
        control,
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        relay,
    )
}

#[tokio::test]
async fn udp_source_port_control_close_and_target_budget_are_enforced() {
    let (address,cancel,task)=node_limits(json!({}),"127.0.0.1:0",json!({"max_sessions":2,"connect_timeout_ms":300,"idle_timeout_ms":2000,"drain_timeout_ms":30})).await;
    let (control, client, relay) = association(address).await;
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend(first.local_addr().unwrap().port().to_be_bytes());
    packet.push(7);
    client.send_to(&packet, relay).await.unwrap();
    let mut bytes = [0; 128];
    let (count, from) = timeout(Duration::from_secs(1), first.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..count], &[7]);
    first.send_to(&bytes[..count], from).await.unwrap();
    timeout(Duration::from_secs(1), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let wrong_port = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    wrong_port.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), first.recv_from(&mut bytes))
            .await
            .is_err()
    );
    packet[8..10].copy_from_slice(&second.local_addr().unwrap().port().to_be_bytes());
    client.send_to(&packet, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), second.recv_from(&mut bytes))
            .await
            .is_err()
    );
    drop(control);
    timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(socket) = UdpSocket::bind(relay).await {
                drop(socket);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn handshake_timeout_truncation_bad_address_and_connect_failure() {
    let (address, cancel, task) = node_limits(
        json!({}),
        "127.0.0.1:0",
        json!({"connect_timeout_ms":60,"idle_timeout_ms":1000,"drain_timeout_ms":30}),
    )
    .await;
    let mut silent = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(1), silent.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let mut truncated = TcpStream::connect(address).await.unwrap();
    truncated.write_all(&[5, 1, 0, 5, 1]).await.unwrap();
    truncated.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(1), truncated.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [5, 0]);
    let mut invalid = TcpStream::connect(address).await.unwrap();
    invalid.write_all(&[5, 1, 0, 5, 1, 0, 99]).await.unwrap();
    let mut reply = [0; 12];
    invalid.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[3], 8);
    let mut zero_port = TcpStream::connect(address).await.unwrap();
    zero_port
        .write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .unwrap();
    zero_port.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[3], 8);
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let mut refused = TcpStream::connect(address).await.unwrap();
    let mut request = vec![5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    refused.write_all(&request).await.unwrap();
    refused.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[3], 5);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn udp_relay_family_can_differ_from_tcp_control() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay = UdpSocket::bind("[::1]:0").await.unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let control = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut reply = vec![5, 0, 0, 4];
        reply.extend(std::net::Ipv6Addr::LOCALHOST.octets());
        reply.extend(relay_port.to_be_bytes());
        stream.write_all(&reply).await.unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
    });
    let udp = tokio::spawn(async move {
        let mut bytes = [0; 128];
        let (count, source) = relay.recv_from(&mut bytes).await.unwrap();
        assert!(source.is_ipv6());
        assert_eq!(&bytes[..count], &[0, 0, 0, 1, 127, 0, 0, 1, 0, 9, 7]);
        relay.send_to(&bytes[..count], source).await.unwrap();
    });
    let outbound = SocksFactory
        .build(&json!({"server":{"host":"127.0.0.1","port":address.port()}}))
        .unwrap();
    let mut channel = outbound
        .connect_udp(
            &Destination::new("127.0.0.1", 9).unwrap(),
            &ConnectContext::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    channel.sender.send(&[7]).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        [7]
    );
    drop(channel);
    udp.await.unwrap();
    timeout(Duration::from_secs(2), control)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn malformed_udp_does_not_keep_an_idle_association_alive() {
    let (address, cancel, task) = node_limits(
        json!({}),
        "127.0.0.1:0",
        json!({"connect_timeout_ms":1000,"idle_timeout_ms":90,"drain_timeout_ms":30}),
    )
    .await;
    let (mut control, socket, relay) = association(address).await;
    let stop = CancellationToken::new();
    let flooding = stop.clone();
    let producer = tokio::spawn(async move {
        loop {
            tokio::select! {_=flooding.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(2))=>{socket.send_to(&[0,0],relay).await.unwrap();}}
        }
    });
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_millis(500), control.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    stop.cancel();
    producer.await.unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn one_way_udp_activity_preserves_the_target_socket() {
    let (address, cancel, task) = node_limits(
        json!({}),
        "127.0.0.1:0",
        json!({"connect_timeout_ms":1000,"idle_timeout_ms":180,"drain_timeout_ms":30}),
    )
    .await;
    let (control, client, relay) = association(address).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend(target.local_addr().unwrap().port().to_be_bytes());
    packet.push(7);
    let mut peer = None;
    let mut bytes = [0; 128];
    for index in 0..6 {
        client.send_to(&packet, relay).await.unwrap();
        let (count, source) = timeout(Duration::from_secs(1), target.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..count], &[7]);
        if let Some(previous) = peer {
            assert_eq!(source, previous);
        } else {
            peer = Some(source);
        }
        if index < 5 {
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    }
    target.send_to(&[7], peer.unwrap()).await.unwrap();
    let (count, _) = timeout(Duration::from_secs(1), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..count], packet.as_slice());
    drop(control);
    cancel.cancel();
    task.await.unwrap().unwrap();
}
