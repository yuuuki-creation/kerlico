use kerlico_config::{OutboundFactory, Registry, parse};
use kerlico_core::{
    BindEvidence, CancellationToken, ConnectContext, Destination, ServiceContext, TargetBind,
};
use kerlico_egress::{FlowEnd, Telemetry};
use kerlico_engine::Engine;
use kerlico_net::DirectFactory;
use kerlico_socks::{SocksFactory, SocksNodeFactory};
use serde_json::json;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn ended(telemetry: &Telemetry) -> kerlico_egress::FlowRecord {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let records = telemetry.records(0, 8).unwrap();
            if let Some(record) = records.into_iter().find(|record| record.end.is_some()) {
                return record;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}
async fn reply(stream: &mut TcpStream) -> SocketAddr {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix[..3], &[5, 0, 0]);
    let address = match prefix[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await.unwrap();
            IpAddr::from(ip)
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await.unwrap();
            IpAddr::from(ip)
        }
        _ => panic!("测试回复必须是字面地址"),
    };
    SocketAddr::new(address, stream.read_u16().await.unwrap())
}

#[tokio::test]
async fn connect_reply_uses_actual_direct_bind_for_ipv4_and_ipv6() {
    for host in ["127.0.0.1", "::1"] {
        let target = TcpListener::bind((host, 0)).await.unwrap();
        let address = target.local_addr().unwrap();
        let (bound, observed) = tokio::sync::oneshot::channel();
        let echo = tokio::spawn(async move {
            let (mut socket, peer) = target.accept().await.unwrap();
            bound.send(peer).unwrap();
            let mut data = Vec::new();
            socket.read_to_end(&mut data).await.unwrap();
            socket.write_all(&data).await.unwrap();
            socket.write_all(b"tail").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let mut registry = Registry::default();
        registry.register(DirectFactory).unwrap();
        registry.register_node(SocksNodeFactory).unwrap();
        let config = json!({"version":2,"outbounds":[{"tag":"direct","type":"direct"}],"local_inbounds":[{"tag":"node","type":"socks","listen":"127.0.0.1:0","outbound":"direct","options":{}}]});
        let engine = Engine::bind(
            registry
                .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
                .unwrap(),
        )
        .await
        .unwrap();
        let telemetry = engine.telemetry();
        let listen = engine.listeners().unwrap()[0].1;
        let stop = CancellationToken::new();
        let running = tokio::spawn(engine.run(stop.clone()));
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        assert_eq!(client.read_u16().await.unwrap(), 0x0500);
        let mut request = vec![5, 1, 0];
        match address.ip() {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend(ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend(ip.octets());
            }
        }
        request.extend(address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let bound = reply(&mut client).await;
        assert_eq!(bound, observed.await.unwrap());
        client.write_all(b"payload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut data = Vec::new();
        client.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"payloadtail");
        let record = ended(&telemetry).await;
        assert_eq!(record.end, Some(FlowEnd::Completed));
        assert_eq!(
            record.target_bind,
            TargetBind::Known {
                endpoint: Destination::new(&bound.ip().to_string(), bound.port()).unwrap(),
                evidence: BindEvidence::LocalSocket
            }
        );
        assert_eq!(record.usage.upload_bytes, 7);
        assert_eq!(record.usage.download_bytes, 11);
        echo.await.unwrap();
        stop.cancel();
        running.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn upstream_bind_preserves_ipv4_ipv6_domain_and_explicit_unknown() {
    let cases = vec![
        (
            vec![1, 192, 0, 2, 8, 0x23, 0x45],
            Some(Destination::new("192.0.2.8", 0x2345).unwrap()),
        ),
        (
            {
                let mut bytes = vec![4];
                bytes.extend(
                    "2001:db8::8"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                bytes.extend(9090u16.to_be_bytes());
                bytes
            },
            Some(Destination::new("2001:db8::8", 9090).unwrap()),
        ),
        (
            {
                let mut bytes = vec![3, 12];
                bytes.extend(b"bind.invalid");
                bytes.extend(9090u16.to_be_bytes());
                bytes
            },
            Some(Destination::new("bind.invalid", 9090).unwrap()),
        ),
        (vec![1, 0, 0, 0, 0, 0, 0], None),
    ];
    for (binding, expected) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut negotiate = [0; 3];
            stream.read_exact(&mut negotiate).await.unwrap();
            assert_eq!(negotiate, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..4], &[5, 1, 0, 3]);
            let mut host = vec![0; usize::from(header[4]) + 2];
            stream.read_exact(&mut host).await.unwrap();
            assert_eq!(&host[..host.len() - 2], b"website.invalid");
            stream.write_all(&[5, 0, 0]).await.unwrap();
            stream.write_all(&binding).await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let host = ServiceContext::for_test();
        let outbound = SocksFactory
            .compile(&json!({"server":{"host":"127.0.0.1","port":address.port()}}))
            .unwrap()
            .start(host.clone())
            .await
            .unwrap();
        let mut opened = outbound
            .connect_tcp(
                &Destination::new("website.invalid", 443).unwrap(),
                &ConnectContext::new(Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(
            opened.info.target_bind(),
            &expected
                .map(|endpoint| TargetBind::Known {
                    endpoint,
                    evidence: BindEvidence::PeerReported
                })
                .unwrap_or(TargetBind::Unknown)
        );
        opened.stream.write_all(b"echo").await.unwrap();
        let mut echo = [0; 4];
        opened.stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"echo");
        drop(opened);
        endpoint.await.unwrap();
        outbound.shutdown().await.unwrap();
        assert!(
            host.shutdown(tokio::time::Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
    }
}

#[tokio::test]
async fn remote_unknown_uses_named_zero_reply_without_fabricating_target_observation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut method = [0; 3];
        stream.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut head = [0; 5];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..4], &[5, 1, 0, 3]);
        let mut target = vec![0; usize::from(head[4]) + 2];
        stream.read_exact(&mut target).await.unwrap();
        assert_eq!(&target[..target.len() - 2], b"website.invalid");
        stream
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let mut registry = Registry::default();
    registry.register(SocksFactory).unwrap();
    registry.register_node(SocksNodeFactory).unwrap();
    let config = json!({"version":2,"outbounds":[{"tag":"remote","type":"socks","options":{"server":{"host":"127.0.0.1","port":address.port()}}}],"local_inbounds":[{"tag":"node","type":"socks","listen":"127.0.0.1:0","outbound":"remote","options":{}}]});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let telemetry = engine.telemetry();
    let listen = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(client.read_u16().await.unwrap(), 0x0500);
    let mut request = vec![5, 1, 0, 3, 15];
    request.extend(b"website.invalid");
    request.extend(443u16.to_be_bytes());
    client.write_all(&request).await.unwrap();
    assert_eq!(reply(&mut client).await, "0.0.0.0:0".parse().unwrap());
    client.write_all(b"remote").await.unwrap();
    client.shutdown().await.unwrap();
    let mut data = Vec::new();
    client.read_to_end(&mut data).await.unwrap();
    assert_eq!(data, b"remote");
    let record = ended(&telemetry).await;
    assert_eq!(record.target_bind, TargetBind::Unknown);
    assert_eq!(record.observed_target, None);
    assert_eq!(
        record.original.unwrap().target(),
        &Destination::new("website.invalid", 443).unwrap()
    );
    assert_eq!(record.end, Some(FlowEnd::Completed));
    proxy.await.unwrap();
    stop.cancel();
    running.await.unwrap().unwrap();
}
