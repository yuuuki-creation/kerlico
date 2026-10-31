use kerlico_anytls::{AnyTlsFactory, AnyTlsNodeFactory};
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    Destination, InboundContext, Outbound, Result, StreamBudget,
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
};
struct Observer;
impl kerlico_core::NodeObserver for Observer {
    fn record(&self, _: kerlico_core::NodeEvent) {}
}
struct Access(Arc<dyn Outbound>);
impl AccessService for Access {
    fn connect_tcp<'a>(
        &'a self,
        t: &'a Destination,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.0.connect_tcp(t, c)
    }
    fn connect_udp<'a>(
        &'a self,
        t: &'a Destination,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.0.connect_udp(t, c)
    }
}
async fn fixture() -> (
    Arc<dyn Outbound>,
    CancellationToken,
    Arc<AtomicUsize>,
    serde_json::Value,
) {
    fixture_on("127.0.0.1", "test-password").await
}
async fn fixture_on(
    host: &str,
    password: &str,
) -> (
    Arc<dyn Outbound>,
    CancellationToken,
    Arc<AtomicUsize>,
    serde_json::Value,
) {
    fixture_with_budget(
        host,
        password,
        StreamBudget::new(Arc::new(Semaphore::new(16)), Arc::new(Semaphore::new(16))),
    )
    .await
}
async fn fixture_with_budget(
    host: &str,
    password: &str,
    budget: StreamBudget,
) -> (
    Arc<dyn Outbound>,
    CancellationToken,
    Arc<AtomicUsize>,
    serde_json::Value,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let key = cert.signing_key.serialize_pem();
    let node = AnyTlsNodeFactory
        .build(&json!({"passwords":[password],"tls":{"certificate_pem":pem,"private_key_pem":key}}))
        .unwrap();
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let access = Arc::new(Access(
        kerlico_net::DirectFactory.build(&json!({})).unwrap(),
    ));
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let stream =
                tokio::select! {_ = stop.cancelled()=>break,r=listener.accept()=>r.unwrap().0};
            count.fetch_add(1, Ordering::AcqRel);
            let node = node.clone();
            let access = access.clone();
            let context = InboundContext {
            peer_addr: None,
            local_addr: None,
                events: Arc::new(Observer),
                cancel: stop.clone(),
                connect_timeout: Duration::from_secs(3),
                idle_timeout: Duration::from_secs(10),
                drain_timeout: Duration::from_secs(1),
                max_datagram_size: 65535,
                max_streams: 16,
                stream_budget: budget.clone(),
            };
            tokio::spawn(async move {
                let _ = node.handle(Box::new(stream), access, context).await;
            });
        }
    });
    let options = json!({"server":{"host":host,"port":port},"password":password,"tls":{"server_name":"localhost","ca_pem":pem}});
    let outbound = AnyTlsFactory.build(&options).unwrap();
    (outbound, cancel, accepted, options)
}
#[tokio::test]
async fn tls_tcp_udp_and_pool_reuse() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", echo.local_addr().unwrap().port()).unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let (outbound, cancel, count, _) = fixture().await;
    let context = ConnectContext::new(Duration::from_secs(3));
    for _ in 0..3 {
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
        stream.write_all(b"anytls-test").await.unwrap();
        let mut data = [0; 11];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data, b"anytls-test");
        drop(stream);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(count.load(Ordering::Acquire), 1);
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", udp.local_addr().unwrap().port()).unwrap();
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            udp.send_to(&buf[..n], peer).await.unwrap();
        }
    });
    let mut channel = outbound.connect_udp(&target, &context).await.unwrap();
    for data in [vec![], b"uot-v2".to_vec(), vec![42; 65507]] {
        channel.sender.send(&data).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(3), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(data, answer);
    }
    cancel.cancel();
    echo_task.abort();
    udp_task.abort();
}
#[test]
fn configuration_rejects_invalid_and_credentials_are_scoped() {
    for value in [
        json!({}),
        json!({"server":{"host":"localhost","port":443},"password":"","tls":{"server_name":"localhost"}}),
        json!({"server":{"host":"localhost","port":443},"password":"valid","tls":{"server_name":"localhost"},"transport":"ws"}),
    ] {
        assert!(AnyTlsFactory.build(&value).is_err());
    }
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = json!({"certificate_pem":cert.cert.pem(),"private_key_pem":cert.signing_key.serialize_pem()});
    let first = AnyTlsNodeFactory
        .build(&json!({"passwords":["first"],"tls":tls}))
        .unwrap();
    let second = AnyTlsNodeFactory
        .build(&json!({"passwords":["second"],"tls":tls}))
        .unwrap();
    assert_ne!(
        first.credential_fingerprints(),
        second.credential_fingerprints()
    );
    assert!(!first.requires_loopback());
    assert!(
        AnyTlsNodeFactory
            .build(&json!({"passwords":["same","same"],"tls":tls}))
            .is_err()
    );
}

struct Reference(std::process::Child);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn launch_reference(config: serde_json::Value, label: &str) -> Reference {
    let binary = std::env::var("ANYTLS_SING_BOX").expect("缺少固定参考程序");
    let directory = std::env::var("ANYTLS_TEST_DIR").expect("缺少私有测试目录");
    let path = std::path::Path::new(&directory).join(format!("{label}.json"));
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = std::fs::File::create(std::path::Path::new(&directory).join(format!("{label}.log")))
        .unwrap();
    let process = Reference(
        std::process::Command::new(binary)
            .args(["run", "-c"])
            .arg(path)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    process
}
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}
async fn socks(port: u16, command: u8, target_port: u16) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, command, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    stream
}
async fn socks_reply(stream: &mut tokio::net::TcpStream) -> u16 {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[1], 0);
    let length = match head[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await.unwrap() as usize,
        _ => panic!("SOCKS 地址不合法"),
    };
    let mut ignored = vec![0; length];
    stream.read_exact(&mut ignored).await.unwrap();
    stream.read_u16().await.unwrap()
}
#[tokio::test]
#[ignore = "仅在 worker 配置固定 sing-box 后执行"]
async fn sing_box_both_roles_tcp_and_uot_v2() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = echo.local_addr().unwrap().port();
    let tcp_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    let udp_task = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        loop {
            let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
            udp.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let port = free_port().await;
    let server=launch_reference(json!({"log":{"level":"debug"},"inbounds":[{"type":"anytls","listen":"127.0.0.1","listen_port":port,"users":[{"name":"test","password":"test-password"}],"tls":{"enabled":true,"certificate":[pem],"key":[cert.signing_key.serialize_pem()]}}],"outbounds":[{"type":"direct"}]}),"reference-server").await;
    let options = json!({"server":{"host":"127.0.0.1","port":port},"password":"test-password","tls":{"server_name":"localhost","ca_pem":pem}});
    let outbound = AnyTlsFactory.build(&options).unwrap();
    let context = ConnectContext::new(Duration::from_secs(5));
    for _ in 0..3 {
        let target = Destination::new("127.0.0.1", tcp_port).unwrap();
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
        let payload = vec![21; 262144];
        stream.write_all(&payload).await.unwrap();
        let mut data = vec![0; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, payload);
        drop(stream);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let target = Destination::new("127.0.0.1", udp_port).unwrap();
    let mut channel = outbound.connect_udp(&target, &context).await.unwrap();
    for payload in [vec![], b"reference-server".to_vec(), vec![33; 12000]] {
        channel.sender.send(&payload).await.unwrap();
        let data = tokio::time::timeout(Duration::from_secs(5), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(data, payload);
    }
    let mut wrong = options;
    wrong["password"] = json!("wrong-password");
    let bad = AnyTlsFactory.build(&wrong).unwrap();
    let target = Destination::new("127.0.0.1", tcp_port).unwrap();
    let mut stream = bad.connect_tcp(&target, &context).await.unwrap();
    let _ = stream.write_all(b"rejected").await;
    let mut byte = [0];
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
        Ok(Ok(1))
    ));
    drop(server);
    let (_, cancel, _, options) = fixture().await;
    let socks_port = free_port().await;
    let client=launch_reference(json!({"log":{"level":"debug"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":socks_port}],"outbounds":[{"type":"anytls","tag":"proxy","server":"127.0.0.1","server_port":options["server"]["port"],"password":"test-password","tls":{"enabled":true,"server_name":"localhost","certificate":[options["tls"]["ca_pem"]]}}],"route":{"final":"proxy"}}),"reference-client").await;
    for _ in 0..3 {
        let mut stream = socks(socks_port, 1, tcp_port).await;
        socks_reply(&mut stream).await;
        stream.write_all(b"client-role").await.unwrap();
        let mut data = [0; 11];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data, b"client-role");
    }
    let mut control = socks(socks_port, 3, 0).await;
    let relay = socks_reply(&mut control).await;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(("127.0.0.1", relay)).await.unwrap();
    for payload in [vec![], b"reference-client".to_vec(), vec![44; 12000]] {
        let mut wire = vec![0, 0, 0, 1, 127, 0, 0, 1];
        wire.extend_from_slice(&udp_port.to_be_bytes());
        wire.extend_from_slice(&payload);
        udp.send(&wire).await.unwrap();
        let mut bytes = vec![0; 65535];
        let n = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[10..n], payload);
    }
    drop(client);
    cancel.cancel();
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn separate_ipv4_ipv6_credentials_and_cross_family_targets() {
    let echo = TcpListener::bind("[::1]:0").await.unwrap();
    let target = Destination::new("::1", echo.local_addr().unwrap().port()).unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let (v4, stop4, _, options4) = fixture_on("127.0.0.1", "node-four-password").await;
    let (v6, stop6, _, options6) = fixture_on("::1", "node-six-password").await;
    let context = ConnectContext::new(Duration::from_secs(3));
    for outbound in [v4, v6] {
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
        stream.write_all(b"node").await.unwrap();
        let mut data = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data, b"node");
    }
    for (mut options, password) in [
        (options4, "node-six-password"),
        (options6, "node-four-password"),
    ] {
        options["password"] = json!(password);
        let outbound = AnyTlsFactory.build(&options).unwrap();
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
        let _ = stream.write_all(b"must-fail").await;
        let mut byte = [0];
        assert!(!matches!(
            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
            Ok(Ok(1))
        ));
    }
    let context = ConnectContext::new(Duration::from_secs(1));
    context.cancel.cancel();
    let (outbound, stop, _, _) = fixture().await;
    assert!(matches!(
        outbound.connect_tcp(&target, &context).await,
        Err(kerlico_core::Error::Cancelled)
    ));
    stop.cancel();
    stop4.cancel();
    stop6.cancel();
    echo_task.abort();
}

#[tokio::test]
async fn closed_budget_refuses_new_stream_and_drains_existing() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", echo.local_addr().unwrap().port()).unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let slots = Arc::new(Semaphore::new(16));
    let budget = StreamBudget::new(Arc::new(Semaphore::new(16)), slots.clone());
    let (outbound, stop, _, _) = fixture_with_budget("127.0.0.1", "drain-password", budget).await;
    let context = ConnectContext::new(Duration::from_secs(2));
    let mut existing = outbound.connect_tcp(&target, &context).await.unwrap();
    existing.write_all(b"before").await.unwrap();
    let mut data = [0; 6];
    existing.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"before");
    slots.close();
    existing.write_all(b"drains").await.unwrap();
    existing.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"drains");
    let mut refused = outbound.connect_tcp(&target, &context).await.unwrap();
    let _ = refused.write_all(b"denied").await;
    let mut byte = [0];
    assert!(!matches!(
        tokio::time::timeout(Duration::from_secs(1), refused.read(&mut byte)).await,
        Ok(Ok(1))
    ));
    existing.write_all(b"active").await.unwrap();
    existing.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"active");
    stop.cancel();
    echo_task.abort();
}

#[tokio::test]
async fn finite_target_preserves_response_before_fin() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", echo.local_addr().unwrap().port()).unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let n = stream.read_u32().await.unwrap() as usize;
                let mut data = vec![0; n];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
            });
        }
    });
    let (outbound, stop, _, _) = fixture().await;
    let context = ConnectContext::new(Duration::from_secs(2));
    let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
    let data = vec![11; 262144];
    stream.write_u32(data.len() as u32).await.unwrap();
    stream.write_all(&data).await.unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, received);
    stop.cancel();
    echo_task.abort();
}

#[tokio::test]
async fn client_shutdown_preserves_large_response_and_reuses_session() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", echo.local_addr().unwrap().port()).unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let n = stream.read_u32().await.unwrap() as usize;
                let mut data = vec![0; n];
                stream.read_exact(&mut data).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
                stream.write_all(&data).await.unwrap();
            });
        }
    });
    let (outbound, stop, accepted, _) = fixture().await;
    let context = ConnectContext::new(Duration::from_secs(3));
    for size in [128 * 1024, 256 * 1024] {
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
        let data = vec![31; size];
        stream.write_u32(data.len() as u32).await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(
            stream.write_all(b"closed").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data.len(), received.len());
        assert_eq!(data, received);
        drop(stream);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(accepted.load(Ordering::Acquire), 1);
    stop.cancel();
    echo_task.abort();
    let _ = echo_task.await;
}
