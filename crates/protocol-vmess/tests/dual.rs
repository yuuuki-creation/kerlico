use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel,
    Destination, InboundContext, NodeEvent, NodeObserver, Outbound, Result, StreamBudget,
};
use kerlico_vmess::{VmessFactory, VmessNodeFactory};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
};
const ID: &str = "00000000-0000-4000-8000-000000000001";
struct Events;
impl NodeObserver for Events {
    fn record(&self, _: NodeEvent) {}
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
fn context(cancel: CancellationToken) -> InboundContext {
    InboundContext {
        peer_addr: None,
        local_addr: None,
        cancel,
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(8),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 32,
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(32)),
            Arc::new(Semaphore::new(32)),
        ),
        events: Arc::new(Events),
    }
}
struct Fixture {
    outbound: Arc<dyn Outbound>,
    options: Value,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
async fn fixture(cipher: &str, transport: Value, tls: bool, host: &str, flags: u8) -> Fixture {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let key = cert.signing_key.serialize_pem();
    let server_security = if tls {
        json!({"type":"tls","certificate_pem":pem,"private_key_pem":key})
    } else {
        json!({"type":"none"})
    };
    let node = VmessNodeFactory
        .build(&json!({"uuid":ID,"security":server_security,"transport":transport}))
        .unwrap();
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let scope = cancel.clone();
    let access = Arc::new(Access(
        kerlico_net::DirectFactory.build(&json!({})).unwrap(),
    ));
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {_=scope.cancelled()=>break,result=listener.accept()=>{let(stream,peer)=result.unwrap();let node=node.clone();let access=access.clone();let mut context=context(scope.clone());context.peer_addr=Some(peer);context.local_addr=Some(stream.local_addr().unwrap());tasks.spawn(async move{let _=node.handle(Box::new(stream),access,context).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });
    let client_security = if tls {
        json!({"type":"tls","server_name":"localhost","ca_pem":pem})
    } else {
        json!({"type":"none"})
    };
    let options = json!({"server":{"host":host,"port":port},"uuid":ID,"security":cipher,"tls":client_security,"transport":transport,"chunk_masking":flags&4!=0,"global_padding":flags&8!=0,"authenticated_length":flags&16!=0});
    let outbound = VmessFactory.build(&options).unwrap();
    Fixture {
        outbound,
        options,
        cancel,
        task,
    }
}
async fn tcp_echo(host: &str) -> (Destination, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let destination = Destination::new(host, listener.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {result=listener.accept()=>{let(mut stream,_)=result.unwrap();tasks.spawn(async move{let(mut reader,mut writer)=stream.split();let _=tokio::io::copy(&mut reader,&mut writer).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    (destination, task)
}
async fn udp_echo(host: &str) -> (Destination, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind((host, 0)).await.unwrap();
    let destination = Destination::new(host, socket.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    (destination, task)
}
async fn verify_tcp(f: &Fixture, target: &Destination) {
    let mut stream = f
        .outbound
        .connect_tcp(target, &ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    let data = vec![42; 27000];
    stream.write_all(&data).await.unwrap();
    stream.flush().await.unwrap();
    let mut answer = vec![0; data.len()];
    tokio::time::timeout(Duration::from_secs(4), stream.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, data);
    stream.shutdown().await.unwrap();
    let mut last = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(4), stream.read(&mut last))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
async fn verify_udp(f: &Fixture, target: &Destination) {
    let mut channel = f
        .outbound
        .connect_udp(target, &ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    assert!(channel.sender.send(b"").await.is_err());
    for size in [1, 1200, 12000, 65000] {
        let data = vec![7; size];
        channel.sender.send(&data).await.unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(4), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(answer, data);
    }
}
#[tokio::test]
async fn dual_cipher_transport_security_matrix() {
    let (tcp, tt) = tcp_echo("127.0.0.1").await;
    let (udp, ut) = udp_echo("127.0.0.1").await;
    for cipher in ["aes-128-gcm", "chacha20-poly1305"] {
        for tls in [false, true] {
            for transport in [
                json!({"type":"tcp"}),
                json!({"type":"ws","path":"/vmess"}),
                json!({"type":"httpupgrade","path":"/vmess"}),
                json!({"type":"grpc","service_name":"proxy","multi_mode":false}),
                json!({"type":"grpc","service_name":"proxy","multi_mode":true}),
            ] {
                let f = fixture(cipher, transport, tls, "127.0.0.1", 13).await;
                verify_tcp(&f, &tcp).await;
                verify_udp(&f, &udp).await;
            }
        }
    }
    tt.abort();
    ut.abort();
}
#[tokio::test]
async fn record_flags_ipv6_and_domain() {
    let (tcp, tt) = tcp_echo("::1").await;
    let (udp, ut) = udp_echo("::1").await;
    for flags in [1, 5, 13, 17, 21, 29] {
        for cipher in ["aes-128-gcm", "chacha20-poly1305"] {
            let f = fixture(cipher, json!({"type":"tcp"}), false, "::1", flags).await;
            verify_tcp(&f, &tcp).await;
            verify_udp(&f, &udp).await;
        }
    }
    let (tcp4, t4) = tcp_echo("127.0.0.1").await;
    let domain = Destination::new("localhost", tcp4.port()).unwrap();
    let f = fixture("auto", json!({"type":"tcp"}), true, "::1", 29).await;
    verify_tcp(&f, &domain).await;
    tt.abort();
    ut.abort();
    t4.abort();
}
#[tokio::test]
async fn half_close_preserves_reverse_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"request");
        stream.write_all(b"after-eof").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let f = fixture(
        "chacha20-poly1305",
        json!({"type":"tcp"}),
        true,
        "127.0.0.1",
        29,
    )
    .await;
    let mut stream = f
        .outbound
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(3)))
        .await
        .unwrap();
    stream.write_all(b"request").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, b"after-eof");
    target_task.await.unwrap();
}
#[test]
fn rejects_unknown_and_conflicting_configuration() {
    let base = json!({"server":{"host":"127.0.0.1","port":443},"uuid":ID});
    for (key, value) in [
        ("alter_id", json!(1)),
        ("security", json!("none")),
        ("transport", json!({"type":"xhttp"})),
        ("chunk_masking", json!(false)),
        ("uuid", json!("invalid")),
    ] {
        let mut options = base.clone();
        options[key] = value;
        assert!(VmessFactory.build(&options).is_err());
    }
    assert!(
        VmessNodeFactory
            .build(&json!({"users":[{"uuid":ID},{"uuid":ID}]}))
            .is_err()
    );
    assert!(
        VmessNodeFactory
            .build(&json!({"uuid":ID,"users":[{"uuid":ID}]}))
            .is_err()
    );
    let node = VmessNodeFactory.build(&json!({"uuid":ID})).unwrap();
    assert!(!node.requires_loopback());
    assert_eq!(node.credential_fingerprints().len(), 1);
}

#[tokio::test]
async fn wrong_uuid_certificate_name_and_cancellation_fail() {
    let (target, task) = tcp_echo("127.0.0.1").await;
    let f = fixture("aes-128-gcm", json!({"type":"tcp"}), true, "127.0.0.1", 13).await;
    let mut wrong = f.options.clone();
    wrong["tls"]["server_name"] = json!("wrong.invalid");
    let outbound = VmessFactory.build(&wrong).unwrap();
    assert!(
        outbound
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
            .await
            .is_err()
    );
    let mut wrong = f.options.clone();
    wrong["uuid"] = json!("00000000-0000-4000-8000-000000000002");
    let outbound = VmessFactory.build(&wrong).unwrap();
    let mut stream = outbound
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
        .await
        .unwrap();
    let _ = stream.write_all(b"must-not-pass").await;
    let _ = stream.flush().await;
    let mut bytes = [0; 13];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes)).await;
    assert!(matches!(result, Ok(Ok(0)) | Ok(Err(_))));
    let context = ConnectContext::new(Duration::from_secs(2));
    context.cancel.cancel();
    assert!(matches!(
        f.outbound.connect_tcp(&target, &context).await,
        Err(kerlico_core::Error::Cancelled)
    ));
    let mut options = f.options.clone();
    options["no_termination_signal"] = json!(true);
    assert!(!VmessFactory.build(&options).unwrap().capabilities().tcp_eof);
    task.abort();
}
