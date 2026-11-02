#![cfg(target_os = "linux")]
//! 需要独立网络命名空间和 CAP_NET_ADMIN：
//! `cargo test -p kerlico-tun --test netns --no-run && unshare -n cargo test -p kerlico-tun --test netns --offline -- --ignored`

use kerlico_config::{OutboundFactory, OutboundPlan, Registry, parse};
use kerlico_core::{
    BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, Destination, Error,
    OpenedTcp, Outbound, Result, TargetPolicy, TcpConnectInfo,
};
use kerlico_engine::Engine;
use kerlico_tun::TunNodeFactory;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

struct EchoSender(mpsc::UnboundedSender<(Destination, Vec<u8>)>);
impl DatagramAssociationSender for EchoSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send((target.clone(), packet.to_vec()))
                .map_err(|_| Error::Cancelled)
        })
    }
}
struct EchoReceiver(mpsc::UnboundedReceiver<(Destination, Vec<u8>)>);
impl DatagramAssociationReceiver for EchoReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<(Destination, Vec<u8>)>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}

/// 进程内回显目标，不开真实 socket，避免回包来源成为本机地址被内核丢弃。
struct Echo;
impl Outbound for Echo {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async {
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let mut bytes = vec![0; 8192];
                while let Ok(length) = server.read(&mut bytes).await {
                    if length == 0 || server.write_all(&bytes[..length]).await.is_err() {
                        break;
                    }
                }
            });
            Ok(OpenedTcp {
                stream: Box::new(client),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试出站只提供关联")) })
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async {
            let (sender, receiver) = mpsc::unbounded_channel();
            Ok(DatagramAssociation {
                sender: Box::new(EchoSender(sender)),
                receiver: Box::new(EchoReceiver(receiver)),
            })
        })
    }
}
struct EchoFactory;
impl OutboundFactory for EchoFactory {
    fn kind(&self) -> &'static str {
        "echo"
    }
    fn compile(&self, _: &Value) -> Result<OutboundPlan> {
        Ok(OutboundPlan::new(
            Echo.capabilities(),
            true,
            TargetPolicy::Remote,
            |_| Box::pin(async { Ok(Arc::new(Echo) as Arc<dyn Outbound>) }),
        ))
    }
}

fn connect_with_retry(target: &str) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect_timeout(&target.parse().unwrap(), Duration::from_secs(2)) {
            Ok(stream) => return stream,
            Err(error) if Instant::now() > deadline => panic!("TUN 连接失败：{error}"),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 root，并在独立网络命名空间内运行"]
async fn kernel_packets_reach_the_dispatcher_and_return() {
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let mut registry = Registry::default();
    registry.register(EchoFactory).unwrap();
    registry.register_node(TunNodeFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"echo"}],
        "local_inbounds": [{"tag":"tun","type":"tun","listen":"127.0.0.1:0","outbound":"exit",
            "options":{"name":"kl0","addresses":["198.18.0.1/24"],"mtu":1500}}],
        "limits": {"drain_timeout_ms":1000}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let telemetry = engine.telemetry();
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !Command::new("ip")
        .args(["-o", "addr", "show", "kl0"])
        .output()
        .unwrap()
        .stdout
        .windows(11)
        .any(|part| part == b"198.18.0.1/")
    {
        assert!(Instant::now() < deadline, "TUN 接口未就绪");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let tcp_result = tokio::task::spawn_blocking(|| {
        let mut stream = connect_with_retry("198.18.0.200:7000");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let payload = vec![0x5a; 256 * 1024];
        let mut writer = stream.try_clone().unwrap();
        let expected = payload.clone();
        let sender = std::thread::spawn(move || writer.write_all(&payload).unwrap());
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).unwrap();
        sender.join().unwrap();
        received == expected
    })
    .await
    .unwrap();
    assert!(tcp_result, "TCP 经 TUN 往返应保持字节不变");

    let udp_result = tokio::task::spawn_blocking(|| {
        let socket = UdpSocket::bind("198.18.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket.connect("198.18.0.200:7001").unwrap();
        socket.send(b"ping-over-tun").unwrap();
        let mut bytes = [0; 64];
        let length = socket.recv(&mut bytes).unwrap();
        bytes[..length].to_vec()
    })
    .await
    .unwrap();
    assert_eq!(udp_result, b"ping-over-tun", "UDP 经 TUN 往返");

    let usage = telemetry.usage().unwrap();
    assert!(
        usage.engine.upload_bytes >= 256 * 1024,
        "TUN 流量应经过唯一计量边界"
    );

    stop.cancel();
    running.await.unwrap().unwrap();
}
