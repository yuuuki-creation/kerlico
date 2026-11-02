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
    sync::{Arc, atomic::Ordering},
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

/// 目标是此端口时，回显出站持续主动写，让用户态栈在链路 down 时仍有包要发。
const TICKING_PORT: u16 = 7100;

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
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let (client, mut server) = tokio::io::duplex(64 * 1024);
            let ticking = target.port() == TICKING_PORT;
            tokio::spawn(async move {
                while ticking && server.write_all(b".").await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
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

    ip(&["addr", "add", "10.99.0.1/32", "dev", "lo"]);
    let forwarded = tokio::task::spawn_blocking(|| {
        let socket = UdpSocket::bind("10.99.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket.connect("198.18.0.200:7001").unwrap();
        socket.send(b"from-another-host").unwrap();
        let mut bytes = [0; 64];
        let length = socket.recv(&mut bytes).unwrap();
        bytes[..length].to_vec()
    })
    .await
    .unwrap();
    assert_eq!(
        forwarded, b"from-another-host",
        "网关转发的来源不是接口地址"
    );

    let usage = telemetry.usage().unwrap();
    assert!(
        usage.engine.upload_bytes >= 256 * 1024,
        "TUN 流量应经过唯一计量边界"
    );

    stop.cancel();
    running.await.unwrap().unwrap();
}

fn ip(arguments: &[&str]) {
    assert!(
        Command::new("ip")
            .args(arguments)
            .status()
            .unwrap()
            .success(),
        "ip {arguments:?}"
    );
}
async fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "等待超时：{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn start_tun(name: &str, address: &str, limits: Value) -> Engine {
    ip(&["link", "set", "lo", "up"]);
    let mut registry = Registry::default();
    registry.register(EchoFactory).unwrap();
    registry.register_node(TunNodeFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"echo"}],
        "inbounds": [{"tag":"keep","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"192.0.2.1","port":7000},"outbound":"exit"}],
        "local_inbounds": [{"tag":"tun","type":"tun","listen":"127.0.0.1:0","outbound":"exit",
            "options":{"name":name,"addresses":[address],"mtu":1500}}],
        "limits": limits,
    });
    Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap()
}
fn echo_once(target: &str) -> TcpStream {
    let mut stream = connect_with_retry(target);
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    let mut byte = [0; 1];
    stream.read_exact(&mut byte).unwrap();
    stream
}
async fn interface_ready(name: &str) {
    let name = name.to_owned();
    wait_until("TUN 接口就绪", move || {
        Command::new("ip")
            .args(["-o", "addr", "show", &name])
            .output()
            .is_ok_and(|output| output.status.success() && !output.stdout.is_empty())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 root，并在独立网络命名空间内运行"]
async fn link_down_only_drops_packets_and_deleting_the_device_stops_the_node() {
    let engine = start_tun("kl1", "198.19.0.1/24", json!({"drain_timeout_ms":1000})).await;
    let forward = engine.listeners().unwrap()[0].1;
    let global = engine.stats();
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    interface_ready("kl1").await;

    let target = format!("198.19.0.200:{TICKING_PORT}");
    let _ticking = tokio::task::spawn_blocking(move || {
        let mut stream = connect_with_retry(&target);
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut tick = [0; 1];
        stream.read_exact(&mut tick).unwrap();
        stream
    })
    .await
    .unwrap();

    let dropped = global.dropped.load(Ordering::Relaxed);
    ip(&["link", "set", "kl1", "down"]);
    let observed = global.clone();
    wait_until("写入已 down 的接口有结果", move || {
        observed.dropped.load(Ordering::Relaxed) > dropped
            || observed.failed.load(Ordering::Relaxed) > 0
    })
    .await;
    assert_eq!(
        global.failed.load(Ordering::Relaxed),
        0,
        "链路 down 不应结束节点"
    );

    ip(&["link", "set", "kl1", "up"]);
    tokio::task::spawn_blocking(|| echo_once("198.19.0.200:7000"))
        .await
        .unwrap();

    ip(&["link", "del", "kl1"]);
    let observed = global.clone();
    wait_until("接口删除后节点失败", move || {
        observed.failed.load(Ordering::Relaxed) > 0
    })
    .await;
    let mut keep = tokio::net::TcpStream::connect(forward).await.unwrap();
    keep.write_all(b"y").await.unwrap();
    let mut byte = [0; 1];
    tokio::time::timeout(Duration::from_secs(5), keep.read_exact(&mut byte))
        .await
        .expect("其他入口不受 TUN 影响")
        .unwrap();
    stop.cancel();
    assert!(
        running.await.unwrap().is_err(),
        "接口被删除后节点应报告失败"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 root，并在独立网络命名空间内运行"]
async fn flow_limit_follows_max_flows_rather_than_the_stream_cap() {
    let engine = start_tun(
        "kl2",
        "198.20.0.1/24",
        json!({"max_sessions":512,"drain_timeout_ms":1000}),
    )
    .await;
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    interface_ready("kl2").await;
    let held = tokio::task::spawn_blocking(|| {
        (0..300)
            .map(|index| echo_once(&format!("198.20.0.200:{}", 7000 + index)))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert_eq!(held.len(), 300, "全部流同时存活");
    drop(held);
    stop.cancel();
    running.await.unwrap().unwrap();
}
