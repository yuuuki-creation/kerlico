use kerlico_config::{OutboundFactory, OutboundPlan, Registry, parse};
use kerlico_core::*;
use kerlico_egress::{EgressRuntime, native_device};
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;

/// 远端代理替身：记录收到的业务目标，返回一条空闲双工流。
struct Recorder {
    name: String,
    seen: Arc<Mutex<Vec<(String, Destination)>>>,
}
impl Outbound for Recorder {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push((self.name.clone(), target.clone()));
            let (client, server) = tokio::io::duplex(64);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                drop(server);
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
        Box::pin(async { Err(Error::Unsupported("只测 TCP")) })
    }
}
struct RecorderFactory(Arc<Mutex<Vec<(String, Destination)>>>);
impl OutboundFactory for RecorderFactory {
    fn kind(&self) -> &'static str {
        "recorder-test"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let name = options["name"].as_str().unwrap().to_owned();
        let seen = self.0.clone();
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            },
            false,
            TargetPolicy::Remote,
            move |_| {
                Box::pin(async move { Ok(Arc::new(Recorder { name, seen }) as Arc<dyn Outbound>) })
            },
        ))
    }
}

/// 回环权威 DNS：`ip-rule.test` 的 A 记录为 10.20.0.1，其余名称 NXDOMAIN。
async fn authority() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let q = kerlico_dns::wire::parse_question(&buf[..n]).unwrap();
            let reply = if q.name == "ip-rule.test" && q.qtype == kerlico_dns::wire::TYPE_A {
                let ip = kerlico_dns::wire::Synth::Ip("10.20.0.1".parse().unwrap());
                kerlico_dns::wire::reply(&buf[..n], &q, 0, &[ip], 60)
            } else {
                kerlico_dns::wire::reply(&buf[..n], &q, kerlico_dns::wire::RCODE_NXDOMAIN, &[], 60)
            };
            socket.send_to(&reply, peer).await.unwrap();
        }
    });
    addr
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
fn context() -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: NodeTasks::new(NodeId::parse("entry").unwrap(), CancellationToken::new()),
        peer_addr: Some("127.0.0.1:12345".parse().unwrap()),
        local_addr: None,
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_millis(50),
        max_datagram_size: 65535,
        max_streams: 8,
        stream_budget: StreamBudget::new(
            Arc::new(tokio::sync::Semaphore::new(8)),
            Arc::new(tokio::sync::Semaphore::new(8)),
        ),
        events: Arc::new(Observer),
    }
}

#[tokio::test]
async fn mihomo_ip_rules_resolve_domains_and_dns_listen_answers() {
    let upstream = authority().await;
    let listen = free_port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(RecorderFactory(seen.clone())).unwrap();
    let input = json!({
        "version": 2,
        "outbounds": [
            {"tag": "proxy-a", "type": "recorder-test", "options": {"name": "proxy-a"}},
            {"tag": "proxy-b", "type": "recorder-test", "options": {"name": "proxy-b"}}
        ],
        "dns": {
            "nameserver": [format!("udp://{upstream}")],
            "listen": format!("127.0.0.1:{listen}"),
            "ipv6": false,
            "use-system-hosts": false
        },
        "rules": [
            "IP-CIDR,10.30.0.0/16,proxy-b,no-resolve",
            "IP-CIDR,10.20.0.0/16,proxy-a",
            "MATCH,proxy-b"
        ],
        "inbounds": [{"tag": "entry", "type": "tcp-forward", "listen": "127.0.0.1:0",
            "outbound": "proxy-b", "target": {"host": "unused.invalid", "port": 80}}]
    });
    let plan = registry
        .prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap())
        .unwrap()
        .into_parts()
        .egress;
    let runtime = EgressRuntime::start(plan, native_device(), Duration::from_secs(2))
        .await
        .unwrap();
    let peer = runtime
        .ingress(&NodeId::parse("entry").unwrap())
        .unwrap()
        .local(&context())
        .unwrap();
    for host in ["ip-rule.test", "missing.test"] {
        let target = Destination::new(host, 443).unwrap();
        drop(
            peer.connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            (
                "proxy-a".to_owned(),
                Destination::new("ip-rule.test", 443).unwrap()
            ),
            (
                "proxy-b".to_owned(),
                Destination::new("missing.test", 443).unwrap()
            ),
        ],
        "IP 规则按解析结果命中，远端仍收到原域名；解析无地址时继续匹配"
    );

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = kerlico_dns::wire::build_query(9, "ip-rule.test", 1).unwrap();
    client.send_to(&query, ("127.0.0.1", listen)).await.unwrap();
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        kerlico_dns::wire::answer_ips(&buf[..n]),
        vec!["10.20.0.1".parse::<std::net::IpAddr>().unwrap()]
    );

    let view = runtime.control_plane().dns_query("ip-rule.test", "A").await;
    assert_eq!(view["Answer"][0]["data"], "10.20.0.1");
    let txt = runtime
        .control_plane()
        .dns_query("missing.test", "TXT")
        .await;
    assert_eq!(txt["Status"], 3, "非 A/AAAA 类型经上游返回原 RCODE");
    runtime.shutdown(Duration::from_secs(1)).await;
}
