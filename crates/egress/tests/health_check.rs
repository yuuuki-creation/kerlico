use kerlico_config::{OutboundFactory, OutboundPlan, Registry, parse};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, Error, OpenedTcp, OutId,
    Outbound, Result, TargetPolicy, TcpConnectInfo,
};
use kerlico_egress::{EgressRuntime, ProbeError, ProbeSpec, native_device};
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// 远端代理替身：忽略业务目标，固定连到本机端口，并记录收到的未解析目标。
struct Pinned {
    port: u16,
    seen: Arc<Mutex<Vec<Destination>>>,
}
impl Outbound for Pinned {
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
            self.seen.lock().unwrap().push(target.clone());
            let stream = TcpStream::connect(("127.0.0.1", self.port)).await?;
            Ok(OpenedTcp {
                stream: Box::new(stream),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("探测只用 TCP")) })
    }
}
struct PinnedFactory(Arc<Mutex<Vec<Destination>>>);
impl OutboundFactory for PinnedFactory {
    fn kind(&self) -> &'static str {
        "pinned-test"
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let port = options["port"].as_u64().unwrap() as u16;
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
                Box::pin(async move { Ok(Arc::new(Pinned { port, seen }) as Arc<dyn Outbound>) })
            },
        ))
    }
}

/// 每个连接读完请求头后等待 `delay`，再回 `status`。
async fn http_server(delay: Duration, status: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 512];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                assert!(request.starts_with(b"HEAD /generate_204 HTTP/1.1\r\n"));
                tokio::time::sleep(delay).await;
                let reply = format!("HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.write_all(reply.as_bytes()).await;
            });
        }
    });
    port
}

async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn runtime(outbounds: Value, groups: Value) -> (EgressRuntime, Arc<Mutex<Vec<Destination>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(PinnedFactory(seen.clone())).unwrap();
    let first = groups[0]["name"].clone();
    let input = json!({
        "version": 2,
        "outbounds": outbounds,
        "proxy_groups": groups,
        "inbounds": [{"tag": "entry", "type": "tcp-forward", "listen": "127.0.0.1:0",
            "outbound": first, "target": {"host": "unused.invalid", "port": 80}}]
    });
    let plan = registry
        .prepare(parse(&serde_json::to_vec(&input).unwrap()).unwrap())
        .unwrap()
        .into_parts()
        .egress;
    let runtime = EgressRuntime::start(plan, native_device(), Duration::from_secs(1))
        .await
        .unwrap();
    (runtime, seen)
}

fn id(name: &str) -> OutId {
    OutId::parse(name).unwrap()
}

fn state(runtime: &EgressRuntime, name: &str) -> Value {
    runtime.control_plane().proxy_by_name_json(name).unwrap()
}

/// 等到每个名称都至少有一条探测历史。
async fn probed(runtime: &EgressRuntime, names: &[&str]) {
    timeout(Duration::from_secs(5), async {
        while names
            .iter()
            .any(|n| state(runtime, n)["history"].as_array().unwrap().is_empty())
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("启动后应立即完成一轮健康检查");
}

fn last_delay(runtime: &EgressRuntime, name: &str) -> u64 {
    state(runtime, name)["history"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["delay"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn url_test_switches_to_the_faster_measured_candidate() {
    let fast = http_server(Duration::ZERO, 204).await;
    let slow = http_server(Duration::from_millis(300), 204).await;
    let (runtime, seen) = runtime(
        json!([
            {"tag": "slow", "type": "pinned-test", "options": {"port": slow}},
            {"tag": "fast", "type": "pinned-test", "options": {"port": fast}}
        ]),
        json!([{"name": "auto", "type": "url-test", "proxies": ["slow", "fast"],
            "url": "http://probe.test/generate_204", "interval": 600, "lazy": false}]),
    )
    .await;
    probed(&runtime, &["slow", "fast"]).await;

    let slow_delay = last_delay(&runtime, "slow");
    let fast_delay = last_delay(&runtime, "fast");
    assert!(slow_delay >= 300, "慢节点实测 {slow_delay} ms");
    assert!(
        fast_delay < slow_delay,
        "快 {fast_delay} ms，慢 {slow_delay} ms"
    );
    let (picked, _) = runtime
        .control_plane()
        .resolve_outbound(&id("auto"), None, None)
        .unwrap();
    assert_eq!(picked, id("fast"));
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|t| t == &Destination::new("probe.test", 80).unwrap()),
        "Remote 出站应收到未解析的测试域名"
    );

    let report = runtime.shutdown(Duration::from_secs(2)).await;
    assert!(!report.timed_out, "健康检查任务应随关闭退出");
}

#[tokio::test]
async fn fallback_skips_a_candidate_whose_probe_fails() {
    let live = http_server(Duration::ZERO, 204).await;
    let dead = closed_port().await;
    let (runtime, _) = runtime(
        json!([
            {"tag": "dead", "type": "pinned-test", "options": {"port": dead}},
            {"tag": "live", "type": "pinned-test", "options": {"port": live}}
        ]),
        json!([{"name": "backup", "type": "fallback", "proxies": ["dead", "live"],
            "url": "http://probe.test/generate_204", "interval": 600}]),
    )
    .await;
    probed(&runtime, &["dead", "live"]).await;

    let dead_state = state(&runtime, "dead");
    assert_eq!(dead_state["alive"], false);
    assert_eq!(last_delay(&runtime, "dead"), 0);
    assert_eq!(state(&runtime, "live")["alive"], true);
    let (picked, _) = runtime
        .control_plane()
        .resolve_outbound(&id("backup"), None, None)
        .unwrap();
    assert_eq!(picked, id("live"));
}

#[tokio::test]
async fn direct_probe_measures_and_rejects_unexpected_status() {
    let delayed = http_server(Duration::from_millis(100), 204).await;
    let ok_only = http_server(Duration::ZERO, 200).await;
    let (runtime, _) = runtime(
        json!([{"tag": "exit", "type": "direct"}]),
        json!([{"name": "manual", "type": "select", "proxies": ["exit"]}]),
    )
    .await;
    let prober = runtime.prober();
    let url = |port: u16| format!("http://127.0.0.1:{port}/generate_204");
    let timeout = Duration::from_secs(2);

    let measured = prober
        .probe(
            &id("exit"),
            &ProbeSpec::new(&url(delayed), timeout, "204").unwrap(),
        )
        .await
        .unwrap();
    assert!(measured >= 100, "实测 {measured} ms");
    assert_eq!(last_delay(&runtime, "exit"), u64::from(measured));

    let mismatch = prober
        .probe(
            &id("exit"),
            &ProbeSpec::new(&url(ok_only), timeout, "204").unwrap(),
        )
        .await;
    assert!(
        matches!(mismatch, Err(ProbeError::UnexpectedStatus(200))),
        "{mismatch:?}"
    );
    assert_eq!(state(&runtime, "exit")["alive"], false);

    prober
        .probe(
            &id("exit"),
            &ProbeSpec::new(&url(ok_only), timeout, "200-299").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(state(&runtime, "exit")["alive"], true);

    let unknown = prober
        .probe(
            &id("missing"),
            &ProbeSpec::new(&url(ok_only), timeout, "").unwrap(),
        )
        .await;
    assert!(matches!(unknown, Err(ProbeError::UnknownOutbound)));
}
