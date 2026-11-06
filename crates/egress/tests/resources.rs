use kerlico_config::{OutboundFactory, OutboundPlan, Registry, ResourceKey, ResourceSpec, parse};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, Error, OpenedTcp,
    Outbound, Result, TargetPolicy, TcpConnectInfo,
};
use kerlico_egress::{EgressRuntime, Refreshed, native_device};
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

/// 回环 HTTP 源：按 ETag 回 304，可切换为 500；记录每个请求头。
#[derive(Clone)]
struct Origin {
    state: Arc<Mutex<OriginState>>,
    port: u16,
}
struct OriginState {
    body: Vec<u8>,
    version: u32,
    failing: bool,
    requests: Vec<String>,
}
impl Origin {
    async fn start(body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = Self {
            state: Arc::new(Mutex::new(OriginState {
                body: body.as_bytes().to_vec(),
                version: 1,
                failing: false,
                requests: Vec::new(),
            })),
            port,
        };
        let state = origin.state.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(serve(stream, state.clone()));
            }
        });
        origin
    }
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
    fn set_body(&self, body: &str) {
        let mut state = self.state.lock().unwrap();
        state.body = body.as_bytes().to_vec();
        state.version += 1;
    }
    fn set_failing(&self, failing: bool) {
        self.state.lock().unwrap().failing = failing;
    }
    fn requests(&self) -> Vec<String> {
        self.state.lock().unwrap().requests.clone()
    }
}

async fn serve(mut stream: TcpStream, state: Arc<Mutex<OriginState>>) {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
    let reply = {
        let mut state = state.lock().unwrap();
        state.requests.push(head.clone());
        let etag = format!("\"v{}\"", state.version);
        if state.failing {
            b"HTTP/1.1 500 Broken\r\nContent-Length: 0\r\n\r\n".to_vec()
        } else if head.contains(&format!("if-none-match: {etag}")) {
            format!("HTTP/1.1 304 Not Modified\r\nETag: {etag}\r\n\r\n").into_bytes()
        } else {
            let mut reply = format!(
                "HTTP/1.1 200 OK\r\nETag: {etag}\r\nContent-Length: {}\r\n\r\n",
                state.body.len()
            )
            .into_bytes();
            reply.extend_from_slice(&state.body);
            reply
        }
    };
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}

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
        Box::pin(async { Err(Error::Unsupported("只用 TCP")) })
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

fn registry(seen: &Arc<Mutex<Vec<Destination>>>) -> Registry {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(PinnedFactory(seen.clone())).unwrap();
    registry
}

fn base(extra: Value) -> Value {
    let mut config = json!({
        "version": 2,
        "outbounds": [{"tag": "a", "type": "direct"}, {"tag": "b", "type": "direct"}],
        "inbounds": [{"tag": "entry", "type": "tcp-forward", "listen": "127.0.0.1:0",
            "outbound": "b", "target": {"host": "unused.invalid", "port": 80}}]
    });
    for (key, value) in extra.as_object().unwrap() {
        config[key] = value.clone();
    }
    config
}

fn prepare(
    seen: &Arc<Mutex<Vec<Destination>>>,
    config: &Value,
) -> Result<kerlico_config::EgressPlan> {
    let parsed = parse(&serde_json::to_vec(config).unwrap())?;
    Ok(registry(seen).prepare(parsed)?.into_parts().egress)
}

async fn start(config: &Value) -> Result<(EgressRuntime, kerlico_egress::Refresher)> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    start_with(&seen, config).await
}

async fn start_with(
    seen: &Arc<Mutex<Vec<Destination>>>,
    config: &Value,
) -> Result<(EgressRuntime, kerlico_egress::Refresher)> {
    let plan = prepare(seen, config)?;
    let resources: Vec<ResourceSpec> = plan.resources().to_vec();
    let runtime = EgressRuntime::start(plan, native_device(), Duration::from_secs(1)).await?;
    let refresher = runtime.start_resources(resources).await?;
    Ok((runtime, refresher))
}

fn routed(runtime: &EgressRuntime, host: &str) -> String {
    runtime
        .control_plane()
        .test_route(host, 443, "tcp", "")
        .unwrap()["outbound"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn rule_body(suffix: &str) -> String {
    json!({"version": 1, "rules": [{"domain_suffix": [suffix]}]}).to_string()
}

fn remote_rules(url: &str, path: &Path, detour: Option<&str>) -> Value {
    let mut set = json!({"tag": "corp", "type": "remote", "format": "source", "url": url,
        "path": path.to_str().unwrap(), "update_interval": "1d"});
    if let Some(detour) = detour {
        set["download_detour"] = json!(detour);
    }
    base(
        json!({"route": {"rule_set": [set], "rules": [{"rule_set": ["corp"], "outbound": "a"}],
        "final": "b"}}),
    )
}

fn corp() -> ResourceKey {
    ResourceKey::RuleSet("corp".into())
}

#[tokio::test]
async fn remote_rule_set_loads_at_startup_and_refresh_swaps_routing() {
    let origin = Origin::start(&rule_body("corp.test")).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("rules").join("corp.json");
    let (runtime, refresher) = start(&remote_rules(&origin.url("/corp.json"), &cache, None))
        .await
        .unwrap();
    assert_eq!(routed(&runtime, "www.corp.test"), "a");
    assert_eq!(routed(&runtime, "www.other.test"), "b");
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        rule_body("corp.test")
    );

    origin.set_body(&rule_body("other.test"));
    let refreshed = refresher.refresh(&corp()).await.unwrap().unwrap();
    assert_eq!(refreshed, Refreshed::Changed);
    assert_eq!(routed(&runtime, "www.corp.test"), "b");
    assert_eq!(routed(&runtime, "www.other.test"), "a");
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        rule_body("other.test")
    );
    assert!(refresher.status(&corp()).unwrap().error.is_none());
}

#[tokio::test]
async fn not_modified_reply_keeps_the_loaded_rule_set() {
    let origin = Origin::start(&rule_body("corp.test")).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("corp.json");
    let (runtime, refresher) = start(&remote_rules(&origin.url("/corp.json"), &cache, None))
        .await
        .unwrap();
    let refreshed = refresher.refresh(&corp()).await.unwrap().unwrap();
    assert_eq!(refreshed, Refreshed::Unchanged);
    let requests = origin.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].contains("if-none-match: \"v1\""),
        "{}",
        requests[1]
    );
    assert_eq!(routed(&runtime, "www.corp.test"), "a");
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        rule_body("corp.test")
    );
}

#[tokio::test]
async fn failed_download_keeps_the_stale_cache() {
    let origin = Origin::start(&rule_body("new.test")).await;
    origin.set_failing(true);
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("corp.json");
    std::fs::write(&cache, rule_body("corp.test")).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&cache)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(3 * 86_400))
        .unwrap();

    let (runtime, refresher) = start(&remote_rules(&origin.url("/corp.json"), &cache, None))
        .await
        .unwrap();
    assert_eq!(origin.requests().len(), 1, "过期缓存应在启动时刷新");
    assert_eq!(routed(&runtime, "www.corp.test"), "a");
    let error = refresher.status(&corp()).unwrap().error.unwrap();
    assert!(error.contains("500"), "{error}");

    assert!(refresher.refresh(&corp()).await.unwrap().is_err());
    assert_eq!(routed(&runtime, "www.corp.test"), "a");
    assert_eq!(
        std::fs::read_to_string(&cache).unwrap(),
        rule_body("corp.test")
    );
}

#[tokio::test]
async fn referenced_rule_set_without_any_content_fails_loudly() {
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/corp.json",
        closed.local_addr().unwrap().port()
    );
    drop(closed);
    let dir = tempfile::tempdir().unwrap();
    let error = start(&remote_rules(&url, &dir.path().join("corp.json"), None))
        .await
        .err()
        .expect("无缓存且下载失败时应拒绝启动");
    assert!(error.to_string().contains("rule-set corp"), "{error}");

    let local = base(json!({"route": {
        "rule_set": [{"tag": "corp", "type": "local", "path": dir.path().join("absent.json").to_str().unwrap()}],
        "rules": [{"rule_set": ["corp"], "outbound": "a"}]}}));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let error = prepare(&seen, &local)
        .err()
        .expect("本地规则集文件缺失应拒绝配置");
    assert!(error.to_string().contains("规则集文件不存在"), "{error}");
}

#[tokio::test]
async fn download_detour_sends_the_unresolved_url_host_to_the_outbound() {
    let origin = Origin::start(&rule_body("corp.test")).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let dir = tempfile::tempdir().unwrap();
    let mut config = remote_rules(
        "http://rules.test/corp.json",
        &dir.path().join("corp.json"),
        Some("relay"),
    );
    config["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tag": "relay", "type": "pinned-test", "options": {"port": origin.port}}));
    let (runtime, _) = start_with(&seen, &config).await.unwrap();
    assert_eq!(routed(&runtime, "www.corp.test"), "a");
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        &[Destination::new("rules.test", 80).unwrap()]
    );
    assert!(origin.requests()[0].contains("host: rules.test"));
}

#[tokio::test]
async fn http_provider_download_writes_the_cache_and_signals_new_members() {
    let origin = Origin::start(&json!([{"tag": "n1", "type": "direct"}]).to_string()).await;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("proxies").join("sub.json");
    let config = base(json!({
        "proxy_providers": {"sub": {"type": "http", "url": origin.url("/sub"),
            "path": cache.to_str().unwrap(), "interval": 3600}},
        "proxy_groups": [{"name": "pick", "type": "select", "use": ["sub"]}]
    }));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let empty = prepare(&seen, &config).unwrap();
    assert!(
        empty.providers()[0].proxies.is_empty(),
        "首次启动前没有缓存"
    );

    let (runtime, refresher) = start_with(&seen, &config).await.unwrap();
    let mut changes = refresher.provider_changes();
    assert!(changes.has_changed().unwrap(), "首次下载应通知重建代际");
    changes.borrow_and_update();
    assert!(
        std::fs::read_to_string(&cache).unwrap().contains("\"n1\""),
        "缓存应写入下载内容"
    );
    let rebuilt = prepare(&seen, &config).unwrap();
    assert_eq!(rebuilt.providers()[0].proxies[0].as_str(), "n1");

    origin.set_body(&json!([{"tag": "n2", "type": "direct"}]).to_string());
    let key = ResourceKey::ProxyProvider("sub".into());
    assert_eq!(
        refresher.refresh(&key).await.unwrap().unwrap(),
        Refreshed::Changed
    );
    assert_eq!(
        prepare(&seen, &config).unwrap().providers()[0].proxies[0].as_str(),
        "n2"
    );
    origin.set_body("<html>maintenance</html>");
    assert!(refresher.refresh(&key).await.unwrap().is_err());
    assert!(std::fs::read_to_string(&cache).unwrap().contains("\"n2\""));
    drop(runtime);
}
