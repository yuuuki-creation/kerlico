use kerlico_config::{ControlSpec, NodeBuildContext, NodeFactory, Registry, parse};
use kerlico_control::ControlServer;
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, CredentialManifest, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_engine::Engine;
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
    time::timeout,
};

async fn get(address: SocketAddr, path: &str, secret: Option<&str>) -> (u16, Value) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let authorization = secret
        .map(|secret| format!("Authorization: Bearer {secret}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: control\r\nConnection: close\r\n{authorization}\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let status = text.split(' ').nth(1).unwrap().parse().unwrap();
    let body = text.split_once("\r\n\r\n").unwrap().1;
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn control_requires_the_secret_and_reports_runtime_state() {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":9},"outbound":"exit"}]
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let spec = ControlSpec {
        listen: "127.0.0.1:0".parse().unwrap(),
        secret: Some("synthetic-control-secret".into()),
    };
    let server = ControlServer::bind(&spec, &engine).await.unwrap();
    let address = server.local_addr().unwrap();
    let stop = CancellationToken::new();
    let serving = tokio::spawn(server.serve(stop.clone()));

    assert_eq!(get(address, "/v1/health", None).await.0, 401);
    assert_eq!(get(address, "/v1/health", Some("wrong")).await.0, 401);
    let secret = Some("synthetic-control-secret");
    let (status, health) = get(address, "/v1/health", secret).await;
    assert_eq!(status, 200);
    assert_eq!(health["status"], "ok");
    let (status, usage) = get(address, "/v1/usage", secret).await;
    assert_eq!(status, 200);
    assert_eq!(usage["active_flows"], 0);
    assert_eq!(get(address, "/v1/online", secret).await.1, json!([]));
    assert_eq!(
        get(address, "/v1/flows?limit=10", secret).await.1,
        json!([])
    );
    assert_eq!(get(address, "/v1/flows?limit=0", secret).await.0, 400);
    assert_eq!(get(address, "/v1/stats", secret).await.0, 200);
    assert_eq!(get(address, "/v1/nothing", secret).await.0, 404);

    stop.cancel();
    serving.await.unwrap();
}

struct FailingNode;
impl InboundProtocol for FailingNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_virtual(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _: BoxStream,
        _: IngressBinding,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Rejected) })
    }
    fn handle_virtual<'a>(
        &'a self,
        _: IngressBinding,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async {
            Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )))
        })
    }
}
struct FailingFactory;
impl NodeFactory for FailingFactory {
    fn kind(&self) -> &'static str {
        "failing"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, _: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(FailingNode))
    }
}

struct Running {
    control: SocketAddr,
    forward: SocketAddr,
    stop: CancellationToken,
    engine: JoinHandle<Result<()>>,
    server: JoinHandle<()>,
}
impl Running {
    async fn stop(self) -> Result<()> {
        self.stop.cancel();
        self.server.await.unwrap();
        self.engine.await.unwrap()
    }
}
async fn start(mut config: Value) -> Running {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(FailingFactory).unwrap();
    config["version"] = json!(2);
    config["outbounds"] = json!([{"tag":"exit","type":"direct"}]);
    config["limits"] = json!({"drain_timeout_ms":1000});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let forward = engine.listeners().unwrap()[0].1;
    let spec = ControlSpec {
        listen: "127.0.0.1:0".parse().unwrap(),
        secret: None,
    };
    let server = ControlServer::bind(&spec, &engine).await.unwrap();
    let control = server.local_addr().unwrap();
    let stop = CancellationToken::new();
    Running {
        control,
        forward,
        server: tokio::spawn(server.serve(stop.clone())),
        engine: tokio::spawn(engine.run(stop.clone())),
        stop,
    }
}
fn forward_to(port: u16) -> Value {
    json!({"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
        "target":{"host":"127.0.0.1","port":port},"outbound":"exit"}]})
}

#[tokio::test]
async fn health_reports_a_failed_node_while_other_inbounds_keep_serving() {
    let mut config = forward_to(9);
    config["local_inbounds"] = json!([{"tag":"bad","type":"failing","listen":"127.0.0.1:0",
        "outbound":"exit","options":{}}]);
    let running = start(config).await;
    let health = timeout(Duration::from_secs(5), async {
        loop {
            let (_, health) = get(running.control, "/v1/health", None).await;
            if health["status"] != "ok" {
                return health;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("节点失败后 health 应转为 degraded");
    assert_eq!(health["status"], "degraded");
    assert_eq!(health["failed_nodes"], json!(["bad"]));
    TcpStream::connect(running.forward)
        .await
        .expect("其他入口继续接受连接");
    assert!(running.stop().await.is_err());
}

#[tokio::test]
async fn health_stays_ok_without_failures() {
    let running = start(forward_to(9)).await;
    let (_, health) = get(running.control, "/v1/health", None).await;
    assert_eq!(health["status"], "ok");
    assert_eq!(health["failed_nodes"], json!([]));
    running.stop().await.unwrap();
}

#[tokio::test]
async fn online_masks_and_merges_sources_like_flows() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let holding = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            held.push(target.accept().await.unwrap());
        }
    });
    let running = start(forward_to(port)).await;
    let mut clients = Vec::new();
    for source in ["127.0.0.1:0", "127.0.0.2:0"] {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(source.parse().unwrap()).unwrap();
        clients.push(socket.connect(running.forward).await.unwrap());
    }
    let online = timeout(Duration::from_secs(5), async {
        loop {
            let (_, online) = get(running.control, "/v1/online", None).await;
            let flows: u64 = online
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["active_flows"].as_u64().unwrap())
                .sum();
            if flows == 2 {
                return online;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("两条流应出现在在线视图");
    assert_eq!(
        online,
        json!([{"user":null,"node":"entry","address":"127.0.0.0/24","active_flows":2}])
    );
    drop(clients);
    holding.abort();
    running.stop().await.unwrap();
}

async fn request_on(stream: &mut TcpStream) -> Vec<u8> {
    let _ = stream
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: control\r\n\r\n")
        .await;
    let mut bytes = vec![0; 1024];
    let length = timeout(Duration::from_secs(5), stream.read(&mut bytes))
        .await
        .expect("应答或关闭应立即到达")
        .unwrap_or(0);
    bytes.truncate(length);
    bytes
}

#[tokio::test]
async fn connections_over_the_limit_are_closed_at_once() {
    let running = start(forward_to(9)).await;
    let mut held = Vec::new();
    for _ in 0..64 {
        let mut stream = TcpStream::connect(running.control).await.unwrap();
        assert!(request_on(&mut stream).await.starts_with(b"HTTP/1.1 200"));
        held.push(stream);
    }
    let mut excess = TcpStream::connect(running.control).await.unwrap();
    assert_eq!(
        request_on(&mut excess).await,
        b"",
        "第 65 条连接应被直接关闭"
    );

    drop(held.pop());
    let served = timeout(Duration::from_secs(5), async {
        loop {
            let mut stream = TcpStream::connect(running.control).await.unwrap();
            if !request_on(&mut stream).await.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(served.is_ok(), "释放名额后应重新服务");
    running.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn silent_connection_is_closed_by_the_total_timeout() {
    let running = start(forward_to(9)).await;
    let started = tokio::time::Instant::now();
    let mut idle = TcpStream::connect(running.control).await.unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(60), idle.read_to_end(&mut bytes))
        .await
        .expect("无请求的连接应被总时限关闭")
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(30));
    running.stop().await.unwrap();
}

async fn request_json(
    address: SocketAddr,
    method: &str,
    path: &str,
    secret: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let authorization = secret
        .map(|s| format!("Authorization: Bearer {s}\r\n"))
        .unwrap_or_default();
    let payload = body
        .map(|v| serde_json::to_vec(&v).unwrap())
        .unwrap_or_default();
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: control\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{authorization}\r\n",
        payload.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    if !payload.is_empty() {
        stream.write_all(&payload).await.unwrap();
    }
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let status = text.split(' ').nth(1).unwrap().parse().unwrap();
    let resp_body = text.split_once("\r\n\r\n").unwrap().1;
    let val = if resp_body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(resp_body).unwrap()
    };
    (status, val)
}

#[tokio::test]
async fn m4_clash_xray_ssm_endpoints_and_websocket_token_auth() {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [
            {"tag": "exit-a", "type": "direct"},
            {"tag": "exit-b", "type": "direct"}
        ],
        "proxy_groups": [
            {
                "name": "SelectorGroup",
                "type": "select",
                "proxies": ["exit-a", "exit-b"],
                "default": "exit-a"
            }
        ],
        "route": {
            "final": "SelectorGroup",
            "balancers": [
                {
                    "tag": "bal-1",
                    "selector": ["exit-a", "exit-b"],
                    "strategy": {"type": "round-robin"}
                }
            ]
        },
        "inbounds": [
            {
                "tag": "entry",
                "type": "tcp-forward",
                "listen": "127.0.0.1:0",
                "target": {"host": "127.0.0.1", "port": 9},
                "outbound": "SelectorGroup"
            }
        ]
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let spec = ControlSpec {
        listen: "127.0.0.1:0".parse().unwrap(),
        secret: Some("m4-secret".into()),
    };
    let server = ControlServer::bind(&spec, &engine).await.unwrap();
    let addr = server.local_addr().unwrap();
    let stop = CancellationToken::new();
    let serving = tokio::spawn(server.serve(stop.clone()));

    let (status, ver) = get(addr, "/version?token=m4-secret", None).await;
    assert_eq!(status, 200);
    assert!(ver["version"].is_string());

    let sec = Some("m4-secret");
    let (status, proxies) = get(addr, "/proxies", sec).await;
    assert_eq!(status, 200);
    assert_eq!(proxies["proxies"]["SelectorGroup"]["now"], "exit-a");

    let (status, _) = request_json(
        addr,
        "PUT",
        "/proxies/SelectorGroup",
        sec,
        Some(json!({"name": "exit-b"})),
    )
    .await;
    assert_eq!(status, 204);
    let (_, group) = get(addr, "/group/SelectorGroup", sec).await;
    assert_eq!(group["now"], "exit-b");

    let (status, _) = request_json(
        addr,
        "PUT",
        "/routing/balancers/bal-1",
        sec,
        Some(json!({"target": "exit-b"})),
    )
    .await;
    assert_eq!(status, 204);
    let (_, bals) = get(addr, "/routing/balancers", sec).await;
    assert_eq!(bals["balancers"]["bal-1"]["override_target"], "exit-b");

    assert_eq!(
        request_json(addr, "POST", "/cache/fakeip/flush", sec, None)
            .await
            .0,
        204
    );
    assert_eq!(get(addr, "/logs", sec).await.0, 200);
    assert_eq!(get(addr, "/observatory/status", sec).await.0, 200);
    let (status, rtest) = request_json(
        addr,
        "POST",
        "/routing/test",
        sec,
        Some(json!({"domain": "example.com"})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(rtest["outbound"], "exit-b");

    let (status, _) = request_json(
        addr,
        "POST",
        "/ssm/users",
        sec,
        Some(json!({"username": "u1", "password": "p1"})),
    )
    .await;
    assert_eq!(status, 204);
    let (_, ssm_list) = get(addr, "/ssm/users", sec).await;
    assert_eq!(ssm_list["users"].as_array().unwrap().len(), 1);

    stop.cancel();
    serving.await.unwrap();
}
