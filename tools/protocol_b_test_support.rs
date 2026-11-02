use kerlico_config::{NodeBuildContext, OutboundFactory};
use kerlico_core::{Outbound, Result, ServiceContext};
use serde_json::{Value, json};
use std::sync::Arc;

pub async fn outbound(factory: &dyn OutboundFactory, value: &Value) -> Result<Arc<dyn Outbound>> {
    factory.compile(value)?.start(ServiceContext::for_test()).await
}

pub fn node_input(protocol: &str, value: &Value) -> NodeBuildContext {
    let mut options = value.clone();
    let credentials = take_credentials(protocol, &mut options);
    if credentials.is_empty() { NodeBuildContext::local_for_test(options) }
    else { NodeBuildContext::for_test(options, credentials) }
}

fn take_credentials(protocol: &str, options: &mut Value) -> Vec<Value> {
    if protocol == "mieru" && options["unsafe_udp_compatibility"] == true
        || protocol == "sudoku" && options["protocol"]["aead"] == "none" { return Vec::new(); }
    let Some(object) = options.as_object_mut() else { return Vec::new(); };
    if let Some(users) = object.remove("users") {
        return users.as_array().cloned().unwrap_or_default();
    }
    let mut row = serde_json::Map::new();
    match protocol {
        "socks" | "http" => return object.remove("auth").filter(|auth| !auth.is_null()).into_iter().collect(),
        "tuic" => {
            if let Some(tokens) = object.remove("tokens") { return tokens.as_array().into_iter().flatten().map(|token|json!({"token":token})).collect(); }
            for field in ["token", "uuid", "password"] { if let Some(value) = object.remove(field) { row.insert(field.into(), value); } }
        }
        "hysteria1" => { for field in ["auth", "auth_str"] { if let Some(value) = object.remove(field) { row.insert(field.into(), value); } } }
        "hysteria2" => { if let Some(value) = object.remove("auth") { row.insert("auth".into(), value); } }
        "sudoku" => {
            if let Some(key) = object.get_mut("protocol").and_then(Value::as_object_mut).and_then(|protocol|protocol.remove("key")) { row.insert("key".into(), key); }
        }
        "shadowquic" | "mieru" | "naive" | "trusttunnel" => {
            for field in ["username", "password"] { if let Some(value) = object.remove(field) { row.insert(field.into(), value); } }
        }
        _ => {}
    }
    if row.is_empty() { Vec::new() } else { vec![Value::Object(row)] }
}

pub fn configuration(mut value: Value) -> Value {
    value["version"] = json!(2);
    let mut accounts = value.get("accounts").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut nodes = value.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
    let locals = value.get("local_inbounds").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut local_inbounds = Vec::new();
    for mut node in locals {
        if node["members"].as_array().is_some_and(|members| !members.is_empty()) {
            nodes.push(node);
            continue;
        }
        let kind = node["type"].as_str().unwrap().to_owned();
        let credentials = take_credentials(&kind, &mut node["options"]);
        if credentials.is_empty() {
            node["members"] = json!([]);
            local_inbounds.push(node);
        } else {
            bind_fixture_members(&mut accounts, &mut node, credentials);
            nodes.push(node);
        }
    }
    for node in &mut nodes {
        if node.get("members").is_some() { continue; }
        let kind = node["type"].as_str().unwrap().to_owned();
        let credentials = take_credentials(&kind, &mut node["options"]);
        bind_fixture_members(&mut accounts, node, credentials);
    }
    value["nodes"] = Value::Array(nodes);
    value["local_inbounds"] = Value::Array(local_inbounds);
    value["accounts"] = Value::Array(accounts);
    value
}

fn bind_fixture_members(accounts: &mut Vec<Value>, node: &mut Value, credentials: Vec<Value>) {
    let mut members = Vec::new();
    for credential in credentials {
        let id = format!("00000000-0000-4000-8000-{:012}", accounts.len() + 1);
        accounts.push(json!({"user_id":id,"username":format!("fixture_{id}"),"password_hash":"$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXRlc3Qtc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}));
        members.push(json!({"user_id":id,"credential_epoch":1,"native_credential":credential}));
    }
    node["members"] = Value::Array(members);
}

pub fn authentication(manifest: &kerlico_core::CredentialManifest) -> Vec<[u8; 32]> {
    manifest.entries().iter().filter(|entry|matches!(entry.purpose,kerlico_core::CredentialPurpose::Authentication { .. })).map(|entry|entry.fingerprint).collect()
}

pub async fn assert_member_scope(
    node_factory: &dyn kerlico_config::NodeFactory,
    outbound_factory: &dyn OutboundFactory,
    options: Value,
    credentials: Vec<Value>,
    mut clients: Vec<Value>,
) {
    use kerlico_core::{BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, InboundContext, NodeEvent, NodeObserver, ResourceKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Observer;
    impl NodeObserver for Observer { fn record(&self, _: NodeEvent) {} }
    struct Recorder(Arc<std::sync::Mutex<Vec<ResourceKey>>>);
    impl Outbound for Recorder {
        fn capabilities(&self) -> Capabilities { Capabilities { tcp: true, tcp_eof: true, udp: true } }
        fn supports_udp_association(&self) -> bool { true }
        fn connect_tcp<'a>(&'a self, target: &'a Destination, context: &'a ConnectContext) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            Box::pin(async move {
                assert_eq!(target.host(), "unresolved.example.invalid");
                self.0.lock().unwrap().push(context.resource_key().clone());
                let (stream, mut echo) = tokio::io::duplex(128);
                let cancel = context.cancel.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(&mut echo);
                    tokio::select! { _=cancel.cancelled()=>{}, _=tokio::io::copy(&mut reader,&mut writer)=>{} }
                });
                Ok(kerlico_core::OpenedTcp { stream: Box::new(stream), info: kerlico_core::TcpConnectInfo::unknown() })
            })
        }
        fn connect_udp<'a>(&'a self, _: &'a Destination, _: &'a ConnectContext) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(kerlico_core::Error::Unsupported("此身份夹具只发送TCP业务")) })
        }
    }
    let input = NodeBuildContext::for_test(options, credentials);
    let node = node_factory.build(&input).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = Arc::new(tokio::net::UdpSocket::bind(address).await.unwrap());
    let cancel = kerlico_core::CancellationToken::new();
    let context = InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(kerlico_core::NodeId::parse("test-node").unwrap(), cancel.clone()),
        cancel: cancel.clone(), connect_timeout: std::time::Duration::from_secs(5), idle_timeout: std::time::Duration::from_secs(8),
        drain_timeout: std::time::Duration::from_millis(300), max_datagram_size: 65507, max_streams: 64,
        stream_budget: kerlico_core::StreamBudget::new(Arc::new(tokio::sync::Semaphore::new(128)), Arc::new(tokio::sync::Semaphore::new(128))),
        events: Arc::new(Observer), peer_addr: None, local_addr: Some(address),
    };
    let keys = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ingress = kerlico_egress::testing::ingress(&input, Arc::new(Recorder(keys.clone())), kerlico_core::TargetPolicy::Remote).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    if node.supports_virtual() {
        let node = node.clone(); let ingress = ingress.clone(); let context = context.clone();
        tasks.spawn(async move { let _ = node.handle_virtual(ingress, context).await; });
    }
    if node.supports_udp() {
        let node = node.clone(); let ingress = ingress.clone(); let context = context.clone();
        tasks.spawn(async move { let _ = node.handle_udp(socket, ingress, context).await; });
    }
    if node.supports_tcp() {
        let node = node.clone(); let ingress = ingress.clone(); let context = context.clone();
        tasks.spawn(async move {
            let mut flows = tokio::task::JoinSet::new();
            loop {
                tokio::select! { biased; _=context.cancel.cancelled()=>break,
                    _=flows.join_next(), if !flows.is_empty()=>{},
                    accepted=listener.accept()=>{
                        let (stream, peer) = accepted.unwrap(); let node = node.clone(); let ingress = ingress.clone(); let mut context = context.clone(); context.peer_addr=Some(peer);
                        flows.spawn(async move { let _ = node.handle(Box::new(stream), ingress, context).await; });
                    }
                }
            }
            flows.abort_all(); while flows.join_next().await.is_some() {}
        });
    }
    for client in &mut clients { client["server"] = json!({"host":"127.0.0.1","port":address.port()}); }
    clients.push(clients[0].clone());
    for client in clients {
        let outbound = outbound(outbound_factory, &client).await.unwrap();
        let target = Destination::new("unresolved.example.invalid", 443).unwrap();
        let context = ConnectContext::new(std::time::Duration::from_secs(5));
        let mut stream = outbound.connect_tcp(&target, &context).await.unwrap().stream;
        stream.write_all(b"peer").await.unwrap(); stream.flush().await.unwrap();
        let mut bytes = [0; 4];
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut bytes)).await.unwrap().unwrap();
        assert_eq!(&bytes, b"peer"); drop(stream); outbound.shutdown().await.unwrap();
    }
    let captured = keys.lock().unwrap().clone();
    assert_eq!(captured.len(), 3); assert_ne!(captured[0], captured[1]); assert_eq!(captured[0], captured[2]);
    cancel.cancel();
    if tokio::time::timeout(std::time::Duration::from_secs(2), async { while tasks.join_next().await.is_some() {} }).await.is_err() { tasks.abort_all(); while tasks.join_next().await.is_some() {} }
    let report = context.tasks.shutdown_at(tokio::time::Instant::now() + std::time::Duration::from_secs(2)).await;
    assert!(report.is_clean(), "真实节点任务回收失败：{report:?}");
}
