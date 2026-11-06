#[path = "../../protocol-shadowsocks/tests/support/mod.rs"]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, ConnectContext, CredentialManifest, DatagramChannel,
    Destination, Error, InboundContext, InboundProtocol, IngressBinding, NodeEvent, NodeObserver,
    Outbound, Result, StreamBudget, StreamConnector,
};
use kerlico_net::{DirectFactory, TcpConnector};
use kerlico_shadowsocks::{
    AEAD_METHODS, ShadowsocksNode, ShadowsocksNodeFactory, ShadowsocksOutbound,
};
use kerlico_ss2022::{Ss2022Node, Ss2022Outbound};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    time::timeout,
};

#[derive(Default)]
struct Echo {
    targets: Mutex<Vec<Destination>>,
}
impl Outbound for Echo {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        kerlico_core::Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            self.targets.lock().unwrap().push(target.clone());
            let (local, mut remote) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                remote.read_to_end(&mut bytes).await.unwrap();
                remote.write_all(&bytes).await.unwrap();
            });
            Ok(kerlico_core::OpenedTcp {
                stream: Box::new(local),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("本回归只访问 TCP")) })
    }
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
fn context() -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        peer_addr: None,
        local_addr: None,
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(3),
        drain_timeout: Duration::from_millis(50),
        max_datagram_size: 65000,
        max_streams: 64,
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(64)),
            Arc::new(Semaphore::new(64)),
        ),
        events: Arc::new(Observer),
    }
}

struct RecordedConnector {
    endpoints: Mutex<Vec<Destination>>,
    eof: bool,
}
impl StreamConnector for RecordedConnector {
    fn tcp_eof(&self) -> bool {
        self.eof
    }
    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.endpoints.lock().unwrap().push(endpoint.clone());
            StreamConnector::connect_tcp(
                &TcpConnector::plain(Default::default()),
                endpoint,
                context,
            )
            .await
        })
    }
}

#[tokio::test]
async fn ss_stream_injection_keeps_endpoint_target_eih_and_capabilities_separate() {
    let mut cases: Vec<_> = AEAD_METHODS
        .iter()
        .map(|method| ("shadowsocks", *method, false))
        .collect();
    for method in [
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ] {
        cases.push(("ss2022", method, false));
        if method.contains("aes") {
            cases.push(("ss2022", method, true));
        }
    }
    for (kind, method, eih) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let size = if method.contains("aes-128") { 16 } else { 32 };
        let mut client = if kind == "shadowsocks" {
            json!({"server":"127.0.0.1","port":endpoint.port(),"method":method,"password":"synthetic-secret"})
        } else {
            json!({"server":"127.0.0.1","port":endpoint.port(),"method":method,"key":STANDARD.encode(vec![1;size])})
        };
        let mut node = if kind == "shadowsocks" {
            json!({"method":method,"password":"synthetic-secret"})
        } else {
            json!({"method":method,"key":STANDARD.encode(vec![1;size])})
        };
        if eih {
            client["key"] = json!(STANDARD.encode(vec![2; size]));
            client["identity_keys"] = json!([STANDARD.encode(vec![1; size])]);
            node["users"] = json!([STANDARD.encode(vec![2; size])]);
        }
        let (options, credentials, _) = support::credentials(kind, &node);
        let input = kerlico_config::NodeBuildContext::for_test(options, credentials);
        let inner: Arc<dyn InboundProtocol> = if kind == "shadowsocks" {
            Arc::new(ShadowsocksNode::from_context(&input).unwrap())
        } else {
            Arc::new(Ss2022Node::from_context(&input).unwrap())
        };
        let connector = Arc::new(RecordedConnector {
            endpoints: Mutex::new(Vec::new()),
            eof: false,
        });
        let out: Arc<dyn Outbound> = if kind == "shadowsocks" {
            support::start(
                ShadowsocksOutbound::compile_with_connector(&client, Some(connector.clone()))
                    .unwrap(),
            )
            .unwrap()
        } else {
            support::start(
                Ss2022Outbound::compile_with_connector(&client, Some(connector.clone())).unwrap(),
            )
            .unwrap()
        };
        assert!(!out.capabilities().udp);
        assert!(!out.capabilities().tcp_eof);
        let access = Arc::new(Echo::default());
        let observed = access.clone();
        let ingress =
            kerlico_egress::testing::ingress(&input, access, kerlico_core::TargetPolicy::Remote)
                .unwrap();
        let handler = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            inner
                .handle(Box::new(stream), ingress, context())
                .await
                .unwrap();
        });
        let target = Destination::new("site.invalid", 443).unwrap();
        let budget = ConnectContext::new(Duration::from_secs(3));
        let mut stream = out.connect_tcp(&target, &budget).await.unwrap().stream;
        let payload = vec![0x53; 65_537];
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut result = Vec::new();
        timeout(Duration::from_secs(3), stream.read_to_end(&mut result))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, payload);
        drop(stream);
        handler.await.unwrap();
        assert_eq!(*observed.targets.lock().unwrap(), vec![target.clone()]);
        assert_eq!(
            *connector.endpoints.lock().unwrap(),
            vec![Destination::new("127.0.0.1", endpoint.port()).unwrap()]
        );
        assert!(matches!(
            out.connect_udp(&target, &budget).await,
            Err(Error::Unsupported(_))
        ));
        assert_eq!(connector.endpoints.lock().unwrap().len(), 1);
        let direct = Arc::new(RecordedConnector {
            endpoints: Mutex::new(Vec::new()),
            eof: true,
        });
        let out: Arc<dyn Outbound> = if kind == "shadowsocks" {
            support::start(
                ShadowsocksOutbound::compile_with_connector(&client, Some(direct)).unwrap(),
            )
            .unwrap()
        } else {
            support::start(Ss2022Outbound::compile_with_connector(&client, Some(direct)).unwrap())
                .unwrap()
        };
        assert!(out.capabilities().tcp_eof);
        assert!(!out.capabilities().udp);
    }
}

struct Wrapped {
    inner: ShadowsocksNode,
}
impl InboundProtocol for Wrapped {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = self.inner.credential_manifest();
        manifest.protection("shadowtls", [9; 32]);
        manifest
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        self.inner.handle(stream, access, context)
    }
}
struct WrappedFactory(&'static str);
impl kerlico_config::NodeFactory for WrappedFactory {
    fn kind(&self) -> &'static str {
        self.0
    }
    fn build(&self, input: &kerlico_config::NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(Wrapped {
            inner: ShadowsocksNode::from_context(input)?,
        }))
    }
}

#[test]
fn actual_inner_and_outer_authentication_domains_prevent_wrapper_alias_bypass() {
    let mut registry = kerlico_config::Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(ShadowsocksNodeFactory).unwrap();
    registry.register_node(WrappedFactory("wrapped-a")).unwrap();
    registry.register_node(WrappedFactory("wrapped-b")).unwrap();
    let entry = |tag: &str, kind: &str, address: &str, password: &str| json!({"tag":tag,"type":kind,"listen":address,"outbound":"direct","options":{"method":"aes-128-gcm"},"members":[{"user_id":"10000000-0000-4000-8000-000000000001","credential_epoch":1,"native_credential":{"password":password}}]});
    let mut value = json!({"version":2,"accounts":[{"user_id":"10000000-0000-4000-8000-000000000001","username":"fixture_10000000-0000-4000-8000-000000000001","password_hash":"$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXRlc3Qtc2FsdA$c3ludGhldGljLXRlc3QtZGlnZXN0LWNvbnRlbnQ"}],"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[entry("plain","shadowsocks","127.0.0.1:0","first-secret"),entry("wrapped","wrapped-a","[::1]:0","first-secret")]});
    let prepare = |value: &Value| {
        registry.prepare(kerlico_config::parse(&serde_json::to_vec(value).unwrap()).unwrap())
    };
    assert!(prepare(&value).is_err());
    value["nodes"][1]["members"][0]["native_credential"]["password"] = json!("second-secret");
    assert!(prepare(&value).is_ok());
    value["nodes"].as_array_mut().unwrap().push(entry(
        "other-wrapper",
        "wrapped-b",
        "127.0.0.1:1",
        "third-secret",
    ));
    assert!(prepare(&value).is_err());
}
