#![allow(dead_code)]
use kerlico_config::{NodeBuildContext, NodeFactory, OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxStream, CredentialEntry, InboundContext, InboundProtocol, IngressBinding, Outbound, Result,
    TargetPolicy,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
struct TestBackend {
    capabilities: kerlico_core::Capabilities,
    association: bool,
    plan: Mutex<Option<OutboundPlan>>,
    backend: tokio::sync::OnceCell<Arc<dyn Outbound>>,
    host: kerlico_core::ServiceContext,
}
impl TestBackend {
    async fn backend(&self) -> Result<&Arc<dyn Outbound>> {
        self.backend
            .get_or_try_init(|| async {
                let plan = self
                    .plan
                    .lock()
                    .map_err(|_| kerlico_core::Error::Rejected)?
                    .take()
                    .ok_or(kerlico_core::Error::Rejected)?;
                plan.start(self.host.clone()).await
            })
            .await
    }
}
impl Drop for TestBackend {
    fn drop(&mut self) {
        self.host.cancel().cancel();
    }
}
impl Outbound for TestBackend {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        self.capabilities
    }
    fn supports_udp_association(&self) -> bool {
        self.association
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a kerlico_core::Destination,
        context: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move { self.backend().await?.connect_tcp(target, context).await })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a kerlico_core::Destination,
        context: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, Result<kerlico_core::DatagramChannel>> {
        Box::pin(async move { self.backend().await?.connect_udp(target, context).await })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, Result<kerlico_core::DatagramAssociation>> {
        Box::pin(async move { self.backend().await?.associate_udp(context).await })
    }
    fn shutdown(&self) -> kerlico_core::BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if let Some(backend) = self.backend.get() {
                backend.shutdown().await?;
            }
            let report = self
                .host
                .shutdown(tokio::time::Instant::now() + std::time::Duration::from_secs(3))
                .await;
            if !report.is_clean() {
                return Err(kerlico_core::Error::Timeout);
            }
            Ok(())
        })
    }
}
pub fn start(plan: OutboundPlan) -> Result<Arc<dyn Outbound>> {
    Ok(Arc::new(TestBackend {
        capabilities: plan.capabilities(),
        association: plan.supports_udp_association(),
        plan: Mutex::new(Some(plan)),
        backend: tokio::sync::OnceCell::new(),
        host: kerlico_core::ServiceContext::for_test(),
    }))
}
pub fn outbound(factory: &impl OutboundFactory, options: &Value) -> Result<Arc<dyn Outbound>> {
    start(factory.compile(options)?)
}
pub fn credentials(kind: &str, source: &Value) -> (Value, Vec<Value>, bool) {
    let mut options = source.clone();
    let Some(object) = options.as_object_mut() else {
        return (options, Vec::new(), false);
    };
    let rows = match kind {
        "vless" | "vmess" => {
            if let Some(uuid) = object.remove("uuid") {
                let mut row = json!({"uuid":uuid});
                if let Some(flow) = object.remove("flow") {
                    row["flow"] = flow;
                }
                vec![row]
            } else {
                object
                    .remove("users")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
            }
        }
        "trojan" | "anytls" => {
            if let Some(password) = object.remove("password") {
                vec![json!({"password":password})]
            } else {
                object
                    .remove("passwords")
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|password| json!({"password":password}))
                    .collect()
            }
        }
        "shadowsocks" => {
            let method = object.get("method").and_then(Value::as_str).unwrap_or("");
            let authenticated =
                method.contains("gcm") || method.contains("poly1305") || method.contains("ccm");
            if !authenticated {
                return (options, Vec::new(), true);
            }
            object
                .remove("password")
                .map(|password| vec![json!({"password":password})])
                .unwrap_or_default()
        }
        "ss2022" => {
            let key = object.remove("key");
            let users = object
                .remove("users")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            if users.is_empty() {
                key.map(|key| vec![json!({"key":key})]).unwrap_or_default()
            } else {
                if let Some(key) = key {
                    object.insert("identity_key".into(), key);
                }
                users.into_iter().map(|key| json!({"key":key})).collect()
            }
        }
        "snell" => {
            let psk = object.remove("psk").unwrap_or(Value::Null);
            let users = object
                .remove("users")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            if users.is_empty() {
                vec![json!({"psk":psk})]
            } else {
                users
                    .into_iter()
                    .map(|user| json!({"psk":psk,"userkey":user["userkey"]}))
                    .collect()
            }
        }
        "shadowsocksr" => {
            let protocol = object
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("origin");
            let obfs = object
                .get("obfs")
                .and_then(Value::as_str)
                .unwrap_or("plain");
            let udp = object.get("udp").and_then(Value::as_bool).unwrap_or(true);
            let mac = matches!(
                protocol,
                "auth_aes128_md5" | "auth_aes128_sha1" | "auth_chain_a" | "auth_chain_b"
            );
            if (protocol == "origin" && !obfs.starts_with("tls1.2_")) || (udp && !mac) {
                return (options, Vec::new(), true);
            }
            let password = object.remove("password").unwrap_or(Value::Null);
            let users = object
                .remove("users")
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            if users.is_empty() {
                vec![json!({"password":password})]
            } else {
                users
                    .into_iter()
                    .map(|user| json!({"password":password,"user":user}))
                    .collect()
            }
        }
        "shadowtls" => {
            let inner = object.get("inner").cloned().unwrap_or(Value::Null);
            let (inner_options, rows, local) =
                credentials(inner["type"].as_str().unwrap_or(""), &inner["options"]);
            options["inner"]["options"] = inner_options;
            return (options, rows, local);
        }
        _ => Vec::new(),
    };
    (options, rows, false)
}
#[derive(Clone)]
pub struct TestNode {
    protocol: Arc<dyn InboundProtocol>,
    input: NodeBuildContext,
    binding: Arc<Mutex<Option<IngressBinding>>>,
}
impl std::ops::Deref for TestNode {
    type Target = dyn InboundProtocol;
    fn deref(&self) -> &Self::Target {
        self.protocol.as_ref()
    }
}
pub fn node(factory: &impl NodeFactory, options: &Value) -> Result<TestNode> {
    let (options, rows, local) = credentials(factory.kind(), options);
    let input = if local {
        NodeBuildContext::local_for_test(options)
    } else {
        NodeBuildContext::for_test(options, rows)
    };
    let protocol = factory.build(&input)?;
    Ok(TestNode {
        protocol,
        input,
        binding: Arc::new(Mutex::new(None)),
    })
}
impl TestNode {
    pub fn ingress(&self, outbound: Arc<dyn Outbound>) -> Result<IngressBinding> {
        self.ingress_with_policy(outbound, TargetPolicy::Remote)
    }
    pub fn ingress_with_policy(
        &self,
        outbound: Arc<dyn Outbound>,
        policy: TargetPolicy,
    ) -> Result<IngressBinding> {
        let mut binding = self
            .binding
            .lock()
            .map_err(|_| kerlico_core::Error::Rejected)?;
        if let Some(binding) = &*binding {
            return Ok(binding.clone());
        }
        let result = kerlico_egress::testing::ingress(&self.input, outbound, policy)?;
        *binding = Some(result.clone());
        Ok(result)
    }
    pub fn manifest(&self) -> Vec<[u8; 32]> {
        self.protocol
            .credential_manifest()
            .entries()
            .iter()
            .map(|entry| entry.fingerprint)
            .collect()
    }
    pub fn scoped_manifest(&self, _: &str) -> Vec<CredentialEntry> {
        self.protocol.credential_manifest().entries().to_vec()
    }
    pub async fn handle(
        &self,
        stream: BoxStream,
        outbound: Arc<dyn Outbound>,
        mut context: InboundContext,
    ) -> Result<()> {
        if self.input.is_local() && context.local_addr.is_none() {
            context.local_addr = Some("127.0.0.1:1".parse().expect("测试回环地址"));
        }
        self.protocol
            .handle(stream, self.ingress(outbound)?, context)
            .await
    }
    pub async fn handle_local(
        &self,
        stream: BoxStream,
        outbound: Arc<dyn Outbound>,
        context: InboundContext,
    ) -> Result<()> {
        self.protocol
            .handle(
                stream,
                self.ingress_with_policy(outbound, TargetPolicy::Local)?,
                context,
            )
            .await
    }
    pub async fn handle_udp(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        outbound: Arc<dyn Outbound>,
        context: InboundContext,
    ) -> Result<()> {
        self.protocol
            .handle_udp(socket, self.ingress(outbound)?, context)
            .await
    }
    pub async fn serve_udp(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        outbound: Arc<dyn Outbound>,
        context: InboundContext,
    ) -> Result<()> {
        self.handle_udp(socket, outbound, context).await
    }
}
pub fn configuration(mut config: Value) -> Value {
    if config.get("outbounds").is_none() {
        return config;
    }
    config["version"] = json!(2);
    let mut accounts = config["accounts"].as_array().cloned().unwrap_or_default();
    let mut locals = config["local_inbounds"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some(nodes) = config.get_mut("nodes").and_then(Value::as_array_mut) {
        let mut remote = Vec::new();
        for mut node in std::mem::take(nodes) {
            if node.get("members").is_some() {
                remote.push(node);
                continue;
            }
            let (options, rows, local) =
                credentials(node["type"].as_str().unwrap_or(""), &node["options"]);
            node["options"] = options;
            let mut members = Vec::new();
            for native in rows {
                let id = format!("10000000-0000-4000-8000-{:012x}", accounts.len() + 1);
                accounts.push(json!({"user_id":id,"username":format!("fixture_{id}"),"password_hash":"$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXRlc3Qtc2FsdA$c3ludGhldGljLXRlc3QtZGlnZXN0LWNvbnRlbnQ"}));
                members.push(json!({"user_id":id,"credential_epoch":1,"native_credential":native}));
            }
            node["members"] = Value::Array(members);
            if local {
                locals.push(node);
            } else {
                remote.push(node);
            }
        }
        *nodes = remote;
    }
    config["accounts"] = Value::Array(accounts);
    config["local_inbounds"] = Value::Array(locals);
    config
}
