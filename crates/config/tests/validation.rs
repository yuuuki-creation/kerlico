use kerlico_config::{AccountSpec, NodeBuildContext, NodeFactory, Registry, parse};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, CredentialManifest, DatagramChannel,
    Destination, Error, InboundContext, InboundProtocol, IngressBinding, Outbound, Result,
    TargetPolicy,
};
use serde_json::{Value, json};
use std::sync::Arc;

struct Exit(Capabilities);
impl Outbound for Exit {
    fn capabilities(&self) -> Capabilities {
        self.0
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async { Err(Error::Rejected) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Rejected) })
    }
}
struct ExitFactory {
    kind: &'static str,
    tcp_eof: bool,
}
impl OutboundFactory for ExitFactory {
    fn kind(&self) -> &'static str {
        self.kind
    }
    fn compile(&self, _: &Value) -> Result<OutboundPlan> {
        let capabilities = Capabilities {
            tcp: true,
            tcp_eof: self.tcp_eof,
            udp: true,
        };
        Ok(OutboundPlan::new(
            capabilities,
            false,
            TargetPolicy::Remote,
            move |_| Box::pin(async move { Ok(Arc::new(Exit(capabilities)) as Arc<dyn Outbound>) }),
        ))
    }
}
struct TcpNode;
impl InboundProtocol for TcpNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }
    fn handle<'a>(
        &'a self,
        _: BoxStream,
        _: IngressBinding,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Rejected) })
    }
}
struct TcpNodeFactory;
impl NodeFactory for TcpNodeFactory {
    fn kind(&self) -> &'static str {
        "tcp-node"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, _: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(TcpNode))
    }
}

fn prepare(config: Value) -> Result<()> {
    let mut registry = Registry::default();
    registry.register(ExitFactory {
        kind: "eof",
        tcp_eof: true,
    })?;
    registry.register(ExitFactory {
        kind: "no-eof",
        tcp_eof: false,
    })?;
    registry.register_node(TcpNodeFactory)?;
    registry.prepare(parse(&serde_json::to_vec(&config).unwrap())?)?;
    Ok(())
}
fn with(mut base: Value, field: &str, value: Value) -> Value {
    base[field] = value;
    base
}
fn forward(tag: &str, listen: &str, kind: &str) -> Value {
    json!({"tag":tag,"type":kind,"listen":listen,"target":{"host":"127.0.0.1","port":9},"outbound":"exit"})
}
fn base() -> Value {
    json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"eof"},{"tag":"lossy","type":"no-eof"}],
        "inbounds": [forward("entry","127.0.0.1:7000","tcp-forward")],
        "local_inbounds": [{"tag":"local","type":"tcp-node","listen":"127.0.0.1:7001","outbound":"exit","options":{}}],
    })
}

#[test]
fn route_references_must_exist() {
    assert!(
        prepare(with(
            base(),
            "routes",
            json!([{"outbound":"exit","node":["entry"]}])
        ))
        .is_ok()
    );
    assert!(
        prepare(with(
            base(),
            "routes",
            json!([{"outbound":"exit","node":["local"]}])
        ))
        .is_ok()
    );
    assert!(
        prepare(with(
            base(),
            "routes",
            json!([{"outbound":"exit","node":["typo"]}])
        ))
        .is_err(),
        "节点标签拼错的规则永远不会命中"
    );
    let account =
        serde_json::to_value(AccountSpec::create("user", b"synthetic-password").unwrap()).unwrap();
    let known = account["user_id"].clone();
    let config = with(base(), "accounts", json!([account]));
    assert!(
        prepare(with(
            config.clone(),
            "routes",
            json!([{"outbound":"exit","user":[known]}])
        ))
        .is_ok()
    );
    assert!(
        prepare(with(
            config,
            "routes",
            json!([{"outbound":"exit","user":["00000000-0000-4000-8000-000000000009"]}])
        ))
        .is_err(),
        "不在 accounts 内的用户永远不会命中"
    );
}

#[test]
fn remote_eof_requirement_covers_routes_that_can_reach_the_forward() {
    let strict = with(
        base(),
        "inbounds",
        json!([{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:7000",
            "target":{"host":"127.0.0.1","port":9},"outbound":"exit","require_remote_eof":true}]),
    );
    assert!(prepare(strict.clone()).is_ok());
    assert!(
        prepare(with(
            strict.clone(),
            "routes",
            json!([{"outbound":"exit","port":[9]}])
        ))
        .is_ok()
    );
    assert!(
        prepare(with(
            strict.clone(),
            "routes",
            json!([{"outbound":"lossy","port":[9]}])
        ))
        .is_err(),
        "路由可把该入口转给没有 tcp_eof 的出站"
    );
    assert!(
        prepare(with(
            strict.clone(),
            "routes",
            json!([{"outbound":"lossy","node":["entry"]}])
        ))
        .is_err()
    );
    assert!(
        prepare(with(
            strict.clone(),
            "routes",
            json!([{"outbound":"lossy","node":["local"]}])
        ))
        .is_ok(),
        "限定到其他入口的规则到不了该入口"
    );
    assert!(
        prepare(with(
            strict,
            "routes",
            json!([{"outbound":"lossy","network":"udp"}])
        ))
        .is_ok(),
        "UDP 规则到不了 TCP 入口"
    );
}

#[test]
fn control_listener_must_not_collide_with_a_tcp_listener() {
    for listen in ["127.0.0.1:7000", "127.0.0.1:7001"] {
        assert!(
            prepare(with(base(), "control", json!({"listen":listen}))).is_err(),
            "{listen} 已被入口占用"
        );
    }
    assert!(prepare(with(base(), "control", json!({"listen":"127.0.0.1:7002"}))).is_ok());
    let udp = with(
        base(),
        "inbounds",
        json!([forward("entry", "127.0.0.1:7000", "udp-forward")]),
    );
    assert!(
        prepare(with(udp, "control", json!({"listen":"127.0.0.1:7000"}))).is_ok(),
        "UDP 入口不占 TCP 端口"
    );
}
