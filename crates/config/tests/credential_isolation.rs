use kerlico_config::{
    Config, NodeBuildContext, NodeFactory, OutboundFactory, OutboundPlan, Registry,
};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, CredentialManifest, DatagramChannel,
    Destination, Error, InboundContext, InboundProtocol, IngressBinding, Outbound, Result,
    TargetPolicy,
};
use serde_json::{Value, json};
use std::sync::Arc;

struct Exit;
impl Outbound for Exit {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
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
struct ExitFactory;
impl OutboundFactory for ExitFactory {
    fn kind(&self) -> &'static str {
        "synthetic-exit"
    }
    fn compile(&self, _: &Value) -> Result<OutboundPlan> {
        Ok(OutboundPlan::new(
            Exit.capabilities(),
            false,
            TargetPolicy::Remote,
            |_| Box::pin(async { Ok(Arc::new(Exit) as Arc<dyn Outbound>) }),
        ))
    }
}
struct Protocol {
    auth: bool,
    value: u8,
    empty_isolation: bool,
    invalid_scope: bool,
}
impl InboundProtocol for Protocol {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        if self.auth {
            manifest.authentication("synthetic-auth", 0, [self.value; 32]);
        }
        if !self.empty_isolation {
            manifest.protection(
                if self.invalid_scope {
                    "invalid scope"
                } else {
                    "synthetic-auth"
                },
                [self.value; 32],
            );
        }
        manifest
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
struct Factory;
impl NodeFactory for Factory {
    fn kind(&self) -> &'static str {
        "synthetic"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let value = input.options();
        Ok(Arc::new(Protocol {
            auth: value["auth"].as_bool().unwrap_or(false),
            value: value["value"].as_u64().unwrap_or(1) as u8,
            empty_isolation: value["empty_isolation"].as_bool().unwrap_or(false),
            invalid_scope: value["invalid_scope"].as_bool().unwrap_or(false),
        }))
    }
}
fn registry() -> Registry {
    let mut registry = Registry::default();
    registry.register(ExitFactory).unwrap();
    registry.register_node(Factory).unwrap();
    registry
}
fn entry(tag: &str, listen: &str, auth: bool, value: u8) -> Value {
    let mut entry = json!({"tag":tag,"type":"synthetic","listen":listen,"outbound":"exit","options":{"auth":auth,"value":value}});
    if auth {
        entry["members"] = json!([{"user_id":"00000000-0000-4000-8000-000000000001","native_credential":{"value":value}}]);
    }
    entry
}
fn config(nodes: Vec<Value>, locals: Vec<Value>) -> Config {
    serde_json::from_value(json!({"version":2,"accounts":[{"user_id":"00000000-0000-4000-8000-000000000001","username":"test-user_00000000-0000-4000-8000-000000000001","password_hash":"$argon2id$v=19$m=19456,t=2,p=1$dGVzdC1zYWx0LTEyMzQ1Ng$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}],"outbounds":[{"tag":"exit","type":"synthetic-exit"}],"inbounds":[],"nodes":nodes,"local_inbounds":locals})).unwrap()
}

#[test]
fn isolation_secret_does_not_grant_public_authentication() {
    let local = entry("local", "127.0.0.1:10443", false, 1);
    assert!(
        registry()
            .prepare(config(Vec::new(), vec![local.clone()]))
            .is_ok()
    );
    assert!(registry().prepare(config(vec![local], Vec::new())).is_err());
    let public = entry("public", "0.0.0.0:10443", false, 1);
    assert!(
        registry()
            .prepare(config(Vec::new(), vec![public]))
            .is_err()
    );
}
#[test]
fn authentication_and_isolation_share_one_cross_entry_secret_domain() {
    let authenticated = entry("node4", "127.0.0.1:10443", true, 1);
    let local = entry("local6", "[::1]:10444", false, 1);
    assert!(
        registry()
            .prepare(config(vec![authenticated.clone()], vec![local.clone()]))
            .is_err()
    );
    let local4 = entry("local4", "127.0.0.1:10445", false, 1);
    assert!(
        registry()
            .prepare(config(Vec::new(), vec![local4, local]))
            .is_err()
    );
    let unique = entry("local6", "[::1]:10444", false, 2);
    assert!(
        registry()
            .prepare(config(vec![authenticated], vec![unique]))
            .is_ok()
    );
}
#[test]
fn an_empty_isolation_override_cannot_hide_real_authentication_duplicates() {
    let mut a = entry("node4", "127.0.0.1:10443", true, 1);
    a["options"]["empty_isolation"] = json!(true);
    let mut b = entry("node6", "[::1]:10444", true, 1);
    b["options"]["empty_isolation"] = json!(true);
    assert!(registry().prepare(config(vec![a, b], Vec::new())).is_err());
    let mut local = entry("local", "127.0.0.1:10443", false, 1);
    local["options"]["invalid_scope"] = json!(true);
    assert!(registry().prepare(config(Vec::new(), vec![local])).is_err());
}
