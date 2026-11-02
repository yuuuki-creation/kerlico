use kerlico_config::{OutboundFactory, OutboundPlan, Registry, parse};
use kerlico_core::{
    BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, Error, Outbound, Result,
    TargetPolicy,
};
use kerlico_tun::TunNodeFactory;
use serde_json::{Value, json};
use std::sync::Arc;

struct Exit;
impl Outbound for Exit {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
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
        "exit"
    }
    fn compile(&self, _: &Value) -> Result<OutboundPlan> {
        Ok(OutboundPlan::new(
            Exit.capabilities(),
            true,
            TargetPolicy::Remote,
            |_| Box::pin(async { Ok(Arc::new(Exit) as Arc<dyn Outbound>) }),
        ))
    }
}

fn check(node: Value, limits: Value) -> Result<()> {
    let mut registry = Registry::default();
    registry.register(ExitFactory)?;
    registry.register_node(TunNodeFactory)?;
    let mut inbound = json!({"tag":"tun","type":"tun","listen":"127.0.0.1:0","outbound":"exit","options":{"addresses":["198.18.0.1/16"]}});
    inbound.as_object_mut().unwrap().extend(
        node.as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"exit"}],
        "local_inbounds": [inbound],
        "limits": limits,
    });
    registry.prepare(parse(&serde_json::to_vec(&config).unwrap())?)?;
    Ok(())
}
fn options(value: Value) -> Value {
    json!({ "options": value })
}

#[test]
fn check_rejects_addresses_that_only_fail_at_run() {
    assert!(check(options(json!({"addresses":["198.18.0.1/16"]})), json!({})).is_ok());
    for address in [
        "::ffff:198.18.0.1/96",
        "255.255.255.254/24",
        "223.255.255.255/24",
    ] {
        assert!(
            check(options(json!({"addresses":[address]})), json!({})).is_err(),
            "{address} 的用户态栈地址不是单播"
        );
    }
}

#[test]
fn tunnel_permit_needs_a_session_left_for_flows() {
    assert!(check(json!({"max_sessions":2}), json!({})).is_ok());
    assert!(
        check(json!({"max_sessions":1}), json!({})).is_err(),
        "隧道占满唯一的会话配额后没有流可用"
    );
    assert!(
        check(json!({}), json!({"max_sessions":1})).is_err(),
        "节点未单独设置时继承全局上限"
    );
}

#[test]
fn max_flows_uses_the_stack_range() {
    let flows = |value: u64| {
        check(
            options(json!({"addresses":["198.18.0.1/16"],"max_flows":value})),
            json!({}),
        )
    };
    assert!(flows(1).is_ok());
    assert!(flows(4096).is_ok());
    assert!(flows(0).is_err());
    assert!(flows(4097).is_err());
}
