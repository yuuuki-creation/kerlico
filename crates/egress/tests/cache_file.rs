use kerlico_config::{CompiledProxyGroup, LoadBalanceStrategy, LogSpec, ProxyGroupKind};
use kerlico_core::{BoxFuture, OutId, Result};
use kerlico_dns::FakeIpPool;
use kerlico_egress::{ControlPlane, Resolver, Telemetry};
use kerlico_routing::RouteTable;
use std::{collections::BTreeMap, net::IpAddr, path::Path, sync::Arc};

struct NoResolver;
impl Resolver for NoResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn id(name: &str) -> OutId {
    OutId::parse(name).unwrap()
}

fn control_plane(path: &Path) -> ControlPlane {
    let group = CompiledProxyGroup {
        id: id("proxy"),
        kind: ProxyGroupKind::Select,
        candidates: vec![id("node-a"), id("node-b")],
        default_selected: Some(id("node-a")),
        fallback_outbound: None,
        url: String::new(),
        interval_secs: 0,
        tolerance_ms: 0,
        timeout_ms: 0,
        idle_timeout_secs: 0,
        lazy: false,
        max_failed_times: 0,
        expected_status: String::new(),
        disable_udp: false,
        empty_fallback: false,
        interrupt_exist_connections: false,
        strategy: LoadBalanceStrategy::default(),
        hash_key: Vec::new(),
        hidden: false,
        icon: None,
    };
    ControlPlane::new(
        vec![
            (id("node-a"), "direct".into(), true),
            (id("node-b"), "direct".into(), true),
        ],
        vec![group],
        Vec::new(),
        BTreeMap::new(),
        RouteTable::default(),
        Some(path.to_string_lossy().into_owned()),
        LogSpec::default(),
        Arc::new(NoResolver),
        Telemetry::new(16),
    )
}

fn fakeip_pool(path: &Path) -> FakeIpPool {
    FakeIpPool::new(
        Some("198.18.0.0/15"),
        None,
        16,
        1,
        Vec::new(),
        Some(path.to_path_buf()),
    )
    .unwrap()
}

#[test]
fn store_selected_and_fakeip_share_default_cache_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");

    let pool = fakeip_pool(&path);
    let fake = pool.allocate_v4("a.example").unwrap();
    control_plane(&path)
        .select_in_group("proxy", "node-b")
        .unwrap();
    pool.allocate_v4("b.example").unwrap();

    let on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(on_disk["selected"]["proxy"], "node-b");
    assert!(on_disk["fakeip"]["v4"]["b.example"].is_string());

    let restarted = control_plane(&path);
    let groups = restarted.groups_json().to_string();
    assert!(groups.contains("\"now\":\"node-b\""), "{groups}");
    assert_eq!(fakeip_pool(&path).allocate_v4("a.example"), Some(fake));
}
