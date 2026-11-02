use kerlico_config::{Registry, parse};
use kerlico_core::CancellationToken;
use kerlico_egress::{HistoryQuery, HistoryReader};
use kerlico_engine::Engine;
use kerlico_net::DirectFactory;
use serde_json::json;
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn transfer(directory: &Path, access_records: bool) {
    transfer_inner(directory, access_records, false).await;
}
async fn transfer_inner(directory: &Path, access_records: bool, manual: bool) {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let mut config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":target.local_addr().unwrap().port()},"outbound":"exit"}],
        "telemetry": {"directory": directory, "sample_interval_ms":60000,"access_records":access_records},
        "limits": {"max_sessions":1,"max_flow_records":2,"drain_timeout_ms":1000}
    });
    if manual {
        config.as_object_mut().unwrap().remove("telemetry");
    }
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let telemetry = engine.telemetry();
    let mut writer = manual.then(|| {
        kerlico_egress::HistoryWriter::open(
            directory,
            telemetry.clone(),
            true,
            access_records,
            Duration::from_secs(86400),
        )
        .unwrap()
    });
    let stats = engine.stats();
    let address = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    for index in 0..4 {
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut peer, _) = target.accept().await.unwrap();
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        peer.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        peer.write_all(b"reply").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"reply");
        timeout(Duration::from_secs(2), async {
            while stats.completed.load(std::sync::atomic::Ordering::Acquire) <= index {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    assert!(telemetry.online().unwrap().is_empty());
    assert_eq!(telemetry.usage().unwrap().engine.upload_bytes, 28);
    assert_eq!(telemetry.usage().unwrap().engine.download_bytes, 20);
    stop.cancel();
    running.await.unwrap().unwrap();
    if let Some(writer) = &mut writer {
        let blocker = rusqlite::Connection::open(directory.join("history.sqlite3")).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(writer.checkpoint().is_err());
        blocker.execute_batch("ROLLBACK").unwrap();
        writer.checkpoint().unwrap();
        writer.checkpoint().unwrap();
        let reader = HistoryReader::open(directory).unwrap();
        assert_eq!(reader.flows(&HistoryQuery::default()).unwrap().len(), 4);
        let usage = reader.usage().unwrap();
        let engine = usage.iter().find(|row| row.dimension == "engine").unwrap();
        assert_eq!(engine.usage.upload_bytes, 28);
        assert_eq!(engine.usage.download_bytes, 20);
    }
}

#[tokio::test]
async fn failed_nonzero_checkpoint_retries_without_losing_evicted_records_or_double_counting() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    timeout(
        Duration::from_secs(10),
        transfer_inner(directory.path(), true, true),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn sqlite_write_lock_does_not_extend_engine_shutdown_budget() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let value = json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],
        "inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":9},"outbound":"exit"}],
        "telemetry":{"directory":directory.path(),"sample_interval_ms":60000},"limits":{"drain_timeout_ms":30}});
    let prepared = registry
        .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
        .unwrap();
    let engine = Engine::bind(prepared).await.unwrap();
    let receipt = engine.history_retirement().unwrap();
    let blocker = rusqlite::Connection::open(directory.path().join("history.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let stop = CancellationToken::new();
    stop.cancel();
    let result = timeout(Duration::from_millis(500), engine.run(stop))
        .await
        .unwrap();
    assert!(result.is_err(), "最终提交被真实写锁拒绝时不能报告成功");
    timeout(Duration::from_secs(1), receipt.wait())
        .await
        .unwrap();
    assert!(receipt.is_finished());
    blocker.execute_batch("ROLLBACK").unwrap();
}

#[tokio::test]
async fn cancelling_an_active_flow_commits_delivered_usage_and_terminal_record() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let value = json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],
        "inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":target.local_addr().unwrap().port()},"outbound":"exit"}],
        "telemetry":{"directory":directory.path(),"sample_interval_ms":60000},"limits":{"drain_timeout_ms":300}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let telemetry = engine.telemetry();
    let receipt = engine.history_retirement().unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let mut client = TcpStream::connect(address).await.unwrap();
    let (mut peer, _) = target.accept().await.unwrap();
    client.write_all(b"active-payload").await.unwrap();
    let mut delivered = [0; 14];
    peer.read_exact(&mut delivered).await.unwrap();
    assert_eq!(&delivered, b"active-payload");
    timeout(Duration::from_secs(2), async {
        while telemetry.usage().unwrap().engine.upload_bytes != 14 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.cancel();
    timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), receipt.wait())
        .await
        .unwrap();
    let reader = HistoryReader::open(directory.path()).unwrap();
    let records = reader.flows(&HistoryQuery::default()).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].1.end.is_some());
    assert_eq!(records[0].1.usage.upload_bytes, 14);
    assert_eq!(
        reader
            .usage()
            .unwrap()
            .iter()
            .find(|row| row.dimension == "engine")
            .unwrap()
            .usage
            .upload_bytes,
        14
    );
    assert!(telemetry.online().unwrap().is_empty());
}

async fn persistence_failure_policy(policy: &str, keeps_running: bool) {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let value = json!({"version":2,"outbounds":[{"tag":"exit","type":"direct"}],
        "inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":target.local_addr().unwrap().port()},"outbound":"exit"}],
        "telemetry":{"directory":directory.path(),"sample_interval_ms":100,"failure_policy":policy},"limits":{"drain_timeout_ms":500}});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&value).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let stats = engine.stats();
    let address = engine.listeners().unwrap()[0].1;
    let blocker = rusqlite::Connection::open(directory.path().join("history.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    timeout(Duration::from_secs(2), async {
        while stats
            .history_failures
            .load(std::sync::atomic::Ordering::Relaxed)
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    if keeps_running {
        assert!(!running.is_finished());
        let mut client = TcpStream::connect(address).await.unwrap();
        let (mut peer, _) = target.accept().await.unwrap();
        client.write_all(b"still-forwarding").await.unwrap();
        let mut request = [0; 16];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"still-forwarding");
        peer.write_all(b"ok").await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        blocker.execute_batch("ROLLBACK").unwrap();
        drop(client);
        drop(peer);
        stop.cancel();
        timeout(Duration::from_secs(2), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            HistoryReader::open(directory.path())
                .unwrap()
                .usage()
                .unwrap()
                .iter()
                .find(|row| row.dimension == "engine")
                .unwrap()
                .usage
                .upload_bytes,
            16
        );
    } else {
        assert!(
            timeout(Duration::from_secs(2), running)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        blocker.execute_batch("ROLLBACK").unwrap();
    }
}

#[tokio::test]
async fn degraded_storage_keeps_forwarding_and_commits_after_recovery() {
    persistence_failure_policy("degrade", true).await;
}
#[tokio::test]
async fn strict_storage_policy_stops_engine_on_periodic_failure() {
    persistence_failure_policy("stop-engine", false).await;
}

#[tokio::test]
async fn final_commit_preserves_evicted_flows_and_restart_totals() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    timeout(Duration::from_secs(10), transfer(directory.path(), true))
        .await
        .unwrap();
    let reader = HistoryReader::open(directory.path()).unwrap();
    let records = reader.flows(&HistoryQuery::default()).unwrap();
    assert_eq!(records.len(), 4);
    assert!(
        records
            .iter()
            .all(|(_, flow)| flow.end.as_deref() == Some("completed"))
    );
    assert!(records.iter().all(|(_, flow)| {
        flow.observed_source
            .as_ref()
            .is_none_or(|source| source.ends_with("/24"))
    }));
    let cursor = records[1].0;
    let next = reader
        .flows(&HistoryQuery {
            after: cursor,
            limit: 1,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(next[0].0, records[2].0);
    assert!(
        reader
            .flows(&HistoryQuery {
                node: Some("missing".into()),
                ..Default::default()
            })
            .unwrap()
            .is_empty()
    );
    timeout(Duration::from_secs(10), transfer(directory.path(), true))
        .await
        .unwrap();
    let usage = reader.usage().unwrap();
    for dimension in ["engine", "node", "outbound"] {
        let row = usage.iter().find(|row| row.dimension == dimension).unwrap();
        assert_eq!(row.usage.upload_bytes, 56);
        assert_eq!(row.usage.download_bytes, 40);
    }
    let records = reader.flows(&HistoryQuery::default()).unwrap();
    assert_eq!(records.len(), 8);
    assert_ne!(records[0].1.run, records[4].1.run);
    let samples = reader.bandwidth(0, 0, 100).unwrap();
    assert!(
        samples
            .iter()
            .any(|(_, sample)| sample.upload_bytes_per_second > 0.0)
    );
    let scope = kerlico_egress::HistoryScope::Node(kerlico_core::NodeId::parse("entry").unwrap());
    let scoped = reader.usage_in(Some(&scope)).unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].dimension, "node");
    assert_eq!(scoped[0].usage.upload_bytes, 56);
    let page = reader.bandwidth_in(0, 0, 1, Some(&scope)).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].1.dimension, "node");
    let next = reader.bandwidth_in(0, page[0].0, 1, Some(&scope)).unwrap();
    assert_eq!(next.len(), 1);
    assert!(next[0].0 > page[0].0);
    let missing = kerlico_egress::HistoryScope::User(kerlico_core::UserId::generate());
    assert!(reader.usage_in(Some(&missing)).unwrap().is_empty());
    assert!(
        reader
            .bandwidth_in(0, 0, 10, Some(&missing))
            .unwrap()
            .is_empty()
    );
    assert!(
        samples.iter().all(
            |(_, sample)| sample.peak_upload_bytes_per_second >= sample.upload_bytes_per_second
        )
    );
    assert_eq!(reader.usage().unwrap()[0].usage, usage[0].usage);
}

#[tokio::test]
async fn access_logging_can_be_disabled_without_disabling_usage() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    timeout(Duration::from_secs(10), transfer(directory.path(), false))
        .await
        .unwrap();
    let reader = HistoryReader::open(directory.path()).unwrap();
    assert!(reader.flows(&HistoryQuery::default()).unwrap().is_empty());
    assert_eq!(
        reader
            .usage()
            .unwrap()
            .iter()
            .find(|row| row.dimension == "engine")
            .unwrap()
            .usage
            .upload_bytes,
        28
    );
}

#[test]
fn history_query_does_not_create_missing_storage() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    assert!(HistoryReader::open(&directory.path().join("missing")).is_err());
    assert!(!directory.path().join("missing").exists());
}

#[tokio::test]
async fn dns_and_connect_failures_are_persisted_as_events() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"localhost","port":port},"outbound":"exit"}],
        "telemetry": {"directory": directory.path(), "sample_interval_ms":60000},
        "limits": {"drain_timeout_ms":1000}
    });
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let (_, address) = engine.listeners().unwrap().remove(0);
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("目标拒绝连接后入口应结束");
    stop.cancel();
    running.await.unwrap().unwrap();
    let events = HistoryReader::open(directory.path())
        .unwrap()
        .events(&HistoryQuery::default())
        .unwrap();
    let dns = events
        .iter()
        .find(|(_, event)| event.kind == "dns")
        .expect("应记录域名解析")
        .1
        .clone();
    assert_eq!(dns.target.as_deref(), Some("localhost"));
    assert_eq!(dns.code, "ok");
    assert!(!dns.addresses.is_empty());
    let error = events
        .iter()
        .find(|(_, event)| event.kind == "error")
        .expect("应记录建立失败")
        .1
        .clone();
    assert_eq!(error.code, "io.failed");
    assert_eq!(error.outbound, "exit");
    assert_eq!(error.node, "entry");
}

async fn events_after_closed_connection(
    config: serde_json::Value,
    registry: Registry,
    directory: &Path,
) -> Vec<kerlico_egress::EventRecord> {
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let (_, address) = engine.listeners().unwrap().remove(0);
    let stop = CancellationToken::new();
    let running = tokio::spawn(engine.run(stop.clone()));
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(10), stream.read_to_end(&mut bytes))
        .await
        .expect("入口应在期限内结束连接");
    stop.cancel();
    running.await.unwrap().unwrap();
    HistoryReader::open(directory)
        .unwrap()
        .events(&HistoryQuery::default())
        .unwrap()
        .into_iter()
        .map(|(_, event)| event)
        .collect()
}

#[tokio::test]
async fn flow_ending_without_a_reported_failure_still_records_one_event() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let holding = tokio::spawn(async move {
        let _held = silent.accept().await;
        std::future::pending::<()>().await;
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":port},"outbound":"exit"}],
        "telemetry": {"directory": directory.path(), "sample_interval_ms":60000},
        "limits": {"idle_timeout_ms":200,"drain_timeout_ms":1000}
    });
    let events = events_after_closed_connection(config, registry, directory.path()).await;
    holding.abort();
    let errors: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "error")
        .collect();
    assert_eq!(errors.len(), 1, "{events:?}");
    assert_eq!(errors[0].code, "operation.timeout");
    assert_eq!(errors[0].outbound, "exit");
}

struct UdpOnly;
impl kerlico_core::Outbound for UdpOnly {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        kerlico_core::Capabilities {
            tcp: false,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a kerlico_core::Destination,
        _: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::OpenedTcp>> {
        Box::pin(async { Err(kerlico_core::Error::Rejected) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a kerlico_core::Destination,
        _: &'a kerlico_core::ConnectContext,
    ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::DatagramChannel>> {
        Box::pin(async { Err(kerlico_core::Error::Rejected) })
    }
}
struct UdpOnlyFactory;
impl kerlico_config::OutboundFactory for UdpOnlyFactory {
    fn kind(&self) -> &'static str {
        "udp-only"
    }
    fn compile(&self, _: &serde_json::Value) -> kerlico_core::Result<kerlico_config::OutboundPlan> {
        Ok(kerlico_config::OutboundPlan::new(
            kerlico_core::Outbound::capabilities(&UdpOnly),
            false,
            kerlico_core::TargetPolicy::Remote,
            |_| {
                Box::pin(async {
                    Ok(std::sync::Arc::new(UdpOnly) as std::sync::Arc<dyn kerlico_core::Outbound>)
                })
            },
        ))
    }
}

#[tokio::test]
async fn failure_before_a_flow_exists_records_one_event() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register(UdpOnlyFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"},{"tag":"datagrams","type":"udp-only"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"192.0.2.1","port":9},"outbound":"exit"}],
        "routes": [{"outbound":"datagrams","port":[9]}],
        "telemetry": {"directory": directory.path(), "sample_interval_ms":60000},
        "limits": {"drain_timeout_ms":1000}
    });
    let events = events_after_closed_connection(config, registry, directory.path()).await;
    let errors: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "error")
        .collect();
    assert_eq!(errors.len(), 1, "{events:?}");
    assert_eq!(errors[0].code, "capability.unsupported");
    assert_eq!(errors[0].outbound, "datagrams");
    assert_eq!(errors[0].node, "entry");
    assert_eq!(errors[0].target.as_deref(), Some("192.0.2.1:9"));
}

#[tokio::test]
async fn lookup_abandoned_by_the_outer_deadline_records_an_aborted_event() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = silent.local_addr().unwrap();
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let config = json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"slow.example","port":9},"outbound":"exit"}],
        "dns": {"servers":[format!("udp://{upstream}")]},
        "telemetry": {"directory": directory.path(), "sample_interval_ms":60000},
        "limits": {"connect_timeout_ms":2000,"drain_timeout_ms":1000}
    });
    let events = events_after_closed_connection(config, registry, directory.path()).await;
    drop(silent);
    let dns: Vec<_> = events.iter().filter(|event| event.kind == "dns").collect();
    assert_eq!(dns.len(), 1, "{events:?}");
    assert_eq!(dns[0].code, "dns.aborted");
    assert_eq!(dns[0].target.as_deref(), Some("slow.example"));
}
