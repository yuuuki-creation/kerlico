mod common;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, ConnectContext, Destination, InboundContext,
    NodeEvent, NodeObserver, ResourceKey, Result, ServiceContext, StreamBudget, StreamConnector,
    TargetPolicy,
};
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{Notify, Semaphore},
};

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}

#[derive(Default)]
struct Gate {
    attempts: AtomicUsize,
    entered: Notify,
    released: Notify,
    first_dropped: AtomicBool,
    scopes: Mutex<Vec<ResourceKey>>,
}
struct PendingDial<'a>(&'a Gate);
impl Drop for PendingDial<'_> {
    fn drop(&mut self) {
        self.0.first_dropped.store(true, Ordering::Release);
        self.0.released.notify_one();
    }
}
impl StreamConnector for Gate {
    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.scopes
                .lock()
                .unwrap()
                .push(context.resource_key().clone());
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                let _pending = PendingDial(self);
                self.entered.notify_one();
                context
                    .run(std::future::pending::<Result<BoxStream>>())
                    .await
            } else {
                kerlico_net::TcpConnector::plain(Default::default())
                    .connect_tcp(endpoint, context)
                    .await
            }
        })
    }
}

fn inbound(cancel: CancellationToken, budget: Arc<Semaphore>) -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        cancel,
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(8),
        drain_timeout: Duration::from_millis(300),
        max_datagram_size: 65507,
        max_streams: 32,
        stream_budget: StreamBudget::new(budget, Arc::new(Semaphore::new(32))),
        events: Arc::new(Observer),
        peer_addr: None,
        local_addr: None,
    }
}

async fn request(stream: &mut DuplexStream, target: &Destination, user: &str) {
    let auth = STANDARD.encode(format!("{user}:synthetic-secret"));
    stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n").as_bytes()).await.unwrap();
}

async fn accepted(stream: &mut DuplexStream) {
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        assert!(response.len() < 4096);
        response.push(stream.read_u8().await.unwrap());
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
}

async fn exchange(stream: &mut DuplexStream, expected: &[u8]) {
    stream.write_all(expected).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, expected);
}

#[tokio::test]
async fn stalled_member_dial_and_cancellation_do_not_block_other_member() {
    let mut remote = common::fixture("h2", "127.0.0.1", 2).await;
    let gate = Arc::new(Gate::default());
    let outbound =
        kerlico_naive::NaiveFactory::compile_with_connector(&remote.options, gate.clone())
            .unwrap()
            .start(ServiceContext::for_test())
            .await
            .unwrap();
    let input = NodeBuildContext::for_test(
        json!({}),
        vec![
            json!({"username":"member-a","password":"synthetic-secret"}),
            json!({"username":"member-b","password":"synthetic-secret"}),
        ],
    );
    let node = kerlico_http::HttpNodeFactory.build(&input).unwrap();
    let ingress =
        kerlico_egress::testing::ingress(&input, outbound.clone(), TargetPolicy::Remote).unwrap();
    let runtime_owner = ingress.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
    let echo = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    });
    let quota = Arc::new(Semaphore::new(64));
    let cancel_a = CancellationToken::new();
    let cancel_b = CancellationToken::new();
    let (mut client_a, server_a) = tokio::io::duplex(8192);
    let (mut client_b, server_b) = tokio::io::duplex(8192);
    let task_a = {
        let node = node.clone();
        let ingress = ingress.clone();
        let context = inbound(cancel_a.clone(), quota.clone());
        tokio::spawn(async move { node.handle(Box::new(server_a), ingress, context).await })
    };
    let task_b = {
        let context = inbound(cancel_b.clone(), quota);
        tokio::spawn(async move { node.handle(Box::new(server_b), ingress, context).await })
    };
    request(&mut client_a, &target, "member-a").await;
    tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    request(&mut client_b, &target, "member-b").await;
    tokio::time::timeout(Duration::from_secs(2), accepted(&mut client_b))
        .await
        .unwrap();
    exchange(&mut client_b, b"before-cancel").await;
    assert!(
        !gate.first_dropped.load(Ordering::Acquire),
        "成员B必须在成员A仍挂起时完成转发"
    );
    assert_eq!(gate.attempts.load(Ordering::Acquire), 2);
    {
        let scopes = gate.scopes.lock().unwrap();
        assert_ne!(scopes[0], scopes[1]);
    }
    cancel_a.cancel();
    tokio::time::timeout(Duration::from_secs(2), gate.released.notified())
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), task_a)
        .await
        .unwrap()
        .unwrap();
    assert!(!cancel_b.is_cancelled());
    exchange(&mut client_b, b"after-cancel").await;
    cancel_b.cancel();
    drop(client_a);
    drop(client_b);
    let _ = tokio::time::timeout(Duration::from_secs(2), task_b)
        .await
        .unwrap()
        .unwrap();
    outbound.shutdown().await.unwrap();
    drop(runtime_owner);
    remote.stop().await;
    tokio::time::timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
}
