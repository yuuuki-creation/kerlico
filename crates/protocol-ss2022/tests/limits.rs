mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramChannel, Destination, Error,
    InboundContext, NodeEvent, NodeObserver, Outbound, Result, StreamBudget,
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Semaphore};

struct DenyTarget(AtomicUsize);
impl Outbound for DenyTarget {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        kerlico_core::Capabilities {
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
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(Error::Rejected)
        })
    }
}
#[derive(Default)]
struct Counts {
    accepted: AtomicUsize,
    completed: AtomicUsize,
    dropped: AtomicUsize,
}
impl NodeObserver for Counts {
    fn record(&self, event: NodeEvent) {
        match event {
            NodeEvent::Accepted => {
                self.accepted.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Completed => {
                self.completed.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Dropped => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

#[tokio::test]
async fn udp_budget_denial_and_cancel_release_resources() {
    let method = "2022-blake3-aes-128-gcm";
    let key = STANDARD.encode([7; 16]);
    let node = support::node(
        &kerlico_ss2022::Ss2022NodeFactory,
        &json!({"method":method,"key":key}),
    )
    .unwrap();
    assert!(node.supports_udp());
    assert!(!node.requires_loopback());
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let port = socket.local_addr().unwrap().port();
    let global = Arc::new(Semaphore::new(1));
    let slots = Arc::new(Semaphore::new(1));
    let counts = Arc::new(Counts::default());
    let cancel = CancellationToken::new();
    let access = Arc::new(DenyTarget(AtomicUsize::new(0)));
    let context = InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        peer_addr: None,
        local_addr: None,
        cancel: cancel.clone(),
        connect_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(1),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65000,
        max_streams: 1,
        stream_budget: StreamBudget::new(global.clone(), slots.clone()),
        events: counts.clone(),
    };
    let task = {
        let access = access.clone();
        tokio::spawn(async move { node.serve_udp(socket, access, context).await })
    };
    let outbound = support::outbound(
        &kerlico_ss2022::Ss2022Factory,
        &json!({"server":"127.0.0.1","port":port,"method":method,"key":key}),
    )
    .unwrap();
    let target = Destination::new("example.invalid", 53).unwrap();
    let connect = ConnectContext::new(Duration::from_secs(1));
    let mut channel = outbound.connect_udp(&target, &connect).await.unwrap();
    channel.sender.send(b"budget").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), channel.receiver.recv())
            .await
            .is_err()
    );
    assert_eq!(counts.accepted.load(Ordering::Relaxed), 1);
    assert_eq!(counts.dropped.load(Ordering::Relaxed), 1);
    assert_eq!(access.0.load(Ordering::Relaxed), 0);
    assert_eq!(global.available_permits(), 0);
    cancel.cancel();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(global.available_permits(), 1);
    assert_eq!(slots.available_permits(), 1);
    assert_eq!(counts.completed.load(Ordering::Relaxed), 1);
}
