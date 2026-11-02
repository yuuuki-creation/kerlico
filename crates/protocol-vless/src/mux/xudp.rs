//! 非零 Global ID 的 UDP 会话独立于物理载体；新载体用同一 ID 发 NEW 时接回原出口。
//!
//! 行为对应 Xray common/mux/server.go 的 handleStatusNew 与 common/mux/session.go 的
//! XUDPManager。Xray 按进程共用一张表；这里按节点分表并把用户标识放进键，避免其他成员接管。

use super::completion::{Completions, Scope, outcome};
use super::frame::Frame;
use super::server::{Delivery, SessionContext, udp_session};
use kerlico_core::{
    CancellationToken, FlowOutcome, InboundContext, PeerSession, Result, StreamLease,
};
use std::{
    collections::HashMap,
    future::{Future, pending},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};
use xray_routing::Target;

type Key = ([u8; 16], [u8; 8]);

struct Entry {
    uplink: mpsc::Sender<Frame>,
    link: watch::Sender<Option<Attachment>>,
    cancel: CancellationToken,
    attached_at: Instant,
    _lease: StreamLease,
}
impl Entry {
    fn detached(&self) -> bool {
        self.link
            .borrow()
            .as_ref()
            .is_none_or(|link| link.released.is_cancelled())
    }
}

pub(crate) struct Table {
    sessions: Mutex<HashMap<Key, Entry>>,
    grace: Duration,
}
impl Table {
    pub fn new(grace: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            grace,
        }
    }
    /// 只移除仍属于该会话的条目；被回收后同键可能已是新会话。
    fn remove(&self, key: &Key, uplink: &mpsc::Sender<Frame>) -> Option<Entry> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if sessions.get(key)?.uplink.same_channel(uplink) {
            sessions.remove(key)
        } else {
            None
        }
    }
}

/// 会话当前的回包去向。`released` 取消后回包丢弃，直到新载体接回或宽限期结束。
#[derive(Clone)]
pub(super) struct Attachment {
    pub id: u16,
    pub output: mpsc::Sender<Delivery>,
    pub released: CancellationToken,
}

/// 单个已认证载体创建或接回 XUDP 会话所需的节点级能力。
pub(crate) struct Migration {
    pub table: Arc<Table>,
    pub user: [u8; 16],
    pub access: PeerSession,
    pub context: InboundContext,
}
impl Migration {
    /// 返回会话上行队列。命中已有会话时立即摘下旧载体，与 Xray 的 XUDP hit 一致。
    pub(super) fn attach(
        &self,
        global_id: [u8; 8],
        attachment: Attachment,
        initial: &Target,
    ) -> Result<mpsc::Sender<Frame>> {
        let key = (self.user, global_id);
        let mut sessions = self
            .table
            .sessions
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(entry) = sessions.get_mut(&key) {
            entry.attached_at = Instant::now();
            if let Some(previous) = entry.link.send_replace(Some(attachment)) {
                previous.released.cancel();
            }
            return Ok(entry.uplink.clone());
        }
        let lease = match self.context.stream_budget.try_acquire() {
            Ok(lease) => lease,
            Err(error) => {
                // 等待接回的会话不能挤占在用载体：配额耗尽时回收最早的一条。
                let oldest = sessions
                    .iter()
                    .filter(|(_, entry)| entry.detached())
                    .min_by_key(|(_, entry)| entry.attached_at)
                    .map(|(key, _)| *key)
                    .ok_or(error)?;
                if let Some(entry) = sessions.remove(&oldest) {
                    entry.cancel.cancel();
                }
                self.context.stream_budget.try_acquire()?
            }
        };
        let (uplink, incoming) = mpsc::channel(32);
        let (link, links) = watch::channel(Some(attachment));
        let (output, responses) = mpsc::channel(32);
        let mut context = self.context.clone();
        let cancel = self.context.cancel.child_token();
        let session_cancel = cancel.clone();
        context.cancel = cancel.clone();
        let access = self.access.clone();
        let table = self.table.clone();
        let initial = initial.clone();
        let own = uplink.clone();
        self.context.tasks.spawn(async move {
            let grace = table.grace;
            let scope_key = Scope(0, 0);
            let completions = Completions::new(context.max_streams);
            let result = match completions.scope(scope_key) {
                Ok(()) => {
                    let serving = udp_session(
                        initial,
                        incoming,
                        SessionContext {
                            scope_key,
                            output,
                            access,
                            context,
                            completions: completions.clone(),
                        },
                    );
                    relay(serving, links, responses, grace, &completions, cancel).await
                }
                Err(error) => Err(error),
            };
            completions.close(outcome(&result));
            let last = table
                .remove(&key, &own)
                .and_then(|entry| entry.link.borrow().clone());
            if let Some(last) = last {
                tokio::select! {
                    _ = last.released.cancelled() => {}
                    _ = last.output.send(Delivery::signal(Frame::end(last.id, result.is_err()))) => {}
                }
                last.released.cancel();
            }
        })?;
        sessions.insert(
            key,
            Entry {
                uplink: uplink.clone(),
                link,
                cancel: session_cancel,
                attached_at: Instant::now(),
                _lease: lease,
            },
        );
        Ok(uplink)
    }
}

async fn relay(
    serving: impl Future<Output = Result<()>>,
    mut links: watch::Receiver<Option<Attachment>>,
    mut responses: mpsc::Receiver<Delivery>,
    grace: Duration,
    completions: &Completions,
    cancel: CancellationToken,
) -> Result<()> {
    tokio::pin!(serving);
    let forwarding = async {
        let mut attached = links.borrow_and_update().clone();
        let expiry = tokio::time::sleep(grace);
        tokio::pin!(expiry);
        loop {
            let released = attached.as_ref().map(|link| link.released.clone());
            tokio::select! {
                biased;
                Ok(()) = links.changed() => attached = links.borrow_and_update().clone(),
                _ = async {
                    match &released {
                        Some(token) => token.cancelled().await,
                        None => pending().await,
                    }
                } => {
                    attached = None;
                    expiry.as_mut().reset(Instant::now() + grace);
                }
                _ = &mut expiry, if attached.is_none() => return,
                Some(delivery) = responses.recv() => {
                    let Delivery { mut frame, receipt } = delivery;
                    if let Some(link) = &attached {
                        frame.id = link.id;
                        tokio::select! {
                            biased;
                            _ = link.released.cancelled() => {}
                            _ = link.output.send(Delivery { frame, receipt: None }) => {}
                        }
                    }
                    // 载体失败只丢这一个数据报，出口流继续等新载体接回。
                    if let Some(receipt) = receipt {
                        let _ = receipt.send(Ok(()));
                    }
                }
            }
        }
    };
    tokio::select! {
        biased;
        result = &mut serving => result,
        () = forwarding => {
            completions.close(FlowOutcome::ProtocolEnd);
            cancel.cancel();
            serving.await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::frame;
    use super::*;
    use crate::carrier;
    use kerlico_config::NodeBuildContext;
    use kerlico_core::{
        BoxFuture, Capabilities, ConnectContext, DatagramChannel, DatagramReceiver, DatagramSender,
        Destination, Error, FamilyMode, NodeEvent, NodeId, NodeObserver, NodeTasks, OpenedTcp,
        Outbound, StreamBudget, TargetPolicy,
    };
    use kerlico_egress::Telemetry;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncWriteExt, DuplexStream};
    use xray_proxy::mux::Status;

    struct Observer;
    impl NodeObserver for Observer {
        fn record(&self, _: NodeEvent) {}
    }
    struct NoDns;
    impl kerlico_egress::Resolver for NoDns {
        fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
            Box::pin(async { Err(Error::Unsupported("此回归不解析域名")) })
        }
    }
    /// 每次 connect_udp 代表一个真实出口映射；测试从这里观察上行并注入回包。
    #[derive(Default)]
    struct Egress {
        opened: AtomicUsize,
        flows: Mutex<Vec<EgressFlow>>,
    }
    struct EgressFlow {
        upload: mpsc::Receiver<Vec<u8>>,
        reply: mpsc::Sender<Vec<u8>>,
    }
    struct Upload(mpsc::Sender<Vec<u8>>);
    impl DatagramSender for Upload {
        fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.0
                    .send(packet.to_vec())
                    .await
                    .map_err(|_| Error::Cancelled)
            })
        }
    }
    struct Reply(mpsc::Receiver<Vec<u8>>);
    impl DatagramReceiver for Reply {
        fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
            Box::pin(async move { Ok(self.0.recv().await) })
        }
    }
    impl Outbound for Egress {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                tcp: false,
                tcp_eof: false,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<OpenedTcp>> {
            Box::pin(async { Err(Error::Unsupported("此回归仅使用 UDP")) })
        }
        fn connect_udp<'a>(
            &'a self,
            _: &'a Destination,
            _: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async move {
                self.opened.fetch_add(1, Ordering::SeqCst);
                let (upload_tx, upload) = mpsc::channel(8);
                let (reply, reply_rx) = mpsc::channel(8);
                self.flows
                    .lock()
                    .unwrap()
                    .push(EgressFlow { upload, reply });
                Ok(DatagramChannel {
                    sender: Box::new(Upload(upload_tx)),
                    receiver: Box::new(Reply(reply_rx)),
                })
            })
        }
    }
    struct Fixture {
        budget: StreamBudget,
        egress: Arc<Egress>,
        telemetry: Telemetry,
        ingress: kerlico_core::IngressBinding,
        table: Arc<Table>,
        tasks: NodeTasks,
        node: CancellationToken,
    }
    impl Fixture {
        fn new(grace: Duration) -> Self {
            Self::with_quota(grace, 8)
        }
        fn with_quota(grace: Duration, quota: usize) -> Self {
            let egress = Arc::new(Egress::default());
            let input = NodeBuildContext::local_for_test(serde_json::json!({}));
            let (ingress, telemetry) = kerlico_egress::testing::ingress_with_resolver(
                &input,
                egress.clone(),
                TargetPolicy::Remote,
                FamilyMode::DualV4Preferred,
                Arc::new(NoDns),
            )
            .unwrap();
            let node = CancellationToken::new();
            Self {
                budget: StreamBudget::new(
                    Arc::new(tokio::sync::Semaphore::new(quota)),
                    Arc::new(tokio::sync::Semaphore::new(quota)),
                ),
                egress,
                telemetry,
                ingress,
                table: Arc::new(Table::new(grace)),
                tasks: NodeTasks::new(NodeId::parse("xudp-test").unwrap(), node.clone()),
                node,
            }
        }
        fn context(&self, cancel: CancellationToken) -> InboundContext {
            InboundContext {
                peer_lease: None,
                tasks: self.tasks.clone(),
                cancel,
                peer_addr: None,
                local_addr: Some("127.0.0.1:1".parse().unwrap()),
                connect_timeout: Duration::from_secs(2),
                idle_timeout: Duration::from_secs(10),
                drain_timeout: Duration::from_secs(1),
                max_datagram_size: 65535,
                max_streams: 8,
                events: Arc::new(Observer),
                stream_budget: self.budget.clone(),
            }
        }
        /// 一条独立物理载体：断开客户端一侧即载体中断。
        fn carrier(&self, user: [u8; 16]) -> (DuplexStream, tokio::task::JoinHandle<Result<()>>) {
            let (server, client) = tokio::io::duplex(8192);
            let cancel = self.node.child_token();
            let context = self.context(cancel);
            let peer = self.ingress.local(&context).unwrap();
            let mut detached = context.clone();
            detached.cancel = self.node.child_token();
            let migration = Migration {
                table: self.table.clone(),
                user,
                access: self.ingress.local(&detached).unwrap(),
                context: detached,
            };
            let serving = tokio::spawn(super::super::server::serve(
                Box::new(server),
                peer,
                context,
                false,
                migration,
            ));
            (client, serving)
        }
        async fn next_upload(&self, flow: usize) -> Vec<u8> {
            self.wait_opened(flow + 1).await;
            let mut upload = {
                let mut flows = self.egress.flows.lock().unwrap();
                let (_, replacement) = mpsc::channel(1);
                std::mem::replace(&mut flows[flow].upload, replacement)
            };
            let packet = tokio::time::timeout(Duration::from_secs(2), upload.recv())
                .await
                .unwrap()
                .unwrap();
            self.egress.flows.lock().unwrap()[flow].upload = upload;
            packet
        }
        async fn wait_opened(&self, count: usize) {
            tokio::time::timeout(Duration::from_secs(2), async {
                while self.egress.flows.lock().unwrap().len() < count {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        }
        fn reply(&self, flow: usize) -> mpsc::Sender<Vec<u8>> {
            self.egress.flows.lock().unwrap()[flow].reply.clone()
        }
    }
    fn target() -> Target {
        carrier::target(&Destination::new("192.0.2.1", 53).unwrap(), true)
    }
    async fn open(client: &mut DuplexStream, id: u16, global_id: [u8; 8], payload: &[u8]) {
        frame::write(
            client,
            Frame {
                id,
                status: Status::New,
                error: false,
                target: Some(target()),
                global_id: Some(global_id),
                payload: Some(payload.to_vec()),
            },
        )
        .await
        .unwrap();
    }
    async fn next_frame(client: &mut DuplexStream) -> Frame {
        tokio::time::timeout(Duration::from_secs(2), frame::read(client))
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn new_carrier_with_same_id_keeps_the_egress_flow() {
        let fixture = Fixture::new(Duration::from_secs(5));
        let (mut first, first_serving) = fixture.carrier([1; 16]);
        open(&mut first, 1, [9; 8], b"before").await;
        assert_eq!(fixture.next_upload(0).await, b"before");
        fixture.reply(0).send(b"reply-1".to_vec()).await.unwrap();
        let reply = next_frame(&mut first).await;
        assert_eq!(
            (reply.id, reply.payload.as_deref()),
            (1, Some(&b"reply-1"[..]))
        );

        first.shutdown().await.unwrap();
        drop(first);
        first_serving.await.unwrap().ok();

        let (mut second, _second_serving) = fixture.carrier([1; 16]);
        open(&mut second, 7, [9; 8], b"after").await;
        assert_eq!(fixture.next_upload(0).await, b"after");
        assert_eq!(fixture.egress.opened.load(Ordering::SeqCst), 1);
        fixture.reply(0).send(b"reply-2".to_vec()).await.unwrap();
        let reply = next_frame(&mut second).await;
        assert_eq!(
            (reply.id, reply.payload.as_deref()),
            (7, Some(&b"reply-2"[..]))
        );
        fixture.node.cancel();
    }

    #[tokio::test]
    async fn takeover_ends_the_old_carrier_session() {
        let fixture = Fixture::new(Duration::from_secs(5));
        let (mut first, _first_serving) = fixture.carrier([1; 16]);
        open(&mut first, 1, [9; 8], b"one").await;
        assert_eq!(fixture.next_upload(0).await, b"one");
        let (mut second, _second_serving) = fixture.carrier([1; 16]);
        open(&mut second, 2, [9; 8], b"two").await;
        assert_eq!(fixture.next_upload(0).await, b"two");

        tokio::time::sleep(Duration::from_millis(50)).await;
        frame::write(
            &mut first,
            Frame::data(1, b"stale".to_vec(), Some(target())),
        )
        .await
        .unwrap();
        let ended = next_frame(&mut first).await;
        assert_eq!((ended.id, ended.status), (1, Status::End));
        fixture.node.cancel();
    }

    #[tokio::test]
    async fn another_member_cannot_take_over_the_same_id() {
        let fixture = Fixture::new(Duration::from_secs(5));
        let (mut first, _first_serving) = fixture.carrier([1; 16]);
        open(&mut first, 1, [9; 8], b"mine").await;
        assert_eq!(fixture.next_upload(0).await, b"mine");
        let (mut other, _other_serving) = fixture.carrier([2; 16]);
        open(&mut other, 1, [9; 8], b"theirs").await;
        fixture.wait_opened(2).await;
        assert_eq!(fixture.next_upload(1).await, b"theirs");
        fixture.reply(0).send(b"still-mine".to_vec()).await.unwrap();
        let reply = next_frame(&mut first).await;
        assert_eq!(reply.payload.as_deref(), Some(&b"still-mine"[..]));
        fixture.node.cancel();
    }

    #[tokio::test]
    async fn exhausted_quota_reclaims_detached_but_not_attached_sessions() {
        let fixture = Fixture::with_quota(Duration::from_secs(30), 1);
        let (mut first, first_serving) = fixture.carrier([1; 16]);
        open(&mut first, 1, [1; 8], b"first").await;
        assert_eq!(fixture.next_upload(0).await, b"first");

        let (mut refused, _refused_serving) = fixture.carrier([1; 16]);
        open(&mut refused, 1, [2; 8], b"refused").await;
        let ended = next_frame(&mut refused).await;
        assert_eq!((ended.status, ended.error), (Status::End, true));
        assert_eq!(fixture.egress.opened.load(Ordering::SeqCst), 1);

        first.shutdown().await.unwrap();
        drop(first);
        first_serving.await.unwrap().ok();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !fixture
                .table
                .sessions
                .lock()
                .unwrap()
                .values()
                .all(Entry::detached)
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        let (mut next, _next_serving) = fixture.carrier([1; 16]);
        open(&mut next, 1, [3; 8], b"next").await;
        assert_eq!(fixture.next_upload(1).await, b"next");
        fixture.node.cancel();
    }

    #[tokio::test]
    async fn detached_session_ends_after_grace_and_releases_the_flow() {
        let fixture = Fixture::new(Duration::from_millis(50));
        let (mut first, first_serving) = fixture.carrier([1; 16]);
        open(&mut first, 1, [9; 8], b"before").await;
        assert_eq!(fixture.next_upload(0).await, b"before");
        first.shutdown().await.unwrap();
        drop(first);
        first_serving.await.unwrap().ok();
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.telemetry.usage().unwrap().active_flows != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(fixture.table.sessions.lock().unwrap().is_empty());

        let (mut second, _second_serving) = fixture.carrier([1; 16]);
        open(&mut second, 1, [9; 8], b"after").await;
        fixture.wait_opened(2).await;
        fixture.node.cancel();
    }
}
