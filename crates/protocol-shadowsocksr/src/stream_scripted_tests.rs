#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;
use super::*;
use kerlico_core::{
    BoxFuture, ConnectContext, DatagramChannel, Destination, Error, InboundContext, NodeEvent,
    NodeObserver, Outbound, StreamBudget,
};
use serde_json::{Value, json};
use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Waker,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};

// 输入脚本区分真实EOF、一次Pending和等待外部事件，不能用空读冒充Pending。
enum ReadStep {
    Data(Vec<u8>),
    Pending,
    AfterShutdown(Vec<u8>),
    Eof,
}
enum WriteStep {
    Limit(usize),
    Pending,
    Blocked,
}
#[derive(Clone, Copy)]
enum FlushStep {
    Pending,
    Blocked,
}
struct Script {
    reads: VecDeque<ReadStep>,
    writes: VecDeque<WriteStep>,
    flushes: VecDeque<FlushStep>,
    sent: Vec<u8>,
    events: Vec<Value>,
    shutdown: bool,
    wake: Option<Waker>,
}
#[derive(Clone)]
struct Trace(Arc<Mutex<Script>>);
impl Trace {
    fn new(reads: Vec<ReadStep>) -> Self {
        Self(Arc::new(Mutex::new(Script {
            reads: reads.into(),
            writes: VecDeque::new(),
            flushes: VecDeque::new(),
            sent: Vec::new(),
            events: Vec::new(),
            shutdown: false,
            wake: None,
        })))
    }
    fn sent(&self) -> Vec<u8> {
        self.0.lock().unwrap().sent.clone()
    }
    fn has(&self, operation: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|event| event["op"] == operation)
    }
    fn add_reads(&self, reads: Vec<ReadStep>) {
        let mut script = self.0.lock().unwrap();
        script.reads.extend(reads);
        if let Some(wake) = script.wake.take() {
            wake.wake();
        }
    }
    fn short_writes(&self) {
        self.0.lock().unwrap().writes = [
            WriteStep::Limit(1),
            WriteStep::Pending,
            WriteStep::Limit(1),
            WriteStep::Pending,
            WriteStep::Limit(2),
            WriteStep::Pending,
            WriteStep::Limit(7),
            WriteStep::Pending,
            WriteStep::Limit(12),
            WriteStep::Pending,
            WriteStep::Limit(31),
            WriteStep::Pending,
            WriteStep::Limit(36),
            WriteStep::Pending,
        ]
        .into();
        self.0.lock().unwrap().flushes = [FlushStep::Pending].into();
    }
    fn save(&self, name: &str) -> io::Result<()> {
        let Ok(root) = std::env::var("KERLICO_SSR_TRACE_DIR") else {
            return Ok(());
        };
        let root = std::path::Path::new(&root);
        std::fs::create_dir_all(root)?;
        let script = self
            .0
            .lock()
            .map_err(|_| io::Error::other("脚本流记录锁已损坏"))?;
        let value = json!({"events":&script.events,"sent":&script.sent});
        std::fs::write(
            root.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&value).map_err(io::Error::other)?,
        )
    }
}
struct ScriptedRaw {
    trace: Trace,
    name: String,
}
impl ScriptedRaw {
    fn boxed(trace: &Trace, name: &str) -> BoxStream {
        Box::new(Self {
            trace: trace.clone(),
            name: name.to_owned(),
        })
    }
}
impl Drop for ScriptedRaw {
    fn drop(&mut self) {
        if let Ok(mut script) = self.trace.0.lock() {
            script.events.push(json!({"op":"drop"}));
        }
        let _ = self.trace.save(&self.name);
    }
}
impl AsyncRead for ScriptedRaw {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut script = self.trace.0.lock().unwrap();
        script.wake = Some(cx.waker().clone());
        let Some(step) = script.reads.pop_front() else {
            script.events.push(json!({"op":"read_wait"}));
            return Poll::Pending;
        };
        let bytes = match step {
            ReadStep::Data(bytes) => bytes,
            ReadStep::AfterShutdown(bytes) => {
                if !script.shutdown {
                    script.reads.push_front(ReadStep::AfterShutdown(bytes));
                    script.events.push(json!({"op":"read_wait_shutdown"}));
                    return Poll::Pending;
                }
                bytes
            }
            ReadStep::Pending => {
                script.events.push(json!({"op":"read_pending"}));
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            ReadStep::Eof => {
                script.reads.push_front(ReadStep::Eof);
                script.events.push(json!({"op":"read_eof"}));
                return Poll::Ready(Ok(()));
            }
        };
        assert!(!bytes.is_empty());
        let count = output.remaining().min(bytes.len());
        output.put_slice(&bytes[..count]);
        script
            .events
            .push(json!({"op":"read","bytes":&bytes[..count]}));
        if count < bytes.len() {
            script
                .reads
                .push_front(ReadStep::Data(bytes[count..].to_vec()));
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ScriptedRaw {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut script = self.trace.0.lock().unwrap();
        script.wake = Some(cx.waker().clone());
        if script.shutdown {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let count = match script.writes.pop_front() {
            Some(WriteStep::Limit(limit)) => bytes.len().min(limit),
            Some(WriteStep::Pending) => {
                script.events.push(json!({"op":"write_pending"}));
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Some(WriteStep::Blocked) => {
                script.writes.push_front(WriteStep::Blocked);
                script.events.push(json!({"op":"write_blocked"}));
                return Poll::Pending;
            }
            None => bytes.len(),
        };
        script.sent.extend_from_slice(&bytes[..count]);
        script
            .events
            .push(json!({"op":"write","offered":bytes.len(),"bytes":&bytes[..count]}));
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut script = self.trace.0.lock().unwrap();
        script.wake = Some(cx.waker().clone());
        match script.flushes.pop_front() {
            Some(FlushStep::Pending) => {
                script.events.push(json!({"op":"flush_pending"}));
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(FlushStep::Blocked) => {
                script.flushes.push_front(FlushStep::Blocked);
                script.events.push(json!({"op":"flush_blocked"}));
                Poll::Pending
            }
            None => {
                script.events.push(json!({"op":"flush"}));
                Poll::Ready(Ok(()))
            }
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut script = self.trace.0.lock().unwrap();
        script.shutdown = true;
        script.events.push(json!({"op":"shutdown"}));
        cx.waker().wake_by_ref();
        Poll::Ready(Ok(()))
    }
}

fn options(method: &str, protocol: &str, obfs: &str) -> Value {
    json!({"method":method,"password":"synthetic-script-base","protocol":protocol,"obfs":obfs,"udp":false,"allow_insecure":true})
}
fn configs(method: &str, protocol: &str, obfs: &str) -> (Arc<Shared>, Value) {
    let mut node = options(method, protocol, obfs);
    node["users"] = json!([{"id":7,"password":"synthetic-script-user"}]);
    let mut client = options(method, protocol, obfs);
    client["server"] = json!({"host":"127.0.0.1","port":1});
    client["user"] = json!({"id":7,"password":"synthetic-script-user"});
    (Shared::client(&client).unwrap().0, node)
}
fn random_head() -> Vec<u8> {
    let mut head = b"synthetic-random-head".to_vec();
    head.extend_from_slice(&(u32::MAX - crc32fast::hash(&head)).to_le_bytes());
    head
}
struct Flight {
    cfg: Arc<Shared>,
    codec: Codec,
    iv: Vec<u8>,
    encoded: Vec<u8>,
}
impl Flight {
    fn new(cfg: Arc<Shared>, data: &[u8], corrupt: bool) -> Self {
        let iv = vec![0x42; cfg.method.iv_len()];
        let mut codec = Codec::new(cfg.clone(), Role::Client, iv.clone());
        let mut encoded = codec.encode(data, crate::now()).unwrap();
        if corrupt {
            let index = if cfg.protocol.chain() { 4 } else { 1 };
            encoded[index] ^= 0x80;
        }
        Self {
            cfg,
            codec,
            iv,
            encoded,
        }
    }
    fn cipher(&self) -> Vec<u8> {
        let mut bytes = self.encoded.clone();
        State::new(self.cfg.method, &self.cfg.key, &self.iv)
            .unwrap()
            .apply(&mut bytes, true)
            .unwrap();
        bytes
    }
    fn reads(&self, eof: bool) -> Vec<ReadStep> {
        let mut reads = Vec::new();
        if self.cfg.obfs == crate::config::Obfs::Random {
            let head = random_head();
            reads.extend([
                ReadStep::Data(head[..7].to_vec()),
                ReadStep::Pending,
                ReadStep::Data(head[7..].to_vec()),
                ReadStep::Pending,
            ]);
        }
        if !self.iv.is_empty() {
            reads.extend([
                ReadStep::Data(self.iv[..7].to_vec()),
                ReadStep::Pending,
                ReadStep::Data(self.iv[7..].to_vec()),
                ReadStep::Pending,
            ]);
        }
        let cipher = self.cipher();
        let mut start = 0;
        for end in [7, 12, 31, 36, 37, cipher.len()] {
            let end = end.min(cipher.len());
            if end > start {
                reads.extend([
                    ReadStep::Data(cipher[start..end].to_vec()),
                    ReadStep::Pending,
                ]);
                start = end;
            }
        }
        if eof {
            reads.push(ReadStep::Eof)
        }
        reads
    }
    fn decode_response(&mut self, wire: &[u8]) -> Vec<u8> {
        let wire = if self.cfg.obfs == crate::config::Obfs::Random {
            assert!(wire.len() > 4 + self.iv.len());
            &wire[4..]
        } else {
            wire
        };
        let length = self.cfg.method.iv_len();
        let iv = &wire[..length];
        assert_ne!(iv, self.iv.as_slice(), "独立方向不得沿用客户端固定IV");
        let mut plain = wire[length..].to_vec();
        State::new(self.cfg.method, &self.cfg.key, iv)
            .unwrap()
            .apply(&mut plain, false)
            .unwrap();
        let mut decoded = Vec::new();
        for chunk in plain.chunks(19) {
            decoded.extend(self.codec.feed(chunk, iv, crate::now()).unwrap().data);
        }
        assert!(self.codec.finished());
        decoded
    }
}
#[derive(Default)]
struct Events;
impl NodeObserver for Events {
    fn record(&self, _: NodeEvent) {}
}
fn context(cancel: CancellationToken) -> InboundContext {
    InboundContext {
        peer_lease: None,
        tasks: kerlico_core::NodeTasks::new(
            kerlico_core::NodeId::parse("test-node").unwrap(),
            kerlico_core::CancellationToken::new(),
        ),
        cancel,
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65000,
        max_streams: 4,
        stream_budget: StreamBudget::new(Arc::new(Semaphore::new(4)), Arc::new(Semaphore::new(4))),
        events: Arc::new(Events),
        local_addr: Some("127.0.0.1:1".parse().unwrap()),
        peer_addr: Some("127.0.0.1:2".parse().unwrap()),
    }
}
struct Target {
    requests: Mutex<Vec<Destination>>,
    raw: Trace,
}
impl Outbound for Target {
    fn capabilities(&self) -> kerlico_core::Capabilities {
        kerlico_core::Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            self.requests.lock().unwrap().push(target.clone());
            let stream = ScriptedRaw::boxed(&self.raw, "target");
            Ok(kerlico_core::OpenedTcp {
                stream,
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("此回归仅验证TCP")) })
    }
}
fn target() -> Arc<Target> {
    Arc::new(Target {
        requests: Mutex::new(Vec::new()),
        raw: Trace::new(vec![
            ReadStep::Data(b"target-banner|".to_vec()),
            ReadStep::AfterShutdown(b"reverse-after-fin|".to_vec()),
            ReadStep::Eof,
        ]),
    })
}
fn request() -> Vec<u8> {
    let mut bytes = vec![1, 127, 0, 0, 1, 1, 187];
    bytes.extend_from_slice(b"client-first|");
    bytes
}

#[tokio::test]
async fn scripted_random_head_preserves_wire_order_and_half_close() {
    for method in ["aes-128-cfb", "chacha20-ietf"] {
        for protocol in ["auth_aes128_md5", "auth_chain_a", "auth_chain_b"] {
            let (cfg, node_options) = configs(method, protocol, "random_head");
            let mut flight = Flight::new(cfg, &request(), false);
            flight
                .encoded
                .extend(flight.codec.encode(b"tail-frame|", crate::now()).unwrap());
            flight
                .encoded
                .extend(flight.codec.encode(&[], crate::now()).unwrap());
            let trace = Trace::new(flight.reads(true));
            trace.short_writes();
            let access = target();
            let node = support::node(&crate::ShadowsocksRNodeFactory, &node_options).unwrap();
            let name = format!("ordered-{method}-{protocol}");
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                node.handle(
                    ScriptedRaw::boxed(&trace, &name),
                    access.clone(),
                    context(CancellationToken::new()),
                ),
            )
            .await;
            trace.save(&name).unwrap();
            result.unwrap().unwrap();
            assert_eq!(
                *access.requests.lock().unwrap(),
                vec![Destination::new("127.0.0.1", 443).unwrap()]
            );
            assert_eq!(access.raw.sent(), b"client-first|tail-frame|");
            assert_eq!(
                flight.decode_response(&trace.sent()),
                b"target-banner|reverse-after-fin|"
            );
            for event in [
                "read_pending",
                "write_pending",
                "flush_pending",
                "read_eof",
                "shutdown",
                "drop",
            ] {
                assert!(trace.has(event), "{method} {protocol} 缺少事件 {event}");
            }
            assert!(access.raw.has("shutdown"));
        }
    }
}

#[tokio::test]
async fn scripted_client_shutdown_sends_tail_then_reads_reverse_data() {
    for protocol in ["auth_aes128_md5", "auth_chain_a", "auth_chain_b"] {
        let (cfg, node_options) = configs("aes-128-cfb", protocol, "random_head");
        let trace = Trace::new(Vec::new());
        trace.short_writes();
        let mut stream = Stream::new(
            ScriptedRaw::boxed(&trace, &format!("client-fin-{protocol}")),
            cfg,
            Role::Client,
            CancellationToken::new(),
            "127.0.0.1".into(),
            1,
        )
        .unwrap();
        stream.write_all(&request()).await.unwrap();
        let wake = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&wake);
        // 在随机头回写到达前，flush必须等待握手；已发送的首段只含随机头。
        for _ in 0..128 {
            if trace.has("flush") {
                break;
            }
            assert!(Pin::new(&mut stream).poll_flush(&mut cx).is_pending());
        }
        assert!(trace.has("flush"));
        let first = trace.sent();
        assert_eq!(crc32fast::hash(&first), u32::MAX);
        trace.add_reads(vec![ReadStep::Data(vec![0x11; 4]), ReadStep::Pending]);
        tokio::time::timeout(Duration::from_secs(2), stream.flush())
            .await
            .unwrap()
            .unwrap();
        let sent = trace.sent();
        let server = Shared::node(&node_options).unwrap();
        let server_iv = vec![0x24; server.method.iv_len()];
        let mut reader = Reader {
            cfg: server.clone(),
            state: None,
            pending: Vec::new(),
            iv: Vec::new(),
        };
        let mut peer = Codec::new(server.clone(), Role::Server, server_iv.clone());
        let cipher = reader.decode(&sent[first.len()..]).unwrap();
        let decoded = peer.feed(&cipher, &reader.iv, crate::now()).unwrap();
        assert_eq!(decoded.data, request());
        let mut writer = Writer {
            method: server.method,
            state: State::new(server.method, &server.key, &server_iv).unwrap(),
            iv: server_iv,
            sent: false,
        };
        let banner = peer.encode(b"target-banner|", crate::now()).unwrap();
        let wire = writer.encode(&banner).unwrap();
        trace.add_reads(vec![
            ReadStep::Data(wire[..7].to_vec()),
            ReadStep::Pending,
            ReadStep::Data(wire[7..16].to_vec()),
            ReadStep::Pending,
            ReadStep::Data(wire[16..].to_vec()),
        ]);
        let mut received = vec![0; b"target-banner|".len()];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"target-banner|");
        stream.write_all(b"tail-frame|").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), stream.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(trace.has("shutdown"));
        let final_wire = trace.sent();
        let cipher = reader.decode(&final_wire[sent.len()..]).unwrap();
        let decoded = peer.feed(&cipher, &reader.iv, crate::now()).unwrap();
        assert_eq!(decoded.data, b"tail-frame|");
        assert!(peer.finished());
        let reverse = peer.encode(b"reverse-after-fin|", crate::now()).unwrap();
        let mut wire = writer.encode(&reverse).unwrap();
        let empty = peer.encode(&[], crate::now()).unwrap();
        wire.extend(writer.encode(&empty).unwrap());
        trace.add_reads(vec![ReadStep::Data(wire), ReadStep::Pending, ReadStep::Eof]);
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"reverse-after-fin|");
        assert!(stream.write_all(b"after-fin").await.is_err());
    }
}

#[tokio::test]
async fn scripted_bad_authentication_never_accesses_a_target() {
    for protocol in ["auth_aes128_md5", "auth_chain_a", "auth_chain_b"] {
        for mutation in ["header_mac", "base_key", "uid", "user_key"] {
            let (cfg, mut node_options) = configs("aes-128-cfb", protocol, "random_head");
            match mutation {
                "base_key" => node_options["password"] = json!("synthetic-wrong-base"),
                "uid" => node_options["users"][0]["id"] = json!(8),
                "user_key" => node_options["users"][0]["password"] = json!("synthetic-wrong-user"),
                _ => {}
            }
            let flight = Flight::new(cfg, &request(), mutation == "header_mac");
            let trace = Trace::new(flight.reads(true));
            trace.short_writes();
            let access = target();
            let node = support::node(&crate::ShadowsocksRNodeFactory, &node_options).unwrap();
            let name = format!("rejected-{protocol}-{mutation}");
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                node.handle(
                    ScriptedRaw::boxed(&trace, &name),
                    access.clone(),
                    context(CancellationToken::new()),
                ),
            )
            .await
            .unwrap();
            trace.save(&name).unwrap();
            assert!(result.is_err(), "{protocol} {mutation}");
            assert!(access.requests.lock().unwrap().is_empty());
            assert!(access.raw.sent().is_empty());
            assert!(trace.has("drop"));
        }
    }
}

#[tokio::test]
async fn scripted_truncated_iv_and_auth_headers_are_rejected() {
    for protocol in ["auth_aes128_md5", "auth_chain_a", "auth_chain_b"] {
        for cut in [
            7,
            16,
            16 + 6,
            16 + 7,
            16 + 11,
            16 + 12,
            16 + 30,
            16 + 31,
            16 + 35,
            16 + 36,
        ] {
            let (cfg, node_options) = configs("aes-128-cfb", protocol, "plain");
            let flight = Flight::new(cfg, &request(), false);
            let mut wire = flight.iv.clone();
            wire.extend(flight.cipher());
            let trace = Trace::new(vec![
                ReadStep::Data(wire[..cut].to_vec()),
                ReadStep::Pending,
                ReadStep::Eof,
            ]);
            let access = target();
            let node = support::node(&crate::ShadowsocksRNodeFactory, &node_options).unwrap();
            let name = format!("truncated-{protocol}-{cut}");
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                node.handle(
                    ScriptedRaw::boxed(&trace, &name),
                    access.clone(),
                    context(CancellationToken::new()),
                ),
            )
            .await
            .unwrap();
            assert!(result.is_err(), "{protocol} {cut}");
            assert!(access.requests.lock().unwrap().is_empty());
            assert!(trace.has("drop"));
        }
    }
}

#[test]
fn scripted_server_cancellation_closes_partial_input_and_pending_output() {
    for protocol in ["auth_aes128_md5", "auth_chain_a", "auth_chain_b"] {
        for phase in [
            "reply", "iv7", "iv16", "header7", "header12", "header31", "header35", "queue", "flush",
        ] {
            let (cfg, node_options) = configs("aes-128-cfb", protocol, "random_head");
            let flight = Flight::new(cfg, &request(), false);
            let mut wire = random_head();
            if !matches!(phase, "reply" | "flush") {
                let count = match phase {
                    "iv7" => 7,
                    "iv16" => 16,
                    "header7" => 23,
                    "header12" => 28,
                    "header31" => 47,
                    "header35" => 51,
                    _ => usize::MAX,
                };
                let mut cipher = flight.iv.clone();
                cipher.extend(flight.cipher());
                wire.extend_from_slice(&cipher[..count.min(cipher.len())]);
            }
            let trace = Trace::new(vec![ReadStep::Data(wire)]);
            if matches!(phase, "reply" | "queue") {
                trace.0.lock().unwrap().writes = [WriteStep::Limit(1), WriteStep::Blocked].into();
            }
            if phase == "flush" {
                trace.0.lock().unwrap().flushes = [FlushStep::Blocked].into();
            }
            let cancel = CancellationToken::new();
            let mut stream = Stream::new(
                ScriptedRaw::boxed(&trace, &format!("cancel-server-{protocol}-{phase}")),
                Shared::node(&node_options).unwrap(),
                Role::Server,
                cancel.clone(),
                String::new(),
                0,
            )
            .unwrap();
            let task = Arc::new(TaskWake::new());
            let output_wait = matches!(phase, "reply" | "queue" | "flush");
            let mut bytes = [0; 64];
            task.drain_wakes_until_pending(&format!("server-{protocol}-{phase}"), |cx| {
                if output_wait {
                    Pin::new(&mut stream).poll_flush(cx)
                } else {
                    Pin::new(&mut stream).poll_read(cx, &mut ReadBuf::new(&mut bytes))
                }
            });
            assert!(trace.has("read_wait"), "{protocol} {phase}");
            if matches!(phase, "reply" | "queue") {
                assert!(trace.has("write_blocked"), "{protocol} {phase}");
            }
            if phase == "flush" {
                assert!(trace.has("flush_blocked"), "{protocol} {phase}");
            }
            let before = trace.sent();
            let before_events = trace.0.lock().unwrap().events.len();
            let before_wake = task.count.load(Ordering::SeqCst);
            cancel.cancel();
            assert!(
                task.count.load(Ordering::SeqCst) > before_wake,
                "{protocol} {phase}"
            );
            assert!(matches!(
                task.poll(|cx| {
                    if output_wait {
                        Pin::new(&mut stream).poll_flush(cx)
                    } else {
                        Pin::new(&mut stream).poll_read(cx, &mut ReadBuf::new(&mut bytes))
                    }
                }),
                Poll::Ready(Err(_))
            ));
            let wake = futures_util::task::waker(task.clone());
            let mut cx = Context::from_waker(&wake);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes)),
                Poll::Ready(Err(_))
            ));
            assert!(trace.has("drop"));
            assert!(matches!(
                Pin::new(&mut stream).poll_write(&mut cx, b"after-cancel"),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_flush(&mut cx),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut stream).poll_shutdown(&mut cx),
                Poll::Ready(Err(_))
            ));
            assert_eq!(trace.sent(), before);
            assert_eq!(
                trace.0.lock().unwrap().events[before_events..],
                [json!({"op":"drop"})],
                "{protocol} {phase} 取消后不得继续底层I/O"
            );
        }
    }
}

struct TaskWake {
    scheduled: AtomicBool,
    count: AtomicUsize,
}
impl TaskWake {
    fn new() -> Self {
        Self {
            scheduled: AtomicBool::new(true),
            count: AtomicUsize::new(0),
        }
    }
    fn poll<T>(self: &Arc<Self>, poll: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> Poll<T> {
        assert!(
            self.scheduled.swap(false, Ordering::SeqCst),
            "任务没有待处理唤醒，不能手工推进poll"
        );
        let wake = futures_util::task::waker(self.clone());
        poll(&mut Context::from_waker(&wake))
    }
    fn drain_wakes_until_pending<T>(
        self: &Arc<Self>,
        phase: &str,
        mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>,
    ) {
        for _ in 0..128 {
            assert!(
                self.poll(&mut poll).is_pending(),
                "{phase} 必须等待外部事件"
            );
            if !self.scheduled.load(Ordering::SeqCst) {
                return;
            }
        }
        panic!("{phase} 持续自唤醒，未进入静止Pending");
    }
}
impl ArcWake for TaskWake {
    fn wake_by_ref(value: &Arc<Self>) {
        value.count.fetch_add(1, Ordering::SeqCst);
        value.scheduled.store(true, Ordering::SeqCst);
    }
}

#[test]
fn scripted_client_cancellation_closes_handshake_queue_and_flush() {
    for phase in ["handshake", "queue", "flush"] {
        let (cfg, _) = configs("aes-128-cfb", "auth_chain_b", "random_head");
        let trace = Trace::new(Vec::new());
        if phase == "queue" {
            trace.0.lock().unwrap().writes = [WriteStep::Limit(1), WriteStep::Blocked].into();
        }
        if phase == "flush" {
            trace.0.lock().unwrap().flushes = [FlushStep::Blocked].into();
        }
        let cancel = CancellationToken::new();
        let mut stream = Stream::new(
            ScriptedRaw::boxed(&trace, &format!("cancel-client-{phase}")),
            cfg,
            Role::Client,
            cancel.clone(),
            "127.0.0.1".into(),
            1,
        )
        .unwrap();
        let task = Arc::new(TaskWake::new());
        assert!(matches!(
            task.poll(|cx| Pin::new(&mut stream).poll_write(cx, &request())),
            Poll::Ready(Ok(_))
        ));
        task.drain_wakes_until_pending(&format!("client-{phase}"), |cx| {
            Pin::new(&mut stream).poll_flush(cx)
        });
        assert!(trace.has("read_wait"), "{phase}");
        if phase == "queue" {
            assert!(trace.has("write_blocked"));
        }
        if phase == "flush" {
            assert!(trace.has("flush_blocked"));
        }
        let before = trace.sent();
        let before_events = trace.0.lock().unwrap().events.len();
        let before_wake = task.count.load(Ordering::SeqCst);
        cancel.cancel();
        assert!(task.count.load(Ordering::SeqCst) > before_wake, "{phase}");
        assert!(matches!(
            task.poll(|cx| Pin::new(&mut stream).poll_flush(cx)),
            Poll::Ready(Err(_))
        ));
        let wake = futures_util::task::waker(task.clone());
        let mut cx = Context::from_waker(&wake);
        let mut bytes = [0; 64];
        assert!(matches!(
            Pin::new(&mut stream).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes)),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, b"after-cancel"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_flush(&mut cx),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut stream).poll_shutdown(&mut cx),
            Poll::Ready(Err(_))
        ));
        assert_eq!(trace.sent(), before);
        assert!(trace.has("drop"));
        assert_eq!(
            trace.0.lock().unwrap().events[before_events..],
            [json!({"op":"drop"})],
            "{phase} 取消后不得继续底层I/O"
        );
    }
}
