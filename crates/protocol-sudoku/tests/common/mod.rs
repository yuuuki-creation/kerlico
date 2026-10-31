#![allow(dead_code)]

use kerlico_config::{NodeFactory, OutboundFactory, PreparedConfig, Registry, parse};
use kerlico_core::{
    AccessService, AddressedDatagram, BoxFuture, BoxStream, CancellationToken, Capabilities,
    ConnectContext, DatagramAssociation, DatagramAssociationReceiver, DatagramAssociationSender,
    DatagramChannel, Destination, Error, InboundContext, InboundProtocol, Outbound, Result,
    ScopedCredentialFingerprint, StreamBudget,
};
use kerlico_engine::{Engine, Stats};
use kerlico_net::DirectFactory;
use kerlico_sudoku::{SudokuFactory, SudokuNodeFactory};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Notify, mpsc},
    task::JoinHandle,
};

pub const KEY: &str = "synthetic-sudoku-node-a-secret";
pub const OTHER_KEY: &str = "synthetic-sudoku-node-b-secret";
pub const BANNER: &[u8] = b"ready";
pub const TAIL: &[u8] = b"tail";
pub const WAIT: Duration = Duration::from_secs(8);

#[derive(Default)]
pub struct TargetCounters {
    pub read_bytes: AtomicUsize,
    pub read_eof: AtomicUsize,
    pub tail_written: AtomicUsize,
    pub shutdown_done: AtomicUsize,
}
#[derive(Debug, Default)]
pub struct TargetSnapshot {
    pub read_bytes: usize,
    pub read_eof: usize,
    pub tail_written: usize,
    pub shutdown_done: usize,
}
impl TargetCounters {
    pub fn snapshot(&self) -> TargetSnapshot {
        TargetSnapshot {
            read_bytes: self.read_bytes.load(Ordering::SeqCst),
            read_eof: self.read_eof.load(Ordering::SeqCst),
            tail_written: self.tail_written.load(Ordering::SeqCst),
            shutdown_done: self.shutdown_done.load(Ordering::SeqCst),
        }
    }
}
#[derive(Default)]
pub struct State {
    pub physical: AtomicUsize,
    pub active_tcp: AtomicUsize,
    pub associations: AtomicUsize,
    pub decoded: Mutex<Vec<Destination>>,
    pub resolved: Mutex<Vec<Destination>>,
    pub budgets: Mutex<Vec<StreamBudget>>,
    pub release_slow: Notify,
    pub targets: Mutex<BTreeMap<u16, Arc<TargetCounters>>>,
}
impl State {
    pub fn target_snapshot(&self, port: u16) -> TargetSnapshot {
        self.targets.lock().unwrap().get(&port).map_or_else(TargetSnapshot::default, |target|target.snapshot())
    }
}
struct Active(Arc<State>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active_tcp.fetch_sub(1, Ordering::SeqCst);
    }
}
struct OwnedIo {
    inner: tokio::io::DuplexStream,
    cancel: CancellationToken,
}
impl Drop for OwnedIo {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl AsyncRead for OwnedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, data)
    }
}
impl AsyncWrite for OwnedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct Echo(Arc<State>);
struct EchoFactory(Arc<State>);
struct Sender(mpsc::Sender<AddressedDatagram>);
struct Receiver(mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for Sender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send((target.clone(), packet.to_vec()))
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramAssociationReceiver for Receiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl OutboundFactory for EchoFactory {
    fn kind(&self) -> &'static str {
        "sudoku-test-echo"
    }
    fn build(&self, _: &Value) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(Echo(self.0.clone())))
    }
}
impl Outbound for Echo {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            self.0.associations.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = mpsc::channel(32);
            Ok(DatagramAssociation {
                sender: Box::new(Sender(tx)),
                receiver: Box::new(Receiver(rx)),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("此夹具要求真实多目标关联")) })
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.0.resolved.lock().unwrap().push(target.clone());
            if target.port() == 1 {
                return Err(Error::Rejected);
            }
            let slow = target.port() == 9;
            let state = self.0.clone();
            let progress = state.targets.lock().unwrap().entry(target.port()).or_default().clone();
            state.active_tcp.fetch_add(1, Ordering::SeqCst);
            let active = Active(state.clone());
            let cancel = context.cancel.child_token();
            let stopped = cancel.clone();
            let (client, mut server) = tokio::io::duplex(128 * 1024);
            tokio::spawn(async move {
                let _active = active;
                let work = async {
                    server.write_all(BANNER).await?;
                    if slow {
                        state.release_slow.notified().await;
                    }
                    let mut bytes = [0; 32768];
                    loop {
                        let count = server.read(&mut bytes).await?;
                        if count == 0 {
                            progress.read_eof.fetch_add(1, Ordering::SeqCst);
                            server.write_all(TAIL).await?;
                            progress.tail_written.fetch_add(1, Ordering::SeqCst);
                            server.shutdown().await?;
                            progress.shutdown_done.fetch_add(1, Ordering::SeqCst);
                            return Ok::<(), std::io::Error>(());
                        }
                        progress.read_bytes.fetch_add(count, Ordering::SeqCst);
                        server.write_all(&bytes[..count]).await?;
                    }
                };
                tokio::select! { biased; _ = stopped.cancelled() => {}, _ = work => {} }
            });
            Ok(Box::new(OwnedIo {
                inner: client,
                cancel,
            }) as BoxStream)
        })
    }
}

struct ObservedFactory(Arc<State>);
struct Observed {
    inner: Arc<dyn InboundProtocol>,
    state: Arc<State>,
}
struct Tapped {
    inner: Arc<dyn AccessService>,
    state: Arc<State>,
}
impl AccessService for Tapped {
    fn supports_udp_association(&self) -> bool {
        self.inner.supports_udp_association()
    }
    fn associate_udp<'a>(
        &'a self,
        ctx: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.inner.associate_udp(ctx)
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        ctx: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.state.decoded.lock().unwrap().push(target.clone());
        self.inner.connect_tcp(target, ctx)
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        ctx: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.inner.connect_udp(target, ctx)
    }
}
impl NodeFactory for ObservedFactory {
    fn kind(&self) -> &'static str {
        "sudoku"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(Observed {
            inner: SudokuNodeFactory.build(value)?,
            state: self.0.clone(),
        }))
    }
}
impl InboundProtocol for Observed {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.inner.credential_fingerprints()
    }
    fn scoped_credential_fingerprints(&self, kind: &str) -> Vec<ScopedCredentialFingerprint> {
        self.inner.scoped_credential_fingerprints(kind)
    }
    fn credential_isolation_fingerprints(&self, kind: &str) -> Vec<ScopedCredentialFingerprint> {
        self.inner.credential_isolation_fingerprints(kind)
    }
    fn requires_loopback(&self) -> bool {
        self.inner.requires_loopback()
    }
    fn requires_udp_association(&self) -> bool {
        self.inner.requires_udp_association()
    }
    fn supports_tcp(&self) -> bool {
        self.inner.supports_tcp()
    }
    fn supports_udp(&self) -> bool {
        self.inner.supports_udp()
    }
    fn supports_virtual(&self) -> bool {
        self.inner.supports_virtual()
    }
    fn handle<'a>(
        &'a self,
        io: BoxStream,
        access: Arc<dyn AccessService>,
        ctx: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        self.state.physical.fetch_add(1, Ordering::SeqCst);
        self.inner.handle(io, access, ctx)
    }
    fn handle_virtual<'a>(
        &'a self,
        access: Arc<dyn AccessService>,
        ctx: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        self.state
            .budgets
            .lock()
            .unwrap()
            .push(ctx.stream_budget.clone());
        self.inner.handle_virtual(
            Arc::new(Tapped {
                inner: access,
                state: self.state.clone(),
            }),
            ctx,
        )
    }
}

pub fn prepare(value: Value, state: Arc<State>) -> Result<PreparedConfig> {
    let mut registry = Registry::default();
    registry.register(SudokuFactory)?;
    registry.register(DirectFactory)?;
    registry.register(EchoFactory(state.clone()))?;
    registry.register_node(ObservedFactory(state))?;
    registry.prepare(parse(&serde_json::to_vec(&value).unwrap())?)
}
pub fn protocol(key: &str, aead: &str) -> Value {
    json!({"key":key,"aead":aead,"padding_min":0,"padding_max":0,"allow_insecure":aead=="none"})
}
pub fn node_options(mode: &str, key: &str, aead: &str) -> Value {
    json!({"protocol":protocol(key,aead),"http_mask":{"mode":mode}})
}
pub fn client_options(addr: SocketAddr, mode: &str, key: &str, aead: &str, mux: &str) -> Value {
    json!({"server":{"host":addr.ip().to_string(),"port":addr.port()},"protocol":protocol(key,aead),"http_mask":{"mode":mode},"multiplex":mux,"pool_idle_ms":1000})
}
pub fn configuration(options: Value, ipv6: bool, local: bool) -> Value {
    let mut value = json!({"version":1,"outbounds":[{"tag":"exit","type":"sudoku-test-echo"}],"inbounds":[],"nodes":[],"local_inbounds":[],"limits":{"connect_timeout_ms":2000,"idle_timeout_ms":15000,"drain_timeout_ms":300,"max_sessions":128,"max_datagram_size":65507}});
    value[if local { "local_inbounds" } else { "nodes" }] = json!([{"tag":"node","type":"sudoku","listen":if ipv6 {"[::1]:0"}else{"127.0.0.1:0"},"outbound":"exit","options":options}]);
    value
}
pub struct Running {
    pub addresses: BTreeMap<String, SocketAddr>,
    pub stats: Arc<Stats>,
    pub node_stats: BTreeMap<String, Arc<Stats>>,
    pub stop: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Running {
    pub async fn start(value: Value, state: Arc<State>) -> Self {
        let engine = Engine::bind(prepare(value, state).unwrap()).await.unwrap();
        let addresses = engine.listeners().unwrap().into_iter().collect();
        let stats = engine.stats();
        let node_stats = engine.node_stats();
        let stop = CancellationToken::new();
        let task = Some(tokio::spawn(engine.run(stop.clone())));
        Self {
            addresses,
            stats,
            node_stats,
            stop,
            task,
        }
    }
    pub async fn close(mut self) {
        self.stop.cancel();
        tokio::time::timeout(WAIT, self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
pub struct Fixture {
    pub server: Running,
    pub outbound: Arc<dyn Outbound>,
    pub state: Arc<State>,
}
impl Fixture {
    pub async fn start(mode: &str, aead: &str, mux: &str, ipv6: bool) -> Self {
        let state = Arc::new(State::default());
        let server = Running::start(
            configuration(node_options(mode, KEY, aead), ipv6, aead == "none"),
            state.clone(),
        )
        .await;
        let outbound = SudokuFactory
            .build(&client_options(
                server.addresses["node"],
                mode,
                KEY,
                aead,
                mux,
            ))
            .unwrap();
        Self {
            server,
            outbound,
            state,
        }
    }
    pub async fn close(self) {
        drop(self.outbound);
        self.server.close().await;
        eventually(|| self.state.active_tcp.load(Ordering::SeqCst) == 0).await;
    }
}
pub async fn eventually(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
pub async fn banner(stream: &mut BoxStream) {
    let mut bytes = [0; 5];
    tokio::time::timeout(WAIT, stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, BANNER);
}
pub async fn exchange(outbound: &Arc<dyn Outbound>, target: &Destination, bytes: Vec<u8>) {
    let context = ConnectContext::new(WAIT);
    let mut stream = outbound.connect_tcp(target, &context).await.unwrap();
    banner(&mut stream).await;
    let eof = outbound.capabilities().tcp_eof;
    let (mut read, mut write) = tokio::io::split(stream);
    let send = async {
        write.write_all(&bytes).await.unwrap();
        write.flush().await.unwrap();
        if eof {
            write.shutdown().await.unwrap();
        }
    };
    let receive = async {
        let mut data = vec![0; bytes.len()];
        read.read_exact(&mut data).await.unwrap();
        assert_eq!(data, bytes);
        if eof {
            let mut tail = Vec::new();
            read.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, TAIL);
        }
    };
    tokio::time::timeout(WAIT, async {
        tokio::join!(send, receive);
    })
    .await
    .unwrap();
}
pub fn certificates() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}
pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
