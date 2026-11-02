use super::*;
use kerlico_core::{NodeObserver, StreamBudget};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Operation {
    Read,
    Write,
}

struct PendingOperation {
    operation: Operation,
    destroyed: mpsc::UnboundedSender<Operation>,
    destruction_order: Arc<Mutex<Vec<Operation>>>,
}
impl Drop for PendingOperation {
    fn drop(&mut self) {
        self.destruction_order.lock().unwrap().push(self.operation);
        let _ = self.destroyed.send(self.operation);
    }
}

struct BlockedStorage {
    entered: mpsc::UnboundedSender<Operation>,
    destroyed: mpsc::UnboundedSender<Operation>,
    destruction_order: Arc<Mutex<Vec<Operation>>>,
    writes_complete: bool,
}
impl BlockedStorage {
    fn block<T: Send + 'static>(&self, operation: Operation) -> BoxFuture<'_, Result<T>> {
        Box::pin(async move {
            let _operation = PendingOperation {
                operation,
                destroyed: self.destroyed.clone(),
                destruction_order: self.destruction_order.clone(),
            };
            self.entered.send(operation).unwrap();
            std::future::pending().await
        })
    }
}
impl Storage for BlockedStorage {
    fn put<'a>(&'a self, _name: &'a str, _data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        if self.writes_complete {
            Box::pin(async { Ok(()) })
        } else {
            self.block(Operation::Write)
        }
    }
    fn get<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        self.block(Operation::Read)
    }
    fn delete<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn list<'a>(&'a self, _prefix: &'a str) -> BoxFuture<'a, Result<Vec<storage::Entry>>> {
        self.block(Operation::Read)
    }
    fn description<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<String>> {
        if self.writes_complete && id.ends_with("-mark") {
            Box::pin(async { Ok("0".to_owned()) })
        } else {
            self.block(Operation::Read)
        }
    }
    fn set_slot<'a>(
        &'a self,
        _id: &'a str,
        _description: String,
        _body: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<()>> {
        if self.writes_complete {
            Box::pin(async { Ok(()) })
        } else {
            self.block(Operation::Write)
        }
    }
}

struct Probe {
    entered: mpsc::UnboundedReceiver<Operation>,
    destroyed: mpsc::UnboundedReceiver<Operation>,
    destruction_order: Arc<Mutex<Vec<Operation>>>,
}
impl Probe {
    async fn both_started(&mut self) {
        let mut operations = tokio::time::timeout(Duration::from_secs(2), async {
            vec![
                self.entered.recv().await.unwrap(),
                self.entered.recv().await.unwrap(),
            ]
        })
        .await
        .unwrap();
        operations.sort();
        assert_eq!(operations, vec![Operation::Read, Operation::Write]);
    }
    fn both_destroyed(&mut self) {
        let mut operations = vec![
            self.destroyed.try_recv().unwrap(),
            self.destroyed.try_recv().unwrap(),
        ];
        operations.sort();
        assert_eq!(operations, vec![Operation::Read, Operation::Write]);
        assert!(self.destroyed.try_recv().is_err());
    }
}

fn connection(ring: bool, writes_complete: bool) -> (Connection, Probe) {
    let (entered, entered_rx) = mpsc::unbounded_channel();
    let (destroyed, destroyed_rx) = mpsc::unbounded_channel();
    let destruction_order = Arc::new(Mutex::new(Vec::new()));
    let transport = Arc::new(Transport {
        settings: Settings {
            segment_bytes: 1024,
            ..Default::default()
        },
        store: Arc::new(BlockedStorage {
            entered,
            destroyed,
            destruction_order: destruction_order.clone(),
            writes_complete,
        }),
    });
    let ring = ring.then(|| {
        slots::Ring::parse(
        br#"{"u":{"s":["upload"],"w":"upload-mark"},"d":{"s":["download"],"w":"download-mark"}}"#,
    ).unwrap()
    });
    (
        transport.connection("00000000000000000000000000000001", true, ring),
        Probe {
            entered: entered_rx,
            destroyed: destroyed_rx,
            destruction_order,
        },
    )
}

fn session(
    connection: Connection,
    cancel: CancellationToken,
    finish: oneshot::Receiver<Result<()>>,
) -> impl Future<Output = Result<()>> + Send {
    connection.serve(cancel, move |mut io| async move {
        io.write_all(&[1; 1024]).await?;
        let result = finish.await.unwrap();
        drop(io);
        result
    })
}

#[tokio::test]
async fn node_cancel_destroys_pending_segment_and_slot_operations_before_join() {
    for ring in [false, true] {
        let (connection, mut probe) = connection(ring, false);
        let node = CancellationToken::new();
        let (finish, finished) = oneshot::channel();
        let task = tokio::spawn(session(connection, node.child_token(), finished));
        probe.both_started().await;
        node.cancel();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Cancelled)
        ));
        probe.both_destroyed();
        drop(finish);
    }
}

#[tokio::test]
async fn one_session_error_destroys_its_drivers_without_cancelling_its_sibling() {
    for ring in [false, true] {
        let (first, mut first_probe) = connection(ring, false);
        let (second, mut second_probe) = connection(ring, false);
        let node = CancellationToken::new();
        let (fail, failed) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let first = tokio::spawn(session(first, node.child_token(), failed));
        let second = tokio::spawn(session(second, node.child_token(), finished));
        first_probe.both_started().await;
        second_probe.both_started().await;
        fail.send(Err(Error::Rejected)).unwrap();
        assert!(matches!(first.await.unwrap(), Err(Error::Rejected)));
        first_probe.both_destroyed();
        assert!(!node.is_cancelled());
        assert!(!second.is_finished());
        assert!(second_probe.destroyed.try_recv().is_err());
        finish.send(Ok(())).unwrap();
        second.await.unwrap().unwrap();
        second_probe.both_destroyed();
    }
}

#[tokio::test]
async fn completed_write_eof_drops_the_pending_read_driver_before_session_returns() {
    for ring in [false, true] {
        let (connection, mut probe) = connection(ring, true);
        let (finish, finished) = oneshot::channel();
        let task = tokio::spawn(connection.serve(
            CancellationToken::new(),
            move |mut io| async move {
                finished.await.unwrap();
                io.write_all(&[1; 1024]).await?;
                io.shutdown().await?;
                Ok(())
            },
        ));
        assert_eq!(probe.entered.recv().await.unwrap(), Operation::Read);
        finish.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(probe.destroyed.try_recv().unwrap(), Operation::Read);
        assert!(probe.destroyed.try_recv().is_err());
    }
}

#[tokio::test]
async fn node_owner_joins_pending_storage_operations_after_outer_handler_abort() {
    let owner = kerlico_core::NodeTasks::new(
        kerlico_core::NodeId::parse("test-node").unwrap(),
        CancellationToken::new(),
    );
    let (connection, mut probe) = connection(false, false);
    let (_finish, finished) = oneshot::channel();
    let task = owner
        .spawn_tracked(session(connection, owner.cancel().child_token(), finished))
        .unwrap();
    let outer = tokio::spawn(async move { task.await });
    probe.both_started().await;
    outer.abort();
    assert!(outer.await.unwrap_err().is_cancelled());
    let report = owner
        .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
        .await;
    assert!(report.is_clean());
    probe.both_destroyed();
}

struct CleanupObserver {
    destruction_order: Arc<Mutex<Vec<Operation>>>,
    forced: AtomicBool,
}
impl NodeObserver for CleanupObserver {
    fn record(&self, event: NodeEvent) {
        if matches!(event, NodeEvent::ForcedCleanup) {
            let mut destroyed = self.destruction_order.lock().unwrap().clone();
            destroyed.sort();
            assert_eq!(destroyed, vec![Operation::Read, Operation::Write]);
            self.forced.store(true, Ordering::Release);
        }
    }
}

#[tokio::test]
async fn forced_drain_joins_real_drivers_before_recording_cleanup_and_releasing_budget() {
    for ring in [false, true] {
        let (connection, mut probe) = connection(ring, false);
        let observer = Arc::new(CleanupObserver {
            destruction_order: probe.destruction_order.clone(),
            forced: AtomicBool::new(false),
        });
        let context = InboundContext {
            peer_lease: None,
            tasks: kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                kerlico_core::CancellationToken::new(),
            ),
            peer_addr: None,
            local_addr: None,
            cancel: CancellationToken::new(),
            connect_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            drain_timeout: Duration::from_millis(100),
            max_datagram_size: 65535,
            max_streams: 1,
            stream_budget: StreamBudget::new(
                Arc::new(tokio::sync::Semaphore::new(1)),
                Arc::new(tokio::sync::Semaphore::new(1)),
            ),
            events: observer.clone(),
        };
        let lease = context.stream_budget.try_acquire().unwrap();
        let (finish, finished) = oneshot::channel();
        let mut tasks = JoinSet::new();
        let cancel = context.cancel.child_token();
        tasks.spawn(async move {
            let _lease = lease;
            let _ = session(connection, cancel, finished).await;
        });
        probe.both_started().await;
        assert!(context.stream_budget.try_acquire().is_err());
        drain_sessions(&mut tasks, &context).await.unwrap();
        probe.both_destroyed();
        assert!(tasks.is_empty());
        assert!(observer.forced.load(Ordering::Acquire));
        assert!(context.stream_budget.try_acquire().is_ok());
        assert!(!context.cancel.is_cancelled());
        drop(finish);
    }
}

struct HttpStorage {
    client: super::http::Client,
    base: String,
}
impl Storage for HttpStorage {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if name.starts_with("sessions/") {
                return Ok(());
            }
            self.client
                .request(
                    ::http::Method::PUT,
                    url::Url::parse(&format!("{}{name}", self.base)).unwrap(),
                )
                .body(data.to_vec())
                .send()
                .await?;
            Ok(())
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            self.client
                .request(
                    ::http::Method::GET,
                    url::Url::parse(&format!("{}{name}", self.base)).unwrap(),
                )
                .send()
                .await?;
            Ok(None)
        })
    }
    fn delete<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn list<'a>(&'a self, _prefix: &'a str) -> BoxFuture<'a, Result<Vec<storage::Entry>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

#[tokio::test]
async fn session_cancel_and_shared_shutdown_close_both_real_http_driver_connections() {
    for outbound in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, mut received) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let ready = ready.clone();
                connections.spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(stream.read_u8().await.unwrap());
                    }
                    ready.send(()).unwrap();
                    let mut bytes = [0; 4096];
                    while stream.read(&mut bytes).await.unwrap() != 0 {}
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        });
        let transport = Arc::new(Transport {
            settings: Settings {
                segment_bytes: 1024,
                ..Default::default()
            },
            store: Arc::new(HttpStorage {
                client: super::http::Client::new(super::http::tls(None).unwrap()),
                base: format!("http://{address}/"),
            }),
        });
        let node = CancellationToken::new();
        let (finish, finished) = oneshot::channel();
        let host = kerlico_core::ServiceContext::for_test();
        let mut stream = None;
        let task = if outbound {
            let mut io = transport.open(&host).await.unwrap();
            io.write_all(&[1; 1024]).await.unwrap();
            stream = Some(io);
            None
        } else {
            Some(tokio::spawn(session(
                transport.connection("00000000000000000000000000000001", true, None),
                node.child_token(),
                finished,
            )))
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            received.recv().await.unwrap();
            received.recv().await.unwrap();
        })
        .await
        .unwrap();
        if let Some(task) = task {
            node.cancel();
            assert!(matches!(task.await.unwrap(), Err(Error::Cancelled)));
        }
        drop(stream);
        let report = host
            .shutdown(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        assert!(report.is_clean());
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        drop(finish);
    }
}
