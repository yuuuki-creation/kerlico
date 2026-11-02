use super::NodeExecutor;
use bytes::Bytes;
use http_body_util::Empty;
use hyper::rt::Executor;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerlico_core::{CancellationToken, NodeId, NodeTasks};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn h2_node_owner_joins_pending_service_after_outer_connection_abort() {
    tokio::time::timeout(Duration::from_secs(4), async {
        let owner = NodeTasks::new(
            NodeId::parse("h2-owner-test").unwrap(),
            CancellationToken::new(),
        );
        let executor = NodeExecutor(owner.clone());
        let dropped = Arc::new(AtomicBool::new(false));
        let active = Arc::new(tokio::sync::Notify::new());
        let service_dropped = dropped.clone();
        let service_active = active.clone();
        let service =
            hyper::service::service_fn(move |_request: http::Request<hyper::body::Incoming>| {
                let probe = Dropped(service_dropped.clone());
                let active = service_active.clone();
                async move {
                    let _probe = probe;
                    active.notify_one();
                    std::future::pending::<
                        std::result::Result<http::Response<Empty<Bytes>>, Infallible>,
                    >()
                    .await
                }
            });
        let (server, client) = tokio::io::duplex(16384);
        let server_executor = executor.clone();
        let outer = tokio::spawn(async move {
            hyper_util::server::conn::auto::Builder::new(server_executor)
                .serve_connection_with_upgrades(TokioIo::new(server), service)
                .await
        });
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(client),
        )
        .await
        .unwrap();
        let client_driver = tokio::spawn(connection);
        let request = tokio::spawn(async move {
            sender
                .send_request(
                    http::Request::builder()
                        .uri("http://h2-test.invalid/")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
        });
        active.notified().await;
        assert!(!dropped.load(Ordering::SeqCst));
        outer.abort();
        assert!(outer.await.unwrap_err().is_cancelled());
        let report = owner
            .shutdown_at(tokio::time::Instant::now() + Duration::from_secs(1))
            .await;
        assert!(report.is_clean());
        assert!(dropped.load(Ordering::SeqCst));

        let rejected = Arc::new(AtomicBool::new(false));
        let probe = Dropped(rejected.clone());
        executor.execute(async move {
            let _probe = probe;
            std::future::pending::<()>().await;
        });
        assert!(rejected.load(Ordering::SeqCst), "关闭后不能建立备用任务");
        request.abort();
        let _ = request.await;
        client_driver.abort();
        let _ = client_driver.await;
    })
    .await
    .expect("真实 HTTP/2 派生任务回收超时");
}
