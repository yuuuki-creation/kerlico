use super::{codec::Mode, pull, session::Registry};
use crate::{config::NodeOptions, scope::Scope};
use bytes::Bytes;
use http_body_util::BodyExt;
use kerlico_core::{CancellationToken, InboundContext, NodeEvent, NodeObserver, StreamBudget};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};

struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
fn registry(
    ttl: Duration,
) -> (
    Arc<Registry>,
    tokio::sync::mpsc::Receiver<super::session::Backend>,
    Arc<Scope>,
    Arc<Semaphore>,
) {
    let protocol = serde_json::from_value::<NodeOptions>(
        json!({"protocol":{"key":"synthetic-sudoku-http-state-seed"}}),
    )
    .unwrap()
    .prepare()
    .unwrap()
    .protocol;
    let parent = CancellationToken::new();
    let scope = Scope::new(&parent);
    let slots = Arc::new(Semaphore::new(8));
    let context = InboundContext {
        peer_addr: None,
        local_addr: None,
        cancel: parent,
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(2),
        drain_timeout: Duration::from_millis(100),
        max_datagram_size: 65507,
        max_streams: 8,
        stream_budget: StreamBudget::new(slots.clone(), Arc::new(Semaphore::new(8))),
        events: Arc::new(Observer),
    };
    let (registry, backends) = Registry::new(protocol, scope.clone(), context, 8, ttl);
    (registry, backends, scope, slots)
}

#[tokio::test]
async fn upload_duplicate_is_exactly_once_and_fin_is_idempotent() {
    let (registry, mut backends, scope, slots) = registry(Duration::from_secs(2));
    let authorized = registry.authorize(Mode::Stream, None).unwrap();
    let mut backend = backends.recv().await.unwrap();
    let token = authorized.token;
    assert_eq!(slots.available_permits(), 7);
    token.push(1, Bytes::from_static(b"abc")).await.unwrap();
    token.push(1, Bytes::from_static(b"abc")).await.unwrap();
    assert!(matches!(
        token.push(1, Bytes::from_static(b"changed")).await,
        Err(kerlico_core::Error::Protocol(_))
    ));
    assert!(token.push(3, Bytes::from_static(b"gap")).await.is_err());
    assert!(token.push(0, Bytes::from_static(b"legacy")).await.is_err());
    token.push(2, Bytes::from_static(b"def")).await.unwrap();
    token.fin().await.unwrap();
    token.fin().await.unwrap();
    let mut bytes = Vec::new();
    backend.stream.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"abcdef");
    assert!(
        token
            .push(3, Bytes::from_static(b"after-fin"))
            .await
            .is_err()
    );
    registry.remove(&token.value);
    drop(backend);
    drop(token);
    scope.shutdown().await;
    assert_eq!(slots.available_permits(), 8);
}

#[tokio::test]
async fn disconnected_upload_request_does_not_cancel_or_duplicate_owned_batch() {
    let (registry, mut backends, scope, _) = registry(Duration::from_secs(5));
    let authorized = registry.authorize(Mode::Stream, None).unwrap();
    let backend = backends.recv().await.unwrap();
    let token = authorized.token;
    let bytes = Bytes::from(vec![0x5a; 200_000]);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), token.push(1, bytes.clone()))
            .await
            .is_err()
    );
    let reading = tokio::spawn(async move {
        let mut stream = backend.stream;
        let mut read = Vec::new();
        stream.read_to_end(&mut read).await.unwrap();
        read
    });
    token.push(1, bytes.clone()).await.unwrap();
    token.fin().await.unwrap();
    assert_eq!(reading.await.unwrap(), bytes);
    registry.remove(&token.value);
    scope.shutdown().await;
}

#[tokio::test]
async fn unpolled_pull_preserves_bytes_but_uncertain_delivery_closes_token() {
    let (registry, mut backends, scope, _) = registry(Duration::from_secs(5));
    let authorized = registry.authorize(Mode::Stream, None).unwrap();
    let mut backend = backends.recv().await.unwrap();
    let token = authorized.token;
    backend.stream.write_all(b"retained").await.unwrap();
    let body = pull::start(token.clone(), &scope);
    tokio::task::yield_now().await;
    drop(body);
    assert!(!token.cancel.is_cancelled());
    let mut second = pull::start(token.clone(), &scope);
    let frame = tokio::time::timeout(Duration::from_secs(1), second.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.data_ref().unwrap().as_ref(), b"retained");
    drop(second);
    tokio::time::timeout(Duration::from_secs(1), token.cancel.cancelled())
        .await
        .unwrap();
    registry.shutdown();
    scope.shutdown().await;
}

#[tokio::test]
async fn eof_trailer_preserves_upload_half_and_reaper_returns_leases() {
    let (registry, mut backends, scope, slots) = registry(Duration::from_millis(150));
    let authorized = registry.authorize(Mode::Poll, None).unwrap();
    let mut backend = backends.recv().await.unwrap();
    let token = authorized.token;
    backend.stream.write_all(b"tail").await.unwrap();
    backend.stream.shutdown().await.unwrap();
    let mut body = pull::start(token.clone(), &scope);
    let frame = body.frame().await.unwrap().unwrap();
    assert_eq!(frame.data_ref().unwrap().as_ref(), b"dGFpbA==\n");
    let trailer = body.frame().await.unwrap().unwrap();
    assert_eq!(trailer.trailers_ref().unwrap()["x-sudoku-stream-eof"], "1");
    drop(body);
    assert!(!token.cancel.is_cancelled());
    token
        .push(1, Bytes::from_static(b"after-eof"))
        .await
        .unwrap();
    let mut bytes = [0; 9];
    backend.stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"after-eof");
    let value = token.value.clone();
    drop(backend);
    drop(token);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if registry.get(&value, Mode::Poll).is_none() && slots.available_permits() == 8 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    scope.shutdown().await;
}
