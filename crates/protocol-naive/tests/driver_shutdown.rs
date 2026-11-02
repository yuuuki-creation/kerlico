mod common;

use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, ServiceContext};
use std::time::Duration;
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    time::{Instant, timeout},
};

async fn target() -> (Destination, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes).await;
    });
    (destination, task)
}

#[tokio::test]
async fn client_shutdown_releases_live_target_with_retained_stream_for_all_transports() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = common::fixture(transport, "127.0.0.1", 2).await;
        let host = ServiceContext::for_test();
        let outbound = kerlico_naive::NaiveFactory
            .compile(&fixture.options)
            .unwrap()
            .start(host.clone())
            .await
            .unwrap();
        let (target, peer) = target().await;
        let context = ConnectContext::new(Duration::from_secs(3));
        let mut stream = outbound
            .connect_tcp(&target, &context)
            .await
            .unwrap()
            .stream;
        timeout(Duration::from_secs(3), outbound.shutdown())
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_secs(1), stream.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        assert!(!context.cancel.is_cancelled());
        assert!(outbound.connect_tcp(&target, &context).await.is_err());
        let report = host.shutdown(Instant::now() + Duration::from_secs(3)).await;
        assert!(report.is_clean());
        fixture.stop().await;
    }
}

#[tokio::test]
async fn node_shutdown_releases_live_target_with_independent_client_for_all_transports() {
    for transport in ["h1", "h2", "h3"] {
        let mut fixture = common::fixture(transport, "127.0.0.1", 2).await;
        let (target, peer) = target().await;
        let context = ConnectContext::new(Duration::from_secs(3));
        let mut stream = fixture
            .outbound
            .connect_tcp(&target, &context)
            .await
            .unwrap()
            .stream;
        fixture.stop().await;
        timeout(Duration::from_secs(3), peer)
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_secs(1), stream.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        assert!(!context.cancel.is_cancelled());
        timeout(Duration::from_secs(3), fixture.outbound.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}
