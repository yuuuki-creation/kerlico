#![cfg(target_os = "linux")]

use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, ServiceContext};
use kerlico_net::DirectFactory;
use serde_json::json;
use std::time::Duration;
use tokio::net::TcpListener;

async fn connect(interface: &str, port: u16) -> kerlico_core::Result<()> {
    let plan = DirectFactory.compile(&json!({"interface": interface}))?;
    let outbound = plan.start(ServiceContext::for_test()).await?;
    let target = Destination::new("127.0.0.1", port)?;
    outbound
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(3)))
        .await
        .map(|_| ())
}

#[tokio::test]
async fn direct_uses_the_configured_interface() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!(connect("lo", port).await.is_ok());
    assert!(connect("kerlico-absent", port).await.is_err());
}

#[test]
fn direct_rejects_unknown_fields_and_bad_names() {
    assert!(DirectFactory.compile(&json!({"unknown": true})).is_err());
    assert!(DirectFactory.compile(&json!({"interface": ""})).is_err());
    assert!(
        DirectFactory
            .compile(&json!({"interface": "this-name-is-too-long"}))
            .is_err()
    );
    assert!(DirectFactory.compile(&json!({})).is_ok());
}
