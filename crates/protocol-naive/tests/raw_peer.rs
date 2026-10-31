mod common;
use common::*;
use kerlico_core::{ConnectContext, Destination};
use kerlico_naive::{NaiveFactory, NaiveNodeFactory};
use serde_json::json;
use std::{sync::atomic::Ordering, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
async fn tls(fixture: &Fixture) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let cert = fixture.options["tls"]["ca_pem"].as_str().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(cert))
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap()
    {
        roots.add(cert).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(fixture.address)
        .await
        .unwrap();
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("proxy.invalid").unwrap(),
            tcp,
        )
        .await
        .unwrap()
}
async fn head(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut bytes = Vec::new();
    while bytes.len() < 20000 {
        bytes.push(stream.read_u8().await.unwrap());
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(bytes).unwrap()
}
fn auth() -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("test-user:synthetic-secret")
    )
}
#[tokio::test]
async fn malformed_and_unauthorized_headers_do_not_reach_access() {
    let mut fixture = fixture("h1", "127.0.0.1", 2).await;
    let target = tcp_echo("127.0.0.1").await;
    for extra in [
        format!(
            "Proxy-Authorization: {}\r\nPadding: p\r\nPadding-Type-Request: 0\r\n",
            auth()
        ),
        format!(
            "Proxy-Authorization: {}\r\nPadding: p\r\nPadding-Type-Request: 9\r\n",
            auth()
        ),
        format!("Proxy-Authorization: {}\r\n", auth()),
        format!(
            "Proxy-Authorization: {}\r\nProxy-Authorization: {}\r\nPadding: p\r\n",
            auth(),
            auth()
        ),
        "Proxy-Authorization: Basic wrong\r\nPadding: p\r\n".into(),
    ] {
        let mut stream = tls(&fixture).await;
        stream
            .write_all(format!("CONNECT {} HTTP/1.1\r\n{extra}\r\n", target.target).as_bytes())
            .await
            .unwrap();
        let response = head(&mut stream).await;
        assert!(response.starts_with("HTTP/1.1 400") || response.starts_with("HTTP/1.1 407"));
    }
    assert_eq!(fixture.accesses.load(Ordering::Acquire), 0);
    fixture.stop().await;
}
#[tokio::test]
async fn header_and_uot_preamble_have_timeout_and_cancel_reclaims_leases() {
    let mut fixture = fixture_with("h1", "127.0.0.1", 2, 1, Duration::from_millis(70)).await;
    let mut stream = tls(&fixture).await;
    stream.write_all(b"CONNECT unfinished").await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), head(&mut stream))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 502"));
    drop(stream);
    let mut stream = tls(&fixture).await;
    stream.write_all(format!("CONNECT sp.v2.udp-over-tcp.arpa:0 HTTP/1.1\r\nProxy-Authorization: {}\r\nPadding: p\r\n\r\n",auth()).as_bytes()).await.unwrap();
    assert!(head(&mut stream).await.starts_with("HTTP/1.1 200"));
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
        .await
        .unwrap();
    assert!(result.is_err());
    drop(stream);
    assert_eq!(fixture.associations.load(Ordering::Acquire), 0);
    let echo = tcp_echo("127.0.0.1").await;
    let mut active = fixture
        .outbound
        .connect_tcp(&echo.target, &fixture.context())
        .await
        .unwrap();
    fixture.stop().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), active.read_u8())
            .await
            .unwrap()
            .is_err()
    );
}
#[tokio::test]
async fn connector_injection_is_used_for_h2_and_does_not_change_target() {
    struct Count(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl kerlico_core::StreamConnector for Count {
        fn tcp_eof(&self) -> bool {
            true
        }
        fn connect_tcp<'a>(
            &'a self,
            target: &'a Destination,
            context: &'a ConnectContext,
        ) -> kerlico_core::BoxFuture<'a, kerlico_core::Result<kerlico_core::BoxStream>> {
            self.0.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                kerlico_core::StreamConnector::connect_tcp(
                    &kerlico_net::TcpConnector::plain(),
                    target,
                    context,
                )
                .await
            })
        }
    }
    let mut fixture = fixture("h2", "127.0.0.1", 2).await;
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outbound = NaiveFactory::build_with_connector(
        &fixture.options,
        std::sync::Arc::new(Count(count.clone())),
    )
    .unwrap();
    let echo = tcp_echo("127.0.0.1").await;
    tcp(&outbound, &fixture.context(), &echo.target, 12000).await;
    assert_eq!(count.load(Ordering::Acquire), 1);
    fixture.stop().await;
}
#[tokio::test]
async fn real_registry_separates_http_basic_secrets_and_requires_full_cone_egress() {
    let mut fixture = fixture("h2", "127.0.0.1", 2).await;
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry.register(kerlico_net::RejectFactory).unwrap();
    registry
        .register_node(kerlico_http::HttpNodeFactory)
        .unwrap();
    registry.register_node(NaiveNodeFactory).unwrap();
    let config = |password: &str, outbound: &str| json!({"version":1,"outbounds":[{"tag":"direct","type":"direct"},{"tag":"reject","type":"reject"}],"inbounds":[],"nodes":[{"tag":"http-node","type":"http","listen":"127.0.0.1:32001","outbound":"direct","options":{"auth":{"username":"test-user","password":password},"tls":{"cert_pem":fixture.node_options["tls"]["certificate_pem"],"key_pem":fixture.node_options["tls"]["private_key_pem"]}}},{"tag":"naive-node","type":"naive","listen":"[::1]:32002","outbound":outbound,"options":fixture.node_options}]});
    let same = serde_json::from_value(config("synthetic-secret", "direct")).unwrap();
    assert!(registry.prepare(same).is_err());
    let distinct = serde_json::from_value(config("independent-secret", "direct")).unwrap();
    assert!(registry.prepare(distinct).is_ok());
    let unsupported = serde_json::from_value(config("independent-secret", "reject")).unwrap();
    assert!(registry.prepare(unsupported).is_err());
    fixture.stop().await;
}
