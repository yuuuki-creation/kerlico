//! 模拟 sing-quic（Mihomo）服务端：TCP 响应头推迟到目标首次回写时才发送。

use kerlico_core::{ConnectContext, Destination};
use serde_json::json;
use std::{io::Cursor, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}

fn server_config(certificate: &str, key: &str) -> quinn::ServerConfig {
    let certs = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut Cursor::new(key))
        .unwrap()
        .unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ))
}

/// HTTP/3 HEADERS 帧：`:status: 233`、`hysteria-udp: false`、`hysteria-cc-rx: auto`（QPACK 字面量）。
fn auth_reply() -> Vec<u8> {
    let mut block = vec![0x00, 0x00, 0x5f, 0x09, 0x03];
    block.extend_from_slice(b"233");
    for (name, value) in [("hysteria-udp", "false"), ("hysteria-cc-rx", "auto")] {
        block.extend_from_slice(&[0x27, name.len() as u8 - 7]);
        block.extend_from_slice(name.as_bytes());
        block.push(value.len() as u8);
        block.extend_from_slice(value.as_bytes());
    }
    let mut frame = vec![0x01, block.len() as u8];
    frame.extend_from_slice(&block);
    frame
}

async fn read_field(receive: &mut quinn::RecvStream) -> Vec<u8> {
    let first = receive.read_u8().await.unwrap();
    let mut length = u64::from(first & 63);
    for _ in 1..(1usize << (first >> 6)) {
        length = length << 8 | u64::from(receive.read_u8().await.unwrap());
    }
    let mut field = vec![0; length as usize];
    receive.read_exact(&mut field).await.unwrap();
    field
}

async fn deferring_server(endpoint: quinn::Endpoint) {
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let mut control = connection.open_uni().await.unwrap();
    control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();
    let (mut send, mut receive) = connection.accept_bi().await.unwrap();
    receive.read_to_end(64 * 1024).await.unwrap();
    send.write_all(&auth_reply()).await.unwrap();
    send.finish().unwrap();
    let (mut send, mut receive) = connection.accept_bi().await.unwrap();
    let mut id = [0u8; 2];
    receive.read_exact(&mut id).await.unwrap();
    assert_eq!(id, [0x44, 0x01], "TCP 请求 ID");
    assert_eq!(read_field(&mut receive).await, b"example.com:80");
    read_field(&mut receive).await;
    let mut request = [0u8; 3];
    receive.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");
    send.write_all(&[0x00, 0x00, 0x00]).await.unwrap();
    send.write_all(b"HTTP").await.unwrap();
    send.finish().unwrap();
    let _ = receive.read_to_end(1024).await;
    connection.closed().await;
}

#[tokio::test]
async fn client_first_tcp_works_when_server_defers_the_response() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.cert.pem();
    let endpoint = quinn::Endpoint::server(
        server_config(&certificate, &cert.signing_key.serialize_pem()),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let server = tokio::spawn(deferring_server(endpoint));
    let outbound = shared::outbound(
        &kerlico_hysteria2::Hysteria2Factory,
        &json!({"server":{"host":"127.0.0.1","port":port},"auth":"synthetic-password","tls":{"server_name":"localhost","ca_pem":certificate}}),
    )
    .await
    .unwrap();
    let target = Destination::new("example.com", 80).unwrap();
    let exchange = async {
        let mut stream = outbound
            .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(5)))
            .await
            .unwrap()
            .stream;
        stream.write_all(b"GET").await.unwrap();
        stream.flush().await.unwrap();
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.unwrap();
        body
    };
    let body = tokio::time::timeout(Duration::from_secs(10), exchange)
        .await
        .expect("客户端先发数据时不应等待服务端 TCP 响应");
    assert_eq!(body, b"HTTP");
    drop(outbound);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn rejected_tcp_response_fails_the_first_read() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.cert.pem();
    let endpoint = quinn::Endpoint::server(
        server_config(&certificate, &cert.signing_key.serialize_pem()),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut control = connection.open_uni().await.unwrap();
        control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();
        let (mut send, mut receive) = connection.accept_bi().await.unwrap();
        receive.read_to_end(64 * 1024).await.unwrap();
        send.write_all(&auth_reply()).await.unwrap();
        send.finish().unwrap();
        let (mut send, _receive) = connection.accept_bi().await.unwrap();
        send.write_all(&[0x01, 0x06]).await.unwrap();
        send.write_all(b"denied").await.unwrap();
        send.write_all(&[0x00]).await.unwrap();
        send.finish().unwrap();
        connection.closed().await;
    });
    let outbound = shared::outbound(
        &kerlico_hysteria2::Hysteria2Factory,
        &json!({"server":{"host":"127.0.0.1","port":port},"auth":"synthetic-password","tls":{"server_name":"localhost","ca_pem":certificate}}),
    )
    .await
    .unwrap();
    let target = Destination::new("example.com", 80).unwrap();
    let mut stream = outbound
        .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(5)))
        .await
        .unwrap()
        .stream;
    stream.write_all(b"GET").await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), stream.read_u8())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("denied"), "{error}");
    drop(outbound);
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
