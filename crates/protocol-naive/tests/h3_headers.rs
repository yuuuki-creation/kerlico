//! 原始QPACK/QUIC负例，不使用h3请求编码器生成待拒绝伪头。
mod common;
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use kerlico_config::OutboundFactory;
use kerlico_core::Destination;
use kerlico_naive::NaiveFactory;
use serde_json::json;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::io::AsyncReadExt;
fn integer(out: &mut Vec<u8>, mut value: usize, prefix: u8, first: u8) {
    let limit = (1usize << prefix) - 1;
    if value < limit {
        out.push(first | value as u8);
        return;
    }
    out.push(first | limit as u8);
    value -= limit;
    while value >= 128 {
        out.push((value as u8 & 127) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn qpack(fields: &[(&str, String)]) -> Vec<u8> {
    let mut out = vec![0, 0];
    for (name, value) in fields {
        integer(&mut out, name.len(), 3, 0x20);
        out.extend(name.as_bytes());
        integer(&mut out, value.len(), 7, 0);
        out.extend(value.as_bytes());
    }
    out
}
fn varint(value: usize) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else {
        assert!(value < 16384);
        vec![0x40 | ((value >> 8) as u8), value as u8]
    }
}
async fn send_headers(stream: &mut quinn::SendStream, fields: &[(&str, String)]) {
    let block = qpack(fields);
    stream.write_all(&[1]).await.unwrap();
    stream.write_all(&varint(block.len())).await.unwrap();
    stream.write_all(&block).await.unwrap();
    stream.finish().unwrap();
}
async fn controls(connection: &quinn::Connection) -> Vec<quinn::SendStream> {
    let mut streams = Vec::new();
    for bytes in [&[0, 4, 0][..], &[2][..], &[3][..]] {
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(bytes).await.unwrap();
        streams.push(stream);
    }
    streams
}
async fn connect(fixture: &Fixture) -> (quinn::Endpoint, quinn::Connection) {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(
        fixture.options["tls"]["ca_pem"].as_str().unwrap(),
    ))
    .collect::<std::io::Result<Vec<_>>>()
    .unwrap()
    {
        roots.add(cert).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(fixture.address, "proxy.invalid")
        .unwrap()
        .await
        .unwrap();
    (endpoint, connection)
}
#[tokio::test]
async fn duplicate_request_pseudo_headers_and_late_pseudo_headers_never_reach_access() {
    for kind in [
        "valid",
        "duplicate-method",
        "duplicate-authority",
        "late-authority",
    ] {
        let mut fixture = fixture("h3", "127.0.0.1", 2).await;
        let echo = tcp_echo("127.0.0.1").await;
        let (endpoint, connection) = connect(&fixture).await;
        let _controls = controls(&connection).await;
        let mut fields = vec![(":method", "CONNECT".into())];
        if kind == "duplicate-method" {
            fields.push((":method", "CONNECT".into()));
        }
        if kind == "late-authority" {
            fields.push(("padding", "p".into()));
        }
        fields.push((":authority", echo.target.to_string()));
        if kind == "duplicate-authority" {
            fields.push((":authority", echo.target.to_string()));
        }
        fields.push((
            "proxy-authorization",
            format!("Basic {}", STANDARD.encode("test-user:synthetic-secret")),
        ));
        if kind != "late-authority" {
            fields.push(("padding", "p".into()));
        }
        let (mut sender, mut receiver) = connection.open_bi().await.unwrap();
        send_headers(&mut sender, &fields).await;
        let result = tokio::time::timeout(Duration::from_secs(3), receiver.read_to_end(16384))
            .await
            .expect("H3伪头响应不能无限等待");
        if kind == "valid" {
            assert!(result.as_ref().is_ok_and(|data| !data.is_empty()));
            assert_eq!(fixture.accesses.load(Ordering::Acquire), 1);
        } else {
            assert!(
                match result.as_ref() {
                    Ok(data) => data.is_empty(),
                    Err(_) => true,
                },
                "{kind}必须在消息解码层拒绝"
            );
            assert_eq!(
                fixture.accesses.load(Ordering::Acquire),
                0,
                "{kind}不能访问目标"
            );
        }
        connection.close(0u32.into(), b"test complete");
        endpoint.close(0u32.into(), b"test complete");
        fixture.stop().await;
    }
}
#[tokio::test]
async fn duplicate_status_is_rejected_by_real_naive_client_with_valid_tls_control() {
    for duplicate in [false, true] {
        let certificate = rcgen::generate_simple_self_signed(vec!["proxy.invalid".into()]).unwrap();
        let cert = certificate.cert.pem();
        let private =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], private.into())
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = endpoint.local_addr().unwrap();
        let peer = endpoint.clone();
        let task = tokio::spawn(async move {
            let connection = peer.accept().await.unwrap().await.unwrap();
            let _controls = controls(&connection).await;
            let (mut sender, mut receiver) = connection.accept_bi().await.unwrap();
            let kind = receiver.read_u8().await.unwrap();
            assert_eq!(kind, 1);
            let first = receiver.read_u8().await.unwrap();
            let size = if first >> 6 == 0 {
                usize::from(first)
            } else {
                assert_eq!(first >> 6, 1);
                (usize::from(first & 63) << 8) | usize::from(receiver.read_u8().await.unwrap())
            };
            let mut bytes = vec![0; size];
            receiver.read_exact(&mut bytes).await.unwrap();
            let mut fields = vec![(":status", "200".into())];
            if duplicate {
                fields.push((":status", "200".into()));
            }
            fields.extend([("padding", "p".into()), ("padding-type-reply", "1".into())]);
            send_headers(&mut sender, &fields).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            connection.close(0u32.into(), b"test complete");
        });
        let outbound=NaiveFactory.build(&json!({"server":{"host":"127.0.0.1","port":address.port()},"username":"test-user","password":"synthetic-secret","tls":{"server_name":"proxy.invalid","ca_pem":cert},"transport":"h3"})).unwrap();
        let result = outbound
            .connect_tcp(
                &Destination::new("example.invalid", 443).unwrap(),
                &kerlico_core::ConnectContext::new(Duration::from_secs(3)),
            )
            .await;
        assert_eq!(
            result.is_err(),
            duplicate,
            "重复状态拒绝必须与有效TLS/单状态控制组区分"
        );
        drop(result);
        drop(outbound);
        task.await.unwrap();
        endpoint.close(0u32.into(), b"test complete");
    }
}
