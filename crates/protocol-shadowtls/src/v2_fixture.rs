use super::*;
use crate::{config, tls};
use std::{io::Cursor, task::Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

struct FragmentedIo {
    raw: DuplexStream,
    consumed: tokio::sync::watch::Sender<usize>,
    total: usize,
}
impl AsyncRead for FragmentedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut bytes = [0; 3];
        let limit = out.remaining().min(bytes.len());
        let mut part = ReadBuf::new(&mut bytes[..limit]);
        match Pin::new(&mut self.raw).poll_read(cx, &mut part) {
            Poll::Ready(Ok(())) => {
                out.put_slice(part.filled());
                self.total += part.filled().len();
                let total = self.total;
                self.consumed.send_replace(total);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for FragmentedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.raw).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

fn records(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut offset = 0;
    let mut records = Vec::new();
    while offset < bytes.len() {
        assert!(offset + 5 <= bytes.len());
        let end = offset + 5 + u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]) as usize;
        assert!(end <= bytes.len());
        records.push(bytes[offset..end].to_vec());
        offset = end;
    }
    records
}

struct Fixture {
    outcome: tls::Outcome,
    origin: DuplexStream,
    handshake: Vec<u8>,
    late: Vec<Vec<u8>>,
    consumed: tokio::sync::watch::Receiver<usize>,
}
async fn fixture(tls13: bool, tickets: usize) -> Fixture {
    let certificate =
        rcgen::generate_simple_self_signed(vec!["shadowtls.example.invalid".into()]).unwrap();
    let pem = certificate.cert.pem();
    let chain = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let key_pem = certificate.signing_key.serialize_pem();
    let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem.as_bytes()))
        .unwrap()
        .unwrap();
    let version = if tls13 {
        &rustls::version::TLS13
    } else {
        &rustls::version::TLS12
    };
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[version])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = tickets;
    let settings = tls::settings(
        &config::Tls {
            server_name: "shadowtls.example.invalid".into(),
            ca_pem: Some(pem),
            version: if tls13 { "1.3" } else { "1.2" }.into(),
            alpn: vec!["http/1.1".into()],
        },
        2,
        false,
    )
    .unwrap();
    let (client, mut origin) = tokio::io::duplex(16384);
    let server = async move {
        let mut session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut handshake = Vec::new();
        loop {
            let record = wire::read(&mut origin).await.unwrap().unwrap();
            session.read_tls(&mut Cursor::new(record)).unwrap();
            session.process_new_packets().unwrap();
            let mut outgoing = Vec::new();
            while session.wants_write() {
                session.write_tls(&mut outgoing).unwrap();
            }
            if tls13 && !session.is_handshaking() {
                return (origin, handshake, records(&outgoing));
            }
            for record in records(&outgoing) {
                for part in [
                    record[..2].to_vec(),
                    record[2..5].to_vec(),
                    record[5..].to_vec(),
                ] {
                    origin.write_all(&part).await.unwrap();
                }
                handshake.extend_from_slice(&record);
            }
            if !session.is_handshaking() {
                return (origin, handshake, Vec::new());
            }
        }
    };
    let (observed, consumed) = tokio::sync::watch::channel(0);
    let client = tls::handshake(
        Box::new(FragmentedIo {
            raw: client,
            consumed: observed,
            total: 0,
        }),
        &settings,
        2,
        false,
        Arc::from(b"real-boundary-test".as_slice()),
    );
    let (outcome, (origin, handshake, late)) = tokio::join!(client, server);
    Fixture {
        outcome: outcome.unwrap(),
        origin,
        handshake,
        late,
        consumed,
    }
}

#[tokio::test]
async fn real_tls_session_bridge_filters_late_tickets_across_the_first_one_byte_write() {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for tls13 in [false, true] {
            for tickets in [2, 8] {
                for requested in if tls13 {
                    vec![2, 5, 8, usize::MAX]
                } else {
                    vec![0]
                } {
                    let Fixture {
                        outcome,
                        mut origin,
                        handshake,
                        late,
                        mut consumed,
                    } = fixture(tls13, tickets).await;
                    let mut expected = wire::hash(b"real-boundary-test", &handshake);
                    assert_eq!(
                        wire::sum::<8>(&outcome.transcript),
                        wire::sum::<8>(&expected)
                    );
                    assert_eq!(*consumed.borrow(), handshake.len());
                    let (raw, capture) = wrap(outcome.stream, outcome.transcript);
                    let mut user = crate::stream::wrap(
                        raw,
                        Vec::new(),
                        crate::stream::ReadMode::V2(Some(Box::new(outcome.session))),
                        crate::stream::WriteMode::V2(Some(capture.clone())),
                        kerlico_core::CancellationToken::new(),
                        crate::stream::test_owner(),
                    )
                    .unwrap();
                    let boundary = if tls13 {
                        assert!(!late.is_empty(), "真实 TLS1.3 握手必须产生票据记录");
                        let boundary = requested.min(late[0].len());
                        origin.write_all(&late[0][..boundary]).await.unwrap();
                        consumed
                            .wait_for(|count| *count == handshake.len() + boundary)
                            .await
                            .unwrap();
                        expected.update(&late[0][..boundary]);
                        boundary
                    } else {
                        assert!(late.is_empty());
                        0
                    };
                    user.write_all(b"x").await.unwrap();
                    user.flush().await.unwrap();
                    let first_business = wire::read(&mut origin).await.unwrap().unwrap();
                    let tag = wire::sum::<8>(&expected);
                    assert_eq!(first_business[0], wire::APP);
                    assert_eq!(
                        first_business.len(),
                        5 + 8 + 1,
                        "首个真实ShadowTLS业务写必须恰好1字节"
                    );
                    assert_eq!(&first_business[5..13], &tag);
                    assert_eq!(&first_business[13..], b"x");
                    assert!(capture.lock().unwrap().is_none());
                    for (index, record) in late.iter().enumerate() {
                        let remaining = if index == 0 {
                            &record[boundary..]
                        } else {
                            record.as_slice()
                        };
                        origin.write_all(remaining).await.unwrap();
                    }
                    let marker = b"server-business-after-tickets";
                    origin
                        .write_all(&wire::frame(wire::APP, marker))
                        .await
                        .unwrap();
                    let mut received = vec![0; marker.len()];
                    user.read_exact(&mut received).await.unwrap();
                    assert_eq!(
                        received, marker,
                        "真实票据不得作为业务明文泄漏，后继业务必须到达"
                    );
                    user.write_all(b"y").await.unwrap();
                    user.flush().await.unwrap();
                    assert_eq!(
                        &wire::read(&mut origin).await.unwrap().unwrap()[5..],
                        b"y",
                        "后续写不得重复首写标签"
                    );
                    origin
                        .write_all(&wire::frame(wire::APP, b"after-switch"))
                        .await
                        .unwrap();
                    origin.shutdown().await.unwrap();
                    let mut tail = Vec::new();
                    user.read_to_end(&mut tail).await.unwrap();
                    assert_eq!(tail, b"after-switch");
                    user.shutdown().await.unwrap();
                    assert!(wire::read(&mut origin).await.unwrap().is_none());
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "fixture": "real-tls-production-bridge-boundary", "tls13": tls13,
                            "tls13_tickets_configured": tickets, "late_record_count": late.len(),
                            "handshake_bytes": handshake.len(), "raw_late_prefix_bytes": boundary,
                            "first_shadowtls_write_bytes": 1, "first_business_tag": tag,
                            "first_late_record_bytes": late.first().map(Vec::len),
                            "real_tls_session_in_production_bridge": true,
                            "late_ticket_bytes_leaked": 0
                        })
                    );
                }
            }
        }
    })
    .await
    .expect("真实 TLS 分片与晚到票据边界夹具超时");
}
