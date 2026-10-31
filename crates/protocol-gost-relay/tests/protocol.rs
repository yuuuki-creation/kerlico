use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Error};
use kerlico_gost_relay::GostRelayFactory;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn context() -> ConnectContext {
    ConnectContext::new(Duration::from_secs(3))
}
fn target() -> Destination {
    Destination::new("192.0.2.11", 443).unwrap()
}
fn options(addr: std::net::SocketAddr) -> Value {
    json!({"server":{"host":addr.ip().to_string(),"port":addr.port()},"username":"synthetic-user","password":"synthetic-password"})
}
async fn request(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Vec<u8> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 1);
    let mut body = vec![0; u16::from_be_bytes([head[2], head[3]]) as usize];
    stream.read_exact(&mut body).await.unwrap();
    let mut bytes = head.to_vec();
    bytes.extend(body);
    bytes
}

#[test]
fn configuration_capabilities_and_no_association_fallback() {
    let factory = GostRelayFactory;
    let base = json!({"server":{"host":"127.0.0.1","port":10443}});
    let outbound = factory.build(&base).unwrap();
    assert!(outbound.capabilities().tcp_eof);
    assert!(outbound.capabilities().udp);
    assert!(!outbound.supports_udp_association());
    let mut mux = base.clone();
    mux["mux"] = json!(true);
    assert!(!factory.build(&mux).unwrap().capabilities().tcp_eof);
    for patch in [
        json!({"server":{"host":"192.0.2.1","port":443}}),
        json!({"server":{"host":"localhost","port":443}}),
        json!({"server":{"host":"127.0.0.1","port":0}}),
        json!({"username":"x".repeat(256)}),
        json!({"password":"x".repeat(256)}),
        json!({"mux_version":2}),
        json!({"response_mode":"unknown"}),
        json!({"forward_target":{"host":"example.invalid","port":443}}),
        json!({"tls":{"server_name":"test.invalid","skip_verify":true}}),
    ] {
        let mut value = base.clone();
        for (key, value_patch) in patch.as_object().unwrap() {
            value[key] = value_patch.clone();
        }
        assert!(factory.build(&value).is_err());
    }
    let remote = json!({"server":{"host":"192.0.2.1","port":443},"allow_insecure":true});
    assert!(factory.build(&remote).is_ok());
    let empty_password = json!({"server":{"host":"127.0.0.1","port":443},"username":"user"});
    assert!(factory.build(&empty_password).is_ok());
}

#[tokio::test]
async fn tcp_families_targets_features_prefetched_response_and_half_close() {
    for host in ["127.0.0.1", "::1"] {
        for website in [
            Destination::new("198.51.100.2", 80).unwrap(),
            Destination::new("2001:db8::2", 80).unwrap(),
            Destination::new("target.invalid", 80).unwrap(),
        ] {
            let listener = TcpListener::bind((host, 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let website_copy = website.clone();
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let bytes = request(&mut stream).await;
                assert_eq!(bytes[1], 1);
                assert!(bytes.windows(14).any(|w| w == b"synthetic-user"));
                assert!(bytes.windows(18).any(|w| w == b"synthetic-password"));
                let expected_type = match website_copy.address() {
                    kerlico_core::Address::Ip(ip) if ip.is_ipv4() => 1,
                    kerlico_core::Address::Ip(_) => 4,
                    _ => 3,
                };
                let mut pos = 4;
                let mut address_count = 0;
                while pos < bytes.len() {
                    let n = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                    if bytes[pos] == 2 {
                        assert_eq!(bytes[pos + 3], expected_type);
                        address_count += 1;
                    }
                    pos += 3 + n;
                }
                assert_eq!(address_count, 1);
                // 未知扩展与问候同一次写；客户端只能吃掉扩展，不能吞业务。
                stream
                    .write_all(&[1, 0, 0, 5, 99, 0, 2, 8, 9, b'h', b'i'])
                    .await
                    .unwrap();
                let mut body = Vec::new();
                stream.read_to_end(&mut body).await.unwrap();
                assert_eq!(body, vec![0x93; 65537]);
                stream.write_all(b"after-fin").await.unwrap();
            });
            let outbound = GostRelayFactory.build(&options(addr)).unwrap();
            let ctx = context();
            let mut stream = outbound.connect_tcp(&website, &ctx).await.unwrap();
            let mut greeting = [0; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"hi");
            stream.write_all(&vec![0x93; 65537]).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(&reply, b"after-fin");
            peer.await.unwrap();
        }
    }
}

#[tokio::test]
async fn fixed_forward_checks_before_dial_and_omits_address() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut value = options(addr);
    value["forward_target"] = json!({"host":"192.0.2.11","port":443});
    let outbound = GostRelayFactory.build(&value).unwrap();
    let ctx = context();
    assert!(matches!(
        outbound
            .connect_tcp(&Destination::new("192.0.2.12", 443).unwrap(), &ctx)
            .await,
        Err(Error::Unsupported(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let bytes = request(&mut stream).await;
        let mut p = 4;
        while p < bytes.len() {
            assert_ne!(bytes[p], 2);
            p += 3 + u16::from_be_bytes([bytes[p + 1], bytes[p + 2]]) as usize;
        }
        stream.write_all(&[1, 0, 0, 0]).await.unwrap();
    });
    drop(outbound.connect_tcp(&target(), &ctx).await.unwrap());
    peer.await.unwrap();
}

#[tokio::test]
async fn udp_packet_boundaries_large_zero_and_oversize_without_truncation() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let bytes = request(&mut stream).await;
        assert_eq!(bytes[1], 0x81);
        assert_eq!(&bytes[bytes.len() - 5..], &[4, 0, 2, 0, 1]);
        stream.write_all(&[1, 0, 0, 0]).await.unwrap();
        for len in [0, 17, 12000, 65507, 3] {
            let mut head = [0; 2];
            stream.read_exact(&mut head).await.unwrap();
            assert_eq!(u16::from_be_bytes(head) as usize, len);
            let mut body = vec![0; len];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, vec![0xab; len]);
            stream.write_all(&head).await.unwrap();
            stream.write_all(&body).await.unwrap();
        }
    });
    let outbound = GostRelayFactory.build(&options(addr)).unwrap();
    let ctx = context();
    let mut channel = outbound.connect_udp(&target(), &ctx).await.unwrap();
    assert_eq!(channel.receiver.peer_addr(), Some(target()));
    for len in [0, 17, 12000, 65507, 3] {
        if len == 3 {
            assert!(channel.sender.send(&vec![0; 65508]).await.is_err());
        }
        let bytes = vec![0xab; len];
        channel.sender.send(&bytes).await.unwrap();
        assert_eq!(channel.receiver.recv().await.unwrap(), Some(bytes));
    }
    peer.await.unwrap();
    drop(channel);
}

#[tokio::test]
async fn response_rejection_truncation_and_unsupported_association_do_not_send_payload() {
    for status in 1..=9 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            stream.write_all(&[1, status, 255, 255]).await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert!(bytes.is_empty());
        });
        let outbound = GostRelayFactory.build(&options(addr)).unwrap();
        let ctx = context();
        assert!(outbound.connect_tcp(&target(), &ctx).await.is_err());
        assert!(outbound.associate_udp(&ctx).await.is_err());
        peer.await.unwrap();
    }
    for response in [
        vec![2, 0, 0, 0],
        vec![1, 0, 0, 3, 99, 0],
        vec![1, 0, 0, 4, 4, 0, 1, 1],
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            stream.write_all(&response).await.unwrap();
        });
        let outbound = GostRelayFactory.build(&options(addr)).unwrap();
        assert!(outbound.connect_tcp(&target(), &context()).await.is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn deferred_response_sends_first_payload_and_preserves_fragment_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        request(&mut stream).await;
        let mut payload = [0; 5];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"hello");
        stream.write_all(&[1, 0]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        stream
            .write_all(&[0, 5, 99, 0, 2, 8, 9, b'w', b'o', b'r', b'l', b'd'])
            .await
            .unwrap();
    });
    let mut value = options(addr);
    value["response_mode"] = json!("deferred");
    let outbound = GostRelayFactory.build(&value).unwrap();
    let ctx = context();
    let mut stream = outbound.connect_tcp(&target(), &ctx).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let mut one = [0; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(10), stream.read(&mut one))
            .await
            .is_err()
    );
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    assert_eq!(&body, b"world");
    peer.await.unwrap();
}

#[tokio::test]
async fn deferred_status_and_deadline_are_reported_before_business_bytes() {
    for status in [2, 4, 7] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request(&mut stream).await;
            stream.write_all(&[1, status, 0, 0, b'x']).await.unwrap();
            let mut tail = Vec::new();
            let _ = stream.read_to_end(&mut tail).await;
        });
        let mut value = options(addr);
        value["response_mode"] = json!("deferred");
        let outbound = GostRelayFactory.build(&value).unwrap();
        let mut stream = outbound.connect_tcp(&target(), &context()).await.unwrap();
        assert!(stream.read(&mut [0; 1]).await.is_err());
        assert!(stream.write_all(b"must-fail").await.is_err());
        drop(stream);
        peer.await.unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        request(&mut stream).await;
        let mut tail = Vec::new();
        let _ = stream.read_to_end(&mut tail).await;
        assert!(tail.is_empty());
    });
    let mut value = options(addr);
    value["response_mode"] = json!("deferred");
    let outbound = GostRelayFactory.build(&value).unwrap();
    let ctx = ConnectContext::new(Duration::from_millis(50));
    let mut stream = outbound.connect_tcp(&target(), &ctx).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .is_err()
    );
    drop(stream);
    peer.await.unwrap();
}

#[tokio::test]
async fn establish_timeout_cancel_active_stream_and_drop_release_real_socket() {
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let addr = listener.local_addr().unwrap();
    let peer_listener = listener.clone();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = peer_listener.accept().await.unwrap();
        request(&mut stream).await;
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    });
    let outbound = GostRelayFactory.build(&options(addr)).unwrap();
    let short = ConnectContext::new(Duration::from_millis(40));
    assert!(matches!(
        outbound.connect_tcp(&target(), &short).await,
        Err(Error::Timeout)
    ));
    peer.await.unwrap();
    let pre = context();
    pre.cancel.cancel();
    assert!(matches!(
        outbound.connect_tcp(&target(), &pre).await,
        Err(Error::Cancelled)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        request(&mut stream).await;
        stream.write_all(&[1, 0, 0, 0]).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    });
    let active = context();
    let mut stream = outbound.connect_tcp(&target(), &active).await.unwrap();
    active.cancel.cancel();
    assert!(stream.read(&mut [0; 1]).await.is_err());
    drop(stream);
    peer.await.unwrap();
}

#[tokio::test]
async fn tls_validates_name_and_issuer_before_authentication() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["relay.test.invalid".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        for valid in [true, false, false] {
            let (stream, _) = listener.accept().await.unwrap();
            let result = acceptor.accept(stream).await;
            if valid {
                let mut stream = result.unwrap();
                request(&mut stream).await;
                stream.write_all(&[1, 0, 0, 0]).await.unwrap();
                stream.write_all(b"verified").await.unwrap();
            } else {
                assert!(result.is_err());
            }
        }
    });
    for (name, ca, valid) in [
        ("relay.test.invalid", Some(cert.pem()), true),
        ("wrong.test.invalid", Some(cert.pem()), false),
        ("relay.test.invalid", None, false),
    ] {
        let mut value = options(addr);
        value["tls"] = json!({"server_name":name,"ca_pem":ca});
        let outbound = GostRelayFactory.build(&value).unwrap();
        assert!(!outbound.capabilities().tcp_eof);
        let result = outbound.connect_tcp(&target(), &context()).await;
        if valid {
            let mut stream = result.unwrap();
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"verified");
        } else {
            assert!(result.is_err());
        }
    }
    peer.await.unwrap();
}
