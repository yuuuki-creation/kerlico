use kerlico_config::{OutboundFactory, TargetSpec};
use kerlico_core::{ConnectContext, Destination, Error, Outbound};
use kerlico_net::TcpConnector;
use kerlico_vless::{
    UserId, VlessFactory, VlessOutbound,
    codec::{self, Command},
};
use rustls::{
    ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde_json::json;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::Duration,
};
use tokio_rustls::TlsAcceptor;

fn certificate() -> (String, TlsAcceptor) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = key.cert.pem();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![key.cert.der().clone()], private)
            .unwrap();
    (pem, TlsAcceptor::from(Arc::new(config)))
}

#[tokio::test]
async fn tcp_tls_reads_response_after_first_application_write() {
    let (pem, acceptor) = certificate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let header = codec::read_request(&mut stream).await.unwrap();
        assert!(header.user.matches(&UserId::from_bytes([0; 16])));
        assert_eq!(header.command, Command::Tcp);
        assert_eq!(header.target.host(), "example.invalid");
        let mut data = [0; 5];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"hello");
        codec::write_response(&mut stream).await.unwrap();
        stream.write_all(b"reply").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let outbound = VlessOutbound::new(
        Destination::new("127.0.0.1", address.port()).unwrap(),
        UserId::from_bytes([0; 16]),
        TcpConnector::tls("localhost", Some(&pem)).unwrap(),
    )
    .unwrap();
    let context = ConnectContext::new(Duration::from_secs(2));
    let target = Destination::new("example.invalid", 443).unwrap();
    let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply");
    peer.await.unwrap();
}

#[tokio::test]
async fn udp_tls_halves_can_send_and_receive_concurrently() {
    let (pem, acceptor) = certificate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let header = codec::read_request(&mut stream).await.unwrap();
        assert_eq!(header.command, Command::Udp);
        codec::write_response(&mut stream).await.unwrap();
        for _ in 0..3 {
            let packet = codec::read_datagram(&mut stream, 65_535)
                .await
                .unwrap()
                .unwrap();
            codec::write_datagram(&mut stream, &packet).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });
    let outbound = VlessOutbound::new(
        Destination::new("127.0.0.1", port).unwrap(),
        UserId::from_bytes([0; 16]),
        TcpConnector::tls("localhost", Some(&pem)).unwrap(),
    )
    .unwrap();
    let context = ConnectContext::new(Duration::from_secs(2));
    let channel = outbound
        .connect_udp(&Destination::new("example.invalid", 53).unwrap(), &context)
        .await
        .unwrap();
    let mut sender = channel.sender;
    let mut receiver = channel.receiver;
    let write = async {
        for bytes in [b"one".as_slice(), b"".as_slice(), b"two".as_slice()] {
            sender.send(bytes).await.unwrap();
        }
    };
    let read = async {
        for bytes in [b"one".as_slice(), b"".as_slice(), b"two".as_slice()] {
            assert_eq!(receiver.recv().await.unwrap().unwrap(), bytes);
        }
        assert!(receiver.recv().await.unwrap().is_none());
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(write, read);
    })
    .await
    .unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn rejects_untrusted_or_wrong_name_certificates() {
    for trusted in [false, true] {
        let (pem, acceptor) = certificate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        let connector = TcpConnector::tls(
            if trusted {
                "wrong.invalid"
            } else {
                "localhost"
            },
            if trusted { Some(&pem) } else { None },
        )
        .unwrap();
        let outbound = VlessOutbound::new(
            Destination::new("127.0.0.1", port).unwrap(),
            UserId::from_bytes([0; 16]),
            connector,
        )
        .unwrap();
        let context = ConnectContext::new(Duration::from_secs(2));
        assert!(
            outbound
                .connect_tcp(&Destination::new("example.invalid", 443).unwrap(), &context)
                .await
                .is_err()
        );
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn handshake_uses_one_timeout_and_cancellation_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let outbound = VlessOutbound::new(
        Destination::new("127.0.0.1", port).unwrap(),
        UserId::from_bytes([0; 16]),
        TcpConnector::tls("localhost", None).unwrap(),
    )
    .unwrap();
    let context = ConnectContext::new(Duration::from_millis(30));
    assert!(matches!(
        outbound
            .connect_tcp(&Destination::new("example.invalid", 443).unwrap(), &context)
            .await,
        Err(Error::Timeout)
    ));
    context.cancel.cancel();
    assert!(matches!(
        outbound
            .connect_tcp(&Destination::new("example.invalid", 443).unwrap(), &context)
            .await,
        Err(Error::Cancelled)
    ));
    peer.abort();
    let _ = peer.await;
}

#[test]
fn configuration_fails_closed_and_user_ids_are_redacted() {
    let base = json!({"server":{"host":"server.invalid","port":443},"uuid":"00000000-0000-0000-0000-000000000000"});
    assert!(VlessFactory.build(&base).is_ok());
    for (key, value) in [
        ("transport", json!("xhttp")),
        ("flow", json!("xtls-rprx-vision")),
        ("encryption", json!("future")),
        ("security", json!({"type":"reality"})),
        ("mux", json!(true)),
        ("security", json!({"type":"none"})),
    ] {
        let mut options = base.clone();
        options[key] = value;
        assert!(VlessFactory.build(&options).is_err());
    }
    let mut invalid = base;
    invalid["uuid"] = json!("synthetic-invalid-identifier");
    let error = VlessFactory.build(&invalid).err().unwrap().to_string();
    assert!(!error.contains("synthetic-invalid-identifier"));
    assert!(
        VlessOutbound::new(
            TargetSpec {
                host: "server.invalid".into(),
                port: 443
            }
            .destination()
            .unwrap(),
            UserId::from_bytes([0; 16]),
            TcpConnector::plain()
        )
        .is_err()
    );
}

#[test]
fn eof_dependent_forward_requires_a_compatible_outbound() {
    let mut registry = kerlico_config::Registry::default();
    registry.register(VlessFactory).unwrap();
    let config = json!({"version":1,"outbounds":[{"tag":"proxy","type":"vless","options":{"server":{"host":"server.invalid","port":443},"uuid":"00000000-0000-0000-0000-000000000000"}}],"inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"target.invalid","port":443},"outbound":"proxy","require_remote_eof":true}]});
    let prepared =
        registry.prepare(kerlico_config::parse(&serde_json::to_vec(&config).unwrap()).unwrap());
    assert!(matches!(prepared,Err(Error::Config(message)) if message.contains("EOF")));
}
