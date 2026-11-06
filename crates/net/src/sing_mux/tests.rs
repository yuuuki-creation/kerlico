use super::{
    frame::{Codec, FrameSession},
    padding::PaddedIo,
    wire::{SessionRequest, SocksAddr, StreamKind, StreamRequest, encode_error_status},
    *,
};
use kerlico_core::BoxStream;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 模拟 sing-mux 服务端：状态字节随首个下行数据写出；目标端口 1 返回错误。
async fn echo_stream(mut stream: BoxStream) {
    let request = StreamRequest::read(&mut stream).await.unwrap();
    if request.addr.port == 1 {
        stream
            .write_all(&encode_error_status("dial refused"))
            .await
            .unwrap();
        let _ = stream.shutdown().await;
        return;
    }
    let mut first = true;
    let mut buf = vec![0u8; 70_000];
    loop {
        let frame = match request.kind {
            StreamKind::Tcp => {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    let _ = stream.shutdown().await;
                    return;
                }
                buf[..n].to_vec()
            }
            StreamKind::Udp => {
                let Ok(len) = stream.read_u16().await else {
                    return;
                };
                let mut p = vec![0u8; usize::from(len)];
                stream.read_exact(&mut p).await.unwrap();
                [&len.to_be_bytes()[..], &p].concat()
            }
            StreamKind::UdpPacketAddr => {
                let Ok(addr) = SocksAddr::read(&mut stream).await else {
                    return;
                };
                let len = stream.read_u16().await.unwrap();
                let mut p = vec![0u8; usize::from(len)];
                stream.read_exact(&mut p).await.unwrap();
                let mut out = Vec::new();
                addr.encode_into(&mut out).unwrap();
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(&p);
                out
            }
        };
        let out = if std::mem::take(&mut first) {
            [&[0u8][..], &frame].concat()
        } else {
            frame
        };
        stream.write_all(&out).await.unwrap();
    }
}

async fn reference_server(mut carrier: tokio::io::DuplexStream, expect_padding: bool) {
    let request = SessionRequest::read(&mut carrier).await.unwrap();
    assert_eq!(request.padding, expect_padding);
    let io: BoxStream = if request.padding {
        Box::new(PaddedIo::new(carrier))
    } else {
        Box::new(carrier)
    };
    match request.protocol {
        SingMuxProtocol::H2Mux => {
            h2mux::serve(io, tokio_util::sync::CancellationToken::new(), |s| {
                tokio::spawn(echo_stream(Box::new(s)));
            })
            .await
            .unwrap();
        }
        protocol => {
            let codec = if protocol == SingMuxProtocol::Smux {
                Codec::Smux
            } else {
                Codec::Yamux
            };
            let (_session, mut accept) = FrameSession::server(io, codec);
            while let Some(s) = accept.recv().await {
                tokio::spawn(echo_stream(Box::new(s)));
            }
        }
    }
}

fn client_for(protocol: SingMuxProtocol, padding: bool) -> SingMuxClient {
    let config = SingMuxOutboundConfig {
        enabled: true,
        protocol,
        max_connections: Some(1),
        min_streams: Some(4),
        padding,
        ..Default::default()
    };
    config.validate().unwrap();
    SingMuxClient::new(config)
}

#[tokio::test]
async fn client_speaks_sing_mux_to_reference_server_for_every_protocol() {
    for protocol in [
        SingMuxProtocol::Smux,
        SingMuxProtocol::Yamux,
        SingMuxProtocol::H2Mux,
    ] {
        for padding in [false, true] {
            let client = Arc::new(client_for(protocol, padding));
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            tokio::spawn(reference_server(theirs, padding));
            let target = Destination::new("example.com", 443).unwrap();
            let opened = client
                .connect_tcp(&target, |_| async move { Ok(Box::new(ours) as BoxStream) })
                .await
                .unwrap();
            let mut tasks = vec![tokio::spawn(echo_check(opened.stream, 300_000))];
            for i in 0..8 {
                let client = client.clone();
                let target = target.clone();
                tasks.push(tokio::spawn(async move {
                    let opened = client
                        .connect_tcp(&target, |_| async {
                            Err(Error::Protocol("不应新建载体"))
                        })
                        .await
                        .unwrap();
                    echo_check(opened.stream, 20_000 + i).await;
                }));
            }
            for t in tasks {
                t.await.unwrap();
            }

            let refused = Destination::new("example.com", 1).unwrap();
            let mut failed = client
                .connect_tcp(&refused, |_| async {
                    Err(Error::Protocol("不应新建载体"))
                })
                .await
                .unwrap()
                .stream;
            let err = failed.read_u8().await.unwrap_err();
            assert!(
                err.to_string().contains("dial refused"),
                "{protocol:?} {err}"
            );

            let mut channel = client
                .connect_udp(&target, |_| async {
                    Err(Error::Protocol("不应新建载体"))
                })
                .await
                .unwrap();
            for size in [0usize, 1, 1400] {
                let packet = vec![size as u8; size];
                channel.sender.send(&packet).await.unwrap();
                assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), packet);
            }

            let mut association = client
                .associate_udp(|_| async { Err(Error::Protocol("不应新建载体")) })
                .await
                .unwrap();
            let dns = Destination::new("1.1.1.1", 53).unwrap();
            association.sender.send_to(b"query", &dns).await.unwrap();
            let (source, payload) = association.receiver.recv_from().await.unwrap().unwrap();
            assert_eq!((source, payload), (dns, b"query".to_vec()));
        }
    }
}

async fn echo_check(stream: BoxStream, size: usize) {
    let payload: Vec<u8> = (0..size).map(|i| (i % 249) as u8).collect();
    let (mut r, mut w) = tokio::io::split(stream);
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w
    });
    let mut back = vec![0u8; size];
    r.read_exact(&mut back).await.unwrap();
    assert_eq!(back, payload);
    writer.await.unwrap();
}

#[tokio::test]
async fn pool_reuses_sessions_like_sing_mux_select_session() {
    let client = client_for(SingMuxProtocol::Smux, false);
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    tokio::spawn(reference_server(theirs, false));
    let target = Destination::new("example.com", 443).unwrap();
    let mut held = Vec::new();
    held.push(
        client
            .connect_tcp(&target, |_| async move { Ok(Box::new(ours) as BoxStream) })
            .await
            .unwrap(),
    );
    for _ in 0..5 {
        held.push(
            client
                .connect_tcp(&target, |_| async {
                    Err(Error::Protocol("不应新建载体"))
                })
                .await
                .unwrap(),
        );
    }
    assert_eq!(client.sessions.lock().await.len(), 1);

    let unlimited = SingMuxClient::new(SingMuxOutboundConfig {
        enabled: true,
        protocol: SingMuxProtocol::Smux,
        ..Default::default()
    });
    let (a, b) = tokio::io::duplex(64 * 1024);
    tokio::spawn(reference_server(b, false));
    let _first = unlimited
        .connect_tcp(&target, |_| async move { Ok(Box::new(a) as BoxStream) })
        .await
        .unwrap();
    let busy = unlimited
        .connect_tcp(&target, |_| async {
            Err(Error::Protocol("需要新载体"))
        })
        .await;
    assert!(
        busy.is_err(),
        "默认配置下忙会话不承接新流，与 sing-mux 一致"
    );
}

#[test]
fn inbound_brutal_is_rejected_and_outbound_brutal_needs_rates() {
    let err = serde_json::from_value::<SingMuxInboundConfig>(
        serde_json::json!({"enabled": true, "brutal": {"enabled": true, "up_mbps": 1, "down_mbps": 1}}),
    )
    .unwrap_err();
    assert!(err.to_string().contains("Brutal"));
    let config: SingMuxOutboundConfig = serde_json::from_value(serde_json::json!({
        "enabled": true, "protocol": "smux", "brutal": {"enabled": true, "up_mbps": 10, "down_mbps": 0}
    }))
    .unwrap();
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn brutal_exchange_refusal_fails_the_new_session() {
    let client = SingMuxClient::new(SingMuxOutboundConfig {
        enabled: true,
        protocol: SingMuxProtocol::Yamux,
        brutal: Some(SingMuxBrutalConfig {
            enabled: true,
            up_mbps: 10,
            down_mbps: 50,
        }),
        ..Default::default()
    });
    let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        SessionRequest::read(&mut theirs).await.unwrap();
        let (_session, mut accept) = FrameSession::server(theirs, Codec::Yamux);
        let mut s = accept.recv().await.unwrap();
        let request = StreamRequest::read(&mut s).await.unwrap();
        assert!(request.addr.is_domain(wire::BRUTAL_EXCHANGE_DOMAIN));
        assert_eq!(s.read_u64().await.unwrap(), 50 * 125_000);
        let mut out = vec![0u8];
        out.extend_from_slice(&wire::encode_brutal_response(
            None,
            wire::BRUTAL_DISABLED_MESSAGE,
        ));
        s.write_all(&out).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    });
    let target = Destination::new("example.com", 443).unwrap();
    let err = client
        .connect_tcp(&target, |_| async move { Ok(Box::new(ours) as BoxStream) })
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("brutal is not enabled"), "{err}");
}
