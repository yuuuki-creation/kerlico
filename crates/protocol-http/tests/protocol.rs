use kerlico_config::{OutboundFactory, Registry, parse};
use kerlico_core::{CancellationToken, ConnectContext, Destination};
use kerlico_engine::Engine;
use kerlico_http::{HttpFactory, HttpNodeFactory};
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

async fn node(
    options: Value,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<kerlico_core::Result<()>>,
) {
    node_limits(
        options,
        json!({"connect_timeout_ms":1000,"idle_timeout_ms":2000,"drain_timeout_ms":50}),
    )
    .await
}

async fn node_limits(
    options: Value,
    limits: Value,
) -> (
    SocketAddr,
    CancellationToken,
    tokio::task::JoinHandle<kerlico_core::Result<()>>,
) {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(HttpNodeFactory).unwrap();
    let config = json!({"version":1,"outbounds":[{"tag":"exit","type":"direct"}],"inbounds":[],"local_inbounds":[{"tag":"node","type":"http","listen":"127.0.0.1:0","outbound":"exit","options":options}],"limits":limits});
    let engine = Engine::bind(
        registry
            .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
            .unwrap(),
    )
    .await
    .unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(engine.run(cancel.clone()));
    (address, cancel, task)
}

#[tokio::test]
async fn plain_tls_connect_preserves_half_close() {
    for tls in [false, true] {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let mut server = json!({"auth":{"username":"proxy-test","password":"synthetic-secret"}});
        let mut client = server.clone();
        if tls {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            server["tls"] =
                json!({"cert_pem":cert.cert.pem(),"key_pem":cert.signing_key.serialize_pem()});
            client["tls"] = json!({"server_name":"localhost","ca_pem":cert.cert.pem()});
        }
        let (address, cancel, task) = node(server).await;
        client["server"] = json!({"host":"127.0.0.1","port":address.port()});
        let outbound = HttpFactory.build(&client).unwrap();
        let mut stream = outbound
            .connect_tcp(
                &Destination::new("localhost", port).unwrap(),
                &ConnectContext::new(Duration::from_secs(3)),
            )
            .await
            .unwrap();
        stream.write_all(b"half-close").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes, b"half-close");
        peer.await.unwrap();
        drop(stream);
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn outbound_does_not_drop_prefetched_payload_and_rejects_failure() {
    for status in [200, 299, 407] {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = peer.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = peer.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
            stream
                .write_all(format!("HTTP/1.1 {status} test\r\n\r\nfirst-payload").as_bytes())
                .await
                .unwrap();
        });
        let out = HttpFactory
            .build(&json!({"server":{"host":"127.0.0.1","port":port}}))
            .unwrap();
        let result = out
            .connect_tcp(
                &Destination::new("example.invalid", 443).unwrap(),
                &ConnectContext::new(Duration::from_secs(2)),
            )
            .await;
        if status == 407 {
            assert!(result.is_err());
        } else {
            let mut stream = result.unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"first-payload");
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn ordinary_post_strips_hop_and_proxy_auth_and_streams_chunks() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = origin.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        let text = String::from_utf8(header).unwrap().to_lowercase();
        assert!(text.starts_with("post /upload?q=1 http/1.1"));
        assert!(!text.contains("proxy-authorization"));
        assert!(!text.contains("x-hop:"));
        let mut body = vec![0; 11];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, b"hello-world");
        stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close, X-Hop\r\nX-Hop: hidden\r\n\r\n5\r\nhello\r\n6\r\n-world\r\n0\r\n\r\n").await.unwrap();
    });
    let (address, cancel, task) = node(json!({"auth":{"username":"a","password":"b"}})).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("POST http://127.0.0.1:{port}/upload?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Authorization: Basic YTpi\r\nConnection: close, X-Hop\r\nX-Hop: hidden\r\nContent-Length: 11\r\n\r\nhello-world").as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(!response.to_lowercase().contains("x-hop:"));
    assert!(response.contains("hello"));
    assert!(response.contains("-world"));
    peer.await.unwrap();
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn wrong_auth_and_conflicting_host_are_rejected() {
    let (address, cancel, task) = node(json!({"auth":{"username":"a","password":"b"}})).await;
    let out=HttpFactory.build(&json!({"server":{"host":"127.0.0.1","port":address.port()},"auth":{"username":"a","password":"wrong"}})).unwrap();
    assert!(
        out.connect_tcp(
            &Destination::new("127.0.0.1", 9).unwrap(),
            &ConnectContext::new(Duration::from_secs(2))
        )
        .await
        .is_err()
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (address, cancel, task) = node(json!({})).await;
    for request in [
        "GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
        "CONNECT example.invalid HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
        "GET https://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n",
    ] {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert!(bytes.starts_with(b"HTTP/1.1 400"));
    }
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn active_tunnel_drains_and_listener_can_be_rebound() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });
    let (address, cancel, task) = node_limits(
        json!({}),
        json!({"connect_timeout_ms":1000,"idle_timeout_ms":2000,"drain_timeout_ms":1000}),
    )
    .await;
    let out = HttpFactory
        .build(&json!({"server":{"host":"127.0.0.1","port":address.port()}}))
        .unwrap();
    let mut stream = out
        .connect_tcp(
            &Destination::new("127.0.0.1", port).unwrap(),
            &ConnectContext::new(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    stream.write_all(b"before").await.unwrap();
    let mut bytes = [0; 6];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"before");
    cancel.cancel();
    stream.write_all(b"during").await.unwrap();
    timeout(Duration::from_secs(1), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"during");
    stream.shutdown().await.unwrap();
    let mut tail = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    peer.await.unwrap();
    let rebound = TcpListener::bind(address).await.unwrap();
    drop(rebound);
}

#[tokio::test]
async fn slow_headers_and_connect_request_bodies_are_rejected() {
    let (address, cancel, task) = node_limits(
        json!({}),
        json!({"connect_timeout_ms":60,"idle_timeout_ms":1000,"drain_timeout_ms":30}),
    )
    .await;
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"GET http://example.invalid/")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(1), slow.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.is_empty() || bytes.starts_with(b"HTTP/1.1 408"));
    let mut body = TcpStream::connect(address).await.unwrap();
    body.write_all(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").await.unwrap();
    bytes.clear();
    timeout(Duration::from_secs(1), body.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.starts_with(b"HTTP/1.1 400"));
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn ordinary_get_head_and_chunked_post_keep_message_boundaries() {
    for method in ["GET", "HEAD", "POST"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
            let text = String::from_utf8(header).unwrap();
            assert!(text.starts_with(&format!("{method} /resource HTTP/1.1")));
            if method == "POST" {
                let mut body = Vec::<u8>::new();
                loop {
                    let mut line = Vec::new();
                    while !line.ends_with(b"\r\n") {
                        line.push(stream.read_u8().await.unwrap());
                    }
                    let size = usize::from_str_radix(
                        std::str::from_utf8(&line[..line.len() - 2])
                            .unwrap()
                            .split(';')
                            .next()
                            .unwrap(),
                        16,
                    )
                    .unwrap();
                    if size == 0 {
                        let mut end = [0; 2];
                        stream.read_exact(&mut end).await.unwrap();
                        assert_eq!(end, *b"\r\n");
                        break;
                    }
                    let mut bytes = vec![0; size + 2];
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes[size..], b"\r\n");
                    body.extend(&bytes[..size]);
                }
                assert_eq!(body, b"helloworld");
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            if method != "HEAD" {
                stream.write_all(b"hello").await.unwrap();
            }
        });
        let (address, cancel, task) = node(json!({})).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        let body = if method == "POST" {
            "Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"
        } else {
            "\r\n"
        };
        let request = format!(
            "{method} http://127.0.0.1:{port}/resource HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n{body}"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        if method == "HEAD" {
            assert!(response.ends_with(b"\r\n\r\n"));
        } else {
            assert!(response.ends_with(b"hello"));
        }
        peer.await.unwrap();
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
