mod common;

use common::*;
use kerlico_core::CancellationToken;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

struct Reply {
    status: u16,
    body: Vec<u8>,
}
async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &str,
    body: &[u8],
) -> Reply {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    timeout(WAIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let end = response
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .expect("完整HTTP响应");
    let text = std::str::from_utf8(&response[..end]).unwrap();
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        body: response[end + 4..].to_vec(),
    }
}
async fn session(address: std::net::SocketAddr, mode: &str) -> String {
    let reply = request(
        address,
        "GET",
        "/gate/session",
        &format!("X-Sudoku-Tunnel: {mode}\r\n"),
        &[],
    )
    .await;
    assert_eq!(reply.status, 200);
    let text = String::from_utf8(reply.body).unwrap();
    text.lines()
        .find_map(|line| line.strip_prefix("token="))
        .unwrap()
        .to_owned()
}
async fn fixture(mode: &str, ttl: u64, max: usize) -> Running {
    let mut node = node_options(mode, KEY, "chacha20-poly1305");
    node["http_mask"]["path_root"] = json!("gate");
    node["http_session_ttl_ms"] = json!(ttl);
    node["max_http_sessions"] = json!(max);
    Running::start(
        configuration(node, false, false),
        Arc::new(State::default()),
    )
    .await
}

#[tokio::test]
async fn http_paths_methods_query_and_mode_controls_do_not_reach_egress() {
    let server = fixture("auto", 30000, 16).await;
    let address = server.addresses["node"];
    for (method, path, headers, status) in [
        ("GET", "/session", "X-Sudoku-Tunnel: stream\r\n", 404),
        (
            "GET",
            "/gate-other/session",
            "X-Sudoku-Tunnel: stream\r\n",
            404,
        ),
        ("GET", "/gate/session", "", 404),
        ("GET", "/gate/session", "X-Sudoku-Tunnel: unknown\r\n", 404),
        ("POST", "/gate/session", "X-Sudoku-Tunnel: stream\r\n", 405),
        (
            "GET",
            "/gate/session?ed=%%",
            "X-Sudoku-Tunnel: stream\r\n",
            400,
        ),
        (
            "GET",
            "/gate/session?ed=a&ed=b",
            "X-Sudoku-Tunnel: stream\r\n",
            400,
        ),
        (
            "GET",
            "/gate/stream?token=unknown",
            "X-Sudoku-Tunnel: stream\r\n",
            404,
        ),
        (
            "POST",
            "/gate/api/v1/upload?token=unknown",
            "X-Sudoku-Tunnel: poll\r\n",
            404,
        ),
    ] {
        assert_eq!(
            request(address, method, path, headers, &[]).await.status,
            status,
            "{method} {path}"
        );
    }
    server.close().await;
    let server = fixture("stream", 30000, 16).await;
    assert_eq!(
        request(
            server.addresses["node"],
            "GET",
            "/gate/session",
            "X-Sudoku-Tunnel: poll\r\n",
            &[]
        )
        .await
        .status,
        404
    );
    server.close().await;
}

#[tokio::test]
async fn actual_http_upload_sequence_duplicate_conflict_gap_and_close() {
    for mode in ["stream", "poll"] {
        let server = fixture("auto", 30000, 16).await;
        let address = server.addresses["node"];
        let token = session(address, mode).await;
        let headers = format!("X-Sudoku-Tunnel: {mode}\r\n");
        let base = format!("/gate/api/v1/upload?token={token}");
        let empty = if mode == "poll" {
            b"\n".as_slice()
        } else {
            b"".as_slice()
        };
        assert_eq!(
            request(address, "POST", &format!("{base}&seq=1"), &headers, empty)
                .await
                .status,
            200
        );
        assert_eq!(
            request(address, "POST", &format!("{base}&seq=1"), &headers, empty)
                .await
                .status,
            200
        );
        let conflict = if mode == "poll" {
            b"eA==\n".as_slice()
        } else {
            b"x".as_slice()
        };
        assert_eq!(
            request(
                address,
                "POST",
                &format!("{base}&seq=1"),
                &headers,
                conflict
            )
            .await
            .status,
            409
        );
        assert_eq!(
            request(address, "POST", &format!("{base}&seq=3"), &headers, empty)
                .await
                .status,
            409
        );
        assert_eq!(
            request(address, "POST", &format!("{base}&seq=2"), &headers, empty)
                .await
                .status,
            200
        );
        assert_eq!(
            request(address, "POST", &format!("{base}&seq=0"), &headers, empty)
                .await
                .status,
            409
        );
        assert_eq!(
            request(address, "POST", &format!("{base}&close=1"), &headers, &[])
                .await
                .status,
            200
        );
        assert_eq!(
            request(address, "POST", &format!("{base}&seq=3"), &headers, empty)
                .await
                .status,
            404
        );
        server.close().await;
    }
}

#[tokio::test]
async fn http_tokens_are_node_and_mode_bound_expire_and_release_quota() {
    let state = Arc::new(State::default());
    let mut node = node_options("auto", KEY, "aes-128-gcm");
    node["http_mask"]["path_root"] = json!("gate");
    node["http_session_ttl_ms"] = json!(100);
    node["max_http_sessions"] = json!(1);
    let mut config = configuration(node, false, false);
    let mut second = config["nodes"][0].clone();
    second["tag"] = json!("node6");
    second["listen"] = json!("[::1]:0");
    second["options"]["protocol"]["key"] = json!(OTHER_KEY);
    config["nodes"].as_array_mut().unwrap().push(second);
    let server = Running::start(config, state).await;
    let first = server.addresses["node"];
    let other = server.addresses["node6"];
    let token = session(first, "stream").await;
    let upload = format!("/gate/api/v1/upload?token={token}&seq=1");
    assert_eq!(
        request(other, "POST", &upload, "X-Sudoku-Tunnel: stream\r\n", &[])
            .await
            .status,
        404
    );
    assert_eq!(
        request(first, "POST", &upload, "X-Sudoku-Tunnel: poll\r\n", &[])
            .await
            .status,
        404
    );
    assert_eq!(
        request(
            first,
            "GET",
            "/gate/session",
            "X-Sudoku-Tunnel: stream\r\n",
            &[]
        )
        .await
        .status,
        503
    );
    // 这里只等待明确配置的TTL和清扫周期。
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        request(first, "POST", &upload, "X-Sudoku-Tunnel: stream\r\n", &[])
            .await
            .status,
        404
    );
    let fresh = session(first, "stream").await;
    assert_ne!(fresh, token);
    server.close().await;
}

#[tokio::test]
async fn invalid_websocket_auth_early_data_and_oversized_http_are_bounded() {
    let server = fixture("auto", 30000, 16).await;
    let address = server.addresses["node"];
    for (path, extra, status) in [
        (
            "/gate/ws",
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\nAuthorization: invalid\r\n",
            404,
        ),
        (
            "/gate/ws",
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 12\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\n",
            400,
        ),
        (
            "/gate/ws",
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: short\r\n",
            400,
        ),
        (
            "/gate/not-ws",
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\n",
            404,
        ),
        ("/gate/session?ed=AA", "X-Sudoku-Tunnel: stream\r\n", 400),
    ] {
        assert_eq!(
            request(address, "GET", path, extra, &[]).await.status,
            status,
            "path={path} expected={status}"
        );
    }
    let token = session(address, "stream").await;
    let mut oversized = TcpStream::connect(address).await.unwrap();
    let header = format!(
        "POST /gate/api/v1/upload?token={token}&seq=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Sudoku-Tunnel: stream\r\nContent-Length: 1048577\r\n\r\n"
    );
    oversized.write_all(header.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(WAIT, oversized.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 503"));
    let mut stream = TcpStream::connect(address).await.unwrap();
    let head = format!(
        "GET / HTTP/1.1\r\nHost: localhost\r\nX-Fill: {}",
        "a".repeat(33 * 1024)
    );
    let _ = stream.write_all(head.as_bytes()).await;
    let mut received = Vec::new();
    let _ = timeout(WAIT, stream.read_to_end(&mut received))
        .await
        .unwrap();
    assert!(received.len() < 4096);
    server.close().await;
}

#[tokio::test]
async fn cover_fallback_is_fixed_target_safe_get_head_only() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cover_address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = seen.clone();
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let cover = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tokio::select! {_=cancel.cancelled()=>break,value=listener.accept()=>value.unwrap()};
            let mut head = Vec::new();
            loop {
                let mut byte = [0; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    break;
                }
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8(head).unwrap();
            captured.lock().unwrap().push(text.clone());
            let body = if text.starts_with("HEAD ") {
                b"".as_slice()
            } else {
                b"cover".as_slice()
            };
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n";
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        }
    });
    let state = Arc::new(State::default());
    let mut node = node_options("auto", KEY, "aes-128-gcm");
    node["cover_fallback"] =
        json!({"server":{"host":"127.0.0.1","port":cover_address.port()},"host":"fixed.invalid"});
    let server = Running::start(configuration(node, false, false), state.clone()).await;
    let address = server.addresses["node"];
    assert_eq!(
        request(address, "GET", "http://unrelated.invalid/private", "", &[])
            .await
            .body,
        b"cover"
    );
    let head = request(address, "HEAD", "/other-path", "", &[]).await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
    assert_eq!(seen.lock().unwrap().len(), 2);
    for request in seen.lock().unwrap().iter() {
        assert!(
            request.starts_with("GET / HTTP/1.1\r\n") || request.starts_with("HEAD / HTTP/1.1\r\n")
        );
        assert!(request.to_ascii_lowercase().contains("host: fixed.invalid"));
        assert!(!request.contains("unrelated.invalid"));
    }
    assert_eq!(
        request(address, "POST", "/", "", b"private-data")
            .await
            .status,
        404
    );
    assert_eq!(
        request(address, "GET", "/", "X-Sudoku-Tunnel: stream\r\n", &[])
            .await
            .status,
        405
    );
    assert_eq!(request(address, "GET", "/", "", b"body").await.status, 404);
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert!(state.decoded.lock().unwrap().is_empty());
    server.close().await;
    stop.cancel();
    timeout(WAIT, cover).await.unwrap().unwrap();
}

#[tokio::test]
async fn signed_websocket_masked_fragment_ping_and_invalid_unmasked_frame() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let state = Arc::new(State::default());
    let mut node = node_options("ws", KEY, "aes-128-gcm");
    node["http_mask"]["path_root"] = json!("gate");
    let server = Running::start(configuration(node, false, false), state.clone()).await;
    let mut stream = TcpStream::connect(server.addresses["node"]).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut key = Sha256::new();
    key.update(b"sudoku-httpmask-auth-v1:");
    key.update(KEY.as_bytes());
    let key = key.finalize();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
    mac.update(b"ws\0GET\0/ws\0");
    mac.update(&now.to_be_bytes());
    let signature = mac.finalize().into_bytes();
    let mut token = now.to_be_bytes().to_vec();
    token.extend_from_slice(&signature[..16]);
    let auth = URL_SAFE_NO_PAD.encode(token);
    let request = format!(
        "GET /gate/ws?auth={auth} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut header = Vec::new();
    timeout(WAIT, async {
        while !header.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).await.unwrap();
            header.push(byte[0]);
            assert!(header.len() < 4096);
        }
    })
    .await
    .unwrap();
    assert!(header.starts_with(b"HTTP/1.1 101"));
    // 两个正确mask的空片段不应伪造业务数据；随后控制帧仍可交互。
    stream
        .write_all(&[0x02, 0x80, 1, 2, 3, 4, 0x80, 0x80, 5, 6, 7, 8])
        .await
        .unwrap();
    stream
        .write_all(&[
            0x89,
            0x84,
            1,
            2,
            3,
            4,
            b'p' ^ 1,
            b'o' ^ 2,
            b'k' ^ 3,
            b'e' ^ 4,
        ])
        .await
        .unwrap();
    let mut pong = [0; 6];
    timeout(WAIT, stream.read_exact(&mut pong))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&pong, b"\x8a\x04poke");
    stream.write_all(&[0x82, 0x01, 0]).await.unwrap();
    let mut remainder = Vec::new();
    let _ = timeout(WAIT, stream.read_to_end(&mut remainder))
        .await
        .unwrap();
    assert!(state.decoded.lock().unwrap().is_empty());
    server.close().await;
}
