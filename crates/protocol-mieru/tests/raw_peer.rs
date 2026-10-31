mod common;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use common::*;
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    Address, CancellationToken, Destination, InboundContext, NodeEvent, NodeObserver, StreamBudget,
};
use kerlico_mieru::MieruNodeFactory;
use pbkdf2::pbkdf2_hmac;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
fn request(target: &Destination) -> Vec<u8> {
    let mut bytes = vec![5, 1, 0];
    match target.address() {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        _ => panic!("原始对端测试使用 IPv4 目标"),
    };
    bytes.extend(target.port().to_be_bytes());
    bytes
}
fn segment(
    fixture: &Fixture,
    nonce_byte: u8,
    kind: u8,
    timestamp_delta: i32,
    target: &Destination,
) -> Vec<u8> {
    let user = fixture.options["username"].as_str().unwrap();
    let password = fixture.options["password"].as_str().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let bucket = (now + 60) / 120 * 120;
    let mut password_bytes = password.as_bytes().to_vec();
    password_bytes.push(0);
    password_bytes.extend(user.as_bytes());
    let secret = Sha256::digest(&password_bytes);
    let salt = Sha256::digest(bucket.to_be_bytes());
    let mut key = [0; 32];
    pbkdf2_hmac::<Sha256>(&secret, &salt, 64, &mut key);
    let aead = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut nonce = [nonce_byte; 24];
    let mut hint = user.as_bytes().to_vec();
    hint.extend(&nonce[..16]);
    nonce[20..].copy_from_slice(&Sha256::digest(hint)[..4]);
    let body = request(target);
    let mut meta = [0; 32];
    meta[0] = kind;
    let minute: u32 = ((now / 60) as i64 + i64::from(timestamp_delta))
        .try_into()
        .unwrap();
    meta[2..6].copy_from_slice(&minute.to_be_bytes());
    meta[6..10].copy_from_slice(&0x10203040u32.to_be_bytes());
    meta[15..17].copy_from_slice(&(body.len() as u16).to_be_bytes());
    let mut wire = nonce.to_vec();
    wire.extend(
        aead.encrypt(XNonce::from_slice(&nonce), meta.as_slice())
            .unwrap(),
    );
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
    wire.extend(
        aead.encrypt(XNonce::from_slice(&nonce), body.as_slice())
            .unwrap(),
    );
    wire
}
async fn closed(mut stream: TcpStream) {
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
}
#[tokio::test]
async fn authentication_replay_direction_and_failed_payload_cannot_poison_first_nonce_cache() {
    let echo = tcp_echo("127.0.0.1").await;
    let mut f = fixture(Setup::new("tcp", "127.0.0.1")).await;
    let mut bad = segment(&f, 1, 2, 0, &echo.target);
    *bad.last_mut().unwrap() ^= 1;
    let mut socket = TcpStream::connect(f.address).await.unwrap();
    socket.write_all(&bad).await.unwrap();
    closed(socket).await;
    assert_eq!(f.count.load(Ordering::Acquire), 0);
    let good = segment(&f, 1, 2, 0, &echo.target);
    let mut socket = TcpStream::connect(f.address).await.unwrap();
    for byte in good.chunks(1) {
        socket.write_all(byte).await.unwrap();
        tokio::task::yield_now().await;
    }
    wait_count(&f.count, 1).await;
    drop(socket);
    let mut replay = TcpStream::connect(f.address).await.unwrap();
    replay.write_all(&good).await.unwrap();
    closed(replay).await;
    assert_eq!(f.count.load(Ordering::Acquire), 1);
    for (nonce, kind, time_delta) in [(2, 3, 0), (3, 2, -3)] {
        let rejected = segment(&f, nonce, kind, time_delta, &echo.target);
        let mut socket = TcpStream::connect(f.address).await.unwrap();
        socket.write_all(&rejected).await.unwrap();
        closed(socket).await;
        assert_eq!(f.count.load(Ordering::Acquire), 1);
    }
    let reused_after_invalid_role = segment(&f, 2, 2, 0, &echo.target);
    let mut socket = TcpStream::connect(f.address).await.unwrap();
    socket.write_all(&reused_after_invalid_role).await.unwrap();
    wait_count(&f.count, 2).await;
    drop(socket);
    f.stop().await;
}
#[tokio::test]
async fn slow_initial_header_timeout_and_node_exit_return_physical_budget_and_port() {
    let mut setup = Setup::new("tcp", "127.0.0.1");
    setup.timeout = Duration::from_millis(120);
    let mut f = fixture(setup).await;
    let mut socket = TcpStream::connect(f.address).await.unwrap();
    socket.write_all(&[1]).await.unwrap();
    wait_count(&f.accepts, 1).await;
    assert_eq!(f.global.available_permits(), 63);
    closed(socket).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while f.global.available_permits() != 64 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.count.load(Ordering::Acquire), 0);
    f.stop().await;
    let listener = TcpListener::bind(f.address).await.unwrap();
    drop(listener);
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
#[tokio::test]
async fn unsafe_udp_runtime_guard_rejects_wildcard_socket_even_without_config_registry() {
    let node = MieruNodeFactory.build(&json!({"transport":"udp","unsafe_udp_compatibility":true,"username":"node-user","password":"synthetic-password"})).unwrap();
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    let global = Arc::new(Semaphore::new(64));
    let context = InboundContext {
        peer_addr: None,
        local_addr: Some(socket.local_addr().unwrap()),
        cancel: CancellationToken::new(),
        connect_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(1),
        drain_timeout: Duration::from_millis(100),
        max_datagram_size: 65535,
        max_streams: 64,
        stream_budget: StreamBudget::new(global.clone(), Arc::new(Semaphore::new(64))),
        events: Arc::new(Observer),
    };
    let access = Arc::new(kerlico_egress::Egress::new(
        kerlico_net::DirectFactory.build(&json!({})).unwrap(),
    ));
    assert!(node.handle_udp(socket, access, context).await.is_err());
    assert_eq!(global.available_permits(), 64);
}
