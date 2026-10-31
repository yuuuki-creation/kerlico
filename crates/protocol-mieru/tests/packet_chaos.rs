mod common;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use common::*;
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Outbound, Result,
};
use kerlico_mieru::MieruFactory;
use pbkdf2::pbkdf2_hmac;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    task::JoinHandle,
};
struct Proxy {
    address: SocketAddr,
    dropped: Arc<AtomicUsize>,
    duplicated: Arc<AtomicUsize>,
    reordered: Arc<AtomicUsize>,
    reused: Arc<AtomicUsize>,
    zero_window: Arc<AtomicUsize>,
    client_peers: Arc<Mutex<HashSet<SocketAddr>>>,
    task: JoinHandle<()>,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn lossy(server: SocketAddr, chaos: bool) -> Proxy {
    let host = server.ip().to_string();
    let socket = UdpSocket::bind((host.as_str(), 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let dropped = Arc::new(AtomicUsize::new(0));
    let duplicated = Arc::new(AtomicUsize::new(0));
    let reordered = Arc::new(AtomicUsize::new(0));
    let reused = Arc::new(AtomicUsize::new(0));
    let d = dropped.clone();
    let du = duplicated.clone();
    let r = reordered.clone();
    let reuse = reused.clone();
    let zero_window = Arc::new(AtomicUsize::new(0));
    let client_peers = Arc::new(Mutex::new(HashSet::new()));
    let seen_peers = client_peers.clone();
    let observed = zero_window.clone();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let rounded = (now + 60) / 120 * 120;
    let base = Sha256::digest(b"synthetic-password-1\0node-1");
    let keys = [rounded - 120, rounded, rounded + 120].map(|time| {
        let salt = Sha256::digest(time.to_be_bytes());
        let mut key = [0; 32];
        pbkdf2_hmac::<Sha256>(&base, &salt, 64, &mut key);
        XChaCha20Poly1305::new_from_slice(&key).unwrap()
    });
    let task = tokio::spawn(async move {
        let mut buffer = [0; 65536];
        let mut client = None;
        let mut counts = [0usize; 2];
        let mut held: [Option<(Vec<u8>, SocketAddr)>; 2] = [None, None];
        let mut nonces = [HashSet::<[u8; 24]>::new(), HashSet::<[u8; 24]>::new()];
        let mut timer = tokio::time::interval(Duration::from_millis(10));
        loop {
            tokio::select! {
                packet = socket.recv_from(&mut buffer) => {
                    let Ok((n, from)) = packet else { break; }; let direction = usize::from(from == server);
                    if direction == 0 { client = Some(from); seen_peers.lock().unwrap().insert(from); }
                    let Some(destination) = (if direction == 0 { Some(server) } else { client }) else { continue; };
                    if n >= 24 { let nonce = buffer[..24].try_into().unwrap(); if !nonces[direction].insert(nonce) { reuse.fetch_add(1, Ordering::AcqRel); } }
                    if direction == 1 && n >= 72 { for key in &keys { if let Ok(meta) = key.decrypt(XNonce::from_slice(&buffer[..24]), &buffer[24..72]) { if meta.len() == 32 && meta[0] == 9 && meta[18..20] == [0, 0] { observed.fetch_add(1, Ordering::AcqRel); } break; } } }
                    let index = counts[direction]; counts[direction] += 1;
                    if chaos && (index == 0 || index > 0 && index % 29 == 0) { d.fetch_add(1, Ordering::AcqRel); continue; }
                    if let Some((previous, peer)) = held[direction].take() { let _ = socket.send_to(&buffer[..n], destination).await; let _ = socket.send_to(&previous, peer).await; r.fetch_add(1, Ordering::AcqRel); continue; }
                    if chaos && index % 7 == 0 { held[direction] = Some((buffer[..n].to_vec(), destination)); continue; }
                    let _ = socket.send_to(&buffer[..n], destination).await;
                    if chaos && index % 11 == 0 { let _ = socket.send_to(&buffer[..n], destination).await; du.fetch_add(1, Ordering::AcqRel); }
                }
                _ = timer.tick() => { for pending in &mut held { if let Some((bytes, peer)) = pending.take() { let _ = socket.send_to(&bytes, peer).await; } } }
            }
        }
    });
    Proxy {
        address,
        dropped,
        duplicated,
        reordered,
        reused,
        zero_window,
        client_peers,
        task,
    }
}
#[tokio::test]
async fn local_udp_arq_recovers_loss_duplicates_reordering_and_uses_fresh_transmission_nonces() {
    let echo = tcp_echo("127.0.0.1").await;
    let packet = udp_echo("127.0.0.1").await;
    for host in ["127.0.0.1", "::1"] {
        let mut setup = Setup::new("udp", host);
        setup.idle = Duration::from_secs(20);
        setup.timeout = Duration::from_secs(8);
        let mut f = fixture(setup).await;
        let proxy = lossy(f.address, true).await;
        let mut options = f.options.clone();
        options["server"] = json!({"host":host,"port":proxy.address.port()});
        f.outbound = MieruFactory.build(&options).unwrap();
        tcp(&f, &echo.target, 257024).await;
        let mut association = f.outbound.associate_udp(&f.context()).await.unwrap();
        for size in [0, 17, 12000, 65507] {
            let data = vec![0x63; size];
            association
                .sender
                .send_to(&data, &packet.target)
                .await
                .unwrap();
            let actual =
                tokio::time::timeout(Duration::from_secs(10), association.receiver.recv_from())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(actual, (packet.target.clone(), data));
        }
        assert!(proxy.dropped.load(Ordering::Acquire) >= 2);
        assert!(proxy.duplicated.load(Ordering::Acquire) > 0);
        assert!(proxy.reordered.load(Ordering::Acquire) > 0);
        assert_eq!(proxy.reused.load(Ordering::Acquire), 0);
        drop(association);
        f.stop().await;
    }
}
#[tokio::test]
async fn malformed_unassociated_datagrams_do_not_allocate_target_or_keep_node_port() {
    let mut f = fixture(Setup::new("udp", "127.0.0.1")).await;
    let sending = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for size in [0, 1, 71, 72, 1501, 65507] {
        sending.send_to(&vec![0x88; size], f.address).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(f.count.load(Ordering::Acquire), 0);
    assert_eq!(f.global.available_permits(), 64);
    f.stop().await;
    let socket = UdpSocket::bind(f.address).await.unwrap();
    drop(socket);
}
struct DelayedTarget {
    direct: Arc<dyn Outbound>,
}
impl Outbound for DelayedTarget {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.direct.associate_udp(context)
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.direct.connect_udp(target, context)
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            assert!(target.is_loopback());
            let (stream, mut peer) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let Ok(size) = peer.read_u32().await else {
                    return;
                };
                assert!(size <= 2 * 1024 * 1024);
                let mut data = vec![0; size as usize];
                if peer.read_exact(&mut data).await.is_ok() {
                    let _ = peer.write_all(&data).await;
                    let _ = peer.shutdown().await;
                }
            });
            Ok(Box::new(stream) as BoxStream)
        })
    }
}
#[tokio::test]
async fn local_udp_zero_window_is_observed_and_recovers_when_application_resumes() {
    // 延迟的内存目标制造背压；仅用于流控回归，不作为独立对端验收。
    let delayed = Arc::new(DelayedTarget {
        direct: kerlico_net::DirectFactory.build(&json!({})).unwrap(),
    });
    let mut setup = Setup::new("udp", "127.0.0.1");
    setup.outbound = Some(delayed);
    setup.idle = Duration::from_secs(20);
    let mut f = fixture(setup).await;
    let proxy = lossy(f.address, false).await;
    let mut options = f.options.clone();
    options["server"] = json!({"host":"127.0.0.1","port":proxy.address.port()});
    f.outbound = MieruFactory.build(&options).unwrap();
    tcp(&f, &Destination::new("127.0.0.1", 9).unwrap(), 1024 * 1024).await;
    assert!(proxy.zero_window.load(Ordering::Acquire) > 0);
    f.stop().await;
}
#[tokio::test]
async fn local_udp_concurrent_logical_streams_share_one_carrier_and_keep_payloads_separate() {
    let echo = tcp_echo("127.0.0.1").await;
    let packet = udp_echo("127.0.0.1").await;
    let mut f = fixture(Setup::new("udp", "127.0.0.1")).await;
    let proxy = lossy(f.address, false).await;
    let mut options = f.options.clone();
    options["server"] = json!({"host":"127.0.0.1","port":proxy.address.port()});
    f.outbound = MieruFactory.build(&options).unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..16u8 {
        let outbound = f.outbound.clone();
        let target = echo.target.clone();
        let context = f.context();
        tasks.spawn(async move {
            let mut stream = outbound.connect_tcp(&target, &context).await.unwrap();
            let data = vec![index; 65536];
            stream.write_u32(data.len() as u32).await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.flush().await.unwrap();
            let mut answer = vec![0; data.len()];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, data);
            let mut end = [0];
            assert_eq!(stream.read(&mut end).await.unwrap(), 0);
        });
    }
    for index in 0..8u8 {
        let outbound = f.outbound.clone();
        let target = packet.target.clone();
        let context = f.context();
        tasks.spawn(async move {
            let mut channel = outbound.connect_udp(&target, &context).await.unwrap();
            let data = vec![index; 12000];
            channel.sender.send(&data).await.unwrap();
            assert_eq!(channel.receiver.recv().await.unwrap().unwrap(), data);
        });
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(proxy.client_peers.lock().unwrap().len(), 1);
    assert_eq!(proxy.reused.load(Ordering::Acquire), 0);
    f.stop().await;
}
