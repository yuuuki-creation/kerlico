use super::*;
use std::{
    io,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct ReadyKeepalive {
    output: tokio::io::DuplexStream,
    offset: usize,
    reads: Arc<AtomicU64>,
}
impl AsyncRead for ReadyKeepalive {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let frame = [DATA, 0, 0, 0, 0, 0, 0, 0, 0];
        let count = buffer.remaining().min(frame.len() - self.offset);
        buffer.put_slice(&frame[self.offset..self.offset + count]);
        self.offset = (self.offset + count) % frame.len();
        self.reads.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ReadyKeepalive {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.output).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_shutdown(cx)
    }
}

fn ready_session(
    idle: Duration,
) -> (
    Session,
    tokio::io::DuplexStream,
    Arc<AtomicU64>,
    CancellationToken,
) {
    let (output, peer) = tokio::io::duplex(1024);
    let reads = Arc::new(AtomicU64::new(0));
    let cancel = CancellationToken::new();
    let session = Session::start(
        Box::new(ReadyKeepalive {
            output,
            offset: 0,
            reads: reads.clone(),
        }),
        &cancel,
        1,
        idle,
        None,
        false,
    );
    (session, peer, reads, cancel)
}

#[tokio::test]
async fn continuously_ready_carrier_reclaims_cancelled_stream_while_handle_is_retained() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (session, mut peer, reads, parent) = ready_session(Duration::from_secs(30));
        let context = ConnectContext::new(Duration::from_secs(2));
        let target = Destination::new("192.0.2.1", 443).unwrap();
        let held = session.open(&target, &context).await.unwrap();
        let (kind, old_id, payload) = receive(&mut peer).await;
        assert_eq!(kind, OPEN);
        assert_eq!(address::decode(&payload).unwrap().0, target);
        assert!(!session.available());
        let before = reads.load(Ordering::Relaxed);
        context.cancel.cancel();
        let (kind, id, payload) = tokio::time::timeout(Duration::from_secs(1), receive(&mut peer))
            .await
            .unwrap();
        assert_eq!((kind, id, payload), (RESET, old_id, Vec::new()));
        assert!(reads.load(Ordering::Relaxed) > before);
        assert!(session.available());
        let next_context = ConnectContext::new(Duration::from_secs(2));
        let next = session.open(&target, &next_context).await.unwrap();
        let (kind, next_id, payload) = receive(&mut peer).await;
        assert_eq!(kind, OPEN);
        assert_ne!(next_id, old_id);
        assert_eq!(address::decode(&payload).unwrap().0, target);
        assert!(!session.is_closed());
        drop(held);
        drop(next);
        parent.cancel();
        let tasks = std::mem::take(&mut *session._owner.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn continuously_ready_keepalive_does_not_keep_an_idle_session_alive() {
    let (session, _peer, reads, parent) = ready_session(Duration::from_millis(100));
    let tasks = std::mem::take(&mut *session._owner.tasks.lock().unwrap());
    tokio::time::timeout(Duration::from_secs(1), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(session.is_closed());
    assert!(!parent.is_cancelled());
    assert!(reads.load(Ordering::Relaxed) > 0);
}

/// 两端持续收发时返回（对端收到的字节，本地读到的字节）。
async fn saturated(server: bool) -> (u64, u64) {
    let (peer, transport) = tokio::io::duplex(256 * 1024);
    let cancel = CancellationToken::new();
    let session = Session::start(
        Box::new(transport),
        &cancel,
        4,
        Duration::from_secs(30),
        None,
        server,
    );
    let (mut peer_read, mut peer_write) = tokio::io::split(peer);
    let target = Destination::new("192.0.2.3", 443).unwrap();
    let (stream, id) = if server {
        send(&mut peer_write, OPEN, 1, &address::encode(&target)).await;
        (session.accept().await.unwrap().stream, 1)
    } else {
        let context = ConnectContext::new(Duration::from_secs(2));
        let opened = tokio::spawn(async move {
            let (kind, id, _) = receive(&mut peer_read).await;
            assert_eq!(kind, OPEN);
            (id, peer_read)
        });
        let stream = session.open(&target, &context).await.unwrap();
        let (id, reader) = opened.await.unwrap();
        peer_read = reader;
        (stream, id)
    };
    let peer_received = Arc::new(AtomicU64::new(0));
    let counted = peer_received.clone();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        loop {
            let (kind, _, payload) = receive(&mut peer_read).await;
            assert_eq!(kind, DATA);
            counted.fetch_add(payload.len() as u64, Ordering::Relaxed);
        }
    });
    tasks.spawn(async move {
        let payload = vec![0x11; SEND_CHUNK];
        loop {
            send(&mut peer_write, DATA, id, &payload).await;
        }
    });
    let (mut down, mut up) = tokio::io::split(stream);
    tasks.spawn(async move {
        let payload = vec![0x22; SEND_CHUNK];
        loop {
            up.write_all(&payload).await.unwrap();
        }
    });
    let mut local_received = 0u64;
    let mut buffer = vec![0; 64 * 1024];
    while peer_received.load(Ordering::Relaxed) + local_received < 16 * 1024 * 1024 {
        let count = down.read(&mut buffer).await.unwrap();
        assert_ne!(count, 0);
        local_received += count as u64;
    }
    let result = (peer_received.load(Ordering::Relaxed), local_received);
    tasks.abort_all();
    cancel.cancel();
    result
}

#[tokio::test]
async fn saturated_client_gives_the_downlink_the_larger_share() {
    let (uplink, downlink) = tokio::time::timeout(Duration::from_secs(20), saturated(false))
        .await
        .unwrap();
    assert!(downlink >= 2 * uplink, "上行 {uplink}，下行 {downlink}");
}

#[tokio::test]
async fn saturated_node_gives_the_downlink_the_larger_share() {
    let (downlink, uplink) = tokio::time::timeout(Duration::from_secs(20), saturated(true))
        .await
        .unwrap();
    assert!(downlink >= 2 * uplink, "上行 {uplink}，下行 {downlink}");
}

async fn send(writer: &mut (impl AsyncWrite + Unpin), kind: u8, id: u32, payload: &[u8]) {
    let mut header = [0; 9];
    header[0] = kind;
    header[1..5].copy_from_slice(&id.to_be_bytes());
    header[5..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await.unwrap();
    writer.write_all(payload).await.unwrap();
}
async fn receive(reader: &mut (impl AsyncRead + Unpin)) -> (u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    reader.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes(header[5..].try_into().unwrap()) as usize;
    assert!(length <= MAX_FRAME);
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await.unwrap();
    (
        header[0],
        u32::from_be_bytes(header[1..5].try_into().unwrap()),
        payload,
    )
}
async fn exchange(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    server: &Session,
    id: u32,
    content: &[u8],
) -> Vec<u32> {
    send(
        writer,
        OPEN,
        id,
        &address::encode(&Destination::new("192.0.2.1", 443).unwrap()),
    )
    .await;
    let accepted = server.accept().await.unwrap();
    let echo = tokio::spawn(async move {
        let _lease = accepted.lease;
        let mut stream = accepted.stream;
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    send(writer, DATA, id, content).await;
    send(writer, FIN, id, &[]).await;
    let mut actual = Vec::new();
    let mut resets = Vec::new();
    loop {
        let (kind, stream_id, payload) = receive(reader).await;
        match (kind, stream_id) {
            (DATA, stream_id) if stream_id == id => actual.extend(payload),
            (FIN, stream_id) if stream_id == id => break,
            (RESET, stream_id) => resets.push(stream_id),
            _ => panic!("Mux返回了非预期帧"),
        }
    }
    assert_eq!(actual, content);
    echo.await.unwrap();
    resets
}

#[tokio::test]
async fn large_peer_frames_keep_fast_flow_live_before_and_after_slow_reset() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (peer, transport) = tokio::io::duplex(16 * 1024 * 1024);
        let cancel = CancellationToken::new();
        let server = Session::start(
            Box::new(transport),
            &cancel,
            4,
            Duration::from_secs(30),
            None,
            true,
        );
        let (mut reader, mut writer) = tokio::io::split(peer);
        send(
            &mut writer,
            OPEN,
            1,
            &address::encode(&Destination::new("192.0.2.2", 443).unwrap()),
        )
        .await;
        let mut held = server.accept().await.unwrap();
        let payload = vec![0x5a; 64512];
        for _ in 0..32 {
            send(&mut writer, DATA, 1, &payload).await;
        }
        assert!(
            exchange(&mut reader, &mut writer, &server, 3, b"before-overflow")
                .await
                .is_empty()
        );
        assert!(!held.stream.state.is_reset());
        for _ in 0..100 {
            send(&mut writer, DATA, 1, &payload).await;
        }
        assert_eq!(
            exchange(&mut reader, &mut writer, &server, 5, b"after-overflow").await,
            vec![1]
        );
        assert!(held.stream.read(&mut [0; 1]).await.is_err());
        assert!(!server.is_closed());
        assert_eq!(
            server.shared.receive_budget.available_permits(),
            8 * 1024 * 1024
        );
        drop(held);
        cancel.cancel();
        let tasks = std::mem::take(&mut *server._owner.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .unwrap();
}
