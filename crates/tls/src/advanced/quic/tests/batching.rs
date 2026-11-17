use std::cell::Cell;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};

thread_local! {
    static POLL_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
}

#[derive(Debug)]
struct AuditedRuntime;

struct AuditedPoll(Pin<Box<dyn Future<Output = ()> + Send>>);

impl Future for AuditedPoll {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let prior = POLL_BYTES.replace(Some(0));
        let result = self.0.as_mut().poll(cx);
        POLL_BYTES.set(prior);
        result
    }
}

impl Runtime for AuditedRuntime {
    fn new_timer(&self, at: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(at)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        quinn::TokioRuntime.spawn(Box::pin(AuditedPoll(future)));
    }
    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

#[derive(Debug)]
struct CheckedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    cap: usize,
    block_above: usize,
    largest: AtomicUsize,
    blocked_once: AtomicBool,
    wait: Arc<AtomicBool>,
    pending: Mutex<Option<(Vec<u8>, SocketAddr, Option<usize>)>>,
    resumed: AtomicBool,
}

#[derive(Debug)]
struct CheckedPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    wait: Arc<AtomicBool>,
}

impl UdpPoller for CheckedPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.wait.swap(false, Ordering::AcqRel) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.inner.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for CheckedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(CheckedPoller {
            inner: self.inner.clone().create_io_poller(),
            wait: self.wait.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        assert!(
            transmit.contents.len() <= 65_507,
            "a GSO train must fit the UDP send length"
        );
        let segments = transmit
            .segment_size
            .map_or(1, |s| transmit.contents.len().div_ceil(s));
        assert!(segments <= self.cap);
        self.largest.fetch_max(segments, Ordering::Relaxed);
        let mut pending = self.pending.lock().unwrap();
        if let Some((bytes, destination, segment_size)) = pending.take() {
            assert_eq!(
                transmit.contents, bytes,
                "resume identical encrypted packet bytes"
            );
            assert_eq!(transmit.destination, destination);
            assert_eq!(transmit.segment_size, segment_size);
            self.resumed.store(true, Ordering::Release);
        } else if segments > self.block_above && !self.blocked_once.swap(true, Ordering::AcqRel) {
            *pending = Some((
                transmit.contents.to_vec(),
                transmit.destination,
                transmit.segment_size,
            ));
            self.wait.store(true, Ordering::Release);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.try_send(transmit)?;
        POLL_BYTES.with(|count| {
            let total = count
                .get()
                .expect("server datagrams belong to a driver poll")
                + transmit.contents.len();
            assert!(
                total <= 256 * 1024,
                "one driver poll exceeded its byte budget: {total}"
            );
            count.set(Some(total));
        });
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.cap.min(self.inner.max_transmit_segments())
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[test]
fn quic_gso_batches_preserve_pending_ciphertext_and_single_segment_sockets() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for (cap, mtu) in [(1, 1200), (64, 1200), (64, 9000)] {
            tokio::time::timeout(Duration::from_secs(10), async {
                let mut options = super::super::super::tests::options();
                options.alpn = vec!["h3".into()];
                let mut server_config = quinn::ServerConfig::with_crypto(
                    super::super::advanced_quic_server_config(&options).unwrap(),
                );
                // Give the fixture enough initial credit to exercise GSO
                // immediately; this does not change production congestion control.
                let mut reno = quinn_proto::congestion::NewRenoConfig::default();
                reno.initial_window(1 << 20);
                let mut transport = quinn::TransportConfig::default();
                transport
                    .congestion_controller_factory(Arc::new(reno))
                    .initial_rtt(Duration::from_millis(1))
                    .initial_mtu(mtu)
                    .mtu_discovery_config(None);
                server_config.transport_config(Arc::new(transport));
                let inner = quinn::TokioRuntime
                    .wrap_udp_socket(UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap();
                assert!(
                    cap <= inner.max_transmit_segments(),
                    "Linux fixture must expose GSO"
                );
                let socket = Arc::new(CheckedSocket {
                    inner,
                    cap,
                    block_above: if mtu > 1200 { 1 } else { 10 },
                    largest: AtomicUsize::new(0),
                    blocked_once: AtomicBool::new(false),
                    wait: Arc::new(AtomicBool::new(false)),
                    pending: Mutex::new(None),
                    resumed: AtomicBool::new(false),
                });
                let mut endpoint_config = quinn::EndpointConfig::default();
                endpoint_config.max_udp_payload_size(mtu.max(1472)).unwrap();
                let server = quinn::Endpoint::new_with_abstract_socket(
                    endpoint_config.clone(),
                    Some(server_config),
                    socket.clone(),
                    Arc::new(AuditedRuntime),
                )
                .unwrap();
                let mut client = quinn::Endpoint::new(
                    endpoint_config,
                    None,
                    UdpSocket::bind("127.0.0.1:0").unwrap(),
                    Arc::new(quinn::TokioRuntime),
                )
                .unwrap();
                client.set_default_client_config(quinn::ClientConfig::new(
                    super::super::advanced_quic_client_config(&options, false).unwrap(),
                ));
                let listener = server.clone();
                let incoming =
                    tokio::spawn(async move { listener.accept().await.unwrap().await.unwrap() });
                let client_conn = client
                    .connect(server.local_addr().unwrap(), "localhost")
                    .unwrap()
                    .await
                    .unwrap();
                let server_conn = incoming.await.unwrap();
                let (mut request, mut response) = client_conn.open_bi().await.unwrap();
                request.write_all(b"ready").await.unwrap();
                request.finish().unwrap();
                let (mut send, mut receive) = server_conn.accept_bi().await.unwrap();
                assert_eq!(receive.read_to_end(64).await.unwrap(), b"ready");
                let payload: Vec<_> = (0..524_301).map(|i| (i % 251) as u8).collect();
                let expected = payload.clone();
                let write = tokio::spawn(async move {
                    send.write_all(&payload).await.unwrap();
                    send.finish().unwrap();
                });
                assert_eq!(
                    response.read_to_end(expected.len()).await.unwrap(),
                    expected
                );
                write.await.unwrap();
                assert!(socket.pending.lock().unwrap().is_none());
                if cap == 1 {
                    assert_eq!(socket.largest.load(Ordering::Relaxed), 1);
                } else {
                    assert!(
                        socket.largest.load(Ordering::Relaxed) > if mtu > 1200 { 1 } else { 32 }
                    );
                    assert!(socket.resumed.load(Ordering::Acquire));
                }
                client_conn.close(0u32.into(), b"done");
                server_conn.close(0u32.into(), b"done");
            })
            .await
            .unwrap();
        }
    });
}
