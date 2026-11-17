use std::future::Future;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use quinn::{Endpoint, EndpointConfig, RecvStream, SendStream, TokioRuntime, VarInt};
use tokio::runtime::Runtime;

pub fn runtime() -> io::Result<&'static Runtime> {
    static RUNTIME: OnceLock<io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

pub fn block<T>(wait: Duration, op: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    runtime()?.block_on(async {
        tokio::time::timeout(wait, op)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    })
}

pub fn listen_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub fn endpoint(
    socket: UdpSocket,
    config: EndpointConfig,
    server: Option<quinn::ServerConfig>,
    obfs: Option<&crate::obfs::Salamander>,
) -> io::Result<Endpoint> {
    let _guard = runtime()?.enter();
    if let Some(obfs) = obfs {
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        packet_endpoint(Arc::new(socket), config, server, Some(obfs))
    } else {
        Endpoint::new(config, server, socket, Arc::new(TokioRuntime))
    }
}

pub fn packet_endpoint(
    packets: Arc<dyn kerlico_shared::runtime::PacketIo>,
    config: EndpointConfig,
    server: Option<quinn::ServerConfig>,
    obfs: Option<&crate::obfs::Salamander>,
) -> io::Result<Endpoint> {
    let _guard = runtime()?.enter();
    let packets = if let Some(obfs) = obfs {
        obfs.wrap(packets)
    } else {
        packets
    };
    Endpoint::new_with_abstract_socket(
        config,
        server,
        super::MaskedSocket::new(packets)?,
        Arc::new(TokioRuntime),
    )
}

pub struct Duplex {
    recv: Mutex<RecvStream>,
    send: Mutex<SendStream>,
    recv_wait: StreamWait,
    send_wait: StreamWait,
    cancelled: tokio::sync::watch::Sender<bool>,
}

// Quinn's established stream futures only poll connection state and register a
// waker. The connection driver still runs on Tokio; a blocking caller doesn't
// need to register a new Tokio timer each time it waits for a stream.
struct StreamWait {
    signal: Arc<StreamSignal>,
    waker: Waker,
}

#[derive(Default)]
struct StreamSignal {
    notified: Mutex<bool>,
    ready: Condvar,
}

impl Wake for StreamSignal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let notified = std::mem::replace(&mut *self.notified.lock().unwrap(), true);
        if !notified {
            self.ready.notify_one();
        }
    }
}

impl StreamWait {
    fn new() -> Self {
        let signal = Arc::new(StreamSignal::default());
        let waker = Waker::from(signal.clone());
        Self { signal, waker }
    }

    fn wait<T>(&self, limit: Duration, op: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        let mut op = std::pin::pin!(op);
        let mut cx = Context::from_waker(&self.waker);
        let start = Instant::now();
        loop {
            if let Poll::Ready(result) = op.as_mut().poll(&mut cx) {
                return result;
            }
            let left = limit.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let notified = self.signal.notified.lock().unwrap();
            let (mut notified, _) = self
                .signal
                .ready
                .wait_timeout_while(notified, left, |notified| !*notified)
                .unwrap();
            *notified = false;
        }
    }
}

impl Duplex {
    pub fn into_async(self, executor: tokio::runtime::Handle) -> kerlico_shared::AsyncTcp {
        kerlico_shared::AsyncTcp {
            executor,
            read: kerlico_shared::AsyncReadHalf::Plain(Box::new(self.recv.into_inner().expect("Hy2 receive stream"))),
            write: kerlico_shared::AsyncWriteHalf::plain(self.send.into_inner().expect("Hy2 send stream")),
        }
    }

    pub fn new(recv: RecvStream, send: SendStream) -> Self {
        Self {
            recv: Mutex::new(recv),
            send: Mutex::new(send),
            recv_wait: StreamWait::new(),
            send_wait: StreamWait::new(),
            cancelled: tokio::sync::watch::Sender::new(false),
        }
    }

    pub fn read(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        let mut recv = self.recv.lock().expect("Hy2 receive stream");
        let mut cancel = self.cancelled.subscribe();
        self.recv_wait.wait(wait, async {
            tokio::select! {
                biased;
                _ = cancel.wait_for(|yes| *yes) => Ok(0),
                value = recv.read(buf) => Ok(value?.unwrap_or(0)),
            }
        })
    }

    pub fn write(&self, buf: &[u8], wait: Duration) -> io::Result<()> {
        let mut send = self.send.lock().expect("Hy2 send stream");
        let mut cancel = self.cancelled.subscribe();
        self.send_wait.wait(wait, async {
            tokio::select! {
                biased;
                _ = cancel.wait_for(|yes| *yes) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                result = send.write_all(buf) => result.map_err(Into::into),
            }
        })
    }

    pub fn finish(&self) -> io::Result<()> {
        self.send
            .lock()
            .expect("Hy2 send stream")
            .finish()
            .map_err(io::Error::other)
    }

    pub fn close(&self) {
        self.cancelled.send_replace(true);
        let _ = self
            .recv
            .lock()
            .expect("Hy2 receive stream")
            .stop(VarInt::from_u32(0));
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, poll_fn};

    #[test]
    fn notification_before_sleep_repolls_the_same_future() {
        let mut started = false;
        let read = poll_fn(|cx| {
            if std::mem::replace(&mut started, true) {
                Poll::Ready(Ok(13))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        });
        assert_eq!(
            StreamWait::new()
                .wait(Duration::from_secs(1), read)
                .unwrap(),
            13
        );
    }

    #[test]
    fn read_deadline_and_cross_thread_cancellation_need_no_runtime() {
        let wait = StreamWait::new();
        let deadline = Duration::from_millis(10);
        let start = Instant::now();
        let error = wait
            .wait(deadline, pending::<io::Result<()>>())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= deadline);

        let (cancel, mut watch) = tokio::sync::watch::channel(false);
        let (started, ready) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                ready.recv_timeout(Duration::from_secs(1)).unwrap();
                cancel.send(true).unwrap();
            });
            wait.wait(Duration::from_secs(2), async {
                let mut subscribe = std::pin::pin!(watch.wait_for(|yes| *yes));
                let mut started = Some(started);
                poll_fn(|cx| {
                    let state = subscribe.as_mut().poll(cx);
                    if state.is_pending() {
                        if let Some(started) = started.take() {
                            started.send(()).unwrap();
                        }
                    }
                    state
                })
                .await
                .unwrap();
                Ok(())
            })
            .unwrap();
        });
    }
}
