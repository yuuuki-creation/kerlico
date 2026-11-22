//! One owned task relays both directions on the inbound engine's executor.

use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kerlico_shared::{
    AsyncReadHalf, AsyncTcp, AsyncWriteHalf, OpenError, TrafficCounters, MAX_WRITE_INPUT_PARTS,
};
use std::pin::Pin;
use std::task::{ready, Poll};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::time::Instant;

use super::copy::{BUF as BUFFER, IDLE};
const TURN: usize = 256 * 1024;

pub(super) fn dispatch(
    socket: TcpStream,
    inbound: AsyncTcp,
    counters: TrafficCounters,
    detached: bool,
) -> Result<(), OpenError> {
    socket
        .set_nonblocking(true)
        .map_err(|_| OpenError::Transport)?;
    let executor = inbound.executor.clone();
    let socket = {
        let _entered = executor.enter();
        tokio::net::TcpStream::from_std(socket).map_err(|_| OpenError::Transport)?
    };
    let (completed, wait) = std::sync::mpsc::sync_channel(1);
    executor.spawn(async move {
        let result = relay(inbound, socket, counters, IDLE)
            .await
            .map_err(|_| OpenError::Transport);
        if detached && result.is_err() {
            eprintln!("flow transport error");
        }
        let _ = completed.send(result);
    });
    if detached {
        Ok(())
    } else {
        wait.recv().unwrap_or(Err(OpenError::Transport))
    }
}

struct Activity {
    start: Instant,
    last_ns: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ns: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        self.last_ns.store(
            self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }

    async fn expired(&self, idle: Duration) {
        loop {
            let last = self.start + Duration::from_nanos(self.last_ns.load(Ordering::Relaxed));
            let deadline = last + idle;
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep_until(deadline).await;
        }
    }
}

async fn relay(
    inbound: AsyncTcp,
    socket: tokio::net::TcpStream,
    counters: TrafficCounters,
    idle: Duration,
) -> io::Result<()> {
    let (target_read, target_write) = socket.into_split();
    relay_sources(
        inbound,
        Source::Tcp(target_read),
        target_write,
        counters,
        idle,
    )
    .await
}

#[cfg(test)]
async fn relay_halves<R, W>(
    inbound: AsyncTcp,
    target_read: R,
    target_write: W,
    counters: TrafficCounters,
    idle: Duration,
) -> io::Result<()>
where
    R: AsyncBufRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    relay_sources(
        inbound,
        Source::Other(Box::new(target_read)),
        target_write,
        counters,
        idle,
    )
    .await
}

async fn relay_sources<W>(
    inbound: AsyncTcp,
    target_read: Source,
    target_write: W,
    counters: TrafficCounters,
    idle: Duration,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let activity = Activity::new();
    let transfer = async {
        tokio::try_join!(
            run_pump(
                Transfer::borrow(inbound.read, AsyncWriteHalf::plain(target_write)),
                &activity,
                |n| counters.add_uplink(n)
            ),
            run_pump(
                Transfer::target(target_read, inbound.write),
                &activity,
                |n| counters.add_downlink(n)
            ),
        )?;
        Ok(())
    };
    // Dropping the other future closes its owned halves on error or idle. No
    // thread remains blocked in a socket write, and either EOF preserves the
    // opposite direction until it also ends or the common idle deadline expires.
    tokio::select! {
        result = transfer => result,
        _ = activity.expired(idle) => Ok(()),
    }
}

enum Source {
    Tcp(tokio::net::tcp::OwnedReadHalf),
    Other(Box<dyn AsyncRead + Send + Unpin>),
}

impl AsyncRead for Source {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(read) => Pin::new(read).poll_read(cx, out),
            Self::Other(read) => Pin::new(read).poll_read(cx, out),
        }
    }
}

impl Source {
    fn poll_input(
        &mut self,
        cx: &mut std::task::Context<'_>,
        mut writer: Pin<&mut (dyn kerlico_shared::AsyncWriteInput + Unpin)>,
    ) -> Poll<io::Result<usize>> {
        loop {
            // An idle native connection should not allocate the encoder's
            // record buffers just to register a socket readiness notification.
            if let Self::Tcp(read) = self {
                ready!(read.as_ref().poll_read_ready(cx))?;
            }
            let mut input = ready!(writer.as_mut().poll_input(cx))?;
            let mut slots =
                std::array::from_fn::<_, MAX_WRITE_INPUT_PARTS, _>(
                    |_| io::IoSliceMut::new(&mut []),
                );
            let count = input.slices(&mut slots);
            let n = match self {
                Self::Tcp(read) => match read.try_read_vectored(&mut slots[..count]) {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue
                    }
                    result => result?,
                },
                Self::Other(read) => {
                    let mut out = ReadBuf::new(&mut slots[0]);
                    ready!(Pin::new(read).poll_read(cx, &mut out))?;
                    out.filled().len()
                }
            };
            if n != 0 {
                input.commit(n);
            }
            return Poll::Ready(Ok(n));
        }
    }
}

enum Storage {
    Borrowed(AsyncReadHalf),
    Input {
        source: Source,
        pending: Option<usize>,
    },
}

struct Transfer {
    storage: Storage,
    write: AsyncWriteHalf,
}

impl Transfer {
    fn borrow(read: AsyncReadHalf, write: AsyncWriteHalf) -> Self {
        let read = match read {
            AsyncReadHalf::Plain(read) => {
                AsyncReadHalf::Buffered(Box::new(BufReader::with_capacity(BUFFER, read)))
            }
            read => read,
        };
        Self {
            storage: Storage::Borrowed(read),
            write,
        }
    }

    fn target(source: Source, write: AsyncWriteHalf) -> Self {
        if matches!(write, AsyncWriteHalf::Input(_)) {
            Self {
                storage: Storage::Input {
                    source,
                    pending: None,
                },
                write,
            }
        } else {
            Self::borrow(AsyncReadHalf::Plain(Box::new(source)), write)
        }
    }

    fn poll_transfer(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<Option<usize>>> {
        let Storage::Borrowed(read) = &mut self.storage else {
            let Storage::Input { source, pending } = &mut self.storage else {
                unreachable!()
            };
            let AsyncWriteHalf::Input(write) = &mut self.write else {
                unreachable!("input-capable writer")
            };
            if pending.is_none() {
                let n = ready!(source.poll_input(cx, Pin::new(&mut **write)))?;
                if n == 0 {
                    return Poll::Ready(Ok(None));
                }
                *pending = Some(n);
            }
            let n = ready!(Pin::new(&mut **write).poll_send_input(cx))?;
            if Some(n) != *pending {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            *pending = None;
            return Poll::Ready(Ok(Some(n)));
        };
        let n = {
            let mut slices = [io::IoSlice::new(&[]); 16];
            let len = match read {
                AsyncReadHalf::Buffered(read) => {
                    let bytes = ready!(Pin::new(read).poll_fill_buf(cx))?;
                    if bytes.is_empty() {
                        0
                    } else {
                        slices[0] = io::IoSlice::new(bytes);
                        1
                    }
                }
                AsyncReadHalf::Vectored(read) => {
                    ready!(Pin::new(&mut **read).poll_fill_buf_vectored(cx, &mut slices))?
                }
                AsyncReadHalf::Plain(_) => unreachable!("copy reader is buffered"),
            };
            if len == 0 {
                return Poll::Ready(Ok(None));
            }
            if len > 1 && self.write.is_write_vectored() {
                ready!(Pin::new(&mut self.write).poll_write_vectored(cx, &slices[..len]))?
            } else {
                ready!(Pin::new(&mut self.write).poll_write(cx, &slices[0]))?
            }
        };
        match read {
            AsyncReadHalf::Buffered(read) => Pin::new(read).consume(n),
            AsyncReadHalf::Vectored(read) => Pin::new(read).consume(n),
            AsyncReadHalf::Plain(_) => unreachable!("copy reader is buffered"),
        }
        Poll::Ready(Ok(Some(n)))
    }
}

#[cfg(test)]
async fn pump<W>(
    read: AsyncReadHalf,
    write: W,
    activity: &Activity,
    count: impl Fn(u64),
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    run_pump(
        Transfer::borrow(read, AsyncWriteHalf::plain(write)),
        activity,
        count,
    )
    .await
}

// A pending socket or writer already yields to the executor. Count only
// consecutive ready bytes against the voluntary fairness budget.
fn reset_on_wait<T>(result: Poll<T>, turn: &mut usize) -> Poll<T> {
    if result.is_pending() {
        *turn = 0;
    }
    result
}

async fn run_pump(
    mut transfer: Transfer,
    activity: &Activity,
    count: impl Fn(u64),
) -> io::Result<()> {
    let mut turn = 0;
    loop {
        let n =
            std::future::poll_fn(|cx| reset_on_wait(transfer.poll_transfer(cx), &mut turn)).await?;
        let Some(n) = n else {
            return transfer.write.shutdown().await;
        };
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        count(n as u64);
        activity.touch();
        // AsyncWrite may buffer even a successful write. Commit before waiting
        // for the next input, otherwise a request/reply exchange can deadlock.
        turn += n;
        std::future::poll_fn(|cx| {
            reset_on_wait(Pin::new(&mut transfer.write).poll_flush(cx), &mut turn)
        })
        .await?;
        if turn >= TURN {
            turn = 0;
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_shared::WriteInput;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, DuplexStream};

    #[derive(Default)]
    struct InputAudit {
        bytes: Vec<u8>,
        batches: Vec<usize>,
        closed: bool,
        discarded: usize,
        loans: usize,
    }

    struct InputSink {
        storage: Vec<u8>,
        regions: [std::ops::Range<usize>; 3],
        filled: usize,
        pending: bool,
        stall: bool,
        audit: Arc<std::sync::Mutex<InputAudit>>,
    }

    impl InputSink {
        fn new(stall: bool, audit: Arc<std::sync::Mutex<InputAudit>>) -> Self {
            Self {
                storage: vec![0xa5; 50],
                regions: [3..11, 17..33, 39..45],
                filled: 0,
                pending: true,
                stall,
                audit,
            }
        }
    }

    impl AsyncWrite for InputSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            panic!("native source must use the supplied encoder regions");
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<()>> {
            self.audit.lock().unwrap().closed = true;
            Poll::Ready(Ok(()))
        }
    }

    impl kerlico_shared::AsyncWriteInput for InputSink {
        fn poll_input(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<WriteInput<'_>>> {
            let this = self.get_mut();
            this.audit.lock().unwrap().loans += 1;
            Poll::Ready(Ok(WriteInput::new(
                &mut this.storage,
                &this.regions,
                &mut this.filled,
            )))
        }
        fn poll_send_input(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<usize>> {
            if self.stall {
                return Poll::Pending;
            }
            if self.pending {
                self.pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = self.filled;
            {
                let mut audit = self.audit.lock().unwrap();
                for (i, byte) in self.storage.iter().enumerate() {
                    if !self.regions.iter().any(|region| region.contains(&i)) {
                        assert_eq!(*byte, 0xa5);
                    }
                }
                let mut remaining = n;
                for region in &self.regions {
                    let count = remaining.min(region.len());
                    audit
                        .bytes
                        .extend_from_slice(&self.storage[region.start..region.start + count]);
                    remaining -= count;
                }
                assert_eq!(remaining, 0);
                audit.batches.push(n);
            }
            self.filled = 0;
            self.pending = true;
            Poll::Ready(Ok(n))
        }
    }

    impl Drop for InputSink {
        fn drop(&mut self) {
            self.audit.lock().unwrap().discarded = self.filled;
        }
    }

    #[tokio::test]
    async fn native_reads_fill_frame_regions_keep_gaps_and_half_close_with_exact_counts() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut origin, _) = listener.accept().await.unwrap();
        let payload: Vec<_> = (0..47).collect();
        origin.write_all(&payload).await.unwrap();
        origin.shutdown().await.unwrap();
        let audit = Arc::new(std::sync::Mutex::new(InputAudit::default()));
        let inbound = AsyncTcp {
            executor: tokio::runtime::Handle::current(),
            read: AsyncReadHalf::Plain(Box::new(std::io::Cursor::new(b"uplink".to_vec()))),
            write: AsyncWriteHalf::Input(Box::new(InputSink::new(false, audit.clone()))),
        };
        let (counts, up, down) = counters();
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                async {
                    relay(inbound, target, counts, IDLE).await.unwrap();
                },
                async {
                    let mut got = Vec::new();
                    origin.read_to_end(&mut got).await.unwrap();
                    assert_eq!(got, b"uplink");
                },
            );
        })
        .await
        .unwrap();
        let audit = audit.lock().unwrap();
        assert_eq!(audit.bytes, payload);
        assert_eq!(audit.batches, [30, 17]);
        assert!(audit.closed);
        assert_eq!(audit.discarded, 0);
        for n in up {
            assert_eq!(n.load(Ordering::Relaxed), 6);
        }
        for n in down {
            assert_eq!(n.load(Ordering::Relaxed), 47);
        }
    }

    #[tokio::test]
    async fn idle_native_source_borrows_encoder_storage_only_after_readiness() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut origin, _) = listener.accept().await.unwrap();
        let (read, _write) = target.into_split();
        let audit = Arc::new(std::sync::Mutex::new(InputAudit::default()));
        let sink = AsyncWriteHalf::Input(Box::new(InputSink::new(false, audit.clone())));
        let mut transfer = Transfer::target(Source::Tcp(read), sink);
        std::future::poll_fn(|cx| {
            assert!(transfer.poll_transfer(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(audit.lock().unwrap().loans, 0);
        origin.write_all(b"data").await.unwrap();
        let count = std::future::poll_fn(|cx| transfer.poll_transfer(cx))
            .await
            .unwrap();
        assert_eq!(count, Some(4));
        assert_eq!(audit.lock().unwrap().bytes, b"data");
    }

    #[tokio::test]
    async fn idle_discards_pending_encoder_input_without_counting_unsent_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut origin, _) = listener.accept().await.unwrap();
        origin.write_all(b"not delivered").await.unwrap();
        let audit = Arc::new(std::sync::Mutex::new(InputAudit::default()));
        let inbound = AsyncTcp {
            executor: tokio::runtime::Handle::current(),
            read: AsyncReadHalf::Plain(Box::new(tokio::io::empty())),
            write: AsyncWriteHalf::Input(Box::new(InputSink::new(true, audit.clone()))),
        };
        let (counts, up, down) = counters();
        tokio::time::timeout(
            Duration::from_secs(2),
            relay(inbound, target, counts, Duration::from_millis(60)),
        )
        .await
        .unwrap()
        .unwrap();
        let audit = audit.lock().unwrap();
        assert_eq!(audit.discarded, 13);
        assert!(audit.bytes.is_empty() && audit.batches.is_empty());
        for n in up.into_iter().chain(down) {
            assert_eq!(n.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn only_continuously_ready_bytes_exhaust_a_relay_turn() {
        use std::future::Future;
        use std::task::{Context, Wake, Waker};

        struct SourceChunks {
            remaining: usize,
            paced: bool,
            wait: bool,
        }
        impl AsyncRead for SourceChunks {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if std::mem::take(&mut self.wait) {
                    // The test supplies the next socket event explicitly.
                    return Poll::Pending;
                }
                if self.remaining > 0 {
                    const CHUNK: &[u8] = &[0; TURN / 2];
                    out.put_slice(CHUNK);
                    self.remaining -= 1;
                    self.wait = self.paced;
                }
                Poll::Ready(Ok(()))
            }
        }
        #[derive(Default)]
        struct Wakes(std::sync::atomic::AtomicUsize);
        impl Wake for Wakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        for paced in [false, true] {
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            let bytes = std::cell::Cell::new(0u64);
            let activity = Activity::new();
            let read = AsyncReadHalf::Plain(Box::new(SourceChunks {
                remaining: 4,
                paced,
                wait: false,
            }));
            let mut future = std::pin::pin!(pump(read, tokio::io::sink(), &activity, |n| bytes
                .set(bytes.get() + n)));
            let mut polls = 0;
            loop {
                polls += 1;
                assert!(polls < 10);
                if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                    result.unwrap();
                    break;
                }
            }
            assert_eq!(bytes.get(), (2 * TURN) as u64);
            assert_eq!(wakes.0.load(Ordering::Relaxed), if paced { 0 } else { 2 });
        }
    }

    fn counters() -> (TrafficCounters, [Arc<AtomicU64>; 3], [Arc<AtomicU64>; 3]) {
        let up = std::array::from_fn(|_| Arc::new(AtomicU64::new(0)));
        let down = std::array::from_fn(|_| Arc::new(AtomicU64::new(0)));
        (TrafficCounters::new(up.clone(), down.clone()), up, down)
    }

    fn inbound(stream: DuplexStream) -> AsyncTcp {
        let (read, write) = tokio::io::split(stream);
        AsyncTcp {
            executor: tokio::runtime::Handle::current(),
            read: kerlico_shared::AsyncReadHalf::Plain(Box::new(read)),
            write: AsyncWriteHalf::plain(write),
        }
    }

    #[tokio::test]
    async fn backpressure_prefix_half_close_and_all_counters() {
        let (mut user, source) = tokio::io::duplex(137);
        let (target, mut origin) = tokio::io::duplex(191);
        let mut source = inbound(source);
        source.prepend(b"prefetched".to_vec());
        let (read, write) = tokio::io::split(target);
        let (counts, up, down) = counters();
        let request = vec![29; 262_151];
        let reply = vec![73; 196_621];
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    relay_halves(source, BufReader::new(read), write, counts, IDLE)
                        .await
                        .unwrap();
                },
                async {
                    user.write_all(&request).await.unwrap();
                    user.shutdown().await.unwrap();
                    let mut response = Vec::new();
                    user.read_to_end(&mut response).await.unwrap();
                    assert_eq!(response, reply);
                },
                async {
                    let mut received = Vec::new();
                    origin.read_to_end(&mut received).await.unwrap();
                    assert_eq!(&received[..10], b"prefetched");
                    assert_eq!(&received[10..], &request);
                    origin.write_all(&reply).await.unwrap();
                    origin.shutdown().await.unwrap();
                },
            );
        })
        .await
        .unwrap();
        for count in up {
            assert_eq!(count.load(Ordering::Relaxed), request.len() as u64 + 10);
        }
        for count in down {
            assert_eq!(count.load(Ordering::Relaxed), reply.len() as u64);
        }
    }

    #[tokio::test]
    async fn idle_cancels_a_blocked_write_and_counts_only_delivered_bytes() {
        let (mut user, source) = tokio::io::duplex(17);
        let (target, mut origin) = tokio::io::duplex(19);
        let (read, write) = tokio::io::split(target);
        let (counts, up, down) = counters();
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                async {
                    relay_halves(
                        inbound(source),
                        BufReader::new(read),
                        write,
                        counts,
                        Duration::from_millis(60),
                    )
                    .await
                    .unwrap();
                },
                async {
                    assert!(user.write_all(&vec![1; 65536]).await.is_err());
                },
            );
        })
        .await
        .unwrap();
        let mut delivered = Vec::new();
        origin.read_to_end(&mut delivered).await.unwrap();
        assert_eq!(delivered.len(), 19);
        for count in up {
            assert_eq!(count.load(Ordering::Relaxed), delivered.len() as u64);
        }
        for count in down {
            assert_eq!(count.load(Ordering::Relaxed), 0);
        }
    }

    #[tokio::test]
    async fn reverse_activity_extends_the_shared_idle_deadline() {
        let (mut user, source) = tokio::io::duplex(32);
        let (target, mut origin) = tokio::io::duplex(32);
        let (read, write) = tokio::io::split(target);
        let (counts, _, down) = counters();
        tokio::time::timeout(Duration::from_secs(4), async {
            tokio::join!(
                async {
                    relay_halves(
                        inbound(source),
                        BufReader::new(read),
                        write,
                        counts,
                        Duration::from_millis(200),
                    )
                    .await
                    .unwrap();
                },
                async {
                    user.shutdown().await.unwrap();
                    let mut received = Vec::new();
                    user.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, b"123456");
                },
                async {
                    let mut empty = Vec::new();
                    origin.read_to_end(&mut empty).await.unwrap();
                    for byte in b"123456" {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        origin.write_all(&[*byte]).await.unwrap();
                    }
                    origin.shutdown().await.unwrap();
                },
            );
        })
        .await
        .unwrap();
        for count in down {
            assert_eq!(count.load(Ordering::Relaxed), 6);
        }
    }

    #[tokio::test]
    async fn buffered_protocol_writer_commits_before_waiting_for_more_input() {
        let (mut user, source) = tokio::io::duplex(32);
        let (target, mut origin) = tokio::io::duplex(32);
        let mut source = inbound(source);
        source.write =
            AsyncWriteHalf::plain(tokio::io::BufWriter::with_capacity(1024, source.write));
        let (read, write) = tokio::io::split(target);
        let (counts, up, down) = counters();
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                async {
                    relay_halves(source, BufReader::new(read), write, counts, IDLE)
                        .await
                        .unwrap();
                },
                async {
                    user.write_all(b"request").await.unwrap();
                    let mut response = [0; 5];
                    user.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"reply");
                    user.write_all(b"ack").await.unwrap();
                    user.shutdown().await.unwrap();
                    assert_eq!(user.read(&mut response).await.unwrap(), 0);
                },
                async {
                    let mut request = [0; 7];
                    origin.read_exact(&mut request).await.unwrap();
                    assert_eq!(&request, b"request");
                    origin.write_all(b"reply").await.unwrap();
                    let mut ack = Vec::new();
                    origin.read_to_end(&mut ack).await.unwrap();
                    assert_eq!(&ack, b"ack");
                    origin.shutdown().await.unwrap();
                },
            );
        })
        .await
        .unwrap();
        for count in up {
            assert_eq!(count.load(Ordering::Relaxed), 10);
        }
        for count in down {
            assert_eq!(count.load(Ordering::Relaxed), 5);
        }
    }
    struct Records {
        parts: std::collections::VecDeque<Vec<u8>>,
        offset: usize,
    }

    impl AsyncBufRead for Records {
        fn poll_fill_buf(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<io::Result<&[u8]>> {
            let this = self.get_mut();
            Poll::Ready(Ok(this
                .parts
                .front()
                .map_or(&[], |bytes| &bytes[this.offset..])))
        }
        fn consume(self: Pin<&mut Self>, mut n: usize) {
            let this = self.get_mut();
            while n > 0 {
                let available = this.parts.front().unwrap().len() - this.offset;
                let consumed = n.min(available);
                n -= consumed;
                this.offset += consumed;
                if consumed == available {
                    this.parts.pop_front();
                    this.offset = 0;
                }
            }
        }
    }

    impl tokio::io::AsyncRead for Records {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            out: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let bytes = ready!(self.as_mut().poll_fill_buf(cx))?;
            let n = bytes.len().min(out.remaining());
            out.put_slice(&bytes[..n]);
            self.consume(n);
            Poll::Ready(Ok(()))
        }
    }

    impl kerlico_shared::AsyncBufReadVectored for Records {
        fn poll_fill_buf_vectored<'a>(
            self: Pin<&'a mut Self>,
            _: &mut std::task::Context<'_>,
            slices: &mut [io::IoSlice<'a>],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            let n = this.parts.len().min(slices.len());
            for (i, (slice, part)) in slices.iter_mut().zip(&this.parts).enumerate() {
                *slice = io::IoSlice::new(&part[if i == 0 { this.offset } else { 0 }..]);
            }
            Poll::Ready(Ok(n))
        }
    }

    #[tokio::test]
    async fn vectored_copy_keeps_prefix_counts_and_short_writes_with_scalar_fallback() {
        #[derive(Default)]
        struct Output {
            bytes: Vec<u8>,
            vector_calls: usize,
            closed: bool,
        }
        struct Writer {
            state: std::sync::Arc<std::sync::Mutex<Output>>,
            vector: bool,
            pending: bool,
        }
        impl AsyncWrite for Writer {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.poll_write_vectored(cx, &[io::IoSlice::new(bytes)])
            }
            fn poll_write_vectored(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                slices: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                if self.pending {
                    self.pending = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.pending = true;
                let mut state = self.state.lock().unwrap();
                if slices.len() > 1 {
                    state.vector_calls += 1;
                }
                let mut n = 0;
                for bytes in slices {
                    let take = bytes.len().min(7 - n);
                    state.bytes.extend_from_slice(&bytes[..take]);
                    n += take;
                    if n == 7 {
                        break;
                    }
                }
                Poll::Ready(Ok(n))
            }
            fn is_write_vectored(&self) -> bool {
                self.vector
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> Poll<io::Result<()>> {
                self.state.lock().unwrap().closed = true;
                Poll::Ready(Ok(()))
            }
        }
        for vector in [true, false] {
            let mut read = AsyncReadHalf::Vectored(Box::new(Records {
                parts: [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()].into(),
                offset: 0,
            }));
            read.prepend(b"handshake-".to_vec());
            read.prepend(b"sniff-".to_vec());
            let state = std::sync::Arc::new(std::sync::Mutex::new(Output::default()));
            let writer = Writer {
                state: state.clone(),
                vector,
                pending: true,
            };
            let (counts, up, down) = counters();
            pump(read, writer, &Activity::new(), |n| counts.add_uplink(n))
                .await
                .unwrap();
            let state = state.lock().unwrap();
            assert_eq!(state.bytes, b"sniff-handshake-firstsecondthird");
            assert_eq!(state.vector_calls > 0, vector);
            assert!(state.closed);
            for n in up {
                assert_eq!(n.load(Ordering::Relaxed), state.bytes.len() as u64);
            }
            for n in down {
                assert_eq!(n.load(Ordering::Relaxed), 0);
            }
        }
    }
}
