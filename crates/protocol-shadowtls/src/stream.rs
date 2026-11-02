use crate::wire;
use kerlico_core::{BoxStream, CancellationToken, Result};
use rustls::ClientConnection;
use std::{
    io::{self, Read},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

#[derive(Clone)]
pub(crate) enum Owner {
    Node(kerlico_core::NodeTasks),
    Service(kerlico_core::ServiceContext),
}
enum Task {
    Node(kerlico_core::NodeTask<()>),
    Service(kerlico_core::ServiceTask<()>),
}
impl Task {
    fn abort(&self) {
        match self {
            Self::Node(task) => task.abort(),
            Self::Service(task) => task.abort(),
        }
    }
}
impl Owner {
    fn cancel(&self) -> CancellationToken {
        match self {
            Self::Node(owner) => owner.cancel(),
            Self::Service(owner) => owner.cancel(),
        }
    }
    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) -> Result<Task> {
        match self {
            Self::Node(owner) => owner.spawn_tracked(task).map(Task::Node),
            Self::Service(owner) => owner.spawn_tracked(task).map(Task::Service),
        }
    }
}

pub(crate) enum ReadMode {
    V2(Option<Box<ClientConnection>>),
    V3 {
        verify: Box<wire::Hash>,
        ignore: Option<Box<wire::Hash>>,
    },
}
pub(crate) enum WriteMode {
    V2(Option<crate::v2::Capture>),
    V3(wire::Hash),
}
struct ErrorState {
    error: Mutex<Option<BridgeFailure>>,
    accepted: AtomicU64,
    flushed: AtomicU64,
    closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}
#[derive(Clone, Copy)]
enum BridgeFailure {
    Cancelled,
    Io(io::ErrorKind),
}
impl ErrorState {
    fn get(&self) -> Option<io::Error> {
        self.error
            .lock()
            .ok()
            .and_then(|v| *v)
            .map(|failure| match failure {
                BridgeFailure::Cancelled => io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    kerlico_core::Error::Cancelled,
                ),
                BridgeFailure::Io(kind) => io::Error::new(kind, "ShadowTLS 记录桥已终止"),
            })
    }
    fn wake(&self) {
        if let Ok(mut value) = self.waker.lock()
            && let Some(waker) = value.take()
        {
            waker.wake();
        }
    }
    fn register(&self, cx: &Context<'_>) {
        if let Ok(mut value) = self.waker.lock() {
            *value = Some(cx.waker().clone());
        }
    }
}
struct Bridge {
    io: DuplexStream,
    error: Arc<ErrorState>,
    task: Task,
    _owner: Owner,
}
impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl AsyncRead for Bridge {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, out) {
            Poll::Ready(Ok(())) if out.filled().len() == before && out.remaining() > 0 => {
                Poll::Ready(this.error.get().map_or(Ok(()), Err))
            }
            other => other,
        }
    }
}
impl AsyncWrite for Bridge {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(error) = this.error.get() {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut this.io).poll_write(cx, bytes) {
            Poll::Ready(Ok(length)) => {
                this.error
                    .accepted
                    .fetch_add(length as u64, Ordering::SeqCst);
                Poll::Ready(Ok(length))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.error.register(cx);
        if let Some(error) = this.error.get() {
            return Poll::Ready(Err(error));
        }
        if this.error.flushed.load(Ordering::SeqCst) >= this.error.accepted.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        this.error.register(cx);
        if let Some(error) = this.error.get() {
            return Poll::Ready(Err(error));
        }
        if this.error.closed.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
pub(crate) fn wrap(
    raw: BoxStream,
    initial: Vec<u8>,
    mut read_mode: ReadMode,
    mut write_mode: WriteMode,
    cancel: CancellationToken,
    owner: Owner,
) -> Result<BoxStream> {
    let (local, peer) = tokio::io::duplex(65536);
    let error = Arc::new(ErrorState {
        error: Mutex::new(None),
        accepted: AtomicU64::new(0),
        flushed: AtomicU64::new(0),
        closed: AtomicBool::new(false),
        waker: Mutex::new(None),
    });
    let shared = error.clone();
    let shutdown = owner.cancel();
    let task = owner.spawn(async move {
        let (mut socket_r, mut socket_w) = tokio::io::split(raw);
        let (mut user_r, mut user_w) = tokio::io::split(peer);
        let result: Result<()> = tokio::select! {
            _=shutdown.cancelled()=>Err(kerlico_core::Error::Cancelled),
            _=cancel.cancelled()=>Err(kerlico_core::Error::Cancelled),
            result=async {
                tokio::try_join!(async {
                    if !initial.is_empty(){user_w.write_all(&initial).await?;}
                    while let Some(record)=wire::read(&mut socket_r).await? {
                        if record[0]==wire::ALERT {break;}
                        if record[0]!=wire::APP || record[1..3]!=[3,3]{return Err(wire::error());}
                        let payload=match &mut read_mode {
                            ReadMode::V2(session)=>{
                                if let Some(tls)=session {
                                    tls.read_tls(&mut io::Cursor::new(&record))?;
                                    if tls.process_new_packets().is_ok(){
                                        let mut plaintext=Vec::new();let _=tls.reader().read_to_end(&mut plaintext);
                                        if !plaintext.is_empty(){return Err(wire::error());}
                                        continue;
                                    }
                                    *session=None;
                                }
                                &record[5..]
                            },
                            ReadMode::V3{verify,ignore}=>{
                                if let Some(hash)=ignore {
                                    if wire::verify(hash,&record[5..],false){continue;}
                                    *ignore=None;
                                }
                                if !wire::verify(verify,&record[5..],true){return Err(wire::error());}
                                &record[9..]
                            },
                        };
                        if !payload.is_empty(){user_w.write_all(payload).await?;}
                    }
                    user_w.shutdown().await?;Ok::<(),kerlico_core::Error>(())
                },async {
                    let mut payload=vec![0;wire::MAX_PLAIN];
                    loop {
                        let length=user_r.read(&mut payload).await?;
                        if length==0 {
                            if matches!(&write_mode,WriteMode::V3(_)){wire::alert(&mut socket_w).await;}
                            socket_w.shutdown().await?;shared.closed.store(true,Ordering::SeqCst);shared.wake();return Ok::<(),kerlico_core::Error>(());
                        }
                        let mut output=Vec::with_capacity(length+8);
                        match &mut write_mode {
                            WriteMode::V2(prefix)=>{if let Some(tag)=prefix.take(){output.extend_from_slice(&crate::v2::first(&tag)?);}output.extend_from_slice(&payload[..length]);},
                            WriteMode::V3(hash)=>{let tag=wire::tag(hash,&payload[..length],true);output.extend_from_slice(&tag);output.extend_from_slice(&payload[..length]);},
                        }
                        socket_w.write_all(&wire::frame(wire::APP,&output)).await?;socket_w.flush().await?;shared.flushed.fetch_add(length as u64,Ordering::SeqCst);shared.wake();
                    }
                })?;Ok(())
            }=>result,
        };
        if let Err(value) = result {
            let failure = if kerlico_core::FlowFailure::from_error(&value)
                == kerlico_core::FlowFailure::Cancelled
            {
                BridgeFailure::Cancelled
            } else {
                BridgeFailure::Io(match value {
                    kerlico_core::Error::Io(error) => error.kind(),
                    _ => io::ErrorKind::InvalidData,
                })
            };
            if let Ok(mut error) = shared.error.lock() {
                *error = Some(failure);
            }
            shared.wake();
            if matches!(&write_mode, WriteMode::V3(_)) {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(250),
                    wire::alert(&mut socket_w),
                )
                .await;
            }
        }
    })?;
    Ok(Box::new(Bridge {
        io: local,
        error,
        task,
        _owner: owner,
    }))
}

#[cfg(test)]
pub(crate) fn test_owner() -> Owner {
    Owner::Node(kerlico_core::NodeTasks::new(
        kerlico_core::NodeId::parse("shadowtls-test").unwrap(),
        CancellationToken::new(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_bridge_write_all_and_read_exact_return_terminal_cancellation() {
        for verified in [false, true] {
            let owner = test_owner();
            let cancel = CancellationToken::new();
            let (raw, _peer) = tokio::io::duplex(32);
            let seed = [4; 32];
            let (read, write) = if verified {
                (
                    ReadMode::V3 {
                        verify: Box::new(wire::directional(b"cancel-test", &seed, b'S')),
                        ignore: None,
                    },
                    WriteMode::V3(wire::directional(b"cancel-test", &seed, b'C')),
                )
            } else {
                (ReadMode::V2(None), WriteMode::V2(None))
            };
            let mut stream = wrap(
                Box::new(raw),
                Vec::new(),
                read,
                write,
                cancel.clone(),
                owner.clone(),
            )
            .unwrap();
            cancel.cancel();
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                stream.read_exact(&mut [0; 1]),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                kerlico_core::FlowFailure::from_error(&kerlico_core::Error::Io(error)),
                kerlico_core::FlowFailure::Cancelled
            );
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                stream.write_all(b"after-cancel"),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
            assert_eq!(
                kerlico_core::FlowFailure::from_error(&kerlico_core::Error::Io(error)),
                kerlico_core::FlowFailure::Cancelled
            );
            drop(stream);
            assert!(shutdown(&owner).await.is_clean());
        }
    }

    struct ObservedSocket {
        io: DuplexStream,
        polled: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for ObservedSocket {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }
    impl AsyncRead for ObservedSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.polled.notify_one();
            Pin::new(&mut this.io).poll_read(cx, out)
        }
    }
    impl AsyncWrite for ObservedSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().io).poll_write(cx, data)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }
    async fn shutdown(owner: &Owner) -> kerlico_core::ShutdownReport {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        match owner {
            Owner::Node(owner) => owner.shutdown_at(deadline).await,
            Owner::Service(owner) => owner.shutdown(deadline).await,
        }
    }
    #[tokio::test]
    async fn bridge_owners_join_actual_socket_drop_after_outer_abort_and_reject_new_work() {
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            for service in [false, true] {
                let owner = if service {
                    Owner::Service(kerlico_core::ServiceContext::new(
                        kerlico_core::OutId::parse("bridge-service").unwrap(),
                    ))
                } else {
                    test_owner()
                };
                let polled = Arc::new(tokio::sync::Notify::new());
                let dropped = Arc::new(AtomicBool::new(false));
                let (raw, _peer) = tokio::io::duplex(32);
                let mut bridge = wrap(
                    Box::new(ObservedSocket {
                        io: raw,
                        polled: polled.clone(),
                        dropped: dropped.clone(),
                    }),
                    Vec::new(),
                    ReadMode::V2(None),
                    WriteMode::V2(None),
                    CancellationToken::new(),
                    owner.clone(),
                )
                .unwrap();
                let outer = tokio::spawn(async move {
                    let mut byte = [0];
                    bridge.read(&mut byte).await
                });
                polled.notified().await;
                outer.abort();
                assert!(outer.await.unwrap_err().is_cancelled());
                assert!(shutdown(&owner).await.is_clean());
                assert!(dropped.load(Ordering::SeqCst));
                let rejected_drop = Arc::new(AtomicBool::new(false));
                let (raw, _peer) = tokio::io::duplex(32);
                assert!(matches!(
                    wrap(
                        Box::new(ObservedSocket {
                            io: raw,
                            polled: polled.clone(),
                            dropped: rejected_drop.clone()
                        }),
                        Vec::new(),
                        ReadMode::V2(None),
                        WriteMode::V2(None),
                        CancellationToken::new(),
                        owner
                    ),
                    Err(kerlico_core::Error::Cancelled)
                ));
                assert!(rejected_drop.load(Ordering::SeqCst));
            }
        })
        .await
        .expect("ShadowTLS bridge 真实任务回收超时");
    }
    #[tokio::test]
    async fn flush_and_shutdown_wait_for_the_actual_socket_writer() {
        let (raw, mut other) = tokio::io::duplex(32);
        let mut stream = wrap(
            Box::new(raw),
            Vec::new(),
            ReadMode::V2(None),
            WriteMode::V2(None),
            CancellationToken::new(),
            test_owner(),
        )
        .unwrap();
        stream.write_all(&vec![9; 32768]).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), stream.flush())
                .await
                .is_err()
        );
        let ((), packets) = tokio::join!(
            async {
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
            },
            async {
                let mut length = 0;
                while let Some(record) = wire::read(&mut other).await.unwrap() {
                    assert!(record[5..].iter().all(|b| *b == 9));
                    length += record.len() - 5;
                }
                length
            }
        );
        assert_eq!(packets, 32768);
    }
    #[tokio::test]
    async fn bad_mac_and_truncated_record_surface_an_io_error_instead_of_clean_eof() {
        for truncated in [false, true] {
            let (raw, mut other) = tokio::io::duplex(64);
            let seed = [2; 32];
            let mut stream = wrap(
                Box::new(raw),
                Vec::new(),
                ReadMode::V3 {
                    verify: Box::new(wire::directional(b"test", &seed, b'S')),
                    ignore: None,
                },
                WriteMode::V3(wire::directional(b"test", &seed, b'C')),
                CancellationToken::new(),
                test_owner(),
            )
            .unwrap();
            if truncated {
                other.write_all(&[23, 3, 3, 0, 20, 1]).await.unwrap();
            } else {
                other
                    .write_all(&wire::frame(wire::APP, b"bad-authentication-tag"))
                    .await
                    .unwrap();
            }
            other.shutdown().await.unwrap();
            let mut bytes = [0; 1];
            assert!(stream.read(&mut bytes).await.is_err());
        }
    }
}

#[cfg(test)]
mod large_record_tests {
    use super::*;
    #[tokio::test]
    async fn full_u16_records_survive_real_queue_backpressure_before_clean_eof() {
        for verified in [false, true] {
            let (raw, mut other) = tokio::io::duplex(32);
            let seed = [12; 32];
            let key = b"large-record-test";
            let (read, write) = if verified {
                (
                    ReadMode::V3 {
                        verify: Box::new(wire::directional(key, &seed, b'S')),
                        ignore: None,
                    },
                    WriteMode::V3(wire::directional(key, &seed, b'C')),
                )
            } else {
                (ReadMode::V2(None), WriteMode::V2(None))
            };
            let mut stream = wrap(
                Box::new(raw),
                Vec::new(),
                read,
                write,
                CancellationToken::new(),
                test_owner(),
            )
            .unwrap();
            let length = wire::MAX_RECORD - if verified { 4 } else { 0 };
            let mut writer = tokio::spawn(async move {
                let mut hash = wire::directional(key, &seed, b'S');
                for byte in [7, 9, 11] {
                    let payload = vec![byte; length];
                    let mut body = Vec::new();
                    if verified {
                        body.extend_from_slice(&wire::tag(&mut hash, &payload, true));
                    }
                    body.extend_from_slice(&payload);
                    other
                        .write_all(&wire::frame(wire::APP, &body))
                        .await
                        .unwrap();
                }
                other.shutdown().await.unwrap();
            });
            // 三个记录超过用户队列、单条解码缓存及载体队列之和，未消费时生产者必须阻塞。
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), &mut writer)
                    .await
                    .is_err()
            );
            let (reply, ()) = tokio::join!(
                async {
                    let mut reply = Vec::new();
                    stream.read_to_end(&mut reply).await.unwrap();
                    reply
                },
                async {
                    writer.await.unwrap();
                }
            );
            assert_eq!(reply.len(), length * 3);
            for (index, byte) in [7, 9, 11].iter().enumerate() {
                assert!(
                    reply[index * length..(index + 1) * length]
                        .iter()
                        .all(|v| v == byte)
                );
            }
        }
    }
}
