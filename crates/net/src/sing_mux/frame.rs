//! smux（xtaci/smux v1，sing-mux 固定版本 1）与 yamux（hashicorp/yamux）帧会话。
//!
//! 一个读任务分发帧，一个写任务批量写出；流数据走有界通道保证同流有序，
//! 窗口更新、ACK 与 Ping 回应走无界控制通道优先写出。

use bytes::{Buf, Bytes};
use std::{
    collections::{HashMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    sync::{Notify, mpsc},
};
use tokio_util::sync::{CancellationToken, PollSender};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Codec {
    Smux,
    Yamux,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

const SMUX_VERSION: u8 = 1;
const SMUX_SYN: u8 = 0;
const SMUX_FIN: u8 = 1;
const SMUX_PSH: u8 = 2;
const SMUX_NOP: u8 = 3;
const SMUX_UPD: u8 = 4;
const SMUX_MAX_FRAME: usize = 32 * 1024;
/// 对应 smux v1 `MaxReceiveBuffer`：会话内尚未被读走的数据超过它时暂停读载体。
const SMUX_RECEIVE_BUFFER: usize = 4 * 1024 * 1024;

const YAMUX_VERSION: u8 = 0;
const YAMUX_DATA: u8 = 0;
const YAMUX_WINDOW: u8 = 1;
const YAMUX_PING: u8 = 2;
const YAMUX_GO_AWAY: u8 = 3;
const F_SYN: u16 = 1;
const F_ACK: u16 = 2;
const F_FIN: u16 = 4;
const F_RST: u16 = 8;
const YAMUX_INITIAL_WINDOW: u32 = 256 * 1024;
const YAMUX_MAX_FRAME: usize = 32 * 1024;
/// 与 sing-mux 的 yamux `StreamCloseTimeout` 一致：本端关闭后等待对端 FIN 的时长。
const YAMUX_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

const DATA_QUEUE: usize = 256;
const ACCEPT_BACKLOG: usize = 256;
const WRITE_BATCH: usize = 64 * 1024;

fn smux_frame(cmd: u8, sid: u32, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&[SMUX_VERSION, cmd]);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&sid.to_le_bytes());
    out.extend_from_slice(payload);
    out.into()
}

fn yamux_frame(kind: u8, flags: u16, sid: u32, length: u32, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(&[YAMUX_VERSION, kind]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    out.into()
}

impl Codec {
    fn open_frame(self, sid: u32) -> Bytes {
        match self {
            Self::Smux => smux_frame(SMUX_SYN, sid, &[]),
            Self::Yamux => yamux_frame(YAMUX_WINDOW, F_SYN, sid, 0, &[]),
        }
    }

    fn data_frame(self, sid: u32, payload: &[u8]) -> Bytes {
        match self {
            Self::Smux => smux_frame(SMUX_PSH, sid, payload),
            Self::Yamux => yamux_frame(YAMUX_DATA, 0, sid, payload.len() as u32, payload),
        }
    }

    fn fin_frame(self, sid: u32) -> Bytes {
        match self {
            Self::Smux => smux_frame(SMUX_FIN, sid, &[]),
            Self::Yamux => yamux_frame(YAMUX_WINDOW, F_FIN, sid, 0, &[]),
        }
    }

    fn max_frame(self) -> usize {
        match self {
            Self::Smux => SMUX_MAX_FRAME,
            Self::Yamux => YAMUX_MAX_FRAME,
        }
    }
}

#[derive(Default)]
struct StreamState {
    recv: VecDeque<Bytes>,
    recv_len: usize,
    remote_fin: bool,
    reset: bool,
    detached: bool,
    read_waker: Option<Waker>,
    send_window: u32,
    write_waker: Option<Waker>,
    recv_window: u32,
    consumed: u32,
}

impl StreamState {
    fn new() -> Self {
        Self {
            send_window: YAMUX_INITIAL_WINDOW,
            recv_window: YAMUX_INITIAL_WINDOW,
            ..Self::default()
        }
    }

    fn wake(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

type Entry = Arc<Mutex<StreamState>>;

struct Shared {
    codec: Codec,
    streams: Mutex<HashMap<u32, Entry>>,
    data: mpsc::Sender<Bytes>,
    ctrl: mpsc::UnboundedSender<Bytes>,
    next_id: AtomicU32,
    closed: CancellationToken,
    buffered: AtomicUsize,
    drained: Notify,
}

impl Shared {
    fn entry(&self, sid: u32) -> Option<Entry> {
        self.streams.lock().expect("流表锁").get(&sid).cloned()
    }

    fn remove(&self, sid: u32) {
        self.streams.lock().expect("流表锁").remove(&sid);
    }

    fn shutdown(&self) {
        self.closed.cancel();
        let streams: Vec<Entry> = self
            .streams
            .lock()
            .expect("流表锁")
            .drain()
            .map(|(_, e)| e)
            .collect();
        for entry in streams {
            let mut st = entry.lock().expect("流状态锁");
            if !st.remote_fin {
                st.reset = true;
            }
            st.wake();
        }
        self.drained.notify_waiters();
    }

    fn release(&self, n: usize) {
        if self.codec == Codec::Smux && n > 0 {
            self.buffered.fetch_sub(n, Ordering::AcqRel);
            self.drained.notify_waiters();
        }
    }

    fn stream(self: &Arc<Self>, sid: u32, entry: Entry) -> FrameStream {
        FrameStream {
            sid,
            entry,
            shared: self.clone(),
            sender: PollSender::new(self.data.clone()),
            local_fin: false,
        }
    }
}

/// 帧会话句柄；所有句柄与流都释放后仍由读写任务持有，直到载体关闭。
#[derive(Clone)]
pub(super) struct FrameSession {
    shared: Arc<Shared>,
}

impl FrameSession {
    pub fn client<S>(io: S, codec: Codec) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (session, _) = Self::start(io, codec, Role::Client);
        session
    }

    pub fn server<S>(io: S, codec: Codec) -> (Self, mpsc::Receiver<FrameStream>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (session, accept) = Self::start(io, codec, Role::Server);
        (session, accept.expect("服务端接收队列"))
    }

    fn start<S>(io: S, codec: Codec, role: Role) -> (Self, Option<mpsc::Receiver<FrameStream>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (data, data_rx) = mpsc::channel(DATA_QUEUE);
        let (ctrl, ctrl_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            codec,
            streams: Mutex::new(HashMap::new()),
            data,
            ctrl,
            next_id: AtomicU32::new(1),
            closed: CancellationToken::new(),
            buffered: AtomicUsize::new(0),
            drained: Notify::new(),
        });
        let (reader, writer) = tokio::io::split(io);
        let (accept_tx, accept_rx) = match role {
            Role::Server => {
                let (tx, rx) = mpsc::channel(ACCEPT_BACKLOG);
                (Some(tx), Some(rx))
            }
            Role::Client => (None, None),
        };
        tokio::spawn(write_loop(writer, data_rx, ctrl_rx, shared.closed.clone()));
        let read_shared = shared.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::with_capacity(64 * 1024, reader);
            let closed = read_shared.closed.clone();
            tokio::select! {
                _ = closed.cancelled() => {}
                _ = read_loop(&mut reader, &read_shared, accept_tx) => {}
            }
            read_shared.shutdown();
        });
        (Self { shared }, accept_rx)
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.is_cancelled()
    }

    pub fn close(&self) {
        self.shared.shutdown();
    }

    pub async fn open(&self) -> io::Result<FrameStream> {
        let shared = &self.shared;
        if shared.closed.is_cancelled() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let sid = shared.next_id.fetch_add(2, Ordering::Relaxed);
        let entry = Arc::new(Mutex::new(StreamState::new()));
        shared
            .streams
            .lock()
            .expect("流表锁")
            .insert(sid, entry.clone());
        if shared
            .data
            .send(shared.codec.open_frame(sid))
            .await
            .is_err()
        {
            shared.remove(sid);
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(shared.stream(sid, entry))
    }
}

async fn write_loop<W: AsyncWrite>(
    writer: W,
    mut data: mpsc::Receiver<Bytes>,
    mut ctrl: mpsc::UnboundedReceiver<Bytes>,
    closed: CancellationToken,
) {
    let mut writer = std::pin::pin!(writer);
    let mut batch = Vec::with_capacity(WRITE_BATCH * 2);
    loop {
        let first = tokio::select! {
            biased;
            _ = closed.cancelled() => break,
            Some(frame) = ctrl.recv() => frame,
            Some(frame) = data.recv() => frame,
            else => break,
        };
        batch.clear();
        batch.extend_from_slice(&first);
        while batch.len() < WRITE_BATCH {
            if let Ok(frame) = ctrl.try_recv() {
                batch.extend_from_slice(&frame);
            } else if let Ok(frame) = data.try_recv() {
                batch.extend_from_slice(&frame);
            } else {
                break;
            }
        }
        if writer.write_all(&batch).await.is_err() || writer.flush().await.is_err() {
            break;
        }
    }
    closed.cancel();
    let _ = writer.shutdown().await;
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn skip<R: AsyncRead + Unpin>(reader: &mut R, len: usize) -> io::Result<()> {
    let copied = tokio::io::copy(&mut reader.take(len as u64), &mut tokio::io::sink()).await?;
    if copied != len as u64 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

async fn read_payload<R: AsyncRead + Unpin>(reader: &mut R, len: usize) -> io::Result<Bytes> {
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload.into())
}

async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    shared: &Arc<Shared>,
    accept: Option<mpsc::Sender<FrameStream>>,
) -> io::Result<()> {
    match shared.codec {
        Codec::Smux => smux_read_loop(reader, shared, accept).await,
        Codec::Yamux => yamux_read_loop(reader, shared, accept).await,
    }
}

async fn incoming(
    shared: &Arc<Shared>,
    accept: &Option<mpsc::Sender<FrameStream>>,
    sid: u32,
) -> Option<Entry> {
    let accept = accept.as_ref()?;
    let entry = {
        let mut streams = shared.streams.lock().expect("流表锁");
        if streams.contains_key(&sid) {
            return None;
        }
        let entry = Arc::new(Mutex::new(StreamState::new()));
        streams.insert(sid, entry.clone());
        entry
    };
    if shared.codec == Codec::Yamux {
        let _ = shared
            .ctrl
            .send(yamux_frame(YAMUX_WINDOW, F_ACK, sid, 0, &[]));
    }
    let stream = shared.stream(sid, entry.clone());
    let _ = accept.send(stream).await;
    Some(entry)
}

fn push_data(shared: &Shared, entry: &Entry, payload: Bytes) {
    let mut st = entry.lock().expect("流状态锁");
    if st.detached || st.reset {
        return;
    }
    if shared.codec == Codec::Smux {
        shared.buffered.fetch_add(payload.len(), Ordering::AcqRel);
    }
    st.recv_len += payload.len();
    st.recv.push_back(payload);
    if let Some(w) = st.read_waker.take() {
        w.wake();
    }
}

fn mark_remote_fin(shared: &Shared, sid: u32, entry: &Entry) {
    let mut st = entry.lock().expect("流状态锁");
    st.remote_fin = true;
    let detached = st.detached;
    st.wake();
    drop(st);
    if detached {
        shared.remove(sid);
    }
}

fn mark_reset(shared: &Shared, sid: u32, entry: &Entry) {
    let mut st = entry.lock().expect("流状态锁");
    st.reset = true;
    let released = std::mem::take(&mut st.recv_len);
    st.recv.clear();
    st.wake();
    drop(st);
    shared.release(released);
    shared.remove(sid);
}

async fn smux_read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    shared: &Arc<Shared>,
    accept: Option<mpsc::Sender<FrameStream>>,
) -> io::Result<()> {
    let mut hdr = [0u8; 8];
    loop {
        loop {
            let drained = shared.drained.notified();
            if shared.buffered.load(Ordering::Acquire) <= SMUX_RECEIVE_BUFFER
                || shared.closed.is_cancelled()
            {
                break;
            }
            drained.await;
        }
        match reader.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        if hdr[0] != SMUX_VERSION {
            return Err(protocol_error("smux 帧版本不匹配"));
        }
        let len = usize::from(u16::from_le_bytes([hdr[2], hdr[3]]));
        let sid = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        match hdr[1] {
            SMUX_SYN => {
                skip(reader, len).await?;
                incoming(shared, &accept, sid).await;
            }
            SMUX_FIN => {
                skip(reader, len).await?;
                if let Some(entry) = shared.entry(sid) {
                    mark_remote_fin(shared, sid, &entry);
                }
            }
            SMUX_PSH => {
                if len == 0 {
                    continue;
                }
                let payload = read_payload(reader, len).await?;
                if let Some(entry) = shared.entry(sid) {
                    push_data(shared, &entry, payload);
                }
            }
            SMUX_NOP | SMUX_UPD => skip(reader, len).await?,
            _ => return Err(protocol_error("smux 未知帧命令")),
        }
    }
}

async fn yamux_read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    shared: &Arc<Shared>,
    accept: Option<mpsc::Sender<FrameStream>>,
) -> io::Result<()> {
    let mut hdr = [0u8; 12];
    loop {
        match reader.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
        if hdr[0] != YAMUX_VERSION {
            return Err(protocol_error("yamux 帧版本不匹配"));
        }
        let kind = hdr[1];
        let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
        let sid = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let length = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        match kind {
            YAMUX_DATA | YAMUX_WINDOW => {
                let mut entry = if flags & F_SYN != 0 {
                    incoming(shared, &accept, sid).await
                } else {
                    None
                };
                if entry.is_none() {
                    entry = shared.entry(sid);
                }
                if kind == YAMUX_DATA {
                    if length > YAMUX_INITIAL_WINDOW * 4 {
                        return Err(protocol_error("yamux 数据帧超过接收窗口"));
                    }
                    let payload = read_payload(reader, length as usize).await?;
                    if let Some(entry) = &entry {
                        {
                            let mut st = entry.lock().expect("流状态锁");
                            if length > st.recv_window {
                                return Err(protocol_error("yamux 对端越过接收窗口"));
                            }
                            st.recv_window -= length;
                        }
                        if !payload.is_empty() {
                            push_data(shared, entry, payload);
                        }
                    }
                } else if let Some(entry) = &entry
                    && length > 0
                {
                    let mut st = entry.lock().expect("流状态锁");
                    st.send_window = st.send_window.saturating_add(length);
                    if let Some(w) = st.write_waker.take() {
                        w.wake();
                    }
                }
                if let Some(entry) = &entry {
                    if flags & F_RST != 0 {
                        mark_reset(shared, sid, entry);
                    } else if flags & F_FIN != 0 {
                        mark_remote_fin(shared, sid, entry);
                    }
                }
            }
            YAMUX_PING => {
                if flags & F_SYN != 0 {
                    let _ = shared
                        .ctrl
                        .send(yamux_frame(YAMUX_PING, F_ACK, 0, length, &[]));
                }
            }
            YAMUX_GO_AWAY => return Ok(()),
            _ => return Err(protocol_error("yamux 未知帧类型")),
        }
    }
}

/// 帧会话中的逻辑流。smux 无半关闭：本端关闭写即整流 FIN，对端 FIN 后写入失败；
/// yamux 支持半关闭。
pub(super) struct FrameStream {
    sid: u32,
    entry: Entry,
    shared: Arc<Shared>,
    sender: PollSender<Bytes>,
    local_fin: bool,
}

impl AsyncRead for FrameStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut st = this.entry.lock().expect("流状态锁");
        if st.recv.is_empty() {
            if st.reset {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            if st.remote_fin {
                return Poll::Ready(Ok(()));
            }
            st.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut copied = 0;
        while buf.remaining() > 0 {
            let Some(front) = st.recv.front_mut() else {
                break;
            };
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                st.recv.pop_front();
            }
            copied += n;
        }
        st.recv_len -= copied;
        let mut credit = None;
        if this.shared.codec == Codec::Yamux {
            st.consumed += copied as u32;
            if st.consumed >= YAMUX_INITIAL_WINDOW / 2 {
                let delta = std::mem::take(&mut st.consumed);
                st.recv_window += delta;
                credit = Some(delta);
            }
        }
        drop(st);
        this.shared.release(copied);
        if let Some(delta) = credit {
            let _ = this
                .shared
                .ctrl
                .send(yamux_frame(YAMUX_WINDOW, 0, this.sid, delta, &[]));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FrameStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.local_fin {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        {
            let mut st = this.entry.lock().expect("流状态锁");
            if st.reset || (this.shared.codec == Codec::Smux && st.remote_fin) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if this.shared.codec == Codec::Yamux && st.send_window == 0 {
                if this.shared.closed.is_cancelled() {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                st.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        ready!(this.sender.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let mut n = buf.len().min(this.shared.codec.max_frame());
        if this.shared.codec == Codec::Yamux {
            let mut st = this.entry.lock().expect("流状态锁");
            n = n.min(st.send_window as usize);
            st.send_window -= n as u32;
        }
        let frame = this.shared.codec.data_frame(this.sid, &buf[..n]);
        this.sender
            .send_item(frame)
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.local_fin {
            return Poll::Ready(Ok(()));
        }
        let reserved = ready!(this.sender.poll_reserve(cx));
        this.local_fin = true;
        if reserved.is_ok() {
            let _ = this.sender.send_item(this.shared.codec.fin_frame(this.sid));
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for FrameStream {
    fn drop(&mut self) {
        let (remote_done, released) = {
            let mut st = self.entry.lock().expect("流状态锁");
            st.detached = true;
            st.recv.clear();
            (st.remote_fin || st.reset, std::mem::take(&mut st.recv_len))
        };
        self.shared.release(released);
        let codec = self.shared.codec;
        if !self.local_fin {
            let frame = codec.fin_frame(self.sid);
            if let Err(mpsc::error::TrySendError::Full(frame)) = self.shared.data.try_send(frame)
                && let Ok(handle) = tokio::runtime::Handle::try_current()
            {
                let data = self.shared.data.clone();
                handle.spawn(async move {
                    let _ = data.send(frame).await;
                });
            }
        }
        if remote_done || codec == Codec::Smux {
            self.shared.remove(self.sid);
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.shared.remove(self.sid);
            return;
        };
        let shared = self.shared.clone();
        let entry = self.entry.clone();
        let sid = self.sid;
        handle.spawn(async move {
            tokio::select! {
                _ = shared.closed.cancelled() => return,
                _ = tokio::time::sleep(YAMUX_CLOSE_TIMEOUT) => {}
            }
            let finished = entry.lock().expect("流状态锁").remote_fin;
            if !finished {
                let _ = shared
                    .data
                    .send(yamux_frame(YAMUX_WINDOW, F_RST, sid, 0, &[]))
                    .await;
            }
            shared.remove(sid);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair(codec: Codec) -> (FrameSession, mpsc::Receiver<FrameStream>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let client = FrameSession::client(a, codec);
        let (_server, accept) = FrameSession::server(b, codec);
        (client, accept)
    }

    #[tokio::test]
    async fn smux_wire_frames_match_xtaci_layout() {
        assert_eq!(
            &smux_frame(SMUX_PSH, 3, b"ab")[..],
            &[1, 2, 2, 0, 3, 0, 0, 0, b'a', b'b']
        );
        assert_eq!(
            &yamux_frame(YAMUX_WINDOW, F_SYN, 1, 0, &[])[..],
            &[0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]
        );
    }

    #[tokio::test]
    async fn yamux_moves_more_than_a_window_and_half_closes() {
        let (client, mut accept) = pair(Codec::Yamux).await;
        let mut stream = client.open().await.unwrap();
        let server = tokio::spawn(async move {
            let mut s = accept.recv().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            s.write_all(&got).await.unwrap();
            s.shutdown().await.unwrap();
            got.len()
        });
        let payload: Vec<u8> = (0..2_000_000u32).map(|i| (i % 253) as u8).collect();
        let (mut r, mut w) = tokio::io::split(stream);
        let send = payload.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&send).await.unwrap();
            w.shutdown().await.unwrap();
            w
        });
        let mut echoed = Vec::new();
        r.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(server.await.unwrap(), payload.len());
        assert_eq!(echoed, payload);
        stream = r.unsplit(writer.await.unwrap());
        drop(stream);
    }

    #[tokio::test]
    async fn smux_carries_many_concurrent_streams() {
        let (client, mut accept) = pair(Codec::Smux).await;
        tokio::spawn(async move {
            while let Some(mut s) = accept.recv().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 100_000];
                    s.read_exact(&mut buf).await.unwrap();
                    s.write_all(&buf).await.unwrap();
                });
            }
        });
        let mut tasks = Vec::new();
        for i in 0..32u8 {
            let mut s = client.open().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let data = vec![i; 100_000];
                s.write_all(&data).await.unwrap();
                let mut back = vec![0u8; 100_000];
                s.read_exact(&mut back).await.unwrap();
                assert_eq!(back, data);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    #[tokio::test]
    async fn yamux_answers_ping_and_acks_new_streams() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        let (_session, _accept) = FrameSession::server(ours, Codec::Yamux);
        peer.write_all(&yamux_frame(YAMUX_WINDOW, F_SYN, 1, 0, &[]))
            .await
            .unwrap();
        peer.write_all(&yamux_frame(YAMUX_PING, F_SYN, 0, 77, &[]))
            .await
            .unwrap();
        let mut frames = [[0u8; 12]; 2];
        for f in &mut frames {
            peer.read_exact(f).await.unwrap();
        }
        assert!(frames.contains(&[0, 1, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]));
        assert!(frames.contains(&[0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 77]));
    }
}
