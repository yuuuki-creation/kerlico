use crate::{
    codec::{self, Frame},
    padding::Padding,
};
use kerlico_core::{BoxStream, CancellationToken, Error, Result};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf},
    sync::mpsc,
    time::Instant,
};
use tokio_util::sync::PollSender;

struct Entry {
    data: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
    ending: tokio::sync::watch::Sender<Option<kerlico_core::FlowOutcome>>,
    delivery: Arc<Delivery>,
}
impl Entry {
    fn end(self, reason: kerlico_core::FlowOutcome) {
        let (reason, waiter) = self.delivery.end(reason);
        self.ending.send_replace(Some(reason));
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}
#[derive(Default, PartialEq, Eq)]
enum FinState {
    #[default]
    Open,
    Pending,
    Flushed,
}
#[derive(Default)]
struct DeliveryState {
    submitted: u64,
    flushed: u64,
    fin: FinState,
    ending: Option<kerlico_core::FlowOutcome>,
    waiter: Option<Waker>,
}
#[derive(Default)]
struct Delivery(Mutex<DeliveryState>);
enum WriteMark {
    Bytes(u64),
    Fin(tokio::sync::oneshot::Sender<()>),
}
struct FrameDelivery {
    stream: Arc<Delivery>,
    mark: WriteMark,
}
struct QueuedFrame {
    frame: Frame,
    delivery: Option<FrameDelivery>,
}
impl Delivery {
    fn check_writable(&self, len: usize) -> io::Result<()> {
        let state = self.0.lock().unwrap();
        if let Some(reason) = state.ending {
            return Err(Self::error(reason));
        }
        if state.submitted.checked_add(len as u64).is_none() {
            return Err(io::Error::other("AnyTLS 流字节序号耗尽"));
        }
        Ok(())
    }
    fn commit_write(&self, len: usize) -> io::Result<u64> {
        let mut state = self.0.lock().unwrap();
        if let Some(reason) = state.ending {
            return Err(Self::error(reason));
        }
        state.submitted = state
            .submitted
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::other("AnyTLS 流字节序号耗尽"))?;
        Ok(state.submitted)
    }
    fn closed_error(&self) -> io::Error {
        let state = self.0.lock().unwrap();
        state.ending.map(Self::error).unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS 流在物理交付前结束")
        })
    }
    fn poll_flush(&self, cx: &mut Context<'_>, fin: bool) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().unwrap();
        if state.flushed == state.submitted && (!fin || state.fin == FinState::Flushed) {
            return Poll::Ready(Ok(()));
        }
        if let Some(reason) = state.ending {
            return Poll::Ready(Err(Self::error(reason)));
        }
        state.waiter = Some(cx.waker().clone());
        Poll::Pending
    }
    fn request_fin(&self) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        if state.fin == FinState::Flushed {
            return Ok(());
        }
        if let Some(reason) = state.ending {
            return Err(Self::error(reason));
        }
        state.fin = FinState::Pending;
        Ok(())
    }
    fn confirm(&self, mark: WriteMark) {
        let (waiter, fin) = {
            let mut state = self.0.lock().unwrap();
            if state.ending.is_some() {
                return;
            }
            let fin = match mark {
                WriteMark::Bytes(position) => {
                    state.flushed = position;
                    None
                }
                WriteMark::Fin(delivered) => {
                    state.fin = FinState::Flushed;
                    Some(delivered)
                }
            };
            (state.waiter.take(), fin)
        };
        if let Some(waiter) = waiter {
            waiter.wake();
        }
        if let Some(fin) = fin {
            let _ = fin.send(());
        }
    }
    fn end(&self, reason: kerlico_core::FlowOutcome) -> (kerlico_core::FlowOutcome, Option<Waker>) {
        let mut state = self.0.lock().unwrap();
        let reason = if matches!(
            reason,
            kerlico_core::FlowOutcome::ProtocolEnd | kerlico_core::FlowOutcome::DuplexEof
        ) && (state.submitted != state.flushed || state.fin == FinState::Pending)
        {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Failed)
        } else {
            reason
        };
        let reason = *state.ending.get_or_insert(reason);
        (reason, state.waiter.take())
    }
    fn error(reason: kerlico_core::FlowOutcome) -> io::Error {
        match reason {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Timeout) => {
                io::Error::new(io::ErrorKind::TimedOut, Error::Timeout)
            }
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Cancelled) => {
                io::Error::new(io::ErrorKind::ConnectionAborted, Error::Cancelled)
            }
            _ => io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS 流在物理交付前结束"),
        }
    }
}
pub struct Session {
    frames: mpsc::Sender<QueuedFrame>,
    streams: Mutex<HashMap<u32, Entry>>,
    pub closed: CancellationToken,
    reason: Mutex<Option<kerlico_core::FlowOutcome>>,
    next: AtomicU32,
    pub active: AtomicUsize,
    idle_since: Mutex<Instant>,
    padding: Arc<RwLock<Padding>>,
    client: bool,
    max_streams: usize,
    host: Owner,
    tasks: Mutex<Vec<Task>>,
    permit: Mutex<Option<tokio::sync::OwnedSemaphorePermit>>,
}
pub(crate) enum Owner {
    Node(kerlico_core::NodeTasks),
    Service(kerlico_core::ServiceContext),
}
enum Task {
    Local(kerlico_core::NodeTask<()>),
    Shared(kerlico_core::ServiceTask<()>),
}
pub struct Incoming {
    pub id: u32,
    pub stream: BoxStream,
    pub ending: tokio::sync::watch::Receiver<Option<kerlico_core::FlowOutcome>>,
}
struct LogicalStream {
    id: u32,
    session: Arc<Session>,
    frames: PollSender<QueuedFrame>,
    rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    cancel: CancellationToken,
    delivery: Arc<Delivery>,
    fin_sent: Arc<AtomicBool>,
    client: bool,
    write_closed: bool,
}
impl Drop for LogicalStream {
    fn drop(&mut self) {
        if let Some(entry) = self.session.streams.lock().unwrap().remove(&self.id) {
            entry.end(kerlico_core::FlowOutcome::ClosedByCaller);
        }
        self.session.active.fetch_sub(1, Ordering::AcqRel);
        *self.session.idle_since.lock().unwrap() = Instant::now();
        self.cancel.cancel();
    }
}
impl AsyncRead for LogicalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let before = buf.filled().len();
        if this.read_pos < this.read_buf.len() {
            let avail = &this.read_buf[this.read_pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.read_pos += n;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf = Vec::new();
                this.read_pos = 0;
            } else {
                return Poll::Ready(Ok(()));
            }
        }
        if buf.filled().len() == before {
            loop {
                match this.rx.poll_recv(cx) {
                    Poll::Ready(Some(data)) => {
                        if data.is_empty() {
                            continue;
                        }
                        if buf.remaining() >= data.len() {
                            buf.put_slice(&data);
                            break;
                        } else {
                            let n = buf.remaining();
                            buf.put_slice(&data[..n]);
                            this.read_buf = data;
                            this.read_pos = n;
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Poll::Ready(None) => return Poll::Ready(Ok(())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        while buf.remaining() > 0 {
            match this.rx.try_recv() {
                Ok(data) => {
                    if data.is_empty() {
                        continue;
                    }
                    if buf.remaining() >= data.len() {
                        buf.put_slice(&data);
                    } else {
                        this.read_buf = data;
                        this.read_pos = 0;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for LogicalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let this = self.get_mut();
        if let Err(err) = this.delivery.check_writable(buf.len()) {
            return Poll::Ready(Err(err));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.frames.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(_)) => return Poll::Ready(Err(this.delivery.closed_error())),
            Poll::Pending => return Poll::Pending,
        }
        let n = buf.len().min(16384);
        let position = match this.delivery.commit_write(n) {
            Ok(pos) => pos,
            Err(err) => {
                this.frames.abort_send();
                return Poll::Ready(Err(err));
            }
        };
        let frame = Frame::new(codec::PSH, this.id, buf[..n].to_vec());
        let delivery = Some(FrameDelivery {
            stream: this.delivery.clone(),
            mark: WriteMark::Bytes(position),
        });
        if this
            .frames
            .send_item(QueuedFrame { frame, delivery })
            .is_err()
        {
            return Poll::Ready(Err(this.delivery.closed_error()));
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.delivery.poll_flush(cx, false)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_closed = true;
        std::task::ready!(this.delivery.poll_flush(cx, false))?;
        if this.client {
            // AnyTLS FIN 会结束全流；本地停写只禁写并保留回包，不向目标承诺 EOF。
            Poll::Ready(Ok(()))
        } else {
            if !this.fin_sent.load(Ordering::Acquire) {
                this.delivery.request_fin()?;
                match this.frames.poll_reserve(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(this.delivery.closed_error())),
                    Poll::Pending => return Poll::Pending,
                }
                let (delivered, _confirmed) = tokio::sync::oneshot::channel();
                this.fin_sent.store(true, Ordering::Release);
                if this
                    .frames
                    .send_item(QueuedFrame {
                        frame: Frame::new(codec::FIN, this.id, Vec::new()),
                        delivery: Some(FrameDelivery {
                            stream: this.delivery.clone(),
                            mark: WriteMark::Fin(delivered),
                        }),
                    })
                    .is_err()
                {
                    return Poll::Ready(Err(this.delivery.closed_error()));
                }
            }
            let res = std::task::ready!(this.delivery.poll_flush(cx, true));
            if res.is_ok()
                && let Some(entry) = this.session.streams.lock().unwrap().remove(&this.id)
            {
                entry.end(kerlico_core::FlowOutcome::ProtocolEnd);
            }
            Poll::Ready(res)
        }
    }
}
impl Session {
    pub async fn start(
        stream: BoxStream,
        client: bool,
        padding: Arc<RwLock<Padding>>,
        max_streams: usize,
        idle: Duration,
        incoming: Option<mpsc::Sender<Incoming>>,
        host: Owner,
    ) -> Result<Arc<Self>> {
        let (tx, mut rx) = mpsc::channel::<QueuedFrame>(128);
        let session = Arc::new(Self {
            frames: tx,
            streams: Mutex::new(HashMap::new()),
            closed: CancellationToken::new(),
            reason: Mutex::new(None),
            next: AtomicU32::new(0),
            active: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
            padding,
            client,
            max_streams,
            host,
            tasks: Mutex::new(Vec::new()),
            permit: Mutex::new(None),
        });
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::with_capacity(131072, reader);
        let write_session = session.clone();
        session.spawn(async move {
            let result = async {
                let mut packet = 0u32;
                let mut write_buf = Vec::with_capacity(65536 + 1024);
                let mut pending_deliveries = Vec::with_capacity(16);
                loop {
                    let QueuedFrame { frame, delivery } = tokio::select! {_ = write_session.closed.cancelled()=>return Ok::<_,Error>(()), frame=rx.recv()=>match frame {Some(f)=>f,None=>return Ok(())}};
                    packet = packet.saturating_add(1);
                    let stop = if client {
                        write_session.padding.read().unwrap().stop
                    } else {
                        0
                    };
                    if client && packet < stop {
                        let mut bytes = frame.encode()?;
                        let scheme = write_session.padding.read().unwrap().clone();
                        for size in scheme.sizes(packet) {
                            let Some(size) = size else {
                                if bytes.is_empty() { break } else { continue }
                            };
                            if bytes.len() > size {
                                writer.write_all(&bytes[..size]).await?;
                                bytes.drain(..size);
                            } else if !bytes.is_empty() {
                                if size > bytes.len() + 7 {
                                    let waste = Frame::new(
                                        codec::WASTE,
                                        0,
                                        vec![0; size - bytes.len() - 7],
                                    )
                                    .encode()?;
                                    bytes.extend_from_slice(&waste);
                                }
                                writer.write_all(&bytes).await?;
                                bytes.clear();
                            } else {
                                writer
                                    .write_all(
                                        &Frame::new(codec::WASTE, 0, vec![0; size]).encode()?,
                                    )
                                    .await?;
                            }
                        }
                        if !bytes.is_empty() {
                            writer.write_all(&bytes).await?;
                        }
                        writer.flush().await?;
                        if let Some(delivery) = delivery {
                            delivery.stream.confirm(delivery.mark);
                        }
                    } else {
                        write_buf.clear();
                        frame.encode_into(&mut write_buf)?;
                        if let Some(delivery) = delivery {
                            pending_deliveries.push(delivery);
                        }
                        while write_buf.len() < 48 * 1024 {
                            let Ok(QueuedFrame {
                                frame: next_frame,
                                delivery: next_delivery,
                            }) = rx.try_recv()
                            else {
                                break;
                            };
                            packet = packet.saturating_add(1);
                            next_frame.encode_into(&mut write_buf)?;
                            if let Some(d) = next_delivery {
                                pending_deliveries.push(d);
                            }
                        }
                        writer.write_all(&write_buf).await?;
                        writer.flush().await?;
                        for d in pending_deliveries.drain(..) {
                            d.stream.confirm(d.mark);
                        }
                    }
                }
            };
            let result=tokio::select! {_ = write_session.closed.cancelled()=>return, result=result=>result};
            write_session.close_with(crate::flow::reason(&result));
        })?;
        let read_session = session.clone();
        session.spawn(async move {
            let result = read_session.receive(&mut reader, incoming);
            let result =
                tokio::select! {_ = read_session.closed.cancelled()=>return, result=result=>result};
            read_session.close_with(crate::flow::reason(&result));
        })?;
        let idle_session = session.clone();
        session.spawn(async move {
            loop {
                tokio::select! {_ = idle_session.closed.cancelled()=>break,_ = tokio::time::sleep(idle.min(Duration::from_secs(5)))=>{}}
                if idle_session.active.load(Ordering::Acquire) == 0
                    && idle_session.idle_since.lock().unwrap().elapsed() >= idle
                {
                    idle_session.close_with(kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::Timeout));
                    break;
                }
            }
        })?;
        if client {
            let md5 = session.padding.read().unwrap().md5.clone();
            session
                .send(Frame::new(
                    codec::SETTINGS,
                    0,
                    format!("v=2\nclient=kerlico\npadding-md5={md5}").into_bytes(),
                ))
                .await?;
        }
        Ok(session)
    }
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) -> Result<()> {
        let task = match &self.host {
            Owner::Service(host) => Task::Shared(host.spawn_tracked(future)?),
            Owner::Node(owner) => Task::Local(owner.spawn_tracked(future)?),
        };
        self.tasks.lock().map_err(|_| Error::Rejected)?.push(task);
        Ok(())
    }
    pub async fn shutdown(&self) {
        self.close();
        let tasks = self
            .tasks
            .lock()
            .map(|mut tasks| std::mem::take(&mut *tasks))
            .unwrap_or_default();
        for task in tasks {
            match task {
                Task::Local(task) => {
                    task.abort();
                    let _ = task.await;
                }
                Task::Shared(task) => {
                    task.abort();
                    let _ = task.await;
                }
            }
        }
    }
    pub fn assign_permit(&self, permit: tokio::sync::OwnedSemaphorePermit) {
        let mut held = self.permit.lock().unwrap();
        if !self.closed.is_cancelled() {
            *held = Some(permit);
        }
    }
    pub fn finish_reason(&self) -> kerlico_core::FlowOutcome {
        self.reason
            .lock()
            .ok()
            .and_then(|value| *value)
            .unwrap_or(kerlico_core::FlowOutcome::ClosedByCaller)
    }
    pub fn close_with(&self, reason: kerlico_core::FlowOutcome) {
        if let Ok(mut value) = self.reason.lock() {
            value.get_or_insert(reason);
        }
        self.close();
    }
    pub fn close(&self) {
        let reason = *self
            .reason
            .lock()
            .unwrap()
            .get_or_insert(kerlico_core::FlowOutcome::ClosedByCaller);
        let entries = std::mem::take(&mut *self.streams.lock().unwrap());
        for entry in entries.into_values() {
            entry.end(reason);
        }
        self.closed.cancel();
        self.permit.lock().unwrap().take();
    }
    pub async fn send(&self, frame: Frame) -> Result<()> {
        self.queue(QueuedFrame {
            frame,
            delivery: None,
        })
        .await
    }
    async fn queue(&self, frame: QueuedFrame) -> Result<()> {
        tokio::select! {biased;_ = self.closed.cancelled()=>Err(Error::Protocol("AnyTLS 会话已关闭")),r=self.frames.send(frame)=>r.map_err(|_|Error::Protocol("AnyTLS 会话已关闭"))}
    }
    fn logical(self: &Arc<Self>, id: u32) -> Result<BoxStream> {
        let mut streams = self.streams.lock().unwrap();
        if streams.len() >= self.max_streams || streams.contains_key(&id) {
            return Err(Error::ResourceLimit);
        }
        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
        let cancel = CancellationToken::new();
        let delivery = Arc::new(Delivery::default());
        let fin_sent = Arc::new(AtomicBool::new(false));
        let (ending_tx, mut ended) = tokio::sync::watch::channel(None);
        streams.insert(
            id,
            Entry {
                data: tx,
                cancel: cancel.clone(),
                ending: ending_tx,
                delivery: delivery.clone(),
            },
        );
        self.active.fetch_add(1, Ordering::AcqRel);
        let session = self.clone();
        let task_cancel = cancel.clone();
        let task_fin_sent = fin_sent.clone();
        self.spawn(async move {
            let reason = tokio::select! {
                biased;
                _ = session.closed.cancelled() => session.finish_reason(),
                _ = task_cancel.cancelled() => kerlico_core::FlowOutcome::ClosedByCaller,
                reason = crate::flow::ended(&mut ended) => reason,
            };
            if let Some(entry) = session.streams.lock().unwrap().remove(&id) {
                entry.end(reason);
            }
            if !task_fin_sent.load(Ordering::Acquire) {
                let _ = session.send(Frame::new(codec::FIN, id, Vec::new())).await;
            }
        })?;
        Ok(Box::new(LogicalStream {
            id,
            session: self.clone(),
            frames: PollSender::new(self.frames.clone()),
            rx,
            read_buf: Vec::new(),
            read_pos: 0,
            cancel,
            delivery,
            fin_sent,
            client: self.client,
            write_closed: false,
        }))
    }
    pub fn reserve_stream(self: &Arc<Self>) -> Result<(u32, BoxStream)> {
        let id = self
            .next
            .fetch_add(1, Ordering::AcqRel)
            .checked_add(1)
            .ok_or(Error::ResourceLimit)?;
        if id == u32::MAX {
            self.close();
            return Err(Error::ResourceLimit);
        }
        let stream = self.logical(id)?;
        Ok((id, stream))
    }
    pub async fn send_syn(&self, id: u32) -> Result<()> {
        self.send(Frame::new(codec::SYN, id, Vec::new())).await
    }
    #[cfg(test)]
    pub async fn open(self: &Arc<Self>) -> Result<BoxStream> {
        let (id, stream) = self.reserve_stream()?;
        self.send_syn(id).await?;
        Ok(stream)
    }
    async fn receive(
        self: &Arc<Self>,
        reader: &mut (impl AsyncRead + Unpin),
        incoming: Option<mpsc::Sender<Incoming>>,
    ) -> Result<()> {
        let mut settings = false;
        let mut last_id = 0;
        loop {
            let frame = Frame::read(reader).await?;
            match frame.command {
                codec::PSH => {
                    let sender = self
                        .streams
                        .lock()
                        .unwrap()
                        .get(&frame.id)
                        .map(|e| e.data.clone());
                    if let Some(sender) = sender
                        && sender.send(frame.data).await.is_err()
                    {
                        self.finish(frame.id);
                        self.send(Frame::new(codec::FIN, frame.id, Vec::new()))
                            .await?;
                    }
                }
                codec::SYN if !self.client => {
                    if !settings || frame.id == 0 || frame.id <= last_id || !frame.data.is_empty() {
                        return Err(Error::Protocol("AnyTLS 流建立顺序不合法"));
                    }
                    last_id = frame.id;
                    let stream = match self.logical(frame.id) {
                        Ok(s) => s,
                        Err(_) => {
                            self.send(Frame::new(
                                codec::SYNACK,
                                frame.id,
                                "流数量达到上限".as_bytes().to_vec(),
                            ))
                            .await?;
                            self.send(Frame::new(codec::FIN, frame.id, Vec::new()))
                                .await?;
                            continue;
                        }
                    };
                    let ending = self
                        .streams
                        .lock()
                        .unwrap()
                        .get(&frame.id)
                        .ok_or(Error::Cancelled)?
                        .ending
                        .subscribe();
                    if let Some(tx) = &incoming
                        && tx
                            .try_send(Incoming {
                                id: frame.id,
                                stream,
                                ending,
                            })
                            .is_err()
                    {
                        self.finish(frame.id);
                        self.send(Frame::new(codec::FIN, frame.id, Vec::new()))
                            .await?;
                    }
                }
                codec::FIN => {
                    let entry = self.streams.lock().unwrap().remove(&frame.id);
                    if let Some(entry) = entry {
                        entry.end(kerlico_core::FlowOutcome::ProtocolEnd);
                    }
                }
                codec::SETTINGS if !self.client => {
                    if settings || frame.id != 0 {
                        return Err(Error::Protocol("AnyTLS 设置重复或流标识不合法"));
                    }
                    let text = std::str::from_utf8(&frame.data)
                        .map_err(|_| Error::Protocol("AnyTLS 设置编码不合法"))?;
                    let values: HashMap<_, _> =
                        text.lines().filter_map(|s| s.split_once('=')).collect();
                    settings = true;
                    let scheme = self.padding.read().unwrap().clone();
                    if values.get("padding-md5").copied() != Some(scheme.md5.as_str()) {
                        self.send(Frame::new(codec::PADDING, 0, scheme.raw.into_bytes()))
                            .await?;
                    }
                    if values
                        .get("v")
                        .and_then(|v| v.parse::<u32>().ok())
                        .unwrap_or(0)
                        >= 2
                    {
                        self.send(Frame::new(codec::SERVER_SETTINGS, 0, b"v=2".to_vec()))
                            .await?;
                    }
                }
                codec::PADDING if self.client => {
                    if let Ok(text) = std::str::from_utf8(&frame.data)
                        && let Ok(p) = Padding::parse(text)
                    {
                        *self.padding.write().unwrap() = p;
                    }
                }
                codec::SYNACK if self.client => {
                    if !frame.data.is_empty() {
                        self.finish(frame.id);
                    }
                }
                codec::HEART_REQUEST => {
                    if !frame.data.is_empty() {
                        return Err(Error::Protocol("AnyTLS 心跳长度不合法"));
                    }
                    self.send(Frame::new(codec::HEART_RESPONSE, frame.id, Vec::new()))
                        .await?;
                }
                codec::ALERT => return Err(Error::Protocol("AnyTLS 对端拒绝会话")),
                codec::WASTE | codec::SERVER_SETTINGS | codec::HEART_RESPONSE => {}
                _ => return Err(Error::Protocol("AnyTLS 命令或方向不合法")),
            }
        }
    }
    fn finish(&self, id: u32) {
        if let Some(entry) = self.streams.lock().unwrap().remove(&id) {
            entry.cancel.cancel();
            entry.end(kerlico_core::FlowOutcome::ClosedByCaller);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn concurrent_streams_heartbeat_and_close() {
        let padding = Arc::new(RwLock::new(Padding::parse(padding::DEFAULT).unwrap()));
        let (a, b) = tokio::io::duplex(65536);
        let (tx, mut rx) = mpsc::channel(4);
        let server = Session::start(
            Box::new(a),
            false,
            padding.clone(),
            4,
            Duration::from_secs(2),
            Some(tx),
            Owner::Node(kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                CancellationToken::new(),
            )),
        )
        .await
        .unwrap();
        let client = Session::start(
            Box::new(b),
            true,
            padding,
            4,
            Duration::from_secs(2),
            None,
            Owner::Node(kerlico_core::NodeTasks::new(
                kerlico_core::NodeId::parse("test-node").unwrap(),
                CancellationToken::new(),
            )),
        )
        .await
        .unwrap();
        let mut first = client.open().await.unwrap();
        let mut second = client.open().await.unwrap();
        first.write_all(b"one").await.unwrap();
        second.write_all(b"two").await.unwrap();
        let mut incoming = rx.recv().await.unwrap();
        let mut another = rx.recv().await.unwrap();
        let mut bytes = [0; 3];
        incoming.stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"one");
        another.stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"two");
        client
            .send(Frame::new(codec::HEART_REQUEST, 11, Vec::new()))
            .await
            .unwrap();
        incoming.stream.write_all(b"ONE").await.unwrap();
        another.stream.write_all(b"TWO").await.unwrap();
        first.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ONE");
        second.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"TWO");
        drop(first);
        drop(second);
        drop(incoming);
        drop(another);
        client.close();
        tokio::time::timeout(Duration::from_secs(1), server.closed.cancelled())
            .await
            .unwrap();
    }
}
