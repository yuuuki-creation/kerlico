mod http;
mod slots;
mod storage;
#[cfg(test)]
mod tests;
use kerlico_core::{
    BoxFuture, CancellationToken, Diagnostic, DiagnosticSink, Error, InboundContext,
    IngressBinding, NodeEvent, Result,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage::Storage;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    task::JoinSet,
};
use xray_transport::BoxedTransportStream;

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Settings {
    pub service: String,
    pub remote_folder: String,
    pub secrets: Vec<String>,
    pub template: Option<String>,
    pub s3: Option<S3>,
    pub segment_bytes: usize,
    pub flush_interval_ms: u64,
    pub poll_interval_ms: u64,
    pub max_poll_interval_ms: u64,
    pub session_ttl_seconds: u64,
    pub concurrency: usize,
    pub eager_window_ms: u64,
    pub hole_timeout_ms: u64,
    pub ca_pem: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            service: "local".into(),
            remote_folder: String::new(),
            secrets: Vec::new(),
            template: None,
            s3: None,
            segment_bytes: 65536,
            flush_interval_ms: 20,
            poll_interval_ms: 100,
            max_poll_interval_ms: 2000,
            session_ttl_seconds: 300,
            concurrency: 4,
            eager_window_ms: 1000,
            hole_timeout_ms: 10000,
            ca_pem: None,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct S3 {
    pub endpoint: String,
    #[serde(default)]
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub path_style: bool,
}
#[derive(Clone)]
pub(crate) struct Plan {
    settings: Settings,
    store: storage::Plan,
}
impl Plan {
    pub fn start(&self) -> Result<Arc<Transport>> {
        Ok(Arc::new(Transport {
            settings: self.settings.clone(),
            store: self.store.start()?,
        }))
    }
}
pub(crate) struct Transport {
    settings: Settings,
    store: Arc<dyn Storage>,
}
impl Transport {
    pub fn new(settings: Settings, ca: Option<&str>) -> Result<Arc<Self>> {
        Self::compile(settings, ca)?.start()
    }
    pub fn compile(settings: Settings, ca: Option<&str>) -> Result<Plan> {
        if !(1024..=1024 * 1024).contains(&settings.segment_bytes)
            || !(1..=1000).contains(&settings.flush_interval_ms)
            || !(1..=5000).contains(&settings.poll_interval_ms)
            || settings.max_poll_interval_ms < settings.poll_interval_ms
            || settings.max_poll_interval_ms > 60000
            || !(1..=86400).contains(&settings.session_ttl_seconds)
            || !(1..=32).contains(&settings.concurrency)
            || settings.hole_timeout_ms == 0
            || settings.remote_folder.len() > 4096
        {
            return Err(Error::Config("XDRIVE 资源或时间参数不合法".into()));
        }
        let store = storage::compile(&settings, settings.ca_pem.as_deref().or(ca))?;
        Ok(Plan { settings, store })
    }
    pub async fn open(
        self: &Arc<Self>,
        host: &kerlico_core::ServiceContext,
    ) -> Result<BoxedTransportStream> {
        let id = rand::random::<[u8; 16]>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Protocol("系统时间不可用"))?
            .as_nanos();
        self.store
            .put(&format!("sessions/{nanos}-{id}"), &[])
            .await?;
        let Connection { mut io, driving } =
            self.connection(&id, false, None, DiagnosticSink::stderr(host.language()));
        io.task = Some(host.spawn_tracked(driving)?);
        Ok(Box::new(crate::server_io::Plain(Box::new(io))))
    }
    fn connection(
        self: &Arc<Self>,
        id: &str,
        server: bool,
        ring: Option<slots::Ring>,
        diagnostics: DiagnosticSink,
    ) -> Connection {
        let (local, remote) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(remote);
        let progress = Arc::new(Progress::default());
        let cancel = CancellationToken::new();
        let write_prefix = format!("streams/{id}/{}", if server { "s2c" } else { "c2s" });
        let read_prefix = format!("streams/{id}/{}", if server { "c2s" } else { "s2c" });
        let this = self.clone();
        let status = progress.clone();
        let stop = cancel.clone();
        let writing_ring = ring
            .as_ref()
            .map(|r| if server { r.down.clone() } else { r.up.clone() });
        let write_diagnostics = diagnostics.clone();
        let writing = async move {
            let result = tokio::select! {_=stop.cancelled()=>Ok(()),r=async {if let Some(table)=writing_ring {slots::write(this.store.clone(),reader,table,&this.settings,status.clone()).await}else{write_segments(this.store.clone(),reader,&write_prefix,&this.settings,status.clone()).await}}=>r};
            if let Err(error) = result {
                write_diagnostics.emit(Diagnostic {
                    code: "vless.xdrive.background_failed",
                    error: &error,
                });
                status.fail();
            } else {
                status.finished.store(true, Ordering::Release);
                status.wake();
            }
        };
        let this = self.clone();
        let status = progress.clone();
        let stop = cancel.clone();
        let reading_ring = ring.map(|r| if server { r.up } else { r.down });
        let reading = async move {
            let result = tokio::select! {_=stop.cancelled()=>Ok(()),r=async {if let Some(table)=reading_ring {slots::read(this.store.clone(),writer,table,&this.settings).await}else{read_segments(this.store.clone(),writer,&read_prefix,&this.settings).await}}=>r};
            if let Err(error) = result {
                diagnostics.emit(Diagnostic {
                    code: "vless.xdrive.background_failed",
                    error: &error,
                });
                status.fail();
            }
        };
        Connection {
            io: DriveIo {
                io: local,
                progress,
                cancel,
                task: None,
                closing: false,
            },
            driving: Box::pin(async move {
                tokio::join!(writing, reading);
            }),
        }
    }
    pub async fn serve(
        self: Arc<Self>,
        payload: Arc<crate::inbound::Payload>,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let mut handled = HashMap::<String, Instant>::new();
        let mut tasks = JoinSet::new();
        let sessions = context.cancel.child_token();
        let polling = async {
            loop {
                tokio::select! {
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if result.is_some_and(|r| r.is_err()) {
                            context.events.record(NodeEvent::Failed);
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(self.settings.poll_interval_ms)) => {
                        if context.stream_budget.is_closed() {
                            continue;
                        }
                        handled.retain(|_, time| {
                            time.elapsed() < Duration::from_secs(self.settings.session_ttl_seconds)
                        });
                        let entries = self.store.list("sessions").await?;
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(|_| Error::Protocol("系统时间不可用"))?
                            .as_nanos();
                        for entry in entries.into_iter().take(context.max_streams.saturating_mul(4)) {
                            let Some((stamp, id)) = entry.name.split_once('-') else { continue };
                            let Ok(stamp) = stamp.parse::<u128>() else { continue };
                            if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                                continue;
                            }
                            let announce = format!("sessions/{}", entry.name);
                            if now.abs_diff(stamp) > self.settings.session_ttl_seconds as u128 * 1_000_000_000 {
                                let _ = self.store.delete(&announce).await;
                                continue;
                            }
                            if handled.contains_key(id) {
                                continue;
                            }
                            let Ok(lease) = context.stream_budget.try_acquire() else {
                                context.events.record(NodeEvent::Dropped);
                                continue;
                            };
                            let data = match entry.inline {
                                Some(data) => data,
                                None => self.store.get(&announce).await?.unwrap_or_default(),
                            };
                            let ring = match announced_ring(&data) {
                                Ok(ring) => ring,
                                Err(error) => {
                                    context.events.diagnostic(Diagnostic { code: "vless.xdrive.announcement_invalid", error: &error });
                                    let _ = self.store.delete(&announce).await;
                                    continue;
                                }
                            };
                            let diagnostic_events = context.events.clone();
                            let diagnostics = DiagnosticSink::new(move |event| diagnostic_events.diagnostic(event));
                            let connection = self.connection(id, true, ring, diagnostics);
                            handled.insert(id.to_owned(), Instant::now());
                            let payload = payload.clone();
                            let access = access.clone();
                            let mut session = context.clone();
                            session.cancel = sessions.child_token();
                            context.events.record(NodeEvent::Accepted);
                            let task = context.tasks.spawn_tracked(async move {
                                let _lease = lease;
                                let events = session.events.clone();
                                let result = connection.serve(session.cancel.clone(), move |io| async move {
                                    payload.serve(Box::new(crate::server_io::Plain(Box::new(io))), access, session).await
                                }).await;
                                if let Err(error) = &result {
                                    events.diagnostic(Diagnostic { code: "vless.xdrive.session_failed", error });
                                }
                                events.record(if result.is_ok() { NodeEvent::Completed } else { NodeEvent::Failed });
                            })?;
                            tasks.spawn(async move { let _ = task.await; });
                            let _ = self.store.delete(&announce).await;
                        }
                    }
                }
            }
        };
        let result: Result<()> = tokio::select! {
            _ = context.cancel.cancelled() => Ok(()),
            result = polling => result,
        };
        sessions.cancel();
        let cleanup = drain_sessions(&mut tasks, &context).await;
        result.and(cleanup)
    }
}

/// 公告来自共享存储。解析失败只影响这一条，调用方记诊断、删除后继续，不能停掉节点。
fn announced_ring(data: &[u8]) -> Result<Option<slots::Ring>> {
    if data.is_empty() {
        return Ok(None);
    }
    slots::Ring::parse(data).map(Some)
}

async fn drain_sessions(tasks: &mut JoinSet<()>, context: &InboundContext) -> Result<()> {
    let now = tokio::time::Instant::now();
    let deadline = now + context.drain_timeout;
    let graceful = now + context.drain_timeout.mul_f32(0.8);
    let mut forced = false;
    loop {
        match tokio::time::timeout_at(if forced { deadline } else { graceful }, tasks.join_next())
            .await
        {
            Ok(Some(result)) => {
                if result.is_err_and(|error| !error.is_cancelled()) {
                    context.events.record(NodeEvent::Failed);
                }
            }
            Ok(None) => {
                if forced {
                    context.events.record(NodeEvent::ForcedCleanup);
                }
                return Ok(());
            }
            Err(_) if !forced => {
                forced = true;
                tasks.abort_all();
            }
            Err(_) => {
                context.events.record(NodeEvent::Failed);
                return Err(Error::Timeout);
            }
        }
    }
}

struct Connection {
    io: DriveIo,
    driving: BoxFuture<'static, ()>,
}
impl Connection {
    async fn serve<F, Fut>(self, cancel: CancellationToken, serve: F) -> Result<()>
    where
        F: FnOnce(DriveIo) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let Self { io, driving } = self;
        let serving = async move {
            tokio::select! {
                _ = cancel.cancelled() => Err(Error::Cancelled),
                result = serve(io) => result,
            }
        };
        let (result, ()) = tokio::join!(serving, driving);
        result
    }
}
#[derive(Default)]
pub(crate) struct Progress {
    written: AtomicU64,
    flushed: AtomicU64,
    failed: AtomicBool,
    finished: AtomicBool,
    wakers: Mutex<Vec<Waker>>,
}
impl Progress {
    // Encryption 的读路径也可能驱动 flush；两个方向都必须收到提交完成通知。
    fn register(&self, waker: &Waker) {
        let stale = {
            let mut entries = self
                .wakers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if entries.iter().any(|entry| entry.will_wake(waker)) {
                return;
            }
            let stale = if entries.len() >= 4 {
                std::mem::take(&mut *entries)
            } else {
                Vec::new()
            };
            entries.push(waker.clone());
            stale
        };
        for waker in stale {
            waker.wake();
        }
    }
    fn wake(&self) {
        let entries = {
            let mut entries = self
                .wakers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            std::mem::take(&mut *entries)
        };
        for waker in entries {
            waker.wake();
        }
    }
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.wake();
    }
    pub fn committed(&self, n: usize) {
        self.flushed.fetch_add(n as u64, Ordering::AcqRel);
        self.wake();
    }
}
struct DriveIo {
    io: DuplexStream,
    progress: Arc<Progress>,
    cancel: CancellationToken,
    task: Option<kerlico_core::ServiceTask<()>>,
    closing: bool,
}
impl Drop for DriveIo {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl AsyncRead for DriveIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = out.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, out);
        if matches!(result, Poll::Ready(Ok(())))
            && out.filled().len() == n
            && out.remaining() > 0
            && this.progress.failed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "XDRIVE 读取失败",
            )));
        }
        result
    }
}
impl AsyncWrite for DriveIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing || this.progress.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XDRIVE 写入已结束",
            )));
        }
        this.progress.register(cx.waker());
        let result = Pin::new(&mut this.io).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = &result {
            this.progress.written.fetch_add(*n as u64, Ordering::AcqRel);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.progress.register(cx.waker());
        if this.progress.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XDRIVE 提交失败",
            )));
        }
        if this.progress.flushed.load(Ordering::Acquire)
            >= this.progress.written.load(Ordering::Acquire)
        {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        let this = self.get_mut();
        this.closing = true;
        match Pin::new(&mut this.io).poll_shutdown(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        this.progress.register(cx.waker());
        if this.progress.finished.load(Ordering::Acquire) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
async fn write_segments<R: AsyncRead + Unpin>(
    store: Arc<dyn Storage>,
    mut reader: R,
    prefix: &str,
    settings: &Settings,
    progress: Arc<Progress>,
) -> Result<()> {
    let mut sequence = 0u64;
    let mut buffer = Vec::with_capacity(settings.segment_bytes);
    let mut bytes = vec![0; settings.segment_bytes.min(65536)];
    let timer = tokio::time::sleep(Duration::from_millis(settings.flush_interval_ms));
    tokio::pin!(timer);
    loop {
        let (ended, tick) = tokio::select! {result=reader.read(&mut bytes)=>{let n=result?;buffer.extend_from_slice(&bytes[..n]);(n==0,false)},_=&mut timer=>(false,true)};
        while buffer.len() >= settings.segment_bytes || ((ended || tick) && !buffer.is_empty()) {
            let length = buffer.len().min(settings.segment_bytes);
            store
                .put(&format!("{prefix}/{sequence:09}.seg"), &buffer[..length])
                .await?;
            progress.committed(length);
            buffer.drain(..length);
            sequence = sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
        }
        if ended {
            store
                .put(&format!("{prefix}/{sequence:09}.end"), &[])
                .await?;
            return Ok(());
        }
        if tick {
            timer.as_mut().reset(
                tokio::time::Instant::now() + Duration::from_millis(settings.flush_interval_ms),
            );
        }
    }
}
async fn read_segments<W: AsyncWrite + Unpin>(
    store: Arc<dyn Storage>,
    mut writer: W,
    prefix: &str,
    settings: &Settings,
) -> Result<()> {
    let mut sequence = 0u64;
    let mut delay = settings.poll_interval_ms;
    let mut hole = None;
    let mut last_data = Instant::now();
    loop {
        let name = format!("{prefix}/{sequence:09}.seg");
        if let Some(data) = store.get(&name).await? {
            writer.write_all(&data).await?;
            writer.flush().await?;
            let _ = store.delete(&name).await;
            sequence = sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
            delay = settings.poll_interval_ms;
            hole = None;
            last_data = Instant::now();
            continue;
        }
        if store
            .get(&format!("{prefix}/{sequence:09}.err"))
            .await?
            .is_some()
        {
            return Err(Error::Protocol("XDRIVE 对端分段失败"));
        }
        let end = format!("{prefix}/{sequence:09}.end");
        if store.get(&end).await?.is_some() {
            let _ = store.delete(&end).await;
            writer.shutdown().await?;
            return Ok(());
        }
        let ahead = store.list(prefix).await?.iter().any(|entry| {
            entry
                .name
                .split_once('.')
                .and_then(|(n, _)| n.parse::<u64>().ok())
                .is_some_and(|n| n > sequence)
        });
        if ahead {
            let since = hole.get_or_insert_with(Instant::now);
            if since.elapsed() > Duration::from_millis(settings.hole_timeout_ms) {
                return Err(Error::Protocol("XDRIVE 分段缺口超时"));
            }
        } else {
            hole = None;
        }
        tokio::time::sleep(Duration::from_millis(delay)).await;
        delay = if last_data.elapsed() < Duration::from_millis(settings.eager_window_ms) {
            settings.poll_interval_ms
        } else {
            delay.saturating_mul(2).min(settings.max_poll_interval_ms)
        };
    }
}
