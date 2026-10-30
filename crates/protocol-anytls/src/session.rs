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
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::mpsc,
    time::Instant,
};

struct Entry {
    data: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
}
pub struct Session {
    frames: mpsc::Sender<Frame>,
    streams: Mutex<HashMap<u32, Entry>>,
    pub closed: CancellationToken,
    next: AtomicU32,
    pub active: AtomicUsize,
    idle_since: Mutex<Instant>,
    padding: Arc<RwLock<Padding>>,
    client: bool,
    max_streams: usize,
}
pub struct Incoming {
    pub id: u32,
    pub stream: BoxStream,
}
struct LogicalStream {
    io: DuplexStream,
    cancel: CancellationToken,
    client: bool,
    write_closed: bool,
}
impl Drop for LogicalStream {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl AsyncRead for LogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for LogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.client {
            // AnyTLS FIN 会结束全流；本地停写只禁写并保留回包，不向目标承诺 EOF。
            self.write_closed = true;
            Pin::new(&mut self.io).poll_flush(cx)
        } else {
            Pin::new(&mut self.io).poll_shutdown(cx)
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
    ) -> Result<Arc<Self>> {
        let (tx, mut rx) = mpsc::channel::<Frame>(64);
        let session = Arc::new(Self {
            frames: tx,
            streams: Mutex::new(HashMap::new()),
            closed: CancellationToken::new(),
            next: AtomicU32::new(0),
            active: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
            padding,
            client,
            max_streams,
        });
        let (mut reader, mut writer) = tokio::io::split(stream);
        let write_session = session.clone();
        tokio::spawn(async move {
            let result = async {
                let mut packet = 0u32;
                loop {
                    let frame = tokio::select! {_ = write_session.closed.cancelled()=>return Ok::<_,Error>(()), frame=rx.recv()=>match frame {Some(f)=>f,None=>return Ok(())}};
                    let mut bytes = frame.encode()?;
                    packet = packet.saturating_add(1);
                    let scheme = write_session.padding.read().unwrap().clone();
                    if client && packet < scheme.stop {
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
                    }
                    if !bytes.is_empty() {
                        writer.write_all(&bytes).await?;
                    }
                    writer.flush().await?;
                }
            };
            tokio::select! {_ = write_session.closed.cancelled()=>{}, _ = result=>{}}
            write_session.close();
        });
        let read_session = session.clone();
        tokio::spawn(async move {
            let result = read_session.receive(&mut reader, incoming);
            tokio::select! {_ = read_session.closed.cancelled()=>{}, _ = result=>{}}
            read_session.close();
        });
        let idle_session = session.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {_ = idle_session.closed.cancelled()=>break,_ = tokio::time::sleep(idle.min(Duration::from_secs(5)))=>{}}
                if idle_session.active.load(Ordering::Acquire) == 0
                    && idle_session.idle_since.lock().unwrap().elapsed() >= idle
                {
                    idle_session.close();
                    break;
                }
            }
        });
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
    pub fn close(&self) {
        self.closed.cancel();
        self.streams.lock().unwrap().clear();
    }
    pub async fn send(&self, frame: Frame) -> Result<()> {
        tokio::select! {biased;_ = self.closed.cancelled()=>Err(Error::Protocol("AnyTLS 会话已关闭")),r=self.frames.send(frame)=>r.map_err(|_|Error::Protocol("AnyTLS 会话已关闭"))}
    }
    fn logical(self: &Arc<Self>, id: u32) -> Result<BoxStream> {
        let mut streams = self.streams.lock().unwrap();
        if streams.len() >= self.max_streams || streams.contains_key(&id) {
            return Err(Error::ResourceLimit);
        }
        let (app, network) = tokio::io::duplex(65536);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
        let cancel = CancellationToken::new();
        streams.insert(
            id,
            Entry {
                data: tx,
                cancel: cancel.clone(),
            },
        );
        self.active.fetch_add(1, Ordering::AcqRel);
        let session = self.clone();
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(network);
            let outgoing = async {
                let mut buf = vec![0; 16384];
                loop {
                    let n = reader.read(&mut buf).await?;
                    if n == 0 {
                        return Ok::<_, Error>(());
                    }
                    session
                        .send(Frame::new(codec::PSH, id, buf[..n].to_vec()))
                        .await?;
                }
            };
            let incoming = async {
                while let Some(data) = rx.recv().await {
                    writer.write_all(&data).await?;
                }
                writer.shutdown().await?;
                Ok::<_, Error>(())
            };
            tokio::select! {_ = session.closed.cancelled()=>{},_ = task_cancel.cancelled()=>{},_ = outgoing=>{},_ = incoming=>{}}
            session.streams.lock().unwrap().remove(&id);
            session.active.fetch_sub(1, Ordering::AcqRel);
            *session.idle_since.lock().unwrap() = Instant::now();
            let _ = session.send(Frame::new(codec::FIN, id, Vec::new())).await;
        });
        Ok(Box::new(LogicalStream {
            io: app,
            cancel,
            client: self.client,
            write_closed: false,
        }))
    }
    pub async fn open(self: &Arc<Self>) -> Result<BoxStream> {
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
        self.send(Frame::new(codec::SYN, id, Vec::new())).await?;
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
                    if let Some(tx) = &incoming
                        && tx
                            .try_send(Incoming {
                                id: frame.id,
                                stream,
                            })
                            .is_err()
                    {
                        self.finish(frame.id);
                        self.send(Frame::new(codec::FIN, frame.id, Vec::new()))
                            .await?;
                    }
                }
                codec::FIN => {
                    self.streams.lock().unwrap().remove(&frame.id);
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding;
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
        )
        .await
        .unwrap();
        let client = Session::start(Box::new(b), true, padding, 4, Duration::from_secs(2), None)
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
