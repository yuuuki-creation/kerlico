//! 客户端连接池与逻辑流。会话选择与 sing-mux `Client.selectSession` 一致。

use super::{
    SingMuxOutboundConfig, SingMuxProtocol,
    frame::{Codec, FrameSession},
    h2mux::H2Client,
    magic_destination,
    padding::PaddedIo,
    wire::{
        BRUTAL_EXCHANGE_DOMAIN, SessionRequest, SocksAddr, StreamKind, StreamRequest,
        read_brutal_response,
    },
};
use kerlico_core::{
    AddressedDatagram, BoxFuture, BoxStream, DatagramAssociation, DatagramAssociationReceiver,
    DatagramAssociationSender, DatagramChannel, DatagramReceiver, DatagramSender, Destination,
    Error, OpenedTcp, Result, TcpConnectInfo,
};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    sync::Mutex,
};

#[derive(Clone)]
enum Session {
    Frame(FrameSession),
    H2(H2Client),
}

impl Session {
    async fn connect(mut carrier: BoxStream, config: &SingMuxOutboundConfig) -> Result<Self> {
        let request = SessionRequest {
            protocol: config.protocol,
            padding: config.padding,
        };
        carrier.write_all(&request.encode()).await?;
        carrier.flush().await?;
        let io: BoxStream = if config.padding {
            Box::new(PaddedIo::new(carrier))
        } else {
            carrier
        };
        Ok(match config.protocol {
            SingMuxProtocol::Smux => Self::Frame(FrameSession::client(io, Codec::Smux)),
            SingMuxProtocol::Yamux => Self::Frame(FrameSession::client(io, Codec::Yamux)),
            SingMuxProtocol::H2Mux => Self::H2(H2Client::connect(io).await?),
        })
    }

    async fn open(&self) -> io::Result<BoxStream> {
        Ok(match self {
            Self::Frame(session) => Box::new(session.open().await?),
            Self::H2(client) => Box::new(client.open().await?),
        })
    }

    fn is_closed(&self) -> bool {
        match self {
            Self::Frame(session) => session.is_closed(),
            Self::H2(client) => client.is_closed(),
        }
    }

    fn close(&self) {
        match self {
            Self::Frame(session) => session.close(),
            Self::H2(client) => client.close(),
        }
    }
}

pub(super) struct Pooled {
    session: Session,
    streams: Arc<AtomicUsize>,
}

impl Pooled {
    fn streams(&self) -> usize {
        self.streams.load(Ordering::Acquire)
    }
}

struct StreamGuard(Arc<AtomicUsize>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct SingMuxClient {
    config: SingMuxOutboundConfig,
    pub(super) sessions: Mutex<Vec<Arc<Pooled>>>,
}

impl SingMuxClient {
    pub fn new(config: SingMuxOutboundConfig) -> Self {
        Self {
            config,
            sessions: Mutex::new(Vec::new()),
        }
    }

    pub fn only_tcp(&self) -> bool {
        self.config.only_tcp
    }

    pub fn config(&self) -> &SingMuxOutboundConfig {
        &self.config
    }

    pub fn handles_tcp(&self) -> bool {
        self.config.handles_tcp()
    }

    pub fn handles_udp(&self) -> bool {
        self.config.handles_udp()
    }

    fn select(&self, sessions: &[Arc<Pooled>]) -> Option<Arc<Pooled>> {
        if self.config.brutal_bps().is_some() {
            return sessions.first().cloned();
        }
        let max_connections = self.config.max_connections.unwrap_or(0) as usize;
        let max_streams = self.config.max_streams.unwrap_or(0) as usize;
        let min_streams = self.config.min_streams.unwrap_or(0) as usize;
        let session = sessions.iter().min_by_key(|s| s.streams())?;
        let streams = session.streams();
        let reuse = streams == 0
            || if max_connections > 0 {
                sessions.len() >= max_connections || streams < min_streams
            } else {
                max_streams > 0 && streams < max_streams
            };
        reuse.then(|| session.clone())
    }

    async fn offer<F, Fut>(&self, dial: &mut Option<F>) -> Result<Arc<Pooled>>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|s| !s.session.is_closed());
        if let Some(session) = self.select(&sessions) {
            session.streams.fetch_add(1, Ordering::AcqRel);
            return Ok(session);
        }
        let dial = dial
            .take()
            .ok_or(Error::Protocol("sing-mux 会话在打开流前关闭"))?;
        let carrier = dial(magic_destination()).await?;
        let session = Session::connect(carrier, &self.config).await?;
        if let Some((_, receive_bps)) = self.config.brutal_bps()
            && let Err(err) = brutal_exchange(&session, receive_bps).await
        {
            session.close();
            return Err(err);
        }
        let pooled = Arc::new(Pooled {
            session,
            streams: Arc::new(AtomicUsize::new(1)),
        });
        sessions.push(pooled.clone());
        Ok(pooled)
    }

    /// `request` 为空时由调用方随首个数据包写出流请求。
    async fn open_stream<F, Fut>(
        &self,
        request: Option<StreamRequest>,
        dial: F,
    ) -> Result<ClientStream>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let header = request.map(|r| r.encode()).transpose()?;
        let mut dial = Some(dial);
        let mut last = None;
        for _ in 0..2 {
            let pooled = self.offer(&mut dial).await?;
            let guard = StreamGuard(pooled.streams.clone());
            match pooled.session.open().await {
                Ok(mut stream) => {
                    if let Some(header) = &header {
                        stream.write_all(header).await?;
                    }
                    return Ok(ClientStream::new(stream, Some(guard)));
                }
                Err(err) => {
                    pooled.session.close();
                    last = Some(err.into());
                }
            }
        }
        Err(last.unwrap_or(Error::Protocol("sing-mux 无法打开逻辑流")))
    }

    pub async fn connect_tcp<F, Fut>(&self, target: &Destination, dial: F) -> Result<OpenedTcp>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let request = StreamRequest {
            kind: StreamKind::Tcp,
            addr: SocksAddr::from_destination(target),
        };
        let stream = self.open_stream(Some(request), dial).await?;
        Ok(OpenedTcp {
            stream: Box::new(stream),
            info: TcpConnectInfo::unknown(),
        })
    }

    pub async fn connect_udp<F, Fut>(
        &self,
        target: &Destination,
        dial: F,
    ) -> Result<DatagramChannel>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let request = StreamRequest {
            kind: StreamKind::Udp,
            addr: SocksAddr::from_destination(target),
        };
        let (reader, writer) = tokio::io::split(self.open_stream(Some(request), dial).await?);
        Ok(DatagramChannel {
            sender: Box::new(UdpSender { writer }),
            receiver: Box::new(UdpReceiver {
                reader,
                peer: target.clone(),
            }),
        })
    }

    pub async fn associate_udp<F, Fut>(&self, dial: F) -> Result<DatagramAssociation>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let (reader, writer) = tokio::io::split(self.open_stream(None, dial).await?);
        Ok(DatagramAssociation {
            sender: Box::new(AssocSender {
                writer,
                request_written: false,
            }),
            receiver: Box::new(AssocReceiver { reader }),
        })
    }
}

async fn brutal_exchange(session: &Session, receive_bps: u64) -> Result<()> {
    let mut stream = session.open().await?;
    let mut request = StreamRequest {
        kind: StreamKind::Tcp,
        addr: SocksAddr::domain(BRUTAL_EXCHANGE_DOMAIN, 0),
    }
    .encode()?;
    request.extend_from_slice(&receive_bps.to_be_bytes());
    stream.write_all(&request).await?;
    let mut stream = ClientStream::new(stream, None);
    read_brutal_response(&mut stream).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

enum Status {
    Pending,
    ErrorLen { value: u64, shift: u32 },
    ErrorText { len: usize, text: Vec<u8> },
    Ready,
}

/// 客户端逻辑流：流请求在打开时写出；服务端状态字节在首次读取时解析，
/// 因为 sing-mux 服务端在首个下行数据前才写状态。
pub(super) struct ClientStream {
    inner: BoxStream,
    status: Status,
    _guard: Option<StreamGuard>,
}

impl ClientStream {
    fn new(inner: BoxStream, guard: Option<StreamGuard>) -> Self {
        Self {
            inner,
            status: Status::Pending,
            _guard: guard,
        }
    }

    fn poll_status(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if matches!(self.status, Status::Ready) {
                return Poll::Ready(Ok(()));
            }
            let mut byte = [0u8; 1];
            let mut buf = ReadBuf::new(&mut byte);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sing-mux 流在状态响应前关闭",
                )));
            }
            let b = byte[0];
            let next = match &mut self.status {
                Status::Pending => match b {
                    0 => Status::Ready,
                    1 => Status::ErrorLen { value: 0, shift: 0 },
                    _ => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sing-mux 流状态字节不合法",
                        )));
                    }
                },
                Status::ErrorLen { value, shift } => {
                    *value |= u64::from(b & 0x7f) << *shift;
                    if b & 0x80 != 0 {
                        *shift += 7;
                        if *shift > 63 {
                            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                        }
                        continue;
                    }
                    let len = (*value).min(4096) as usize;
                    if len == 0 {
                        return Poll::Ready(Err(io::Error::other("sing-mux 远端错误")));
                    }
                    Status::ErrorText {
                        len,
                        text: Vec::with_capacity(len),
                    }
                }
                Status::ErrorText { len, text } => {
                    text.push(b);
                    if text.len() < *len {
                        continue;
                    }
                    return Poll::Ready(Err(io::Error::other(format!(
                        "sing-mux 远端错误：{}",
                        String::from_utf8_lossy(text)
                    ))));
                }
                Status::Ready => unreachable!("已在循环入口返回"),
            };
            self.status = next;
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_status(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn length_prefix(packet: &[u8]) -> Result<[u8; 2]> {
    u16::try_from(packet.len())
        .map(u16::to_be_bytes)
        .map_err(|_| Error::Protocol("UDP 负载超过 65535"))
}

struct UdpSender {
    writer: WriteHalf<ClientStream>,
}

impl DatagramSender for UdpSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut frame = Vec::with_capacity(2 + packet.len());
            frame.extend_from_slice(&length_prefix(packet)?);
            frame.extend_from_slice(packet);
            self.writer.write_all(&frame).await?;
            Ok(())
        })
    }
}

struct UdpReceiver {
    reader: ReadHalf<ClientStream>,
    peer: Destination,
}

impl DatagramReceiver for UdpReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.peer.clone())
    }

    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let len = match self.reader.read_u16().await {
                Ok(n) => usize::from(n),
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            let mut buf = vec![0u8; len];
            self.reader.read_exact(&mut buf).await?;
            Ok(Some(buf))
        })
    }
}

/// 与 sing-mux `clientPacketAddrConn` 一致：流请求随首包写出，请求目标取首包目标；
/// sing-box 服务端按该目标路由整条 UDP 流，占位目标会被拒绝。
struct AssocSender {
    writer: WriteHalf<ClientStream>,
    request_written: bool,
}

impl DatagramAssociationSender for AssocSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let addr = SocksAddr::from_destination(target);
            let mut frame = if self.request_written {
                Vec::with_capacity(264 + packet.len())
            } else {
                StreamRequest {
                    kind: StreamKind::UdpPacketAddr,
                    addr: addr.clone(),
                }
                .encode()?
            };
            addr.encode_into(&mut frame)?;
            frame.extend_from_slice(&length_prefix(packet)?);
            frame.extend_from_slice(packet);
            self.writer.write_all(&frame).await?;
            self.request_written = true;
            Ok(())
        })
    }
}

struct AssocReceiver {
    reader: ReadHalf<ClientStream>,
}

impl DatagramAssociationReceiver for AssocReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            let family = match self.reader.read_u8().await {
                Ok(f) => f,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            let source = SocksAddr::read_with_family(family, &mut self.reader)
                .await?
                .to_destination()?;
            let len = usize::from(self.reader.read_u16().await?);
            let mut buf = vec![0u8; len];
            self.reader.read_exact(&mut buf).await?;
            Ok(Some((source, buf)))
        })
    }
}
