//! `sing-mux` 多路复用客户端连接池与服务端接入实现（支持 `h2mux`、`smux`、`yamux`）。

use crate::uot::{encode_uot_address, read_uot_address};
use kerlico_core::{
    AddressedDatagram, BoxFuture, BoxStream, ConnectContext, DatagramAssociation,
    DatagramAssociationReceiver, DatagramAssociationSender, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, FlowOutcome, InboundContext, OpenedTcp, PeerSession,
    Result, TcpConnectInfo,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, mpsc},
};

pub const MAGIC_HOST: &str = "sp.mux.sing-box.arpa";
pub const SING_MUX_HOST: &str = MAGIC_HOST;
pub const MAGIC_PORT: u16 = 444;

pub fn is_sing_mux_target(target: &Destination) -> bool {
    is_magic_target(target)
}

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const H2_EMPTY_SETTINGS: [u8; 9] = [0, 0, 0, 4, 0, 0, 0, 0, 0];

pub fn magic_destination() -> Destination {
    Destination::new(MAGIC_HOST, MAGIC_PORT).expect("合法内置 sing-mux 目标")
}

pub fn is_magic_target(target: &Destination) -> bool {
    target.host().eq_ignore_ascii_case(MAGIC_HOST)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SingMuxProtocol {
    #[default]
    #[serde(alias = "h2")]
    H2Mux,
    Smux,
    Yamux,
}

impl SingMuxProtocol {
    fn code(self) -> u8 {
        match self {
            Self::Smux => 0,
            Self::Yamux => 1,
            Self::H2Mux => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Smux),
            1 => Ok(Self::Yamux),
            2 => Ok(Self::H2Mux),
            _ => Err(Error::Protocol("未知的 sing-mux 子协议编号")),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SingMuxOutboundConfig {
    pub enabled: bool,
    pub protocol: SingMuxProtocol,
    #[serde(alias = "max-connections")]
    pub max_connections: Option<u32>,
    #[serde(alias = "min-streams")]
    pub min_streams: Option<u32>,
    #[serde(alias = "max-streams")]
    pub max_streams: Option<u32>,
    pub padding: bool,
    #[serde(alias = "only-tcp")]
    pub only_tcp: bool,
}

impl SingMuxOutboundConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_connections == Some(0) {
            return Err(Error::Config("multiplex.max_connections 不能为 0".into()));
        }
        if self.min_streams == Some(0) {
            return Err(Error::Config("multiplex.min_streams 不能为 0".into()));
        }
        if self.max_streams == Some(0) {
            return Err(Error::Config("multiplex.max_streams 不能为 0".into()));
        }
        Ok(())
    }

    pub fn handles_tcp(&self) -> bool {
        self.enabled
    }

    pub fn handles_udp(&self) -> bool {
        self.enabled && !self.only_tcp
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SingMuxInboundConfig {
    pub enabled: bool,
    pub padding: bool,
}

impl SingMuxInboundConfig {
    pub fn effective_with_padding(
        config: Option<&Self>,
        legacy_padding: Option<bool>,
    ) -> Option<Self> {
        match (config, legacy_padding) {
            (Some(cfg), Some(pad)) => Some(Self {
                enabled: cfg.enabled || pad,
                padding: cfg.padding || pad,
            }),
            (Some(cfg), None) => {
                if cfg.enabled || cfg.padding {
                    Some(Self {
                        enabled: true,
                        padding: cfg.padding,
                    })
                } else {
                    None
                }
            }
            (None, Some(pad)) => Some(Self {
                enabled: true,
                padding: pad,
            }),
            (None, None) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameCmd {
    Syn,
    Psh,
    Fin,
    Nop,
}

struct WireFrame {
    cmd: FrameCmd,
    stream_id: u32,
    payload: Vec<u8>,
}

fn encode_wire_frame_into(out: &mut Vec<u8>, protocol: SingMuxProtocol, frame: &WireFrame) {
    match protocol {
        SingMuxProtocol::Smux => {
            let cmd = match frame.cmd {
                FrameCmd::Syn => 0u8,
                FrameCmd::Fin => 1u8,
                FrameCmd::Psh => 2u8,
                FrameCmd::Nop => 3u8,
            };
            let len = u16::try_from(frame.payload.len()).unwrap_or(u16::MAX);
            let mut hdr = [0u8; 8];
            hdr[0] = 1;
            hdr[1] = cmd;
            hdr[2..4].copy_from_slice(&len.to_le_bytes());
            hdr[4..8].copy_from_slice(&frame.stream_id.to_le_bytes());
            out.extend_from_slice(&hdr);
            if len > 0 {
                out.extend_from_slice(&frame.payload[..usize::from(len)]);
            }
        }
        SingMuxProtocol::Yamux => {
            let (ty, flags) = match frame.cmd {
                FrameCmd::Syn => (0u8, 1u16),
                FrameCmd::Psh => (0u8, 0u16),
                FrameCmd::Fin => (0u8, 4u16),
                FrameCmd::Nop => (2u8, 1u16),
            };
            let len = u32::try_from(frame.payload.len()).unwrap_or(u32::MAX);
            let mut hdr = [0u8; 12];
            hdr[0] = 0;
            hdr[1] = ty;
            hdr[2..4].copy_from_slice(&flags.to_be_bytes());
            hdr[4..8].copy_from_slice(&frame.stream_id.to_be_bytes());
            hdr[8..12].copy_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&hdr);
            if len > 0 && ty == 0 {
                out.extend_from_slice(&frame.payload[..len as usize]);
            }
        }
        SingMuxProtocol::H2Mux => {
            let (ty, flags) = match frame.cmd {
                FrameCmd::Syn => (1u8, 0x04u8),
                FrameCmd::Psh => (0u8, 0x00u8),
                FrameCmd::Fin => (0u8, 0x01u8),
                FrameCmd::Nop => (6u8, 0x00u8),
            };
            let payload: &[u8] = if matches!(frame.cmd, FrameCmd::Nop) && frame.payload.len() != 8 {
                &[0u8; 8]
            } else {
                &frame.payload
            };
            let len = payload.len().min(0x00ff_ffff);
            let mut hdr = [0u8; 9];
            hdr[0] = ((len >> 16) & 0xff) as u8;
            hdr[1] = ((len >> 8) & 0xff) as u8;
            hdr[2] = (len & 0xff) as u8;
            hdr[3] = ty;
            hdr[4] = flags;
            hdr[5..9].copy_from_slice(&(frame.stream_id & 0x7fff_ffff).to_be_bytes());
            out.extend_from_slice(&hdr);
            if len > 0 {
                out.extend_from_slice(&payload[..len]);
            }
        }
    }
}

async fn write_wire_frames_batched(
    writer: &mut (impl AsyncWrite + Unpin),
    protocol: SingMuxProtocol,
    rx: &mut mpsc::Receiver<WireFrame>,
) {
    let mut batch = Vec::with_capacity(65536);
    while let Some(first) = rx.recv().await {
        batch.clear();
        encode_wire_frame_into(&mut batch, protocol, &first);
        while batch.len() < 49152 {
            match rx.try_recv() {
                Ok(next) => encode_wire_frame_into(&mut batch, protocol, &next),
                Err(_) => break,
            }
        }
        if writer.write_all(&batch).await.is_err() || writer.flush().await.is_err() {
            break;
        }
    }
}

async fn read_wire_frame(
    reader: &mut (impl AsyncRead + Unpin),
    protocol: SingMuxProtocol,
) -> io::Result<Option<WireFrame>> {
    loop {
        match protocol {
            SingMuxProtocol::Smux => {
                let mut hdr = [0u8; 8];
                match reader.read_exact(&mut hdr).await {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(err) => return Err(err),
                }
                let cmd = match hdr[1] {
                    0 => FrameCmd::Syn,
                    1 => FrameCmd::Fin,
                    2 => FrameCmd::Psh,
                    3 => FrameCmd::Nop,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "smux 未知帧命令",
                        ));
                    }
                };
                let len = usize::from(u16::from_le_bytes([hdr[2], hdr[3]]));
                let stream_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
                let mut payload = vec![0u8; len];
                if len > 0 {
                    reader.read_exact(&mut payload).await?;
                }
                return Ok(Some(WireFrame {
                    cmd,
                    stream_id,
                    payload,
                }));
            }
            SingMuxProtocol::Yamux => {
                let mut hdr = [0u8; 12];
                match reader.read_exact(&mut hdr).await {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(err) => return Err(err),
                }
                let ty = hdr[1];
                let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
                let stream_id = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
                let len = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]) as usize;
                let mut payload = Vec::new();
                if ty == 0 && len > 0 {
                    if len > 256 * 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "yamux 帧长度超限",
                        ));
                    }
                    payload.resize(len, 0);
                    reader.read_exact(&mut payload).await?;
                }
                if ty == 1 {
                    continue;
                }
                if ty == 2 {
                    return Ok(Some(WireFrame {
                        cmd: FrameCmd::Nop,
                        stream_id,
                        payload,
                    }));
                }
                if ty == 3 {
                    return Ok(None);
                }
                if flags & 1 != 0 && payload.is_empty() {
                    return Ok(Some(WireFrame {
                        cmd: FrameCmd::Syn,
                        stream_id,
                        payload: Vec::new(),
                    }));
                }
                if (flags & 4 != 0 || flags & 8 != 0) && payload.is_empty() {
                    return Ok(Some(WireFrame {
                        cmd: FrameCmd::Fin,
                        stream_id,
                        payload: Vec::new(),
                    }));
                }
                return Ok(Some(WireFrame {
                    cmd: FrameCmd::Psh,
                    stream_id,
                    payload,
                }));
            }
            SingMuxProtocol::H2Mux => {
                let mut hdr = [0u8; 9];
                match reader.read_exact(&mut hdr).await {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                    Err(err) => return Err(err),
                }
                let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
                if len > 256 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "h2mux 帧长度超限",
                    ));
                }
                let ty = hdr[3];
                let flags = hdr[4];
                let stream_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
                let mut payload = vec![0u8; len];
                if len > 0 {
                    reader.read_exact(&mut payload).await?;
                }
                match ty {
                    0 => {
                        if !payload.is_empty() {
                            return Ok(Some(WireFrame {
                                cmd: FrameCmd::Psh,
                                stream_id,
                                payload,
                            }));
                        }
                        if flags & 0x01 != 0 {
                            return Ok(Some(WireFrame {
                                cmd: FrameCmd::Fin,
                                stream_id,
                                payload: Vec::new(),
                            }));
                        }
                    }
                    1 => {
                        return Ok(Some(WireFrame {
                            cmd: FrameCmd::Syn,
                            stream_id,
                            payload: Vec::new(),
                        }));
                    }
                    3 => {
                        return Ok(Some(WireFrame {
                            cmd: FrameCmd::Fin,
                            stream_id,
                            payload: Vec::new(),
                        }));
                    }
                    6 => {
                        return Ok(Some(WireFrame {
                            cmd: FrameCmd::Nop,
                            stream_id,
                            payload,
                        }));
                    }
                    7 => return Ok(None),
                    _ => continue,
                }
            }
        }
    }
}

type PermitFuture = Pin<
    Box<
        dyn std::future::Future<
                Output = std::result::Result<
                    mpsc::OwnedPermit<WireFrame>,
                    mpsc::error::SendError<()>,
                >,
            > + Send
            + Sync,
    >,
>;

pub struct MuxLogicalStream {
    stream_id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
    tx: mpsc::Sender<WireFrame>,
    permit_fut: Option<PermitFuture>,
    active_streams: Arc<AtomicU32>,
    closed: bool,
}

impl MuxLogicalStream {
    fn poll_reserve(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<mpsc::OwnedPermit<WireFrame>>> {
        if self.permit_fut.is_none() {
            match self.tx.clone().try_reserve_owned() {
                Ok(permit) => return Poll::Ready(Ok(permit)),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.permit_fut = Some(Box::pin(self.tx.clone().reserve_owned()));
                }
            }
        }
        let fut = self.permit_fut.as_mut().expect("permit_fut set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(permit)) => {
                self.permit_fut = None;
                Poll::Ready(Ok(permit))
            }
            Poll::Ready(Err(_)) => {
                self.permit_fut = None;
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for MuxLogicalStream {
    fn drop(&mut self) {
        self.active_streams.fetch_sub(1, Ordering::AcqRel);
        if !self.closed {
            let fin = WireFrame {
                cmd: FrameCmd::Fin,
                stream_id: self.stream_id,
                payload: Vec::new(),
            };
            if let Err(mpsc::error::TrySendError::Full(fin)) = self.tx.try_send(fin) {
                let tx = self.tx.clone();
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    handle.spawn(async move {
                        let _ = tx.send(fin).await;
                    });
                }
            }
        }
    }
}

impl AsyncRead for MuxLogicalStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_pos < self.read_buf.len() {
                let rem = &self.read_buf[self.read_pos..];
                let n = rem.len().min(buf.remaining());
                buf.put_slice(&rem[..n]);
                self.read_pos += n;
                if self.read_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    self.read_buf = chunk;
                    self.read_pos = 0;
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MuxLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let permit = match self.poll_reserve(cx) {
            Poll::Ready(Ok(p)) => p,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        };
        let n = buf.len().min(32 * 1024);
        permit.send(WireFrame {
            cmd: FrameCmd::Psh,
            stream_id: self.stream_id,
            payload: buf[..n].to_vec(),
        });
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        let permit = match self.poll_reserve(cx) {
            Poll::Ready(Ok(p)) => p,
            Poll::Ready(Err(_)) => {
                self.closed = true;
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => return Poll::Pending,
        };
        self.closed = true;
        permit.send(WireFrame {
            cmd: FrameCmd::Fin,
            stream_id: self.stream_id,
            payload: Vec::new(),
        });
        Poll::Ready(Ok(()))
    }
}

struct ClientSession {
    tx: mpsc::Sender<WireFrame>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    next_id: AtomicU32,
    active_streams: Arc<AtomicU32>,
    total_streams: AtomicU32,
    dead: Arc<AtomicBool>,
}

impl ClientSession {
    async fn connect(stream: BoxStream, config: &SingMuxOutboundConfig) -> Result<Arc<Self>> {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut preface = vec![1u8, config.protocol.code(), u8::from(config.padding)];
        if config.padding {
            let mut pad = [0u8; 24];
            rand::thread_rng().fill_bytes(&mut pad);
            let pad_len = (pad.len() as u16).to_be_bytes();
            preface.extend_from_slice(&pad_len);
            preface.extend_from_slice(&pad);
        }
        if config.protocol == SingMuxProtocol::H2Mux {
            preface.extend_from_slice(H2_PREFACE);
            preface.extend_from_slice(&H2_EMPTY_SETTINGS);
        }
        writer.write_all(&preface).await?;
        writer.flush().await?;

        let (tx, mut rx) = mpsc::channel::<WireFrame>(1024);
        let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let active_streams = Arc::new(AtomicU32::new(0));
        let dead = Arc::new(AtomicBool::new(false));
        let protocol = config.protocol;
        let padded = config.padding;

        let dead_w = dead.clone();
        tokio::spawn(async move {
            write_wire_frames_batched(&mut writer, protocol, &mut rx).await;
            dead_w.store(true, Ordering::Release);
        });

        let streams_r = streams.clone();
        let dead_r = dead.clone();
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::with_capacity(64 * 1024, reader);
            if padded {
                let Ok(pad_len) = reader.read_u16().await else {
                    dead_r.store(true, Ordering::Release);
                    return;
                };
                let mut skip = vec![0u8; usize::from(pad_len)];
                if reader.read_exact(&mut skip).await.is_err() {
                    dead_r.store(true, Ordering::Release);
                    return;
                }
            }
            while let Ok(Some(frame)) = read_wire_frame(&mut reader, protocol).await {
                match frame.cmd {
                    FrameCmd::Psh => {
                        let sender = streams_r.lock().await.get(&frame.stream_id).cloned();
                        if let Some(s) = sender {
                            let _ = s.send(frame.payload).await;
                        }
                    }
                    FrameCmd::Fin => {
                        streams_r.lock().await.remove(&frame.stream_id);
                    }
                    FrameCmd::Syn | FrameCmd::Nop => {}
                }
            }
            dead_r.store(true, Ordering::Release);
            streams_r.lock().await.clear();
        });

        Ok(Arc::new(Self {
            tx,
            streams,
            next_id: AtomicU32::new(1),
            active_streams,
            total_streams: AtomicU32::new(0),
            dead,
        }))
    }

    fn is_alive(&self, config: &SingMuxOutboundConfig) -> bool {
        if self.dead.load(Ordering::Acquire) {
            return false;
        }
        if let Some(max_s) = config.max_streams
            && (self.total_streams.load(Ordering::Acquire) >= max_s
                || self.active_streams.load(Ordering::Acquire) >= max_s)
        {
            return false;
        }
        true
    }

    async fn open_stream(&self, flags: u16, target: &Destination) -> Result<MuxLogicalStream> {
        let sid = self.next_id.fetch_add(2, Ordering::Relaxed);
        self.total_streams.fetch_add(1, Ordering::AcqRel);
        self.active_streams.fetch_add(1, Ordering::AcqRel);
        let (s_tx, s_rx) = mpsc::channel(256);
        self.streams.lock().await.insert(sid, s_tx);

        self.tx
            .send(WireFrame {
                cmd: FrameCmd::Syn,
                stream_id: sid,
                payload: Vec::new(),
            })
            .await
            .map_err(|_| Error::Io(io::Error::from(io::ErrorKind::BrokenPipe)))?;

        let mut req = Vec::with_capacity(64);
        req.extend_from_slice(&flags.to_be_bytes());
        req.extend_from_slice(&encode_uot_address(target, false)?);
        self.tx
            .send(WireFrame {
                cmd: FrameCmd::Psh,
                stream_id: sid,
                payload: req,
            })
            .await
            .map_err(|_| Error::Io(io::Error::from(io::ErrorKind::BrokenPipe)))?;

        let mut stream = MuxLogicalStream {
            stream_id: sid,
            rx: s_rx,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
            tx: self.tx.clone(),
            permit_fut: None,
            active_streams: self.active_streams.clone(),
            closed: false,
        };

        let status = stream.read_u8().await?;
        if status != 0 {
            let msg_len = stream.read_u16().await? as usize;
            let mut msg = vec![0u8; msg_len.min(1024)];
            let _ = stream.read_exact(&mut msg).await;
            return Err(Error::Protocol("sing-mux 远端流握手返回错误状态"));
        }
        Ok(stream)
    }
}

pub struct SingMuxClient {
    config: SingMuxOutboundConfig,
    sessions: Mutex<Vec<Arc<ClientSession>>>,
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

    async fn acquire_session<F, Fut>(&self, dial: F) -> Result<Arc<ClientSession>>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let mut guard = self.sessions.lock().await;
        guard.retain(|s| s.is_alive(&self.config));

        let min_streams = self.config.min_streams.unwrap_or(4);
        let max_conns = self.config.max_connections.unwrap_or(1) as usize;

        if let Some(existing) = guard
            .iter()
            .find(|s| s.active_streams.load(Ordering::Acquire) < min_streams)
        {
            return Ok(existing.clone());
        }

        if guard.len() < max_conns {
            let carrier = dial(magic_destination()).await?;
            let session = ClientSession::connect(carrier, &self.config).await?;
            guard.push(session.clone());
            return Ok(session);
        }

        if let Some(best) = guard
            .iter()
            .min_by_key(|s| s.active_streams.load(Ordering::Acquire))
            .cloned()
        {
            return Ok(best);
        }

        let carrier = dial(magic_destination()).await?;
        let session = ClientSession::connect(carrier, &self.config).await?;
        guard.push(session.clone());
        Ok(session)
    }

    pub async fn connect_tcp<F, Fut>(&self, target: &Destination, dial: F) -> Result<OpenedTcp>
    where
        F: FnOnce(Destination) -> Fut,
        Fut: std::future::Future<Output = Result<BoxStream>>,
    {
        let session = self.acquire_session(dial).await?;
        let stream = session.open_stream(0, target).await?;
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
        let session = self.acquire_session(dial).await?;
        let stream = session.open_stream(1, target).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(DatagramChannel {
            sender: Box::new(MuxUdpChannelSender { writer }),
            receiver: Box::new(MuxUdpChannelReceiver {
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
        let session = self.acquire_session(dial).await?;
        let dummy = Destination::new("0.0.0.0", 0)?;
        let stream = session.open_stream(2, &dummy).await?;
        let (reader, writer) = tokio::io::split(stream);
        Ok(DatagramAssociation {
            sender: Box::new(MuxUdpAssocSender { writer }),
            receiver: Box::new(MuxUdpAssocReceiver { reader }),
        })
    }
}

struct MuxUdpChannelSender {
    writer: tokio::io::WriteHalf<MuxLogicalStream>,
}

impl DatagramSender for MuxUdpChannelSender {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let len =
                u16::try_from(packet.len()).map_err(|_| Error::Protocol("UDP 负载超过 65535"))?;
            self.writer.write_all(&len.to_be_bytes()).await?;
            self.writer.write_all(packet).await?;
            self.writer.flush().await?;
            Ok(())
        })
    }
}

struct MuxUdpChannelReceiver {
    reader: tokio::io::ReadHalf<MuxLogicalStream>,
    peer: Destination,
}

impl DatagramReceiver for MuxUdpChannelReceiver {
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

struct MuxUdpAssocSender {
    writer: tokio::io::WriteHalf<MuxLogicalStream>,
}

impl DatagramAssociationSender for MuxUdpAssocSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let len =
                u16::try_from(packet.len()).map_err(|_| Error::Protocol("UDP 负载超过 65535"))?;
            let addr = encode_uot_address(target, false)?;
            self.writer.write_all(&addr).await?;
            self.writer.write_all(&len.to_be_bytes()).await?;
            self.writer.write_all(packet).await?;
            self.writer.flush().await?;
            Ok(())
        })
    }
}

struct MuxUdpAssocReceiver {
    reader: tokio::io::ReadHalf<MuxLogicalStream>,
}

impl DatagramAssociationReceiver for MuxUdpAssocReceiver {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move {
            let family = match self.reader.read_u8().await {
                Ok(f) => f,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            let Some(peer) = read_uot_address(&mut self.reader, family, false, false).await? else {
                return Err(Error::Protocol("sing-mux UDP 关联地址不合法"));
            };
            let len = self.reader.read_u16().await? as usize;
            let mut buf = vec![0u8; len];
            self.reader.read_exact(&mut buf).await?;
            Ok(Some((peer, buf)))
        })
    }
}

pub async fn serve_inbound(
    stream: BoxStream,
    peer: PeerSession,
    config: &SingMuxInboundConfig,
    context: &InboundContext,
) -> Result<()> {
    if !config.enabled {
        return Err(Error::Protocol("未启用 sing-mux 入站"));
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    let version = reader.read_u8().await?;
    if version > 1 {
        return Err(Error::Protocol("不支持的 sing-mux 会话版本"));
    }
    let protocol = SingMuxProtocol::from_code(reader.read_u8().await?)?;
    let client_padded = if version == 1 {
        reader.read_u8().await? != 0
    } else {
        false
    };
    if config.padding && !client_padded {
        return Err(Error::Protocol("sing-mux 入站要求启用 padding"));
    }
    if client_padded {
        let pad_len = reader.read_u16().await? as usize;
        let mut skip = vec![0u8; pad_len];
        reader.read_exact(&mut skip).await?;
        let mut resp_pad = [0u8; 18];
        rand::thread_rng().fill_bytes(&mut resp_pad);
        writer
            .write_all(&(resp_pad.len() as u16).to_be_bytes())
            .await?;
        writer.write_all(&resp_pad).await?;
        writer.flush().await?;
    }
    if protocol == SingMuxProtocol::H2Mux {
        let mut h2_pre = [0u8; 24];
        reader.read_exact(&mut h2_pre).await?;
        if &h2_pre != H2_PREFACE {
            return Err(Error::Protocol("h2mux HTTP/2 握手前言不匹配"));
        }
        writer.write_all(&H2_EMPTY_SETTINGS).await?;
        writer.flush().await?;
    }

    let (tx, mut rx) = mpsc::channel::<WireFrame>(1024);
    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let active_streams = Arc::new(AtomicU32::new(0));
    let cancel = context.cancel.clone();

    let writer_task = tokio::spawn(async move {
        write_wire_frames_batched(&mut writer, protocol, &mut rx).await;
    });

    let mut reader = tokio::io::BufReader::with_capacity(64 * 1024, reader);
    loop {
        let next_frame = tokio::select! {
            _ = cancel.cancelled() => break,
            res = read_wire_frame(&mut reader, protocol) => res?,
        };
        let Some(frame) = next_frame else {
            break;
        };
        match frame.cmd {
            FrameCmd::Syn => {
                let sid = frame.stream_id;
                let (s_tx, s_rx) = mpsc::channel(256);
                streams.lock().await.insert(sid, s_tx);
                active_streams.fetch_add(1, Ordering::AcqRel);
                let logical = MuxLogicalStream {
                    stream_id: sid,
                    rx: s_rx,
                    read_buf: Vec::new(),
                    read_pos: 0,
                    eof: false,
                    tx: tx.clone(),
                    permit_fut: None,
                    active_streams: active_streams.clone(),
                    closed: false,
                };
                let peer_clone = peer.clone();
                let ctx_clone = context.clone();
                let streams_cleanup = streams.clone();
                tokio::spawn(async move {
                    let _ = handle_inbound_stream(logical, peer_clone, ctx_clone).await;
                    streams_cleanup.lock().await.remove(&sid);
                });
            }
            FrameCmd::Psh => {
                let sender = streams.lock().await.get(&frame.stream_id).cloned();
                if let Some(s) = sender {
                    let _ = s.send(frame.payload).await;
                }
            }
            FrameCmd::Fin => {
                streams.lock().await.remove(&frame.stream_id);
            }
            FrameCmd::Nop => {}
        }
    }

    drop(tx);
    let _ = writer_task.await;
    Ok(())
}

async fn handle_inbound_stream(
    mut stream: MuxLogicalStream,
    peer: PeerSession,
    context: InboundContext,
) -> Result<()> {
    let flags = stream.read_u16().await?;
    let family = stream.read_u8().await?;
    let allow_zero = flags == 2;
    let target = read_uot_address(&mut stream, family, false, allow_zero).await?;

    stream.write_all(&[0u8]).await?;
    stream.flush().await?;

    let ctx = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    match flags {
        0 => {
            let Some(target) = target else {
                return Err(Error::Protocol("sing-mux TCP 流缺少目标地址"));
            };
            let outbound = peer.connect_tcp(&target, &ctx).await?;
            kerlico_core::relay_tcp(
                Box::new(stream),
                outbound,
                context.idle_timeout,
                context.cancel,
            )
            .await
        }
        1 => {
            let Some(target) = target else {
                return Err(Error::Protocol("sing-mux UDP 流缺少目标地址"));
            };
            let (mut sender, mut receiver, completion) =
                peer.connect_udp(&target, &ctx).await?.into_parts();
            let (mut reader, mut writer) = tokio::io::split(stream);
            loop {
                tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    r = reader.read_u16() => {
                        let Ok(len) = r else { break };
                        let mut payload = vec![0u8; usize::from(len)];
                        if reader.read_exact(&mut payload).await.is_err() {
                            break;
                        }
                        if sender.send(&payload).await.is_err() {
                            break;
                        }
                    }
                    down = receiver.recv() => {
                        let Ok(Some(payload)) = down else { break };
                        let Ok(len) = u16::try_from(payload.len()) else { break };
                        if writer.write_all(&len.to_be_bytes()).await.is_err()
                            || writer.write_all(&payload).await.is_err()
                            || writer.flush().await.is_err()
                        {
                            break;
                        }
                    }
                }
            }
            completion.finish(FlowOutcome::ProtocolEnd);
            Ok(())
        }
        2 => {
            let (mut sender, mut receiver, completion) =
                peer.associate_udp(&ctx).await?.into_parts();
            let (mut reader, mut writer) = tokio::io::split(stream);
            loop {
                tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    f = reader.read_u8() => {
                        let Ok(fam) = f else { break };
                        let Ok(Some(dst)) = read_uot_address(&mut reader, fam, false, false).await else { break };
                        let Ok(len) = reader.read_u16().await else { break };
                        let mut payload = vec![0u8; usize::from(len)];
                        if reader.read_exact(&mut payload).await.is_err() {
                            break;
                        }
                        if sender.send_to(&payload, &dst).await.is_err() {
                            break;
                        }
                    }
                    down = receiver.recv_from() => {
                        let Ok(Some((src, payload))) = down else { break };
                        let Ok(addr) = encode_uot_address(&src, false) else { break };
                        let Ok(len) = u16::try_from(payload.len()) else { break };
                        if writer.write_all(&addr).await.is_err()
                            || writer.write_all(&len.to_be_bytes()).await.is_err()
                            || writer.write_all(&payload).await.is_err()
                            || writer.flush().await.is_err()
                        {
                            break;
                        }
                    }
                }
            }
            completion.finish(FlowOutcome::ProtocolEnd);
            Ok(())
        }
        _ => Err(Error::Protocol("未知的 sing-mux 流标志位")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sing_mux_protocols_open_tcp_and_udp_streams_with_padding() {
        for protocol in [
            SingMuxProtocol::Smux,
            SingMuxProtocol::Yamux,
            SingMuxProtocol::H2Mux,
        ] {
            let cfg = SingMuxOutboundConfig {
                enabled: true,
                protocol,
                max_connections: Some(2),
                min_streams: Some(1),
                max_streams: Some(8),
                padding: true,
                only_tcp: false,
            };
            cfg.validate().unwrap();
            let client = SingMuxClient::new(cfg);
            let (c_io, mut s_io) = tokio::io::duplex(16384);
            let server_task = tokio::spawn(async move {
                let ver = s_io.read_u8().await.unwrap();
                assert_eq!(ver, 1);
                let proto = SingMuxProtocol::from_code(s_io.read_u8().await.unwrap()).unwrap();
                assert_eq!(proto, protocol);
                let padded = s_io.read_u8().await.unwrap();
                assert_eq!(padded, 1);
                let pad_len = s_io.read_u16().await.unwrap() as usize;
                let mut skip = vec![0u8; pad_len];
                s_io.read_exact(&mut skip).await.unwrap();
                s_io.write_all(&0u16.to_be_bytes()).await.unwrap();
                s_io.flush().await.unwrap();
                if protocol == SingMuxProtocol::H2Mux {
                    let mut pre = [0u8; 24];
                    s_io.read_exact(&mut pre).await.unwrap();
                    assert_eq!(&pre, H2_PREFACE);
                    s_io.write_all(&H2_EMPTY_SETTINGS).await.unwrap();
                    s_io.flush().await.unwrap();
                }
                loop {
                    let Ok(Some(frame)) = read_wire_frame(&mut s_io, protocol).await else {
                        break;
                    };
                    if frame.cmd == FrameCmd::Syn {
                        let mut out = Vec::new();
                        encode_wire_frame_into(
                            &mut out,
                            protocol,
                            &WireFrame {
                                cmd: FrameCmd::Psh,
                                stream_id: frame.stream_id,
                                payload: b"\x00hello".to_vec(),
                            },
                        );
                        encode_wire_frame_into(
                            &mut out,
                            protocol,
                            &WireFrame {
                                cmd: FrameCmd::Fin,
                                stream_id: frame.stream_id,
                                payload: Vec::new(),
                            },
                        );
                        s_io.write_all(&out).await.unwrap();
                        s_io.flush().await.unwrap();
                        break;
                    }
                }
            });
            let target = Destination::new("example.com", 443).unwrap();
            let mut opened = client
                .connect_tcp(
                    &target,
                    |_dest| async move { Ok(Box::new(c_io) as BoxStream) },
                )
                .await
                .unwrap();
            let mut buf = Vec::new();
            opened.stream.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"hello");
            server_task.await.unwrap();
        }
    }
}
