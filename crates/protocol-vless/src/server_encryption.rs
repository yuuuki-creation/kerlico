//! 服务端 Encryption 握手使用固定 Rust 原语，流适配保留独立方向的 Vision 转换。
use kerlico_core::{Error, Result};
use rust_xhttp::vless::encryption::{
    EncryptionConfig, HandshakeError, HandshakeResult, HeaderXor, RecordCipher, Server,
    decode_header,
};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_transport::{BoxedTransportStream, TransportStream};

struct Generation {
    server: Arc<Server>,
    attempts: usize,
}
pub(crate) struct Decryption {
    config: EncryptionConfig,
    generation: Mutex<Generation>,
}
impl Decryption {
    pub fn parse(value: &str) -> Result<Option<Self>> {
        if value == "none" {
            return Ok(None);
        }
        if value.len() > 16384 {
            return Err(Error::Config("VLESS decryption 超过长度限制".into()));
        }
        let config = EncryptionConfig::parse(value)
            .map_err(|_| Error::Config("VLESS decryption 参数不合法".into()))?;
        if config.keys.len() > 8
            || config.lifetime_to != 0 && config.lifetime_to < config.lifetime_from
            || !config.padding.is_empty()
        {
            return Err(Error::Config(
                "VLESS decryption 密钥链、票据使用期或 padding 超出当前范围".into(),
            ));
        }
        Ok(Some(Self {
            generation: Mutex::new(Generation {
                server: Server::new(config.clone()),
                attempts: 0,
            }),
            config,
        }))
    }
    pub async fn accept(&self, stream: BoxedTransportStream) -> Result<BoxedTransportStream> {
        // 依赖的票据及 replay-key 表按代次硬性限量，旧代次不接受新握手。
        let server = {
            let mut generation = self
                .generation
                .lock()
                .map_err(|_| Error::Protocol("Encryption 状态不可用"))?;
            if generation.attempts >= 1024 {
                *generation = Generation {
                    server: Server::new(self.config.clone()),
                    attempts: 0,
                };
            }
            generation.attempts += 1;
            generation.server.clone()
        };
        let (mut reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let handshake = server
            .handshake(&mut reader, |bytes| {
                let writer = writer.clone();
                async move {
                    let mut writer = writer.lock().await;
                    writer.write_all(&bytes).await.map_err(HandshakeError::Io)?;
                    writer.flush().await.map_err(HandshakeError::Io)
                }
            })
            .await
            .map_err(|_| Error::Protocol("VLESS Encryption 握手失败"))?;
        let writer = Arc::try_unwrap(writer)
            .map_err(|_| Error::Protocol("Encryption 写端仍被占用"))?
            .into_inner();
        Ok(Box::new(Encrypted::new(reader.unsplit(writer), handshake)))
    }
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "VLESS Encryption 记录不合法")
}

struct Encrypted {
    inner: BoxedTransportStream,
    decrypt: RecordCipher,
    encrypt: RecordCipher,
    read_xor: Option<HeaderXor>,
    write_xor: Option<HeaderXor>,
    header: [u8; 5],
    header_pos: usize,
    body: Vec<u8>,
    body_pos: usize,
    plaintext: Vec<u8>,
    plain_pos: usize,
    pending: Vec<u8>,
    sent: usize,
    direct_read: bool,
    direct_write: bool,
    failed: bool,
    read_ended: bool,
    write_closed: bool,
}
impl Encrypted {
    fn new(inner: BoxedTransportStream, state: HandshakeResult) -> Self {
        Self {
            inner,
            decrypt: state.decrypt,
            encrypt: state.encrypt,
            read_xor: state.inbound_xor,
            write_xor: state.outbound_xor,
            header: [0; 5],
            header_pos: 0,
            body: Vec::new(),
            body_pos: 0,
            plaintext: Vec::new(),
            plain_pos: 0,
            pending: Vec::new(),
            sent: 0,
            direct_read: false,
            direct_write: false,
            failed: false,
            read_ended: false,
            write_closed: false,
        }
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(malformed()));
        }
        while self.sent < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.failed = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(0)) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Encryption 记录无法继续写入",
                    )));
                }
                Poll::Ready(Ok(n)) => self.sent += n,
            }
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
    fn read_record(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(malformed()));
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_ended {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.plain_pos < self.plaintext.len() {
                let count = (self.plaintext.len() - self.plain_pos).min(out.remaining());
                out.put_slice(&self.plaintext[self.plain_pos..self.plain_pos + count]);
                self.plain_pos += count;
                return Poll::Ready(Ok(()));
            }
            if self.direct_read && self.read_xor.is_none() {
                return Pin::new(&mut self.inner).poll_read(cx, out);
            }
            while self.header_pos < 5 {
                let mut buffer = ReadBuf::new(&mut self.header[self.header_pos..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.failed = true;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => {
                        let n = buffer.filled().len();
                        if n == 0 {
                            if self.header_pos == 0 {
                                self.read_ended = true;
                                return Poll::Ready(Ok(()));
                            }
                            self.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Encryption 记录头被截断",
                            )));
                        }
                        self.header_pos += n;
                    }
                }
            }
            if self.body.is_empty() {
                if let Some(mask) = &mut self.read_xor
                    && mask.apply(&mut self.header).is_err()
                {
                    self.failed = true;
                    return Poll::Ready(Err(malformed()));
                }
                let length = match decode_header(&self.header) {
                    Ok(n) => n,
                    Err(_) => {
                        self.failed = true;
                        return Poll::Ready(Err(malformed()));
                    }
                };
                self.body.resize(length, 0);
                self.body_pos = 0;
            }
            while self.body_pos < self.body.len() {
                let mut buffer = ReadBuf::new(&mut self.body[self.body_pos..]);
                match Pin::new(&mut self.inner).poll_read(cx, &mut buffer) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.failed = true;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => {
                        let n = buffer.filled().len();
                        if n == 0 {
                            self.failed = true;
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Encryption 记录体被截断",
                            )));
                        }
                        self.body_pos += n;
                    }
                }
            }
            if let Some(mask) = &mut self.read_xor
                && mask.apply(&mut self.body).is_err()
            {
                self.failed = true;
                return Poll::Ready(Err(malformed()));
            }
            self.plaintext = if self.direct_read {
                let mut bytes = self.header.to_vec();
                bytes.extend_from_slice(&self.body);
                bytes
            } else {
                match self.decrypt.open(&self.header, &self.body) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.failed = true;
                        return Poll::Ready(Err(malformed()));
                    }
                }
            };
            self.plain_pos = 0;
            self.header_pos = 0;
            self.body.clear();
            self.body_pos = 0;
        }
    }
}
impl AsyncRead for Encrypted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().read_record(cx, out)
    }
}
impl AsyncWrite for Encrypted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Encryption 写端已关闭",
            )));
        }
        match this.drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            _ => {}
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(8192);
        this.pending = if this.direct_write {
            bytes[..count].to_vec()
        } else {
            match this.encrypt.seal(&bytes[..count]) {
                Ok(v) => v,
                Err(_) => {
                    this.failed = true;
                    return Poll::Ready(Err(malformed()));
                }
            }
        };
        if let Some(mask) = &mut this.write_xor
            && mask.apply(&mut this.pending).is_err()
        {
            this.failed = true;
            return Poll::Ready(Err(malformed()));
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write_closed = true;
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Pin::new(&mut self.get_mut().inner).poll_shutdown(cx),
        }
    }
}
impl TransportStream for Encrypted {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.direct_read = true;
        this.read_record(cx, out)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.direct_write = true;
        AsyncWrite::poll_write(Pin::new(this), cx, bytes)
    }
}
