use crate::{
    config::Shared,
    crypto::{self, State},
    invalid, obfs,
    protocol::{Codec, Role},
};
use bytes::Bytes;
use futures_util::task::{ArcWake, AtomicWaker, waker_ref};
use kerlico_core::{BoxStream, CancellationToken, Result};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
};

struct Wakes {
    read: AtomicWaker,
    write: AtomicWaker,
}
impl ArcWake for Wakes {
    fn wake_by_ref(value: &Arc<Self>) {
        value.read.wake();
        value.write.wake();
    }
}
struct Writer {
    state: State,
    iv: Vec<u8>,
    sent: bool,
}
impl Writer {
    fn encode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = data.to_vec();
        self.state.apply(&mut output, true)?;
        if !self.sent {
            let mut prefix = self.iv.clone();
            prefix.extend(output);
            output = prefix;
            self.sent = true;
        }
        Ok(output)
    }
}
struct Reader {
    cfg: Arc<Shared>,
    state: Option<State>,
    pending: Vec<u8>,
    iv: Vec<u8>,
}
impl Reader {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let mut output = data.to_vec();
        if self.state.is_none() {
            self.pending.extend_from_slice(data);
            let size = self.cfg.method.iv_len();
            // IV本身不是cipher正文；保留此前缀，避免空decrypt和将截断前缀误判为正常EOF。
            if self.pending.len() <= size {
                return Ok(Vec::new());
            }
            self.iv = self.pending[..size].to_vec();
            self.state = Some(State::new(self.cfg.method, &self.cfg.key, &self.iv)?);
            output = self.pending[size..].to_vec();
            self.pending.clear();
        }
        self.state
            .as_mut()
            .ok_or_else(invalid)?
            .apply(&mut output, false)?;
        Ok(output)
    }
}

/// 原始流和所有编解码状态直接归此对象所有；丢弃即同步回收，不脱离 engine 另建任务。
pub(crate) struct Stream {
    raw: Option<BoxStream>,
    cfg: Arc<Shared>,
    role: Role,
    cancel: Pin<Box<dyn Future<Output = ()> + Send>>,
    wakes: Arc<Wakes>,
    writer: Writer,
    reader: Reader,
    codec: Codec,
    layer: obfs::Layer,
    network: VecDeque<Bytes>,
    plain: VecDeque<Bytes>,
    network_offset: usize,
    plain_offset: usize,
    network_bytes: usize,
    plain_bytes: usize,
    buffer: Vec<u8>,
    needs_flush: bool,
    request: bool,
    incoming_end: bool,
    outgoing_end: bool,
    write_closed: bool,
    failed: bool,
    nonce_checked: bool,
    _permit: Option<OwnedSemaphorePermit>,
}
impl Stream {
    pub(crate) fn new(
        raw: BoxStream,
        cfg: Arc<Shared>,
        role: Role,
        cancel: CancellationToken,
        host: String,
        port: u16,
    ) -> Result<Self> {
        let iv = crypto::random(cfg.method.iv_len());
        let writer = Writer {
            state: State::new(cfg.method, &cfg.key, &iv)?,
            iv: iv.clone(),
            sent: false,
        };
        let reader = Reader {
            cfg: cfg.clone(),
            state: None,
            pending: Vec::new(),
            iv: Vec::new(),
        };
        let codec = Codec::new(cfg.clone(), role, iv);
        let layer = obfs::Layer::new(cfg.clone(), role, host, port);
        Ok(Self {
            raw: Some(raw),
            cfg,
            role,
            cancel: Box::pin(cancel.cancelled_owned()),
            wakes: Arc::new(Wakes {
                read: AtomicWaker::new(),
                write: AtomicWaker::new(),
            }),
            writer,
            reader,
            codec,
            layer,
            network: VecDeque::new(),
            plain: VecDeque::new(),
            network_offset: 0,
            plain_offset: 0,
            network_bytes: 0,
            plain_bytes: 0,
            buffer: vec![0; 4096],
            needs_flush: false,
            request: false,
            incoming_end: false,
            outgoing_end: false,
            write_closed: false,
            failed: false,
            nonce_checked: false,
            _permit: None,
        })
    }
    pub(crate) fn with_permit(mut self, permit: OwnedSemaphorePermit) -> Self {
        self._permit = Some(permit);
        self
    }
    fn error(&mut self) -> io::Error {
        self.failed = true;
        self.raw.take();
        self.network.clear();
        self.plain.clear();
        self.wakes.read.wake();
        self.wakes.write.wake();
        io::Error::other("ShadowsocksR 会话校验或传输失败")
    }
    fn queue(&mut self, data: Vec<u8>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if self.network_bytes + data.len() > 131072 {
            return Err(kerlico_core::Error::ResourceLimit);
        }
        self.network_bytes += data.len();
        self.network.push_back(Bytes::from(data));
        Ok(())
    }
    fn output(&mut self, data: &[u8]) -> Result<()> {
        let data = self.codec.encode(data, crate::now())?;
        let data = self.writer.encode(&data)?;
        let data = self.layer.encode(&data)?;
        self.queue(data)
    }
    fn input(&mut self, data: &[u8]) -> Result<()> {
        let decoded = self.layer.feed(data)?;
        self.queue(decoded.reply)?;
        let plain = self.reader.decode(&decoded.cipher)?;
        // 握手回写已入队；没有新增明文时不重入协议首部/帧状态机。
        if plain.is_empty() {
            return Ok(());
        }
        let decoded = self.codec.feed(&plain, &self.reader.iv, crate::now())?;
        let verified = if self.role == Role::Server {
            self.codec.received_header
        } else {
            self.cfg.protocol == crate::config::Protocol::Origin || self.codec.receive_id > 1
        };
        if verified && !self.nonce_checked && self.reader.state.is_some() {
            self.cfg.replay.nonce(&self.reader.iv)?;
            self.nonce_checked = true;
        }
        if decoded.reply && self.role == Role::Server && !self.outgoing_end {
            self.output(&[])?;
        }
        if !decoded.data.is_empty() {
            if self.plain_bytes + decoded.data.len() > 131072 {
                return Err(kerlico_core::Error::ResourceLimit);
            }
            self.plain_bytes += decoded.data.len();
            self.plain.push_back(Bytes::from(decoded.data));
            self.wakes.read.wake();
        }
        Ok(())
    }
    fn drive(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.failed {
            return Err(self.error());
        }
        let wakes = self.wakes.clone();
        let wake = waker_ref(&wakes);
        let mut io_context = Context::from_waker(&wake);
        for _ in 0..32 {
            if self.cancel.as_mut().poll(&mut io_context).is_ready() {
                return Err(self.error());
            }
            let mut progress = false;
            if let Some(data) = self.network.front().cloned() {
                let result = Pin::new(
                    self.raw
                        .as_mut()
                        .ok_or_else(|| io::Error::other("SSR 流已关闭"))?,
                )
                .poll_write(&mut io_context, &data[self.network_offset..]);
                match result {
                    Poll::Ready(Ok(count)) => {
                        if count == 0 {
                            return Err(self.error());
                        }
                        self.network_offset += count;
                        self.network_bytes -= count;
                        self.needs_flush = true;
                        progress = true;
                        if self.network_offset == data.len() {
                            self.network.pop_front();
                            self.network_offset = 0;
                        }
                        self.wakes.write.wake();
                    }
                    Poll::Ready(Err(_)) => return Err(self.error()),
                    Poll::Pending => {}
                }
            }
            if self.network.is_empty() && self.needs_flush {
                match Pin::new(
                    self.raw
                        .as_mut()
                        .ok_or_else(|| io::Error::other("SSR 流已关闭"))?,
                )
                .poll_flush(&mut io_context)
                {
                    Poll::Ready(Ok(())) => {
                        self.needs_flush = false;
                        progress = true;
                        self.wakes.write.wake();
                    }
                    Poll::Ready(Err(_)) => return Err(self.error()),
                    Poll::Pending => {}
                }
            }
            if !self.incoming_end && self.plain_bytes < 65536 {
                let mut buffer = ReadBuf::new(&mut self.buffer);
                let result = Pin::new(
                    self.raw
                        .as_mut()
                        .ok_or_else(|| io::Error::other("SSR 流已关闭"))?,
                )
                .poll_read(&mut io_context, &mut buffer);
                match result {
                    Poll::Ready(Ok(())) => {
                        let count = buffer.filled().len();
                        progress = true;
                        if count == 0 {
                            if !self.reader.pending.is_empty()
                                || !self.codec.finished()
                                || !self.layer.finished()
                            {
                                return Err(self.error());
                            }
                            self.incoming_end = true;
                            self.wakes.read.wake();
                        } else {
                            let bytes = self.buffer[..count].to_vec();
                            if self.input(&bytes).is_err() {
                                return Err(self.error());
                            }
                        }
                    }
                    Poll::Ready(Err(_)) => return Err(self.error()),
                    Poll::Pending => {}
                }
            }
            if !progress {
                return Ok(());
            }
        }
        cx.waker().wake_by_ref();
        Ok(())
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.wakes.read.register(cx.waker());
        this.drive(cx)?;
        if let Some(data) = this.plain.front() {
            let count = output.remaining().min(data.len() - this.plain_offset);
            output.put_slice(&data[this.plain_offset..this.plain_offset + count]);
            this.plain_offset += count;
            this.plain_bytes -= count;
            if this.plain_offset == data.len() {
                this.plain.pop_front();
                this.plain_offset = 0;
            }
            this.wakes.read.wake();
            return Poll::Ready(Ok(()));
        }
        if this.incoming_end {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.wakes.write.register(cx.waker());
        this.drive(cx)?;
        if this.outgoing_end {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "SSR 写端已关闭",
            )));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.network_bytes >= 65536 {
            return Poll::Pending;
        }
        let count = data.len().min(4096);
        if this.output(&data[..count]).is_err() {
            return Poll::Ready(Err(this.error()));
        }
        this.request = true;
        this.wakes.write.wake();
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.wakes.write.register(cx.waker());
        this.drive(cx)?;
        if this.network.is_empty() && !this.needs_flush && (!this.request || this.layer.ready()) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let this = self.as_mut().get_mut();
            if !this.outgoing_end {
                if this.output(&[]).is_err() {
                    return Poll::Ready(Err(this.error()));
                }
                this.outgoing_end = true;
            }
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        let result = Pin::new(
            this.raw
                .as_mut()
                .ok_or_else(|| io::Error::other("SSR 流已关闭"))?,
        )
        .poll_shutdown(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.write_closed = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[derive(serde::Deserialize)]
    struct Vectors {
        plain: Vec<u8>,
        records: Vec<Vector>,
    }
    #[derive(serde::Deserialize)]
    struct Vector {
        method: String,
        key: Vec<u8>,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../tests/fixtures/cipher-vectors.json")).unwrap()
    }
    fn settings(method: &str) -> Arc<Shared> {
        Shared::node(&serde_json::json!({"method":method,"password":"synthetic-cipher-vector-secret","protocol":"origin","obfs":"plain","udp":false,"allow_insecure":true})).unwrap()
    }

    #[test]
    fn independent_vectors_preserve_iv_only_and_empty_fragments() {
        let vectors = vectors();
        for vector in vectors.records {
            let cfg = settings(&vector.method);
            assert_eq!(cfg.key, vector.key);
            let mut reader = Reader {
                cfg,
                state: None,
                pending: Vec::new(),
                iv: Vec::new(),
            };
            assert!(reader.decode(&[]).unwrap().is_empty());
            assert!(reader.decode(&vector.iv).unwrap().is_empty());
            let mut decoded = reader.decode(&vector.ciphertext[..1]).unwrap();
            for chunk in vector.ciphertext[1..].chunks(17) {
                assert!(reader.decode(&[]).unwrap().is_empty());
                decoded.extend(reader.decode(chunk).unwrap());
            }
            assert_eq!(decoded, vectors.plain, "方法 {}", vector.method);
        }
    }

    struct PrefixThenEof {
        prefix: Vec<u8>,
        offset: usize,
    }
    impl AsyncRead for PrefixThenEof {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let count = output.remaining().min(this.prefix.len() - this.offset);
            output.put_slice(&this.prefix[this.offset..this.offset + count]);
            this.offset += count;
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for PrefixThenEof {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn iv_only_eof_is_not_a_clean_empty_response() {
        for vector in vectors().records {
            let mut empty = Stream::new(
                Box::new(PrefixThenEof {
                    prefix: Vec::new(),
                    offset: 0,
                }),
                settings(&vector.method),
                Role::Client,
                CancellationToken::new(),
                "127.0.0.1".into(),
                1,
            )
            .unwrap();
            let mut byte = [0; 1];
            assert_eq!(empty.read(&mut byte).await.unwrap(), 0);
            if vector.iv.is_empty() {
                continue;
            }
            let mut stream = Stream::new(
                Box::new(PrefixThenEof {
                    prefix: vector.iv,
                    offset: 0,
                }),
                settings(&vector.method),
                Role::Client,
                CancellationToken::new(),
                "127.0.0.1".into(),
                1,
            )
            .unwrap();
            assert!(
                stream.read(&mut byte).await.is_err(),
                "方法 {}",
                vector.method
            );
        }
    }
}
