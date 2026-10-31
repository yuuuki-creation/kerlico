use crate::io::DuplexWake;
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use kerlico_core::{Error, Result};
use serde::Deserialize;
use sha2::Sha256;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

pub(crate) const MAX_PLAIN: usize = 65507;
pub(crate) const UPDATE_BYTES: u64 = 32 << 20;

#[derive(Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub(crate) enum Method {
    #[serde(rename = "aes-128-gcm")]
    Aes,
    #[default]
    #[serde(rename = "chacha20-poly1305")]
    ChaCha,
    #[serde(rename = "none")]
    None,
}
impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes => "aes-128-gcm",
            Self::ChaCha => "chacha20-poly1305",
            Self::None => "none",
        }
    }
}

enum Cipher {
    Aes(Box<Aes128Gcm>),
    ChaCha(ChaCha20Poly1305),
}
impl Cipher {
    fn new(method: Method, base: &[u8; 32], epoch: u32) -> Result<Self> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(base).map_err(|_| crate::invalid())?;
        mac.update(b"sudoku-record:");
        mac.update(method.name().as_bytes());
        mac.update(&epoch.to_be_bytes());
        let key = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        match method {
            Method::Aes => Ok(Self::Aes(Box::new(
                Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| crate::invalid())?,
            ))),
            Method::ChaCha => Ok(Self::ChaCha(
                ChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| crate::invalid())?,
            )),
            Method::None => Err(crate::invalid()),
        }
    }
    fn seal(&self, nonce: &[u8; 12], plain: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: plain,
            aad: nonce,
        };
        match self {
            Self::Aes(cipher) => cipher.encrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::ChaCha(cipher) => {
                cipher.encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            }
        }
        .map_err(|_| crate::invalid())
    }
    fn open(&self, nonce: &[u8; 12], cipher: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: cipher,
            aad: nonce,
        };
        match self {
            Self::Aes(cipher) => cipher.decrypt(aes_gcm::Nonce::from_slice(nonce), payload),
            Self::ChaCha(cipher) => {
                cipher.decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
            }
        }
        .map_err(|_| crate::invalid())
    }
}

fn random_sequence() -> Result<u64> {
    for _ in 0..16 {
        let value = u64::from_be_bytes(crate::key::random()?);
        if value != 0 && value != u64::MAX {
            return Ok(value);
        }
    }
    Err(Error::Protocol("Sudoku无法生成非零记录序号"))
}
fn random_position() -> Result<(u32, u64)> {
    for _ in 0..16 {
        let epoch = u32::from_be_bytes(crate::key::random()?);
        if epoch != 0 && epoch != u32::MAX {
            return Ok((epoch, random_sequence()?));
        }
    }
    Err(Error::Protocol("Sudoku无法生成记录epoch"))
}

pub(crate) struct Sender {
    method: Method,
    base: Zeroizing<[u8; 32]>,
    cipher: Option<(u32, Cipher)>,
    epoch: u32,
    sequence: u64,
    plain_bytes: u64,
    updates: u32,
    threshold: u64,
    failed: bool,
}
impl Sender {
    pub fn new(method: Method, base: [u8; 32], threshold: u64) -> Result<Self> {
        let (epoch, sequence) = random_position()?;
        Ok(Self {
            method,
            base: Zeroizing::new(base),
            cipher: None,
            epoch,
            sequence,
            plain_bytes: 0,
            updates: 0,
            threshold,
            failed: false,
        })
    }
    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(crate::invalid());
        }
        let result = self.seal_inner(plain);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn seal_inner(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        if plain.is_empty() || self.method == Method::None {
            return Ok(plain.to_vec());
        }
        if plain.len() > MAX_PLAIN {
            return Err(Error::ResourceLimit);
        }
        let next_sequence = self.sequence.checked_add(1).ok_or(Error::ResourceLimit)?;
        let total = self
            .plain_bytes
            .checked_add(plain.len() as u64)
            .ok_or(Error::ResourceLimit)?;
        if self.cipher.as_ref().map(|(epoch, _)| *epoch) != Some(self.epoch) {
            self.cipher = Some((
                self.epoch,
                Cipher::new(self.method, &self.base, self.epoch)?,
            ));
        }
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&self.sequence.to_be_bytes());
        let encrypted = self.cipher.as_ref().unwrap().1.seal(&nonce, plain)?;
        let mut frame = Vec::with_capacity(14 + encrypted.len());
        frame.extend_from_slice(&((12 + encrypted.len()) as u16).to_be_bytes());
        frame.extend_from_slice(&nonce);
        frame.extend(encrypted);
        self.sequence = next_sequence;
        self.plain_bytes = total;
        if self.threshold > 0
            && self.plain_bytes >= self.threshold.saturating_mul(u64::from(self.updates) + 1)
        {
            self.epoch = self.epoch.checked_add(1).ok_or(Error::ResourceLimit)?;
            self.updates = self.updates.checked_add(1).ok_or(Error::ResourceLimit)?;
            self.sequence = random_sequence()?;
        }
        Ok(frame)
    }
}

pub(crate) struct Receiver {
    method: Method,
    base: Zeroizing<[u8; 32]>,
    cipher: Option<(u32, Cipher)>,
    next: Option<(u32, u64)>,
    failed: bool,
}
impl Receiver {
    pub fn new(method: Method, base: [u8; 32]) -> Self {
        Self {
            method,
            base: Zeroizing::new(base),
            cipher: None,
            next: None,
            failed: false,
        }
    }
    pub fn open(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(crate::invalid());
        }
        let result = self.open_inner(body);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn open_inner(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        if self.method == Method::None {
            return Ok(body.to_vec());
        }
        if !(28..=65535).contains(&body.len()) {
            return Err(crate::invalid());
        }
        let header: &[u8; 12] = body[..12].try_into().unwrap();
        let epoch = u32::from_be_bytes(header[..4].try_into().unwrap());
        let sequence = u64::from_be_bytes(header[4..].try_into().unwrap());
        let next_sequence = sequence.checked_add(1).ok_or_else(crate::invalid)?;
        if let Some((previous, expected)) = self.next
            && (epoch < previous
                || (epoch == previous && sequence != expected)
                || epoch.saturating_sub(previous) > 8)
        {
                return Err(crate::invalid());
        }
        if self.cipher.as_ref().map(|(epoch, _)| *epoch) != Some(epoch) {
            self.cipher = Some((epoch, Cipher::new(self.method, &self.base, epoch)?));
        }
        let plain = self.cipher.as_ref().unwrap().1.open(header, &body[12..])?;
        self.next = Some((epoch, next_sequence));
        Ok(plain)
    }
}

pub(crate) struct RecordStream<T> {
    inner: T,
    method: Method,
    sender: Sender,
    receiver: Receiver,
    pending: Vec<u8>,
    written: usize,
    header: [u8; 2],
    header_used: usize,
    body: Vec<u8>,
    body_used: usize,
    plain: Vec<u8>,
    plain_used: usize,
    failed: bool,
    write_closed: bool,
    read_closed: bool,
    flush_pending: bool,
    shutdown_done: bool,
    wake: std::sync::Arc<DuplexWake>,
}
impl<T> RecordStream<T> {
    pub fn new(inner: T, method: Method, send: [u8; 32], receive: [u8; 32]) -> Result<Self> {
        Ok(Self {
            inner,
            method,
            sender: Sender::new(method, send, UPDATE_BYTES)?,
            receiver: Receiver::new(method, receive),
            pending: Vec::new(),
            written: 0,
            header: [0; 2],
            header_used: 0,
            body: Vec::new(),
            body_used: 0,
            plain: Vec::new(),
            plain_used: 0,
            failed: false,
            write_closed: false,
            read_closed: false,
            flush_pending: false,
            shutdown_done: false,
            wake: DuplexWake::new(),
        })
    }
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
    fn fail(&mut self) {
        if !self.failed { self.failed = true; self.wake.wake_both(); }
    }
    pub fn rekey(&mut self, send: [u8; 32], receive: [u8; 32]) -> Result<()> {
        if self.failed
            || self.write_closed
            || self.flush_pending
            || !self.pending.is_empty()
            || self.header_used != 0
            || !self.body.is_empty()
            || self.plain_used != self.plain.len()
        {
            return Err(Error::Protocol("Sudoku不能丢弃未读旧密钥数据后Rekey"));
        }
        let sender = Sender::new(self.method, send, UPDATE_BYTES)?;
        self.sender = sender;
        self.receiver = Receiver::new(self.method, receive);
        self.plain.clear();
        self.plain_used = 0;
        Ok(())
    }
}
fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "Sudoku记录载体已关闭")
}
impl<T: AsyncWrite + Unpin> RecordStream<T> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            match ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..])) {
                Ok(0) => {
                    self.fail();
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(n) => { self.written += n; self.wake.wake_writer(); },
                Err(error) => {
                    self.fail();
                    return Poll::Ready(Err(error));
                }
            }
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
    fn output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        if self.write_closed && !self.shutdown_done {
            match ready!(Pin::new(&mut self.inner).poll_shutdown(cx)) {
                Ok(()) => { self.shutdown_done = true; self.flush_pending = false; self.wake.wake_writer(); },
                Err(error) => { self.fail(); return Poll::Ready(Err(error)); },
            }
        } else if self.flush_pending {
            match ready!(Pin::new(&mut self.inner).poll_flush(cx)) {
                Ok(()) => { self.flush_pending = false; self.wake.wake_writer(); },
                Err(error) => { self.fail(); return Poll::Ready(Err(error)); },
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for RecordStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.reader(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(broken()));
        }
        // 输出Pending不能阻塞反向读取；下层就绪会经共享waker唤醒两个方向。
        if let Poll::Ready(Err(error)) = this.output(cx) {
            return Poll::Ready(Err(error));
        }
        if this.method == Method::None {
            let result = Pin::new(&mut this.inner).poll_read(cx, output);
            if matches!(result, Poll::Ready(Err(_))) { this.fail(); }
            return result;
        }
        for _ in 0..64 {
            if this.plain_used < this.plain.len() {
                let count = output.remaining().min(this.plain.len() - this.plain_used);
                output.put_slice(&this.plain[this.plain_used..this.plain_used + count]);
                this.plain_used += count;
                return Poll::Ready(Ok(()));
            }
            if this.read_closed {
                return Poll::Ready(Ok(()));
            }
            while this.header_used < 2 {
                let mut buffer = ReadBuf::new(&mut this.header[this.header_used..]);
                if let Err(error) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer)) {
                    this.fail();
                    return Poll::Ready(Err(error));
                }
                let count = buffer.filled().len();
                if count == 0 {
                    if this.header_used != 0 {
                        this.fail();
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                this.header_used += count;
            }
            if this.body.is_empty() {
                let len = u16::from_be_bytes(this.header) as usize;
                if len < 28 {
                    this.fail();
                    return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                }
                this.body.resize(len, 0);
                this.body_used = 0;
            }
            while this.body_used < this.body.len() {
                let mut buffer = ReadBuf::new(&mut this.body[this.body_used..]);
                if let Err(error) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer)) {
                    this.fail();
                    return Poll::Ready(Err(error));
                }
                let count = buffer.filled().len();
                if count == 0 {
                    this.fail();
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.body_used += count;
            }
            match this.receiver.open(&this.body) {
                Ok(plain) => this.plain = plain,
                Err(error) => {
                    this.fail();
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
                }
            }
            this.plain_used = 0;
            this.body.clear();
            this.body_used = 0;
            this.header_used = 0;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RecordStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failed || this.write_closed {
            return Poll::Ready(Err(broken()));
        }
        ready!(this.output(cx))?;
        if this.method == Method::None {
            let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
            if matches!(result, Poll::Ready(Err(_))) { this.fail(); }
            return result;
        }
        let count = bytes.len().min(MAX_PLAIN);
        match this.sender.seal(&bytes[..count]) {
            Ok(frame) => { this.pending = frame; this.wake.wake_reader(); },
            Err(error) => {
                this.fail();
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
            }
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failed {
            return Poll::Ready(Err(broken()));
        }
        if !this.shutdown_done { this.flush_pending = true; }
        this.output(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let forwarded = this.wake.writer(cx.waker());
        let mut inner_context = Context::from_waker(&forwarded);
        let cx = &mut inner_context;
        if this.failed {
            return Poll::Ready(Err(broken()));
        }
        this.write_closed = true;
        this.output(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn rotations_sequence_replay_reflection_and_bounds() {
        for method in [Method::Aes, Method::ChaCha] {
            let mut sender = Sender::new(method, [0x37; 32], 32).unwrap();
            let mut receiver = Receiver::new(method, [0x37; 32]);
            let first_epoch = sender.epoch;
            for len in [17, 17, MAX_PLAIN, 33] {
                let frame = sender.seal(&vec![0xab; len]).unwrap();
                assert_eq!(receiver.open(&frame[2..]).unwrap(), vec![0xab; len]);
            }
            assert!(sender.epoch > first_epoch);
            let frame = sender.seal(b"one").unwrap();
            assert_eq!(receiver.open(&frame[2..]).unwrap(), b"one");
            assert!(receiver.open(&frame[2..]).is_err());
            let mut reflected = Receiver::new(method, [0x38; 32]);
            assert!(reflected.open(&frame[2..]).is_err());
            let mut full = Sender::new(method, [0x37; 32], UPDATE_BYTES).unwrap();
            assert!(full.seal(&vec![0; MAX_PLAIN + 1]).is_err());
            assert!(full.seal(b"poisoned").is_err());
            let mut overflow = Sender::new(method, [0x37; 32], UPDATE_BYTES).unwrap();
            overflow.sequence = u64::MAX;
            assert!(overflow.seal(b"no-wrap").is_err());
        }
    }
    #[tokio::test]
    async fn split_record_cancellation_rekey_and_real_half_close() {
        for method in [Method::Aes, Method::ChaCha, Method::None] {
            let (a, b) = tokio::io::duplex(37);
            let mut client = RecordStream::new(a, method, [1; 32], [2; 32]).unwrap();
            let mut server = RecordStream::new(b, method, [2; 32], [1; 32]).unwrap();
            let peer = tokio::spawn(async move {
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, vec![0x5a; 65537]);
                server.write_all(b"after-fin").await.unwrap();
                server.shutdown().await.unwrap();
            });
            client.write_all(&vec![0x5a; 65537]).await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(&reply, b"after-fin");
            peer.await.unwrap();
        }
        let (a, mut b) = tokio::io::duplex(64);
        let mut stream = RecordStream::new(a, Method::Aes, [1; 32], [2; 32]).unwrap();
        let mut encoder = Sender::new(Method::Aes, [2; 32], UPDATE_BYTES).unwrap();
        let frame = encoder.seal(b"abc").unwrap();
        let peer = tokio::spawn(async move {
            b.write_all(&frame[..1]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            b.write_all(&frame[1..]).await.unwrap();
        });
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                stream.read(&mut [0; 1])
            )
            .await
            .is_err()
        );
        assert!(stream.rekey([3; 32], [4; 32]).is_err());
        let mut first = [0; 1];
        stream.read_exact(&mut first).await.unwrap();
        assert!(stream.rekey([3; 32], [4; 32]).is_err());
        let mut tail = [0; 2];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"bc");
        stream.rekey([3; 32], [4; 32]).unwrap();
        peer.await.unwrap();
    }
}

#[cfg(test)]
mod task_wake_tests {
    use super::{Method, RecordStream};
    use crate::codec::{layout::Mode, obfs::ObfsStream, table::{GridOrder, Pair}};
    use kerlico_core::BoxStream;
    use std::{
        future::{Future,poll_fn},
        io,
        pin::Pin,
        sync::{Arc,OnceLock},
        task::{Context,Poll},
        time::Duration,
    };
    use tokio::{io::{AsyncRead,AsyncReadExt,AsyncWrite,AsyncWriteExt,ReadBuf},sync::{Notify,oneshot}};

    fn table() -> Arc<Pair> {
        static TABLE: OnceLock<Arc<Pair>> = OnceLock::new();
        TABLE.get_or_init(|| {
            let order = Arc::new(GridOrder::new("synthetic-codec-dual-task-wake"));
            Arc::new(Pair::new("synthetic-codec-dual-task-wake",Mode::parse("prefer_entropy").unwrap(),"",order).unwrap())
        }).clone()
    }
    struct ObservedIo { inner: tokio::io::DuplexStream, blocked: Arc<Notify> }
    impl AsyncRead for ObservedIo {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_read(cx,data) }
    }
    impl AsyncWrite for ObservedIo {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            let this=self.get_mut();let result=Pin::new(&mut this.inner).poll_write(cx,data);
            if result.is_pending(){this.blocked.notify_one();}result
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_flush(cx) }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.get_mut().inner).poll_shutdown(cx) }
    }
    fn layered(method: Method, packed: bool) -> (BoxStream,BoxStream,Arc<Notify>) {
        let pair=table();let (a,b)=tokio::io::duplex(97);let blocked=Arc::new(Notify::new());
        let client=ObfsStream::new(Box::new(ObservedIo{inner:a,blocked:blocked.clone()}),pair.down.clone(),pair.up.clone(),packed,false,0,0).unwrap();
        let server=ObfsStream::new(Box::new(b),pair.up.clone(),pair.down.clone(),false,packed,0,0).unwrap();
        (Box::new(RecordStream::new(client,method,[1;32],[2;32]).unwrap()),Box::new(RecordStream::new(server,method,[2;32],[1;32]).unwrap()),blocked)
    }

    #[tokio::test]
    async fn real_record_obfs_split_two_tasks_keep_full_duplex_and_eof() {
        for method in [Method::Aes,Method::ChaCha,Method::None] {for packed in [false,true] {
            let (client,server,_)=layered(method,packed);
            let (mut cr,mut cw)=tokio::io::split(client);let (mut sr,mut sw)=tokio::io::split(server);
            let client_read=tokio::spawn(async move{let mut data=Vec::new();cr.read_to_end(&mut data).await.unwrap();assert_eq!(data,vec![0x62;100003]);});
            let client_write=tokio::spawn(async move{cw.write_all(&vec![0x31;98305]).await.unwrap();cw.flush().await.unwrap();cw.shutdown().await.unwrap();});
            let server_read=tokio::spawn(async move{let mut data=Vec::new();sr.read_to_end(&mut data).await.unwrap();assert_eq!(data,vec![0x31;98305]);});
            let server_write=tokio::spawn(async move{sw.write_all(&vec![0x62;100003]).await.unwrap();sw.flush().await.unwrap();sw.shutdown().await.unwrap();});
            tokio::time::timeout(Duration::from_secs(8),async{client_read.await.unwrap();client_write.await.unwrap();server_read.await.unwrap();server_write.await.unwrap();}).await.expect("真实叠层、独立读写Task和大于缓冲的双向数据必须完成");
        }}
    }

    #[tokio::test]
    async fn abandoned_reader_cannot_steal_blocked_writer_wakeup() {
        let (client,mut server,blocked)=layered(Method::ChaCha,false);let (mut read,mut write)=tokio::io::split(client);
        let writer=tokio::spawn(async move{write.write_all(&vec![0x43;96001]).await.unwrap();write.flush().await.unwrap();write.shutdown().await.unwrap();});
        tokio::time::timeout(Duration::from_secs(3),blocked.notified()).await.unwrap();
        // 先保证写Task真的被小载体阻塞，再用另一个Task读poll推进同一待写缓冲。
        let cancelled_reader=tokio::spawn(async move {
            let mut byte=[0;1];let mut future=Box::pin(read.read(&mut byte));
            assert!(poll_fn(|cx|Poll::Ready(future.as_mut().poll(cx).is_pending())).await);
            drop(future);read
        });
        let mut read=cancelled_reader.await.unwrap();
        // 此时读Future及其Task都已结束；释放对端容量仍须唤醒原写Task。
        let peer=tokio::spawn(async move{let mut data=Vec::new();server.read_to_end(&mut data).await.unwrap();assert_eq!(data,vec![0x43;96001]);server.write_all(b"after-cancelled-read").await.unwrap();server.shutdown().await.unwrap();});
        tokio::time::timeout(Duration::from_secs(8),async{writer.await.unwrap();let mut data=Vec::new();read.read_to_end(&mut data).await.unwrap();assert_eq!(data,b"after-cancelled-read");peer.await.unwrap();}).await.expect("放弃读Future不能夺走原写Task的就绪通知");
    }

    #[tokio::test]
    async fn abandoned_buffered_write_wakes_already_pending_reader() {
        for method in [Method::Aes,Method::ChaCha,Method::None] {
            let (client,mut server,_)=layered(method,true);let (mut read,mut write)=tokio::io::split(client);
            let (registered,ready)=oneshot::channel();
            let reader=tokio::spawn(async move{
                let mut data=Vec::new();let mut future=Box::pin(read.read_to_end(&mut data));
                assert!(poll_fn(|cx|Poll::Ready(future.as_mut().poll(cx).is_pending())).await);
                registered.send(()).unwrap();future.await.unwrap();data
            });
            ready.await.unwrap();
            let bytes=vec![0x74;32768];let expected=bytes.clone();
            let writer=tokio::spawn(async move{let accepted=write.write(&bytes).await.unwrap();(write,accepted)});
            let (held,accepted)=writer.await.unwrap();assert!(accepted>97);
            // 写Task已完成，既不flush也不shutdown；已接受的缓冲必须由读侧继续推进。
            let peer=tokio::spawn(async move{let mut data=vec![0;accepted];server.read_exact(&mut data).await.unwrap();assert_eq!(data,&expected[..accepted]);server.write_all(b"after-buffered-write").await.unwrap();server.shutdown().await.unwrap();});
            tokio::time::timeout(Duration::from_secs(8),async{assert_eq!(reader.await.unwrap(),b"after-buffered-write");peer.await.unwrap();}).await.expect("接受写缓冲后必须唤醒已等待的读Task");drop(held);
        }
    }

    #[tokio::test]
    async fn read_continues_abandoned_flush_and_shutdown_without_repeating_bytes() {
        for method in [Method::Aes,Method::ChaCha,Method::None] {for shutdown in [false,true] {
            let (mut client,mut server,_)=layered(method,false);let bytes=vec![0x85;32768];let accepted=client.write(&bytes).await.unwrap();assert!(accepted>97);let bytes=bytes[..accepted].to_vec();
            let mut future:Pin<Box<dyn Future<Output=io::Result<()>>+'_>>=if shutdown{Box::pin(client.shutdown())}else{Box::pin(client.flush())};
            assert!(poll_fn(|cx|Poll::Ready(future.as_mut().poll(cx).is_pending())).await);drop(future);
            let peer=tokio::spawn(async move{
                let mut data=Vec::new();if shutdown{server.read_to_end(&mut data).await.unwrap();}else{data.resize(bytes.len(),0);server.read_exact(&mut data).await.unwrap();}assert_eq!(data,bytes);server.write_all(b"after-owned-output").await.unwrap();server.shutdown().await.unwrap();
            });
            let mut reply=Vec::new();tokio::time::timeout(Duration::from_secs(8),async{client.read_to_end(&mut reply).await.unwrap();peer.await.unwrap();}).await.expect("放弃输出Future后读侧仍须完成已有输出及EOF");assert_eq!(reply,b"after-owned-output");
            if shutdown {client.shutdown().await.unwrap();assert!(client.write(b"late").await.is_err());}
        }}
    }

    struct RejectOutput { shutdown: bool }
    impl AsyncRead for RejectOutput {
        fn poll_read(self:Pin<&mut Self>,_:&mut Context<'_>,_:&mut ReadBuf<'_>)->Poll<io::Result<()>>{Poll::Pending}
    }
    impl AsyncWrite for RejectOutput {
        fn poll_write(self:Pin<&mut Self>,_:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>>{Poll::Ready(Ok(bytes.len()))}
        fn poll_flush(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<io::Result<()>>{if self.shutdown{Poll::Ready(Ok(()))}else{Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))}}
        fn poll_shutdown(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<io::Result<()>>{Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))}
    }
    #[tokio::test]
    async fn output_failure_wakes_independent_reader_and_stays_failed() {
        for shutdown in [false,true] {
            let pair=table();let obfs=ObfsStream::new(Box::new(RejectOutput{shutdown}),pair.down.clone(),pair.up.clone(),false,false,0,0).unwrap();let stream=RecordStream::new(obfs,Method::Aes,[1;32],[2;32]).unwrap();let(mut read,mut write)=tokio::io::split(stream);let(registered,ready)=oneshot::channel();
            let reader=tokio::spawn(async move{let mut byte=[0;1];let mut future=Box::pin(read.read(&mut byte));assert!(poll_fn(|cx|Poll::Ready(future.as_mut().poll(cx).is_pending())).await);registered.send(()).unwrap();assert!(future.await.is_err());});ready.await.unwrap();
            let result=if shutdown{write.shutdown().await}else{write.flush().await};assert!(result.is_err());assert!(write.flush().await.is_err());assert!(write.shutdown().await.is_err());assert!(write.write(b"late").await.is_err());tokio::time::timeout(Duration::from_secs(2),reader).await.unwrap().unwrap();
        }
    }
}
