//! TS2021 控制连接的 Noise IK 客户端（上游 `control/controlbase`）。
//! 传输 nonce 按上游使用大端计数，与 Noise 规范的小端不同。

use crate::keys::{MachineKey, Secret};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hmac::{Mac, SimpleHmac};
use kerlico_core::{Error, Result};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_PREFIX: &str = "Tailscale Control Protocol v";
const TYPE_INITIATION: u8 = 1;
const TYPE_RESPONSE: u8 = 2;
const TYPE_ERROR: u8 = 3;
const TYPE_RECORD: u8 = 4;
const HEADER: usize = 3;
const OVERHEAD: usize = 16;
const MAX_MESSAGE: usize = 4096;
const MAX_PLAINTEXT: usize = MAX_MESSAGE - HEADER - OVERHEAD;
pub const INITIATION_LEN: usize = 101;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Blake2s256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <SimpleHmac<Blake2s256> as Mac>::new_from_slice(key).expect("HMAC接受任意密钥长度");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
fn hkdf(chain: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let pseudo_random = hmac(chain, &[input]);
    let first = hmac(&pseudo_random, &[&[1]]);
    let second = hmac(&pseudo_random, &[&first, &[2]]);
    (first, second)
}

struct Symmetric {
    hash: [u8; 32],
    chain: [u8; 32],
}
impl Symmetric {
    fn new() -> Self {
        let hash = hash(&[PROTOCOL_NAME]);
        Self { hash, chain: hash }
    }
    fn mix_hash(&mut self, data: &[u8]) {
        self.hash = hash(&[&self.hash, data]);
    }
    fn mix_dh(&mut self, secret: &Secret, public: &[u8; 32]) -> Result<ChaCha20Poly1305> {
        let shared = secret.diffie_hellman(public)?;
        let (chain, key) = hkdf(&self.chain, &shared);
        self.chain = chain;
        Ok(ChaCha20Poly1305::new((&key).into()))
    }
    fn encrypt_and_hash(&mut self, cipher: &ChaCha20Poly1305, plain: &[u8]) -> Result<Vec<u8>> {
        let sealed = cipher
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: plain,
                    aad: &self.hash,
                },
            )
            .map_err(|_| Error::Protocol("Tailscale控制握手失败"))?;
        self.mix_hash(&sealed);
        Ok(sealed)
    }
    fn decrypt_and_hash(&mut self, cipher: &ChaCha20Poly1305, sealed: &[u8]) -> Result<Vec<u8>> {
        let plain = cipher
            .decrypt(
                &Nonce::default(),
                Payload {
                    msg: sealed,
                    aad: &self.hash,
                },
            )
            .map_err(|_| Error::Protocol("Tailscale控制握手失败"))?;
        self.mix_hash(sealed);
        Ok(plain)
    }
}

pub struct Handshake {
    symmetric: Symmetric,
    ephemeral: Secret,
    machine: Secret,
}
impl Handshake {
    pub fn start(machine: &Secret, control: &MachineKey, version: u16) -> Result<(Vec<u8>, Self)> {
        Self::start_with_ephemeral(machine, control, version, Secret::generate())
    }
    fn start_with_ephemeral(
        machine: &Secret,
        control: &MachineKey,
        version: u16,
        ephemeral: Secret,
    ) -> Result<(Vec<u8>, Self)> {
        let mut symmetric = Symmetric::new();
        symmetric.mix_hash(format!("{PROLOGUE_PREFIX}{version}").as_bytes());
        symmetric.mix_hash(&control.0);
        let mut message = Vec::with_capacity(INITIATION_LEN);
        message.extend_from_slice(&version.to_be_bytes());
        message.push(TYPE_INITIATION);
        message.extend_from_slice(&96u16.to_be_bytes());
        let ephemeral_public = ephemeral.public();
        message.extend_from_slice(&ephemeral_public);
        symmetric.mix_hash(&ephemeral_public);
        let cipher = symmetric.mix_dh(&ephemeral, &control.0)?;
        message.extend_from_slice(&symmetric.encrypt_and_hash(&cipher, &machine.public())?);
        let cipher = symmetric.mix_dh(machine, &control.0)?;
        message.extend_from_slice(&symmetric.encrypt_and_hash(&cipher, &[])?);
        Ok((
            message,
            Self {
                symmetric,
                ephemeral,
                machine: machine.clone(),
            },
        ))
    }
    /// 读取响应或服务端错误帧；错误帧未经认证，因此只作为通用失败返回。
    pub async fn finish<S>(self, mut stream: S) -> Result<NoiseStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut header = [0; HEADER];
        stream.read_exact(&mut header).await?;
        if header[0] == TYPE_ERROR {
            return Err(Error::Protocol("Tailscale控制面拒绝握手"));
        }
        if header[0] != TYPE_RESPONSE || u16::from_be_bytes([header[1], header[2]]) != 48 {
            return Err(Error::Protocol("Tailscale控制握手失败"));
        }
        let mut payload = [0; 48];
        stream.read_exact(&mut payload).await?;
        let (tx, rx) = self.complete(&payload)?;
        Ok(NoiseStream {
            inner: stream,
            tx: Direction::new(tx),
            rx: Direction::new(rx),
            frame: vec![0; HEADER],
            filled: 0,
            plain: Vec::new(),
            taken: 0,
            pending: Vec::new(),
            flushed: 0,
        })
    }
    fn complete(mut self, payload: &[u8; 48]) -> Result<([u8; 32], [u8; 32])> {
        let (control_ephemeral, tag) = payload.split_at(32);
        let control_ephemeral: [u8; 32] = control_ephemeral.try_into().expect("固定长度");
        self.symmetric.mix_hash(&control_ephemeral);
        self.symmetric.mix_dh(&self.ephemeral, &control_ephemeral)?;
        let cipher = self.symmetric.mix_dh(&self.machine, &control_ephemeral)?;
        self.symmetric.decrypt_and_hash(&cipher, tag)?;
        Ok(hkdf(&self.symmetric.chain, &[]))
    }
}

struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}
impl Direction {
    fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new((&key).into()),
            counter: 0,
        }
    }
    fn nonce(&mut self) -> io::Result<Nonce> {
        if self.counter == u64::MAX {
            return Err(io::Error::other("Tailscale控制连接密钥已耗尽"));
        }
        let mut nonce = Nonce::default();
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        Ok(nonce)
    }
}

/// Noise 记录帧上的字节流；单次写入按上游上限切分。
pub struct NoiseStream<S> {
    inner: S,
    tx: Direction,
    rx: Direction,
    frame: Vec<u8>,
    filled: usize,
    plain: Vec<u8>,
    taken: usize,
    pending: Vec<u8>,
    flushed: usize,
}
impl<S: AsyncRead + AsyncWrite + Unpin> NoiseStream<S> {
    /// 把已读出的明文放回流前端。
    pub fn unread(&mut self, bytes: &[u8]) {
        let mut plain = bytes.to_vec();
        plain.extend_from_slice(&self.plain[self.taken..]);
        self.plain = plain;
        self.taken = 0;
    }
    fn poll_drain(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.flushed < self.pending.len() {
            let count = ready!(
                Pin::new(&mut self.inner).poll_write(context, &self.pending[self.flushed..])
            )?;
            if count == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.flushed += count;
        }
        self.pending.clear();
        self.flushed = 0;
        Poll::Ready(Ok(()))
    }
    fn poll_fill(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            while self.filled < self.frame.len() {
                let mut buffer = ReadBuf::new(&mut self.frame[self.filled..]);
                ready!(Pin::new(&mut self.inner).poll_read(context, &mut buffer))?;
                let count = buffer.filled().len();
                if count == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                self.filled += count;
            }
            let total = HEADER + usize::from(u16::from_be_bytes([self.frame[1], self.frame[2]]));
            if self.frame[0] != TYPE_RECORD || !(HEADER + OVERHEAD..=MAX_MESSAGE).contains(&total) {
                return Poll::Ready(Err(io::Error::other("Tailscale控制记录帧不合法")));
            }
            if self.frame.len() < total {
                self.frame.resize(total, 0);
                continue;
            }
            let nonce = self.rx.nonce()?;
            self.plain = self
                .rx
                .cipher
                .decrypt(&nonce, &self.frame[HEADER..])
                .map_err(|_| io::Error::other("Tailscale控制记录帧解密失败"))?;
            self.taken = 0;
            self.frame.truncate(HEADER);
            self.filled = 0;
            return Poll::Ready(Ok(()));
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for NoiseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.taken >= this.plain.len() {
            ready!(this.poll_fill(context))?;
        }
        let count = output.remaining().min(this.plain.len() - this.taken);
        output.put_slice(&this.plain[this.taken..this.taken + count]);
        this.taken += count;
        Poll::Ready(Ok(()))
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for NoiseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        let count = input.len().min(MAX_PLAINTEXT);
        let nonce = this.tx.nonce()?;
        let sealed = this
            .tx
            .cipher
            .encrypt(&nonce, &input[..count])
            .map_err(|_| io::Error::other("Tailscale控制记录帧加密失败"))?;
        this.pending.push(TYPE_RECORD);
        this.pending
            .extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        this.pending.extend_from_slice(&sealed);
        // 已加密的记录由下一次写入或刷新发完，尚未写出也算接收成功。
        let _ = this.poll_drain(context)?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        Pin::new(&mut this.inner).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(context))?;
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    // 由上游 controlbase 的 `Server` 与 `continueClientHandshake` 生成：
    // machine=01*32，ephemeral=02*32，control=03*32，version=131。
    const CONTROL_PUBLIC: &str = "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";
    const INITIATION: &str = concat!(
        "0083010060ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d",
        "594391bcfef3f1b0f051873c2103356110f8056ef928c4354783347c74dc7b71b7e70fe8",
        "356bc6d2d41862acd3ece46f2693ff1360489f4618872428ae68eb17e1"
    );
    const RESPONSE: &str = concat!(
        "0200307fd8442479b1549a988a60b1ada7e90963567c785f88218a2aee9acc76b52a4aec",
        "bbe47c4ecbe1cb6c6b756e59b1abda"
    );
    const SERVER_RECORD: &str =
        "04002035398b9eb3e0e07295c53c15730873c40914c74870636594d238f04ecc3073fb";
    const CLIENT_RECORD: &str =
        "040020b7f8f8c013f951131b170719976c776e13895f335ddc80b4b2f9570c95530ba8";

    #[tokio::test]
    async fn matches_upstream_handshake_and_records() {
        let control = MachineKey(hex::decode(CONTROL_PUBLIC).unwrap().try_into().unwrap());
        let (initiation, handshake) = Handshake::start_with_ephemeral(
            &Secret::from_bytes([1; 32]),
            &control,
            131,
            Secret::from_bytes([2; 32]),
        )
        .unwrap();
        assert_eq!(hex::encode(&initiation), INITIATION);
        assert_eq!(initiation.len(), INITIATION_LEN);

        let (near, mut far) = duplex(4096);
        far.write_all(&hex::decode(RESPONSE).unwrap())
            .await
            .unwrap();
        far.write_all(&hex::decode(SERVER_RECORD).unwrap())
            .await
            .unwrap();
        let mut stream = handshake.finish(near).await.unwrap();

        let mut plain = [0; 16];
        stream.read_exact(&mut plain).await.unwrap();
        assert_eq!(&plain, b"server to client");

        stream.write_all(b"client to server").await.unwrap();
        stream.flush().await.unwrap();
        let mut record = vec![0; CLIENT_RECORD.len() / 2];
        far.read_exact(&mut record).await.unwrap();
        assert_eq!(hex::encode(record), CLIENT_RECORD);
    }

    fn looped<S>(inner: S) -> NoiseStream<S> {
        NoiseStream {
            inner,
            tx: Direction::new([7; 32]),
            rx: Direction::new([7; 32]),
            frame: vec![0; HEADER],
            filled: 0,
            plain: Vec::new(),
            taken: 0,
            pending: Vec::new(),
            flushed: 0,
        }
    }

    #[tokio::test]
    async fn long_write_is_split_at_the_record_limit() {
        let (near, mut far) = duplex(1 << 16);
        let mut stream = looped(near);
        let payload = vec![9; MAX_PLAINTEXT + 10];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut wire = vec![0; payload.len() + 2 * (HEADER + OVERHEAD)];
        far.read_exact(&mut wire).await.unwrap();
        assert_eq!(wire[0], TYPE_RECORD);
        assert_eq!(
            usize::from(u16::from_be_bytes([wire[1], wire[2]])),
            MAX_MESSAGE - HEADER
        );
        far.write_all(&wire).await.unwrap();
        let mut received = vec![0; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn unread_bytes_come_back_before_the_rest() {
        let (near, mut far) = duplex(1 << 16);
        let mut stream = looped(near);
        stream.write_all(b"abcdefg").await.unwrap();
        stream.flush().await.unwrap();
        let mut wire = vec![0; 7 + HEADER + OVERHEAD];
        far.read_exact(&mut wire).await.unwrap();
        far.write_all(&wire).await.unwrap();
        let mut head = [0; 3];
        stream.read_exact(&mut head).await.unwrap();
        stream.unread(&head);
        let mut all = [0; 7];
        stream.read_exact(&mut all).await.unwrap();
        assert_eq!(&all, b"abcdefg");
    }

    #[tokio::test]
    async fn tampered_record_fails() {
        let (near, mut far) = duplex(1 << 16);
        let mut stream = looped(near);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut wire = vec![0; 5 + HEADER + OVERHEAD];
        far.read_exact(&mut wire).await.unwrap();
        wire[HEADER] ^= 1;
        far.write_all(&wire).await.unwrap();
        let mut received = [0; 5];
        assert!(stream.read_exact(&mut received).await.is_err());
    }
}
