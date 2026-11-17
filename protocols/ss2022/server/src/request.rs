//! SIP022 requires the address and padding to fit in the first encrypted chunk.

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use kerlico_shared::{AsyncBufReadVectored, AsyncWriteInput, WriteInput};
use kerlico_ss2022::{
    config::ServerUserManager,
    context::SharedContext,
    relay::tcprelay::crypto_io::{DecryptedReader, EncryptedWriter, StreamType},
    Address, CipherKind,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const READ_AHEAD: usize = 32 * 1024;
const RECORD_BATCH: usize = 4;
const RECORD_SLAB: usize = RECORD_BATCH * u16::MAX as usize + 16;

pub(crate) struct Stream {
    socket: TcpStream,
    context: SharedContext,
    reader: DecryptedReader,
    writer: EncryptedWriter,
}

impl Stream {
    pub(crate) async fn handshake(
        mut socket: TcpStream,
        context: SharedContext,
        kind: CipherKind,
        key: &[u8],
        users: Option<Arc<ServerUserManager>>,
    ) -> io::Result<(Self, Address, Vec<u8>)> {
        let mut reader = DecryptedReader::with_user_manager(StreamType::Server, kind, key, users);
        let mut chunk = vec![0; u16::MAX.into()];
        let mut out = ReadBuf::new(&mut chunk);
        std::future::poll_fn(|cx| reader.poll_read_decrypted(cx, &context, &mut socket, &mut out))
            .await?;
        let len = out.filled().len();
        chunk.truncate(len);
        let mut header = Cursor::new(&chunk[..]);
        let target = Address::read_from(&mut header).await?;
        let padding = usize::from(header.read_u16().await?);
        let start = usize::try_from(header.position()).expect("chunk length fits usize") + padding;
        if padding > 900 || start > len || (padding == 0 && start == len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SS2022 initial request chunk",
            ));
        }
        let request = reader.nonce().ok_or(io::ErrorKind::InvalidData)?;
        let mut nonce = vec![0; kind.salt_len()];
        context.generate_nonce(kind, &mut nonce, false);
        let mut writer = EncryptedWriter::new(
            StreamType::Server,
            kind,
            reader.user_key().unwrap_or(key),
            &nonce,
        );
        writer.set_request_nonce(Bytes::copy_from_slice(request));
        let payload = chunk.split_off(start);
        Ok((
            Self {
                socket,
                context,
                reader,
                writer,
            },
            target,
            payload,
        ))
    }

    pub(crate) fn user_key(&self) -> Option<&[u8]> {
        self.reader.user_key()
    }

    /// Handshake has already bound the writer to the authenticated key and request salt.
    pub(crate) fn into_halves(
        self,
    ) -> (
        impl AsyncBufReadVectored + Send + Unpin,
        impl AsyncWriteInput + Send + Unpin,
    ) {
        let (read, write) = self.socket.into_split();
        (
            Receive {
                socket: WireRead::new(read),
                context: self.context,
                reader: self.reader,
                records: Vec::with_capacity(RECORD_BATCH),
                first: 0,
                deferred_error: None,
                eof: false,
            },
            SendRecords {
                socket: write,
                writer: self.writer,
                filled: 0,
            },
        )
    }
}

struct Receive<R = OwnedReadHalf> {
    socket: WireRead<R>,
    context: SharedContext,
    reader: DecryptedReader,
    records: Vec<Bytes>,
    first: usize,
    deferred_error: Option<io::Error>,
    eof: bool,
}

impl<R: AsyncRead + Unpin> Receive<R> {
    fn poll_records(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.first < self.records.len() {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = self.deferred_error.take() {
            return Poll::Ready(Err(error));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        let DecryptedReader::Aead2022(reader) = &mut self.reader else {
            unreachable!("SS2022 receiver uses the AEAD2022 reader");
        };
        // All previous leases have been consumed. Reclaim their slab before
        // taking more records; never concatenate authenticated payloads.
        reader.reserve_owned_records(RECORD_SLAB);
        while self.records.len() < RECORD_BATCH {
            match reader.poll_fill_buf_decrypted(cx, &self.context, &mut self.socket) {
                Poll::Ready(Ok(bytes)) if bytes.is_empty() => {
                    self.eof = true;
                    break;
                }
                Poll::Ready(Ok(_)) => self.records.push(reader.take_decrypted()),
                Poll::Pending if self.records.is_empty() => return Poll::Pending,
                Poll::Pending => break,
                Poll::Ready(Err(error)) => {
                    self.eof = true;
                    if self.records.is_empty() {
                        return Poll::Ready(Err(error.into()));
                    }
                    self.deferred_error = Some(error.into());
                    break;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

// In the established stream the cipher requests an encrypted length and body
// separately. A socket read can fill both without changing either boundary.
struct WireRead<R> {
    socket: R,
    bytes: Box<[u8]>,
    head: usize,
    tail: usize,
}

impl<R> WireRead<R> {
    fn new(socket: R) -> Self {
        Self {
            socket,
            bytes: vec![0; READ_AHEAD].into_boxed_slice(),
            head: 0,
            tail: 0,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for WireRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if this.head == this.tail {
            if out.remaining() >= this.bytes.len() {
                return Pin::new(&mut this.socket).poll_read(cx, out);
            }
            let mut incoming = ReadBuf::new(&mut this.bytes);
            ready!(Pin::new(&mut this.socket).poll_read(cx, &mut incoming))?;
            this.head = 0;
            this.tail = incoming.filled().len();
        }
        let n = (this.tail - this.head).min(out.remaining());
        out.put_slice(&this.bytes[this.head..this.head + n]);
        this.head += n;
        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Receive<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let bytes = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = bytes.len().min(buf.remaining());
        buf.put_slice(&bytes[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

impl<R: AsyncRead + Unpin> AsyncBufRead for Receive<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        ready!(this.poll_records(cx))?;
        Poll::Ready(Ok(this
            .records
            .get(this.first)
            .map_or(&[], |bytes| &bytes[..])))
    }

    fn consume(self: Pin<&mut Self>, mut amount: usize) {
        let this = self.get_mut();
        while amount > 0 {
            let bytes = &mut this.records[this.first];
            let n = amount.min(bytes.len());
            bytes.advance(n);
            amount -= n;
            if bytes.is_empty() {
                *bytes = Bytes::new();
                this.first += 1;
            }
        }
        if this.first == this.records.len() {
            this.records.clear();
            this.first = 0;
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncBufReadVectored for Receive<R> {
    fn poll_fill_buf_vectored<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
        slices: &mut [io::IoSlice<'a>],
    ) -> Poll<io::Result<usize>> {
        assert!(!slices.is_empty());
        let this = self.get_mut();
        ready!(this.poll_records(cx))?;
        let records = &this.records[this.first..];
        let n = records.len().min(slices.len());
        for (out, record) in slices.iter_mut().zip(records) {
            *out = io::IoSlice::new(record);
        }
        Poll::Ready(Ok(n))
    }
}

struct SendRecords {
    socket: OwnedWriteHalf,
    writer: EncryptedWriter,
    filled: usize,
}

impl AsyncWriteInput for SendRecords {
    fn poll_input(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<WriteInput<'_>>> {
        let this = self.get_mut();
        let EncryptedWriter::Aead2022(writer) = &mut this.writer else {
            unreachable!("SS2022 sender uses the AEAD2022 writer");
        };
        let (storage, regions) = writer.prepare_input();
        Poll::Ready(Ok(WriteInput::new(storage, regions, &mut this.filled)))
    }

    fn poll_send_input(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let EncryptedWriter::Aead2022(writer) = &mut this.writer else {
            unreachable!("SS2022 sender uses the AEAD2022 writer");
        };
        let n = ready!(writer.poll_send_input(cx, &mut this.socket, this.filled))?;
        this.filled = 0;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for SendRecords {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.writer
            .poll_write_encrypted(cx, &mut this.socket, buf)
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_ss2022::relay::tcprelay::ProxyClientStream;
    use kerlico_ss2022::{config::ServerType, context::Context as SsContext, method, remote};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn encrypted_records(kind: CipherKind, parts: &[&[u8]]) -> io::Result<Vec<u8>> {
        let key = vec![0x34; kind.key_len()];
        let salt = vec![0x56; kind.salt_len()];
        let mut writer = EncryptedWriter::new(StreamType::Client, kind, &key, &salt);
        let mut wire = Vec::new();
        for part in parts {
            let n =
                std::future::poll_fn(|cx| writer.poll_write_encrypted(cx, &mut wire, part)).await?;
            assert_eq!(n, part.len());
        }
        Ok(wire)
    }

    fn receive<R>(socket: R, kind: CipherKind) -> Receive<R> {
        Receive {
            socket: WireRead::new(socket),
            context: SsContext::new_shared(ServerType::Server),
            reader: DecryptedReader::new(StreamType::Server, kind, &vec![0x34; kind.key_len()]),
            records: Vec::with_capacity(RECORD_BATCH),
            first: 0,
            deferred_error: None,
            eof: false,
        }
    }

    #[tokio::test]
    async fn direct_encoder_input_reuses_storage_and_interleaves_with_ordinary_writes(
    ) -> io::Result<()> {
        for name in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha12-poly1305",
            "chacha8-poly1305",
        ] {
            let kind = method(&format!("2022-blake3-{name}")).unwrap();
            let mut cipher = EncryptedWriter::new(
                StreamType::Client,
                kind,
                &vec![0x34; kind.key_len()],
                &vec![0x56; kind.salt_len()],
            );
            let EncryptedWriter::Aead2022(writer) = &mut cipher else {
                unreachable!()
            };
            let mut wire = Vec::new();
            let mut expected = Vec::new();
            let mut pointer = None;
            for size in [2 * 65_535 + 19, 4 * 65_535, 3] {
                let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
                let address = writer.prepare_input().0.as_ptr();
                assert_eq!(
                    *pointer.get_or_insert(address),
                    address,
                    "reuse the encoder allocation"
                );
                let (storage, regions) = writer.prepare_input();
                assert_eq!(storage.as_ptr(), address);
                let mut rest = &payload[..];
                for region in regions {
                    let n = rest.len().min(region.len());
                    storage[region.start..region.start + n].copy_from_slice(&rest[..n]);
                    rest = &rest[n..];
                    if rest.is_empty() {
                        break;
                    }
                }
                assert!(rest.is_empty());
                let n =
                    std::future::poll_fn(|cx| writer.poll_send_input(cx, &mut wire, payload.len()))
                        .await?;
                assert_eq!(n, payload.len());
                expected.extend_from_slice(&payload);
                let n = std::future::poll_fn(|cx| {
                    writer.poll_write_encrypted(cx, &mut wire, b"middle")
                })
                .await?;
                assert_eq!(n, 6);
                expected.extend_from_slice(b"middle");
            }
            let mut actual = Vec::new();
            receive(Cursor::new(wire), kind)
                .read_to_end(&mut actual)
                .await?;
            assert_eq!(
                actual, expected,
                "{name}: no skipped prefix, duplicate bytes or stale tail"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn owned_records_keep_their_storage_and_reclaim_it_after_delivery() -> io::Result<()> {
        let kind = method("2022-blake3-aes-128-gcm").unwrap();
        let body = vec![0x79; u16::MAX as usize];
        let parts = vec![body.as_slice(); 3 * RECORD_BATCH];
        let wire = encrypted_records(kind, &parts).await?;
        let context = SsContext::new_shared(ServerType::Server);
        let mut source = Cursor::new(wire);
        let mut cipher =
            DecryptedReader::new(StreamType::Server, kind, &vec![0x34; kind.key_len()]);
        let DecryptedReader::Aead2022(reader) = &mut cipher else {
            unreachable!()
        };
        let mut first_pointer = None;
        for _ in 0..3 {
            reader.reserve_owned_records(RECORD_SLAB);
            let mut leases = Vec::new();
            for i in 0..RECORD_BATCH {
                let pointer = std::future::poll_fn(|cx| {
                    let bytes = ready!(reader.poll_fill_buf_decrypted(cx, &context, &mut source))?;
                    Poll::Ready(Ok::<_, io::Error>(bytes.as_ptr()))
                })
                .await?;
                let record = reader.take_decrypted();
                assert_eq!(record.as_ptr(), pointer, "taking a record must not copy it");
                assert_eq!(&record[..], &body);
                if i == 0 {
                    assert_eq!(
                        *first_pointer.get_or_insert(pointer),
                        pointer,
                        "reuse the released slab"
                    );
                }
                leases.push(record);
            }
            // All record leases stay alive until this batch has been delivered.
            drop(leases);
        }
        Ok(())
    }

    #[tokio::test]
    async fn vectored_records_keep_partial_consumption_and_defer_bad_authentication(
    ) -> io::Result<()> {
        for name in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha12-poly1305",
            "chacha8-poly1305",
        ] {
            let kind = method(&format!("2022-blake3-{name}")).unwrap();
            let mut wire =
                encrypted_records(kind, &[b"first", b"second", b"third", b"untrusted"]).await?;
            *wire.last_mut().unwrap() ^= 1;
            let mut source = receive(Cursor::new(wire), kind);
            let mut slices = [io::IoSlice::new(&[]); 8];
            // All input is already present, so a single poll lends the good
            // records even though authentication of the last one fails.
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(matches!(
                Pin::new(&mut source).poll_fill_buf_vectored(&mut cx, &mut slices),
                Poll::Ready(Ok(3))
            ));
            assert_eq!(&*slices[0], b"first");
            assert_eq!(&*slices[1], b"second");
            assert_eq!(&*slices[2], b"third");
            source.consume(7); // one entire record and part of the next
            assert_eq!(source.fill_buf().await?, b"cond");
            let mut ordinary = [0; 4];
            source.read_exact(&mut ordinary).await?;
            assert_eq!(&ordinary, b"cond");
            assert_eq!(source.fill_buf().await?, b"third");
            source.consume(5);
            assert!(source.fill_buf().await.is_err(), "{name}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn batched_encoder_preserves_nonce_order_across_short_writes_and_pending(
    ) -> io::Result<()> {
        struct ShortWrites {
            bytes: Vec<u8>,
            pending: bool,
            calls: usize,
        }
        impl AsyncWrite for ShortWrites {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.pending {
                    self.pending = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = bytes.len().min(4093);
                self.bytes.extend_from_slice(&bytes[..n]);
                self.pending = true;
                self.calls += 1;
                Poll::Ready(Ok(n))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let payload: Vec<u8> = (0..600_017).map(|n| (n % 251) as u8).collect();
        for name in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha12-poly1305",
            "chacha8-poly1305",
        ] {
            let kind = method(&format!("2022-blake3-{name}")).unwrap();
            let mut writer = EncryptedWriter::new(
                StreamType::Client,
                kind,
                &vec![0x34; kind.key_len()],
                &vec![0x56; kind.salt_len()],
            );
            let mut wire = ShortWrites {
                bytes: Vec::new(),
                pending: false,
                calls: 0,
            };
            let mut accepted = 0;
            while accepted < payload.len() {
                let remaining = &payload[accepted..];
                let n = std::future::poll_fn(|cx| {
                    writer.poll_write_encrypted(cx, &mut wire, remaining)
                })
                .await?;
                assert_eq!(n, remaining.len().min(4 * u16::MAX as usize));
                accepted += n;
            }
            assert!(wire.calls > 100);
            let mut decoded = Vec::new();
            receive(Cursor::new(wire.bytes), kind)
                .read_to_end(&mut decoded)
                .await?;
            assert_eq!(decoded, payload, "{name}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn borrowed_records_share_consumption_with_ordinary_reads_for_every_cipher(
    ) -> io::Result<()> {
        for name in [
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "chacha12-poly1305",
            "chacha8-poly1305",
        ] {
            let kind = method(&format!("2022-blake3-{name}")).unwrap();
            let large: Vec<u8> = (0..65_535).map(|i| (i % 251) as u8).collect();
            let wire = encrypted_records(kind, &[b"first", &large, b"last"]).await?;
            let mut reader = receive(Cursor::new(wire), kind);
            let pointer = reader.fill_buf().await?.as_ptr();
            assert_eq!(reader.fill_buf().await?, b"first");
            assert_eq!(reader.fill_buf().await?.as_ptr(), pointer);
            reader.consume(2);
            let mut part = [0; 2];
            reader.read_exact(&mut part).await?;
            assert_eq!(&part, b"rs");
            assert_eq!(reader.fill_buf().await?, b"t");
            reader.consume(1);
            assert_eq!(reader.fill_buf().await?, large);
            reader.consume(large.len());
            assert_eq!(reader.fill_buf().await?, b"last");
            reader.consume(4);
            assert!(reader.fill_buf().await?.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn partial_borrowed_record_survives_a_read_timeout() -> io::Result<()> {
        let kind = method("2022-blake3-aes-128-gcm").unwrap();
        let wire = encrypted_records(kind, &[b"first", b"second"]).await?;
        let first_len = encrypted_records(kind, &[b"first"]).await?.len();
        let split = first_len + 3;
        let (mut send, socket) = tokio::io::duplex(1024);
        send.write_all(&wire[..split]).await?;
        let mut reader = receive(socket, kind);
        assert_eq!(reader.fill_buf().await?, b"first");
        reader.consume(5);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), reader.fill_buf())
                .await
                .is_err()
        );
        send.write_all(&wire[split..]).await?;
        send.shutdown().await?;
        assert_eq!(reader.fill_buf().await?, b"second");
        reader.consume(6);
        assert!(reader.fill_buf().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn failed_authentication_never_exposes_a_borrowed_record() -> io::Result<()> {
        let kind = method("2022-blake3-aes-128-gcm").unwrap();
        let mut wire = encrypted_records(kind, &[b"first", b"untrusted"]).await?;
        *wire.last_mut().unwrap() ^= 1;
        let mut reader = receive(Cursor::new(wire), kind);
        assert_eq!(reader.fill_buf().await?, b"first");
        reader.consume(5);
        assert!(reader.fill_buf().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn split_stream_keeps_request_payload_record_order_and_both_half_closes() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let kind = method("2022-blake3-aes-128-gcm").unwrap();
            let config =
                remote(kind, "AAAAAAAAAAAAAAAAAAAAAA==", "127.0.0.1", addr.port()).unwrap();
            let key = config.key().to_vec();
            let destination = Address::SocketAddress("127.0.0.1:8443".parse().unwrap());
            let wanted = destination.clone();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (request, target, first) = Stream::handshake(
                    socket,
                    SsContext::new_shared(ServerType::Server),
                    kind,
                    &key,
                    None,
                )
                .await
                .unwrap();
                assert_eq!(target, wanted);
                assert_eq!(first, b"initial");
                let (mut read, mut write) = request.into_halves();
                tokio::join!(
                    async {
                        let mut tail = Vec::new();
                        read.read_to_end(&mut tail).await.unwrap();
                        assert_eq!(
                            tail,
                            (0..140_000).map(|i| (i % 251) as u8).collect::<Vec<_>>()
                        );
                    },
                    async {
                        write.write_all(b"server-first").await.unwrap();
                        write.shutdown().await.unwrap();
                    },
                );
            });
            let socket = TcpStream::connect(addr).await.unwrap();
            let mut client = ProxyClientStream::from_stream(
                SsContext::new_shared(ServerType::Local),
                socket,
                &config,
                destination,
            );
            client.write_all(b"initial").await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"server-first");
            let uplink: Vec<u8> = (0..140_000).map(|i| (i % 251) as u8).collect();
            client.write_all(&uplink).await.unwrap();
            client.shutdown().await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn wire_read_keeps_pending_ciphertext_spanning_a_read_timeout() -> io::Result<()> {
        let (mut wire, socket) = tokio::io::duplex(128);
        let mut reader = WireRead::new(socket);
        let mut part = [0; 4];
        wire.write_all(b"12345678").await?;
        reader.read_exact(&mut part).await?;
        assert_eq!(&part, b"1234");
        // The socket has no more queued bytes, but the buffer still holds the
        // other half. It must be delivered before asking the socket again.
        tokio::time::timeout(Duration::from_secs(1), reader.read_exact(&mut part)).await??;
        assert_eq!(&part, b"5678");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), reader.read_exact(&mut part))
                .await
                .is_err()
        );
        wire.write_all(b"abcd").await?;
        reader.read_exact(&mut part).await?;
        assert_eq!(&part, b"abcd");
        Ok(())
    }
}
