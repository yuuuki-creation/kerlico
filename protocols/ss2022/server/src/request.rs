//! SIP022 requires the address and padding to fit in the first encrypted chunk.

use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use kerlico_ss2022::{
    config::ServerUserManager,
    context::SharedContext,
    relay::tcprelay::crypto_io::{DecryptedReader, EncryptedWriter, StreamType},
    Address, CipherKind,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

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
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reader
            .poll_read_decrypted(cx, &this.context, &mut this.socket, buf)
            .map_err(Into::into)
    }
}

impl AsyncWrite for Stream {
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
