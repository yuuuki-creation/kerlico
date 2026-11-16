use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use kerlico_ss2022::{config::ServerConfig, context::SharedContext, relay};
use rand_core::{OsRng, RngCore};
use relay::socks5::Address;
use relay::tcprelay::crypto_io::{CryptoRead, CryptoStream, CryptoWrite, StreamType};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

const MAX_PADDING: u16 = 900;

pub(crate) struct ClientStream {
    stream: CryptoStream<tokio::net::TcpStream>,
    context: SharedContext,
}

impl ClientStream {
    pub(crate) async fn start(
        socket: tokio::net::TcpStream,
        context: SharedContext,
        config: &ServerConfig,
        destination: &Address,
    ) -> io::Result<Self> {
        let mut stream = Self {
            stream: CryptoStream::from_stream_with_identity(
                &context,
                socket,
                StreamType::Client,
                config.method(),
                config.key(),
                config.identity_keys(),
                None,
            ),
            context,
        };
        stream.stream.bind_response_salt();
        // There is no early payload: SIP022 requires nonzero padding. This also
        // starts the request for servers that speak first.
        stream.write_all(&request(destination)?).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

fn request(destination: &Address) -> io::Result<BytesMut> {
    let padding = loop {
        let mut random = [0u8; 2];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| io::Error::other("cannot generate Shadowsocks request padding"))?;
        let sample = u16::from_ne_bytes(random);
        if sample < u16::MAX / MAX_PADDING * MAX_PADDING {
            break 1 + sample % MAX_PADDING;
        }
    };
    let len = destination.serialized_len() + 2 + usize::from(padding);
    let mut request = BytesMut::with_capacity(len);
    destination.write_to_buf(&mut request);
    request.put_u16(padding);
    request.resize(len, 0);
    Ok(request)
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream)
            .poll_read_decrypted(cx, &this.context, buf)
            .map_err(Into::into)
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream)
            .poll_write_encrypted(cx, buf)
            .map_err(Into::into)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_shutdown(cx).map_err(Into::into)
    }
}
