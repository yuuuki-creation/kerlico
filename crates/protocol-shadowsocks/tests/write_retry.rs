//! `tokio::io::copy_bidirectional` 在写 Pending 后会先读入更多数据，再用更长的切片重试。
//! 加密写端必须只确认已加密的字节，否则多出的部分会被静默丢弃。
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::Context as CryptoContext,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::proxy_stream::{ProxyClientStream, ProxyServerStream},
    },
};
use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

struct BlockOnce {
    inner: DuplexStream,
    block_next_write: Arc<AtomicBool>,
}

impl AsyncRead for BlockOnce {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl AsyncWrite for BlockOnce {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.block_next_write.swap(false, Ordering::SeqCst) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 写入 `payload`，首次写 Pending 后用更长的切片重试，模拟 `CopyBuffer::poll_copy`。
async fn write_with_growing_retry<W>(writer: &mut W, block: &AtomicBool, payload: &[u8])
where
    W: AsyncWrite + Unpin,
{
    let (first, _) = payload.split_at(payload.len() / 2);
    block.store(true, Ordering::SeqCst);
    let pending = poll_fn(|cx| Poll::Ready(Pin::new(&mut *writer).poll_write(cx, first))).await;
    assert!(pending.is_pending(), "首次写应被阻塞");
    let accepted = poll_fn(|cx| Pin::new(&mut *writer).poll_write(cx, payload))
        .await
        .unwrap();
    assert_eq!(accepted, first.len(), "只能确认已加密的字节");
    writer.write_all(&payload[accepted..]).await.unwrap();
    writer.flush().await.unwrap();
}

async fn round_trip(method: CipherKind, password: &str) {
    let (near, far) = tokio::io::duplex(1 << 20);
    let (block_client, block_server) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let config = ServerConfig::new(("127.0.0.1", 1), password, method).unwrap();
    let target = Address::DomainNameAddress("example.invalid".into(), 443);
    let mut client = ProxyClientStream::from_stream(
        CryptoContext::new_shared(ServerType::Local),
        BlockOnce {
            inner: near,
            block_next_write: block_client.clone(),
        },
        &config,
        target,
    );
    let mut server = ProxyServerStream::from_stream(
        CryptoContext::new_shared(ServerType::Server),
        BlockOnce {
            inner: far,
            block_next_write: block_server.clone(),
        },
        method,
        config.key(),
    );
    let request: Vec<u8> = (0..4096u32).map(|index| index as u8).collect();
    let response: Vec<u8> = request.iter().rev().copied().collect();

    write_with_growing_retry(&mut client, &block_client, &request).await;
    write_with_growing_retry(&mut client, &block_client, &request).await;
    server.handshake().await.unwrap();
    let mut received = vec![0; request.len() * 2];
    server.read_exact(&mut received).await.unwrap();
    assert_eq!(received, [request.as_slice(), &request].concat());

    write_with_growing_retry(&mut server, &block_server, &response).await;
    write_with_growing_retry(&mut server, &block_server, &response).await;
    let mut received = vec![0; response.len() * 2];
    client.read_exact(&mut received).await.unwrap();
    assert_eq!(received, [response.as_slice(), &response].concat());
}

#[tokio::test]
async fn growing_write_retry_keeps_every_byte_for_each_cipher_family() {
    for (method, password) in [
        (CipherKind::AES_128_CFB128, "stream-password"),
        (CipherKind::AES_128_GCM, "aead-password"),
        (
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            "AAAAAAAAAAAAAAAAAAAAAA==",
        ),
    ] {
        tokio::time::timeout(Duration::from_secs(10), round_trip(method, password))
            .await
            .unwrap_or_else(|_| panic!("{method:?} 回显超时"));
    }
}
