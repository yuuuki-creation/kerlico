use kerlico_core::{BoxStream, Result};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

const ID: u32 = 3;
const MAX_SEND: usize = 32768;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "SMUX v1 帧不合法")
}
fn header(command: u8, len: usize) -> [u8; 8] {
    let mut head = [1, command, 0, 0, 0, 0, 0, 0];
    head[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    head[4..].copy_from_slice(&ID.to_le_bytes());
    head
}

/// 与参考出站一致：每个拨号拥有一个物理会话和一个逻辑流。
pub(crate) struct SingleStream {
    inner: BoxStream,
    head: [u8; 8],
    head_used: usize,
    body_left: usize,
    remote_fin: bool,
    local_fin: bool,
    pending: Vec<u8>,
    written: usize,
}
impl SingleStream {
    pub async fn open(mut inner: BoxStream) -> Result<Self> {
        inner.write_all(&header(0, 0)).await?;
        inner.flush().await?;
        Ok(Self {
            inner,
            head: [0; 8],
            head_used: 0,
            body_left: 0,
            remote_fin: false,
            local_fin: false,
            pending: Vec::new(),
            written: 0,
        })
    }
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for SingleStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // 读也推进已接纳的写，单次 write 后 read 不要求调用方另行 flush。
        if let Poll::Ready(Err(error)) = this.drain(cx) {
            return Poll::Ready(Err(error));
        }
        for _ in 0..32 {
            if this.body_left > 0 {
                let count = output.remaining().min(this.body_left);
                let mut body = ReadBuf::new(output.initialize_unfilled_to(count));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut body))?;
                let n = body.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                output.advance(n);
                this.body_left -= n;
                return Poll::Ready(Ok(()));
            }
            if this.remote_fin {
                return Poll::Ready(Ok(()));
            }
            while this.head_used < 8 {
                let mut buffer = ReadBuf::new(&mut this.head[this.head_used..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buffer))?;
                let n = buffer.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.head_used += n;
            }
            let [version, command, ..] = this.head;
            let len = u16::from_le_bytes([this.head[2], this.head[3]]) as usize;
            let id = u32::from_le_bytes(this.head[4..].try_into().unwrap());
            this.head_used = 0;
            if version != 1 {
                return Poll::Ready(Err(invalid()));
            }
            match command {
                1 if id == ID && len == 0 => this.remote_fin = true,
                2 if id == ID => this.body_left = len,
                3 if len == 0 => {}
                _ => return Poll::Ready(Err(invalid())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for SingleStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.local_fin || this.remote_fin {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(cx))?;
        let n = bytes.len().min(MAX_SEND);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        this.pending.extend_from_slice(&header(2, n));
        this.pending.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if !this.local_fin {
            this.local_fin = true;
            this.pending.extend_from_slice(&header(1, 0));
        }
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn split_headers_maximum_record_fin_and_cancelled_reads() {
        let (client, mut peer) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let mut syn = [0; 8];
            peer.read_exact(&mut syn).await.unwrap();
            assert_eq!(syn, header(0, 0));
            peer.write_all(&header(2, 65535)[..3]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            peer.write_all(&header(2, 65535)[3..]).await.unwrap();
            peer.write_all(&vec![0x5a; 65535]).await.unwrap();
            peer.write_all(&header(1, 0)).await.unwrap();
        });
        let mut stream = SingleStream::open(Box::new(client)).await.unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), stream.read(&mut byte))
                .await
                .is_err()
        );
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, vec![0x5a; 65535]);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn ordered_data_fin_and_write_then_read_without_flush() {
        let (client, mut peer) = tokio::io::duplex(16);
        let task = tokio::spawn(async move {
            let mut head = [0; 8];
            peer.read_exact(&mut head).await.unwrap();
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(head, header(2, 5));
            let mut bytes = [0; 5];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
            peer.write_all(&header(2, 5)).await.unwrap();
            peer.write_all(b"world").await.unwrap();
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(head, header(1, 0));
        });
        let mut stream = SingleStream::open(Box::new(client)).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut bytes = [0; 5];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"world");
        stream.shutdown().await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_wrong_version_stream_command_and_truncation() {
        for head in [
            [2, 2, 0, 0, 3, 0, 0, 0],
            [1, 2, 0, 0, 5, 0, 0, 0],
            [1, 4, 0, 0, 3, 0, 0, 0],
            [1, 1, 1, 0, 3, 0, 0, 0],
        ] {
            let (client, mut peer) = tokio::io::duplex(64);
            let task = tokio::spawn(async move {
                let mut syn = [0; 8];
                peer.read_exact(&mut syn).await.unwrap();
                peer.write_all(&head).await.unwrap();
            });
            let mut stream = SingleStream::open(Box::new(client)).await.unwrap();
            assert!(stream.read(&mut [0; 1]).await.is_err());
            task.await.unwrap();
        }
    }
}
