//! HTTP流与内部双向字节流的适配；每次只缓存有界DATA并遵守窗口背压。
use bytes::{Buf, Bytes};
use futures_util::future::poll_fn;
use kerlico_core::{BoxStream, CancellationToken};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(crate) type H3Bidi = h3_quinn::BidiStream<Bytes>;
pub(crate) type H3Client = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
async fn h2_send(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    mut writer: h2::SendStream<Bytes>,
    progress: crate::io::ReadCompletion,
) -> io::Result<()> {
    let mut buffer = vec![0; crate::config::BUFFER];
    loop {
        let size = reader.read(&mut buffer).await?;
        if size == 0 {
            writer
                .send_data(Bytes::new(), true)
                .map_err(|_| crate::io::failed())?;
            return Ok(());
        }
        let mut offset = 0;
        while offset < size {
            writer.reserve_capacity(size - offset);
            let capacity = poll_fn(|cx| writer.poll_capacity(cx))
                .await
                .ok_or_else(crate::io::failed)?
                .map_err(|_| crate::io::failed())?;
            if capacity == 0 {
                continue;
            }
            let count = capacity.min(size - offset);
            writer
                .send_data(
                    Bytes::copy_from_slice(&buffer[offset..offset + count]),
                    false,
                )
                .map_err(|_| crate::io::failed())?;
            offset += count;
        }
        progress.advance_write(size);
    }
}
async fn h2_recv(
    mut reader: h2::RecvStream,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
) -> io::Result<()> {
    while let Some(data) = reader.data().await {
        let data = data.map_err(|_| crate::io::failed())?;
        writer.write_all(&data).await?;
        writer.flush().await?;
        reader
            .flow_control()
            .release_capacity(data.len())
            .map_err(|_| crate::io::failed())?;
    }
    if reader
        .trailers()
        .await
        .map_err(|_| crate::io::failed())?
        .is_some()
    {
        return Err(crate::io::failed());
    }
    writer.shutdown().await
}
pub(crate) fn h2(
    reader: h2::RecvStream,
    writer: h2::SendStream<Bytes>,
    cancel: CancellationToken,
    hold: Option<Box<dyn Send + Sync>>,
) -> BoxStream {
    crate::io::spawn(cancel, hold, move |peer, complete| async move {
        let (local_read, local_write) = tokio::io::split(peer);
        let incoming = async {
            let result = h2_recv(reader, local_write).await;
            complete.finish_read(&result);
            result
        };
        tokio::try_join!(
            incoming,
            complete.writing(h2_send(local_read, writer, complete.clone()))
        )?;
        Ok(())
    })
}
pub(crate) fn h3_client(
    stream: h3::client::RequestStream<H3Bidi, Bytes>,
    cancel: CancellationToken,
    hold: Option<Box<dyn Send + Sync>>,
) -> BoxStream {
    let (mut writer, mut reader) = stream.split();
    crate::io::spawn(cancel, hold, move |peer, complete| async move {
        let (mut local_read, mut local_write) = tokio::io::split(peer);
        let incoming = async {
            let result = async {
                while let Some(mut data) =
                    reader.recv_data().await.map_err(|_| crate::io::failed())?
                {
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        local_write.write_all(chunk).await?;
                        let length = chunk.len();
                        data.advance(length);
                    }
                    local_write.flush().await?;
                }
                if reader
                    .recv_trailers()
                    .await
                    .map_err(|_| crate::io::failed())?
                    .is_some()
                {
                    return Err(crate::io::failed());
                }
                local_write.shutdown().await
            }
            .await;
            complete.finish_read(&result);
            result
        };
        let outgoing = complete.writing(async {
            let mut bytes = vec![0; crate::config::BUFFER];
            loop {
                let size = local_read.read(&mut bytes).await?;
                if size == 0 {
                    writer.finish().await.map_err(|_| crate::io::failed())?;
                    return Ok::<_, io::Error>(());
                }
                writer
                    .send_data(Bytes::copy_from_slice(&bytes[..size]))
                    .await
                    .map_err(|_| crate::io::failed())?;
                complete.advance_write(size);
            }
        });
        tokio::try_join!(incoming, outgoing)?;
        Ok(())
    })
}
pub(crate) fn h3_server(
    stream: h3::server::RequestStream<H3Bidi, Bytes>,
    cancel: CancellationToken,
) -> BoxStream {
    let (mut writer, mut reader) = stream.split();
    crate::io::spawn(cancel, None, move |peer, complete| async move {
        let (mut local_read, mut local_write) = tokio::io::split(peer);
        let incoming = async {
            let result = async {
                while let Some(mut data) =
                    reader.recv_data().await.map_err(|_| crate::io::failed())?
                {
                    while data.has_remaining() {
                        let chunk = data.chunk();
                        local_write.write_all(chunk).await?;
                        let length = chunk.len();
                        data.advance(length);
                    }
                    local_write.flush().await?;
                }
                if reader
                    .recv_trailers()
                    .await
                    .map_err(|_| crate::io::failed())?
                    .is_some()
                {
                    return Err(crate::io::failed());
                }
                local_write.shutdown().await
            }
            .await;
            complete.finish_read(&result);
            result
        };
        let outgoing = complete.writing(async {
            let mut bytes = vec![0; crate::config::BUFFER];
            loop {
                let size = local_read.read(&mut bytes).await?;
                if size == 0 {
                    writer.finish().await.map_err(|_| crate::io::failed())?;
                    return Ok::<_, io::Error>(());
                }
                writer
                    .send_data(Bytes::copy_from_slice(&bytes[..size]))
                    .await
                    .map_err(|_| crate::io::failed())?;
                complete.advance_write(size);
            }
        });
        tokio::try_join!(incoming, outgoing)?;
        Ok(())
    })
}
