//! 先八帧填充，再原流；状态按方向、逻辑流独立。
use kerlico_core::{BoxStream, CancellationToken};
use rand::{Rng, RngCore};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub(crate) const COUNT: usize = 8;
pub(crate) fn header(response: bool) -> String {
    let mut random = rand::thread_rng();
    let len = if response {
        random.gen_range(30..=62)
    } else {
        random.gen_range(16..=32)
    };
    let bits: u64 = random.next_u64();
    let alphabet = b"!#$()+<>?@[]^`{}";
    (0..len)
        .map(|i| {
            if i < 16 {
                alphabet[((bits >> (i * 4)) & 15) as usize] as char
            } else {
                '~'
            }
        })
        .collect()
}
pub(crate) fn wrap(stream: BoxStream, cancel: CancellationToken) -> BoxStream {
    crate::io::spawn(cancel, None, move |peer, completed| async move {
        let (source, sink) = tokio::io::split(stream);
        let (reader, writer) = tokio::io::split(peer);
        let receive = async {
            let result = decode(source, writer).await;
            completed.finish_read(&result);
            result
        };
        tokio::try_join!(
            receive,
            completed.writing(encode(reader, sink, completed.clone()))
        )?;
        Ok(())
    })
}
pub(crate) async fn decode(
    mut source: impl AsyncRead + Unpin,
    mut sink: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut bytes = vec![0; crate::config::BUFFER];
    for _ in 0..COUNT {
        let mut first = [0];
        if source.read(&mut first).await? == 0 {
            sink.shutdown().await?;
            return Ok(());
        }
        let length = u16::from_be_bytes([first[0], source.read_u8().await?]) as usize;
        let padding = source.read_u8().await? as usize;
        let mut remaining = length;
        while remaining > 0 {
            let count = remaining.min(bytes.len());
            source.read_exact(&mut bytes[..count]).await?;
            sink.write_all(&bytes[..count]).await?;
            remaining -= count;
        }
        if padding > 0 {
            source.read_exact(&mut bytes[..padding]).await?;
        }
        if length > 0 {
            sink.flush().await?;
        }
    }
    tokio::io::copy(&mut source, &mut sink).await?;
    sink.shutdown().await
}
pub(crate) async fn encode(
    mut source: impl AsyncRead + Unpin,
    mut sink: impl AsyncWrite + Unpin,
    progress: crate::io::ReadCompletion,
) -> io::Result<()> {
    let mut bytes = vec![0; crate::config::BUFFER];
    for _ in 0..COUNT {
        let size = source.read(&mut bytes).await?;
        if size == 0 {
            sink.shutdown().await?;
            return Ok(());
        }
        let padding = rand::thread_rng().gen_range(0..=255usize);
        sink.write_all(&(size as u16).to_be_bytes()).await?;
        sink.write_u8(padding as u8).await?;
        sink.write_all(&bytes[..size]).await?;
        sink.write_all(&[0; 255][..padding]).await?;
        sink.flush().await?;
        progress.advance_write(size);
    }
    loop {
        let size = source.read(&mut bytes).await?;
        if size == 0 {
            break;
        }
        sink.write_all(&bytes[..size]).await?;
        sink.flush().await?;
        progress.advance_write(size);
    }
    sink.shutdown().await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn fragmented_frames_zero_payload_eighth_transition_and_truncation() {
        let (mut writer, reader) = tokio::io::duplex(1);
        let (sink, mut decoded) = tokio::io::duplex(32);
        let task = tokio::spawn(decode(reader, sink));
        let mut wire = Vec::new();
        for i in 0..COUNT {
            let payload = if i == 0 { vec![] } else { vec![i as u8; 3] };
            wire.extend((payload.len() as u16).to_be_bytes());
            wire.push(255);
            wire.extend(payload);
            wire.extend([0; 255]);
        }
        wire.extend(b"raw ninth");
        let send = tokio::spawn(async move {
            writer.write_all(&wire).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        let mut out = Vec::new();
        decoded.read_to_end(&mut out).await.unwrap();
        send.await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(
            out,
            [
                (1..8).flat_map(|i| vec![i; 3]).collect::<Vec<u8>>(),
                b"raw ninth".to_vec()
            ]
            .concat()
        );
        for bytes in [vec![0], vec![0, 1], vec![0, 1, 0], vec![0, 0, 1]] {
            let mut out = Vec::new();
            assert_eq!(
                decode(bytes.as_slice(), &mut out).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
    #[tokio::test]
    async fn maximum_wire_record_and_late_raw_bytes() {
        let mut wire = vec![255, 255, 255];
        wire.extend(vec![71; 65535]);
        wire.extend(vec![0; 255]);
        for _ in 1..8 {
            wire.extend([0, 0, 0]);
        }
        wire.extend([1, 2, 3]);
        let mut out = Vec::new();
        decode(wire.as_slice(), &mut out).await.unwrap();
        assert_eq!(out, [vec![71; 65535], vec![1, 2, 3]].concat());
    }
}
