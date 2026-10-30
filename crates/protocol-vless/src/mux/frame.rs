use kerlico_core::{Destination, Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_proxy::mux::{self, Status};
use xray_routing::{Target, TargetAddr};

pub(crate) struct Frame {
    pub id: u16,
    pub status: Status,
    pub error: bool,
    pub target: Option<Target>,
    pub global_id: Option<[u8; 8]>,
    pub payload: Option<Vec<u8>>,
}
impl Frame {
    pub fn data(id: u16, payload: Vec<u8>, target: Option<Target>) -> Self {
        Self {
            id,
            status: Status::Keep,
            error: false,
            target,
            global_id: None,
            payload: Some(payload),
        }
    }
    pub fn end(id: u16, error: bool) -> Self {
        Self {
            id,
            status: Status::End,
            error,
            target: None,
            global_id: None,
            payload: None,
        }
    }
}
pub(crate) fn destination(target: &Target) -> Result<Destination> {
    Destination::new(
        &match &target.addr {
            TargetAddr::Ip(ip) => ip.to_string(),
            TargetAddr::Domain(name) => name.clone(),
        },
        target.port,
    )
}
pub(crate) async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>> {
    let mut prefix = [0; 2];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..]).await?;
    let length = u16::from_be_bytes(prefix) as usize;
    if !(4..=mux::MAX_METADATA).contains(&length) {
        return Err(Error::Protocol("Mux 元数据长度不合法"));
    }
    let mut wire = Vec::with_capacity(2 + length + 2 + mux::MAX_PAYLOAD);
    wire.extend_from_slice(&prefix);
    wire.resize(2 + length, 0);
    reader.read_exact(&mut wire[2..]).await?;
    if wire[5] & 1 != 0 {
        let len = reader.read_u16().await? as usize;
        if len > mux::MAX_PAYLOAD {
            return Err(Error::ResourceLimit);
        }
        wire.extend_from_slice(&(len as u16).to_be_bytes());
        let offset = wire.len();
        wire.resize(offset + len, 0);
        reader.read_exact(&mut wire[offset..]).await?;
    }
    let (frame, used) = mux::decode(&wire)?.ok_or(Error::Protocol("Mux 帧不完整"))?;
    if used != wire.len() {
        return Err(Error::Protocol("Mux 帧存在额外数据"));
    }
    Ok(Some(Frame {
        id: frame.session_id,
        status: frame.status,
        error: frame.error,
        target: frame.target,
        global_id: frame.global_id,
        payload: frame.payload.map(ToOwned::to_owned),
    }))
}
pub(crate) async fn write<W: AsyncWrite + Unpin>(writer: &mut W, frame: Frame) -> Result<()> {
    let bytes = mux::encode(&mux::Frame {
        session_id: frame.id,
        status: frame.status,
        error: frame.error,
        target: frame.target,
        global_id: frame.global_id,
        payload: frame.payload.as_deref(),
    })?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[tokio::test]
    async fn independent_mux_vector_and_all_truncations() {
        let wire = [0, 12, 0, 1, 1, 0, 1, 0, 80, 1, 127, 0, 0, 1];
        let mut reader = Cursor::new([wire.as_slice(), b"tail"].concat());
        let frame = read(&mut reader).await.unwrap().unwrap();
        assert_eq!(frame.id, 1);
        assert_eq!(frame.status, Status::New);
        assert_eq!(
            destination(frame.target.as_ref().unwrap())
                .unwrap()
                .to_string(),
            "127.0.0.1:80"
        );
        assert_eq!(reader.position(), wire.len() as u64);
        assert!(
            read(&mut Cursor::new(Vec::<u8>::new()))
                .await
                .unwrap()
                .is_none()
        );
        for n in 1..wire.len() {
            assert!(read(&mut Cursor::new(wire[..n].to_vec())).await.is_err());
        }
        assert!(read(&mut Cursor::new(vec![2, 1])).await.is_err());
        let mut invalid = wire;
        invalid[5] = 4;
        assert!(read(&mut Cursor::new(invalid)).await.is_err());
    }
}
