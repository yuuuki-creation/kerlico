//! 服务端请求解析；认证在节点实例中完成，Mux 不读取不存在的目标字段。
use crate::{UserId, codec};
use kerlico_core::{Destination, Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) struct Request {
    pub user: UserId,
    pub flow: String,
    pub command: u8,
    pub target: Option<Destination>,
}

pub(crate) async fn read<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<Request> {
    if reader.read_u8().await? != codec::VERSION {
        return Err(Error::Protocol("VLESS 版本不支持"));
    }
    let mut user = [0; 16];
    reader.read_exact(&mut user).await?;
    let len = reader.read_u8().await? as usize;
    let mut addons = vec![0; len];
    reader.read_exact(&mut addons).await?;
    let flow = codec::decode_flow(&addons)?;
    if !flow.is_empty() && flow != "xtls-rprx-vision" {
        return Err(Error::Unsupported("VLESS flow"));
    }
    let command = reader.read_u8().await?;
    let target = match command {
        1 | 2 => {
            let port = reader.read_u16().await?;
            Some(address(reader, port,command==2).await?)
        }
        3 => None,
        _ => return Err(Error::Unsupported("VLESS 指令")),
    };
    Ok(Request {
        user: UserId::from_bytes(user),
        flow,
        command,
        target,
    })
}

pub(crate) async fn address<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    port: u16,
    packetaddr:bool,
) -> Result<Destination> {
    let host = match reader.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            std::net::Ipv4Addr::from(bytes).to_string()
        }
        2 => {
            let len = reader.read_u8().await? as usize;
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| Error::InvalidAddress)?
        }
        3 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            std::net::Ipv6Addr::from(bytes).to_string()
        }
        _ => return Err(Error::Protocol("VLESS 地址类型不支持")),
    };
    Destination::new(&host,if packetaddr&&port==0&&host=="sp.packet-addr.v2fly.arpa"{1}else{port})
}


#[cfg(test)]
mod tests {
    use super::*;
    fn request(command:u8,host:&str)->Vec<u8>{let mut bytes=vec![0];bytes.extend_from_slice(&[0;16]);bytes.extend_from_slice(&[0,command,0,0,2,host.len() as u8]);bytes.extend_from_slice(host.as_bytes());bytes}
    #[tokio::test]
    async fn packetaddr_zero_port_marker_does_not_open_general_zero_port_targets(){
        let magic="sp.packet-addr.v2fly.arpa";
        let parsed=read(&mut std::io::Cursor::new(request(2,magic))).await.unwrap();assert_eq!(parsed.target.unwrap().host(),magic);
        assert!(read(&mut std::io::Cursor::new(request(1,magic))).await.is_err());assert!(read(&mut std::io::Cursor::new(request(2,"example.invalid"))).await.is_err());
    }
}
