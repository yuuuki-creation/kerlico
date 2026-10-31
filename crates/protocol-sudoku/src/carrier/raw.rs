use crate::config::{CarrierMode, OutConfig};
use kerlico_core::{BoxStream, Error, Result};
use tokio::io::AsyncWriteExt;

pub(crate) async fn connect(
    config: &OutConfig,
    endpoint: &super::endpoint::Endpoint,
) -> Result<BoxStream> {
    if !matches!(config.mask.mode, CarrierMode::Raw | CarrierMode::Legacy) {
        return Err(Error::Unsupported("此连接器只处理raw/legacy载体"));
    }
    let mut stream = endpoint.connect().await?;
    if config.mask.mode == CarrierMode::Legacy {
        let host = config
            .mask
            .host
            .clone()
            .unwrap_or_else(|| config.server.to_string());
        let path = format!("{}/", config.mask.path_root);
        let header = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(header.as_bytes()).await?;
        stream.flush().await?;
    }
    Ok(stream)
}
