use kerlico_core::{BoxStream, Destination, Result};
use tokio::{net::TcpStream, sync::Mutex};

/// 同一出站的载体连接固定首次成功的接入IP，不在鉴权失败后换节点。
pub(crate) struct Endpoint {
    configured: Destination,
    selected: Mutex<Option<Destination>>,
}
impl Endpoint {
    pub fn new(configured: Destination) -> Self {
        Self {
            configured,
            selected: Mutex::new(None),
        }
    }
    pub async fn connect(&self) -> Result<BoxStream> {
        let mut selected = self.selected.lock().await;
        let target = selected.as_ref().unwrap_or(&self.configured);
        let stream = TcpStream::connect((target.host().as_str(), target.port())).await?;
        stream.set_nodelay(true)?;
        if selected.is_none() {
            let peer = stream.peer_addr()?;
            *selected = Some(Destination::new(
                &peer.ip().to_canonical().to_string(),
                peer.port(),
            )?);
        }
        Ok(Box::new(stream))
    }
}
