use kerlico_core::{Address, BoxStream, Destination, DialerOptions, Error, Result};
use std::net::SocketAddr;
use tokio::sync::Mutex;

/// 同一出站的载体连接固定首次成功的接入IP，不在鉴权失败后换节点。
pub(crate) struct Endpoint {
    dialer: DialerOptions,
    configured: Destination,
    selected: Mutex<Option<Destination>>,
}
impl Endpoint {
    pub fn new(configured: Destination, dialer: DialerOptions) -> Self {
        Self {
            dialer,
            configured,
            selected: Mutex::new(None),
        }
    }
    pub async fn connect(&self) -> Result<BoxStream> {
        let mut selected = self.selected.lock().await;
        if let Some(target) = selected.as_ref() {
            return self.dialer.connect(target).await;
        }
        // 经上游出站时本机看不到真实对端地址，无法固定接入 IP。
        if self.dialer.has_detour() {
            return self.dialer.connect(&self.configured).await;
        }
        let candidates: Vec<SocketAddr> = match self.configured.address() {
            Address::Ip(ip) => vec![SocketAddr::new(*ip, self.configured.port())],
            Address::Domain(host) => {
                kerlico_core::lookup_host((host.as_str(), self.configured.port()))
                    .await?
                    .collect()
            }
        };
        let dialer = &self.dialer;
        let (stream, _) = kerlico_core::dialer::happy_eyeballs(
            candidates,
            dialer.fallback_delay(),
            |peer| async move { Ok(dialer.connect_addr(peer).await?) },
        )
        .await?;
        let peer = stream.peer_addr().map_err(Error::Io)?;
        *selected = Some(Destination::new(
            &peer.ip().to_canonical().to_string(),
            peer.port(),
        )?);
        Ok(Box::new(stream))
    }
}
