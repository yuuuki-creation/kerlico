//! REALITY 节点只处理安全载体；失败连接按已配置的 cover 原样转发。
use crate::{UserId, reality_io::RealityIo};
use kerlico_core::{BoxStream, Destination, Error, InboundContext, Result};
use rust_reality::{
    config::node::entry::EntryConfig,
    protocol::reality::{
        RealityAuthenticator, read_client_hello,
        tls13::{
            CertificateIdentity, TlsApplicationIo, build_server_flight, read_client_finished,
            read_target_server_hello,
        },
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncWriteExt;
use xray_transport::BoxedTransportStream;

pub(crate) enum Accepted {
    Stream(BoxedTransportStream),
    Fallback {
        client: BoxStream,
        cover: BoxStream,
        client_prefix: Vec<u8>,
        server_prefix: Vec<u8>,
    },
}
struct Reservation {
    entries: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    key: [u8; 32],
    committed: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed
            && let Ok(mut entries) = self.entries.lock()
        {
            entries.remove(&self.key);
        }
    }
}
pub(crate) struct Reality {
    auth: RealityAuthenticator,
    identity: CertificateIdentity,
    cover: Destination,
    replays: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
}
impl Reality {
    pub fn new(
        cover: Destination,
        private_key: String,
        server_names: Vec<String>,
        short_ids: Vec<String>,
        max_time_diff_ms: u64,
        owner: UserId,
    ) -> Result<Self> {
        if server_names.is_empty()
            || server_names.len() > 32
            || short_ids.is_empty()
            || short_ids.len() > 256
            || max_time_diff_ms > 300000
        {
            return Err(Error::Config("REALITY 身份或时间参数超出范围".into()));
        }
        let entry:EntryConfig=serde_json::from_value(serde_json::json!({"role":"entry","listeners":[],"reality":{"cover":cover.to_string(),"privateKey":private_key,"serverNames":server_names,"maxTimeDiffMs":max_time_diff_ms},"users":[{"id":uuid::Uuid::from_bytes(*owner.as_bytes()).to_string(),"shortIds":short_ids}],"routing":{"default":"direct"}})).map_err(|_|Error::Config("REALITY 配置不合法".into()))?;
        Ok(Self {
            auth: RealityAuthenticator::from_entry(&entry)
                .map_err(|_| Error::Config("REALITY 密钥、名称或 short ID 不合法".into()))?,
            identity: CertificateIdentity::generate()
                .map_err(|_| Error::Protocol("REALITY 证书身份生成失败"))?,
            cover,
            replays: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    async fn cover(&self) -> Result<BoxStream> {
        kerlico_net::TcpConnector::plain()
            .connect(&self.cover)
            .await
    }
    pub async fn accept(
        &self,
        mut client: BoxStream,
        context: &InboundContext,
    ) -> Result<Accepted> {
        let hello = match read_client_hello(&mut client, context.connect_timeout).await {
            Ok(hello) => hello,
            Err(error) => {
                let (_, prefix) = error.into_parts();
                if prefix.is_empty() {
                    return Err(Error::Protocol("REALITY 客户端已结束"));
                }
                return Ok(Accepted::Fallback {
                    client,
                    cover: self.cover().await?,
                    client_prefix: prefix,
                    server_prefix: Vec::new(),
                });
            }
        };
        let (hello, prefix, remainder) = hello.into_parts();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Protocol("系统时间不可用"))?
            .as_secs();
        let auth = match self.auth.authenticate(&hello, now) {
            Ok(auth) if remainder.is_empty() => auth,
            _ => {
                return Ok(Accepted::Fallback {
                    client,
                    cover: self.cover().await?,
                    client_prefix: prefix,
                    server_prefix: Vec::new(),
                });
            }
        };
        let key: [u8; 32] = Sha256::digest(hello.raw_message()).into();
        let reserved = {
            let mut entries = self
                .replays
                .lock()
                .map_err(|_| Error::Protocol("REALITY 重放状态不可用"))?;
            entries.retain(|_, time| time.elapsed() < Duration::from_secs(300));
            if entries.len() >= 4096 || entries.contains_key(&key) {
                false
            } else {
                entries.insert(key, Instant::now());
                true
            }
        };
        if !reserved {
            return Ok(Accepted::Fallback {
                client,
                cover: self.cover().await?,
                client_prefix: prefix,
                server_prefix: Vec::new(),
            });
        }
        let mut reservation = Reservation {
            entries: self.replays.clone(),
            key,
            committed: false,
        };
        let mut cover = self.cover().await?;
        cover.write_all(&prefix).await?;
        cover.flush().await?;
        let target =
            match read_target_server_hello(&mut cover, &hello, context.connect_timeout).await {
                Ok(target) => target,
                Err(error) => {
                    let (_, server_prefix) = error.into_parts();
                    return Ok(Accepted::Fallback {
                        client,
                        cover,
                        client_prefix: Vec::new(),
                        server_prefix,
                    });
                }
            };
        let (template, server_prefix) = target.into_parts();
        let alpn = hello
            .alpn_protocols()
            .find(|p| *p == b"h2")
            .or_else(|| hello.alpn_protocols().find(|p| *p == b"http/1.1"));
        let flight =
            match build_server_flight(&hello, auth.auth_key(), template, &self.identity, alpn) {
                Ok(flight) => flight,
                Err(_) => {
                    return Ok(Accepted::Fallback {
                        client,
                        cover,
                        client_prefix: Vec::new(),
                        server_prefix,
                    });
                }
            };
        drop(cover);
        client.write_all(flight.wire()).await?;
        client.flush().await?;
        let established = read_client_finished(&mut client, flight, context.connect_timeout)
            .await
            .map_err(|_| Error::Protocol("REALITY ClientFinished 校验失败"))?;
        reservation.committed = true;
        Ok(Accepted::Stream(Box::new(RealityIo::new(
            TlsApplicationIo::new(client, established),
            context.idle_timeout,
        ))))
    }
}
