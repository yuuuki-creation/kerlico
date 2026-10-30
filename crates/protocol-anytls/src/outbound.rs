use crate::{
    codec,
    padding::{self, Padding},
    session::Session,
    uot,
};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
};
use kerlico_net::TcpConnector;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock, atomic::Ordering};
use tokio::{io::AsyncWriteExt, sync::Mutex};

pub struct AnyTlsFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: Server,
    password: String,
    tls: Tls,
    #[serde(default = "idle_default")]
    idle_session_timeout_ms: u64,
    #[serde(default = "pool_default")]
    max_sessions: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    host: String,
    port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    server_name: String,
    #[serde(default)]
    ca_pem: Option<String>,
}
fn idle_default() -> u64 {
    30000
}
fn pool_default() -> usize {
    64
}
struct AnyTlsOutbound {
    server: Destination,
    password: [u8; 32],
    connector: TcpConnector,
    sessions: Mutex<Vec<Arc<Session>>>,
    padding: Arc<RwLock<Padding>>,
    idle: std::time::Duration,
    max_sessions: usize,
}
impl Drop for AnyTlsOutbound {
    fn drop(&mut self) {
        for session in self.sessions.get_mut() {
            session.close();
        }
    }
}
impl OutboundFactory for AnyTlsFactory {
    fn kind(&self) -> &'static str {
        "anytls"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("AnyTLS 出站字段不合法".into()))?;
        if options.password.is_empty()
            || options.password.len() > 4096
            || !(1..=4096).contains(&options.max_sessions)
            || !(100..=86400000).contains(&options.idle_session_timeout_ms)
        {
            return Err(Error::Config("AnyTLS 口令或会话限制不合法".into()));
        }
        Ok(Arc::new(AnyTlsOutbound {
            server: Destination::new(&options.server.host, options.server.port)?,
            password: Sha256::digest(options.password.as_bytes()).into(),
            connector: TcpConnector::tls(&options.tls.server_name, options.tls.ca_pem.as_deref())?,
            sessions: Mutex::new(Vec::new()),
            padding: Arc::new(RwLock::new(Padding::parse(padding::DEFAULT)?)),
            idle: std::time::Duration::from_millis(options.idle_session_timeout_ms),
            max_sessions: options.max_sessions,
        }))
    }
}
impl AnyTlsOutbound {
    async fn open(&self, target: Option<&Destination>) -> Result<BoxStream> {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|s| !s.closed.is_cancelled());
        let reusable = sessions
            .iter()
            .rev()
            .find(|s| s.active.load(Ordering::Acquire) == 0)
            .cloned();
        let session = if let Some(s) = reusable {
            s
        } else {
            if sessions.len() >= self.max_sessions {
                return Err(Error::ResourceLimit);
            }
            let mut stream = self.connector.connect(&self.server).await?;
            let count = self
                .padding
                .read()
                .unwrap()
                .sizes(0)
                .first()
                .copied()
                .flatten()
                .unwrap_or(0);
            let mut auth = self.password.to_vec();
            auth.extend_from_slice(&(count as u16).to_be_bytes());
            auth.resize(auth.len() + count, 0);
            stream.write_all(&auth).await?;
            stream.flush().await?;
            let session =
                Session::start(stream, true, self.padding.clone(), 1, self.idle, None).await?;
            sessions.push(session.clone());
            session
        };
        let mut stream = session.open().await?;
        drop(sessions);
        let header = target
            .map(|t| codec::address(t, false))
            .unwrap_or_else(codec::uot_target);
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(stream)
    }
}
impl Outbound for AnyTlsOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move { context.run(self.open(Some(target))).await })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let mut stream = self.open(None).await?;
                    stream.write_u8(1).await?;
                    stream.write_all(&codec::address(target, false)).await?;
                    stream.flush().await?;
                    Ok(uot::channel(stream))
                })
                .await
        })
    }
}
