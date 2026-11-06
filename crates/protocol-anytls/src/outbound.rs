use crate::{
    codec,
    padding::{self, Padding},
    session::Session,
    uot,
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
};
use kerlico_net::TcpConnector;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock, atomic::Ordering},
};
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
    #[serde(default, alias = "allow_insecure", alias = "skip_cert_verify")]
    insecure: bool,
    /// uTLS ClientHello 指纹，对应 Mihomo `client-fingerprint`。
    #[serde(default)]
    fingerprint: Option<String>,
}
fn idle_default() -> u64 {
    30000
}
fn pool_default() -> usize {
    64
}
type SessionPool = Arc<Mutex<Vec<Arc<Session>>>>;

struct AnyTlsOutbound {
    server: Destination,
    password: [u8; 32],
    connector: TcpConnector,
    sessions: std::sync::Mutex<HashMap<kerlico_core::ResourceKey, SessionPool>>,
    host: kerlico_core::ServiceContext,
    idle: std::time::Duration,
    capacity: Arc<tokio::sync::Semaphore>,
    closed: std::sync::atomic::AtomicBool,
}
impl Drop for AnyTlsOutbound {
    fn drop(&mut self) {
        if let Ok(partitions) = self.sessions.get_mut() {
            for bucket in partitions.values() {
                if let Ok(sessions) = bucket.try_lock() {
                    for session in sessions.iter() {
                        session.close();
                    }
                }
            }
        }
    }
}
impl OutboundFactory for AnyTlsFactory {
    fn kind(&self) -> &'static str {
        "anytls"
    }
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("AnyTLS 出站字段不合法".into()))?;
        if options.password.is_empty()
            || options.password.len() > 4096
            || !(1..=4096).contains(&options.max_sessions)
            || !(100..=86400000).contains(&options.idle_session_timeout_ms)
        {
            return Err(Error::Config("AnyTLS 口令或会话限制不合法".into()));
        }
        let server = Destination::new(&options.server.host, options.server.port)?;
        let password = Sha256::digest(options.password.as_bytes()).into();
        let connector = TcpConnector::tls_client(
            &kerlico_net::TlsClientOptions {
                protocol: "AnyTLS",
                server_name: &options.tls.server_name,
                ca_pem: options.tls.ca_pem.as_deref(),
                insecure: options.tls.insecure,
                fingerprint: options.tls.fingerprint.as_deref(),
                alpn: &[],
            },
            kerlico_core::current_compile_dialer(),
        )?;
        let idle = std::time::Duration::from_millis(options.idle_session_timeout_ms);
        let max_sessions = options.max_sessions;
        Padding::parse(padding::DEFAULT)?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: false,
                udp: true,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(AnyTlsOutbound {
                        server,
                        password,
                        connector,
                        sessions: std::sync::Mutex::new(HashMap::new()),
                        host,
                        idle,
                        capacity: Arc::new(tokio::sync::Semaphore::new(max_sessions)),
                        closed: std::sync::atomic::AtomicBool::new(false),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
impl AnyTlsOutbound {
    async fn open(
        &self,
        target: Option<&Destination>,
        context: &ConnectContext,
    ) -> Result<BoxStream> {
        if self.closed.load(Ordering::Acquire) || self.host.cancel().is_cancelled() {
            return Err(Error::Cancelled);
        }
        let bucket = {
            let mut partitions = self.sessions.lock().map_err(|_| Error::Rejected)?;
            partitions
                .entry(context.resource_key().clone())
                .or_insert_with(|| Arc::new(Mutex::new(Vec::new())))
                .clone()
        };
        let reserved = {
            let mut sessions = bucket.lock().await;
            if self.closed.load(Ordering::Acquire) || self.host.cancel().is_cancelled() {
                return Err(Error::Cancelled);
            }
            sessions.retain(|session| !session.closed.is_cancelled());
            let reusable = sessions
                .iter()
                .rev()
                .find(|s| s.active.load(Ordering::Acquire) == 0)
                .cloned();
            if let Some(s) = reusable {
                let (id, stream) = s.reserve_stream()?;
                Some((s, id, stream))
            } else {
                None
            }
        };
        let (session, id, mut stream) = if let Some(reserved) = reserved {
            reserved
        } else {
            let permit = self
                .capacity
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            let mut raw = self.connector.connect(&self.server).await?;
            let padding = Arc::new(RwLock::new(Padding::parse(padding::DEFAULT)?));
            let count = padding
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
            raw.write_all(&auth).await?;
            raw.flush().await?;
            let session = Session::start(
                raw,
                true,
                padding,
                1,
                self.idle,
                None,
                crate::session::Owner::Service(self.host.clone()),
            )
            .await?;
            session.assign_permit(permit);
            let (id, stream) = session.reserve_stream()?;
            let mut sessions = bucket.lock().await;
            if self.closed.load(Ordering::Acquire) || self.host.cancel().is_cancelled() {
                session.close();
                return Err(Error::Cancelled);
            }
            sessions.push(session.clone());
            drop(sessions);
            (session, id, stream)
        };
        session.send_syn(id).await?;
        let header = target
            .map(|t| codec::address(t, false))
            .unwrap_or_else(codec::uot_target);
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(stream)
    }
}
impl Outbound for AnyTlsOutbound {
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::Release);
            self.capacity.close();
            let partitions =
                std::mem::take(&mut *self.sessions.lock().map_err(|_| Error::Rejected)?);
            let mut all = Vec::new();
            for bucket in partitions.into_values() {
                let mut sessions = bucket.lock().await;
                for session in sessions.iter() {
                    session.close();
                }
                all.extend(std::mem::take(&mut *sessions));
            }
            for session in all {
                session.shutdown().await;
            }
            Ok(())
        })
    }
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
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            let opening: kerlico_core::BoxFuture<'_, Result<BoxStream>> =
                Box::pin(async move { context.run(self.open(Some(target), context)).await });
            let stream = opening.await?;
            Ok(kerlico_core::OpenedTcp {
                stream,
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let mut stream = self.open(None, context).await?;
                    stream.write_u8(1).await?;
                    stream.write_all(&codec::address(target, false)).await?;
                    stream.flush().await?;
                    Ok(uot::channel(stream))
                })
                .await
        })
    }
}
