//! VLESS 节点鉴权与业务适配；网站目标全部交给统一访问服务。

use crate::{
    UserId, codec, inbound_wire,
    server_io::{Plain, RecordAligned, ServerTls},
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, DatagramChannel, Error, InboundContext,
    InboundProtocol, Result,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Cursor, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use xray_transport::BoxedTransportStream;

pub struct VlessNodeFactory;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    flow: String,
    #[serde(default)]
    users: Vec<UserOptions>,
    security: Security,
    #[serde(default)]
    transport: crate::server_http::Input,
    #[serde(default = "none")]
    decryption: String,
}
fn none() -> String {
    "none".into()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserOptions {
    uuid: String,
    #[serde(default)]
    flow: String,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Security {
    Tls {
        #[serde(default)]
        certificate_pem: Option<String>,
        #[serde(default)]
        private_key_pem: Option<String>,
        #[serde(default)]
        certificate_file: Option<String>,
        #[serde(default)]
        private_key_file: Option<String>,
    },
    Reality {
        cover: kerlico_config::TargetSpec,
        private_key: String,
        server_names: Vec<String>,
        short_ids: Vec<String>,
        #[serde(default = "time_diff")]
        max_time_diff_ms: u64,
    },
    None,
}
fn time_diff() -> u64 {
    60000
}
struct User {
    id: UserId,
    vision: bool,
}
pub(crate) struct Payload {
    users: Vec<User>,
    decryption: Option<crate::server_encryption::Decryption>,
    mux_udp_only:bool,
}
struct VlessNode {
    payload: Arc<Payload>,
    tls: Option<TlsAcceptor>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    reality: Option<crate::server_reality::Reality>,
    transport: crate::server_http::Transport,
    http: Arc<crate::server_http::State>,
    storage: Option<Arc<crate::xdrive::Transport>>,
}

fn invalid() -> Error {
    Error::Config("VLESS 节点配置不合法".into())
}
fn pem(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(value), None) if value.len() <= 1024 * 1024 => Ok(value),
        (None, Some(path)) => {
            let meta = std::fs::metadata(&path).map_err(|_| invalid())?;
            if meta.len() > 1024 * 1024 {
                return Err(invalid());
            }
            std::fs::read_to_string(path).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
impl NodeFactory for VlessNodeFactory {
    fn kind(&self) -> &'static str {
        "vless"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let mut options: Options =
            serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let transport = options.transport.normalize()?;
        if let Some(uuid) = options.uuid {
            if !options.users.is_empty() {
                return Err(invalid());
            }
            options.users.push(UserOptions {
                uuid,
                flow: options.flow,
            });
        } else if !options.flow.is_empty() {
            return Err(invalid());
        }
        if options.users.is_empty() || options.users.len() > 256 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for user in options.users {
            let id = UserId::parse(&user.uuid)?;
            if !seen.insert(*id.as_bytes()) {
                return Err(invalid());
            }
            let vision = match user.flow.as_str() {
                "" => false,
                "xtls-rprx-vision" => true,
                _ => return Err(invalid()),
            };
            users.push(User { id, vision });
        }
        let decryption = crate::server_encryption::Decryption::parse(&options.decryption)?;
        if !transport.raw() && decryption.is_none() && users.iter().any(|u| u.vision) {
            return Err(Error::Config("包装载体上的 Vision 需要 Encryption".into()));
        }
        let storage = if let crate::server_http::Transport::Xdrive { settings } = &transport {
            if decryption.is_none()
                || users.iter().any(|u| u.vision)
                || !matches!(options.security, Security::None)
            {
                return Err(Error::Config(
                    "XDRIVE 节点要求 decryption、空 flow 和存储自身 TLS 配置".into(),
                ));
            }
            Some(crate::xdrive::Transport::new(settings.clone(), None)?)
        } else {
            None
        };
        let mut reality = None;
        let mut tls_config = None;
        let tls = match options.security {
            Security::Reality {
                cover,
                private_key,
                server_names,
                short_ids,
                max_time_diff_ms,
            } => {
                if matches!(
                    transport,
                    crate::server_http::Transport::Ws { .. }
                        | crate::server_http::Transport::Httpupgrade { .. }
                ) || !transport.tcp()
                    || matches!(&transport,crate::server_http::Transport::Xhttp{settings} if !matches!(settings.http_version.as_str(),"auto"|"h2"))
                {
                    return Err(invalid());
                }
                reality = Some(crate::server_reality::Reality::new(
                    cover.destination()?,
                    private_key,
                    server_names,
                    short_ids,
                    max_time_diff_ms,
                    users[0].id,
                )?);
                None
            }
            Security::None => {
                if decryption.is_none() && users.iter().any(|u| u.vision) {
                    return Err(invalid());
                }
                None
            }
            Security::Tls {
                certificate_pem,
                private_key_pem,
                certificate_file,
                private_key_file,
            } => {
                let cert = pem(certificate_pem, certificate_file)?;
                let key = pem(private_key_pem, private_key_file)?;
                let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
                    .collect::<std::io::Result<Vec<_>>>()
                    .map_err(|_| invalid())?;
                let key = rustls_pemfile::private_key(&mut Cursor::new(key))
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ));
                let mut config = if decryption.is_none() && users.iter().any(|u| u.vision) {
                    builder.with_protocol_versions(&[&rustls::version::TLS13])
                } else {
                    builder.with_safe_default_protocol_versions()
                }
                .map_err(|_| invalid())?
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|_| invalid())?;
                config.send_tls13_tickets = 0;
                config.alpn_protocols = transport.alpn();
                let config = Arc::new(config);
                tls_config = Some(config.clone());
                Some(TlsAcceptor::from(config))
            }
        };
        if storage.is_none() && !transport.tcp() && tls_config.is_none() {
            return Err(Error::Config("HTTP/3 节点必须提供 TLS".into()));
        }
        let http = crate::server_http::State::new(transport.clone());
        Ok(Arc::new(VlessNode {
            payload: Arc::new(Payload { users, decryption, mux_udp_only:matches!(transport,crate::server_http::Transport::Xhttp{..}) }),
            tls,
            tls_config,
            reality,
            transport,
            http,
            storage,
        }))
    }
}

impl InboundProtocol for VlessNode {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.payload
            .users
            .iter()
            .map(|user| {
                let mut h = Sha256::new();
                h.update(b"kerlico/vless/node-user/");
                h.update(user.id.as_bytes());
                h.finalize().into()
            })
            .collect()
    }
    fn supports_virtual(&self) -> bool {
        self.storage.is_some()
    }
    fn supports_tcp(&self) -> bool {
        self.transport.tcp()
    }
    fn supports_udp(&self) -> bool {
        self.transport.udp() && self.tls_config.is_some()
    }
    fn requires_loopback(&self) -> bool {
        self.tls.is_none() && self.reality.is_none() && self.payload.decryption.is_none()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        mut context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let deadline = Instant::now() + context.connect_timeout;
            let accepted = tokio::time::timeout(context.connect_timeout, async {
                if let Some(reality) = &self.reality {
                    return reality.accept(stream, &context).await;
                }
                let stream: BoxedTransportStream = if let Some(tls) = &self.tls {
                    Box::new(ServerTls(tls.accept(RecordAligned::new(stream)).await?))
                } else {
                    Box::new(Plain(stream))
                };
                Ok(crate::server_reality::Accepted::Stream(stream))
            })
            .await
            .map_err(|_| Error::Timeout)??;
            match accepted {
                crate::server_reality::Accepted::Stream(stream) => {
                    context.connect_timeout = deadline.saturating_duration_since(Instant::now());
                    if self.transport.raw() {
                        self.payload.serve(stream, access, context).await
                    } else {
                        self.http
                            .clone()
                            .serve(Box::new(stream), self.payload.clone(), access, context)
                            .await
                    }
                }
                crate::server_reality::Accepted::Fallback {
                    mut client,
                    mut cover,
                    client_prefix,
                    server_prefix,
                } => {
                    cover.write_all(&client_prefix).await?;
                    client.write_all(&server_prefix).await?;
                    cover.flush().await?;
                    client.flush().await?;
                    kerlico_core::relay_tcp(client, cover, context.idle_timeout, context.cancel)
                        .await
                }
            }
        })
    }
    fn handle_virtual<'a>(
        &'a self,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.storage
                .clone()
                .ok_or(Error::Unsupported("节点存储载体"))?
                .serve(self.payload.clone(), access, context)
                .await
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = self
                .tls_config
                .clone()
                .ok_or(Error::Unsupported("HTTP/3 TLS"))?;
            crate::server_h3::serve(
                socket,
                config,
                self.http.clone(),
                self.payload.clone(),
                access,
                context,
            )
            .await
        })
    }
}
impl Payload {
    pub(crate) async fn serve(
        &self,
        mut stream: BoxedTransportStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let deadline = Instant::now() + context.connect_timeout;
        let (mut stream, request, vision) = tokio::time::timeout(context.connect_timeout, async {
            if let Some(decryption) = &self.decryption {
                stream = decryption.accept(stream).await?;
            }
            let request = inbound_wire::read(&mut stream).await?;
            let user = self
                .users
                .iter()
                .find(|user| request.user.matches(&user.id))
                .ok_or(Error::Rejected)?;
            if user.vision != (request.flow == "xtls-rprx-vision")
                || user.vision && request.command == 2
            {
                return Err(Error::Rejected);
            }
            Ok::<_, Error>((stream, request, user.vision))
        })
        .await
        .map_err(|_| Error::Timeout)??;
        let budget = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: deadline.saturating_duration_since(Instant::now()),
        };
        match request.command {
            1 => {
                let target = request.target.ok_or(Error::InvalidAddress)?;
                let remote = access.connect_tcp(&target, &budget).await?;
                codec::write_response(&mut stream).await?;
                stream.flush().await?;
                let local = if vision {
                    crate::payload::server_vision(stream, request.user)
                } else {
                    Box::new(stream) as BoxStream
                };
                kerlico_core::relay_tcp(local, remote, context.idle_timeout, context.cancel).await
            }
            2 => {
                let target = request.target.ok_or(Error::InvalidAddress)?;
                if target.host() == "sp.packet-addr.v2fly.arpa" {
                    codec::write_response(&mut stream).await?;
                    stream.flush().await?;
                    return crate::mux::serve_packetaddr(Box::new(stream), access, context).await;
                }
                let channel = access.connect_udp(&target, &budget).await?;
                codec::write_response(&mut stream).await?;
                stream.flush().await?;
                relay_udp(Box::new(stream), channel, &context).await
            }
            3 => {
                codec::write_response(&mut stream).await?;
                stream.flush().await?;
                let local = if vision {
                    crate::payload::server_vision(stream, request.user)
                } else {
                    Box::new(stream) as BoxStream
                };
                crate::mux::serve(local, access, context, vision||self.mux_udp_only).await
            }
            _ => Err(Error::Unsupported("VLESS 指令")),
        }
    }
}

async fn relay_udp(
    stream: BoxStream,
    channel: DatagramChannel,
    context: &InboundContext,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut sender = channel.sender;
    let mut receiver = channel.receiver;
    let (activity, mut changes) = watch::channel(Instant::now());
    let incoming = async {
        while let Some(packet) =
            codec::read_datagram(&mut reader, context.max_datagram_size).await?
        {
            sender.send(&packet).await?;
            activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    let outgoing = async {
        while let Some(packet) = receiver.recv().await? {
            if packet.len() > context.max_datagram_size {
                return Err(Error::ResourceLimit);
            }
            codec::write_datagram(&mut writer, &packet).await?;
            activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    tokio::pin!(incoming, outgoing);
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _=context.cancel.cancelled()=>return Err(Error::Cancelled),
            r=&mut incoming=>return r,
            r=&mut outgoing=>return r,
            _=&mut timer=>return Err(Error::Timeout),
            changed=changes.changed()=>{if changed.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+context.idle_timeout);}},
        }
    }
}
