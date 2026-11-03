//! VLESS 节点鉴权与业务适配；网站目标全部交给统一访问服务。
use kerlico_core::{DatagramReceiver, DatagramSender};

use crate::{
    UserId, codec, inbound_wire,
    server_io::{Plain, RecordAligned, ServerTls},
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_net::fallback::{FallbackRule, FallbackRuleInput, RecordingStream, try_fallback};
use serde::Deserialize;
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
    security: Security,
    #[serde(default)]
    transport: crate::server_http::Input,
    #[serde(default = "none")]
    decryption: String,
    #[serde(default)]
    fallbacks: Vec<FallbackRuleInput>,
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
/// 载体断开后 XUDP 会话等待接回的时长，取 Xray common/mux/session.go 的 Expire。
const XUDP_DETACHED_GRACE: std::time::Duration = std::time::Duration::from_secs(60);
pub(crate) struct Payload {
    users: CredentialSet<User>,
    decryption: Option<crate::server_encryption::Decryption>,
    fallbacks: Vec<FallbackRule>,
    mux_udp_only: bool,
    xudp: Arc<crate::mux::Table>,
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
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;
        let transport = options.transport.normalize()?;
        let fallbacks = options
            .fallbacks
            .into_iter()
            .map(FallbackRuleInput::compile)
            .collect::<Result<Vec<_>>>()?;
        let credentials = input
            .native_credentials()
            .iter()
            .map(|value| {
                serde_json::from_value::<UserOptions>(value.clone()).map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>>>()?;
        if credentials.is_empty() || credentials.len() > 256 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for user in credentials {
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
                let mut alpns = transport.alpn();
                if alpns.is_empty() && fallbacks.iter().any(|r| r.alpn.is_some()) {
                    for alpn in fallbacks.iter().filter_map(|r| r.alpn.as_ref()) {
                        let bytes = alpn.as_bytes().to_vec();
                        if !alpns.contains(&bytes) {
                            alpns.push(bytes);
                        }
                    }
                    if !alpns.iter().any(|a| a == b"http/1.1") {
                        alpns.push(b"http/1.1".to_vec());
                    }
                }
                config.alpn_protocols = alpns;
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
            payload: Arc::new(Payload {
                users: input.credentials(users)?,
                decryption,
                fallbacks,
                mux_udp_only: matches!(transport, crate::server_http::Transport::Xhttp { .. }),
                xudp: Arc::new(crate::mux::Table::new(XUDP_DETACHED_GRACE)),
            }),
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
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, user)) in self.payload.users.rows().enumerate() {
            let mut hash = Sha256::new();
            hash.update(b"kerlico/vless/node-user/");
            hash.update(user.id.as_bytes());
            manifest.authentication("vless", slot, hash.finalize().into());
        }
        manifest
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
        access: IngressBinding,
        mut context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let deadline = Instant::now() + context.connect_timeout;
            let (accepted, sni, alpn) = tokio::time::timeout(context.connect_timeout, async {
                if let Some(reality) = &self.reality {
                    return Ok::<_, Error>((reality.accept(stream, &context).await?, None, None));
                }
                if let Some(tls) = &self.tls {
                    let tls_stream = tls.accept(RecordAligned::new(stream)).await?;
                    let (_, conn) = tls_stream.get_ref();
                    let sni = conn.server_name().map(str::to_owned);
                    let alpn = conn
                        .alpn_protocol()
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .map(str::to_owned);
                    let stream: BoxedTransportStream = Box::new(ServerTls(tls_stream));
                    Ok((crate::server_reality::Accepted::Stream(stream), sni, alpn))
                } else {
                    let stream: BoxedTransportStream = Box::new(Plain(stream));
                    Ok((crate::server_reality::Accepted::Stream(stream), None, None))
                }
            })
            .await
            .map_err(|_| Error::Timeout)??;
            match accepted {
                crate::server_reality::Accepted::Stream(stream) => {
                    context.connect_timeout = deadline.saturating_duration_since(Instant::now());
                    if self.transport.raw() {
                        self.payload
                            .serve_with_meta(
                                stream,
                                access,
                                context,
                                sni.as_deref(),
                                alpn.as_deref(),
                            )
                            .await
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
                    kerlico_core::relay_streams(client, cover, context.idle_timeout, context.cancel)
                        .await
                }
            }
        })
    }
    fn handle_virtual<'a>(
        &'a self,
        access: IngressBinding,
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
        access: IngressBinding,
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
    fn verify(&self, request: &inbound_wire::Request) -> Result<kerlico_core::Verified<bool>> {
        self.users.verify(request, |user, request| {
            if !request.user.matches(&user.id) {
                return Ok(None);
            }
            if user.vision != (request.flow == "xtls-rprx-vision")
                || user.vision && request.command == 2
            {
                return Err(Error::Rejected);
            }
            Ok(Some(user.vision))
        })
    }
    pub(crate) async fn serve(
        &self,
        stream: BoxedTransportStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        self.serve_with_meta(stream, access, context, None, None)
            .await
    }
    pub(crate) async fn serve_with_meta(
        &self,
        mut stream: BoxedTransportStream,
        access: IngressBinding,
        context: InboundContext,
        sni: Option<&str>,
        alpn: Option<&str>,
    ) -> Result<()> {
        let deadline = Instant::now() + context.connect_timeout;
        let binding = access;
        let handshake = tokio::time::timeout(context.connect_timeout, async {
            if let Some(decryption) = &self.decryption {
                stream = decryption.accept(stream).await.map_err(|e| (e, None))?;
            }
            let mut recorder = RecordingStream::new(stream, 4096);
            let parsed = inbound_wire::read(&mut recorder).await;
            let (stream, recorded) = recorder.into_parts();
            let request = match parsed {
                Ok(req) => req,
                Err(err) => return Err((err, Some((stream, recorded)))),
            };
            match self.verify(&request) {
                Ok(verified) => {
                    let (access, vision) = binding
                        .authenticated(verified, &context)
                        .map_err(|e| (e, None))?;
                    Ok((stream, request, vision, access))
                }
                Err(err) => Err((err, Some((stream, recorded)))),
            }
        })
        .await
        .map_err(|_| Error::Timeout)?;

        let (mut stream, request, vision, access) = match handshake {
            Ok(tuple) => tuple,
            Err((err, Some((stream, recorded)))) => {
                if let Some(res) = try_fallback(
                    Box::new(stream),
                    recorded,
                    &self.fallbacks,
                    sni,
                    alpn,
                    &context,
                )
                .await
                {
                    return res;
                }
                return Err(err);
            }
            Err((err, None)) => return Err(err),
        };

        let budget = ConnectContext::new(deadline.saturating_duration_since(Instant::now()))
            .with_cancel(context.cancel.clone());
        match request.command {
            1 => {
                let target = request.target.ok_or(Error::InvalidAddress)?;
                let remote = access.connect_tcp(&target, &budget).await?;
                if let Err(error) = budget
                    .run(async {
                        codec::write_response(&mut stream).await?;
                        stream.flush().await?;
                        Ok(())
                    })
                    .await
                {
                    remote.finish(kerlico_core::FlowOutcome::Failed(
                        kerlico_core::FlowFailure::from_error(&error),
                    ));
                    return Err(error);
                }
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
                if let Err(error) = budget
                    .run(async {
                        codec::write_response(&mut stream).await?;
                        stream.flush().await?;
                        Ok(())
                    })
                    .await
                {
                    channel.finish(kerlico_core::FlowOutcome::Failed(
                        kerlico_core::FlowFailure::from_error(&error),
                    ));
                    return Err(error);
                }
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
                // XUDP 会话跨载体存活，不能持有首个载体的取消域和 peer 租约。
                let mut detached = context.clone();
                detached.peer_lease = None;
                detached.cancel = detached.tasks.cancel().child_token();
                let (detached_access, _) =
                    binding.authenticated(self.verify(&request)?, &detached)?;
                let migration = crate::mux::Migration {
                    table: self.xudp.clone(),
                    user: *request.user.as_bytes(),
                    access: detached_access,
                    context: detached,
                };
                crate::mux::serve(
                    local,
                    access,
                    context,
                    vision || self.mux_udp_only,
                    migration,
                )
                .await
            }
            _ => Err(Error::Unsupported("VLESS 指令")),
        }
    }
}

async fn relay_udp(
    stream: BoxStream,
    channel: kerlico_core::FixedUdpFlow,
    context: &InboundContext,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (mut sender, mut receiver, completion) = channel.into_parts();
    let result = async {
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
    .await;
    completion.finish(match &result {
        Ok(()) => kerlico_core::FlowOutcome::ProtocolEnd,
        Err(error) => {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::from_error(error))
        }
    });
    result
}
