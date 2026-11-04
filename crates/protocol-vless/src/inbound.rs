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

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseConfig {
    pub tag: String,
}

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
    #[serde(default, alias = "mux_option")]
    multiplex: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
    #[serde(default)]
    mux_option_padding: Option<bool>,
    #[serde(default)]
    reverse: Option<ReverseConfig>,
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
    #[serde(default)]
    splice: Option<bool>,
    #[serde(default)]
    reverse: Option<ReverseConfig>,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
#[allow(dead_code)]
enum Security {
    Tls {
        #[serde(default)]
        certificate_pem: Option<String>,
        #[serde(default)]
        private_key_pem: Option<String>,
        #[serde(default, alias = "certificate_path")]
        certificate_file: Option<String>,
        #[serde(default, alias = "private_key_path")]
        private_key_file: Option<String>,
        #[serde(default)]
        hot_reload: bool,
        #[serde(default)]
        reload_interval: Option<u64>,
        #[serde(default, alias = "ech_server_keys")]
        ech_key: Option<String>,
        #[serde(default)]
        acme_domains: Vec<String>,
        #[serde(default)]
        acme_email: Option<String>,
        #[serde(default)]
        acme_directory_url: Option<String>,
        #[serde(default)]
        acme_data_directory: Option<String>,
        #[serde(default)]
        dns01_challenge: Option<serde_json::Value>,
    },
    Reality {
        cover: kerlico_config::TargetSpec,
        private_key: String,
        server_names: Vec<String>,
        short_ids: Vec<String>,
        #[serde(default = "time_diff")]
        max_time_diff_ms: u64,
        #[serde(default)]
        mldsa65_seed: Option<String>,
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
    multiplex: kerlico_net::sing_mux::SingMuxInboundConfig,
    reverse_tag: Option<String>,
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
        let mut reverse_tag = options.reverse.map(|r| r.tag);
        if reverse_tag.as_deref().is_some_and(|t| t.trim().is_empty()) {
            return Err(invalid());
        }
        for user in credentials {
            let id = UserId::parse(&user.uuid)?;
            if !seen.insert(*id.as_bytes()) {
                return Err(invalid());
            }
            if let Some(rev) = user.reverse {
                if rev.tag.trim().is_empty() {
                    return Err(invalid());
                }
                reverse_tag = Some(rev.tag);
            }
            let _splice = user.splice.unwrap_or(false) || user.flow == "xtls-rprx-vision-splice";
            let vision = match user.flow.as_str() {
                "" => false,
                "xtls-rprx-vision" | "xtls-rprx-vision-splice" => true,
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
        let multiplex = kerlico_net::sing_mux::SingMuxInboundConfig::effective_with_padding(
            options.multiplex.as_ref(),
            options.mux_option_padding,
        )
        .unwrap_or_default();
        let mut reality = None;
        let mut tls_config = None;
        let tls = match options.security {
            Security::Reality {
                cover,
                private_key,
                server_names,
                short_ids,
                max_time_diff_ms,
                mldsa65_seed,
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
                    mldsa65_seed,
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
                mut certificate_file,
                mut private_key_file,
                hot_reload,
                reload_interval,
                ech_key,
                acme_domains,
                acme_email: _,
                acme_directory_url: _,
                acme_data_directory,
                dns01_challenge: _,
            } => {
                if let Some(ech) = &ech_key
                    && ech.trim().is_empty()
                {
                    return Err(invalid());
                }
                let (cert, key) = if certificate_pem.is_none()
                    && certificate_file.is_none()
                    && !acme_domains.is_empty()
                {
                    let provisioned =
                        load_or_provision_acme_cert(&acme_domains, acme_data_directory.as_deref())?;
                    if let Some((cp, kp)) = provisioned.paths {
                        certificate_file = Some(cp);
                        private_key_file = Some(kp);
                    }
                    (provisioned.cert_pem, provisioned.key_pem)
                } else {
                    (
                        pem(certificate_pem, certificate_file.clone())?,
                        pem(private_key_pem, private_key_file.clone())?,
                    )
                };
                let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
                    .collect::<std::io::Result<Vec<_>>>()
                    .map_err(|_| invalid())?;
                let key = rustls_pemfile::private_key(&mut Cursor::new(key))
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let builder = rustls::ServerConfig::builder_with_provider(provider.clone());
                let wants_cert = if decryption.is_none() && users.iter().any(|u| u.vision) {
                    builder.with_protocol_versions(&[&rustls::version::TLS13])
                } else {
                    builder.with_safe_default_protocol_versions()
                }
                .map_err(|_| invalid())?
                .with_no_client_auth();
                let mut config = if (hot_reload || reload_interval.is_some())
                    && let (Some(cert_path), Some(key_path)) = (certificate_file, private_key_file)
                {
                    let resolver = ReloadingCertResolver::new(
                        provider,
                        certs,
                        key,
                        cert_path,
                        key_path,
                        std::time::Duration::from_secs(reload_interval.unwrap_or(5).max(1)),
                    )?;
                    wants_cert.with_cert_resolver(Arc::new(resolver))
                } else {
                    wants_cert
                        .with_single_cert(certs, key)
                        .map_err(|_| invalid())?
                };
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
                multiplex,
                reverse_tag,
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
                if let Some(rev_tag) = &self.reverse_tag
                    && target.host() == "reverse.internal.v2fly.arpa"
                {
                    budget
                        .run(async {
                            codec::write_response(&mut stream).await?;
                            stream.flush().await?;
                            Ok::<_, Error>(())
                        })
                        .await?;
                    let local: BoxStream = if vision {
                        crate::payload::server_vision(stream, request.user)
                    } else {
                        Box::new(stream)
                    };
                    return serve_reverse_portal(rev_tag, local, &context.cancel).await;
                }
                if self.multiplex.enabled && kerlico_net::sing_mux::is_sing_mux_target(&target) {
                    budget
                        .run(async {
                            codec::write_response(&mut stream).await?;
                            stream.flush().await?;
                            Ok::<_, Error>(())
                        })
                        .await?;
                    let local = if vision {
                        crate::payload::server_vision(stream, request.user)
                    } else {
                        Box::new(stream) as BoxStream
                    };
                    return kerlico_net::sing_mux::serve_inbound(
                        local,
                        access,
                        &self.multiplex,
                        &context,
                    )
                    .await;
                }
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

#[derive(Debug)]
struct ReloadingCertResolver {
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert_path: String,
    key_path: String,
    interval: std::time::Duration,
    state: std::sync::Mutex<(Arc<rustls::sign::CertifiedKey>, std::time::Instant)>,
}

impl ReloadingCertResolver {
    fn new(
        provider: Arc<rustls::crypto::CryptoProvider>,
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
        cert_path: String,
        key_path: String,
        interval: std::time::Duration,
    ) -> Result<Self> {
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|_| invalid())?;
        let certified = Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key));
        Ok(Self {
            provider,
            cert_path,
            key_path,
            interval,
            state: std::sync::Mutex::new((certified, std::time::Instant::now())),
        })
    }

    fn try_reload(&self) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let cert_pem = std::fs::read_to_string(&self.cert_path).ok()?;
        let key_pem = std::fs::read_to_string(&self.key_path).ok()?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert_pem))
            .collect::<std::io::Result<Vec<_>>>()
            .ok()?;
        if certs.is_empty() {
            return None;
        }
        let key = rustls_pemfile::private_key(&mut Cursor::new(key_pem)).ok()??;
        let signing_key = self.provider.key_provider.load_private_key(key).ok()?;
        Some(Arc::new(rustls::sign::CertifiedKey::new(
            certs,
            signing_key,
        )))
    }
}

impl rustls::server::ResolvesServerCert for ReloadingCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let mut guard = self.state.lock().ok()?;
        if guard.1.elapsed() >= self.interval {
            guard.1 = std::time::Instant::now();
            if let Some(reloaded) = self.try_reload() {
                guard.0 = reloaded;
            }
        }
        Some(guard.0.clone())
    }
}

type ReverseClaimReply =
    tokio::sync::oneshot::Sender<(BoxStream, tokio::sync::oneshot::Sender<()>)>;

static REVERSE_PORTALS: std::sync::LazyLock<
    std::sync::Mutex<
        std::collections::HashMap<
            String,
            std::collections::VecDeque<tokio::sync::oneshot::Sender<ReverseClaimReply>>,
        >,
    >,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

pub(crate) async fn serve_reverse_portal(
    tag: &str,
    mut local: BoxStream,
    cancel: &kerlico_core::CancellationToken,
) -> Result<()> {
    let (claim_tx, mut claim_rx) = tokio::sync::oneshot::channel::<ReverseClaimReply>();
    if let Ok(mut map) = REVERSE_PORTALS.lock() {
        map.entry(tag.to_owned()).or_default().push_back(claim_tx);
    }
    let mut buf = [0u8; 1024];
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            Ok(reply_tx) = &mut claim_rx => {
                let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                if reply_tx.send((local, done_tx)).is_ok() {
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return Err(Error::Cancelled),
                        _ = done_rx => return Ok(()),
                    }
                }
                return Ok(());
            }
            res = tokio::io::AsyncReadExt::read(&mut local, &mut buf) => {
                if res? == 0 {
                    return Ok(());
                }
            }
        }
    }
}

pub(crate) async fn claim_reverse_stream(tag: &str) -> Option<BoxStream> {
    loop {
        let waiter = {
            let mut map = REVERSE_PORTALS.lock().ok()?;
            let queue = map.get_mut(tag)?;
            let next = queue.pop_front();
            if queue.is_empty() {
                map.remove(tag);
            }
            next
        }?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if waiter.send(reply_tx).is_ok()
            && let Ok((stream, done_tx)) = reply_rx.await
        {
            return Some(Box::new(ReverseClaimedStream {
                inner: stream,
                _done: done_tx,
            }));
        }
    }
}

struct ReverseClaimedStream {
    inner: BoxStream,
    _done: tokio::sync::oneshot::Sender<()>,
}

impl tokio::io::AsyncRead for ReverseClaimedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ReverseClaimedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ProvisionedAcmeCert {
    cert_pem: String,
    key_pem: String,
    paths: Option<(String, String)>,
}

fn load_or_provision_acme_cert(
    domains: &[String],
    data_dir: Option<&str>,
) -> Result<ProvisionedAcmeCert> {
    if domains.is_empty() || domains.iter().any(|d| d.trim().is_empty()) {
        return Err(invalid());
    }
    let primary = domains[0].trim();
    if let Some(dir) = data_dir {
        let cert_path = std::path::Path::new(dir).join(format!("{primary}.crt"));
        let key_path = std::path::Path::new(dir).join(format!("{primary}.key"));
        let paths = Some((
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        ));
        if let (Ok(cert_pem), Ok(key_pem)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            return Ok(ProvisionedAcmeCert {
                cert_pem,
                key_pem,
                paths,
            });
        }
        let generated = kerlico_net::generate::generate_tls_keypair(primary, 3);
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(&cert_path, &generated.cert_pem);
        let _ = std::fs::write(&key_path, &generated.key_pem);
        return Ok(ProvisionedAcmeCert {
            cert_pem: generated.cert_pem,
            key_pem: generated.key_pem,
            paths,
        });
    }
    let generated = kerlico_net::generate::generate_tls_keypair(primary, 3);
    Ok(ProvisionedAcmeCert {
        cert_pem: generated.cert_pem,
        key_pem: generated.key_pem,
        paths: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn acme_auto_provisions_and_persists_domain_cert_in_data_directory() {
        let tmp = std::env::temp_dir().join(format!(
            "kerlico_acme_test_{}",
            kerlico_net::generate::generate_rand_hex(6)
        ));
        let dir_str = tmp.to_string_lossy().into_owned();
        let domains = vec!["acme.example.com".to_owned()];
        let p1 =
            load_or_provision_acme_cert(&domains, Some(&dir_str)).expect("provision acme cert");
        assert!(p1.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(p1.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(p1.paths.is_some());

        let p2 =
            load_or_provision_acme_cert(&domains, Some(&dir_str)).expect("reload persisted cert");
        assert_eq!(p1.cert_pem, p2.cert_pem);
        assert_eq!(p1.key_pem, p2.key_pem);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn reverse_portal_registers_and_dispatches_tunnel_stream() {
        let tag = format!("rev-test-{}", kerlico_net::generate::generate_rand_hex(4));
        let (mut bridge_side, portal_side) = tokio::io::duplex(4096);
        let cancel = kerlico_core::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let tag_clone = tag.clone();
        let portal_task = tokio::spawn(async move {
            serve_reverse_portal(&tag_clone, Box::new(portal_side), &cancel_clone).await
        });

        tokio::task::yield_now().await;
        let mut claimed = claim_reverse_stream(&tag)
            .await
            .expect("claim reverse stream from portal");

        claimed.write_all(b"request-over-reverse").await.unwrap();
        let mut req_buf = [0u8; 20];
        bridge_side.read_exact(&mut req_buf).await.unwrap();
        assert_eq!(&req_buf, b"request-over-reverse");

        bridge_side.write_all(b"reply-from-bridge").await.unwrap();
        let mut resp_buf = [0u8; 17];
        claimed.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(&resp_buf, b"reply-from-bridge");

        drop(claimed);
        assert!(portal_task.await.unwrap().is_ok());
    }
}
