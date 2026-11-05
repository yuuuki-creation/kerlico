use crate::{config, credential_io::Candidates, destination};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use serde::Deserialize;
use shadowsocks::{
    ServerConfig, config::ServerType, context::SharedContext, relay::tcprelay::ProxyServerStream,
};
use std::sync::Arc;
use tokio::task::JoinSet;

pub(crate) struct Credential {
    pub config: Arc<ServerConfig>,
    pub key: Vec<u8>,
    pub fingerprints: Vec<[u8; 32]>,
}
pub struct ShadowsocksNode {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) crypto: SharedContext,
    pub(crate) credentials: CredentialSet<Credential>,
    local: bool,
    local_fingerprints: Vec<[u8; 32]>,
    mux: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
}
impl ShadowsocksNode {
    pub fn from_context(input: &NodeBuildContext) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Options {
            method: String,
            #[serde(default)]
            allow_insecure: bool,
            #[serde(default)]
            password: Option<String>,
            #[serde(default)]
            multiplex: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
            #[serde(default, alias = "mux-option-padding")]
            mux_option_padding: Option<bool>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Native {
            password: String,
        }
        let options: Options = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("Shadowsocks 节点字段不合法".into()))?;
        let mut rows = Vec::new();
        let mut local_fingerprints = Vec::new();
        let mut fallback = None;
        if input.is_local() {
            let password = options
                .password
                .ok_or_else(|| Error::Config("本地旧式 Shadowsocks 需要编码密码".into()))?;
            let (config, fingerprints) = config::node(config::NodeOptions {
                method: options.method.clone(),
                password,
                allow_insecure: options.allow_insecure,
            })?;
            if config.method().is_aead() {
                return Err(Error::Config("AEAD 节点必须配置成员".into()));
            }
            fallback = Some(Arc::new(config));
            local_fingerprints = fingerprints;
        } else {
            if options.password.is_some() {
                return Err(Error::Config("认证密码必须放在成员凭据中".into()));
            }
            let mut seen = std::collections::HashSet::new();
            for value in input.native_credentials() {
                let native: Native = serde_json::from_value(value.clone())
                    .map_err(|_| Error::Config("Shadowsocks 成员凭据不合法".into()))?;
                let (config, fingerprints) = config::node(config::NodeOptions {
                    method: options.method.clone(),
                    password: native.password,
                    allow_insecure: options.allow_insecure,
                })?;
                if !config.method().is_aead() {
                    return Err(Error::Config(
                        "旧式 Shadowsocks 只允许无身份本地接入".into(),
                    ));
                }
                if !seen.insert(config.key().to_vec()) {
                    return Err(Error::Config("Shadowsocks 成员密钥重复".into()));
                }
                rows.push(Credential {
                    key: config.key().to_vec(),
                    config: Arc::new(config),
                    fingerprints,
                });
            }
            if rows.is_empty() || rows.len() > 256 {
                return Err(Error::Config("Shadowsocks 成员数量不合法".into()));
            }
        }
        let local = input.is_local();
        let config = fallback
            .or_else(|| rows.first().map(|row| row.config.clone()))
            .ok_or(Error::Rejected)?;
        let mux = kerlico_net::sing_mux::SingMuxInboundConfig::effective_with_padding(
            options.multiplex.as_ref(),
            options.mux_option_padding,
        );
        Ok(Self {
            config,
            crypto: crate::crypto(ServerType::Server),
            credentials: input.credentials(rows)?,
            local,
            local_fingerprints,
            mux,
        })
    }
}
impl InboundProtocol for ShadowsocksNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, row)) in self.credentials.rows().enumerate() {
            for fingerprint in &row.fingerprints {
                manifest.authentication("shadowsocks", slot, *fingerprint);
            }
        }
        for fingerprint in &self.local_fingerprints {
            manifest.protection("shadowsocks", *fingerprint);
        }

        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.local
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve_udp(socket, ingress, context))
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let handshake =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let (key, stream, target) =
                if self.local && self.config.method() == shadowsocks::crypto::CipherKind::NONE {
                    let mut stream = stream;
                    let addr = handshake
                        .run(async {
                            shadowsocks::relay::socks5::Address::read_from(&mut stream)
                                .await
                                .map_err(|_| crate::protocol_error())
                        })
                        .await?;
                    let target = destination(&addr)?;
                    (Vec::new(), stream, target)
                } else {
                    let candidates = Candidates::new(stream);
                    let mut tasks = JoinSet::new();
                    let configurations: Vec<_> = if self.local {
                        vec![self.config.clone()]
                    } else {
                        self.credentials
                            .rows()
                            .map(|(_, row)| row.config.clone())
                            .collect()
                    };
                    for config in configurations {
                        let stream = candidates.reader();
                        let crypto = crate::crypto(ServerType::Server);
                        let owner = context.tasks.clone();
                        let task = owner.spawn_tracked(async move {
                            let mut stream = ProxyServerStream::from_stream(
                                crypto,
                                stream,
                                config.method(),
                                config.key(),
                            );
                            let target = destination(&stream.handshake().await?)?;
                            Ok::<_, Error>((
                                config.key().to_vec(),
                                Box::new(stream) as BoxStream,
                                target,
                            ))
                        })?;
                        tasks.spawn(async move {
                            task.await
                                .unwrap_or(Err(Error::Protocol("认证任务异常退出")))
                        });
                    }
                    let selected = handshake
                        .run(async {
                            while let Some(result) = tasks.join_next().await {
                                if let Ok(Ok(result)) = result {
                                    return Ok(result);
                                }
                            }
                            Err(Error::Rejected)
                        })
                        .await;
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    let (key, stream, target) = selected?;
                    let nonce = candidates.prefix(
                        if self.config.method().is_aead() || self.config.method().is_aead_2022() {
                            self.config.method().salt_len()
                        } else {
                            self.config.method().iv_len()
                        },
                    )?;
                    self.crypto
                        .check_nonce_replay(self.config.method(), &nonce)?;
                    candidates.accept();
                    (key, stream, target)
                };
            let access = if self.local {
                ingress.local(&context)?
            } else {
                let slot = self
                    .credentials
                    .rows()
                    .find(|(_, row)| row.key == key)
                    .map(|(slot, _)| slot)
                    .ok_or(Error::Rejected)?;
                ingress
                    .authenticated(self.credentials.verified(&slot, ())?, &context)?
                    .0
            };
            if let Some(version) = kerlico_net::uot::magic_version(&target) {
                return kerlico_net::uot::serve(stream, version, access, context).await;
            }
            if kerlico_net::sing_mux::is_magic_target(&target) {
                let Some(mux_cfg) = &self.mux else {
                    return Err(Error::Rejected);
                };
                return kerlico_net::sing_mux::serve_inbound(stream, access, mux_cfg, &context)
                    .await;
            }
            let remote = access.connect_tcp(&target, &handshake).await?;
            kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
        })
    }
}
pub struct ShadowsocksNodeFactory;
impl NodeFactory for ShadowsocksNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowsocks"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(ShadowsocksNode::from_context(input)?))
    }
}
