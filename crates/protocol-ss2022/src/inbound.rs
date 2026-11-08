use crate::{config, credential_io::Candidates, destination};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_net::sing_mux::SingMuxInboundConfig;
use serde::Deserialize;
use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::{Context, SharedContext},
    relay::tcprelay::ProxyServerStream,
};
use std::sync::Arc;
use tokio::task::JoinSet;

pub(crate) struct Credential {
    pub config: Arc<ServerConfig>,
    pub key: Vec<u8>,
    pub fingerprints: Vec<[u8; 32]>,
}
pub struct Ss2022Node {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) crypto: SharedContext,
    pub(crate) credentials: CredentialSet<Credential>,
    local: bool,
    mux: Option<SingMuxInboundConfig>,
}
impl Ss2022Node {
    pub fn from_context(input: &NodeBuildContext) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Options {
            method: String,
            #[serde(default)]
            identity_key: Option<String>,
            #[serde(default)]
            multiplex: Option<SingMuxInboundConfig>,
            #[serde(default, alias = "mux-option-padding")]
            mux_option_padding: Option<bool>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Native {
            key: String,
        }
        let options: Options = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("Ss2022 节点字段不合法".into()))?;
        let mut rows = Vec::new();
        if input.is_local() {
            return Err(Error::Config("SS2022 必须配置认证成员".into()));
        }
        let mut texts = Vec::new();
        for value in input.native_credentials() {
            let native: Native = serde_json::from_value(value.clone())
                .map_err(|_| Error::Config("SS2022 成员凭据不合法".into()))?;
            texts.push(native.key);
        }
        if texts.is_empty() || texts.len() > 1024 {
            return Err(Error::Config("SS2022 成员数量不合法".into()));
        }
        let mut seen = std::collections::HashSet::new();
        let (config, _) = if let Some(identity) = options.identity_key {
            config::node(config::NodeOptions {
                method: options.method.clone(),
                key: identity,
                users: texts.clone(),
            })?
        } else {
            config::node(config::NodeOptions {
                method: options.method.clone(),
                key: texts[0].clone(),
                users: Vec::new(),
            })?
        };
        let config = Arc::new(config);
        let eih = config.user_manager().is_some();
        for text in texts {
            let key = config::key(&text, config.method())?;
            if !seen.insert(key.clone()) {
                return Err(Error::Config("SS2022 成员密钥重复".into()));
            }
            let row_config = if eih {
                config.clone()
            } else {
                Arc::new(
                    config::node(config::NodeOptions {
                        method: options.method.clone(),
                        key: text,
                        users: Vec::new(),
                    })?
                    .0,
                )
            };
            rows.push(Credential {
                config: row_config,
                fingerprints: vec![config::fingerprint(&key)],
                key,
            });
        }
        let local = false;
        let mux = SingMuxInboundConfig::effective_with_padding(
            options.multiplex.as_ref(),
            options.mux_option_padding,
        );
        Ok(Self {
            config,
            crypto: Context::new_shared(ServerType::Server),
            credentials: input.credentials(rows)?,
            local,
            mux,
        })
    }
}
impl InboundProtocol for Ss2022Node {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, row)) in self.credentials.rows().enumerate() {
            for fingerprint in &row.fingerprints {
                manifest.authentication("ss2022", slot, *fingerprint);
            }
        }
        if self.config.user_manager().is_some() {
            manifest.protection("ss2022", config::fingerprint(self.config.key()));
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
            let mut configurations = Vec::new();
            for (_, row) in self.credentials.rows() {
                if !configurations
                    .iter()
                    .any(|config: &Arc<ServerConfig>| Arc::ptr_eq(config, &row.config))
                {
                    configurations.push(row.config.clone());
                }
            }
            let (key, stream, target) = if configurations.len() == 1 {
                let config = &configurations[0];
                let mut stream = ProxyServerStream::from_stream_with_user_manager(
                    self.crypto.clone(),
                    stream,
                    config.method(),
                    config.key(),
                    config.clone_user_manager(),
                );
                let addr = handshake
                    .run(async { stream.handshake().await.map_err(Error::from) })
                    .await?;
                let target = destination(&addr)?;
                let key = stream.user_key().unwrap_or(config.key()).to_vec();
                (key, Box::new(stream) as BoxStream, target)
            } else {
                let candidates = Candidates::new(stream);
                let mut tasks = JoinSet::new();
                for config in configurations {
                    let stream = candidates.reader();
                    let crypto = Context::new_shared(ServerType::Server);
                    let owner = context.tasks.clone();
                    let task = owner.spawn_tracked(async move {
                        let mut stream = ProxyServerStream::from_stream_with_user_manager(
                            crypto,
                            stream,
                            config.method(),
                            config.key(),
                            config.clone_user_manager(),
                        );
                        let target = destination(&stream.handshake().await?)?;
                        let key = stream.user_key().unwrap_or(config.key()).to_vec();
                        Ok::<_, Error>((key, Box::new(stream) as BoxStream, target))
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
                let nonce = candidates.prefix(self.config.method().salt_len())?;
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
            if kerlico_net::sing_mux::is_magic_target(&target) {
                let Some(mux) = &self.mux else {
                    return Err(Error::Rejected);
                };
                return kerlico_net::sing_mux::serve_inbound(stream, access, mux, &context).await;
            }
            let remote = access.connect_tcp(&target, &handshake).await?;
            kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
        })
    }
}
pub struct Ss2022NodeFactory;
impl NodeFactory for Ss2022NodeFactory {
    fn kind(&self) -> &'static str {
        "ss2022"
    }
    fn allows_local_inbound(&self) -> bool {
        false
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(Ss2022Node::from_context(input)?))
    }
}
