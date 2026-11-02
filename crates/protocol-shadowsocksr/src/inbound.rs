use crate::{config::Shared, credential_io::Candidates, destination, protocol::Role, stream};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use serde::Deserialize;
use serde_json::Value;
use shadowsocks::relay::socks5::Address;
use std::sync::Arc;
use tokio::{net::UdpSocket, sync::Semaphore, task::JoinSet};

pub(crate) struct Credential {
    pub group: usize,
    pub user: Option<u32>,
    pub fingerprints: Vec<[u8; 32]>,
}
pub struct ShadowsocksRNode {
    pub(crate) cfg: Arc<Shared>,
    pub(crate) groups: Vec<Arc<Shared>>,
    pub(crate) credentials: CredentialSet<Credential>,
    pub(crate) slots: Arc<Semaphore>,
}
impl ShadowsocksRNode {
    pub fn from_context(input: &NodeBuildContext) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Native {
            password: String,
            #[serde(default)]
            user: Option<crate::config::User>,
        }
        let mut groups = Vec::<Arc<Shared>>::new();
        let mut rows = Vec::new();
        let mut configurations = Vec::<Value>::new();
        if input.is_local() {
            let cfg = Shared::node(input.options())?;
            if cfg.authenticated() {
                return Err(Error::Config("已鉴权 SSR 必须配置成员".into()));
            }
            groups.push(cfg);
        } else {
            if input.options().get("password").is_some() || input.options().get("users").is_some() {
                return Err(Error::Config("SSR 原生凭据必须放在成员中".into()));
            }
            for value in input.native_credentials() {
                let native: Native = serde_json::from_value(value.clone())
                    .map_err(|_| Error::Config("SSR 成员凭据不合法".into()))?;
                let group = configurations.iter().position(|v| {
                    v.get("password").and_then(Value::as_str) == Some(native.password.as_str())
                });
                let group = if let Some(group) = group {
                    group
                } else {
                    let mut options = input.options().clone();
                    options["password"] = Value::String(native.password);
                    options["users"] = serde_json::json!([]);
                    configurations.push(options);
                    configurations.len() - 1
                };
                let user = native.user.as_ref().map(|user| user.id);
                if rows.iter().any(|row: &Credential| {
                    row.group == group && (row.user == user || row.user.is_none() || user.is_none())
                }) {
                    return Err(Error::Config("SSR 成员鉴别范围重复".into()));
                }
                if let Some(user) = native.user {
                    configurations[group]["users"]
                        .as_array_mut()
                        .ok_or(Error::Rejected)?
                        .push(serde_json::json!({"id":user.id,"password":user.password}));
                }
                let mut single = configurations[group].clone();
                if let Some(uid) = user {
                    single["users"]
                        .as_array_mut()
                        .ok_or(Error::Rejected)?
                        .retain(|user| user["id"] == uid);
                }
                let cfg = Shared::node(&single)?;
                if !cfg.authenticated() {
                    return Err(Error::Config("无鉴权 SSR 组合只允许本地接入".into()));
                }
                rows.push(Credential {
                    group,
                    user,
                    fingerprints: cfg.fingerprints(),
                });
            }
            if rows.is_empty() || rows.len() > 1024 {
                return Err(Error::Config("SSR 成员数量不合法".into()));
            }
            for options in configurations {
                groups.push(Shared::node(&options)?);
            }
        }
        let cfg = groups.first().cloned().ok_or(Error::Rejected)?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(cfg.limits.max_sessions)),
            cfg,
            groups,
            credentials: input.credentials(rows)?,
        })
    }
}
impl InboundProtocol for ShadowsocksRNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, row)) in self.credentials.rows().enumerate() {
            let group = &self.groups[row.group];
            if let Some(user) = row.user {
                for fingerprint in &row.fingerprints {
                    manifest.protection("shadowsocksr", *fingerprint);
                }
                let key = group.users.get(&user).expect("成员已校验");
                use sha2::{Digest, Sha256};
                manifest.authentication("shadowsocksr", slot, Sha256::digest(key).into());
            } else {
                for fingerprint in &row.fingerprints {
                    manifest.authentication("shadowsocksr", slot, *fingerprint);
                }
            }
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.credentials.is_empty()
    }
    fn requires_udp_association(&self) -> bool {
        self.cfg.udp
    }
    fn supports_udp(&self) -> bool {
        self.cfg.udp
    }
    fn handle<'a>(
        &'a self,
        raw: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.credentials.is_empty()
                && !context
                    .local_addr
                    .is_some_and(|address| address.ip().is_loopback())
            {
                return Err(Error::Unsupported(
                    "未鉴权 SSR 组合只能用作明确的回环本地接入",
                ));
            }
            let _permit = self
                .slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            let establish =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let candidates = Candidates::new(raw);
            let mut tasks = JoinSet::new();
            for (group, cfg) in self.groups.iter().enumerate() {
                let cfg = cfg.candidate();
                let raw = candidates.reader();
                let cancel = context.cancel.clone();
                let owner = context.tasks.clone();
                let task = owner.spawn_tracked(async move {
                    let mut plain = stream::Stream::new(
                        Box::new(raw),
                        cfg.clone(),
                        Role::Server,
                        cancel,
                        String::new(),
                        0,
                    )?;
                    let target = Address::read_from(&mut plain)
                        .await
                        .map_err(|_| crate::invalid())?;
                    let target = destination(&target)?;
                    let user = if cfg.authenticated() {
                        plain.authenticated_user()?
                    } else {
                        None
                    };
                    Ok::<_, Error>((group, user, plain, target, cfg))
                })?;
                tasks.spawn(async move {
                    task.await
                        .unwrap_or(Err(Error::Protocol("认证任务异常退出")))
                });
            }
            let selected = establish
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
            let (group, user, plain, target, cfg) = selected?;
            cfg.replay.commit()?;
            candidates.accept();
            let access = if self.credentials.is_empty() {
                ingress.local(&context)?
            } else {
                let slot = self
                    .credentials
                    .rows()
                    .find(|(_, row)| row.group == group && row.user == user)
                    .map(|(slot, _)| slot)
                    .ok_or(Error::Rejected)?;
                ingress
                    .authenticated(self.credentials.verified(&slot, ())?, &context)?
                    .0
            };
            let remote = access.connect_tcp(&target, &establish).await?;
            kerlico_core::relay_tcp(
                Box::new(plain),
                remote,
                context.idle_timeout,
                context.cancel,
            )
            .await
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve_udp(socket, ingress, context))
    }
}
pub struct ShadowsocksRNodeFactory;
impl NodeFactory for ShadowsocksRNodeFactory {
    fn kind(&self) -> &'static str {
        "shadowsocksr"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        Ok(Arc::new(ShadowsocksRNode::from_context(input)?))
    }
}
