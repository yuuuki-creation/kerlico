//! 服务端身份隔离、预算和统一目标访问。
use crate::{
    carrier::{self, ServerSecurity, Transport},
    codec::{self, Account, Replay},
    crypto::MAX_DATAGRAM,
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    Result,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    security: ServerSecurity,
    #[serde(default)]
    transport: Transport,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    uuid: String,
}
pub struct VmessNodeFactory;
struct Node {
    payload: Arc<Payload>,
    transport: Transport,
    tls: Option<tokio_rustls::TlsAcceptor>,
}
pub(crate) struct Payload {
    accounts: Vec<Account>,
    replay: Replay,
}
fn invalid() -> Error {
    Error::Config("VMess 节点配置不合法".into())
}
impl NodeFactory for VmessNodeFactory {
    fn kind(&self) -> &'static str {
        "vmess"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let mut options: Options = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
        if let Some(uuid) = options.uuid {
            if !options.users.is_empty() {
                return Err(invalid());
            }
            options.users.push(User { uuid });
        }
        if options.users.is_empty() || options.users.len() > 256 {
            return Err(invalid());
        }
        options.transport.validate()?;
        let mut seen = BTreeSet::new();
        let mut accounts = Vec::new();
        for user in options.users {
            let id = *uuid::Uuid::parse_str(&user.uuid)
                .map_err(|_| invalid())?
                .as_bytes();
            if !seen.insert(id) {
                return Err(invalid());
            }
            accounts.push(Account::new(id));
        }
        let tls = carrier::server_tls(options.security, &options.transport)?;
        Ok(Arc::new(Node {
            payload: Arc::new(Payload {
                accounts,
                replay: Replay::new(),
            }),
            transport: options.transport,
            tls,
        }))
    }
}
impl InboundProtocol for Node {
    fn requires_loopback(&self) -> bool {
        false
    }
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.payload
            .accounts
            .iter()
            .map(|a| Sha256::digest(a.id).into())
            .collect()
    }
    fn handle<'a>(
        &'a self,
        mut inner: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(tls) = &self.tls {
                inner = ConnectContext {
                    cancel: context.cancel.clone(),
                    timeout: context.connect_timeout,
                }
                .run(async { Ok(Box::new(tls.accept(inner).await?) as BoxStream) })
                .await?;
            }
            if self.transport.raw() {
                self.payload.serve(inner, access, context).await
            } else {
                crate::http::serve(
                    inner,
                    self.transport.clone(),
                    self.payload.clone(),
                    access,
                    context,
                )
                .await
            }
        })
    }
}
impl Payload {
    pub async fn serve(
        &self,
        inner: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let connect = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let session = connect
            .run(async {
                codec::accept(inner, &self.accounts, &self.replay)
                    .await
                    .map_err(Error::Io)
            })
            .await?;
        if !session.udp {
            let target = access.connect_tcp(&session.target, &connect).await?;
            return kerlico_core::relay_tcp(
                Box::new(session.stream),
                target,
                context.idle_timeout,
                context.cancel,
            )
            .await;
        }
        let mut remote = access.connect_udp(&session.target, &connect).await?;
        let (mut reader, mut writer) = tokio::io::split(session.stream);
        let (activity, mut changed) = tokio::sync::watch::channel(tokio::time::Instant::now());
        let up = async {
            let mut bytes = vec![0; 65535];
            loop {
                let n = reader.read(&mut bytes).await?;
                if n == 0 {
                    return Ok::<_, Error>(());
                }
                if n > context.max_datagram_size || n > MAX_DATAGRAM {
                    return Err(Error::ResourceLimit);
                }
                remote.sender.send(&bytes[..n]).await?;
                activity.send_replace(tokio::time::Instant::now());
            }
        };
        let down = async {
            loop {
                let Some(bytes) = remote.receiver.recv().await? else {
                    return Ok::<_, Error>(());
                };
                if bytes.is_empty()
                    || bytes.len() > context.max_datagram_size
                    || bytes.len() > MAX_DATAGRAM
                {
                    return Err(Error::ResourceLimit);
                }
                writer.write_all(&bytes).await?;
                writer.flush().await?;
                activity.send_replace(tokio::time::Instant::now());
            }
        };
        tokio::pin!(up, down);
        let timer = tokio::time::sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=&mut up=>return result,result=&mut down=>return result,_=&mut timer=>return Err(Error::Timeout),result=changed.changed()=>{if result.is_ok(){timer.as_mut().reset(*changed.borrow_and_update()+context.idle_timeout);}}}
        }
    }
}
