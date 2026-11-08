//! 服务端身份隔离、预算和统一目标访问。
use crate::{
    carrier::{self, ServerSecurity, Transport},
    codec::{self, Account, Replay},
    crypto::MAX_DATAGRAM,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_core::{DatagramReceiver, DatagramSender};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    security: ServerSecurity,
    #[serde(default)]
    transport: Transport,
    #[serde(default)]
    multiplex: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
    #[serde(default, alias = "mux-option-padding")]
    mux_option_padding: Option<bool>,
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
    accounts: CredentialSet<Account>,
    replay: Replay,
    mux: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
}
fn invalid() -> Error {
    Error::Config("VMess 节点配置不合法".into())
}
impl NodeFactory for VmessNodeFactory {
    fn kind(&self) -> &'static str {
        "vmess"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;
        let credentials = input
            .native_credentials()
            .iter()
            .map(|value| serde_json::from_value::<User>(value.clone()).map_err(|_| invalid()))
            .collect::<Result<Vec<_>>>()?;
        if credentials.is_empty() || credentials.len() > 256 {
            return Err(invalid());
        }
        options.transport.validate()?;
        let mut seen = BTreeSet::new();
        let mut accounts = Vec::new();
        for user in credentials {
            let id = *uuid::Uuid::parse_str(&user.uuid)
                .map_err(|_| invalid())?
                .as_bytes();
            if !seen.insert(id) {
                return Err(invalid());
            }
            accounts.push(Account::new(id));
        }
        let mux = kerlico_net::sing_mux::SingMuxInboundConfig::effective_with_padding(
            options.multiplex.as_ref(),
            options.mux_option_padding,
        );
        let tls = carrier::server_tls(options.security, &options.transport)?;
        Ok(Arc::new(Node {
            payload: Arc::new(Payload {
                accounts: input.credentials(accounts)?,
                replay: Replay::new(),
                mux,
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
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, account)) in self.payload.accounts.rows().enumerate() {
            manifest.authentication("vmess", slot, Sha256::digest(account.id).into());
        }
        manifest
    }
    fn handle<'a>(
        &'a self,
        mut inner: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(tls) = &self.tls {
                inner = ConnectContext::new(context.connect_timeout)
                    .with_cancel(context.cancel.clone())
                    .run(async {
                        let mut tls_stream = tls.accept(inner).await?;
                        tls_stream.get_mut().1.set_buffer_limit(Some(68 * 1024));
                        Ok(Box::new(ServerTls(tls_stream)) as BoxStream)
                    })
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
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let session = connect
            .run(async {
                codec::accept_verified(inner, &self.accounts, &self.replay)
                    .await
                    .map_err(Error::Io)
            })
            .await?;
        let (access, session) = access.authenticated(session, &context)?;
        if !session.udp {
            if kerlico_net::sing_mux::is_magic_target(&session.target) {
                let Some(mux_cfg) = &self.mux else {
                    return Err(Error::Rejected);
                };
                return kerlico_net::sing_mux::serve_inbound(
                    Box::new(session.stream),
                    access,
                    mux_cfg,
                    &context,
                )
                .await;
            }
            let target = access.connect_tcp(&session.target, &connect).await?;
            return kerlico_core::relay_tcp(
                Box::new(session.stream),
                target,
                context.idle_timeout,
                context.cancel,
            )
            .await;
        }
        let remote = access.connect_udp(&session.target, &connect).await?;
        let (mut sender, mut receiver, completion) = remote.into_parts();
        let result = async {
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
                sender.send(&bytes[..n]).await?;
                activity.send_replace(tokio::time::Instant::now());
            }
        };
        let down = async {
            loop {
                let Some(bytes) = receiver.recv().await? else {
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
        }.await;
        completion.finish(match &result {
            Ok(()) => kerlico_core::FlowOutcome::ProtocolEnd,
            Err(error) => {
                kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::from_error(error))
            }
        });
        result
    }
}
struct ServerTls(tokio_rustls::server::TlsStream<BoxStream>);
impl tokio::io::AsyncRead for ServerTls {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let poll = std::pin::Pin::new(&mut this.0).poll_read(cx, out);
        if matches!(poll, std::task::Poll::Ready(Ok(()))) && out.filled().len() > before {
            while out.remaining() >= 16384 {
                let prev = out.filled().len();
                match std::pin::Pin::new(&mut this.0).poll_read(cx, out) {
                    std::task::Poll::Ready(Ok(())) if out.filled().len() > prev => {}
                    _ => break,
                }
            }
        }
        poll
    }
}
impl tokio::io::AsyncWrite for ServerTls {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return std::pin::Pin::new(&mut this.0).poll_write(cx, bytes);
        }
        let limit = bytes.len().min(65536);
        let mut total = 0;
        while total < limit {
            match std::pin::Pin::new(&mut this.0).poll_write(cx, &bytes[total..limit]) {
                std::task::Poll::Ready(Ok(0)) => break,
                std::task::Poll::Ready(Ok(n)) => total += n,
                std::task::Poll::Ready(Err(_)) if total > 0 => {
                    return std::task::Poll::Ready(Ok(total));
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending if total > 0 => {
                    return std::task::Poll::Ready(Ok(total));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        std::task::Poll::Ready(Ok(total))
    }
    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
