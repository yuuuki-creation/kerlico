//! 透明代理入站（`redirect` NAT 重定向与 `tproxy` 透明拦截）。

use kerlico_config::{NodeBuildContext, NodeFactory, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, DatagramReceiver, DatagramSender,
    Destination, Error, FlowFailure, FlowOutcome, InboundContext, InboundProtocol, IngressBinding,
    NodeEvent, Result,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TransparentOptions {
    #[serde(alias = "fallback-target")]
    pub target: Option<TargetSpec>,
    #[serde(default)]
    pub network: Option<String>,
}

fn resolve_target(
    fallback: Option<&Destination>,
    original: Option<SocketAddr>,
    local: Option<SocketAddr>,
) -> Result<Destination> {
    if let Some(orig) = original
        && (Some(orig) != local || fallback.is_none())
    {
        return Destination::new(&orig.ip().to_string(), orig.port());
    }
    fallback.cloned().ok_or(Error::InvalidAddress)
}

struct RedirectNode {
    fallback: Option<Destination>,
}

impl InboundProtocol for RedirectNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }

    fn requires_loopback(&self) -> bool {
        false
    }

    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let access = ingress.local(&context)?;
            let target = resolve_target(
                self.fallback.as_ref(),
                context.original_dst(),
                context.local_addr,
            )?;
            let budget =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let remote = budget.run(access.connect_tcp(&target, &budget)).await?;
            kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
        })
    }
}

pub struct RedirectNodeFactory;

impl NodeFactory for RedirectNodeFactory {
    fn kind(&self) -> &'static str {
        "redirect"
    }

    fn allows_local_inbound(&self) -> bool {
        true
    }

    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        if !input.native_credentials().is_empty() {
            return Err(Error::Config("redirect 入站不支持用户认证凭据".into()));
        }
        let options: TransparentOptions = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("redirect 节点配置不合法".into()))?;
        if let Some(net) = &options.network
            && !net.eq_ignore_ascii_case("tcp")
        {
            return Err(Error::Config("redirect 入站仅支持 TCP".into()));
        }
        let fallback = options
            .target
            .as_ref()
            .map(TargetSpec::destination)
            .transpose()?;
        Ok(Arc::new(RedirectNode { fallback }))
    }
}

struct TproxyNode {
    fallback: Option<Destination>,
    tcp: bool,
    udp: bool,
}

impl InboundProtocol for TproxyNode {
    fn credential_manifest(&self) -> CredentialManifest {
        CredentialManifest::new()
    }

    fn requires_loopback(&self) -> bool {
        false
    }

    fn supports_tcp(&self) -> bool {
        self.tcp
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn transparent(&self) -> bool {
        true
    }

    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let access = ingress.local(&context)?;
            let target = resolve_target(
                self.fallback.as_ref(),
                context.original_dst(),
                context.local_addr,
            )?;
            let budget =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let remote = budget.run(access.connect_tcp(&target, &budget)).await?;
            kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
        })
    }

    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let access = ingress.local(&context)?;
            let local_addr = socket.local_addr().ok();
            let mut buffer = vec![0u8; context.max_datagram_size.max(2048)];
            loop {
                let (len, peer) = tokio::select! {
                    biased;
                    _ = context.cancel.cancelled() => return Ok(()),
                    res = socket.recv_from(&mut buffer) => match res {
                        Ok(v) => v,
                        Err(e) if kerlico_core::is_peer_path_error(&e) => {
                            context.events.record(NodeEvent::Dropped);
                            continue;
                        }
                        Err(e) => return Err(Error::Io(e)),
                    }
                };
                let target = match resolve_target(self.fallback.as_ref(), local_addr, local_addr) {
                    Ok(t) => t,
                    Err(_) => {
                        context.events.record(NodeEvent::Dropped);
                        continue;
                    }
                };
                let payload = buffer[..len].to_vec();
                let budget = ConnectContext::new(context.connect_timeout)
                    .with_cancel(context.cancel.clone())
                    .with_udp_source(peer);
                let Ok(channel) = budget.run(access.connect_udp(&target, &budget)).await else {
                    context.events.record(NodeEvent::Failed);
                    continue;
                };
                let (mut sender, mut receiver, completion) = channel.into_parts();
                if let Err(err) = sender.send(&payload).await {
                    completion.finish(FlowOutcome::Failed(FlowFailure::from_error(&err)));
                    context.events.record(NodeEvent::Failed);
                    continue;
                }
                if let Ok(Ok(Some(reply))) =
                    tokio::time::timeout(context.connect_timeout, receiver.recv()).await
                {
                    let _ = socket.send_to(&reply, peer).await;
                }
                completion.finish(FlowOutcome::ProtocolEnd);
                context.events.record(NodeEvent::Completed);
            }
        })
    }
}

pub struct TproxyNodeFactory;

impl NodeFactory for TproxyNodeFactory {
    fn kind(&self) -> &'static str {
        "tproxy"
    }

    fn allows_local_inbound(&self) -> bool {
        true
    }

    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        if !input.native_credentials().is_empty() {
            return Err(Error::Config("tproxy 入站不支持用户认证凭据".into()));
        }
        let options: TransparentOptions = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("tproxy 节点配置不合法".into()))?;
        let (tcp, udp) = match options.network.as_deref() {
            None | Some("tcp,udp") | Some("both") => (true, true),
            Some("tcp") => (true, false),
            Some("udp") => (false, true),
            Some(_) => return Err(Error::Config("tproxy network 字段不合法".into())),
        };
        let fallback = options
            .target
            .as_ref()
            .map(TargetSpec::destination)
            .transpose()?;
        Ok(Arc::new(TproxyNode { fallback, tcp, udp }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redirect_and_tproxy_factories_validate_options() {
        let redirect = RedirectNodeFactory
            .build(&NodeBuildContext::local_for_test(json!({
                "target": { "host": "127.0.0.1", "port": 8080 }
            })))
            .unwrap();
        assert!(redirect.supports_tcp());
        assert!(!redirect.supports_udp());
        assert!(!redirect.transparent());

        assert!(
            RedirectNodeFactory
                .build(&NodeBuildContext::local_for_test(json!({
                    "network": "udp"
                })))
                .is_err()
        );

        let tproxy = TproxyNodeFactory
            .build(&NodeBuildContext::local_for_test(json!({
                "network": "tcp,udp"
            })))
            .unwrap();
        assert!(tproxy.supports_tcp());
        assert!(tproxy.supports_udp());
        assert!(tproxy.transparent());
    }
}
