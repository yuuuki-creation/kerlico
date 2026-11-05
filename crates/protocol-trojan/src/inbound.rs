use crate::{
    codec,
    config::{ServerSecurity, Transport, TransportInput, server_tls},
    invalid, key,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use kerlico_net::fallback::{
    FallbackDestInput, FallbackRule, FallbackRuleInput, RecordingStream, compile_trojan_fallbacks,
    try_fallback,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
pub struct TrojanNodeFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    security: ServerSecurity,
    #[serde(default)]
    transport: TransportInput,
    #[serde(default, alias = "fallback_server", alias = "fallback-server")]
    fallback: Option<FallbackDestInput>,
    #[serde(default, alias = "fallback-server-port")]
    fallback_server_port: Option<u16>,
    #[serde(default, alias = "fallback-for-alpn")]
    fallback_for_alpn: BTreeMap<String, FallbackDestInput>,
    #[serde(default)]
    fallbacks: Vec<FallbackRuleInput>,
    #[serde(default)]
    multiplex: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
    #[serde(default, alias = "mux-option-padding")]
    mux_option_padding: Option<bool>,
}
pub(crate) struct Payload {
    pub users: CredentialSet<[u8; 56]>,
    pub fallbacks: Vec<FallbackRule>,
    pub mux: Option<kerlico_net::sing_mux::SingMuxInboundConfig>,
}
struct TrojanNode {
    payload: Arc<Payload>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    transport: Transport,
}
impl NodeFactory for TrojanNodeFactory {
    fn kind(&self) -> &'static str {
        "trojan"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Credential {
            password: String,
        }
        let credentials = input
            .native_credentials()
            .iter()
            .map(|value| serde_json::from_value::<Credential>(value.clone()).map_err(|_| invalid()))
            .collect::<Result<Vec<_>>>()?;
        if credentials.is_empty() || credentials.len() > 256 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for credential in credentials {
            let value = key(&credential.password)?;
            if !seen.insert(value) {
                return Err(invalid());
            }
            users.push(value);
        }
        let fallbacks = compile_trojan_fallbacks(
            options.fallback,
            options.fallback_server_port,
            options.fallback_for_alpn,
            options.fallbacks,
        )?;
        let fallback_alpns: Vec<String> = fallbacks.iter().filter_map(|r| r.alpn.clone()).collect();
        let transport = options.transport.normalize()?;
        let tls = server_tls(options.security, &transport, &fallback_alpns)?;
        let mux = kerlico_net::sing_mux::SingMuxInboundConfig::effective_with_padding(
            options.multiplex.as_ref(),
            options.mux_option_padding,
        );
        Ok(Arc::new(TrojanNode {
            payload: Arc::new(Payload {
                users: input.credentials(users)?,
                fallbacks,
                mux,
            }),
            tls,
            transport,
        }))
    }
}
impl InboundProtocol for TrojanNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, key)) in self.payload.users.rows().enumerate() {
            let mut hash = Sha256::new();
            hash.update(b"kerlico/trojan/node-password/");
            hash.update(key);
            manifest.authentication("trojan", slot, hash.finalize().into());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.tls.is_none()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let connect =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let (stream, sni, alpn): (BoxStream, Option<String>, Option<String>) = connect
                .run(async {
                    match &self.tls {
                        Some(tls) => {
                            let tls_stream = tls.accept(stream).await?;
                            let (_, conn) = tls_stream.get_ref();
                            let sni = conn.server_name().map(str::to_owned);
                            let alpn = conn
                                .alpn_protocol()
                                .and_then(|b| std::str::from_utf8(b).ok())
                                .map(str::to_owned);
                            Ok((
                                Box::new(crate::io::ServerTls(tls_stream)) as BoxStream,
                                sni,
                                alpn,
                            ))
                        }
                        None => Ok((stream, None, None)),
                    }
                })
                .await?;
            let (stream, activity) = crate::io::observe(stream);
            if self.transport.raw() {
                crate::io::bounded(
                    self.payload.serve_with_meta(
                        stream,
                        access,
                        context.clone(),
                        sni.as_deref(),
                        alpn.as_deref(),
                    ),
                    activity,
                    context.idle_timeout,
                    context.cancel.clone(),
                )
                .await
            } else {
                crate::io::bounded(
                    crate::http_server::serve(
                        stream,
                        self.transport.clone(),
                        self.payload.clone(),
                        access,
                        context.clone(),
                    ),
                    activity,
                    context.idle_timeout,
                    context.cancel.clone(),
                )
                .await
            }
        })
    }
}
impl Payload {
    pub async fn serve(
        &self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        self.serve_with_meta(stream, access, context, None, None)
            .await
    }
    pub async fn serve_with_meta(
        &self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
        sni: Option<&str>,
        alpn: Option<&str>,
    ) -> Result<()> {
        let connect =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let (stream, (slot, target, udp)) = if self.fallbacks.is_empty() {
            let mut stream = stream;
            let parsed = connect
                .run(codec::request(&mut stream, &self.users))
                .await?;
            (stream, parsed)
        } else {
            let mut recorder = RecordingStream::new(stream, 4096);
            let handshake = connect
                .run(codec::request(&mut recorder, &self.users))
                .await;
            let (stream, recorded) = recorder.into_parts();
            match handshake {
                Ok(parsed) => (stream, parsed),
                Err(err) => {
                    if let Some(res) =
                        try_fallback(stream, recorded, &self.fallbacks, sni, alpn, &context).await
                    {
                        return res;
                    }
                    return Err(err);
                }
            }
        };
        let (access, (target, udp)) =
            access.authenticated(self.users.verified(&slot, (target, udp))?, &context)?;
        if udp {
            return crate::udp::serve(stream, access, context).await;
        }
        if kerlico_net::sing_mux::is_magic_target(&target) {
            let Some(mux_cfg) = &self.mux else {
                return Err(kerlico_core::Error::Rejected);
            };
            return kerlico_net::sing_mux::serve_inbound(stream, access, mux_cfg, &context).await;
        }
        let remote = access.connect_tcp(&target, &connect).await?;
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }
}
