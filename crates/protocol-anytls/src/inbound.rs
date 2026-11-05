use crate::{
    codec,
    padding::{self, Padding},
    session::{Incoming, Session},
    uot,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, PeerSession, Result,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Cursor,
    sync::{Arc, RwLock},
};
use subtle::ConstantTimeEq;
use tokio::{io::AsyncReadExt, sync::mpsc, task::JoinSet};
use tokio_rustls::TlsAcceptor;
pub struct AnyTlsNodeFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    tls: Tls,
    #[serde(default)]
    padding_scheme: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    #[serde(default)]
    certificate_pem: Option<String>,
    #[serde(default)]
    private_key_pem: Option<String>,
    #[serde(default)]
    certificate_file: Option<String>,
    #[serde(default)]
    private_key_file: Option<String>,
}
struct AnyTlsNode {
    passwords: CredentialSet<[u8; 32]>,
    tls: TlsAcceptor,
    padding: Arc<RwLock<Padding>>,
}
fn invalid() -> Error {
    Error::Config("AnyTLS 节点配置不合法".into())
}
fn pem(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(value), None) if value.len() <= 1024 * 1024 => Ok(value),
        (None, Some(path)) => {
            if std::fs::metadata(&path).map_err(|_| invalid())?.len() > 1024 * 1024 {
                return Err(invalid());
            }
            std::fs::read_to_string(path).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
impl NodeFactory for AnyTlsNodeFactory {
    fn kind(&self) -> &'static str {
        "anytls"
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
        let mut passwords = Vec::new();
        for credential in credentials {
            let password = credential.password;
            if password.is_empty() || password.len() > 4096 {
                return Err(invalid());
            }
            let digest: [u8; 32] = Sha256::digest(password.as_bytes()).into();
            if !seen.insert(digest) {
                return Err(invalid());
            }
            passwords.push(digest);
        }
        let cert = pem(options.tls.certificate_pem, options.tls.certificate_file)?;
        let key = pem(options.tls.private_key_pem, options.tls.private_key_file)?;
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| invalid())?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(key))
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| invalid())?;
        tls.send_tls13_tickets = 0;
        Ok(Arc::new(AnyTlsNode {
            passwords: input.credentials(passwords)?,
            tls: TlsAcceptor::from(Arc::new(tls)),
            padding: Arc::new(RwLock::new(Padding::parse(
                options
                    .padding_scheme
                    .as_deref()
                    .unwrap_or(padding::DEFAULT),
            )?)),
        }))
    }
}
impl InboundProtocol for AnyTlsNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, password)) in self.passwords.rows().enumerate() {
            let mut digest = Sha256::new();
            digest.update(b"kerlico/anytls/node-password/");
            digest.update(password);
            manifest.authentication("anytls", slot, digest.finalize().into());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let connection =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let (stream, access) = connection
                .run(async {
                    let mut stream = self.tls.accept(stream).await?;
                    stream.get_mut().1.set_buffer_limit(Some(68 * 1024));
                    let mut password = [0; 32];
                    stream.read_exact(&mut password).await?;
                    let verified = self.passwords.verify(&password, |expected, password| {
                        Ok(bool::from(password.ct_eq(expected)).then_some(()))
                    })?;
                    let (access, ()) = access.authenticated(verified, &context)?;
                    let padding = stream.read_u16().await? as usize;
                    let mut bytes = vec![0; padding];
                    stream.read_exact(&mut bytes).await?;
                    Ok((Box::new(ServerTls(stream)) as BoxStream, access))
                })
                .await?;
            let (tx, mut rx) = mpsc::channel::<Incoming>(context.max_streams.clamp(1, 64));
            let session = Session::start(
                stream,
                false,
                self.padding.clone(),
                context.max_streams,
                context.idle_timeout,
                Some(tx),
                crate::session::Owner::Node(context.tasks.clone()),
            )
            .await?;
            let mut workers = JoinSet::new();
            let mut first = true;
            let result = loop {
                tokio::select! {
                    biased;
                    _ = context.cancel.cancelled()=>break Err(Error::Cancelled),
                    _ = session.closed.cancelled()=>break crate::flow::result(session.finish_reason()),
                    next=rx.recv()=>{
                        let Some(incoming)=next else {break Ok(())};
                        if context.stream_budget.is_closed(){drop(incoming);continue}
                        let lease=if first {first=false;None}else {match context.stream_budget.try_acquire(){Ok(lease)=>Some(lease),Err(_)=>{drop(incoming);continue}}};
                        let access=access.clone();let context=context.clone();let session=session.clone();
                        let owner=context.tasks.clone();
                    let task=owner.spawn_tracked(async move {let _lease=lease;let _=serve_stream(incoming,access,context,session).await;})?;
                    workers.spawn(async move {let _=task.await;});
                    },
                    _ = workers.join_next(),if !workers.is_empty()=>{},
                }
            };
            session.close_with(if result.is_err() {
                crate::flow::reason(&result)
            } else {
                session.finish_reason()
            });
            if tokio::time::timeout(context.drain_timeout, async {
                while workers.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                workers.abort_all();
            }
            while workers.join_next().await.is_some() {}
            session.shutdown().await;
            result
        })
    }
}
async fn serve_stream(
    mut incoming: Incoming,
    access: PeerSession,
    context: InboundContext,
    session: Arc<Session>,
) -> Result<()> {
    let ending = incoming.ending.clone();
    let connection =
        ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let target = connection
        .run(codec::read_address(&mut incoming.stream, false))
        .await?;
    if target.0 == codec::UOT && target.1 == 0 {
        session
            .send(codec::Frame::new(codec::SYNACK, incoming.id, Vec::new()))
            .await?;
        return uot::serve(incoming.stream, access, context, ending).await;
    }
    let target = kerlico_core::Destination::new(&target.0, target.1)?;
    let remote = match access.connect_tcp(&target, &connection).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = session
                .send(codec::Frame::new(
                    codec::SYNACK,
                    incoming.id,
                    "目标连接失败".as_bytes().to_vec(),
                ))
                .await;
            return Err(error);
        }
    };
    if let Err(error) = connection
        .run(session.send(codec::Frame::new(codec::SYNACK, incoming.id, Vec::new())))
        .await
    {
        remote.finish(
            (*ending.borrow()).unwrap_or(kerlico_core::FlowOutcome::Failed(
                kerlico_core::FlowFailure::from_error(&error),
            )),
        );
        return Err(error);
    }
    crate::flow::relay(
        incoming.stream,
        remote,
        context.idle_timeout,
        context.cancel,
        ending,
    )
    .await
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
        let mut total = 0;
        let limit = bytes.len().min(65536);
        while total < limit {
            match std::pin::Pin::new(&mut this.0).poll_write(cx, &bytes[total..limit]) {
                std::task::Poll::Ready(Ok(0)) => break,
                std::task::Poll::Ready(Ok(n)) => total += n,
                std::task::Poll::Pending if total > 0 => break,
                other => return other,
            }
        }
        std::task::Poll::Ready(Ok(total))
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
