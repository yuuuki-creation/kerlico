use crate::{
    codec,
    padding::{self, Padding},
    session::{Incoming, Session},
    uot,
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    Result,
};
use serde::Deserialize;
use serde_json::Value;
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
    passwords: Vec<String>,
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
    passwords: Vec<[u8; 32]>,
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
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options = serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        if options.passwords.is_empty() || options.passwords.len() > 256 {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut passwords = Vec::new();
        for password in options.passwords {
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
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| invalid())?;
        tls.send_tls13_tickets = 0;
        Ok(Arc::new(AnyTlsNode {
            passwords,
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
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.passwords
            .iter()
            .map(|password| {
                let mut digest = Sha256::new();
                digest.update(b"kerlico/anytls/node-password/");
                digest.update(password);
                digest.finalize().into()
            })
            .collect()
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let connection = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            };
            let stream = connection
                .run(async {
                    let mut stream = self.tls.accept(stream).await?;
                    let mut password = [0; 32];
                    stream.read_exact(&mut password).await?;
                    let mut valid = subtle::Choice::from(0);
                    for expected in &self.passwords {
                        valid |= password.ct_eq(expected);
                    }
                    if !bool::from(valid) {
                        return Err(Error::Rejected);
                    }
                    let padding = stream.read_u16().await? as usize;
                    let mut bytes = vec![0; padding];
                    stream.read_exact(&mut bytes).await?;
                    Ok(Box::new(stream) as BoxStream)
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
            )
            .await?;
            let mut workers = JoinSet::new();
            let mut first = true;
            let result = loop {
                tokio::select! {
                    biased;
                    _ = context.cancel.cancelled()=>break Err(Error::Cancelled),
                    _ = session.closed.cancelled()=>break Ok(()),
                    next=rx.recv()=>{
                        let Some(incoming)=next else {break Ok(())};
                        if context.stream_budget.is_closed(){drop(incoming);continue}
                        let lease=if first {first=false;None}else {match context.stream_budget.try_acquire(){Ok(lease)=>Some(lease),Err(_)=>{drop(incoming);continue}}};
                        let access=access.clone();let context=context.clone();let session=session.clone();
                        workers.spawn(async move {let _lease=lease;let _=serve_stream(incoming,access,context,session).await;});
                    },
                    _ = workers.join_next(),if !workers.is_empty()=>{},
                }
            };
            session.close();
            workers.abort_all();
            while workers.join_next().await.is_some() {}
            result
        })
    }
}
async fn serve_stream(
    mut incoming: Incoming,
    access: Arc<dyn AccessService>,
    context: InboundContext,
    session: Arc<Session>,
) -> Result<()> {
    let connection = ConnectContext {
        cancel: context.cancel.clone(),
        timeout: context.connect_timeout,
    };
    let target = connection
        .run(codec::read_address(&mut incoming.stream, false))
        .await?;
    if target.0 == codec::UOT && target.1 == 0 {
        session
            .send(codec::Frame::new(codec::SYNACK, incoming.id, Vec::new()))
            .await?;
        return uot::serve(incoming.stream, access, context).await;
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
    session
        .send(codec::Frame::new(codec::SYNACK, incoming.id, Vec::new()))
        .await?;
    kerlico_core::relay_tcp(
        incoming.stream,
        remote,
        context.idle_timeout,
        context.cancel,
    )
    .await
}
