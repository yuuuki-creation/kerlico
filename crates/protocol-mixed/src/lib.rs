//! 同一端口接受 HTTP 代理与 SOCKS 4/4a/5，按首字节分流；协议处理全部复用 HTTP 与 SOCKS 模块。
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, Error, InboundContext,
    InboundProtocol, IngressBinding, Result,
};
use serde::Deserialize;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;

fn enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    tls: Option<kerlico_http::ServerTls>,
    #[serde(default = "enabled")]
    udp: bool,
}

struct MixedNode {
    http: Arc<dyn InboundProtocol>,
    socks: kerlico_socks::MixedHandlers,
    tls: Option<TlsAcceptor>,
}

impl InboundProtocol for MixedNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = self.http.credential_manifest();
        manifest.extend(self.socks.five.credential_manifest());
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.socks.five.requires_loopback()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let budget =
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
            let (first, stream) = budget
                .run(async {
                    let mut stream = match &self.tls {
                        Some(tls) => Box::new(tls.accept(stream).await?) as BoxStream,
                        None => stream,
                    };
                    let first = stream.read_u8().await?;
                    Ok((
                        first,
                        Box::new(Replayed {
                            first: Some(first),
                            inner: stream,
                        }) as BoxStream,
                    ))
                })
                .await?;
            let handler = match first {
                4 => &self.socks.four,
                5 => &self.socks.five,
                _ => &self.http,
            };
            handler.handle(stream, ingress, context).await
        })
    }
}

/// 把分流时读走的首字节放回流头。
struct Replayed {
    first: Option<u8>,
    inner: BoxStream,
}
impl AsyncRead for Replayed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() > 0
            && let Some(first) = this.first.take()
        {
            buffer.put_slice(&[first]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Replayed {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct MixedNodeFactory;
impl NodeFactory for MixedNodeFactory {
    fn kind(&self) -> &'static str {
        "mixed"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("Mixed 节点字段不合法".into()))?;
        let empty = input.with_options(serde_json::json!({}));
        Ok(Arc::new(MixedNode {
            http: kerlico_http::HttpNodeFactory.build(&empty)?,
            socks: kerlico_socks::mixed_handlers(input, options.udp)?,
            tls: options.tls.map(kerlico_http::server_tls).transpose()?,
        }))
    }
}
