//! 共享 TCP/TLS 连接器与基础直连/拒绝处理器。

use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, Error, Outbound, Result,
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use serde_json::Value;
use std::{io::Cursor, sync::Arc};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;

#[derive(Clone)]
pub struct TcpConnector {
    tls: Option<(TlsConnector, ServerName<'static>)>,
}

impl TcpConnector {
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }
    pub fn plain() -> Self {
        Self { tls: None }
    }
    /// ca_pem 是内存中的 PEM；为空时仅信任内置公共根证书。
    pub fn tls(server_name: &str, ca_pem: Option<&str>) -> Result<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = ca_pem {
            let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
                .collect::<std::io::Result<Vec<_>>>()?;
            if certs.is_empty() {
                return Err(Error::Config("CA PEM 不包含证书".into()));
            }
            for cert in certs {
                roots
                    .add(cert)
                    .map_err(|_| Error::Config("CA 证书不合法".into()))?;
            }
        }
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Config("TLS 版本不可用".into()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| Error::Config("TLS 服务端名称不合法".into()))?;
        Ok(Self {
            tls: Some((TlsConnector::from(Arc::new(config)), name)),
        })
    }
    pub async fn connect(&self, server: &Destination) -> Result<BoxStream> {
        let tcp = TcpStream::connect((server.host().as_str(), server.port())).await?;
        tcp.set_nodelay(true)?;
        match &self.tls {
            Some((connector, name)) => Ok(Box::new(connector.connect(name.clone(), tcp).await?)),
            None => Ok(Box::new(tcp)),
        }
    }
}

struct Direct;
struct DirectDatagram(Arc<UdpSocket>);

impl DatagramSender for DirectDatagram {
    fn send<'a>(&'a mut self, packet: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0.send(packet).await?;
            Ok(())
        })
    }
}

impl DatagramReceiver for DirectDatagram {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut bytes = vec![0; 65_535];
            let count = self.0.recv(&mut bytes).await?;
            bytes.truncate(count);
            Ok(Some(bytes))
        })
    }
}

impl Outbound for Direct {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move { context.run(TcpConnector::plain().connect(target)).await })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let peer = tokio::net::lookup_host((target.host().as_str(), target.port()))
                        .await?
                        .next()
                        .ok_or(Error::InvalidAddress)?;
                    let socket = UdpSocket::bind(if peer.is_ipv6() {
                        "[::]:0"
                    } else {
                        "0.0.0.0:0"
                    })
                    .await?;
                    socket.connect(peer).await?;
                    let socket = Arc::new(socket);
                    Ok(DatagramChannel {
                        sender: Box::new(DirectDatagram(socket.clone())),
                        receiver: Box::new(DirectDatagram(socket)),
                    })
                })
                .await
        })
    }
}

struct Reject;
impl Outbound for Reject {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: false,
            udp: true,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async { Err(Error::Rejected) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Rejected) })
    }
}

pub struct DirectFactory;
pub struct RejectFactory;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyOptions {}

fn empty(options: &Value) -> Result<()> {
    serde_json::from_value::<EmptyOptions>(options.clone())
        .map_err(|_| Error::Config("基础处理器不接受额外选项".into()))?;
    Ok(())
}

impl OutboundFactory for DirectFactory {
    fn kind(&self) -> &'static str {
        "direct"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        empty(options)?;
        Ok(Arc::new(Direct))
    }
}
impl OutboundFactory for RejectFactory {
    fn kind(&self) -> &'static str {
        "reject"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        empty(options)?;
        Ok(Arc::new(Reject))
    }
}
