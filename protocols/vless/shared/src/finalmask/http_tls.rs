use std::io;
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

use crate::tls_async::connect_async_network;
use crate::{
    advanced_client_config, advanced_quic_client_config, AdvancedTlsClientConfig,
    AdvancedTlsOptions, TlsNetwork,
};

use super::invalid;

pub(super) fn runtime() -> io::Result<&'static Runtime> {
    static RUNTIME: OnceLock<io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

#[derive(Clone, Copy)]
pub(super) enum TlsUsage {
    Realm,
    Doh,
}

#[derive(Clone)]
pub(super) struct TlsClient {
    config: TlsConfig,
    name: String,
}

#[derive(Clone)]
enum TlsConfig {
    Tcp(Arc<AdvancedTlsClientConfig>),
    Quic(Arc<dyn quinn::crypto::ClientConfig>),
}

impl TlsClient {
    pub(super) fn parse(
        value: Value,
        host: &str,
        usage: TlsUsage,
        network: Option<Arc<dyn TlsNetwork>>,
        cache: Option<&crate::AdvancedTlsClientCache>,
    ) -> io::Result<Self> {
        let mut options = if value.is_null() {
            AdvancedTlsOptions {
                use_system_ca: true,
                ..Default::default()
            }
        } else {
            AdvancedTlsOptions::from_json(&value, Vec::new())?
        };
        let name = value
            .get("serverName")
            .map(|name| {
                name.as_str()
                    .ok_or_else(|| invalid("finalmask TLS serverName must be a string"))
            })
            .transpose()?
            .filter(|name| !name.is_empty())
            .unwrap_or(host)
            .to_owned();
        if options.alpn.is_empty() {
            options.alpn = vec!["h2".into(), "http/1.1".into()];
        }
        let h3 = matches!(usage, TlsUsage::Doh) && options.alpn == ["h3"];
        options.network_provider = network;
        // Xray uses its fingerprint presets for DoH over TCP. Realm and DoH
        // over QUIC obtain their TLS options from the standard TLS stack.
        if h3 || matches!(usage, TlsUsage::Realm) {
            options.fingerprint = "unsafe".into();
        }
        let config = if h3 {
            TlsConfig::Quic(match cache { Some(cache) => cache.quic(&options, true)?, None => advanced_quic_client_config(&options, true)? })
        } else {
            TlsConfig::Tcp(match cache { Some(cache) => cache.get(&options)?, None => advanced_client_config(&options)? })
        };
        Ok(Self { config, name })
    }

    pub(super) fn h3(&self) -> bool {
        matches!(self.config, TlsConfig::Quic(_))
    }

    pub(super) fn quic(&self) -> io::Result<(Arc<dyn quinn::crypto::ClientConfig>, &str)> {
        match &self.config {
            TlsConfig::Quic(config) => Ok((config.clone(), &self.name)),
            TlsConfig::Tcp(_) => Err(invalid("finalmask DoH TLS config does not enable h3")),
        }
    }
}

trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}

pub(super) enum HttpConnection {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

impl HttpConnection {
    pub(super) async fn connect(
        host: &str,
        port: u16,
        tls: Option<&TlsClient>,
        carrier: Option<&crate::runtime::CarrierNetwork>,
    ) -> io::Result<Self> {
        let connection = if let Some(carrier) = carrier {
            let carrier = carrier.clone();
            let host = host.to_owned();
            tokio::task::spawn_blocking(move || carrier.tcp(&host, port)).await.map_err(io::Error::other)??
        } else { kerlico_shared::runtime::NetworkConnection::Tcp(TcpStream::connect((host, port)).await?.into_std()?) };
        let config = if let Some(tls) = tls {
            let TlsConfig::Tcp(config) = &tls.config else {
                return Err(invalid(
                    "finalmask HTTPS TCP requires a TCP TLS configuration",
                ));
            };
            Some(config.clone())
        } else { None };
        let name = tls.map(|tls| tls.name.as_str()).unwrap_or(host);
        let local = "0.0.0.0:0".parse().expect("logical local");
        let peer = std::net::SocketAddr::new(host.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into()), port);
        let stream = connect_async_network(connection, config, name, &super::FinalMask::default(), local, peer).await?;
        let h2 = stream.alpn().as_deref() == Some(b"h2");
        let io: Box<dyn AsyncIo> = Box::new(stream);
        let io = TokioIo::new(io);
        if h2 {
            let (send, conn) = http2::handshake(TokioExecutor::new(), io)
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(conn);
            Ok(Self::H2(send))
        } else {
            let (send, conn) = http1::handshake(io).await.map_err(io::Error::other)?;
            tokio::spawn(conn);
            Ok(Self::H1(send))
        }
    }

    pub(super) fn h2(&self) -> bool {
        matches!(self, Self::H2(_))
    }

    pub(super) async fn request(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> io::Result<Response<Incoming>> {
        match self {
            Self::H1(send) => send.send_request(request).await.map_err(io::Error::other),
            Self::H2(send) => send.send_request(request).await.map_err(io::Error::other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use http_body_util::BodyExt;

    #[test]
    fn realm_http_uses_owned_resolver_and_independent_stream_halves() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let network = crate::runtime::testing::NamedNetwork::new(peer);
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") { let mut byte = [0]; socket.read_exact(&mut byte).unwrap(); request.push(byte[0]); }
            assert!(request.starts_with(b"GET /realm HTTP/1.1\r\n"));
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nrealm").unwrap();
        });
        runtime().unwrap().block_on(async {
            let mut connection = HttpConnection::connect("runtime.invalid", peer.port(), None, Some(&network.carrier())).await.unwrap();
            let response = connection.request(Request::builder().uri("/realm").header("host", "runtime.invalid").body(Full::new(Bytes::new())).unwrap()).await.unwrap();
            assert_eq!(response.into_body().collect().await.unwrap().to_bytes(), b"realm"[..]);
        });
        server.join().unwrap();
        assert_eq!(network.connections.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(*network.names.lock().unwrap(), ["runtime.invalid"]);
    }
}
