use crate::config::{ClientTls, ServerTls};
use kerlico_core::{BoxStream, Error, Result};
use rustls::{ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName};
use std::{io::Cursor, sync::Arc};

fn invalid() -> Error {
    Error::Config("Sudoku TLS证书、私钥或名称不合法".into())
}
pub(crate) fn client(options: &ClientTls, alpn: &[&[u8]]) -> Result<ClientConfig> {
    ServerName::try_from(options.server_name.clone()).map_err(|_| invalid())?;
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = options.ca_pem.as_ref() {
        let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| invalid())?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?;
    let mut config = if options.insecure {
        kerlico_net::warn_insecure_tls("Sudoku");
        builder
            .dangerous()
            .with_custom_certificate_verifier(kerlico_net::insecure_verifier(provider))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}
pub(crate) fn server(options: &ServerTls) -> Result<tokio_rustls::TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut Cursor::new(options.cert_pem.as_bytes()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(options.key_pem.as_bytes()))
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    if certs.is_empty() {
        return Err(invalid());
    }
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid())?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|_| invalid())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}
#[derive(Clone)]
pub(crate) struct PreparedTls {
    name: ServerName<'static>,
    config: Arc<ClientConfig>,
}
impl PreparedTls {
    pub fn new(options: &ClientTls, alpn: &[&[u8]]) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            name: ServerName::try_from(options.server_name.clone()).map_err(|_| invalid())?,
            config: Arc::new(client(options, alpn)?),
        }))
    }
}
pub(crate) async fn connect_meta(
    endpoint: &super::endpoint::Endpoint,
    options: Option<&PreparedTls>,
) -> Result<(BoxStream, bool)> {
    let stream = endpoint.connect().await?;
    if let Some(options) = options {
        let stream = tokio_rustls::TlsConnector::from(options.config.clone())
            .connect(options.name.clone(), stream)
            .await?;
        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
        Ok((Box::new(stream), h2))
    } else {
        Ok((stream, false))
    }
}
pub(crate) async fn connect(
    endpoint: &super::endpoint::Endpoint,
    options: Option<&PreparedTls>,
) -> Result<BoxStream> {
    connect_meta(endpoint, options)
        .await
        .map(|(stream, _)| stream)
}
