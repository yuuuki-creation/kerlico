//! OpenVPN TLS control and AEAD data channels. Socket creation belongs to the roles.

mod data;
mod session;
mod wire;

pub use session::{client, server, Session, Tunnel};
#[cfg(unix)]
pub use wire::SocketWake;
#[cfg(target_os = "linux")]
pub use wire::SocketRegistration;
pub use wire::{
    is_initial_reset, retry, Carrier, TcpCarrier, UdpCarrier, FRAME_BATCH, MAX_FRAME, POLL,
};

use std::io;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

pub fn client_tls(ca: &str, certificate: &str, key: &str) -> io::Result<ClientConfig> {
    ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots(ca)?)
        .with_client_auth_cert(certificates(certificate)?, private_key(key)?)
        .map_err(io::Error::other)
}

pub fn server_tls(ca: &str, certificate: &str, key: &str) -> io::Result<ServerConfig> {
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        roots(ca)?.into(),
        rustls::crypto::ring::default_provider().into(),
    )
    .build()
    .map_err(io::Error::other)?;
    ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(certificate)?, private_key(key)?)
        .map_err(io::Error::other)
}

fn certificates(pem: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut pem.as_bytes()).collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(invalid("expected PEM certificate"));
    }
    Ok(certs)
}

fn private_key(pem: &str) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())?
        .ok_or_else(|| invalid("expected PEM private key"))
}

fn roots(pem: &str) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(pem)? {
        roots.add(cert).map_err(io::Error::other)?;
    }
    Ok(roots)
}

pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .try_into()
        .unwrap()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
