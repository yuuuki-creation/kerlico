//! OpenVPN 控制通道的 rustls 配置。

use kerlico_core::{Error, Result};
use rustls::{
    CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::ParsedCertificate,
};
use std::{io::Cursor, sync::Arc};
use x509_parser::prelude::FromDer;

/// OpenVPN 服务端证书通常不含主机名：校验链与 serverAuth 用途，名称只按 `verify-x509-name` 比较 CN。
#[derive(Debug)]
struct Verifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
    common_name: Option<String>,
}
fn subject_matches(certificate: &[u8], expected: &str) -> bool {
    let Ok((_, parsed)) = x509_parser::certificate::X509Certificate::from_der(certificate) else {
        return false;
    };
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        == Some(expected)
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.algorithms.all,
        )?;
        if let Some(expected) = &self.common_name
            && !subject_matches(end_entity.as_ref(), expected)
        {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// `identity` 为客户端证书与私钥的 PEM 文本。
pub(crate) fn client_config(
    ca_pem: &str,
    identity: Option<(&str, &str)>,
    verify_x509_name: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>> {
    let invalid = || Error::Config("OpenVPN 证书或私钥不合法".into());
    let mut roots = RootCertStore::empty();
    let authorities = rustls_pemfile::certs(&mut Cursor::new(ca_pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| invalid())?;
    if authorities.is_empty() {
        return Err(invalid());
    }
    for authority in authorities {
        roots.add(authority).map_err(|_| invalid())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Verifier {
        roots,
        algorithms: provider.signature_verification_algorithms,
        common_name: verify_x509_name.map(str::to_owned),
    });
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid())?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match identity {
        None => builder.with_no_client_auth(),
        Some((certificate, key)) => {
            let chain = rustls_pemfile::certs(&mut Cursor::new(certificate))
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(|_| invalid())?;
            let key = rustls_pemfile::private_key(&mut Cursor::new(key))
                .map_err(|_| invalid())?
                .ok_or_else(invalid)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|_| invalid())?
        }
    };
    // 上游每个 key_id 都做完整握手，也不要求 SNI。
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_sni = false;
    Ok(Arc::new(config))
}
