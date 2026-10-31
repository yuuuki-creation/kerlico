//! 标准 WebPKI 校验之外增加固定 SPKI 拒绝集，不替代链、名称或签名校验。
use crate::config::{ClientTls, ServerTls, Transport, invalid};
use kerlico_core::{Error, Result};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{io::Cursor, sync::Arc};
mod blocklist {
    include!("tls_blocklist.rs");
}
#[derive(Debug)]
struct Verifier {
    inner: Arc<dyn ServerCertVerifier>,
}
fn blocked(cert: &[u8]) -> std::result::Result<bool, rustls::Error> {
    use x509_parser::prelude::FromDer;
    let (rest, certificate) = x509_parser::certificate::X509Certificate::from_der(cert)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    if !rest.is_empty() {
        return Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ));
    }
    let hash: [u8; 32] = Sha256::digest(certificate.public_key().raw).into();
    Ok(blocklist::SPKI.contains(&hash))
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        for certificate in std::iter::once(end_entity).chain(intermediates) {
            if blocked(certificate.as_ref())? {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
pub(crate) fn client(
    options: &ClientTls,
    transport: Transport,
) -> Result<Arc<rustls::ClientConfig>> {
    ServerName::try_from(options.server_name.clone()).map_err(|_| invalid())?;
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = &options.ca_pem {
        let certs =
            rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<std::io::Result<Vec<_>>>()?;
        if certs.is_empty() {
            return Err(invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid())?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .map_err(|_| invalid())?;
    let versions = if transport == Transport::H3 {
        vec![&rustls::version::TLS13]
    } else {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|_| invalid())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier { inner: verifier }))
        .with_no_client_auth();
    config.alpn_protocols = vec![match transport {
        Transport::H1 => b"http/1.1".to_vec(),
        Transport::H2 => b"h2".to_vec(),
        Transport::H3 => b"h3".to_vec(),
    }];
    config.enable_early_data = false;
    Ok(Arc::new(config))
}
pub(crate) fn server(
    options: ServerTls,
    transports: &[Transport],
) -> Result<Arc<rustls::ServerConfig>> {
    let (certificate, key) = options.materials()?;
    let certs = rustls_pemfile::certs(&mut Cursor::new(certificate))
        .collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(key.as_bytes()))?.ok_or_else(invalid)?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|_| invalid())?;
    config.alpn_protocols = [Transport::H2, Transport::H1]
        .iter()
        .filter(|p| transports.contains(p))
        .map(|p| {
            if *p == Transport::H2 {
                b"h2".to_vec()
            } else {
                b"http/1.1".to_vec()
            }
        })
        .collect();
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}
pub(crate) fn quic_transport(
    idle: std::time::Duration,
    streams: usize,
    control: &str,
) -> Result<Arc<quinn::TransportConfig>> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(u32::try_from(streams).map_err(|_| invalid())?.into());
    transport.max_concurrent_uni_streams(16u32.into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle).map_err(|_| invalid())?,
    ));
    transport.stream_receive_window((256u32 * 1024).into());
    transport.receive_window((4u32 * 1024 * 1024).into());
    transport.send_window(4 * 1024 * 1024);
    transport.datagram_receive_buffer_size(None);
    match control {
        "cubic" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
        "reno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        _ => return Err(invalid()),
    };
    Ok(Arc::new(transport))
}
pub(crate) fn quic_client(
    tls: Arc<rustls::ClientConfig>,
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ClientConfig> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
        .map_err(|_| Error::Config("Naive QUIC TLS 配置不合法".into()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport);
    config.version(1);
    Ok(config)
}
pub(crate) fn quic_server(
    tls: Arc<rustls::ServerConfig>,
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ServerConfig> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| invalid())?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport);
    Ok(config)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn blocked_certificate_asset() -> Vec<u8> {
        use x509_parser::prelude::FromDer;
        const RELATIVE_PATH: &str = "naive/blocked-intermediate.der";
        let metadata: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/SOURCE.json"))
                .expect("Naive测试资产来源元数据必须有效");
        assert_eq!(metadata["relative_path"].as_str(), Some(RELATIVE_PATH));
        let directory = std::env::var_os("KERLICO_TEST_ASSETS_DIR")
            .filter(|value| !value.is_empty())
            .expect("缺少KERLICO_TEST_ASSETS_DIR；请先在worker运行prepare_naive_test_assets.py，测试不会联网下载或忽略此项");
        let bytes = std::fs::read(std::path::PathBuf::from(directory).join(RELATIVE_PATH))
            .expect("缺少或无法读取Naive固定测试资产；请在worker准备后重试，测试不会联网下载");
        assert_eq!(
            bytes.len() as u64,
            metadata["byte_len"].as_u64().expect("缺少测试资产固定大小"),
            "Naive测试资产大小不匹配"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            metadata["sha256_der"]
                .as_str()
                .expect("缺少测试资产DER摘要"),
            "Naive测试资产DER摘要不匹配"
        );
        let (rest, certificate) = x509_parser::certificate::X509Certificate::from_der(&bytes)
            .expect("Naive固定测试资产DER解析失败");
        assert!(rest.is_empty(), "Naive固定测试资产不得包含尾随数据");
        assert_eq!(
            format!("{:x}", Sha256::digest(certificate.public_key().raw)),
            metadata["sha256_spki"]
                .as_str()
                .expect("缺少测试资产SPKI摘要"),
            "Naive测试资产SPKI摘要不匹配"
        );
        bytes
    }
    #[test]
    fn invalid_der_is_rejected_and_snapshot_contains_security_update() {
        assert!(blocked(&[0x30, 0]).is_err());
        assert!(blocked(&blocked_certificate_asset()).unwrap());
        let normal = rcgen::generate_simple_self_signed(vec!["normal.invalid".into()]).unwrap();
        assert!(!blocked(normal.cert.der()).unwrap());
        assert!(blocklist::SPKI.len() > 8);
        assert!(blocklist::SPKI.contains(&[
            0x49, 0xdd, 0x35, 0x3d, 0xc2, 0xb9, 0x19, 0xa3, 0x77, 0x06, 0x45, 0x11, 0x7d, 0x0e,
            0x60, 0xc1, 0x61, 0x15, 0xe7, 0xd1, 0xbc, 0x25, 0x9e, 0xef, 0xe7, 0x34, 0xb0, 0x0e,
            0xa4, 0x34, 0xfe, 0x5f
        ]));
    }
}
