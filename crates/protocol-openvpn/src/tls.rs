//! OpenVPN 控制通道的 rustls 配置。

use kerlico_core::{Error, Result};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, NamedGroup, RootCertStore,
    SignatureScheme,
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
    },
    pki_types::{
        CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
    },
    server::{
        ParsedCertificate, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use std::{io::Cursor, sync::Arc};
use subtle::ConstantTimeEq;
use x509_parser::prelude::FromDer;

/// OpenVPN 服务端证书通常不含主机名：校验链与 serverAuth 用途，名称只按 `verify-x509-name` 比较 CN。
#[derive(Debug)]
struct Verifier {
    roots: RootCertStore,
    algorithms: WebPkiSupportedAlgorithms,
    common_name: Option<String>,
}
/// webpki 只在证书带 EKU 扩展时才检查 serverAuth；`remote-cert-tls server` 要求扩展存在，
/// 否则同一 CA 签发的无 EKU 证书也能冒充服务端并拿到用户名密码。
fn has_server_auth(certificate: &[u8]) -> bool {
    let Ok((_, parsed)) = x509_parser::certificate::X509Certificate::from_der(certificate) else {
        return false;
    };
    matches!(parsed.extended_key_usage(), Ok(Some(usage)) if usage.value.server_auth)
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
        if !has_server_auth(end_entity.as_ref()) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::InvalidPurpose,
            ));
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientCertPolicy {
    None,
    Optional,
    Require,
}

/// 对应 OpenVPN `verify-x509-name` 的三种类型。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NameCheck {
    Name(String),
    Prefix(String),
    Subject(String),
}

/// 客户端证书必须带的 Extended Key Usage。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum UsageCheck {
    ClientAuth,
    ServerAuth,
    Oid(String),
}

pub(crate) struct ClientAuth {
    pub policy: ClientCertPolicy,
    pub authorities: Vec<CertificateDer<'static>>,
    pub crls: Vec<CertificateRevocationListDer<'static>>,
    pub fingerprints: Vec<[u8; 32]>,
    pub name: Option<NameCheck>,
    pub usage: Option<UsageCheck>,
    /// OpenVPN `remote-cert-ku` 掩码；`Some` 且为空时只要求扩展存在。
    pub key_usage: Option<Vec<u16>>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum TlsVersion {
    V12,
    V13,
}
impl TlsVersion {
    /// rustls 最低只支持 1.2，`1.0`/`1.1` 作为下限时按 1.2 处理。
    pub fn parse(text: &str) -> Option<Self> {
        let lower = text.trim().to_ascii_lowercase();
        let number = lower
            .strip_prefix("tls")
            .unwrap_or(&lower)
            .trim_start_matches(['v', '_', '-', ' ']);
        match number {
            "1.0" | "1.1" | "1.2" => Some(Self::V12),
            "1.3" => Some(Self::V13),
            _ => None,
        }
    }
}

pub(crate) struct ServerTls {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub client: ClientAuth,
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    /// TLS 1.2 可用 OpenSSL 名称，TLS 1.3 用 IANA 名称；为空时用默认套件。
    pub suites: Vec<String>,
    pub groups: Vec<String>,
}

pub(crate) fn parse_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certificates = rustls_pemfile::certs(&mut Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| Error::Config("OpenVPN 证书 PEM 不合法".into()))?;
    if certificates.is_empty() {
        return Err(Error::Config("OpenVPN 证书 PEM 中没有证书".into()));
    }
    Ok(certificates)
}

pub(crate) fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut Cursor::new(pem))
        .ok()
        .flatten()
        .ok_or_else(|| Error::Config("OpenVPN 服务端私钥不合法".into()))
}

pub(crate) fn parse_crls(pem: &str) -> Result<Vec<CertificateRevocationListDer<'static>>> {
    let crls = rustls_pemfile::crls(&mut Cursor::new(pem))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| Error::Config("OpenVPN CRL PEM 不合法".into()))?;
    if crls.is_empty() {
        return Err(Error::Config("OpenVPN CRL PEM 中没有吊销列表".into()));
    }
    Ok(crls)
}

/// 接受 `AB:CD:..` 或连续十六进制的 SHA-256 指纹。
pub(crate) fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    let invalid = || Error::Config(format!("OpenVPN 证书指纹不合法：{text}"));
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| *byte != b':' && !byte.is_ascii_whitespace())
        .collect();
    if digits.len() != 64 {
        return Err(invalid());
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(digits.chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

pub(crate) fn fingerprint(certificate: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, certificate);
    let mut out = [0; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// 证书里 Key Usage 位串换成 OpenVPN 记法：digitalSignature 为 0x80，依次右移，decipherOnly 为 0x8000。
fn openvpn_key_usage(flags: u16) -> u16 {
    let mut value = 0;
    for bit in 0..8 {
        if flags & 1 << bit != 0 {
            value |= 0x80 >> bit;
        }
    }
    if flags & 1 << 8 != 0 {
        value |= 0x8000;
    }
    value
}

/// 链与 CRL 交给 webpki；之后按 OpenVPN 的 `remote-cert-*`、`verify-x509-name` 与指纹检查叶证书。
#[derive(Debug)]
struct ClientVerifier {
    chain: Option<Arc<dyn ClientCertVerifier>>,
    algorithms: WebPkiSupportedAlgorithms,
    mandatory: bool,
    fingerprints: Vec<[u8; 32]>,
    name: Option<NameCheck>,
    usage: Option<UsageCheck>,
    key_usage: Option<Vec<u16>>,
}
impl ClientVerifier {
    fn check_leaf(&self, certificate: &[u8]) -> std::result::Result<(), rustls::Error> {
        let rejected = |error| Err(rustls::Error::InvalidCertificate(error));
        let actual = fingerprint(certificate);
        if !self.fingerprints.is_empty()
            && !self
                .fingerprints
                .iter()
                .any(|expected| bool::from(expected.ct_eq(&actual)))
        {
            return rejected(CertificateError::ApplicationVerificationFailure);
        }
        let Ok((_, parsed)) = x509_parser::certificate::X509Certificate::from_der(certificate)
        else {
            return rejected(CertificateError::BadEncoding);
        };
        if let Some(usage) = &self.usage {
            let found = match parsed.extended_key_usage() {
                Ok(Some(extension)) => {
                    let value = extension.value;
                    match usage {
                        UsageCheck::ClientAuth => value.client_auth,
                        UsageCheck::ServerAuth => value.server_auth,
                        UsageCheck::Oid(oid) => match oid.as_str() {
                            "1.3.6.1.5.5.7.3.1" => value.server_auth,
                            "1.3.6.1.5.5.7.3.2" => value.client_auth,
                            _ => value.other.iter().any(|other| other.to_id_string() == *oid),
                        },
                    }
                }
                _ => false,
            };
            if !found {
                return rejected(CertificateError::InvalidPurpose);
            }
        }
        if let Some(masks) = &self.key_usage {
            let Ok(Some(extension)) = parsed.key_usage() else {
                return rejected(CertificateError::InvalidPurpose);
            };
            let present = openvpn_key_usage(extension.value.flags);
            if !masks.is_empty() && !masks.iter().any(|mask| present & mask == *mask) {
                return rejected(CertificateError::InvalidPurpose);
            }
        }
        if let Some(name) = &self.name {
            let common_name = parsed
                .subject()
                .iter_common_name()
                .next()
                .and_then(|name| name.as_str().ok());
            let matched = match name {
                NameCheck::Name(expected) => common_name == Some(expected.as_str()),
                NameCheck::Prefix(prefix) => {
                    common_name.is_some_and(|cn| cn.starts_with(prefix.as_str()))
                }
                NameCheck::Subject(expected) => parsed.subject().to_string() == *expected,
            };
            if !matched {
                return rejected(CertificateError::ApplicationVerificationFailure);
            }
        }
        Ok(())
    }
}
impl ClientCertVerifier for ClientVerifier {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chain
            .as_ref()
            .map_or(&[], |chain| chain.root_hint_subjects())
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        if let Some(chain) = &self.chain {
            chain.verify_client_cert(end_entity, intermediates, now)?;
        }
        self.check_leaf(end_entity.as_ref())?;
        Ok(ClientCertVerified::assertion())
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

/// OpenSSL 与 OpenVPN 记法的套件名统一成 rustls 的 IANA 名称。
fn suite_key(name: &str) -> String {
    const OPENSSL: [(&str, &str); 6] = [
        (
            "ECDHE_ECDSA_AES128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            "ECDHE_ECDSA_AES256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            "ECDHE_ECDSA_CHACHA20_POLY1305",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        (
            "ECDHE_RSA_AES128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        (
            "ECDHE_RSA_AES256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        (
            "ECDHE_RSA_CHACHA20_POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
    ];
    let upper = name.trim().to_ascii_uppercase().replace('-', "_");
    if let Some((_, iana)) = OPENSSL.iter().find(|(short, _)| *short == upper) {
        return (*iana).to_owned();
    }
    if upper.starts_with("TLS_AES_") || upper.starts_with("TLS_CHACHA20_") {
        return format!("TLS13_{}", &upper[4..]);
    }
    upper
}

fn group_matches(name: &str, group: NamedGroup) -> bool {
    let name = name.trim().to_ascii_lowercase();
    match group {
        NamedGroup::X25519 => name == "x25519",
        NamedGroup::secp256r1 => matches!(name.as_str(), "p-256" | "secp256r1" | "prime256v1"),
        NamedGroup::secp384r1 => matches!(name.as_str(), "p-384" | "secp384r1"),
        _ => false,
    }
}

fn provider(settings: &ServerTls) -> Result<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    if !settings.suites.is_empty() {
        let wanted: Vec<String> = settings.suites.iter().map(|name| suite_key(name)).collect();
        for (name, key) in settings.suites.iter().zip(&wanted) {
            if !provider
                .cipher_suites
                .iter()
                .any(|suite| suite.suite().as_str() == Some(key.as_str()))
            {
                return Err(Error::Config(format!("OpenVPN 不支持的 TLS 套件：{name}")));
            }
        }
        let tls13 = wanted.iter().any(|key| key.starts_with("TLS13_"));
        let tls12 = wanted.iter().any(|key| !key.starts_with("TLS13_"));
        provider.cipher_suites.retain(|suite| {
            let key = suite.suite().as_str().unwrap_or_default();
            let listed = if key.starts_with("TLS13_") {
                tls13
            } else {
                tls12
            };
            !listed || wanted.iter().any(|wanted| wanted == key)
        });
        provider.cipher_suites.sort_by_key(|suite| {
            wanted
                .iter()
                .position(|key| Some(key.as_str()) == suite.suite().as_str())
        });
    }
    if !settings.groups.is_empty() {
        let mut groups = Vec::new();
        for name in &settings.groups {
            let group = provider
                .kx_groups
                .iter()
                .find(|group| group_matches(name, group.name()))
                .ok_or_else(|| Error::Config(format!("OpenVPN 不支持的 TLS 密钥交换组：{name}")))?;
            groups.push(*group);
        }
        provider.kx_groups = groups;
    }
    Ok(provider)
}

pub(crate) fn server_config(settings: ServerTls) -> Result<Arc<rustls::ServerConfig>> {
    if settings.min_version > settings.max_version {
        return Err(Error::Config("OpenVPN TLS 最低版本高于最高版本".into()));
    }
    let versions: Vec<&'static rustls::SupportedProtocolVersion> = [
        (TlsVersion::V12, &rustls::version::TLS12),
        (TlsVersion::V13, &rustls::version::TLS13),
    ]
    .into_iter()
    .filter(|(version, _)| (settings.min_version..=settings.max_version).contains(version))
    .map(|(_, version)| version)
    .collect();
    let provider = Arc::new(provider(&settings)?);
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&versions)
        .map_err(|_| Error::Config("OpenVPN TLS 版本与套件没有可用组合".into()))?;
    let client = settings.client;
    let builder = if client.policy == ClientCertPolicy::None {
        builder.with_no_client_auth()
    } else {
        let chain = if client.authorities.is_empty() {
            None
        } else {
            let mut roots = RootCertStore::empty();
            for authority in client.authorities {
                roots
                    .add(authority)
                    .map_err(|_| Error::Config("OpenVPN 客户端 CA 证书不合法".into()))?;
            }
            let mut webpki =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone());
            if !client.crls.is_empty() {
                webpki = webpki
                    .with_crls(client.crls)
                    .only_check_end_entity_revocation();
            }
            if client.policy == ClientCertPolicy::Optional {
                webpki = webpki.allow_unauthenticated();
            }
            Some(
                webpki
                    .build()
                    .map_err(|_| Error::Config("OpenVPN 客户端 CA 或 CRL 不合法".into()))?,
            )
        };
        builder.with_client_cert_verifier(Arc::new(ClientVerifier {
            chain,
            algorithms: provider.signature_verification_algorithms,
            mandatory: client.policy == ClientCertPolicy::Require,
            fingerprints: client.fingerprints,
            name: client.name,
            usage: client.usage,
            key_usage: client.key_usage,
        }))
    };
    let mut config = builder
        .with_single_cert(settings.chain, settings.key)
        .map_err(|_| Error::Config("OpenVPN 服务端证书与私钥不匹配".into()))?;
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
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

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };

    fn accepts(usages: Vec<ExtendedKeyUsagePurpose>) -> bool {
        let mut authority = CertificateParams::new(Vec::<String>::new()).unwrap();
        authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let authority_key = KeyPair::generate().unwrap();
        let root = authority.self_signed(&authority_key).unwrap();
        let mut leaf = CertificateParams::new(vec!["server.invalid".to_owned()]).unwrap();
        leaf.extended_key_usages = usages;
        let leaf_key = KeyPair::generate().unwrap();
        let certificate = leaf
            .signed_by(&leaf_key, &Issuer::from_params(&authority, &authority_key))
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        Verifier {
            roots,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            common_name: None,
        }
        .verify_server_cert(
            certificate.der(),
            &[],
            &ServerName::try_from("openvpn.invalid").unwrap(),
            &[],
            UnixTime::now(),
        )
        .is_ok()
    }

    #[test]
    fn server_certificate_must_carry_the_server_auth_extended_key_usage() {
        assert!(accepts(vec![ExtendedKeyUsagePurpose::ServerAuth]));
        assert!(!accepts(vec![ExtendedKeyUsagePurpose::ClientAuth]));
        assert!(!accepts(Vec::new()));
    }
}
