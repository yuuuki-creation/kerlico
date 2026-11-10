use base64::{engine::general_purpose::STANDARD, Engine};
use boring2::hpke::HpkeKey;
use boring2::pkey::{PKey, Private};
use boring2::ssl::{
    select_next_proto, AlpnError, ExtensionType, NameType, SelectCertError, SniError, Ssl,
    SslConnector, SslContext, SslContextBuilder, SslCurve, SslEchKeys, SslMethod, SslOptions,
    SslRef, SslSession, SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use boring2::x509::X509;
use rustls::client::{danger::ServerCertVerifier, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::RootCertStore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsCertificate {
    #[serde(default, deserialize_with = "pem_string")]
    pub certificate: String,
    #[serde(default, deserialize_with = "pem_string")]
    pub key: String,
    #[serde(default)]
    pub certificate_file: String,
    #[serde(default)]
    pub key_file: String,
    #[serde(default)]
    pub usage: String,
    #[serde(default)]
    pub one_time_loading: bool,
    #[serde(default)]
    pub build_chain: bool,
    #[serde(default)]
    pub ocsp_stapling: u64,
}

fn pem_string<'de, D: serde::Deserializer<'de>>(de: D) -> Result<String, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Pem {
        Text(String),
        Lines(Vec<String>),
    }
    Ok(match Pem::deserialize(de)? {
        Pem::Text(s) => s,
        Pem::Lines(lines) => lines.join("\n"),
    })
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AdvancedTlsOptions {
    pub alpn: Vec<String>,
    pub min_version: String,
    pub max_version: String,
    pub cipher_suites: String,
    pub curve_preferences: Vec<String>,
    pub fingerprint: String,
    pub certificates: Vec<TlsCertificate>,
    pub allow_insecure: bool,
    pub pinned_peer_cert_sha256: String,
    pub verify_peer_cert_by_name: Vec<String>,
    pub reject_unknown_sni: bool,
    pub disable_system_root: bool,
    pub use_system_ca: bool,
    pub enable_session_resumption: bool,
    pub master_key_log: String,
    pub ech_config_list: String,
    pub ech_server_keys: String,
    pub ech_socket_settings: Option<serde_json::Value>,
    #[serde(skip)]
    pub network_provider: Option<Arc<dyn super::TlsNetwork>>,
}

impl AdvancedTlsOptions {
    pub fn from_json(value: &serde_json::Value, alpn: Vec<String>) -> io::Result<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid("TLS settings must be an object"))?;
        let settings: HashMap<_, _> = object
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| value.to_string()),
                )
            })
            .collect();
        let alpn = if alpn.is_empty() {
            crate::string_list(settings.get("alpn").map(String::as_str).unwrap_or_default())?
        } else {
            alpn
        };
        Self::from_settings(|key| settings.get(key).map(String::as_str), alpn)
    }

    pub fn from_settings<'a>(
        get: impl Fn(&str) -> Option<&'a str>,
        alpn: Vec<String>,
    ) -> io::Result<Self> {
        let text = |key| get(key).unwrap_or_default().to_string();
        let flag = |key| -> io::Result<bool> {
            match get(key).unwrap_or("false") {
                "false" => Ok(false),
                "true" => Ok(true),
                _ => Err(invalid("TLS boolean")),
            }
        };
        let mut certificates: Vec<TlsCertificate> = match get("certificates") {
            Some(value) => serde_json::from_str(value).map_err(io::Error::other)?,
            None => Vec::new(),
        };
        if get("certificate").is_some() || get("certificateFile").is_some() {
            let pem = |key| -> io::Result<String> {
                let value = text(key);
                if value.trim_start().starts_with('[') {
                    Ok(serde_json::from_str::<Vec<String>>(&value)
                        .map_err(io::Error::other)?
                        .join("\n"))
                } else {
                    Ok(value)
                }
            };
            certificates.push(TlsCertificate {
                certificate: pem("certificate")?,
                key: pem("key")?,
                certificate_file: text("certificateFile"),
                key_file: text("keyFile"),
                ..Default::default()
            });
        }
        for cert in &mut certificates {
            if !matches!(
                cert.usage.to_lowercase().as_str(),
                "" | "encipherment" | "verify" | "issue"
            ) {
                return Err(invalid("TLS certificate usage"));
            }
        }
        Ok(Self {
            alpn,
            certificates,
            min_version: text("minVersion"),
            max_version: text("maxVersion"),
            cipher_suites: text("cipherSuites"),
            curve_preferences: crate::string_list(get("curvePreferences").unwrap_or_default())?,
            fingerprint: text("fingerprint").to_lowercase(),
            allow_insecure: flag("allowInsecure")?,
            pinned_peer_cert_sha256: text("pinnedPeerCertSha256"),
            verify_peer_cert_by_name: crate::string_list(
                get("verifyPeerCertByName").unwrap_or_default(),
            )?,
            reject_unknown_sni: flag("rejectUnknownSni")?,
            disable_system_root: flag("disableSystemRoot")?,
            use_system_ca: flag("useSystemCA")?,
            enable_session_resumption: flag("enableSessionResumption")?,
            master_key_log: text("masterKeyLog"),
            ech_config_list: text("echConfigList"),
            ech_server_keys: text("echServerKeys"),
            ech_socket_settings: get("echSockopt")
                .map(serde_json::from_str)
                .transpose()
                .map_err(io::Error::other)?,
            network_provider: None,
        })
    }
}

type Sessions = Arc<Mutex<HashMap<String, SslSession>>>;

/// Keep this factory with the node or outbound settings across separate dials.
/// The key includes all TLS policy, loaded certificate contents and provider identity.
type CacheKey = (Vec<u8>, usize);

#[derive(Default)]
pub struct AdvancedTlsClientCache {
    entries: Mutex<HashMap<CacheKey, Arc<AdvancedTlsClientConfig>>>,
}

impl AdvancedTlsClientCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, options: &AdvancedTlsOptions) -> io::Result<Arc<AdvancedTlsClientConfig>> {
        self.get_profile(options, super::fingerprint::resolve(&options.fingerprint)?)
    }

    pub(super) fn get_profile(
        &self,
        options: &AdvancedTlsOptions,
        profile: Option<super::fingerprint::Profile>,
    ) -> io::Result<Arc<AdvancedTlsClientConfig>> {
        let mut options = options.clone();
        for entry in &mut options.certificates {
            if !entry.one_time_loading {
                *entry = load_certificate_files(entry)?;
            }
        }
        let mut key_options = options.clone();
        for entry in &mut key_options.certificates {
            if entry.one_time_loading {
                if !entry.certificate_file.is_empty() {
                    entry.certificate.clear();
                }
                if !entry.key_file.is_empty() {
                    entry.key.clear();
                }
            }
        }
        let key = (
            serde_json::to_vec(&(key_options, &profile)).map_err(io::Error::other)?,
            options
                .network_provider
                .as_ref()
                .map(|provider| Arc::as_ptr(provider) as *const () as usize)
                .unwrap_or_default(),
        );
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("TLS config cache poisoned"))?;
        if let Some(config) = entries.get(&key) {
            return Ok(config.clone());
        }
        let config = advanced_client_config_with_profile(&options, profile)?;
        if entries.len() >= 128 {
            entries.clear();
        }
        entries.insert(key, config.clone());
        Ok(config)
    }
}

pub struct AdvancedTlsClientConfig {
    connector: SslConnector,
    options: AdvancedTlsOptions,
    roots: RootCertStore,
    pins: Vec<[u8; 32]>,
    ech: Option<super::ech::EchSource>,
    sessions: Sessions,
    profile: Option<super::fingerprint::Profile>,
}

pub struct AdvancedTlsServerConfig {
    context: SslContext,
}

pub fn advanced_client_config(
    options: &AdvancedTlsOptions,
) -> io::Result<Arc<AdvancedTlsClientConfig>> {
    advanced_client_config_with_profile(options, super::fingerprint::resolve(&options.fingerprint)?)
}

pub(super) fn advanced_client_config_with_profile(
    options: &AdvancedTlsOptions,
    profile: Option<super::fingerprint::Profile>,
) -> io::Result<Arc<AdvancedTlsClientConfig>> {
    let mut effective = options.clone();
    for entry in &mut effective.certificates {
        *entry = load_certificate_files(entry)?;
    }
    if !effective.ech_config_list.is_empty() {
        if !matches!(effective.min_version.as_str(), "" | "1.3")
            || !matches!(effective.max_version.as_str(), "" | "1.3")
        {
            return Err(invalid("ECH requires TLS 1.3"));
        }
        effective.min_version = "1.3".into();
    }
    let options = &effective;
    let mut builder =
        SslConnector::no_default_verify_builder(SslMethod::tls()).map_err(io::Error::other)?;
    common(&mut builder, options)?;
    if let Some(profile) = &profile {
        super::fingerprint::configure_profile(&mut builder, options, profile)?;
    }
    // The same certificate policy is applied after every full and resumed handshake,
    // before a caller obtains an application stream.
    builder.set_verify(SslVerifyMode::NONE);
    let sessions: Sessions = Arc::default();
    if options.enable_session_resumption {
        let cache = sessions.clone();
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        builder.set_new_session_callback(move |ssl, session| {
            if let Some(name) = ssl.servername(NameType::HOST_NAME) {
                let mut cache = cache.lock().expect("TLS session cache");
                if cache.len() >= 128 {
                    cache.clear();
                }
                cache.insert(name.to_string(), session);
            }
        });
    }
    let mut roots = RootCertStore::empty();
    if !options.disable_system_root {
        if options.use_system_ca {
            let native = rustls_native_certs::load_native_certs();
            roots.add_parsable_certificates(native.certs);
            if roots.is_empty() {
                return Err(invalid("no system CA certificates"));
            }
        } else {
            roots
                .roots
                .extend_from_slice(webpki_roots::TLS_SERVER_ROOTS);
        }
    }
    for entry in &options.certificates {
        if options.disable_system_root || entry.usage.eq_ignore_ascii_case("verify") {
            for cert in certificates(&entry.certificate)? {
                roots
                    .add(CertificateDer::from(
                        cert.to_der().map_err(io::Error::other)?,
                    ))
                    .map_err(io::Error::other)?;
            }
        }
    }
    let pins =
        crate::tls::parse_pins(&options.pinned_peer_cert_sha256).map_err(|_| invalid("TLS pin"))?;
    let ech = if options.ech_config_list.is_empty() {
        None
    } else {
        Some(super::ech::EchSource::new(
            &options.ech_config_list,
            options.network_provider.clone(),
            options.ech_socket_settings.clone(),
        )?)
    };
    Ok(Arc::new(AdvancedTlsClientConfig {
        connector: builder.build(),
        options: options.clone(),
        roots,
        pins,
        ech,
        sessions,
        profile,
    }))
}

impl AdvancedTlsClientConfig {
    pub(super) fn ssl(&self, name: &str) -> io::Result<Ssl> {
        let mut configuration = self.connector.configure().map_err(io::Error::other)?;
        configuration.set_verify_hostname(false);
        let mut ssl = configuration
            .into_ssl(Some(name))
            .map_err(io::Error::other)?;
        super::fingerprint::configure_connection(&mut ssl, self.profile.as_ref(), &self.options)?;
        if let Some(ech) = &self.ech {
            ssl.set_ech_config_list(&ech.resolve(name)?)
                .map_err(io::Error::other)?;
        }
        if self.options.enable_session_resumption {
            if let Some(session) = self.sessions.lock().expect("TLS session cache").get(name) {
                // Sessions are scoped to this exact connector and certificate policy.
                unsafe {
                    ssl.set_session(session).map_err(io::Error::other)?;
                }
            }
        }
        Ok(ssl)
    }

    pub(super) fn verify(&self, ssl: &SslRef, name: &str) -> io::Result<()> {
        if self.ech.is_some() && !ssl.ech_accepted() {
            return Err(invalid("ECH rejected"));
        }
        let result = self.verify_certificate(ssl, name);
        if result.is_err() {
            self.sessions
                .lock()
                .expect("TLS session cache")
                .remove(name);
        }
        result
    }

    fn verify_certificate(&self, ssl: &SslRef, name: &str) -> io::Result<()> {
        let leaf = ssl
            .peer_certificate()
            .ok_or_else(|| invalid("missing TLS certificate"))?;
        let leaf = CertificateDer::from(leaf.to_der().map_err(io::Error::other)?);
        let chain = ssl
            .peer_cert_chain()
            .ok_or_else(|| invalid("missing TLS certificate chain"))?;
        let chain = chain
            .iter()
            .map(|cert| {
                cert.to_der()
                    .map(CertificateDer::from)
                    .map_err(io::Error::other)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let intermediates: Vec<_> = chain.into_iter().filter(|cert| cert != &leaf).collect();
        let pinned =
            |cert: &CertificateDer<'_>| self.pins.contains(&Sha256::digest(cert.as_ref()).into());
        if !self.pins.is_empty() && pinned(&leaf) {
            return Ok(());
        }
        let roots = if !self.pins.is_empty() {
            let ca = intermediates
                .iter()
                .find(|cert| pinned(cert) && crate::tls::certificate_is_ca(cert))
                .ok_or_else(|| invalid("TLS certificate does not match a configured pin"))?;
            let mut roots = RootCertStore::empty();
            roots.add(ca.clone()).map_err(io::Error::other)?;
            roots
        } else {
            if self.options.allow_insecure && self.options.verify_peer_cert_by_name.is_empty() {
                return Ok(());
            }
            self.roots.clone()
        };
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(io::Error::other)?;
        let names = if self.options.verify_peer_cert_by_name.is_empty() {
            vec![name.to_string()]
        } else {
            self.options.verify_peer_cert_by_name.clone()
        };
        for name in names {
            let name = ServerName::try_from(name).map_err(io::Error::other)?;
            if verifier
                .verify_server_cert(&leaf, &intermediates, &name, &[], UnixTime::now())
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(invalid("TLS certificate chain or name validation failed"))
    }
}

#[derive(Clone)]
struct Identity {
    context: SslContext,
    names: Vec<String>,
}

#[derive(PartialEq, Eq)]
struct FileVersion(Vec<(u64, Option<std::time::SystemTime>)>);

impl FileVersion {
    fn read(entry: &TlsCertificate) -> io::Result<Self> {
        [&entry.certificate_file, &entry.key_file]
            .into_iter()
            .filter(|path| !path.is_empty())
            .map(|path| std::fs::metadata(path).map(|meta| (meta.len(), meta.modified().ok())))
            .collect::<io::Result<Vec<_>>>()
            .map(Self)
    }
}

struct IdentitySource {
    entry: TlsCertificate,
    current: Mutex<(FileVersion, Identity)>,
}

impl IdentitySource {
    fn new(options: &AdvancedTlsOptions, entry: &TlsCertificate) -> io::Result<Self> {
        let version = FileVersion::read(entry)?;
        let entry = load_certificate_files(entry)?;
        let identity = server_identity(options, &entry)?;
        Ok(Self {
            entry,
            current: Mutex::new((version, identity)),
        })
    }

    fn snapshot(&self, options: &AdvancedTlsOptions) -> Identity {
        let mut current = self.current.lock().expect("TLS certificate cache");
        if !self.entry.one_time_loading {
            if let Ok(version) = FileVersion::read(&self.entry) {
                if version != current.0 {
                    if let Ok(identity) = load_certificate_files(&self.entry)
                        .and_then(|entry| server_identity(options, &entry))
                    {
                        *current = (version, identity);
                    }
                }
            }
        }
        current.1.clone()
    }
}

fn load_certificate_files(entry: &TlsCertificate) -> io::Result<TlsCertificate> {
    let mut entry = entry.clone();
    if !entry.certificate_file.is_empty() {
        entry.certificate = std::fs::read_to_string(&entry.certificate_file)?;
    }
    if !entry.key_file.is_empty() {
        entry.key = std::fs::read_to_string(&entry.key_file)?;
    }
    Ok(entry)
}

fn private_key(pem: &str) -> io::Result<PKey<Private>> {
    use der::{Decode, Encode};
    use rustls::pki_types::PrivateKeyDer;
    let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))?
        .ok_or_else(|| invalid("missing TLS private key"))?;
    if let PrivateKeyDer::Pkcs8(bytes) = key {
        let parsed =
            pkcs8::PrivateKeyInfo::from_der(bytes.secret_pkcs8_der()).map_err(io::Error::other)?;
        // RFC 5958's optional public key is redundant. BoringSSL consumes PKCS#8 v1.
        let canonical = pkcs8::PrivateKeyInfo::new(parsed.algorithm, parsed.private_key)
            .to_der()
            .map_err(io::Error::other)?;
        PKey::private_key_from_pkcs8(&canonical).map_err(io::Error::other)
    } else {
        PKey::private_key_from_der(key.secret_der()).map_err(io::Error::other)
    }
}

fn server_identity(options: &AdvancedTlsOptions, entry: &TlsCertificate) -> io::Result<Identity> {
    let chain = certificates(&entry.certificate)?;
    let key = private_key(&entry.key)?;
    let mut context = SslContextBuilder::new(SslMethod::tls()).map_err(io::Error::other)?;
    common(&mut context, options)?;
    context
        .set_certificate(&chain[0])
        .map_err(io::Error::other)?;
    context.set_private_key(&key).map_err(io::Error::other)?;
    context.check_private_key().map_err(io::Error::other)?;
    super::ocsp::configure(&mut context, options, entry, &chain)?;
    let names = chain[0]
        .subject_alt_names()
        .into_iter()
        .flatten()
        .filter_map(|name| name.dnsname().map(str::to_ascii_lowercase))
        .collect();
    for cert in chain.into_iter().skip(1) {
        context
            .add_extra_chain_cert(cert)
            .map_err(io::Error::other)?;
    }
    configure_server(&mut context, options)?;
    Ok(Identity {
        context: context.build(),
        names,
    })
}

pub fn advanced_server_config(
    options: &AdvancedTlsOptions,
) -> io::Result<Arc<AdvancedTlsServerConfig>> {
    let mut identities = Vec::new();
    let mut issuers = Vec::new();
    for entry in &options.certificates {
        if entry.usage.eq_ignore_ascii_case("issue") {
            let entry = load_certificate_files(entry)?;
            if !crate::tls::certificate_is_ca(
                &certificates(&entry.certificate)?[0]
                    .to_der()
                    .map_err(io::Error::other)?,
            ) {
                return Err(invalid("TLS issuer is not a CA"));
            }
            issuers.push(entry);
        }
        if !matches!(entry.usage.to_lowercase().as_str(), "" | "encipherment") {
            continue;
        }
        identities.push(IdentitySource::new(options, entry)?);
    }
    let mut context = SslContextBuilder::new(SslMethod::tls()).map_err(io::Error::other)?;
    common(&mut context, options)?;
    configure_server(&mut context, options)?;
    let groups = if options.curve_preferences.is_empty() {
        GROUPS
            .iter()
            .filter(|&&(id, ..)| id != MLKEM1024)
            .map(|&(id, curve, _)| (id, curve))
            .collect()
    } else {
        curve_preferences(&options.curve_preferences)?
    };
    context
        .set_curves(&groups.iter().map(|&(_, curve)| curve).collect::<Vec<_>>())
        .map_err(io::Error::other)?;
    if version(&options.max_version, SslVersion::TLS1_3)? == SslVersion::TLS1_3 {
        // BoringSSL picks the client's first listed group and retries when that group has
        // no key share. Xray's uTLS clients list X25519MLKEM768 without a share and abort a
        // HelloRetryRequest for it (Go 1.27 retries there too), so the first server group
        // the client already sent a share for wins. Narrowing is TLS 1.3 only: a TLS 1.2
        // handshake narrowed to a hybrid group would have no ECDHE group left.
        context.set_select_certificate_callback(move |mut hello| {
            let offered = hello
                .get_extension(ExtensionType::SUPPORTED_GROUPS)
                .zip(hello.get_extension(ExtensionType::KEY_SHARE))
                .and_then(|(supported, shares)| key_share_group(&groups, supported, shares));
            if let Some(curve) = offered {
                hello
                    .ssl_mut()
                    .set_curves(&[curve])
                    .map_err(|_| SelectCertError::ERROR)?;
            }
            Ok(())
        });
    }
    if identities.is_empty() && issuers.is_empty() {
        return Err(invalid(
            "TLS server has no encipherment or issue certificate",
        ));
    }
    let reject_unknown = options.reject_unknown_sni;
    let options = options.clone();
    let issued: Mutex<HashMap<String, (std::time::Instant, Identity)>> = Mutex::default();
    context.set_servername_callback(move |ssl, _alert| {
        let name = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let identities: Vec<_> = identities
            .iter()
            .map(|source| source.snapshot(&options))
            .collect();
        let selected = identities.iter().find(|identity| {
            identity
                .names
                .iter()
                .any(|pattern| hostname_matches(pattern, &name))
        });
        let identity = match selected {
            Some(identity) => identity,
            None if !issuers.is_empty() && !name.is_empty() => {
                let mut cache = issued.lock().map_err(|_| SniError::ALERT_FATAL)?;
                if !cache.get(&name).is_some_and(|(created, _)| {
                    created.elapsed() < std::time::Duration::from_secs(3600)
                }) {
                    let identity = issuers
                        .iter()
                        .find_map(|issuer| {
                            load_certificate_files(issuer)
                                .and_then(|issuer| issue_certificate(&issuer, &name))
                                .and_then(|certificate| server_identity(&options, &certificate))
                                .ok()
                        })
                        .ok_or(SniError::ALERT_FATAL)?;
                    if cache.len() >= 256 {
                        cache.clear();
                    }
                    cache.insert(name.clone(), (std::time::Instant::now(), identity));
                }
                return ssl
                    .set_ssl_context(&cache[&name].1.context)
                    .map_err(|_| SniError::ALERT_FATAL);
            }
            None if !reject_unknown && !identities.is_empty() => &identities[0],
            None => return Err(SniError::ALERT_FATAL),
        };
        ssl.set_ssl_context(&identity.context)
            .map_err(|_| SniError::ALERT_FATAL)
    });
    Ok(Arc::new(AdvancedTlsServerConfig {
        context: context.build(),
    }))
}

pub(super) fn issue_certificate(issuer: &TlsCertificate, name: &str) -> io::Result<TlsCertificate> {
    use boring2::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        x509::{
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
            X509NameBuilder,
        },
    };
    let authority = certificates(&issuer.certificate)?.remove(0);
    let authority_key = private_key(&issuer.key)?;
    if !authority
        .public_key()
        .map_err(io::Error::other)?
        .public_eq(&authority_key)
    {
        return Err(invalid("TLS CA key does not match"));
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(io::Error::other)?;
    let key = PKey::from_ec_key(EcKey::generate(&group).map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    let mut subject = X509NameBuilder::new().map_err(io::Error::other)?;
    subject
        .append_entry_by_text("CN", name)
        .map_err(io::Error::other)?;
    let subject = subject.build();
    let mut cert = X509::builder().map_err(io::Error::other)?;
    cert.set_version(2).map_err(io::Error::other)?;
    let mut serial = [0; 16];
    getrandom::getrandom(&mut serial).map_err(|error| io::Error::other(error.to_string()))?;
    serial[0] &= 0x7f;
    let serial = BigNum::from_slice(&serial)
        .and_then(|n| n.to_asn1_integer())
        .map_err(io::Error::other)?;
    cert.set_serial_number(&serial).map_err(io::Error::other)?;
    cert.set_subject_name(&subject).map_err(io::Error::other)?;
    cert.set_issuer_name(authority.subject_name())
        .map_err(io::Error::other)?;
    cert.set_pubkey(&key).map_err(io::Error::other)?;
    let before = Asn1Time::days_from_now(0).map_err(io::Error::other)?;
    let after = Asn1Time::days_from_now(7).map_err(io::Error::other)?;
    cert.set_not_before(&before).map_err(io::Error::other)?;
    cert.set_not_after(&after).map_err(io::Error::other)?;
    let constraints = BasicConstraints::new()
        .critical()
        .build()
        .map_err(io::Error::other)?;
    cert.append_extension(&constraints)
        .map_err(io::Error::other)?;
    let usage = KeyUsage::new()
        .digital_signature()
        .build()
        .map_err(io::Error::other)?;
    cert.append_extension(&usage).map_err(io::Error::other)?;
    let usage = ExtendedKeyUsage::new()
        .server_auth()
        .build()
        .map_err(io::Error::other)?;
    cert.append_extension(&usage).map_err(io::Error::other)?;
    let mut names = SubjectAlternativeName::new();
    if name.parse::<std::net::IpAddr>().is_ok() {
        names.ip(name);
    } else {
        names.dns(name);
    }
    let extension = names
        .build(&cert.x509v3_context(Some(&authority), None))
        .map_err(io::Error::other)?;
    cert.append_extension(&extension)
        .map_err(io::Error::other)?;
    if authority_key.id() == boring2::pkey::Id::ED25519 {
        cert.sign_without_digest(&authority_key)
            .map_err(io::Error::other)?;
    } else {
        cert.sign(&authority_key, MessageDigest::sha256())
            .map_err(io::Error::other)?;
    }
    let mut certificate = String::from_utf8(cert.build().to_pem().map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    if issuer.build_chain {
        certificate.push_str(&issuer.certificate);
    }
    Ok(TlsCertificate {
        certificate,
        key: String::from_utf8(key.private_key_to_pem_pkcs8().map_err(io::Error::other)?)
            .map_err(io::Error::other)?,
        ..Default::default()
    })
}

impl AdvancedTlsServerConfig {
    pub(super) fn ssl(&self) -> io::Result<Ssl> {
        Ssl::new(&self.context).map_err(io::Error::other)
    }
}

fn hostname_matches(pattern: &str, name: &str) -> bool {
    if pattern == name {
        return true;
    }
    pattern.strip_prefix("*.").is_some_and(|suffix| {
        name.split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
    })
}

fn configure_server(
    context: &mut SslContextBuilder,
    options: &AdvancedTlsOptions,
) -> io::Result<()> {
    let alpn = wire_alpn(&options.alpn)?;
    if !alpn.is_empty() {
        context.set_alpn_select_callback(move |_ssl, mut client| {
            let selected = select_next_proto(&alpn, client).ok_or(AlpnError::ALERT_FATAL)?;
            while let Some((&len, rest)) = client.split_first() {
                let value = rest.get(..len as usize).ok_or(AlpnError::ALERT_FATAL)?;
                if value == selected {
                    return Ok(value);
                }
                client = &rest[len as usize..];
            }
            Err(AlpnError::ALERT_FATAL)
        });
    }
    if !options.ech_server_keys.is_empty() {
        let bytes = STANDARD
            .decode(&options.ech_server_keys)
            .map_err(io::Error::other)?;
        let mut bytes = bytes.as_slice();
        let mut keys = SslEchKeys::builder().map_err(io::Error::other)?;
        while !bytes.is_empty() {
            let private = length_prefixed(&mut bytes)?;
            let config = length_prefixed(&mut bytes)?;
            let private = HpkeKey::dhkem_x25519_sha256(private).map_err(io::Error::other)?;
            keys.add_key(true, config, private)
                .map_err(io::Error::other)?;
        }
        context
            .set_ech_keys(&keys.build())
            .map_err(io::Error::other)?;
    }
    Ok(())
}

fn length_prefixed<'a>(bytes: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let len = bytes
        .get(..2)
        .ok_or_else(|| invalid("truncated ECH keyset"))?;
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    let value = bytes
        .get(2..2 + len)
        .ok_or_else(|| invalid("truncated ECH keyset"))?;
    *bytes = &bytes[2 + len..];
    Ok(value)
}

fn common(builder: &mut SslContextBuilder, options: &AdvancedTlsOptions) -> io::Result<()> {
    let min = version(&options.min_version, SslVersion::TLS1_2)?;
    let max = version(&options.max_version, SslVersion::TLS1_3)?;
    let rank = |version| match version {
        SslVersion::TLS1 => 10,
        SslVersion::TLS1_1 => 11,
        SslVersion::TLS1_2 => 12,
        _ => 13,
    };
    if rank(min) > rank(max) {
        return Err(invalid("TLS minVersion exceeds maxVersion"));
    }
    builder
        .set_min_proto_version(Some(min))
        .map_err(io::Error::other)?;
    builder
        .set_max_proto_version(Some(max))
        .map_err(io::Error::other)?;
    if !options.enable_session_resumption {
        builder.set_options(SslOptions::NO_TICKET);
    }
    if !options.cipher_suites.is_empty() {
        builder
            .set_cipher_list(&cipher_names(&options.cipher_suites)?)
            .map_err(io::Error::other)?;
    }
    if !options.curve_preferences.is_empty() {
        let curves: Vec<_> = curve_preferences(&options.curve_preferences)?
            .into_iter()
            .map(|(_, curve)| curve)
            .collect();
        builder.set_curves(&curves).map_err(io::Error::other)?;
    }
    builder
        .set_alpn_protos(&wire_alpn(&options.alpn)?)
        .map_err(io::Error::other)?;
    if !options.master_key_log.is_empty() && options.master_key_log != "none" {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&options.master_key_log)?;
        let file = Mutex::new(file);
        builder.set_keylog_callback(move |_ssl, line| {
            if let Ok(mut file) = file.lock() {
                let _ = writeln!(file, "{line}");
            }
        });
    }
    Ok(())
}

type Group = (u16, SslCurve);

const MLKEM1024: u16 = 0x0202;

/// The groups BoringSSL implements, in Go's fixed preference order, with the
/// `curvePreferences` names Xray and BoringSSL give them. Go enables all but
/// MLKEM1024 by default.
const GROUPS: [(u16, SslCurve, &[&str]); 6] = [
    (0x11ec, SslCurve::X25519_MLKEM768, &["X25519MLKEM768"]),
    (MLKEM1024, SslCurve::MLKEM1024, &["MLKEM1024"]),
    (29, SslCurve::X25519, &["X25519"]),
    (
        23,
        SslCurve::SECP256R1,
        &["CurveP256", "P256", "P-256", "prime256v1"],
    ),
    (
        24,
        SslCurve::SECP384R1,
        &["CurveP384", "P384", "P-384", "secp384r1"],
    ),
    (
        25,
        SslCurve::SECP521R1,
        &["CurveP521", "P521", "P-521", "secp521r1"],
    ),
];

fn curve_preferences(names: &[String]) -> io::Result<Vec<Group>> {
    names
        .iter()
        .map(|name| {
            GROUPS
                .iter()
                .find(|(_, _, names)| names.iter().any(|known| known.eq_ignore_ascii_case(name)))
                .map(|&(id, curve, _)| (id, curve))
                .ok_or_else(|| invalid("unknown TLS curve"))
        })
        .collect()
}

/// The first of `groups` that the ClientHello both lists and sent a key share for.
fn key_share_group(groups: &[Group], supported: &[u8], shares: &[u8]) -> Option<SslCurve> {
    let supported = supported.get(2..)?.as_chunks::<2>().0;
    let mut offered = Vec::new();
    let mut rest = shares.get(2..)?;
    while let [a, b, c, d, tail @ ..] = rest {
        offered.push([*a, *b]);
        rest = tail.get(usize::from(u16::from_be_bytes([*c, *d]))..)?;
    }
    groups
        .iter()
        .find(|(id, _)| {
            let id = id.to_be_bytes();
            offered.contains(&id) && supported.contains(&id)
        })
        .map(|&(_, curve)| curve)
}

fn version(value: &str, default: SslVersion) -> io::Result<SslVersion> {
    match value {
        "" => Ok(default),
        "1.0" => Ok(SslVersion::TLS1),
        "1.1" => Ok(SslVersion::TLS1_1),
        "1.2" => Ok(SslVersion::TLS1_2),
        "1.3" => Ok(SslVersion::TLS1_3),
        _ => Err(invalid("TLS protocol version")),
    }
}

fn cipher_names(value: &str) -> io::Result<String> {
    value
        .split(':')
        .map(|name| {
            Ok(match name.trim() {
                "TLS_RSA_WITH_RC4_128_SHA" => "RC4-SHA",
                "TLS_RSA_WITH_3DES_EDE_CBC_SHA" => "DES-CBC3-SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA" => "AES128-SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA" => "AES256-SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA256" => "AES128-SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256" => "AES128-GCM-SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384" => "AES256-GCM-SHA384",
                "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" => "ECDHE-ECDSA-RC4-SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => "ECDHE-ECDSA-AES128-SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => "ECDHE-ECDSA-AES256-SHA",
                "TLS_ECDHE_RSA_WITH_RC4_128_SHA" => "ECDHE-RSA-RC4-SHA",
                "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" => "ECDHE-RSA-DES-CBC3-SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => "ECDHE-RSA-AES128-SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => "ECDHE-RSA-AES256-SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" => "ECDHE-ECDSA-AES128-SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" => "ECDHE-RSA-AES128-SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "ECDHE-ECDSA-AES128-GCM-SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "ECDHE-ECDSA-AES256-GCM-SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "ECDHE-RSA-AES128-GCM-SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "ECDHE-RSA-AES256-GCM-SHA384",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305" => "ECDHE-RSA-CHACHA20-POLY1305",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305" => "ECDHE-ECDSA-CHACHA20-POLY1305",
                _ => return Err(invalid("unknown TLS cipher suite")),
            })
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|names| names.join(":"))
}

fn certificates(pem: &str) -> io::Result<Vec<X509>> {
    let chain = X509::stack_from_pem(pem.as_bytes()).map_err(io::Error::other)?;
    if chain.is_empty() {
        return Err(invalid("empty TLS certificate chain"));
    }
    Ok(chain)
}

fn wire_alpn(protocols: &[String]) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(invalid("TLS ALPN length"));
        }
        wire.push(protocol.len() as u8);
        wire.extend_from_slice(protocol.as_bytes());
    }
    Ok(wire)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
