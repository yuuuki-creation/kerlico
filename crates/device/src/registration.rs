//! 固定 wgcf v2.3.0 的逆向注册 profile；正常证书验证，不使用系统代理。
use crate::{
    NativeCapabilities, NativeFamily, RegistrationPolicy,
    storage::{Record, StateStore},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Destination, DialerOptions, Error, Result};
use rustls::{
    CipherSuite, ClientConfig, NamedGroup, RootCertStore,
    client::{
        ClientHelloCipherSuites, ClientHelloContext, ClientHelloCustomizer,
        ClientHelloExactExtension, ClientHelloExactExtensions, ClientHelloExtensionOrder,
        ClientHelloExtensionPlan, ClientHelloForcedExtensions, ClientHelloPlan,
        ClientHelloSessionId, ClientHelloSupportedGroups,
    },
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct WarpHello;
impl ClientHelloCustomizer for WarpHello {
    fn build_client_hello_plan(
        &self,
        _: ClientHelloContext<'_>,
    ) -> std::result::Result<Option<ClientHelloPlan>, rustls::Error> {
        Ok(Some(
            ClientHelloPlan::new()
                .with_session_id(ClientHelloSessionId::try_from(vec![])?)
                .with_cipher_suites(ClientHelloCipherSuites::try_from(vec![
                    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                ])?)
                .with_supported_groups(ClientHelloSupportedGroups::try_from(vec![
                    NamedGroup::X25519,
                    NamedGroup::secp256r1,
                    NamedGroup::secp384r1,
                ])?)
                .with_extensions(ClientHelloExtensionPlan::try_from(vec![43])?)
                .with_forced_extensions(
                    ClientHelloForcedExtensions::new()
                        .with_renegotiation_info_empty()
                        .with_session_ticket_request(),
                )
                .with_exact_extensions(ClientHelloExactExtensions::try_from(vec![
                    ClientHelloExactExtension::new(5, vec![1, 0, 0, 0, 0])?,
                    ClientHelloExactExtension::new(
                        13,
                        vec![0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1],
                    )?,
                ])?)
                .with_extension_order(ClientHelloExtensionOrder::try_from(vec![
                    0, 23, 65281, 10, 11, 35, 16, 5, 13,
                ])?),
        ))
    }
}
fn invalid() -> Error {
    Error::Config("WARP注册响应不符合固定WireGuard profile".into())
}
fn tls() -> Result<ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        )
    });
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|_| invalid())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.client_hello_customizer = Some(Arc::new(WarpHello));
    Ok(config)
}
async fn register(public_key: &str, dialer: &DialerOptions) -> Result<Value> {
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| invalid())?;
    let body = serde_json::to_vec(&json!({ "fcm_token":"", "install_id":"", "key":public_key, "locale":"en_US", "model":"PC", "tos":timestamp, "serial_number":"", "os_version":"16.0.0", "key_type":"curve25519", "tunnel_type":"wireguard" })).map_err(|_| invalid())?;
    let stream = dialer
        .connect(&Destination::new("api.cloudflareclient.com", 443)?)
        .await?;
    let name = rustls::pki_types::ServerName::try_from("api.cloudflareclient.com").unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(Arc::new(tls()?))
        .connect(name, stream)
        .await?;
    let request = format!(
        "POST /v0a5641/reg HTTP/1.1\r\nHost: api.cloudflareclient.com\r\nUser-Agent: 1.1.1.1/6.38.9-5641 (Android 16.0.0)\r\nCF-Client-Version: a-6.38.9-5641\r\nContent-Type: application/json; charset=UTF-8\r\nConnection: Keep-Alive\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 16384 {
            return Err(invalid());
        }
        header.push(stream.read_u8().await?);
    }
    let header = std::str::from_utf8(&header).map_err(|_| invalid())?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(invalid)?
        .split_whitespace()
        .nth(1)
        .ok_or_else(invalid)?;
    if status.len() != 3 || !status.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(invalid());
    }
    if status != "200" {
        return Err(Error::Config(format!(
            "WARP注册HTTP状态{status}；保留注册意图，不自动重试"
        )));
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.trim().parse::<usize>().map_err(|_| invalid())?);
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err(invalid());
                }
                chunked = true;
            }
        }
    }
    let mut response = zeroize::Zeroizing::new(Vec::new());
    if chunked {
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                if line.len() > 128 {
                    return Err(invalid());
                }
                line.push(stream.read_u8().await?);
            }
            let line = std::str::from_utf8(&line).map_err(|_| invalid())?.trim();
            let count = usize::from_str_radix(line.split(';').next().unwrap(), 16)
                .map_err(|_| invalid())?;
            if count == 0 {
                break;
            }
            if response.len().saturating_add(count) > 131072 {
                return Err(invalid());
            }
            let start = response.len();
            response.resize(start + count, 0);
            stream.read_exact(&mut response[start..]).await?;
            if stream.read_u16().await? != 0x0d0a {
                return Err(invalid());
            }
        }
    } else {
        let count = length.ok_or_else(invalid)?;
        if count > 131072 {
            return Err(invalid());
        }
        response.resize(count, 0);
        stream.read_exact(&mut response).await?;
    }
    serde_json::from_slice(&response).map_err(|_| invalid())
}
fn text<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(invalid)
}
fn key(value: &str) -> Result<()> {
    let bytes = STANDARD.decode(value).map_err(|_| invalid())?;
    if bytes.len() != 32 || bytes == [0; 32] || STANDARD.encode(&bytes) != value {
        return Err(invalid());
    }
    Ok(())
}
fn profile(record: &Record, capabilities: NativeCapabilities) -> Result<Value> {
    let response = record.response.as_ref().ok_or_else(invalid)?;
    let private_bytes: [u8; 32] = STANDARD
        .decode(&record.private_key)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let expected_public = STANDARD.encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_bytes)).as_bytes(),
    );
    if text(response, "/key")? != expected_public {
        return Err(Error::Config(
            "WARP现有profile与持久私钥不匹配，禁止注册或启动".into(),
        ));
    }
    let _token = text(response, "/token")?;
    let _id = text(response, "/id")?;
    if text(response, "/tunnel_type")? != "wireguard"
        || text(response, "/key_type")? != "curve25519"
    {
        return Err(invalid());
    }
    let addresses = [
        text(response, "/config/interface/addresses/v4")?
            .parse::<IpAddr>()
            .map_err(|_| invalid())?,
        text(response, "/config/interface/addresses/v6")?
            .parse::<IpAddr>()
            .map_err(|_| invalid())?,
    ];
    if !addresses[0].is_ipv4() || !addresses[1].is_ipv6() {
        return Err(invalid());
    }
    let peers = response
        .pointer("/config/peers")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if peers.len() != 1 {
        return Err(invalid());
    }
    let peer = &peers[0];
    let public_key = text(peer, "/public_key")?;
    key(public_key)?;
    // 官方 WireGuard 线格式 reserved 保持0；wgcf 生成标准WG配置亦未注入 client_id。
    let client = STANDARD
        .decode(text(response, "/config/client_id")?)
        .map_err(|_| invalid())?;
    if client.len() != 3 {
        return Err(invalid());
    }
    let endpoint = peer.get("endpoint").ok_or_else(invalid)?;
    let selected = if capabilities.ipv4 == NativeFamily::Routed {
        text(endpoint, "/v4")?
    } else if capabilities.ipv6 == NativeFamily::Routed {
        text(endpoint, "/v6")?
    } else {
        return Err(Error::Unsupported("WARP需要至少一个原生载体地址族"));
    };
    let ip = selected
        .parse::<SocketAddr>()
        .map(|a| a.ip())
        .or_else(|_| selected.parse::<IpAddr>())
        .map_err(|_| invalid())?;
    if (capabilities.ipv4 == NativeFamily::Routed) != ip.is_ipv4() {
        return Err(invalid());
    }
    let port = endpoint
        .get("ports")
        .and_then(Value::as_array)
        .and_then(|ports| ports.first())
        .and_then(Value::as_u64)
        .unwrap_or(2408);
    if port == 0 || port > 65535 {
        return Err(invalid());
    }
    let options = json!({"tunnel":{"private_key":record.private_key,"addresses":addresses,"mtu":1280}, "endpoint":{"host":ip.to_string(),"port":port},"peer":{"public_key":public_key,"allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive":25}});
    // 工厂完整校验密钥、端点、地址和资源边界；保存前先执行无网络编译。
    use kerlico_config::OutboundFactory;
    kerlico_wireguard::WireGuardFactory.compile(&options)?;
    Ok(options)
}
pub(crate) fn existing_profile(
    store: &StateStore,
    capabilities: NativeCapabilities,
) -> Result<Value> {
    let record = store.read()?.ok_or(Error::Config(
        "WARP复用模式要求已有profile，禁止自动注册".into(),
    ))?;
    if record.response.is_none() {
        return Err(Error::Config(
            "WARP已有结果未知的注册意图，禁止自动重复注册".into(),
        ));
    }
    profile(&record, capabilities)
}
pub(crate) async fn prepare(
    store: &StateStore,
    capabilities: NativeCapabilities,
    policy: RegistrationPolicy,
    dialer: &DialerOptions,
) -> Result<Value> {
    prepare_with(store, capabilities, policy, |public| async move {
        register(&public, dialer).await
    })
    .await
}
async fn prepare_with<F, Fut>(
    store: &StateStore,
    capabilities: NativeCapabilities,
    policy: RegistrationPolicy,
    request: F,
) -> Result<Value>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    if policy == RegistrationPolicy::ExistingOnly || store.read()?.is_some() {
        return existing_profile(store, capabilities);
    }
    register_once(store, capabilities, request).await
}
/// 仅空状态可进入的单次注册入口；既有profile验证没有通往此入口的分支。
async fn register_once<F, Fut>(
    store: &StateStore,
    capabilities: NativeCapabilities,
    request: F,
) -> Result<Value>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    if store.read()?.is_some() {
        return Err(Error::Config("WARP单次注册入口要求空状态".into()));
    }
    let private = x25519_dalek::StaticSecret::random_from_rng(rand::thread_rng());
    let public = x25519_dalek::PublicKey::from(&private);
    let mut record = Record {
        private_key: STANDARD.encode(private.to_bytes()),
        response: None,
    };
    store.save(&record)?;
    let response = request(STANDARD.encode(public.as_bytes())).await?;
    record.response = Some(response);
    // 先保留真实返回，校验失败也不丢失已创建身份；启动始终重新完整校验。
    store.save(&record)?;
    profile(&record, capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[tokio::test]
    async fn missing_or_mismatched_reuse_profile_performs_zero_registration_requests() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let store = StateStore::open(&directory.path().join("device")).unwrap();
        let calls = AtomicUsize::new(0);
        let capabilities = NativeCapabilities {
            ipv4: NativeFamily::Routed,
            ipv6: NativeFamily::Missing,
        };
        let result = prepare_with(
            &store,
            capabilities,
            RegistrationPolicy::ExistingOnly,
            |_| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(invalid())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(store.read().unwrap().is_none());
        let mut response = json!({"key":"not-the-persisted-public-key"});
        store
            .save(&Record {
                private_key: STANDARD.encode([1; 32]),
                response: Some(response.take()),
            })
            .unwrap();
        let result = prepare_with(
            &store,
            capabilities,
            RegistrationPolicy::ExistingOnly,
            |_| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(invalid())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    fn emitted_extensions(config: ClientConfig) -> std::result::Result<Vec<u16>, rustls::Error> {
        let mut connection = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("api.cloudflareclient.com").unwrap(),
        )?;
        let mut records = Vec::new();
        connection.write_tls(&mut records).unwrap();
        let hello = &records[5..];
        let mut index = 39 + hello[38] as usize;
        let count = u16::from_be_bytes([hello[index], hello[index + 1]]) as usize;
        index += 2 + count;
        let count = hello[index] as usize;
        index += 1 + count + 2;
        let mut extensions = Vec::new();
        while index < hello.len() {
            let kind = u16::from_be_bytes([hello[index], hello[index + 1]]);
            let count = u16::from_be_bytes([hello[index + 2], hello[index + 3]]) as usize;
            extensions.push(kind);
            index += 4 + count;
        }
        Ok(extensions)
    }
    #[derive(Debug)]
    struct DisableVersions;
    impl ClientHelloCustomizer for DisableVersions {
        fn build_client_hello_plan(
            &self,
            _: ClientHelloContext<'_>,
        ) -> std::result::Result<Option<ClientHelloPlan>, rustls::Error> {
            Ok(Some(ClientHelloPlan::new().with_extensions(
                ClientHelloExtensionPlan::try_from(vec![43])?,
            )))
        }
    }
    #[test]
    fn default_tls12_and_tls13_keep_versions_and_tls13_cannot_disable_it() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[version])
                .unwrap()
                .with_root_certificates(RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                ))
                .with_no_client_auth();
            assert!(emitted_extensions(config.clone()).unwrap().contains(&43));
            let mut custom = config;
            custom.client_hello_customizer = Some(Arc::new(DisableVersions));
            if version.version == rustls::ProtocolVersion::TLSv1_3 {
                assert!(emitted_extensions(custom).is_err());
            } else {
                assert!(!emitted_extensions(custom).unwrap().contains(&43));
            }
        }
    }
    #[test]
    fn profile_does_not_enable_sha1_validation_or_accept_invalid_certificates() {
        use rustls::client::danger::ServerCertVerifier;
        let config = tls().unwrap();
        assert!(
            !config
                .crypto_provider()
                .signature_verification_algorithms
                .supported_schemes()
                .contains(&rustls::SignatureScheme::RSA_PKCS1_SHA1)
        );
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            )),
            config.crypto_provider().clone(),
        )
        .build()
        .unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &rustls::pki_types::CertificateDer::from(vec![0]),
                    &[],
                    &rustls::pki_types::ServerName::try_from("api.cloudflareclient.com").unwrap(),
                    &[],
                    rustls::pki_types::UnixTime::now()
                )
                .is_err()
        );
    }
    #[test]
    fn fixed_wgcf_android_tls12_hello_has_exact_non_random_fields() {
        let mut connection = rustls::ClientConnection::new(
            Arc::new(tls().unwrap()),
            rustls::pki_types::ServerName::try_from("api.cloudflareclient.com").unwrap(),
        )
        .unwrap();
        let mut records = Vec::new();
        connection.write_tls(&mut records).unwrap();
        assert_eq!(&records[..3], &[22, 3, 1]);
        let hello = &records[5..];
        assert_eq!(hello[0], 1);
        assert_eq!(&hello[4..6], &[3, 3]);
        assert_eq!(hello[38], 0);
        let mut index = 39;
        let length = u16::from_be_bytes([hello[index], hello[index + 1]]) as usize;
        index += 2;
        assert_eq!(&hello[index..index + length], &[0xc0, 0x2c, 0xc0, 0x30]);
        index += length;
        assert_eq!(&hello[index..index + 2], &[1, 0]);
        index += 2;
        let length = u16::from_be_bytes([hello[index], hello[index + 1]]) as usize;
        index += 2;
        assert_eq!(hello.len(), index + length);
        let mut extensions = Vec::new();
        while index < hello.len() {
            let kind = u16::from_be_bytes([hello[index], hello[index + 1]]);
            let size = u16::from_be_bytes([hello[index + 2], hello[index + 3]]) as usize;
            index += 4;
            let payload = &hello[index..index + size];
            match kind {
                0 => {
                    let mut expected = vec![0, 27, 0, 0, 24];
                    expected.extend_from_slice(b"api.cloudflareclient.com");
                    assert_eq!(payload, expected);
                }
                10 => assert_eq!(payload, &[0, 6, 0, 29, 0, 23, 0, 24]),
                11 => assert_eq!(payload, &[1, 0]),
                35 | 23 => assert!(payload.is_empty()),
                65281 => assert_eq!(payload, &[0]),
                5 => assert_eq!(payload, &[1, 0, 0, 0, 0]),
                16 => {
                    let mut expected = vec![0, 9, 8];
                    expected.extend_from_slice(b"http/1.1");
                    assert_eq!(payload, expected);
                }
                13 => assert_eq!(
                    payload,
                    &[0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1]
                ),
                _ => (),
            }
            extensions.push(kind);
            index += size;
        }
        assert_eq!(extensions, vec![0, 23, 65281, 10, 11, 35, 16, 5, 13]);
    }
}
