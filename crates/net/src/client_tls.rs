//! 出站客户端 TLS：证书校验方式（系统根加自定义 CA，或对应 Mihomo `skip-cert-verify` /
//! sing-box `tls.insecure` 的跳过校验）与对应 Mihomo `client-fingerprint` 的 uTLS ClientHello 指纹。
use crate::TcpConnector;
use kerlico_core::{Error, Language, Result};
use rustls::{
    ClientConfig, RootCertStore, client::danger::ServerCertVerifier, crypto::CryptoProvider,
    pki_types::ServerName,
};
use std::{io::Cursor, sync::Arc};
use tokio_rustls::TlsConnector;

/// 一个出站的客户端 TLS 选项。`fingerprint` 为 `None` 时发送 rustls 原生 ClientHello。
#[derive(Clone, Copy, Debug)]
pub struct TlsClientOptions<'a> {
    /// 出现在提示里的协议名。
    pub protocol: &'a str,
    pub server_name: &'a str,
    pub ca_pem: Option<&'a str>,
    pub insecure: bool,
    /// xray-transport uTLS 档案名，如 `chrome`、`firefox`、`random`。
    pub fingerprint: Option<&'a str>,
    pub alpn: &'a [String],
}

impl TlsClientOptions<'_> {
    /// 构造 rustls 客户端配置；指纹无法在本实现完成握手时报错。
    pub fn client_config(&self) -> Result<ClientConfig> {
        if self.insecure {
            warn_insecure_tls(self.protocol);
        }
        let custom_ca_der = match self.ca_pem {
            Some(pem) => {
                let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                if certs.is_empty() {
                    return Err(Error::Config("CA PEM 不包含证书".into()));
                }
                certs.into_iter().map(|cert| cert.to_vec()).collect()
            }
            None => Vec::new(),
        };
        if let Some(fingerprint) = self.fingerprint {
            return xray_transport::build_custom_tls_client_config(
                &xray_transport::CustomTlsClientOptions {
                    allow_insecure: self.insecure,
                    use_system_ca: true,
                    custom_ca_der,
                    alpn: self.alpn.to_vec(),
                    fingerprint: Some(fingerprint.to_owned()),
                    ..Default::default()
                },
            )
            .map_err(|error| Error::Config(format!("TLS 指纹 {fingerprint} 不可用：{error}")));
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Config("TLS 版本不可用".into()))?;
        let mut config = if self.insecure {
            builder
                .dangerous()
                .with_custom_certificate_verifier(insecure_verifier(provider))
                .with_no_client_auth()
        } else {
            let mut roots =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for der in custom_ca_der {
                roots
                    .add(der.into())
                    .map_err(|_| Error::Config("CA 证书不合法".into()))?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        config.alpn_protocols = self.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        config.resumption = rustls::client::Resumption::disabled();
        Ok(config)
    }
}

/// 出站编译期在 stderr 提示一次：该出站不校验服务端证书。
pub fn warn_insecure_tls(protocol: &str) {
    let warning = match Language::default() {
        Language::ZhCn => {
            format!("警告：{protocol} 出站已跳过 TLS 证书校验，连接可被中间人截获")
        }
        Language::En => format!(
            "warning: {protocol} outbound skips TLS certificate verification; \
             the connection is open to man-in-the-middle interception"
        ),
    };
    eprintln!("{warning}");
}

/// xray-transport `allowInsecure` 共用的免证书校验器。
///
/// 只跳过证书链、有效期与名称校验；握手签名仍按 `provider` 的算法校验。
/// 调用方保留自身的协议版本、密码提供方与 ALPN。
pub fn insecure_verifier(provider: Arc<CryptoProvider>) -> Arc<dyn ServerCertVerifier> {
    xray_transport::no_certificate_verifier(provider)
}

impl TcpConnector {
    /// 按 [`TlsClientOptions`] 构造 TLS 连接器，不拨号。
    pub fn tls_client(
        options: &TlsClientOptions<'_>,
        dialer: kerlico_core::DialerOptions,
    ) -> Result<Self> {
        let config = options.client_config()?;
        let name = ServerName::try_from(options.server_name.to_owned())
            .map_err(|_| Error::Config("TLS 服务端名称不合法".into()))?;
        Ok(Self {
            tls: Some((TlsConnector::from(Arc::new(config)), name)),
            dialer,
        })
    }
}
