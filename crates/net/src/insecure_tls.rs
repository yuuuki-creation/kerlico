//! 跳过服务端证书校验的客户端 TLS，对应 Mihomo `skip-cert-verify` 与 sing-box `tls.insecure`。
use crate::TcpConnector;
use kerlico_core::{Error, Language, Result};
use rustls::{
    ClientConfig, client::danger::ServerCertVerifier, crypto::CryptoProvider, pki_types::ServerName,
};
use std::sync::Arc;
use tokio_rustls::TlsConnector;

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
    /// 构造发送 `server_name` 作为 SNI、但不校验服务端证书的 TLS 连接器，不拨号。
    pub fn tls_insecure(server_name: &str, dialer: kerlico_core::DialerOptions) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Config("TLS 版本不可用".into()))?
            .dangerous()
            .with_custom_certificate_verifier(insecure_verifier(provider))
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| Error::Config("TLS 服务端名称不合法".into()))?;
        Ok(Self {
            tls: Some((TlsConnector::from(Arc::new(config)), name)),
            dialer,
        })
    }
}
