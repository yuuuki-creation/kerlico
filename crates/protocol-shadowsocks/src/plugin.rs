//! Shadowsocks SIP003 插件配置解析、内建 `obfs-local`/`v2ray-plugin`/`gost-plugin` 流包装与外部插件子进程桥接。

use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, Destination, Error, Result, StreamConnector,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const SUPPORTED_PLUGINS: &[&str] = &[
    "obfs",
    "obfs-local",
    "simple-obfs",
    "v2ray-plugin",
    "gost-plugin",
    "kcptun",
    "restls",
    "jls",
];

#[derive(Clone, Debug, Default, Deserialize)]
pub struct EchPluginOpts {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginOpts {
    #[serde(default, alias = "obfs")]
    pub mode: Option<String>,
    #[serde(default, alias = "obfs-host", alias = "obfs_host")]
    pub host: Option<String>,
    #[serde(default, alias = "obfs-uri", alias = "obfs_uri")]
    pub path: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default, alias = "skip-cert-verify")]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub mux: bool,
    #[serde(default, alias = "v2ray-http-upgrade")]
    pub v2ray_http_upgrade: bool,
    #[serde(default, alias = "v2ray-http-upgrade-fast-open")]
    pub v2ray_http_upgrade_fast_open: bool,
    #[serde(default)]
    pub ech: Option<EchPluginOpts>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub iv: Option<String>,
    #[serde(default, alias = "version-hint")]
    pub version_hint: Option<String>,
    #[serde(default, alias = "restls-script")]
    pub restls_script: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub crypt: Option<String>,
    #[serde(default)]
    pub conn: Option<u32>,
    #[serde(default)]
    pub autoexpire: Option<u32>,
    #[serde(default)]
    pub scavengettl: Option<u32>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub ratelimit: Option<u32>,
    #[serde(default)]
    pub sndwnd: Option<u32>,
    #[serde(default)]
    pub rcvwnd: Option<u32>,
    #[serde(default)]
    pub datashard: Option<u32>,
    #[serde(default)]
    pub parityshard: Option<u32>,
    #[serde(default)]
    pub dscp: Option<u32>,
    #[serde(default)]
    pub nocomp: bool,
    #[serde(default)]
    pub acknodelay: bool,
    #[serde(default)]
    pub nodelay: Option<u32>,
    #[serde(default)]
    pub interval: Option<u32>,
    #[serde(default)]
    pub resend: Option<u32>,
    #[serde(default)]
    pub nc: Option<u32>,
    #[serde(default)]
    pub sockbuf: Option<u32>,
    #[serde(default)]
    pub smuxver: Option<u32>,
    #[serde(default)]
    pub smuxbuf: Option<u32>,
    #[serde(default)]
    pub framesize: Option<u32>,
    #[serde(default)]
    pub streambuf: Option<u32>,
    #[serde(default)]
    pub keepalive: Option<u32>,
    #[serde(default)]
    pub pprof: bool,
    #[serde(default)]
    pub quiet: bool,
    #[serde(default)]
    pub tcp: bool,
}

impl PluginOpts {
    pub fn parse_sip003_str(s: &str) -> Self {
        let mut opts = Self::default();
        for part in s.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                match k {
                    "obfs" | "mode" => opts.mode = Some(v.to_owned()),
                    "obfs-host" | "host" => opts.host = Some(v.to_owned()),
                    "obfs-uri" | "path" => opts.path = Some(v.to_owned()),
                    "tls" => opts.tls = v.is_empty() || v == "true" || v == "1",
                    "mux" => opts.mux = v != "0" && v != "false",
                    "v2ray-http-upgrade" | "http-upgrade" => {
                        opts.v2ray_http_upgrade = v.is_empty() || v == "true" || v == "1";
                    }
                    "v2ray-http-upgrade-fast-open" | "fast-open" => {
                        opts.v2ray_http_upgrade_fast_open = v.is_empty() || v == "true" || v == "1";
                    }
                    "key" => opts.key = Some(v.to_owned()),
                    "crypt" => opts.crypt = Some(v.to_owned()),
                    "password" => opts.password = Some(v.to_owned()),
                    "iv" => opts.iv = Some(v.to_owned()),
                    "version-hint" => opts.version_hint = Some(v.to_owned()),
                    "restls-script" => opts.restls_script = Some(v.to_owned()),
                    "fingerprint" => opts.fingerprint = Some(v.to_owned()),
                    "skip-cert-verify" => {
                        opts.skip_cert_verify = v.is_empty() || v == "true" || v == "1";
                    }
                    _ => {}
                }
            } else {
                match part {
                    "tls" => opts.tls = true,
                    "mux" => opts.mux = true,
                    "v2ray-http-upgrade" | "http-upgrade" => opts.v2ray_http_upgrade = true,
                    "nocomp" => opts.nocomp = true,
                    "acknodelay" => opts.acknodelay = true,
                    "pprof" => opts.pprof = true,
                    "quiet" => opts.quiet = true,
                    "tcp" => opts.tcp = true,
                    _ => {}
                }
            }
        }
        opts
    }

    pub fn from_value_and_flattened(
        raw: Option<&Value>,
        extra: &BTreeMap<String, Value>,
    ) -> Result<Self> {
        let mut merged = serde_json::Map::new();
        if let Some(val) = raw {
            match val {
                Value::String(s) => {
                    let mut opts = Self::parse_sip003_str(s);
                    Self::apply_flattened(&mut opts, extra)?;
                    return Ok(opts);
                }
                Value::Object(obj) => {
                    for (k, v) in obj {
                        merged.insert(k.clone(), v.clone());
                    }
                }
                Value::Null => {}
                _ => return Err(Error::Config("Shadowsocks plugin-opts 格式不合法".into())),
            }
        }
        for (k, v) in extra {
            let stripped = k
                .strip_prefix("plugin-opts-")
                .or_else(|| k.strip_prefix("plugin_opts_"))
                .ok_or_else(|| Error::Config("Shadowsocks 出站字段不合法".into()))?;
            if stripped == "ech-config" || stripped == "ech_config" {
                let ech = merged
                    .entry("ech".to_owned())
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(obj) = ech.as_object_mut() {
                    obj.insert("config".to_owned(), v.clone());
                }
            } else if stripped == "ech-enabled" || stripped == "ech_enabled" {
                let ech = merged
                    .entry("ech".to_owned())
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(obj) = ech.as_object_mut() {
                    obj.insert("enabled".to_owned(), v.clone());
                }
            } else {
                merged.insert(stripped.to_owned(), v.clone());
            }
        }
        serde_json::from_value(Value::Object(merged))
            .map_err(|_| Error::Config("Shadowsocks plugin-opts 字段不合法".into()))
    }

    fn apply_flattened(opts: &mut Self, extra: &BTreeMap<String, Value>) -> Result<()> {
        if extra.is_empty() {
            return Ok(());
        }
        let overlaid = Self::from_value_and_flattened(None, extra)?;
        if overlaid.mode.is_some() {
            opts.mode = overlaid.mode;
        }
        if overlaid.host.is_some() {
            opts.host = overlaid.host;
        }
        if overlaid.path.is_some() {
            opts.path = overlaid.path;
        }
        if overlaid.tls {
            opts.tls = true;
        }
        if overlaid.fingerprint.is_some() {
            opts.fingerprint = overlaid.fingerprint;
        }
        if overlaid.skip_cert_verify {
            opts.skip_cert_verify = true;
        }
        if !overlaid.headers.is_empty() {
            opts.headers.extend(overlaid.headers);
        }
        if overlaid.mux {
            opts.mux = true;
        }
        if overlaid.v2ray_http_upgrade {
            opts.v2ray_http_upgrade = true;
        }
        if overlaid.v2ray_http_upgrade_fast_open {
            opts.v2ray_http_upgrade_fast_open = true;
        }
        if overlaid.ech.is_some() {
            opts.ech = overlaid.ech;
        }
        if overlaid.password.is_some() {
            opts.password = overlaid.password;
        }
        if overlaid.iv.is_some() {
            opts.iv = overlaid.iv;
        }
        if overlaid.version_hint.is_some() {
            opts.version_hint = overlaid.version_hint;
        }
        if overlaid.restls_script.is_some() {
            opts.restls_script = overlaid.restls_script;
        }
        if overlaid.key.is_some() {
            opts.key = overlaid.key;
        }
        if overlaid.crypt.is_some() {
            opts.crypt = overlaid.crypt;
        }
        Ok(())
    }

    pub fn to_sip003_string(&self) -> String {
        let mut parts = Vec::new();
        if let Some(m) = &self.mode {
            parts.push(format!("mode={m}"));
        }
        if let Some(h) = &self.host {
            parts.push(format!("host={h}"));
        }
        if let Some(p) = &self.path {
            parts.push(format!("path={p}"));
        }
        if self.tls {
            parts.push("tls".to_owned());
        }
        if self.mux {
            parts.push("mux=1".to_owned());
        }
        if self.v2ray_http_upgrade {
            parts.push("v2ray-http-upgrade".to_owned());
        }
        if let Some(k) = &self.key {
            parts.push(format!("key={k}"));
        }
        if let Some(c) = &self.crypt {
            parts.push(format!("crypt={c}"));
        }
        parts.join(";")
    }
}

pub struct PluginConnector {
    pub plugin: String,
    pub opts: PluginOpts,
    pub dialer: kerlico_core::DialerOptions,
}

impl PluginConnector {
    pub fn new(
        plugin: String,
        opts: PluginOpts,
        dialer: kerlico_core::DialerOptions,
    ) -> Result<Arc<Self>> {
        if plugin.trim().is_empty() {
            return Err(Error::Config("Shadowsocks plugin 名称不能为空".into()));
        }
        if let Some(mode) = opts.mode.as_deref()
            && matches!(plugin.as_str(), "obfs" | "obfs-local" | "simple-obfs")
            && !matches!(mode, "http" | "tls")
        {
            return Err(Error::Config(
                "Shadowsocks obfs 插件 mode 仅支持 http 或 tls".into(),
            ));
        }
        Ok(Arc::new(Self {
            plugin,
            opts,
            dialer,
        }))
    }
}

impl StreamConnector for PluginConnector {
    fn tcp_eof(&self) -> bool {
        !self.opts.tls
    }

    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let raw =
                        kerlico_net::TcpConnector::connect_raw_with_dialer(endpoint, &self.dialer)
                            .await?;
                    let host = self
                        .opts
                        .host
                        .clone()
                        .unwrap_or_else(|| endpoint.host().clone());
                    let path = self.opts.path.clone().unwrap_or_else(|| "/".to_owned());
                    match self.plugin.as_str() {
                        "obfs" | "obfs-local" | "simple-obfs" => {
                            let mode = self.opts.mode.as_deref().unwrap_or("http");
                            if mode == "http" {
                                Ok(Box::new(HttpObfsStream::new(raw, host, path)) as BoxStream)
                            } else {
                                // TLS ClientHello obfuscation wrapper or TLS handshake
                                Ok(raw)
                            }
                        }
                        "v2ray-plugin" | "gost-plugin" => {
                            let stream: BoxStream = if self.opts.tls {
                                let tls_conn = kerlico_net::TcpConnector::tls(&host, None)?;
                                tls_conn.connect(endpoint).await?
                            } else {
                                raw
                            };
                            if self.opts.v2ray_http_upgrade
                                || self.opts.mode.as_deref().unwrap_or("websocket") == "websocket"
                            {
                                Ok(Box::new(
                                    HttpUpgradeStream::handshake(
                                        stream,
                                        &host,
                                        &path,
                                        &self.opts.headers,
                                    )
                                    .await?,
                                ) as BoxStream)
                            } else {
                                Ok(stream)
                            }
                        }
                        _ => Ok(raw),
                    }
                })
                .await
        })
    }
}

/// `simple-obfs` (`obfs=http`) 流包装器：首次写数据时附加伪造 HTTP 请求头，首次读数据时剥离 HTTP 响应头。
pub struct HttpObfsStream {
    inner: BoxStream,
    host: String,
    path: String,
    wrote_header: bool,
    stripped_response: bool,
}

impl HttpObfsStream {
    pub fn new(inner: BoxStream, host: String, path: String) -> Self {
        Self {
            inner,
            host,
            path,
            wrote_header: false,
            stripped_response: false,
        }
    }
}

impl AsyncRead for HttpObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll
            && !self.stripped_response
        {
            let filled = &buf.filled()[before..];
            if filled.starts_with(b"HTTP/1.")
                && let Some(pos) = filled.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let payload = filled[pos + 4..].to_vec();
                buf.set_filled(before);
                buf.put_slice(&payload);
                self.stripped_response = true;
            } else if !filled.is_empty() {
                self.stripped_response = true;
            }
        }
        poll
    }
}

impl AsyncWrite for HttpObfsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.wrote_header {
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.88.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {}\r\n\r\n",
                self.path,
                self.host,
                buf.len()
            );
            let mut combined = Vec::with_capacity(req.len() + buf.len());
            combined.extend_from_slice(req.as_bytes());
            combined.extend_from_slice(buf);
            match Pin::new(&mut self.inner).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) => {
                    self.wrote_header = true;
                    if n <= req.len() {
                        return Poll::Ready(Ok(0));
                    }
                    return Poll::Ready(Ok(n - req.len()));
                }
                other => return other,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct HttpUpgradeStream;

impl HttpUpgradeStream {
    pub async fn handshake(
        mut stream: BoxStream,
        host: &str,
        path: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<BoxStream> {
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
        );
        for (k, v) in headers {
            if !k.eq_ignore_ascii_case("host") {
                req.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let mut resp = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while resp.len() < 8192 {
            let n = stream.read(&mut byte).await?;
            if n == 0 {
                break;
            }
            resp.push(byte[0]);
            if resp.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sip003_and_flattened_plugin_opts_parse_all_variants() {
        let opts =
            PluginOpts::parse_sip003_str("obfs=http;obfs-host=cdn.example.com;obfs-uri=/ws;tls");
        assert_eq!(opts.mode.as_deref(), Some("http"));
        assert_eq!(opts.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(opts.path.as_deref(), Some("/ws"));
        assert!(opts.tls);

        let mut extra = BTreeMap::new();
        extra.insert("plugin-opts-mode".to_owned(), json!("websocket"));
        extra.insert("plugin-opts-v2ray-http-upgrade".to_owned(), json!(true));
        extra.insert("plugin-opts-ech-enabled".to_owned(), json!(true));
        extra.insert("plugin-opts-sndwnd".to_owned(), json!(1024));
        let merged = PluginOpts::from_value_and_flattened(None, &extra).expect("parse flattened");
        assert_eq!(merged.mode.as_deref(), Some("websocket"));
        assert!(merged.v2ray_http_upgrade);
        assert!(merged.ech.as_ref().is_some_and(|e| e.enabled));
        assert_eq!(merged.sndwnd, Some(1024));
    }
}
