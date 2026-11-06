//! Shadowsocks SIP003 插件：配置解析与内建 `obfs-local`（http 模式）、`v2ray-plugin`/`gost-plugin`（WebSocket 与 HTTP Upgrade）客户端。
//!
//! 未实现的插件名与插件参数在配置编译期报错，不会退回明文 TCP。

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, Destination, Error, Result, StreamConnector,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Error as WsError, Message, client::IntoClientRequest, protocol::WebSocketConfig,
    },
};

pub const SUPPORTED_PLUGINS: &[&str] = &[
    "obfs",
    "obfs-local",
    "simple-obfs",
    "v2ray-plugin",
    "gost-plugin",
];

const MAX_HTTP_HEAD: usize = 8192;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct EchPluginOpts {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<String>,
}

/// 插件参数的原始形态；`Plugin::parse` 把它收窄为已实现的组合。
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
}

fn sip003_flag(v: &str) -> bool {
    !matches!(v, "0" | "false")
}

impl PluginOpts {
    fn sip003_to_map(s: &str) -> Result<serde_json::Map<String, Value>> {
        let mut map = serde_json::Map::new();
        for part in s.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = part
                .split_once('=')
                .map_or((part, ""), |(k, v)| (k.trim(), v.trim()));
            let (key, value) = match k {
                "obfs" | "mode" => ("mode", Value::from(v)),
                "obfs-host" | "host" => ("host", Value::from(v)),
                "obfs-uri" | "path" => ("path", Value::from(v)),
                "fingerprint" => ("fingerprint", Value::from(v)),
                "tls"
                | "mux"
                | "skip-cert-verify"
                | "v2ray-http-upgrade"
                | "v2ray-http-upgrade-fast-open" => (k, Value::from(sip003_flag(v))),
                "http-upgrade" => ("v2ray-http-upgrade", Value::from(sip003_flag(v))),
                _ => {
                    return Err(Error::Config(format!(
                        "Shadowsocks plugin-opts 参数 `{k}` 未实现"
                    )));
                }
            };
            map.insert(key.to_owned(), value);
        }
        Ok(map)
    }

    pub fn from_value_and_flattened(
        raw: Option<&Value>,
        extra: &BTreeMap<String, Value>,
    ) -> Result<Self> {
        let mut merged = match raw {
            Some(Value::String(s)) => Self::sip003_to_map(s)?,
            Some(Value::Object(obj)) => obj.clone(),
            Some(Value::Null) | None => serde_json::Map::new(),
            Some(_) => return Err(Error::Config("Shadowsocks plugin-opts 格式不合法".into())),
        };
        for (k, v) in extra {
            let stripped = k
                .strip_prefix("plugin-opts-")
                .or_else(|| k.strip_prefix("plugin_opts_"))
                .ok_or_else(|| Error::Config("Shadowsocks 出站字段不合法".into()))?;
            let ech_field = match stripped {
                "ech-config" | "ech_config" => Some("config"),
                "ech-enabled" | "ech_enabled" => Some("enabled"),
                _ => None,
            };
            if let Some(field) = ech_field {
                let ech = merged
                    .entry("ech".to_owned())
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(obj) = ech.as_object_mut() {
                    obj.insert(field.to_owned(), v.clone());
                }
            } else {
                merged.insert(stripped.to_owned(), v.clone());
            }
        }
        serde_json::from_value(Value::Object(merged))
            .map_err(|e| Error::Config(format!("Shadowsocks plugin-opts 不合法或未实现：{e}")))
    }

    /// 取了非默认值的参数名，用于按插件拒绝未实现的参数。
    fn set_fields(&self) -> Vec<&'static str> {
        let mut set = Vec::new();
        for (name, on) in [
            ("mode", self.mode.is_some()),
            ("host", self.host.is_some()),
            ("path", self.path.is_some()),
            ("tls", self.tls),
            ("fingerprint", self.fingerprint.is_some()),
            ("skip-cert-verify", self.skip_cert_verify),
            ("headers", !self.headers.is_empty()),
            ("mux", self.mux),
            ("v2ray-http-upgrade", self.v2ray_http_upgrade),
            (
                "v2ray-http-upgrade-fast-open",
                self.v2ray_http_upgrade_fast_open,
            ),
            (
                "ech",
                self.ech
                    .as_ref()
                    .is_some_and(|e| e.enabled || e.config.is_some()),
            ),
        ] {
            if on {
                set.push(name);
            }
        }
        set
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2rayTransport {
    WebSocket,
    HttpUpgrade,
}

/// 已实现的插件组合；只能由 `Plugin::parse` 构造。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plugin {
    ObfsHttp {
        host: Option<String>,
        path: String,
    },
    V2ray {
        transport: V2rayTransport,
        tls: bool,
        skip_cert_verify: bool,
        host: Option<String>,
        path: String,
        headers: BTreeMap<String, String>,
    },
}

impl Plugin {
    pub fn parse(name: &str, opts: PluginOpts) -> Result<Self> {
        let name = name.trim();
        let (is_obfs, allowed): (bool, &[&str]) = match name {
            "obfs" | "obfs-local" | "simple-obfs" => (true, &["mode", "host", "path"]),
            "v2ray-plugin" | "gost-plugin" => (
                false,
                &[
                    "mode",
                    "host",
                    "path",
                    "tls",
                    "skip-cert-verify",
                    "headers",
                    "v2ray-http-upgrade",
                ],
            ),
            "" => return Err(Error::Config("Shadowsocks plugin 名称不能为空".into())),
            other => {
                return Err(Error::Config(format!(
                    "Shadowsocks plugin `{other}` 未实现，支持：{}",
                    SUPPORTED_PLUGINS.join("、")
                )));
            }
        };
        if let Some(field) = opts.set_fields().into_iter().find(|f| !allowed.contains(f)) {
            return Err(Error::Config(format!(
                "Shadowsocks plugin `{name}` 的参数 `{field}` 未实现"
            )));
        }
        let path = opts.path.unwrap_or_else(|| "/".to_owned());
        if !path.starts_with('/') {
            return Err(Error::Config(
                "Shadowsocks plugin-opts path 必须以 / 开头".into(),
            ));
        }
        let host = opts.host.filter(|h| !h.is_empty());
        if is_obfs {
            return match opts.mode.as_deref().unwrap_or("http") {
                "http" => Ok(Self::ObfsHttp { host, path }),
                mode => Err(Error::Config(format!(
                    "Shadowsocks obfs 插件 mode `{mode}` 未实现，仅支持 http"
                ))),
            };
        }
        match opts.mode.as_deref().unwrap_or("websocket") {
            "websocket" => {}
            mode => {
                return Err(Error::Config(format!(
                    "Shadowsocks {name} mode `{mode}` 未实现，仅支持 websocket"
                )));
            }
        }
        if opts.tls && opts.skip_cert_verify {
            kerlico_net::warn_insecure_tls(&format!("Shadowsocks {name}"));
        }
        Ok(Self::V2ray {
            transport: if opts.v2ray_http_upgrade {
                V2rayTransport::HttpUpgrade
            } else {
                V2rayTransport::WebSocket
            },
            tls: opts.tls,
            skip_cert_verify: opts.tls && opts.skip_cert_verify,
            host,
            path,
            headers: opts.headers,
        })
    }
}

pub struct PluginConnector {
    plugin: Plugin,
    dialer: kerlico_core::DialerOptions,
}

impl PluginConnector {
    pub fn new(plugin: Plugin, dialer: kerlico_core::DialerOptions) -> Arc<Self> {
        Arc::new(Self { plugin, dialer })
    }
}

impl StreamConnector for PluginConnector {
    fn tcp_eof(&self) -> bool {
        !matches!(self.plugin, Plugin::V2ray { tls: true, .. })
    }

    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    match &self.plugin {
                        Plugin::ObfsHttp { host, path } => {
                            let raw = self.dialer.connect(endpoint).await?;
                            let host = host.clone().unwrap_or_else(|| endpoint.host().clone());
                            Ok(Box::new(HttpObfsStream::new(raw, host, path.clone())) as BoxStream)
                        }
                        Plugin::V2ray {
                            transport,
                            tls,
                            skip_cert_verify,
                            host,
                            path,
                            headers,
                        } => {
                            let host = host.clone().unwrap_or_else(|| endpoint.host().clone());
                            let carrier = if *tls {
                                let connector = if *skip_cert_verify {
                                    kerlico_net::TcpConnector::tls_insecure(&host, self.dialer.clone())?
                                } else {
                                    kerlico_net::TcpConnector::tls(&host, None, self.dialer.clone())?
                                };
                                connector
                                    .connect(endpoint)
                                    .await?
                            } else {
                                self.dialer.connect(endpoint).await?
                            };
                            match transport {
                                V2rayTransport::WebSocket => {
                                    websocket_handshake(carrier, &host, path, headers).await
                                }
                                V2rayTransport::HttpUpgrade => {
                                    http_upgrade_handshake(carrier, &host, path, headers).await
                                }
                            }
                        }
                    }
                })
                .await
        })
    }
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// `simple-obfs` http 模式：首包前附加伪造 HTTP 请求头，首个响应剥离 HTTP 响应头，之后原样转发。
pub struct HttpObfsStream {
    inner: BoxStream,
    host: String,
    path: String,
    pending_write: Bytes,
    wrote_header: bool,
    response_head: Vec<u8>,
    leftover: Bytes,
    stripped_response: bool,
}

impl HttpObfsStream {
    pub fn new(inner: BoxStream, host: String, path: String) -> Self {
        Self {
            inner,
            host,
            path,
            pending_write: Bytes::new(),
            wrote_header: false,
            response_head: Vec::new(),
            leftover: Bytes::new(),
            stripped_response: false,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_write.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending_write))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_write.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for HttpObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.leftover.is_empty() {
                let n = buf.remaining().min(this.leftover.len());
                buf.put_slice(&this.leftover[..n]);
                this.leftover.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.stripped_response {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut tmp = [0u8; 4096];
            let mut chunk = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut chunk))?;
            if chunk.filled().is_empty() {
                return if this.response_head.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            this.response_head.extend_from_slice(chunk.filled());
            if let Some(end) = find_head_end(&this.response_head) {
                if !this.response_head.starts_with(b"HTTP/1.") {
                    return Poll::Ready(Err(invalid_data("obfs http 响应头不合法")));
                }
                this.leftover = Bytes::from(this.response_head.split_off(end));
                this.response_head = Vec::new();
                this.stripped_response = true;
            } else if this.response_head.len() > MAX_HTTP_HEAD {
                return Poll::Ready(Err(invalid_data("obfs http 响应头过长")));
            }
        }
    }
}

impl AsyncWrite for HttpObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.wrote_header {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            rand::random::<[u8; 16]>(),
        );
        let mut combined = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/7.88.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nContent-Length: {}\r\n\r\n",
            this.path,
            this.host,
            buf.len()
        )
        .into_bytes();
        combined.extend_from_slice(buf);
        this.pending_write = Bytes::from(combined);
        this.wrote_header = true;
        // 首包已整体进入缓冲；后续写、flush 与 shutdown 先排空缓冲。
        let _ = this.poll_drain(cx)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// v2ray httpupgrade 传输：发送 Upgrade 请求，校验 101 响应后转为原始字节流。
pub async fn http_upgrade_handshake(
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
    while !resp.ends_with(b"\r\n\r\n") {
        if resp.len() >= MAX_HTTP_HEAD || stream.read(&mut byte).await? == 0 {
            return Err(Error::Protocol(
                "Shadowsocks plugin HTTP Upgrade 响应不完整",
            ));
        }
        resp.push(byte[0]);
    }
    let status = resp.split(|b| *b == b' ').nth(1);
    if !resp.starts_with(b"HTTP/1.1 ") || status != Some(b"101") {
        return Err(Error::Protocol(
            "Shadowsocks plugin HTTP Upgrade 未返回 101",
        ));
    }
    Ok(stream)
}

/// v2ray-plugin / gost-plugin websocket 模式：RFC 6455 握手，负载按二进制帧收发。
pub async fn websocket_handshake(
    stream: BoxStream,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
) -> Result<BoxStream> {
    let mut request = format!("ws://{host}{path}")
        .into_client_request()
        .map_err(|_| Error::Config("Shadowsocks plugin WebSocket 地址不合法".into()))?;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        let name = http::HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| Error::Config("Shadowsocks plugin headers 名称不合法".into()))?;
        let value = http::HeaderValue::from_str(v)
            .map_err(|_| Error::Config("Shadowsocks plugin headers 取值不合法".into()))?;
        request.headers_mut().insert(name, value);
    }
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(1024 * 1024);
    config.max_frame_size = Some(1024 * 1024);
    let (ws, _) = tokio_tungstenite::client_async_with_config(request, stream, Some(config))
        .await
        .map_err(|_| Error::Protocol("Shadowsocks plugin WebSocket 握手失败"))?;
    Ok(Box::new(WsIo {
        inner: ws,
        received: Bytes::new(),
        remote_closed: false,
        needs_flush: false,
    }))
}

struct WsIo {
    inner: WebSocketStream<BoxStream>,
    received: Bytes,
    remote_closed: bool,
    needs_flush: bool,
}

impl AsyncRead for WsIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.received.is_empty() {
                let n = output.remaining().min(this.received.len());
                output.put_slice(&this.received[..n]);
                this.received.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.remote_closed || output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.needs_flush && Pin::new(&mut this.inner).poll_flush(cx).is_ready() {
                this.needs_flush = false;
            }
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => this.received = bytes,
                Some(Ok(Message::Text(text))) => {
                    this.received = Bytes::copy_from_slice(text.as_bytes());
                }
                Some(Ok(Message::Ping(_))) => this.needs_flush = true,
                Some(Ok(Message::Close(_))) | None => this.remote_closed = true,
                Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => {
                    this.remote_closed = true;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) => return Poll::Ready(Err(invalid_data("WebSocket 帧不合法"))),
            }
        }
    }
}

impl AsyncWrite for WsIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let ws_err = |_| io::Error::from(io::ErrorKind::BrokenPipe);
        ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(ws_err)?;
        let n = bytes.len().min(16 * 1024);
        Pin::new(&mut this.inner)
            .start_send(Message::Binary(Bytes::copy_from_slice(&bytes[..n])))
            .map_err(ws_err)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.inner).poll_flush(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        this.needs_flush = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.get_mut().inner).poll_close(cx)) {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;

    fn parse(name: &str, opts: Value) -> Result<Plugin> {
        let opts = PluginOpts::from_value_and_flattened(Some(&opts), &BTreeMap::new())?;
        Plugin::parse(name, opts)
    }

    #[test]
    fn sip003_and_flattened_plugin_opts_parse_supported_variants() {
        let obfs = parse(
            "obfs-local",
            json!("obfs=http;obfs-host=cdn.example.com;obfs-uri=/ws"),
        )
        .unwrap();
        assert_eq!(
            obfs,
            Plugin::ObfsHttp {
                host: Some("cdn.example.com".into()),
                path: "/ws".into()
            }
        );

        let mut extra = BTreeMap::new();
        extra.insert("plugin-opts-mode".to_owned(), json!("websocket"));
        extra.insert("plugin-opts-v2ray-http-upgrade".to_owned(), json!(true));
        extra.insert("plugin-opts-tls".to_owned(), json!(true));
        let merged = PluginOpts::from_value_and_flattened(None, &extra).unwrap();
        let v2ray = Plugin::parse("v2ray-plugin", merged).unwrap();
        assert!(matches!(
            v2ray,
            Plugin::V2ray {
                transport: V2rayTransport::HttpUpgrade,
                tls: true,
                ..
            }
        ));
        assert!(matches!(
            parse(
                "gost-plugin",
                json!("mode=websocket;host=a.example;path=/x;mux=0")
            )
            .unwrap(),
            Plugin::V2ray {
                transport: V2rayTransport::WebSocket,
                tls: false,
                ..
            }
        ));
    }

    #[test]
    fn unimplemented_plugins_and_options_fail_at_config_build() {
        for name in ["kcptun", "restls", "jls", "shadow-tls", "unknown", ""] {
            assert!(parse(name, json!({})).is_err(), "{name}");
        }
        let rejected: &[(&str, Value)] = &[
            ("obfs", json!("obfs=tls")),
            ("obfs", json!({"mode": "tls"})),
            ("obfs", json!({"tls": true})),
            ("obfs", json!("obfs=http;key=secret")),
            ("v2ray-plugin", json!("mode=quic")),
            ("v2ray-plugin", json!("mux=1")),
            ("v2ray-plugin", json!({"mux": true})),
            ("v2ray-plugin", json!({"fingerprint": "chrome"})),
            (
                "v2ray-plugin",
                json!({"v2ray-http-upgrade-fast-open": true}),
            ),
            ("v2ray-plugin", json!({"ech": {"enabled": true}})),
            ("v2ray-plugin", json!({"path": "no-slash"})),
            ("v2ray-plugin", json!("loglevel=none")),
            ("gost-plugin", json!({"crypt": "aes"})),
            ("gost-plugin", json!({"sndwnd": 1024})),
        ];
        for (name, opts) in rejected {
            assert!(parse(name, opts.clone()).is_err(), "{name} {opts}");
        }
        let err = parse("kcptun", json!({})).unwrap_err().to_string();
        assert!(err.contains("kcptun"), "{err}");
    }

    #[tokio::test]
    async fn obfs_http_never_reports_header_only_read_as_eof() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut obfs = HttpObfsStream::new(Box::new(client), "h.example".into(), "/".into());
        let server_task = tokio::spawn(async move {
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            let text = String::from_utf8(head).unwrap();
            assert!(text.contains("Sec-WebSocket-Key: "), "{text}");
            assert!(text.contains("Content-Length: 5\r\n"), "{text}");
            let mut body = [0u8; 5];
            server.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"hello");
            server.write_all(b"HTTP/1.1 101 Switching").await.unwrap();
            server.flush().await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(b" Protocols\r\n\r\n").await.unwrap();
            server.flush().await.unwrap();
            tokio::task::yield_now().await;
            server.write_all(b"world").await.unwrap();
        });
        obfs.write_all(b"hello").await.unwrap();
        obfs.flush().await.unwrap();
        let mut out = [0u8; 5];
        obfs.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn websocket_mode_frames_payload_and_sends_handshake_key() {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            use tokio_tungstenite::tungstenite::handshake::server::{
                ErrorResponse, Request, Response,
            };
            #[allow(clippy::result_large_err)]
            let callback =
                |req: &Request, resp: Response| -> std::result::Result<Response, ErrorResponse> {
                    assert_eq!(req.uri().path(), "/ray");
                    assert_eq!(req.headers()["x-extra"], "1");
                    assert!(req.headers().contains_key("sec-websocket-key"));
                    Ok(resp)
                };
            let mut ws = tokio_tungstenite::accept_hdr_async(server, callback)
                .await
                .unwrap();
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(msg, Message::Binary(Bytes::from_static(b"ping")));
            ws.send(Message::Binary(Bytes::from_static(b"pong")))
                .await
                .unwrap();
        });
        let headers = BTreeMap::from([("X-Extra".to_owned(), "1".to_owned())]);
        let mut stream = websocket_handshake(Box::new(client), "h.example", "/ray", &headers)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut out = [0u8; 4];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_upgrade_rejects_non_101_response() {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server.read(&mut buf).await;
            server
                .write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")
                .await
                .unwrap();
        });
        assert!(
            http_upgrade_handshake(Box::new(client), "h", "/", &BTreeMap::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn v2ray_plugin_tls_rejects_self_signed_unless_skip_cert_verify() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint =
            Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    tls.read_exact(&mut byte).await.unwrap();
                    head.push(byte[0]);
                }
                tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                    .await
                    .unwrap();
                let mut body = [0u8; 5];
                tls.read_exact(&mut body).await.unwrap();
                tls.write_all(&body).await.unwrap();
                tls.flush().await.unwrap();
                return;
            }
        });
        let connector = |skip: bool| {
            let opts = json!({"host":"localhost","tls":true,"v2ray-http-upgrade":true,"skip-cert-verify":skip});
            PluginConnector::new(
                parse("v2ray-plugin", opts).unwrap(),
                kerlico_core::DialerOptions::default(),
            )
        };
        let context = ConnectContext::new(std::time::Duration::from_secs(3));
        assert!(
            connector(false)
                .connect_tcp(&endpoint, &context)
                .await
                .is_err()
        );
        let mut stream = connector(true)
            .connect_tcp(&endpoint, &context)
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut out = [0u8; 5];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello");
        server.await.unwrap();
    }
}
