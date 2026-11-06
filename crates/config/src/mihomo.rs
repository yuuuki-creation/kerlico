//! Mihomo 代理条目到 kerlico 出站选项的映射。
//!
//! 每个 Mihomo `type` 对应 [`TYPES`] 中的一行：映射函数与 Mihomo 选项结构体定义的字段。映射函数
//! 取走 kerlico 实现的字段；剩余字段按 Mihomo 的结构解码器宽松处理（见 [`Proxy::finish`]）：
//!
//! - Mihomo 未给该类型定义的字段：静默忽略，与 Mihomo 一致（订阅 `override` 会把字段写进每个成员）。
//! - Mihomo 定义、kerlico 未实现、且改变安全或路由语义的字段（[`SECURITY_FIELDS`]）取生效值：
//!   该代理映射失败，错误带代理名与字段路径。
//! - 其余未实现字段：提示后继续。

use kerlico_core::{Error, Language, Result};
use serde_json::{Map, Value, json};

/// 一个 Mihomo 代理条目映射后的 kerlico 出站。
#[derive(Debug, Clone, PartialEq)]
pub struct MihomoOutbound {
    pub name: String,
    pub kind: &'static str,
    pub options: Value,
}

type Mapper = fn(&mut Proxy) -> Result<(&'static str, Opts)>;

/// 一种 Mihomo 代理类型：映射函数与 Mihomo 选项结构体的字段（`proxy` 标签，不含 [`BASIC_FIELDS`]）。
struct ProxyType {
    name: &'static str,
    mapper: Mapper,
    fields: &'static [&'static str],
}

/// Mihomo `BasicOption` 与 `ParseProxy` 对所有类型读取的字段。
const BASIC_FIELDS: &[&str] = &[
    "name",
    "type",
    "tfo",
    "mptcp",
    "interface-name",
    "routing-mark",
    "ip-version",
    "dialer-proxy",
    "smux",
];

/// 未实现时会改变安全或路由语义的字段：取生效值时该代理映射失败，而不是静默降级。
const SECURITY_FIELDS: &[&str] = &[
    "tls",
    "skip-cert-verify",
    "name-cert-verify",
    "fingerprint",
    "certificate",
    "private-key",
    "ech-opts",
    "reality-opts",
    "shadow-tls-opts",
    "restls-opts",
    "jls-opts",
    "tlsmirror-opts",
    "realm-opts",
    "disable-sni",
    "remote-dns-resolve",
];

/// 字段表取自 Mihomo `adapter/outbound/*.go` 的选项结构体（Mihomo v1.19 系列）。不在表中的类型报错。
const TYPES: &[ProxyType] = &[
    ProxyType {
        name: "ss",
        mapper: shadowsocks,
        fields: &[
            "server",
            "port",
            "password",
            "cipher",
            "udp",
            "plugin",
            "plugin-opts",
            "udp-over-tcp",
            "udp-over-tcp-version",
            "client-fingerprint",
        ],
    },
    ProxyType {
        name: "ssr",
        mapper: shadowsocksr,
        fields: &[
            "server",
            "port",
            "password",
            "cipher",
            "obfs",
            "obfs-param",
            "protocol",
            "protocol-param",
            "udp",
        ],
    },
    ProxyType {
        name: "snell",
        mapper: snell,
        fields: &[
            "server",
            "port",
            "psk",
            "udp",
            "version",
            "reuse",
            "obfs-opts",
            "client-fingerprint",
        ],
    },
    ProxyType {
        name: "vmess",
        mapper: vmess,
        fields: &[
            "server",
            "port",
            "uuid",
            "alterId",
            "cipher",
            "udp",
            "network",
            "tls",
            "alpn",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "servername",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "reality-opts",
            "tlsmirror-opts",
            "mekya-opts",
            "mkcp-opts",
            "http-opts",
            "h2-opts",
            "grpc-opts",
            "ws-opts",
            "packet-addr",
            "xudp",
            "packet-encoding",
            "global-padding",
            "authenticated-length",
            "client-fingerprint",
        ],
    },
    ProxyType {
        name: "vless",
        mapper: vless,
        fields: &[
            "server",
            "port",
            "uuid",
            "flow",
            "tls",
            "alpn",
            "udp",
            "packet-addr",
            "xudp",
            "packet-encoding",
            "encryption",
            "network",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "reality-opts",
            "http-opts",
            "h2-opts",
            "grpc-opts",
            "ws-opts",
            "xhttp-opts",
            "ws-headers",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "servername",
            "client-fingerprint",
        ],
    },
    ProxyType {
        name: "trojan",
        mapper: trojan,
        fields: &[
            "server",
            "port",
            "password",
            "alpn",
            "sni",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "udp",
            "network",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "reality-opts",
            "grpc-opts",
            "ws-opts",
            "ss-opts",
            "client-fingerprint",
        ],
    },
    ProxyType {
        name: "anytls",
        mapper: anytls,
        fields: &[
            "server",
            "port",
            "password",
            "alpn",
            "sni",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "client-fingerprint",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "udp",
            "client-metadata",
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
            "disable-reuse",
        ],
    },
    ProxyType {
        name: "http",
        mapper: http,
        fields: &[
            "server",
            "port",
            "username",
            "password",
            "tls",
            "sni",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "headers",
        ],
    },
    ProxyType {
        name: "socks5",
        mapper: socks5,
        fields: &[
            "server",
            "port",
            "username",
            "password",
            "tls",
            "udp",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
        ],
    },
    ProxyType {
        name: "hysteria",
        mapper: hysteria,
        fields: &[
            "server",
            "port",
            "ports",
            "protocol",
            "obfs-protocol",
            "up",
            "up-speed",
            "down",
            "down-speed",
            "auth",
            "auth-str",
            "obfs",
            "sni",
            "ech-opts",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "fast-open",
            "hop-interval",
        ],
    },
    ProxyType {
        name: "hysteria2",
        mapper: hysteria2,
        fields: &[
            "server",
            "port",
            "ports",
            "hop-interval",
            "up",
            "down",
            "password",
            "obfs",
            "obfs-password",
            "obfs-min-packet-size",
            "obfs-max-packet-size",
            "sni",
            "ech-opts",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "cwnd",
            "bbr-profile",
            "udp-mtu",
            "handshake-timeout",
            "realm-opts",
            "initial-stream-receive-window",
            "max-stream-receive-window",
            "initial-connection-receive-window",
            "max-connection-receive-window",
        ],
    },
    ProxyType {
        name: "tuic",
        mapper: tuic,
        fields: &[
            "server",
            "port",
            "token",
            "uuid",
            "password",
            "ip",
            "heartbeat-interval",
            "alpn",
            "reduce-rtt",
            "request-timeout",
            "udp-relay-mode",
            "congestion-controller",
            "disable-sni",
            "max-udp-relay-packet-size",
            "fast-open",
            "max-open-streams",
            "cwnd",
            "bbr-profile",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "max-datagram-frame-size",
            "sni",
            "ech-opts",
            "udp-over-stream",
            "udp-over-stream-version",
        ],
    },
    ProxyType {
        name: "shadowquic",
        mapper: shadowquic,
        fields: &[
            "server",
            "port",
            "username",
            "password",
            "sni",
            "alpn",
            "quic-versions",
            "udp-over-stream",
            "zero-rtt",
            "keep-alive-interval",
            "congestion-controller",
            "up",
            "down",
            "cwnd",
            "bbr-profile",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "max-datagram-frame-size",
            "max-open-streams",
        ],
    },
    ProxyType {
        name: "wireguard",
        mapper: wireguard,
        fields: &[
            "server",
            "port",
            "public-key",
            "pre-shared-key",
            "reserved",
            "allowed-ips",
            "ip",
            "ipv6",
            "private-key",
            "workers",
            "mtu",
            "udp",
            "persistent-keepalive",
            "ip-stack",
            "amnezia-wg-option",
            "peers",
            "remote-dns-resolve",
            "dns",
            "refresh-server-ip-interval",
        ],
    },
    ProxyType {
        name: "ssh",
        mapper: ssh,
        fields: &[
            "server",
            "port",
            "username",
            "password",
            "private-key",
            "private-key-passphrase",
            "host-key",
            "host-key-algorithms",
        ],
    },
    ProxyType {
        name: "mieru",
        mapper: mieru,
        fields: &[
            "server",
            "port",
            "port-range",
            "transport",
            "udp",
            "username",
            "password",
            "multiplexing",
            "handshake-mode",
            "traffic-pattern",
        ],
    },
    ProxyType {
        name: "sudoku",
        mapper: sudoku,
        fields: &[
            "server",
            "port",
            "key",
            "aead-method",
            "padding-min",
            "padding-max",
            "table-type",
            "enable-pure-downlink",
            "http-mask",
            "http-mask-mode",
            "http-mask-tls",
            "http-mask-host",
            "path-root",
            "multiplex",
            "http-mask-multiplex",
            "httpmask",
            "custom-table",
            "custom-tables",
        ],
    },
    ProxyType {
        name: "trusttunnel",
        mapper: trusttunnel,
        fields: &[
            "server",
            "port",
            "username",
            "password",
            "alpn",
            "sni",
            "ech-opts",
            "client-fingerprint",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "udp",
            "health-check",
            "quic",
            "congestion-controller",
            "cwnd",
            "bbr-profile",
            "max-connections",
            "min-streams",
            "max-streams",
        ],
    },
    ProxyType {
        name: "gost-relay",
        mapper: gost_relay,
        fields: &[
            "server",
            "port",
            "forward",
            "udp",
            "tls",
            "mux",
            "sni",
            "username",
            "password",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "client-fingerprint",
        ],
    },
    ProxyType {
        name: "tailscale",
        mapper: tailscale,
        fields: &[
            "hostname",
            "auth-key",
            "control-url",
            "state-dir",
            "ephemeral",
            "udp",
            "accept-routes",
            "exit-node",
            "exit-node-allow-lan-access",
        ],
    },
    ProxyType {
        name: "openvpn",
        mapper: openvpn,
        fields: &[
            "server",
            "port",
            "proto",
            "dev",
            "cipher",
            "data-ciphers",
            "data-ciphers-fallback",
            "auth",
            "comp-lzo",
            "ca",
            "cert",
            "key",
            "tls-auth",
            "key-direction",
            "tls-crypt",
            "tls-crypt-v2",
            "username",
            "password",
            "peer-info",
            "ping",
            "ping-restart",
            "tran-window",
            "handshake-timeout",
            "mtu",
            "udp",
            "ip-stack",
            "remote-dns-resolve",
            "dns",
        ],
    },
    ProxyType {
        name: "easytier",
        mapper: easytier,
        fields: &[
            "network-name",
            "network-secret",
            "hostname",
            "ipv4",
            "dhcp",
            "peers",
            "listeners",
            "no-listener",
            "mapped-listeners",
            "exit-nodes",
            "proxy-networks",
            "instance-name",
            "state-dir",
            "udp",
            "accept-dns",
            "enable-exit-node",
            "enable-encryption",
            "encryption-algorithm",
            "private-mode",
            "latency-first",
            "disable-p2p",
            "enable-kcp-proxy",
            "disable-kcp-input",
            "enable-quic-proxy",
            "disable-quic-input",
            "mtu",
            "tld-dns-zone",
            "secure-mode",
            "local-private-key",
            "local-public-key",
        ],
    },
    ProxyType {
        name: "zerotier",
        mapper: zerotier,
        fields: &[
            "network",
            "state-dir",
            "identity-secret",
            "planet",
            "mtu",
            "ip-stack",
            "physical-mtu",
            "udp",
            "remote-dns-resolve",
            "dns",
            "low-bandwidth",
            "encrypted-hello",
            "primary-port",
            "secondary-port",
            "tcp-fallback-mode",
            "tcp-fallback-relay",
            "orbit",
            "remote-trace-target",
            "remote-trace-level",
        ],
    },
    ProxyType {
        name: "direct",
        mapper: direct,
        fields: &[],
    },
    ProxyType {
        name: "reject",
        mapper: reject,
        fields: &[],
    },
    ProxyType {
        name: "dns",
        mapper: dns,
        fields: &[],
    },
];

/// Mihomo `client-fingerprint` 名到 xray-transport uTLS 档案名，按 Mihomo 所用 metacubex/utls
/// 的 `*_Auto` 别名对齐版本（如 Firefox 120、Safari 16.0）。不在表中的名字 Mihomo 提示后发送原生
/// ClientHello，kerlico 同样处理。`android`（Android 11 OkHttp）与 uTLS 一样不带 supported_versions，
/// 只协商 TLS 1.2。`360`（360 7.5）只有 CBC、RC4、3DES 套件，本实现一个都不支持，照列只会让每次握手
/// 失败，所以同样提示后不整形（阻塞点见 `third_party/shaped-rustls/PATCHES.md`）。
const FINGERPRINTS: &[(&str, &str)] = &[
    ("chrome", "chrome"),
    ("firefox", "hellofirefox_120"),
    ("safari", "hellosafari_16_0"),
    ("ios", "ios"),
    ("android", "android"),
    ("edge", "edge"),
    ("qq", "qq"),
    ("random", "random"),
    ("randomized", "randomized"),
    ("chrome120", "hellochrome_120"),
    ("firefox120", "hellofirefox_120"),
    ("safari16", "hellosafari_16_0"),
];

/// Mihomo 结构解码器的键匹配：先精确匹配，再忽略大小写并把 `_` 视为 `-`。
fn canonical_key(key: &str) -> String {
    key.to_ascii_lowercase().replace('_', "-")
}

/// 未实现字段的取值是否会生效：`false`、空值、`enable(d): false` 的映射都不生效。
fn takes_effect(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::String(s) => !s.is_empty() && !s.eq_ignore_ascii_case("false"),
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => {
            !map.is_empty()
                && ["enable", "enabled"]
                    .iter()
                    .all(|key| map.get(*key).is_none_or(takes_effect))
        }
        Value::Bool(true) => true,
    }
}

/// `proxies` 或订阅成员：带 `tag` 或 `options` 的条目是 kerlico 原生出站（`tag`、`type`、可选
/// `options`），原样保留；其余按 Mihomo 代理映射。
pub(crate) fn member_outbound(raw: Value) -> Result<(String, String, Value)> {
    match raw {
        Value::Object(map) if map.contains_key("tag") || map.contains_key("options") => {
            native_outbound(map)
        }
        raw => {
            let out = translate_proxy(raw)?;
            Ok((out.name, out.kind.to_owned(), out.options))
        }
    }
}

/// 未写或写空 `client-fingerprint` 的 Mihomo 代理映射补上 `global-client-fingerprint`；原生条目不变。
pub(crate) fn default_client_fingerprint(member: &mut Value, fingerprint: &str) {
    let Value::Object(map) = member else {
        return;
    };
    if map.contains_key("tag") || map.contains_key("options") {
        return;
    }
    let unset = map
        .get("client-fingerprint")
        .is_none_or(|value| value.as_str().is_some_and(str::is_empty) || value.is_null());
    if unset {
        map.insert(
            "client-fingerprint".into(),
            Value::String(fingerprint.into()),
        );
    }
}

fn native_outbound(mut map: Map<String, Value>) -> Result<(String, String, Value)> {
    let tag = match map.remove("tag").or_else(|| map.remove("name")) {
        Some(Value::String(s)) => s,
        _ => return Err(Error::Config("出站条目缺少 tag".into())),
    };
    let kind = match map.remove("type") {
        Some(Value::String(s)) => crate::group::normalize_outbound_kind(&s),
        _ => return Err(Error::Config(format!("出站条目 {tag} 缺少 type"))),
    };
    let options = map.remove("options").unwrap_or_else(|| json!({}));
    if let Some(field) = map.keys().next() {
        return Err(Error::Config(format!(
            "出站条目 {tag} 的字段 {field} 不受支持"
        )));
    }
    Ok((tag, kind, options))
}

/// 把一个 Mihomo 代理映射对象（含 `name`、`type`）转为 kerlico 出站。
pub fn translate_proxy(raw: Value) -> Result<MihomoOutbound> {
    let Value::Object(mut map) = raw else {
        return Err(Error::Config("Mihomo 代理条目须为映射".into()));
    };
    let name = match map.remove("name") {
        Some(Value::String(s)) if !s.trim().is_empty() => s,
        _ => return Err(Error::Config("Mihomo 代理条目缺少 name".into())),
    };
    let kind = match map.remove("type") {
        Some(Value::String(s)) => s.trim().to_ascii_lowercase(),
        _ => return Err(Error::Config(format!("Mihomo 代理 {name} 缺少字段 type"))),
    };
    let Some(spec) = TYPES.iter().find(|t| t.name == kind) else {
        return Err(Error::Config(format!(
            "Mihomo 代理 {name} 的类型 {kind} 不受支持"
        )));
    };
    let known = |key: &str| BASIC_FIELDS.contains(&key) || spec.fields.contains(&key);
    for key in map.keys().cloned().collect::<Vec<_>>() {
        if known(&key) {
            continue;
        }
        let canonical = canonical_key(&key);
        if let Some(field) = BASIC_FIELDS
            .iter()
            .chain(spec.fields)
            .find(|f| canonical_key(f) == canonical)
            && !map.contains_key(*field)
            && let Some(value) = map.remove(&key)
        {
            map.insert((*field).to_owned(), value);
        }
    }
    let mut proxy = Proxy {
        name: name.clone(),
        prefix: String::new(),
        map,
        unimplemented: Vec::new(),
    };
    let (kind, mut opts) = (spec.mapper)(&mut proxy)?;
    proxy.map.retain(|key, _| known(key));
    proxy.common(&mut opts)?;
    proxy.finish()?;
    Ok(MihomoOutbound {
        name,
        kind,
        options: Value::Object(opts.0),
    })
}

/// 待消费的 Mihomo 字段集合；嵌套映射以 `prefix` 记录字段路径。`unimplemented` 收集取了生效值、
/// kerlico 却未实现的字段，由 [`Proxy::finish`] 统一判定。
pub(crate) struct Proxy {
    name: String,
    prefix: String,
    map: Map<String, Value>,
    unimplemented: Vec<String>,
}

impl Proxy {
    fn path(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
    fn unsupported(&self, key: &str) -> Error {
        Error::Config(format!(
            "Mihomo 代理 {} 的字段 {} 不受支持",
            self.name,
            self.path(key)
        ))
    }
    fn bad_value(&self, key: &str, value: impl std::fmt::Display) -> Error {
        Error::Config(format!(
            "Mihomo 代理 {} 的字段 {} 取值不受支持：{value}",
            self.name,
            self.path(key)
        ))
    }
    fn bad_type(&self, key: &str) -> Error {
        Error::Config(format!(
            "Mihomo 代理 {} 的字段 {} 类型不合法",
            self.name,
            self.path(key)
        ))
    }
    fn missing(&self, key: &str) -> Error {
        Error::Config(format!(
            "Mihomo 代理 {} 缺少字段 {}",
            self.name,
            self.path(key)
        ))
    }

    fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }
    fn take(&mut self, key: &str) -> Option<Value> {
        self.map.remove(key).filter(|v| !v.is_null())
    }
    fn string(&mut self, key: &str) -> Result<Option<String>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(Value::Number(n)) => Ok(Some(n.to_string())),
            Some(_) => Err(self.bad_type(key)),
        }
    }
    fn required_string(&mut self, key: &str) -> Result<String> {
        self.string(key)?.ok_or_else(|| self.missing(key))
    }
    fn boolean(&mut self, key: &str) -> Result<Option<bool>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(b)),
            Some(Value::String(s)) if s.eq_ignore_ascii_case("true") => Ok(Some(true)),
            Some(Value::String(s)) if s.eq_ignore_ascii_case("false") => Ok(Some(false)),
            Some(_) => Err(self.bad_type(key)),
        }
    }
    fn integer(&mut self, key: &str) -> Result<Option<u64>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Number(n)) => n.as_u64().map(Some).ok_or_else(|| self.bad_type(key)),
            Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| self.bad_type(key)),
            Some(_) => Err(self.bad_type(key)),
        }
    }
    fn port(&mut self) -> Result<u16> {
        let port = self.integer("port")?.ok_or_else(|| self.missing("port"))?;
        u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| self.bad_value("port", port))
    }
    fn strings(&mut self, key: &str) -> Result<Option<Vec<String>>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(vec![s])),
            Some(Value::Array(items)) => items
                .into_iter()
                .map(|v| match v {
                    Value::String(s) => Ok(s),
                    Value::Number(n) => Ok(n.to_string()),
                    _ => Err(self.bad_type(key)),
                })
                .collect::<Result<Vec<_>>>()
                .map(Some),
            Some(_) => Err(self.bad_type(key)),
        }
    }
    fn nested(&mut self, key: &str) -> Result<Option<Proxy>> {
        match self.take(key) {
            None => Ok(None),
            Some(Value::Object(map)) => Ok(Some(Proxy {
                name: self.name.clone(),
                prefix: format!("{}{key}.", self.prefix),
                map,
                unimplemented: Vec::new(),
            })),
            Some(_) => Err(self.bad_type(key)),
        }
    }
    /// `client-fingerprint` 写到出站的 uTLS 指纹选项 `path`；空值与 `none` 不整形。
    fn fingerprint(&mut self, opts: &mut Opts, path: &str) -> Result<()> {
        let Some(name) = self.string("client-fingerprint")? else {
            return Ok(());
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || name == "none" {
            return Ok(());
        }
        match FINGERPRINTS.iter().find(|(mihomo, _)| *mihomo == name) {
            Some((_, profile)) => opts.set(path, *profile),
            None => self
                .unimplemented
                .push(format!("client-fingerprint={name}")),
        }
        Ok(())
    }
    /// `skip-cert-verify: true` 写到出站的跳过证书校验选项 `path`。
    fn insecure(&mut self, opts: &mut Opts, path: &str) -> Result<()> {
        if self.boolean("skip-cert-verify")? == Some(true) {
            opts.set(path, true);
        }
        Ok(())
    }
    /// 未启用 TLS 时 Mihomo 不读取 TLS 字段，订阅里残留的取值不生效。
    fn drop_tls_fields(&mut self) {
        for key in [
            "sni",
            "servername",
            "alpn",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "client-fingerprint",
            "ech-opts",
        ] {
            self.map.remove(key);
        }
    }
    /// kerlico 只实现取值 `allowed`；其他取值记为未实现字段。
    fn noop_bool(&mut self, key: &str, allowed: bool) -> Result<()> {
        if self.boolean(key)?.is_some_and(|v| v != allowed) {
            self.unimplemented.push(key.to_owned());
        }
        Ok(())
    }
    fn server_target(&mut self) -> Result<Value> {
        let host = self.required_string("server")?;
        let port = self.port()?;
        Ok(json!({ "host": host, "port": port }))
    }
    fn sni(&mut self) -> Result<Option<String>> {
        let sni = self.string("sni")?;
        let servername = self.string("servername")?;
        Ok(sni.or(servername))
    }
    /// 把 UDP 开关映射到协议自带的选项；`key` 为 `None` 表示协议始终按自身能力承载 UDP。
    fn udp(&mut self, opts: &mut Opts, key: Option<&str>) -> Result<()> {
        match key {
            Some(k) => {
                if let Some(v) = self.boolean("udp")? {
                    opts.set(k, v);
                }
                Ok(())
            }
            None => self.noop_bool("udp", true),
        }
    }
    /// Mihomo 本身也不为该类型承载 UDP，`udp` 任意取值都无效果。
    fn ignore_udp(&mut self) -> Result<()> {
        self.boolean("udp").map(|_| ())
    }
    fn smux(&mut self, opts: &mut Opts) -> Result<()> {
        let Some(mut smux) = self.nested("smux")? else {
            return Ok(());
        };
        let mut mux = Opts::default();
        if let Some(v) = smux.boolean("enabled")? {
            mux.set("enabled", v);
        }
        if let Some(v) = smux.string("protocol")? {
            mux.set("protocol", v);
        }
        for (from, to) in [
            ("max-connections", "max_connections"),
            ("min-streams", "min_streams"),
            ("max-streams", "max_streams"),
        ] {
            if let Some(v) = smux.integer(from)? {
                mux.set(to, v);
            }
        }
        if let Some(v) = smux.boolean("padding")? {
            mux.set("padding", v);
        }
        if let Some(v) = smux.boolean("only-tcp")? {
            mux.set("only_tcp", v);
        }
        smux.noop_bool("statistic", false)?;
        if let Some(mut brutal) = smux.nested("brutal-opts")? {
            if brutal.boolean("enabled")? == Some(true) {
                let mut out = Opts::default();
                out.set("enabled", true);
                for (key, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
                    let value = brutal.take(key).ok_or_else(|| brutal.missing(key))?;
                    let mbps = bandwidth_bytes(&brutal, key, &value)?.div_ceil(125_000);
                    out.set(to, mbps);
                }
                mux.set("brutal", Value::Object(out.0));
            } else {
                brutal.map.clear();
            }
            brutal.finish()?;
        }
        smux.finish()?;
        if mux.0.get("enabled") == Some(&Value::Bool(true)) {
            opts.set("multiplex", Value::Object(mux.0));
        }
        Ok(())
    }

    /// 所有类型共有的拨号字段。`interface-name` 等交给 `apply_dialer_map` 处理。
    fn common(&mut self, opts: &mut Opts) -> Result<()> {
        for key in [
            "interface-name",
            "routing-mark",
            "dialer-proxy",
            "tfo",
            "mptcp",
        ] {
            if let Some(v) = self.take(key) {
                opts.set(key, v);
            }
        }
        if let Some(v) = self.string("ip-version")?
            && v != "dual"
        {
            return Err(self.bad_value("ip-version", v));
        }
        // `udp: true` 在 kerlico 中由协议能力决定是否承载 UDP，取值 true 无效果。
        self.noop_bool("udp", true)?;
        if let Some(mut smux) = self.nested("smux")? {
            smux.noop_bool("enabled", false)?;
            smux.map.clear();
            smux.finish()?;
        }
        Ok(())
    }
    /// 判定剩余与未实现字段：[`SECURITY_FIELDS`] 取生效值时映射失败，其余生效值提示后忽略。
    fn finish(self) -> Result<()> {
        let effective = self
            .map
            .iter()
            .filter(|(_, value)| takes_effect(value))
            .map(|(key, _)| key.as_str());
        let mut ignored = Vec::new();
        for key in self
            .unimplemented
            .iter()
            .map(String::as_str)
            .chain(effective)
        {
            if SECURITY_FIELDS.contains(&key) {
                return Err(Error::Config(format!(
                    "Mihomo 代理 {} 的字段 {} 改变安全或路由语义，kerlico 尚未实现",
                    self.name,
                    self.path(key)
                )));
            }
            ignored.push(self.path(key));
        }
        if !ignored.is_empty() {
            let fields = ignored.join(", ");
            match Language::default() {
                Language::ZhCn => eprintln!(
                    "警告：Mihomo 代理 {} 的字段 {fields} 尚未实现，已忽略",
                    self.name
                ),
                Language::En => eprintln!(
                    "warning: Mihomo proxy {} fields {fields} are not implemented and were ignored",
                    self.name
                ),
            }
        }
        Ok(())
    }
}

/// kerlico 选项，`set` 的键可用 `.` 写嵌套路径。
#[derive(Default)]
pub(crate) struct Opts(Map<String, Value>);

impl Opts {
    fn set(&mut self, path: &str, value: impl Into<Value>) {
        let mut cursor = &mut self.0;
        let mut parts = path.split('.').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                cursor.insert(part.to_owned(), value.into());
                return;
            }
            let entry = cursor
                .entry(part.to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if !entry.is_object() {
                *entry = Value::Object(Map::new());
            }
            cursor = entry.as_object_mut().expect("object");
        }
    }
}

const SS_AEAD: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "aes-128-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
    "xchacha20-ietf-poly1305",
    "sm4-gcm",
    "sm4-ccm",
];

fn shadowsocks(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let server = p.required_string("server")?;
    let port = p.port()?;
    let cipher = p.required_string("cipher")?.to_ascii_lowercase();
    let password = p.required_string("password")?;
    let plugin = p.string("plugin")?;
    if plugin.as_deref() != Some("shadow-tls") {
        // Mihomo 的 ss 只把 client-fingerprint 用于 shadow-tls 插件。
        p.map.remove("client-fingerprint");
    }
    let mut opts = Opts::default();
    let ss2022 = cipher.starts_with("2022-");
    opts.set("server", server.clone());
    opts.set("port", port);
    opts.set("method", cipher.clone());
    if ss2022 {
        let mut keys: Vec<&str> = password.split(':').collect();
        let key = keys.pop().unwrap_or_default();
        opts.set("key", key);
        if !keys.is_empty() {
            opts.set("identity_keys", keys);
        }
    } else {
        opts.set("password", password);
        if !SS_AEAD.contains(&cipher.as_str()) {
            opts.set("allow_insecure", true);
        }
    }
    if plugin.as_deref() == Some("shadow-tls") {
        let mut po = p
            .nested("plugin-opts")?
            .ok_or_else(|| p.missing("plugin-opts"))?;
        let mut st = Opts::default();
        let version = po.integer("version")?.unwrap_or(2);
        st.set("version", version);
        if let Some(pw) = po.string("password")? {
            st.set("password", pw);
        }
        st.set(
            "tls.server_name",
            po.string("host")?.ok_or_else(|| po.missing("host"))?,
        );
        if let Some(alpn) = po.strings("alpn")? {
            st.set("tls.alpn", alpn);
        }
        po.insecure(&mut st, "tls.insecure")?;
        p.fingerprint(&mut st, "tls.fingerprint")?;
        po.finish()?;
        p.noop_bool("udp-over-tcp", false)?;
        st.set(
            "inner",
            json!({ "type": if ss2022 { "ss2022" } else { "shadowsocks" }, "options": Value::Object(opts.0) }),
        );
        p.noop_bool("udp", true)?;
        return Ok(("shadowtls", st));
    }
    if ss2022 {
        if let Some(name) = plugin {
            return Err(p.bad_value("plugin", name));
        }
        p.noop_bool("udp-over-tcp", false)?;
        p.smux(&mut opts)?;
        p.udp(&mut opts, None)?;
        return Ok(("ss2022", opts));
    }
    if let Some(v) = p.boolean("udp-over-tcp")? {
        opts.set("udp_over_tcp", v);
    }
    if let Some(v) = p.integer("udp-over-tcp-version")? {
        opts.set("udp_over_tcp_version", v);
    }
    p.smux(&mut opts)?;
    match plugin.as_deref() {
        None => {}
        Some("obfs") => {
            let mut po = p
                .nested("plugin-opts")?
                .ok_or_else(|| p.missing("plugin-opts"))?;
            let mut out = Opts::default();
            out.set("mode", po.required_string("mode")?);
            if let Some(host) = po.string("host")? {
                out.set("host", host);
            }
            po.finish()?;
            opts.set("plugin", "obfs");
            opts.set("plugin_opts", Value::Object(out.0));
        }
        Some(name @ ("v2ray-plugin" | "gost-plugin")) => {
            let mut po = p
                .nested("plugin-opts")?
                .ok_or_else(|| p.missing("plugin-opts"))?;
            let mut out = Opts::default();
            if let Some(mode) = po.string("mode")? {
                if mode != "websocket" {
                    return Err(po.bad_value("mode", mode));
                }
                out.set("mode", mode);
            }
            for key in ["tls", "mux"] {
                if let Some(v) = po.boolean(key)? {
                    out.set(key, v);
                }
            }
            if let Some(v) = po.boolean("v2ray-http-upgrade")? {
                out.set("v2ray_http_upgrade", v);
            }
            for key in ["host", "path"] {
                if let Some(v) = po.string(key)? {
                    out.set(key, v);
                }
            }
            if let Some(headers) = po.take("headers") {
                out.set("headers", headers);
            }
            po.insecure(&mut out, "skip_cert_verify")?;
            po.finish()?;
            opts.set("plugin", name);
            opts.set("plugin_opts", Value::Object(out.0));
        }
        Some(other) => return Err(p.bad_value("plugin", other)),
    }
    p.udp(&mut opts, None)?;
    Ok(("shadowsocks", opts))
}

fn shadowsocksr(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("server", p.server_target()?);
    opts.set("method", p.required_string("cipher")?);
    opts.set("password", p.required_string("password")?);
    opts.set("protocol", p.required_string("protocol")?);
    opts.set("obfs", p.required_string("obfs")?);
    if let Some(v) = p.string("protocol-param")? {
        opts.set("protocol_param", v);
    }
    if let Some(v) = p.string("obfs-param")? {
        opts.set("obfs_param", v);
    }
    opts.set("allow_insecure", true);
    p.udp(&mut opts, Some("udp"))?;
    Ok(("shadowsocksr", opts))
}

fn snell(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("server", p.server_target()?);
    opts.set("psk", p.required_string("psk")?);
    let version = p.integer("version")?.unwrap_or(1);
    if !matches!(version, 3 | 4) {
        return Err(p.bad_value("version", version));
    }
    opts.set("version", version);
    // Mihomo 的 snell 只把 client-fingerprint 用于 TLS 混淆；kerlico 只支持 HTTP 混淆。
    p.map.remove("client-fingerprint");
    if let Some(v) = p.boolean("reuse")? {
        opts.set("reuse", v);
    }
    if let Some(mut obfs) = p.nested("obfs-opts")? {
        let mode = obfs.required_string("mode")?;
        if mode != "http" {
            return Err(obfs.bad_value("mode", mode));
        }
        opts.set("obfs_mode", "http");
        if let Some(host) = obfs.string("host")? {
            opts.set("obfs_host", host);
        }
        obfs.finish()?;
    }
    p.udp(&mut opts, None)?;
    Ok(("snell", opts))
}

/// 各 `network` 的选项字段；Mihomo 只读取所选 `network` 对应的一个。
const TRANSPORT_OPTS: &[&str] = &[
    "ws-opts",
    "grpc-opts",
    "h2-opts",
    "http-opts",
    "xhttp-opts",
    "mkcp-opts",
    "mekya-opts",
];

/// `network` 与 `*-opts` 映射到 kerlico `transport`。`headers_list` 为 true 时额外请求头写成
/// `[[k, v]]` 列表（VLESS、Trojan），为 false 时只接受 `Host`（VMess）。
fn v2ray_transport(p: &mut Proxy, opts: &mut Opts, headers_list: bool) -> Result<()> {
    let network = p.string("network")?.unwrap_or_else(|| "tcp".into());
    let selected = format!("{network}-opts");
    for key in TRANSPORT_OPTS {
        if *key != selected {
            p.map.remove(*key);
        }
    }
    match network.as_str() {
        "tcp" => {}
        "ws" => {
            let mut t = Opts::default();
            t.set("type", "ws");
            t.set("path", "/");
            if let Some(mut ws) = p.nested("ws-opts")? {
                if let Some(path) = ws.string("path")? {
                    t.set("path", path);
                }
                if let Some(mut headers) = ws.nested("headers")? {
                    let host_key = headers
                        .map
                        .keys()
                        .find(|k| k.eq_ignore_ascii_case("host"))
                        .cloned();
                    if let Some(k) = host_key {
                        t.set("host", headers.required_string(&k)?);
                    }
                    if headers_list {
                        let mut list = Vec::new();
                        for (k, v) in std::mem::take(&mut headers.map) {
                            match v {
                                Value::String(s) => list.push(json!([k, s])),
                                _ => return Err(headers.bad_type(&k)),
                            }
                        }
                        if !list.is_empty() {
                            t.set("headers", list);
                        }
                    }
                    headers.finish()?;
                }
                if ws.boolean("v2ray-http-upgrade")? == Some(true) {
                    t.set("type", "httpupgrade");
                }
                ws.noop_bool("v2ray-http-upgrade-fast-open", false)?;
                if let Some(bytes) = ws.integer("max-early-data")? {
                    if !headers_list {
                        return Err(ws.unsupported("max-early-data"));
                    }
                    if let Some(name) = ws.string("early-data-header-name")?
                        && !name.eq_ignore_ascii_case("Sec-WebSocket-Protocol")
                    {
                        return Err(ws.bad_value("early-data-header-name", name));
                    }
                    if bytes > 0 {
                        t.set("early_data_bytes", bytes);
                    }
                }
                ws.finish()?;
            }
            opts.set("transport", Value::Object(t.0));
        }
        "grpc" => {
            let mut t = Opts::default();
            t.set("type", "grpc");
            if let Some(mut g) = p.nested("grpc-opts")? {
                if let Some(name) = g.string("grpc-service-name")? {
                    t.set("service_name", name);
                }
                if let Some(ua) = g.string("grpc-user-agent")? {
                    t.set("user_agent", ua);
                }
                g.finish()?;
            }
            opts.set("transport", Value::Object(t.0));
        }
        other => return Err(p.bad_value("network", other)),
    }
    Ok(())
}

fn vmess(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    opts.set("uuid", p.required_string("uuid")?);
    let alter = p.integer("alterId")?.unwrap_or(0);
    if alter != 0 {
        return Err(p.bad_value("alterId", alter));
    }
    let cipher = p.string("cipher")?.unwrap_or_else(|| "auto".into());
    if !matches!(
        cipher.as_str(),
        "auto" | "aes-128-gcm" | "chacha20-poly1305" | "zero"
    ) {
        return Err(p.bad_value("cipher", cipher));
    }
    opts.set("security", cipher);
    opts.set(
        "global_padding",
        p.boolean("global-padding")?.unwrap_or(false),
    );
    if let Some(v) = p.boolean("authenticated-length")? {
        opts.set("authenticated_length", v);
    }
    if let Some(enc) = p.string("packet-encoding")?
        && !enc.is_empty()
    {
        return Err(p.bad_value("packet-encoding", enc));
    }
    p.noop_bool("xudp", false)?;
    p.noop_bool("packet-addr", false)?;
    let sni = p.sni()?;
    if p.boolean("tls")? == Some(true) {
        opts.set("tls.type", "tls");
        opts.set("tls.server_name", sni.unwrap_or(host));
        p.insecure(&mut opts, "tls.insecure")?;
        p.fingerprint(&mut opts, "tls.fingerprint")?;
    } else {
        p.drop_tls_fields();
    }
    v2ray_transport(p, &mut opts, false)?;
    p.smux(&mut opts)?;
    p.udp(&mut opts, None)?;
    Ok(("vmess", opts))
}

fn vless(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    opts.set("server", target);
    opts.set("uuid", p.required_string("uuid")?);
    if let Some(flow) = p.string("flow")?
        && !flow.is_empty()
    {
        opts.set("flow", flow);
    }
    if let Some(enc) = p.string("encryption")?
        && !enc.is_empty()
        && enc != "none"
    {
        opts.set("encryption", enc);
    }
    let mut encoding = p.string("packet-encoding")?.filter(|s| !s.is_empty());
    if p.boolean("xudp")? == Some(true) {
        encoding = Some("xudp".into());
    }
    if p.boolean("packet-addr")? == Some(true) {
        encoding = Some("packetaddr".into());
    }
    if let Some(enc) = encoding {
        opts.set("packet_encoding", enc);
    }
    let sni = p.sni()?;
    let tls = p.boolean("tls")?.unwrap_or(false);
    if let Some(mut reality) = p.nested("reality-opts")? {
        opts.set("security.type", "reality");
        opts.set(
            "security.server_name",
            sni.ok_or_else(|| p.missing("servername"))?,
        );
        opts.set(
            "security.public_key",
            reality.required_string("public-key")?,
        );
        if let Some(sid) = reality.string("short-id")? {
            opts.set("security.short_id", sid);
        }
        reality.finish()?;
        p.fingerprint(&mut opts, "security.fingerprint")?;
        // REALITY 不走证书链校验，Mihomo 不读取 skip-cert-verify。
        p.map.remove("skip-cert-verify");
    } else if tls {
        opts.set("security.type", "tls");
        if let Some(name) = sni {
            opts.set("security.server_name", name);
        }
        p.fingerprint(&mut opts, "security.fingerprint")?;
        if let Some(alpn) = p.strings("alpn")? {
            opts.set("security.alpn", alpn);
        }
        p.insecure(&mut opts, "security.allow_insecure")?;
    } else {
        p.drop_tls_fields();
        opts.set("security.type", "none");
    }
    v2ray_transport(p, &mut opts, true)?;
    p.smux(&mut opts)?;
    p.udp(&mut opts, None)?;
    Ok(("vless", opts))
}

fn trojan(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    opts.set("password", p.required_string("password")?);
    opts.set("security.type", "tls");
    opts.set("security.server_name", p.sni()?.unwrap_or(host));
    p.insecure(&mut opts, "security.insecure")?;
    p.fingerprint(&mut opts, "security.fingerprint")?;
    if let Some(mut ss) = p.nested("ss-opts")? {
        ss.noop_bool("enabled", false)?;
        ss.map.clear();
        ss.finish()?;
    }
    v2ray_transport(p, &mut opts, true)?;
    p.smux(&mut opts)?;
    p.udp(&mut opts, None)?;
    Ok(("trojan", opts))
}

fn anytls(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    opts.set("password", p.required_string("password")?);
    opts.set("tls.server_name", p.sni()?.unwrap_or(host));
    p.insecure(&mut opts, "tls.insecure")?;
    p.fingerprint(&mut opts, "tls.fingerprint")?;
    if let Some(secs) = p.integer("idle-session-timeout")? {
        opts.set("idle_session_timeout_ms", secs.saturating_mul(1000));
    }
    p.udp(&mut opts, None)?;
    Ok(("anytls", opts))
}

fn auth_pair(p: &mut Proxy, opts: &mut Opts) -> Result<()> {
    let user = p.string("username")?;
    let pass = p.string("password")?;
    match (user, pass) {
        (Some(u), Some(pw)) => {
            opts.set("auth.username", u);
            opts.set("auth.password", pw);
            Ok(())
        }
        (None, None) => Ok(()),
        (None, Some(_)) => Err(p.missing("username")),
        (Some(_), None) => Err(p.missing("password")),
    }
}

fn http(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    auth_pair(p, &mut opts)?;
    let sni = p.sni()?;
    if p.boolean("tls")? == Some(true) {
        opts.set("tls.server_name", sni.unwrap_or(host));
        p.insecure(&mut opts, "tls.insecure")?;
    } else {
        p.drop_tls_fields();
    }
    if let Some(headers) = p.take("headers") {
        opts.set("headers", headers);
    }
    p.ignore_udp()?;
    Ok(("http", opts))
}

fn socks5(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("server", p.server_target()?);
    opts.set("version", "5");
    auth_pair(p, &mut opts)?;
    if p.boolean("tls")? == Some(true) {
        p.unimplemented.push("tls".into());
    } else {
        p.drop_tls_fields();
    }
    p.udp(&mut opts, None)?;
    Ok(("socks", opts))
}

/// Mihomo 带宽字符串（无单位为 Mbps）转为每秒字节数。
fn bandwidth_bytes(p: &Proxy, key: &str, value: &Value) -> Result<u64> {
    let text = match value {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return Err(p.bad_type(key)),
    };
    let lower = text.trim().to_ascii_lowercase();
    let digits_end = lower
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(lower.len());
    let number: u64 = lower[..digits_end]
        .parse()
        .map_err(|_| p.bad_value(key, &text))?;
    let bits_per_unit: u64 = match lower[digits_end..].trim() {
        "" | "m" | "mbps" => 1_000_000,
        "b" | "bps" => 1,
        "k" | "kbps" => 1_000,
        "g" | "gbps" => 1_000_000_000,
        "t" | "tbps" => 1_000_000_000_000,
        _ => return Err(p.bad_value(key, &text)),
    };
    Ok(number.saturating_mul(bits_per_unit) / 8)
}

fn quic_tls(p: &mut Proxy, opts: &mut Opts, host: &str, alpn: bool) -> Result<()> {
    opts.set(
        "tls.server_name",
        p.sni()?.unwrap_or_else(|| host.to_owned()),
    );
    if let Some(ca) = p.string("ca-str")? {
        opts.set("tls.ca_pem", ca);
    }
    p.insecure(opts, "tls.insecure")?;
    if alpn && let Some(list) = p.strings("alpn")? {
        opts.set("tls.alpn", list);
    }
    Ok(())
}

fn hop(p: &mut Proxy, opts: &mut Opts) -> Result<()> {
    if let Some(ports) = p.string("ports")? {
        opts.set("ports", ports);
    }
    match p.take("hop-interval") {
        None => {}
        Some(Value::Number(n)) => opts.set("hop_interval", n.as_u64().unwrap_or(0)),
        Some(Value::String(s)) => match s.split_once('-') {
            Some((low, high)) => {
                let parse = |v: &str| v.trim().parse::<u64>();
                match (parse(low), parse(high)) {
                    (Ok(l), Ok(h)) => {
                        opts.set("hop_interval", l);
                        opts.set("hop_interval_max", h);
                    }
                    _ => return Err(p.bad_value("hop-interval", s)),
                }
            }
            None => opts.set("hop_interval", s),
        },
        Some(_) => return Err(p.bad_type("hop-interval")),
    }
    Ok(())
}

fn congestion(p: &mut Proxy, opts: &mut Opts, key: &str) -> Result<()> {
    if let Some(cc) = p.string("congestion-controller")? {
        let cc = match cc.as_str() {
            "new_reno" | "newreno" => "newreno",
            "cubic" => "cubic",
            "bbr" => "bbr",
            _ => return Err(p.bad_value("congestion-controller", cc)),
        };
        opts.set(key, cc);
    }
    Ok(())
}

fn hysteria(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    hop(p, &mut opts)?;
    if let Some(v) = p.string("auth-str")? {
        opts.set("auth_str", v);
    }
    if let Some(v) = p.string("auth")? {
        opts.set("auth", v);
    }
    for (keys, to) in [
        (["up", "up-speed"], "up_bps"),
        (["down", "down-speed"], "down_bps"),
    ] {
        let mut found = None;
        for key in keys {
            if let Some(v) = p.take(key) {
                found = Some(bandwidth_bytes(p, key, &v)?);
            }
        }
        opts.set(to, found.ok_or_else(|| p.missing(keys[0]))?);
    }
    if let Some(v) = p.string("obfs")?
        && !v.is_empty()
    {
        opts.set("obfs", v);
    }
    let protocol = p.string("protocol")?;
    let obfs_protocol = p.string("obfs-protocol")?;
    if let Some(proto) = obfs_protocol.or(protocol) {
        if !matches!(proto.as_str(), "udp" | "wechat-video") {
            return Err(p.bad_value("protocol", proto));
        }
        opts.set("transport", proto);
    }
    quic_tls(p, &mut opts, &host, true)?;
    p.noop_bool("disable-mtu-discovery", false)?;
    p.noop_bool("fast-open", false)?;
    p.udp(&mut opts, Some("udp"))?;
    Ok(("hysteria1", opts))
}

fn hysteria2(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    hop(p, &mut opts)?;
    opts.set("auth", p.required_string("password")?);
    for key in ["up", "down"] {
        if let Some(v) = p.take(key) {
            match v {
                Value::Number(_) | Value::String(_) => opts.set(key, v),
                _ => return Err(p.bad_type(key)),
            }
        }
    }
    match p.string("obfs")?.as_deref() {
        None | Some("") => {}
        Some("salamander") => {
            opts.set("salamander_password", p.required_string("obfs-password")?);
        }
        Some(other) => return Err(p.bad_value("obfs", other)),
    }
    quic_tls(p, &mut opts, &host, false)?;
    if let Some(alpn) = p.strings("alpn")?
        && alpn != ["h3"]
    {
        return Err(p.bad_value("alpn", alpn.join(",")));
    }
    p.udp(&mut opts, None)?;
    Ok(("hysteria2", opts))
}

fn tuic(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let host = p.required_string("server")?;
    let port = p.port()?;
    let dial = p.string("ip")?.unwrap_or_else(|| host.clone());
    opts.set("server", json!({ "host": dial, "port": port }));
    hop(p, &mut opts)?;
    if let Some(token) = p.string("token")? {
        opts.set("version", 4);
        opts.set("token", token);
    } else {
        opts.set("uuid", p.required_string("uuid")?);
        opts.set("password", p.required_string("password")?);
    }
    quic_tls(p, &mut opts, &host, true)?;
    if let Some(ms) = p.integer("heartbeat-interval")? {
        opts.set("heartbeat_interval_secs", ms.div_ceil(1000).max(1));
    }
    if let Some(mode) = p.string("udp-relay-mode")? {
        opts.set("udp_relay_mode", mode);
    }
    congestion(p, &mut opts, "congestion_control")?;
    p.noop_bool("disable-sni", false)?;
    p.noop_bool("reduce-rtt", false)?;
    p.noop_bool("fast-open", false)?;
    p.noop_bool("udp-over-stream", false)?;
    p.udp(&mut opts, None)?;
    Ok(("tuic", opts))
}

fn shadowquic(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    opts.set("username", p.required_string("username")?);
    opts.set("password", p.required_string("password")?);
    opts.set("server_name", p.sni()?.unwrap_or(host));
    if let Some(alpn) = p.strings("alpn")? {
        opts.set("alpn", alpn);
    }
    if p.boolean("udp-over-stream")? == Some(true) {
        opts.set("udp_mode", "stream");
    }
    congestion(p, &mut opts, "congestion_control")?;
    p.noop_bool("zero-rtt", false)?;
    p.udp(&mut opts, None)?;
    Ok(("shadowquic", opts))
}

fn strip_prefix_len(ip: String) -> String {
    match ip.split_once('/') {
        Some((addr, _)) => addr.to_owned(),
        None => ip,
    }
}

fn wireguard(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("tunnel.private_key", p.required_string("private-key")?);
    let mut addresses = Vec::new();
    for key in ["ip", "ipv6"] {
        if let Some(ip) = p.string(key)? {
            addresses.push(strip_prefix_len(ip));
        }
    }
    if addresses.is_empty() {
        return Err(p.missing("ip"));
    }
    opts.set("tunnel.addresses", addresses);
    if let Some(mtu) = p.integer("mtu")? {
        opts.set("tunnel.mtu", mtu);
    }
    let peer_source = match p.take("peers") {
        None => None,
        Some(Value::Array(mut peers)) if peers.len() == 1 => match peers.pop() {
            Some(Value::Object(map)) => Some(map),
            _ => return Err(p.bad_type("peers")),
        },
        Some(Value::Array(peers)) => return Err(p.bad_value("peers", peers.len())),
        Some(_) => return Err(p.bad_type("peers")),
    };
    let mut peer = match peer_source {
        Some(map) => Proxy {
            name: p.name.clone(),
            prefix: "peers[0].".into(),
            map,
            unimplemented: Vec::new(),
        },
        None => Proxy {
            name: p.name.clone(),
            prefix: String::new(),
            map: std::mem::take(&mut p.map),
            unimplemented: Vec::new(),
        },
    };
    let host = peer.required_string("server")?;
    let port = peer.port()?;
    opts.set("endpoint", json!({ "host": host, "port": port }));
    opts.set("peer.public_key", peer.required_string("public-key")?);
    if let Some(psk) = peer.string("pre-shared-key")? {
        opts.set("peer.preshared_key", psk);
    }
    if let Some(reserved) = peer.take("reserved") {
        opts.set("peer.reserved", reserved);
    }
    let allowed = peer
        .strings("allowed-ips")?
        .unwrap_or_else(|| vec!["0.0.0.0/0".into(), "::/0".into()]);
    opts.set("peer.allowed_ips", allowed);
    if let Some(ka) = peer.integer("persistent-keepalive")? {
        opts.set("peer.persistent_keepalive", ka);
    }
    if peer.prefix.is_empty() {
        p.map = std::mem::take(&mut peer.map);
    } else {
        peer.finish()?;
    }
    p.noop_bool("remote-dns-resolve", false)?;
    p.udp(&mut opts, None)?;
    Ok(("wireguard", opts))
}

/// OpenSSH 公钥行（`ssh-ed25519 AAAA...`）转为 kerlico 主机密钥指纹 `SHA256:<base64>`。
fn ssh_host_key_pin(p: &Proxy, line: &str) -> Result<String> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let trimmed = line.trim();
    if trimmed.starts_with("SHA256:") {
        return Ok(trimmed.to_owned());
    }
    let blob = trimmed
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| p.bad_value("host-key", trimmed))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|_| p.bad_value("host-key", trimmed))?;
    let digest = sha2::Sha256::digest(&raw);
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

fn ssh(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("server", p.server_target()?);
    opts.set("username", p.required_string("username")?);
    let password = p.string("password")?;
    let key = p.string("private-key")?;
    let passphrase = p.string("private-key-passphrase")?;
    match (password, key) {
        (_, Some(key)) => {
            opts.set("auth.type", "publickey");
            if key.trim_start().starts_with("-----BEGIN") {
                opts.set("auth.private_key_pem", key);
            } else {
                opts.set("auth.private_key_file", key);
            }
            if let Some(pp) = passphrase {
                opts.set("auth.passphrase", pp);
            }
        }
        (Some(pw), None) => {
            opts.set("auth.type", "password");
            opts.set("auth.password", pw);
        }
        (None, None) => return Err(p.missing("password")),
    }
    let keys = p
        .strings("host-key")?
        .filter(|k| !k.is_empty())
        .ok_or_else(|| p.missing("host-key"))?;
    let pins = keys
        .iter()
        .map(|k| ssh_host_key_pin(p, k))
        .collect::<Result<Vec<_>>>()?;
    opts.set("host_key_sha256", pins);
    p.ignore_udp()?;
    Ok(("ssh", opts))
}

fn mieru(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("server.host", p.required_string("server")?);
    match (p.has("port"), p.string("port-range")?) {
        (true, None) => {
            let port = p.port()?;
            opts.set("server.port", port);
        }
        (false, Some(range)) => opts.set("port_range", range),
        (true, Some(_)) => return Err(p.unsupported("port-range")),
        (false, None) => return Err(p.missing("port")),
    }
    let transport = p.string("transport")?.unwrap_or_else(|| "TCP".into());
    if !transport.eq_ignore_ascii_case("tcp") {
        return Err(p.bad_value("transport", transport));
    }
    opts.set("transport", "tcp");
    opts.set("username", p.required_string("username")?);
    opts.set("password", p.required_string("password")?);
    if let Some(m) = p.string("multiplexing")? {
        let on = match m.as_str() {
            "MULTIPLEXING_OFF" => false,
            "MULTIPLEXING_DEFAULT"
            | "MULTIPLEXING_LOW"
            | "MULTIPLEXING_MIDDLE"
            | "MULTIPLEXING_HIGH" => true,
            _ => return Err(p.bad_value("multiplexing", m)),
        };
        opts.set("multiplexing", on);
    }
    if let Some(h) = p.string("handshake-mode")? {
        let no_wait = match h.as_str() {
            "HANDSHAKE_NO_WAIT" => true,
            "HANDSHAKE_STANDARD" | "HANDSHAKE_DEFAULT" => false,
            _ => return Err(p.bad_value("handshake-mode", h)),
        };
        opts.set("no_wait", no_wait);
    }
    p.udp(&mut opts, None)?;
    Ok(("mieru", opts))
}

fn sudoku(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    opts.set("protocol.key", p.required_string("key")?);
    if let Some(v) = p.string("aead-method")? {
        opts.set("protocol.aead", v);
    }
    for (from, to) in [
        ("padding-min", "protocol.padding_min"),
        ("padding-max", "protocol.padding_max"),
    ] {
        if let Some(v) = p.integer(from)? {
            opts.set(to, v);
        }
    }
    if let Some(v) = p.string("table-type")? {
        opts.set("protocol.table_type", v);
    }
    let mut tables = p.strings("custom-tables")?.unwrap_or_default();
    if let Some(t) = p.string("custom-table")? {
        tables.push(t);
    }
    if !tables.is_empty() {
        opts.set("protocol.custom_tables", tables);
    }
    if let Some(v) = p.boolean("enable-pure-downlink")? {
        opts.set("protocol.pure_downlink", v);
    }
    if let Some(mut mask) = p.nested("httpmask")? {
        let disabled = mask.boolean("disable")?.unwrap_or(false);
        let mode = mask.string("mode")?;
        if disabled {
            opts.set("http_mask.mode", "raw");
        } else if let Some(mode) = mode {
            opts.set("http_mask.mode", mode);
        }
        let mask_host = mask.string("host")?;
        if mask.boolean("tls")? == Some(true) {
            opts.set(
                "http_mask.tls.server_name",
                mask_host.clone().unwrap_or(host),
            );
        }
        if let Some(h) = mask_host {
            opts.set("http_mask.host", h);
        }
        if let Some(root) = mask.string("path-root")? {
            opts.set("http_mask.path_root", root);
        }
        if let Some(m) = mask.string("multiplex")? {
            opts.set("multiplex", m);
        }
        mask.finish()?;
    }
    p.udp(&mut opts, Some("protocol.udp_enabled"))?;
    Ok(("sudoku", opts))
}

fn trusttunnel(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    opts.set("auth.username", p.required_string("username")?);
    opts.set("auth.password", p.required_string("password")?);
    opts.set("tls.server_name", p.sni()?.unwrap_or(host));
    p.insecure(&mut opts, "tls.insecure")?;
    p.fingerprint(&mut opts, "tls.fingerprint")?;
    if p.boolean("quic")? == Some(true) {
        opts.set("transport", "h3");
    }
    for (from, to) in [
        ("max-connections", "limits.max_connections"),
        ("max-streams", "limits.max_streams"),
    ] {
        if let Some(v) = p.integer(from)? {
            opts.set(to, v);
        }
    }
    p.noop_bool("health-check", true)?;
    p.udp(&mut opts, Some("udp"))?;
    Ok(("trusttunnel", opts))
}

fn gost_relay(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    let target = p.server_target()?;
    let host = target["host"].as_str().unwrap_or_default().to_owned();
    opts.set("server", target);
    for key in ["username", "password"] {
        if let Some(v) = p.string(key)? {
            opts.set(key, v);
        }
    }
    if let Some(v) = p.boolean("mux")? {
        opts.set("mux", v);
    }
    let sni = p.sni()?;
    if p.boolean("tls")? == Some(true) {
        opts.set("tls.server_name", sni.unwrap_or(host));
        p.insecure(&mut opts, "tls.insecure")?;
        p.fingerprint(&mut opts, "tls.fingerprint")?;
    } else {
        p.drop_tls_fields();
        opts.set("allow_insecure", true);
    }
    p.udp(&mut opts, None)?;
    Ok(("gost-relay", opts))
}

fn tailscale(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("auth_key", p.required_string("auth-key")?);
    opts.set(
        "control_url",
        p.string("control-url")?
            .unwrap_or_else(|| "https://controlplane.tailscale.com".into()),
    );
    if let Some(v) = p.string("hostname")? {
        opts.set("hostname", v);
    }
    if let Some(v) = p.boolean("ephemeral")? {
        opts.set("ephemeral", v);
    }
    if let Some(v) = p.boolean("accept-routes")? {
        opts.set("accept_routes", v);
    }
    if let Some(v) = p.string("exit-node")? {
        opts.set("exit_node", v);
    }
    p.udp(&mut opts, None)?;
    Ok(("tailscale", opts))
}

fn openvpn(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("remote", p.server_target()?);
    if let Some(proto) = p.string("proto")? {
        opts.set("proto", proto.to_ascii_lowercase());
    }
    auth_pair(p, &mut opts)?;
    if let Some(Value::Object(auth)) = opts.0.remove("auth") {
        opts.0.extend(auth);
    }
    opts.set("ca_pem", p.required_string("ca")?);
    for (from, to) in [("cert", "cert_pem"), ("key", "key_pem")] {
        if let Some(v) = p.string(from)? {
            opts.set(to, v);
        }
    }
    if let Some(key) = p.string("tls-auth")? {
        opts.set("tls_auth.key", key);
        if let Some(dir) = p.integer("key-direction")? {
            opts.set("tls_auth.direction", dir);
        }
        if let Some(digest) = p.string("auth")? {
            opts.set("tls_auth.digest", digest);
        }
    }
    if let Some(v) = p.string("tls-crypt")? {
        opts.set("tls_crypt_key", v);
    }
    if let Some(v) = p.string("tls-crypt-v2")? {
        opts.set("tls_crypt_v2", v);
    }
    let mut ciphers = p.strings("data-ciphers")?.unwrap_or_default();
    if ciphers.len() == 1 && ciphers[0].contains(':') {
        ciphers = ciphers[0].split(':').map(str::to_owned).collect();
    }
    if let Some(c) = p.string("cipher")?
        && !ciphers.contains(&c)
    {
        ciphers.push(c);
    }
    if !ciphers.is_empty() {
        opts.set("ciphers", ciphers);
    }
    for (from, to) in [
        ("ping", "ping_secs"),
        ("ping-restart", "ping_restart_secs"),
        ("mtu", "mtu"),
    ] {
        if let Some(v) = p.integer(from)? {
            opts.set(to, v);
        }
    }
    if let Some(v) = p.integer("handshake-timeout")?
        && v > 0
    {
        opts.set("handshake_timeout_secs", v);
    }
    p.noop_bool("remote-dns-resolve", false)?;
    p.udp(&mut opts, None)?;
    Ok(("openvpn", opts))
}

fn easytier(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("network_name", p.required_string("network-name")?);
    opts.set("network_secret", p.required_string("network-secret")?);
    opts.set(
        "peers",
        p.strings("peers")?.ok_or_else(|| p.missing("peers"))?,
    );
    for key in ["hostname", "ipv4"] {
        if let Some(v) = p.string(key)? {
            opts.set(key, v);
        }
    }
    if p.boolean("dhcp")? == Some(true) && opts.0.contains_key("ipv4") {
        return Err(p.unsupported("dhcp"));
    }
    if let Some(v) = p.boolean("secure-mode")? {
        opts.set("secure_mode", v);
    }
    if let Some(v) = p.strings("exit-nodes")? {
        opts.set("exit_nodes", v);
    }
    let algorithm = p.string("encryption-algorithm")?;
    match p.boolean("enable-encryption")? {
        Some(false) => opts.set("encryption", "none"),
        _ => {
            if let Some(a) = algorithm {
                opts.set("encryption", a);
            }
        }
    }
    p.udp(&mut opts, None)?;
    Ok(("easytier", opts))
}

fn zerotier(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    let mut opts = Opts::default();
    opts.set("network", p.required_string("network")?);
    opts.set("identity", p.required_string("identity-secret")?);
    opts.set("public_planet", true);
    if let Some(mode) = p.string("tcp-fallback-mode")? {
        let mapped = match mode.as_str() {
            "auto" => "auto",
            "force" => "always",
            "disable" => "never",
            _ => return Err(p.bad_value("tcp-fallback-mode", mode)),
        };
        opts.set("tcp_fallback_mode", mapped);
    }
    if let Some(v) = p.string("tcp-fallback-relay")? {
        opts.set("tcp_fallback_relay", v);
    }
    p.noop_bool("remote-dns-resolve", false)?;
    p.udp(&mut opts, None)?;
    Ok(("zerotier", opts))
}

fn direct(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    p.udp(&mut Opts::default(), None)?;
    Ok(("direct", Opts::default()))
}

fn reject(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    p.udp(&mut Opts::default(), None)?;
    Ok(("reject", Opts::default()))
}

fn dns(p: &mut Proxy) -> Result<(&'static str, Opts)> {
    p.udp(&mut Opts::default(), None)?;
    Ok(("dns", Opts::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(yaml: &str) -> Result<MihomoOutbound> {
        let value = crate::parse_yaml_with_anchors(yaml).expect("yaml");
        translate_proxy(value)
    }

    #[test]
    fn fields_mihomo_does_not_define_for_the_type_are_ignored() {
        let out = map(
            "name: hk\ntype: vmess\nserver: a.example.com\nport: 443\nuuid: 11111111-1111-1111-1111-111111111111\nnetwork: ws\nws-opts:\n  path: /ws\n  bogus: 1\ngrpc-opts:\n  grpc-service-name: unused\nup: 100\nobfs-password: x\n",
        )
        .unwrap();
        assert_eq!(out.options["transport"]["path"], "/ws");
        assert!(out.options["transport"].get("service_name").is_none());
        map("name: x\ntype: ss\nserver: a\nport: 1\ncipher: aes-128-gcm\npassword: p\nfoo: 1\nskip-cert-verify: true\n")
            .unwrap();
        map("name: h\ntype: hysteria2\nserver: a.example.com\nport: 443\npassword: p\nudp: false\nuuid: u\n")
            .unwrap();
    }

    #[test]
    fn mihomo_key_matching_ignores_case_and_underscores() {
        let out = map("name: t\ntype: trojan\nserver: a.example.com\nport: 443\npassword: p\nSkip_Cert_Verify: true\n").unwrap();
        assert_eq!(out.options["security"]["insecure"], true);
    }

    #[test]
    fn unimplemented_security_fields_fail_and_others_warn() {
        let base = "name: s\ntype: trojan\nserver: a.example.com\nport: 443\npassword: p\n";
        for extra in [
            "ip-version: ipv6\n",
            "fingerprint: ab12\n",
            "ech-opts:\n  enable: true\n",
            "reality-opts:\n  public-key: k\n",
        ] {
            let err = map(&format!("{base}{extra}")).unwrap_err().to_string();
            let field = extra.split(':').next().unwrap();
            assert!(err.contains("s") && err.contains(field), "{extra}: {err}");
        }
        for extra in [
            "skip-cert-verify: false\n",
            "udp: true\n",
            "udp: false\n",
            "ip-version: dual\n",
            "client-fingerprint: \"\"\n",
            "ech-opts:\n  enable: false\n",
            "alpn: [h2]\n",
            "smux:\n  enabled: false\n",
        ] {
            map(&format!("{base}{extra}")).expect(extra);
        }
        let err = map("name: q\ntype: socks5\nserver: a\nport: 1\ntls: true\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("tls"), "{err}");
    }

    #[test]
    fn client_fingerprint_maps_to_each_tls_carrier() {
        for (yaml, path) in [
            (
                "type: vmess\nuuid: 11111111-1111-1111-1111-111111111111\ntls: true\n",
                "/tls/fingerprint",
            ),
            ("type: trojan\npassword: p\n", "/security/fingerprint"),
            (
                "type: vless\nuuid: 11111111-1111-1111-1111-111111111111\ntls: true\n",
                "/security/fingerprint",
            ),
            ("type: anytls\npassword: p\n", "/tls/fingerprint"),
            (
                "type: trusttunnel\nusername: u\npassword: p\n",
                "/tls/fingerprint",
            ),
            ("type: gost-relay\ntls: true\n", "/tls/fingerprint"),
            (
                "type: ss\ncipher: aes-128-gcm\npassword: p\nplugin: shadow-tls\nplugin-opts:\n  host: a.example.com\n  password: x\n",
                "/tls/fingerprint",
            ),
        ] {
            for (mihomo, profile) in [
                ("chrome", "chrome"),
                ("Firefox", "hellofirefox_120"),
                ("chrome120", "hellochrome_120"),
            ] {
                let out = map(&format!(
                    "name: n\nserver: a.example.com\nport: 443\nclient-fingerprint: {mihomo}\n{yaml}"
                ))
                .unwrap_or_else(|e| panic!("{yaml}: {e}"));
                assert_eq!(out.options.pointer(path), Some(&json!(profile)), "{yaml}");
            }
        }
        for unshaped in ["none", "\"\"", "chrome_psk"] {
            let out = map(&format!(
                "name: n\ntype: trojan\nserver: a.example.com\nport: 443\npassword: p\nclient-fingerprint: {unshaped}\n"
            ))
            .unwrap();
            assert!(
                out.options["security"].get("fingerprint").is_none(),
                "{unshaped}"
            );
        }
        let plain = map("name: n\ntype: vmess\nserver: a\nport: 1\nuuid: 11111111-1111-1111-1111-111111111111\nclient-fingerprint: chrome\n").unwrap();
        assert!(plain.options.get("tls").is_none());
    }

    #[test]
    fn skip_cert_verify_maps_to_each_tls_carrier() {
        for (yaml, path) in [
            (
                "type: vmess\nuuid: 11111111-1111-1111-1111-111111111111\ntls: true\n",
                "/tls/insecure",
            ),
            ("type: trojan\npassword: p\n", "/security/insecure"),
            (
                "type: vless\nuuid: 11111111-1111-1111-1111-111111111111\ntls: true\n",
                "/security/allow_insecure",
            ),
            ("type: anytls\npassword: p\n", "/tls/insecure"),
            ("type: http\ntls: true\n", "/tls/insecure"),
            ("type: hysteria2\npassword: p\n", "/tls/insecure"),
            (
                "type: hysteria\nauth-str: a\nup: 10\ndown: 10\n",
                "/tls/insecure",
            ),
            ("type: tuic\nuuid: u\npassword: p\n", "/tls/insecure"),
            (
                "type: trusttunnel\nusername: u\npassword: p\n",
                "/tls/insecure",
            ),
            ("type: gost-relay\ntls: true\n", "/tls/insecure"),
            (
                "type: ss\ncipher: aes-128-gcm\npassword: p\nplugin: v2ray-plugin\nplugin-opts:\n  mode: websocket\n  tls: true\n  skip-cert-verify: true\n",
                "/plugin_opts/skip_cert_verify",
            ),
            (
                "type: ss\ncipher: aes-128-gcm\npassword: p\nplugin: shadow-tls\nplugin-opts:\n  host: a.example.com\n  password: x\n  skip-cert-verify: true\n",
                "/tls/insecure",
            ),
        ] {
            let out = map(&format!(
                "name: n\nserver: a.example.com\nport: 443\nskip-cert-verify: true\n{yaml}"
            ))
            .unwrap_or_else(|e| panic!("{yaml}: {e}"));
            assert_eq!(out.options.pointer(path), Some(&json!(true)), "{yaml}");
        }
        let plain = map("name: n\ntype: vmess\nserver: a\nport: 1\nuuid: 11111111-1111-1111-1111-111111111111\nskip-cert-verify: true\nservername: x\n").unwrap();
        assert!(plain.options.get("tls").is_none());
    }

    #[test]
    fn unsupported_types_error_with_type_name() {
        let err = map("name: m\ntype: masque\nserver: a\nport: 1\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("masque"), "{err}");
    }

    #[test]
    fn ss_2022_and_shadow_tls_route_to_dedicated_kinds() {
        let out = map("name: a\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: 2022-blake3-aes-128-gcm\npassword: \"AAAAAAAAAAAAAAAAAAAAAA==:BBBBBBBBBBBBBBBBBBBBBB==\"\n").unwrap();
        assert_eq!(out.kind, "ss2022");
        assert_eq!(out.options["key"], "BBBBBBBBBBBBBBBBBBBBBB==");
        assert_eq!(out.options["identity_keys"][0], "AAAAAAAAAAAAAAAAAAAAAA==");
        let out = map("name: b\ntype: ss\nserver: 1.2.3.4\nport: 443\ncipher: aes-128-gcm\npassword: pw\nplugin: shadow-tls\nplugin-opts:\n  host: cloud.tencent.com\n  password: stpw\n  version: 3\n").unwrap();
        assert_eq!(out.kind, "shadowtls");
        assert_eq!(out.options["tls"]["server_name"], "cloud.tencent.com");
        assert_eq!(out.options["inner"]["options"]["method"], "aes-128-gcm");
        let mux = map("name: a\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: 2022-blake3-aes-128-gcm\npassword: AAAAAAAAAAAAAAAAAAAAAA==\nsmux:\n  enabled: true\n  protocol: h2mux\n  max-connections: 2\n").unwrap();
        assert_eq!(mux.kind, "ss2022");
        assert_eq!(mux.options["multiplex"]["protocol"], "h2mux");
        assert_eq!(mux.options["multiplex"]["max_connections"], 2);
    }

    #[test]
    fn bandwidth_units_follow_mihomo() {
        let out = map("name: h\ntype: hysteria\nserver: a.example.com\nport: 443\nauth-str: x\nup: 30 Mbps\ndown: 200\n").unwrap();
        assert_eq!(out.options["up_bps"], 3_750_000);
        assert_eq!(out.options["down_bps"], 25_000_000);
    }

    #[test]
    fn smux_brutal_opts_map_to_multiplex_brutal() {
        let out = map("name: s\ntype: ss\nserver: a.example.com\nport: 443\ncipher: aes-128-gcm\npassword: x\nsmux:\n  enabled: true\n  protocol: yamux\n  max-connections: 2\n  brutal-opts:\n    enabled: true\n    up: 30 Mbps\n    down: 100\n").unwrap();
        let mux = &out.options["multiplex"];
        assert_eq!(mux["protocol"], "yamux");
        assert_eq!(mux["max_connections"], 2);
        assert_eq!(mux["brutal"]["up_mbps"], 30);
        assert_eq!(mux["brutal"]["down_mbps"], 100);
        assert!(map("name: s\ntype: ss\nserver: a.example.com\nport: 443\ncipher: aes-128-gcm\npassword: x\nsmux:\n  enabled: true\n  brutal-opts:\n    enabled: true\n    up: 30\n").is_err());
    }
}
