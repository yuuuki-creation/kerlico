//! 分享链接解析为 Mihomo 代理映射，再经 [`crate::mihomo`] 映射为 kerlico 出站，
//! 与 YAML `proxies` 和订阅成员走同一套字段映射。

use base64::Engine as _;
use kerlico_core::{Error, Result};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// 解析一行分享链接，返回 Mihomo 代理映射。`seq` 用于链接无名称时生成默认名。
pub(crate) fn parse(uri: &str, seq: usize) -> Result<Value> {
    let (scheme, rest) = uri.split_once("://").ok_or_else(|| malformed(uri))?;
    let scheme = scheme.to_ascii_lowercase();
    let (body, name) = match rest.rsplit_once('#') {
        Some((b, f)) => (b, Some(percent_decode(f)).filter(|s| !s.is_empty())),
        None => (rest, None),
    };
    let mut proxy = match scheme.as_str() {
        "vmess" if !body.contains('@') => vmess_json(&scheme, body)?,
        "ssr" => ssr(&scheme, body)?,
        "ss" => shadowsocks(&scheme, body)?,
        "vmess" | "vless" | "trojan" => v2ray_url(&scheme, body)?,
        "hysteria2" | "hy2" => hysteria2(&scheme, body)?,
        "hysteria" => hysteria(&scheme, body)?,
        "tuic" => tuic(&scheme, body)?,
        "socks" | "socks5" | "http" | "https" => socks_http(&scheme, body)?,
        "anytls" => anytls(&scheme, body)?,
        "wireguard" | "wg" => wireguard(&scheme, body)?,
        _ => return Err(Error::Config(format!("分享链接格式不合法：{scheme}"))),
    };
    if !proxy.contains_key("name") {
        let kind = proxy["type"].as_str().unwrap_or("proxy").to_owned();
        proxy.insert(
            "name".into(),
            Value::String(name.unwrap_or_else(|| format!("{kind}-{seq}"))),
        );
    } else if let Some(n) = name {
        proxy.insert("name".into(), Value::String(n));
    }
    Ok(Value::Object(proxy))
}

fn malformed(scheme: &str) -> Error {
    Error::Config(format!(
        "分享链接格式不合法：{}",
        scheme.split("://").next().unwrap_or(scheme)
    ))
}

/// 查询参数集合；未被取走的参数报错。
struct Query {
    scheme: String,
    params: BTreeMap<String, String>,
}

impl Query {
    fn parse(scheme: &str, raw: Option<&str>) -> Self {
        let mut params = BTreeMap::new();
        for pair in raw.unwrap_or("").split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let (k, v) = (percent_decode(k), percent_decode(v));
            if !k.is_empty() && !v.is_empty() {
                params.insert(k, v);
            }
        }
        Self {
            scheme: scheme.to_owned(),
            params,
        }
    }
    fn take(&mut self, keys: &[&str]) -> Option<String> {
        let mut found = None;
        for k in keys {
            if let Some(v) = self.params.remove(*k) {
                found.get_or_insert(v);
            }
        }
        found
    }
    fn flag(&mut self, keys: &[&str]) -> Option<bool> {
        self.take(keys)
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    }
    /// 只接受 `allowed` 中的无效果取值。
    fn noop(&mut self, key: &str, allowed: &[&str]) -> Result<()> {
        match self.params.remove(key) {
            Some(v) if !allowed.contains(&v.as_str()) => Err(self.unsupported(key)),
            _ => Ok(()),
        }
    }
    fn unsupported(&self, key: &str) -> Error {
        Error::Config(format!("分享链接 {} 的参数 {key} 不受支持", self.scheme))
    }
    fn finish(self) -> Result<()> {
        match self.params.keys().next() {
            Some(k) => Err(self.unsupported(k)),
            None => Ok(()),
        }
    }
}

struct Authority {
    user: Option<String>,
    host: String,
    port: u16,
}

/// 拆出 `userinfo@host:port[/]?query`。
fn split_url<'a>(scheme: &str, body: &'a str) -> Result<(Authority, Option<&'a str>)> {
    let (authority, query) = match body.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (body, None),
    };
    let authority = authority.trim_end_matches('/');
    let (user, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_owned()), h),
        None => (None, authority),
    };
    let (host, port) = hostport.rsplit_once(':').ok_or_else(|| malformed(scheme))?;
    let port = port.parse::<u16>().map_err(|_| malformed(scheme))?;
    Ok((
        Authority {
            user,
            host: host.trim_matches(&['[', ']'][..]).to_owned(),
            port,
        },
        query,
    ))
}

fn base(kind: &str, host: &str, port: u16) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), Value::String(kind.into()));
    m.insert("server".into(), Value::String(host.into()));
    m.insert("port".into(), Value::from(port));
    m
}

fn insecure(q: &mut Query, m: &mut Map<String, Value>) {
    if let Some(v) = q.flag(&[
        "insecure",
        "allowInsecure",
        "allow_insecure",
        "skip-cert-verify",
    ]) {
        m.insert("skip-cert-verify".into(), Value::Bool(v));
    }
}

fn alpn(q: &mut Query, m: &mut Map<String, Value>) {
    if let Some(v) = q.take(&["alpn"]) {
        let list: Vec<Value> = v.split(',').map(|s| Value::String(s.into())).collect();
        m.insert("alpn".into(), Value::Array(list));
    }
}

fn shadowsocks(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let resolved;
    let body = if body.contains('@') {
        body
    } else {
        let (encoded, query) = match body.split_once('?') {
            Some((e, q)) => (e, Some(q)),
            None => (body, None),
        };
        let decoded =
            decode_base64_text(encoded.trim_end_matches('/')).ok_or_else(|| malformed(scheme))?;
        resolved = match query {
            Some(q) => format!("{decoded}?{q}"),
            None => decoded,
        };
        resolved.as_str()
    };
    let (auth, query) = split_url(scheme, body)?;
    let user = auth.user.ok_or_else(|| malformed(scheme))?;
    let user = if user.contains(':') {
        percent_decode(&user)
    } else {
        decode_base64_text(&percent_decode(&user)).ok_or_else(|| malformed(scheme))?
    };
    let (cipher, password) = user.split_once(':').ok_or_else(|| malformed(scheme))?;
    let mut m = base("ss", &auth.host, auth.port);
    m.insert("cipher".into(), Value::String(cipher.into()));
    m.insert("password".into(), Value::String(password.into()));
    let mut q = Query::parse(scheme, query);
    if let Some(plugin) = q.take(&["plugin"]) {
        let mut parts = plugin.split(';');
        let name = parts.next().unwrap_or_default();
        let mut opts = Map::new();
        let plugin_name = match name {
            "obfs-local" | "simple-obfs" | "obfs" => "obfs",
            "v2ray-plugin" => "v2ray-plugin",
            _ => return Err(q.unsupported("plugin")),
        };
        for part in parts {
            let (k, v) = part.split_once('=').unwrap_or((part, "true"));
            let (key, value) = match k {
                "obfs" => ("mode", Value::String(v.into())),
                "obfs-host" | "host" => ("host", Value::String(v.into())),
                "mode" => ("mode", Value::String(v.into())),
                "path" => ("path", Value::String(v.into())),
                "tls" => ("tls", Value::Bool(v != "false")),
                "mux" => ("mux", Value::Bool(v != "0" && v != "false")),
                _ => return Err(q.unsupported(&format!("plugin.{k}"))),
            };
            opts.insert(key.into(), value);
        }
        m.insert("plugin".into(), Value::String(plugin_name.into()));
        m.insert("plugin-opts".into(), Value::Object(opts));
    }
    if let Some(v) = q.flag(&["udp-over-tcp", "uot"]) {
        m.insert("udp-over-tcp".into(), Value::Bool(v));
    }
    q.finish()?;
    Ok(m)
}

fn ssr(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let decoded = decode_base64_text(body.trim()).ok_or_else(|| malformed(scheme))?;
    let (main, query) = match decoded.split_once("/?") {
        Some((m, q)) => (m.to_owned(), Some(q.to_owned())),
        None => (decoded.trim_end_matches('/').to_owned(), None),
    };
    let parts: Vec<&str> = main.rsplitn(6, ':').collect();
    let [pass, obfs, method, protocol, port, host] = parts[..] else {
        return Err(malformed(scheme));
    };
    let port = port.parse::<u16>().map_err(|_| malformed(scheme))?;
    let mut m = base("ssr", host, port);
    m.insert("cipher".into(), Value::String(method.into()));
    m.insert("protocol".into(), Value::String(protocol.into()));
    m.insert("obfs".into(), Value::String(obfs.into()));
    let password = decode_base64_text(pass).ok_or_else(|| malformed(scheme))?;
    m.insert("password".into(), Value::String(password));
    let mut q = Query::parse(scheme, query.as_deref());
    let mut b64 = |keys: &[&str]| -> Result<Option<String>> {
        match q.take(keys) {
            None => Ok(None),
            Some(v) => decode_base64_text(&v)
                .map(Some)
                .ok_or_else(|| malformed(scheme)),
        }
    };
    if let Some(v) = b64(&["obfsparam"])? {
        m.insert("obfs-param".into(), Value::String(v));
    }
    if let Some(v) = b64(&["protoparam"])? {
        m.insert("protocol-param".into(), Value::String(v));
    }
    if let Some(v) = b64(&["remarks"])?.filter(|s| !s.is_empty()) {
        m.insert("name".into(), Value::String(v));
    }
    // `group` 只是客户端分组名，不影响连接。
    let _ = q.take(&["group"]);
    q.finish()?;
    Ok(m)
}

fn vmess_json(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let text = decode_base64_text(body.trim()).ok_or_else(|| malformed(scheme))?;
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(&text) else {
        return Err(malformed(scheme));
    };
    let mut q = Query {
        scheme: scheme.into(),
        params: obj
            .into_iter()
            .map(|(k, v)| {
                let s = match v {
                    Value::String(s) => s,
                    other => other.to_string(),
                };
                (k, s)
            })
            .filter(|(_, v)| !v.is_empty())
            .collect(),
    };
    let host = q.take(&["add"]).ok_or_else(|| malformed(scheme))?;
    let port = q
        .take(&["port"])
        .and_then(|p| p.parse::<u16>().ok())
        .ok_or_else(|| malformed(scheme))?;
    let mut m = base("vmess", &host, port);
    if let Some(name) = q.take(&["ps"]) {
        m.insert("name".into(), Value::String(percent_decode(&name)));
    }
    m.insert(
        "uuid".into(),
        Value::String(q.take(&["id"]).ok_or_else(|| malformed(scheme))?),
    );
    let aid = q.take(&["aid"]).unwrap_or_else(|| "0".into());
    m.insert(
        "alterId".into(),
        Value::from(aid.parse::<u64>().map_err(|_| q.unsupported("aid"))?),
    );
    m.insert(
        "cipher".into(),
        Value::String(q.take(&["scy"]).unwrap_or_else(|| "auto".into())),
    );
    let _ = q.take(&["v"]);
    if q.take(&["tls"]).is_some_and(|t| t == "tls") {
        m.insert("tls".into(), Value::Bool(true));
    }
    if let Some(sni) = q.take(&["sni"]) {
        m.insert("servername".into(), Value::String(sni));
    }
    alpn(&mut q, &mut m);
    if let Some(fp) = q.take(&["fp"]) {
        m.insert("client-fingerprint".into(), Value::String(fp));
    }
    q.noop("type", &["none"])?;
    let network = q.take(&["net"]).unwrap_or_else(|| "tcp".into());
    transport(&mut q, &mut m, &network, &["host"], &["path"])?;
    insecure(&mut q, &mut m);
    q.finish()?;
    Ok(m)
}

/// `type`/`net` 及 ws、grpc 参数映射到 Mihomo `network` 与 `*-opts`。
fn transport(
    q: &mut Query,
    m: &mut Map<String, Value>,
    network: &str,
    host_keys: &[&str],
    path_keys: &[&str],
) -> Result<()> {
    match network {
        "tcp" | "raw" => {
            q.noop("headerType", &["none"])?;
        }
        "ws" | "httpupgrade" => {
            let mut ws = Map::new();
            if let Some(path) = q.take(path_keys) {
                ws.insert("path".into(), Value::String(path));
            }
            if let Some(host) = q.take(host_keys) {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            if network == "httpupgrade" {
                ws.insert("v2ray-http-upgrade".into(), Value::Bool(true));
            }
            m.insert("network".into(), Value::String("ws".into()));
            m.insert("ws-opts".into(), Value::Object(ws));
        }
        "grpc" => {
            let mut grpc = Map::new();
            let mut names = vec!["serviceName"];
            names.extend_from_slice(path_keys);
            if let Some(name) = q.take(&names) {
                grpc.insert("grpc-service-name".into(), Value::String(name));
            }
            q.noop("mode", &["gun"])?;
            m.insert("network".into(), Value::String("grpc".into()));
            m.insert("grpc-opts".into(), Value::Object(grpc));
        }
        _ => return Err(q.unsupported("type")),
    }
    Ok(())
}

fn v2ray_url(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let user = percent_decode(&auth.user.ok_or_else(|| malformed(scheme))?);
    let mut m = base(scheme, &auth.host, auth.port);
    let mut q = Query::parse(scheme, query);
    if scheme == "trojan" {
        m.insert("password".into(), Value::String(user));
        q.noop("security", &["tls"])?;
    } else {
        m.insert("uuid".into(), Value::String(user));
        match q.take(&["security"]).as_deref() {
            None | Some("none") => {}
            Some("tls") => {
                m.insert("tls".into(), Value::Bool(true));
            }
            Some("reality") if scheme == "vless" => {
                m.insert("tls".into(), Value::Bool(true));
                let mut reality = Map::new();
                if let Some(pbk) = q.take(&["pbk"]) {
                    reality.insert("public-key".into(), Value::String(pbk));
                }
                if let Some(sid) = q.take(&["sid"]) {
                    reality.insert("short-id".into(), Value::String(sid));
                }
                q.noop("spx", &["/"])?;
                m.insert("reality-opts".into(), Value::Object(reality));
            }
            Some(_) => return Err(q.unsupported("security")),
        }
        if scheme == "vless" {
            q.noop("encryption", &["none"])?;
            if let Some(flow) = q.take(&["flow"]) {
                m.insert("flow".into(), Value::String(flow));
            }
            if let Some(pe) = q.take(&["packetEncoding"]) {
                m.insert("packet-encoding".into(), Value::String(pe));
            }
        } else if let Some(enc) = q.take(&["encryption"]) {
            m.insert("cipher".into(), Value::String(enc));
        }
    }
    if let Some(sni) = q.take(&["sni", "peer"]) {
        let key = if scheme == "trojan" {
            "sni"
        } else {
            "servername"
        };
        m.insert(key.into(), Value::String(sni));
    }
    if let Some(fp) = q.take(&["fp"]) {
        m.insert("client-fingerprint".into(), Value::String(fp));
    }
    alpn(&mut q, &mut m);
    insecure(&mut q, &mut m);
    let network = q.take(&["type"]).unwrap_or_else(|| "tcp".into());
    transport(&mut q, &mut m, &network, &["host"], &["path"])?;
    q.finish()?;
    Ok(m)
}

fn hysteria2(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let mut m = base("hysteria2", &auth.host, auth.port);
    let password = percent_decode(&auth.user.ok_or_else(|| malformed(scheme))?);
    m.insert("password".into(), Value::String(password));
    let mut q = Query::parse(scheme, query);
    if let Some(sni) = q.take(&["sni", "peer"]) {
        m.insert("sni".into(), Value::String(sni));
    }
    if let Some(obfs) = q.take(&["obfs"]) {
        m.insert("obfs".into(), Value::String(obfs));
    }
    if let Some(pw) = q.take(&["obfs-password"]) {
        m.insert("obfs-password".into(), Value::String(pw));
    }
    if let Some(ports) = q.take(&["mport", "ports"]) {
        m.insert("ports".into(), Value::String(ports));
    }
    insecure(&mut q, &mut m);
    q.finish()?;
    Ok(m)
}

fn hysteria(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let mut m = base("hysteria", &auth.host, auth.port);
    let mut q = Query::parse(scheme, query);
    for (from, to) in [
        (&["auth"][..], "auth-str"),
        (&["peer", "sni"][..], "sni"),
        (&["upmbps", "up"][..], "up"),
        (&["downmbps", "down"][..], "down"),
        (&["obfsParam", "obfs"][..], "obfs"),
        (&["protocol"][..], "protocol"),
        (&["mport", "ports"][..], "ports"),
    ] {
        if let Some(v) = q.take(from) {
            m.insert(to.into(), Value::String(v));
        }
    }
    alpn(&mut q, &mut m);
    insecure(&mut q, &mut m);
    q.finish()?;
    Ok(m)
}

fn tuic(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let mut m = base("tuic", &auth.host, auth.port);
    let user = percent_decode(&auth.user.ok_or_else(|| malformed(scheme))?);
    match user.split_once(':') {
        Some((uuid, pass)) => {
            m.insert("uuid".into(), Value::String(uuid.into()));
            m.insert("password".into(), Value::String(pass.into()));
        }
        None => {
            m.insert("token".into(), Value::String(user));
        }
    }
    let mut q = Query::parse(scheme, query);
    for (from, to) in [
        (&["sni"][..], "sni"),
        (
            &["congestion_control", "congestion-controller"][..],
            "congestion-controller",
        ),
        (&["udp_relay_mode", "udp-relay-mode"][..], "udp-relay-mode"),
    ] {
        if let Some(v) = q.take(from) {
            m.insert(to.into(), Value::String(v));
        }
    }
    if let Some(v) = q.flag(&["disable_sni"]) {
        m.insert("disable-sni".into(), Value::Bool(v));
    }
    alpn(&mut q, &mut m);
    insecure(&mut q, &mut m);
    q.finish()?;
    Ok(m)
}

fn socks_http(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let kind = if scheme.starts_with("socks") {
        "socks5"
    } else {
        "http"
    };
    let mut m = base(kind, &auth.host, auth.port);
    if let Some(user) = auth.user {
        let decoded = if user.contains(':') {
            percent_decode(&user)
        } else {
            decode_base64_text(&user).unwrap_or_else(|| percent_decode(&user))
        };
        let (u, p) = decoded.split_once(':').ok_or_else(|| malformed(scheme))?;
        m.insert("username".into(), Value::String(u.into()));
        m.insert("password".into(), Value::String(p.into()));
    }
    if scheme == "https" {
        m.insert("tls".into(), Value::Bool(true));
    }
    let mut q = Query::parse(scheme, query);
    if let Some(sni) = q.take(&["sni"]) {
        m.insert("sni".into(), Value::String(sni));
    }
    insecure(&mut q, &mut m);
    q.finish()?;
    Ok(m)
}

fn anytls(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let mut m = base("anytls", &auth.host, auth.port);
    let password = percent_decode(&auth.user.ok_or_else(|| malformed(scheme))?);
    m.insert("password".into(), Value::String(password));
    let mut q = Query::parse(scheme, query);
    if let Some(sni) = q.take(&["sni", "peer"]) {
        m.insert("sni".into(), Value::String(sni));
    }
    insecure(&mut q, &mut m);
    q.finish()?;
    Ok(m)
}

fn wireguard(scheme: &str, body: &str) -> Result<Map<String, Value>> {
    let (auth, query) = split_url(scheme, body)?;
    let mut m = base("wireguard", &auth.host, auth.port);
    let key = percent_decode(&auth.user.ok_or_else(|| malformed(scheme))?);
    m.insert("private-key".into(), Value::String(key));
    let mut q = Query::parse(scheme, query);
    if let Some(addresses) = q.take(&["address", "ip"]) {
        for addr in addresses.split(',') {
            let bare = addr.split('/').next().unwrap_or(addr);
            let key = if bare.contains(':') { "ipv6" } else { "ip" };
            m.insert(key.into(), Value::String(addr.into()));
        }
    }
    for (from, to) in [
        (&["publickey", "public-key", "peer"][..], "public-key"),
        (&["presharedkey", "pre-shared-key"][..], "pre-shared-key"),
    ] {
        if let Some(v) = q.take(from) {
            m.insert(to.into(), Value::String(v));
        }
    }
    if let Some(r) = q.take(&["reserved"]) {
        let parts: Vec<&str> = r.split(',').collect();
        let value = match parts[..] {
            [a, b, c] => match (
                a.trim().parse::<u8>(),
                b.trim().parse::<u8>(),
                c.trim().parse::<u8>(),
            ) {
                (Ok(a), Ok(b), Ok(c)) => json!([a, b, c]),
                _ => return Err(q.unsupported("reserved")),
            },
            _ => Value::String(r),
        };
        m.insert("reserved".into(), value);
    }
    if let Some(v) = q.take(&["mtu"]) {
        let mtu = v.parse::<u64>().map_err(|_| q.unsupported("mtu"))?;
        m.insert("mtu".into(), Value::from(mtu));
    }
    if let Some(v) = q.take(&["allowedips", "allowed-ips"]) {
        let list: Vec<Value> = v.split(',').map(|s| Value::String(s.into())).collect();
        m.insert("allowed-ips".into(), Value::Array(list));
    }
    q.finish()?;
    Ok(m)
}

pub(crate) fn decode_base64_text(s: &str) -> Option<String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    let engine = if cleaned.contains(['-', '_']) {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD
    };
    let bytes = engine.decode(cleaned).ok()?;
    String::from_utf8(bytes).ok()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_owned())
}
