//! 上游地址解析：Mihomo URL 写法（`8.8.8.8`、`tls://`、`https://`、`quic://`、`system`、`rcode://`、`#出站&参数`）
//! 与 sing-box 结构化对象，统一为 [`ServerDef`]。

use crate::{
    DnsServerInput, DnsServerSpec,
    matcher::invalid,
    wire::{ClientSubnet, RCODE_NOERROR, RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL},
};
use kerlico_core::{Address, Destination, Result};
use std::collections::BTreeMap;

/// 上游连接经由的路径。
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Via {
    /// 本机直接建立套接字。
    Direct,
    /// 经指定命名出站或代理组（Mihomo `#代理名`、sing-box `detour`）。
    Outbound(String),
    /// 按路由规则为上游地址选择出站（Mihomo `respect-rules` 或 `#RULES`）。
    Rules,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Endpoint {
    pub host: Address,
    pub port: u16,
}

impl Endpoint {
    pub(crate) fn destination(&self) -> Result<Destination> {
        Destination::new(&host_text(&self.host), self.port)
    }
    pub(crate) fn host_name(&self) -> String {
        match &self.host {
            Address::Ip(ip) => ip.to_string(),
            Address::Domain(d) => d.trim_end_matches('.').to_owned(),
        }
    }
}

fn host_text(host: &Address) -> String {
    match host {
        Address::Ip(ip) => ip.to_string(),
        Address::Domain(d) => d.clone(),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TlsOpts {
    pub sni: Option<String>,
    pub insecure: bool,
    pub ca_pem: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H3Mode {
    Off,
    /// 先试 HTTP/3，失败再用 HTTP/2（全局 `prefer-h3`）。
    Prefer,
    /// 只用 HTTP/3（`#h3=true`）。
    Only,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Udp(Endpoint),
    Tcp(Endpoint),
    Tls(Endpoint, TlsOpts),
    Https {
        endpoint: Endpoint,
        path: String,
        headers: BTreeMap<String, String>,
        tls: TlsOpts,
        h3: H3Mode,
    },
    Quic(Endpoint, TlsOpts),
    System,
    Rcode(u8),
    FakeIp {
        v4: Option<String>,
        v6: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerDef {
    pub tag: String,
    pub kind: Kind,
    pub via: Via,
    pub ecs: Option<(ClientSubnet, bool)>,
    pub domains: Vec<String>,
}

impl ServerDef {
    pub(crate) fn is_fake(&self) -> bool {
        matches!(self.kind, Kind::FakeIp { .. })
    }
}

fn split_host_port(authority: &str, default_port: u16) -> Result<Endpoint> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err(invalid());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(invalid)?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse::<u16>().map_err(|_| invalid())?,
            None if tail.is_empty() => default_port,
            None => return Err(invalid()),
        };
        (h.to_owned(), port)
    } else if authority.matches(':').count() > 1 {
        (authority.to_owned(), default_port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_owned(), p.parse::<u16>().map_err(|_| invalid())?)
    } else {
        (authority.to_owned(), default_port)
    };
    if port == 0 {
        return Err(invalid());
    }
    let dest = Destination::new(&host, port).map_err(|_| invalid())?;
    Ok(Endpoint {
        host: dest.address().clone(),
        port,
    })
}

fn rcode_named(name: &str) -> Result<u8> {
    Ok(match name.trim().to_ascii_lowercase().as_str() {
        "success" => RCODE_NOERROR,
        "format_error" => 1,
        "server_failure" => RCODE_SERVFAIL,
        "name_error" => RCODE_NXDOMAIN,
        "not_implemented" => 4,
        "refused" => RCODE_REFUSED,
        _ => return Err(invalid()),
    })
}

struct Fragment {
    via: Via,
    h3: Option<bool>,
    ecs: Option<ClientSubnet>,
    ecs_override: bool,
    insecure: bool,
    sni: Option<String>,
}

/// `#代理名&h3=true&ecs=1.2.3.0/24&ecs-override=true&skip-cert-verify=true`。
fn parse_fragment(raw: Option<&str>) -> Result<Fragment> {
    let mut out = Fragment {
        via: Via::Direct,
        h3: None,
        ecs: None,
        ecs_override: false,
        insecure: false,
        sni: None,
    };
    let Some(raw) = raw else {
        return Ok(out);
    };
    let bool_of = |v: &str| match v {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(invalid()),
    };
    let mut named = false;
    for item in raw.split('&').map(str::trim).filter(|s| !s.is_empty()) {
        match item.split_once('=') {
            Some((k, v)) => match k.trim().to_ascii_lowercase().as_str() {
                "h3" => out.h3 = Some(bool_of(v)?),
                "ecs" => out.ecs = Some(v.parse()?),
                "ecs-override" => out.ecs_override = bool_of(v)?,
                "skip-cert-verify" => out.insecure = bool_of(v)?,
                "sni" => out.sni = Some(v.trim().to_owned()),
                "detour" | "proxy" => out.via = via_named(v)?,
                _ => return Err(invalid()),
            },
            None => {
                if named {
                    return Err(invalid());
                }
                named = true;
                out.via = via_named(item)?;
            }
        }
    }
    Ok(out)
}

fn via_named(name: &str) -> Result<Via> {
    let n = name.trim();
    if n.is_empty() {
        return Err(invalid());
    }
    Ok(match n {
        "RULES" => Via::Rules,
        "DIRECT" => Via::Direct,
        other => Via::Outbound(other.to_owned()),
    })
}

pub(crate) fn parse_url(text: &str, tag: String) -> Result<ServerDef> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    let fake = |tag| ServerDef {
        tag,
        kind: Kind::FakeIp { v4: None, v6: None },
        via: Via::Direct,
        ecs: None,
        domains: Vec::new(),
    };
    if matches!(lower.as_str(), "fakedns" | "fakeip" | "fake-ip") {
        return Ok(fake(tag));
    }
    if lower == "system" || lower == "local" {
        return Ok(ServerDef {
            tag,
            kind: Kind::System,
            via: Via::Direct,
            ecs: None,
            domains: Vec::new(),
        });
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("udp".to_owned(), trimmed),
    };
    let (body, fragment) = match rest.split_once('#') {
        Some((a, f)) => (a, Some(f)),
        None => (rest, None),
    };
    let frag = parse_fragment(fragment)?;
    let tls = TlsOpts {
        sni: frag.sni.clone(),
        insecure: frag.insecure,
        ca_pem: None,
    };
    let kind = match scheme.as_str() {
        "udp" => Kind::Udp(split_host_port(body, 53)?),
        "tcp" => Kind::Tcp(split_host_port(body, 53)?),
        "tls" | "dot" => Kind::Tls(split_host_port(body, 853)?, tls),
        "quic" | "doq" => Kind::Quic(split_host_port(body, 853)?, tls),
        "https" | "doh" | "h3" => {
            let (authority, path) = match body.find('/') {
                Some(i) => (&body[..i], body[i..].to_owned()),
                None => (body, "/dns-query".to_owned()),
            };
            Kind::Https {
                endpoint: split_host_port(authority, 443)?,
                path,
                headers: BTreeMap::new(),
                tls,
                h3: match (scheme.as_str(), frag.h3) {
                    ("h3", _) | (_, Some(true)) => H3Mode::Only,
                    _ => H3Mode::Off,
                },
            }
        }
        "system" | "dhcp" => Kind::System,
        "rcode" => Kind::Rcode(rcode_named(body)?),
        _ => return Err(invalid()),
    };
    if frag.h3.is_some() && !matches!(kind, Kind::Https { .. }) {
        return Err(invalid());
    }
    Ok(ServerDef {
        tag,
        kind,
        via: frag.via,
        ecs: frag.ecs.map(|s| (s, frag.ecs_override)),
        domains: Vec::new(),
    })
}

fn parse_structured(spec: &DnsServerSpec, tag: String) -> Result<ServerDef> {
    let proto = spec
        .protocol
        .as_deref()
        .unwrap_or("udp")
        .to_ascii_lowercase();
    let mut domains = Vec::with_capacity(spec.domains.len());
    for d in &spec.domains {
        if d.trim().is_empty() {
            return Err(invalid());
        }
        domains.push(d.trim().to_ascii_lowercase());
    }
    let tls = TlsOpts {
        sni: spec.tls.as_ref().and_then(|t| t.server_name.clone()),
        insecure: spec.tls.as_ref().is_some_and(|t| t.insecure),
        ca_pem: match spec.tls.as_ref() {
            Some(t) => match (&t.ca_pem, &t.certificate_path) {
                (Some(pem), _) => Some(pem.clone()),
                (None, Some(path)) => Some(std::fs::read_to_string(path).map_err(|_| invalid())?),
                (None, None) => None,
            },
            None => None,
        },
    };
    let endpoint = |default: u16| -> Result<Endpoint> {
        let host = spec.server.as_deref().ok_or_else(invalid)?;
        let port = spec.server_port.unwrap_or(default);
        let host = host.trim().trim_start_matches('[').trim_end_matches(']');
        if port == 0 {
            return Err(invalid());
        }
        let dest = Destination::new(host, port).map_err(|_| invalid())?;
        Ok(Endpoint {
            host: dest.address().clone(),
            port,
        })
    };
    let kind = match proto.as_str() {
        "fakeip" | "fakedns" | "fake-ip" => Kind::FakeIp {
            v4: spec.inet4_range.clone(),
            v6: spec.inet6_range.clone(),
        },
        "udp" => Kind::Udp(endpoint(53)?),
        "tcp" => Kind::Tcp(endpoint(53)?),
        "tls" | "dot" => Kind::Tls(endpoint(853)?, tls),
        "quic" | "doq" => Kind::Quic(endpoint(853)?, tls),
        "https" | "doh" | "h3" => {
            let path = spec.path.clone().unwrap_or_else(|| "/dns-query".into());
            if !path.starts_with('/') {
                return Err(invalid());
            }
            Kind::Https {
                endpoint: endpoint(443)?,
                path,
                headers: spec.headers.clone(),
                tls,
                h3: if proto == "h3" {
                    H3Mode::Only
                } else {
                    H3Mode::Off
                },
            }
        }
        "local" | "system" | "dhcp" => Kind::System,
        _ => return Err(invalid()),
    };
    let via = match spec.detour.as_deref() {
        Some(name) => via_named(name)?,
        None => Via::Direct,
    };
    let ecs = spec
        .client_subnet
        .as_deref()
        .map(str::parse::<ClientSubnet>)
        .transpose()?
        .map(|s| (s, true));
    Ok(ServerDef {
        tag,
        kind,
        via,
        ecs,
        domains,
    })
}

/// 解析一个上游；`group` 与序号组成未命名上游的标签。
pub(crate) fn parse_input(input: &DnsServerInput, group: &str, index: usize) -> Result<ServerDef> {
    match input {
        DnsServerInput::Url(url) => parse_url(url, url.trim().to_owned()),
        DnsServerInput::Structured(spec) => {
            let tag = spec
                .tag
                .clone()
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| format!("{group}-{index}"));
            parse_structured(spec, tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> ServerDef {
        parse_url(s, "t".into()).unwrap()
    }

    #[test]
    fn mihomo_nameserver_forms() {
        assert_eq!(
            url("8.8.8.8").kind,
            Kind::Udp(split_host_port("8.8.8.8", 53).unwrap())
        );
        assert!(matches!(
            url("tcp://[2001:db8::1]").kind,
            Kind::Tcp(Endpoint { port: 53, .. })
        ));
        assert!(matches!(
            url("tls://dns.google").kind,
            Kind::Tls(Endpoint { port: 853, .. }, _)
        ));
        let doh =
            url("https://doh.example/custom?x=1#PROXY&h3=true&ecs=1.2.3.0/24&ecs-override=true");
        assert_eq!(doh.via, Via::Outbound("PROXY".into()));
        assert_eq!(doh.ecs.map(|(s, o)| (s.prefix, o)), Some((24, true)));
        match doh.kind {
            Kind::Https {
                path, h3, endpoint, ..
            } => {
                assert_eq!(path, "/custom?x=1");
                assert_eq!(h3, H3Mode::Only);
                assert_eq!(endpoint.host_name(), "doh.example");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(url("https://1.1.1.1/dns-query#RULES").via, Via::Rules);
        assert!(matches!(
            url("quic://dns.adguard.com:784").kind,
            Kind::Quic(Endpoint { port: 784, .. }, _)
        ));
        assert_eq!(url("system").kind, Kind::System);
        assert_eq!(url("dhcp://en0").kind, Kind::System);
        assert_eq!(url("rcode://refused").kind, Kind::Rcode(RCODE_REFUSED));
        for bad in [
            "udp://1.1.1.1:0",
            "bogus://x",
            "tcp://[2001:db8::1",
            "udp://1.1.1.1#a&b",
            "udp://1.1.1.1#h3=true",
            "https://x#unknown=1",
        ] {
            assert!(parse_url(bad, "t".into()).is_err(), "{bad}");
        }
    }
}
