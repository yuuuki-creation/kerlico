use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub enum TlsNetworkRequest {
    Dns {
        server: String,
        tcp: bool,
        message: Vec<u8>,
        socket_settings: Option<serde_json::Value>,
    },
    Http {
        url: String,
        method: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        http2: bool,
        socket_settings: Option<serde_json::Value>,
    },
}

#[derive(Clone, Debug)]
pub struct TlsNetworkResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The caller owns network selection and dialing. DNS responses omit TCP framing.
pub trait TlsNetwork: fmt::Debug + Send + Sync {
    fn exchange(&self, request: &TlsNetworkRequest) -> io::Result<TlsNetworkResponse>;
}

pub(super) enum EchSource {
    Direct(Vec<u8>),
    Remote(Remote),
}
pub(super) struct Remote {
    name: Option<String>,
    server: url::Url,
    provider: Arc<dyn TlsNetwork>,
    socket_settings: Option<serde_json::Value>,
    cache: Mutex<HashMap<String, Arc<Mutex<Option<Cached>>>>>,
}
struct Cached {
    config: Vec<u8>,
    expires: Instant,
}

impl EchSource {
    pub(super) fn new(
        text: &str,
        provider: Option<Arc<dyn TlsNetwork>>,
        socket_settings: Option<serde_json::Value>,
    ) -> io::Result<Self> {
        if !text.contains("://") {
            return Ok(Self::Direct(
                STANDARD.decode(text).map_err(io::Error::other)?,
            ));
        }
        let (name, server) = match text.split_once('+') {
            Some((name, server)) if !name.contains("://") => (Some(domain(name)?), server),
            _ => (None, text),
        };
        let server = url::Url::parse(server).map_err(io::Error::other)?;
        if !matches!(server.scheme(), "udp" | "tcp" | "https" | "h2c")
            || server.host_str().is_none()
        {
            return Err(invalid("ECH DNS URL scheme or host"));
        }
        let provider =
            provider.ok_or_else(|| invalid("ECH DNS source requires a TLS network provider"))?;
        Ok(Self::Remote(Remote {
            name,
            server,
            provider,
            socket_settings,
            cache: Mutex::default(),
        }))
    }
    pub(super) fn resolve(&self, name: &str) -> io::Result<Vec<u8>> {
        match self {
            Self::Direct(bytes) => Ok(bytes.clone()),
            Self::Remote(remote) => remote.resolve(name),
        }
    }
}

impl Remote {
    fn resolve(&self, name: &str) -> io::Result<Vec<u8>> {
        let name = self.name.clone().map(Ok).unwrap_or_else(|| domain(name))?;
        let entry = {
            let mut cache = self.cache.lock().expect("ECH cache");
            if cache.len() >= 128 && !cache.contains_key(&name) {
                cache.clear();
            }
            cache.entry(name.clone()).or_default().clone()
        };
        let mut cached = entry.lock().expect("ECH lookup");
        if let Some(value) = cached
            .as_ref()
            .filter(|value| value.expires > Instant::now())
        {
            return Ok(value.config.clone());
        }
        let (mut current, mut ttl) = (name, u32::MAX);
        let mut visited = HashSet::new();
        for _ in 0..8 {
            if !visited.insert(current.clone()) {
                return Err(invalid("ECH DNS alias loop"));
            }
            let answer = self.query(&current)?;
            ttl = ttl.min(answer.ttl);
            if let Some(config) = answer.config {
                *cached = Some(Cached {
                    config: config.clone(),
                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                });
                return Ok(config);
            }
            current = answer
                .alias
                .ok_or_else(|| invalid("HTTPS DNS answer contains no ECH config"))?;
        }
        Err(invalid("ECH DNS alias limit"))
    }
    fn query(&self, name: &str) -> io::Result<Answer> {
        let http = matches!(self.server.scheme(), "https" | "h2c");
        let mut id = [0; 2];
        if !http {
            getrandom::getrandom(&mut id).map_err(|e| io::Error::other(e.to_string()))?;
        }
        let message = query(name, u16::from_be_bytes(id), http)?;
        let request = if http {
            let mut url = self.server.clone();
            if url.scheme() == "h2c" {
                url = url::Url::parse(&url.as_str().replacen("h2c:", "http:", 1))
                    .map_err(io::Error::other)?;
            }
            TlsNetworkRequest::Http {
                url: url.to_string(),
                method: "POST".into(),
                headers: vec![
                    ("Content-Type".into(), "application/dns-message".into()),
                    ("Accept".into(), "application/dns-message".into()),
                ],
                body: message.clone(),
                http2: true,
                socket_settings: self.socket_settings.clone(),
            }
        } else {
            let host = self.server.host_str().unwrap();
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_string()
            };
            TlsNetworkRequest::Dns {
                server: format!("{host}:{}", self.server.port().unwrap_or(53)),
                tcp: self.server.scheme() == "tcp",
                message: message.clone(),
                socket_settings: self.socket_settings.clone(),
            }
        };
        let mut response = self.provider.exchange(&request)?;
        if http && response.status != 200 {
            return Err(io::Error::other(format!(
                "ECH DoH HTTP status {}",
                response.status
            )));
        }
        if let TlsNetworkRequest::Dns {
            server,
            tcp: false,
            message,
            socket_settings,
        } = request
        {
            if response.body.get(2).is_some_and(|flags| flags & 2 != 0) {
                response = self.provider.exchange(&TlsNetworkRequest::Dns {
                    server,
                    tcp: true,
                    message,
                    socket_settings,
                })?;
            }
        }
        response_ech(&response.body, u16::from_be_bytes(id), name)
    }
}

fn domain(name: &str) -> io::Result<String> {
    let name = name.trim_end_matches('.');
    let name = match url::Host::parse(name).map_err(io::Error::other)? {
        url::Host::Domain(name) => name,
        _ => return Err(invalid("ECH DNS lookup requires a domain name")),
    };
    if name.len() > 253
        || name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(invalid("ECH DNS name length"));
    }
    Ok(name.to_ascii_lowercase())
}

fn query(name: &str, id: u16, edns: bool) -> io::Result<Vec<u8>> {
    let name = domain(name)?;
    let mut message = id.to_be_bytes().to_vec();
    message.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)]);
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.extend_from_slice(&[0, 0, 65, 0, 1]);
    if edns {
        let mut random = [0; 2];
        getrandom::getrandom(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
        let padding = 100 + (u16::from_be_bytes(random) % 201) as usize;
        message.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0]);
        message.extend_from_slice(&((padding + 4) as u16).to_be_bytes());
        message.extend_from_slice(&[0, 12]);
        message.extend_from_slice(&(padding as u16).to_be_bytes());
        message.resize(message.len() + padding, 0);
    }
    Ok(message)
}

struct Answer {
    config: Option<Vec<u8>>,
    alias: Option<String>,
    ttl: u32,
}

fn response_ech(bytes: &[u8], id: u16, question: &str) -> io::Result<Answer> {
    if bytes.len() < 12 || bytes.len() > 65535 {
        return Err(invalid("ECH DNS message length"));
    }
    let word = |offset| -> io::Result<u16> {
        let pair = bytes
            .get(offset..offset + 2)
            .ok_or_else(|| invalid("truncated DNS message"))?;
        Ok(u16::from_be_bytes([pair[0], pair[1]]))
    };
    if word(0)? != id || word(2)? & 0xf80f != 0x8000 || word(2)? & 0x0200 != 0 || word(4)? != 1 {
        return Err(invalid("ECH DNS response header"));
    }
    let mut position = 12;
    let name = read_name(bytes, &mut position)?;
    if name != question || word(position)? != 65 || word(position + 2)? != 1 {
        return Err(invalid("ECH DNS response question"));
    }
    position += 4;
    let mut aliases = Vec::new();
    let mut records = Vec::new();
    let answers = word(6)? as usize;
    let total = answers + word(8)? as usize + word(10)? as usize;
    if total > 1024 {
        return Err(invalid("ECH DNS record count"));
    }
    for index in 0..total {
        let owner = read_name(bytes, &mut position)?;
        let kind = word(position)?;
        let class = word(position + 2)?;
        let ttl = u32::from_be_bytes(
            bytes
                .get(position + 4..position + 8)
                .ok_or_else(|| invalid("DNS TTL"))?
                .try_into()
                .unwrap(),
        );
        let length = word(position + 8)? as usize;
        position += 10;
        let end = position
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid("truncated DNS record"))?;
        if index < answers && class == 1 {
            if kind == 5 {
                let mut value = position;
                let target = read_name(bytes, &mut value)?;
                if value != end {
                    return Err(invalid("DNS CNAME length"));
                }
                aliases.push((owner, target, ttl));
            } else if kind == 65 {
                if length < 3 {
                    return Err(invalid("HTTPS DNS record length"));
                }
                let priority = word(position)?;
                let mut value = position + 2;
                let target = read_name(bytes, &mut value)?;
                if value > end {
                    return Err(invalid("HTTPS DNS target length"));
                }
                if priority == 0 {
                    if value != end {
                        return Err(invalid("HTTPS AliasMode parameters"));
                    }
                    aliases.push((owner, target, ttl));
                } else {
                    let mut previous = None;
                    while value < end {
                        let key = word(value)?;
                        let len = word(value + 2)? as usize;
                        value += 4;
                        if previous.is_some_and(|p| p >= key) || value + len > end {
                            return Err(invalid("HTTPS DNS service parameters"));
                        }
                        previous = Some(key);
                        if key == 5 && !bytes[value..value + len].is_empty() {
                            records.push((
                                owner.clone(),
                                priority,
                                ttl,
                                bytes[value..value + len].to_vec(),
                            ));
                        }
                        value += len;
                    }
                }
            }
        }
        position = end;
    }
    if position != bytes.len() {
        return Err(invalid("trailing DNS bytes"));
    }
    let mut current = question.to_string();
    let mut ttl = u32::MAX;
    let mut visited = HashSet::new();
    for _ in 0..8 {
        if !visited.insert(current.clone()) {
            return Err(invalid("DNS alias loop"));
        }
        if let Some((_, _, record_ttl, config)) = records
            .iter()
            .filter(|(name, _, _, _)| name == &current)
            .min_by_key(|(_, priority, _, _)| *priority)
        {
            return Ok(Answer {
                config: Some(config.clone()),
                alias: None,
                ttl: ttl.min(*record_ttl),
            });
        }
        if let Some((_, target, record_ttl)) = aliases.iter().find(|(name, _, _)| name == &current)
        {
            if target.is_empty() {
                return Err(invalid("empty HTTPS alias"));
            }
            ttl = ttl.min(*record_ttl);
            current = target.clone();
        } else {
            break;
        }
    }
    Ok(Answer {
        config: None,
        alias: (current != question).then_some(current),
        ttl,
    })
}

fn read_name(bytes: &[u8], position: &mut usize) -> io::Result<String> {
    let mut cursor = *position;
    let mut end = None;
    let mut labels = Vec::new();
    let mut seen = HashSet::new();
    let mut length = 0;
    for _ in 0..128 {
        if !seen.insert(cursor) {
            return Err(invalid("DNS name compression loop"));
        }
        let count = *bytes
            .get(cursor)
            .ok_or_else(|| invalid("truncated DNS name"))?;
        if count & 0xc0 == 0xc0 {
            let low = *bytes
                .get(cursor + 1)
                .ok_or_else(|| invalid("DNS name pointer"))?;
            end.get_or_insert(cursor + 2);
            cursor = (((count & 0x3f) as usize) << 8) | low as usize;
            continue;
        }
        if count & 0xc0 != 0 {
            return Err(invalid("DNS label encoding"));
        }
        cursor += 1;
        if count == 0 {
            *position = end.unwrap_or(cursor);
            return Ok(labels.join("."));
        }
        let label = bytes
            .get(cursor..cursor + count as usize)
            .ok_or_else(|| invalid("truncated DNS label"))?;
        length += label.len() + 1;
        if length > 254 {
            return Err(invalid("DNS name length"));
        }
        labels.push(
            std::str::from_utf8(label)
                .map_err(io::Error::other)?
                .to_ascii_lowercase(),
        );
        cursor += count as usize;
    }
    Err(invalid("DNS name pointer limit"))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Debug)]
    struct Network {
        requests: AtomicUsize,
        truncate: bool,
        config: Vec<u8>,
    }
    impl TlsNetwork for Network {
        fn exchange(&self, request: &TlsNetworkRequest) -> io::Result<TlsNetworkResponse> {
            let count = self.requests.fetch_add(1, Ordering::Relaxed);
            let (query, http) = match request {
                TlsNetworkRequest::Dns { message, tcp, .. } => {
                    if self.truncate && count == 1 {
                        assert!(*tcp);
                    }
                    (message, false)
                }
                TlsNetworkRequest::Http {
                    body,
                    method,
                    http2,
                    ..
                } => {
                    assert_eq!(method, "POST");
                    assert!(*http2);
                    (body, true)
                }
            };
            let mut p = 12;
            read_name(query, &mut p)?;
            p += 4;
            let mut response = query[..p].to_vec();
            response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            response[6..8].copy_from_slice(&1u16.to_be_bytes());
            response[10..12].fill(0);
            if self.truncate && count == 0 {
                response[2] |= 2;
                response[6..8].fill(0);
            } else {
                response.extend_from_slice(&[0xc0, 12, 0, 65, 0, 1, 0, 0, 0, 60]);
                let mut data = vec![0, 1, 0, 0, 5];
                data.extend_from_slice(&(self.config.len() as u16).to_be_bytes());
                data.extend_from_slice(&self.config);
                response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                response.extend(data);
            }
            Ok(TlsNetworkResponse {
                status: if http { 200 } else { 0 },
                body: response,
            })
        }
    }
    #[test]
    fn dns_tcp_doh_and_cache_preserve_ech_configuration() {
        for server in [
            "name.test+udp://127.0.0.1:5353",
            "tcp://[::1]",
            "https://dns.test/dns-query",
            "h2c://dns.test/query",
        ] {
            let network = Arc::new(Network {
                requests: AtomicUsize::new(0),
                truncate: server.contains("udp:"),
                config: vec![0, 1, 2, 3],
            });
            let source = EchSource::new(server, Some(network.clone()), None).unwrap();
            assert_eq!(source.resolve("example.com").unwrap(), network.config);
            assert_eq!(source.resolve("example.com").unwrap(), network.config);
            assert_eq!(
                network.requests.load(Ordering::Relaxed),
                if network.truncate { 2 } else { 1 }
            );
        }
    }
    #[test]
    fn dns_rejects_wrong_question_and_pointer_loops() {
        let query = query("example.com", 42, false).unwrap();
        let network = Network {
            requests: AtomicUsize::new(0),
            truncate: false,
            config: vec![1],
        };
        let response = network
            .exchange(&TlsNetworkRequest::Dns {
                server: String::new(),
                tcp: false,
                message: query,
                socket_settings: None,
            })
            .unwrap();
        assert!(response_ech(&response.body, 43, "example.com").is_err());
        assert!(response_ech(&response.body, 42, "wrong.test").is_err());
        assert!(read_name(&[0xc0, 0], &mut 0).is_err());
    }
}
