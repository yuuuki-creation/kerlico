use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{json, Value};

use crate::engine::Profile;

const REGISTRATION: &str = "v0a4005";
#[cfg_attr(windows, allow(dead_code))]
const CLIENT_VERSION: &str = "a-6.30-3596";

pub fn load_profile(explicit: Option<&str>, dir: &Path) -> io::Result<Profile> {
    if let Some(text) = explicit {
        if text.contains("secretKey") {
            return parse(text);
        }
    }
    let path = dir.join("warp.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => parse(&text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let text = register_to(&path)?;
            parse(&text)
        }
        Err(error) => Err(error),
    }
}

fn parse(text: &str) -> io::Result<Profile> {
    let value: Value = serde_json::from_str(text)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let private_key = key(value.get("secretKey"))?;
    let peer = value
        .get("peers")
        .and_then(|peers| peers.get(0))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "peer"))?;
    let peer_public = key(peer.get("publicKey"))?;
    let endpoint = peer
        .get("endpoint")
        .and_then(|item| item.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "endpoint"))?;
    let endpoint = resolve(endpoint)?;
    let addresses = value
        .get("address")
        .and_then(|item| item.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str())
                .filter_map(parse_ip)
                .collect()
        })
        .unwrap_or_default();
    let reserved = value
        .get("reserved")
        .and_then(|item| item.as_array())
        .map(|items| {
            let mut bytes = [0u8; 3];
            for (slot, item) in bytes.iter_mut().zip(items.iter()) {
                *slot = item.as_u64().unwrap_or(0) as u8;
            }
            bytes
        })
        .unwrap_or([0, 0, 0]);
    let mtu = value
        .get("mtu")
        .and_then(|item| item.as_u64())
        .unwrap_or(1280) as usize;
    Ok(Profile {
        private_key,
        peer_public,
        endpoint,
        addresses,
        reserved,
        mtu,
    })
}

fn key(value: Option<&Value>) -> io::Result<[u8; 32]> {
    let text = value
        .and_then(|item| item.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "key"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(text))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key"))?;
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "key"))
}

fn parse_ip(text: &str) -> Option<IpAddr> {
    text.split('/').next()?.parse().ok()
}

fn register_to(path: &Path) -> io::Result<String> {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let public_text = base64::engine::general_purpose::STANDARD.encode(public.to_bytes());
    let body = json!({
        "key": public_text,
        "install_id": "",
        "fcm_token": "",
        "warp_enabled": true,
        "tos": tos_now(),
        "type": "Android",
        "model": "PC",
        "locale": "en_US",
    });
    let response = https_post(
        "api.cloudflareclient.com",
        &format!("/{REGISTRATION}/reg"),
        &body.to_string(),
    )?;
    let value: Value = serde_json::from_str(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let text = registration_document(&secret.to_bytes(), &value)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &text)?;
    Ok(text)
}

fn registration_document(private_key: &[u8; 32], value: &Value) -> io::Result<String> {
    let config = value
        .get("config")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "config"))?;
    let peer = config
        .pointer("/peers/0")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "peer"))?;
    let public_key = peer
        .get("public_key")
        .and_then(|item| item.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "public_key"))?;
    let endpoint = peer
        .pointer("/endpoint/v4")
        .and_then(|item| item.as_str())
        .or_else(|| {
            peer.pointer("/endpoint/host")
                .and_then(|item| item.as_str())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "endpoint"))?;
    let endpoint = if endpoint.contains(':') {
        endpoint.to_string()
    } else {
        format!("{endpoint}:2408")
    };
    let mut addresses = Vec::new();
    if let Some(v4) = config
        .pointer("/interface/addresses/v4")
        .and_then(|item| item.as_str())
    {
        addresses.push(with_prefix(v4, 32));
    }
    if let Some(v6) = config
        .pointer("/interface/addresses/v6")
        .and_then(|item| item.as_str())
    {
        addresses.push(with_prefix(v6, 128));
    }
    let client_id = config
        .get("client_id")
        .and_then(|item| item.as_str())
        .unwrap_or("");
    let reserved = reserved_bytes(client_id);
    let text = json!({
        "secretKey": base64::engine::general_purpose::STANDARD.encode(private_key),
        "address": addresses,
        "peers": [{ "publicKey": public_key, "endpoint": endpoint }],
        "reserved": reserved,
        "mtu": 1280,
        "registration": REGISTRATION,
    });
    Ok(text.to_string())
}

fn with_prefix(text: &str, bits: u8) -> String {
    if text.contains('/') {
        text.to_string()
    } else {
        format!("{text}/{bits}")
    }
}

fn reserved_bytes(client_id: &str) -> [u8; 3] {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(client_id)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(client_id))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(client_id))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(client_id))
        .unwrap_or_default();
    let mut reserved = [0u8; 3];
    for (slot, byte) in reserved.iter_mut().zip(decoded.iter()) {
        *slot = *byte;
    }
    reserved
}

#[cfg(windows)]
fn https_post(_host: &str, _path: &str, _body: &str) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "warp registration runs on the linux build",
    ))
}

#[cfg(not(windows))]
fn https_post(host: &str, path: &str, body: &str) -> io::Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::time::Duration;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sni"))?
        .to_owned();
    let mut connection = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut tcp = TcpStream::connect((host, 443))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut stream = rustls::Stream::new(&mut connection, &mut tcp);
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: okhttp/3.12.1\r\nCF-Client-Version: {CLIENT_VERSION}\r\nContent-Type: application/json; charset=UTF-8\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let text = String::from_utf8(raw)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    http_body(&text)
}

#[cfg(any(test, not(windows)))]
fn http_body(raw: &str) -> io::Result<String> {
    let (head, rest) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "http"))?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200 ") {
        return Err(io::Error::other(status.to_string()));
    }
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return decode_chunks(rest);
    }
    Ok(rest.to_string())
}

#[cfg(any(test, not(windows)))]
fn decode_chunks(mut rest: &str) -> io::Result<String> {
    let mut out = String::new();
    loop {
        let (size, tail) = rest
            .split_once("\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk"))?;
        let size = usize::from_str_radix(size.split(';').next().unwrap_or(size).trim(), 16)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if size == 0 {
            return Ok(out);
        }
        if tail.len() < size + 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk"));
        }
        out.push_str(&tail[..size]);
        rest = &tail[size + 2..];
    }
}

fn tos_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let time = secs % 86_400;
    let (year, month, day) = civil(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000+00:00",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

fn civil(mut days: u64) -> (i32, u32, u32) {
    days += 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month as u32, day as u32)
}

fn resolve(endpoint: &str) -> io::Result<SocketAddr> {
    endpoint
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .or_else(|| {
            endpoint
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "endpoint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_reply_becomes_warp_json() {
        let private = [7u8; 32];
        let public = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let client_id = base64::engine::general_purpose::STANDARD.encode([4u8, 5, 6]);
        let body = json!({
            "config": {
                "client_id": client_id,
                "peers": [{
                    "public_key": public,
                    "endpoint": { "v4": "203.0.113.8:2408", "host": "engage.cloudflareclient.com" }
                }],
                "interface": {
                    "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110::1" }
                }
            }
        });
        let text = registration_document(&private, &body).unwrap();
        assert!(text.contains("\"registration\":\"v0a4005\""));
        let profile = parse(&text).unwrap();
        assert_eq!(profile.private_key, private);
        assert_eq!(profile.peer_public, [9u8; 32]);
        assert_eq!(profile.endpoint, "203.0.113.8:2408".parse().unwrap());
        assert_eq!(profile.reserved, [4, 5, 6]);
        assert!(profile.addresses.iter().any(|addr| addr.is_ipv4()));
        assert!(profile.addresses.iter().any(|addr| addr.is_ipv6()));
        assert_eq!(civil(0), (1970, 1, 1));
    }

    #[test]
    fn http_body_reads_plain_and_chunked_payloads() {
        assert_eq!(
            http_body("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            "{}"
        );
        assert_eq!(
            http_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
                .unwrap(),
            "{}"
        );
        assert!(http_body("HTTP/1.1 403 Forbidden\r\n\r\nno").is_err());
    }
}
