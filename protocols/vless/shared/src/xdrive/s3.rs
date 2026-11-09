use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use url::{Position, Url};

use super::service_http::{backoff, Headers, HttpReply, Redirects, ServiceHttp, ATTEMPTS};
use super::{invalid, Config, Entry, Storage, XdriveHttpOptions};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct S3Config {
    endpoint: String,
    bucket: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    path_style: Option<bool>,
}

#[derive(Clone)]
pub(super) struct S3Storage {
    origin: String,
    host: String,
    base_path: String,
    folder: String,
    region: String,
    access: String,
    secret: String,
    token: String,
    http: ServiceHttp,
}

impl S3Storage {
    pub fn new(config: &Config, options: XdriveHttpOptions) -> io::Result<Self> {
        let s3 = config
            .s3
            .as_ref()
            .ok_or_else(|| invalid("XDrive needs an S3 configuration"))?;
        let endpoint = Url::parse(&s3.endpoint).map_err(|_| invalid("XDrive S3 endpoint"))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(invalid(
                "XDrive S3 endpoint must be HTTP(S) without credentials, query or fragment",
            ));
        }
        if !valid_name(&s3.bucket) || s3.bucket.contains('/') || !valid_region(&s3.region) {
            return Err(invalid("XDrive S3 bucket or region"));
        }
        let folder = config.remote_folder.to_string_lossy();
        let folder = folder.strip_suffix('/').unwrap_or(&folder);
        if !valid_name(folder) {
            return Err(invalid("XDrive S3 remoteFolder must be a relative prefix"));
        }
        let secrets = &config.secrets;
        if !(2..=3).contains(&secrets.len())
            || secrets[0].is_empty()
            || secrets[1].is_empty()
            || secrets[0].contains(['/', ',', ' ', '\t'])
            || secrets
                .iter()
                .any(|secret| http::HeaderValue::from_str(secret).is_err())
        {
            return Err(invalid(
                "XDrive S3 needs access key, secret key and optional session token",
            ));
        }
        let mut host = endpoint[Position::BeforeHost..Position::AfterPort].to_owned();
        let mut base_path = endpoint
            .path()
            .split('/')
            .map(|part| {
                let bytes: Vec<_> = percent_decode_str(part).collect();
                escape(&bytes, false)
            })
            .collect::<Vec<_>>()
            .join("/");
        if !base_path.ends_with('/') {
            base_path.push('/');
        }
        if s3.path_style.unwrap_or(true) {
            base_path.push_str(&escape(s3.bucket.as_bytes(), false));
            base_path.push('/');
        } else {
            if endpoint
                .host_str()
                .expect("endpoint host")
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok()
                || !s3.bucket.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'.')
                })
                || s3.bucket.starts_with('.')
                || s3.bucket.ends_with('.')
                || s3.bucket.contains("..")
            {
                return Err(invalid(
                    "XDrive S3 virtual hosting requires DNS-compatible endpoint and bucket",
                ));
            }
            host = format!("{}.{host}", s3.bucket);
        }
        let origin = format!("{}://{host}", endpoint.scheme());
        let region = if s3.region.is_empty() {
            "us-east-1"
        } else {
            &s3.region
        };
        Ok(Self {
            origin,
            host,
            base_path,
            folder: format!("{folder}/"),
            region: region.into(),
            access: secrets[0].clone(),
            secret: secrets[1].clone(),
            token: secrets.get(2).cloned().unwrap_or_default(),
            http: {
                let xmux = crate::xmux::XmuxConfig::xdrive(Some(&config.xmux), false, options.quic.is_some())?;
                ServiceHttp::configured(options, Redirects::Disabled, xmux, 32)?
            },
        })
    }

    fn key(&self, name: &str) -> io::Result<String> {
        if !valid_name(name) || self.folder.len() + name.len() > 1024 {
            return Err(invalid("XDrive S3 object name"));
        }
        Ok(format!("{}{name}", self.folder))
    }

    fn request(
        &self,
        method: &str,
        key: &str,
        query: &BTreeMap<&str, String>,
        data: &[u8],
    ) -> io::Result<HttpReply> {
        let path = format!("{}{}", self.base_path, escape(key.as_bytes(), true));
        let query = query
            .iter()
            .map(|(name, value)| format!("{name}={}", escape(value.as_bytes(), false)))
            .collect::<Vec<_>>()
            .join("&");
        let target = if query.is_empty() {
            format!("{}{path}", self.origin)
        } else {
            format!("{}{path}?{query}", self.origin)
        };
        let hash = sha256(data);
        let mut latest = None;
        for attempt in 0..ATTEMPTS {
            let headers = self.sign(method, &path, &query, &hash, OffsetDateTime::now_utc());
            let hint = match self.http.call(method, &target, &headers, data) {
                Ok(reply) if matches!(reply.status, 429 | 500 | 502 | 503 | 504) => {
                    latest = Some(reply.error("S3"));
                    reply.retry_after()
                }
                Ok(reply) => return Ok(reply),
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => return Err(error),
                Err(error) => {
                    latest = Some(error);
                    None
                }
            };
            if attempt + 1 < ATTEMPTS {
                backoff(attempt, hint);
            }
        }
        Err(latest.unwrap_or_else(|| io::Error::other("XDrive S3 request failed")))
    }

    fn sign(
        &self,
        method: &str,
        path: &str,
        query: &str,
        hash: &str,
        utc: OffsetDateTime,
    ) -> Headers {
        let date = format!("{:04}{:02}{:02}", utc.year(), utc.month() as u8, utc.day());
        let stamp = format!(
            "{date}T{:02}{:02}{:02}Z",
            utc.hour(),
            utc.minute(),
            utc.second()
        );
        let mut headers = Headers::from([
            ("host".into(), self.host.clone()),
            ("x-amz-content-sha256".into(), hash.into()),
            ("x-amz-date".into(), stamp.clone()),
        ]);
        if method == "PUT" {
            headers.insert("content-type".into(), "application/octet-stream".into());
        }
        if !self.token.is_empty() {
            headers.insert("x-amz-security-token".into(), self.token.clone());
        }
        let signed = headers
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(";");
        let mut canonical = format!("{method}\n{path}\n{query}\n");
        for (name, value) in &headers {
            canonical.push_str(&format!(
                "{name}:{}\n",
                value.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
        }
        canonical.push_str(&format!("\n{signed}\n{hash}"));
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            sha256(canonical.as_bytes())
        );
        let key = mac(format!("AWS4{}", self.secret).as_bytes(), date.as_bytes());
        let key = mac(&key, self.region.as_bytes());
        let key = mac(&key, b"s3");
        let key = mac(&key, b"aws4_request");
        let signature = hex(&mac(&key, to_sign.as_bytes()));
        headers.insert("authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", self.access));
        headers
    }

    fn list_pages(
        &self,
        prefix: &str,
        delimiter: bool,
        mut visit: impl FnMut(ListPage) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut query = BTreeMap::from([
            ("list-type", "2".into()),
            ("max-keys", "1000".into()),
            ("prefix", prefix.into()),
        ]);
        if delimiter {
            query.insert("delimiter", "/".into());
        }
        let mut seen = BTreeSet::new();
        loop {
            let reply = self.request("GET", "", &query, &[])?;
            if reply.status != 200 {
                return Err(reply.error("S3 LIST"));
            }
            let page: ListPage = quick_xml::de::from_reader(reply.body.as_slice())
                .map_err(|_| invalid("XDrive S3 list response"))?;
            if page
                .contents
                .iter()
                .any(|item| !item.key.starts_with(prefix))
                || page
                    .common_prefixes
                    .iter()
                    .any(|item| !item.prefix.starts_with(prefix))
            {
                return Err(invalid(
                    "XDrive S3 list returned an object outside its prefix",
                ));
            }
            let more = page.is_truncated;
            if more {
                if page.next_continuation_token.is_empty()
                    || !seen.insert(page.next_continuation_token.clone())
                {
                    return Err(invalid("XDrive S3 list pagination did not advance"));
                }
                query.insert("continuation-token", page.next_continuation_token.clone());
            }
            visit(page)?;
            if !more {
                return Ok(());
            }
        }
    }

    fn delete_key(&self, key: &str) -> io::Result<()> {
        let reply = self.request("DELETE", key, &BTreeMap::new(), &[])?;
        if matches!(reply.status, 200 | 204) || missing(&reply) {
            Ok(())
        } else {
            Err(reply.error("S3 DELETE"))
        }
    }
}

impl Storage for S3Storage {
    fn session(&self) -> Option<Arc<dyn Storage>> { Some(Arc::new(self.clone())) }
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let reply = self.request("PUT", &self.key(name)?, &BTreeMap::new(), data)?;
        if reply.status == 200 {
            Ok(())
        } else {
            Err(reply.error("S3 PUT"))
        }
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let reply = self.request("GET", &self.key(name)?, &BTreeMap::new(), &[])?;
        if reply.status == 200 {
            Ok(reply.body)
        } else if missing(&reply) {
            Err(io::ErrorKind::NotFound.into())
        } else {
            Err(reply.error("S3 GET"))
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let key = format!("{}/", self.key(prefix)?);
        let mut names = BTreeSet::new();
        self.list_pages(&key, true, |page| {
            for full in page
                .contents
                .into_iter()
                .map(|item| item.key)
                .chain(page.common_prefixes.into_iter().map(|item| item.prefix))
            {
                let rest = &full[key.len()..];
                let name = rest.split('/').next().unwrap_or("");
                if valid_name(name) {
                    names.insert(name.to_owned());
                }
            }
            Ok(())
        })?;
        Ok(names
            .into_iter()
            .map(|name| Entry { name, inline: None })
            .collect())
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let key = self.key(name)?;
        self.delete_key(&key)?;
        self.list_pages(&format!("{key}/"), false, |page| {
            for item in page.contents {
                self.delete_key(&item.key)?;
            }
            Ok(())
        })
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct ListPage {
    is_truncated: bool,
    next_continuation_token: String,
    contents: Vec<ListItem>,
    common_prefixes: Vec<ListPrefix>,
}

#[derive(Deserialize)]
struct ListItem {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Deserialize)]
struct ListPrefix {
    #[serde(rename = "Prefix")]
    prefix: String,
}

fn missing(reply: &HttpReply) -> bool {
    #[derive(Deserialize)]
    struct Error {
        #[serde(rename = "Code")]
        code: String,
    }
    reply.status == 404
        && quick_xml::de::from_reader::<_, Error>(reply.body.as_slice())
            .is_ok_and(|error| matches!(error.code.as_str(), "NoSuchKey" | "NotFound"))
}

fn valid_name(name: &str) -> bool {
    !name.chars().any(|ch| ch.is_ascii_control() || ch == '\\')
        && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn valid_region(region: &str) -> bool {
    http::HeaderValue::from_str(region).is_ok() && !region.contains(['/', ',', ' ', '\t'])
}

fn escape(bytes: &[u8], slash: bool) -> String {
    let mut out = String::new();
    for &byte in bytes {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || slash && byte == b'/'
        {
            out.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(out, "%{byte:02X}").expect("write to string");
        }
    }
    out
}

fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn mac(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}
