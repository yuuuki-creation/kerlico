use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::Deserialize;
use serde_json::{json, Value};
use url::form_urlencoded;

use super::ring::Slots;
use super::service_http::{backoff, Headers, HttpReply, Redirects, ServiceHttp, ATTEMPTS};
use super::{invalid, Config, Entry, Storage, XdriveHttpOptions};

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
const UPLOAD_URL: &str = "https://www.googleapis.com/upload/drive/v3/files";
const JSON: &str = "application/json; charset=UTF-8";
const MULTIPART: &str = "multipart/related; boundary=xdrive-boundary";
const INLINE_LIMIT: usize = 12_000;

#[derive(Clone)]
pub(super) struct DriveStorage {
    folder: String,
    credentials: [String; 3],
    token: Arc<Mutex<Option<(String, Instant)>>>,
    files: Arc<Mutex<HashMap<String, String>>>,
    http: ServiceHttp,
}

#[derive(Deserialize)]
struct File {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Page {
    next_page_token: String,
    files: Vec<File>,
}

impl DriveStorage {
    pub fn new(config: &Config, options: XdriveHttpOptions) -> io::Result<Self> {
        let credentials: [String; 3] = config.secrets.clone().try_into().map_err(|_| {
            invalid("XDrive Google Drive needs client ID, client secret and refresh token")
        })?;
        if credentials.iter().any(String::is_empty) || config.remote_folder.as_os_str().is_empty() {
            return Err(invalid(
                "XDrive Google Drive needs a folder and three secrets",
            ));
        }
        Ok(Self {
            folder: config.remote_folder.to_string_lossy().into_owned(),
            credentials,
            token: Arc::new(Mutex::new(None)),
            files: Arc::new(Mutex::new(HashMap::new())),
            http: {
                let xmux = crate::xmux::XmuxConfig::xdrive(Some(&config.xmux), true, options.quic.is_some())?;
                ServiceHttp::configured(options, Redirects::Follow, xmux, 32)?
            },
        })
    }

    fn token(&self) -> io::Result<String> {
        let mut cached = self.token.lock().expect("XDrive Drive token");
        if let Some((token, _)) = cached.as_ref().filter(|(_, until)| Instant::now() < *until) {
            return Ok(token.clone());
        }
        let [client, secret, refresh] = &self.credentials;
        let body = query(&[
            ("client_id", client),
            ("client_secret", secret),
            ("refresh_token", refresh),
            ("grant_type", "refresh_token"),
        ]);
        let headers = Headers::from([(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        )]);
        let reply = self
            .http
            .call("POST", TOKEN_URL, &headers, body.as_bytes())?;
        if reply.status != 200 {
            return Err(reply.error("Drive OAuth refresh"));
        }
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
            expires_in: u64,
        }
        let token: Token = serde_json::from_slice(&reply.body)
            .map_err(|_| invalid("XDrive Drive OAuth response"))?;
        if token.access_token.is_empty() {
            return Err(invalid("XDrive Drive OAuth token missing"));
        }
        let seconds = if token.expires_in > 60 {
            token.expires_in - 60
        } else {
            token.expires_in
        };
        let now = Instant::now();
        *cached = Some((
            token.access_token.clone(),
            now.checked_add(Duration::from_secs(seconds)).unwrap_or(now),
        ));
        Ok(token.access_token)
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> io::Result<HttpReply> {
        let mut latest = None;
        for attempt in 0..ATTEMPTS {
            let token = self.token()?;
            let mut headers = Headers::from([("authorization".into(), format!("Bearer {token}"))]);
            if !content_type.is_empty() {
                headers.insert("content-type".into(), content_type.into());
            }
            let hint = match self.http.call(method, url, &headers, body) {
                Ok(reply) if reply.status == 401 => {
                    let mut cached = self.token.lock().expect("XDrive Drive token");
                    if cached.as_ref().is_some_and(|(value, _)| value == &token) {
                        *cached = None;
                    }
                    latest = Some(reply.error("Drive OAuth"));
                    None
                }
                Ok(reply) if retryable(&reply) => {
                    latest = Some(reply.error("Drive"));
                    reply.retry_after()
                }
                Ok(reply) => return Ok(reply),
                Err(error) if method == "POST" || error.kind() == io::ErrorKind::InvalidInput => {
                    return Err(error)
                }
                Err(error) => {
                    latest = Some(error);
                    None
                }
            };
            if attempt + 1 < ATTEMPTS {
                backoff(attempt, hint);
            }
        }
        Err(latest.unwrap_or_else(|| io::Error::other("XDrive Drive request failed")))
    }

    fn query(&self, condition: &str) -> io::Result<HashMap<String, File>> {
        let condition = format!(
            "'{}' in parents and trashed = false and {condition}",
            quoted(&self.folder)
        );
        let base = [
            ("q", condition.as_str()),
            ("fields", "nextPageToken,files(id,name,description)"),
            ("pageSize", "1000"),
            ("supportsAllDrives", "true"),
            ("includeItemsFromAllDrives", "true"),
        ];
        let mut files = HashMap::new();
        let mut tokens = HashSet::new();
        let mut page_token = String::new();
        loop {
            let mut pairs = base.to_vec();
            if !page_token.is_empty() {
                pairs.push(("pageToken", &page_token));
            }
            let reply = self.request("GET", &format!("{FILES_URL}?{}", query(&pairs)), "", &[])?;
            if reply.status != 200 {
                return Err(reply.error("Drive LIST"));
            }
            let page: Page = serde_json::from_slice(&reply.body)
                .map_err(|_| invalid("XDrive Drive listing response"))?;
            {
                let mut cached = self.files.lock().expect("XDrive Drive file IDs");
                for file in page.files {
                    if !file.id.is_empty() && !file.name.is_empty() {
                        cached.insert(file.name.clone(), file.id.clone());
                        files.insert(file.name.clone(), file);
                    }
                }
            }
            page_token = page.next_page_token;
            if page_token.is_empty() {
                return Ok(files);
            }
            if !tokens.insert(page_token.clone()) {
                return Err(invalid("XDrive Drive list pagination did not advance"));
            }
        }
    }

    fn resolve(&self, flat: &str) -> io::Result<String> {
        if let Some(id) = self
            .files
            .lock()
            .expect("XDrive Drive file IDs")
            .get(flat)
            .cloned()
        {
            return Ok(id);
        }
        self.query(&format!("name = '{}'", quoted(flat)))?
            .remove(flat)
            .map(|file| file.id)
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn create(
        &self,
        name: &str,
        description: Option<String>,
        body: Option<&[u8]>,
    ) -> io::Result<String> {
        let flat = flatten(name);
        let mut meta = json!({"name": flat, "parents": [self.folder]});
        if let Some(description) = description {
            meta["description"] = json!(description);
        }
        let (target, content_type, bytes) = if let Some(body) = body {
            (
                format!("{UPLOAD_URL}?uploadType=multipart&fields=id,name"),
                MULTIPART,
                multipart(&meta, body)?,
            )
        } else {
            (
                format!("{FILES_URL}?fields=id"),
                JSON,
                serde_json::to_vec(&meta).map_err(invalid)?,
            )
        };
        let reply = match self.request("POST", &target, content_type, &bytes) {
            Ok(reply) => reply,
            Err(error) if error.kind() != io::ErrorKind::InvalidInput => {
                return self.resolve(&flat).map_err(|_| error)
            }
            Err(error) => return Err(error),
        };
        if reply.status != 200 {
            return Err(reply.error("Drive create"));
        }
        let file: File = serde_json::from_slice(&reply.body)
            .map_err(|_| invalid("XDrive Drive create response"))?;
        if file.id.is_empty() {
            return Err(invalid("XDrive Drive create returned no ID"));
        }
        self.files
            .lock()
            .expect("XDrive Drive file IDs")
            .insert(flat, file.id.clone());
        Ok(file.id)
    }

    fn delete_id(&self, name: &str, id: &str) -> io::Result<()> {
        let target = format!("{FILES_URL}/{}?supportsAllDrives=true", escaped(id));
        let reply = self.request("DELETE", &target, "", &[])?;
        if !matches!(reply.status, 200 | 204 | 404) {
            return Err(reply.error("Drive DELETE"));
        }
        self.files
            .lock()
            .expect("XDrive Drive file IDs")
            .remove(name);
        Ok(())
    }
}

impl Storage for DriveStorage {
    fn session(&self) -> Option<Arc<dyn Storage>> { Some(Arc::new(self.clone())) }
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        if data.len() <= INLINE_LIMIT {
            self.create(name, Some(STANDARD.encode(data)), None)?;
        } else {
            self.create(name, None, Some(data))?;
        }
        Ok(())
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let flat = flatten(name);
        let id = self.resolve(&flat)?;
        let bytes = self.body(&id).inspect_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                self.files
                    .lock()
                    .expect("XDrive Drive file IDs")
                    .remove(&flat);
            }
        })?;
        if bytes.is_empty() {
            STANDARD
                .decode(self.description(&id)?)
                .map_err(|_| invalid("XDrive Drive inline data"))
        } else {
            Ok(bytes)
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let flat = format!("{}~", flatten(prefix));
        let mut entries = HashMap::new();
        for (name, file) in self.query(&format!("name contains '{}'", quoted(&flat)))? {
            let Some(rest) = name.strip_prefix(&flat).filter(|rest| !rest.is_empty()) else {
                continue;
            };
            if let Some((parent, _)) = rest.split_once('~') {
                entries.entry(parent.to_owned()).or_insert(None);
            } else {
                let inline = (!file.description.is_empty())
                    .then(|| STANDARD.decode(file.description).ok())
                    .flatten();
                entries.insert(rest.to_owned(), inline);
            }
        }
        Ok(entries
            .into_iter()
            .map(|(name, inline)| Entry { name, inline })
            .collect())
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let flat = flatten(name);
        match self.resolve(&flat) {
            Ok(id) => self.delete_id(&flat, &id)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let prefix = format!("{flat}~");
        for (name, file) in self.query(&format!("name contains '{}'", quoted(&prefix)))? {
            if name.starts_with(&prefix) {
                self.delete_id(&name, &file.id)?;
            }
        }
        Ok(())
    }

    fn slots(&self) -> Option<&dyn Slots> {
        Some(self)
    }
}

impl Slots for DriveStorage {
    fn create_slot(&self, name: &str) -> io::Result<String> {
        self.create(name, Some(String::new()), None)
    }

    fn set(&self, id: &str, description: &str, data: Option<&[u8]>) -> io::Result<()> {
        let meta = json!({"description": description});
        let id = escaped(id);
        let (url, content_type, bytes) = if let Some(data) = data {
            (
                format!("{UPLOAD_URL}/{id}?uploadType=multipart&fields=id&supportsAllDrives=true"),
                MULTIPART,
                multipart(&meta, data)?,
            )
        } else {
            (
                format!("{FILES_URL}/{id}?fields=id&supportsAllDrives=true"),
                JSON,
                serde_json::to_vec(&meta).map_err(invalid)?,
            )
        };
        let reply = self.request("PATCH", &url, content_type, &bytes)?;
        ok(reply, "Drive PATCH").map(|_| ())
    }

    fn description(&self, id: &str) -> io::Result<String> {
        let url = format!(
            "{FILES_URL}/{}?fields=description&supportsAllDrives=true",
            escaped(id)
        );
        let bytes = ok(self.request("GET", &url, "", &[])?, "Drive description")?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("XDrive Drive description response"))?;
        Ok(value
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned())
    }

    fn body(&self, id: &str) -> io::Result<Vec<u8>> {
        let url = format!(
            "{FILES_URL}/{}?alt=media&supportsAllDrives=true",
            escaped(id)
        );
        ok(self.request("GET", &url, "", &[])?, "Drive media")
    }
}

fn ok(reply: HttpReply, operation: &str) -> io::Result<Vec<u8>> {
    match reply.status {
        200 => Ok(reply.body),
        404 => Err(io::ErrorKind::NotFound.into()),
        _ => Err(reply.error(operation)),
    }
}

fn flatten(name: &str) -> String {
    name.replace('/', "~")
}

fn quoted(name: &str) -> String {
    name.replace('\\', "\\\\").replace('\'', "\\'")
}

fn escaped(name: &str) -> String {
    utf8_percent_encode(name, NON_ALPHANUMERIC).to_string()
}

fn query(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish()
}

fn multipart(meta: &Value, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes =
        b"--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n".to_vec();
    serde_json::to_writer(&mut bytes, meta).map_err(invalid)?;
    bytes.extend_from_slice(
        b"\r\n--xdrive-boundary\r\nContent-Type: application/octet-stream\r\n\r\n",
    );
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(b"\r\n--xdrive-boundary--\r\n");
    Ok(bytes)
}

fn retryable(reply: &HttpReply) -> bool {
    if matches!(reply.status, 429 | 500 | 502 | 503 | 504) {
        return true;
    }
    reply.status == 403
        && serde_json::from_slice::<Value>(&reply.body).is_ok_and(|value| {
            let error = &value["error"];
            error["status"] == "RESOURCE_EXHAUSTED"
                || error["errors"].as_array().is_some_and(|reasons| {
                    reasons.iter().any(|reason| {
                        matches!(
                            reason["reason"].as_str(),
                            Some(
                                "rateLimitExceeded"
                                    | "userRateLimitExceeded"
                                    | "sharingRateLimitExceeded"
                            )
                        )
                    })
                })
        })
}
