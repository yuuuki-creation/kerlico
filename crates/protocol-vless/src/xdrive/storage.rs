use super::Settings;
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use kerlico_core::{BoxFuture, Error, Result};
use reqwest::{Client, Method, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub(crate) struct Entry {
    pub name: String,
    pub inline: Option<Vec<u8>>,
}
pub(crate) trait Storage: Send + Sync {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>>;
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>>;
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>>;
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Entry>>>;
    fn description<'a>(&'a self, _id: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { Err(Error::Unsupported("存储未提供槽描述")) })
    }
    fn set_slot<'a>(
        &'a self,
        _id: &'a str,
        _description: String,
        _body: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("存储未提供槽写入")) })
    }
    fn slot_body<'a>(&'a self, _id: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async { Err(Error::Unsupported("存储未提供槽正文")) })
    }
}
fn invalid() -> Error {
    Error::Config("XDRIVE 存储配置不合法".into())
}
fn remote() -> Error {
    Error::Protocol("XDRIVE 存储请求失败")
}
fn safe(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.starts_with(".xdrive-tmp-"))
        && !name.chars().any(|c| c.is_control() || c == '\\')
}
fn backend(settings: &Settings, ca: Option<&str>) -> Result<Arc<dyn Storage>> {
    if settings.service == "local" {
        if settings.remote_folder.is_empty() {
            return Err(invalid());
        }
        return Ok(Arc::new(Local {
            root: PathBuf::from(&settings.remote_folder),
        }));
    }
    let mut client = Client::builder()
        .timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(ca) = ca {
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(ca))
            .collect::<std::io::Result<Vec<_>>>()?;
        for certificate in certs {
            client = client.add_root_certificate(
                reqwest::Certificate::from_der(certificate.as_ref()).map_err(|_| invalid())?,
            );
        }
    }
    let client = client.build().map_err(|_| invalid())?;
    match settings.service.as_str() {
        "s3" => Ok(Arc::new(S3::new(client, settings)?)),
        "google-drive" | "Google Drive" => {
            if settings.secrets.len() != 3 || settings.secrets.iter().any(String::is_empty) {
                return Err(invalid());
            }
            Ok(Arc::new(Drive {
                client,
                folder: settings.remote_folder.clone(),
                secrets: settings.secrets.clone(),
                token: tokio::sync::Mutex::new(None),
            }))
        }
        "template" => {
            let template: Template =
                serde_json::from_str(settings.template.as_deref().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            let names = regex::Regex::new(&template.list.names_regex).map_err(|_| invalid())?;
            if names.captures_len() < 2
                || !matches!(
                    template.auth.kind.as_str(),
                    "" | "none" | "static" | "header" | "basic" | "oauth2"
                )
                || [
                    &template.put,
                    &template.get,
                    &template.delete,
                    &template.list,
                ]
                .iter()
                .any(|op| op.url.is_empty())
                || template.concurrency > 32
            {
                return Err(invalid());
            }
            let inflight = tokio::sync::Semaphore::new(if template.concurrency == 0 {
                settings.concurrency
            } else {
                template.concurrency
            });
            Ok(Arc::new(Templated {
                client,
                template,
                names,
                folder: settings.remote_folder.clone(),
                secrets: settings.secrets.clone(),
                token: tokio::sync::Mutex::new(None),
                inflight,
            }))
        }
        _ => Err(invalid()),
    }
}
pub(crate) fn create(settings: &Settings, ca: Option<&str>) -> Result<Arc<dyn Storage>> {
    Ok(Arc::new(Limited {
        inner: backend(settings, ca)?,
        gate: tokio::sync::Semaphore::new(settings.concurrency),
    }))
}
struct Limited {
    inner: Arc<dyn Storage>,
    gate: tokio::sync::Semaphore,
}
impl Storage for Limited {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.put(name, data).await
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.get(name).await
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.delete(name).await
        })
    }
    fn list<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<Entry>>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.list(name).await
        })
    }
    fn description<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.description(id).await
        })
    }
    fn slot_body<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.slot_body(id).await
        })
    }
    fn set_slot<'a>(
        &'a self,
        id: &'a str,
        description: String,
        data: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let _permit = self.gate.acquire().await.map_err(|_| Error::Cancelled)?;
            self.inner.set_slot(id, description, data).await
        })
    }
}
struct Local {
    root: PathBuf,
}
impl Local {
    fn path(&self, name: &str) -> Result<PathBuf> {
        if !safe(name) {
            return Err(invalid());
        }
        Ok(self.root.join(name))
    }
}
impl Storage for Local {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let path = self.path(name)?;
            let parent = path.parent().ok_or_else(invalid)?;
            tokio::fs::create_dir_all(parent).await?;
            let tmp = parent.join(format!(".xdrive-tmp-{:016x}", rand::random::<u64>()));
            let mut options = tokio::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            use tokio::io::AsyncWriteExt;
            let mut file = options.open(&tmp).await?;
            file.write_all(data).await?;
            file.flush().await?;
            drop(file);
            if let Err(error) = tokio::fs::rename(&tmp, &path).await {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(Error::Io(error));
            }
            Ok(())
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let path = self.path(name)?;
            let metadata = match tokio::fs::metadata(&path).await {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if metadata.len() > 2 * 1024 * 1024 {
                return Err(Error::ResourceLimit);
            }
            Ok(Some(tokio::fs::read(path).await?))
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let path = self.path(name)?;
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => {
                    tokio::fs::remove_dir_all(path).await?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
            }
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Entry>>> {
        Box::pin(async move {
            let mut directory = match tokio::fs::read_dir(self.path(prefix)?).await {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(error) => return Err(error.into()),
            };
            let mut entries = Vec::new();
            while let Some(entry) = directory.next_entry().await? {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with(".xdrive-tmp-") {
                    entries.push(Entry { name, inline: None });
                }
                if entries.len() > 65536 {
                    return Err(Error::ResourceLimit);
                }
            }
            Ok(entries)
        })
    }
}
async fn body(mut response: reqwest::Response) -> Result<(u16, Vec<u8>)> {
    let status = response.status().as_u16();
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| remote())? {
        if data.len() + chunk.len() > 8 * 1024 * 1024 {
            return Err(Error::ResourceLimit);
        }
        data.extend_from_slice(&chunk);
    }
    Ok((status, data))
}
fn success(status: u16) -> bool {
    (200..300).contains(&status)
}
fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let path = path.trim_start_matches("$.");
    path.split('.').try_fold(value, |value, key| value.get(key))
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(bytes: impl AsRef<[u8]>) -> String {
    hex(Sha256::digest(bytes.as_ref()))
}
fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC 接受任意密钥长度");
    h.update(data);
    h.finalize().into_bytes().to_vec()
}

struct S3 {
    client: Client,
    base: Url,
    prefix: String,
    region: String,
    secrets: Vec<String>,
}
impl S3 {
    fn new(client: Client, settings: &Settings) -> Result<Self> {
        let s3 = settings.s3.as_ref().ok_or_else(invalid)?;
        let mut base = Url::parse(&s3.endpoint).map_err(|_| invalid())?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || !safe(&s3.bucket)
            || s3.bucket.contains('/')
            || !safe(&settings.remote_folder)
            || !(2..=3).contains(&settings.secrets.len())
        {
            return Err(invalid());
        }
        if s3.path_style {
            let path = format!("{}/{}", base.path().trim_end_matches('/'), s3.bucket);
            base.set_path(&path);
        } else {
            let host = format!("{}.{}", s3.bucket, base.host_str().ok_or_else(invalid)?);
            base.set_host(Some(&host)).map_err(|_| invalid())?;
        }
        Ok(Self {
            client,
            base,
            prefix: settings.remote_folder.trim_end_matches('/').into(),
            region: if s3.region.is_empty() {
                "us-east-1".into()
            } else {
                s3.region.clone()
            },
            secrets: settings.secrets.clone(),
        })
    }
    async fn request(
        &self,
        method: Method,
        name: Option<&str>,
        query: Option<&str>,
        payload: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut url = self.base.clone();
        if let Some(name) = name {
            if !safe(name) {
                return Err(invalid());
            }
            url.set_path(&format!(
                "{}/{}/{}",
                self.base.path().trim_end_matches('/'),
                self.prefix,
                name
            ));
        }
        url.set_query(query);
        let now = time::OffsetDateTime::now_utc();
        let stamp = now
            .format(&time::macros::format_description!(
                "[year][month][day]T[hour][minute][second]Z"
            ))
            .map_err(|_| remote())?;
        let date = &stamp[..8];
        let mut headers = BTreeMap::new();
        let host = format!(
            "{}{}",
            url.host_str().ok_or_else(invalid)?,
            url.port().map(|p| format!(":{p}")).unwrap_or_default()
        );
        headers.insert("host", host);
        headers.insert("x-amz-content-sha256", sha(&payload));
        headers.insert("x-amz-date", stamp.clone());
        if self.secrets.len() == 3 {
            headers.insert("x-amz-security-token", self.secrets[2].clone());
        }
        let mut pairs: Vec<_> = url
            .query()
            .unwrap_or("")
            .split('&')
            .filter(|s| !s.is_empty())
            .collect();
        pairs.sort_unstable();
        let query = pairs.join("&").replace('+', "%20");
        url.set_query((!query.is_empty()).then_some(&query));
        let signed = headers.keys().copied().collect::<Vec<_>>().join(";");
        let canonical_headers = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect::<String>();
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            url.path(),
            query,
            canonical_headers,
            signed,
            sha(&payload)
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let text = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", sha(canonical));
        let kd = mac(
            format!("AWS4{}", self.secrets[1]).as_bytes(),
            date.as_bytes(),
        );
        let kr = mac(&kd, self.region.as_bytes());
        let ks = mac(&kr, b"s3");
        let signing = mac(&ks, b"aws4_request");
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
            self.secrets[0],
            hex(mac(&signing, text.as_bytes()))
        );
        let mut request = self
            .client
            .request(method, url)
            .header("authorization", authorization)
            .body(payload);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        body(request.send().await.map_err(|_| remote())?).await
    }
}
#[derive(Deserialize)]
struct S3List {
    #[serde(rename = "Contents", default)]
    contents: Vec<S3Object>,
    #[serde(rename = "NextContinuationToken", default)]
    next: Option<String>,
}
#[derive(Deserialize)]
struct S3Object {
    #[serde(rename = "Key")]
    key: String,
}
impl Storage for S3 {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (status, _) = self
                .request(Method::PUT, Some(name), None, data.to_vec())
                .await?;
            if success(status) {
                Ok(())
            } else {
                Err(remote())
            }
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let (status, data) = self
                .request(Method::GET, Some(name), None, Vec::new())
                .await?;
            if status == 404 {
                Ok(None)
            } else if success(status) {
                Ok(Some(data))
            } else {
                Err(remote())
            }
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (status, _) = self
                .request(Method::DELETE, Some(name), None, Vec::new())
                .await?;
            if status == 404 || success(status) {
                Ok(())
            } else {
                Err(remote())
            }
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Entry>>> {
        Box::pin(async move {
            if !safe(prefix) {
                return Err(invalid());
            }
            let full = format!("{}/{prefix}/", self.prefix);
            let mut next:Option<String> = None;
            let mut output = std::collections::BTreeSet::new();
            for _ in 0..64 {
                let mut query = Url::parse("https://storage.invalid/").map_err(|_| invalid())?;
                {
                    let mut pairs = query.query_pairs_mut();
                    pairs
                        .append_pair("list-type", "2")
                        .append_pair("prefix", &full);
                    if let Some(token) = &next {
                        pairs.append_pair("continuation-token", token);
                    }
                }
                let (status, data) = self
                    .request(Method::GET, None, query.query(), Vec::new())
                    .await?;
                if !success(status) {
                    return Err(remote());
                }
                let page: S3List =
                    quick_xml::de::from_reader(data.as_slice()).map_err(|_| remote())?;
                for item in page.contents {
                    if let Some(rest) = item.key.strip_prefix(&full)
                        && let Some(name) = rest.split('/').next()
                        && !name.is_empty()
                    {
                        output.insert(name.to_owned());
                    }
                }
                next = page.next;
                if next.is_none() {
                    return Ok(output
                        .into_iter()
                        .map(|name| Entry { name, inline: None })
                        .collect());
                }
            }
            Err(Error::ResourceLimit)
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct Auth {
    #[serde(rename = "type")]
    kind: String,
    header: BTreeMap<String, String>,
    username: String,
    password: String,
    token_url: String,
    form: BTreeMap<String, String>,
    token_path: String,
    expiry_path: String,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct Operation {
    method: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: String,
    names_regex: String,
    href_path: String,
    href_method: String,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
struct Retry {
    status: Vec<u16>,
    rate_reason: String,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Template {
    flatten: bool,
    concurrency: usize,
    auth: Auth,
    put: Operation,
    get: Operation,
    delete: Operation,
    list: Operation,
    retry: Retry,
}
struct Templated {
    client: Client,
    template: Template,
    names: regex::Regex,
    folder: String,
    secrets: Vec<String>,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
    inflight: tokio::sync::Semaphore,
}
fn substitute(text: &str, vars: &BTreeMap<String, String>) -> String {
    vars.iter().fold(text.to_owned(), |text, (key, value)| {
        text.replace(&format!("{{{key}}}"), value)
    })
}
impl Templated {
    fn variables(&self, name: &str, payload: Option<&[u8]>) -> BTreeMap<String, String> {
        let mut vars = BTreeMap::new();
        vars.insert("folder".into(), self.folder.clone());
        for (index, secret) in self.secrets.iter().enumerate() {
            vars.insert(format!("secret{index}"), secret.clone());
        }
        let stored = if self.template.flatten {
            name.replace('/', "~")
        } else {
            name.into()
        };
        vars.insert("name".into(), stored.clone());
        vars.insert("prefix".into(), stored);
        if let Some(data) = payload {
            vars.insert("data".into(), STANDARD.encode(data));
        }
        vars
    }
    async fn token(&self, vars: &BTreeMap<String, String>) -> Result<String> {
        let mut token = self.token.lock().await;
        if let Some((value, expiry)) = &*token
            && *expiry > Instant::now()
        {
            return Ok(value.clone());
        }
        let form = self
            .template
            .auth
            .form
            .iter()
            .map(|(k, v)| (k.clone(), substitute(v, vars)))
            .collect::<BTreeMap<_, _>>();
        let (status, data) = body(
            self.client
                .post(substitute(&self.template.auth.token_url, vars))
                .form(&form)
                .send()
                .await
                .map_err(|_| remote())?,
        )
        .await?;
        if !success(status) {
            return Err(remote());
        }
        let value: Value = serde_json::from_slice(&data).map_err(|_| remote())?;
        let path = if self.template.auth.token_path.is_empty() {
            "access_token"
        } else {
            &self.template.auth.token_path
        };
        let value_token = value_at(&value, path)
            .and_then(Value::as_str)
            .ok_or_else(remote)?
            .to_owned();
        let duration = value_at(
            &value,
            if self.template.auth.expiry_path.is_empty() {
                "expires_in"
            } else {
                &self.template.auth.expiry_path
            },
        )
        .and_then(Value::as_u64)
        .unwrap_or(3600)
        .saturating_sub(30)
        .min(86400);
        *token = Some((
            value_token.clone(),
            Instant::now() + Duration::from_secs(duration),
        ));
        Ok(value_token)
    }
    async fn call(
        &self,
        op: &Operation,
        vars: &BTreeMap<String, String>,
        payload: Vec<u8>,
        presigned: bool,
    ) -> Result<(u16, Vec<u8>)> {
        let _permit = self
            .inflight
            .acquire()
            .await
            .map_err(|_| Error::Cancelled)?;
        let url = Url::parse(&if presigned {
            op.url.clone()
        } else {
            substitute(&op.url, vars)
        })
        .map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(invalid());
        }
        let method = Method::from_bytes(if op.method.is_empty() {
            b"GET"
        } else {
            op.method.as_bytes()
        })
        .map_err(|_| invalid())?;
        for attempt in 0..8 {
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .body(payload.clone());
            if !presigned {
                for (key, value) in &op.headers {
                    request = request.header(key, substitute(value, vars));
                }
                match self.template.auth.kind.as_str() {
                    "" | "none" => {}
                    "static" | "header" => {
                        for (key, value) in &self.template.auth.header {
                            request = request.header(key, substitute(value, vars));
                        }
                    }
                    "basic" => {
                        request = request.basic_auth(
                            substitute(&self.template.auth.username, vars),
                            Some(substitute(&self.template.auth.password, vars)),
                        );
                    }
                    "oauth2" => {
                        let mut authenticated = vars.clone();
                        authenticated.insert("token".into(), self.token(vars).await?);
                        for (key, value) in &self.template.auth.header {
                            request = request.header(key, substitute(value, &authenticated));
                        }
                    }
                    _ => return Err(invalid()),
                }
            }
            let response = body(request.send().await.map_err(|_| remote())?).await?;
            if response.0 == 401 && self.template.auth.kind == "oauth2" && !presigned {
                *self.token.lock().await = None;
                continue;
            }
            let rate_reason = response.0 == 403
                && !self.template.retry.rate_reason.is_empty()
                && serde_json::from_slice::<Value>(&response.1)
                    .ok()
                    .and_then(|value| {
                        value_at(&value, &self.template.retry.rate_reason)
                            .and_then(Value::as_str)
                            .map(|value| !value.is_empty())
                    })
                    .unwrap_or(false);
            let retry = rate_reason
                || self.template.retry.status.contains(&response.0)
                || response.0 == 429
                || response.0 >= 500;
            if !retry || attempt == 7 {
                return Ok(response);
            }
            tokio::time::sleep(Duration::from_millis(
                100u64.saturating_mul(1 << attempt).min(8000),
            ))
            .await;
        }
        Err(remote())
    }
    async fn run(
        &self,
        op: &Operation,
        name: &str,
        payload: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>)> {
        let vars = self.variables(name, payload);
        let bytes = if !op.body.is_empty() {
            substitute(&op.body, &vars).into_bytes()
        } else {
            payload.unwrap_or_default().to_vec()
        };
        let result = self
            .call(
                op,
                &vars,
                if op.href_path.is_empty() {
                    bytes.clone()
                } else {
                    Vec::new()
                },
                false,
            )
            .await?;
        if op.href_path.is_empty() || !success(result.0) {
            return Ok(result);
        }
        let value: Value = serde_json::from_slice(&result.1).map_err(|_| remote())?;
        let href = value_at(&value, &op.href_path)
            .and_then(Value::as_str)
            .ok_or_else(remote)?;
        self.call(
            &Operation {
                url: href.into(),
                method: op.href_method.clone(),
                ..Default::default()
            },
            &vars,
            bytes,
            true,
        )
        .await
    }
}
impl Storage for Templated {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (status, _) = self.run(&self.template.put, name, Some(data)).await?;
            if success(status) {
                Ok(())
            } else {
                Err(remote())
            }
        })
    }
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let (status, data) = self.run(&self.template.get, name, None).await?;
            if status == 404 {
                Ok(None)
            } else if success(status) {
                Ok(Some(data))
            } else {
                Err(remote())
            }
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (status, _) = self.run(&self.template.delete, name, None).await?;
            if status == 404 || success(status) {
                Ok(())
            } else {
                Err(remote())
            }
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Entry>>> {
        Box::pin(async move {
            let (status, data) = self.run(&self.template.list, prefix, None).await?;
            if status == 404 {
                return Ok(Vec::new());
            }
            if !success(status) {
                return Err(remote());
            }
            let text = std::str::from_utf8(&data).map_err(|_| remote())?;
            let flat = if self.template.flatten {
                prefix.replace('/', "~")
            } else {
                prefix.into()
            };
            let mut names = std::collections::BTreeSet::new();
            for capture in self.names.captures_iter(text).take(65536) {
                let Some(name) = capture.get(1) else { continue };
                let name = if self.template.flatten {
                    let Some(rest) = name.as_str().strip_prefix(&(flat.clone() + "~")) else {
                        continue;
                    };
                    rest
                } else {
                    name.as_str()
                };
                if let Some(name) = name
                    .split(if self.template.flatten { '~' } else { '/' })
                    .next()
                    && !name.is_empty()
                {
                    names.insert(name.to_owned());
                }
            }
            Ok(names
                .into_iter()
                .map(|name| Entry { name, inline: None })
                .collect())
        })
    }
}

struct Drive {
    client: Client,
    folder: String,
    secrets: Vec<String>,
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
}
#[derive(Deserialize)]
struct DrivePage {
    #[serde(default, rename = "nextPageToken")]
    next: Option<String>,
    #[serde(default)]
    files: Vec<DriveFile>,
}
#[derive(Deserialize)]
struct DriveFile {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    size: Option<String>,
}
impl Drive {
    async fn token(&self) -> Result<String> {
        let mut token = self.token.lock().await;
        if let Some((value, expiry)) = &*token
            && *expiry > Instant::now()
        {
            return Ok(value.clone());
        }
        let form = [
            ("client_id", self.secrets[0].as_str()),
            ("client_secret", self.secrets[1].as_str()),
            ("refresh_token", self.secrets[2].as_str()),
            ("grant_type", "refresh_token"),
        ];
        let (status, data) = body(
            self.client
                .post("https://oauth2.googleapis.com/token")
                .form(&form)
                .send()
                .await
                .map_err(|_| remote())?,
        )
        .await?;
        if !success(status) {
            return Err(remote());
        }
        let value: Value = serde_json::from_slice(&data).map_err(|_| remote())?;
        let text = value
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(remote)?
            .to_owned();
        let seconds = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(3600)
            .saturating_sub(30)
            .min(86400);
        *token = Some((text.clone(), Instant::now() + Duration::from_secs(seconds)));
        Ok(text)
    }
    async fn request(
        &self,
        method: Method,
        url: Url,
        content_type: Option<&str>,
        data: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        for attempt in 0..8 {
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .bearer_auth(self.token().await?)
                .body(data.clone());
            if let Some(content) = content_type {
                request = request.header("content-type", content);
            }
            let result = body(request.send().await.map_err(|_| remote())?).await?;
            if result.0 == 401 {
                *self.token.lock().await = None;
            } else if result.0 != 429 && result.0 < 500 {
                return Ok(result);
            }
            if attempt == 7 {
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis((100u64 << attempt).min(8000))).await;
        }
        Err(remote())
    }
    async fn query(&self, condition: &str) -> Result<Vec<DriveFile>> {
        let mut next:Option<String> = None;
        let mut output = Vec::new();
        let folder = self.folder.replace('\\', "\\\\").replace('\'', "\\'");
        for _ in 0..64 {
            let mut url =
                Url::parse("https://www.googleapis.com/drive/v3/files").map_err(|_| invalid())?;
            {
                let mut pairs = url.query_pairs_mut();
                pairs
                    .append_pair(
                        "q",
                        &format!("'{folder}' in parents and trashed = false and ({condition})"),
                    )
                    .append_pair("fields", "nextPageToken,files(id,name,description,size)")
                    .append_pair("pageSize", "1000");
                if let Some(token) = &next {
                    pairs.append_pair("pageToken", token);
                }
            }
            let (status, data) = self.request(Method::GET, url, None, Vec::new()).await?;
            if !success(status) {
                return Err(remote());
            }
            let page: DrivePage = serde_json::from_slice(&data).map_err(|_| remote())?;
            output.extend(page.files);
            next = page.next;
            if next.is_none() {
                return Ok(output);
            }
        }
        Err(Error::ResourceLimit)
    }
    async fn id(&self, name: &str) -> Result<Option<String>> {
        if !safe(name) {
            return Err(invalid());
        }
        let flat = name
            .replace('/', "~")
            .replace('\\', "\\\\")
            .replace('\'', "\\'");
        Ok(self
            .query(&format!("name = '{flat}'"))
            .await?
            .into_iter()
            .last()
            .map(|file| file.id))
    }
    async fn metadata(&self, id: &str) -> Result<Option<DriveFile>> {
        let mut url =
            Url::parse("https://www.googleapis.com/drive/v3/files/").map_err(|_| invalid())?;
        url.path_segments_mut().map_err(|_| invalid())?.push(id);
        url.query_pairs_mut()
            .append_pair("fields", "id,name,description,size");
        let (status, data) = self.request(Method::GET, url, None, Vec::new()).await?;
        if status == 404 {
            return Ok(None);
        }
        if !success(status) {
            return Err(remote());
        }
        Ok(Some(serde_json::from_slice(&data).map_err(|_| remote())?))
    }
    async fn media(&self, id: &str) -> Result<Vec<u8>> {
        let mut url =
            Url::parse("https://www.googleapis.com/drive/v3/files/").map_err(|_| invalid())?;
        url.path_segments_mut().map_err(|_| invalid())?.push(id);
        url.query_pairs_mut().append_pair("alt", "media");
        let (status, data) = self.request(Method::GET, url, None, Vec::new()).await?;
        if success(status) {
            Ok(data)
        } else {
            Err(remote())
        }
    }
    async fn create_file(&self, name: &str, data: &[u8]) -> Result<()> {
        if !safe(name) {
            return Err(invalid());
        }
        let description = if data.len() <= 12000 {
            STANDARD.encode(data)
        } else {
            String::new()
        };
        let metadata =
            json!({"name":name.replace('/',"~"),"parents":[self.folder],"description":description});
        let (url, content, body) = if data.len() <= 12000 {
            (
                Url::parse("https://www.googleapis.com/drive/v3/files?fields=id")
                    .map_err(|_| invalid())?,
                "application/json; charset=UTF-8",
                serde_json::to_vec(&metadata).map_err(|_| invalid())?,
            )
        } else {
            let mut body =
                b"--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
                    .to_vec();
            body.extend(serde_json::to_vec(&metadata).map_err(|_| invalid())?);
            body.extend_from_slice(
                b"\r\n--xdrive-boundary\r\nContent-Type: application/octet-stream\r\n\r\n",
            );
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n--xdrive-boundary--\r\n");
            (Url::parse("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id").map_err(|_|invalid())?,"multipart/related; boundary=xdrive-boundary",body)
        };
        let (status, _) = self.request(Method::POST, url, Some(content), body).await?;
        if success(status) {
            Ok(())
        } else {
            Err(remote())
        }
    }
}
impl Storage for Drive {
    fn put<'a>(&'a self, name: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.create_file(name, data))
    }
    fn get<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let Some(id) = self.id(name).await? else {
                return Ok(None);
            };
            let Some(metadata) = self.metadata(&id).await? else {
                return Ok(None);
            };
            if metadata.size.as_deref() == Some("0") && metadata.description.is_empty() {
                Ok(Some(Vec::new()))
            } else if !metadata.description.is_empty() {
                Ok(Some(
                    STANDARD
                        .decode(metadata.description)
                        .map_err(|_| remote())?,
                ))
            } else {
                Ok(Some(self.media(&id).await?))
            }
        })
    }
    fn delete<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut files = self
                .query(&format!(
                    "name contains '{}'",
                    name.replace('/', "~").replace('\'', "\\'")
                ))
                .await?;
            files.retain(|file| {
                file.name == name.replace('/', "~")
                    || file.name.starts_with(&(name.replace('/', "~") + "~"))
            });
            for file in files {
                let mut url = Url::parse("https://www.googleapis.com/drive/v3/files/")
                    .map_err(|_| invalid())?;
                url.path_segments_mut()
                    .map_err(|_| invalid())?
                    .push(&file.id);
                let (status, _) = self.request(Method::DELETE, url, None, Vec::new()).await?;
                if status != 404 && !success(status) {
                    return Err(remote());
                }
            }
            Ok(())
        })
    }
    fn list<'a>(&'a self, prefix: &'a str) -> BoxFuture<'a, Result<Vec<Entry>>> {
        Box::pin(async move {
            if !safe(prefix) {
                return Err(invalid());
            }
            let flat = prefix.replace('/', "~") + "~";
            let files = self
                .query(&format!("name contains '{}'", flat.replace('\'', "\\'")))
                .await?;
            let mut entries = BTreeMap::new();
            for file in files {
                if let Some(rest) = file.name.strip_prefix(&flat) {
                    let name = rest.split('~').next().unwrap_or("");
                    if !name.is_empty() {
                        let inline = if !rest.contains('~') && !file.description.is_empty() {
                            STANDARD.decode(file.description).ok()
                        } else {
                            None
                        };
                        entries.insert(
                            name.to_owned(),
                            Entry {
                                name: name.into(),
                                inline,
                            },
                        );
                    }
                }
            }
            Ok(entries.into_values().collect())
        })
    }
    fn description<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            self.metadata(id)
                .await?
                .map(|file| file.description)
                .ok_or_else(remote)
        })
    }
    fn slot_body<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(self.media(id))
    }
    fn set_slot<'a>(
        &'a self,
        id: &'a str,
        description: String,
        data: Option<Vec<u8>>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let metadata = json!({"description":description});
            let (mut url, content, body) = if let Some(data) = data {
                let mut bytes =
                    b"--xdrive-boundary\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n"
                        .to_vec();
                bytes.extend(serde_json::to_vec(&metadata).map_err(|_| invalid())?);
                bytes.extend_from_slice(
                    b"\r\n--xdrive-boundary\r\nContent-Type: application/octet-stream\r\n\r\n",
                );
                bytes.extend(data);
                bytes.extend_from_slice(b"\r\n--xdrive-boundary--\r\n");
                (
                    Url::parse("https://www.googleapis.com/upload/drive/v3/files/")
                        .map_err(|_| invalid())?,
                    "multipart/related; boundary=xdrive-boundary",
                    bytes,
                )
            } else {
                (
                    Url::parse("https://www.googleapis.com/drive/v3/files/")
                        .map_err(|_| invalid())?,
                    "application/json; charset=UTF-8",
                    serde_json::to_vec(&metadata).map_err(|_| invalid())?,
                )
            };
            url.path_segments_mut().map_err(|_| invalid())?.push(id);
            if content.starts_with("multipart") {
                url.query_pairs_mut().append_pair("uploadType", "multipart");
            }
            let (status, _) = self
                .request(Method::PATCH, url, Some(content), body)
                .await?;
            if success(status) {
                Ok(())
            } else {
                Err(remote())
            }
        })
    }
}
