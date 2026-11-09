use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use super::service_http::{backoff, Headers, HttpReply, Redirects, ServiceHttp, ATTEMPTS};
use super::{invalid, Config, Entry, Storage, XdriveHttpOptions};

#[derive(Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Auth {
    #[serde(rename = "type")]
    kind: String,
    header: Headers,
    username: String,
    password: String,
    token_url: String,
    form: Headers,
    token_path: String,
    expiry_path: String,
}

#[derive(Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Operation {
    method: String,
    url: String,
    headers: Headers,
    body: String,
    names_regex: String,
    href_path: String,
    href_method: String,
}

#[derive(Clone, Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Retry {
    status: Vec<u16>,
    rate_reason: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Template {
    #[serde(default)]
    concurrency: i32,
    #[serde(default)]
    flatten: bool,
    #[serde(default)]
    auth: Auth,
    put: Operation,
    get: Operation,
    delete: Operation,
    list: Operation,
    #[serde(default)]
    retry: Retry,
}

#[derive(Clone)]
pub(super) struct TemplateStorage {
    template: Template,
    names: Regex,
    base: Headers,
    token: Arc<Mutex<Option<(String, Instant)>>>,
    http: ServiceHttp,
}

impl TemplateStorage {
    pub fn new(config: &Config, options: XdriveHttpOptions) -> io::Result<Self> {
        let template: Template =
            serde_json::from_value(config.template.clone()).map_err(invalid)?;
        if [
            &template.put,
            &template.get,
            &template.delete,
            &template.list,
        ]
        .iter()
        .any(|op| op.url.is_empty())
        {
            return Err(invalid(
                "XDrive template needs put, get, list and delete URLs",
            ));
        }
        let auth = &template.auth;
        if !matches!(
            auth.kind.as_str(),
            "" | "none" | "static" | "basic" | "oauth2"
        ) || auth.kind == "oauth2" && auth.token_url.is_empty()
        {
            return Err(invalid("XDrive template auth configuration"));
        }
        let names = Regex::new(&template.list.names_regex).map_err(invalid)?;
        if names.captures_len() < 2 {
            return Err(invalid(
                "XDrive template list needs a namesRegex capture group",
            ));
        }
        let mut base = Headers::from([(
            "folder".into(),
            config.remote_folder.to_string_lossy().into_owned(),
        )]);
        for (index, secret) in config.secrets.iter().enumerate() {
            base.insert(format!("secret{index}"), secret.clone());
        }
        let concurrency = if template.concurrency <= 0 { 32 } else { (template.concurrency as usize).min(256) };
        let xmux = crate::xmux::XmuxConfig::xdrive(Some(&config.xmux), false, options.quic.is_some())?;
        Ok(Self {
            template,
            names,
            base,
            token: Arc::new(Mutex::new(None)),
            http: ServiceHttp::configured(options, Redirects::Follow, xmux, concurrency)?,
        })
    }

    fn name(&self, name: &str) -> String {
        if self.template.flatten {
            name.replace('/', "~")
        } else {
            name.to_owned()
        }
    }

    fn named_vars(&self, name: &str) -> Headers {
        let mut vars = self.base.clone();
        vars.insert("name".into(), self.name(name));
        vars
    }

    fn token(&self) -> io::Result<String> {
        let mut cached = self.token.lock().expect("XDrive OAuth token");
        if let Some((token, _)) = cached.as_ref().filter(|(_, until)| Instant::now() < *until) {
            return Ok(token.clone());
        }
        let auth = &self.template.auth;
        let body = auth
            .form
            .iter()
            .map(|(key, value)| format!("{key}={}", substitute(value, &self.base)))
            .collect::<Vec<_>>()
            .join("&");
        let headers = Headers::from([(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        )]);
        let reply = self
            .http
            .call("POST", &auth.token_url, &headers, body.as_bytes())?;
        if reply.status != 200 {
            return Err(reply.error("template OAuth token"));
        }
        let json: Value = serde_json::from_slice(&reply.body)
            .map_err(|_| invalid("XDrive template token response"))?;
        let token_path = if auth.token_path.is_empty() {
            "access_token"
        } else {
            &auth.token_path
        };
        let token = json_path(&json, token_path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("XDrive template token missing"))?
            .to_owned();
        let lifetime = json_path(&json, &auth.expiry_path)
            .and_then(Value::as_u64)
            .filter(|seconds| *seconds > 0)
            .unwrap_or(3600);
        let duration = Duration::from_secs(if lifetime > 60 {
            lifetime - 60
        } else {
            lifetime
        });
        let now = Instant::now();
        *cached = Some((token.clone(), now.checked_add(duration).unwrap_or(now)));
        Ok(token)
    }

    fn auth(&self, vars: &mut Headers) -> io::Result<Headers> {
        let auth = &self.template.auth;
        match auth.kind.as_str() {
            "" | "none" => Ok(Headers::new()),
            "basic" => {
                let credentials = format!(
                    "{}:{}",
                    substitute(&auth.username, vars),
                    substitute(&auth.password, vars)
                );
                Ok(Headers::from([(
                    "authorization".into(),
                    format!("Basic {}", STANDARD.encode(credentials)),
                )]))
            }
            "static" | "oauth2" => {
                if auth.kind == "oauth2" {
                    vars.insert("token".into(), self.token()?);
                }
                Ok(headers(&auth.header, vars))
            }
            _ => unreachable!("validated template auth"),
        }
    }

    fn run(&self, op: &Operation, vars: Headers, body: &[u8]) -> io::Result<HttpReply> {
        let target = substitute(&op.url, &vars);
        let initial_body = if op.href_path.is_empty() { body } else { &[] };
        let first = self.request(&op.method, &target, Some(&op.headers), vars, initial_body)?;
        if op.href_path.is_empty() || !first.ok() {
            return Ok(first);
        }
        let value: Value = serde_json::from_slice(&first.body)
            .map_err(|_| invalid("XDrive template href response"))?;
        let href = json_path(&value, &op.href_path)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("XDrive template href missing"))?;
        self.request(&op.href_method, href, None, Headers::new(), body)
    }

    fn request(
        &self,
        method: &str,
        url: &str,
        configured: Option<&Headers>,
        mut vars: Headers,
        body: &[u8],
    ) -> io::Result<HttpReply> {
        let method = if method.is_empty() { "GET" } else { method };
        let mut latest = None;
        for attempt in 0..ATTEMPTS {
            let reply = (|| {
                let headers = if let Some(configured) = configured {
                    let mut auth = self.auth(&mut vars)?;
                    auth.extend(self::headers(configured, &vars));
                    auth
                } else {
                    Headers::new()
                };
                self.http.call(method, url, &headers, body)
            })();
            let hint = match reply {
                Ok(reply)
                    if reply.status == 401
                        && configured.is_some()
                        && self.template.auth.kind == "oauth2" =>
                {
                    let mut token = self.token.lock().expect("XDrive OAuth token");
                    if token
                        .as_ref()
                        .is_some_and(|(current, _)| vars.get("token") == Some(current))
                    {
                        *token = None;
                    }
                    latest = Some(reply.error("template OAuth"));
                    None
                }
                Ok(reply) if self.retry(&reply) => {
                    latest = Some(reply.error("template"));
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
        Err(latest.unwrap_or_else(|| io::Error::other("XDrive template request failed")))
    }

    fn retry(&self, reply: &HttpReply) -> bool {
        let retry = &self.template.retry;
        if retry.status.contains(&reply.status) {
            return true;
        }
        reply.status == 403
            && !retry.rate_reason.is_empty()
            && serde_json::from_slice(&reply.body).is_ok_and(|value| {
                json_path(&value, &retry.rate_reason)
                    .and_then(Value::as_str)
                    .is_some_and(|reason| !reason.is_empty())
            })
    }
}

impl Storage for TemplateStorage {
    fn session(&self) -> Option<Arc<dyn Storage>> { Some(Arc::new(self.clone())) }
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let op = &self.template.put;
        let mut vars = self.named_vars(name);
        let rendered;
        let body = if op.body.is_empty() {
            data
        } else {
            vars.insert("data".into(), STANDARD.encode(data));
            rendered = substitute(&op.body, &vars);
            rendered.as_bytes()
        };
        let reply = self.run(op, vars, body)?;
        if reply.ok() {
            Ok(())
        } else {
            Err(reply.error("template PUT"))
        }
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let reply = self.run(&self.template.get, self.named_vars(name), &[])?;
        match reply.status {
            200..=299 => Ok(reply.body),
            404 => Err(io::ErrorKind::NotFound.into()),
            _ => Err(reply.error("template GET")),
        }
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let name = self.name(prefix);
        let mut vars = self.base.clone();
        vars.insert("prefix".into(), name.clone());
        let reply = self.run(&self.template.list, vars, &[])?;
        if reply.status == 404 {
            return Ok(Vec::new());
        }
        if !reply.ok() {
            return Err(reply.error("template LIST"));
        }
        let prefix = format!("{name}~");
        let payload = String::from_utf8_lossy(&reply.body);
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        for captured in self.names.captures_iter(&payload) {
            let Some(name) = captured.get(1).map(|capture| capture.as_str()) else {
                continue;
            };
            let name = if self.template.flatten {
                let Some(rest) = name.strip_prefix(&prefix) else {
                    continue;
                };
                rest.split('~').next().unwrap_or("")
            } else {
                name
            };
            if !name.is_empty() && seen.insert(name) {
                entries.push(Entry {
                    name: name.into(),
                    inline: None,
                });
            }
        }
        Ok(entries)
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let reply = self.run(&self.template.delete, self.named_vars(name), &[])?;
        if reply.ok() || reply.status == 404 {
            Ok(())
        } else {
            Err(reply.error("template DELETE"))
        }
    }
}

fn headers(configured: &Headers, vars: &Headers) -> Headers {
    configured
        .iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), substitute(value, vars)))
        .collect()
}

fn substitute(template: &str, vars: &Headers) -> String {
    let mut result = template.to_owned();
    for (name, value) in vars {
        result = result.replace(&format!("{{{name}}}"), value);
    }
    result
}

pub(super) fn json_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(root, |value, name| value.as_object()?.get(name))
}
