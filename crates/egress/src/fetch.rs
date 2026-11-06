//! 在已建立的出站流上发一次 HTTP/1.1 GET：条件请求、gzip 解码、大小上限，重定向交给调用方。

use crate::probe::ProbeTarget;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{StatusCode, header};
use hyper_util::rt::TokioIo;
use kerlico_core::{BoxStream, Error, Result};
use std::io::Read;

/// 条件请求的校验值，来自上一次 200 响应。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

pub(crate) struct Request<'a> {
    pub headers: &'a [(String, String)],
    pub validators: &'a Validators,
    pub size_limit: u64,
}

pub(crate) enum Response {
    Body {
        bytes: Vec<u8>,
        validators: Validators,
    },
    NotModified,
    Redirect(String),
}

fn failed(what: &str, error: impl std::fmt::Display) -> Error {
    Error::Config(format!("下载失败：{what}：{error}"))
}

fn too_large(limit: u64) -> Error {
    Error::Config(format!("下载内容超过大小上限 {limit} 字节"))
}

pub(crate) async fn get(
    stream: BoxStream,
    target: &ProbeTarget,
    request: &Request<'_>,
) -> Result<Response> {
    let stream = match &target.tls {
        Some(connector) => connector.handshake(stream).await?,
        None => stream,
    };
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|e| failed("HTTP 握手", e))?;
    let driver = tokio::spawn(connection);
    let result = exchange(&mut sender, target, request).await;
    driver.abort();
    result
}

async fn exchange(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    target: &ProbeTarget,
    request: &Request<'_>,
) -> Result<Response> {
    let mut builder = hyper::Request::get(target.path.as_str())
        .header(header::HOST, target.authority.as_str())
        .header(header::ACCEPT, "*/*")
        .header(header::ACCEPT_ENCODING, "gzip");
    if !request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
    {
        builder = builder.header(
            header::USER_AGENT,
            concat!("clash.meta kerlico/", env!("CARGO_PKG_VERSION")),
        );
    }
    for (name, value) in request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let Some(etag) = &request.validators.etag {
        builder = builder.header(header::IF_NONE_MATCH, etag.as_str());
    }
    if let Some(modified) = &request.validators.last_modified {
        builder = builder.header(header::IF_MODIFIED_SINCE, modified.as_str());
    }
    let http_request = builder
        .body(Empty::new())
        .map_err(|e| failed("请求头", e))?;
    let response = sender
        .send_request(http_request)
        .await
        .map_err(|e| failed("HTTP 请求", e))?;
    let status = response.status();
    let header_text = |name: header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    if status == StatusCode::NOT_MODIFIED {
        return Ok(Response::NotModified);
    }
    if status.is_redirection() {
        return header_text(header::LOCATION)
            .map(Response::Redirect)
            .ok_or_else(|| failed("重定向", format!("HTTP {} 缺少 Location", status.as_u16())));
    }
    if status != StatusCode::OK {
        return Err(Error::Config(format!("下载失败：HTTP {}", status.as_u16())));
    }
    let limit = request.size_limit;
    if let Some(length) = header_text(header::CONTENT_LENGTH).and_then(|v| v.parse::<u64>().ok())
        && length > limit
    {
        return Err(too_large(limit));
    }
    let validators = Validators {
        etag: header_text(header::ETAG),
        last_modified: header_text(header::LAST_MODIFIED),
    };
    let gzip = header_text(header::CONTENT_ENCODING)
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("gzip"));
    let cap = usize::try_from(limit).unwrap_or(usize::MAX);
    let body = Limited::new(response.into_body(), cap)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<http_body_util::LengthLimitError>() {
                too_large(limit)
            } else {
                failed("读取响应", e)
            }
        })?
        .to_bytes();
    let bytes = if gzip {
        gunzip(&body, limit)?
    } else {
        body.to_vec()
    };
    Ok(Response::Body { bytes, validators })
}

fn gunzip(body: &[u8], limit: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(body)
        .take(limit.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| failed("gzip 解码", e))?;
    if out.len() as u64 > limit {
        return Err(too_large(limit));
    }
    Ok(out)
}

/// 按 RFC 3986 的常见形态解析 `Location`：绝对 URL、`//host/...` 与以 `/` 开头的路径。
pub(crate) fn redirect_target(current: &str, location: &str) -> Result<String> {
    let location = location.trim();
    if location.contains("://") {
        return Ok(location.to_owned());
    }
    let (scheme, rest) = current
        .split_once("://")
        .ok_or_else(|| failed("重定向", "当前 URL 不合法"))?;
    if let Some(authority_path) = location.strip_prefix("//") {
        return Ok(format!("{scheme}://{authority_path}"));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if location.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{location}"));
    }
    let path = &rest[authority.len()..];
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let base = path.rsplit_once('/').map_or("", |(dir, _)| dir);
    Ok(format!("{scheme}://{authority}{base}/{location}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_resolves_absolute_and_relative_locations() {
        let from = "https://a.test/dir/file?x=1";
        assert_eq!(
            redirect_target(from, "http://b.test/x").unwrap(),
            "http://b.test/x"
        );
        assert_eq!(
            redirect_target(from, "//c.test/y").unwrap(),
            "https://c.test/y"
        );
        assert_eq!(
            redirect_target(from, "/root").unwrap(),
            "https://a.test/root"
        );
        assert_eq!(
            redirect_target(from, "next").unwrap(),
            "https://a.test/dir/next"
        );
    }

    #[test]
    fn gunzip_enforces_the_size_limit() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[b'a'; 1000]).unwrap();
        let packed = encoder.finish().unwrap();
        assert_eq!(gunzip(&packed, 1000).unwrap().len(), 1000);
        assert!(gunzip(&packed, 999).is_err());
    }
}
