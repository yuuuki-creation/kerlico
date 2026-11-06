//! 未认证 HTTP/3 请求的伪装应答：默认 404、固定字符串、静态目录或反向代理到上游站点。
//!
//! 反向代理同 apernet/hysteria `masquerade.proxy`：路径与查询拼到上游 URL 后，默认保留原请求
//! `Host`，`rewrite_host` 时改为上游主机；`insecure` 跳过上游证书校验；上游失败返回 502。

use crate::{config::MasqueradePlan, invalid};
use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, header};
use kerlico_core::{Error, InboundContext, Result};
use std::{path::Component, time::Duration};

const MAX_REQUEST_BODY: usize = 4 * 1024 * 1024;
const MAX_FILE: usize = 4 * 1024 * 1024;

pub(crate) struct Masquerade {
    plan: MasqueradePlan,
    client: Option<reqwest::Client>,
}

impl Masquerade {
    pub(crate) fn new(plan: MasqueradePlan) -> Result<Self> {
        let client = match &plan {
            MasqueradePlan::Proxy { insecure, .. } => Some(
                reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .danger_accept_invalid_certs(*insecure)
                    .connect_timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|_| Error::Config("Hysteria2 masquerade 代理客户端创建失败".into()))?,
            ),
            _ => None,
        };
        Ok(Self { plan, client })
    }

    pub(crate) async fn serve<S>(
        &self,
        request: Request<()>,
        stream: &mut RequestStream<S, Bytes>,
        context: &InboundContext,
    ) -> Result<()>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let (
            MasqueradePlan::Proxy {
                url,
                rewrite_host,
                headers,
                ..
            },
            Some(client),
        ) = (&self.plan, &self.client)
        else {
            let (status, headers, body) = self.local(request.uri().path());
            return crate::budget(context)
                .run(respond(stream, status, &headers, body))
                .await;
        };
        let budget = crate::budget(context);
        let body = budget.run(read_body(stream)).await?;
        let upstream = budget
            .run(async {
                let (method, target, outgoing) = upstream_request(&request, url, *rewrite_host)?;
                client
                    .request(method, target)
                    .headers(outgoing)
                    .body(body)
                    .send()
                    .await
                    .map_err(|_| Error::Protocol("masquerade 上游不可达"))
            })
            .await;
        let mut upstream = match upstream {
            Ok(upstream) => upstream,
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(_) => {
                return budget
                    .run(respond(
                        stream,
                        StatusCode::BAD_GATEWAY,
                        headers,
                        Bytes::new(),
                    ))
                    .await;
            }
        };
        let mut response = Response::builder().status(upstream.status());
        for (name, value) in upstream.headers() {
            if !hop_by_hop(name) {
                response = response.header(name, value);
            }
        }
        for (name, value) in headers {
            response = response.header(name, value);
        }
        budget
            .run(async {
                stream
                    .send_response(response.body(()).map_err(|_| invalid())?)
                    .await
                    .map_err(|_| invalid())
            })
            .await?;
        loop {
            let chunk = tokio::select! {
                _ = context.cancel.cancelled() => return Err(Error::Cancelled),
                chunk = tokio::time::timeout(context.idle_timeout, upstream.chunk()) => chunk,
            };
            match chunk {
                Err(_) => return Err(Error::Timeout),
                Ok(Err(_)) => return Err(Error::Protocol("masquerade 上游响应中断")),
                Ok(Ok(None)) => break,
                Ok(Ok(Some(data))) => {
                    stream.send_data(data).await.map_err(|_| invalid())?;
                }
            }
        }
        stream.finish().await.map_err(|_| invalid())
    }

    fn local(&self, request_path: &str) -> (StatusCode, Vec<(HeaderName, HeaderValue)>, Bytes) {
        match &self.plan {
            MasqueradePlan::String {
                status_code,
                headers,
                content,
            } => (*status_code, headers.clone(), content.clone()),
            MasqueradePlan::File { directory, headers } => {
                let not_found = || {
                    (
                        StatusCode::NOT_FOUND,
                        headers.clone(),
                        Bytes::from_static(b"Not Found"),
                    )
                };
                let trimmed = request_path.trim_start_matches('/');
                let relative = std::path::Path::new(if trimmed.is_empty() {
                    "index.html"
                } else {
                    trimmed
                });
                if relative
                    .components()
                    .any(|comp| !matches!(comp, Component::Normal(_)))
                {
                    return not_found();
                }
                let full = directory.join(relative);
                let path = if full.is_dir() {
                    full.join("index.html")
                } else {
                    full
                };
                match std::fs::read(&path) {
                    Ok(bytes) if bytes.len() <= MAX_FILE => {
                        (StatusCode::OK, headers.clone(), Bytes::from(bytes))
                    }
                    _ => not_found(),
                }
            }
            MasqueradePlan::Default404 | MasqueradePlan::Proxy { .. } => (
                StatusCode::NOT_FOUND,
                vec![(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                )],
                Bytes::from_static("资源不存在".as_bytes()),
            ),
        }
    }
}

async fn respond<S>(
    stream: &mut RequestStream<S, Bytes>,
    status: StatusCode,
    headers: &[(HeaderName, HeaderValue)],
    body: Bytes,
) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    stream
        .send_response(response.body(()).map_err(|_| invalid())?)
        .await
        .map_err(|_| invalid())?;
    if !body.is_empty() {
        stream.send_data(body).await.map_err(|_| invalid())?;
    }
    stream.finish().await.map_err(|_| invalid())
}

async fn read_body<S>(stream: &mut RequestStream<S, Bytes>) -> Result<Vec<u8>>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|_| invalid())? {
        if body.len() + chunk.remaining() > MAX_REQUEST_BODY {
            return Err(Error::ResourceLimit);
        }
        while chunk.has_remaining() {
            let part = chunk.chunk();
            body.extend_from_slice(part);
            let len = part.len();
            chunk.advance(len);
        }
    }
    Ok(body)
}

/// 上游 URL 为配置 URL 的协议与主机，路径为两段路径以单个 `/` 相接，查询串依次拼接。
pub(crate) fn upstream_request(
    request: &Request<()>,
    base: &http::Uri,
    rewrite_host: bool,
) -> Result<(http::Method, String, HeaderMap)> {
    let scheme = base.scheme_str().ok_or_else(invalid)?;
    let authority = base.authority().ok_or_else(invalid)?;
    let base_path = base.path();
    let path = request.uri().path();
    let joined = match (base_path.ends_with('/'), path.starts_with('/')) {
        (true, true) => format!("{base_path}{}", &path[1..]),
        (false, false) => format!("{base_path}/{path}"),
        _ => format!("{base_path}{path}"),
    };
    let query = match (base.query(), request.uri().query()) {
        (Some(a), Some(b)) if !a.is_empty() && !b.is_empty() => format!("?{a}&{b}"),
        (Some(a), _) if !a.is_empty() => format!("?{a}"),
        (_, Some(b)) if !b.is_empty() => format!("?{b}"),
        _ => String::new(),
    };
    let target = format!("{scheme}://{authority}{joined}{query}");
    let mut headers = HeaderMap::new();
    for (name, value) in request.headers() {
        if !hop_by_hop(name) && name != header::HOST {
            headers.append(name, value.clone());
        }
    }
    let host = if rewrite_host {
        Some(authority.as_str().to_owned())
    } else {
        request
            .uri()
            .authority()
            .map(|a| a.as_str().to_owned())
            .or_else(|| {
                request
                    .headers()
                    .get(header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            })
    };
    if let Some(host) = host {
        headers.insert(
            header::HOST,
            HeaderValue::from_str(&host).map_err(|_| invalid())?,
        );
    }
    Ok((request.method().clone(), target, headers))
}

fn hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::upstream_request;

    fn request(uri: &str) -> http::Request<()> {
        http::Request::builder()
            .uri(uri)
            .header("accept", "text/html")
            .header("connection", "close")
            .body(())
            .unwrap()
    }

    #[test]
    fn joins_paths_and_queries_and_keeps_the_original_host() {
        let base: http::Uri = "https://upstream.invalid/site/?lang=en".parse().unwrap();
        let (method, target, headers) =
            upstream_request(&request("https://front.invalid/a/b?x=1"), &base, false).unwrap();
        assert_eq!(method, http::Method::GET);
        assert_eq!(target, "https://upstream.invalid/site/a/b?lang=en&x=1");
        assert_eq!(headers["host"], "front.invalid");
        assert_eq!(headers["accept"], "text/html");
        assert!(headers.get("connection").is_none());
    }

    #[test]
    fn rewrite_host_uses_the_upstream_authority() {
        let base: http::Uri = "http://127.0.0.1:8080".parse().unwrap();
        let (_, target, headers) =
            upstream_request(&request("https://front.invalid/"), &base, true).unwrap();
        assert_eq!(target, "http://127.0.0.1:8080/");
        assert_eq!(headers["host"], "127.0.0.1:8080");
    }
}
