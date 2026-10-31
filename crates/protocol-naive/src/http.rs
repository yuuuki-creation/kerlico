//! CONNECT 目标、认证与 padding 协商；不向目标传递代理头。
use crate::{
    config::{HEADER_LIMIT, User, malformed},
    padding,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use kerlico_core::{Destination, Error, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub(crate) const V1: &str = "sp.udp-over-tcp.arpa";
pub(crate) const V2: &str = "sp.v2.udp-over-tcp.arpa";
pub(crate) fn authority(value: &str) -> Result<Destination> {
    if value.len() > 300 || value.contains(['/', '\\', '?', '#', '@']) {
        return Err(malformed());
    }
    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        let (host, port) = value.split_once("]:").ok_or_else(malformed)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(malformed());
        }
        (host, port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(malformed)?;
        if host.contains(':') {
            return Err(malformed());
        }
        (host, port)
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    let port: u16 = port.parse().map_err(|_| malformed())?;
    let port = if port == 0 && (host.eq_ignore_ascii_case(V1) || host.eq_ignore_ascii_case(V2)) {
        1
    } else {
        port
    };
    Destination::new(host, port).map_err(|_| malformed())
}
pub(crate) fn unique<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(malformed());
    }
    first
        .map(|v| v.to_str().map_err(|_| malformed()))
        .transpose()
}
fn bounded(headers: &HeaderMap) -> Result<()> {
    if headers.len() > 64
        || headers
            .iter()
            .try_fold(0usize, |n, (k, v)| {
                n.checked_add(k.as_str().len() + v.len() + 4)
            })
            .is_none_or(|n| n > HEADER_LIMIT)
    {
        return Err(Error::ResourceLimit);
    }
    Ok(())
}
pub(crate) fn request(target: &Destination, user: &User) -> Result<Request<()>> {
    Request::builder()
        .method(Method::CONNECT)
        .uri(target.to_string())
        .header("proxy-authorization", user.authorization())
        .header("padding", padding::header(false))
        .header("padding-type-request", "1")
        .body(())
        .map_err(|_| malformed())
}
pub(crate) fn check_request<T>(request: &Request<T>, users: &[Arc<User>]) -> Result<Destination> {
    bounded(request.headers())?;
    if request.method() != Method::CONNECT
        || request.uri().scheme().is_some()
        || request.uri().path_and_query().is_some()
        || request.extensions().get::<h3::ext::Protocol>().is_some()
    {
        return Err(malformed());
    }
    for name in [
        "connection",
        "proxy-connection",
        "upgrade",
        "transfer-encoding",
        "content-length",
        "-connect-authority",
    ] {
        if request.headers().contains_key(name) {
            return Err(malformed());
        }
    }
    let authorization = unique(request.headers(), "proxy-authorization")?.ok_or(Error::Rejected)?;
    let mut authenticated = false;
    for user in users {
        authenticated |= user.matches(authorization);
    }
    if !authenticated {
        return Err(Error::Rejected);
    }
    let padding = unique(request.headers(), "padding")?.ok_or_else(malformed)?;
    if padding.is_empty() || padding.len() > 1024 {
        return Err(malformed());
    }
    if let Some(types) = unique(request.headers(), "padding-type-request")? {
        let mut supported = false;
        let mut count = 0;
        for value in types.split(',') {
            count += 1;
            match value.trim() {
                "1" => supported = true,
                "0" => {}
                _ => return Err(malformed()),
            }
        }
        if !supported || count > 8 {
            return Err(malformed());
        }
    }
    let value = request.uri().authority().ok_or_else(malformed)?.as_str();
    if let Some(host) = unique(request.headers(), "host")?
        && host != value
    {
        return Err(malformed());
    }
    authority(value)
}
pub(crate) fn response() -> Response<()> {
    let mut response = Response::new(());
    response.headers_mut().insert(
        "padding",
        HeaderValue::from_str(&padding::header(true)).expect("填充字符固定合法"),
    );
    response
        .headers_mut()
        .insert("padding-type-reply", HeaderValue::from_static("1"));
    response
}
pub(crate) fn check_response<T>(response: &Response<T>) -> Result<()> {
    bounded(response.headers())?;
    if response.status() != StatusCode::OK {
        return Err(Error::Rejected);
    }
    if unique(response.headers(), "padding")?.is_none_or(str::is_empty) {
        return Err(malformed());
    }
    if let Some(value) = unique(response.headers(), "padding-type-reply")?
        && value != "1"
    {
        return Err(malformed());
    }
    Ok(())
}
async fn head(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    while bytes.len() < HEADER_LIMIT {
        let byte = reader.read_u8().await?;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(Error::ResourceLimit)
}
fn headers<'a>(lines: impl Iterator<Item = &'a str>) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > 64 || line.starts_with([' ', '\t']) {
            return Err(malformed());
        }
        let (name, value) = line.split_once(':').ok_or_else(malformed)?;
        if name.trim() != name {
            return Err(malformed());
        }
        let name =
            http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| malformed())?;
        let value =
            HeaderValue::from_str(value.trim_matches([' ', '\t'])).map_err(|_| malformed())?;
        headers.append(name, value);
    }
    bounded(&headers)?;
    Ok(headers)
}
pub(crate) async fn read_request(reader: &mut (impl AsyncRead + Unpin)) -> Result<Request<()>> {
    let bytes = head(reader).await?;
    let text = std::str::from_utf8(&bytes).map_err(|_| malformed())?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or_else(malformed)?;
    let mut words = first.split(' ');
    if words.next() != Some("CONNECT") {
        return Err(malformed());
    }
    let target = words.next().ok_or_else(malformed)?;
    if words.next() != Some("HTTP/1.1") || words.next().is_some() {
        return Err(malformed());
    }
    authority(target)?;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(target)
        .body(())
        .map_err(|_| malformed())?;
    *request.headers_mut() = headers(lines)?;
    Ok(request)
}
pub(crate) async fn read_response(reader: &mut (impl AsyncRead + Unpin)) -> Result<Response<()>> {
    let bytes = head(reader).await?;
    let text = std::str::from_utf8(&bytes).map_err(|_| malformed())?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or_else(malformed)?;
    let mut words = first.splitn(3, ' ');
    if words.next() != Some("HTTP/1.1") {
        return Err(malformed());
    }
    let status = words
        .next()
        .ok_or_else(malformed)?
        .parse::<u16>()
        .map_err(|_| malformed())?;
    let mut response = Response::builder()
        .status(status)
        .body(())
        .map_err(|_| malformed())?;
    *response.headers_mut() = headers(lines)?;
    Ok(response)
}
pub(crate) async fn write_request(
    writer: &mut (impl AsyncWrite + Unpin),
    request: &Request<()>,
) -> Result<()> {
    let authority = request.uri().authority().ok_or_else(malformed)?;
    let mut text = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    for (name, value) in request.headers() {
        text.push_str(name.as_str());
        text.push_str(": ");
        text.push_str(value.to_str().map_err(|_| malformed())?);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    writer.write_all(text.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn write_response(
    writer: &mut (impl AsyncWrite + Unpin),
    response: &Response<()>,
) -> Result<()> {
    let mut text = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("Response")
    );
    for (name, value) in response.headers() {
        text.push_str(name.as_str());
        text.push_str(": ");
        text.push_str(value.to_str().map_err(|_| malformed())?);
        text.push_str("\r\n");
    }
    text.push_str("\r\n");
    writer.write_all(text.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authority_and_negotiation_reject_ambiguous_inputs() {
        for value in [
            "x:0", "x:1/a", "[::1]", "::1:80", "x:65536", "x:+1", "x: 1", "x:1@evil",
        ] {
            assert!(authority(value).is_err(), "{value}");
        }
        assert_eq!(authority("[::1]:80").unwrap().port(), 80);
        for host in [V1, V2] {
            let target = authority(&format!("{host}:0")).unwrap();
            assert_eq!(target.host(), host);
            assert_eq!(target.port(), 1);
        }
        assert!(authority("not-udp-over-tcp.arpa:0").is_err());
        let user = Arc::new(User::new("test".into(), "secret".into()).unwrap());
        let target = Destination::new("example.invalid", 443).unwrap();
        let mut request = request(&target, &user).unwrap();
        assert_eq!(
            check_request(&request, std::slice::from_ref(&user)).unwrap(),
            target
        );
        request.headers_mut().append(
            "proxy-authorization",
            HeaderValue::from_static("Basic invalid"),
        );
        assert!(check_request(&request, &[user]).is_err());
        let mut response = response();
        check_response(&response).unwrap();
        response
            .headers_mut()
            .insert("padding-type-reply", HeaderValue::from_static("0"));
        assert!(check_response(&response).is_err());
    }
}
