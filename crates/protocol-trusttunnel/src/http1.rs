//! H1 CONNECT 后是原始字节；精确读取头部，不吃掉首段业务数据。
use crate::protocol;
use kerlico_core::{BoxStream, Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub(crate) const MAX_HEADER: usize = 1024;
async fn header(io: &mut BoxStream) -> Result<String> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() == MAX_HEADER {
            return Err(protocol());
        }
        bytes.push(io.read_u8().await?);
    }
    String::from_utf8(bytes).map_err(|_| protocol())
}
fn fields<'a>(lines: impl Iterator<Item = &'a str>) -> Result<http::HeaderMap> {
    let mut out = http::HeaderMap::new();
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > 32 || line.starts_with([' ', '\t']) {
            return Err(protocol());
        }
        let (name, value) = line.split_once(':').ok_or_else(protocol)?;
        let name = http::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| protocol())?;
        let value = http::HeaderValue::from_str(value.trim()).map_err(|_| protocol())?;
        out.append(name, value);
    }
    Ok(out)
}
pub(crate) fn request_bytes(authority: &str, auth: &str) -> Result<Vec<u8>> {
    let text = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: linux kerlico\r\nProxy-Authorization: {auth}\r\n\r\n"
    );
    if text.len() > MAX_HEADER {
        return Err(Error::ResourceLimit);
    }
    Ok(text.into_bytes())
}
pub(crate) async fn connect(mut io: BoxStream, authority: &str, auth: &str) -> Result<BoxStream> {
    io.write_all(&request_bytes(authority, auth)?).await?;
    io.flush().await?;
    let value = header(&mut io).await?;
    let mut lines = value.split("\r\n");
    let first = lines.next().ok_or_else(protocol)?;
    let mut parts = first.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(protocol());
    }
    let status = parts
        .next()
        .ok_or_else(protocol)?
        .parse::<u16>()
        .map_err(|_| protocol())?;
    let _ = fields(lines)?;
    if status != 200 {
        return Err(Error::Rejected);
    }
    Ok(io)
}
pub(crate) async fn request(io: &mut BoxStream) -> Result<http::Request<()>> {
    let text = header(io).await?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or_else(protocol)?;
    let mut parts = first.split(' ');
    if parts.next() != Some("CONNECT") {
        return Err(protocol());
    }
    let target = parts.next().ok_or_else(protocol)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(protocol());
    }
    let uri = http::Uri::builder()
        .authority(target)
        .build()
        .map_err(|_| protocol())?;
    let mut request = http::Request::builder()
        .method("CONNECT")
        .uri(uri)
        .body(())
        .map_err(|_| protocol())?;
    *request.headers_mut() = fields(lines)?;
    if request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .get("content-length")
            .is_some_and(|v| v != "0")
    {
        return Err(protocol());
    }
    Ok(request)
}
pub(crate) async fn respond(io: &mut BoxStream, status: u16) -> Result<()> {
    let reason = match status {
        200 => "Connection Established",
        400 => "Bad Request",
        407 => "Proxy Authentication Required",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let extra = if status == 407 {
        "Proxy-Authenticate: Basic realm=\"TrustTunnel\"\r\n"
    } else {
        ""
    };
    let length = if status == 200 {
        ""
    } else {
        "Content-Length: 0\r\n"
    };
    io.write_all(
        format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n{extra}{length}\r\n")
            .as_bytes(),
    )
    .await?;
    io.flush().await?;
    if status != 200 {
        io.shutdown().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn exact_header_preserves_early_tunnel_and_rejects_duplicate_auth() {
        let (a, mut b) = tokio::io::duplex(4096);
        b.write_all(b"CONNECT _udp2 HTTP/1.1\r\nProxy-Authorization: Basic YTpi\r\nProxy-Authorization: Basic YTpj\r\n\r\nearly").await.unwrap();
        let mut a: BoxStream = Box::new(a);
        let request = request(&mut a).await.unwrap();
        assert_eq!(request.uri().authority().unwrap().as_str(), "_udp2");
        assert_eq!(
            request
                .headers()
                .get_all("proxy-authorization")
                .iter()
                .count(),
            2
        );
        let mut early = [0; 5];
        a.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
    }
    #[test]
    fn oversized_h1_header_is_rejected_before_send() {
        assert!(request_bytes("_udp2", &"a".repeat(1024)).is_err());
    }
}
