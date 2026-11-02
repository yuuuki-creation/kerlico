//! 认证和 CONNECT 使用的最小 HTTP/1.1 响应读取，只接受 Content-Length 定界的响应体。

use bytes::{Buf, BytesMut};
use kerlico_core::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt};

const MAX_HEAD: usize = 256 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADERS: usize = 1024;

#[derive(Debug)]
pub(crate) struct Response {
    pub status: u16,
    headers: Vec<(String, String)>,
}
impl Response {
    pub fn all<'r>(&'r self, name: &str) -> impl Iterator<Item = &'r str> {
        self.headers
            .iter()
            .filter(move |(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.all(name).next()
    }
    /// 解析响应头；不完整时返回 `None`，完整时消费响应头并保留其后的字节。
    pub fn parse(buffer: &mut BytesMut) -> Result<Option<Self>> {
        let invalid = |_| Error::Protocol("OpenConnect HTTP 响应不合法");
        let mut headers = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut response = httparse::Response::new(&mut headers);
        let httparse::Status::Complete(length) = response.parse(buffer).map_err(invalid)? else {
            return Ok(None);
        };
        let parsed = Self {
            status: response
                .code
                .ok_or(Error::Protocol("OpenConnect HTTP 响应不合法"))?,
            headers: response
                .headers
                .iter()
                .map(|header| {
                    (
                        header.name.to_owned(),
                        String::from_utf8_lossy(header.value).trim().to_owned(),
                    )
                })
                .collect(),
        };
        buffer.advance(length);
        Ok(Some(parsed))
    }
}

pub(crate) async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut BytesMut,
) -> Result<Response> {
    loop {
        if let Some(response) = Response::parse(buffer)? {
            return Ok(response);
        }
        if buffer.len() >= MAX_HEAD {
            return Err(Error::Protocol("OpenConnect HTTP 响应不合法"));
        }
        if stream.read_buf(buffer).await? == 0 {
            return Err(Error::Protocol("OpenConnect 服务端提前关闭连接"));
        }
    }
}

pub(crate) async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut BytesMut,
    response: &Response,
) -> Result<String> {
    let length = response
        .header("Content-Length")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|length| *length <= MAX_BODY)
        .ok_or(Error::Unsupported(
            "OpenConnect 认证响应缺少有效的 Content-Length",
        ))?;
    while buffer.len() < length {
        if stream.read_buf(buffer).await? == 0 {
            return Err(Error::Protocol("OpenConnect 服务端提前关闭连接"));
        }
    }
    String::from_utf8(buffer.split_to(length).to_vec())
        .map_err(|_| Error::Protocol("OpenConnect 认证文档不合法"))
}

/// 认证会话的 Cookie；服务端用空值表示删除。
#[derive(Default)]
pub(crate) struct CookieJar(Vec<(String, String)>);
impl CookieJar {
    pub fn absorb(&mut self, response: &Response) {
        for line in response.all("Set-Cookie") {
            let pair = line.split(';').next().unwrap_or_default();
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            self.0.retain(|(existing, _)| existing != name);
            if !value.is_empty() {
                self.0.push((name.to_owned(), value.trim().to_owned()));
            }
        }
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
    pub fn header(&self) -> Option<String> {
        (!self.0.is_empty()).then(|| {
            self.0
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(text: &str) -> Response {
        let mut buffer = BytesMut::from(text.as_bytes());
        Response::parse(&mut buffer).unwrap().unwrap()
    }

    #[test]
    fn jar_keeps_the_last_cookie_and_drops_deleted_ones() {
        let mut jar = CookieJar::default();
        jar.absorb(&response(
            "HTTP/1.1 200 OK\r\n\
             Set-Cookie: webvpncontext=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly\r\n\r\n",
        ));
        assert_eq!(jar.header(), None);
        jar.absorb(&response(
            "HTTP/1.1 200 OK\r\n\
             Set-Cookie: webvpncontext=AC0iz/x=; Max-Age=300; Secure; HttpOnly\r\n\r\n",
        ));
        assert_eq!(jar.header().unwrap(), "webvpncontext=AC0iz/x=");
        jar.absorb(&response(
            "HTTP/1.1 200 OK\r\n\
             Set-Cookie: webvpn=token; Secure; HttpOnly\r\n\
             Set-Cookie: webvpnc=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/; Secure; HttpOnly\r\n\
             Set-Cookie: webvpnc=bu:/&p:t; path=/; Secure; HttpOnly\r\n\r\n",
        ));
        assert_eq!(jar.get("webvpn"), Some("token"));
        assert_eq!(jar.get("webvpnc"), Some("bu:/&p:t"));
    }

    #[tokio::test]
    async fn head_keeps_following_bytes_and_body_respects_content_length() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::io::AsyncWriteExt::write_all(
            &mut server,
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcSTF",
        )
        .await
        .unwrap();
        let mut buffer = BytesMut::new();
        let head = read_head(&mut client, &mut buffer).await.unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(
            read_body(&mut client, &mut buffer, &head).await.unwrap(),
            "abc"
        );
        assert_eq!(buffer.as_ref(), b"STF");
    }

    #[tokio::test]
    async fn missing_content_length_is_refused_with_a_stable_error() {
        let mut buffer = BytesMut::new();
        let (mut client, _server) = tokio::io::duplex(16);
        let head = response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert!(matches!(
            read_body(&mut client, &mut buffer, &head).await,
            Err(Error::Unsupported(_))
        ));
    }
}
