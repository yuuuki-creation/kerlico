use std::io;

use http::{HeaderMap, Method, Request, Response, StatusCode};

pub const HOST: &str = "hysteria";
pub const PATH: &str = "/auth";
pub const STATUS: u16 = 233;
pub const AUTH: &str = "hysteria-auth";
pub const UDP: &str = "hysteria-udp";
pub const RATE: &str = "hysteria-cc-rx";
pub const PADDING: &str = "hysteria-padding";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveRate {
    Auto,
    BytesPerSecond(u64),
}

pub fn credentials(request: &Request<()>) -> Option<(&[u8], u64)> {
    if request.method() != Method::POST
        || request.uri().path() != PATH
        || request
            .uri()
            .authority()
            .is_none_or(|host| host.as_str() != HOST)
    {
        return None;
    }
    let headers = request.headers();
    let rate = match receive_rate(headers.get(RATE).and_then(|value| value.to_str().ok())) {
        ReceiveRate::Auto => 0,
        ReceiveRate::BytesPerSecond(rate) => rate,
    };
    Some((
        headers.get(AUTH).map_or(b"", |header| header.as_bytes()),
        rate,
    ))
}

pub fn padding() -> io::Result<String> {
    super::padding(256, 2048)
}

pub fn response(udp: bool, receive: ReceiveRate) -> http::response::Builder {
    let rate = match receive {
        ReceiveRate::Auto => "auto".to_owned(),
        ReceiveRate::BytesPerSecond(rate) => rate.to_string(),
    };
    Response::builder()
        .status(STATUS)
        .header(UDP, if udp { "true" } else { "false" })
        .header(RATE, rate)
}

pub fn parse_response(status: StatusCode, headers: &HeaderMap) -> io::Result<(bool, ReceiveRate)> {
    if status.as_u16() != STATUS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hysteria authentication failed",
        ));
    }
    let udp = headers.get(UDP).is_some_and(|header| {
        matches!(
            header.as_bytes(),
            b"true" | b"TRUE" | b"True" | b"1" | b"t" | b"T"
        )
    });
    Ok((
        udp,
        receive_rate(headers.get(RATE).and_then(|value| value.to_str().ok())),
    ))
}

fn receive_rate(value: Option<&str>) -> ReceiveRate {
    match value {
        Some("auto") => ReceiveRate::Auto,
        value => {
            ReceiveRate::BytesPerSecond(value.and_then(|value| value.parse().ok()).unwrap_or(0))
        }
    }
}
