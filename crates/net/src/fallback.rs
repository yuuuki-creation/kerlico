//! VLESS 与 Trojan 入站共用的回落（Fallback）匹配、首包录制与 PROXY protocol 转发。
use kerlico_config::TargetSpec;
use kerlico_core::{BoxStream, ConnectContext, Destination, Error, InboundContext, Result};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};

fn invalid() -> Error {
    Error::Config("回落（fallback）配置不合法".into())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum FallbackDestInput {
    Port(u16),
    Text(String),
    Target(TargetSpec),
    ServerPort {
        #[serde(alias = "dest", alias = "address")]
        server: String,
        #[serde(alias = "server_port", alias = "server-port")]
        port: Option<u16>,
    },
}

impl FallbackDestInput {
    pub fn into_destination(self) -> Result<Destination> {
        match self {
            Self::Port(port) => Destination::new("127.0.0.1", port).map_err(|_| invalid()),
            Self::Text(text) => parse_dest_text(&text),
            Self::Target(target) => target.destination().map_err(|_| invalid()),
            Self::ServerPort { server, port } => match port {
                Some(port) => Destination::new(server.trim(), port).map_err(|_| invalid()),
                None => parse_dest_text(&server),
            },
        }
    }
}

fn parse_dest_text(text: &str) -> Result<Destination> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(invalid());
    }
    if let Ok(port) = trimmed.parse::<u16>() {
        return Destination::new("127.0.0.1", port).map_err(|_| invalid());
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Destination::new(&addr.ip().to_string(), addr.port()).map_err(|_| invalid());
    }
    let (host, port_str) = trimmed.rsplit_once(':').ok_or_else(invalid)?;
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let port: u16 = port_str.parse().map_err(|_| invalid())?;
    Destination::new(host, port).map_err(|_| invalid())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackRuleInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(alias = "server")]
    pub dest: FallbackDestInput,
    #[serde(default, alias = "server_port", alias = "server-port")]
    pub port: Option<u16>,
    #[serde(default)]
    pub xver: u8,
}

#[derive(Clone, Debug)]
pub struct FallbackRule {
    pub name: Option<String>,
    pub alpn: Option<String>,
    pub path: Option<String>,
    pub dest: Destination,
    pub xver: u8,
}

impl FallbackRuleInput {
    pub fn compile(self) -> Result<FallbackRule> {
        if self.xver > 2 {
            return Err(invalid());
        }
        let name = match self.name {
            Some(n) => {
                let trimmed = n.trim().to_ascii_lowercase();
                if trimmed.is_empty() {
                    return Err(invalid());
                }
                Some(trimmed)
            }
            None => None,
        };
        let alpn = match self.alpn {
            Some(a) => {
                let trimmed = a.trim().to_owned();
                if trimmed.is_empty() {
                    return Err(invalid());
                }
                Some(trimmed)
            }
            None => None,
        };
        let path = match self.path {
            Some(p) => {
                if !p.starts_with('/') || p.len() > 4096 || p.chars().any(char::is_control) {
                    return Err(invalid());
                }
                Some(p)
            }
            None => None,
        };
        let dest = match (self.dest, self.port) {
            (FallbackDestInput::Text(host), Some(port)) => {
                Destination::new(host.trim(), port).map_err(|_| invalid())?
            }
            (dest, None) => dest.into_destination()?,
            _ => return Err(invalid()),
        };
        Ok(FallbackRule {
            name,
            alpn,
            path,
            dest,
            xver: self.xver,
        })
    }
}

pub fn compile_trojan_fallbacks(
    fallback: Option<FallbackDestInput>,
    fallback_port: Option<u16>,
    fallback_for_alpn: BTreeMap<String, FallbackDestInput>,
    fallbacks: Vec<FallbackRuleInput>,
) -> Result<Vec<FallbackRule>> {
    let mut out = Vec::new();
    for item in fallbacks {
        out.push(item.compile()?);
    }
    for (alpn, dest_input) in fallback_for_alpn {
        if alpn.trim().is_empty() {
            return Err(invalid());
        }
        out.push(FallbackRule {
            name: None,
            alpn: Some(alpn.trim().to_owned()),
            path: None,
            dest: dest_input.into_destination()?,
            xver: 0,
        });
    }
    if let Some(dest_input) = fallback {
        let dest = match (dest_input, fallback_port) {
            (FallbackDestInput::Text(host), Some(port)) => {
                Destination::new(host.trim(), port).map_err(|_| invalid())?
            }
            (other, None) => other.into_destination()?,
            _ => return Err(invalid()),
        };
        out.push(FallbackRule {
            name: None,
            alpn: None,
            path: None,
            dest,
            xver: 0,
        });
    } else if fallback_port.is_some() {
        return Err(invalid());
    }
    Ok(out)
}

fn extract_http_path(first_packet: &[u8]) -> Option<&str> {
    let line_end = first_packet
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(first_packet.len().min(512));
    let line = std::str::from_utf8(&first_packet[..line_end]).ok()?;
    let (method, rest) = line.split_once(' ')?;
    if !matches!(
        method,
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "PRI"
    ) {
        return None;
    }
    let path = rest.split_whitespace().next()?;
    path.starts_with('/').then_some(path)
}

fn name_matches(rule_name: &str, sni: &str) -> bool {
    let sni = sni.to_ascii_lowercase();
    if let Some(suffix) = rule_name.strip_prefix('.') {
        sni == suffix || sni.ends_with(rule_name)
    } else {
        sni == rule_name
    }
}

pub fn select_fallback<'a>(
    rules: &'a [FallbackRule],
    sni: Option<&str>,
    alpn: Option<&str>,
    first_packet: &[u8],
) -> Option<&'a FallbackRule> {
    let http_path = extract_http_path(first_packet);
    rules
        .iter()
        .filter(|rule| {
            let alpn_ok = match &rule.alpn {
                Some(expected) => alpn == Some(expected.as_str()),
                None => true,
            };
            let name_ok = match &rule.name {
                Some(expected) => sni.is_some_and(|actual| name_matches(expected, actual)),
                None => true,
            };
            let path_ok = match &rule.path {
                Some(expected) => http_path.is_some_and(|actual| actual.starts_with(expected)),
                None => true,
            };
            alpn_ok && name_ok && path_ok
        })
        .max_by_key(|rule| {
            (
                rule.path.is_some(),
                rule.alpn.is_some(),
                rule.name.is_some(),
            )
        })
}

pub struct RecordingStream<S> {
    inner: S,
    recorded: Vec<u8>,
    limit: usize,
}

impl<S> RecordingStream<S> {
    pub fn new(inner: S, limit: usize) -> Self {
        Self {
            inner,
            recorded: Vec::new(),
            limit,
        }
    }
    pub fn recorded(&self) -> &[u8] {
        &self.recorded
    }
    pub fn into_parts(self) -> (S, Vec<u8>) {
        (self.inner, self.recorded)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) {
            let newly_read = &buf.filled()[before..];
            if !newly_read.is_empty() && this.recorded.len() < this.limit {
                let take = newly_read.len().min(this.limit - this.recorded.len());
                this.recorded.extend_from_slice(&newly_read[..take]);
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub fn encode_proxy_protocol(
    xver: u8,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
) -> Vec<u8> {
    match xver {
        1 => {
            if let (Some(src), Some(dst)) = (peer_addr, local_addr) {
                let src_ip = src.ip().to_canonical();
                let dst_ip = dst.ip().to_canonical();
                match (src_ip, dst_ip) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => {
                        format!("PROXY TCP4 {s} {d} {} {}\r\n", src.port(), dst.port()).into_bytes()
                    }
                    (IpAddr::V6(s), IpAddr::V6(d)) => {
                        format!("PROXY TCP6 {s} {d} {} {}\r\n", src.port(), dst.port()).into_bytes()
                    }
                    _ => b"PROXY UNKNOWN\r\n".to_vec(),
                }
            } else {
                b"PROXY UNKNOWN\r\n".to_vec()
            }
        }
        2 => {
            let mut out = Vec::with_capacity(52);
            out.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n");
            if let (Some(src), Some(dst)) = (peer_addr, local_addr) {
                let src_ip = src.ip().to_canonical();
                let dst_ip = dst.ip().to_canonical();
                match (src_ip, dst_ip) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => {
                        out.push(0x21);
                        out.push(0x11);
                        out.extend_from_slice(&12u16.to_be_bytes());
                        out.extend_from_slice(&s.octets());
                        out.extend_from_slice(&d.octets());
                        out.extend_from_slice(&src.port().to_be_bytes());
                        out.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    (IpAddr::V6(s), IpAddr::V6(d)) => {
                        out.push(0x21);
                        out.push(0x21);
                        out.extend_from_slice(&36u16.to_be_bytes());
                        out.extend_from_slice(&s.octets());
                        out.extend_from_slice(&d.octets());
                        out.extend_from_slice(&src.port().to_be_bytes());
                        out.extend_from_slice(&dst.port().to_be_bytes());
                    }
                    _ => {
                        out.push(0x20);
                        out.push(0x00);
                        out.extend_from_slice(&0u16.to_be_bytes());
                    }
                }
            } else {
                out.push(0x20);
                out.push(0x00);
                out.extend_from_slice(&0u16.to_be_bytes());
            }
            out
        }
        _ => Vec::new(),
    }
}

pub async fn relay_fallback(
    client: BoxStream,
    recorded: &[u8],
    rule: &FallbackRule,
    context: &InboundContext,
) -> Result<()> {
    let connect = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    let mut upstream = connect
        .run(async { Ok(TcpStream::connect((rule.dest.host().as_str(), rule.dest.port())).await?) })
        .await?;
    let _ = upstream.set_nodelay(true);
    let prefix = encode_proxy_protocol(rule.xver, context.peer_addr, context.local_addr);
    connect
        .run(async {
            if !prefix.is_empty() {
                upstream.write_all(&prefix).await?;
            }
            if !recorded.is_empty() {
                upstream.write_all(recorded).await?;
            }
            upstream.flush().await?;
            Ok(())
        })
        .await?;
    kerlico_core::relay_streams(
        client,
        Box::new(upstream),
        context.idle_timeout,
        context.cancel.clone(),
    )
    .await
}

pub async fn try_fallback(
    mut client: BoxStream,
    mut recorded: Vec<u8>,
    rules: &[FallbackRule],
    sni: Option<&str>,
    alpn: Option<&str>,
    context: &InboundContext,
) -> Option<Result<()>> {
    if rules.is_empty() {
        return None;
    }
    if rules.iter().any(|r| r.path.is_some())
        && !recorded.windows(2).any(|w| w == b"\r\n")
        && recorded.len() < 1024
    {
        let mut extra = [0u8; 1024];
        if let Ok(Ok(n)) = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            client.read(&mut extra),
        )
        .await
            && n > 0
        {
            recorded.extend_from_slice(&extra[..n]);
        }
    }
    let rule = select_fallback(rules, sni, alpn, &recorded)?;
    Some(relay_fallback(client, &recorded, rule, context).await)
}

/// 剥离前导头部后保留残余预读字节的异步流包装器。
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            this.offset += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 解析入站连接的 PROXY protocol v1 或 v2 头部，返回剥离头部后的流及解析出的 `(peer_addr, local_addr)`。
pub async fn accept_proxy_protocol<S>(
    mut stream: S,
) -> Result<(PrefixedStream<S>, Option<SocketAddr>, Option<SocketAddr>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    const V2_SIG: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
    let mut buf = Vec::with_capacity(128);
    let mut scratch = [0u8; 128];
    while buf.len() < 6 {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Err(Error::Protocol("PROXY protocol 头部未完整到达"));
        }
        buf.extend_from_slice(&scratch[..n]);
    }
    if buf.starts_with(b"PROXY ") {
        loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                let header_end = pos + 2;
                if header_end > 107 {
                    return Err(Error::Protocol("PROXY protocol v1 头部超长"));
                }
                let line = std::str::from_utf8(&buf[..pos])
                    .map_err(|_| Error::Protocol("PROXY protocol v1 编码不合法"))?;
                let parts: Vec<&str> = line.split(' ').collect();
                let (peer, local) = match parts.as_slice() {
                    ["PROXY", "UNKNOWN", ..] => (None, None),
                    [
                        "PROXY",
                        proto @ ("TCP4" | "TCP6"),
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    ] => {
                        let s_ip: IpAddr = src_ip
                            .parse()
                            .map_err(|_| Error::Protocol("PROXY protocol v1 源地址不合法"))?;
                        let d_ip: IpAddr = dst_ip
                            .parse()
                            .map_err(|_| Error::Protocol("PROXY protocol v1 目标地址不合法"))?;
                        if (*proto == "TCP4" && (!s_ip.is_ipv4() || !d_ip.is_ipv4()))
                            || (*proto == "TCP6" && (!s_ip.is_ipv6() || !d_ip.is_ipv6()))
                        {
                            return Err(Error::Protocol("PROXY protocol v1 地址族不匹配"));
                        }
                        let s_port: u16 = src_port
                            .parse()
                            .map_err(|_| Error::Protocol("PROXY protocol v1 源端口不合法"))?;
                        let d_port: u16 = dst_port
                            .parse()
                            .map_err(|_| Error::Protocol("PROXY protocol v1 目标端口不合法"))?;
                        (
                            Some(SocketAddr::new(s_ip, s_port)),
                            Some(SocketAddr::new(d_ip, d_port)),
                        )
                    }
                    _ => return Err(Error::Protocol("PROXY protocol v1 格式不合法")),
                };
                let rest = buf.split_off(header_end);
                return Ok((PrefixedStream::new(rest, stream), peer, local));
            }
            if buf.len() >= 107 {
                return Err(Error::Protocol("PROXY protocol v1 缺少行尾"));
            }
            let n = stream.read(&mut scratch).await?;
            if n == 0 {
                return Err(Error::Protocol("PROXY protocol v1 连接提前关闭"));
            }
            buf.extend_from_slice(&scratch[..n]);
        }
    }
    while buf.len() < 16 {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Err(Error::Protocol("PROXY protocol v2 头部未完整到达"));
        }
        buf.extend_from_slice(&scratch[..n]);
    }
    if &buf[..12] != V2_SIG {
        return Err(Error::Protocol("未识别的 PROXY protocol 头部签名"));
    }
    let ver_cmd = buf[12];
    if (ver_cmd & 0xf0) != 0x20 {
        return Err(Error::Protocol("PROXY protocol v2 版本不合法"));
    }
    let fam_proto = buf[13];
    let addr_len = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
    if addr_len > 512 {
        return Err(Error::Protocol("PROXY protocol v2 地址块超长"));
    }
    let total_len = 16 + addr_len;
    while buf.len() < total_len {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            return Err(Error::Protocol("PROXY protocol v2 地址块未完整到达"));
        }
        buf.extend_from_slice(&scratch[..n]);
    }
    let addr_bytes = &buf[16..total_len];
    let (peer, local) = match ver_cmd & 0x0f {
        0x00 => (None, None),
        0x01 => match fam_proto & 0xf0 {
            0x10 => {
                if addr_bytes.len() < 12 {
                    return Err(Error::Protocol("PROXY protocol v2 IPv4 地址长度不足"));
                }
                let s_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                ));
                let d_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    addr_bytes[4],
                    addr_bytes[5],
                    addr_bytes[6],
                    addr_bytes[7],
                ));
                let s_port = u16::from_be_bytes([addr_bytes[8], addr_bytes[9]]);
                let d_port = u16::from_be_bytes([addr_bytes[10], addr_bytes[11]]);
                (
                    Some(SocketAddr::new(s_ip, s_port)),
                    Some(SocketAddr::new(d_ip, d_port)),
                )
            }
            0x20 => {
                if addr_bytes.len() < 36 {
                    return Err(Error::Protocol("PROXY protocol v2 IPv6 地址长度不足"));
                }
                let mut s_oct = [0u8; 16];
                let mut d_oct = [0u8; 16];
                s_oct.copy_from_slice(&addr_bytes[0..16]);
                d_oct.copy_from_slice(&addr_bytes[16..32]);
                let s_ip = IpAddr::V6(std::net::Ipv6Addr::from(s_oct));
                let d_ip = IpAddr::V6(std::net::Ipv6Addr::from(d_oct));
                let s_port = u16::from_be_bytes([addr_bytes[32], addr_bytes[33]]);
                let d_port = u16::from_be_bytes([addr_bytes[34], addr_bytes[35]]);
                (
                    Some(SocketAddr::new(s_ip, s_port)),
                    Some(SocketAddr::new(d_ip, d_port)),
                )
            }
            _ => (None, None),
        },
        _ => return Err(Error::Protocol("PROXY protocol v2 命令不合法")),
    };
    let rest = buf.split_off(total_len);
    Ok((PrefixedStream::new(rest, stream), peer, local))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fallback_selection_respects_specificity_and_http_path() {
        let rules: Vec<FallbackRule> = vec![
            serde_json::from_value::<FallbackRuleInput>(json!({"dest": 8080}))
                .unwrap()
                .compile()
                .unwrap(),
            serde_json::from_value::<FallbackRuleInput>(
                json!({"alpn": "h2", "dest": "127.0.0.1:8081"}),
            )
            .unwrap()
            .compile()
            .unwrap(),
            serde_json::from_value::<FallbackRuleInput>(
                json!({"path": "/ws", "dest": 8082, "xver": 1}),
            )
            .unwrap()
            .compile()
            .unwrap(),
        ];
        let matched_ws = select_fallback(
            &rules,
            Some("example.com"),
            Some("http/1.1"),
            b"GET /ws/chat HTTP/1.1\r\n",
        )
        .unwrap();
        assert_eq!(matched_ws.dest.port(), 8082);
        assert_eq!(matched_ws.xver, 1);

        let matched_h2 =
            select_fallback(&rules, Some("example.com"), Some("h2"), b"\x00\x00\x12").unwrap();
        assert_eq!(matched_h2.dest.port(), 8081);

        let matched_default = select_fallback(
            &rules,
            Some("example.com"),
            Some("http/1.1"),
            b"GET /index.html HTTP/1.1\r\n",
        )
        .unwrap();
        assert_eq!(matched_default.dest.port(), 8080);
    }

    #[tokio::test]
    async fn proxy_protocol_v1_and_v2_roundtrip_and_preserve_payload() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for xver in [1u8, 2u8] {
            for (src, dst) in [
                (
                    "198.51.100.7:54321".parse::<SocketAddr>().unwrap(),
                    "203.0.113.9:443".parse::<SocketAddr>().unwrap(),
                ),
                (
                    "[2001:db8::7]:54321".parse::<SocketAddr>().unwrap(),
                    "[2001:db8::9]:443".parse::<SocketAddr>().unwrap(),
                ),
            ] {
                let (mut client, server) = tokio::io::duplex(256);
                let mut frame = encode_proxy_protocol(xver, Some(src), Some(dst));
                frame.extend_from_slice(b"hello-world");
                client.write_all(&frame).await.unwrap();
                drop(client);
                let (mut stripped, parsed_src, parsed_dst) =
                    accept_proxy_protocol(server).await.unwrap();
                assert_eq!(parsed_src, Some(src));
                assert_eq!(parsed_dst, Some(dst));
                let mut body = Vec::new();
                stripped.read_to_end(&mut body).await.unwrap();
                assert_eq!(body, b"hello-world");
            }
        }
    }
}
