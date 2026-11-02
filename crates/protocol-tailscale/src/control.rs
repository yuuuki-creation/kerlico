//! TS2021 控制面：取服务端公钥、升级 Noise、注册、流式 netmap 与端点上报。

use crate::{
    config::{ControlEndpoint, Prepared},
    keys::{DiscoKey, Identity, MachineKey, NodeKey},
    netmap::{MapFrames, MapResponse, NetMap},
    noise::Handshake,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use h2::{RecvStream, client::SendRequest};
use kerlico_core::{BoxStream, Error, Result, ServiceContext, ServiceFailure};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::watch,
    time::{Instant, timeout},
};

/// 与所读上游 1.92 系列的 `CurrentCapabilityVersion` 对齐。
pub const CAPABILITY_VERSION: u16 = 131;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAP_WATCHDOG: Duration = Duration::from_secs(120);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADER: usize = 64 * 1024;
const EARLY_MAGIC: &[u8; 5] = b"\xff\xff\xffTS";
const ENDPOINT_LOCAL: u8 = 1;
const ENDPOINT_STUN: u8 = 2;

/// 数据面发现的本机状态，变化时通过非流式 map 请求上报。
#[derive(Clone, Default)]
pub struct LocalState {
    pub home_derp: i32,
    pub stun: Vec<SocketAddr>,
    pub local: Vec<SocketAddr>,
}
impl LocalState {
    pub fn endpoints(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.stun.iter().chain(&self.local).copied()
    }
    fn typed(&self) -> (Vec<SocketAddr>, Vec<u8>) {
        let stun = self.stun.iter().map(|address| (*address, ENDPOINT_STUN));
        let local = self.local.iter().map(|address| (*address, ENDPOINT_LOCAL));
        stun.chain(local).unzip()
    }
}

/// 网络中断可重试；服务端不认识节点时重新注册；鉴权与协议拒绝不可重试。
enum Failure {
    Retry,
    Reregister,
    Fatal(&'static str),
}
impl From<Error> for Failure {
    fn from(_: Error) -> Self {
        Self::Retry
    }
}
impl From<std::io::Error> for Failure {
    fn from(_: std::io::Error) -> Self {
        Self::Retry
    }
}
impl From<h2::Error> for Failure {
    fn from(_: h2::Error) -> Self {
        Self::Retry
    }
}

pub struct Control {
    pub prepared: Prepared,
    pub identity: Identity,
    pub disco: DiscoKey,
    pub netmap: watch::Sender<Option<Arc<NetMap>>>,
    pub local: watch::Receiver<LocalState>,
    pub host: ServiceContext,
}
impl Control {
    pub async fn run(mut self) {
        let cancel = self.host.cancel();
        let mut registered = false;
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            let Err(failure) = tokio::select! { biased;
                _ = cancel.cancelled() => return,
                result = self.session(&mut registered) => result,
            };
            match failure {
                Failure::Fatal(message) => {
                    self.host.fail(ServiceFailure::Protocol(message));
                    return;
                }
                Failure::Reregister => registered = false,
                Failure::Retry => {}
            }
            if started.elapsed() >= HEALTHY_SESSION {
                backoff = Duration::from_secs(1);
            }
            tokio::select! { biased;
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn session(
        &mut self,
        registered: &mut bool,
    ) -> std::result::Result<std::convert::Infallible, Failure> {
        let endpoint = &self.prepared.control;
        let control_key = timeout(CONNECT_TIMEOUT, fetch_control_key(endpoint))
            .await
            .map_err(|_| Failure::Retry)??;
        let send = timeout(
            CONNECT_TIMEOUT,
            upgrade(endpoint, &self.identity, &control_key, &self.host),
        )
        .await
        .map_err(|_| Failure::Retry)??;
        if !*registered {
            self.register(&send).await?;
            *registered = true;
        }
        let mut stream = self.map_request(&send, true).await?;
        let mut frames = MapFrames::default();
        let mut netmap = NetMap::default();
        loop {
            tokio::select! {
                chunk = timeout(MAP_WATCHDOG, stream.data()) => {
                    let chunk = chunk.map_err(|_| Failure::Retry)?.ok_or(Failure::Retry)??;
                    stream
                        .flow_control()
                        .release_capacity(chunk.len())
                        .map_err(|_| Failure::Retry)?;
                    self.host.record_carrier(0, chunk.len() as u64);
                    frames.push(&chunk);
                    let mut changed = false;
                    while let Some(frame) = frames.next_frame().map_err(|_| {
                        Failure::Fatal("Tailscale netmap消息过大")
                    })? {
                        let response: MapResponse = serde_json::from_slice(&frame)
                            .map_err(|_| Failure::Fatal("Tailscale netmap消息不合法"))?;
                        changed |= netmap.apply(response);
                    }
                    if changed && netmap.own.is_some() {
                        self.netmap.send_replace(Some(Arc::new(netmap.clone())));
                    }
                }
                result = self.local.changed() => {
                    result.map_err(|_| Failure::Retry)?;
                    let reply = timeout(CONNECT_TIMEOUT, self.map_request(&send, false))
                        .await
                        .map_err(|_| Failure::Retry)??;
                    drop(reply);
                }
            }
        }
    }

    fn hostinfo(&self, local: &LocalState) -> Value {
        json!({
            "IPNVersion": concat!("kerlico-", env!("CARGO_PKG_VERSION")),
            "OS": std::env::consts::OS,
            "Hostname": self.prepared.hostname,
            "Userspace": true,
            "NetInfo": {"PreferredDERP": local.home_derp},
        })
    }

    async fn register(&self, send: &SendRequest<Bytes>) -> std::result::Result<(), Failure> {
        let local = self.local.borrow().clone();
        let body = json!({
            "Version": CAPABILITY_VERSION,
            "NodeKey": NodeKey(self.identity.node.public()),
            "Auth": {"AuthKey": self.prepared.auth_key.as_str()},
            "Hostinfo": self.hostinfo(&local),
            "Ephemeral": self.prepared.ephemeral,
        });
        let (status, stream) = post(
            send,
            &self.prepared.control.authority,
            "/machine/register",
            &body,
        )
        .await?;
        let body = read_body(stream).await?;
        if matches!(status.as_u16(), 400..=499) {
            return Err(Failure::Fatal("Tailscale控制面拒绝注册"));
        }
        if !status.is_success() {
            return Err(Failure::Retry);
        }
        let reply: Value =
            serde_json::from_slice(&body).map_err(|_| Failure::Fatal("Tailscale注册响应不合法"))?;
        if reply["Error"].as_str().is_some_and(|text| !text.is_empty())
            || reply["NodeKeyExpired"].as_bool() == Some(true)
        {
            return Err(Failure::Fatal("Tailscale控制面拒绝注册"));
        }
        if reply["MachineAuthorized"].as_bool() != Some(true) {
            return Err(Failure::Fatal(
                "Tailscale节点未获授权，auth_key需要人工批准",
            ));
        }
        Ok(())
    }

    async fn map_request(
        &self,
        send: &SendRequest<Bytes>,
        streaming: bool,
    ) -> std::result::Result<RecvStream, Failure> {
        let local = self.local.borrow().clone();
        let (endpoints, kinds) = local.typed();
        let body = json!({
            "Version": CAPABILITY_VERSION,
            "KeepAlive": streaming,
            "NodeKey": NodeKey(self.identity.node.public()),
            "DiscoKey": self.disco,
            "Stream": streaming,
            "OmitPeers": !streaming,
            "Hostinfo": self.hostinfo(&local),
            "Endpoints": endpoints,
            "EndpointTypes": kinds,
        });
        let (status, stream) = post(
            send,
            &self.prepared.control.authority,
            "/machine/map",
            &body,
        )
        .await?;
        if status.is_client_error() {
            return Err(Failure::Reregister);
        }
        if !status.is_success() {
            return Err(Failure::Retry);
        }
        Ok(stream)
    }
}

async fn post(
    send: &SendRequest<Bytes>,
    authority: &str,
    path: &str,
    body: &Value,
) -> std::result::Result<(http::StatusCode, RecvStream), Failure> {
    let request = http::Request::post(format!("https://{authority}{path}"))
        .header("content-type", "application/json")
        .body(())
        .map_err(|_| Failure::Retry)?;
    let mut ready = send.clone().ready().await?;
    let (response, mut outgoing) = ready.send_request(request, false)?;
    outgoing.send_data(Bytes::from(body.to_string()), true)?;
    let response = response.await?;
    let status = response.status();
    Ok((status, response.into_body()))
}

async fn read_body(mut stream: RecvStream) -> std::result::Result<Vec<u8>, Failure> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk?;
        stream
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|_| Failure::Retry)?;
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BODY {
            return Err(Failure::Fatal("Tailscale控制响应过大"));
        }
    }
    Ok(body)
}

type Reader = BufReader<BoxStream>;

async fn read_status(reader: &mut Reader) -> Result<(u16, Vec<(String, String)>)> {
    let invalid = || Error::Protocol("Tailscale HTTP响应不合法");
    let mut line = String::new();
    let mut total = read_limited_line(reader, &mut line).await?;
    let status = line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(invalid)?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        total += read_limited_line(reader, &mut line).await?;
        if total > MAX_HEADER {
            return Err(invalid());
        }
        let text = line.trim_end();
        if text.is_empty() {
            return Ok((status, headers));
        }
        let (name, value) = text.split_once(':').ok_or_else(invalid)?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
}
async fn read_limited_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut String,
) -> Result<usize> {
    let mut limited = reader.take(MAX_HEADER as u64);
    let count = limited.read_line(line).await?;
    if count == 0 || !line.ends_with('\n') {
        return Err(Error::Protocol("Tailscale HTTP响应不合法"));
    }
    Ok(count)
}

/// `/key` 响应未经 Noise 认证，HTTPS 时由 TLS 认证，HTTP 时依赖网络路径。
async fn fetch_control_key(endpoint: &ControlEndpoint) -> Result<MachineKey> {
    let mut stream = endpoint.connector.connect(&endpoint.destination).await?;
    let request = format!(
        "GET /key?v={CAPABILITY_VERSION} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        endpoint.authority
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream);
    let (status, headers) = read_status(&mut reader).await?;
    if status != 200 {
        return Err(Error::Protocol("Tailscale控制面公钥请求失败"));
    }
    let mut body = Vec::new();
    (&mut reader)
        .take(MAX_HEADER as u64)
        .read_to_end(&mut body)
        .await?;
    let chunked = headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
    let body = if chunked { dechunk(&body) } else { Some(body) };
    let reply: Value = body
        .and_then(|body| serde_json::from_slice(&body).ok())
        .ok_or(Error::Protocol("Tailscale控制面公钥不合法"))?;
    reply["publicKey"]
        .as_str()
        .and_then(MachineKey::parse)
        .filter(|key| !key.is_zero())
        .ok_or(Error::Protocol("Tailscale控制面公钥不合法"))
}
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let end = body.windows(2).position(|pair| pair == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&body[..end]).ok()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(output);
        }
        output.extend_from_slice(body.get(end + 2..end + 2 + size)?);
        body = body.get(end + 2 + size + 2..)?;
    }
}

async fn upgrade(
    endpoint: &ControlEndpoint,
    identity: &Identity,
    control_key: &MachineKey,
    host: &ServiceContext,
) -> std::result::Result<SendRequest<Bytes>, Failure> {
    let (initiation, handshake) =
        Handshake::start(&identity.machine, control_key, CAPABILITY_VERSION)?;
    let mut stream = endpoint.connector.connect(&endpoint.destination).await?;
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\nHost: {}\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\nX-Tailscale-Handshake: {}\r\nContent-Length: 0\r\n\r\n",
        endpoint.authority,
        STANDARD.encode(&initiation),
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream);
    let (status, _) = read_status(&mut reader).await?;
    if status != 101 {
        return Err(Failure::Retry);
    }
    let mut noise = handshake.finish(reader).await?;
    // 服务端在 HTTP/2 之前可选发送 EarlyNoise，只有 h2 SETTINGS 跟在其后，因此可以先读。
    let mut magic = [0; 5];
    noise.read_exact(&mut magic).await?;
    if &magic == EARLY_MAGIC {
        let mut length = [0; 4];
        noise.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_BODY {
            return Err(Failure::Fatal("Tailscale控制响应过大"));
        }
        let mut skipped = vec![0; length];
        noise.read_exact(&mut skipped).await?;
    } else {
        noise.unread(&magic);
    }
    let (send, connection) = h2::client::handshake(noise).await?;
    let cancel = host.cancel();
    host.spawn(async move {
        tokio::select! { biased;
            _ = cancel.cancelled() => {}
            _ = connection => {}
        }
    })
    .map_err(|_| Failure::Retry)?;
    Ok(send)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_body_decodes() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").as_deref(),
            Some(&b"abcde"[..])
        );
        assert_eq!(dechunk(b"9\r\nabc"), None);
    }

    #[test]
    fn endpoints_keep_their_type_order() {
        let state = LocalState {
            home_derp: 1,
            stun: vec!["192.0.2.1:1".parse().unwrap()],
            local: vec!["10.0.0.1:1".parse().unwrap()],
        };
        let (endpoints, kinds) = state.typed();
        assert_eq!(endpoints.len(), 2);
        assert_eq!(kinds, vec![ENDPOINT_STUN, ENDPOINT_LOCAL]);
    }
}
