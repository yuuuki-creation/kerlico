//! 一次完整建立：XML 认证取得 `webvpn` Cookie，再用新 TLS 连接发起 CSTP CONNECT。

use crate::{
    auth::{self, Answered, AuthDocument},
    config::Config,
    http::{self, CookieJar},
    tunnel::{self, TunnelParams},
};
use bytes::BytesMut;
use kerlico_core::{BoxStream, CancellationToken, Error, Result, ServiceContext};
use kerlico_wireguard::ip::{ClientTunnel, StackLimits, StackOptions};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const USER_AGENT: &str = "Open AnyConnect VPN Agent v9.12";
const MAX_AUTH_ROUNDS: usize = 8;
/// 没有活动流时释放隧道，避免离线用户继续占用服务端地址和 `max-same-clients` 名额。
const SESSION_IDLE: Duration = Duration::from_secs(300);

pub(crate) struct Session {
    pub tunnel: ClientTunnel,
    cancel: CancellationToken,
}
impl Session {
    pub fn is_closed(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

fn status_error(status: u16) -> Error {
    match status {
        401 | 403 => Error::Rejected,
        _ => Error::Protocol("OpenConnect 服务端返回了非成功 HTTP 状态"),
    }
}

async fn post(
    stream: &mut BoxStream,
    buffer: &mut BytesMut,
    config: &Config,
    jar: &mut CookieJar,
    path: &str,
    body: &str,
) -> Result<String> {
    let cookie = jar
        .header()
        .map(|cookie| format!("Cookie: {cookie}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n\
         Accept-Encoding: identity\r\nX-Transcend-Version: 1\r\nX-Aggregate-Auth: 1\r\n\
         X-Support-HTTP-Auth: true\r\n{cookie}Content-Type: application/xml; charset=utf-8\r\n\
         Content-Length: {}\r\n\r\n{body}",
        config.server,
        body.len(),
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let response = http::read_head(stream, buffer).await?;
    if response.status != 200 {
        return Err(status_error(response.status));
    }
    jar.absorb(&response);
    http::read_body(stream, buffer, &response).await
}

async fn login(config: &Config) -> Result<String> {
    let mut stream = config.connector.connect(&config.server).await?;
    let mut buffer = BytesMut::new();
    let mut jar = CookieJar::default();
    let mut answered = Answered::default();
    let mut path = "/".to_owned();
    let mut body = auth::init_request(&format!("https://{}/", config.server));
    for _ in 0..MAX_AUTH_ROUNDS {
        let document = post(&mut stream, &mut buffer, config, &mut jar, &path, &body).await?;
        match auth::parse(&document)? {
            AuthDocument::Complete => {
                return jar
                    .get("webvpn")
                    .map(str::to_owned)
                    .ok_or(Error::Protocol("OpenConnect 认证完成但未返回会话 Cookie"));
            }
            AuthDocument::Form(form) => {
                body = form.reply(&config.credentials, &mut answered)?;
                path = form.action;
            }
        }
    }
    Err(Error::Protocol("OpenConnect 认证交互超过轮数上限"))
}

async fn open_tunnel(config: &Config, cookie: &str) -> Result<(BoxStream, BytesMut, TunnelParams)> {
    let mut stream = config.connector.connect(&config.server).await?;
    let request = format!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\n\
         Cookie: webvpn={cookie}\r\nX-CSTP-Version: 1\r\nX-CSTP-Hostname: kerlico\r\n\
         X-CSTP-Base-MTU: {mtu}\r\nX-CSTP-MTU: {mtu}\r\nX-CSTP-Address-Type: IPv6,IPv4\r\n\
         X-CSTP-Full-IPv6-Capability: true\r\n\r\n",
        config.server,
        mtu = config.mtu,
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut buffer = BytesMut::new();
    let response = http::read_head(&mut stream, &mut buffer).await?;
    if response.status != 200 {
        return Err(status_error(response.status));
    }
    Ok((stream, buffer, TunnelParams::parse(&response)?))
}

pub(crate) async fn establish(
    config: &Config,
    host: &ServiceContext,
    parent: &CancellationToken,
) -> Result<Session> {
    let cookie = login(config).await?;
    let (stream, received, params) = open_tunnel(config, &cookie).await?;
    let cancel = parent.child_token();
    let tunnel = ClientTunnel::new(
        StackOptions {
            addresses: params.addresses(),
            allowed_ips: params.allowed_ips(),
            mtu: params.mtu,
            limits: StackLimits::default(),
        },
        cancel.clone(),
    )?;
    host.spawn(tunnel::run(
        stream,
        received,
        params,
        SESSION_IDLE,
        tunnel.clone(),
        host.clone(),
        cancel.clone(),
    ))?;
    Ok(Session { tunnel, cancel })
}
