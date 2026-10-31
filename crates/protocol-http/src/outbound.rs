use crate::config::{self, Auth, ClientTls};
use kerlico_config::{OutboundFactory, TargetSpec};
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
};
use kerlico_net::TcpConnector;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    server: TargetSpec,
    auth: Option<Auth>,
    tls: Option<ClientTls>,
}
struct HttpOutbound {
    server: Destination,
    connector: TcpConnector,
    auth: Option<Auth>,
}
impl Outbound for HttpOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let mut stream = self.connector.connect(&self.server).await?;
                    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
                    if let Some(auth) = &self.auth {
                        request.push_str("Proxy-Authorization: ");
                        request.push_str(&auth.header());
                        request.push_str("\r\n");
                    }
                    request.push_str("\r\n");
                    stream.write_all(request.as_bytes()).await?;
                    for _ in 0..16 {
                        let mut header = Vec::new();
                        // 精确读取到头末尾，不能吞掉同一 TCP 包内的首段隧道数据。
                        while !header.ends_with(b"\r\n\r\n") {
                            if header.len() == 16_384 {
                                return Err(config::invalid());
                            }
                            header.push(stream.read_u8().await?);
                        }
                        let header = std::str::from_utf8(&header).map_err(|_| config::invalid())?;
                        let mut lines = header.split("\r\n");
                        let status = lines.next().ok_or_else(config::invalid)?;
                        let mut parts = status.splitn(3, ' ');
                        if !matches!(parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                            return Err(config::invalid());
                        }
                        let code = parts
                            .next()
                            .filter(|value| {
                                value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_digit())
                            })
                            .ok_or_else(config::invalid)?
                            .parse::<u16>()
                            .map_err(|_| config::invalid())?;
                        for line in lines.filter(|line| !line.is_empty()) {
                            let Some((name, value)) = line.split_once(':') else {
                                return Err(config::invalid());
                            };
                            if http::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                                || http::HeaderValue::from_str(value.trim()).is_err()
                            {
                                return Err(config::invalid());
                            }
                        }
                        if (200..300).contains(&code) {
                            return Ok(stream);
                        }
                        if !(100..200).contains(&code) || code == 101 {
                            return Err(Error::Rejected);
                        }
                    }
                    Err(config::invalid())
                })
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("HTTP CONNECT 不提供 UDP")) })
    }
}
pub struct HttpFactory;
impl OutboundFactory for HttpFactory {
    fn kind(&self) -> &'static str {
        "http"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("HTTP 出站字段不合法".into()))?;
        if let Some(auth) = &options.auth {
            auth.validate()?;
        }
        let connector = if let Some(tls) = options.tls {
            TcpConnector::tls(&tls.server_name, tls.ca_pem.as_deref())?
        } else {
            TcpConnector::plain()
        };
        Ok(Arc::new(HttpOutbound {
            server: options.server.destination()?,
            connector,
            auth: options.auth,
        }))
    }
}
