//! RFC 8484 DoH 上游：HTTP/2 与 HTTP/1.1 由 ALPN 协商。hickory 自带的 DoH 只有 HTTP/2，
//! 这里接入它的连接池，缓存、并发和多上游切换继续由 hickory 负责。
use crate::{HttpsServerSpec, invalid, normalize};
use futures_util::stream;
use hickory_resolver::{
    ConnectionProvider, PoolContext, Resolver,
    config::ConnectionConfig,
    net::{
        DnsHandle, NetError,
        runtime::TokioRuntimeProvider,
        xfer::{DnsExchange, DnsResponse},
    },
    proto::op::{DnsRequest, DnsResponse as ProtoResponse},
};
use kerlico_core::Result;
use reqwest::{
    Certificate, Client, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_MESSAGE: usize = 65_535;
const DEFAULT_PATH: &str = "/dns-query";
/// 这些头由 DoH 协议或 HTTP 层决定，配置不能覆盖。
const RESERVED_HEADERS: [&str; 8] = [
    "accept",
    "connection",
    "content-length",
    "content-type",
    "host",
    "te",
    "transfer-encoding",
    "upgrade",
];

/// 连接目标：字面 IP 直接拨号，域名由 [`Bootstrap`] 解析。
pub(crate) enum Dial {
    Ip(IpAddr),
    Domain(String),
}

pub(crate) struct HttpsUpstream {
    dial: Dial,
    url: Url,
    headers: HeaderMap,
    ca: Option<Vec<Certificate>>,
}

/// `url` 的主机即证书校验名与 `Host`。
fn request_url(name: &str, port: u16, path: &str) -> Result<Url> {
    let host = if name.contains(':') {
        format!("[{name}]")
    } else {
        name.to_owned()
    };
    let path = if path.is_empty() || path == "/" {
        DEFAULT_PATH
    } else {
        path
    };
    if !path.starts_with('/') || path.contains(['?', '#']) || port == 0 {
        return Err(invalid());
    }
    Url::parse(&format!("https://{host}:{port}{path}")).map_err(|_| invalid())
}

fn dial(host: &str) -> Result<Dial> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse() {
        Ok(ip) => Ok(Dial::Ip(ip)),
        Err(_) => Ok(Dial::Domain(normalize(host)?)),
    }
}

impl HttpsUpstream {
    /// `https://主机[:端口][/路径][#证书名]`；`#证书名` 只在主机是字面 IP 时有意义，
    /// 与 `tls://` 的写法一致。
    pub(crate) fn from_url(text: &str) -> Result<Self> {
        let url = Url::parse(text).map_err(|_| invalid())?;
        let host = url.host_str().ok_or_else(invalid)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
        {
            return Err(invalid());
        }
        let dial = dial(host)?;
        let fragment = url.fragment().filter(|name| !name.is_empty());
        if text.contains('#') && (fragment.is_none() || !matches!(dial, Dial::Ip(_))) {
            return Err(invalid());
        }
        let name = fragment.unwrap_or(host).trim_matches(['[', ']']);
        Ok(Self {
            dial,
            url: request_url(name, url.port().unwrap_or(443), url.path())?,
            headers: HeaderMap::new(),
            ca: None,
        })
    }

    pub(crate) fn from_spec(spec: &HttpsServerSpec) -> Result<Self> {
        let _ = spec.kind;
        let dial = dial(&spec.server)?;
        let tls = spec.tls.as_ref();
        let name = tls
            .and_then(|tls| tls.server_name.as_deref())
            .unwrap_or(&spec.server)
            .trim_matches(['[', ']']);
        let ca = tls
            .and_then(|tls| tls.ca_pem.as_deref())
            .map(|pem| {
                let certificates =
                    Certificate::from_pem_bundle(pem.as_bytes()).map_err(|_| invalid())?;
                if certificates.is_empty() {
                    return Err(invalid());
                }
                Ok(certificates)
            })
            .transpose()?;
        let mut headers = HeaderMap::new();
        for (name, value) in &spec.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
            if RESERVED_HEADERS.contains(&name.as_str()) {
                return Err(invalid());
            }
            headers.insert(
                name,
                HeaderValue::from_str(value).map_err(|_| invalid())?,
            );
        }
        Ok(Self {
            dial,
            url: request_url(
                name,
                spec.server_port.unwrap_or(443),
                spec.path.as_deref().unwrap_or(DEFAULT_PATH),
            )?,
            headers,
            ca,
        })
    }

    pub(crate) fn dial(&self) -> &Dial {
        &self.dial
    }

    /// 只建客户端，不访问网络；`bootstrap` 为 `None` 时用于配置校验和字面 IP 上游。
    pub(crate) fn client(&self, bootstrap: Option<&Arc<Bootstrap>>) -> Result<DohClient> {
        let mut builder = Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(Policy::none())
            .use_rustls_tls()
            .dns_resolver(Arc::new(DialResolver {
                dial: match &self.dial {
                    Dial::Ip(ip) => Dial::Ip(*ip),
                    Dial::Domain(name) => Dial::Domain(name.clone()),
                },
                bootstrap: bootstrap.cloned(),
            }));
        if let Some(ca) = &self.ca {
            builder = builder.tls_built_in_root_certs(false);
            for certificate in ca {
                builder = builder.add_root_certificate(certificate.clone());
            }
        }
        Ok(DohClient {
            client: builder.build().map_err(|_| invalid())?,
            url: self.url.clone(),
            headers: self.headers.clone(),
            timeout: Duration::from_secs(5),
        })
    }
}

/// DoH 域名的引导解析。只查 `hosts` 和字面 IP 的 `default_nameserver`，到不了 `servers`，
/// 不会形成回环。
pub(crate) struct Bootstrap {
    pub(crate) hosts: BTreeMap<String, Vec<IpAddr>>,
    pub(crate) resolver: Option<Resolver<Provider>>,
}

impl Bootstrap {
    async fn lookup(&self, name: &str) -> std::result::Result<Vec<IpAddr>, NetError> {
        if let Some(addresses) = self.hosts.get(name) {
            return Ok(addresses.clone());
        }
        let resolver = self
            .resolver
            .as_ref()
            .ok_or(NetError::from("DoH 域名没有引导解析"))?;
        let lookup = resolver
            .lookup_ip(format!("{name}."))
            .await
            .map_err(|error| NetError::from(error.to_string()))?;
        Ok(lookup.iter().collect())
    }
}

struct DialResolver {
    dial: Dial,
    bootstrap: Option<Arc<Bootstrap>>,
}

impl Resolve for DialResolver {
    fn resolve(&self, _: Name) -> Resolving {
        let target = match &self.dial {
            Dial::Ip(ip) => Ok(*ip),
            Dial::Domain(name) => Err(name.clone()),
        };
        let bootstrap = self.bootstrap.clone();
        Box::pin(async move {
            let addresses = match target {
                Ok(ip) => vec![ip],
                Err(name) => {
                    bootstrap
                        .ok_or(NetError::from("DoH 域名没有引导解析"))?
                        .lookup(&name)
                        .await?
                }
            };
            let addresses: Addrs = Box::new(
                addresses
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addresses)
        })
    }
}

#[derive(Clone)]
pub(crate) struct DohClient {
    client: Client,
    url: Url,
    headers: HeaderMap,
    timeout: Duration,
}

impl DohClient {
    async fn exchange(self, mut request: DnsRequest) -> std::result::Result<DnsResponse, NetError> {
        // RFC 8484 第 4.1 节：ID 取 0 以利于缓存。
        request.metadata.id = 0;
        let body = request.to_vec().map_err(NetError::from)?;
        let mut response = self
            .client
            .post(self.url)
            .headers(self.headers)
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .timeout(self.timeout)
            .body(body)
            .send()
            .await
            .map_err(|error| NetError::from(error.to_string()))?;
        if !response.status().is_success() {
            return Err(NetError::from("DoH 服务器返回错误状态"));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or(value).trim());
        if content_type != Some(DNS_MESSAGE) {
            return Err(NetError::from("DoH 响应类型不是 application/dns-message"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| NetError::from(error.to_string()))?
        {
            if bytes.len() + chunk.len() > MAX_MESSAGE {
                return Err(NetError::from("DoH 响应超过 65535 字节"));
            }
            bytes.extend_from_slice(&chunk);
        }
        ProtoResponse::from_buffer(bytes).map_err(NetError::from)
    }
}

#[derive(Clone)]
pub(crate) enum Connection {
    Native(DnsExchange<TokioRuntimeProvider>),
    Doh(DohClient),
}

type ResponseStream = Pin<
    Box<dyn futures_util::Stream<Item = std::result::Result<DnsResponse, NetError>> + Send>,
>;

impl DnsHandle for Connection {
    type Response = ResponseStream;
    type Runtime = TokioRuntimeProvider;
    fn send(&self, request: DnsRequest) -> Self::Response {
        match self {
            Self::Native(exchange) => Box::pin(exchange.send(request)),
            Self::Doh(client) => Box::pin(stream::once(client.clone().exchange(request))),
        }
    }
}

/// `https` 的键是 DoH 上游在 hickory 池内的占位地址（ULA 段），不会被拨号。
#[derive(Clone, Default)]
pub(crate) struct Provider {
    runtime: TokioRuntimeProvider,
    https: Arc<BTreeMap<IpAddr, DohClient>>,
}

impl Provider {
    pub(crate) fn add(&mut self, client: DohClient) -> IpAddr {
        let https = Arc::make_mut(&mut self.https);
        let placeholder = IpAddr::V6(Ipv6Addr::new(
            0xfdff,
            0x6b6c,
            0x646f,
            0x6800,
            0,
            0,
            0,
            https.len() as u16 + 1,
        ));
        https.insert(placeholder, client);
        placeholder
    }
}

impl ConnectionProvider for Provider {
    type Conn = Connection;
    type FutureConn =
        Pin<Box<dyn Future<Output = std::result::Result<Connection, NetError>> + Send>>;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        cx: &PoolContext,
    ) -> std::result::Result<Self::FutureConn, NetError> {
        if let Some(client) = self.https.get(&ip) {
            let mut client = client.clone();
            client.timeout = cx.options.timeout;
            return Ok(Box::pin(async move { Ok(Connection::Doh(client)) }));
        }
        let native = ConnectionProvider::new_connection(&self.runtime, ip, config, cx)?;
        Ok(Box::pin(async move {
            Ok(Connection::Native(native.await?))
        }))
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}
