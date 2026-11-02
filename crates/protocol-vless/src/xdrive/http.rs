//! 每次存储操作拥有 HTTP 连接驱动；取消操作直接释放驱动和底层连接。
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use kerlico_core::{BoxStream, Error, Result};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use url::Url;

#[derive(Clone)]
pub(crate) struct Client {
    tls: Arc<rustls::ClientConfig>,
}
pub(crate) struct Request {
    client: Client,
    method: Method,
    url: Option<Url>,
    headers: HeaderMap,
    body: Vec<u8>,
    invalid: bool,
}
pub(crate) struct Response {
    status: StatusCode,
    body: Option<Bytes>,
}
impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        Ok(self.body.take())
    }
}
fn invalid() -> Error {
    Error::Config("XDRIVE HTTP 参数不合法".into())
}
fn remote() -> Error {
    Error::Protocol("XDRIVE HTTP 操作失败")
}
pub(crate) fn tls(ca: Option<&str>) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(ca) = ca {
        let invalid_ca = || Error::Config("XDRIVE 自定义 CA 必须包含有效证书".into());
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(ca))
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|_| invalid_ca())?;
        if certs.is_empty() {
            return Err(invalid_ca());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| invalid_ca())?;
        }
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| invalid())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
impl Client {
    pub fn new(tls: Arc<rustls::ClientConfig>) -> Self {
        Self { tls }
    }
    pub fn request(&self, method: Method, url: Url) -> Request {
        self.build(method, Some(url))
    }
    pub fn post(&self, url: impl AsRef<str>) -> Request {
        self.build(Method::POST, Url::parse(url.as_ref()).ok())
    }
    fn build(&self, method: Method, mut url: Option<Url>) -> Request {
        let auth = url.as_mut().and_then(|url| {
            let username = percent_encoding::percent_decode_str(url.username())
                .decode_utf8()
                .ok()?
                .into_owned();
            let password = url.password().and_then(|password| {
                percent_encoding::percent_decode_str(password)
                    .decode_utf8()
                    .ok()
                    .map(|value| value.into_owned())
            });
            if username.is_empty() && password.is_none() {
                return None;
            }
            url.set_username("").ok()?;
            url.set_password(None).ok()?;
            Some((username, password))
        });
        let request = Request {
            client: self.clone(),
            method,
            url,
            headers: HeaderMap::new(),
            body: Vec::new(),
            invalid: false,
        };
        match auth {
            Some((username, password)) => request.basic_auth(username, password),
            None => request,
        }
    }
}
impl Request {
    pub fn header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        match (
            HeaderName::from_bytes(name.as_ref().as_bytes()),
            HeaderValue::from_str(value.as_ref()),
        ) {
            (Ok(name), Ok(value)) => {
                self.headers.append(name, value);
            }
            _ => self.invalid = true,
        }
        self
    }
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }
    pub fn basic_auth(self, username: String, password: Option<String>) -> Self {
        self.header(
            "authorization",
            format!(
                "Basic {}",
                STANDARD.encode(format!("{username}:{}", password.unwrap_or_default()))
            ),
        )
    }
    pub fn bearer_auth(self, token: String) -> Self {
        self.header("authorization", format!("Bearer {token}"))
    }
    pub fn form<T: serde::Serialize + ?Sized>(mut self, form: &T) -> Self {
        let pairs = match serde_json::to_value(form) {
            Ok(serde_json::Value::Object(values)) => values
                .into_iter()
                .map(|(key, value)| value.as_str().map(|value| (key, value.to_owned())))
                .collect::<Option<BTreeMap<_, _>>>(),
            Ok(serde_json::Value::Array(values)) => values
                .into_iter()
                .map(|value| {
                    let pair = value.as_array()?;
                    if pair.len() != 2 {
                        return None;
                    }
                    Some((pair[0].as_str()?.to_owned(), pair[1].as_str()?.to_owned()))
                })
                .collect::<Option<BTreeMap<_, _>>>(),
            _ => None,
        };
        let Some(pairs) = pairs else {
            self.invalid = true;
            return self;
        };
        let mut encoded = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoded.append_pair(&key, &value);
        }
        self.body = encoded.finish().into_bytes();
        self.header("content-type", "application/x-www-form-urlencoded")
    }
    pub async fn send(self) -> Result<Response> {
        tokio::time::timeout(Duration::from_secs(60), self.exchange())
            .await
            .map_err(|_| Error::Timeout)?
    }
    async fn exchange(mut self) -> Result<Response> {
        if self.invalid {
            return Err(invalid());
        }
        let url = self.url.take().ok_or_else(invalid)?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(invalid());
        }
        let host = match url.host().ok_or_else(invalid)? {
            url::Host::Domain(host) => host.to_owned(),
            url::Host::Ipv4(host) => host.to_string(),
            url::Host::Ipv6(host) => host.to_string(),
        };
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
        tcp.set_nodelay(true)?;
        let stream: BoxStream = if url.scheme() == "https" {
            let name = rustls::pki_types::ServerName::try_from(host).map_err(|_| invalid())?;
            Box::new(
                tokio_rustls::TlsConnector::from(self.client.tls.clone())
                    .connect(name, tcp)
                    .await?,
            )
        } else {
            Box::new(tcp)
        };
        let mut path = url.path().to_owned();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        let mut request = http::Request::builder()
            .method(self.method)
            .uri(path)
            .body(Full::new(Bytes::from(self.body)))
            .map_err(|_| invalid())?;
        if !self.headers.contains_key(http::header::HOST) {
            let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
            self.headers.insert(
                http::header::HOST,
                HeaderValue::from_str(authority).map_err(|_| invalid())?,
            );
        }
        self.headers
            .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        *request.headers_mut() = self.headers;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| remote())?;
        let exchange = async move {
            let response = sender.send_request(request).await.map_err(|_| remote())?;
            let status = response.status();
            let mut response = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = response.frame().await {
                if let Ok(data) = frame.map_err(|_| remote())?.into_data() {
                    if bytes.len() + data.len() > 8 * 1024 * 1024 {
                        return Err(Error::ResourceLimit);
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            drop(response);
            drop(sender);
            Ok(Response {
                status,
                body: Some(Bytes::from(bytes)),
            })
        };
        let (response, ()) =
            tokio::try_join!(exchange, async { connection.await.map_err(|_| remote()) })?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn assert_invalid_ca(ca: &str) {
        let settings = crate::xdrive::Settings {
            remote_folder: "unused-test-store".into(),
            ca_pem: Some(ca.into()),
            ..Default::default()
        };
        assert!(matches!(
            crate::xdrive::Transport::compile(settings, None),
            Err(Error::Config(message)) if message == "XDRIVE 自定义 CA 必须包含有效证书"
        ));
    }

    #[test]
    fn empty_custom_ca_is_rejected_during_compile() {
        assert_invalid_ca("");
        assert_invalid_ca(" \r\n\t");
    }

    #[test]
    fn non_certificate_custom_ca_is_rejected_during_compile() {
        assert_invalid_ca("unrelated material");
        let label = "PRIVATE KEY";
        assert_invalid_ca(&format!(
            "-----BEGIN {label}-----\nAQID\n-----END {label}-----\n"
        ));
    }

    #[test]
    fn damaged_custom_ca_is_a_stable_config_error() {
        assert_invalid_ca("-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n");
        assert_invalid_ca("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
        assert_invalid_ca("-----BEGIN CERTIFICATE-----\nAQID\n");
    }

    fn private_ca() -> (
        String,
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&params, &ca_key);
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
        (ca.pem(), leaf.der().clone(), key)
    }

    #[test]
    fn valid_custom_ca_compiles_and_explicit_empty_does_not_use_fallback() {
        let (ca, _, _) = private_ca();
        let mut settings = crate::xdrive::Settings {
            remote_folder: "unused-test-store".into(),
            ca_pem: Some(ca.clone()),
            ..Default::default()
        };
        assert!(crate::xdrive::Transport::compile(settings.clone(), None).is_ok());
        settings.ca_pem = Some(String::new());
        assert!(matches!(
            crate::xdrive::Transport::compile(settings, Some(&ca)),
            Err(Error::Config(_))
        ));
        assert_invalid_ca(&format!(
            "{ca}\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        ));
    }

    #[tokio::test]
    async fn valid_private_ca_authenticates_the_real_https_storage_connection() {
        let (ca, leaf, key) = private_ca();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"GET /segment HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let response = Client::new(tls(Some(&ca)).unwrap())
            .request(
                Method::GET,
                Url::parse(&format!("https://{address}/segment")).unwrap(),
            )
            .send();
        let mut response = tokio::time::timeout(Duration::from_secs(3), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.chunk().await.unwrap().unwrap(), b"ok"[..]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn form_headers_and_chunked_body_are_preserved_without_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = Vec::new();
            let head = loop {
                let byte = stream.read_u8().await.unwrap();
                wire.push(byte);
                if wire.ends_with(b"\r\n\r\n") {
                    break String::from_utf8(wire.clone()).unwrap();
                }
            };
            let length: usize = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            assert!(head.starts_with("POST /token?q=a%20b HTTP/1.1\r\n"));
            assert!(head.to_ascii_lowercase().contains("authorization: basic "));
            assert_eq!(body, b"grant_type=refresh_token&value=a%26b");
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://unused.invalid/\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n").await.unwrap();
        });
        let client = Client::new(tls(None).unwrap());
        let mut response = client
            .post(format!("http://{address}/token?q=a%20b"))
            .basic_auth("synthetic".into(), Some("password".into()))
            .form(&[("grant_type", "refresh_token"), ("value", "a&b")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.chunk().await.unwrap().unwrap(), b"onetwo"[..]);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn cancelling_the_request_drops_the_real_connection_driver() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (ready, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert!(stream.read(&mut bytes).await.unwrap() > 0);
            let _ = ready.send(());
            loop {
                if stream.read(&mut bytes).await.unwrap() == 0 {
                    break;
                }
            }
        });
        let client = Client::new(tls(None).unwrap());
        {
            let request = client.post(format!("http://{address}/blocked")).send();
            tokio::pin!(request);
            tokio::select! { _ = received => {}, _ = &mut request => panic!("测试响应不应提前完成") }
        }
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn token_url_authority_is_decoded_and_fragment_is_not_sent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut wire = Vec::new();
            while !wire.ends_with(b"\r\n\r\n") {
                wire.push(stream.read_u8().await.unwrap());
            }
            let head = String::from_utf8(wire).unwrap();
            assert!(head.starts_with("POST /token?q=a%20b HTTP/1.1\r\n"));
            let expected = format!(
                "authorization: Basic {}",
                STANDARD.encode("synthetic:pass:word")
            );
            assert!(
                head.lines()
                    .any(|line| line.eq_ignore_ascii_case(&expected))
            );
            assert!(!head.contains("ignored"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let client = Client::new(tls(None).unwrap());
        let credentials = ["synthetic", "pass%3Aword"].join(":");
        let response = client
            .post(format!(
                "http://{credentials}@{address}/token?q=a%20b#ignored"
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        server.await.unwrap();
    }
}
