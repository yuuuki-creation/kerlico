use super::super::{endpoint::Endpoint, tls};
use crate::{
    config::{ClientTls, HttpVersion, OutConfig},
    io::CancelIo,
};
use bytes::Bytes;
use http::{Method, Request, Response, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use kerlico_core::{BoxFuture, BoxStream, CancellationToken, Error, Result};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tower_service::Service;

struct CarrierIo {
    inner: TokioIo<CancelIo<BoxStream>>,
    h2: bool,
}
impl Connection for CarrierIo {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if self.h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}
impl hyper::rt::Read for CarrierIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        hyper::rt::Read::poll_read(Pin::new(&mut self.get_mut().inner), cx, buffer)
    }
}
impl hyper::rt::Write for CarrierIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write(Pin::new(&mut self.get_mut().inner), cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_flush(Pin::new(&mut self.get_mut().inner), cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_shutdown(Pin::new(&mut self.get_mut().inner), cx)
    }
    fn is_write_vectored(&self) -> bool {
        hyper::rt::Write::is_write_vectored(&self.inner)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write_vectored(Pin::new(&mut self.get_mut().inner), cx, buffers)
    }
}
#[derive(Clone)]
struct Connector {
    endpoint: Arc<Endpoint>,
    tls: Option<ClientTls>,
    version: HttpVersion,
    authority: String,
    cancel: CancellationToken,
}
impl Service<Uri> for Connector {
    type Response = CarrierIo;
    type Error = Error;
    type Future = BoxFuture<'static, Result<CarrierIo>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            if uri.authority().map(|a| a.as_str()) != Some(this.authority.as_str())
                || (uri.scheme_str() == Some("https")) != this.tls.is_some()
            {
                return Err(Error::Rejected);
            }
            let alpn: &[&[u8]] = match this.version {
                HttpVersion::H1 => &[b"http/1.1"],
                HttpVersion::H2 => &[b"h2"],
                HttpVersion::Auto => &[b"h2", b"http/1.1"],
            };
            let (stream, h2) = tokio::select! {biased;_=this.cancel.cancelled()=>return Err(Error::Cancelled),result=tls::connect_meta(&this.endpoint,this.tls.as_ref(),alpn)=>result?};
            if this.version == HttpVersion::H2 && !h2 {
                return Err(Error::Protocol("HTTP/2要求未被TLS对端协商"));
            }
            Ok(CarrierIo {
                inner: TokioIo::new(CancelIo::new(stream, &this.cancel)),
                h2,
            })
        })
    }
}
pub(crate) struct HttpClient {
    client: Client<Connector, Full<Bytes>>,
    pub cancel: CancellationToken,
    base: String,
    authority: String,
    pub root: String,
}
impl Drop for HttpClient {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
fn transfer_error() -> Error {
    Error::Io(io::Error::other("Sudoku HTTP传输失败"))
}
impl HttpClient {
    pub fn new(
        config: &OutConfig,
        endpoint: Arc<Endpoint>,
        parent: &CancellationToken,
        reuse: bool,
    ) -> Arc<Self> {
        let cancel = parent.child_token();
        let authority = config
            .mask
            .host
            .clone()
            .unwrap_or_else(|| config.server.to_string());
        let connector = Connector {
            endpoint,
            tls: config.mask.tls.clone(),
            version: config.mask.http_version,
            authority: authority.clone(),
            cancel: cancel.clone(),
        };
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(config.idle)
            .pool_timer(TokioTimer::new())
            .timer(TokioTimer::new())
            .pool_max_idle_per_host(if reuse { config.max_pool * 3 } else { 3 })
            .http1_max_buf_size(32 * 1024)
            .http2_max_header_list_size(32 * 1024)
            .http2_max_send_buf_size(128 * 1024);
        if config.mask.http_version == HttpVersion::H2 {
            builder.http2_only(true);
        }
        let scheme = if config.mask.tls.is_some() {
            "https"
        } else {
            "http"
        };
        Arc::new(Self {
            client: builder.build(connector),
            cancel,
            base: format!("{scheme}://{authority}"),
            authority,
            root: config.mask.path_root.clone(),
        })
    }
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &str,
        mode: &str,
        body: Bytes,
        content_type: Option<&str>,
    ) -> Result<Response<Incoming>> {
        self.send(method, path, query, Some(mode), body, content_type)
            .await
    }
    pub fn cover(
        host: String,
        options: Option<ClientTls>,
        endpoint: Arc<Endpoint>,
        parent: &CancellationToken,
    ) -> Arc<Self> {
        let cancel = parent.child_token();
        let scheme = if options.is_some() { "https" } else { "http" };
        let connector = Connector {
            endpoint,
            tls: options,
            version: HttpVersion::H1,
            authority: host.clone(),
            cancel: cancel.clone(),
        };
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_max_idle_per_host(0)
            .http1_max_buf_size(32 * 1024);
        Arc::new(Self {
            client: builder.build(connector),
            cancel,
            base: format!("{scheme}://{host}"),
            authority: host,
            root: String::new(),
        })
    }
    pub async fn page(&self, method: Method) -> Result<Response<Incoming>> {
        self.send(method, "/", "", None, Bytes::new(), None).await
    }
    async fn send(
        &self,
        method: Method,
        path: &str,
        query: &str,
        mode: Option<&str>,
        body: Bytes,
        content_type: Option<&str>,
    ) -> Result<Response<Incoming>> {
        let uri: Uri = format!(
            "{}{}{path}{}",
            self.base,
            self.root,
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        )
        .parse()
        .map_err(|_| crate::invalid())?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::HOST, self.authority.as_str())
            .header(http::header::CACHE_CONTROL, "no-cache")
            .header(http::header::USER_AGENT, "Mozilla/5.0");
        if let Some(mode) = mode {
            request = request.header("x-sudoku-tunnel", mode);
        }
        if path == "/stream" && mode.is_some() {
            request = request.header(http::header::TE, "trailers");
        }
        if let Some(content_type) = content_type {
            request = request.header(http::header::CONTENT_TYPE, content_type);
        }
        let request = request
            .body(Full::new(body))
            .map_err(|_| crate::invalid())?;
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Cancelled),result=tokio::time::timeout(Duration::from_secs(20),self.client.request(request))=>result.map_err(|_|Error::Timeout)?.map_err(|_|transfer_error())}
    }
}
pub(crate) async fn small_body(
    mut response: Response<Incoming>,
    maximum: usize,
) -> Result<(http::StatusCode, Vec<u8>)> {
    if response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > maximum)
    {
        return Err(Error::ResourceLimit);
    }
    let status = response.status();
    let mut body = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| transfer_error())?;
        if let Ok(bytes) = frame.into_data() {
            if body.len().saturating_add(bytes.len()) > maximum {
                return Err(Error::ResourceLimit);
            }
            body.extend_from_slice(&bytes);
        }
    }
    Ok((status, body))
}
