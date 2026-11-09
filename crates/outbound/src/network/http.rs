use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerlico_shared::runtime::{HttpRequest, HttpResponse, NetworkConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) fn exchange(
    request: HttpRequest,
    connection: NetworkConnection,
) -> io::Result<HttpResponse> {
    exchange_with_tls(request, connection, None)
}

fn exchange_with_tls(
    request: HttpRequest,
    connection: NetworkConnection,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> io::Result<HttpResponse> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            tokio::time::timeout(request.dial.timeout, execute(request, connection, tls))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "HTTP metadata request timed out")
                })?
        })
    })
    .join()
    .map_err(|_| io::Error::other("HTTP metadata worker panicked"))?
}

trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}

async fn execute(
    request: HttpRequest,
    mut connection: NetworkConnection,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> io::Result<HttpResponse> {
    let url = url::Url::parse(&request.url).map_err(io::Error::other)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "metadata URL must be HTTP or HTTPS without user information",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "metadata URL has no host"))?;
    let transport: Box<dyn AsyncIo> = match connection {
        NetworkConnection::Tcp(socket) => {
            socket.set_nonblocking(true)?;
            Box::new(tokio::net::TcpStream::from_std(socket)?)
        }
        NetworkConnection::Udp(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "HTTP metadata requires TCP",
            ))
        }
        _ => {
            connection.set_timeout(Duration::from_millis(5))?;
            Box::new(PollStream {
                stream: connection,
                retry: None,
            })
        }
    };
    let transport: Box<dyn AsyncIo> = if url.scheme() == "https" {
        let config = tls.unwrap_or_else(|| tls_config(request.http2));
        let name =
            rustls::pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
                .map_err(io::Error::other)?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(name, transport)
            .await?;
        if request.http2 && stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata TLS peer did not negotiate HTTP/2",
            ));
        }
        Box::new(stream)
    } else {
        transport
    };
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let uri = if request.http2 {
        request.url.as_str()
    } else {
        &url[url::Position::BeforePath..url::Position::AfterQuery]
    };
    let mut builder = hyper::Request::builder()
        .method(request.method.as_str())
        .uri(uri)
        .header("host", authority);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    let message = builder
        .body(Full::new(Bytes::from(request.body)))
        .map_err(io::Error::other)?;
    let response = if request.http2 {
        let (mut send, drive) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(transport))
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = drive.await;
        });
        send.send_request(message).await.map_err(io::Error::other)?
    } else {
        let (mut send, drive) = hyper::client::conn::http1::handshake(TokioIo::new(transport))
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            let _ = drive.await;
        });
        send.send_request(message).await.map_err(io::Error::other)?
    };
    let status = response.status().as_u16();
    let mut incoming = response.into_body();
    let mut body = Vec::new();
    while let Some(frame) = incoming.frame().await {
        if let Ok(bytes) = frame.map_err(io::Error::other)?.into_data() {
            if body.len().saturating_add(bytes.len()) > 16 * 1024 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP metadata response exceeds 16 MiB",
                ));
            }
            body.extend_from_slice(&bytes);
        }
    }
    Ok(HttpResponse { status, body })
}

fn tls_config(http2: bool) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(certificate);
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![if http2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Arc::new(config)
}

struct PollStream {
    stream: NetworkConnection,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl PollStream {
    fn wait(&mut self, context: &mut Context<'_>) -> bool {
        use std::future::Future;
        if let Some(sleep) = self.retry.as_mut() {
            if sleep.as_mut().poll(context).is_pending() {
                return false;
            }
        }
        self.retry = None;
        true
    }
    fn retry(&mut self, context: &mut Context<'_>) {
        use std::future::Future;
        self.retry = Some(Box::pin(tokio::time::sleep(Duration::from_millis(2))));
        let _ = self.retry.as_mut().expect("retry").as_mut().poll(context);
    }
}
impl AsyncRead for PollStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.wait(context) {
            return Poll::Pending;
        }
        match self.stream.read(buffer.initialize_unfilled()) {
            Ok(n) => {
                buffer.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                self.retry(context);
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}
impl AsyncWrite for PollStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.stream.write(bytes) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                self.retry(context);
                Poll::Pending
            }
            result => Poll::Ready(result),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.stream.flush())
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests;
