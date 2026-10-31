use crate::{
    carrier::http::{
        body::Body,
        server::response,
        transport::{HttpClient, small_body},
    },
    io::SharedIo,
};
use bytes::Bytes;
use http::{Method, Response, StatusCode};
use kerlico_core::{Error, Result};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

pub(crate) struct Page {
    status: StatusCode,
    kind: Option<http::HeaderValue>,
    bytes: Vec<u8>,
}
impl Page {
    fn response(self) -> Response<Body> {
        let mut reply = response(self.status, self.bytes);
        if let Some(kind) = self.kind {
            reply.headers_mut().insert(http::header::CONTENT_TYPE, kind);
        }
        reply
    }
}
pub(crate) async fn fetch(client: &HttpClient, method: Method) -> Result<Page> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let reply = client.page(method).await?;
        let kind = reply.headers().get(http::header::CONTENT_TYPE).cloned();
        let (status, bytes) = small_body(reply, 1024 * 1024).await?;
        Ok(Page {
            status,
            kind,
            bytes,
        })
    })
    .await
    .map_err(|_| Error::Timeout)?
}
pub(crate) async fn http(client: Arc<HttpClient>, method: Method) -> Response<Body> {
    match fetch(&client, method).await {
        Ok(page) => page.response(),
        Err(_) => response(StatusCode::BAD_GATEWAY, Bytes::new()),
    }
}
pub(crate) async fn raw(client: &HttpClient, method: Method, mut stream: SharedIo) -> Result<()> {
    let page = fetch(client, method.clone()).await?;
    let kind = page
        .kind
        .as_ref()
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        page.status.as_u16(),
        page.status.canonical_reason().unwrap_or(""),
        page.bytes.len()
    );
    stream.write_all(header.as_bytes()).await?;
    if method != Method::HEAD {
        stream.write_all(&page.bytes).await?;
    }
    stream.shutdown().await?;
    Ok(())
}
