use super::{Opened, tls};
use crate::{config::OutConfig, handshake::EarlyClient, wire::kip};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use hmac::{Hmac, Mac};
use kerlico_core::{BoxStream, Error, Result};
use sha2::{Digest, Sha256};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{
        Error as WsError, Message, client::IntoClientRequest, protocol::WebSocketConfig,
    },
};

pub(crate) const EARLY: &str = "x-sudoku-early";
pub(crate) fn token(seed: &str, time: u64) -> String {
    let mut key = Sha256::new();
    key.update(b"sudoku-httpmask-auth-v1:");
    key.update(seed.as_bytes());
    let key = key.finalize();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("固定SHA256密钥长度");
    mac.update(b"ws\0GET\0/ws\0");
    mac.update(&time.to_be_bytes());
    let signature = mac.finalize().into_bytes();
    let mut bytes = time.to_be_bytes().to_vec();
    bytes.extend_from_slice(&signature[..16]);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn verify(seed: &str, value: &str, time: u64) -> bool {
    let value = value.trim();
    let value = if value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
    {
        &value[7..]
    } else {
        value
    };
    let Ok(raw) = URL_SAFE_NO_PAD.decode(value) else {
        return false;
    };
    if raw.len() != 24 {
        return false;
    }
    let timestamp = u64::from_be_bytes(raw[..8].try_into().unwrap());
    if timestamp.abs_diff(time) > 60 {
        return false;
    }
    let expected = token(seed, timestamp);
    let Ok(expected) = URL_SAFE_NO_PAD.decode(expected) else {
        return false;
    };
    bool::from(raw.as_slice().ct_eq(expected.as_slice()))
}
pub(crate) fn config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(1024 * 1024);
    config.max_frame_size = Some(1024 * 1024);
    config.write_buffer_size = 16 * 1024;
    config.max_write_buffer_size = 128 * 1024;
    config
}
pub(crate) async fn connect(
    options: &OutConfig,
    endpoint: &super::endpoint::Endpoint,
    early: &EarlyClient,
) -> Result<Opened> {
    let secure = options.mask.tls.is_some();
    let host = options
        .mask
        .host
        .clone()
        .unwrap_or_else(|| options.server.to_string());
    let scheme = if secure { "wss" } else { "ws" };
    let auth = token(&options.protocol.material.seed, kip::now()?);
    let ed = URL_SAFE_NO_PAD.encode(&early.request);
    let url = format!(
        "{scheme}://{host}{}/ws?auth={auth}&ed={ed}",
        options.mask.path_root
    );
    let mut request = url
        .into_client_request()
        .map_err(|_| Error::Config("Sudoku WS请求不合法".into()))?;
    for (name, value) in [
        ("x-sudoku-tunnel", "ws"),
        ("x-sudoku-version", "1"),
        ("user-agent", "Mozilla/5.0"),
    ] {
        request
            .headers_mut()
            .insert(name, http::HeaderValue::from_static(value));
    }
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {auth}")).map_err(|_| crate::invalid())?,
    );
    let carrier = tls::connect(endpoint, options.mask.tls.as_ref(), &[b"http/1.1"]).await?;
    let (stream, response) = client_async_with_config(request, carrier, Some(config()))
        .await
        .map_err(|_| Error::Protocol("Sudoku WS升级失败"))?;
    let early_response = response
        .headers()
        .get(EARLY)
        .map(|v| {
            URL_SAFE_NO_PAD
                .decode(v.as_bytes())
                .map_err(|_| crate::invalid())
        })
        .transpose()?;
    Ok(Opened {
        stream: Box::new(WsIo::new(stream)),
        early_response,
    })
}

pub(crate) struct WsIo {
    inner: WebSocketStream<BoxStream>,
    received: Bytes,
    remote_closed: bool,
    local_closed: bool,
    needs_flush: bool,
}
impl WsIo {
    pub fn new(inner: WebSocketStream<BoxStream>) -> Self {
        Self {
            inner,
            received: Bytes::new(),
            remote_closed: false,
            local_closed: false,
            needs_flush: false,
        }
    }
}
fn io_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Sudoku WS帧或连接不合法")
}
impl AsyncRead for WsIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if !this.received.is_empty() {
                let count = output.remaining().min(this.received.len());
                output.put_slice(&this.received[..count]);
                this.received.advance(count);
                return Poll::Ready(Ok(()));
            }
            if this.remote_closed {
                return Poll::Ready(Ok(()));
            }
            if this.needs_flush {
                match Pin::new(&mut this.inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => this.needs_flush = false,
                    Poll::Ready(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => {
                        this.remote_closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(io_error())),
                    Poll::Pending => {}
                }
            }
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => this.received = bytes,
                Some(Ok(Message::Text(text))) => {
                    this.received = Bytes::copy_from_slice(text.as_bytes())
                }
                Some(Ok(Message::Ping(_))) => this.needs_flush = true,
                Some(Ok(Message::Close(_))) | None => {
                    this.remote_closed = true;
                    let _ = Pin::new(&mut this.inner).poll_flush(cx);
                    return Poll::Ready(Ok(()));
                }
                Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => {
                    this.remote_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) => return Poll::Ready(Err(io_error())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for WsIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.local_closed || this.remote_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(|_| io_error())?;
        let count = bytes.len().min(16 * 1024);
        Pin::new(&mut this.inner)
            .start_send(Message::Binary(bytes[..count].to_vec().into()))
            .map_err(|_| io_error())?;
        this.needs_flush = true;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.inner).poll_flush(cx)).map_err(|_| io_error())?;
        this.needs_flush = false;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.local_closed = true;
        match ready!(Pin::new(&mut this.inner).poll_close(cx)) {
            Ok(()) | Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(io_error())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_uses_canonical_ws_path_and_bounded_time() {
        let seed = "synthetic-sudoku-websocket-secret";
        let value = token(seed, 1000);
        assert!(verify(seed, &value, 1060));
        assert!(verify(seed, &format!("Bearer {value}"), 1000));
        assert!(!verify(seed, &value, 1061));
        assert!(!verify("synthetic-other-seed", &value, 1000));
        assert!(!verify(seed, "invalid", 1000));
        assert!(!verify(seed, "合成无效输入", 1000));
    }
}
