//! v2 首写摘要覆盖实际接收到的全部原始字节，不以 TLS 握手返回时间代替首写事件。
use crate::wire;
use hmac::Mac;
use kerlico_core::{BoxStream, Result};
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(crate) type Capture = Arc<Mutex<Option<wire::Hash>>>;
struct Tap {
    inner: BoxStream,
    state: Capture,
}
pub(crate) fn wrap(inner: BoxStream, hash: wire::Hash) -> (BoxStream, Capture) {
    let state = Arc::new(Mutex::new(Some(hash)));
    (
        Box::new(Tap {
            inner,
            state: state.clone(),
        }),
        state,
    )
}
pub(crate) fn first(state: &Capture) -> Result<[u8; 8]> {
    let hash = state
        .lock()
        .map_err(|_| wire::error())?
        .take()
        .ok_or_else(wire::error)?;
    Ok(wire::sum::<8>(&hash))
}
impl AsyncRead for Tap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, out);
        if result.is_ready() && out.filled().len() > before {
            let Ok(mut state) = this.state.lock() else {
                return Poll::Ready(Err(io::Error::other("ShadowTLS 摘要状态不可用")));
            };
            if let Some(hash) = state.as_mut() {
                hash.update(&out.filled()[before..]);
            }
        }
        result
    }
}
impl AsyncWrite for Tap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn partial_raw_reads_extend_the_prefix_until_the_actual_first_write() {
        let (raw, mut peer) = tokio::io::duplex(64);
        let base = wire::hash(b"capture-test", b"handshake");
        let (mut tapped, state) = wrap(Box::new(raw), base.clone());
        peer.write_all(b"ticket-record").await.unwrap();
        let mut part = [0; 3];
        tapped.read_exact(&mut part).await.unwrap();
        let mut expected = base;
        expected.update(&part);
        assert_eq!(first(&state).unwrap(), wire::sum::<8>(&expected));
        let mut rest = [0; 10];
        tapped.read_exact(&mut rest).await.unwrap();
        assert!(state.lock().unwrap().is_none());
        assert!(first(&state).is_err());
    }
}

/// 没有 0-RTT 或客户端证书的握手，通过客户端 Finished 事件区分后续票据。
#[derive(Default)]
pub(crate) struct Gate {
    tls13: Option<bool>,
    client_ccs: bool,
    server_ccs: bool,
    client_finished: bool,
    server_finished: bool,
}
impl Gate {
    pub fn ready(&self) -> bool {
        self.client_finished && (self.tls13 == Some(true) || self.server_finished)
    }
    pub fn client(&mut self, record: &[u8]) {
        match self.tls13 {
            Some(true) => {
                if record[0] == wire::APP {
                    self.client_finished = true;
                }
            }
            Some(false) => {
                if record[0] == wire::CCS {
                    self.client_ccs = true;
                }
                if self.client_ccs && record[0] == wire::HANDSHAKE {
                    self.client_finished = true;
                }
            }
            None => {}
        }
    }
    pub fn server(&mut self, record: &[u8]) {
        if self.tls13.is_none()
            && record[0] == wire::HANDSHAKE
            && record.get(5) == Some(&2)
            && let Ok((_, tls13)) = wire::server_hello(record)
        {
            self.tls13 = Some(tls13);
        }
        if self.tls13 == Some(false) {
            if record[0] == wire::CCS {
                self.server_ccs = true;
            }
            if self.server_ccs && record[0] == wire::HANDSHAKE {
                self.server_finished = true;
            }
        }
    }
}
#[cfg(test)]
mod gate_tests {
    use super::*;
    #[test]
    fn late_record_gating_starts_only_after_both_required_tls_flights() {
        let mut twelve = Gate {
            tls13: Some(false),
            ..Gate::default()
        };
        twelve.client(&wire::frame(wire::CCS, &[1]));
        twelve.client(&wire::frame(wire::HANDSHAKE, b"finished"));
        assert!(!twelve.ready());
        twelve.server(&wire::frame(wire::CCS, &[1]));
        assert!(!twelve.ready());
        twelve.server(&wire::frame(wire::HANDSHAKE, b"finished"));
        assert!(twelve.ready());
        let mut thirteen = Gate {
            tls13: Some(true),
            ..Gate::default()
        };
        assert!(!thirteen.ready());
        thirteen.client(&wire::frame(wire::CCS, &[1]));
        assert!(!thirteen.ready());
        thirteen.client(&wire::frame(wire::APP, b"client-finished"));
        assert!(thirteen.ready());
    }
}
