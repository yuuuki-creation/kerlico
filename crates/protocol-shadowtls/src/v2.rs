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
#[cfg(test)]
#[path = "v2_fixture.rs"]
mod real_tls_tests;
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

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use std::{future::Future, task::Poll};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn first_write_records_header_body_and_complete_late_record_prefixes() {
        for (tls, kind) in [("1.2", wire::HANDSHAKE), ("1.3", wire::APP)] {
            for tickets in [2, 8] {
                let records: Vec<_> = (0..tickets)
                    .map(|index| wire::frame(kind, &[4, 0, 0, 3, index, 11, 17]))
                    .collect();
                for boundary in [2, 5, 8, records[0].len()] {
                    let (raw, mut origin) = tokio::io::duplex(4096);
                    let base = wire::hash(b"boundary-test", b"completed-handshake");
                    let (mut tapped, state) = wrap(Box::new(raw), base.clone());
                    origin.write_all(&records[0][..boundary]).await.unwrap();
                    let mut reader = wire::Reader::new();
                    let complete = {
                        let mut next = std::pin::pin!(reader.next(&mut tapped));
                        std::future::poll_fn(|cx| match next.as_mut().poll(cx) {
                            Poll::Ready(value) => Poll::Ready(Some(value.unwrap().unwrap())),
                            Poll::Pending => Poll::Ready(None),
                        })
                        .await
                    };
                    if boundary < records[0].len() {
                        assert!(complete.is_none());
                        assert_eq!(reader.pending(), records[0][..boundary]);
                    } else {
                        assert_eq!(complete.as_ref().unwrap(), &records[0]);
                    }
                    let mut expected = base.clone();
                    expected.update(&records[0][..boundary]);
                    let actual = first(&state).unwrap();
                    assert_eq!(actual, wire::sum::<8>(&expected));
                    let mut complete_record = base;
                    complete_record.update(&records[0]);
                    assert_eq!(
                        actual == wire::sum::<8>(&complete_record),
                        boundary == records[0].len()
                    );
                    let mut body = actual.to_vec();
                    body.push(b'x');
                    tapped
                        .write_all(&wire::frame(wire::APP, &body))
                        .await
                        .unwrap();
                    let business = wire::read(&mut origin).await.unwrap().unwrap();
                    assert_eq!(&business[5..13], &actual);
                    assert_eq!(&business[13..], b"x");
                    if complete.is_none() {
                        origin.write_all(&records[0][boundary..]).await.unwrap();
                        assert_eq!(reader.next(&mut tapped).await.unwrap().unwrap(), records[0]);
                    }
                    for record in &records[1..] {
                        origin.write_all(record).await.unwrap();
                        assert_eq!(reader.next(&mut tapped).await.unwrap().unwrap(), *record);
                    }
                    assert!(state.lock().unwrap().is_none());
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "fixture": "synthetic-raw-boundary", "tls_record_shape": tls,
                            "tickets": tickets, "raw_prefix_bytes": boundary,
                            "record_bytes": records[0].len(), "tag": actual,
                            "complete_record_tag": wire::sum::<8>(&complete_record),
                            "first_business_bytes": 1, "pending_preserved": true
                        })
                    );
                }
            }
        }
    }

    struct ObservedRead {
        raw: tokio::io::DuplexStream,
        consumed: tokio::sync::watch::Sender<usize>,
        total: usize,
    }
    impl AsyncRead for ObservedRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = out.filled().len();
            let result = Pin::new(&mut self.raw).poll_read(cx, out);
            self.total += out.filled().len() - before;
            let _ = self.consumed.send(self.total);
            result
        }
    }
    impl AsyncWrite for ObservedRead {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.raw).poll_write(cx, bytes)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.raw).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn synthetic_bridge_first_small_write_can_freeze_inside_an_incomplete_record() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            for boundary in [2, 5, 8] {
                let (raw, mut peer) = tokio::io::duplex(256);
                let (observed, mut received) = tokio::sync::watch::channel(0);
                let base = wire::hash(b"bridge-boundary-test", b"handshake");
                let (raw, capture) = wrap(
                    Box::new(ObservedRead {
                        raw,
                        consumed: observed,
                        total: 0,
                    }),
                    base.clone(),
                );
                let mut user = crate::stream::wrap(
                    raw,
                    Vec::new(),
                    crate::stream::ReadMode::V2(None),
                    crate::stream::WriteMode::V2(Some(capture.clone())),
                    kerlico_core::CancellationToken::new(),
                    crate::stream::test_owner(),
                )
                .unwrap();
                let late = wire::frame(wire::APP, b"late-record");
                peer.write_all(&late[..boundary]).await.unwrap();
                received.wait_for(|count| *count == boundary).await.unwrap();
                user.write_all(b"x").await.unwrap();
                user.flush().await.unwrap();
                let first = wire::read(&mut peer).await.unwrap().unwrap();
                let mut expected = base;
                expected.update(&late[..boundary]);
                assert_eq!(&first[5..13], &wire::sum::<8>(&expected));
                assert_eq!(&first[13..], b"x");
                assert!(capture.lock().unwrap().is_none());
                peer.write_all(&late[boundary..]).await.unwrap();
                let mut late_payload = [0; 11];
                user.read_exact(&mut late_payload).await.unwrap();
                assert_eq!(&late_payload, b"late-record");
                user.write_all(b"y").await.unwrap();
                user.flush().await.unwrap();
                assert_eq!(&wire::read(&mut peer).await.unwrap().unwrap()[5..], b"y");
                drop(user);
            }
        })
        .await
        .expect("v2 首写与部分记录交错夹具超时");
    }
}
