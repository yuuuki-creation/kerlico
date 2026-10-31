//! 逐个 UDP 数据报处理 v1 的 xplus 与 WeChat-video，不使用 Salamander。
use crate::config::Carrier;
use quinn::{AsyncUdpSocket, UdpPoller, udp};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
pub(crate) struct Settings {
    pub carrier: Carrier,
    pub key: Option<Arc<[u8]>>,
}
impl Settings {
    fn overhead(&self) -> usize {
        usize::from(self.carrier == Carrier::WechatVideo) * 13
            + usize::from(self.key.is_some()) * 16
    }
}
struct Socket {
    inner: Arc<dyn AsyncUdpSocket>,
    settings: Arc<Settings>,
    sequence: AtomicU32,
    send: Mutex<Vec<u8>>,
    receive: Mutex<Vec<u8>>,
}
impl std::fmt::Debug for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hysteria1UdpSocket")
    }
}
fn mask(key: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(key);
    hash.update(salt);
    hash.finalize().into()
}
fn pack(settings: &Settings, sequence: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + settings.overhead());
    if settings.carrier == Carrier::WechatVideo {
        out.extend_from_slice(&[0xa1, 0x08]);
        out.extend_from_slice(&sequence.to_be_bytes());
        out.extend_from_slice(&[0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
    }
    if let Some(key) = &settings.key {
        let mut salt = [0; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let hash = mask(key, &salt);
        out.extend_from_slice(&salt);
        out.extend(
            bytes
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ hash[index % 32]),
        );
    } else {
        out.extend_from_slice(bytes);
    }
    out
}
fn unpack(settings: &Settings, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = bytes;
    if settings.carrier == Carrier::WechatVideo {
        if bytes.len() <= 13
            || bytes[..2] != [0xa1, 0x08]
            || bytes[6..13] != [0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]
        {
            return None;
        }
        bytes = &bytes[13..];
    }
    if let Some(key) = &settings.key {
        if bytes.len() <= 16 {
            return None;
        }
        let hash = mask(key, &bytes[..16]);
        Some(
            bytes[16..]
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ hash[index % 32])
                .collect(),
        )
    } else {
        Some(bytes.to_vec())
    }
}
struct Waiter(Mutex<Option<Waker>>);
struct Writers(Mutex<Vec<Weak<Waiter>>>);
impl Writers {
    fn wake_all(&self) {
        let mut wakes = Vec::new();
        if let Ok(mut writers) = self.0.lock() {
            writers.retain(|weak| {
                let Some(writer) = weak.upgrade() else {
                    return false;
                };
                if let Ok(mut wake) = writer.0.lock()
                    && let Some(wake) = wake.take()
                {
                    wakes.push(wake);
                }
                true
            });
        }
        for wake in wakes {
            wake.wake();
        }
    }
}
impl Wake for Writers {
    fn wake(self: Arc<Self>) {
        self.wake_all()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all()
    }
}
struct Raw {
    socket: Mutex<Option<tokio::net::UdpSocket>>,
    address: SocketAddr,
    reader: Mutex<Option<Waker>>,
    writer: Arc<Writers>,
}
impl std::fmt::Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hysteria1RawUdp")
    }
}
impl Raw {
    fn close(&self) {
        if let Ok(mut socket) = self.socket.lock() {
            socket.take();
        }
        if let Ok(mut waker) = self.reader.lock()
            && let Some(waker) = waker.take()
        {
            waker.wake();
        }
        self.writer.wake_all();
    }
}
pub(crate) struct Close {
    inner: Arc<Raw>,
}
impl Drop for Close {
    fn drop(&mut self) {
        self.inner.close();
    }
}
struct Poller {
    inner: Weak<Raw>,
    event: Arc<Waiter>,
}
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hysteria1UdpPoller")
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(raw) = self.inner.upgrade() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        if let Ok(mut waker) = self.event.0.lock() {
            *waker = Some(cx.waker().clone());
        }
        let guard = raw
            .socket
            .lock()
            .map_err(|_| io::Error::other("Hysteria v1 UDP 状态不可用"))?;
        let Some(socket) = guard.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let wake = Waker::from(raw.writer.clone());
        let mut context = Context::from_waker(&wake);
        socket.poll_send_ready(&mut context)
    }
}
impl AsyncUdpSocket for Raw {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        let event = Arc::new(Waiter(Mutex::new(None)));
        if let Ok(mut writers) = self.writer.0.lock() {
            writers.retain(|writer| writer.strong_count() > 0);
            writers.push(Arc::downgrade(&event));
        }
        Box::pin(Poller {
            inner: Arc::downgrade(&self),
            event,
        })
    }
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit
            .segment_size
            .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let guard = self
            .socket
            .lock()
            .map_err(|_| io::Error::other("Hysteria v1 UDP 状态不可用"))?;
        let socket = guard.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let sent = socket.try_send_to(transmit.contents, transmit.destination)?;
        if sent != transmit.contents.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        output: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Ok(mut waker) = self.reader.lock() {
            *waker = Some(cx.waker().clone());
        }
        let guard = self
            .socket
            .lock()
            .map_err(|_| io::Error::other("Hysteria v1 UDP 状态不可用"))?;
        let Some(socket) = guard.as_ref() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        loop {
            std::task::ready!(socket.poll_recv_ready(cx))?;
            match socket.try_recv_from(&mut output[0]) {
                Ok((len, addr)) => {
                    meta[0] = udp::RecvMeta {
                        addr,
                        len,
                        stride: len.max(1),
                        ecn: None,
                        dst_ip: if self.address.ip().is_unspecified() {
                            None
                        } else {
                            Some(self.address.ip())
                        },
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.address)
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        1
    }
    fn may_fragment(&self) -> bool {
        false
    }
}
pub(crate) fn wrap(
    socket: UdpSocket,
    settings: Arc<Settings>,
) -> io::Result<(Arc<dyn AsyncUdpSocket>, Close)> {
    let address = socket.local_addr()?;
    let raw = Arc::new(Raw {
        socket: Mutex::new(Some(tokio::net::UdpSocket::from_std(socket)?)),
        address,
        reader: Mutex::new(None),
        writer: Arc::new(Writers(Mutex::new(Vec::new()))),
    });
    let close = Close { inner: raw.clone() };
    let inner: Arc<dyn AsyncUdpSocket> = raw;
    if settings.carrier == Carrier::Udp && settings.key.is_none() {
        return Ok((inner, close));
    }
    Ok((
        Arc::new(Socket {
            inner,
            settings,
            sequence: AtomicU32::new(rand::rngs::OsRng.next_u32() & 0xffff),
            send: Mutex::new(Vec::with_capacity(1500)),
            receive: Mutex::new(vec![0; 65535]),
        }),
        close,
    ))
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.contents.len() + self.settings.overhead() > 65507
            || transmit
                .segment_size
                .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hysteria v1 包装超出单包边界",
            ));
        }
        let bytes = pack(
            &self.settings,
            self.sequence.fetch_add(1, Ordering::Relaxed),
            transmit.contents,
        );
        let mut send = self
            .send
            .lock()
            .map_err(|_| io::Error::other("Hysteria v1 发送状态不可用"))?;
        *send = bytes;
        self.inner.try_send(&udp::Transmit {
            contents: &send,
            segment_size: None,
            ..*transmit
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        output: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut scratch = self
            .receive
            .lock()
            .map_err(|_| io::Error::other("Hysteria v1 接收状态不可用"))?;
        let count = std::task::ready!(self.inner.poll_recv(
            cx,
            &mut [IoSliceMut::new(&mut scratch)],
            &mut meta[..1]
        ))?;
        if count == 0 {
            return Poll::Ready(Ok(0));
        }
        let info = &mut meta[0];
        let length = info.len.min(scratch.len());
        let stride = info.stride.max(1);
        let mut written = 0;
        let overhead = self.settings.overhead();
        if stride <= overhead {
            info.len = 0;
            info.stride = 1;
            return Poll::Ready(Ok(1));
        }
        for start in (0..length).step_by(stride) {
            let end = (start + stride).min(length);
            if let Some(data) = unpack(&self.settings, &scratch[start..end]) {
                if written + data.len() > output[0].len() {
                    info.len = 0;
                    info.stride = 1;
                    return Poll::Ready(Ok(1));
                }
                output[0][written..written + data.len()].copy_from_slice(&data);
                written += data.len();
            }
        }
        info.len = written;
        info.stride = stride - overhead;
        Poll::Ready(Ok(1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        1
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xplus_key_order_and_each_carrier_roundtrip() {
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(mask(b"a", b"bc"), expected);
        for carrier in [Carrier::Udp, Carrier::WechatVideo] {
            for key in [None, Some(Arc::from(b"xplus-test-only-key".as_slice()))] {
                let settings = Settings { carrier, key };
                let payload = vec![17; 1200];
                let bytes = pack(&settings, 0x01020304, &payload);
                assert_eq!(unpack(&settings, &bytes).unwrap(), payload);
                assert_eq!(bytes.len(), 1200 + settings.overhead());
                if settings.overhead() > 0 {
                    assert!(unpack(&settings, &bytes[..settings.overhead()]).is_none());
                }
            }
        }
    }
}
