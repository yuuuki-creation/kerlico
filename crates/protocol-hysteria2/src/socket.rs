use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller, udp};
use rand::RngCore;
use std::{
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

struct Salamander {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Arc<String>,
    send: Mutex<Vec<u8>>,
    receive: Mutex<Vec<u8>>,
}
impl std::fmt::Debug for Salamander {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hysteria2SalamanderSocket")
    }
}
fn mask(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hash = Blake2b::<U32>::new();
    hash.update(password.as_bytes());
    hash.update(salt);
    hash.finalize().into()
}
pub(crate) fn wrap(
    socket: UdpSocket,
    password: Option<Arc<String>>,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let inner = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    Ok(match password {
        None => inner,
        Some(password) => Arc::new(Salamander {
            inner,
            password,
            send: Mutex::new(Vec::with_capacity(1500)),
            receive: Mutex::new(vec![0; 65536]),
        }),
    })
}
impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.contents.len() > 65499
            || transmit
                .segment_size
                .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander 数据报超出单包边界",
            ));
        }
        let mut salt = [0; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = mask(&self.password, &salt);
        let mut buffer = self
            .send
            .lock()
            .map_err(|_| io::Error::other("Salamander 状态不可用"))?;
        buffer.resize(transmit.contents.len() + 8, 0);
        buffer[..8].copy_from_slice(&salt);
        for (i, byte) in transmit.contents.iter().enumerate() {
            buffer[i + 8] = byte ^ key[i % 32];
        }
        self.inner.try_send(&udp::Transmit {
            contents: &buffer,
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
            .map_err(|_| io::Error::other("Salamander 状态不可用"))?;
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
        if stride <= 8 {
            info.len = 0;
            info.stride = 1;
            return Poll::Ready(Ok(1));
        }
        for start in (0..length).step_by(stride) {
            let end = (start + stride).min(length);
            if end - start <= 8 {
                continue;
            }
            let key = mask(&self.password, &scratch[start..start + 8]);
            for index in start + 8..end {
                scratch[written] = scratch[index] ^ key[(index - start - 8) % 32];
                written += 1;
            }
        }
        if written > output[0].len() {
            info.len = 0;
            info.stride = 1;
            return Poll::Ready(Ok(1));
        }
        output[0][..written].copy_from_slice(&scratch[..written]);
        info.len = written;
        info.stride = stride - 8;
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
