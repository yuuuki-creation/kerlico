use std::future::Future;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use quinn::{Endpoint, EndpointConfig, RecvStream, SendStream, TokioRuntime, VarInt};
use tokio::runtime::Runtime;

pub fn runtime() -> io::Result<&'static Runtime> {
    static RUNTIME: OnceLock<io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))
}

pub fn block<T>(wait: Duration, op: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    runtime()?.block_on(async {
        tokio::time::timeout(wait, op)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    })
}

pub fn listen_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub fn endpoint(
    socket: UdpSocket,
    config: EndpointConfig,
    server: Option<quinn::ServerConfig>,
    obfs: Option<&crate::obfs::Salamander>,
) -> io::Result<Endpoint> {
    let _guard = runtime()?.enter();
    if let Some(obfs) = obfs {
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        packet_endpoint(Arc::new(socket), config, server, Some(obfs))
    } else {
        Endpoint::new(config, server, socket, Arc::new(TokioRuntime))
    }
}

pub fn packet_endpoint(
    packets: Arc<dyn kerlico_shared::runtime::PacketIo>,
    config: EndpointConfig,
    server: Option<quinn::ServerConfig>,
    obfs: Option<&crate::obfs::Salamander>,
) -> io::Result<Endpoint> {
    let _guard = runtime()?.enter();
    let packets = if let Some(obfs) = obfs {
        obfs.wrap(packets)
    } else {
        packets
    };
    Endpoint::new_with_abstract_socket(
        config,
        server,
        super::MaskedSocket::new(packets)?,
        Arc::new(TokioRuntime),
    )
}

pub struct Duplex {
    recv: Mutex<RecvStream>,
    send: Mutex<SendStream>,
    cancelled: tokio::sync::watch::Sender<bool>,
}

impl Duplex {
    pub fn new(recv: RecvStream, send: SendStream) -> Self {
        Self {
            recv: Mutex::new(recv),
            send: Mutex::new(send),
            cancelled: tokio::sync::watch::Sender::new(false),
        }
    }

    pub fn read(&self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
        let mut recv = self.recv.lock().expect("Hy2 receive stream");
        let mut cancel = self.cancelled.subscribe();
        block(wait, async {
            tokio::select! {
                biased;
                _ = cancel.wait_for(|yes| *yes) => Ok(0),
                value = recv.read(buf) => Ok(value?.unwrap_or(0)),
            }
        })
    }

    pub fn write(&self, buf: &[u8], wait: Duration) -> io::Result<()> {
        let mut send = self.send.lock().expect("Hy2 send stream");
        let mut cancel = self.cancelled.subscribe();
        block(wait, async {
            tokio::select! {
                biased;
                _ = cancel.wait_for(|yes| *yes) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                result = send.write_all(buf) => result.map_err(Into::into),
            }
        })
    }

    pub fn finish(&self) -> io::Result<()> {
        self.send
            .lock()
            .expect("Hy2 send stream")
            .finish()
            .map_err(io::Error::other)
    }

    pub fn close(&self) {
        self.cancelled.send_replace(true);
        let _ = self
            .recv
            .lock()
            .expect("Hy2 receive stream")
            .stop(VarInt::from_u32(0));
        let _ = self.finish();
    }
}
