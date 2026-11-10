use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::{
    connect_advanced_tls_over, AdvancedTlsClientConfig, AdvancedTlsRead, AdvancedTlsWrite,
};

/// Dropping a pending handshake closes its socket.
#[cfg(test)]
pub(crate) async fn connect_async_tls(
    tcp: TcpStream,
    config: Arc<AdvancedTlsClientConfig>,
    server_name: &str,
) -> io::Result<AsyncTlsStream> {
    connect_async_masked(tcp, Some(config), server_name, &crate::finalmask::FinalMask::default()).await
}

pub(crate) async fn connect_async_masked(
    tcp: TcpStream,
    config: Option<Arc<AdvancedTlsClientConfig>>,
    server_name: &str,
    masks: &crate::finalmask::FinalMask,
) -> io::Result<AsyncTlsStream> {
    let stream = tcp.into_std()?;
    stream.set_nonblocking(false)?;
    let mut guard = HandshakeGuard(Some(stream.try_clone()?));
    let name = server_name.to_owned();
    let masks = masks.clone();
    let ready = Arc::new(OnceLock::new());
    let ready_io = ready.clone();
    let (read, write) = tokio::task::spawn_blocking(move || {
        let local = stream.local_addr()?;
        let peer = stream.peer_addr()?;
        let stream = Arc::new(stream);
        let reader = ReadySocket { blocking: stream.clone(), ready: ready_io.clone() };
        let writer = ReadySocket { blocking: stream, ready: ready_io };
        let (read, write) = masks.wrap_tcp((Box::new(reader), Box::new(writer)), local, peer, crate::finalmask::Side::Client)?;
        match config {
            Some(config) => {
                let (read, write) = connect_advanced_tls_over(read, write, config, &name)?;
                Ok::<_, io::Error>((StreamRead::Tls(read), StreamWrite::Tls(write)))
            }
            None => Ok((StreamRead::Plain(read), StreamWrite::Plain(write))),
        }
    })
    .await
    .map_err(io::Error::other)??;
    let stream = guard.0.take().expect("completed async TLS handshake");
    stream.set_nonblocking(true)?;
    let socket = Arc::new(TcpStream::from_std(stream)?);
    let _ = ready.set(socket.clone());
    Ok(AsyncTlsStream {
        read,
        write,
        socket: Some(socket),
        retry: None,
        network: None,
    })
}

pub(crate) async fn connect_async_network(
    connection: kerlico_shared::runtime::NetworkConnection,
    config: Option<Arc<AdvancedTlsClientConfig>>,
    server_name: &str,
    masks: &crate::finalmask::FinalMask,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
) -> io::Result<AsyncTlsStream> {
    if let kerlico_shared::runtime::NetworkConnection::Tcp(socket) = connection {
        socket.set_nonblocking(true)?;
        return connect_async_masked(TcpStream::from_std(socket)?, config, server_name, masks).await;
    }
    let state = Arc::new(NetworkState { ready: AtomicBool::new(false), canceled: AtomicBool::new(false), deadline: Instant::now() + Duration::from_secs(10) });
    let mut guard = NetworkGuard { state: state.clone(), armed: true };
    let (read, write) = connection.split()?;
    let reader = NetworkReader { inner: read, state: state.clone() };
    let writer = NetworkWriter { inner: write, state: state.clone() };
    let masks = masks.clone();
    let name = server_name.to_owned();
    let (read, write) = tokio::task::spawn_blocking(move || {
        let (read, write) = masks.wrap_tcp((Box::new(reader), Box::new(writer)), local, peer, crate::finalmask::Side::Client)?;
        match config {
            Some(config) => {
                let (read, write) = connect_advanced_tls_over(read, write, config, &name)?;
                Ok::<_, io::Error>((StreamRead::Tls(read), StreamWrite::Tls(write)))
            }
            None => Ok((StreamRead::Plain(read), StreamWrite::Plain(write))),
        }
    }).await.map_err(io::Error::other)??;
    state.ready.store(true, Ordering::Release);
    guard.armed = false;
    Ok(AsyncTlsStream { socket: None, read, write, retry: None, network: Some(state) })
}

struct NetworkState { ready: AtomicBool, canceled: AtomicBool, deadline: Instant }
struct NetworkGuard { state: Arc<NetworkState>, armed: bool }
impl Drop for NetworkGuard { fn drop(&mut self) { if self.armed { self.state.canceled.store(true, Ordering::Release); } } }
struct NetworkReader { inner: Box<dyn kerlico_shared::runtime::NetworkRead>, state: Arc<NetworkState> }
struct NetworkWriter { inner: Box<dyn kerlico_shared::runtime::NetworkWrite>, state: Arc<NetworkState> }

fn network_io<T>(state: &NetworkState, mut operation: impl FnMut(Duration) -> io::Result<T>) -> io::Result<T> {
    let ready = state.ready.load(Ordering::Acquire);
    let poll = if ready { Duration::from_millis(1) } else { Duration::from_millis(50) };
    loop {
        if state.canceled.load(Ordering::Acquire) { return Err(io::ErrorKind::BrokenPipe.into()); }
        match operation(poll) {
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if ready { return Err(io::ErrorKind::WouldBlock.into()); }
                if Instant::now() >= state.deadline { return Err(io::Error::new(io::ErrorKind::TimedOut, "carrier TLS handshake timed out")); }
            }
            result => return result,
        }
    }
}
impl Read for NetworkReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> { network_io(&self.state, |timeout| { self.inner.set_timeout(timeout)?; self.inner.read(bytes) }) }
}
impl Write for NetworkWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { network_io(&self.state, |timeout| { self.inner.set_timeout(timeout)?; self.inner.write(bytes) }) }
    fn flush(&mut self) -> io::Result<()> { network_io(&self.state, |timeout| { self.inner.set_timeout(timeout)?; self.inner.flush() }) }
}

struct HandshakeGuard(Option<StdTcpStream>);

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        if let Some(stream) = self.0.as_ref() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

struct ReadySocket {
    blocking: Arc<StdTcpStream>,
    ready: Arc<OnceLock<Arc<TcpStream>>>,
}

impl Read for ReadySocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.ready.get() {
            Some(socket) => socket.try_read(buf),
            None => (&*self.blocking).read(buf),
        }
    }
}

impl Write for ReadySocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.ready.get() {
            Some(socket) => socket.try_write(buf),
            None => (&*self.blocking).write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct AsyncTlsStream {
    socket: Option<Arc<TcpStream>>,
    read: StreamRead,
    write: StreamWrite,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
    network: Option<Arc<NetworkState>>,
}

impl Drop for AsyncTlsStream {
    fn drop(&mut self) { if let Some(state) = &self.network { state.canceled.store(true, Ordering::Release); } }
}

enum StreamRead {
    Plain(Box<dyn Read + Send>),
    Tls(AdvancedTlsRead<Box<dyn Read + Send>>),
}

enum StreamWrite {
    Plain(Box<dyn Write + Send>),
    Tls(AdvancedTlsWrite<Box<dyn Write + Send>>),
}

impl Read for StreamRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self { Self::Plain(read) => read.read(buf), Self::Tls(read) => read.read(buf) }
    }
}

impl Write for StreamWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self { Self::Plain(write) => write.write(buf), Self::Tls(write) => write.write(buf) }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self { Self::Plain(write) => write.flush(), Self::Tls(write) => write.flush() }
    }
}

impl AsyncTlsStream {
    fn poll_ready(&mut self, cx: &mut Context<'_>, write: bool) -> Poll<io::Result<()>> {
        if let Some(socket) = &self.socket { return if write { socket.poll_write_ready(cx) } else { socket.poll_read_ready(cx) }; }
        use std::future::Future;
        let sleep = self.retry.get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_millis(2))));
        ready!(sleep.as_mut().poll(cx));
        self.retry = None;
        Poll::Ready(Ok(()))
    }
    pub(crate) fn alpn(&self) -> Option<Vec<u8>> {
        match &self.read { StreamRead::Tls(read) => read.alpn(), StreamRead::Plain(_) => None }
    }
}

impl AsyncRead for AsyncTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read.read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if matches!(&self.read, StreamRead::Tls(read) if read.needs_write()) {
                        ready!(self.poll_ready(cx, true))?;
                    } else {
                        ready!(self.poll_ready(cx, false))?;
                    }
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl AsyncWrite for AsyncTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write.write(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_ready(cx, true))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.write.flush() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.poll_ready(cx, true))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Poll::Ready(match &self.socket { Some(socket) => socket2::SockRef::from(socket.as_ref()).shutdown(Shutdown::Write), None => Ok(()) })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use crate::{advanced_client_config, AdvancedTlsOptions};

    use super::*;

    #[tokio::test]
    async fn canceling_a_stalled_handshake_closes_its_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let options = AdvancedTlsOptions {
            fingerprint: "unsafe".into(),
            ..Default::default()
        };
        let config = advanced_client_config(&options).unwrap();
        let mut handshake = Box::pin(connect_async_tls(socket, config, "localhost"));
        let mut header = [0; 5];
        timeout(Duration::from_secs(2), async {
            tokio::select! {
                result = &mut handshake => assert!(result.is_ok(), "TLS handshake exited before cancellation"),
                read = peer.read_exact(&mut header) => { read.unwrap(); }
            }
        }).await.unwrap();
        assert_eq!(header[0], 0x16);
        drop(handshake);
        let mut remaining = Vec::new();
        timeout(Duration::from_secs(2), peer.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            remaining.len(),
            usize::from(u16::from_be_bytes([header[3], header[4]]))
        );
    }
}
