//! Move an established native TCP/TLS stack onto readiness-driven I/O.
//! The existing VLESS response, prefetch and TLS record states stay in place.

use std::future::Future;
use std::io::{self, IoSlice, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use kerlico_shared::{AsyncBufReadVectored, AsyncReadHalf, AsyncTcp, PlaneFault};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use super::{Link, Stream};

pub(super) fn take(stream: &mut Stream) -> Result<Option<AsyncTcp>, PlaneFault> {
    if stream.plain_udp.is_some() {
        return Ok(None);
    }
    let read = stream.read.get_mut().expect("VLESS read ownership");
    let write = stream.write.get_mut().expect("VLESS write ownership");
    let Some(reader) = native_socket(read, false).map_err(super::map_io)? else {
        return Ok(None);
    };
    let Some(writer) = native_socket(write, true).map_err(super::map_io)? else {
        return Ok(None);
    };
    if reader.local_addr().map_err(super::map_io)? != writer.local_addr().map_err(super::map_io)?
        || reader.peer_addr().map_err(super::map_io)?
            != writer.peer_addr().map_err(super::map_io)?
    {
        return Err(PlaneFault::Transport);
    }
    let executor = kerlico_vless::io_executor().map_err(super::map_io)?;
    // A failed registration is a failed transfer, not a fall-back to a socket
    // whose blocking mode has already changed. The owner closes both ends.
    reader.set_nonblocking(true).map_err(super::map_io)?;
    let socket = {
        let _entered = executor.enter();
        Arc::new(tokio::net::TcpStream::from_std(reader).map_err(super::map_io)?)
    };
    promote(read, &socket);
    promote(write, &socket);
    let read = std::mem::replace(read, Link::Closed);
    let write = std::mem::replace(write, Link::Closed);
    Ok(Some(AsyncTcp {
        executor,
        read: read_half(read, socket.clone()),
        write: kerlico_shared::AsyncWriteHalf::plain(Writer {
            link: write,
            socket,
            shutdown: writer,
            closed: false,
        }),
    }))
}

fn native_socket(link: &mut Link, write: bool) -> io::Result<Option<TcpStream>> {
    match link {
        Link::Tcp(socket) => socket.try_clone().map(Some),
        Link::Prefix(inner, _) | Link::Response(inner, _) => native_socket(inner, write),
        Link::TlsRead(tls) if !write => match tls.inner_mut().as_ref() {
            Link::Tcp(socket) => socket.try_clone().map(Some),
            _ => Ok(None),
        },
        Link::TlsWrite(tls) if write => match tls.inner_mut().as_ref() {
            Link::Tcp(socket) => socket.try_clone().map(Some),
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

fn promote(link: &mut Link, socket: &Arc<tokio::net::TcpStream>) {
    match link {
        Link::Tcp(_) => *link = Link::ReadyTcp(socket.clone()),
        Link::Prefix(inner, _) | Link::Response(inner, _) => promote(inner, socket),
        Link::TlsRead(tls) => promote(tls.inner_mut(), socket),
        Link::TlsWrite(tls) => promote(&mut tls.inner_mut(), socket),
        _ => unreachable!("native TCP stack checked before transferring ownership"),
    }
}

fn needs_write(link: &Link) -> bool {
    match link {
        Link::TlsRead(tls) => tls.needs_write(),
        Link::Prefix(inner, _) | Link::Response(inner, _) => needs_write(inner),
        _ => false,
    }
}

fn close_notify(link: &mut Link) -> io::Result<()> {
    match link {
        Link::TlsWrite(tls) => tls.send_close_notify(),
        Link::Prefix(inner, _) | Link::Response(inner, _) => close_notify(inner),
        Link::ReadyTcp(_) => Ok(()),
        _ => unreachable!("native writer stack"),
    }
}

fn read_half(link: Link, socket: Arc<tokio::net::TcpStream>) -> AsyncReadHalf {
    match link {
        Link::Prefix(inner, prefix) => {
            let mut read = read_half(*inner, socket);
            read.prepend(prefix.into_iter().collect());
            read
        }
        Link::TlsRead(tls) if tls.has_buffered_records() => {
            AsyncReadHalf::Vectored(Box::new(TlsRecords {
                tls,
                socket,
                writable: None,
                ended: false,
            }))
        }
        link => AsyncReadHalf::Plain(Box::new(Reader {
            link,
            socket,
            writable: None,
            ended: false,
            pending_error: None,
        })),
    }
}

type Writable = Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>;

fn wait_ready(
    socket: &Arc<tokio::net::TcpStream>,
    writable: &mut Writable,
    write: bool,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if write {
        // A control reply has its own waiter; poll_write_ready would replace
        // the application writer's waker when halves run on separate tasks.
        if writable.is_none() {
            let socket = socket.clone();
            *writable = Some(Box::pin(async move { socket.writable().await }));
        }
        ready!(writable
            .as_mut()
            .expect("control readiness")
            .as_mut()
            .poll(cx))?;
        *writable = None;
    } else {
        *writable = None;
        ready!(socket.poll_read_ready(cx))?;
    }
    Poll::Ready(Ok(()))
}

struct TlsRecords {
    tls: Box<kerlico_vless::AdvancedTlsRead<Box<Link>>>,
    socket: Arc<tokio::net::TcpStream>,
    writable: Writable,
    ended: bool,
}

impl TlsRecords {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ended {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.tls.prepare_nonblocking_records() {
                Ok(()) => {
                    self.writable = None;
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(wait_ready(
                        &self.socket,
                        &mut self.writable,
                        self.tls.needs_write(),
                        cx
                    ))?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    self.ended = true;
                    return Poll::Ready(Ok(()));
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl AsyncBufReadVectored for TlsRecords {
    fn poll_fill_buf_vectored<'a>(
        self: Pin<&'a mut Self>,
        cx: &mut Context<'_>,
        slices: &mut [IoSlice<'a>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_ready(cx))?;
        Poll::Ready(Ok(this.tls.buffered_records(slices)))
    }
}

impl AsyncBufRead for TlsRecords {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        ready!(this.poll_ready(cx))?;
        Poll::Ready(Ok(this.tls.buffered_record()))
    }
    fn consume(self: Pin<&mut Self>, n: usize) {
        self.get_mut().tls.consume_records(n);
    }
}

impl AsyncRead for TlsRecords {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let bytes = ready!(self.as_mut().poll_fill_buf(cx))?;
        let n = bytes.len().min(out.remaining());
        out.put_slice(&bytes[..n]);
        self.consume(n);
        Poll::Ready(Ok(()))
    }
}

struct Reader {
    link: Link,
    socket: Arc<tokio::net::TcpStream>,
    writable: Writable,
    ended: bool,
    pending_error: Option<io::Error>,
}

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(error) = self.pending_error.take() {
            return Poll::Ready(Err(error));
        }
        if self.ended {
            return Poll::Ready(Ok(()));
        }
        let start = out.filled().len();
        loop {
            match self.link.read(out.initialize_unfilled()) {
                Ok(0) => {
                    self.ended = true;
                    return Poll::Ready(Ok(()));
                }
                Ok(n) => {
                    self.writable = None;
                    out.advance(n);
                    if out.remaining() == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if out.filled().len() != start {
                        // Hand off all currently ready bytes before waiting
                        // for more input or a pending TLS control write.
                        return Poll::Ready(Ok(()));
                    }
                    let this = &mut *self;
                    ready!(wait_ready(
                        &this.socket,
                        &mut this.writable,
                        needs_write(&this.link),
                        cx
                    ))?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    self.ended = true;
                    return Poll::Ready(Ok(()));
                }
                Err(error) => {
                    if out.filled().len() == start {
                        return Poll::Ready(Err(error));
                    }
                    self.pending_error = Some(error);
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

struct Writer {
    link: Link,
    socket: Arc<tokio::net::TcpStream>,
    shutdown: TcpStream,
    closed: bool,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        loop {
            match self.link.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.socket.poll_write_ready(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.link.flush() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.socket.poll_write_ready(cx))?;
                }
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        loop {
            match close_notify(&mut self.link) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    ready!(self.socket.poll_write_ready(cx))?;
                }
                Err(error) => return Poll::Ready(Err(error)),
                Ok(()) => {
                    self.shutdown.shutdown(Shutdown::Write)?;
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_shared::{InboundStream, Settings};
    use std::net::TcpListener;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn ready_prefix_is_delivered_before_a_later_read_error() {
        let executor = kerlico_vless::io_executor().unwrap();
        let _entered = executor.enter();
        let socket: TcpStream = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap()
        .into();
        socket.set_nonblocking(true).unwrap();
        let socket = Arc::new(tokio::net::TcpStream::from_std(socket).unwrap());
        let mut read = Reader {
            link: Link::Prefix(
                Box::new(Link::ReadyTcp(socket.clone())),
                b"ready bytes".to_vec().into(),
            ),
            socket,
            writable: None,
            ended: false,
            pending_error: None,
        };
        let mut bytes = [0; 64];
        let mut out = ReadBuf::new(&mut bytes);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Pin::new(&mut read).poll_read(&mut cx, &mut out),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(out.filled(), b"ready bytes");
        let error = executor.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), read.read(&mut bytes))
                .await
                .unwrap()
                .unwrap_err()
        });
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn native_and_tls_transfer_preserves_prefetch_backpressure_response_and_half_close() {
        for version in [None, Some("1.0"), Some("1.1"), Some("1.2"), Some("1.3")] {
            exercise(version);
        }
    }

    fn exercise(version: Option<&str>) {
        eprintln!("native asynchronous ownership / TLS {version:?}");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (client_config, server_config) = if let Some(version) = version {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let mut settings = Settings::default();
            settings.insert_text("certificate", cert.cert.pem());
            settings.insert_text("key", cert.key_pair.serialize_pem());
            settings.insert_text("minVersion", version);
            settings.insert_text("maxVersion", version);
            let server = super::super::tls_server_config(&settings, &[]).unwrap();
            settings.insert_text("allowInsecure", "true");
            settings.insert_text("fingerprint", "unsafe");
            let options = kerlico_vless::AdvancedTlsOptions::from_settings(
                |key| settings.text(key).ok(),
                Vec::new(),
            )
            .unwrap();
            (
                Some(kerlico_vless::advanced_client_config(&options).unwrap()),
                Some(server),
            )
        } else {
            (None, None)
        };
        let payload = vec![53; 256 * 1024 + 13];
        let expected = payload.clone();
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let client = std::thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            socket.set_nodelay(true).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket2::SockRef::from(&socket)
                .set_recv_buffer_size(4096)
                .unwrap();
            let (mut read, mut write): (Box<dyn Read>, Box<dyn Write>) =
                if let Some(config) = client_config {
                    let (read, write) = kerlico_vless::connect_advanced_tls_over(
                        socket.try_clone().unwrap(),
                        socket.try_clone().unwrap(),
                        config,
                        "localhost",
                    )
                    .unwrap();
                    (Box::new(read), Box::new(write))
                } else {
                    (
                        Box::new(socket.try_clone().unwrap()),
                        Box::new(socket.try_clone().unwrap()),
                    )
                };
            socket
                .set_read_timeout(Some(Duration::from_millis(40)))
                .unwrap();
            let error = read.read(&mut [0]).unwrap_err();
            assert!(matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ));
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            write.write_all(b"later").unwrap();
            write.flush().unwrap();
            released.recv_timeout(Duration::from_secs(10)).unwrap();
            socket2::SockRef::from(&socket)
                .set_recv_buffer_size(1024 * 1024)
                .unwrap();
            let mut response = Vec::new();
            read.read_to_end(&mut response).unwrap();
            assert_eq!(&response[..2], &[0, 0]);
            assert_eq!(&response[2..], expected);
            write.write_all(b"after-half-close").unwrap();
            write.flush().unwrap();
            socket.shutdown(Shutdown::Write).unwrap();
        });
        let (socket, _) = listener.accept().unwrap();
        socket.set_nodelay(true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket2::SockRef::from(&socket)
            .set_send_buffer_size(4096)
            .unwrap();
        let control = socket.try_clone().unwrap();
        let (read, write) = if let Some(config) = server_config {
            let (read, write) = kerlico_vless::accept_advanced_tls_over(
                Box::new(Link::Tcp(socket.try_clone().unwrap())),
                Box::new(Link::Tcp(socket)),
                config,
            )
            .unwrap();
            (
                Link::TlsRead(Box::new(read)),
                Link::TlsWrite(Box::new(write)),
            )
        } else {
            (Link::Tcp(socket.try_clone().unwrap()), Link::Tcp(socket))
        };
        let mut stream = Stream::new(
            read,
            Link::Response(Box::new(write), vec![0, 0]),
            false,
            b"early".to_vec(),
        );
        let native = stream.take_async_tcp().unwrap().unwrap();
        assert!(stream.take_async_tcp().unwrap().is_none());
        assert_eq!(stream.read_from_user(&mut [0]), Err(PlaneFault::Closed));
        drop(stream);
        let executor = native.executor.clone();
        executor.block_on(async move {
            tokio::time::timeout(Duration::from_secs(15), async move {
                let mut read = native.read.into_buffered(8192);
                let mut write = native.write;
                let mut first = [0; 10];
                read.read_exact(&mut first).await.unwrap();
                assert_eq!(&first, b"earlylater");
                let mut sending = Box::pin(write.write_all(&payload));
                assert!(
                    tokio::time::timeout(Duration::from_millis(40), &mut sending)
                        .await
                        .is_err(),
                    "fixture did not produce write backpressure"
                );
                socket2::SockRef::from(&control)
                    .set_send_buffer_size(1024 * 1024)
                    .unwrap();
                release.send(()).unwrap();
                sending.await.unwrap();
                write.shutdown().await.unwrap();
                let mut remainder = Vec::new();
                read.read_to_end(&mut remainder).await.unwrap();
                assert_eq!(remainder, b"after-half-close");
            })
            .await
            .unwrap();
        });
        client.join().unwrap();
    }
}
