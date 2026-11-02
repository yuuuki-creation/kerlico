use crate::error::cancelled;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use kerlico_core::{BoxFuture, BoxStream, CancellationToken, DeviceLease, Error, ServiceStatus};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tor_general_addr::unix;
use tor_rtcompat::{
    NetStreamListener, NetStreamProvider, StreamOps, TcpConnectOptions, TcpListenOptions,
    UdpProvider, UdpSocket, UnixConnectOptions, UnixListenOptions,
};

#[derive(Clone)]
pub(crate) struct CarrierProvider {
    device: DeviceLease,
    cancel: CancellationToken,
    status: ServiceStatus,
    timeout: Duration,
}

impl CarrierProvider {
    pub fn new(
        device: DeviceLease,
        cancel: CancellationToken,
        status: ServiceStatus,
        timeout: Duration,
    ) -> Self {
        Self {
            device,
            cancel,
            status,
            timeout,
        }
    }
    fn check(&self) -> io::Result<()> {
        service_check(&self.status)?;
        if self.cancel.is_cancelled() {
            Err(cancelled())
        } else {
            Ok(())
        }
    }
}

fn service_check(status: &ServiceStatus) -> io::Result<()> {
    match status.failure() {
        Some(failure) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            failure.error(),
        )),
        None => Ok(()),
    }
}

struct CarrierIo {
    stream: Compat<BoxStream>,
    status: ServiceStatus,
    read_cancel: BoxFuture<'static, ()>,
    write_cancel: BoxFuture<'static, ()>,
    read_stopped: bool,
    write_stopped: bool,
}

pub(crate) struct CarrierStream(Mutex<CarrierIo>);
impl CarrierStream {
    fn new(stream: BoxStream, cancel: &CancellationToken, status: ServiceStatus) -> Self {
        Self(Mutex::new(CarrierIo {
            stream: stream.compat(),
            status,
            read_cancel: Box::pin(cancel.clone().cancelled_owned()),
            write_cancel: Box::pin(cancel.clone().cancelled_owned()),
            read_stopped: false,
            write_stopped: false,
        }))
    }
    fn io(&mut self) -> io::Result<&mut CarrierIo> {
        self.0
            .get_mut()
            .map_err(|_| io::Error::other("Tor载体状态已损坏"))
    }
}

impl AsyncRead for CarrierStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let io = self.get_mut().io()?;
        service_check(&io.status)?;
        if io.read_stopped || io.read_cancel.as_mut().poll(cx).is_ready() {
            io.read_stopped = true;
            return Poll::Ready(Err(cancelled()));
        }
        Pin::new(&mut io.stream).poll_read(cx, buffer)
    }
}

impl CarrierIo {
    fn writable(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        service_check(&self.status)?;
        if self.write_stopped || self.write_cancel.as_mut().poll(cx).is_ready() {
            self.write_stopped = true;
            Err(cancelled())
        } else {
            Ok(())
        }
    }
}

impl AsyncWrite for CarrierStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let io = self.get_mut().io()?;
        io.writable(cx)?;
        Pin::new(&mut io.stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let io = self.get_mut().io()?;
        io.writable(cx)?;
        Pin::new(&mut io.stream).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let io = self.get_mut().io()?;
        io.writable(cx)?;
        Pin::new(&mut io.stream).poll_close(cx)
    }
}
impl StreamOps for CarrierStream {}

pub(crate) enum NoListener {}
impl<A: Send + Sync + Unpin + 'static> NetStreamListener<A> for NoListener {
    type Stream = CarrierStream;
    type Incoming = futures::stream::Empty<io::Result<(CarrierStream, A)>>;
    fn incoming(self) -> Self::Incoming {
        match self {}
    }
    fn local_addr(&self) -> io::Result<A> {
        match *self {}
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "Tor客户端未开放该载体能力")
}

#[async_trait]
impl NetStreamProvider<SocketAddr> for CarrierProvider {
    type Stream = CarrierStream;
    type Listener = NoListener;
    type ConnectOptions = TcpConnectOptions;
    type ListenOptions = TcpListenOptions;

    async fn connect(
        &self,
        address: &SocketAddr,
        options: &TcpConnectOptions,
    ) -> io::Result<CarrierStream> {
        if options != &TcpConnectOptions::default() {
            return Err(unsupported());
        }
        self.check()?;
        let result = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => { self.check()?; return Err(cancelled()); }
            result = tokio::time::timeout(self.timeout, self.device.connect_tcp(*address)) => result,
        };
        let opened = match result {
            Ok(Ok(opened)) => opened,
            Ok(Err(Error::Cancelled)) => return Err(cancelled()),
            Ok(Err(Error::Timeout)) | Err(_) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, Error::Timeout));
            }
            Ok(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "Tor载体连接失败",
                ));
            }
        };
        self.check()?;
        Ok(CarrierStream::new(
            opened.stream,
            &self.cancel,
            self.status.clone(),
        ))
    }
    async fn listen(&self, _: &SocketAddr, _: &TcpListenOptions) -> io::Result<NoListener> {
        Err(unsupported())
    }
}

#[async_trait]
impl NetStreamProvider<unix::SocketAddr> for CarrierProvider {
    type Stream = CarrierStream;
    type Listener = NoListener;
    type ConnectOptions = UnixConnectOptions;
    type ListenOptions = UnixListenOptions;
    async fn connect(
        &self,
        _: &unix::SocketAddr,
        _: &UnixConnectOptions,
    ) -> io::Result<CarrierStream> {
        Err(unsupported())
    }
    async fn listen(&self, _: &unix::SocketAddr, _: &UnixListenOptions) -> io::Result<NoListener> {
        Err(unsupported())
    }
}

pub(crate) enum NoUdp {}
#[async_trait]
impl UdpSocket for NoUdp {
    async fn recv(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match *self {}
    }
    async fn send(&self, _: &[u8], _: &SocketAddr) -> io::Result<usize> {
        match *self {}
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match *self {}
    }
}
#[async_trait]
impl UdpProvider for CarrierProvider {
    type UdpSocket = NoUdp;
    async fn bind(&self, _: &SocketAddr) -> io::Result<NoUdp> {
        Err(unsupported())
    }
}
