//! h2mux：每条逻辑流是一个 HTTP/2 `CONNECT` 请求（`:authority localhost`），
//! 请求体为上行、`200` 响应体为下行，与 sing-mux 的 Go `x/net/http2` 实现互通。

use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream, client::ResponseFuture};
use http::{Method, Request, Response, StatusCode, Uri};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

const STREAM_WINDOW: u32 = 4 * 1024 * 1024;
const CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;
const WRITE_CHUNK: usize = 64 * 1024;

fn h2_error(err: h2::Error) -> io::Error {
    if err.is_io() {
        return err
            .into_io()
            .unwrap_or_else(|| io::ErrorKind::BrokenPipe.into());
    }
    io::Error::new(io::ErrorKind::ConnectionReset, err)
}

#[derive(Clone)]
pub(super) struct H2Client {
    send: h2::client::SendRequest<Bytes>,
    closed: CancellationToken,
}

impl H2Client {
    pub async fn connect<S>(io: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (send, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(h2_error)?;
        let closed = CancellationToken::new();
        let done = closed.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = connection => {}
                _ = done.cancelled() => {}
            }
            done.cancel();
        });
        Ok(Self { send, closed })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub fn close(&self) {
        self.closed.cancel();
    }

    pub async fn open(&self) -> io::Result<H2Stream> {
        let mut send = self.send.clone().ready().await.map_err(|err| {
            self.closed.cancel();
            h2_error(err)
        })?;
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(
                Uri::builder()
                    .authority("localhost")
                    .build()
                    .expect("合法 authority"),
            )
            .body(())
            .expect("合法 CONNECT 请求");
        let (response, stream) = send.send_request(request, false).map_err(h2_error)?;
        Ok(H2Stream {
            send: stream,
            recv: Recv::Response(response),
            pending: Bytes::new(),
            write_closed: false,
        })
    }
}

/// 服务端：逐个接受 `CONNECT` 流并立即回 `200`，直到对端关闭或取消。
pub(super) async fn serve<S>(
    io: S,
    cancel: CancellationToken,
    mut on_stream: impl FnMut(H2Stream),
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut connection = h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(h2_error)?;
    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            next = connection.accept() => next,
        };
        let Some(next) = next else {
            return Ok(());
        };
        let (request, mut respond) = next.map_err(h2_error)?;
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .expect("合法响应");
        let Ok(send) = respond.send_response(response, false) else {
            continue;
        };
        on_stream(H2Stream {
            send,
            recv: Recv::Body(request.into_body()),
            pending: Bytes::new(),
            write_closed: false,
        });
    }
}

enum Recv {
    Response(ResponseFuture),
    Body(RecvStream),
    Eof,
}

pub(super) struct H2Stream {
    send: SendStream<Bytes>,
    recv: Recv,
    pending: Bytes,
    write_closed: bool,
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match &mut this.recv {
                Recv::Response(response) => {
                    let response = ready!(Pin::new(response).poll(cx)).map_err(h2_error)?;
                    if response.status() != StatusCode::OK {
                        this.recv = Recv::Eof;
                        return Poll::Ready(Err(io::Error::other(format!(
                            "h2mux 远端返回状态 {}",
                            response.status()
                        ))));
                    }
                    this.recv = Recv::Body(response.into_body());
                }
                Recv::Body(body) => match ready!(body.poll_data(cx)) {
                    Some(Ok(data)) => {
                        let _ = body.flow_control().release_capacity(data.len());
                        this.pending = data;
                    }
                    Some(Err(err)) if err.reason() == Some(Reason::NO_ERROR) => {
                        this.recv = Recv::Eof;
                    }
                    Some(Err(err)) => return Poll::Ready(Err(h2_error(err))),
                    None => this.recv = Recv::Eof,
                },
                Recv::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(buf.len().min(WRITE_CHUNK));
        match ready!(this.send.poll_capacity(cx)) {
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Some(Err(err)) => Poll::Ready(Err(h2_error(err))),
            Some(Ok(0)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Some(Ok(capacity)) => {
                let n = capacity.min(buf.len());
                this.send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(h2_error)?;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.write_closed = true;
            this.send.reserve_capacity(0);
            let _ = this.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        if !self.write_closed {
            self.send.reserve_capacity(0);
            let _ = self.send.send_data(Bytes::new(), true);
        }
    }
}
