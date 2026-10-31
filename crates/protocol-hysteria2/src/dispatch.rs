use bytes::{Buf, Bytes};
use futures_util::{StreamExt, stream::FuturesUnordered};
use h3::quic::{self, RecvStream as _, SendStream as _};
use kerlico_core::{InboundContext, NodeEvent, StreamLease};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

pub(crate) struct Bi {
    inner: h3_quinn::BidiStream<Bytes>,
    prefix: Bytes,
    lease: Option<Arc<StreamLease>>,
}
impl Bi {
    fn new(inner: h3_quinn::BidiStream<Bytes>, lease: Option<Arc<StreamLease>>) -> Self {
        Self {
            inner,
            prefix: Bytes::new(),
            lease,
        }
    }
    fn reject(&mut self) {
        self.inner.reset(0x10c);
        self.inner.stop_sending(0x10c);
    }
}
impl quic::SendStream<Bytes> for Bi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }
    fn send_data<T: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), quic::StreamErrorIncoming> {
        self.inner.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }
    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}
impl quic::RecvStream for Bi {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            return Poll::Ready(Ok(Some(std::mem::take(&mut self.prefix))));
        }
        self.inner.poll_data(cx)
    }
    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }
    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}
pub(crate) struct WriteHalf {
    inner: h3_quinn::SendStream<Bytes>,
    _lease: Option<Arc<StreamLease>>,
}
pub(crate) struct ReadHalf {
    inner: h3_quinn::RecvStream,
    prefix: Bytes,
    _lease: Option<Arc<StreamLease>>,
}
impl quic::BidiStream<Bytes> for Bi {
    type SendStream = WriteHalf;
    type RecvStream = ReadHalf;
    fn split(self) -> (WriteHalf, ReadHalf) {
        let (send, receive) = self.inner.split();
        (
            WriteHalf {
                inner: send,
                _lease: self.lease.clone(),
            },
            ReadHalf {
                inner: receive,
                prefix: self.prefix,
                _lease: self.lease,
            },
        )
    }
}
impl quic::SendStream<Bytes> for WriteHalf {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }
    fn send_data<T: Into<quic::WriteBuf<Bytes>>>(
        &mut self,
        data: T,
    ) -> Result<(), quic::StreamErrorIncoming> {
        self.inner.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), quic::StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }
    fn send_id(&self) -> quic::StreamId {
        self.inner.send_id()
    }
}
impl quic::RecvStream for ReadHalf {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            return Poll::Ready(Ok(Some(std::mem::take(&mut self.prefix))));
        }
        self.inner.poll_data(cx)
    }
    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }
    fn recv_id(&self) -> quic::StreamId {
        self.inner.recv_id()
    }
}
fn io_error(_: quic::StreamErrorIncoming) -> io::Error {
    io::Error::other("Hysteria2 QUIC 流已结束")
}
impl AsyncRead for Bi {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.prefix.is_empty() {
            match std::task::ready!(this.inner.poll_data(cx)).map_err(io_error)? {
                None => return Poll::Ready(Ok(())),
                Some(bytes) => this.prefix = bytes,
            }
        }
        let count = out.remaining().min(this.prefix.len());
        out.put_slice(&this.prefix[..count]);
        this.prefix.advance(count);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Bi {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.inner.poll_ready(cx)).map_err(io_error)?;
        let mut input = data;
        quic::SendStreamUnframed::poll_send(&mut this.inner, cx, &mut input).map_err(io_error)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.inner.poll_ready(cx)).map_err(io_error)?;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        self.get_mut().inner.poll_finish(cx).map_err(io_error)
    }
}
pub(crate) struct Open(h3_quinn::OpenStreams);
impl quic::OpenStreams<Bytes> for Open {
    type BidiStream = Bi;
    type SendStream = h3_quinn::SendStream<Bytes>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bi, quic::StreamErrorIncoming>> {
        self.0
            .poll_open_bidi(cx)
            .map_ok(|inner| Bi::new(inner, None))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.0.poll_open_send(cx)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::close(&mut self.0, code, reason);
    }
}
type Sniff = Pin<Box<dyn Future<Output = Option<(u64, Bi)>> + Send>>;
pub(crate) struct Connection {
    inner: h3_quinn::Connection,
    sniffers: FuturesUnordered<Sniff>,
    proxy: mpsc::Sender<Bi>,
    authenticated: Arc<AtomicBool>,
    context: InboundContext,
}
impl Connection {
    pub(crate) fn new(
        connection: quinn::Connection,
        proxy: mpsc::Sender<Bi>,
        authenticated: Arc<AtomicBool>,
        context: InboundContext,
    ) -> Self {
        Self {
            inner: h3_quinn::Connection::new(connection),
            sniffers: FuturesUnordered::new(),
            proxy,
            authenticated,
            context,
        }
    }
}
impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = Bi;
    type SendStream = h3_quinn::SendStream<Bytes>;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bi, quic::StreamErrorIncoming>> {
        self.inner
            .poll_open_bidi(cx)
            .map_ok(|inner| Bi::new(inner, None))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, quic::StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }
    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}
impl quic::Connection<Bytes> for Connection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Open;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, quic::ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
    }
    fn opener(&self) -> Open {
        Open(<h3_quinn::Connection as quic::Connection<Bytes>>::opener(
            &self.inner,
        ))
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bi, quic::ConnectionErrorIncoming>> {
        let mut accepted = 0;
        for _ in 0..64 {
            match self.inner.poll_accept_bidi(cx) {
                Poll::Ready(Ok(mut inner)) => {
                    accepted += 1;
                    let Ok(lease) = self.context.stream_budget.try_acquire() else {
                        inner.reset(0x107);
                        inner.stop_sending(0x107);
                        self.context.events.record(NodeEvent::Dropped);
                        continue;
                    };
                    let deadline = self.context.connect_timeout;
                    let cancel = self.context.cancel.clone();
                    self.sniffers.push(Box::pin(async move {
                        let mut stream=Bi::new(inner,Some(Arc::new(lease)));
                        let classified=async {
                            let mut bytes=Vec::new();loop {
                                if let Some(first)=bytes.first().copied() { let width=1usize<<(first>>6);if bytes.len()>=width {let mut value=u64::from(first&63);for byte in &bytes[1..width] {value=value<<8|u64::from(*byte);}stream.prefix=Bytes::from(bytes);return Ok::<_,()>(value);} }
                                let Some(data)=std::future::poll_fn(|cx| stream.inner.poll_data(cx)).await.map_err(|_|())? else{return Err(());};
                                if bytes.len()+data.len()>65536{return Err(());}bytes.extend_from_slice(&data);
                            }
                        };
                        let value=tokio::select!{_ = cancel.cancelled()=>None,result=tokio::time::timeout(deadline,classified)=>result.ok().and_then(Result::ok)};
                        match value {Some(value)=>Some((value,stream)),None=>{stream.reject();None}}
                    }));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => break,
            }
        }
        if accepted == 64 {
            cx.waker().wake_by_ref();
        }
        loop {
            match self.sniffers.poll_next_unpin(cx) {
                Poll::Ready(Some(Some((kind, stream)))) => {
                    if kind == crate::wire::TCP_ID && self.authenticated.load(Ordering::Acquire) {
                        match self.proxy.try_send(stream) {
                            Ok(()) => {}
                            Err(error) => {
                                let mut stream = error.into_inner();
                                stream.reject();
                                self.context.events.record(NodeEvent::Dropped);
                            }
                        }
                    } else {
                        return Poll::Ready(Ok(stream));
                    }
                }
                Poll::Ready(Some(None)) => {}
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            }
        }
    }
}
