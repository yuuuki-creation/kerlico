//! HTTP DATA 到字节流的有界适配；写入等待流控，shutdown 在最后一段之后发 FIN。
use bytes::{Buf, Bytes};
use kerlico_core::{BoxFuture, BoxStream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub(crate) type H3ClientSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(crate) type H3ServerSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(crate) type H3Server = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
pub(crate) enum Writer {
    H2(h2::SendStream<Bytes>),
    Client(H3ClientSend),
    Server(H3ServerSend),
}
pub(crate) enum Reader {
    H2(h2::RecvStream),
    Client(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>),
    Server(h3::server::RequestStream<h3_quinn::RecvStream, Bytes>),
}
fn error() -> io::Error {
    io::Error::other("TrustTunnel HTTP 流失败")
}
impl Writer {
    async fn data(&mut self, mut bytes: Bytes) -> io::Result<()> {
        match self {
            Self::H2(send) => {
                while !bytes.is_empty() {
                    send.reserve_capacity(bytes.len());
                    let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .ok_or_else(error)?
                        .map_err(|_| error())?;
                    if capacity == 0 {
                        continue;
                    }
                    let count = capacity.min(bytes.len());
                    send.send_data(bytes.split_to(count), false)
                        .map_err(|_| error())?;
                }
                Ok(())
            }
            Self::Client(send) => send.send_data(bytes).await.map_err(|_| error()),
            Self::Server(send) => send.send_data(bytes).await.map_err(|_| error()),
        }
    }
    async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::H2(send) => send.send_data(Bytes::new(), true).map_err(|_| error()),
            Self::Client(send) => send.finish().await.map_err(|_| error()),
            Self::Server(send) => send.finish().await.map_err(|_| error()),
        }
    }
}
impl Reader {
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        match self {
            Self::H2(recv) => match ready!(recv.poll_data(cx)) {
                Some(Ok(bytes)) => {
                    recv.flow_control()
                        .release_capacity(bytes.len())
                        .map_err(|_| error())?;
                    Poll::Ready(Ok(Some(bytes)))
                }
                Some(Err(_)) => Poll::Ready(Err(error())),
                None => Poll::Ready(Ok(None)),
            },
            Self::Client(recv) => Poll::Ready(
                ready!(recv.poll_recv_data(cx))
                    .map(|v| {
                        v.map(|mut b| {
                            let n = b.remaining();
                            b.copy_to_bytes(n)
                        })
                    })
                    .map_err(|_| error()),
            ),
            Self::Server(recv) => Poll::Ready(
                ready!(recv.poll_recv_data(cx))
                    .map(|v| {
                        v.map(|mut b| {
                            let n = b.remaining();
                            b.copy_to_bytes(n)
                        })
                    })
                    .map_err(|_| error()),
            ),
        }
    }
}
type Pending = BoxFuture<'static, (Writer, io::Result<()>)>;
pub(crate) struct BodyIo {
    writer: Option<Writer>,
    reader: Reader,
    pending: Option<Pending>,
    buffer: Bytes,
    closing: bool,
    closed: bool,
}
impl BodyIo {
    pub fn boxed(writer: Writer, reader: Reader) -> BoxStream {
        Box::new(Self {
            writer: Some(writer),
            reader,
            pending: None,
            buffer: Bytes::new(),
            closing: false,
            closed: false,
        })
    }
    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(future) = &mut self.pending {
            let (writer, result) = ready!(future.as_mut().poll(cx));
            self.pending = None;
            self.writer = Some(writer);
            result?;
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for BodyIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.buffer.is_empty() {
                let count = buf.remaining().min(this.buffer.len());
                buf.put_slice(&this.buffer.split_to(count));
                return Poll::Ready(Ok(()));
            }
            match ready!(this.reader.poll_data(cx))? {
                Some(bytes) => this.buffer = bytes,
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for BodyIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.poll_pending(cx))?;
        let count = buf.len().min(16384);
        let bytes = Bytes::copy_from_slice(&buf[..count]);
        let mut writer = this.writer.take().ok_or_else(error)?;
        // 此次写入先取得有界缓冲所有权；后续 write/flush/shutdown 都等待该段真正提交。
        this.pending = Some(Box::pin(async move {
            let result = writer.data(bytes).await;
            (writer, result)
        }));
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_pending(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Ok(()));
        }
        ready!(this.poll_pending(cx))?;
        if !this.closing {
            this.closing = true;
            let mut writer = this.writer.take().ok_or_else(error)?;
            this.pending = Some(Box::pin(async move {
                let result = writer.finish().await;
                (writer, result)
            }));
        }
        ready!(this.poll_pending(cx))?;
        this.closed = true;
        Poll::Ready(Ok(()))
    }
}

/// 资源所有权跟随业务流；读写不需要额外后台复制队列。
pub(crate) struct HeldIo {
    inner: BoxStream,
    _carrier: Option<std::sync::Arc<crate::client::Carrier>>,
    _slot: Option<tokio::sync::OwnedSemaphorePermit>,
    _all: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl HeldIo {
    pub fn boxed(
        inner: BoxStream,
        carrier: Option<std::sync::Arc<crate::client::Carrier>>,
        slot: tokio::sync::OwnedSemaphorePermit,
        all: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> BoxStream {
        Box::new(Self {
            inner,
            _carrier: carrier,
            _slot: Some(slot),
            _all: all,
        })
    }
}
impl Drop for HeldIo {
    fn drop(&mut self) {
        if let Some(carrier) = &self._carrier {
            carrier.touch();
        }
    }
}
impl AsyncRead for HeldIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, b)
    }
}
impl AsyncWrite for HeldIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
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
    use kerlico_config::OutboundFactory;
    use kerlico_core::{ConnectContext,Destination};
    use std::time::Duration;
    use serde_json::json;

    #[tokio::test]
    async fn h2_connection_credit_allows_atomic_large_udp_reply_after_small_replies() {
        tokio::time::timeout(Duration::from_secs(8),async{
            let certified=rcgen::generate_simple_self_signed(vec!["credit.example.invalid".into()]).unwrap();
            let cert=certified.cert.pem();let key=certified.signing_key.serialize_pem();
            let tls=crate::config::server_tls(serde_json::from_value(json!({"certificate_pem":cert,"private_key_pem":key,"version":"tls13"})).unwrap(),crate::config::Transport::H2).unwrap();
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
            let(release,wait)=tokio::sync::oneshot::channel::<()>();
            let peer=tokio::spawn(async move{
                let(stream,_)=listener.accept().await.unwrap();let stream=tokio_rustls::TlsAcceptor::from(tls).accept(stream).await.unwrap();
                let mut connection=h2::server::handshake(stream).await.unwrap();
                let(request,mut response)=connection.accept().await.unwrap().unwrap();
                let auth=crate::config::Auth{username:"credit-user".into(),password:"credit-test-secret".into()};assert!(crate::config::authenticate(request.headers(),&[auth.hash()]));assert_eq!(request.uri().authority().unwrap().as_str(),"_udp2");
                let send=response.send_response(http::Response::builder().status(200).body(()).unwrap(),false).unwrap();
                let mut io=BodyIo{writer:Some(Writer::H2(send)),reader:Reader::H2(request.into_body()),pending:None,buffer:Bytes::new(),closing:false,closed:false};
                let mut worker=tokio::spawn(async move{
                    for size in [17,4096,12000,65000]{
                        let packet=crate::udp::read(&mut io,true,crate::udp::MAX_PAYLOAD).await.unwrap().unwrap();assert_eq!(packet.data.len(),size);
                        let bytes=crate::udp::encode(packet.target,packet.source,None,&packet.data,crate::udp::MAX_PAYLOAD).unwrap();
                        let Some(Writer::H2(send))=io.writer.as_mut()else{panic!("夹具必须使用真实H2响应发送端")};
                        send.reserve_capacity(bytes.len());
                        // 模拟真实对端的 atomic DroppingSink：credit不足就无法提交整个记录。
                        assert!(send.capacity()>=bytes.len(),"连接剩余credit不足一条完整UDP记录：{} < {}",send.capacity(),bytes.len());
                        send.send_data(Bytes::from(bytes),false).unwrap();
                    }
                    let _=wait.await;
                });
                loop{tokio::select!{result=&mut worker=>{result.unwrap();break;},request=connection.accept()=>{if request.is_none(){break;}panic!("夹具只接受一个固定UDP HTTP流");}}}
            });
            let outbound=crate::TrustTunnelFactory.build(&json!({"server":{"host":"127.0.0.1","port":address.port()},"auth":{"username":"credit-user","password":"credit-test-secret"},"transport":"h2","tls":{"server_name":"credit.example.invalid","ca_pem":cert,"version":"tls13"}})).unwrap();
            let context=ConnectContext::new(Duration::from_secs(3));let target=Destination::new("192.0.2.1",53).unwrap();let mut channel=outbound.connect_udp(&target,&context).await.unwrap();
            for size in [17,4096,12000,65000]{let bytes=vec![size as u8;size];channel.sender.send(&bytes).await.unwrap();assert_eq!(channel.receiver.recv().await.unwrap().unwrap(),bytes);}
            release.send(()).unwrap();drop(channel);drop(outbound);peer.await.unwrap();
        }).await.unwrap();
    }
}
