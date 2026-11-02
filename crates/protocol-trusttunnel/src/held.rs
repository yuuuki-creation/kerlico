use kerlico_core::BoxStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
    use bytes::Bytes;
    use kerlico_config::OutboundFactory;
    use kerlico_core::{ConnectContext, Destination};
    use serde_json::json;
    use std::time::Duration;

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
                let auth=crate::config::Auth{username:"credit-user".into(),password:"credit-test-secret".into()};assert_eq!(crate::config::authentication_hash(request.headers()).unwrap(),auth.hash());assert_eq!(request.uri().authority().unwrap().as_str(),"_udp2");
                let mut send=response.send_response(http::Response::builder().status(200).body(()).unwrap(),false).unwrap();
                let mut receive=request.into_body();
                let mut worker=tokio::spawn(async move{
                    let mut buffered=Vec::new();
                    for size in [17,4096,12000,65000]{
                        while buffered.len()<4 || buffered.len()<4+u32::from_be_bytes(buffered[..4].try_into().unwrap())as usize {
                            let bytes=receive.data().await.unwrap().unwrap();
                            receive.flow_control().release_capacity(bytes.len()).unwrap();
                            buffered.extend_from_slice(&bytes);
                        }
                        let length=4+u32::from_be_bytes(buffered[..4].try_into().unwrap())as usize;
                        let packet=crate::udp::read(&mut &buffered[..length],true,crate::udp::MAX_PAYLOAD).await.unwrap().unwrap();assert_eq!(packet.data.len(),size);
                        buffered.drain(..length);
                        let bytes=crate::udp::encode(packet.target,packet.source,None,&packet.data,crate::udp::MAX_PAYLOAD).unwrap();
                        send.reserve_capacity(bytes.len());
                        // 模拟真实对端的 atomic DroppingSink：credit不足就无法提交整个记录。
                        assert!(send.capacity()>=bytes.len(),"连接剩余credit不足一条完整UDP记录：{} < {}",send.capacity(),bytes.len());
                        send.send_data(Bytes::from(bytes),false).unwrap();
                    }
                    let _=wait.await;
                });
                tokio::select! {
                    result = &mut worker => result.unwrap(),
                    request = connection.accept() => {
                        assert!(request.is_none(), "夹具只接受一个固定UDP HTTP流");
                        worker.await.unwrap();
                    }
                }
            });
            let outbound=crate::TrustTunnelFactory.compile(&json!({"server":{"host":"127.0.0.1","port":address.port()},"auth":{"username":"credit-user","password":"credit-test-secret"},"transport":"h2","tls":{"server_name":"credit.example.invalid","ca_pem":cert,"version":"tls13"}})).unwrap().start(kerlico_core::ServiceContext::for_test()).await.unwrap();
            let context=ConnectContext::new(Duration::from_secs(3));let target=Destination::new("192.0.2.1",53).unwrap();let mut channel=outbound.connect_udp(&target,&context).await.unwrap();
            for size in [17,4096,12000,65000]{let bytes=vec![size as u8;size];channel.sender.send(&bytes).await.unwrap();assert_eq!(channel.receiver.recv().await.unwrap().unwrap(),bytes);}
            release.send(()).unwrap();drop(channel);drop(outbound);peer.await.unwrap();
        }).await.unwrap();
    }
}
