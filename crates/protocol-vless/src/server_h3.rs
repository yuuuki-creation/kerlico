use crate::{inbound::Payload, server_http::State};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use kerlico_core::{AccessService, Error, InboundContext, NodeEvent, Result};
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_stream::wrappers::ReceiverStream;

pub(crate) async fn serve(
    socket: Arc<tokio::net::UdpSocket>,
    config: Arc<rustls::ServerConfig>,
    state: Arc<State>,
    payload: Arc<Payload>,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let mut tls = (*config).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|_| Error::Config("HTTP/3 TLS 配置不合法".into()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams((context.max_streams as u32).into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(context.idle_timeout)
            .map_err(|_| Error::Config("QUIC 空闲预算不合法".into()))?,
    ));
    server.transport_config(Arc::new(transport));
    let fd = socket2::SockRef::from(socket.as_ref()).try_clone()?;
    let standard: std::net::UdpSocket = fd.into();
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        standard,
        Arc::new(quinn::TokioRuntime),
    )?;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _=context.cancel.cancelled()=>break,
            result=connections.join_next(),if !connections.is_empty()=>{if result.is_some_and(|r|r.is_err()){context.events.record(NodeEvent::Failed);}},
            incoming=endpoint.accept()=>{
                let Some(incoming)=incoming else{break};let Ok(lease)=context.stream_budget.try_acquire() else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};
                let state=state.clone();let payload=payload.clone();let access=access.clone();let context=context.clone();
                connections.spawn(async move {let _lease=lease;context.events.record(NodeEvent::Accepted);let result=async {let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|Error::Protocol("QUIC 握手失败"))?;connection_loop(connection,state,payload,access,context.clone()).await}.await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});
            }
        }
    }
    endpoint.close(0u32.into(), b"stopping");
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    let _ = tokio::time::timeout(context.drain_timeout, endpoint.wait_idle()).await;
    Ok(())
}
async fn connection_loop(
    connection: quinn::Connection,
    state: Arc<State>,
    payload: Arc<Payload>,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let mut server = h3::server::Connection::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|_| Error::Protocol("HTTP/3 连接初始化失败"))?;
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        let resolver = tokio::select! {_=context.cancel.cancelled()=>break,r=server.accept()=>match r{Ok(Some(v))=>v,Ok(None)=>break,Err(_)=>return Err(Error::Protocol("HTTP/3 请求接收失败"))}};
        let state = state.clone();
        let payload = payload.clone();
        let access = access.clone();
        let context = context.clone();
        tasks.spawn(async move {
            let Ok((request,stream))=resolver.resolve_request().await else{return};
            let (mut send,mut receive)=stream.split();let (body_tx,body_rx)=mpsc::channel::<std::io::Result<Frame<Bytes>>>(16);
            let request=request.map(|_|StreamBody::new(ReceiverStream::new(body_rx)));
            let upload=async move {while let Some(mut bytes)=receive.recv_data().await.map_err(|_|Error::Protocol("HTTP/3 上传失败"))? {let size=bytes.remaining();body_tx.send(Ok(Frame::data(bytes.copy_to_bytes(size)))).await.map_err(|_|Error::Cancelled)?;}Ok::<_,Error>(())};
            let response=async {
                let response=state.request(request,payload,access,context.clone()).await;let (parts,mut body)=response.into_parts();
                send.send_response(http::Response::from_parts(parts,())).await.map_err(|_|Error::Protocol("HTTP/3 响应头失败"))?;
                while let Some(frame)=body.frame().await {let frame=frame.map_err(Error::Io)?;match frame.into_data(){Ok(data)=>send.send_data(data).await.map_err(|_|Error::Protocol("HTTP/3 下载失败"))?,Err(frame)=>{if let Ok(trailers)=frame.into_trailers(){send.send_trailers(trailers).await.map_err(|_|Error::Protocol("HTTP/3 trailers 失败"))?;}}}}
                send.finish().await.map_err(|_|Error::Protocol("HTTP/3 结束失败"))?;Ok::<_,Error>(())
            };
            let _=tokio::select! {_=context.cancel.cancelled()=>Err(Error::Cancelled),r=async{tokio::try_join!(upload,response).map(|_|())}=>r};
        });
    }
    if tokio::time::timeout(context.drain_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}
