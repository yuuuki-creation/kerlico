//! 服务端：解析会话请求，按子协议接受逻辑流并分派 TCP、UDP 与 Brutal 交换。

use super::{
    SingMuxInboundConfig, SingMuxProtocol,
    frame::{Codec, FrameSession},
    h2mux,
    padding::PaddedIo,
    wire::{
        BRUTAL_DISABLED_MESSAGE, BRUTAL_EXCHANGE_DOMAIN, STATUS_SUCCESS, SessionRequest, SocksAddr,
        StreamKind, StreamRequest, encode_brutal_response, encode_error_status,
    },
};
use kerlico_core::{
    BoxStream, ConnectContext, DatagramAssociationReceiver, DatagramAssociationSender,
    DatagramReceiver, DatagramSender, Error, FlowOutcome, InboundContext, PeerSession, Result,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn serve_inbound(
    mut stream: BoxStream,
    peer: PeerSession,
    config: &SingMuxInboundConfig,
    context: &InboundContext,
) -> Result<()> {
    if !config.enabled {
        return Err(Error::Protocol("未启用 sing-mux 入站"));
    }
    let request = SessionRequest::read(&mut stream).await?;
    if config.padding && !request.padding {
        return Err(Error::Protocol("sing-mux 入站要求启用 padding"));
    }
    let io: BoxStream = if request.padding {
        Box::new(PaddedIo::new(stream))
    } else {
        stream
    };
    let dispatch = |stream: BoxStream| {
        let peer = peer.clone();
        let context = context.clone();
        let _ = context.tasks.clone().spawn(async move {
            let _ = handle_stream(stream, peer, context).await;
        });
    };
    match request.protocol {
        SingMuxProtocol::Smux | SingMuxProtocol::Yamux => {
            let codec = if request.protocol == SingMuxProtocol::Smux {
                Codec::Smux
            } else {
                Codec::Yamux
            };
            let (session, mut accept) = FrameSession::server(io, codec);
            loop {
                tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    next = accept.recv() => match next {
                        Some(stream) => dispatch(Box::new(stream)),
                        None => break,
                    },
                }
            }
            session.close();
        }
        SingMuxProtocol::H2Mux => {
            h2mux::serve(io, context.cancel.clone(), |stream| {
                dispatch(Box::new(stream))
            })
            .await?;
        }
    }
    Ok(())
}

async fn reject(stream: &mut BoxStream, err: &Error) {
    let _ = stream
        .write_all(&encode_error_status(&err.to_string()))
        .await;
    let _ = stream.shutdown().await;
}

async fn handle_stream(
    mut stream: BoxStream,
    peer: PeerSession,
    context: InboundContext,
) -> Result<()> {
    let request = StreamRequest::read(&mut stream).await?;
    let ctx = ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
    if request.kind == StreamKind::Tcp && request.addr.is_domain(BRUTAL_EXCHANGE_DOMAIN) {
        let _client_receive_bps = stream.read_u64().await?;
        let mut response = vec![STATUS_SUCCESS];
        response.extend_from_slice(&encode_brutal_response(None, BRUTAL_DISABLED_MESSAGE));
        stream.write_all(&response).await?;
        let _ = stream.shutdown().await;
        return Ok(());
    }
    if request.kind == StreamKind::UdpPacketAddr {
        let association = match peer.associate_udp(&ctx).await {
            Ok(association) => association,
            Err(err) => {
                reject(&mut stream, &err).await;
                return Err(err);
            }
        };
        stream.write_all(&[STATUS_SUCCESS]).await?;
        let (mut sender, mut receiver, completion) = association.into_parts();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let up = async {
            while let Ok(family) = reader.read_u8().await {
                let Ok(target) = SocksAddr::read_with_family(family, &mut reader).await else {
                    break;
                };
                let Ok(payload) = read_packet(&mut reader).await else {
                    break;
                };
                let Ok(target) = target.to_destination() else {
                    continue;
                };
                if sender.send_to(&payload, &target).await.is_err() {
                    break;
                }
            }
        };
        let down = async {
            while let Ok(Some((source, payload))) = receiver.recv_from().await {
                let mut frame = Vec::with_capacity(264 + payload.len());
                if SocksAddr::from_destination(&source)
                    .encode_into(&mut frame)
                    .is_err()
                    || write_packet(&mut writer, frame, &payload).await.is_err()
                {
                    break;
                }
            }
        };
        tokio::select! {
            _ = context.cancel.cancelled() => {}
            _ = up => {}
            _ = down => {}
        }
        completion.finish(FlowOutcome::ProtocolEnd);
        return Ok(());
    }
    let target = match request.addr.to_destination() {
        Ok(target) => target,
        Err(err) => {
            reject(&mut stream, &err).await;
            return Err(err);
        }
    };
    if request.kind == StreamKind::Udp {
        let channel = match peer.connect_udp(&target, &ctx).await {
            Ok(channel) => channel,
            Err(err) => {
                reject(&mut stream, &err).await;
                return Err(err);
            }
        };
        stream.write_all(&[STATUS_SUCCESS]).await?;
        let (mut sender, mut receiver, completion) = channel.into_parts();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let up = async {
            while let Ok(payload) = read_packet(&mut reader).await {
                if sender.send(&payload).await.is_err() {
                    break;
                }
            }
        };
        let down = async {
            while let Ok(Some(payload)) = receiver.recv().await {
                if write_packet(&mut writer, Vec::new(), &payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        };
        tokio::select! {
            _ = context.cancel.cancelled() => {}
            _ = up => {}
            _ = down => {}
        }
        completion.finish(FlowOutcome::ProtocolEnd);
        return Ok(());
    }
    let outbound = match peer.connect_tcp(&target, &ctx).await {
        Ok(outbound) => outbound,
        Err(err) => {
            reject(&mut stream, &err).await;
            return Err(err);
        }
    };
    stream.write_all(&[STATUS_SUCCESS]).await?;
    kerlico_core::relay_tcp(stream, outbound, context.idle_timeout, context.cancel).await
}

async fn read_packet(reader: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let len = usize::from(reader.read_u16().await?);
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_packet(
    writer: &mut (impl AsyncWrite + Unpin),
    mut frame: Vec<u8>,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await
}
