use crate::{
    config::{self, Auth, NodeOptions, Version},
    wire,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    Address, BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet,
    DatagramAssociationReceiver, DatagramAssociationSender, Destination, Error, FlowFailure,
    FlowOutcome, InboundContext, InboundProtocol, IngressBinding, NodeEvent, PeerSession, Result,
    TargetBind, Verified,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::watch,
};

struct SocksNode {
    version: Version,
    auth: CredentialSet<Auth>,
    userid: String,
    allow_udp: bool,
}

fn budget(context: &InboundContext) -> ConnectContext {
    ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone())
}
async fn response(stream: &mut BoxStream, code: u8, address: SocketAddr) -> Result<()> {
    let mut bytes = vec![5, code, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
    }
    bytes.extend(address.port().to_be_bytes());
    stream.write_all(&bytes).await?;
    Ok(())
}
enum ConnectReplyBind {
    Known(Destination),
    CompatibleUnknown,
}
fn connect_reply_bind(bind: &TargetBind) -> ConnectReplyBind {
    match bind {
        TargetBind::Known { endpoint, .. } => ConnectReplyBind::Known(endpoint.clone()),
        TargetBind::Unknown => ConnectReplyBind::CompatibleUnknown,
    }
}
async fn connect_response(stream: &mut BoxStream, binding: ConnectReplyBind) -> Result<()> {
    let mut bytes = vec![5, 0, 0];
    match binding {
        ConnectReplyBind::Known(endpoint) => wire::encode(&endpoint, &mut bytes),
        ConnectReplyBind::CompatibleUnknown => bytes.extend([1, 0, 0, 0, 0, 0, 0]),
    }
    stream.write_all(&bytes).await?;
    Ok(())
}
fn connect_response_four(binding: &TargetBind) -> [u8; 8] {
    let mut bytes = [0, 90, 0, 0, 0, 0, 0, 0];
    if let TargetBind::Known { endpoint, .. } = binding
        && let Address::Ip(IpAddr::V4(ip)) = endpoint.address()
    {
        bytes[2..4].copy_from_slice(&endpoint.port().to_be_bytes());
        bytes[4..].copy_from_slice(&ip.octets());
    }
    bytes
}
fn failure(error: &Error) -> u8 {
    match error {
        Error::Rejected => 2,
        Error::InvalidAddress => 8,
        Error::Timeout => 6,
        Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => 5,
        _ => 1,
    }
}

impl SocksNode {
    async fn authenticate(&self, stream: &mut BoxStream) -> Result<Option<Verified<()>>> {
        if stream.read_u8().await? != 5 {
            return Err(wire::invalid());
        }
        let count = stream.read_u8().await?;
        let mut methods = vec![0; usize::from(count)];
        stream.read_exact(&mut methods).await?;
        let selected = if self.auth.is_empty() { 0 } else { 2 };
        if !methods.contains(&selected) {
            stream.write_all(&[5, 255]).await?;
            return Err(Error::Rejected);
        }
        stream.write_all(&[5, selected]).await?;
        if !self.auth.is_empty() {
            if stream.read_u8().await? != 1 {
                return Err(wire::invalid());
            }
            let count = stream.read_u8().await?;
            let mut username = vec![0; usize::from(count)];
            stream.read_exact(&mut username).await?;
            let count = stream.read_u8().await?;
            let mut password = vec![0; usize::from(count)];
            stream.read_exact(&mut password).await?;
            let verified = self
                .auth
                .verify(&(username, password), |auth, (username, password)| {
                    Ok((config::equal(username, auth.username.as_bytes())
                        & config::equal(password, auth.password.as_bytes()))
                    .then_some(()))
                });
            let valid = verified.is_ok();
            stream.write_all(&[1, u8::from(!valid)]).await?;
            return verified.map(Some);
        }
        Ok(None)
    }

    async fn five(
        &self,
        mut stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let handshake = budget(&context);
        let (access, command, host, port) = handshake
            .run(async {
                let access = match self.authenticate(&mut stream).await? {
                    Some(verified) => ingress.authenticated(verified, &context)?.0,
                    None => ingress.local(&context)?,
                };
                let mut header = [0; 3];
                stream.read_exact(&mut header).await?;
                if header[0] != 5 || header[2] != 0 {
                    return Err(wire::invalid());
                }
                let (host, port) = match wire::read_address(&mut *stream).await {
                    Ok(address) => address,
                    Err(error) => {
                        response(&mut stream, 8, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
                        return Err(error);
                    }
                };
                Ok((access, header[1], host, port))
            })
            .await?;
        if command == 3 {
            if !self.allow_udp {
                response(&mut stream, 7, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
                return Err(Error::Unsupported("SOCKS UDP关联未启用"));
            }
            return self
                .udp(stream, &host, port, access, handshake, context)
                .await;
        }
        if command != 1 {
            response(&mut stream, 7, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
            return Err(Error::Unsupported("SOCKS 请求命令未实现"));
        }
        let target = match Destination::new(&host, port) {
            Ok(target) => target,
            Err(error) => {
                handshake
                    .run(response(
                        &mut stream,
                        8,
                        SocketAddr::from(([0, 0, 0, 0], 0)),
                    ))
                    .await?;
                return Err(error);
            }
        };
        let remote = match handshake.run(access.connect_tcp(&target, &handshake)).await {
            Ok(remote) => remote,
            Err(error) => {
                handshake
                    .run(response(
                        &mut stream,
                        failure(&error),
                        SocketAddr::from(([0, 0, 0, 0], 0)),
                    ))
                    .await?;
                return Err(error);
            }
        };
        let binding = connect_reply_bind(remote.info().target_bind());
        if let Err(error) = handshake.run(connect_response(&mut stream, binding)).await {
            remote.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
            return Err(error);
        }
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }

    async fn four(
        &self,
        mut stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let access = ingress.local(&context)?;
        let handshake = budget(&context);
        let target = handshake
            .run(async {
                let mut header = [0; 8];
                stream.read_exact(&mut header).await?;
                let userid = wire::cstring(&mut *stream, 255).await?;
                let port = u16::from_be_bytes([header[2], header[3]]);
                let extension = header[4..7] == [0, 0, 0] && header[7] != 0;
                let host = if extension && self.version == Version::FourA {
                    String::from_utf8(wire::cstring(&mut *stream, 255).await?)
                        .map_err(|_| wire::invalid())?
                } else {
                    Ipv4Addr::new(header[4], header[5], header[6], header[7]).to_string()
                };
                if header[0] != 4
                    || header[1] != 1
                    || (extension && self.version != Version::FourA)
                    || !config::equal(&userid, self.userid.as_bytes())
                {
                    stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?;
                    return Err(Error::Rejected);
                }
                Destination::new(&host, port)
            })
            .await?;
        let remote = match access.connect_tcp(&target, &handshake).await {
            Ok(remote) => remote,
            Err(error) => {
                let _ = handshake
                    .run(async {
                        stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?;
                        Ok(())
                    })
                    .await;
                return Err(error);
            }
        };
        let reply = connect_response_four(remote.info().target_bind());
        if let Err(error) = handshake
            .run(async {
                stream.write_all(&reply).await?;
                Ok(())
            })
            .await
        {
            remote.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
            return Err(error);
        }
        kerlico_core::relay_tcp(stream, remote, context.idle_timeout, context.cancel).await
    }

    async fn udp(
        &self,
        mut stream: BoxStream,
        host: &str,
        port: u16,
        access: PeerSession,
        connect: ConnectContext,
        context: InboundContext,
    ) -> Result<()> {
        let peer = context
            .peer_addr
            .ok_or(Error::Unsupported("SOCKS UDP关联需要TCP对端地址"))?;
        let local = context
            .local_addr
            .ok_or(Error::Unsupported("SOCKS UDP关联需要TCP本地地址"))?;
        let claimed: IpAddr = host.parse().map_err(|_| wire::invalid())?;
        if !claimed.is_unspecified() && claimed != peer.ip() {
            response(&mut stream, 2, SocketAddr::new(local.ip(), 0)).await?;
            return Err(Error::Rejected);
        }
        if !access.supports_udp_association() {
            response(&mut stream, 7, SocketAddr::new(local.ip(), 0)).await?;
            return Err(Error::Unsupported("所选出站不支持SOCKS多目标UDP关联"));
        }
        let socket = UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?;
        let channel = match connect.run(access.associate_udp(&connect)).await {
            Ok(channel) => channel,
            Err(error) => {
                response(&mut stream, failure(&error), SocketAddr::new(local.ip(), 0)).await?;
                return Err(error);
            }
        };
        if let Err(error) = connect
            .run(async { response(&mut stream, 0, socket.local_addr()?).await })
            .await
        {
            channel.finish(FlowOutcome::Failed(FlowFailure::from_error(&error)));
            return Err(error);
        }
        let source = Arc::new(Mutex::new(
            (port != 0).then(|| SocketAddr::new(peer.ip(), port)),
        ));
        let (activity, mut observed) = watch::channel(tokio::time::Instant::now());
        let (mut sender, mut receiver, completion) = channel.into_parts();
        let result = async {
        let uploading = activity.clone();
        let upload: BoxFuture<'_, Result<()>> = Box::pin(async {
            let mut bytes = vec![0; 65535];
            loop {
                let (count, from) = socket.recv_from(&mut bytes).await?;
                if from.ip() != peer.ip()
                    || source
                        .lock()
                        .map_err(|_| wire::invalid())?
                        .is_some_and(|expected| expected != from)
                {
                    context.events.record(NodeEvent::Dropped);
                    continue;
                }
                let (target, payload) = match wire::packet(&bytes[..count]) {
                    Ok(packet) => packet,
                    Err(_) => {
                        context.events.record(NodeEvent::Dropped);
                        continue;
                    }
                };
                if payload.len() > context.max_datagram_size {
                    context.events.record(NodeEvent::Dropped);
                    continue;
                }
                *source.lock().map_err(|_| wire::invalid())? = Some(from);
                sender.send_to(payload, &target).await?;
                uploading.send_replace(tokio::time::Instant::now());
            }
        });
        let download = async {
            while let Some((target, payload)) = receiver.recv_from().await? {
                if payload.len() > context.max_datagram_size {
                    context.events.record(NodeEvent::Dropped);
                    continue;
                }
                let source = *source.lock().map_err(|_| wire::invalid())?;
                if let Some(source) = source {
                    let packet = match wire::datagram(&target, &payload) {
                        Ok(packet) => packet,
                        Err(_) => {
                            context.events.record(NodeEvent::Dropped);
                            continue;
                        }
                    };
                    socket.send_to(&packet, source).await?;
                    activity.send_replace(tokio::time::Instant::now());
                }
            }
            Ok::<(), Error>(())
        };
        let control = async {
            let mut bytes = [0; 1];
            if stream.read(&mut bytes).await? == 0 {
                Ok(())
            } else {
                Err(wire::invalid())
            }
        };
        tokio::pin!(upload, download, control);
        let timer = tokio::time::sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! { biased;
                _=context.cancel.cancelled()=>return Err(Error::Cancelled),
                result=&mut control=>return result,
                result=&mut upload=>return result,
                result=&mut download=>return result,
                _=&mut timer=>return Err(Error::Timeout),
                changed=observed.changed()=>{ if changed.is_ok(){ timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout); } },
            }
        }
        }.await;
        completion.finish(match &result {
            Ok(()) => FlowOutcome::ProtocolEnd,
            Err(error) => FlowOutcome::Failed(FlowFailure::from_error(error)),
        });
        result
    }
}
impl InboundProtocol for SocksNode {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, auth)) in self.auth.rows().enumerate() {
            manifest.authentication("socks", index, auth.fingerprint());
        }
        manifest
    }
    fn requires_loopback(&self) -> bool {
        self.version != Version::Five || self.auth.is_empty()
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        ingress: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.version == Version::Five {
                self.five(stream, ingress, context).await
            } else {
                self.four(stream, ingress, context).await
            }
        })
    }
}

pub struct SocksNodeFactory;
impl NodeFactory for SocksNodeFactory {
    fn kind(&self) -> &'static str {
        "socks"
    }
    fn allows_local_inbound(&self) -> bool {
        true
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: NodeOptions = serde_json::from_value(input.options().clone())
            .map_err(|_| Error::Config("SOCKS 节点字段不合法".into()))?;
        config::validate(options.version, &None, &options.userid)?;
        let rows = input
            .native_credentials()
            .iter()
            .map(|value| {
                let auth: Auth = serde_json::from_value(value.clone())
                    .map_err(|_| Error::Config("SOCKS 用户凭据字段不合法".into()))?;
                auth.validate()?;
                Ok(auth)
            })
            .collect::<Result<Vec<_>>>()?;
        if options.version != Version::Five && !rows.is_empty() {
            return Err(Error::Config("SOCKS4/4a 只能作为 Local 入站".into()));
        }
        Ok(Arc::new(SocksNode {
            version: options.version,
            auth: input.credentials(rows)?,
            userid: options.userid,
            allow_udp: true,
        }))
    }
}

/// 为 `mixed` 入站构造内部 SOCKS5 与 SOCKS4/4a 处理器。
pub type MixedSocksNodes = (Arc<dyn InboundProtocol>, Option<Arc<dyn InboundProtocol>>);

pub fn build_mixed_socks(
    input: &NodeBuildContext,
    userid: String,
    allow_udp: bool,
) -> Result<MixedSocksNodes> {
    config::validate(Version::FourA, &None, &userid)?;
    let rows = input
        .native_credentials()
        .iter()
        .map(|value| {
            let auth: Auth = serde_json::from_value(value.clone())
                .map_err(|_| Error::Config("SOCKS 用户凭据字段不合法".into()))?;
            auth.validate()?;
            Ok(auth)
        })
        .collect::<Result<Vec<_>>>()?;
    let socks4 = if rows.is_empty() {
        Some(Arc::new(SocksNode {
            version: Version::FourA,
            auth: input.credentials(Vec::new())?,
            userid,
            allow_udp: false,
        }) as Arc<dyn InboundProtocol>)
    } else {
        None
    };
    let socks5 = Arc::new(SocksNode {
        version: Version::Five,
        auth: input.credentials(rows)?,
        userid: String::new(),
        allow_udp,
    }) as Arc<dyn InboundProtocol>;
    Ok((socks5, socks4))
}
