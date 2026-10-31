//! 公网 TCP 与本地旧 UDP 分别注册能力；目标访问全部由注入服务提供。
use crate::{
    codec,
    config::{self, ServerOptions, Transport, User, UserOptions},
    crypto::{Replay, StreamCipher, Users},
    packet,
    session::{self, Scope, Server, SessionIo, TcpSettings},
    udp,
};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, DatagramAssociation, Destination, Error,
    InboundContext, InboundProtocol, Result,
};
use std::{collections::BTreeSet, sync::Arc};
use tokio::{io::AsyncWriteExt, net::UdpSocket};
pub(crate) struct Node {
    users: Arc<Users>,
    transport: Transport,
    traffic: config::Traffic,
    mtu: usize,
    replay: Arc<Replay>,
}
impl Node {
    pub fn build(mut options: ServerOptions) -> Result<Self> {
        if options.username.is_some() || options.password.is_some() {
            if !options.users.is_empty() {
                return Err(config::invalid());
            }
            options.users.push(UserOptions {
                username: options.username.ok_or_else(config::invalid)?,
                password: options.password.ok_or_else(config::invalid)?,
            });
        }
        if options.users.is_empty() || options.users.len() > 256 {
            return Err(config::invalid());
        }
        let transport = Transport::parse(&options.transport, options.unsafe_udp_compatibility)?;
        config::validate_limits(128, 60, options.mtu)?;
        options.traffic.validate()?;
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for options in options.users {
            let user = User::new(options.username, options.password)?;
            if !seen.insert(user.identity_fingerprint()) {
                return Err(config::invalid());
            }
            users.push(user);
        }
        Ok(Self {
            users: Arc::new(Users::new(users, options.user_hint_required)),
            transport,
            traffic: options.traffic,
            mtu: options.mtu,
            replay: Arc::new(Replay::new()),
        })
    }
    fn check_access(access: &dyn AccessService) -> Result<()> {
        if access.supports_udp_association() {
            Ok(())
        } else {
            Err(Error::Unsupported("Mieru 节点需要 Full Cone UDP 关联出口"))
        }
    }
}
impl InboundProtocol for Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        if self.transport == Transport::LocalUnsafeUdp {
            Vec::new()
        } else {
            self.users
                .entries
                .iter()
                .map(|user| user.fingerprint())
                .collect()
        }
    }
    fn credential_isolation_fingerprints(
        &self,
        _default_protocol: &str,
    ) -> Vec<kerlico_core::ScopedCredentialFingerprint> {
        self.users
            .entries
            .iter()
            .flat_map(|user| {
                [
                    kerlico_core::ScopedCredentialFingerprint {
                        protocol: "mieru".into(),
                        fingerprint: user.fingerprint(),
                    },
                    kerlico_core::ScopedCredentialFingerprint {
                        protocol: "mieru-user".into(),
                        fingerprint: user.identity_fingerprint(),
                    },
                ]
            })
            .collect()
    }
    fn requires_loopback(&self) -> bool {
        self.transport == Transport::LocalUnsafeUdp
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn supports_tcp(&self) -> bool {
        self.transport == Transport::Tcp
    }
    fn supports_udp(&self) -> bool {
        self.transport == Transport::LocalUnsafeUdp
    }
    fn handle<'a>(
        &'a self,
        mut stream: BoxStream,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.transport != Transport::Tcp {
                return Err(Error::Unsupported("该 Mieru 条目没有 TCP 载体"));
            }
            Self::check_access(access.as_ref())?;
            let opening = ConnectContext {
                cancel: context.cancel.clone(),
                timeout: context.connect_timeout,
            };
            let (frame, receive, nonce) = opening
                .run(codec::read_server_first(&mut stream, &self.users))
                .await?;
            if frame.kind != 2 {
                return Err(codec::bad());
            }
            frame.direction(false)?;
            self.replay.accept(&receive.key, &nonce)?;
            let send = StreamCipher::new(receive.key.clone());
            let scope = Scope::new(&context.cancel);
            let settings = TcpSettings {
                traffic: self.traffic.clone(),
                idle: context.idle_timeout,
                connect_timeout: context.connect_timeout,
                multiplexing: true,
                server: Some(Server { access, context }),
            };
            let link = session::tcp_link(stream, receive, send, scope, settings, Some(frame));
            link.scope.cancel.cancelled().await;
            link.scope.shutdown().await;
            Ok(())
        })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.transport != Transport::LocalUnsafeUdp {
                return Err(Error::Unsupported("公网 Mieru UDP 载体未支持"));
            }
            let address = socket.local_addr()?;
            if !address.ip().is_loopback() || address.ip().to_canonical() != address.ip() {
                return Err(Error::Config("Mieru 不安全 UDP 必须回环监听".into()));
            }
            Self::check_access(access.as_ref())?;
            let scope = Scope::new(&context.cancel);
            let common = TcpSettings {
                traffic: self.traffic.clone(),
                idle: context.idle_timeout,
                connect_timeout: context.connect_timeout,
                multiplexing: true,
                server: Some(Server { access, context }),
            };
            let link = packet::start(
                socket,
                scope,
                packet::Settings {
                    common,
                    mtu: self.mtu,
                    key: None,
                    peer: None,
                    users: Some(self.users.clone()),
                    replay: Some(self.replay.clone()),
                },
            )?;
            link.scope.cancel.cancelled().await;
            link.scope.shutdown().await;
            Ok(())
        })
    }
}
enum Ready {
    Tcp(BoxStream),
    Udp(DatagramAssociation),
}
pub(crate) async fn run_session(
    mut stream: SessionIo,
    access: Arc<dyn AccessService>,
    context: InboundContext,
) -> Result<()> {
    let cancel = stream.life.abort_cancel.clone();
    let connecting = ConnectContext {
        cancel: cancel.clone(),
        timeout: context.connect_timeout,
    };
    let target = connecting
        .run(async {
            let (command, host, port) = codec::read_request(&mut stream).await?;
            let target = if command == 1 {
                let destination = Destination::new(&host, port)?;
                access
                    .connect_tcp(&destination, &connecting)
                    .await
                    .map(Ready::Tcp)
            } else {
                access.associate_udp(&connecting).await.map(Ready::Udp)
            };
            match target {
                Ok(target) => {
                    stream.write_all(&codec::response(0)).await?;
                    stream.flush().await?;
                    Ok(target)
                }
                Err(error) => {
                    let _ = stream.write_all(&codec::response(1)).await;
                    let _ = stream.flush().await;
                    Err(error)
                }
            }
        })
        .await?;
    match target {
        Ready::Tcp(target) => {
            kerlico_core::relay_tcp(Box::new(stream), target, context.idle_timeout, cancel).await
        }
        Ready::Udp(association) => {
            udp::relay(
                stream,
                association,
                context.max_datagram_size.min(codec::MAX_UDP),
                context.idle_timeout,
                cancel,
            )
            .await
        }
    }
}
