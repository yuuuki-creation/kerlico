use crate::{
    config::{Authentication, Options, Prepared},
    transport::{ConnectionGuard, Transport},
};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    BoxFuture, CancellationToken, Capabilities, ConnectContext, DatagramChannel, Destination,
    Error, Outbound, Result,
};
use russh::{
    ChannelStream, client,
    keys::{HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate},
};
use serde_json::Value;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct VerifyHost {
    pins: Arc<Vec<String>>,
}
impl client::Handler for VerifyHost {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if key.certificate().is_some() {
            return Ok(false);
        }
        let actual = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let mut accepted = subtle::Choice::from(0);
        for pin in self.pins.iter() {
            accepted |= actual.as_bytes().ct_eq(pin.as_bytes());
        }
        Ok(bool::from(accepted))
    }
}

fn failure(error: russh::Error) -> Error {
    match error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => Error::Rejected,
        russh::Error::ConnectionTimeout => Error::Timeout,
        russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::ConnectFailed) => Error::Io(
            io::Error::new(io::ErrorKind::ConnectionRefused, "SSH 远端目标连接失败"),
        ),
        _ => Error::Protocol("SSH 握手、鉴权或通道建立失败"),
    }
}

struct SshOutbound {
    prepared: Arc<Prepared>,
    drivers: Arc<crate::runtime::Drivers>,
}
impl Drop for SshOutbound {
    fn drop(&mut self) {
        self.drivers.cancel().cancel();
    }
}
struct SshStream {
    _guard: ConnectionGuard,
    channel: ChannelStream<client::Msg>,
}
impl AsyncRead for SshStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().channel).poll_read(cx, bytes)
    }
}
impl AsyncWrite for SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().channel).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().channel).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().channel).poll_shutdown(cx)
    }
}

impl Outbound for SshOutbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: false,
        }
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.drivers.shutdown())
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
        Box::pin(async move {
            let guard = ConnectionGuard(context.cancel.child_token());
            let cancel = guard.0.clone();
            let service = self.drivers.cancel();
            let (send, receive) = tokio::sync::oneshot::channel();
            let prepared = self.prepared.clone();
            let target = target.clone();
            let operation = context.clone();
            let owner = self.drivers.clone();
            let service_for_driver = service.clone();
            self.drivers.spawn(async move {
                russh_util::runtime::scope(
                    owner,
                    drive(
                        prepared,
                        target,
                        operation,
                        cancel,
                        service_for_driver,
                        send,
                    ),
                )
                .await;
            })?;
            let channel = context.run(async {
                tokio::select! {
                    biased;
                    _ = service.cancelled() => Err(Error::Cancelled),
                    result = receive => result.map_err(|_| Error::Protocol("SSH驱动未交付通道"))?,
                }
            }).await?;
            Ok(kerlico_core::OpenedTcp {
                stream: Box::new(SshStream {
                    _guard: guard,
                    channel,
                }),
                info: kerlico_core::TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("SSH direct-tcpip 不提供 UDP")) })
    }
}

async fn interrupted(
    context: &ConnectContext,
    service: &CancellationToken,
    cancel: &CancellationToken,
) -> Error {
    tokio::select! {
        biased;
        _ = service.cancelled() => Error::Cancelled,
        _ = cancel.cancelled() => Error::Cancelled,
        result = context.run(std::future::pending::<Result<()>>()) => result.err().unwrap_or(Error::Cancelled),
    }
}

async fn channel(
    session: &mut client::Handle<VerifyHost>,
    prepared: &Prepared,
    target: &Destination,
) -> Result<ChannelStream<client::Msg>> {
    let authenticated = match &prepared.auth {
        Authentication::Password(password) => session
            .authenticate_password(&prepared.username, password)
            .await
            .map_err(failure)?,
        Authentication::Key(key) => {
            let hash = if key.algorithm().is_rsa() {
                Some(
                    session
                        .best_supported_rsa_hash()
                        .await
                        .map_err(failure)?
                        .flatten()
                        .ok_or(Error::Unsupported("SSH 对端未提供 RSA SHA-2 签名"))?,
                )
            } else {
                None
            };
            session
                .authenticate_publickey(
                    &prepared.username,
                    PrivateKeyWithHashAlg::new(key.clone(), hash),
                )
                .await
                .map_err(failure)?
        }
    };
    if !authenticated.success() {
        return Err(Error::Rejected);
    }
    session
        .channel_open_direct_tcpip(target.host(), u32::from(target.port()), "0.0.0.0", 0)
        .await
        .map(|channel| channel.into_stream())
        .map_err(failure)
}

async fn drive(
    prepared: Arc<Prepared>,
    target: Destination,
    context: ConnectContext,
    cancel: CancellationToken,
    service: CancellationToken,
    ready: tokio::sync::oneshot::Sender<Result<ChannelStream<client::Msg>>>,
) {
    let socket = tokio::select! {
        biased;
        error = interrupted(&context, &service, &cancel) => Err(error),
        result = prepared.dialer.connect(&prepared.server) => result,
    };
    let stream = match socket {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let mut handshake = Box::pin(client::connect_stream(
        prepared.ssh.clone(),
        Transport::new(stream, &cancel),
        VerifyHost {
            pins: prepared.pins.clone(),
        },
    ));
    let connected = tokio::select! {
        biased;
        error = interrupted(&context, &service, &cancel) => {
            cancel.cancel();
            let _ = handshake.await;
            Err(error)
        },
        result = &mut handshake => result.map_err(failure),
    };
    let mut session = match connected {
        Ok(session) => session,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let opened = tokio::select! {
        biased;
        error = interrupted(&context, &service, &cancel) => Err(error),
        result = channel(&mut session, &prepared, &target) => result,
    };
    let failed = opened.is_err();
    if ready.send(opened).is_err() || failed {
        cancel.cancel();
    }
    tokio::select! {
        biased;
        _ = service.cancelled() => { cancel.cancel(); let _ = session.await; },
        _ = cancel.cancelled() => { let _ = session.await; },
        _ = &mut session => {},
    }
}

pub struct SshFactory;
impl OutboundFactory for SshFactory {
    fn kind(&self) -> &'static str {
        "ssh"
    }
    fn supports_detour(&self) -> bool {
        true
    }
    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SSH 出站字段不合法".into()))?;
        let prepared = options.prepare(kerlico_core::current_compile_dialer())?;
        Ok(OutboundPlan::new(
            Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: false,
            },
            false,
            kerlico_core::TargetPolicy::Remote,
            move |host| {
                Box::pin(async move {
                    Ok(Arc::new(SshOutbound {
                        prepared: Arc::new(prepared),
                        drivers: crate::runtime::Drivers::new(host),
                    }) as Arc<dyn Outbound>)
                })
            },
        ))
    }
}
