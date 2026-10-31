use crate::{
    config::{Authentication, Options, Prepared},
    transport::{ConnectionGuard, Transport},
};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    Outbound, Result,
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
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

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

struct SshOutbound(Prepared);
struct SshStream {
    // 先取消底层连接，再释放通道和库句柄，避免后台 SSH actor 脱离所属流。
    _guard: ConnectionGuard,
    channel: ChannelStream<client::Msg>,
    _session: client::Handle<VerifyHost>,
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
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let stream =
                        TcpStream::connect((self.0.server.host().as_str(), self.0.server.port()))
                            .await?;
                    stream.set_nodelay(true)?;
                    let guard = ConnectionGuard(context.cancel.child_token());
                    let transport = Transport::new(stream, &guard.0);
                    let mut session = client::connect_stream(
                        self.0.ssh.clone(),
                        transport,
                        VerifyHost {
                            pins: self.0.pins.clone(),
                        },
                    )
                    .await
                    .map_err(failure)?;
                    let authenticated = match &self.0.auth {
                        Authentication::Password(password) => session
                            .authenticate_password(&self.0.username, password)
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
                                        .ok_or(Error::Unsupported(
                                            "SSH 对端未提供 RSA SHA-2 签名",
                                        ))?,
                                )
                            } else {
                                None
                            };
                            session
                                .authenticate_publickey(
                                    &self.0.username,
                                    PrivateKeyWithHashAlg::new(key.clone(), hash),
                                )
                                .await
                                .map_err(failure)?
                        }
                    };
                    if !authenticated.success() {
                        return Err(Error::Rejected);
                    }
                    let channel = session
                        .channel_open_direct_tcpip(
                            target.host(),
                            u32::from(target.port()),
                            "0.0.0.0",
                            0,
                        )
                        .await
                        .map_err(failure)?;
                    Ok(Box::new(SshStream {
                        _guard: guard,
                        channel: channel.into_stream(),
                        _session: session,
                    }) as BoxStream)
                })
                .await
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

pub struct SshFactory;
impl OutboundFactory for SshFactory {
    fn kind(&self) -> &'static str {
        "ssh"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("SSH 出站字段不合法".into()))?;
        Ok(Arc::new(SshOutbound(options.prepare()?)))
    }
}
