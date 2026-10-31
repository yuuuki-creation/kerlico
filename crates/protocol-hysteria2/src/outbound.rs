use crate::{
    config::{self, ClientOptions, Limits},
    invalid, io, udp, wire,
};
use bytes::Bytes;
use http::{HeaderValue, Request};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, Capabilities, ConnectContext, DatagramAssociation, DatagramChannel,
    Destination, Error, Outbound, Result,
};
use rand::Rng;
use serde_json::Value;
use std::{
    future::poll_fn,
    net::UdpSocket,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

type AuthSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
struct Session {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    auth_sender: StdMutex<Option<AuthSender>>,
    driver: tokio::task::JoinHandle<()>,
    udp_driver: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    registry: Arc<udp::Registry>,
    tcp_slots: Arc<Semaphore>,
    udp_enabled: bool,
}
impl Session {
    fn alive(&self) -> bool {
        self.connection.close_reason().is_none() && !self.driver.is_finished()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.connection.close(0x100u32.into(), b"");
        self.endpoint.close(0x100u32.into(), b"");
        self.driver.abort();
        if let Ok(driver) = self.udp_driver.get_mut()
            && let Some(driver) = driver.take()
        {
            driver.abort();
        }
        if let Ok(sender) = self.auth_sender.get_mut() {
            sender.take();
        }
    }
}
struct Pending {
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    driver: Option<tokio::task::JoinHandle<()>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(connection) = &self.connection {
            connection.close(0x100u32.into(), b"");
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(0x100u32.into(), b"");
        }
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}
struct TcpOwner {
    _session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
}
pub struct Hysteria2Outbound {
    server: Destination,
    name: String,
    tls: Arc<rustls::ClientConfig>,
    auth: HeaderValue,
    salamander: Option<Arc<String>>,
    limits: Limits,
    pool: Mutex<Option<Arc<Session>>>,
}
impl Hysteria2Outbound {
    pub fn from_options(options: &Value) -> Result<Self> {
        let options: ClientOptions = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Hysteria2 出站字段不合法".into()))?;
        config::auth(&options.auth)?;
        options.limits.validate()?;
        let mut auth = HeaderValue::from_str(&options.auth).map_err(|_| invalid())?;
        auth.set_sensitive(true);
        Ok(Self {
            server: Destination::new(&options.server.host, options.server.port)?,
            name: options.tls.server_name.clone(),
            tls: config::client_tls(&options.tls)?,
            auth,
            salamander: config::obfs(options.salamander_password)?,
            limits: options.limits,
            pool: Mutex::new(None),
        })
    }
    async fn session(&self) -> Result<Arc<Session>> {
        let mut pool = self.pool.lock().await;
        if let Some(session) = pool.as_ref().filter(|session| session.alive()) {
            return Ok(session.clone());
        }
        pool.take();
        let mut peers: Vec<_> =
            tokio::net::lookup_host((self.server.host().as_str(), self.server.port()))
                .await?
                .collect();
        peers.sort_by_key(|peer| peer.is_ipv6());
        let peer = *peers.first().ok_or(Error::InvalidAddress)?;
        let socket = UdpSocket::bind(if peer.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?;
        socket.set_nonblocking(true)?;
        let transport = self
            .limits
            .transport(self.limits.max_streams, self.salamander.is_some())?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*self.tls).clone())
            .map_err(|_| invalid())?;
        let mut client = quinn::ClientConfig::new(Arc::new(crypto));
        client.transport_config(transport);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            crate::socket::wrap(socket, self.salamander.clone())?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(client);
        let mut pending = Pending {
            endpoint: Some(endpoint),
            connection: None,
            driver: None,
        };
        let connection = pending
            .endpoint
            .as_ref()
            .expect("端点已创建")
            .connect(peer, &self.name)
            .map_err(|_| invalid())?
            .await
            .map_err(|_| invalid())?;
        pending.connection = Some(connection.clone());
        let (mut driver, mut sender) = h3::client::builder()
            .max_field_section_size(8192)
            .build(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|_| invalid())?;
        let driver_connection = connection.clone();
        pending.driver = Some(tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            driver_connection.close(0x100u32.into(), b"");
        }));
        let padding: String = rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(256)
            .map(char::from)
            .collect();
        let request = Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("hysteria-auth", self.auth.clone())
            .header("hysteria-cc-rx", "0")
            .header("hysteria-padding", padding)
            .body(())
            .map_err(|_| invalid())?;
        let mut stream = sender.send_request(request).await.map_err(|_| invalid())?;
        stream.finish().await.map_err(|_| invalid())?;
        let response = stream.recv_response().await.map_err(|_| invalid())?;
        if response.status().as_u16() != 233 {
            return Err(Error::Rejected);
        }
        let one = |name: &str| -> Result<&str> {
            let mut values = response.headers().get_all(name).iter();
            let value = values.next().ok_or_else(invalid)?;
            if values.next().is_some() {
                return Err(invalid());
            }
            value.to_str().map_err(|_| invalid())
        };
        let udp_enabled = match one("hysteria-udp")? {
            "true" => true,
            "false" => false,
            _ => return Err(invalid()),
        };
        let rate = one("hysteria-cc-rx")?;
        if rate != "auto" {
            if rate.is_empty() || !rate.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            let rate: u64 = rate.parse().map_err(|_| invalid())?;
            if rate != 0 {
                return Err(Error::Unsupported("Hysteria2 固定速率拥塞模式尚未实现"));
            }
        }
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        drop(stream);
        let registry = udp::Registry::new(self.limits.clone());
        let udp_driver = udp_enabled.then(|| registry.spawn(connection.clone()));
        let session = Arc::new(Session {
            endpoint: pending.endpoint.take().expect("端点存在"),
            connection: pending.connection.take().expect("连接存在"),
            auth_sender: StdMutex::new(Some(sender)),
            driver: pending.driver.take().expect("驱动已创建"),
            udp_driver: StdMutex::new(udp_driver),
            registry,
            tcp_slots: Arc::new(Semaphore::new(self.limits.max_streams)),
            udp_enabled,
        });
        *pool = Some(session.clone());
        Ok(session)
    }
}
impl Outbound for Hysteria2Outbound {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let session = self.session().await?;
                    let permit = session
                        .tcp_slots
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| Error::ResourceLimit)?;
                    let (send, receive) =
                        session.connection.open_bi().await.map_err(|_| invalid())?;
                    let owner = Arc::new(TcpOwner {
                        _session: session,
                        _permit: permit,
                    });
                    let mut stream = io::Stream {
                        send,
                        receive,
                        prefix: Bytes::new(),
                        _owner: owner,
                    };
                    wire::send_request(&mut stream, &target.to_string()).await?;
                    wire::response(&mut stream).await?;
                    Ok(Box::new(stream) as BoxStream)
                })
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            context
                .run(async {
                    let session = self.session().await?;
                    if !session.udp_enabled || session.connection.max_datagram_size().is_none() {
                        return Err(Error::Unsupported("Hysteria2 对端未启用 UDP"));
                    }
                    udp::fixed(
                        &session.registry,
                        session.connection.clone(),
                        target.clone(),
                        context.cancel.clone(),
                        session.clone(),
                    )
                })
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            context
                .run(async {
                    let session = self.session().await?;
                    if !session.udp_enabled || session.connection.max_datagram_size().is_none() {
                        return Err(Error::Unsupported("Hysteria2 对端未启用 UDP"));
                    }
                    udp::association(
                        &session.registry,
                        session.connection.clone(),
                        context.cancel.clone(),
                        session.clone(),
                    )
                })
                .await
        })
    }
}
pub struct Hysteria2Factory;
impl OutboundFactory for Hysteria2Factory {
    fn kind(&self) -> &'static str {
        "hysteria2"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn Outbound>> {
        Ok(Arc::new(Hysteria2Outbound::from_options(options)?))
    }
}
