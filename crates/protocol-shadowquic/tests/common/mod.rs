#![allow(dead_code)]
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, InboundContext, NodeEvent, NodeObserver, Outbound, Result,
    StreamBudget,
};
use kerlico_shadowquic::{ShadowQuicFactory, ShadowQuicNodeFactory};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Semaphore, task::JoinSet};
pub const NAME: &str = "cover.invalid";
pub struct Cover {
    pub endpoint: jls_quinn::Endpoint,
    pub certificate: Vec<u8>,
    pub address: std::net::SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Cover {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
        self.task.abort();
    }
}
pub fn plain_crypto(
    alpn: Vec<Vec<u8>>,
    certificate: Option<&[u8]>,
    user: Option<(&str, &str)>,
) -> rustls_jls::ClientConfig {
    let mut roots = rustls_jls::RootCertStore::empty();
    if let Some(certificate) = certificate {
        roots
            .add(rustls_jls::pki_types::CertificateDer::from(
                certificate.to_vec(),
            ))
            .unwrap();
    }
    let mut tls = rustls_jls::ClientConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = alpn;
    tls.enable_early_data = false;
    tls.resumption = rustls_jls::client::Resumption::disabled();
    tls.jls_config = match user {
        Some((username, password)) => rustls_jls::jls::JlsClientConfig::new(password, username),
        None => rustls_jls::jls::JlsClientConfig::default().enable(false),
    };
    tls
}
pub fn client_config(
    version: u32,
    certificate: Option<&[u8]>,
    user: Option<(&str, &str)>,
) -> jls_quinn::ClientConfig {
    let mut config = jls_quinn::ClientConfig::new(Arc::new(
        jls_quinn::crypto::rustls::QuicClientConfig::try_from(plain_crypto(
            vec![b"h3".to_vec()],
            certificate,
            user,
        ))
        .unwrap(),
    ));
    config.version(version);
    config
}
pub async fn cover(host: &str) -> Cover {
    let cert = rcgen::generate_simple_self_signed(vec![NAME.into()]).unwrap();
    let certificate = cert.cert.der().to_vec();
    let key = rustls_jls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls_jls::ServerConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls_jls::pki_types::CertificateDer::from(
            certificate.clone(),
        )],
        key.into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.jls_config = rustls_jls::jls::JlsServerConfig::default()
        .enable(false)
        .into();
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    let mut server = jls_quinn::ServerConfig::with_crypto(Arc::new(
        jls_quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let mut transport = jls_quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        jls_quinn::IdleTimeout::try_from(Duration::from_secs(10)).unwrap(),
    ));
    server.transport_config(Arc::new(transport));
    let socket = std::net::UdpSocket::bind((host, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut config = jls_quinn::EndpointConfig::default();
    config.supported_versions(vec![1, 0x6b3343cf]);
    let endpoint = jls_quinn::Endpoint::new(
        config,
        Some(server),
        socket,
        Arc::new(jls_quinn::TokioRuntime),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let accepting = endpoint.clone();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        while let Some(incoming) = accepting.accept().await {
            tasks.spawn(async move {
                if let Ok(connection) = incoming.await {
                    let mut streams = JoinSet::new();
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        streams.spawn(async move {
                            let _ = tokio::io::copy(&mut recv, &mut send).await;
                            let _ = send.finish();
                        });
                    }
                }
            });
            while tasks.try_join_next().is_some() {}
        }
    });
    Cover {
        endpoint,
        certificate,
        address,
        task,
    }
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
struct Access {
    inner: kerlico_egress::Egress,
    count: Arc<AtomicUsize>,
}
impl AccessService for Access {
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::associate_udp(&self.inner, c)
    }
    fn connect_tcp<'a>(
        &'a self,
        t: &'a Destination,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_tcp(&self.inner, t, c)
    }
    fn connect_udp<'a>(
        &'a self,
        t: &'a Destination,
        c: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_udp(&self.inner, t, c)
    }
}
pub struct Fixture {
    pub outbound: Arc<dyn Outbound>,
    pub options: Value,
    pub node_options: Value,
    pub address: std::net::SocketAddr,
    pub count: Arc<AtomicUsize>,
    pub global: Arc<Semaphore>,
    pub cancel: CancellationToken,
    pub cover: Cover,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Fixture {
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}
pub async fn fixture(version: &str, mode: &str, host: &str, congestion: &str) -> Fixture {
    fixture_custom(
        version,
        mode,
        host,
        congestion,
        None,
        1,
        64,
        Duration::from_secs(10),
    )
    .await
}
// 显式列出矩阵维度与预算，调用处可直接核对测试组合。
#[allow(clippy::too_many_arguments)]
pub async fn fixture_custom(
    version: &str,
    mode: &str,
    host: &str,
    congestion: &str,
    outbound: Option<Arc<dyn Outbound>>,
    identity: u8,
    streams: usize,
    idle: Duration,
) -> Fixture {
    let cover = cover(if host == "::1" { "127.0.0.1" } else { "::1" }).await;
    let username = format!("node-{identity}");
    let password = format!("synthetic-password-{identity}");
    let node_options = json!({"username":username,"password":password,"upstream":{"host":cover.address.ip().to_string(),"port":cover.address.port()},"server_name":NAME,"quic_versions":["v1","v2"],"congestion_control":congestion});
    let node = ShadowQuicNodeFactory.build(&node_options).unwrap();
    let socket = Arc::new(UdpSocket::bind((host, 0)).await.unwrap());
    let address = socket.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let global = Arc::new(Semaphore::new(64));
    let context = InboundContext {
        peer_addr: None,
        local_addr: Some(address),
        cancel: cancel.clone(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: idle,
        drain_timeout: Duration::from_millis(300),
        max_datagram_size: 65535,
        max_streams: streams,
        stream_budget: StreamBudget::new(global.clone(), Arc::new(Semaphore::new(64))),
        events: Arc::new(Observer),
    };
    let count = Arc::new(AtomicUsize::new(0));
    let access = Arc::new(Access {
        inner: kerlico_egress::Egress::new(
            outbound.unwrap_or_else(|| kerlico_net::DirectFactory.build(&json!({})).unwrap()),
        ),
        count: count.clone(),
    });
    let task = tokio::spawn(async move { node.handle_udp(socket, access, context).await });
    let options = json!({"username":username,"password":password,"server":{"host":host,"port":address.port()},"server_name":NAME,"quic_version":version,"udp_mode":mode,"congestion_control":congestion});
    let outbound = ShadowQuicFactory.build(&options).unwrap();
    Fixture {
        outbound,
        options,
        node_options,
        address,
        count,
        global,
        cancel,
        cover,
        task: Some(task),
    }
}
pub async fn plain_connection(
    fixture: &Fixture,
    version: u32,
) -> (jls_quinn::Endpoint, jls_quinn::Connection) {
    let endpoint = jls_quinn::Endpoint::client(if fixture.address.is_ipv6() {
        "[::1]:0".parse().unwrap()
    } else {
        "127.0.0.1:0".parse().unwrap()
    })
    .unwrap();
    let connection = tokio::time::timeout(
        Duration::from_secs(3),
        endpoint
            .connect_with(
                client_config(version, Some(&fixture.cover.certificate), None),
                fixture.address,
                NAME,
            )
            .unwrap(),
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "普通 QUIC 版本 {version:x} 超时：{error}；上游握手 {:?}；剩余许可 {}",
            fixture.cover.endpoint.stats(),
            fixture.global.available_permits()
        )
    })
    .unwrap();
    (endpoint, connection)
}
