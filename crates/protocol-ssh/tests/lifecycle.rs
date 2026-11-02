use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Outbound, ServiceContext, ServiceTask};
use kerlico_ssh::SshFactory;
use russh::{
    keys::{Algorithm, HashAlg, PrivateKey},
    server,
};
use serde_json::{Value, json};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::Notify,
    time::{Instant, timeout},
};

struct Spawner(ServiceContext);
impl russh_util::runtime::TaskSpawner for Spawner {
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<(), russh_util::runtime::SpawnRejected> {
        self.0
            .spawn(future)
            .map_err(|_| russh_util::runtime::SpawnRejected)
    }
}

struct Handler {
    host: ServiceContext,
    block_auth: bool,
    auth_entered: Arc<Notify>,
    auth_release: Arc<Notify>,
}
impl server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.auth_entered.notify_one();
        if self.block_auth {
            self.auth_release.notified().await;
        }
        Ok(if user == "proxy-test" && password == "synthetic-secret" {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<server::Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let mut target = TcpStream::connect((host, u16::try_from(port).unwrap())).await?;
        reply.accept().await;
        let cancel = self.host.cancel();
        self.host
            .spawn(async move {
                let mut stream = channel.into_stream();
                tokio::select! {
                    _ = cancel.cancelled() => {},
                    _ = tokio::io::copy_bidirectional(&mut stream, &mut target) => {},
                }
            })
            .unwrap();
        Ok(())
    }
}

struct Fixture {
    options: Value,
    host: ServiceContext,
    auth_entered: Arc<Notify>,
    auth_release: Arc<Notify>,
}
impl Fixture {
    async fn new(block_auth: bool) -> Self {
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let pin = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = ServiceContext::for_test();
        let owner = host.clone();
        let auth_entered = Arc::new(Notify::new());
        let auth_release = Arc::new(Notify::new());
        let entered = auth_entered.clone();
        let release = auth_release.clone();
        host.spawn(async move {
            let cancel = owner.cancel();
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let handler = Handler { host: owner.clone(), block_auth, auth_entered: entered.clone(), auth_release: release.clone() };
                        let spawner = Arc::new(Spawner(owner.clone()));
                        let config = config.clone();
                        if owner.spawn(async move {
                            russh_util::runtime::scope(spawner, async move {
                                if let Ok(session) = server::run_stream(config, socket, handler).await { let _ = session.await; }
                            }).await;
                        }).is_err() { break; }
                    }
                }
            }
        }).unwrap();
        Self {
            options: options(address.port(), &pin),
            host,
            auth_entered,
            auth_release,
        }
    }
    async fn stop(self) {
        self.auth_release.notify_waiters();
        assert!(
            self.host
                .shutdown(Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
    }
}

fn options(port: u16, pin: &str) -> Value {
    json!({"server":{"host":"127.0.0.1","port":port},"username":"proxy-test","host_key_sha256":[pin],"auth":{"type":"password","password":"synthetic-secret"}})
}

async fn outbound(options: &Value) -> (Arc<dyn Outbound>, ServiceContext) {
    let host = ServiceContext::for_test();
    let outbound = SshFactory
        .compile(options)
        .unwrap()
        .start(host.clone())
        .await
        .unwrap();
    (outbound, host)
}

async fn shutdown(outbound: &Arc<dyn Outbound>, host: &ServiceContext) {
    timeout(Duration::from_secs(2), outbound.shutdown())
        .await
        .unwrap()
        .unwrap();
    let report = host.shutdown(Instant::now() + Duration::from_secs(1)).await;
    assert!(report.is_clean());
    assert_eq!(report.forced_tasks, 0);
}

async fn stalled_kex() -> (Value, Arc<Notify>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let options = options(
        listener.local_addr().unwrap().port(),
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    let entered = Arc::new(Notify::new());
    let ready = entered.clone();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut banner = String::new();
        socket.read_line(&mut banner).await.unwrap();
        assert!(banner.starts_with("SSH-2.0-"));
        socket
            .get_mut()
            .write_all(b"SSH-2.0-synthetic-peer\r\n")
            .await
            .unwrap();
        socket.read_u8().await.unwrap();
        ready.notify_one();
        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest).await;
    });
    (options, entered, peer)
}

#[tokio::test]
async fn service_shutdown_joins_actor_during_stalled_kex() {
    let (options, entered, peer) = stalled_kex().await;
    let (outbound, host) = outbound(&options).await;
    let request = {
        let outbound = outbound.clone();
        tokio::spawn(async move {
            outbound
                .connect_tcp(
                    &Destination::new("example.invalid", 443).unwrap(),
                    &ConnectContext::new(Duration::from_secs(10)),
                )
                .await
        })
    };
    timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    shutdown(&outbound, &host).await;
    assert!(matches!(
        request.await.unwrap(),
        Err(kerlico_core::Error::Cancelled)
    ));
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn request_timeout_joins_stalled_kex_actor() {
    let (options, entered, peer) = stalled_kex().await;
    let (outbound, host) = outbound(&options).await;
    let result = outbound
        .connect_tcp(
            &Destination::new("example.invalid", 443).unwrap(),
            &ConnectContext::new(Duration::from_millis(300)),
        )
        .await;
    assert!(matches!(result, Err(kerlico_core::Error::Timeout)));
    timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    shutdown(&outbound, &host).await;
    timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn service_shutdown_joins_authentication_actor() {
    let fixture = Fixture::new(true).await;
    let (outbound, host) = outbound(&fixture.options).await;
    let request = {
        let outbound = outbound.clone();
        tokio::spawn(async move {
            outbound
                .connect_tcp(
                    &Destination::new("example.invalid", 443).unwrap(),
                    &ConnectContext::new(Duration::from_secs(10)),
                )
                .await
        })
    };
    timeout(Duration::from_secs(2), fixture.auth_entered.notified())
        .await
        .unwrap();
    shutdown(&outbound, &host).await;
    assert!(matches!(
        request.await.unwrap(),
        Err(kerlico_core::Error::Cancelled)
    ));
    fixture.stop().await;
}

async fn echo(host: &ServiceContext) -> (Destination, ServiceTask<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", listener.local_addr().unwrap().port()).unwrap();
    let task = host
        .spawn_tracked(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = socket.split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        })
        .unwrap();
    (target, task)
}

#[tokio::test]
async fn dropping_one_stream_keeps_other_stream_live_until_service_shutdown() {
    let fixture = Fixture::new(false).await;
    let (outbound, host) = outbound(&fixture.options).await;
    let (target_a, peer_a) = echo(&fixture.host).await;
    let (target_b, peer_b) = echo(&fixture.host).await;
    let context = ConnectContext::new(Duration::from_secs(3));
    let first = outbound
        .connect_tcp(&target_a, &context)
        .await
        .unwrap()
        .stream;
    let mut second = outbound
        .connect_tcp(&target_b, &context)
        .await
        .unwrap()
        .stream;
    drop(first);
    timeout(Duration::from_secs(2), peer_a)
        .await
        .unwrap()
        .unwrap();
    second.write_all(b"still-live").await.unwrap();
    let mut bytes = [0; 10];
    timeout(Duration::from_secs(2), second.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"still-live");
    shutdown(&outbound, &host).await;
    timeout(Duration::from_secs(2), peer_b)
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_secs(1), second.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    assert!(!context.cancel.is_cancelled());
    assert!(outbound.connect_tcp(&target_b, &context).await.is_err());
    fixture.stop().await;
}
