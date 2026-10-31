use kerlico_config::OutboundFactory;
use kerlico_core::{CancellationToken, ConnectContext, Destination, Error, Outbound};
use kerlico_egress::Egress;
use kerlico_ssh::SshFactory;
use russh::{
    keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, PublicKey, ssh_key::LineEnding},
    server,
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

#[derive(Default)]
struct Counts {
    active: AtomicUsize,
    requests: AtomicUsize,
    passwords: AtomicUsize,
}
struct Handler {
    counts: Arc<Counts>,
    keys: Arc<Vec<PublicKey>>,
    password: String,
}
impl Drop for Handler {
    fn drop(&mut self) {
        self.counts.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> std::result::Result<server::Auth, Self::Error> {
        self.counts.passwords.fetch_add(1, Ordering::SeqCst);
        Ok(if user == "proxy-test" && password == self.password {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> std::result::Result<server::Auth, Self::Error> {
        Ok(
            if user == "proxy-test"
                && self
                    .keys
                    .iter()
                    .any(|allowed| allowed.key_data() == key.key_data())
            {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<server::Msg>,
        host: &str,
        port: u32,
        origin: &str,
        origin_port: u32,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> std::result::Result<(), Self::Error> {
        assert_eq!(origin, "0.0.0.0");
        assert_eq!(origin_port, 0);
        self.counts.requests.fetch_add(1, Ordering::SeqCst);
        let remote = TcpStream::connect((host, u16::try_from(port).unwrap())).await;
        match remote {
            Ok(mut remote) => {
                reply.accept().await;
                tokio::spawn(async move {
                    let mut channel = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut channel, &mut remote).await;
                });
            }
            Err(_) => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }
}
struct Fixture {
    address: SocketAddr,
    pin: String,
    counts: Arc<Counts>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
fn key(algorithm: Algorithm) -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), algorithm).unwrap()
}

impl Fixture {
    async fn new(host: &str, password: &str, keys: Vec<PublicKey>) -> Self {
        let host_key = key(Algorithm::Ed25519);
        let pin = host_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let cfg = Arc::new(server::Config {
            keys: vec![host_key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: Some(Duration::from_secs(3)),
            ..Default::default()
        });
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let counts = Arc::new(Counts::default());
        let observed = counts.clone();
        let password = password.to_owned();
        let keys = Arc::new(keys);
        let cancel = CancellationToken::new();
        let stopped = cancel.clone();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    _=stopped.cancelled()=>break,
                    Some(_)=sessions.join_next(),if !sessions.is_empty()=>{},
                    accepted=listener.accept()=>{let(stream,_)=accepted.unwrap();let cfg=cfg.clone();let counts=observed.clone();counts.active.fetch_add(1,Ordering::SeqCst);let handler=Handler{counts,keys:keys.clone(),password:password.clone()};sessions.spawn(async move{if let Ok(session)=server::run_stream(cfg,stream,handler).await{let _=session.await;}});}
                }
            }
        });
        Self {
            address,
            pin,
            counts,
            cancel,
            task,
        }
    }
    fn options(&self, auth: Value) -> Value {
        json!({"server":{"host":self.address.ip().to_string(),"port":self.address.port()},"username":"proxy-test","host_key_sha256":[self.pin],"auth":auth})
    }
    async fn drained(&self) {
        timeout(Duration::from_secs(1), async {
            while self.counts.active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

async fn echo(host: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        if stream.read_to_end(&mut bytes).await.is_ok() {
            let _ = stream.write_all(&bytes).await;
            let _ = stream.shutdown().await;
        }
    });
    (address, task)
}

#[tokio::test]
async fn password_all_families_domain_and_half_close() {
    for node_host in ["127.0.0.1", "::1"] {
        let fixture = Fixture::new(node_host, "fixture-password", vec![]).await;
        let out = Arc::new(Egress::new(
            SshFactory
                .build(&fixture.options(json!({"type":"password","password":"fixture-password"})))
                .unwrap(),
        ));
        for (host, target_host) in [
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "::1"),
            ("127.0.0.1", "localhost"),
        ] {
            let (address, peer) = echo(host).await;
            let context = ConnectContext::new(Duration::from_secs(3));
            let mut stream = out
                .connect_tcp(
                    &Destination::new(target_host, address.port()).unwrap(),
                    &context,
                )
                .await
                .unwrap();
            let payload = vec![0x51; 262_145];
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, payload);
            drop(stream);
            peer.await.unwrap();
            fixture.drained().await;
        }
    }
}

#[tokio::test]
async fn public_key_algorithms_and_encrypted_private_key() {
    let algorithms = [
        Algorithm::Ed25519,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP384,
        },
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP521,
        },
        Algorithm::Rsa { hash: None },
    ];
    for algorithm in algorithms {
        let key = key(algorithm);
        let fixture = Fixture::new("127.0.0.1", "not-used", vec![key.public_key().clone()]).await;
        for encrypted in [false, true] {
            let private = if encrypted {
                key.encrypt(&mut rand::rng(), "synthetic-passphrase")
                    .unwrap()
            } else {
                key.clone()
            };
            let mut auth = json!({"type":"publickey","private_key_pem":private.to_openssh(LineEnding::LF).unwrap().to_string()});
            if encrypted {
                auth["passphrase"] = json!("synthetic-passphrase");
            }
            let out = SshFactory.build(&fixture.options(auth)).unwrap();
            let (address, peer) = echo("127.0.0.1").await;
            let mut stream = out
                .connect_tcp(
                    &Destination::new("127.0.0.1", address.port()).unwrap(),
                    &ConnectContext::new(Duration::from_secs(5)),
                )
                .await
                .unwrap();
            stream.write_all(b"key-auth").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut bytes = Vec::new();
            timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, b"key-auth");
            drop(stream);
            peer.await.unwrap();
            fixture.drained().await;
        }
    }
}

#[tokio::test]
async fn rejects_wrong_identity_and_host_without_target_access() {
    let fixture = Fixture::new("127.0.0.1", "correct-password", vec![]).await;
    let base = fixture.options(json!({"type":"password","password":"correct-password"}));
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Destination::new("127.0.0.1", unused.local_addr().unwrap().port()).unwrap();
    drop(unused);
    let wrong_key = key(Algorithm::Ed25519);
    for (index, options) in [
        {let mut value=base.clone();value["auth"]["password"]=json!("wrong-password");value},
        {let mut value=base.clone();value["username"]=json!("wrong-user");value},
        {let mut value=base.clone();value["host_key_sha256"]=json!([wrong_key.public_key().fingerprint(HashAlg::Sha256).to_string()]);value},
        fixture.options(json!({"type":"publickey","private_key_pem":wrong_key.to_openssh(LineEnding::LF).unwrap().to_string()})),
    ].into_iter().enumerate() {
        let passwords_before=fixture.counts.passwords.load(Ordering::SeqCst);
        assert!(SshFactory.build(&options).unwrap().connect_tcp(&target,&ConnectContext::new(Duration::from_secs(2))).await.is_err());fixture.drained().await;assert_eq!(fixture.counts.requests.load(Ordering::SeqCst),0);
        if index>=2 {assert_eq!(fixture.counts.passwords.load(Ordering::SeqCst),passwords_before);}
    }
    let before = fixture.counts.passwords.load(Ordering::SeqCst);
    let mut pins = base;
    pins["host_key_sha256"] = json!([
        wrong_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string(),
        fixture.pin
    ]);
    let out = SshFactory.build(&pins).unwrap();
    assert!(matches!(
        out.connect_tcp(&target, &ConnectContext::new(Duration::from_secs(2)))
            .await,
        Err(Error::Io(_))
    ));
    fixture.drained().await;
    assert_eq!(fixture.counts.passwords.load(Ordering::SeqCst), before + 1);
}

#[tokio::test]
async fn timeout_and_drop_close_actual_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let observed = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(1), stream.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
    });
    let options = json!({"server":{"host":"127.0.0.1","port":port},"username":"proxy-test","host_key_sha256":["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],"auth":{"type":"password","password":"synthetic"}});
    let out = SshFactory.build(&options).unwrap();
    let target = Destination::new("127.0.0.1", 9).unwrap();
    assert!(matches!(
        out.connect_tcp(&target, &ConnectContext::new(Duration::from_millis(60)))
            .await,
        Err(Error::Timeout)
    ));
    observed.await.unwrap();
    let context = ConnectContext::new(Duration::from_secs(1));
    context.cancel.cancel();
    assert!(matches!(
        out.connect_tcp(&target, &context).await,
        Err(Error::Cancelled)
    ));
    let fixture = Fixture::new("127.0.0.1", "password", vec![]).await;
    let out = SshFactory
        .build(&fixture.options(json!({"type":"password","password":"password"})))
        .unwrap();
    let (address, peer) = echo("127.0.0.1").await;
    let context = ConnectContext::new(Duration::from_secs(2));
    let stream = out
        .connect_tcp(
            &Destination::new("127.0.0.1", address.port()).unwrap(),
            &context,
        )
        .await
        .unwrap();
    drop(stream);
    fixture.drained().await;
    peer.await.unwrap();
}

#[tokio::test]
async fn cancellation_and_parallel_credentials_stay_scoped() {
    let first = Fixture::new("127.0.0.1", "first-password", vec![]).await;
    let second = Fixture::new("::1", "second-password", vec![]).await;
    let mut tasks = JoinSet::new();
    for fixture in [&first, &second] {
        let password = if fixture.address.is_ipv4() {
            "first-password"
        } else {
            "second-password"
        };
        let out = SshFactory
            .build(&fixture.options(json!({"type":"password","password":password})))
            .unwrap();
        for index in 0..4 {
            let out = out.clone();
            tasks.spawn(async move {
                let (address, peer) = echo("127.0.0.1").await;
                let context = ConnectContext::new(Duration::from_secs(3));
                let mut stream = out
                    .connect_tcp(
                        &Destination::new("127.0.0.1", address.port()).unwrap(),
                        &context,
                    )
                    .await
                    .unwrap();
                let payload = vec![index; 16_385];
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, payload);
                drop(stream);
                peer.await.unwrap();
            });
        }
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    first.drained().await;
    second.drained().await;
    let out = SshFactory
        .build(&first.options(json!({"type":"password","password":"first-password"})))
        .unwrap();
    let (address, peer) = echo("127.0.0.1").await;
    let context = ConnectContext::new(Duration::from_secs(2));
    let mut stream = out
        .connect_tcp(
            &Destination::new("127.0.0.1", address.port()).unwrap(),
            &context,
        )
        .await
        .unwrap();
    context.cancel.cancel();
    let mut bytes = Vec::new();
    let _ = timeout(Duration::from_secs(1), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    drop(stream);
    first.drained().await;
    peer.await.unwrap();
}

#[test]
fn config_unknown_fields_key_permissions_and_missing_capabilities() {
    let base = json!({"server":{"host":"127.0.0.1","port":22},"username":"proxy-test","host_key_sha256":["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],"auth":{"type":"password","password":"password"}});
    for value in [
        {
            let mut value = base.clone();
            value["host_key_sha256"] = json!([]);
            value
        },
        {
            let mut value = base.clone();
            value["host_key_sha256"] = json!(["invalid"]);
            value
        },
        {
            let mut value = base.clone();
            value["insecure"] = json!(true);
            value
        },
        {
            let mut value = base.clone();
            value["auth"]["type"] = json!("none");
            value
        },
        {
            let mut value = base.clone();
            value["username"] = json!("");
            value
        },
        {
            let mut value = base.clone();
            value["auth"] = json!({"type":"publickey","private_key_pem":"invalid"});
            value
        },
    ] {
        assert!(SshFactory.build(&value).is_err());
    }
    let out = SshFactory.build(&base).unwrap();
    assert!(out.capabilities().tcp_eof);
    assert!(!out.capabilities().udp);
    assert!(!out.supports_udp_association());
    let key = key(Algorithm::Ed25519);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-key");
    std::fs::write(&path, key.to_openssh(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let mut value = base;
    value["auth"] = json!({"type":"publickey","private_key_file":path.to_string_lossy()});
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SshFactory.build(&value).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(SshFactory.build(&value).is_ok());
}
