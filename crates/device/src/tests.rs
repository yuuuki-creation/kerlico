use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    AddressedDatagram, Capabilities, InboundContext, NodeId, NodeObserver, NodeTasks, StreamBudget,
    TargetPolicy, TcpConnectInfo,
};
use serde_json::json;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};

fn directory() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap()
}
fn private(number: u8) -> String {
    STANDARD.encode([number; 32])
}
fn public(number: u8) -> String {
    STANDARD.encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([number; 32])).as_bytes(),
    )
}
fn requirements() -> DeviceRequirements {
    DeviceRequirements {
        local_ipv4: true,
        local_ipv6: true,
        auto_warp: true,
    }
}
fn seed(path: &std::path::Path, endpoint: SocketAddr) {
    let store = storage::StateStore::open(path).unwrap();
    store.save(&storage::Record { private_key: private(1), response: Some(json!({"id":"test-device", "token":"test-token", "key":public(1), "key_type":"curve25519", "tunnel_type":"wireguard", "config":{"client_id":"AAAA", "interface":{"addresses":{"v4":"10.77.0.2", "v6":"fd77::2"}}, "peers":[{"public_key":public(2), "endpoint":{"v4":endpoint.to_string(), "v6":endpoint.to_string(), "ports":[endpoint.port()]}}]}})) }).unwrap();
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: kerlico_core::NodeEvent) {}
}
struct NoDns;
impl kerlico_egress::Resolver for NoDns {
    fn resolve<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<std::net::IpAddr>>> {
        Box::pin(async { Err(Error::Unsupported("设备测试禁止目标DNS")) })
    }
}
struct Echo {
    tasks: NodeTasks,
    associations: AtomicUsize,
}
struct Send(mpsc::Sender<AddressedDatagram>);
struct Receive(mpsc::Receiver<AddressedDatagram>);
impl DatagramAssociationSender for Send {
    fn send_to<'a>(
        &'a mut self,
        payload: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0
                .send((target.clone(), payload.to_vec()))
                .await
                .map_err(|_| Error::Cancelled)
        })
    }
}
impl DatagramAssociationReceiver for Receive {
    fn recv_from(&mut self) -> BoxFuture<'_, Result<Option<AddressedDatagram>>> {
        Box::pin(async move { Ok(self.0.recv().await) })
    }
}
impl Outbound for Echo {
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
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            let (front, mut back) = tokio::io::duplex(65536);
            self.tasks.spawn(async move {
                let mut data = Vec::new();
                back.read_to_end(&mut data).await.unwrap();
                back.write_all(&data).await.unwrap();
                back.shutdown().await.unwrap();
            })?;
            Ok(OpenedTcp {
                stream: Box::new(front),
                info: TcpConnectInfo::unknown(),
            })
        })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("测试服务仅多目标UDP")) })
    }
    fn associate_udp<'a>(
        &'a self,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.associations.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let (send, recv) = mpsc::channel(8);
            Ok(DatagramAssociation {
                sender: Box::new(Send(send)),
                receiver: Box::new(Receive(recv)),
            })
        })
    }
}
struct Rig {
    endpoint: SocketAddr,
    context: InboundContext,
    serving: tokio::task::JoinHandle<Result<()>>,
    echo: Arc<Echo>,
}
impl Rig {
    async fn start(ipv6: bool) -> Self {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap(),
        );
        let endpoint = socket.local_addr().unwrap();
        let cancel = kerlico_core::CancellationToken::new();
        let context = InboundContext {
            peer_lease: None,
            peer_addr: None,
            local_addr: Some(endpoint),
            tasks: NodeTasks::new(NodeId::parse("test-node").unwrap(), cancel.clone()),
            cancel,
            connect_timeout: Duration::from_secs(4),
            idle_timeout: Duration::from_secs(5),
            drain_timeout: Duration::from_secs(1),
            max_datagram_size: 65535,
            max_streams: 64,
            stream_budget: StreamBudget::new(
                Arc::new(Semaphore::new(64)),
                Arc::new(Semaphore::new(64)),
            ),
            events: Arc::new(Observer),
        };
        let input = NodeBuildContext::for_test(
            json!({"tunnel":{"private_key":private(2),"addresses":["10.77.0.1","fd77::1"],"mtu":1280}}),
            vec![json!({"public_key":public(1), "allowed_ips":["10.77.0.2/32","fd77::2/128"]})],
        );
        let node = kerlico_wireguard::WireGuardNodeFactory
            .build(&input)
            .unwrap();
        let echo = Arc::new(Echo {
            tasks: context.tasks.clone(),
            associations: AtomicUsize::new(0),
        });
        let (ingress, _) = kerlico_egress::testing::ingress_with_resolver(
            &input,
            echo.clone(),
            TargetPolicy::Local,
            FamilyMode::DualV4Preferred,
            Arc::new(NoDns),
        )
        .unwrap();
        let node_context = context.clone();
        let serving =
            tokio::spawn(async move { node.handle_udp(socket, ingress, node_context).await });
        Self {
            endpoint,
            context,
            serving,
            echo,
        }
    }
    async fn stop(self) {
        self.context.cancel.cancel();
        assert!(matches!(self.serving.await.unwrap(), Err(Error::Cancelled)));
        assert!(
            self.context
                .tasks
                .shutdown_at(Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
    }
}

#[tokio::test]
async fn shared_wireguard_half_close_datagrams_and_mixed_association() {
    for missing_v4 in [false, true] {
        let rig = Rig::start(missing_v4).await;
        let directory = directory();
        let path = directory.path().join("device");
        seed(&path, rig.endpoint);
        let capabilities = if missing_v4 {
            NativeCapabilities {
                ipv4: NativeFamily::Missing,
                ipv6: NativeFamily::Routed,
            }
        } else {
            NativeCapabilities {
                ipv4: NativeFamily::Routed,
                ipv6: NativeFamily::Missing,
            }
        };
        let owner =
            DeviceRuntime::start_with_capabilities(DeviceOptions::new(path), capabilities).unwrap();
        let (first, second) =
            tokio::join!(owner.prepare(requirements()), owner.prepare(requirements()));
        let first = first.unwrap();
        let second = second.unwrap();
        let (a, b) = tokio::join!(owner.state.backend(), owner.state.backend());
        assert!(Arc::ptr_eq(&a.unwrap(), &b.unwrap()));
        let target: SocketAddr = if missing_v4 {
            "192.0.2.5:8080"
        } else {
            "[2001:db8::5]:8080"
        }
        .parse()
        .unwrap();
        let context = ConnectContext::new(Duration::from_secs(5));
        let mut stream = first
            .connect_target_tcp(target, &context)
            .await
            .unwrap()
            .stream;
        let data = vec![0x73; 256 * 1024];
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, data);
        drop(first);
        let mut channel = second
            .connect_target_udp(target, &ConnectContext::new(Duration::from_secs(4)))
            .await
            .unwrap();
        let maximum = if missing_v4 { 65507 } else { 65527 };
        for size in [0, 1, 4096, maximum] {
            let payload = vec![0x65; size];
            channel.sender.send(&payload).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), channel.receiver.recv())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
                payload
            );
        }
        let native =
            tokio::net::UdpSocket::bind(if missing_v4 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap();
        let native_target = destination(native.local_addr().unwrap()).unwrap();
        let warp_target = destination(target).unwrap();
        let mut association = second
            .target_association(&ConnectContext::new(Duration::from_secs(4)))
            .await
            .unwrap();
        let mut prior = None;
        for _ in 0..2 {
            association
                .sender
                .send_to(b"native", &native_target)
                .await
                .unwrap();
            let mut data = [0; 32];
            let (count, source) = native.recv_from(&mut data).await.unwrap();
            if let Some(prior) = prior {
                assert_eq!(source, prior);
            }
            prior = Some(source);
            native.send_to(&data[..count], source).await.unwrap();
            let (source, body) =
                tokio::time::timeout(Duration::from_secs(3), association.receiver.recv_from())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(source, native_target);
            assert_eq!(body, b"native");
            association
                .sender
                .send_to(b"warp", &warp_target)
                .await
                .unwrap();
            let (source, body) =
                tokio::time::timeout(Duration::from_secs(3), association.receiver.recv_from())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            assert_eq!(source, warp_target);
            assert_eq!(body, b"warp");
        }
        assert!(rig.echo.associations.load(Ordering::SeqCst) >= 2);
        drop(channel);
        drop(association);
        drop(stream);
        drop(second);
        assert!(
            owner
                .shutdown_at(Instant::now() + Duration::from_secs(2))
                .await
                .is_clean()
        );
        assert!(owner.retirement().try_join().is_some());
        rig.stop().await;
    }
}

#[tokio::test]
async fn device_survives_first_callers_runtime_and_reports_real_join_after_deadline() {
    let directory = directory();
    let path = directory.path().join("device");
    let owner = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let owner = DeviceRuntime::start_with_capabilities(
                DeviceOptions::new(path),
                NativeCapabilities {
                    ipv4: NativeFamily::Routed,
                    ipv6: NativeFamily::Routed,
                },
            )
            .unwrap();
            owner.prepare(requirements()).await.unwrap();
            owner
        })
    })
    .join()
    .unwrap();
    let lease = owner.prepare(requirements()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let context = ConnectContext::new(Duration::from_secs(2));
    let mut stream = lease
        .connect_target_tcp(listener.local_addr().unwrap(), &context)
        .await
        .unwrap()
        .stream;
    let (mut accepted, _) = listener.accept().await.unwrap();
    stream.write_all(b"alive").await.unwrap();
    let mut data = [0; 5];
    accepted.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"alive");
    let host = owner.state.host.clone();
    owner
        .dispatch(async move {
            host.spawn_blocking_tracked(|| std::thread::sleep(Duration::from_millis(200)))?;
            Ok(())
        })
        .await
        .unwrap();
    let first = Instant::now() + Duration::from_millis(5);
    assert!(owner.shutdown_at(first).await.timed_out);
    assert!(
        owner
            .shared
            .deadline
            .lock()
            .unwrap()
            .is_some_and(|deadline| deadline == first)
    );
    assert!(owner.retirement().wait().await.timed_out);
    assert!(owner.retirement().try_join().is_some());
}

#[tokio::test]
async fn unknown_registration_intent_is_preserved_without_second_attempt() {
    let directory = directory();
    let path = directory.path().join("device");
    let store = storage::StateStore::open(&path).unwrap();
    store
        .save(&storage::Record {
            private_key: private(1),
            response: None,
        })
        .unwrap();
    drop(store);
    let owner = DeviceRuntime::start_with_capabilities(
        DeviceOptions::new(path.clone()),
        NativeCapabilities {
            ipv4: NativeFamily::Routed,
            ipv6: NativeFamily::Missing,
        },
    )
    .unwrap();
    assert!(storage::StateStore::open(&path).is_err());
    let (a, b) = tokio::join!(owner.prepare(requirements()), owner.prepare(requirements()));
    assert!(a.is_err() && b.is_err());
    assert!(
        owner
            .state
            .storage
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .read()
            .unwrap()
            .unwrap()
            .response
            .is_none()
    );
    assert!(
        owner
            .shutdown_at(Instant::now() + Duration::from_secs(2))
            .await
            .is_clean()
    );
    assert!(storage::StateStore::open(&path).is_ok());
}

#[test]
fn private_state_rejects_public_directories_and_links() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = directory();
    let path = directory.path().join("device");
    let store = storage::StateStore::open(&path).unwrap();
    store
        .save(&storage::Record {
            private_key: private(1),
            response: None,
        })
        .unwrap();
    drop(store);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(storage::StateStore::open(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = directory.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(storage::StateStore::open(&link).is_err());
    let identity = path.join("identity.json");
    let hard = path.join("hard.json");
    std::fs::hard_link(&identity, &hard).unwrap();
    let store = storage::StateStore::open(&path).unwrap();
    assert!(store.read().is_err());
}

#[tokio::test]
#[ignore = "仅海外复用已保存profile；缺失身份时禁止发起注册"]
async fn real_cloudflare_saved_profile_both_families() {
    let path = std::env::var_os("KERLICO_WARP_REAL_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                std::env::var_os("KERLICO_TEST_ASSETS_DIR")
                    .expect("真实测试只允许海外worker私有目录"),
            )
            .parent()
            .unwrap()
            .join("device-warp-runtime-private")
        });
    let store = storage::StateStore::open(&path).unwrap();
    assert!(
        store
            .read()
            .unwrap()
            .is_some_and(|record| record.response.is_some()),
        "真实数据面验证要求已有完整profile，禁止自动注册"
    );
    drop(store);
    let owner = DeviceRuntime::start_with_capabilities(
        DeviceOptions::existing(path),
        NativeCapabilities {
            ipv4: NativeFamily::Routed,
            ipv6: NativeFamily::Missing,
        },
    )
    .unwrap();
    let result = owner.prepare(requirements()).await;
    let lease = match result {
        Ok(lease) => lease,
        Err(error) => {
            assert!(
                owner
                    .shutdown_at(Instant::now() + Duration::from_secs(2))
                    .await
                    .is_clean()
            );
            panic!("{error}");
        }
    };
    let backend = owner.state.backend().await.unwrap();
    for ipv6 in [false, true] {
        let address = tokio::net::lookup_host(("www.cloudflare.com", 443))
            .await
            .unwrap()
            .find(|address| address.is_ipv6() == ipv6)
            .expect("测试网站须提供对应地址族");
        let context = ConnectContext::new(Duration::from_secs(10));
        let stream = if ipv6 {
            lease
                .connect_target_tcp(address, &context)
                .await
                .unwrap()
                .stream
        } else {
            backend
                .connect_tcp(&destination(address).unwrap(), &context)
                .await
                .unwrap()
                .stream
        };
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
        .with_no_client_auth();
        let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("www.cloudflare.com").unwrap(),
                stream,
            )
            .await
            .unwrap();
        stream.write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let status = response
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        assert!(
            response.starts_with(b"HTTP/1.1 200"),
            "trace HTTP status: {}",
            String::from_utf8_lossy(status)
        );
        assert!(response.windows(8).any(|part| part == b"warp=on\n"));
        let dns = if ipv6 {
            "[2606:4700:4700::1111]:53"
        } else {
            "1.1.1.1:53"
        }
        .parse()
        .unwrap();
        let mut channel = backend
            .connect_udp(
                &destination(dns).unwrap(),
                &ConnectContext::new(Duration::from_secs(5)),
            )
            .await
            .unwrap();
        channel.sender.send(b"\x4b\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01").await.unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), channel.receiver.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(response.len() > 12 && response[..2] == [0x4b, 0x11] && response[2] & 0x80 != 0);
    }
    drop(backend);
    drop(lease);
    assert!(
        owner
            .shutdown_at(Instant::now() + Duration::from_secs(2))
            .await
            .is_clean()
    );
}

fn prepared_engine(mode: &str, wireguard: bool) -> kerlico_config::PreparedConfig {
    let mut registry = kerlico_config::Registry::default();
    registry.register(kerlico_net::DirectFactory).unwrap();
    registry
        .register(kerlico_wireguard::WireGuardFactory)
        .unwrap();
    let outbound = if wireguard {
        json!({"tag":"exit","type":"wireguard", "options":{"tunnel":{"private_key":private(1),"addresses":["10.77.0.2","fd77::2"]},"peer":{"public_key":public(2),"allowed_ips":["0.0.0.0/0","::/0"]},"endpoint":{"host":"127.0.0.1","port":12345}}})
    } else {
        json!({"tag":"exit","type":"direct"})
    };
    registry.prepare(kerlico_config::parse(&serde_json::to_vec(&json!({"version":2,"outbounds":[outbound],"inbounds":[{"tag":"entry","type":"tcp-forward","mode":mode,"listen":"127.0.0.1:0","target":{"host":"2001:db8::5","port":8080},"outbound":"exit"}]})).unwrap()).unwrap()).unwrap()
}
#[test]
fn only_dual_stack_native_targets_request_automatic_warp() {
    assert!(
        prepared_engine("dual-stack", false)
            .device_requirements()
            .auto_warp
    );
    let single = prepared_engine("ipv4-only", false).device_requirements();
    assert!(single.local_ipv4);
    assert!(!single.local_ipv6 && !single.auto_warp);
    let tunnel = prepared_engine("dual-stack", true).device_requirements();
    assert!(!tunnel.local_ipv4 && !tunnel.local_ipv6 && !tunnel.auto_warp);
}
#[tokio::test]
async fn two_engines_share_device_and_first_engine_exit_keeps_second_running() {
    let rig = Rig::start(false).await;
    let directory = directory();
    let path = directory.path().join("device");
    seed(&path, rig.endpoint);
    let owner = DeviceRuntime::start_with_capabilities(
        DeviceOptions::new(path),
        NativeCapabilities {
            ipv4: NativeFamily::Routed,
            ipv6: NativeFamily::Missing,
        },
    )
    .unwrap();
    let first = prepared_engine("dual-stack", false);
    let lease = owner.prepare(first.device_requirements()).await.unwrap();
    let first = kerlico_engine::Engine::bind_with_device(first, lease.clone())
        .await
        .unwrap();
    let second =
        kerlico_engine::Engine::bind_with_device(prepared_engine("dual-stack", false), lease)
            .await
            .unwrap();
    let first_address = first.listeners().unwrap()[0].1;
    let second_address = second.listeners().unwrap()[0].1;
    let first_telemetry = first.telemetry();
    let second_telemetry = second.telemetry();
    let cancel_first = kerlico_core::CancellationToken::new();
    let cancel_second = kerlico_core::CancellationToken::new();
    let first_task = tokio::spawn(first.run(cancel_first.clone()));
    let second_task = tokio::spawn(second.run(cancel_second.clone()));
    async fn echo(address: SocketAddr, payload: &[u8]) {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, payload);
    }
    echo(first_address, b"first").await;
    cancel_first.cancel();
    first_task.await.unwrap().unwrap();
    echo(second_address, b"second-owner-alive").await;
    cancel_second.cancel();
    second_task.await.unwrap().unwrap();
    assert_eq!(first_telemetry.usage().unwrap().engine.upload_bytes, 5);
    assert_eq!(second_telemetry.usage().unwrap().engine.upload_bytes, 18);
    assert!(
        owner
            .state
            .prepared
            .get()
            .is_some_and(|result| result.is_ok())
    );
    assert!(
        owner
            .shutdown_at(Instant::now() + Duration::from_secs(2))
            .await
            .is_clean()
    );
    rig.stop().await;
}

enum ControlledShutdown {
    Clean,
    Error,
    Pending(Arc<AtomicBool>),
}
struct ControlledBackend(ControlledShutdown);
impl Outbound for ControlledBackend {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: true,
            udp: true,
        }
    }
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            match &self.0 {
                ControlledShutdown::Clean => Ok(()),
                ControlledShutdown::Error => Err(Error::Protocol("受控设备后端关闭失败")),
                ControlledShutdown::Pending(dropped) => {
                    struct Guard(Arc<AtomicBool>);
                    impl Drop for Guard {
                        fn drop(&mut self) {
                            self.0.store(true, Ordering::Release);
                        }
                    }
                    let _guard = Guard(dropped.clone());
                    std::future::pending::<Result<()>>().await
                }
            }
        })
    }
    fn connect_tcp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async { Err(Error::Unsupported("受控后端不建立业务连接")) })
    }
    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("受控后端不建立业务连接")) })
    }
}
fn controlled_device(backend: ControlledShutdown) -> (DeviceRuntime, tempfile::TempDir) {
    let directory = directory();
    let owner = DeviceRuntime::start_with_capabilities(
        DeviceOptions::new(directory.path().join("device")),
        NativeCapabilities {
            ipv4: NativeFamily::Routed,
            ipv6: NativeFamily::Routed,
        },
    )
    .unwrap();
    assert!(
        owner
            .state
            .prepared
            .set(Ok(Arc::new(ControlledBackend(backend))))
            .is_ok()
    );
    (owner, directory)
}
#[tokio::test]
async fn background_failure_changes_phase_preserves_first_cause_and_fails_real_receipt() {
    let (owner, _directory) = controlled_device(ControlledShutdown::Clean);
    owner.prepare(DeviceRequirements::default()).await.unwrap();
    assert_eq!(owner.phase(), DevicePhase::Ready);
    let failure = ServiceFailure::Io(std::io::ErrorKind::ConnectionReset, "受控设备后台载体失败");
    let (trigger, receive) = oneshot::channel();
    let host = owner.state.host.clone();
    owner
        .dispatch(async move {
            let failed = host.clone();
            host.spawn(async move {
                receive.await.unwrap();
                failed.fail(failure);
            })?;
            Ok(())
        })
        .await
        .unwrap();
    trigger.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while owner.phase() != DevicePhase::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(owner.failure(), Some(failure));
    owner
        .state
        .host
        .fail(ServiceFailure::Protocol("受控稍后失败"));
    assert_eq!(owner.failure(), Some(failure));
    assert!(
        matches!(owner.prepare(DeviceRequirements::default()).await,Err(Error::Io(error)) if error.kind()==std::io::ErrorKind::ConnectionReset)
    );
    let retirement = owner.retirement();
    let report = owner
        .shutdown_at(Instant::now() + Duration::from_secs(2))
        .await;
    assert!(!report.is_clean());
    assert!(report.failed_tasks >= 1);
    assert_eq!(owner.phase(), DevicePhase::Closed);
    drop(owner);
    assert_eq!(retirement.failure(), Some(failure));
    assert!(retirement.try_join().is_some());
}
#[tokio::test]
async fn backend_shutdown_error_is_counted_and_retained_after_native_join() {
    let (owner, _directory) = controlled_device(ControlledShutdown::Error);
    owner.prepare(DeviceRequirements::default()).await.unwrap();
    let receipt = owner.retirement();
    let report = owner
        .shutdown_at(Instant::now() + Duration::from_secs(2))
        .await;
    assert!(!report.timed_out);
    assert_eq!(report.failed_tasks, 1);
    assert!(!report.is_clean());
    assert_eq!(
        receipt.failure(),
        Some(ServiceFailure::Protocol("受控设备后端关闭失败"))
    );
    assert_eq!(owner.phase(), DevicePhase::Closed);
    drop(owner);
    assert!(receipt.try_join().is_some());
    assert_eq!(
        receipt.failure(),
        Some(ServiceFailure::Protocol("受控设备后端关闭失败"))
    );
}
#[tokio::test]
async fn backend_shutdown_timeout_is_latched_into_native_join_receipt() {
    let dropped = Arc::new(AtomicBool::new(false));
    let (owner, _directory) = controlled_device(ControlledShutdown::Pending(dropped.clone()));
    owner.prepare(DeviceRequirements::default()).await.unwrap();
    let first = Instant::now() + Duration::from_millis(20);
    assert!(owner.shutdown_at(first).await.timed_out);
    let receipt = owner.retirement();
    let report = tokio::time::timeout(Duration::from_secs(2), receipt.wait())
        .await
        .unwrap();
    assert!(report.timed_out);
    assert!(!report.is_clean());
    assert!(dropped.load(Ordering::Acquire));
    assert_eq!(receipt.failure(), Some(ServiceFailure::Timeout));
    assert!(
        owner
            .shutdown_at(Instant::now() + Duration::from_secs(10))
            .await
            .timed_out
    );
    assert_eq!(owner.shared.deadline.lock().unwrap().unwrap(), first);
    assert_eq!(owner.phase(), DevicePhase::Closed);
    assert!(receipt.try_join().is_some());
}
