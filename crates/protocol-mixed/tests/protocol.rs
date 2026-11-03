use kerlico_config::{Registry, parse};
use kerlico_core::{CancellationToken, Error};
use kerlico_engine::Engine;
use kerlico_mixed::MixedNodeFactory;
use kerlico_net::DirectFactory;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Duration, timeout},
};

const USER_ID: &str = "00000000-0000-4000-8000-000000000001";
const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXRlc3Qtc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn registry() -> Registry {
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    registry.register_node(MixedNodeFactory).unwrap();
    registry.register_node(kerlico_http::HttpNodeFactory).unwrap();
    registry
}

fn account() -> Value {
    json!({"user_id":USER_ID,"username":"member_a","password_hash":PASSWORD_HASH})
}

fn member() -> Value {
    json!({"user_id":USER_ID,"native_credential":{"username":"member-a","password":"synthetic-secret"}})
}

fn config(section: &str, options: Value, members: Value) -> Value {
    let mut value = json!({
        "version":2,
        "accounts":[account()],
        "outbounds":[{"tag":"exit","type":"direct"}],
    });
    value[section] = json!([{
        "tag":"mixed","type":"mixed","listen":"127.0.0.1:0","outbound":"exit",
        "options":options,"members":members,
    }]);
    value
}

fn prepare(value: &Value) -> kerlico_core::Result<kerlico_config::PreparedConfig> {
    registry().prepare(parse(&serde_json::to_vec(value).unwrap()).unwrap())
}

async fn start(value: Value) -> (SocketAddr, CancellationToken) {
    let engine = Engine::bind(prepare(&value).unwrap()).await.unwrap();
    let address = engine.listeners().unwrap()[0].1;
    let cancel = CancellationToken::new();
    tokio::spawn(engine.run(cancel.clone()));
    (address, cancel)
}

async fn echo_target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 1024];
                while let Ok(count) = stream.read(&mut bytes).await {
                    if count == 0 || stream.write_all(&bytes[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

async fn exact<S: AsyncRead + Unpin>(stream: &mut S, count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    timeout(Duration::from_secs(5), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

async fn assert_echo<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(b"mixed-echo").await.unwrap();
    assert_eq!(exact(stream, 10).await, b"mixed-echo");
}

async fn socks5_no_auth<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(exact(stream, 2).await, [5, 0]);
}

async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, target: SocketAddr) {
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let reply = exact(stream, 10).await;
    assert_eq!(reply[..2], [5, 0]);
}

async fn http_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.extend(exact(stream, 1).await);
    }
    String::from_utf8(head).unwrap()
}

#[tokio::test]
async fn one_port_serves_http_and_all_socks_versions() {
    let target = echo_target().await;
    let (address, cancel) = start(config("local_inbounds", json!({}), json!([]))).await;

    let mut http = TcpStream::connect(address).await.unwrap();
    http.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(http_head(&mut http).await.starts_with("HTTP/1.1 200"));
    assert_echo(&mut http).await;

    let mut four = TcpStream::connect(address).await.unwrap();
    let mut request = vec![4, 1];
    request.extend(target.port().to_be_bytes());
    request.extend([127, 0, 0, 1]);
    request.extend(b"any-userid\0");
    four.write_all(&request).await.unwrap();
    assert_eq!(exact(&mut four, 8).await[..2], [0, 90]);
    assert_echo(&mut four).await;

    let mut four_a = TcpStream::connect(address).await.unwrap();
    let mut request = vec![4, 1];
    request.extend(target.port().to_be_bytes());
    request.extend([0, 0, 0, 1]);
    request.extend(b"\0localhost\0");
    four_a.write_all(&request).await.unwrap();
    assert_eq!(exact(&mut four_a, 8).await[..2], [0, 90]);
    assert_echo(&mut four_a).await;

    let mut five = TcpStream::connect(address).await.unwrap();
    socks5_no_auth(&mut five).await;
    socks5_connect(&mut five, target).await;
    assert_echo(&mut five).await;
    cancel.cancel();
}

#[tokio::test]
async fn plain_http_request_is_forwarded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let head = http_head(&mut stream).await;
        assert!(head.starts_with("GET /path HTTP/1.1"), "{head}");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let (address, cancel) = start(config("local_inbounds", json!({}), json!([]))).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client
        .write_all(
            format!("GET http://{target}/path HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    assert!(http_head(&mut client).await.starts_with("HTTP/1.1 200"));
    assert_eq!(exact(&mut client, 2).await, b"ok");
    cancel.cancel();
}

/// 建立 UDP 关联并返回控制连接（保持关联存活）和 relay 地址。
async fn associate(address: SocketAddr) -> (TcpStream, Vec<u8>) {
    let mut control = TcpStream::connect(address).await.unwrap();
    socks5_no_auth(&mut control).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let reply = exact(&mut control, 10).await;
    (control, reply)
}

#[tokio::test]
async fn socks5_udp_associate_relays_datagrams() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    tokio::spawn(async move {
        let mut bytes = [0; 64];
        let (count, peer) = target.recv_from(&mut bytes).await.unwrap();
        target.send_to(&bytes[..count], peer).await.unwrap();
    });
    let (address, cancel) = start(config("local_inbounds", json!({}), json!([]))).await;
    let (_control, reply) = associate(address).await;
    assert_eq!(reply[..2], [5, 0]);
    let relay = SocketAddr::new(
        std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]).into(),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend(target_address.port().to_be_bytes());
    packet.extend(b"udp-echo");
    client.send_to(&packet, relay).await.unwrap();
    let mut bytes = [0; 64];
    let (count, _) = timeout(Duration::from_secs(5), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[10..count], b"udp-echo");
    cancel.cancel();
}

#[tokio::test]
async fn udp_false_rejects_associate_with_command_not_supported() {
    let (address, cancel) = start(config("local_inbounds", json!({"udp":false}), json!([]))).await;
    let (_control, reply) = associate(address).await;
    assert_eq!(reply[..2], [5, 7]);
    cancel.cancel();
}

#[tokio::test]
async fn members_authenticate_http_and_socks5_and_deny_socks4() {
    let target = echo_target().await;
    let (address, cancel) = start(config("nodes", json!({}), json!([member()]))).await;

    let mut no_credentials = TcpStream::connect(address).await.unwrap();
    no_credentials
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = http_head(&mut no_credentials).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    assert!(head.to_ascii_lowercase().contains("proxy-authenticate: basic"));

    // member-a:synthetic-secret
    let mut http = TcpStream::connect(address).await.unwrap();
    http.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic bWVtYmVyLWE6c3ludGhldGljLXNlY3JldA==\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(http_head(&mut http).await.starts_with("HTTP/1.1 200"));
    assert_echo(&mut http).await;

    let mut no_method = TcpStream::connect(address).await.unwrap();
    socks5_offer_no_auth_rejected(&mut no_method).await;

    let mut wrong = TcpStream::connect(address).await.unwrap();
    socks5_password(&mut wrong, b"member-a", b"wrong-secret", 1).await;

    let mut five = TcpStream::connect(address).await.unwrap();
    socks5_password(&mut five, b"member-a", b"synthetic-secret", 0).await;
    socks5_connect(&mut five, target).await;
    assert_echo(&mut five).await;

    let mut four = TcpStream::connect(address).await.unwrap();
    let mut request = vec![4, 1];
    request.extend(target.port().to_be_bytes());
    request.extend([127, 0, 0, 1]);
    request.extend(b"member-a\0");
    four.write_all(&request).await.unwrap();
    assert_eq!(exact(&mut four, 8).await[..2], [0, 91]);
    cancel.cancel();
}

async fn socks5_offer_no_auth_rejected(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(exact(stream, 2).await, [5, 255]);
}

async fn socks5_password(stream: &mut TcpStream, user: &[u8], password: &[u8], status: u8) {
    stream.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(exact(stream, 2).await, [5, 2]);
    let mut request = vec![1, user.len() as u8];
    request.extend(user);
    request.push(password.len() as u8);
    request.extend(password);
    stream.write_all(&request).await.unwrap();
    assert_eq!(exact(stream, 2).await, [1, status]);
}

#[tokio::test]
async fn non_proxy_first_byte_gets_http_bad_request() {
    let (address, cancel) = start(config("local_inbounds", json!({}), json!([]))).await;
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"\x16\x03\x01garbage\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    let _ = timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .unwrap();
    assert!(
        response.is_empty() || response.starts_with(b"HTTP/1.1 400"),
        "{response:?}"
    );
    cancel.cancel();
}

#[tokio::test]
async fn tls_wraps_every_branch_and_first_byte_comes_from_plaintext() {
    let target = echo_target().await;
    let key = rcgen::generate_simple_self_signed(vec!["mixed.test".to_owned()]).unwrap();
    let (address, cancel) = start(config(
        "nodes",
        json!({"tls":{"cert_pem":key.cert.pem(),"key_pem":key.signing_key.serialize_pem()}}),
        json!([member()]),
    ))
    .await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert.der().clone()).unwrap();
    let client = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    ));
    let name = rustls::pki_types::ServerName::try_from("mixed.test").unwrap();

    let tcp = TcpStream::connect(address).await.unwrap();
    let mut http = client.connect(name.clone(), tcp).await.unwrap();
    http.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic bWVtYmVyLWE6c3ludGhldGljLXNlY3JldA==\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(http_head(&mut http).await.starts_with("HTTP/1.1 200"));
    assert_echo(&mut http).await;

    let tcp = TcpStream::connect(address).await.unwrap();
    let mut five = client.connect(name, tcp).await.unwrap();
    five.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(exact(&mut five, 2).await, [5, 2]);
    let mut auth = vec![1, 8];
    auth.extend(b"member-a");
    auth.push(16);
    auth.extend(b"synthetic-secret");
    five.write_all(&auth).await.unwrap();
    assert_eq!(exact(&mut five, 2).await, [1, 0]);
    socks5_connect(&mut five, target).await;
    assert_echo(&mut five).await;
    cancel.cancel();
}

fn rejection(value: &Value) -> String {
    match prepare(value) {
        Ok(_) => panic!("配置应被拒绝"),
        Err(Error::Config(message)) => message,
        Err(other) => panic!("错误类型不符：{other}"),
    }
}

#[test]
fn invalid_combinations_fail_at_check() {
    rejection(&config("nodes", json!({}), json!([])));
    rejection(&config("local_inbounds", json!({"unknown":1}), json!([])));
    rejection(&config("local_inbounds", json!({"udp":"yes"}), json!([])));
    rejection(&config(
        "local_inbounds",
        json!({"tls":{"cert_pem":"bad","key_pem":"bad"}}),
        json!([]),
    ));

    let mut public_without_members = config("local_inbounds", json!({}), json!([]));
    public_without_members["local_inbounds"][0]["listen"] = json!("0.0.0.0:0");
    rejection(&public_without_members);

    // 用户名含冒号时 HTTP Basic 无法表示，密码超过 255 字节时 SOCKS5 无法表示。
    for credential in [
        json!({"username":"a:b","password":"synthetic-secret"}),
        json!({"username":"member-a","password":"x".repeat(256)}),
    ] {
        rejection(&config(
            "nodes",
            json!({}),
            json!([{"user_id":USER_ID,"native_credential":credential}]),
        ));
    }

    let mut public_with_members = config("nodes", json!({}), json!([member()]));
    public_with_members["nodes"][0]["listen"] = json!("0.0.0.0:0");
    assert!(prepare(&public_with_members).is_ok());
}

#[test]
fn credentials_cannot_be_reused_on_a_http_node() {
    let mut value = config("nodes", json!({}), json!([member()]));
    value["nodes"].as_array_mut().unwrap().push(json!({
        "tag":"http-node","type":"http","listen":"127.0.0.1:0","outbound":"exit",
        "options":{},"members":[member()],
    }));
    rejection(&value);
}

#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}

#[tokio::test]
async fn socks5_and_http_clients_keep_member_scope() {
    let users = vec![
        json!({"username":"member-a","password":"synthetic-secret-a"}),
        json!({"username":"member-b","password":"synthetic-secret-b"}),
    ];
    let clients: Vec<Value> = users.iter().map(|user| json!({"auth":user})).collect();
    shared::assert_member_scope(
        &MixedNodeFactory,
        &kerlico_socks::SocksFactory,
        json!({}),
        users.clone(),
        clients.clone(),
    )
    .await;
    shared::assert_member_scope(
        &MixedNodeFactory,
        &kerlico_http::HttpFactory,
        json!({}),
        users,
        clients,
    )
    .await;
}
