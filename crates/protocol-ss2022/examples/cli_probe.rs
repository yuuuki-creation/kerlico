//! 仅供 worker 验证正式 CLI 节点的原生数据报、目标访问与预算边界。
use bytes::BytesMut;
use serde::Deserialize;
use shadowsocks::{
    ServerConfig,
    config::ServerType,
    context::Context,
    crypto::CipherKind,
    relay::{
        socks5::Address,
        tcprelay::ProxyClientStream,
        udprelay::{crypto_io, options::UdpSocketControlData},
    },
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[derive(Deserialize)]
struct Options {
    mode: String,
    server: SocketAddr,
    key: String,
    targets: Vec<SocketAddr>,
    domain_port: Option<u16>,
    other_server: Option<SocketAddr>,
    other_key: Option<String>,
    other_allowed: Option<bool>,
}
fn invalid() -> io::Error {
    io::Error::other("集成探针结果不符")
}
fn config(server: SocketAddr, key: &str) -> io::Result<ServerConfig> {
    ServerConfig::new(
        server,
        key.to_owned(),
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
    )
    .map_err(|_| invalid())
}
fn packet(
    config: &ServerConfig,
    session: u64,
    id: u64,
    target: &Address,
    payload: &[u8],
) -> BytesMut {
    let mut control = UdpSocketControlData::default();
    control.client_session_id = session;
    control.packet_id = id;
    let mut wire = BytesMut::new();
    crypto_io::encrypt_client_payload(
        &Context::new(ServerType::Local),
        config.method(),
        config.key(),
        target,
        &control,
        &[],
        payload,
        &mut wire,
    );
    wire
}
async fn receive(
    socket: &UdpSocket,
    config: &ServerConfig,
    session: u64,
    payload: &[u8],
    family: &[u8],
) -> io::Result<u64> {
    let mut bytes = vec![0; 65536];
    let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut bytes))
        .await
        .map_err(|_| invalid())??;
    let (len, _, control) = crypto_io::decrypt_server_payload(
        &Context::new(ServerType::Local),
        config.method(),
        config.key(),
        &mut bytes[..len],
    )
    .map_err(|_| invalid())?;
    let control = control.ok_or_else(invalid)?;
    let expected = [family, payload].concat();
    if bytes[..len] != expected || control.client_session_id != session {
        return Err(invalid());
    }
    Ok(control.server_session_id)
}
async fn silence(socket: &UdpSocket) -> io::Result<()> {
    let mut bytes = vec![0; 65536];
    if matches!(
        tokio::time::timeout(Duration::from_millis(150), socket.recv(&mut bytes)).await,
        Ok(Ok(_))
    ) {
        return Err(invalid());
    }
    Ok(())
}
async fn tcp(
    server: SocketAddr,
    key: &str,
    target: Address,
    payload: &[u8],
    expected: &[u8],
) -> io::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let socket = TcpStream::connect(server).await?;
        socket.set_nodelay(true)?;
        let mut stream = ProxyClientStream::from_stream(
            Arc::new(Context::new(ServerType::Local)),
            socket,
            &config(server, key)?,
            target,
        );
        stream.write_all(payload).await?;
        stream.flush().await?;
        let mut result = vec![0; expected.len()];
        stream.read_exact(&mut result).await?;
        if result != expected {
            return Err(invalid());
        }
        stream.shutdown().await?;
        Ok(())
    })
    .await
    .map_err(|_| invalid())?
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let file = std::env::args().nth(1).ok_or_else(invalid)?;
    let options: Options = serde_json::from_slice(&std::fs::read(file)?).map_err(|_| invalid())?;
    let config = config(options.server, &options.key)?;
    let bind = if options.server.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let a = UdpSocket::bind(bind).await?;
    a.connect(options.server).await?;
    let b = UdpSocket::bind(bind).await?;
    b.connect(options.server).await?;
    let session = rand::random();
    let target = Address::SocketAddress(options.targets[0]);
    let first = packet(&config, session, 0, &target, b"probe-first");
    a.send(&first).await?;
    let server_id = receive(&a, &config, session, b"probe-first", b"v4|").await?;
    if options.mode == "v6only" {
        tcp(
            options.server,
            &options.key,
            target.clone(),
            b"v6only-tcp",
            b"v4|v6only-tcp",
        )
        .await?;
        let ipv4 = UdpSocket::bind("127.0.0.1:0").await?;
        ipv4.connect((std::net::Ipv4Addr::LOCALHOST, options.server.port()))
            .await?;
        ipv4.send(&packet(&config, rand::random(), 0, &target, b"block-ipv4"))
            .await?;
        silence(&ipv4).await?;
        println!("{{\"mode\":\"v6only\",\"ipv6_tcp_udp\":true,\"ipv4_udp_rejected\":true}}");
        return Ok(());
    }
    if options.mode == "budget" {
        let second = packet(
            &config,
            session,
            1,
            &Address::SocketAddress(options.targets[1]),
            b"block-target",
        );
        a.send(&second).await?;
        silence(&a).await?;
        let other = packet(&config, rand::random(), 0, &target, b"block-session");
        b.send(&other).await?;
        silence(&b).await?;
        if tcp(
            options.server,
            &options.key,
            target.clone(),
            b"block-tcp",
            b"v4|block-tcp",
        )
        .await
        .is_ok()
        {
            return Err(invalid());
        }
        let allowed = options.other_allowed.ok_or_else(invalid)?;
        let result = tcp(
            options.other_server.ok_or_else(invalid)?,
            options.other_key.as_deref().ok_or_else(invalid)?,
            target.clone(),
            b"other-node",
            b"v4|other-node",
        )
        .await;
        if result.is_ok() != allowed {
            return Err(invalid());
        }
        a.send(&packet(&config, session, 2, &target, b"budget-still-works"))
            .await?;
        receive(&a, &config, session, b"budget-still-works", b"v4|").await?;
        println!(
            "{{\"mode\":\"budget\",\"shared_tcp_udp_limit\":true,\"other_node_allowed\":{allowed}}}"
        );
        return Ok(());
    }
    b.send(&first).await?;
    silence(&b).await?;
    let second = packet(
        &config,
        session,
        1,
        &Address::SocketAddress(options.targets[1]),
        b"probe-second",
    );
    b.send(&second).await?;
    if receive(&b, &config, session, b"probe-second", b"v6|").await? != server_id {
        return Err(invalid());
    }
    b.send(&packet(&config, session, 2, &target, b"probe-third"))
        .await?;
    if receive(&b, &config, session, b"probe-third", b"v4|").await? != server_id {
        return Err(invalid());
    }
    b.send(&second).await?;
    silence(&b).await?;
    if let Some(port) = options.domain_port {
        let resolved: Vec<_> = tokio::net::lookup_host(("localhost", port))
            .await?
            .collect();
        if !resolved.iter().any(SocketAddr::is_ipv4) || !resolved.iter().any(SocketAddr::is_ipv6) {
            return Err(invalid());
        }
        let domain = Address::DomainNameAddress("localhost".into(), port);
        b.send(&packet(&config, session, 3, &domain, b"domain-udp"))
            .await?;
        receive(&b, &config, session, b"domain-udp", b"v4|").await?;
        tcp(
            options.server,
            &options.key,
            domain,
            b"domain-tcp",
            b"v4|domain-tcp",
        )
        .await?;
    }
    println!(
        "{{\"mode\":\"udp\",\"replay_rejected\":true,\"migration\":true,\"multi_target\":true,\"domain_ipv4_first\":{}}}",
        options.domain_port.is_some()
    );
    Ok(())
}
