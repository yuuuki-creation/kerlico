//! 专用 worker 合成普通 QUIC 上游；仅作 JLS 回退互通的测试对端。
use std::{sync::Arc, time::Duration};
use tokio::task::JoinSet;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args
        .get(1)
        .is_some_and(|value| value == "probe" || value == "probe-jls")
    {
        return probe(&args[2..], args[1] == "probe-jls").await;
    }
    if args.len() != 4 {
        return Err("需要监听地址、证书输出文件和 QUIC 版本参数".into());
    }
    let bind = args[1].parse::<std::net::SocketAddr>()?;
    if !bind.ip().is_loopback() {
        return Err("合成上游仅允许回环地址".into());
    }
    let versions = match args[3].as_str() {
        "v1" => vec![1],
        "v2" => vec![0x6b3343cf],
        "both" => vec![1, 0x6b3343cf],
        _ => return Err("QUIC 版本不合法".into()),
    };
    let cert = rcgen::generate_simple_self_signed(vec!["cover.invalid".into()])?;
    std::fs::write(&args[2], cert.cert.pem())?;
    let key = rustls_jls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls_jls::ServerConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls_jls::pki_types::CertificateDer::from(
            cert.cert.der().to_vec(),
        )],
        key.into(),
    )?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.jls_config = rustls_jls::jls::JlsServerConfig::default()
        .enable(false)
        .into();
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    let mut server = jls_quinn::ServerConfig::with_crypto(Arc::new(
        jls_quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    let mut transport = jls_quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(jls_quinn::IdleTimeout::try_from(
        Duration::from_secs(10),
    )?));
    server.transport_config(Arc::new(transport));
    let mut config = jls_quinn::EndpointConfig::default();
    config.supported_versions(versions);
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.set_nonblocking(true)?;
    let endpoint = jls_quinn::Endpoint::new(
        config,
        Some(server),
        socket,
        Arc::new(jls_quinn::TokioRuntime),
    )?;
    println!("合成 QUIC 上游已监听");
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {_=tokio::signal::ctrl_c()=>break,_=tasks.join_next(),if !tasks.is_empty()=>{},incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};tasks.spawn(async move{if let Ok(connection)=incoming.await{let mut streams=JoinSet::new();while let Ok((mut send,mut recv))=connection.accept_bi().await{streams.spawn(async move{let _=tokio::io::copy(&mut recv,&mut send).await;let _=send.finish();});}streams.abort_all();}});}}
    }
    endpoint.close(0u32.into(), b"");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn probe(args: &[String], jls: bool) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 3 {
        return Err("探测需要目标地址、合成证书文件和版本".into());
    }
    let target = args[0].parse::<std::net::SocketAddr>()?;
    if !target.ip().is_loopback() {
        return Err("合成探测仅允许回环目标".into());
    }
    let version = match args[2].as_str() {
        "v1" => 1,
        "v2" => 0x6b3343cf,
        _ => return Err("QUIC 版本不合法".into()),
    };
    let certificates = rustls_pemfile::certs(&mut std::io::Cursor::new(std::fs::read(&args[1])?))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut roots = rustls_jls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate)?;
    }
    let mut tls = rustls_jls::ClientConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.jls_config = if jls {
        // 与本项目互通工具相同的合成身份，仅用于回环握手诊断。
        rustls_jls::jls::JlsClientConfig::new("synthetic-password", "node-user")
    } else {
        rustls_jls::jls::JlsClientConfig::default().enable(false)
    };
    tls.resumption = rustls_jls::client::Resumption::disabled();
    let mut config = jls_quinn::ClientConfig::new(Arc::new(
        jls_quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.version(version);
    let endpoint = jls_quinn::Endpoint::client(if target.is_ipv6() {
        "[::1]:0".parse()?
    } else {
        "127.0.0.1:0".parse()?
    })?;
    let connection = tokio::time::timeout(
        Duration::from_secs(4),
        endpoint.connect_with(config, target, "cover.invalid")?,
    )
    .await??;
    if jls {
        if connection.is_jls() != Some(true) {
            return Err("合成 JLS 探测认证失败".into());
        }
        connection.close(0u32.into(), b"");
        endpoint.close(0u32.into(), b"");
        println!("合成 JLS 握手验证通过");
        return Ok(());
    }
    if connection.is_jls() == Some(true) {
        return Err("普通 QUIC 探测被错误识别为 JLS".into());
    }
    let (mut send, mut recv) = connection.open_bi().await?;
    tokio::io::AsyncWriteExt::write_all(&mut send, b"ordinary-quic-cover").await?;
    let mut answer = [0; 19];
    tokio::time::timeout(
        Duration::from_secs(4),
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut answer),
    )
    .await??;
    if &answer != b"ordinary-quic-cover" {
        return Err("普通 QUIC 上游回写不一致".into());
    }
    connection.close(0u32.into(), b"");
    endpoint.close(0u32.into(), b"");
    println!("普通 QUIC 回退验证通过");
    Ok(())
}
