mod common;
use bytes::Bytes;
use common::*;
use jls_proto::{crypto, transport_parameters::TransportParameters};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{io::AsyncReadExt, net::UdpSocket};
fn addr(target: std::net::SocketAddr, id: u16) -> Vec<u8> {
    let mut out = vec![1];
    match target.ip() {
        std::net::IpAddr::V4(ip) => out.extend(ip.octets()),
        _ => panic!("测试目标必须是 IPv4"),
    };
    out.extend(target.port().to_be_bytes());
    out.extend(id.to_be_bytes());
    out
}
async fn client(f: &Fixture) -> (jls_quinn::Endpoint, jls_quinn::Connection) {
    let endpoint = jls_quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connection = tokio::time::timeout(
        Duration::from_secs(3),
        endpoint
            .connect_with(
                client_config(0x6b3343cf, None, Some(("node-1", "synthetic-password-1"))),
                f.address,
                NAME,
            )
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(connection.is_jls(), Some(true));
    (endpoint, connection)
}
#[tokio::test]
async fn early_datagrams_are_bounded_and_conflicting_control_id_cannot_redirect_association() {
    let f = fixture("v2", "datagram", "127.0.0.1", "cubic").await;
    let (endpoint, connection) = client(&f).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (mut control, mut response) = connection.open_bi().await.unwrap();
    control.write_all(&[3, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    connection
        .send_datagram(Bytes::from_static(b"\x00\x07early"))
        .unwrap();
    for id in 1000u16..1300 {
        let mut packet = id.to_be_bytes().to_vec();
        packet.extend([1; 500]);
        let _ = connection.send_datagram(Bytes::from(packet));
        tokio::task::yield_now().await;
    }
    let mapping = addr(target.local_addr().unwrap(), 7);
    control.write_all(&mapping[..2]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    control.write_all(&mapping[2..]).await.unwrap();
    let mut buffer = [0; 64];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"early");
    target.send_to(b"reply", peer).await.unwrap();
    let mut source = [0; 7];
    tokio::time::timeout(Duration::from_secs(3), response.read_exact(&mut source))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source[0], 1);
    assert_eq!(
        u16::from_be_bytes(source[5..7].try_into().unwrap()),
        target.local_addr().unwrap().port()
    );
    let reply_id = response.read_u16().await.unwrap();
    let packet = connection.read_datagram().await.unwrap();
    assert_eq!(
        u16::from_be_bytes(packet[..2].try_into().unwrap()),
        reply_id
    );
    assert_eq!(&packet[2..], b"reply");
    let (mut second, mut closed) = connection.open_bi().await.unwrap();
    second.write_all(&[3, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    second
        .write_all(&addr(other.local_addr().unwrap(), 7))
        .await
        .unwrap();
    let mut byte = [0; 1];
    let result = tokio::time::timeout(Duration::from_secs(3), closed.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(result, Ok(None) | Err(_)));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), other.recv_from(&mut buffer))
            .await
            .is_err()
    );
    let mut next = 7u16.to_be_bytes().to_vec();
    next.extend_from_slice(b"still-correct");
    connection.send_datagram(Bytes::from(next)).unwrap();
    let (n, next_peer) =
        tokio::time::timeout(Duration::from_secs(3), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&buffer[..n], b"still-correct");
    assert_eq!(next_peer.port(), peer.port());
    connection.close(0u32.into(), b"");
    endpoint.close(0u32.into(), b"");
}
struct FalseVersion {
    omit: bool,
    inner: Arc<jls_proto::crypto::rustls::QuicClientConfig>,
}
fn variable(bytes: &[u8], position: &mut usize) -> u64 {
    let n = 1usize << ((bytes[*position] >> 6) as usize);
    let mut value = (bytes[*position] & 63) as u64;
    for byte in &bytes[*position + 1..*position + n] {
        value = (value << 8) | u64::from(*byte);
    }
    *position += n;
    value
}
impl crypto::ClientConfig for FalseVersion {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, jls_proto::ConnectError> {
        let mut bytes = Vec::new();
        params.write(&mut bytes);
        let mut position = 0;
        while position < bytes.len() {
            let start = position;
            let id = variable(&bytes, &mut position);
            let len = variable(&bytes, &mut position) as usize;
            if id == 0x11 && self.omit {
                bytes.drain(start..position + len);
                position = start;
                continue;
            }
            if id == 0x11 {
                bytes[position..position + 4].copy_from_slice(&1u32.to_be_bytes());
                bytes[position + 4..position + 8].copy_from_slice(&1u32.to_be_bytes());
            }
            position += len;
        }
        let params =
            TransportParameters::read(jls_proto::Side::Server, &mut bytes.as_slice()).unwrap();
        self.inner.clone().start_session(version, name, &params)
    }
}
#[tokio::test]
async fn authenticated_version_information_cannot_claim_v1_or_omit_on_v2_wire() {
    for omit in [false, true] {
        let f = fixture("v2", "stream", "127.0.0.1", "cubic").await;
        let crypto = jls_proto::crypto::rustls::QuicClientConfig::try_from(plain_crypto(
            vec![b"h3".to_vec()],
            None,
            Some(("node-1", "synthetic-password-1")),
        ))
        .unwrap();
        let mut config = jls_quinn::ClientConfig::new(Arc::new(FalseVersion {
            omit,
            inner: Arc::new(crypto),
        }));
        config.version(0x6b3343cf);
        let endpoint = jls_quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            endpoint.connect_with(config, f.address, NAME).unwrap(),
        )
        .await
        .unwrap();
        let error = result.expect_err("不一致的受认证版本信息被接受");
        let code = match error {
            jls_quinn::ConnectionError::ConnectionClosed(error) => u64::from(error.error_code),
            jls_quinn::ConnectionError::TransportError(error) => u64::from(error.code),
            _ => panic!("版本信息失败未返回传输错误"),
        };
        assert_eq!(code, 0x11);
        assert_eq!(f.count.load(Ordering::Acquire), 0);
        endpoint.close(0u32.into(), b"");
    }
}
#[tokio::test]
async fn incomplete_request_shutdown_does_not_keep_node_budget_or_port() {
    let mut f = fixture("v2", "stream", "127.0.0.1", "cubic").await;
    let (endpoint, connection) = client(&f).await;
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send.write_all(&[1, 4, 0]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    f.stop().await;
    assert_eq!(f.global.available_permits(), 64);
    let socket = UdpSocket::bind(f.address).await.unwrap();
    drop(socket);
    connection.close(0u32.into(), b"");
    endpoint.close(0u32.into(), b"");
}
