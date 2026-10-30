use kerlico_core::{Destination, Error};
use kerlico_vless::{
    UserId, VlessStream,
    codec::{self, Command, RequestHeader},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

fn request(host: &str, command: Command) -> RequestHeader {
    RequestHeader {
        user: UserId::from_bytes([0; 16]),
        command,
        target: Destination::new(host, 443).unwrap(),
    }
}

#[tokio::test]
async fn fixed_ipv4_wire_vector_and_no_payload_overread() {
    let mut data = Vec::new();
    codec::write_request(&mut data, &request("127.0.0.1", Command::Tcp))
        .await
        .unwrap();
    let mut expected = vec![0; 18];
    expected.extend_from_slice(&[1, 1, 187, 1, 127, 0, 0, 1]);
    assert_eq!(data, expected);
    data.extend_from_slice(b"payload");
    let mut source = data.as_slice();
    let parsed = codec::read_request(&mut source).await.unwrap();
    assert!(parsed.user.matches(&UserId::from_bytes([0; 16])));
    assert_eq!(parsed.command, Command::Tcp);
    assert_eq!(parsed.target, Destination::new("127.0.0.1", 443).unwrap());
    assert_eq!(source, b"payload");
}

#[tokio::test]
async fn all_address_types_and_every_header_truncation() {
    for host in ["127.0.0.1", "example.invalid", "2001:db8::1"] {
        for command in [Command::Tcp, Command::Udp] {
            let header = request(host, command);
            let mut data = Vec::new();
            codec::write_request(&mut data, &header).await.unwrap();
            for size in 0..data.len() {
                assert!(
                    codec::read_request(&mut &data[..size]).await.is_err(),
                    "截断长度 {size}"
                );
            }
            let parsed = codec::read_request(&mut data.as_slice()).await.unwrap();
            assert_eq!(parsed.target, header.target);
            assert_eq!(parsed.command, command);
        }
    }
}

#[tokio::test]
async fn rejects_invalid_version_command_address_and_flow() {
    let mut original = Vec::new();
    codec::write_request(&mut original, &request("127.0.0.1", Command::Tcp))
        .await
        .unwrap();
    for (index, value) in [(0, 1), (18, 3), (21, 9)] {
        let mut data = original.clone();
        data[index] = value;
        assert!(codec::read_request(&mut data.as_slice()).await.is_err());
    }
    let flow = b"xtls-rprx-vision";
    let mut addons = vec![0x0a, flow.len() as u8];
    addons.extend_from_slice(flow);
    let mut data = original[..17].to_vec();
    data.push(addons.len() as u8);
    data.extend(addons);
    data.extend_from_slice(&original[18..]);
    assert!(matches!(
        codec::read_request(&mut data.as_slice()).await,
        Err(Error::Unsupported(_))
    ));
    let mut data = original[..17].to_vec();
    data.extend_from_slice(&[2, 0x48, 0x07]);
    data.extend_from_slice(&original[18..]);
    assert!(codec::read_request(&mut data.as_slice()).await.is_ok());
    let mut data = original[..17].to_vec();
    data.extend_from_slice(&[1, 0x80]);
    data.extend_from_slice(&original[18..]);
    assert!(codec::read_request(&mut data.as_slice()).await.is_err());
}

#[tokio::test]
async fn udp_frames_preserve_zero_and_maximum_and_reject_truncation() {
    let mut bytes = Vec::new();
    for packet in [vec![], vec![7], vec![3; 65_535]] {
        codec::write_datagram(&mut bytes, &packet).await.unwrap();
    }
    let mut source = bytes.as_slice();
    assert_eq!(
        codec::read_datagram(&mut source, 65_535).await.unwrap(),
        Some(vec![])
    );
    assert_eq!(
        codec::read_datagram(&mut source, 65_535).await.unwrap(),
        Some(vec![7])
    );
    assert_eq!(
        codec::read_datagram(&mut source, 65_535).await.unwrap(),
        Some(vec![3; 65_535])
    );
    assert_eq!(
        codec::read_datagram(&mut source, 65_535).await.unwrap(),
        None
    );
    for bad in [&[0u8][..], &[0, 2, 1][..]] {
        assert!(codec::read_datagram(&mut &bad[..], 65_535).await.is_err());
    }
    assert!(matches!(
        codec::read_datagram(&mut &[0, 2, 1, 2][..], 1).await,
        Err(Error::ResourceLimit)
    ));
    assert!(matches!(
        codec::write_datagram(&mut Vec::new(), &vec![0; 65_536]).await,
        Err(Error::ResourceLimit)
    ));
}

#[tokio::test]
async fn stream_writes_before_response_and_handles_byte_fragments() {
    let (client, mut server) = tokio::io::duplex(1);
    let mut client = VlessStream::new(client);
    let peer = tokio::spawn(async move {
        let mut bytes = [0; 4];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        for byte in [0, 2, 0x48, 7, b'p', b'o', b'n', b'g'] {
            server.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    timeout(Duration::from_secs(2), client.write_all(b"ping"))
        .await
        .unwrap()
        .unwrap();
    let mut reply = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"pong");
    peer.await.unwrap();
}

#[tokio::test]
async fn response_failure_is_terminal_and_header_is_not_body() {
    for bytes in [vec![], vec![0], vec![0, 2, 0x48], vec![1, 0]] {
        let mut stream = VlessStream::new(bytes.as_slice());
        let mut data = [0; 8];
        assert!(stream.read(&mut data).await.is_err());
        assert!(stream.read(&mut data).await.is_err());
    }
    let mut source = &[0, 0, 9, 8, 7][..];
    codec::read_response(&mut source).await.unwrap();
    assert_eq!(source, &[9, 8, 7]);
    assert!(!UserId::from_bytes([0; 16]).matches(&UserId::from_bytes([1; 16])));
    assert!(!format!("{:?}", UserId::from_bytes([1; 16])).contains("010101"));
}

#[tokio::test]
async fn udp_does_not_hide_a_truncated_response_as_clean_eof() {
    for bytes in [vec![], vec![0], vec![0, 1]] {
        let mut stream = VlessStream::new(bytes.as_slice());
        assert!(codec::read_datagram(&mut stream, 65_535).await.is_err());
    }
    let mut stream = VlessStream::new(&[0, 0][..]);
    assert!(
        codec::read_datagram(&mut stream, 65_535)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn logical_write_close_does_not_close_the_carrier_before_response() {
    let (client, mut peer) = tokio::io::duplex(128);
    let mut client = VlessStream::new(client);
    let server = tokio::spawn(async move {
        let mut payload = [0; 4];
        peer.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        let mut byte = [0];
        assert!(
            timeout(Duration::from_millis(30), peer.read(&mut byte))
                .await
                .is_err()
        );
        codec::write_response(&mut peer).await.unwrap();
        peer.write_all(b"reply").await.unwrap();
    });
    client.write_all(b"ping").await.unwrap();
    client.shutdown().await.unwrap();
    assert!(client.write_all(b"not-written").await.is_err());
    let mut reply = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"reply");
    server.await.unwrap();
}
