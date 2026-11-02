use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Error, ServiceContext};
use kerlico_net::DirectFactory;
use serde_json::json;
use std::time::Duration;
use tokio::{net::UdpSocket, time::timeout};

#[tokio::test]
async fn association_accepts_family_payload_limits_and_rejects_oversize() {
    let direct = DirectFactory
        .compile(&json!({}))
        .unwrap()
        .start(ServiceContext::for_test())
        .await
        .unwrap();
    let context = ConnectContext::new(Duration::from_secs(2));
    let mut channel = direct.associate_udp(&context).await.unwrap();
    for (listen, maximum) in [("127.0.0.1:0", 65507), ("[::1]:0", 65527)] {
        let target = UdpSocket::bind(listen).await.unwrap();
        let address = target.local_addr().unwrap();
        let destination = Destination::new(&address.ip().to_string(), address.port()).unwrap();
        let payload = vec![0x5a; maximum];
        channel
            .sender
            .send_to(&payload, &destination)
            .await
            .unwrap();
        let mut buffer = vec![0; 65535];
        let (count, source) = timeout(Duration::from_secs(2), target.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..count], &payload);
        target.send_to(&payload, source).await.unwrap();
        let (observed, reply) = timeout(Duration::from_secs(2), channel.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(observed, destination);
        assert_eq!(reply, payload);
        assert!(matches!(
            channel
                .sender
                .send_to(&vec![0; maximum + 1], &destination)
                .await,
            Err(Error::ResourceLimit)
        ));
        if address.is_ipv4() {
            let mapped = Destination::new("::ffff:127.0.0.1", address.port()).unwrap();
            assert!(matches!(
                channel.sender.send_to(&vec![0; 65508], &mapped).await,
                Err(Error::ResourceLimit)
            ));
        }
    }
}
