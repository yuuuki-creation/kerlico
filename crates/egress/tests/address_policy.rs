use kerlico_config::OutboundFactory;
use kerlico_core::{ConnectContext, Destination, Outbound};
use kerlico_egress::Egress;
use kerlico_net::DirectFactory;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn domain_prefers_ipv4_and_falls_back_before_payload() {
    let ipv4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ipv4.local_addr().unwrap().port();
    let ipv6 = TcpListener::bind(("::1", port)).await.unwrap();
    let egress = Egress::new(DirectFactory.build(&serde_json::json!({})).unwrap());
    let context = ConnectContext::new(Duration::from_secs(2));
    let target = Destination::new("localhost", port).unwrap();
    let send4 = tokio::spawn(async move {
        let (mut socket, _) = ipv4.accept().await.unwrap();
        socket.write_all(b"v4").await.unwrap();
    });
    let mut stream = egress.connect_tcp(&target, &context).await.unwrap();
    let mut bytes = [0; 2];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"v4");
    drop(stream);
    send4.await.unwrap();
    let send6 = tokio::spawn(async move {
        let (mut socket, _) = ipv6.accept().await.unwrap();
        socket.write_all(b"v6").await.unwrap();
    });
    let mut stream = egress.connect_tcp(&target, &context).await.unwrap();
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"v6");
    drop(stream);
    send6.await.unwrap();
}
