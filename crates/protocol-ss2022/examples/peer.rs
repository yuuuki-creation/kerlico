//! 仅供 worker 互通的进程内适配器；不参与正式程序入口。
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, DatagramChannel, DatagramReceiver,
    DatagramSender, Destination, InboundContext, InboundProtocol, NodeEvent, NodeObserver,
    Outbound, Result, StreamBudget,
};
use kerlico_ss2022::{Ss2022Node, Ss2022Outbound};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
};
struct Direct;
struct Udp(Arc<UdpSocket>);
impl DatagramSender for Udp {
    fn send<'a>(&'a mut self, p: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.0.send(p).await?;
            Ok(())
        })
    }
}
impl DatagramReceiver for Udp {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            let mut p = vec![0; 65536];
            let n = self.0.recv(&mut p).await?;
            p.truncate(n);
            Ok(Some(p))
        })
    }
}
impl AccessService for Direct {
    fn connect_tcp<'a>(
        &'a self,
        t: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            Ok(Box::new(TcpStream::connect((t.host().as_str(), t.port())).await?) as BoxStream)
        })
    }
    fn connect_udp<'a>(
        &'a self,
        t: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            let peer = tokio::net::lookup_host((t.host().as_str(), t.port()))
                .await?
                .next()
                .unwrap();
            let socket = Arc::new(
                UdpSocket::bind(if peer.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                })
                .await?,
            );
            socket.connect(peer).await?;
            Ok(DatagramChannel {
                sender: Box::new(Udp(socket.clone())),
                receiver: Box::new(Udp(socket)),
            })
        })
    }
}
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
fn context() -> InboundContext {
    InboundContext {
        cancel: Default::default(),
        connect_timeout: Duration::from_secs(3),
        idle_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65000,
        max_streams: 64,
        events: Arc::new(Observer),
        stream_budget: StreamBudget::new(
            Arc::new(Semaphore::new(128)),
            Arc::new(Semaphore::new(128)),
        ),
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let options: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[2])?).unwrap();
    let listen = &args[3];
    if args[1] == "server" {
        let node = Arc::new(Ss2022Node::from_options(&options)?);
        let listener = TcpListener::bind(listen).await?;
        let socket = Arc::new(UdpSocket::bind(listen).await?);
        let ctx = context();
        {
            let node = node.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move { node.handle_udp(socket, Arc::new(Direct), ctx).await });
        }
        loop {
            let (stream, _) = listener.accept().await?;
            let node = node.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move { node.handle(Box::new(stream), Arc::new(Direct), ctx).await });
        }
    } else {
        let outbound = Arc::new(Ss2022Outbound::from_options(&options)?);
        let target = Destination::new(&args[4], args[5].parse().unwrap())?;
        let listener = TcpListener::bind(listen).await?;
        let socket = Arc::new(UdpSocket::bind(listen).await?);
        {
            let outbound = outbound.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let mut buf = vec![0; 65536];
                loop {
                    let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                    let mut channel = outbound
                        .connect_udp(&target, &ConnectContext::new(Duration::from_secs(3)))
                        .await
                        .unwrap();
                    channel.sender.send(&buf[..n]).await.unwrap();
                    if let Ok(Ok(Some(packet))) =
                        tokio::time::timeout(Duration::from_secs(3), channel.receiver.recv()).await
                    {
                        socket.send_to(&packet, peer).await.unwrap();
                    }
                }
            });
        }
        loop {
            let (stream, _) = listener.accept().await?;
            let outbound = outbound.clone();
            let target = target.clone();
            tokio::spawn(async move {
                if let Ok(remote) = outbound
                    .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(3)))
                    .await
                {
                    let _ = kerlico_core::relay_tcp(
                        Box::new(stream),
                        remote,
                        Duration::from_secs(5),
                        Default::default(),
                    )
                    .await;
                }
            });
        }
    }
}
