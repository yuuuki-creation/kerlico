#![allow(dead_code)]
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, InboundContext, NodeEvent, NodeObserver, Outbound, Result,
    StreamBudget,
};
use kerlico_mieru::{MieruFactory, MieruNodeFactory};
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
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
};
struct Observer;
impl NodeObserver for Observer {
    fn record(&self, _: NodeEvent) {}
}
struct Access {
    egress: kerlico_egress::Egress,
    count: Arc<AtomicUsize>,
}
impl AccessService for Access {
    fn supports_udp_association(&self) -> bool {
        AccessService::supports_udp_association(&self.egress)
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::associate_udp(&self.egress, context)
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_tcp(&self.egress, target, context)
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.count.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_udp(&self.egress, target, context)
    }
}
pub struct Setup<'a> {
    pub transport: &'a str,
    pub host: &'a str,
    pub identity: u8,
    pub multiplex: bool,
    pub no_wait: bool,
    pub mode: u8,
    pub rotation: u8,
    pub idle: Duration,
    pub timeout: Duration,
    pub outbound: Option<Arc<dyn Outbound>>,
}
impl<'a> Setup<'a> {
    pub fn new(transport: &'a str, host: &'a str) -> Self {
        Self {
            transport,
            host,
            identity: 1,
            multiplex: true,
            no_wait: false,
            mode: 0,
            rotation: 0,
            idle: Duration::from_secs(10),
            timeout: Duration::from_secs(4),
            outbound: None,
        }
    }
}
pub struct Fixture {
    pub outbound: Arc<dyn Outbound>,
    pub options: Value,
    pub node_options: Value,
    pub address: SocketAddr,
    pub cancel: CancellationToken,
    pub global: Arc<Semaphore>,
    pub count: Arc<AtomicUsize>,
    pub accepts: Arc<AtomicUsize>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Fixture {
    pub fn context(&self) -> ConnectContext {
        ConnectContext {
            cancel: self.cancel.clone(),
            timeout: Duration::from_secs(8),
        }
    }
    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            tokio::time::timeout(Duration::from_secs(3), task)
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.global.available_permits() != 64 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }
}
pub async fn fixture(setup: Setup<'_>) -> Fixture {
    let user = format!("node-{}", setup.identity);
    let password = format!("synthetic-password-{}", setup.identity);
    let node_options = json!({"username":user,"password":password,"transport":setup.transport,"unsafe_udp_compatibility":setup.transport=="udp","traffic":{"low_entropy_mode":setup.mode,"mask_rotation":setup.rotation,"max_padding":32}});
    let node = MieruNodeFactory.build(&node_options).unwrap();
    let global = Arc::new(Semaphore::new(64));
    let cancel = CancellationToken::new();
    let count = Arc::new(AtomicUsize::new(0));
    let accepts = Arc::new(AtomicUsize::new(0));
    let access = Arc::new(Access {
        egress: kerlico_egress::Egress::new(
            setup
                .outbound
                .unwrap_or_else(|| kerlico_net::DirectFactory.build(&json!({})).unwrap()),
        ),
        count: count.clone(),
    });
    let mut context = InboundContext {
        peer_addr: None,
        local_addr: None,
        cancel: cancel.clone(),
        connect_timeout: setup.timeout,
        idle_timeout: setup.idle,
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 64,
        stream_budget: StreamBudget::new(global.clone(), Arc::new(Semaphore::new(64))),
        events: Arc::new(Observer),
    };
    let (address, task) = if setup.transport == "tcp" {
        let listener = TcpListener::bind((setup.host, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        context.local_addr = Some(address);
        let hits = accepts.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! { biased;
                    _ = context.cancel.cancelled() => break,
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    connection = listener.accept() => { let Ok((stream, peer)) = connection else { break; }; let Ok(lease) = context.stream_budget.try_acquire() else { continue; }; hits.fetch_add(1, Ordering::AcqRel); let node = node.clone(); let access = access.clone(); let mut context = context.clone(); context.peer_addr = Some(peer); tasks.spawn(async move { let _lease = lease; let _ = node.handle(Box::new(stream), access, context).await; }); }
                }
            }
            drop(listener);
            let waiting = async { while tasks.join_next().await.is_some() {} };
            if tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .is_err()
            {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        });
        (address, task)
    } else {
        let socket = Arc::new(UdpSocket::bind((setup.host, 0)).await.unwrap());
        let address = socket.local_addr().unwrap();
        context.local_addr = Some(address);
        (
            address,
            tokio::spawn(async move {
                let _ = node.handle_udp(socket, access, context).await;
            }),
        )
    };
    let options = json!({"server":{"host":setup.host,"port":address.port()},"username":user,"password":password,"transport":setup.transport,"unsafe_udp_compatibility":setup.transport=="udp","multiplexing":setup.multiplex,"no_wait":setup.no_wait,"idle_timeout_secs":10,"traffic":{"low_entropy_mode":setup.mode,"mask_rotation":setup.rotation,"max_padding":32}});
    let outbound = MieruFactory.build(&options).unwrap();
    Fixture {
        outbound,
        options,
        node_options,
        address,
        cancel,
        global,
        count,
        accepts,
        task: Some(task),
    }
}
pub struct Echo {
    pub target: Destination,
    task: JoinHandle<()>,
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub async fn tcp_echo(host: &str) -> Echo {
    let listener = TcpListener::bind((host, 0)).await.unwrap();
    let target = Destination::new(host, listener.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! { connection = listener.accept() => { let Ok((mut stream, _)) = connection else { break; }; tasks.spawn(async move { let Ok(n) = stream.read_u32().await else { return; }; let n = n as usize; if n > 2 * 1024 * 1024 { return; } let mut data = vec![0; n]; if stream.read_exact(&mut data).await.is_ok() { let _ = stream.write_all(&data).await; let _ = stream.shutdown().await; } }); }, _ = tasks.join_next(), if !tasks.is_empty() => {} }
        }
    });
    Echo { target, task }
}
pub async fn tcp(fixture: &Fixture, target: &Destination, size: usize) {
    let context = fixture.context();
    let mut stream = fixture
        .outbound
        .connect_tcp(target, &context)
        .await
        .unwrap();
    let data = (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    stream
        .write_all(&(size as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&data).await.unwrap();
    stream.flush().await.unwrap();
    let mut result = vec![0; size];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, data);
    let mut end = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(8), stream.read(&mut end))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
pub async fn udp_echo(host: &str) -> Echo {
    let socket = UdpSocket::bind((host, 0)).await.unwrap();
    let target = Destination::new(host, socket.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        while let Ok((n, peer)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], peer).await;
        }
    });
    Echo { target, task }
}
pub async fn wait_count(counter: &AtomicUsize, value: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while counter.load(Ordering::Acquire) != value {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}
