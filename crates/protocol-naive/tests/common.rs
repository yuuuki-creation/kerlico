#![allow(dead_code)]
use kerlico_config::{NodeFactory, OutboundFactory};
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, CancellationToken, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, InboundContext, NodeEvent, NodeObserver, Outbound, Result,
    StreamBudget,
};
use kerlico_naive::{NaiveFactory, NaiveNodeFactory};
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
struct Observer(Arc<AtomicUsize>);
impl NodeObserver for Observer {
    fn record(&self, event: NodeEvent) {
        if matches!(event, NodeEvent::Accepted) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
}
struct Access {
    egress: kerlico_egress::Egress,
    pub accesses: Arc<AtomicUsize>,
    pub associations: Arc<AtomicUsize>,
}
impl AccessService for Access {
    fn supports_udp_association(&self) -> bool {
        true
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        self.associations.fetch_add(1, Ordering::AcqRel);
        AccessService::associate_udp(&self.egress, context)
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        self.accesses.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_tcp(&self.egress, target, context)
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        self.accesses.fetch_add(1, Ordering::AcqRel);
        AccessService::connect_udp(&self.egress, target, context)
    }
}
pub struct Fixture {
    pub outbound: Arc<dyn Outbound>,
    pub options: Value,
    pub node_options: Value,
    pub address: SocketAddr,
    pub cancel: CancellationToken,
    pub accesses: Arc<AtomicUsize>,
    pub associations: Arc<AtomicUsize>,
    pub accepts: Arc<AtomicUsize>,
    pub global: Arc<Semaphore>,
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
            while self.global.available_permits() != 128 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }
}
pub async fn fixture(transport: &str, host: &str, version: u8) -> Fixture {
    fixture_with(transport, host, version, 1, Duration::from_secs(2)).await
}
pub async fn fixture_with(
    transport: &str,
    host: &str,
    version: u8,
    max_sessions: usize,
    timeout: Duration,
) -> Fixture {
    fixture_named(
        transport,
        host,
        version,
        max_sessions,
        timeout,
        "test-user",
        "synthetic-secret",
    )
    .await
}
pub async fn fixture_named(
    transport: &str,
    host: &str,
    version: u8,
    max_sessions: usize,
    timeout: Duration,
    username: &str,
    password: &str,
) -> Fixture {
    let certificate = rcgen::generate_simple_self_signed(vec!["proxy.invalid".into()]).unwrap();
    let cert = certificate.cert.pem();
    let key = certificate.signing_key.serialize_pem();
    let node_options = json!({"users":[{"username":username,"password":password}],"tls":{"certificate_pem":cert,"private_key_pem":key},"transports":[transport],"udp_over_tcp":true});
    let node = NaiveNodeFactory.build(&node_options).unwrap();
    let cancel = CancellationToken::new();
    let global = Arc::new(Semaphore::new(128));
    let accesses = Arc::new(AtomicUsize::new(0));
    let associations = Arc::new(AtomicUsize::new(0));
    let accepts = Arc::new(AtomicUsize::new(0));
    let access = Arc::new(Access {
        egress: kerlico_egress::Egress::new(kerlico_net::DirectFactory.build(&json!({})).unwrap()),
        accesses: accesses.clone(),
        associations: associations.clone(),
    });
    let mut context = InboundContext {
        peer_addr: None,
        local_addr: None,
        cancel: cancel.clone(),
        connect_timeout: timeout,
        idle_timeout: Duration::from_secs(8),
        drain_timeout: Duration::from_secs(1),
        max_datagram_size: 65535,
        max_streams: 64,
        stream_budget: StreamBudget::new(global.clone(), Arc::new(Semaphore::new(128))),
        events: Arc::new(Observer(accepts.clone())),
    };
    let (address, task) = if transport == "h3" {
        let socket = Arc::new(UdpSocket::bind((host, 0)).await.unwrap());
        let address = socket.local_addr().unwrap();
        context.local_addr = Some(address);
        let task = tokio::spawn(async move {
            let _ = node.handle_udp(socket, access, context).await;
        });
        (address, task)
    } else {
        let listener = TcpListener::bind((host, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        context.local_addr = Some(address);
        let count = accepts.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {biased;_=context.cancel.cancelled()=>break,_=tasks.join_next(),if !tasks.is_empty()=>{},incoming=listener.accept()=>{let Ok((stream,peer))=incoming else{break};let Ok(lease)=context.stream_budget.try_acquire()else{continue};count.fetch_add(1,Ordering::AcqRel);let node=node.clone();let access=access.clone();let mut context=context.clone();context.peer_addr=Some(peer);tasks.spawn(async move{let _lease=lease;let _=node.handle(Box::new(stream),access,context).await;});}}
            }
            drop(listener);
            if tokio::time::timeout(Duration::from_secs(2), async {
                while tasks.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            }
        });
        (address, task)
    };
    let options = json!({"server":{"host":host,"port":address.port()},"username":username,"password":password,"tls":{"server_name":"proxy.invalid","ca_pem":cert},"transport":transport,"udp_over_tcp":{"enabled":true,"version":version},"max_sessions":max_sessions,"max_streams":64,"idle_session_timeout_ms":1000});
    let outbound = NaiveFactory.build(&options).unwrap();
    Fixture {
        outbound,
        options,
        node_options,
        address,
        cancel,
        accesses,
        associations,
        accepts,
        global,
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
            tokio::select! {incoming=listener.accept()=>{let Ok((mut stream,_))=incoming else{break};tasks.spawn(async move{let Ok(size)=stream.read_u32().await else{return};if size>2*1024*1024{return;}let mut bytes=vec![0;size as usize];if stream.read_exact(&mut bytes).await.is_ok(){let _=stream.write_all(&bytes).await;let _=stream.shutdown().await;}});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    Echo { target, task }
}
pub async fn udp_echo(host: &str) -> Echo {
    let socket = UdpSocket::bind((host, 0)).await.unwrap();
    let target = Destination::new(host, socket.local_addr().unwrap().port()).unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        loop {
            let Ok((n, source)) = socket.recv_from(&mut bytes).await else {
                break;
            };
            if socket.send_to(&bytes[..n], source).await.is_err() {
                break;
            }
        }
    });
    Echo { target, task }
}
pub async fn tcp(
    outbound: &Arc<dyn Outbound>,
    context: &ConnectContext,
    target: &Destination,
    size: usize,
) {
    let mut stream = outbound.connect_tcp(target, context).await.unwrap();
    let bytes = (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    stream.write_u32(size as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
    let mut result = vec![0; size];
    tokio::time::timeout(Duration::from_secs(8), stream.read_exact(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, bytes);
}
pub async fn udp(
    outbound: &Arc<dyn Outbound>,
    context: &ConnectContext,
    target: &Destination,
    size: usize,
) {
    let mut channel = outbound.connect_udp(target, context).await.unwrap();
    let bytes = (0..size).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    channel.sender.send(&bytes).await.unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(8), channel.receiver.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(packet, bytes);
}
