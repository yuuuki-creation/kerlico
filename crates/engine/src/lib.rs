//! 固定目标转发调度；协议通过 Outbound 注入，不按协议名称分支。

use kerlico_config::{ForwardKind, ForwardSpec, Limits, PreparedConfig};
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, Destination, Error, Outbound, Result,
};
use std::{
    collections::{HashMap, hash_map::Entry},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout},
};

#[derive(Default)]
pub struct Stats {
    pub accepted: AtomicU64,
    pub completed: AtomicU64,
    pub failed: AtomicU64,
    pub dropped: AtomicU64,
}

struct Inbound {
    spec: ForwardSpec,
    target: Destination,
    outbound: Arc<dyn Outbound>,
    socket: Socket,
}

enum Socket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

pub struct Engine {
    inbounds: Vec<Inbound>,
    limits: Limits,
    stats: Arc<Stats>,
}

impl Engine {
    pub async fn bind(config: PreparedConfig) -> Result<Self> {
        if config.inbounds.is_empty() {
            return Err(Error::Config("没有配置入站".into()));
        }
        let mut inbounds = Vec::new();
        for spec in config.inbounds {
            let target = spec.target.destination()?;
            let outbound = config
                .outbounds
                .get(&spec.outbound)
                .ok_or_else(|| Error::Config("出站引用不存在".into()))?
                .clone();
            let socket = match spec.kind {
                ForwardKind::Tcp => Socket::Tcp(TcpListener::bind(spec.listen).await?),
                ForwardKind::Udp => Socket::Udp(Arc::new(UdpSocket::bind(spec.listen).await?)),
            };
            inbounds.push(Inbound {
                spec,
                target,
                outbound,
                socket,
            });
        }
        Ok(Self {
            inbounds,
            limits: config.limits,
            stats: Arc::new(Stats::default()),
        })
    }

    pub fn listeners(&self) -> Result<Vec<(String, SocketAddr)>> {
        self.inbounds
            .iter()
            .map(|inbound| {
                let address = match &inbound.socket {
                    Socket::Tcp(value) => value.local_addr()?,
                    Socket::Udp(value) => value.local_addr()?,
                };
                Ok((inbound.spec.tag.clone(), address))
            })
            .collect()
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    pub async fn run(self, cancel: CancellationToken) -> Result<()> {
        let scope = cancel.child_token();
        let _guard = scope.clone().drop_guard();
        let semaphore = Arc::new(Semaphore::new(self.limits.max_sessions));
        let mut workers = JoinSet::new();
        for inbound in self.inbounds {
            let limits = self.limits.clone();
            let token = scope.clone();
            let slots = semaphore.clone();
            let stats = self.stats.clone();
            workers.spawn(async move {
                match inbound.socket {
                    Socket::Tcp(listener) => {
                        serve_tcp(
                            listener,
                            inbound.target,
                            inbound.outbound,
                            limits,
                            token,
                            slots,
                            stats,
                        )
                        .await
                    }
                    Socket::Udp(socket) => {
                        serve_udp(
                            socket,
                            inbound.target,
                            inbound.outbound,
                            limits,
                            token,
                            slots,
                            stats,
                        )
                        .await
                    }
                }
            });
        }
        let mut failure = None;
        while let Some(result) = workers.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                    scope.cancel();
                }
                Err(_) => {
                    failure.get_or_insert(Error::Protocol("入口任务异常退出"));
                    scope.cancel();
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

async fn drain<T: Send + 'static>(
    tasks: &mut JoinSet<T>,
    force: &CancellationToken,
    limits: &Limits,
) {
    if timeout(limits.drain_timeout(), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        force.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

async fn serve_tcp(
    listener: TcpListener,
    target: Destination,
    outbound: Arc<dyn Outbound>,
    limits: Limits,
    stop: CancellationToken,
    slots: Arc<Semaphore>,
    stats: Arc<Stats>,
) -> Result<()> {
    let force = CancellationToken::new();
    let _guard = force.clone().drop_guard();
    let mut sessions = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            result=sessions.join_next(),if !sessions.is_empty()=>{ if result.is_some_and(|result|result.is_err()) { stats.failed.fetch_add(1,Ordering::Relaxed); } },
            accepted=listener.accept()=>{
                let (stream,_)=match accepted { Ok(value)=>value, Err(error)=>{failure=Some(Error::Io(error));break;} };
                let permit=match slots.clone().try_acquire_owned() { Ok(value)=>value,Err(_)=>{stats.dropped.fetch_add(1,Ordering::Relaxed);continue;} };
                let target=target.clone();let outbound=outbound.clone();let limits=limits.clone();let token=force.child_token();let stats=stats.clone();
                stats.accepted.fetch_add(1,Ordering::Relaxed);
                sessions.spawn(async move {
                    let _permit=permit;
                    let result=tcp_session(stream,&target,outbound.as_ref(),&limits,token).await;
                    if result.is_ok() { stats.completed.fetch_add(1,Ordering::Relaxed); } else { stats.failed.fetch_add(1,Ordering::Relaxed); }
                });
            }
        }
    }
    drop(listener);
    if failure.is_some() {
        force.cancel();
    }
    drain(&mut sessions, &force, &limits).await;
    failure.map_or(Ok(()), Err)
}

async fn tcp_session(
    stream: TcpStream,
    target: &Destination,
    outbound: &dyn Outbound,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<()> {
    let context = ConnectContext {
        cancel: cancel.clone(),
        timeout: limits.connect_timeout(),
    };
    let remote = outbound.connect_tcp(target, &context).await?;
    relay(Box::new(stream), remote, limits, cancel).await
}

async fn relay(
    a: BoxStream,
    b: BoxStream,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<()> {
    let (activity, mut observed) = watch::channel(Instant::now());
    let mut a = ActiveIo {
        inner: a,
        activity: activity.clone(),
    };
    let mut b = ActiveIo { inner: b, activity };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    tokio::pin!(copy);
    let timer = tokio::time::sleep(limits.idle_timeout());
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _=cancel.cancelled()=>return Err(Error::Cancelled),
            result=&mut copy=>return result.map(|_|()).map_err(Error::Io),
            changed=observed.changed()=>{ if changed.is_ok() { timer.as_mut().reset(*observed.borrow_and_update()+limits.idle_timeout()); } },
            _=&mut timer=>return Err(Error::Timeout),
        }
    }
}

struct ActiveIo {
    inner: BoxStream,
    activity: watch::Sender<Instant>,
}
impl AsyncRead for ActiveIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let previous = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > previous {
            this.activity.send_replace(Instant::now());
        }
        result
    }
}
impl AsyncWrite for ActiveIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
        if matches!(result,Poll::Ready(Ok(count)) if count>0) {
            this.activity.send_replace(Instant::now());
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn serve_udp(
    socket: Arc<UdpSocket>,
    target: Destination,
    outbound: Arc<dyn Outbound>,
    limits: Limits,
    stop: CancellationToken,
    slots: Arc<Semaphore>,
    stats: Arc<Stats>,
) -> Result<()> {
    let force = CancellationToken::new();
    let _guard = force.clone().drop_guard();
    let mut sessions = JoinSet::new();
    let mut senders: HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)> = HashMap::new();
    let mut owners = HashMap::new();
    let mut generation = 0u64;
    let mut buffer = vec![0; limits.max_datagram_size + 1];
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            result=sessions.join_next_with_id(),if !sessions.is_empty()=>{
                let finished=match result {
                    Some(Ok((task,())))=>owners.remove(&task),
                    Some(Err(error))=>{stats.failed.fetch_add(1,Ordering::Relaxed);owners.remove(&error.id())},
                    None=>None,
                };
                if let Some((peer,id))=finished && senders.get(&peer).is_some_and(|(current,_)|*current==id) { senders.remove(&peer); }
            },
            packet=socket.recv_from(&mut buffer)=>{
                let (count,peer)=match packet {Ok(value)=>value,Err(error)=>{failure=Some(Error::Io(error));break;}};
                if count>limits.max_datagram_size {stats.dropped.fetch_add(1,Ordering::Relaxed);continue;}
                if senders.get(&peer).is_some_and(|(_,sender)|sender.is_closed()) {senders.remove(&peer);}
                if let Entry::Vacant(entry)=senders.entry(peer) {
                    let permit=match slots.clone().try_acquire_owned() {Ok(value)=>value,Err(_)=>{stats.dropped.fetch_add(1,Ordering::Relaxed);continue;}};
                    generation=match generation.checked_add(1) {Some(value)=>value,None=>{failure=Some(Error::ResourceLimit);break;}};let id=generation;
                    let (sender,receiver)=mpsc::channel(limits.udp_queue_packets);
                    entry.insert((id,sender));
                    let socket=socket.clone();let target=target.clone();let outbound=outbound.clone();let limits=limits.clone();let token=force.child_token();let stats=stats.clone();
                    stats.accepted.fetch_add(1,Ordering::Relaxed);
                    let task=sessions.spawn(async move {
                        let _permit=permit;
                        let result=udp_session(socket,peer,&target,outbound.as_ref(),receiver,&limits,token).await;
                        if result.is_ok() {stats.completed.fetch_add(1,Ordering::Relaxed);} else {stats.failed.fetch_add(1,Ordering::Relaxed);}
                    });
                    owners.insert(task.id(),(peer,id));
                }
                if senders.get(&peer).expect("关联刚建立").1.try_send(buffer[..count].to_vec()).is_err() {stats.dropped.fetch_add(1,Ordering::Relaxed);}
            }
        }
    }
    drop(senders);
    if failure.is_some() {
        force.cancel();
    }
    drain(&mut sessions, &force, &limits).await;
    failure.map_or(Ok(()), Err)
}

async fn udp_session(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    target: &Destination,
    outbound: &dyn Outbound,
    mut queue: mpsc::Receiver<Vec<u8>>,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<()> {
    let context = ConnectContext {
        cancel: cancel.clone(),
        timeout: limits.connect_timeout(),
    };
    let channel = outbound.connect_udp(target, &context).await?;
    let mut sender = channel.sender;
    let mut receiver = channel.receiver;
    let (activity, mut observed) = watch::channel(Instant::now());
    let outgoing = async {
        while let Some(packet) = queue.recv().await {
            sender.send(&packet).await?;
            activity.send_replace(Instant::now());
        }
        // 入口关闭后仍等候已发送包的回写，由空闲或统一排空预算结束。
        std::future::pending::<Result<()>>().await
    };
    let incoming = async {
        while let Some(packet) = receiver.recv().await? {
            if packet.len() > limits.max_datagram_size {
                return Err(Error::ResourceLimit);
            }
            socket.send_to(&packet, peer).await?;
            activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    tokio::pin!(outgoing, incoming);
    let timer = tokio::time::sleep(limits.idle_timeout());
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _=cancel.cancelled()=>return Err(Error::Cancelled),
            result=&mut outgoing=>return result,
            result=&mut incoming=>return result,
            changed=observed.changed()=>{if changed.is_ok(){timer.as_mut().reset(*observed.borrow_and_update()+limits.idle_timeout());}},
            _=&mut timer=>return Err(Error::Timeout),
        }
    }
}
