//! 转发入口与协议节点调度；核心不按协议名称分支。

use kerlico_config::{ForwardKind, ForwardSpec, Limits, PreparedConfig, PreparedNode};
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, Destination, Error, InboundContext, Outbound,
    Result,
};
use std::{
    collections::{BTreeMap, HashMap, hash_map::Entry},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{Instant, timeout},
};

/// 运行期累计事件计数，供调用方观测；不是活跃连接数或业务成功数。
///
/// 各原子计数独立更新，读取多个字段不形成一致事务快照。
/// 调用方应只读；当前公开原子字段并未在类型层面禁止外部写入。
#[derive(Default)]
pub struct Stats {
    /// 接纳的会话或逻辑处理单元数，不代表鉴权或目标连接成功。
    pub accepted: AtomicU64,
    /// 正常结束的处理单元数，不代表应用层请求成功。
    pub completed: AtomicU64,
    /// 失败事件数，可包含载体和逻辑流各自报告的事件。
    pub failed: AtomicU64,
    /// 因队列、配额等边界丢弃的事件数，可按数据报计数。
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

struct BoundNode {
    spec: PreparedNode,
    tcp: Option<TcpListener>,
    udp: Option<Arc<UdpSocket>>,
}
#[derive(Clone)]
struct NodeResources {
    global: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    stats: Arc<Stats>,
    local_stats: Arc<Stats>,
}
struct Observer {
    global: Arc<Stats>,
    local: Arc<Stats>,
}
impl kerlico_core::NodeObserver for Observer {
    fn record(&self, event: kerlico_core::NodeEvent) {
        for stats in [&self.global, &self.local] {
            let counter = match event {
                kerlico_core::NodeEvent::Accepted => &stats.accepted,
                kerlico_core::NodeEvent::Completed => &stats.completed,
                kerlico_core::NodeEvent::Failed => &stats.failed,
                kerlico_core::NodeEvent::Dropped => &stats.dropped,
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}
fn node_context(
    limits: &Limits,
    node: &PreparedNode,
    cancel: CancellationToken,
    resources: &NodeResources,
) -> InboundContext {
    InboundContext {
        peer_addr: None,
        local_addr: None,
        cancel,
        connect_timeout: limits.connect_timeout(),
        idle_timeout: limits.idle_timeout(),
        drain_timeout: limits.drain_timeout(),
        max_datagram_size: limits.max_datagram_size,
        max_streams: node.max_sessions.min(256),
        stream_budget: kerlico_core::StreamBudget::new(
            resources.global.clone(),
            resources.slots.clone(),
        ),
        events: Arc::new(Observer {
            global: resources.stats.clone(),
            local: resources.local_stats.clone(),
        }),
    }
}
fn node_socket(address: SocketAddr, udp: bool) -> Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        if address.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        if udp {
            socket2::Type::DGRAM
        } else {
            socket2::Type::STREAM
        },
        Some(if udp {
            socket2::Protocol::UDP
        } else {
            socket2::Protocol::TCP
        }),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket)
}

/// 已持有监听器的运行实例；通过统一出口调度固定入口和独立协议节点。
pub struct Engine {
    inbounds: Vec<Inbound>,
    nodes: Vec<BoundNode>,
    node_stats: BTreeMap<String, Arc<Stats>>,
    limits: Limits,
    stats: Arc<Stats>,
}

impl Engine {
    /// 绑定全部入口及节点监听器，不建立业务目标连接。
    ///
    /// 任一绑定失败会释放此前取得的监听资源；没有入口时返回配置错误。
    /// 节点 IPv6 监听显式仅接收 IPv6，节点身份及带身份的资源分别管理。
    pub async fn bind(config: PreparedConfig) -> Result<Self> {
        if config.inbounds.is_empty() && config.nodes.is_empty() {
            return Err(Error::Config("没有配置入站".into()));
        }
        let mut inbounds = Vec::new();
        for spec in config.inbounds {
            let target = spec.target.destination()?;
            let raw_outbound = config
                .outbounds
                .get(&spec.outbound)
                .ok_or_else(|| Error::Config("出站引用不存在".into()))?
                .clone();
            let outbound: Arc<dyn Outbound> = Arc::new(kerlico_egress::Egress::new(raw_outbound));
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
        let mut nodes = Vec::new();
        let mut node_stats = BTreeMap::new();
        for mut node in config.nodes {
            let tcp = if node.protocol.supports_tcp() {
                let socket = node_socket(node.listen, false)?;
                socket.listen(1024)?;
                let listener = TcpListener::from_std(socket.into())?;
                node.listen = listener.local_addr()?;
                Some(listener)
            } else {
                None
            };
            let udp = if node.protocol.supports_udp() {
                let socket = node_socket(node.listen, true)?;
                let socket = Arc::new(UdpSocket::from_std(socket.into())?);
                if tcp.is_none() {
                    node.listen = socket.local_addr()?;
                }
                Some(socket)
            } else {
                None
            };
            node_stats.insert(node.tag.clone(), Arc::new(Stats::default()));
            nodes.push(BoundNode {
                spec: node,
                tcp,
                udp,
            });
        }
        Ok(Self {
            inbounds,
            nodes,
            node_stats,
            limits: config.limits,
            stats: Arc::new(Stats::default()),
        })
    }

    /// 返回入口标签与实际绑定地址，包括端口 `0` 分配后的结果。
    ///
    /// 同一节点的 TCP、UDP 共用绑定端口时只列一项；虚拟入口没有物理地址可列。
    pub fn listeners(&self) -> Result<Vec<(String, SocketAddr)>> {
        let mut result: Vec<_> = self
            .inbounds
            .iter()
            .map(|inbound| {
                let address = match &inbound.socket {
                    Socket::Tcp(value) => value.local_addr()?,
                    Socket::Udp(value) => value.local_addr()?,
                };
                Ok((inbound.spec.tag.clone(), address))
            })
            .collect::<Result<_>>()?;
        for node in &self.nodes {
            if let Some(listener) = &node.tcp {
                result.push((node.spec.tag.clone(), listener.local_addr()?));
            } else if let Some(socket) = &node.udp {
                result.push((node.spec.tag.clone(), socket.local_addr()?));
            }
        }
        Ok(result)
    }

    /// 获取全局累计统计的共享观测句柄；计数仍随运行更新，不是值拷贝快照。
    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    /// 返回按节点标签索引的统计句柄，包含本地协议入口；原子计数仍实时更新。
    pub fn node_stats(&self) -> BTreeMap<String, Arc<Stats>> {
        self.node_stats.clone()
    }

    /// 消费本实例并运行入口，直到取消或入口调度失败；调用方应等待返回以完成回收。
    ///
    /// 取消后停止新接入，给予已有任务有限排空时间，再取消并回收。
    /// 单个业务会话失败通常计入统计，不意味着此方法一定返回错误；成功返回也不代表全部业务成功。
    pub async fn run(self, cancel: CancellationToken) -> Result<()> {
        let scope = cancel.child_token();
        let _guard = scope.clone().drop_guard();
        let semaphore = Arc::new(Semaphore::new(self.limits.max_sessions));
        let mut workers = JoinSet::new();
        for bound in self.nodes {
            let resources = NodeResources {
                global: semaphore.clone(),
                slots: Arc::new(Semaphore::new(bound.spec.max_sessions)),
                stats: self.stats.clone(),
                local_stats: self
                    .node_stats
                    .get(&bound.spec.tag)
                    .expect("节点统计已构造")
                    .clone(),
            };
            workers.spawn(serve_bound_node(
                bound,
                self.limits.clone(),
                scope.clone(),
                resources,
            ));
        }
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

async fn serve_bound_node(
    bound: BoundNode,
    limits: Limits,
    stop: CancellationToken,
    resources: NodeResources,
) -> Result<()> {
    // 同一节点的 TCP/UDP/虚拟入口共用生命周期，单个入口结束不能取消另一入口的业务。
    let force = CancellationToken::new();
    let _guard = force.clone().drop_guard();
    let mut handlers = JoinSet::new();
    let node = bound.spec;
    if let Some(listener) = bound.tcp {
        handlers.spawn(serve_node(
            node.clone(),
            listener,
            limits.clone(),
            stop.clone(),
            resources.clone(),
            force.clone(),
        ));
    }
    if bound.udp.is_some() || node.protocol.supports_virtual() {
        let force = force.clone();
        handlers.spawn(async move {
            let context=node_context(&limits,&node,force.clone(),&resources);let access:Arc<dyn kerlico_core::AccessService>=Arc::new(kerlico_egress::Egress::new(node.outbound.clone()));
            let running=async {if let Some(socket)=bound.udp {node.protocol.handle_udp(socket,access,context).await}else{node.protocol.handle_virtual(access,context).await}};tokio::pin!(running);
            tokio::select! {result=&mut running=>result,_=stop.cancelled()=>{resources.slots.close();if timeout(limits.drain_timeout(),&mut running).await.is_err(){force.cancel();}Ok(())}}
        });
    }
    while let Some(result) = handlers.join_next().await {
        let error = match result {
            Ok(Ok(())) => continue,
            Ok(Err(error)) => error,
            Err(_) => Error::Protocol("节点入口任务异常退出"),
        };
        force.cancel();
        handlers.abort_all();
        while handlers.join_next().await.is_some() {}
        return Err(error);
    }
    Ok(())
}

async fn serve_node(
    node: PreparedNode,
    listener: TcpListener,
    limits: Limits,
    stop: CancellationToken,
    resources: NodeResources,
    force: CancellationToken,
) -> Result<()> {
    let shared = resources.clone();
    let NodeResources {
        global,
        slots,
        stats,
        local_stats,
    } = resources;
    let access: Arc<dyn kerlico_core::AccessService> =
        Arc::new(kerlico_egress::Egress::new(node.outbound.clone()));
    let mut sessions = JoinSet::new();
    let mut failure = None;
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            result=sessions.join_next(),if !sessions.is_empty()=>{if result.is_some_and(|r|r.is_err()){stats.failed.fetch_add(1,Ordering::Relaxed);local_stats.failed.fetch_add(1,Ordering::Relaxed);}},
            accepted=listener.accept()=>{
                let (stream,peer_addr)=match accepted {Ok(v)=>v,Err(error)=>{failure=Some(Error::Io(error));break;}};
                let (Ok(global_permit),Ok(node_permit))=(global.clone().try_acquire_owned(),slots.clone().try_acquire_owned()) else {stats.dropped.fetch_add(1,Ordering::Relaxed);local_stats.dropped.fetch_add(1,Ordering::Relaxed);continue;};
                let _=stream.set_nodelay(true);
                let protocol=node.protocol.clone();let access=access.clone();let token=force.child_token();let stats=stats.clone();let local_stats=local_stats.clone();
                let mut context=node_context(&limits,&node,token.clone(),&shared);
                context.peer_addr=Some(peer_addr);context.local_addr=stream.local_addr().ok();
                stats.accepted.fetch_add(1,Ordering::Relaxed);
                local_stats.accepted.fetch_add(1,Ordering::Relaxed);
                sessions.spawn(async move {
                    let _global=global_permit;let _node=node_permit;
                    let result=tokio::select! {_=token.cancelled()=>Err(Error::Cancelled),r=protocol.handle(Box::new(stream),access,context)=>r};
                    if result.is_ok(){stats.completed.fetch_add(1,Ordering::Relaxed);local_stats.completed.fetch_add(1,Ordering::Relaxed);}else{stats.failed.fetch_add(1,Ordering::Relaxed);local_stats.failed.fetch_add(1,Ordering::Relaxed);}
                });
            }
        }
    }
    slots.close();
    drop(listener);
    if failure.is_some() {
        force.cancel();
    }
    drain(&mut sessions, &force, &limits).await;
    failure.map_or(Ok(()), Err)
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
    kerlico_core::relay_tcp(a, b, limits.idle_timeout(), cancel).await
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
