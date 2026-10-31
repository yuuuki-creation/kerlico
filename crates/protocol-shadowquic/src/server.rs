//! JLS 上游回退与已鉴权网站访问分开；前者持有同一节点/全局资源许可。
use crate::{
    config::{self, ServerOptions, User},
    runtime::{RuntimeGuard, ScopedRuntime},
    session::Connection,
};
use jls_quinn::Runtime;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Destination, Error, InboundContext,
    InboundProtocol, NodeEvent, Result,
};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::task::JoinSet;
pub(crate) struct Node {
    users: Vec<User>,
    upstream: Destination,
    name: String,
    alpn: Vec<Vec<u8>>,
    versions: Vec<u32>,
    congestion: String,
    rate: u64,
}
impl Node {
    pub fn build(mut options: ServerOptions) -> Result<Self> {
        if options.username.is_some() || options.password.is_some() {
            if !options.users.is_empty() {
                return Err(config::invalid());
            }
            options.users.push(config::UserOptions {
                username: options.username.ok_or_else(config::invalid)?,
                password: options.password.ok_or_else(config::invalid)?,
            });
        }
        if options.users.is_empty()
            || options.users.len() > 256
            || options.upstream_rate_bps < 8000
            || options.upstream_rate_bps > 8_000_000_000
        {
            return Err(config::invalid());
        }
        config::validate_name(&options.server_name)?;
        let mut users = Vec::new();
        let mut seen = BTreeSet::new();
        for user in options.users {
            let user = User::parse(user.username, user.password)?;
            if !seen.insert(user.fingerprint()) {
                return Err(config::invalid());
            }
            users.push(user);
        }
        let mut versions = Vec::new();
        for version in options.quic_versions {
            let version = config::version(&version)?;
            if !versions.contains(&version) {
                versions.push(version);
            }
        }
        if versions.is_empty() || versions.len() > 2 {
            return Err(config::invalid());
        }
        let _ = config::transport(
            &options.congestion_control,
            Duration::from_secs(60),
            128,
            false,
        )?;
        Ok(Self {
            users,
            upstream: options.upstream.destination()?,
            name: options.server_name,
            alpn: config::alpn_bytes(options.alpn)?,
            versions,
            congestion: options.congestion_control,
            rate: options.upstream_rate_bps,
        })
    }
    async fn serve(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        if !access.supports_udp_association() {
            return Err(Error::Unsupported(
                "ShadowQUIC 节点需要 Full Cone UDP 关联出口",
            ));
        }
        let upstream = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        }
        .run(async {
            let mut addresses =
                tokio::net::lookup_host((self.upstream.host().as_str(), self.upstream.port()))
                    .await?
                    .take(32)
                    .collect::<Vec<_>>();
            addresses.sort_by_key(|address| address.is_ipv6());
            addresses.first().copied().ok_or(Error::InvalidAddress)
        })
        .await?;
        if upstream == socket.local_addr()? {
            return Err(Error::Config("JLS 上游不能指向当前节点".into()));
        }
        let mut server = jls_quinn::ServerConfig::with_crypto(config::server_crypto(
            &self.users,
            &self.name,
            self.alpn.clone(),
            upstream,
            self.rate,
        )?);
        server.transport_config(config::transport(
            &self.congestion,
            context.idle_timeout,
            context.max_streams,
            false,
        )?);
        server.max_incoming(context.max_streams.min(128));
        server.incoming_buffer_size(32 * 1024);
        server.incoming_buffer_size_total(2 * 1024 * 1024);
        let runtime = ScopedRuntime::new();
        let _guard = RuntimeGuard::new(runtime.clone());
        let fd = socket2::SockRef::from(socket.as_ref()).try_clone()?;
        let standard: std::net::UdpSocket = fd.into();
        standard.set_nonblocking(true)?;
        let socket = runtime.wrap_udp_socket(standard)?;
        let budget = context.stream_budget.clone();
        let limits = jls_quinn::JlsForwardConfig {
            max_connections: context.max_streams.min(64),
            idle_timeout: context.idle_timeout.min(Duration::from_secs(30)),
            permit_factory: Some(Arc::new(move || {
                budget
                    .try_acquire()
                    .ok()
                    .map(|lease| Arc::new(lease) as jls_quinn::JlsForwardPermit)
            })),
        };
        let endpoint = jls_quinn::Endpoint::new_with_jls_socket(
            config::endpoint(self.versions.clone())?,
            Some(server),
            socket,
            runtime.clone(),
            limits,
        )?;
        let mut tasks = JoinSet::new();
        let mut gc = tokio::time::interval(Duration::from_millis(200));
        loop {
            tokio::select! {biased;
                _=context.cancel.cancelled()=>break,
                _=gc.tick()=>{endpoint.prune_jls_forwarding();},
                _=tasks.join_next(),if !tasks.is_empty()=>{},
                incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};let Ok(lease)=context.stream_budget.try_acquire()else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};let access=access.clone();let context=context.clone();let allowed=self.users.iter().map(|user|user.username.clone()).collect::<Vec<_>>();tasks.spawn(async move{let _lease=lease;context.events.record(NodeEvent::Accepted);let result=async{let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|Error::Rejected)?;if connection.is_jls()!=Some(true)||connection.jls_chosen_user().is_none_or(|user|!allowed.contains(&user)){connection.close(0u32.into(),b"");return Err(Error::Rejected);}Connection::new(connection,None,Some(context.clone()),Some(access)).serve().await}.await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});}
            }
        }
        endpoint.close(0u32.into(), b"");
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let _ = tokio::time::timeout(context.drain_timeout, endpoint.wait_idle()).await;
        drop(endpoint);
        runtime.shutdown().await;
        Ok(())
    }
}
impl InboundProtocol for Node {
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        self.users.iter().map(User::fingerprint).collect()
    }
    fn requires_loopback(&self) -> bool {
        false
    }
    fn supports_tcp(&self) -> bool {
        false
    }
    fn supports_udp(&self) -> bool {
        true
    }
    fn requires_udp_association(&self) -> bool {
        true
    }
    fn handle<'a>(
        &'a self,
        _: BoxStream,
        _: Arc<dyn AccessService>,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("ShadowQUIC 仅监听 QUIC UDP 载体")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve(socket, access, context))
    }
}
