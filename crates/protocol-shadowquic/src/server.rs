//! JLS 上游回退与已鉴权网站访问分开；前者持有同一节点/全局资源许可。
use crate::{
    config::{self, ServerOptions, User},
    runtime::NodeRuntime,
    session::Connection,
};
use jls_quinn::Runtime;
use kerlico_config::NodeBuildContext;
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Destination, Error,
    InboundContext, InboundProtocol, IngressBinding, NodeEvent, Result,
};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::task::JoinSet;
pub(crate) struct Node {
    users: CredentialSet<User>,
    upstream: Destination,
    name: String,
    alpn: Vec<Vec<u8>>,
    versions: Vec<u32>,
    congestion: String,
    rate: u64,
}
impl Node {
    pub fn build(input: &NodeBuildContext) -> Result<Self> {
        let options: ServerOptions =
            serde_json::from_value(input.options().clone()).map_err(|_| config::invalid())?;
        if input.native_credentials().is_empty()
            || input.native_credentials().len() > 256
            || !(8000..=8_000_000_000).contains(&options.upstream_rate_bps)
        {
            return Err(config::invalid());
        }
        config::validate_name(&options.server_name)?;
        let mut users = Vec::new();
        let mut seen = BTreeSet::new();
        for value in input.native_credentials() {
            let user: config::UserOptions =
                serde_json::from_value(value.clone()).map_err(|_| config::invalid())?;
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
            users: input.credentials(users)?,
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
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        if !access.supports_udp_association() {
            return Err(Error::Unsupported(
                "ShadowQUIC 节点需要 Full Cone UDP 关联出口",
            ));
        }
        let upstream = ConnectContext::new(context.connect_timeout)
            .with_cancel(context.cancel.clone())
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
        let runtime = NodeRuntime::new(&context.cancel, context.tasks.clone());
        let _runtime_guard = runtime.guard();
        let mut context = context;
        context.cancel = runtime.cancel();
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
                            _=gc.tick()=>{endpoint.prune_jls_forwarding();if context.stream_budget.is_closed()&&tasks.is_empty(){break;}},
                            result=tasks.join_next(),if !tasks.is_empty()=>{runtime.observe(&result);},
                            incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};let Ok(lease)=context.stream_budget.try_acquire()else{incoming.refuse();context.events.record(NodeEvent::Dropped);continue;};let access=access.clone();let mut context=context.clone();let users=self.users.clone();crate::runtime::spawn_owned(context.tasks.clone(), context.events.clone(), &mut tasks, async move{let _lease=lease;context.events.record(NodeEvent::Accepted);let result=async{let connection=tokio::time::timeout(context.connect_timeout,incoming).await.map_err(|_|Error::Timeout)?.map_err(|_|Error::Rejected)?;context.peer_addr=Some(connection.remote_address());if connection.is_jls()!=Some(true){connection.close(0u32.into(),b"");return Err(Error::Rejected);}
            let chosen=connection.jls_chosen_user().ok_or(Error::Rejected)?;
            let (slot,_)=users.rows().find(|(_,user)|user.username==chosen).ok_or(Error::Rejected)?;
            let peer=access.authenticated(users.verified(&slot,())?,&context)?.0;
            Connection::new(connection,None,Some(context.clone()),Some(peer),None).serve().await}.await;context.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});}, |_| ())?;}
                        }
        }
        if runtime
            .shutdown(endpoint, &mut tasks, context.drain_timeout)
            .await?
            == crate::runtime::NodeDrain::Forced
        {
            context.events.record(NodeEvent::ForcedCleanup);
        }
        Ok(())
    }
}
impl InboundProtocol for Node {
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (index, (_, user)) in self.users.rows().enumerate() {
            manifest.authentication("shadowquic", index, user.fingerprint());
        }
        manifest
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
        _: IngressBinding,
        _: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::Unsupported("ShadowQUIC 仅监听 QUIC UDP 载体")) })
    }
    fn handle_udp<'a>(
        &'a self,
        socket: Arc<tokio::net::UdpSocket>,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.serve(socket, access, context))
    }
}
