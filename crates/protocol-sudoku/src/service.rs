use crate::{
    config::NodeConfig,
    handshake::Negotiated,
    members::{Members, Opening},
    mux::Session,
    scope::Scope,
    udp,
    wire::{address, kip},
};
use kerlico_core::{
    BoxStream, ConnectContext, DatagramAssociationReceiver, DatagramAssociationSender, Error,
    InboundContext, IngressBinding, NodeEvent, PeerSession, Result,
};
use std::sync::Arc;
use tokio::{
    sync::watch,
    time::{Instant, sleep},
};

pub(crate) struct Runtime {
    pub config: Arc<NodeConfig>,
    pub members: Arc<Members>,
    pub scope: Arc<Scope>,
    pub access: IngressBinding,
    pub context: InboundContext,
    pub registry: Arc<crate::carrier::http::session::Registry>,
    pub cover: Option<Arc<crate::carrier::http::transport::HttpClient>>,
}
impl Runtime {
    pub fn start(
        config: Arc<NodeConfig>,
        members: Arc<Members>,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<(
        Arc<Self>,
        tokio::sync::mpsc::Receiver<crate::carrier::http::session::Backend>,
    )> {
        let scope = Scope::node(&context.cancel, context.tasks.clone());
        let (registry, backends) = crate::carrier::http::session::Registry::new(
            members.clone(),
            scope.clone(),
            context.clone(),
            config.max_http_sessions,
            config.http_ttl,
        );
        let cover = if let Some(cover) = config.fallback.as_ref() {
            let target = cover.server.destination()?;
            let endpoint = Arc::new(crate::carrier::endpoint::Endpoint::new(target));
            Some(crate::carrier::http::transport::HttpClient::cover(
                cover.host.clone(),
                cover.compiled_tls.clone(),
                endpoint,
                scope.clone(),
            ))
        } else {
            None
        };
        Ok((
            Arc::new(Self {
                config,
                members,
                scope,
                access,
                context,
                registry,
                cover,
            }),
            backends,
        ))
    }
    pub async fn accept(
        self: &Arc<Self>,
        stream: BoxStream,
        early: Option<Opening>,
        mut context: InboundContext,
    ) -> Result<()> {
        let start = Instant::now();
        let opening =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let (negotiated, peer) = opening.run(self.negotiate(stream, early, &context)).await?;
        context.connect_timeout = context.connect_timeout.saturating_sub(start.elapsed());
        self.process(negotiated, peer, context).await
    }
    pub async fn negotiate(
        &self,
        stream: BoxStream,
        early: Option<Opening>,
        context: &InboundContext,
    ) -> Result<(Negotiated, PeerSession)> {
        let (negotiated, selected) = self.members.negotiate(stream, early).await?;
        let peer = match selected.slot {
            Some(slot) => {
                self.access
                    .authenticated(self.members.credentials.verified(&slot, ())?, context)?
                    .0
            }
            None => self.access.local(context)?,
        };
        Ok((negotiated, peer))
    }
    pub async fn process(
        self: &Arc<Self>,
        mut negotiated: Negotiated,
        peer: PeerSession,
        context: InboundContext,
    ) -> Result<()> {
        let start = Instant::now();
        let opening =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let intent = opening
            .run(async {
                for _ in 0..16 {
                    let intent = kip::read(&mut negotiated.stream).await?;
                    if intent.kind == kip::KEEPALIVE {
                        if !intent.payload.is_empty() {
                            return Err(crate::invalid());
                        }
                        continue;
                    }
                    return Ok(intent);
                }
                Err(Error::ResourceLimit)
            })
            .await?;
        let connecting =
            ConnectContext::new(context.connect_timeout.saturating_sub(start.elapsed()))
                .with_cancel(context.cancel.clone());
        match intent.kind {
            kip::OPEN_TCP if negotiated.features & 1 != 0 => {
                let (target, _) = address::decode(&intent.payload)?;
                let stream = peer.connect_tcp(&target, &connecting).await?;
                kerlico_core::relay_tcp(
                    negotiated.stream,
                    stream,
                    context.idle_timeout,
                    context.cancel,
                )
                .await
            }
            kip::START_UOT
                if negotiated.features & 4 != 0
                    && self.config.protocol.udp_enabled
                    && intent.payload.is_empty() =>
            {
                let access = peer.associate_udp(&connecting).await?;
                let wire = udp::association(
                    negotiated.stream,
                    &context.cancel,
                    context.max_datagram_size,
                    false,
                );
                relay_udp(wire, access, context).await
            }
            kip::START_MUX if negotiated.features & 2 != 0 && intent.payload.is_empty() => {
                self.multiplex(negotiated.stream, peer, context).await
            }
            _ => Err(Error::Unsupported("Sudoku意图未协商或格式不合法")),
        }
    }
    async fn multiplex(
        self: &Arc<Self>,
        stream: BoxStream,
        peer: PeerSession,
        context: InboundContext,
    ) -> Result<()> {
        let session = Session::start_node(
            stream,
            &self.scope,
            &context.cancel,
            self.config.max_streams.min(context.max_streams),
            context.idle_timeout,
            context.stream_budget.clone(),
        );
        let flows = crate::flow::FlowSet::new(context.max_streams, context.cancel.clone());
        let _flows_guard = flows.guard();
        let mut tasks = tokio::task::JoinSet::new();
        let result = loop {
            tokio::select! {biased;
                _=context.cancel.cancelled()=>break Err(Error::Cancelled),
                Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                incoming=session.accept()=>{
                    let incoming=match incoming{Ok(value)=>value,Err(error)=>break if tasks.is_empty(){Ok(())}else{Err(error)}};
                    let access=peer.clone();let flows=flows.clone();let mut logical=context.clone();logical.connect_timeout=self.context.connect_timeout;logical.cancel=incoming.stream.cancel_token();logical.events.record(NodeEvent::Accepted);
                    let task = context.tasks.spawn_tracked(async move {let _lease=incoming.lease;let connecting=ConnectContext::new(logical.connect_timeout).with_cancel(logical.cancel.clone());let result=async{let target=flows.tcp(access.connect_tcp(&incoming.target,&connecting).await?)?;target.relay(Box::new(incoming.stream),logical.idle_timeout,logical.cancel.clone()).await}.await;logical.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});})?;
                    let events = context.events.clone();
                    tasks.spawn(async move { if task.await.is_err() { events.record(NodeEvent::Failed); } });
                }
            }
        };
        flows.close(crate::flow::outcome(&result));
        let draining = async { while tasks.join_next().await.is_some() {} };
        tokio::select! {biased;_=context.cancel.cancelled()=>{},_=tokio::time::timeout(context.drain_timeout,draining)=>{}}
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        session.close();
        result
    }
}

async fn relay_udp(
    mut wire: kerlico_core::DatagramAssociation,
    access: kerlico_core::UdpAssociation,
    context: InboundContext,
) -> Result<()> {
    let (mut sender, mut receiver, completion) = access.into_parts();
    let result = {
        let (activity, mut observed) = watch::channel(Instant::now());
        let responding = activity.clone();
        let request = async {
            loop {
                let Some((target, packet)) = wire.receiver.recv_from().await? else {
                    return Ok::<(), Error>(());
                };
                sender.send_to(&packet, &target).await?;
                activity.send_replace(Instant::now());
            }
        };
        let response = async {
            loop {
                let Some((source, packet)) = receiver.recv_from().await? else {
                    return Ok::<(), Error>(());
                };
                if packet.len() > context.max_datagram_size.min(udp::MAX_PACKET) {
                    context.events.record(NodeEvent::Dropped);
                    continue;
                }
                wire.sender.send_to(&packet, &source).await?;
                responding.send_replace(Instant::now());
            }
        };
        tokio::pin!(request);
        tokio::pin!(response);
        let timer = sleep(context.idle_timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {biased;_=context.cancel.cancelled()=>break Err(Error::Cancelled),result=&mut request=>break result,result=&mut response=>break result,changed=observed.changed()=>{if changed.is_err(){break Err(Error::Cancelled);}timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout);},_=&mut timer=>break Err(Error::Timeout)}
        }
    };
    completion.finish(match &result {
        Ok(()) => kerlico_core::FlowOutcome::ProtocolEnd,
        Err(error) => {
            kerlico_core::FlowOutcome::Failed(kerlico_core::FlowFailure::from_error(error))
        }
    });
    result
}
