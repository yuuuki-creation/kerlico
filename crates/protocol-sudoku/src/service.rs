use crate::{
    config::NodeConfig,
    handshake::{self, EarlyServer, Negotiated},
    mux::Session,
    scope::Scope,
    udp,
    wire::{address, kip},
};
use kerlico_core::{
    AccessService, BoxStream, ConnectContext, Error, InboundContext, NodeEvent, Result,
};
use std::sync::Arc;
use tokio::{
    sync::watch,
    time::{Instant, sleep},
};

pub(crate) struct Runtime {
    pub config: Arc<NodeConfig>,
    pub scope: Arc<Scope>,
    pub access: Arc<dyn AccessService>,
    pub context: InboundContext,
    pub registry: Arc<crate::carrier::http::session::Registry>,
    pub cover: Option<Arc<crate::carrier::http::transport::HttpClient>>,
}
impl Runtime {
    pub fn start(
        config: Arc<NodeConfig>,
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<(
        Arc<Self>,
        tokio::sync::mpsc::Receiver<crate::carrier::http::session::Backend>,
    )> {
        let scope = Scope::new(&context.cancel);
        let (registry, backends) = crate::carrier::http::session::Registry::new(
            config.protocol.clone(),
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
                cover.tls.clone(),
                endpoint,
                &scope.cancel,
            ))
        } else {
            None
        };
        Ok((
            Arc::new(Self {
                config,
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
        early: Option<EarlyServer>,
        mut context: InboundContext,
    ) -> Result<()> {
        let start = Instant::now();
        let opening = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let negotiated = opening
            .run(async {
                if let Some(early) = early {
                    early.finish(stream)
                } else {
                    handshake::server(stream, &self.config.protocol).await
                }
            })
            .await?;
        context.connect_timeout = context.connect_timeout.saturating_sub(start.elapsed());
        self.process(negotiated, context).await
    }
    pub async fn process(
        self: &Arc<Self>,
        mut negotiated: Negotiated,
        context: InboundContext,
    ) -> Result<()> {
        let start = Instant::now();
        let opening = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
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
        let connecting = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout.saturating_sub(start.elapsed()),
        };
        match intent.kind {
            kip::OPEN_TCP if negotiated.features & 1 != 0 => {
                let (target, _) = address::decode(&intent.payload)?;
                let stream = self.access.connect_tcp(&target, &connecting).await?;
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
                let access = self.access.associate_udp(&connecting).await?;
                let wire = udp::association(
                    negotiated.stream,
                    &context.cancel,
                    context.max_datagram_size,
                    false,
                );
                relay_udp(wire, access, context).await
            }
            kip::START_MUX if negotiated.features & 2 != 0 && intent.payload.is_empty() => {
                self.multiplex(negotiated.stream, context).await
            }
            _ => Err(Error::Unsupported("Sudoku意图未协商或格式不合法")),
        }
    }
    async fn multiplex(self: &Arc<Self>, stream: BoxStream, context: InboundContext) -> Result<()> {
        let session = Session::start(
            stream,
            &context.cancel,
            self.config.max_streams.min(context.max_streams),
            context.idle_timeout,
            Some(context.stream_budget.clone()),
            true,
        );
        let mut tasks = tokio::task::JoinSet::new();
        let result = loop {
            tokio::select! {biased;
                _=context.cancel.cancelled()=>break Err(Error::Cancelled),
                Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                incoming=session.accept()=>{
                    let incoming=match incoming{Ok(value)=>value,Err(error)=>break if tasks.is_empty(){Ok(())}else{Err(error)}};
                    let runtime=self.clone();let mut logical=context.clone();logical.connect_timeout=self.context.connect_timeout;logical.cancel=incoming.stream.cancel_token();logical.events.record(NodeEvent::Accepted);
                    tasks.spawn(async move {let _lease=incoming.lease;let connecting=ConnectContext {cancel:logical.cancel.clone(),timeout:logical.connect_timeout};let result=async{let target=runtime.access.connect_tcp(&incoming.target,&connecting).await?;kerlico_core::relay_tcp(Box::new(incoming.stream),target,logical.idle_timeout,logical.cancel.clone()).await}.await;logical.events.record(if result.is_ok(){NodeEvent::Completed}else{NodeEvent::Failed});});
                }
            }
        };
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
    mut access: kerlico_core::DatagramAssociation,
    context: InboundContext,
) -> Result<()> {
    let (activity, mut observed) = watch::channel(Instant::now());
    let responding = activity.clone();
    let request = async {
        loop {
            let Some((target, packet)) = wire.receiver.recv_from().await? else {
                return Ok::<(), Error>(());
            };
            access.sender.send_to(&packet, &target).await?;
            activity.send_replace(Instant::now());
        }
    };
    let response = async {
        loop {
            let Some((source, packet)) = access.receiver.recv_from().await? else {
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
        tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),result=&mut request=>return result,result=&mut response=>return result,changed=observed.changed()=>{if changed.is_err(){return Err(Error::Cancelled);}timer.as_mut().reset(*observed.borrow_and_update()+context.idle_timeout);},_=&mut timer=>return Err(Error::Timeout)}
    }
}
