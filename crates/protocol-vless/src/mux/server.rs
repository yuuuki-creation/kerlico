use super::completion::{Completions, Key, Scope, outcome};
use super::frame::{self, Frame};
use crate::carrier;
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, Destination, Error, InboundContext, PeerSession,
    Result,
};
use kerlico_core::{DatagramReceiver, DatagramSender, FlowFailure, FlowOutcome};
use std::collections::HashMap;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use xray_proxy::mux::{MAX_PAYLOAD, Status};
use xray_routing::{Network, Target};

struct Delivery {
    frame: Frame,
    receipt: Option<oneshot::Sender<Result<()>>>,
}
impl Delivery {
    fn signal(frame: Frame) -> Self {
        Self {
            frame,
            receipt: None,
        }
    }
}
async fn deliver(output: &mpsc::Sender<Delivery>, frame: Frame) -> Result<()> {
    let (send, receive) = oneshot::channel();
    output
        .send(Delivery {
            frame,
            receipt: Some(send),
        })
        .await
        .map_err(|_| Error::Cancelled)?;
    receive.await.map_err(|_| Error::Cancelled)?
}
struct Session {
    generation: u64,
    sender: mpsc::Sender<Frame>,
    cancel: CancellationToken,
}

pub(crate) async fn serve(
    stream: BoxStream,
    access: PeerSession,
    context: InboundContext,
    udp_only: bool,
) -> Result<()> {
    let scope = context.cancel.child_token();
    let _guard = scope.clone().drop_guard();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (output, mut frames) = mpsc::channel::<Delivery>(32);
    let (activity, mut changes) = watch::channel(Instant::now());
    let writer_activity = activity.clone();
    let writing = async move {
        while let Some(delivery) = frames.recv().await {
            let result = frame::write(&mut writer, delivery.frame).await;
            if let Some(receipt) = delivery.receipt {
                let _ = receipt.send(
                    result
                        .as_ref()
                        .map(|_| ())
                        .map_err(|_| Error::Protocol("Mux 回包写入失败")),
                );
            }
            result?;
            writer_activity.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    tokio::pin!(writing);
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    let mut sessions: HashMap<u16, Session> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut generation = 0u64;
    let completions = Completions::new(context.max_streams);
    let mut carrier_eof = false;
    let result=async {
        loop {
            // 读帧 future 跨其他事件继续，避免取消半个长度前缀后重新读取。
            let reading=frame::read(&mut reader);tokio::pin!(reading);
            let frame=loop {tokio::select! {
                biased;
                _=scope.cancelled()=>return Err(Error::Cancelled),
                result=&mut writing=>return result,
                _=&mut timer=>return Err(Error::Timeout),
                changed=changes.changed()=>{if changed.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+context.idle_timeout);}},
                result=tasks.join_next(),if !tasks.is_empty()=>{
                    if let Some(Ok((id,generation,result)))=result { completions.retire(Scope(id,generation),outcome(&result)); if sessions.get(&id).is_some_and(|s|s.generation==generation){sessions.remove(&id);} }
                },
                result=&mut reading=>break result?,
            }};
            let Some(frame)=frame else{carrier_eof=true;return Ok(())};activity.send_replace(Instant::now());
            match frame.status {
                Status::New=>{
                    if context.stream_budget.is_closed(){output.try_send(Delivery::signal(Frame::end(frame.id,true))).map_err(|_|Error::ResourceLimit)?;continue;}
                    if sessions.contains_key(&frame.id) {return Err(Error::Protocol("Mux 会话编号重复"));}
                    let target=frame.target.as_ref().ok_or(Error::InvalidAddress)?;
                    if udp_only && target.network!=Network::Udp {return Err(Error::Protocol("当前载体的 Mux 通道只允许 UDP"));}
                    if sessions.len()>=context.max_streams {output.try_send(Delivery::signal(Frame::end(frame.id,true))).map_err(|_|Error::ResourceLimit)?;continue;}
                    let permit=if sessions.is_empty(){None}else{match context.stream_budget.try_acquire(){Ok(v)=>Some(v),Err(_)=>{output.try_send(Delivery::signal(Frame::end(frame.id,true))).map_err(|_|Error::ResourceLimit)?;continue;}}};
                    generation=generation.checked_add(1).ok_or(Error::ResourceLimit)?;
                    let gen_id=generation;let id=frame.id;let udp=target.network==Network::Udp;let target=target.clone();
                    let (sender,receiver)=mpsc::channel(32);let cancel=scope.child_token();
                    sender.try_send(frame).map_err(|_|Error::ResourceLimit)?;
                    completions.scope(Scope(id,gen_id))?;
                    sessions.insert(id,Session {generation:gen_id,sender,cancel:cancel.clone()});
                    let mut context=context.clone();context.cancel=cancel.clone();let output=output.clone();let access=access.clone();
                    let owner = context.tasks.clone(); let completions = completions.clone();
                    let task = owner.spawn_tracked(async move {
                        let _permit=permit;
                        let result=if udp {udp_session(id,target,receiver,output.clone(),access,context,completions.clone(),Scope(id,gen_id)).await}else{tcp_session(id,target,receiver,output.clone(),access,context,completions.clone(),Scope(id,gen_id)).await};
                        completions.close_scope(Scope(id,gen_id),outcome(&result));
                        if udp || result.is_err() {tokio::select! {_=cancel.cancelled()=>{},_=output.send(Delivery::signal(Frame::end(id,result.is_err())))=>{}}}
                        result
                    })?;
                    tasks.spawn(async move {(id,gen_id,task.await.unwrap_or(Err(Error::Protocol("Mux 会话任务异常退出"))))});
                },
                Status::Keep=>{
                    let id=frame.id;
                    if let Some(session)=sessions.get(&id) {let sender=session.sender.clone();let delivered=tokio::select! {_=scope.cancelled()=>return Err(Error::Cancelled),r=&mut writing=>return r,r=sender.send(frame)=>r.is_ok()};if delivered{continue;}}
                    if let Some(session)=sessions.remove(&id){completions.close_scope(Scope(id,session.generation),FlowOutcome::Failed(FlowFailure::Failed));session.cancel.cancel();}
                    output.try_send(Delivery::signal(Frame::end(id,true))).map_err(|_|Error::ResourceLimit)?;
                },
                Status::End=>{if let Some(session)=sessions.remove(&frame.id){completions.close_scope(Scope(frame.id,session.generation),if frame.error {FlowOutcome::Failed(FlowFailure::Failed)} else {FlowOutcome::ProtocolEnd});session.cancel.cancel();}},
                Status::KeepAlive=>{},
            }
        }
    }.await;
    while let Some(Ok((id, generation, child))) = tasks.try_join_next() {
        completions.retire(Scope(id, generation), outcome(&child));
    }
    completions.close(if carrier_eof {
        FlowOutcome::ClosedByCaller
    } else {
        outcome(&result)
    });
    scope.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

async fn tcp_session(
    id: u16,
    target: Target,
    mut incoming: mpsc::Receiver<Frame>,
    out: mpsc::Sender<Delivery>,
    access: PeerSession,
    context: InboundContext,
    completions: Completions,
    scope_key: Scope,
) -> Result<()> {
    let target = frame::destination(&target)?;
    let remote = access
        .connect_tcp(
            &target,
            &ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone()),
        )
        .await?;
    let (remote, completion) = remote.into_parts();
    let key = Key(scope_key, 0);
    if let Err((completion, reason, error)) = completions.register(key, completion) {
        completion.finish(reason);
        return Err(error);
    }
    let (mut reader, mut writer) = tokio::io::split(remote);
    let result = async {
    let (activity, mut changes) = watch::channel(Instant::now());
    let uplink = async {
        while let Some(frame) = incoming.recv().await {
            if let Some(bytes) = frame.payload {
                writer.write_all(&bytes).await?;
                writer.flush().await?;
                activity.send_replace(Instant::now());
            }
        }
        writer.shutdown().await?;
        Ok::<_, Error>(())
    };
    let downlink = async {
        let mut bytes = vec![0; MAX_PAYLOAD];
        loop {
            let count = reader.read(&mut bytes).await?;
            if count == 0 {
                deliver(&out,Frame::end(id,false)).await?;
                return Ok::<_, Error>(());
            }
            deliver(&out, Frame::data(id, bytes[..count].to_vec(), None)).await?;
            activity.send_replace(Instant::now());
        }
    };
    tokio::pin!(uplink, downlink);
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {
            biased;
            _=context.cancel.cancelled()=>return Err(Error::Cancelled),
            result=&mut uplink=>return result,
            result=&mut downlink=>return result,
            _=&mut timer=>return Err(Error::Timeout),
            changed=changes.changed()=>{if changed.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+context.idle_timeout);}},
        }
    }
    }.await;
    completions.finish(key, outcome(&result));
    result
}

async fn udp_session(
    id: u16,
    initial: Target,
    mut incoming: mpsc::Receiver<Frame>,
    output: mpsc::Sender<Delivery>,
    access: PeerSession,
    context: InboundContext,
    completions: Completions,
    scope_key: Scope,
) -> Result<()> {
    let scope = context.cancel.child_token();
    let _guard = scope.clone().drop_guard();
    let mut targets: HashMap<Destination, (u64, mpsc::Sender<Vec<u8>>)> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut generation = 0u64;
    let (activity, mut changes) = watch::channel(Instant::now());
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    let result=async {loop {tokio::select! {
        biased;
        _=scope.cancelled()=>return Err(Error::Cancelled),
        _=&mut timer=>return Err(Error::Timeout),
        changed=changes.changed()=>{if changed.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+context.idle_timeout);}},
        done=tasks.join_next(),if !tasks.is_empty()=>{if let Some(Ok((target,generation,result)))=done {completions.finish(Key(scope_key,generation),outcome(&result));if targets.get(&target).is_some_and(|(g,_)|*g==generation){targets.remove(&target);}}},
        frame=incoming.recv()=>{
            let Some(frame)=frame else{return Ok(())};let Some(packet)=frame.payload else{continue};
            if packet.len()>context.max_datagram_size {return Err(Error::ResourceLimit);}
            let target=frame.target.as_ref().unwrap_or(&initial);
            if target.network!=Network::Udp {return Err(Error::Protocol("XUDP 目标不是 UDP"));}
            let target=frame::destination(target)?;
            if !targets.contains_key(&target) {
                if targets.len()>=context.max_streams {return Err(Error::ResourceLimit);}
                let permit=if targets.is_empty(){None}else{Some(context.stream_budget.try_acquire()?)};
                generation=generation.checked_add(1).ok_or(Error::ResourceLimit)?;let gen_id=generation;
                let (sender,receiver)=mpsc::channel(16);targets.insert(target.clone(),(gen_id,sender));
                let target=target.clone();let access=access.clone();let output=output.clone();let mut context=context.clone();context.cancel=scope.child_token();let activity=activity.clone();
                let owner=context.tasks.clone();let completed=completions.clone();
                let task=owner.spawn_tracked(async move {let _permit=permit;udp_target(id,&target,receiver,output,access,context,activity,completed,Key(scope_key,gen_id)).await})?;
                let done_target=frame::destination(frame.target.as_ref().unwrap_or(&initial))?;
                tasks.spawn(async move {(done_target,gen_id,task.await.unwrap_or(Err(Error::Protocol("Mux UDP 任务异常退出"))))});
            }
            targets.get(&target).ok_or(Error::Cancelled)?.1.try_send(packet).map_err(|_|Error::ResourceLimit)?;activity.send_replace(Instant::now());
        }
    }}}.await;
    while let Some(Ok((_, generation, child))) = tasks.try_join_next() {
        completions.finish(Key(scope_key, generation), outcome(&child));
    }
    completions.close_scope(scope_key, outcome(&result));
    scope.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

async fn udp_target(
    id: u16,
    target: &Destination,
    mut queue: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Delivery>,
    access: PeerSession,
    context: InboundContext,
    activity: watch::Sender<Instant>,
    completions: Completions,
    key: Key,
) -> Result<()> {
    let channel = access
        .connect_udp(
            target,
            &ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone()),
        )
        .await?;
    let (mut sender, mut receiver, completion) = channel.into_parts();
    if let Err((completion, reason, error)) = completions.register(key, completion) {
        completion.finish(reason);
        return Err(error);
    }
    let result = async {
    let (local, mut changes) = watch::channel(Instant::now());
    let uplink = async {
        while let Some(packet) = queue.recv().await {
            sender.send(&packet).await?;
            activity.send_replace(Instant::now());
            local.send_replace(Instant::now());
        }
        std::future::pending::<Result<()>>().await
    };
    let downlink = async {
        while let Some(packet) = receiver.recv().await? {
            if packet.len() > context.max_datagram_size {
                return Err(Error::ResourceLimit);
            }
            deliver(&out,Frame::data(id, packet, Some(carrier::target(target, true)))).await?;
            activity.send_replace(Instant::now());
            local.send_replace(Instant::now());
        }
        Ok::<_, Error>(())
    };
    tokio::pin!(uplink, downlink);
    let timer = tokio::time::sleep(context.idle_timeout);
    tokio::pin!(timer);
    loop {
        tokio::select! {biased;_=context.cancel.cancelled()=>return Err(Error::Cancelled),r=&mut uplink=>return r,r=&mut downlink=>return r,_=&mut timer=>return Err(Error::Timeout),changed=changes.changed()=>{if changed.is_ok(){timer.as_mut().reset(*changes.borrow_and_update()+context.idle_timeout);}}}
    }
    }.await;
    completions.finish(key, outcome(&result));
    result
}

pub(crate) async fn serve_packetaddr(
    stream: BoxStream,
    access: PeerSession,
    mut context: InboundContext,
) -> Result<()> {
    let scope = context.cancel.child_token();
    let _guard = scope.clone().drop_guard();
    context.cancel = scope.clone();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (input, receiver) = mpsc::channel(16);
    let (output, mut responses) = mpsc::channel::<Delivery>(16);
    let completions = Completions::new(context.max_streams);
    let scope_key = Scope(0, 0);
    completions.scope(scope_key)?;
    let limit = context.max_datagram_size;
    let wire_limit = limit.saturating_add(19).min(u16::MAX as usize);
    let uplink = async {
        while let Some(bytes) = crate::codec::read_datagram(&mut reader, wire_limit).await? {
            let (target, payload) = crate::packetaddr::decode(&bytes)?;
            input
                .send(Frame::data(
                    0,
                    payload.to_vec(),
                    Some(carrier::target(&target, true)),
                ))
                .await
                .map_err(|_| Error::Cancelled)?;
        }
        Ok::<_, Error>(())
    };
    let downlink = async {
        while let Some(delivery) = responses.recv().await {
            let frame = delivery.frame;
            let target = frame::destination(frame.target.as_ref().ok_or(Error::InvalidAddress)?)?;
            let bytes = crate::packetaddr::encode(
                &target,
                frame
                    .payload
                    .as_deref()
                    .ok_or(Error::Protocol("packetaddr 回包没有负载"))?,
            )?;
            if bytes.len() > wire_limit {
                return Err(Error::ResourceLimit);
            }
            let result = crate::codec::write_datagram(&mut writer, &bytes).await;
            if let Some(receipt) = delivery.receipt {
                let _ = receipt.send(
                    result
                        .as_ref()
                        .map(|_| ())
                        .map_err(|_| Error::Protocol("packetaddr 回包失败")),
                );
            }
            result?;
        }
        Ok::<_, Error>(())
    };
    let initial = carrier::target(&Destination::new("127.0.0.1", 1)?, true);
    let serving = udp_session(
        0,
        initial,
        receiver,
        output,
        access,
        context,
        completions.clone(),
        scope_key,
    );
    tokio::pin!(serving);
    let result = tokio::select! {biased;_=scope.cancelled()=>Err(Error::Cancelled),r=uplink=>r,r=downlink=>r,r=&mut serving=>r};
    completions.close(outcome(&result));
    scope.cancel();
    result
}

#[cfg(test)]
#[path = "server_flow_tests.rs"]
mod flow_tests;
