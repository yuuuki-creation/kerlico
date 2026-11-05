#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod support;
use crate::{
    config::{Mode, Obfs, Settings, userkey},
    invalid, obfs, protocol,
    stream::{Pool, Session, Stream},
    wire,
};
use kerlico_config::{NodeBuildContext, NodeFactory};
use kerlico_core::{
    BoxFuture, BoxStream, ConnectContext, CredentialManifest, CredentialSet, Error, InboundContext,
    InboundProtocol, IngressBinding, NodeEvent, Result,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
pub struct SnellNodeFactory;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    version: u8,
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    obfs_mode: Obfs,
    #[serde(default)]
    obfs_host: Option<String>,
    #[serde(default)]
    obfs_uri: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    psk: String,
    #[serde(default)]
    userkey: String,
}
struct Credential {
    settings: Arc<Settings>,
    user: Option<[u8; 32]>,
}
struct SnellNode {
    settings: Arc<Settings>,
    credentials: CredentialSet<Credential>,
    replays: Mutex<HashMap<[u8; 16], Instant>>,
}
impl NodeFactory for SnellNodeFactory {
    fn kind(&self) -> &'static str {
        "snell"
    }
    fn build(&self, input: &NodeBuildContext) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options =
            serde_json::from_value(input.options().clone()).map_err(|_| invalid())?;
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        for value in input.native_credentials() {
            let user: User = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            let settings = Arc::new(
                Settings::new(
                    options.version,
                    user.psk,
                    options.mode,
                    options.obfs_mode.clone(),
                    options.obfs_host.clone(),
                    options.obfs_uri.clone(),
                    true,
                )?
                .with_cipher(options.cipher.as_deref())?,
            );
            let key = userkey(&user.userkey)?;
            if settings.raw() && key.is_empty() {
                return Err(invalid());
            }
            let hash = (!key.is_empty()).then(|| <[u8; 32]>::from(Sha256::digest(&key)));
            let effective = if settings.raw() {
                Vec::new()
            } else {
                settings.psk.to_vec()
            };
            if !seen.insert((effective.clone(), hash))
                || rows.iter().any(|row: &Credential| {
                    !settings.raw()
                        && row.settings.psk.as_ref() == effective.as_slice()
                        && (row.user.is_none() || hash.is_none())
                })
            {
                return Err(invalid());
            }
            rows.push(Credential {
                settings,
                user: hash,
            });
        }
        if rows.is_empty() || rows.len() > 256 {
            return Err(invalid());
        }
        let settings = rows[0].settings.clone();
        Ok(Arc::new(SnellNode {
            settings,
            credentials: input.credentials(rows)?,
            replays: Mutex::new(HashMap::new()),
        }))
    }
}
impl SnellNode {
    fn replay(&self, salt: Option<[u8; 16]>) -> Result<()> {
        let Some(salt) = salt else {
            return Ok(());
        };
        let mut replays = self.replays.lock().map_err(|_| protocol())?;
        replays.retain(|_, time| time.elapsed() < Duration::from_secs(300));
        if replays.contains_key(&salt) {
            return Err(protocol());
        }
        if replays.len() >= 8192 {
            return Err(Error::ResourceLimit);
        }
        replays.insert(salt, Instant::now());
        Ok(())
    }
    async fn serve(
        &self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> Result<()> {
        let budget =
            ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone());
        let raw = budget
            .run(async {
                obfs::wrap(stream, &self.settings, true)
                    .await
                    .map_err(Error::from)
            })
            .await?;
        let candidates = crate::credential_io::Candidates::new(raw);
        let mut tasks = tokio::task::JoinSet::new();
        for (slot, row) in self.credentials.rows() {
            let settings = row.settings.clone();
            let user = row.user;
            let raw = candidates.reader();
            let owner = context.tasks.clone();
            let task = owner.spawn_tracked(async move {
                let mut session = Session::new(Box::new(raw), settings)?;
                let record = session.reader.next().await?.ok_or_else(protocol)?;
                session
                    .writer
                    .sync_v3_cipher(session.reader.v3_chacha_used)?;
                let request = wire::parse_request(&record)?;
                let hash: [u8; 32] = Sha256::digest(&request.userkey).into();
                if user.is_some_and(|expected| !bool::from(expected.ct_eq(&hash))) {
                    return Err(protocol());
                }
                Ok::<_, Error>((slot, user, session, record))
            })?;
            tasks.spawn(async move {
                task.await
                    .unwrap_or(Err(Error::Protocol("Snell 认证任务异常退出")))
            });
        }
        let selected = budget
            .run(async {
                while let Some(result) = tasks.join_next().await {
                    if let Ok(Ok(result)) = result {
                        return Ok(result);
                    }
                }
                Err(Error::Rejected)
            })
            .await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        let (slot, user, mut session, first_record) = selected?;
        self.replay(session.reader.salt())?;
        candidates.accept();
        let (access, ()) = access.authenticated(self.credentials.verified(&slot, ())?, &context)?;
        let mut first_record = Some(first_record);
        loop {
            let opening = if first_record.is_some() {
                budget.clone()
            } else {
                ConnectContext::new(context.connect_timeout).with_cancel(context.cancel.clone())
            };
            let record = if let Some(record) = first_record.take() {
                record
            } else {
                match session.reader.next().await? {
                    Some(record) => record,
                    None => return Ok(()),
                }
            };
            let request = wire::parse_request(&record)?;
            let hash: [u8; 32] = Sha256::digest(&request.userkey).into();
            if user.is_some_and(|expected| !bool::from(expected.ct_eq(&hash))) {
                return Err(protocol());
            }
            match request.command {
                0 => {
                    session.send(&[1]).await?;
                    return Ok(());
                }
                6 => {
                    if !request.tail.is_empty() {
                        return Err(protocol());
                    }
                    opening
                        .run(async { session.send(&[0]).await.map_err(Error::Io) })
                        .await?;
                    return crate::udp::serve(session, access, context).await;
                }
                1 | 5 => {
                    if context.stream_budget.is_closed() {
                        return Err(Error::Cancelled);
                    }
                    let reuse = request.command == 5;
                    let lease = if reuse {
                        Some(context.stream_budget.try_acquire()?)
                    } else {
                        None
                    };
                    let target = request.target.ok_or_else(protocol)?;
                    let remote = match access.connect_tcp(&target, &opening).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = session.send(&wire::error_reply(1, "目标连接失败")).await;
                            return Err(error);
                        }
                    };
                    if let Err(error) = opening
                        .run(async { session.send(&[0]).await.map_err(Error::Io) })
                        .await
                    {
                        remote.finish(kerlico_core::FlowOutcome::Failed(
                            kerlico_core::FlowFailure::from_error(&error),
                        ));
                        return Err(error);
                    }
                    let handoff = if reuse { Some(Pool::new(1)) } else { None };
                    let stream = Stream::new(session, false, request.tail, handoff.clone(), reuse);
                    if reuse {
                        context.events.record(NodeEvent::Accepted);
                    }
                    let result = kerlico_core::relay_tcp(
                        Box::new(stream),
                        remote,
                        context.idle_timeout,
                        context.cancel.clone(),
                    )
                    .await;
                    if reuse {
                        context.events.record(if result.is_ok() {
                            NodeEvent::Completed
                        } else {
                            NodeEvent::Failed
                        });
                    }
                    drop(lease);
                    result?;
                    if !reuse || context.stream_budget.is_closed() {
                        return Ok(());
                    }
                    session = handoff.and_then(|pool| pool.take()).ok_or_else(protocol)?;
                }
                _ => return Err(protocol()),
            }
        }
    }
}
impl InboundProtocol for SnellNode {
    fn requires_loopback(&self) -> bool {
        self.settings.raw()
    }
    fn credential_manifest(&self) -> CredentialManifest {
        let mut manifest = CredentialManifest::new();
        for (slot, (_, row)) in self.credentials.rows().enumerate() {
            let mut hash = Sha256::new();
            if row.settings.raw() {
                hash.update(b"kerlico/snell/raw/");
                hash.update(row.user.expect("raw 成员已校验"));
                manifest.authentication("snell", slot, hash.finalize().into());
            } else if let Some(user) = row.user {
                hash.update(b"kerlico/snell/sealed/");
                hash.update(&*row.settings.psk);
                manifest.protection("snell", hash.finalize().into());
                let mut hash = Sha256::new();
                hash.update(b"kerlico/snell/user/");
                hash.update(user);
                manifest.authentication("snell", slot, hash.finalize().into());
            } else {
                hash.update(b"kerlico/snell/sealed/");
                hash.update(&*row.settings.psk);
                manifest.authentication("snell", slot, hash.finalize().into());
            }
        }
        manifest
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: IngressBinding,
        context: InboundContext,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (stream, activity) = crate::io::observe(stream);
            crate::io::bounded(
                self.serve(stream, access, context.clone()),
                activity,
                context.idle_timeout,
                context.cancel,
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_state_is_bounded_and_requires_new_salt() {
        let settings = Arc::new(
            Settings::new(
                6,
                "snell-replay-test-key".into(),
                Some(Mode::Unshaped),
                Obfs::None,
                None,
                None,
                true,
            )
            .unwrap(),
        );
        let node = SnellNode {
            settings,
            credentials: NodeBuildContext::local_for_test(serde_json::json!({}))
                .credentials(Vec::new())
                .unwrap(),
            replays: Mutex::new(HashMap::new()),
        };
        assert!(node.replay(Some([17; 16])).is_ok());
        assert!(node.replay(Some([17; 16])).is_err());
        node.replays
            .lock()
            .unwrap()
            .insert([17; 16], Instant::now() - Duration::from_secs(301));
        assert!(node.replay(Some([17; 16])).is_ok());
        let mut replays = node.replays.lock().unwrap();
        for n in 0..8192u64 {
            let mut salt = [0; 16];
            salt[..8].copy_from_slice(&n.to_be_bytes());
            replays.insert(salt, Instant::now());
        }
        drop(replays);
        assert!(matches!(
            node.replay(Some([23; 16])),
            Err(Error::ResourceLimit)
        ));
    }
}

#[cfg(test)]
mod multi_target_test {
    use super::*;
    use kerlico_core::{DatagramChannel, Destination, NodeObserver, Outbound, StreamBudget};
    use tokio::{net::UdpSocket, sync::Semaphore, task::JoinSet};
    struct Direct(Arc<dyn Outbound>);
    impl Outbound for Direct {
        fn capabilities(&self) -> kerlico_core::Capabilities {
            kerlico_core::Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            target: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            self.0.connect_tcp(target, context)
        }
        fn connect_udp<'a>(
            &'a self,
            target: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            self.0.connect_udp(target, context)
        }
    }
    struct Events;
    impl NodeObserver for Events {
        fn record(&self, _: NodeEvent) {}
    }
    #[tokio::test]
    async fn one_authenticated_udp_carrier_keeps_multiple_targets_distinct() {
        tokio::time::timeout(Duration::from_secs(5),async{
            let mut tasks=JoinSet::new();let mut targets=Vec::new();
            for &marker in b"ab"{
                let socket=UdpSocket::bind("127.0.0.1:0").await.unwrap();let target=Destination::new("127.0.0.1",socket.local_addr().unwrap().port()).unwrap();targets.push((target,marker));
                tasks.spawn(async move{let mut bytes=[0;64];let(n,peer)=socket.recv_from(&mut bytes).await.unwrap();let mut packet=vec![marker];packet.extend_from_slice(&bytes[..n]);socket.send_to(&packet,peer).await.unwrap();});
            }
            let node=support::node(&SnellNodeFactory,&serde_json::json!({"version":6,"psk":"snell-multi-target-psk","users":[{"userkey":"test-user"}]})).unwrap();let access:Arc<dyn Outbound>=Arc::new(Direct(support::outbound(&kerlico_net::DirectFactory,&serde_json::json!({})).unwrap()));let cancel=kerlico_core::CancellationToken::new();
            let context=InboundContext{peer_lease:None,tasks:kerlico_core::NodeTasks::new(kerlico_core::NodeId::parse("test-node").unwrap(),kerlico_core::CancellationToken::new()),cancel:cancel.clone(),connect_timeout:Duration::from_secs(1),idle_timeout:Duration::from_secs(2),drain_timeout:Duration::from_secs(1),max_datagram_size:65535,max_streams:16,stream_budget:StreamBudget::new(Arc::new(Semaphore::new(32)),Arc::new(Semaphore::new(32))),events:Arc::new(Events),peer_addr:None,local_addr:None};
            let(left,right)=tokio::io::duplex(65536);tasks.spawn(async move{let _=node.handle(Box::new(right),access,context).await;});
            let settings=Arc::new(Settings::new(6,"snell-multi-target-psk".into(),Some(Mode::Default),Obfs::None,None,None,false).unwrap());let mut session=Session::new(Box::new(left),settings).unwrap();session.send(&wire::request(6,b"test-user",None)).await.unwrap();assert_eq!(wire::reply(session.reader.next().await.unwrap().unwrap()).unwrap(),Vec::<u8>::new());
            for(target,_)in &targets{session.send(&wire::udp_request(target,b"packet").unwrap()).await.unwrap();}
            let mut actual=Vec::new();for _ in 0..2{let record=session.reader.next().await.unwrap().unwrap();let(target,payload)=wire::parse_udp(&record,true).unwrap();actual.push((target.port(),payload));}
            let mut expected:Vec<_>=targets.into_iter().map(|(target,marker)|{let mut payload=vec![marker];payload.extend_from_slice(b"packet");(target.port(),payload)}).collect();actual.sort();expected.sort();assert_eq!(actual,expected);drop(session);cancel.cancel();
        }).await.expect("多目标 UDP 回写超时");
    }
    #[tokio::test]
    async fn target_reply_must_respect_node_datagram_limit() {
        tokio::time::timeout(Duration::from_secs(5),async{
            let target=UdpSocket::bind("127.0.0.1:0").await.unwrap();let destination=Destination::new("127.0.0.1",target.local_addr().unwrap().port()).unwrap();let mut tasks=JoinSet::new();
            tasks.spawn(async move{let mut bytes=[0;64];for _ in 0..2{let(n,peer)=target.recv_from(&mut bytes).await.unwrap();let mut reply=bytes[..n].to_vec();reply.extend_from_slice(&bytes[..n]);target.send_to(&reply,peer).await.unwrap();}});
            let node=support::node(&SnellNodeFactory,&serde_json::json!({"version":6,"psk":"snell-reply-limit-key","mode":"unshaped","users":[{"userkey":"test-user"}]})).unwrap();let access:Arc<dyn Outbound>=Arc::new(Direct(support::outbound(&kerlico_net::DirectFactory,&serde_json::json!({})).unwrap()));let cancel=kerlico_core::CancellationToken::new();
            let context=InboundContext{peer_lease:None,tasks:kerlico_core::NodeTasks::new(kerlico_core::NodeId::parse("test-node").unwrap(),kerlico_core::CancellationToken::new()),cancel,connect_timeout:Duration::from_secs(1),idle_timeout:Duration::from_secs(2),drain_timeout:Duration::from_secs(1),max_datagram_size:4,max_streams:16,stream_budget:StreamBudget::new(Arc::new(Semaphore::new(32)),Arc::new(Semaphore::new(32))),events:Arc::new(Events),peer_addr:None,local_addr:None};
            let(left,right)=tokio::io::duplex(65536);let running=tokio::spawn(async move{node.handle(Box::new(right),access,context).await});
            let settings=Arc::new(Settings::new(6,"snell-reply-limit-key".into(),Some(Mode::Unshaped),Obfs::None,None,None,false).unwrap());let mut session=Session::new(Box::new(left),settings).unwrap();session.send(&wire::request(6,b"test-user",None)).await.unwrap();wire::reply(session.reader.next().await.unwrap().unwrap()).unwrap();
            session.send(&wire::udp_request(&destination,b"ok").unwrap()).await.unwrap();let record=session.reader.next().await.unwrap().unwrap();assert_eq!(wire::parse_udp(&record,true).unwrap().1,b"okok");
            session.send(&wire::udp_request(&destination,b"four").unwrap()).await.unwrap();assert!(matches!(session.reader.next().await,Ok(None)|Err(_)));assert!(matches!(running.await.unwrap(),Err(Error::ResourceLimit)));
        }).await.expect("节点 UDP 回写包长限制未生效");
    }
}
