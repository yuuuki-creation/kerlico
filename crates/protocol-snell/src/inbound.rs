use crate::{
    config::{Mode, Obfs, Settings, userkey},
    invalid, obfs, protocol,
    stream::{Pool, Session, Stream},
    wire,
};
use kerlico_config::NodeFactory;
use kerlico_core::{
    AccessService, BoxFuture, BoxStream, ConnectContext, Error, InboundContext, InboundProtocol,
    NodeEvent, Result,
};
use serde::Deserialize;
use serde_json::Value;
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
    psk: String,
    #[serde(default)]
    users: Vec<User>,
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
    userkey: String,
}
struct SnellNode {
    settings: Arc<Settings>,
    users: Vec<[u8; 32]>,
    replays: Mutex<HashMap<[u8; 16], Instant>>,
}
impl NodeFactory for SnellNodeFactory {
    fn kind(&self) -> &'static str {
        "snell"
    }
    fn build(&self, options: &Value) -> Result<Arc<dyn InboundProtocol>> {
        let options: Options = serde_json::from_value(options.clone()).map_err(|_| invalid())?;
        let settings = Arc::new(Settings::new(
            options.version,
            options.psk,
            options.mode,
            options.obfs_mode,
            options.obfs_host,
            options.obfs_uri,
            true,
        )?);
        if options.users.len() > 256 || (settings.raw() && options.users.is_empty()) {
            return Err(invalid());
        }
        let mut seen = BTreeSet::new();
        let mut users = Vec::new();
        for user in options.users {
            let key = userkey(&user.userkey)?;
            if key.is_empty() {
                return Err(invalid());
            }
            let hash: [u8; 32] = Sha256::digest(&key).into();
            if !seen.insert(hash) {
                return Err(invalid());
            }
            users.push(hash);
        }
        Ok(Arc::new(SnellNode {
            settings,
            users,
            replays: Mutex::new(HashMap::new()),
        }))
    }
}
impl SnellNode {
    fn authenticate(&self, key: &[u8]) -> Result<()> {
        if self.users.is_empty() {
            return Ok(());
        }
        let hash: [u8; 32] = Sha256::digest(key).into();
        let mut accepted = subtle::Choice::from(0);
        for user in &self.users {
            accepted |= user.ct_eq(&hash);
        }
        if bool::from(accepted) {
            Ok(())
        } else {
            Err(protocol())
        }
    }
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
        access: Arc<dyn AccessService>,
        context: InboundContext,
    ) -> Result<()> {
        let budget = ConnectContext {
            cancel: context.cancel.clone(),
            timeout: context.connect_timeout,
        };
        let mut session = budget
            .run(async {
                let stream = obfs::wrap(stream, &self.settings, true).await?;
                Ok(Session::new(stream, self.settings.clone())?)
            })
            .await?;
        let mut first = true;
        loop {
            let record = if first {
                budget
                    .run(async { session.reader.next().await?.ok_or_else(protocol) })
                    .await?
            } else {
                match session.reader.next().await? {
                    Some(record) => record,
                    None => return Ok(()),
                }
            };
            let request = wire::parse_request(&record)?;
            self.authenticate(&request.userkey)?;
            if first {
                self.replay(session.reader.salt())?;
                first = false;
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
                    session.send(&[0]).await?;
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
                    let remote = match access.connect_tcp(&target, &budget).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = session.send(&wire::error_reply(1, "目标连接失败")).await;
                            return Err(error);
                        }
                    };
                    session.send(&[0]).await?;
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
    fn credential_fingerprints(&self) -> Vec<[u8; 32]> {
        if self.settings.raw() {
            return self
                .users
                .iter()
                .map(|user| {
                    let mut hash = Sha256::new();
                    hash.update(b"kerlico/snell/raw/");
                    hash.update(user);
                    hash.finalize().into()
                })
                .collect();
        }
        // 单 PSK 节点接受任意 client-id，因此所有加密节点都登记 PSK 本身的范围。
        let mut hash = Sha256::new();
        hash.update(b"kerlico/snell/sealed/");
        hash.update(&*self.settings.psk);
        vec![hash.finalize().into()]
    }
    fn handle<'a>(
        &'a self,
        stream: BoxStream,
        access: Arc<dyn AccessService>,
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
            users: Vec::new(),
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
    use kerlico_config::OutboundFactory;
    use kerlico_core::{DatagramChannel, Destination, NodeObserver, Outbound, StreamBudget};
    use tokio::{net::UdpSocket, sync::Semaphore, task::JoinSet};
    struct Direct(Arc<dyn Outbound>);
    impl AccessService for Direct {
        fn connect_tcp<'a>(
            &'a self,
            target: &'a Destination,
            context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<BoxStream>> {
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
            let node=SnellNodeFactory.build(&serde_json::json!({"version":6,"psk":"snell-multi-target-psk","users":[{"userkey":"test-user"}]})).unwrap();let access:Arc<dyn AccessService>=Arc::new(Direct(kerlico_net::DirectFactory.build(&serde_json::json!({})).unwrap()));let cancel=kerlico_core::CancellationToken::new();
            let context=InboundContext{cancel:cancel.clone(),connect_timeout:Duration::from_secs(1),idle_timeout:Duration::from_secs(2),drain_timeout:Duration::from_secs(1),max_datagram_size:65535,max_streams:16,stream_budget:StreamBudget::new(Arc::new(Semaphore::new(32)),Arc::new(Semaphore::new(32))),events:Arc::new(Events),peer_addr:None,local_addr:None};
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
            let node=SnellNodeFactory.build(&serde_json::json!({"version":6,"psk":"snell-reply-limit-key","mode":"unshaped","users":[{"userkey":"test-user"}]})).unwrap();let access:Arc<dyn AccessService>=Arc::new(Direct(kerlico_net::DirectFactory.build(&serde_json::json!({})).unwrap()));let cancel=kerlico_core::CancellationToken::new();
            let context=InboundContext{cancel,connect_timeout:Duration::from_secs(1),idle_timeout:Duration::from_secs(2),drain_timeout:Duration::from_secs(1),max_datagram_size:4,max_streams:16,stream_budget:StreamBudget::new(Arc::new(Semaphore::new(32)),Arc::new(Semaphore::new(32))),events:Arc::new(Events),peer_addr:None,local_addr:None};
            let(left,right)=tokio::io::duplex(65536);let running=tokio::spawn(async move{node.handle(Box::new(right),access,context).await});
            let settings=Arc::new(Settings::new(6,"snell-reply-limit-key".into(),Some(Mode::Unshaped),Obfs::None,None,None,false).unwrap());let mut session=Session::new(Box::new(left),settings).unwrap();session.send(&wire::request(6,b"test-user",None)).await.unwrap();wire::reply(session.reader.next().await.unwrap().unwrap()).unwrap();
            session.send(&wire::udp_request(&destination,b"ok").unwrap()).await.unwrap();let record=session.reader.next().await.unwrap().unwrap();assert_eq!(wire::parse_udp(&record,true).unwrap().1,b"okok");
            session.send(&wire::udp_request(&destination,b"four").unwrap()).await.unwrap();assert!(matches!(session.reader.next().await,Ok(None)|Err(_)));assert!(matches!(running.await.unwrap(),Err(Error::ResourceLimit)));
        }).await.expect("节点 UDP 回写包长限制未生效");
    }
}
