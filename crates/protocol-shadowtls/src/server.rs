//! 只把已完成切换的流交给内层；探测回退不接触网站访问服务。
use crate::{config, prefix, stream, wire};
use hmac::Mac;
use kerlico_core::{BoxStream, CancellationToken, Destination, Result};
use std::{collections::VecDeque, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub(crate) enum Outcome {
    Ready(BoxStream),
    Fallback(BoxStream, BoxStream),
}
struct Limit {
    frames: usize,
    bytes: usize,
}
impl Limit {
    fn add(&mut self, record: &[u8]) -> Result<()> {
        self.frames += 1;
        self.bytes += record.len();
        if self.frames > 256 || self.bytes > 1024 * 1024 {
            Err(wire::error())
        } else {
            Ok(())
        }
    }
}
async fn dial(target: &Destination) -> Result<BoxStream> {
    let stream = TcpStream::connect((target.host().as_str(), target.port())).await?;
    stream.set_nodelay(true)?;
    Ok(Box::new(stream))
}
pub(crate) async fn negotiate(
    mut front: BoxStream,
    settings: &config::Server,
    keys: &[Arc<[u8]>],
    cancel: CancellationToken,
    owner: kerlico_core::NodeTasks,
) -> Result<Outcome> {
    let first = wire::read(&mut front).await?.ok_or_else(wire::error)?;
    let name = wire::server_name(&first).ok().flatten();
    let target = match name
        .as_ref()
        .and_then(|name| settings.handshake_for_server_name.get(name))
    {
        Some(target) => target.destination()?,
        None => settings.handshake.destination()?,
    };
    let mut origin = dial(&target).await?;
    origin.write_all(&first).await?;
    let selected = if settings.version == 3 {
        keys.iter()
            .find(|key| wire::client_auth(&first, key))
            .cloned()
    } else {
        None
    };
    if settings.version == 3 && selected.is_none()
        || settings.version == 2 && wire::client_early_data(&first)
    {
        return Ok(Outcome::Fallback(front, origin));
    }
    let (mut client_r, mut client_w) = tokio::io::split(front);
    let (mut origin_r, mut origin_w) = tokio::io::split(origin);
    let mut from_client = wire::Reader::new();
    let mut from_server = wire::Reader::new();
    let mut client_ccs = false;
    let mut server_ccs = false;
    let mut client_done = false;
    let mut server_done = false;
    let mut hashes = VecDeque::<[u8; 8]>::new();
    let mut transcript = wire::hash(keys.first().map_or(&[][..], |key| key.as_ref()), &[]);
    let mut seed = None;
    let mut handshake_hash = None;
    let mut verify_hash = None;
    let mut rejected_app = 0;
    let mut gate = crate::v2::Gate::default();
    let mut late = Vec::<Vec<u8>>::new();
    let mut limit = Limit {
        frames: 1,
        bytes: first.len(),
    };
    loop {
        if settings.version == 1 && client_done && server_done {
            return Ok(Outcome::Ready(client_r.unsplit(client_w)));
        }
        tokio::select! {
            biased;
            _=cancel.cancelled()=>return Err(kerlico_core::Error::Cancelled),
            result=from_client.next(&mut client_r),if !client_done=>{
                let record=result?.ok_or_else(wire::error)?;limit.add(&record)?;
                if settings.version==1 {
                    if record[0]==wire::CCS{client_ccs=true;}else if record[0]!=wire::HANDSHAKE{return Err(wire::error());}
                    origin_w.write_all(&record).await?;
                    if client_ccs && record[0]==wire::HANDSHAKE{client_done=true;}
                }else{
                    if record[0]==wire::APP{
                        if record[1..3]!=[3,3]{return Err(wire::error());}
                        let mut matched=None;
                        if settings.version==2 && record.len()>=13 && hashes.iter().any(|hash|wire::equal(hash,&record[5..13])){matched=Some(record[13..].to_vec());}
                        if settings.version==3 && let Some(state)=verify_hash.as_mut() && wire::verify(state,&record[5..],true){matched=Some(record[9..].to_vec());}
                        if let Some(initial)=matched {
                            let raw=client_r.unsplit(client_w);
                            drop(origin_r);drop(origin_w);
                            let (read,write)=if settings.version==2 {
                                (stream::ReadMode::V2(None),stream::WriteMode::V2(None))
                            }else{
                                let random=seed.ok_or_else(wire::error)?;let key=selected.as_ref().ok_or_else(wire::error)?;
                                (stream::ReadMode::V3{verify:Box::new(verify_hash.take().ok_or_else(wire::error)?),ignore:None},stream::WriteMode::V3(wire::directional(key,&random,b'S')))
                            };
                            return Ok(Outcome::Ready(stream::wrap(raw,initial,read,write,cancel,stream::Owner::Node(owner))?));
                        }
                        // 尚未切换时的 TLS 密文不能改变累计业务 HMAC。
                        if settings.version==3 && let (Some(key),Some(random))=(&selected,&seed){verify_hash=Some(wire::directional(key,random,b'C'));}
                        rejected_app+=1;
                    }
                    origin_w.write_all(&record).await?;
                    if settings.version==2 {
                        let completed=gate.ready();gate.client(&record);
                        if completed || rejected_app>2 {
                            for buffered in late { client_w.write_all(&buffered).await?; }
                            client_w.flush().await?;
                            let front=prefix::prepend(client_r.unsplit(client_w),from_client.pending());
                            let origin=prefix::prepend(origin_r.unsplit(origin_w),from_server.pending());
                            return Ok(Outcome::Fallback(front,origin));
                        }
                    }
                }
            },
            result=from_server.next(&mut origin_r),if !server_done=>{
                let mut record=result?.ok_or_else(wire::error)?;limit.add(&record)?;
                if settings.version==1 {
                    if record[0]==wire::CCS{server_ccs=true;}else if record[0]!=wire::HANDSHAKE{return Err(wire::error());}
                    client_w.write_all(&record).await?;
                    if server_ccs && record[0]==wire::HANDSHAKE{server_done=true;}
                }else if settings.version==2 {
                    if gate.ready(){late.push(record);continue;}
                    gate.server(&record);
                    transcript.update(&record);hashes.push_back(wire::sum::<8>(&transcript));if hashes.len()>8{hashes.pop_front();}
                    client_w.write_all(&record).await?;
                }else{
                    let key=selected.as_ref().ok_or_else(wire::error)?;
                    if seed.is_none() && record[0]==wire::HANDSHAKE && record.get(5)==Some(&2){
                        let (random,tls13)=wire::server_hello(&record)?;
                        client_w.write_all(&record).await?;
                        if settings.strict()&&!tls13 {
                            let front=prefix::prepend(client_r.unsplit(client_w),from_client.pending());
                            let origin=prefix::prepend(origin_r.unsplit(origin_w),from_server.pending());
                            return Ok(Outcome::Fallback(front,origin));
                        }
                        if tls13 && random==wire::HRR_RANDOM { continue; }
                        seed=Some(random);handshake_hash=Some(wire::hash(key,&random));verify_hash=Some(wire::directional(key,&random,b'C'));
                        continue;
                    }
                    if record[0]==wire::APP {
                        if record.len()-5+4>wire::MAX_RECORD{return Err(wire::error());}
                        let random=seed.ok_or_else(wire::error)?;let mut payload=record[5..].to_vec();wire::xor(key,&random,&mut payload);
                        let hash=handshake_hash.as_mut().ok_or_else(wire::error)?;let tag=wire::tag(hash,&payload,false);
                        let mut protected=tag.to_vec();protected.extend_from_slice(&payload);record=wire::frame(wire::APP,&protected);
                    }
                    client_w.write_all(&record).await?;
                }
                client_w.flush().await?;
            },
        }
    }
}

#[cfg(test)]
mod replay_tests {
    use super::*;
    use kerlico_core::{
        BoxFuture, ConnectContext, CredentialManifest, DatagramChannel, InboundContext,
        InboundProtocol, IngressBinding, NodeEvent, NodeObserver, Outbound, StreamBudget,
    };
    use serde_json::json;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::{io::AsyncWriteExt, net::TcpListener};
    #[tokio::test]
    async fn recorded_hrr_seed_mac_never_authorizes_a_new_carrier() {
        tokio::time::timeout(std::time::Duration::from_secs(3),async{
            let key=b"hrr-replay-test";let hello=crate::tls::signed_hello_for_replay_test(key);assert!(wire::client_auth(&hello,key));
            let (_,_,sid)=wire::hello(&hello,1).unwrap();let sid=sid.to_vec();
            let listener=TcpListener::bind(("127.0.0.1",0)).await.unwrap();let port=listener.local_addr().unwrap().port();
            let origin=tokio::spawn(async move{
                let(mut stream,_)=listener.accept().await.unwrap();wire::read(&mut stream).await.unwrap().unwrap();
                let mut message=vec![2,0,0,0,3,3];message.extend_from_slice(&wire::HRR_RANDOM);message.push(sid.len() as u8);message.extend_from_slice(&sid);message.extend_from_slice(&[0x13,1,0,0,12,0,43,0,2,3,4,0,51,0,2,0,23]);let length=message.len()-4;message[1..4].copy_from_slice(&[(length>>16) as u8,(length>>8) as u8,length as u8]);stream.write_all(&wire::frame(wire::HANDSHAKE,&message)).await.unwrap();
                let forwarded=wire::read(&mut stream).await.unwrap();stream.shutdown().await.unwrap();forwarded.is_some()
            });
            let settings:config::Server=config::parse(&json!({"version":3,"password":"hrr-replay-test","handshake":{"host":"127.0.0.1","port":port},"inner":{"type":"shadowsocks","options":{"method":"aes-128-gcm","password":"inner-test"}}})).unwrap();let keys=settings.validate().unwrap();
            let (raw,mut client)=tokio::io::duplex(4096);let server=tokio::spawn(async move{negotiate(Box::new(raw),&settings,&keys,CancellationToken::new(),kerlico_core::NodeTasks::new(kerlico_core::NodeId::parse("shadowtls-test").unwrap(),CancellationToken::new())).await});
            client.write_all(&hello).await.unwrap();let retry=wire::read(&mut client).await.unwrap().unwrap();assert_eq!(wire::server_hello(&retry).unwrap().0,wire::HRR_RANDOM);
            let mut old=wire::directional(key,&wire::HRR_RANDOM,b'C');let payload=b"recorded-data";let mut body=wire::tag(&mut old,payload,true).to_vec();body.extend_from_slice(payload);client.write_all(&wire::frame(wire::APP,&body)).await.unwrap();
            let outcome=server.await.unwrap();assert!(!matches!(outcome,Ok(Outcome::Ready(_))),"HRR 常量 MAC 被错误当成当前连接认证");assert!(origin.await.unwrap());
        }).await.expect("HRR 重放拒绝边界超时");
    }

    struct ProbeInner(Arc<AtomicUsize>);
    impl InboundProtocol for ProbeInner {
        fn credential_manifest(&self) -> CredentialManifest {
            CredentialManifest::new()
        }
        fn handle<'a>(
            &'a self,
            _stream: BoxStream,
            access: IngressBinding,
            context: InboundContext,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                let target = Destination::new("127.0.0.1", 9)?;
                access
                    .local(&context)?
                    .connect_tcp(&target, &ConnectContext::new(Duration::from_secs(1)))
                    .await?;
                Ok(())
            })
        }
    }
    struct ProbeAccess(Arc<AtomicUsize>);
    impl Outbound for ProbeAccess {
        fn capabilities(&self) -> kerlico_core::Capabilities {
            kerlico_core::Capabilities {
                tcp: true,
                tcp_eof: true,
                udp: true,
            }
        }
        fn connect_tcp<'a>(
            &'a self,
            _target: &'a Destination,
            _context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<kerlico_core::OpenedTcp>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(kerlico_core::Error::Unsupported("测试访问探针不拨号"))
            })
        }
        fn connect_udp<'a>(
            &'a self,
            _target: &'a Destination,
            _context: &'a ConnectContext,
        ) -> BoxFuture<'a, Result<DatagramChannel>> {
            Box::pin(async { Err(kerlico_core::Error::Unsupported("测试不使用 UDP")) })
        }
    }
    struct Events;
    impl NodeObserver for Events {
        fn record(&self, _: NodeEvent) {}
    }
    #[tokio::test]
    async fn hrr_only_old_mac_never_invokes_inner_or_target_access() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let key = b"hrr-replay-test";
            let hello = crate::tls::signed_hello_for_replay_test(key);
            let (_, _, sid) = wire::hello(&hello, 1).unwrap();
            let mut retry = vec![2, 0, 0, 0, 3, 3];
            retry.extend_from_slice(&wire::HRR_RANDOM);
            retry.push(sid.len() as u8);
            retry.extend_from_slice(sid);
            retry.extend_from_slice(&[0x13, 1, 0, 0, 12, 0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 23]);
            let length = retry.len()-4;
            retry[1..4].copy_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let origin = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                wire::read(&mut stream).await.unwrap().unwrap();
                stream.write_all(&wire::frame(wire::HANDSHAKE, &retry)).await.unwrap();
                let _ = wire::read(&mut stream).await;
                let _ = stream.shutdown().await;
            });
            let settings: config::Server = config::parse(&json!({"version":3,"password":"hrr-replay-test","handshake":{"host":"127.0.0.1","port":port},"inner":{"type":"shadowsocks","options":{"method":"aes-128-gcm","password":"inner-test"}}})).unwrap();
            let keys = settings.validate().unwrap();
            let inner_calls = Arc::new(AtomicUsize::new(0));
            let access_calls = Arc::new(AtomicUsize::new(0));
            let node = crate::ShadowTlsNode { settings, keys, inner: Arc::new(ProbeInner(inner_calls.clone())) };
            let context = InboundContext {
                peer_lease: None,
    tasks: kerlico_core::NodeTasks::new(kerlico_core::NodeId::parse("test-node").unwrap(), kerlico_core::CancellationToken::new()),
                peer_addr: None, local_addr: None, cancel: CancellationToken::new(),
                connect_timeout: Duration::from_secs(2), idle_timeout: Duration::from_secs(2),
                drain_timeout: Duration::from_millis(100), max_datagram_size: 65535, max_streams: 1,
                stream_budget: StreamBudget::new(Arc::new(tokio::sync::Semaphore::new(1)), Arc::new(tokio::sync::Semaphore::new(1))),
                events: Arc::new(Events),
            };
            let input = kerlico_config::NodeBuildContext::local_for_test(json!({}));
            let access = kerlico_egress::testing::ingress(&input, Arc::new(ProbeAccess(access_calls.clone())), kerlico_core::TargetPolicy::Remote).unwrap();
            let (raw, mut client) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move { node.handle(Box::new(raw), access, context).await });
            client.write_all(&hello).await.unwrap();
            let retry = wire::read(&mut client).await.unwrap().unwrap();
            assert_eq!(wire::server_hello(&retry).unwrap().0, wire::HRR_RANDOM);
            let mut old = wire::directional(key, &wire::HRR_RANDOM, b'C');
            let mut body = wire::tag(&mut old, b"recorded-data", true).to_vec();
            body.extend_from_slice(b"recorded-data");
            client.write_all(&wire::frame(wire::APP, &body)).await.unwrap();
            assert!(task.await.unwrap().is_err());
            origin.await.unwrap();
            assert_eq!(inner_calls.load(Ordering::SeqCst), 0, "HRR 旧 MAC 不得移交内层");
            assert_eq!(access_calls.load(Ordering::SeqCst), 0, "HRR 旧 MAC 不得调用目标访问服务");
        }).await.expect("HRR 拒绝路径与目标访问隔离超时");
    }
}
