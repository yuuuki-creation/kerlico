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
                            return Ok(Outcome::Ready(stream::wrap(raw,initial,read,write,cancel)));
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
    use serde_json::json;
    use tokio::{net::TcpListener,io::AsyncWriteExt};
    #[tokio::test]
    async fn recorded_hrr_seed_mac_never_authorizes_a_new_carrier(){
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
            let (raw,mut client)=tokio::io::duplex(4096);let server=tokio::spawn(async move{negotiate(Box::new(raw),&settings,&keys,CancellationToken::new()).await});
            client.write_all(&hello).await.unwrap();let retry=wire::read(&mut client).await.unwrap().unwrap();assert_eq!(wire::server_hello(&retry).unwrap().0,wire::HRR_RANDOM);
            let mut old=wire::directional(key,&wire::HRR_RANDOM,b'C');let payload=b"recorded-data";let mut body=wire::tag(&mut old,payload,true).to_vec();body.extend_from_slice(payload);client.write_all(&wire::frame(wire::APP,&body)).await.unwrap();
            let outcome=server.await.unwrap();assert!(!matches!(outcome,Ok(Outcome::Ready(_))),"HRR 常量 MAC 被错误当成当前连接认证");assert!(origin.await.unwrap());
        }).await.expect("HRR 重放拒绝边界超时");
    }
}
