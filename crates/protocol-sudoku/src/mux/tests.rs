use super::*;
use kerlico_core::StreamBudget;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pair(
    maximum: usize,
    budget: Option<StreamBudget>,
) -> (Arc<Session>, Arc<Session>, CancellationToken) {
    let (a, b) = tokio::io::duplex(173);
    let cancel = CancellationToken::new();
    (
        Arc::new(Session::start(
            Box::new(a),
            &cancel,
            maximum,
            Duration::from_secs(30),
            None,
            false,
        )),
        Arc::new(Session::start(
            Box::new(b),
            &cancel,
            maximum,
            Duration::from_secs(30),
            budget,
            true,
        )),
        cancel,
    )
}
fn context() -> ConnectContext {
    ConnectContext::new(Duration::from_secs(5))
}

#[tokio::test]
async fn many_targets_share_one_carrier_keep_order_and_return_budget() {
    let global = Arc::new(Semaphore::new(8));
    let node = Arc::new(Semaphore::new(8));
    let (client, server, cancel) = pair(8, Some(StreamBudget::new(global.clone(), node.clone())));
    let serving = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let incoming = server.accept().await.unwrap();
            tasks.spawn(async move {
                let _lease = incoming.lease;
                let mut stream = incoming.stream;
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                assert_eq!(data.len(), 65537);
                assert_eq!(incoming.target.port(), 10000 + u16::from(data[0]));
                assert!(data.iter().all(|b| *b == data[0]));
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        server
    });
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..8u8 {
        let client = client.clone();
        tasks.spawn(async move {
            let target =
                Destination::new(&format!("target{index}.invalid"), 10000 + u16::from(index))
                    .unwrap();
            let context = context();
            let mut stream = client.open(&target, &context).await.unwrap();
            let data = vec![index; 65537];
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, data);
        });
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    let server = serving.await.unwrap();
    assert!(!client.is_closed());
    assert!(!server.is_closed());
    assert_eq!(global.available_permits(), 8);
    assert_eq!(node.available_permits(), 8);
    cancel.cancel();
}

#[tokio::test]
async fn slow_receive_queue_is_reset_without_blocking_another_stream() {
    let (client, server, cancel) = pair(4, None);
    let slow_context = context();
    let fast_context = context();
    let target = Destination::new("192.0.2.1", 80).unwrap();
    let mut slow = client.open(&target, &slow_context).await.unwrap();
    let held = server.accept().await.unwrap();
    let mut fast = client.open(&target, &fast_context).await.unwrap();
    let mut accepted = server.accept().await.unwrap().stream;
    let source = tokio::spawn(async move {
        let result = slow.write_all(&vec![0x5a; 5 * 1024 * 1024]).await;
        if result.is_ok() {
            let _ = slow.flush().await;
        }
        let mut byte = [0; 1];
        assert!(slow.read(&mut byte).await.is_err());
    });
    tokio::time::timeout(Duration::from_secs(10), source)
        .await
        .unwrap()
        .unwrap();
    assert!(!client.is_closed());
    assert!(!server.is_closed());
    assert_eq!(
        server.shared.receive_budget.available_permits(),
        8 * 1024 * 1024
    );
    fast.write_all(b"still-active").await.unwrap();
    fast.flush().await.unwrap();
    let mut payload = [0; 12];
    accepted.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"still-active");
    accepted.write_all(b"reply").await.unwrap();
    accepted.flush().await.unwrap();
    let mut reply = [0; 5];
    fast.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");
    drop(held);
    cancel.cancel();
}

#[tokio::test]
async fn logical_cancellation_and_session_close_have_distinct_scopes() {
    let (client, server, cancel) = pair(4, None);
    let a_context = context();
    let b_context = context();
    let target = Destination::new("::1", 443).unwrap();
    let mut a = client.open(&target, &a_context).await.unwrap();
    let mut server_a = server.accept().await.unwrap().stream;
    let mut b = client.open(&target, &b_context).await.unwrap();
    let mut server_b = server.accept().await.unwrap().stream;
    a_context.cancel.cancel();
    assert!(a.read(&mut [0; 1]).await.is_err());
    drop(a);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server_a.read(&mut [0; 1]))
            .await
            .unwrap()
            .is_err()
    );
    b.write_all(b"safe").await.unwrap();
    b.flush().await.unwrap();
    let mut value = [0; 4];
    server_b.read_exact(&mut value).await.unwrap();
    assert_eq!(&value, b"safe");
    assert!(!client.is_closed());
    client.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), b.read(&mut [0; 1]))
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server_b.read(&mut [0; 1]))
            .await
            .unwrap()
            .is_err()
    );
    cancel.cancel();
}

#[tokio::test]
async fn rejects_bad_frames_refuses_identifier_wrap_and_reaps_idle_carrier() {
    let (client, _server, cancel) = pair(1, None);
    client.shared.next.store(u32::MAX, Ordering::Relaxed);
    assert!(matches!(
        client
            .open(&Destination::new("192.0.2.1", 80).unwrap(), &context())
            .await,
        Err(Error::ResourceLimit)
    ));
    cancel.cancel();
    for header in [
        [9, 0, 0, 0, 1, 0, 0, 0, 0],
        [OPEN, 0, 0, 0, 0, 0, 0, 0, 0],
        [PING, 0, 0, 0, 1, 0, 0, 0, 0],
        [DATA, 0, 0, 0, 1, 0, 4, 0, 1],
    ] {
        let (a, mut b) = tokio::io::duplex(32);
        let cancel = CancellationToken::new();
        let session = Session::start(Box::new(a), &cancel, 1, Duration::from_secs(3), None, true);
        b.write_all(&header).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !session.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(session.is_closed());
    }
    let (a, mut b) = tokio::io::duplex(32);
    let cancel = CancellationToken::new();
    let session = Session::start(
        Box::new(a),
        &cancel,
        1,
        Duration::from_millis(40),
        None,
        false,
    );
    let mut byte = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), b.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(session.is_closed());
}

#[tokio::test]
async fn remote_fin_data_survives_physical_carrier_eof() {
    let (a, mut b) = tokio::io::duplex(256);
    let parent = CancellationToken::new();
    let session = Session::start(Box::new(a), &parent, 2, Duration::from_secs(5), None, true);
    let target = crate::wire::address::encode(&Destination::new("192.0.2.1", 80).unwrap());
    let peer = tokio::spawn(async move {
        for (kind, payload) in [
            (OPEN, target),
            (DATA, b"tail-before-fin".to_vec()),
            (FIN, Vec::new()),
        ] {
            let mut head = [0; 9];
            head[0] = kind;
            head[1..5].copy_from_slice(&1u32.to_be_bytes());
            head[5..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            b.write_all(&head).await.unwrap();
            b.write_all(&payload).await.unwrap();
        }
    });
    let mut incoming = session.accept().await.unwrap().stream;
    peer.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !session.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut bytes = Vec::new();
    incoming.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"tail-before-fin");
}

struct BackpressuredCarrier {
    inner: tokio::io::DuplexStream,
    pending_writes: Arc<std::sync::atomic::AtomicUsize>,
}
impl tokio::io::AsyncRead for BackpressuredCarrier {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, data)
    }
}
impl tokio::io::AsyncWrite for BackpressuredCarrier {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, data);
        if result.is_pending() {
            this.pending_writes.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn record_obfs_layers_keep_both_directions_live_under_real_write_backpressure() {
    use crate::codec::{
        layout::Mode,
        obfs::ObfsStream,
        record::{Method, RecordStream},
        table::{GridOrder, Pair},
    };
    use std::sync::atomic::AtomicUsize;
    let order = Arc::new(GridOrder::new("synthetic-layered-mux-wakeup"));
    let pair = Pair::new(
        "synthetic-layered-mux-wakeup",
        Mode::parse("prefer_entropy").unwrap(),
        "",
        order,
    ).unwrap();
    for packed_downlink in [false, true] {
        let (client_io, server_io) = tokio::io::duplex(97);
        let client_pending = Arc::new(AtomicUsize::new(0));
        let server_pending = Arc::new(AtomicUsize::new(0));
        let client_obfs = ObfsStream::new(
            Box::new(BackpressuredCarrier { inner: client_io, pending_writes: client_pending.clone() }),
            pair.down.clone(), pair.up.clone(), packed_downlink, false, 0, 0,
        ).unwrap();
        let server_obfs = ObfsStream::new(
            Box::new(BackpressuredCarrier { inner: server_io, pending_writes: server_pending.clone() }),
            pair.up.clone(), pair.down.clone(), false, packed_downlink, 0, 0,
        ).unwrap();
        let client_record = RecordStream::new(client_obfs, Method::ChaCha, [0x11;32], [0x22;32]).unwrap();
        let server_record = RecordStream::new(server_obfs, Method::ChaCha, [0x22;32], [0x11;32]).unwrap();
        let cancel = CancellationToken::new();
        let client = Arc::new(Session::start(Box::new(client_record), &cancel, 8, Duration::from_secs(30), None, false));
        let server = Arc::new(Session::start(Box::new(server_record), &cancel, 8, Duration::from_secs(30), None, true));
        let serving = tokio::spawn(async move {
            let mut jobs = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let incoming = server.accept().await.unwrap();
                jobs.spawn(async move {
                    let mut stream = incoming.stream;
                    stream.write_all(b"ready").await.unwrap();
                    stream.flush().await.unwrap();
                    let mut piece = [0;8192];
                    loop {
                        let count = stream.read(&mut piece).await.unwrap();
                        if count == 0 { break; }
                        stream.write_all(&piece[..count]).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                    stream.write_all(b"tail").await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
            while let Some(result) = jobs.join_next().await { result.unwrap(); }
            server
        });
        let running = async {
            let mut jobs = tokio::task::JoinSet::new();
            for index in 0..4u8 {
                let client = client.clone();
                jobs.spawn(async move {
                    let target = Destination::new("192.0.2.1", 10000+u16::from(index)).unwrap();
                    let mut stream = client.open(&target, &context()).await.unwrap();
                    let mut banner = [0;5]; stream.read_exact(&mut banner).await.unwrap(); assert_eq!(&banner,b"ready");
                    let bytes = vec![index;65536+usize::from(index)];
                    let (mut read,mut write) = tokio::io::split(stream);
                    let sending = async { write.write_all(&bytes).await.unwrap(); write.flush().await.unwrap(); write.shutdown().await.unwrap(); };
                    let receiving = async { let mut received=Vec::new(); read.read_to_end(&mut received).await.unwrap(); let mut expected=bytes.clone(); expected.extend_from_slice(b"tail"); assert_eq!(received,expected); };
                    tokio::join!(sending,receiving);
                });
            }
            while let Some(result) = jobs.join_next().await { result.unwrap(); }
            serving.await.unwrap()
        };
        let server = tokio::time::timeout(Duration::from_secs(8),running).await.expect("真实Record+Obfs双向背压不得遗失唤醒");
        assert!(client_pending.load(Ordering::SeqCst)>0);
        assert!(server_pending.load(Ordering::SeqCst)>0);
        assert!(!client.is_closed()); assert!(!server.is_closed());
        cancel.cancel();
    }
}

#[cfg(test)]
mod relay_diagnostics {
    use crate::{
        codec::{layout::Mode,obfs::ObfsStream,record::{Method,RecordStream},table::{GridOrder,Pair}},
        mux::{LogicalStream,Session},
    };
    use kerlico_core::{BoxStream,CancellationToken,ConnectContext,Destination};
    use std::{collections::BTreeMap,sync::{Arc,Mutex,atomic::{AtomicUsize,Ordering}},time::Duration};
    use tokio::{io::{AsyncReadExt,AsyncWriteExt},sync::Notify,task::JoinHandle,time::{Instant,timeout}};

    const LIMIT:Duration=Duration::from_secs(8);
    #[derive(Default)]
    struct Target {
        stream_id:AtomicUsize,
        read:AtomicUsize,
        eof:AtomicUsize,
        tail:AtomicUsize,
        shutdown:AtomicUsize,
    }
    impl Target {
        fn snapshot(&self)->[usize;5] {
            [&self.stream_id,&self.read,&self.eof,&self.tail,&self.shutdown].map(|n|n.load(Ordering::SeqCst))
        }
    }
    #[derive(Default)]
    struct Progress {
        targets:Mutex<BTreeMap<u16,Arc<Target>>>,
        client_read:Mutex<BTreeMap<u16,Arc<AtomicUsize>>>,
        client_send:Mutex<BTreeMap<u16,Arc<AtomicUsize>>>,
        release_slow:Notify,
        trace:Mutex<Vec<String>>,
    }
    fn session_state(session:&Session)->Vec<(u32,usize,bool,bool,bool)> {
        session.shared.states.lock().unwrap().iter().map(|(&id,state)| {
            let receive=state.receive.lock().unwrap();
            (id,receive.bytes,receive.remote_fin,receive.local_fin,receive.reset)
        }).collect()
    }
    impl Progress {
        fn snapshot(&self,client:&Session,server:&Session)->String {
            let targets:Vec<_>=self.targets.lock().unwrap().iter().map(|(&port,target)|(port,target.snapshot())).collect();
            let read:Vec<_>=self.client_read.lock().unwrap().iter().map(|(&port,count)|(port,count.load(Ordering::SeqCst))).collect();
            let send:Vec<_>=self.client_send.lock().unwrap().iter().map(|(&port,stage)|(port,stage.load(Ordering::SeqCst))).collect();
            format!("target(port:[id,read,eof,tail,shutdown])={targets:?} client_read={read:?} client_send={send:?} client_fifo_free={} server_fifo_free={} client(id,queued,remote_fin,local_fin,reset)={:?} server={:?}",client.shared.data.capacity(),server.shared.data.capacity(),session_state(client),session_state(server))
        }
    }
    struct Sampler(JoinHandle<()>);
    impl Drop for Sampler {fn drop(&mut self){self.0.abort();}}
    struct Fixture {
        client:Arc<Session>,server:Arc<Session>,cancel:CancellationToken,
        progress:Arc<Progress>,controller:Option<JoinHandle<()>>,
    }
    impl Drop for Fixture {
        fn drop(&mut self){self.cancel.cancel();if let Some(task)=self.controller.take(){task.abort();}}
    }
    impl Fixture {
        fn new(layered:bool)->Self {
            let (a,b)=tokio::io::duplex(128*1024);
            let (a,b):(BoxStream,BoxStream)=if layered {
                let order=Arc::new(GridOrder::new("synthetic-core-relay-original-load"));
                let pair=Pair::new("synthetic-core-relay-original-load",Mode::parse("prefer_entropy").unwrap(),"",order).unwrap();
                let client=ObfsStream::new(Box::new(a),pair.down.clone(),pair.up.clone(),false,false,0,0).unwrap();
                let server=ObfsStream::new(Box::new(b),pair.up.clone(),pair.down.clone(),false,false,0,0).unwrap();
                (Box::new(RecordStream::new(client,Method::ChaCha,[1;32],[2;32]).unwrap()),Box::new(RecordStream::new(server,Method::ChaCha,[2;32],[1;32]).unwrap()))
            }else{(Box::new(a),Box::new(b))};
            let cancel=CancellationToken::new();
            let client=Arc::new(Session::start(a,&cancel,32,Duration::from_secs(30),None,false));
            let server=Arc::new(Session::start(b,&cancel,32,Duration::from_secs(30),None,true));
            let progress=Arc::new(Progress::default());
            let observed=progress.clone();let accepting=server.clone();let stopped=cancel.clone();
            let controller=tokio::spawn(async move {
                let mut jobs=tokio::task::JoinSet::new();
                loop {
                    let incoming=tokio::select!{biased;_=stopped.cancelled()=>break,incoming=accepting.accept()=>match incoming{Ok(value)=>value,Err(_)=>break}};
                    let port=incoming.target.port();
                    let target=observed.targets.lock().unwrap().entry(port).or_default().clone();
                    let stream_id=accepting.shared.states.lock().unwrap().iter().find_map(|(&id,state)|Arc::ptr_eq(state,&incoming.stream.state).then_some(id)).unwrap_or(0);
                    target.stream_id.store(stream_id as usize,Ordering::SeqCst);
                    let (destination,mut echo)=tokio::io::duplex(128*1024);
                    let cancel=incoming.stream.cancel_token();let echo_stop=cancel.child_token();let release=observed.clone();
                    jobs.spawn(async move {
                        let work=async {
                            echo.write_all(b"ready").await?;
                            if port==9{release.release_slow.notified().await;}
                            let mut bytes=[0;32768];
                            loop {
                                let count=echo.read(&mut bytes).await?;
                                if count==0{
                                    target.eof.fetch_add(1,Ordering::SeqCst);
                                    echo.write_all(b"tail").await?;target.tail.fetch_add(1,Ordering::SeqCst);
                                    echo.shutdown().await?;target.shutdown.fetch_add(1,Ordering::SeqCst);
                                    return Ok::<(),std::io::Error>(());
                                }
                                target.read.fetch_add(count,Ordering::SeqCst);
                                echo.write_all(&bytes[..count]).await?;
                            }
                        };
                        tokio::select!{biased;_=echo_stop.cancelled()=>{},_=work=>{}}
                    });
                    jobs.spawn(async move {
                        let _lease=incoming.lease;
                        let _=kerlico_core::relay_tcp(Box::new(incoming.stream),Box::new(destination),Duration::from_secs(15),cancel).await;
                    });
                    while jobs.try_join_next().is_some(){}
                }
                jobs.abort_all();while jobs.join_next().await.is_some(){}
            });
            Self{client,server,cancel,progress,controller:Some(controller)}
        }
        async fn open(&self,target:&Destination,context:&ConnectContext)->LogicalStream {
            let mut stream=self.client.open(target,context).await.unwrap();
            let mut banner=[0;5];timeout(LIMIT,stream.read_exact(&mut banner)).await.unwrap().unwrap();assert_eq!(&banner,b"ready");stream
        }
        fn sampler(&self)->Sampler {
            let client=self.client.clone();let server=self.server.clone();let progress=self.progress.clone();
            Sampler(tokio::spawn(async move {
                let start=Instant::now();let mut ticks=tokio::time::interval(Duration::from_secs(1));
                for _ in 0..9 {ticks.tick().await;let sample=format!("t={}ms {}",start.elapsed().as_millis(),progress.snapshot(&client,&server));progress.trace.lock().unwrap().push(sample);}
            }))
        }
        async fn close(mut self) {
            self.cancel.cancel();timeout(LIMIT,self.controller.take().unwrap()).await.unwrap().unwrap();
        }
    }
    async fn exchange(client:Arc<Session>,server:Arc<Session>,progress:Arc<Progress>,target:Destination,bytes:Vec<u8>,label:&str) {
        let mut stream=client.open(&target,&ConnectContext::new(LIMIT)).await.unwrap();let mut banner=[0;5];timeout(LIMIT,stream.read_exact(&mut banner)).await.unwrap().unwrap();assert_eq!(&banner,b"ready");
        let sent=Arc::new(AtomicUsize::new(0));let received=Arc::new(AtomicUsize::new(0));
        progress.client_read.lock().unwrap().insert(target.port(),received.clone());progress.client_send.lock().unwrap().insert(target.port(),sent.clone());
        let(mut read,mut write)=tokio::io::split(stream);
        let sending=async{write.write_all(&bytes).await.unwrap();sent.store(1,Ordering::SeqCst);write.flush().await.unwrap();sent.store(2,Ordering::SeqCst);write.shutdown().await.unwrap();sent.store(3,Ordering::SeqCst);};
        let receiving=async {
            let mut all=vec![0;bytes.len()];let mut used=0;
            while used<all.len(){let count=read.read(&mut all[used..]).await.unwrap();assert!(count!=0,"受控relay提前EOF: {label} target={target} received={used}");used+=count;received.store(used,Ordering::SeqCst);}
            assert_eq!(all,bytes);let mut tail=Vec::new();read.read_to_end(&mut tail).await.unwrap();assert_eq!(tail,b"tail");
        };
        let result=timeout(LIMIT,async{tokio::join!(sending,receiving);}).await;
        assert!(result.is_ok(),"受控relay超时: {label} target={target} {} trace={:?}",progress.snapshot(&client,&server),progress.trace.lock().unwrap());
    }
    async fn sixteen(layered:bool) {
        let fixture=Fixture::new(layered);let sampler=fixture.sampler();
        let context=ConnectContext::new(LIMIT);let mut held=fixture.open(&Destination::new("127.0.0.1",10000).unwrap(),&context).await;
        let mut jobs=tokio::task::JoinSet::new();
        for index in 0..16u16 {
            let client=fixture.client.clone();let server=fixture.server.clone();let progress=fixture.progress.clone();
            jobs.spawn(async move {let target=Destination::new(if index%2==0{"127.0.0.1"}else{"::1"},10001+index).unwrap();exchange(client,server,progress,target,vec![index as u8;65536+usize::from(index)],if layered{"record-obfs/16"}else{"plain/16"}).await;});
        }
        while let Some(result)=jobs.join_next().await{result.unwrap();}
        let mut tail=Vec::new();timeout(LIMIT,async{held.shutdown().await.unwrap();held.read_to_end(&mut tail).await.unwrap();}).await.unwrap();assert_eq!(tail,b"tail");drop(held);drop(sampler);fixture.close().await;
    }
    async fn slow(layered:bool) {
        let fixture=Fixture::new(layered);let sampler=fixture.sampler();let slow_context=ConnectContext::new(LIMIT);let mut slow=fixture.open(&Destination::new("127.0.0.1",9).unwrap(),&slow_context).await;
        let filling=tokio::spawn(async move{let result=slow.write_all(&vec![0x33;6*1024*1024]).await;(slow,result)});
        exchange(fixture.client.clone(),fixture.server.clone(),fixture.progress.clone(),Destination::new("127.0.0.1",443).unwrap(),vec![0x91;16384],if layered{"record-obfs/slow-active"}else{"plain/slow-active"}).await;
        slow_context.cancel.cancel();let(stream,_)=timeout(LIMIT,filling).await.unwrap().unwrap();drop(stream);
        exchange(fixture.client.clone(),fixture.server.clone(),fixture.progress.clone(),Destination::new("::1",8443).unwrap(),vec![0x62;16384],if layered{"record-obfs/slow-cancelled"}else{"plain/slow-cancelled"}).await;
        drop(sampler);fixture.close().await;
    }
    #[tokio::test]
    async fn core_relay_sixteen_streams_plain_original_load(){sixteen(false).await;}
    #[tokio::test]
    async fn core_relay_sixteen_streams_record_obfs_original_load(){sixteen(true).await;}
    #[tokio::test]
    async fn core_relay_slow_stream_plain_original_load(){slow(false).await;}
    #[tokio::test]
    async fn core_relay_slow_stream_record_obfs_original_load(){slow(true).await;}
}
