use super::frame::{self, Frame};
use crate::carrier;
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, DatagramChannel, DatagramReceiver, DatagramSender,
    Destination, Error, Result,
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::AbortHandle,
    time::Instant,
};
use xray_proxy::mux::{MAX_PAYLOAD, Status};

struct Message {
    frame: Frame,
    ack: Option<oneshot::Sender<()>>,
}
struct ReceiverEntry {
    sender: mpsc::Sender<Frame>,
    failed: Arc<AtomicBool>,
    cancel: CancellationToken,
    ended: bool,
}
struct Connection {
    output: mpsc::Sender<Message>,
    sessions: Mutex<HashMap<u16, ReceiverEntry>>,
    slots: Arc<Semaphore>,
    capacity: usize,
    next: AtomicU32,
    accepting: AtomicBool,
    closed: AtomicBool,
    cancel: CancellationToken,
    activity: Mutex<Instant>,
    tasks: Mutex<Vec<AbortHandle>>,
    connection_permit: Mutex<Option<OwnedSemaphorePermit>>,
}
impl Connection {
    fn touch(&self) {
        if let Ok(mut time) = self.activity.lock() {
            *time = Instant::now();
        }
    }
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.accepting.store(false, Ordering::Release);
        self.cancel.cancel();
        if let Ok(mut sessions) = self.sessions.lock() {
            for session in sessions.values() {
                if !session.ended {
                    session.failed.store(true, Ordering::Release);
                }
            }
            sessions.clear();
        }
        if let Ok(mut permit) = self.connection_permit.lock() {
            permit.take();
        }
    }
    fn create(stream: BoxStream, capacity: usize, permit: OwnedSemaphorePermit) -> Arc<Self> {
        let (output, mut outgoing) = mpsc::channel::<Message>(32);
        let cancel = CancellationToken::new();
        let value = Arc::new(Self {
            output,
            sessions: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(capacity)),
            capacity,
            next: AtomicU32::new(1),
            accepting: AtomicBool::new(true),
            closed: AtomicBool::new(false),
            cancel: cancel.clone(),
            activity: Mutex::new(Instant::now()),
            tasks: Mutex::new(Vec::new()),
            connection_permit: Mutex::new(Some(permit)),
        });
        let (mut reader, mut writer) = tokio::io::split(stream);
        let weak = Arc::downgrade(&value);
        let stop = cancel.clone();
        let writing = tokio::spawn(async move {
            loop {
                let message = tokio::select! {_=stop.cancelled()=>break,message=outgoing.recv()=>match message{Some(v)=>v,None=>break}};
                let ending=message.frame.status==Status::End;
                let result = tokio::select! {_=stop.cancelled()=>break,result=frame::write(&mut writer,message.frame)=>result};
                if let Err(error)=result {if !ending{eprintln!("VLESS Mux 载体写入失败：{error}");}break;}
                if let Some(ack) = message.ack {
                    let _ = ack.send(());
                }
                if let Some(value) = weak.upgrade() {
                    value.touch();
                } else {
                    break;
                }
            }
            if let Some(value) = weak.upgrade() {
                value.accepting.store(false,Ordering::Release);
            }
        });
        let weak = Arc::downgrade(&value);
        let stop = cancel.clone();
        let reading = tokio::spawn(async move {
            loop {
                let frame = tokio::select! {_=stop.cancelled()=>break,frame=frame::read(&mut reader)=>match frame{Ok(Some(v))=>v,Ok(None)=>break,Err(error)=>{eprintln!("VLESS Mux 载体读取失败：{error}");break}}};
                let Some(value) = weak.upgrade() else { break };
                value.touch();
                if frame.status == Status::KeepAlive {
                    continue;
                }
                let id = frame.id;
                let entry={let mut sessions=match value.sessions.lock(){Ok(v)=>v,Err(_)=>break};sessions.get_mut(&id).map(|entry|{if frame.error{entry.failed.store(true,Ordering::Release);}entry.ended=frame.status==Status::End;(entry.sender.clone(),entry.failed.clone(),entry.cancel.clone())})};
                if let Some((sender,failed,cancel))=entry {
                    let delivered=tokio::select! {_=stop.cancelled()=>break,_=cancel.cancelled()=>false,result=sender.send(frame)=>result.is_ok()};
                    if delivered{continue;}failed.store(true,Ordering::Release);cancel.cancel();
                }
                if let Ok(mut sessions)=value.sessions.lock(){sessions.remove(&id);}
                let _ = value.output.try_send(Message {
                    frame: Frame::end(id, true),
                    ack: None,
                });
            }
            if let Some(value) = weak.upgrade() {
                value.close();
            }
        });
        let weak = Arc::downgrade(&value);
        let stop = cancel;
        let idle = tokio::spawn(async move {
            loop {
                tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(5))=>{}}
                let Some(value) = weak.upgrade() else { break };
                let should_close = {
                    let Ok(_sessions) = value.sessions.lock() else {
                        break;
                    };
                    let expired = value
                        .activity
                        .lock()
                        .map(|t| t.elapsed() > Duration::from_secs(30))
                        .unwrap_or(true);
                    let idle = expired && value.slots.available_permits() == value.capacity;
                    if idle {
                        value.accepting.store(false, Ordering::Release);
                    }
                    idle
                };
                if should_close {
                    value.close();
                    break;
                }
            }
        });
        if let Ok(mut tasks) = value.tasks.lock() {
            tasks.extend([
                writing.abort_handle(),
                reading.abort_handle(),
                idle.abort_handle(),
            ]);
        }
        value
    }
    fn reserve(self: &Arc<Self>) -> Option<(u16, OwnedSemaphorePermit)> {
        let _sessions = self.sessions.lock().ok()?;
        if !self.accepting.load(Ordering::Acquire) {
            return None;
        }
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        let id = self.next.fetch_add(1, Ordering::AcqRel);
        if id > u16::MAX as u32 {
            self.accepting.store(false, Ordering::Release);
            return None;
        }
        if id == u16::MAX as u32 {
            self.accepting.store(false, Ordering::Release);
        }
        Some((id as u16, permit))
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(tasks) = self.tasks.get_mut() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

struct Lease {
    connection: Arc<Connection>,
    id: u16,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
    failed: Arc<AtomicBool>,
    cancel: CancellationToken,
    ended: AtomicBool,
}
impl Lease {
    fn finish(&self) {
        if self.ended.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancel.cancel();
        if let Ok(mut sessions) = self.connection.sessions.lock() {
            sessions.remove(&self.id);
        }
        if let Ok(mut permit) = self.permit.lock() {
            permit.take();
        }
        let _ = self.connection.output.try_send(Message {
            frame: Frame::end(self.id, false),
            ack: None,
        });
        if !self.connection.accepting.load(Ordering::Acquire)
            && self.connection.slots.available_permits() == self.connection.capacity
        {
            self.connection.close();
        }
    }
    async fn send(&self, frame: Frame) -> Result<()> {
        if self.ended.load(Ordering::Acquire) || self.connection.closed.load(Ordering::Acquire) {
            return Err(Error::Protocol("Mux 会话已结束"));
        }
        tokio::select! {_=self.cancel.cancelled()=>Err(Error::Cancelled),result=self.connection.output.send(Message {frame,ack:None})=>result.map_err(|_|Error::Protocol("Mux 载体已结束"))}
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.finish();
    }
}

type Reservation=(Arc<Connection>,u16,OwnedSemaphorePermit);
pub(crate) struct Pool {
    creating:tokio::sync::Mutex<()>,
    connections: Mutex<Vec<Arc<Connection>>>,
    slots: Arc<Semaphore>,
    concurrency: usize,
}
impl Pool {
    pub fn new(concurrency: usize, max_connections: usize) -> Self {
        Self {
            creating:tokio::sync::Mutex::new(()),
            connections: Mutex::new(Vec::new()),
            slots: Arc::new(Semaphore::new(max_connections)),
            concurrency,
        }
    }
    fn reusable(&self)->Result<Option<Reservation>> {
        let mut connections=self.connections.lock().map_err(|_|Error::Protocol("Mux 连接池不可用"))?;
        connections.retain(|connection|!connection.closed.load(Ordering::Acquire));
        for connection in connections.iter(){if let Some((id,permit))=connection.reserve(){return Ok(Some((connection.clone(),id,permit)));}}
        Ok(None)
    }
    async fn acquire<F: Future<Output = Result<BoxStream>> + Send>(
        &self,
        open: F,
    ) -> Result<Reservation> {
        if let Some(reserved)=self.reusable()?{return Ok(reserved);}
        let _creating=self.creating.lock().await;
        if let Some(reserved)=self.reusable()?{return Ok(reserved);}
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let connection = Connection::create(open.await?, self.concurrency, permit);
        let (id, permit) = connection.reserve().ok_or(Error::ResourceLimit)?;
        self.connections
            .lock()
            .map_err(|_| Error::Protocol("Mux 连接池不可用"))?
            .push(connection.clone());
        Ok((connection, id, permit))
    }
    async fn session<F: Future<Output = Result<BoxStream>> + Send>(
        &self,
        target: &Destination,
        udp: bool,
        xudp: bool,
        open: F,
    ) -> Result<(Arc<Lease>, mpsc::Receiver<Frame>,Option<Frame>)> {
        let (connection, id, permit) = self.acquire(open).await?;
        let (sender, receiver) = mpsc::channel(32);
        let failed = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let lease = Arc::new(Lease {
            connection: connection.clone(),
            id,
            permit: Mutex::new(Some(permit)),
            failed: failed.clone(),
            cancel: cancel.clone(),
            ended: AtomicBool::new(false),
        });
        {
            let mut sessions = connection
                .sessions
                .lock()
                .map_err(|_| Error::Protocol("Mux 会话表不可用"))?;
            if connection.closed.load(Ordering::Acquire) {
                return Err(Error::Protocol("Mux 载体已结束"));
            }
            sessions.insert(
                id,
                ReceiverEntry {
                    sender,
                    failed,
                    cancel,
                    ended: false,
                },
            );
        }
        let first=Frame {id,status:Status::New,error:false,target:Some(carrier::target(target,udp)),global_id:(udp&&xudp).then(rand::random),payload:None};
        // Xray 的非零 global ID 分支会直接读取首包；不能先发送没有数据的 NEW。
        if udp&&xudp{return Ok((lease,receiver,Some(first)));}
        let (ack,ready)=oneshot::channel();
        connection.output.send(Message {frame:first,ack:Some(ack)}).await.map_err(|_|Error::Protocol("Mux 建立失败"))?;

        ready
            .await
            .map_err(|_| Error::Protocol("Mux 载体写入失败"))?;
        Ok((lease, receiver,None))
    }
    pub async fn tcp<F: Future<Output = Result<BoxStream>> + Send>(
        &self,
        target: &Destination,
        open: F,
    ) -> Result<BoxStream> {
        let (lease, mut incoming,_) = self.session(target, false, false, open).await?;
        let (local, peer) = tokio::io::duplex(32 * 1024);
        let held = lease.clone();
        let task = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(peer);
            let uplink = async {
                let mut bytes = vec![0; MAX_PAYLOAD];
                loop {
                    let count = reader.read(&mut bytes).await?;
                    if count == 0 {
                        return Ok::<_, Error>(());
                    }
                    held.send(Frame::data(held.id, bytes[..count].to_vec(), None))
                        .await?;
                }
            };
            let downlink = async {
                while let Some(frame) = incoming.recv().await {
                    if frame.error {
                        return Err(Error::Protocol("Mux 对端拒绝会话"));
                    }
                    if let Some(bytes) = frame.payload {
                        writer.write_all(&bytes).await?;
                    }
                    if frame.status == Status::End {
                        return Ok::<_, Error>(());
                    }
                }
                Ok(())
            };
            tokio::pin!(uplink,downlink);
            let result=tokio::select! {_=held.cancel.cancelled()=>Ok(()),r=&mut downlink=>r,r=&mut uplink=>{if r.is_err(){held.failed.store(true,Ordering::Release);}tokio::select! {_=held.cancel.cancelled()=>Ok(()),r=&mut downlink=>r}}};
            if result.is_err() {
                held.failed.store(true, Ordering::Release);
            }
            held.finish();
        });
        Ok(Box::new(Tcp {
            io: local,
            lease,
            task: task.abort_handle(),
            write_closed: false,
        }))
    }
    pub async fn udp<F: Future<Output = Result<BoxStream>> + Send>(
        &self,
        target: &Destination,
        xudp: bool,
        open: F,
    ) -> Result<DatagramChannel> {
        let (lease, incoming,first) = self.session(target, true, xudp, open).await?;
        Ok(DatagramChannel {
            sender: Box::new(Sender {
                lease: lease.clone(),first,target:target.clone(),
            }),
            receiver: Box::new(Receiver { lease, incoming }),
        })
    }
}

struct Tcp {
    io: DuplexStream,
    lease: Arc<Lease>,
    task: AbortHandle,
    write_closed: bool,
}
impl Drop for Tcp {
    fn drop(&mut self) {
        self.lease.finish();
        self.task.abort();
    }
}
impl AsyncRead for Tcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = out.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, out);
        if matches!(result, Poll::Ready(Ok(())))
            && out.filled().len() == before
            && out.remaining() > 0
            && this.lease.failed.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Mux 会话失败",
            )));
        }
        result
    }
}
impl AsyncWrite for Tcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed || this.lease.failed.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Mux 写端已关闭",
            )));
        }
        Pin::new(&mut this.io).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write_closed = true;
        Pin::new(&mut this.io).poll_flush(cx)
    }
}
struct Sender {
    lease: Arc<Lease>,
    first:Option<Frame>,
    target:Destination,
}
impl DatagramSender for Sender {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if bytes.len() > MAX_PAYLOAD {
                return Err(Error::ResourceLimit);
            }
            let frame=if let Some(mut first)=self.first.take(){first.payload=Some(bytes.to_vec());first}else{Frame::data(self.lease.id,bytes.to_vec(),Some(carrier::target(&self.target,true)))};
            let guard=self.lease.cancel.clone().drop_guard();let result=self.lease.send(frame).await;if result.is_ok(){guard.disarm();}result
        })
    }
}
struct Receiver {
    lease: Arc<Lease>,
    incoming: mpsc::Receiver<Frame>,
}
impl DatagramReceiver for Receiver {
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        Box::pin(async move {
            loop {
                let frame = tokio::select! {_=self.lease.cancel.cancelled()=>{if self.lease.failed.load(Ordering::Acquire){return Err(Error::Protocol("Mux 数据报会话失败"));}return Ok(None);},v=self.incoming.recv()=>match v{Some(v)=>v,None=>{if self.lease.failed.load(Ordering::Acquire){return Err(Error::Protocol("Mux 载体中断"));}return Ok(None)}}};
                if frame.error {
                    self.lease.failed.store(true, Ordering::Release);
                    self.lease.finish();
                    return Err(Error::Protocol("Mux 对端拒绝数据报会话"));
                }
                if frame.status == Status::End {
                    self.lease.finish();
                    return Ok(None);
                }
                if let Some(bytes) = frame.payload {
                    return Ok(Some(bytes));
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn concurrent_first_streams_share_the_connection_being_created() {
        let pool=Arc::new(Pool::new(4,1));let barrier=Arc::new(tokio::sync::Barrier::new(4));let opened=Arc::new(std::sync::atomic::AtomicUsize::new(0));let mut tasks=tokio::task::JoinSet::new();
        for _ in 0..4 {let pool=pool.clone();let barrier=barrier.clone();let opened=opened.clone();tasks.spawn(async move {
            barrier.wait().await;let target=Destination::new("127.0.0.1",80).unwrap();
            let mut stream=pool.tcp(&target,async move {opened.fetch_add(1,Ordering::SeqCst);tokio::time::sleep(Duration::from_millis(30)).await;let (client,mut peer)=tokio::io::duplex(4096);tokio::spawn(async move {let mut served=0;while served<4 {let Some(request)=frame::read(&mut peer).await.unwrap() else{return};if request.status!=Status::New{continue;}served+=1;frame::write(&mut peer,Frame::data(request.id,vec![request.id as u8],None)).await.unwrap();frame::write(&mut peer,Frame::end(request.id,false)).await.unwrap();}});Ok(Box::new(client) as BoxStream)}).await.unwrap();
            let mut bytes=Vec::new();stream.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes.len(),1);bytes[0]
        });}
        let mut ids=Vec::new();while let Some(result)=tasks.join_next().await{ids.push(result.unwrap());}ids.sort_unstable();assert_eq!(ids,[1,2,3,4]);assert_eq!(opened.load(Ordering::SeqCst),1);
    }
    #[tokio::test]
    async fn xudp_new_waits_for_first_packet_and_carries_it_atomically() {
        let (client,mut peer)=tokio::io::duplex(4096);let (quiet,ready)=oneshot::channel();
        let target=Destination::new("127.0.0.1",53).unwrap();let reply=target.clone();
        let peer_task=tokio::spawn(async move {
            assert!(tokio::time::timeout(Duration::from_millis(20),frame::read(&mut peer)).await.is_err());
            quiet.send(()).unwrap();
            let first=frame::read(&mut peer).await.unwrap().unwrap();
            assert_eq!(first.status,Status::New);assert!(first.global_id.is_some());assert_eq!(first.payload.as_deref(),Some(b"first-packet".as_slice()));
            frame::write(&mut peer,Frame::data(first.id,b"reply".to_vec(),Some(carrier::target(&reply,true)))).await.unwrap();
            frame::write(&mut peer,Frame::end(first.id,false)).await.unwrap();
        });
        let pool=Pool::new(1,1);let mut channel=pool.udp(&target,true,async{Ok(Box::new(client) as BoxStream)}).await.unwrap();
        ready.await.unwrap();channel.sender.send(b"first-packet").await.unwrap();
        assert_eq!(channel.receiver.recv().await.unwrap(),Some(b"reply".to_vec()));
        assert!(channel.receiver.recv().await.unwrap().is_none());peer_task.await.unwrap();
    }
    #[tokio::test]
    async fn carrier_eof_delivers_complete_frames_before_reporting_reset(){
        let (client,mut peer)=tokio::io::duplex(4096);let expected=vec![19u8;128*1024];let payload=expected.clone();
        let sending=tokio::spawn(async move {let request=frame::read(&mut peer).await.unwrap().unwrap();for bytes in payload.chunks(1024){frame::write(&mut peer,Frame::data(request.id,bytes.to_vec(),None)).await.unwrap();}});
        let pool=Pool::new(1,1);let target=Destination::new("127.0.0.1",80).unwrap();let mut stream=pool.tcp(&target,async{Ok(Box::new(client) as BoxStream)}).await.unwrap();let mut output=Vec::new();let error=stream.read_to_end(&mut output).await.unwrap_err();assert_eq!(error.kind(),io::ErrorKind::ConnectionReset);assert_eq!(output,expected);sending.await.unwrap();
    }
    #[tokio::test]
    async fn slow_reader_drains_bounded_queue_and_end_without_losing_data() {
        let (client, mut peer)=tokio::io::duplex(4096);
        let payload:Vec<u8>=(0..256*1024).map(|index|(index%251) as u8).collect();
        let expected=payload.clone();
        let sending=tokio::spawn(async move {
            let request=frame::read(&mut peer).await.unwrap().unwrap();
            assert_eq!(request.status,Status::New);
            for bytes in payload.chunks(1024){frame::write(&mut peer,Frame::data(request.id,bytes.to_vec(),None)).await.unwrap();}
            frame::write(&mut peer,Frame::end(request.id,false)).await.unwrap();
        });
        let pool=Pool::new(1,1);
        let target=Destination::new("127.0.0.1",80).unwrap();
        let mut stream=pool.tcp(&target,async {Ok(Box::new(client) as BoxStream)}).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut received=Vec::new();
        tokio::time::timeout(Duration::from_secs(5),stream.read_to_end(&mut received)).await.unwrap().unwrap();
        assert_eq!(received,expected);
        sending.await.unwrap();
    }
}
