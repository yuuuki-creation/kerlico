use super::codec::Mode;
use crate::{config::Protocol, handshake::EarlyServer, key, scope::Scope};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use kerlico_core::{BoxStream, CancellationToken, Error, InboundContext, Result, StreamLease};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
};

enum Upload {
    Data {
        sequence: u64,
        bytes: Bytes,
        ack: oneshot::Sender<Result<()>>,
    },
    Fin(oneshot::Sender<Result<()>>),
}
pub(crate) struct Download {
    pub reader: ReadHalf<DuplexStream>,
    pub pending: Option<Bytes>,
    pub eof: bool,
}
pub(crate) struct Token {
    pub value: String,
    pub mode: Mode,
    pub cancel: CancellationToken,
    pub down: tokio::sync::Mutex<Download>,
    upload: mpsc::Sender<Upload>,
    pull: Mutex<Option<CancellationToken>>,
    touched: Mutex<Instant>,
    pub failed: AtomicBool,
    pub upload_requests: Arc<Semaphore>,
    _lease: StreamLease,
    _slot: OwnedSemaphorePermit,
}
impl Token {
    pub fn touch(&self) {
        *self.touched.lock().unwrap() = Instant::now();
    }
    pub fn begin_pull(&self) -> CancellationToken {
        let next = self.cancel.child_token();
        if let Some(old) = self.pull.lock().unwrap().replace(next.clone()) {
            old.cancel();
        }
        self.touch();
        next
    }
    pub async fn push(&self, sequence: u64, bytes: Bytes) -> Result<()> {
        let (ack, received) = oneshot::channel();
        tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Cancelled),result=self.upload.send(Upload::Data {sequence,bytes,ack})=>result.map_err(|_|Error::Cancelled)?};
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Cancelled),result=received=>result.map_err(|_|Error::Cancelled)?}
    }
    pub async fn fin(&self) -> Result<()> {
        let (ack, received) = oneshot::channel();
        tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Cancelled),result=self.upload.send(Upload::Fin(ack))=>result.map_err(|_|Error::Cancelled)?};
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Cancelled),result=received=>result.map_err(|_|Error::Cancelled)?}
    }
}
pub(crate) struct Backend {
    pub stream: BoxStream,
    pub early: Option<EarlyServer>,
    pub token: Arc<Token>,
}
pub(crate) struct Authorized {
    pub token: Arc<Token>,
    pub early_response: Option<Vec<u8>>,
}
pub(crate) struct Registry {
    pub protocol: Arc<Protocol>,
    pub scope: Arc<Scope>,
    pub context: InboundContext,
    entries: Mutex<HashMap<String, Arc<Token>>>,
    slots: Arc<Semaphore>,
    ttl: Duration,
    accepted: mpsc::Sender<Backend>,
    pub requests: Arc<Semaphore>,
}
impl Drop for Registry {
    fn drop(&mut self) {
        for token in self.entries.get_mut().unwrap().values() {
            token.cancel.cancel();
        }
    }
}
impl Registry {
    pub fn new(
        protocol: Arc<Protocol>,
        scope: Arc<Scope>,
        context: InboundContext,
        maximum: usize,
        ttl: Duration,
    ) -> (Arc<Self>, mpsc::Receiver<Backend>) {
        let (accepted, receiver) = mpsc::channel(maximum.min(128));
        let registry = Arc::new(Self {
            protocol,
            scope: scope.clone(),
            context,
            entries: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(maximum)),
            ttl,
            accepted,
            requests: Arc::new(Semaphore::new((maximum * 2).clamp(4, 128))),
        });
        let weak = Arc::downgrade(&registry);
        let cancel = scope.cancel.clone();
        scope.spawn(async move {
            let mut timer=tokio::time::interval(Duration::from_millis(100));loop {tokio::select!{biased;_=cancel.cancelled()=>break,_=timer.tick()=>{let Some(registry)=weak.upgrade()else{break;};registry.reap();}}}
        });
        (registry, receiver)
    }
    pub fn get(&self, value: &str, mode: Mode) -> Option<Arc<Token>> {
        self.entries
            .lock()
            .unwrap()
            .get(value)
            .filter(|entry| entry.mode == mode && !entry.cancel.is_cancelled())
            .cloned()
    }
    pub fn remove(&self, value: &str) {
        if let Some(token) = self.entries.lock().unwrap().remove(value) {
            token.cancel.cancel();
        }
    }
    pub fn shutdown(&self) {
        let tokens: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .drain()
            .map(|(_, v)| v)
            .collect();
        for token in tokens {
            token.cancel.cancel();
        }
    }
    fn reap(&self) {
        let expired: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, entry)| {
                entry.cancel.is_cancelled() || entry.touched.lock().unwrap().elapsed() >= self.ttl
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
    }
    pub fn authorize(self: &Arc<Self>, mode: Mode, early: Option<&[u8]>) -> Result<Authorized> {
        if self.scope.cancel.is_cancelled() || self.context.stream_budget.is_closed() {
            return Err(Error::ResourceLimit);
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let lease = self.context.stream_budget.try_acquire()?;
        let prepared = early
            .map(|bytes| EarlyServer::prepare(self.protocol.clone(), bytes))
            .transpose()?;
        let early_response = prepared.as_ref().map(|s| s.response.clone());
        let value = URL_SAFE_NO_PAD.encode(key::random::<16>()?);
        let (logical, transport) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(transport);
        let (upload, receiver) = mpsc::channel(4);
        let token = Arc::new(Token {
            value: value.clone(),
            mode,
            cancel: self.scope.cancel.child_token(),
            down: tokio::sync::Mutex::new(Download {
                reader,
                pending: None,
                eof: false,
            }),
            upload,
            pull: Mutex::new(None),
            touched: Mutex::new(Instant::now()),
            failed: AtomicBool::new(false),
            upload_requests: Arc::new(Semaphore::new(2)),
            _lease: lease,
            _slot: slot,
        });
        {
            let mut entries = self.entries.lock().unwrap();
            if entries.contains_key(&value) {
                return Err(Error::ResourceLimit);
            }
            entries.insert(value.clone(), token.clone());
        }
        let backend = Backend {
            stream: Box::new(logical),
            early: prepared,
            token: token.clone(),
        };
        if self.accepted.try_send(backend).is_err() {
            self.remove(&value);
            return Err(Error::ResourceLimit);
        }
        let weak = Arc::downgrade(self);
        let managed = token.clone();
        self.scope.spawn(async move {
            upload_loop(writer, managed, receiver, weak).await;
        });
        Ok(Authorized {
            token,
            early_response,
        })
    }
}

async fn upload_loop(
    mut writer: WriteHalf<DuplexStream>,
    token: Arc<Token>,
    mut receiver: mpsc::Receiver<Upload>,
    registry: Weak<Registry>,
) {
    let mut next = 1u64;
    let mut legacy = None;
    let mut last = None;
    let mut closed = false;
    loop {
        let request = tokio::select! {biased;_=token.cancel.cancelled()=>break,request=receiver.recv()=>request};
        let Some(request) = request else {
            break;
        };
        match request {
            Upload::Fin(ack) => {
                if closed {
                    let _ = ack.send(Ok(()));
                    continue;
                }
                let result = tokio::select! {biased;_=token.cancel.cancelled()=>Err(Error::Cancelled),result=tokio::time::timeout(Duration::from_secs(30),writer.shutdown())=>result.map_err(|_|Error::Timeout).and_then(|r|r.map_err(Error::Io))};
                if result.is_err() {
                    let _ = ack.send(result);
                    token.failed.store(true, Ordering::Release);
                    break;
                }
                closed = true;
                token.touch();
                let _ = ack.send(Ok(()));
            }
            Upload::Data {
                sequence,
                bytes,
                ack,
            } => {
                if closed {
                    let _ = ack.send(Err(Error::Protocol("HTTP上传方向已结束")));
                    continue;
                }
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                if let Some(is_legacy) = legacy
                    && is_legacy != (sequence == 0) {
                        let _ = ack.send(Err(Error::Protocol("HTTP上传序号模式不能混用")));
                        continue;
                }
                if sequence > 0 {
                    if sequence < next {
                        let same = last
                            .as_ref()
                            .is_some_and(|(seq, hash)| *seq == sequence && hash == &digest);
                        let _ = ack.send(if same {
                            Ok(())
                        } else {
                            Err(Error::Protocol("HTTP重复上传内容或序号不一致"))
                        });
                        continue;
                    }
                    if sequence != next || sequence == u64::MAX {
                        let _ = ack.send(Err(Error::Protocol("HTTP上传序号缺口")));
                        continue;
                    }
                }
                let result = tokio::select! {biased;_=token.cancel.cancelled()=>Err(Error::Cancelled),result=tokio::time::timeout(Duration::from_secs(30),async{writer.write_all(&bytes).await?;writer.flush().await})=>result.map_err(|_|Error::Timeout).and_then(|r:std::io::Result<()>|r.map_err(Error::Io))};
                if result.is_err() {
                    token.failed.store(true, Ordering::Release);
                    let _ = ack.send(result);
                    break;
                }
                legacy = Some(sequence == 0);
                if sequence > 0 {
                    last = Some((sequence, digest));
                    next += 1;
                }
                token.touch();
                let _ = ack.send(Ok(()));
            }
        }
    }
    token.cancel.cancel();
    if let Some(registry) = registry.upgrade() {
        registry.remove(&token.value);
    }
}
