mod driver;
mod state;
mod stream;
#[cfg(test)]
mod tests;

use crate::wire::address;
use kerlico_core::{
    BoxStream, CancellationToken, ConnectContext, Destination, Error, Result, StreamBudget,
    StreamLease,
};
use std::{
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
pub(crate) use stream::LogicalStream;
use tokio::{
    sync::{Semaphore, mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};

pub(super) const OPEN: u8 = 1;
pub(super) const DATA: u8 = 2;
pub(super) const FIN: u8 = 3;
pub(super) const RESET: u8 = 4;
pub(super) const PING: u8 = 5;
pub(super) const PONG: u8 = 6;
pub(super) const MAX_FRAME: usize = 256 * 1024;
pub(super) const SEND_CHUNK: usize = 32 * 1024;
pub(super) const STREAM_QUEUE: usize = 4 * 1024 * 1024;

pub(super) struct Frame {
    kind: u8,
    id: u32,
    payload: Vec<u8>,
    owner: Option<Weak<state::State>>,
    ack: Option<oneshot::Sender<std::io::Result<()>>>,
}
pub(super) enum Command {
    Frame(Frame),
    Flush(oneshot::Sender<std::io::Result<()>>),
}
pub(crate) struct Accepted {
    pub target: Destination,
    pub stream: LogicalStream,
    pub lease: Option<StreamLease>,
}
struct Owner {
    cancel: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.cancel.cancel();
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

pub(super) struct Shared {
    cancel: CancellationToken,
    stream_parent: CancellationToken,
    states: Mutex<std::collections::HashMap<u32, Arc<state::State>>>,
    data: mpsc::Sender<Command>,
    control: mpsc::Sender<Frame>,
    slots: Arc<Semaphore>,
    receive_budget: Arc<Semaphore>,
    next: AtomicU32,
    owner: OnceLock<Weak<Owner>>,
    touched: Mutex<Instant>,
    idle: Duration,
    budget: Option<StreamBudget>,
}
impl Shared {
    fn touch(&self) {
        *self.touched.lock().unwrap() = Instant::now();
    }
    fn state(&self, id: u32) -> Option<Arc<state::State>> {
        self.states.lock().unwrap().get(&id).cloned()
    }
    fn remove(&self, id: u32) {
        self.states.lock().unwrap().remove(&id);
    }
    fn reset(&self, id: u32) {
        if let Some(state) = self.states.lock().unwrap().remove(&id) {
            state.reset();
        }
        self.control(RESET, id);
    }
    fn control(&self, kind: u8, id: u32) {
        let frame = Frame {
            kind,
            id,
            payload: Vec::new(),
            owner: None,
            ack: None,
        };
        if self.control.try_send(frame).is_err() {
            self.cancel.cancel();
        }
    }
    fn fail_all(&self) {
        self.cancel.cancel();
        let states: Vec<_> = self
            .states
            .lock()
            .unwrap()
            .drain()
            .map(|(_, v)| v)
            .collect();
        for state in states {
            state.reset();
        }
    }
    fn transport_ended(&self) {
        let states: Vec<_> = {
            let mut entries = self.states.lock().unwrap();
            let states = entries.drain().map(|(_, v)| v).collect();
            self.cancel.cancel();
            states
        };
        for state in states {
            let mut receive = state.receive.lock().unwrap();
            if receive.remote_fin && !receive.reset {
                if let Some(waker) = receive.waker.take() {
                    waker.wake();
                }
                drop(receive);
            } else {
                drop(receive);
                state.reset();
            }
        }
    }
    fn make_stream(self: &Arc<Self>, id: u32, cancel: CancellationToken) -> Result<LogicalStream> {
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::ResourceLimit)?;
        let owner = self
            .owner
            .get()
            .and_then(Weak::upgrade)
            .ok_or(Error::Cancelled)?;
        let state = Arc::new(state::State::new(cancel, slot));
        {
            let mut states = self.states.lock().unwrap();
            if self.cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            states.insert(id, state.clone());
            self.touch();
        }
        Ok(LogicalStream::new(self.clone(), owner, id, state))
    }
    fn committed_fin(&self, id: u32, state: &state::State) {
        let mut receive = state.receive.lock().unwrap();
        receive.local_fin = true;
        let remove = receive.remote_fin && receive.bytes == 0;
        drop(receive);
        if remove {
            self.remove(id);
        }
    }
    fn gc(&self) {
        let cancelled: Vec<_> = self
            .states
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.cancel.is_cancelled())
            .map(|(&id, _)| id)
            .collect();
        for id in cancelled {
            self.reset(id);
        }
        let states = self.states.lock().unwrap();
        if states.is_empty() && self.touched.lock().unwrap().elapsed() >= self.idle {
            self.cancel.cancel();
        }
    }
}

pub(crate) struct Session {
    shared: Arc<Shared>,
    _owner: Arc<Owner>,
    incoming: Option<tokio::sync::Mutex<mpsc::Receiver<Accepted>>>,
}
impl Session {
    pub fn start(
        stream: BoxStream,
        parent: &CancellationToken,
        maximum: usize,
        idle: Duration,
        budget: Option<StreamBudget>,
        server: bool,
    ) -> Self {
        let cancel = parent.child_token();
        let (data, data_rx) = mpsc::channel(64);
        let (control, control_rx) = mpsc::channel(64);
        let (accept, accept_rx) = mpsc::channel(32);
        let owner = Arc::new(Owner {
            cancel: cancel.clone(),
            tasks: Mutex::new(Vec::new()),
        });
        let shared = Arc::new(Shared {
            cancel,
            stream_parent: parent.clone(),
            states: Mutex::new(std::collections::HashMap::new()),
            data,
            control,
            slots: Arc::new(Semaphore::new(maximum)),
            receive_budget: Arc::new(Semaphore::new(8 * 1024 * 1024)),
            next: AtomicU32::new(1),
            owner: OnceLock::new(),
            touched: Mutex::new(Instant::now()),
            idle,
            budget,
        });
        let _ = shared.owner.set(Arc::downgrade(&owner));
        let (reader, writer) = tokio::io::split(stream);
        let driving = shared.clone();
        let driver = tokio::spawn(async move {
            {
                // RecordStream/ObfsStream的读操作也会推进待写缓冲。两个方向必须
                // 使用同一任务waker，避免读侧替换写就绪注册后遗失写侧推进。
                let reading = driver::read_loop(reader, driving.clone(), server.then_some(accept));
                let writing = driver::write_loop(writer, driving.clone(), data_rx, control_rx);
                tokio::pin!(reading);
                tokio::pin!(writing);
                tokio::select! {
                    _ = &mut reading => {},
                    _ = &mut writing => {},
                }
            }
            driving.transport_ended();
        });
        owner.tasks.lock().unwrap().push(driver);
        Self {
            shared,
            _owner: owner,
            incoming: server.then(|| tokio::sync::Mutex::new(accept_rx)),
        }
    }
    pub fn is_closed(&self) -> bool {
        self.shared.cancel.is_cancelled()
    }
    pub fn available(&self) -> bool {
        !self.is_closed() && self.shared.slots.available_permits() > 0
    }
    pub fn close(&self) {
        self.shared.fail_all();
    }
    pub async fn open(
        &self,
        target: &Destination,
        context: &ConnectContext,
    ) -> Result<LogicalStream> {
        if self.is_closed() {
            return Err(Error::Cancelled);
        }
        let id = self
            .shared
            .next
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                id.checked_add(1).filter(|v| *v != 0)
            })
            .map_err(|_| Error::ResourceLimit)?;
        let stream = self.shared.make_stream(id, context.cancel.child_token())?;
        let (ack, received) = oneshot::channel();
        let frame = Frame {
            kind: OPEN,
            id,
            payload: address::encode(target),
            owner: Some(Arc::downgrade(&stream.state)),
            ack: Some(ack),
        };
        context
            .run(async {
                self.shared
                    .data
                    .send(Command::Frame(frame))
                    .await
                    .map_err(|_| Error::Cancelled)?;
                received.await.map_err(|_| Error::Cancelled)??;
                Ok(())
            })
            .await?;
        self.shared.touch();
        Ok(stream)
    }
    pub async fn accept(&self) -> Result<Accepted> {
        let receiver = self
            .incoming
            .as_ref()
            .ok_or(Error::Unsupported("客户端复用会话不接受对端Open"))?;
        let mut receiver = receiver.lock().await;
        loop {
            if self.shared.stream_parent.is_cancelled() {
                return Err(Error::Cancelled);
            }
            // 物理EOF不能抢在已排队的Open/Data/Fin之前丢弃完整逻辑尾部。
            let incoming = tokio::select! {biased;
                incoming=receiver.recv()=>incoming.ok_or(Error::Cancelled)?,
                _=self.shared.cancel.cancelled()=>return Err(Error::Cancelled),
            };
            let valid = {
                let receive = incoming.stream.state.receive.lock().unwrap();
                !receive.reset
                    && !incoming.stream.state.cancel.is_cancelled()
                    && (!self.shared.cancel.is_cancelled() || receive.remote_fin)
            };
            if valid && !self.shared.stream_parent.is_cancelled() {
                return Ok(incoming);
            }
        }
    }
}
