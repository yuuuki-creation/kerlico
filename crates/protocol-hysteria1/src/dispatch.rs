//! 一个 QUIC 连接只有一个数据报读取者，完整包按活动会话与代次分发。
use crate::{
    fragment::{Reassembler, Sequence},
    protocol,
    wire::{MAX_PACKET, Packet},
};
use kerlico_core::{Error, Result};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
pub(crate) struct Queued {
    pub packet: Packet,
    _bytes: OwnedSemaphorePermit,
}
#[derive(Clone)]
struct Entry {
    generation: u64,
    sender: mpsc::Sender<Queued>,
    cancel: kerlico_core::CancellationToken,
}
pub(crate) struct Hub {
    entries: Mutex<HashMap<u32, Entry>>,
    fragments: Mutex<Reassembler>,
    bytes: Arc<Semaphore>,
    generation: AtomicU64,
    queue: usize,
    maximum: usize,
}
impl Hub {
    pub fn new(queue: usize, bytes: usize, maximum: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            fragments: Mutex::new(Reassembler::new(maximum)),
            bytes: Arc::new(Semaphore::new(bytes)),
            generation: AtomicU64::new(1),
            queue,
            maximum,
        }
    }
    pub fn register(
        &self,
        id: u32,
        cancel: kerlico_core::CancellationToken,
    ) -> Result<(u64, mpsc::Receiver<Queued>)> {
        let mut entries = self.entries.lock().map_err(|_| protocol())?;
        if entries.contains_key(&id) {
            return Err(protocol());
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(self.queue);
        entries.insert(
            id,
            Entry {
                generation,
                sender,
                cancel,
            },
        );
        Ok((generation, receiver))
    }
    pub fn remove(&self, id: u32, generation: u64) {
        let entry = if let Ok(mut entries) = self.entries.lock() {
            if entries
                .get(&id)
                .is_some_and(|entry| entry.generation == generation)
            {
                entries.remove(&id)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(entry) = entry {
            entry.cancel.cancel();
            if let Ok(mut fragments) = self.fragments.lock() {
                fragments.remove_session(id, generation);
            }
        }
    }
    pub fn close(&self) {
        let entries = if let Ok(mut entries) = self.entries.lock() {
            std::mem::take(&mut *entries)
        } else {
            HashMap::new()
        };
        for (_, entry) in entries {
            entry.cancel.cancel();
        }
    }
    pub fn input(&self, bytes: &[u8]) -> bool {
        let Ok(packet) = Packet::decode(bytes) else {
            return false;
        };
        let Some(entry) = self
            .entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(&packet.session).cloned())
        else {
            return false;
        };
        if entry.cancel.is_cancelled() {
            return false;
        }
        let Some(packet) = self
            .fragments
            .lock()
            .ok()
            .and_then(|mut fragments| fragments.feed(packet, entry.generation, Instant::now()))
        else {
            return true;
        };
        if packet.data.len() > self.maximum || entry.cancel.is_cancelled() {
            return false;
        }
        let Ok(permit) = self
            .bytes
            .clone()
            .try_acquire_many_owned(packet.data.len().max(1) as u32)
        else {
            return false;
        };
        entry
            .sender
            .try_send(Queued {
                packet,
                _bytes: permit,
            })
            .is_ok()
    }
    pub fn prune(&self) {
        if let Ok(mut fragments) = self.fragments.lock() {
            fragments.prune(Instant::now());
        }
    }
}
pub(crate) struct Sender {
    lock: tokio::sync::Mutex<Sequence>,
}
impl Sender {
    pub fn new() -> Self {
        Self {
            lock: tokio::sync::Mutex::new(Sequence::new()),
        }
    }
    pub async fn send(
        &self,
        connection: &quinn::Connection,
        session: u32,
        target: &kerlico_core::Destination,
        packet: &[u8],
        cancel: &kerlico_core::CancellationToken,
    ) -> Result<()> {
        if packet.len() > MAX_PACKET {
            return Err(Error::ResourceLimit);
        }
        let maximum = connection
            .max_datagram_size()
            .ok_or(Error::Unsupported("Hysteria v1 对端未启用 QUIC 数据报"))?;
        let mut sequence = tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::Cancelled),lock=self.lock.lock()=>lock};
        let parts = crate::fragment::split(
            Packet {
                session,
                target: target.clone(),
                message: 0,
                index: 0,
                count: 1,
                data: packet.to_vec(),
            },
            maximum,
            &mut sequence,
            Instant::now(),
        )?;
        for part in parts {
            tokio::select! {biased;_=cancel.cancelled()=>return Err(Error::Cancelled),result=connection.send_datagram_wait(bytes::Bytes::from(part.encode()))=>result.map_err(|_|protocol())?};
        }
        Ok(())
    }
}
