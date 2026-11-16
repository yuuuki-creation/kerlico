//! A bounded set of flow readers sharing one datagram carrier.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use kerlico_shared::OpenError;

use crate::copy::{PipeRead, ReadEvent};

pub(crate) const IO_WAIT: Duration = Duration::from_millis(200);
const MAX_QUEUED: usize = 16 * 1024 * 1024;

type Routes<K> = HashMap<K, Vec<(u64, mpsc::SyncSender<Datagram>)>>;

pub(crate) struct Mux<K> {
    routes: Mutex<Routes<K>>,
    next: AtomicU64,
    last: AtomicU64,
    allow_other_sources: bool,
    pending: Arc<AtomicUsize>,
}

struct Datagram {
    data: Vec<u8>,
    source: Option<SocketAddr>,
    pending: Arc<AtomicUsize>,
}

impl Datagram {
    fn try_new(
        data: &[u8],
        source: Option<SocketAddr>,
        pending: &Arc<AtomicUsize>,
    ) -> Option<Self> {
        let mut old = pending.load(Ordering::Relaxed);
        loop {
            let new = old.checked_add(data.len())?;
            if new > MAX_QUEUED {
                return None;
            }
            match pending.compare_exchange_weak(old, new, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(current) => old = current,
            }
        }
        Some(Self {
            data: data.to_vec(),
            source,
            pending: pending.clone(),
        })
    }
}

impl Drop for Datagram {
    fn drop(&mut self) {
        self.pending.fetch_sub(self.data.len(), Ordering::Relaxed);
    }
}

impl<K: Eq + Hash> Mux<K> {
    pub(crate) fn new(allow_other_sources: bool, pending: Arc<AtomicUsize>) -> Arc<Self> {
        Arc::new(Self {
            routes: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            last: AtomicU64::new(0),
            allow_other_sources,
            pending,
        })
    }

    pub(crate) fn register(self: &Arc<Self>, key: K) -> (u64, Reader<K>)
    where
        K: Clone,
    {
        let (send, recv) = mpsc::sync_channel(16);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.routes
            .lock()
            .expect("UDP routes")
            .entry(key.clone())
            .or_default()
            .push((id, send));
        (
            id,
            Reader {
                mux: self.clone(),
                key,
                id,
                recv,
            },
        )
    }

    pub(crate) fn mark_sent(&self, id: u64) {
        self.last.store(id, Ordering::Release);
    }

    pub(crate) fn deliver(&self, key: &K, source: Option<SocketAddr>, data: &[u8]) {
        let routes = self.routes.lock().expect("UDP routes");
        let route = routes.get(key).and_then(|sinks| sinks.last()).or_else(|| {
            let id = self.last.load(Ordering::Acquire);
            if !self.allow_other_sources || id == 0 {
                return None;
            }
            routes
                .values()
                .flatten()
                .find(|(candidate, _)| *candidate == id)
        });
        if let Some((_, deliver)) = route {
            if let Some(datagram) = Datagram::try_new(data, source, &self.pending) {
                let _ = deliver.try_send(datagram);
            }
        }
    }

    pub(crate) fn close(&self) {
        self.routes.lock().expect("UDP routes").clear();
    }
}

pub(crate) struct Reader<K: Eq + Hash> {
    mux: Arc<Mux<K>>,
    key: K,
    id: u64,
    recv: mpsc::Receiver<Datagram>,
}

impl<K: Eq + Hash> Drop for Reader<K> {
    fn drop(&mut self) {
        let mut routes = self.mux.routes.lock().expect("UDP routes");
        if let Some(sinks) = routes.get_mut(&self.key) {
            sinks.retain(|(id, _)| *id != self.id);
            if sinks.is_empty() {
                routes.remove(&self.key);
            }
        }
    }
}

impl<K: Eq + Hash + Send> PipeRead for Reader<K> {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<ReadEvent, OpenError> {
        let datagram = self
            .recv
            .recv_timeout(IO_WAIT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => OpenError::Again,
                mpsc::RecvTimeoutError::Disconnected => OpenError::Transport,
            })?;
        let len = datagram.data.len();
        buf.get_mut(..len)
            .ok_or(OpenError::Transport)?
            .copy_from_slice(&datagram.data);
        Ok(datagram.source.map_or(ReadEvent::Data(len), |source| {
            ReadEvent::Datagram(len, source)
        }))
    }
}
