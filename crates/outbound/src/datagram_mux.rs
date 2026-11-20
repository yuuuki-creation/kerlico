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

type Routes<K> = HashMap<K, Vec<(u64, Sink)>>;
pub(crate) trait DirectSink: Send + Sync {
    fn is_live(&self) -> bool;
    fn deliver(&self, source: Option<SocketAddr>, payload: &[u8]);
}

enum Sink {
    Queued(mpsc::SyncSender<Datagram>),
    Direct(Box<dyn DirectSink>),
}

impl Sink {
    fn is_live(&self) -> bool {
        match self {
            Self::Queued(_) => true,
            Self::Direct(sink) => sink.is_live(),
        }
    }
}

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
        let route = self.insert(key, Sink::Queued(send));
        (
            route.id,
            Reader {
                _route: route,
                recv,
            },
        )
    }

    pub(crate) fn register_direct(self: &Arc<Self>, key: K, sink: Box<dyn DirectSink>) -> Route<K>
    where
        K: Clone,
    {
        self.insert(key, Sink::Direct(sink))
    }

    fn insert(self: &Arc<Self>, key: K, sink: Sink) -> Route<K>
    where
        K: Clone,
    {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.routes
            .lock()
            .expect("UDP routes")
            .entry(key.clone())
            .or_default()
            .push((id, sink));
        Route {
            mux: self.clone(),
            key,
            id,
        }
    }

    pub(crate) fn mark_sent(&self, id: u64) {
        self.last.store(id, Ordering::Release);
    }

    pub(crate) fn deliver(&self, key: &K, source: Option<SocketAddr>, data: &[u8]) {
        let routes = self.routes.lock().expect("UDP routes");
        let route = routes
            .get(key)
            .and_then(|sinks| sinks.iter().rev().find(|(_, sink)| sink.is_live()))
            .or_else(|| {
                let id = self.last.load(Ordering::Acquire);
                if !self.allow_other_sources || id == 0 {
                    return None;
                }
                routes
                    .values()
                    .flatten()
                    .find(|(candidate, sink)| *candidate == id && sink.is_live())
            });
        match route.map(|(_, sink)| sink) {
            Some(Sink::Direct(sink)) => sink.deliver(source, data),
            Some(Sink::Queued(deliver)) => {
                if let Some(datagram) = Datagram::try_new(data, source, &self.pending) {
                    let _ = deliver.try_send(datagram);
                }
            }
            None => {}
        }
    }

    pub(crate) fn close(&self) {
        self.routes.lock().expect("UDP routes").clear();
    }

    pub(crate) fn prune_idle(&self) {
        self.routes.lock().expect("UDP routes").retain(|_, sinks| {
            sinks.retain(|(_, sink)| sink.is_live());
            !sinks.is_empty()
        });
    }
}

pub(crate) struct Route<K: Eq + Hash> {
    mux: Arc<Mux<K>>,
    key: K,
    pub(crate) id: u64,
}

pub(crate) struct Reader<K: Eq + Hash> {
    _route: Route<K>,
    recv: mpsc::Receiver<Datagram>,
}

impl<K: Eq + Hash> Drop for Route<K> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    struct Direct {
        live: Arc<AtomicBool>,
        replies: mpsc::Sender<(Option<SocketAddr>, Vec<u8>)>,
    }

    impl DirectSink for Direct {
        fn is_live(&self) -> bool {
            self.live.load(Ordering::Relaxed)
        }

        fn deliver(&self, source: Option<SocketAddr>, payload: &[u8]) {
            self.replies.send((source, payload.to_vec())).unwrap();
        }
    }

    #[test]
    fn expired_direct_route_leaves_alternate_replies_to_the_latest_sender() {
        let first = SocketAddr::from(([127, 0, 0, 1], 1001));
        let second = SocketAddr::from(([127, 0, 0, 1], 1002));
        let mux = Mux::new(true, Arc::new(0.into()));
        let (first_send, first_receive) = mpsc::channel();
        let (second_send, second_receive) = mpsc::channel();
        let live = Arc::new(AtomicBool::new(true));
        let _first = mux.register_direct(
            first,
            Box::new(Direct {
                live: live.clone(),
                replies: first_send,
            }),
        );
        let second_route = mux.register_direct(
            second,
            Box::new(Direct {
                live: Arc::new(true.into()),
                replies: second_send,
            }),
        );
        mux.mark_sent(second_route.id);
        mux.deliver(&first, Some(first), b"first");
        assert_eq!(
            first_receive.try_recv().unwrap(),
            (Some(first), b"first".to_vec())
        );
        live.store(false, Ordering::Relaxed);
        mux.deliver(&first, Some(first), b"alternate");
        assert_eq!(
            second_receive.try_recv().unwrap(),
            (Some(first), b"alternate".to_vec())
        );
        assert!(first_receive.try_recv().is_err());
        drop(second_route);
        mux.prune_idle();
        mux.deliver(&first, Some(first), b"discard");
        assert!(first_receive.try_recv().is_err());
    }
}
