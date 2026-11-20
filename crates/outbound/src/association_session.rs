//! Reuses an outbound association for all targets in one inbound UDP session.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use kerlico_shared::{
    Association, DatagramSession, Destination, InboundStream, OpenError, PeerAddr, ProxyFn,
    Settings, Upstream,
};

use crate::copy::{self, PipeWrite};
use crate::datagram_mux::{Mux, IO_WAIT};

type Target = (String, u16);
const LIMIT: usize = 4096;

pub(crate) struct AssociationSessions {
    opener: Box<dyn Fn() -> Result<Box<dyn Association>, OpenError> + Send + Sync>,
    groups: Mutex<HashMap<usize, Weak<Group>>>,
    pending: Arc<AtomicUsize>,
}

struct Group {
    session: Weak<DatagramSession>,
    carrier: Mutex<Weak<Carrier>>,
}

struct Carrier {
    group: Arc<Group>,
    association: Box<dyn Association>,
    mux: Arc<Mux<Target>>,
    source: SocketAddr,
    alive: AtomicBool,
}

impl AssociationSessions {
    pub(crate) fn new(opener: ProxyFn, host: String, port: u16, settings: Settings) -> Self {
        let upstream = Mutex::new(None::<Arc<dyn Upstream>>);
        Self::with_opener(move || {
            let upstream = {
                let mut cached = upstream.lock().expect("landing upstream");
                if let Some(upstream) = &*cached {
                    upstream.clone()
                } else {
                    let peer = PeerAddr::from_host_port(host.clone(), port)
                        .map_err(|_| OpenError::Settings)?;
                    cached.insert(opener(&peer, &settings)?).clone()
                }
            };
            upstream.associate_landing().map_err(|_| OpenError::Transport)
        })
    }

    pub(crate) fn with_opener(
        opener: impl Fn() -> Result<Box<dyn Association>, OpenError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            opener: Box::new(opener),
            groups: Mutex::default(),
            pending: Arc::default(),
        }
    }

    pub(crate) fn dial(
        &self,
        session: Arc<DatagramSession>,
        source: Option<SocketAddr>,
        destination: &Destination,
        stream: &dyn InboundStream,
        flow: copy::Flow<'_>,
    ) -> Result<(), OpenError> {
        let (read, write) = copy::report_connect(
            stream,
            (|| {
                let carrier = self.carrier(&session, source)?;
                let target = (destination.host().to_owned(), destination.port());
                let (id, read) = carrier.mux.register(route(&target.0, target.1));
                Ok((
                    read,
                    Write {
                        carrier,
                        target,
                        id,
                    },
                ))
            })(),
        )?;
        drop(session);
        copy::bridge(stream, write, read, flow)
    }

    fn carrier(
        &self,
        session: &Arc<DatagramSession>,
        source: Option<SocketAddr>,
    ) -> Result<Arc<Carrier>, OpenError> {
        let owner = Arc::downgrade(session);
        let key = Arc::as_ptr(session) as usize;
        let group = {
            let mut groups = self.groups.lock().expect("UDP associations");
            groups.retain(|_, entry| entry.strong_count() > 0);
            if let Some(group) = groups.get(&key).and_then(Weak::upgrade) {
                debug_assert!(group.session.ptr_eq(&owner));
                group
            } else {
                if groups.len() >= LIMIT {
                    return Err(OpenError::Again);
                }
                let group = Arc::new(Group {
                    session: owner,
                    carrier: Mutex::new(Weak::new()),
                });
                groups.insert(key, Arc::downgrade(&group));
                group
            }
        };
        let mut installed = group.carrier.lock().expect("UDP association group");
        if let Some(carrier) = installed.upgrade().filter(|carrier| carrier.alive.load(Ordering::Acquire)) {
            return Ok(carrier);
        }
        let association = (self.opener)()?;
        let carrier = Arc::new(Carrier {
            group: group.clone(),
            association,
            mux: Mux::new(session.allows_other_sources(), self.pending.clone()),
            source: source.unwrap_or_else(|| ([127, 0, 0, 1], 0).into()),
            alive: AtomicBool::new(true),
        });
        let recv = carrier.clone();
        std::thread::Builder::new()
            .name("kerlico-outbound-udp".into())
            .spawn(move || recv.receive())
            .map_err(|_| OpenError::Transport)?;
        *installed = Arc::downgrade(&carrier);
        Ok(carrier)
    }
}

fn route(host: &str, port: u16) -> Target {
    (
        host.parse::<IpAddr>()
            .map_or_else(|_| host.to_ascii_lowercase(), |ip| ip.to_string()),
        port,
    )
}

impl Carrier {
    fn receive(&self) {
        while self.group.session.strong_count() != 0 {
            match self.association.recv_for(IO_WAIT) {
                Ok((host, port, data)) => {
                    let source = host
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| SocketAddr::new(ip, port));
                    self.mux.deliver(&route(&host, port), source, &data);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
        }
        self.alive.store(false, Ordering::Release);
        self.association.close();
        self.mux.close();
    }
}

struct Write {
    carrier: Arc<Carrier>,
    target: Target,
    id: u64,
}

impl PipeWrite for Write {
    fn write_pipe(&mut self, data: &[u8]) -> Result<(), OpenError> {
        self.carrier.mux.mark_sent(self.id);
        self.carrier
            .association
            .send_to(self.carrier.source, &self.target.0, self.target.1, data)
            .map_err(|_| OpenError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, mpsc};
    use std::time::Duration;

    #[test]
    fn opening_an_association_does_not_hold_the_session_table() {
        let (started, opening) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let calls = AtomicUsize::new(0);
        let sessions = AssociationSessions::with_opener(move || {
            if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                started.send(()).unwrap();
                let _ = released.lock().unwrap().recv_timeout(Duration::from_secs(5));
            }
            Err(OpenError::Transport)
        });
        let first = Arc::new(DatagramSession::default());
        let second = Arc::new(DatagramSession::default());
        std::thread::scope(|scope| {
            scope.spawn(|| assert!(sessions.carrier(&first, None).is_err()));
            opening.recv_timeout(Duration::from_secs(2)).unwrap();
            let (done, result) = mpsc::channel();
            let (sessions, second) = (&sessions, &second);
            scope.spawn(move || {
                let _ = sessions.carrier(second, None);
                let _ = done.send(());
            });
            let independent = result.recv_timeout(Duration::from_secs(2));
            release.send(()).unwrap();
            independent.unwrap();
        });
    }
}
