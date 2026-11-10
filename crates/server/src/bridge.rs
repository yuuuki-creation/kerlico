//! A VLESS reverse bridge run as a node. Every flow the portal opens becomes a `Handoff` of
//! this node, so the node's rules and `OutboundChoice` pick the exit and `crates/outbound` dials.

use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use kerlico_shared::{Accept, Handoff, NodeTag, OpenError, Settings, UserEmail};
use landing_vless::{BridgeLoad, ReverseBridge};

use crate::Error;

/// Xray's VLESS outbound checks its reverse connections on this period.
const CHECK_EVERY: Duration = Duration::from_secs(2);
const SESSIONS_PER_LINK: usize = 16;

type Links = Mutex<Vec<ReverseBridge>>;

struct Bridge {
    tag: NodeTag,
    user: UserEmail,
    links: Arc<Links>,
    next: usize,
}

/// The supervisor thread dials the portal, so an unreachable portal does not fail the config.
/// It stops once the node is dropped.
pub(crate) fn open(tag: &NodeTag, host: String, port: u16, settings: Settings) -> Result<Box<dyn Accept>, Error> {
    let user = UserEmail::parse(tag.as_str())?;
    let links = Arc::new(Links::default());
    let supervised = Arc::downgrade(&links);
    let name = tag.clone();
    thread::spawn(move || supervise(&supervised, &name, &host, port, &settings));
    Ok(Box::new(Bridge { tag: tag.clone(), user, links, next: 0 }))
}

impl Accept for Bridge {
    fn add_user(&mut self, _: &UserEmail, _: &Settings) -> Result<(), OpenError> {
        Err(OpenError::Settings)
    }

    fn remove_user(&mut self, _: &UserEmail) -> Result<(), OpenError> {
        Err(OpenError::Settings)
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        let links = self.links.lock().expect("bridge links");
        for offset in 0..links.len() {
            let index = (self.next + offset) % links.len();
            if let Ok(flow) = links[index].accept() {
                self.next = index + 1;
                let (destination, stream) = flow.into_parts();
                return Ok(Handoff::new(self.tag.clone(), self.user.clone(), destination, stream));
            }
        }
        Err(OpenError::Again)
    }
}

fn supervise(links: &Weak<Links>, tag: &NodeTag, host: &str, port: u16, settings: &Settings) {
    while let Some(shared) = links.upgrade() {
        let wanted = {
            let mut list = shared.lock().expect("bridge links");
            list.retain(|link| link.load() != BridgeLoad::Closed);
            needs_link(&list.iter().map(ReverseBridge::load).collect::<Vec<_>>())
        };
        drop(shared);
        if wanted {
            match landing_vless::reverse_bridge(host, port, settings) {
                Ok(link) => match links.upgrade() {
                    Some(shared) => shared.lock().expect("bridge links").push(link),
                    None => return,
                },
                Err(error) => eprintln!("bridge {} {host}:{port} {error:?}", tag.as_str()),
            }
        }
        thread::sleep(CHECK_EVERY);
    }
}

/// Xray's bridge monitor: one more connection when none is active, or when the active ones
/// average more than 16 sessions. Draining connections keep their sessions but do not count.
fn needs_link(loads: &[BridgeLoad]) -> bool {
    let active: Vec<usize> = loads
        .iter()
        .filter_map(|load| match load {
            BridgeLoad::Active(sessions) => Some(*sessions),
            BridgeLoad::Draining | BridgeLoad::Closed => None,
        })
        .collect();
    active.is_empty() || active.iter().sum::<usize>() / active.len() > SESSIONS_PER_LINK
}

#[cfg(test)]
mod tests {
    use super::*;
    use landing_vless::BridgeLoad::{Active, Closed, Draining};

    #[test]
    fn another_link_opens_where_xrays_bridge_monitor_opens_one() {
        assert!(needs_link(&[]), "no connection yet");
        assert!(needs_link(&[Draining, Closed]), "no active connection");
        assert!(!needs_link(&[Active(16)]), "16 sessions fit one connection");
        assert!(needs_link(&[Active(17)]), "17 sessions overflow one connection");
        assert!(!needs_link(&[Active(33), Active(0)]), "the average rounds down");
        assert!(needs_link(&[Active(34), Active(0)]));
        assert!(!needs_link(&[Draining, Active(1)]), "a draining connection is not counted");
    }
}
