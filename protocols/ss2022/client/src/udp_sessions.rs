use std::time::{Duration, Instant};

use kerlico_ss2022::Replay;

const PREVIOUS_IDLE: Duration = Duration::from_secs(60);

struct Session {
    id: u64,
    seen: Instant,
    replay: Replay,
}

impl Session {
    fn accept(&mut self, packet: u64, now: Instant) -> bool {
        if !self.replay.accept(packet) {
            return false;
        }
        self.seen = now;
        true
    }
}

/// The two-session option in SIP022 §3.2.4, also used by Xray.
#[derive(Default)]
pub(super) struct ServerSessions {
    current: Option<Session>,
    previous: Option<Session>,
}

impl ServerSessions {
    /// The caller has already authenticated the UDP packet and its client session ID.
    pub(super) fn accept(&mut self, id: u64, packet: u64, now: Instant) -> bool {
        if let Some(current) = self.current.as_mut().filter(|state| state.id == id) {
            return current.accept(packet, now);
        }
        if let Some(previous) = self.previous.as_mut() {
            let idle = now.saturating_duration_since(previous.seen);
            if previous.id == id {
                if idle > PREVIOUS_IDLE {
                    self.previous = None;
                    return false;
                }
                return previous.accept(packet, now);
            }
            if idle < PREVIOUS_IDLE {
                return false;
            }
        }

        let mut next = Session {
            id,
            seen: now,
            replay: Replay::default(),
        };
        if !next.accept(packet, now) {
            return false;
        }
        self.previous = self.current.replace(next);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_keeps_previous_replay_window_and_gates_a_third_session() {
        let start = Instant::now();
        let after = |seconds| start + Duration::from_secs(seconds);
        let mut sessions = ServerSessions::default();
        assert!(sessions.accept(1, 8193, after(0)));
        assert!(sessions.accept(2, 1, after(1)));
        assert!(sessions.accept(1, 65, after(2)));
        assert!(!sessions.accept(1, 64, after(3)));
        assert!(!sessions.accept(1, 65, after(31)));
        assert!(!sessions.accept(3, 0, after(61)));
        assert!(sessions.accept(2, 2, after(61)));
        assert!(sessions.accept(3, 0, after(62)));
        assert!(sessions.accept(2, 3, after(63)));
        assert!(!sessions.accept(3, 0, after(63)));
        assert!(!sessions.accept(2, 3, after(123)));
        assert!(!sessions.accept(2, 4, after(124)));
        assert!(sessions.accept(4, 0, after(124)));
    }
}
