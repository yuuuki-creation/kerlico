//! 控制通道可靠层：按 key_id 独立的发送窗口、接收重排与 ACK 记账。

use crate::wire::Opcode;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

/// 上游 `TLS_RELIABLE_N_SEND_BUFFERS`。
const SEND_WINDOW: u32 = 6;
/// 上游 `TLS_RELIABLE_N_REC_BUFFERS`。
const RECEIVE_WINDOW: u32 = 12;
const INITIAL_RETRY: Duration = Duration::from_secs(2);
const MAX_RETRY: Duration = Duration::from_secs(16);
/// 上游 `CONTROL_SEND_ACK_MAX`。
const ACKS_PER_PACKET: usize = 4;

pub(crate) struct Outgoing {
    pub packet_id: u32,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
    next_send: Option<Instant>,
    retry: Duration,
}

#[derive(Default)]
pub(crate) struct ReliableSend {
    next_id: u32,
    queue: VecDeque<Outgoing>,
}
impl ReliableSend {
    pub fn push(&mut self, opcode: Opcode, payload: Vec<u8>) {
        self.queue.push_back(Outgoing {
            packet_id: self.next_id,
            opcode,
            payload,
            next_send: None,
            retry: INITIAL_RETRY,
        });
        self.next_id += 1;
    }
    pub fn ack(&mut self, packet_id: u32) {
        self.queue.retain(|entry| entry.packet_id != packet_id);
    }
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
    /// 返回窗口内已到发送时刻的包，并推进其下一次重传时刻。
    pub fn take_due(&mut self, now: Instant) -> Vec<&Outgoing> {
        let Some(oldest) = self.queue.front().map(|entry| entry.packet_id) else {
            return Vec::new();
        };
        let mut due = Vec::new();
        for entry in &mut self.queue {
            if entry.packet_id - oldest >= SEND_WINDOW {
                break;
            }
            if entry.next_send.is_none_or(|at| at <= now) {
                entry.next_send = Some(now + entry.retry);
                entry.retry = (entry.retry * 2).min(MAX_RETRY);
                due.push(&*entry);
            }
        }
        due
    }
}

#[derive(Default)]
pub(crate) struct ReliableReceive {
    next: u32,
    held: BTreeMap<u32, (Opcode, Vec<u8>)>,
    pending_acks: VecDeque<u32>,
    recent_acks: VecDeque<u32>,
}
impl ReliableReceive {
    pub fn accept(&mut self, packet_id: u32, opcode: Opcode, payload: &[u8]) {
        if packet_id >= self.next.saturating_add(RECEIVE_WINDOW) {
            return;
        }
        if !self.pending_acks.contains(&packet_id) {
            self.pending_acks.push_back(packet_id);
        }
        if packet_id >= self.next {
            self.held
                .entry(packet_id)
                .or_insert_with(|| (opcode, payload.to_vec()));
        }
    }
    pub fn pop_ready(&mut self) -> Option<(Opcode, Vec<u8>)> {
        let ready = self.held.remove(&self.next)?;
        self.next += 1;
        Some(ready)
    }
    pub fn has_pending_acks(&self) -> bool {
        !self.pending_acks.is_empty()
    }
    /// 待确认的 ID 优先，余位重复最近确认过的 ID，以弥补 ACK 丢失（上游 `lru_acks`）。
    pub fn acks_for_packet(&mut self) -> Vec<u32> {
        let mut acks = Vec::with_capacity(ACKS_PER_PACKET);
        while acks.len() < ACKS_PER_PACKET {
            let Some(id) = self.pending_acks.pop_front() else {
                break;
            };
            self.recent_acks.retain(|recent| *recent != id);
            self.recent_acks.push_front(id);
            self.recent_acks.truncate(ACKS_PER_PACKET);
            acks.push(id);
        }
        for id in &self.recent_acks {
            if acks.len() < ACKS_PER_PACKET && !acks.contains(id) {
                acks.push(*id);
            }
        }
        acks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_window_limits_in_flight_packets_until_oldest_is_acked() {
        let now = Instant::now();
        let mut send = ReliableSend::default();
        for _ in 0..8 {
            send.push(Opcode::Control, vec![]);
        }
        let ids = |due: Vec<&Outgoing>| due.iter().map(|entry| entry.packet_id).collect::<Vec<_>>();
        assert_eq!(ids(send.take_due(now)), [0, 1, 2, 3, 4, 5]);
        assert!(send.take_due(now).is_empty());
        send.ack(0);
        assert_eq!(ids(send.take_due(now)), [6]);
    }

    #[test]
    fn unacked_packet_is_retransmitted_with_exponential_backoff() {
        let start = Instant::now();
        let mut send = ReliableSend::default();
        send.push(Opcode::Control, vec![]);
        assert_eq!(send.take_due(start).len(), 1);
        assert!(send.take_due(start + Duration::from_secs(1)).is_empty());
        assert_eq!(send.take_due(start + Duration::from_secs(2)).len(), 1);
        assert!(send.take_due(start + Duration::from_secs(5)).is_empty());
        assert_eq!(send.take_due(start + Duration::from_secs(6)).len(), 1);
    }

    #[test]
    fn receive_reorders_acks_duplicates_and_drops_beyond_window() {
        let mut receive = ReliableReceive::default();
        receive.accept(1, Opcode::Control, b"b");
        assert!(receive.pop_ready().is_none());
        receive.accept(0, Opcode::HardResetServer, b"");
        assert_eq!(receive.pop_ready().unwrap().0, Opcode::HardResetServer);
        assert_eq!(receive.pop_ready().unwrap().1, b"b");
        assert_eq!(receive.acks_for_packet(), [1, 0]);
        assert!(!receive.has_pending_acks());
        receive.accept(0, Opcode::HardResetServer, b"");
        assert!(receive.pop_ready().is_none());
        assert!(receive.has_pending_acks());
        receive.accept(14, Opcode::Control, b"far");
        assert_eq!(receive.acks_for_packet(), [0, 1]);
        assert!(!receive.has_pending_acks());
    }

    #[test]
    fn packets_after_a_lost_ack_still_repeat_the_recent_ack() {
        let mut receive = ReliableReceive::default();
        receive.accept(0, Opcode::HardResetServer, b"");
        assert_eq!(receive.acks_for_packet(), [0]);
        assert_eq!(receive.acks_for_packet(), [0]);
    }
}
