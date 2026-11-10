//! One exit, two directions. Each direction blocks on its own read.
//! A quiet direction does not pace the other, and neither side queues
//! more bytes than the buffer it is writing.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kerlico_shared::{
    InboundStream, NodeTag, OpenError, PlaneFault, Traffic, TrafficCounters, Transport, UserEmail,
};

use crate::Exit;

const BUF: usize = 1024 * 1024;
const IDLE: Duration = Duration::from_secs(300);

#[derive(Clone, Copy)]
pub struct Flow<'a> {
    pub user: &'a UserEmail,
    pub node: &'a NodeTag,
    pub exit: Exit,
    pub traffic: &'a dyn Traffic,
    pub transport: Transport,
}

pub trait PipeRead: Send {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<ReadEvent, OpenError>;
}

pub enum ReadEvent {
    Data(usize),
    Eof,
}

pub trait PipeWrite: Send {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError>;
    fn finish(&mut self) -> Result<(), OpenError> {
        Ok(())
    }
}

struct Pace {
    start: Instant,
    last_ms: AtomicU64,
    stop: AtomicBool,
}

impl Pace {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            stop: AtomicBool::new(false),
        }
    }

    fn mark(&self) {
        let ms = self.start.elapsed().as_millis() as u64;
        self.last_ms.store(ms, Ordering::Release);
    }

    fn idle(&self) -> bool {
        let now = self.start.elapsed().as_millis() as u64;
        now.saturating_sub(self.last_ms.load(Ordering::Acquire)) > IDLE.as_millis() as u64
    }

    fn halt(&self) {
        self.stop.store(true, Ordering::Release);
    }

    fn halted(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

pub fn bridge(
    stream: &dyn InboundStream,
    toward_exit: impl PipeWrite,
    from_exit: impl PipeRead + 'static,
    flow: Flow<'_>,
) -> Result<(), OpenError> {
    let pace = Arc::new(Pace::new());
    let counters = flow.traffic.bind(flow.user, flow.node, flow.exit.tag());
    thread::scope(|scope| {
        let pace_up = Arc::clone(&pace);
        let traffic = &counters;
        let up =
            scope.spawn(move || pump_up(stream, toward_exit, traffic, flow.transport, &pace_up));
        let down = pump_down(stream, from_exit, &counters, flow.transport, &pace);
        pace.halt();
        let up = up.join().unwrap_or(Err(OpenError::Transport));
        down.and(up)
    })
}

fn pump_up(
    stream: &dyn InboundStream,
    mut toward_exit: impl PipeWrite,
    traffic: &TrafficCounters,
    transport: Transport,
    pace: &Pace,
) -> Result<(), OpenError> {
    let mut buf = vec![0u8; BUF];
    loop {
        if pace.halted() {
            return Ok(());
        }
        match stream.read_from_user(&mut buf) {
            Ok(0) if transport == Transport::Tcp => {
                toward_exit.finish()?;
                return Ok(());
            }
            Err(PlaneFault::Closed) => {
                if transport == Transport::Tcp {
                    toward_exit.finish()?;
                } else {
                    pace.halt();
                }
                return Ok(());
            }
            Ok(n) => {
                pace.mark();
                if let Err(error) = toward_exit.write_pipe(&buf[..n]) {
                    pace.halt();
                    return Err(error);
                }
                traffic.add_uplink(n as u64);
            }
            Err(PlaneFault::Again) => {
                if pace.idle() {
                    pace.halt();
                    return Ok(());
                }
            }
            Err(PlaneFault::Transport) => {
                pace.halt();
                return Err(OpenError::Transport);
            }
        }
    }
}

fn pump_down(
    stream: &dyn InboundStream,
    mut from_exit: impl PipeRead,
    traffic: &TrafficCounters,
    transport: Transport,
    pace: &Pace,
) -> Result<(), OpenError> {
    let mut buf = vec![0u8; BUF];
    loop {
        if pace.halted() {
            return Ok(());
        }
        match from_exit.read_pipe(&mut buf) {
            Ok(ReadEvent::Eof) => {
                pace.halt();
                return Ok(());
            }
            Ok(ReadEvent::Data(n)) => {
                pace.mark();
                let n = if transport == Transport::Udp {
                    // 每次写入恰好一个数据报，零长度也必须实际调用。
                    let written = stream
                        .write_to_user(&buf[..n])
                        .map_err(|_| OpenError::Transport)?;
                    if written != n {
                        pace.halt();
                        return Err(OpenError::Transport);
                    }
                    n as u64
                } else {
                    write_all_user(stream, &buf[..n])?
                };
                traffic.add_downlink(n);
            }
            Err(OpenError::Again) => {
                if pace.idle() {
                    pace.halt();
                    return Ok(());
                }
            }
            Err(error) => {
                pace.halt();
                return Err(error);
            }
        }
    }
}

fn write_all_user(stream: &dyn InboundStream, chunk: &[u8]) -> Result<u64, OpenError> {
    let mut sent = 0;
    while sent < chunk.len() {
        match stream.write_to_user(&chunk[sent..]) {
            Ok(0) => return Err(OpenError::Transport),
            Ok(n) => sent += n,
            Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(5)),
            Err(PlaneFault::Closed) => return Err(OpenError::Transport),
            Err(PlaneFault::Transport) => return Err(OpenError::Transport),
        }
    }
    Ok(sent as u64)
}
