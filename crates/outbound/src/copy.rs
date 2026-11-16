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
const UDP_BUF: usize = 65_536;
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
    Datagram(usize, std::net::SocketAddr),
    Eof,
}

pub trait PipeWrite: Send {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError>;
    fn finish(&mut self) -> Result<(), OpenError> {
        Ok(())
    }
}

pub fn report_connect<T>(stream: &dyn InboundStream, result: Result<T, OpenError>) -> Result<T, OpenError> {
    match result {
        Ok(connected) => {
            stream.report_connect(Ok(())).map_err(|_| OpenError::Transport)?;
            Ok(connected)
        }
        Err(error) => {
            let _ = stream.report_connect(Err(error.clone()));
            Err(error)
        }
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
        if down.is_err() { pace.halt(); }
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
    let mut buf = vec![0u8; if transport == Transport::Udp { UDP_BUF } else { BUF }];
    loop {
        if pace.halted() {
            return Ok(());
        }
        // The stream may give its own bytes, so they go to the exit without a copy into `buf`.
        // A TCP read of nothing is EOF, not a write; a UDP datagram of nothing is still sent.
        let mut failed = None;
        let read = stream.read_from_user_to(&mut buf, &mut |bytes| {
            if failed.is_some() || (bytes.is_empty() && transport == Transport::Tcp) {
                return;
            }
            if let Err(error) = toward_exit.write_pipe(bytes) {
                failed = Some(error);
            }
        });
        match read {
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
                if let Some(error) = failed {
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
    let mut buf = vec![0u8; if transport == Transport::Udp { UDP_BUF } else { BUF }];
    loop {
        if pace.halted() {
            return Ok(());
        }
        match from_exit.read_pipe(&mut buf) {
            Ok(ReadEvent::Eof) => {
                if transport != Transport::Tcp || !stream.finish_to_user().map_err(|_| OpenError::Transport)? {
                    pace.halt();
                }
                return Ok(());
            }
            Ok(event @ (ReadEvent::Data(_) | ReadEvent::Datagram(..))) => {
                pace.mark();
                let (n, source) = match event {
                    ReadEvent::Data(n) => (n, None),
                    ReadEvent::Datagram(n, source) => (n, Some(source)),
                    _ => unreachable!(),
                };
                let n = if transport == Transport::Udp {
                    // 每次写入恰好一个数据报，零长度也必须实际调用。
                    let written = match source {
                        Some(source) => stream.write_datagram_to_user(&buf[..n], source),
                        None => stream.write_to_user(&buf[..n]),
                    }.map_err(|_| OpenError::Transport)?;
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
