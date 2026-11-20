//! Level-triggered native TCP relay for sockets with their protocol state drained.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{mpsc, OnceLock};
use std::time::Instant;

use kerlico_shared::{OpenError, TrafficCounters};

use super::{pipe, retryable, transfer, unsupported, SLICE};
use crate::copy::IDLE;

const READ: u32 = libc::EPOLLIN as u32;
const WRITE: u32 = libc::EPOLLOUT as u32;
const HUP: u32 = libc::EPOLLHUP as u32;
const ERROR: u32 = libc::EPOLLERR as u32;
const QUEUE: usize = 256;

type Completion = mpsc::SyncSender<Result<(), OpenError>>;

pub(crate) fn reactor() -> Option<&'static Reactor> {
    static REACTOR: OnceLock<io::Result<Reactor>> = OnceLock::new();
    REACTOR.get_or_init(Reactor::new).as_ref().ok()
}

pub(crate) struct Reactor {
    incoming: mpsc::SyncSender<Flow>,
    wake: OwnedFd,
}

impl Reactor {
    fn new() -> io::Result<Self> {
        // SAFETY: These syscalls only take integer arguments and return new fds.
        let epoll = owned(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        let wake = owned(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
        watch(
            epoll.as_raw_fd(),
            wake.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            READ,
            0,
        )?;
        let ready = wake.try_clone()?;
        let (incoming, queue) = mpsc::sync_channel(QUEUE);
        std::thread::Builder::new()
            .name("kerlico-native-splice".into())
            .spawn(move || {
                if let Err(error) = run(epoll, ready, queue) {
                    eprintln!("native TCP relay: {error}");
                }
            })?;
        Ok(Self { incoming, wake })
    }

    pub(crate) fn dispatch(
        &self,
        user: TcpStream,
        target: TcpStream,
        counters: TrafficCounters,
        detached: bool,
    ) -> Result<(), OpenError> {
        user.set_nonblocking(true)
            .map_err(|_| OpenError::Transport)?;
        target
            .set_nonblocking(true)
            .map_err(|_| OpenError::Transport)?;
        let (complete, done) = mpsc::sync_channel(1);
        let flow = Flow {
            sockets: [user, target],
            directions: [Direction::new(), Direction::new()],
            watched: [0, 0],
            last: Instant::now(),
            counters,
            complete: (!detached).then_some(complete),
        };
        self.incoming
            .try_send(flow)
            .map_err(|_| OpenError::Transport)?;
        signal(self.wake.as_raw_fd()).map_err(|_| OpenError::Transport)?;
        if detached {
            Ok(())
        } else {
            done.recv().unwrap_or(Err(OpenError::Transport))
        }
    }
}

fn owned(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Only fresh successful descriptor returns are passed in.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn signal(fd: RawFd) -> io::Result<()> {
    let increment = 1u64.to_ne_bytes();
    loop {
        // SAFETY: increment is exactly the eight bytes eventfd expects.
        if unsafe { libc::write(fd, increment.as_ptr().cast(), increment.len()) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock => return Ok(()),
            _ => return Err(error),
        }
    }
}

fn watch(epoll: RawFd, fd: RawFd, op: libc::c_int, interests: u32, tag: u64) -> io::Result<()> {
    let mut event = libc::epoll_event {
        events: interests,
        u64: tag,
    };
    // SAFETY: The event points to initialized storage, consumed during this call.
    if unsafe { libc::epoll_ctl(epoll, op, fd, &mut event) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn run(epoll: OwnedFd, wake: OwnedFd, incoming: mpsc::Receiver<Flow>) -> io::Result<()> {
    let poll = epoll.as_raw_fd();
    let wake = wake.as_raw_fd();
    let mut flows = HashMap::<u64, Flow>::new();
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 64];
    let mut next_id = 1;
    let mut deadline: Option<Instant> = None;
    loop {
        let now = Instant::now();
        if deadline.is_some_and(|limit| now >= limit) {
            flows.retain(|_, flow| {
                if now.duration_since(flow.last) < IDLE {
                    return true;
                }
                flow.finish(poll, Ok(()));
                false
            });
            deadline = flows.values().map(|flow| flow.last + IDLE).min();
        }
        let timeout = deadline.map_or(-1, |limit| {
            let remaining = limit.saturating_duration_since(now);
            (remaining.as_millis() + 1).min(libc::c_int::MAX as u128) as libc::c_int
        });
        // SAFETY: events is a writable array of the specified length.
        let count =
            unsafe { libc::epoll_wait(poll, events.as_mut_ptr(), events.len() as _, timeout) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        for event in &events[..count as usize] {
            let tag = event.u64;
            if tag == 0 {
                let mut count = [0u8; 8];
                // SAFETY: eventfd reads one counter into this eight-byte buffer.
                unsafe { libc::read(wake, count.as_mut_ptr().cast(), count.len()) };
                for mut flow in incoming.try_iter().take(QUEUE) {
                    let id = next_id;
                    next_id += 1;
                    if let Err(error) = flow.refresh(poll, id) {
                        flow.finish(poll, Err(error));
                        continue;
                    }
                    let expires = flow.last + IDLE;
                    deadline = Some(deadline.map_or(expires, |limit| limit.min(expires)));
                    flows.insert(id, flow);
                }
                continue;
            }
            let id = tag >> 1;
            let side = (tag & 1) as usize;
            let Some(flow) = flows.get_mut(&id) else {
                continue;
            };
            let result = flow.step(side, event.events).and_then(|finished| {
                if !finished {
                    flow.refresh(poll, id)?;
                }
                Ok(finished)
            });
            if !matches!(result, Ok(false)) {
                let mut flow = flows.remove(&id).expect("active flow");
                flow.finish(poll, result.map(|_| ()));
                if flows.is_empty() {
                    deadline = None;
                }
            }
        }
    }
}

struct Flow {
    sockets: [TcpStream; 2],
    directions: [Direction; 2],
    watched: [u32; 2],
    last: Instant,
    counters: TrafficCounters,
    complete: Option<Completion>,
}

impl Flow {
    fn refresh(&mut self, poll: RawFd, id: u64) -> io::Result<()> {
        for side in 0..2 {
            let mut interests = 0;
            if self.directions[side].can_read() {
                interests |= READ;
            }
            if self.directions[side ^ 1].remaining != 0 {
                interests |= WRITE;
            }
            if interests == self.watched[side] {
                continue;
            }
            let op = match (self.watched[side], interests) {
                (_, 0) => libc::EPOLL_CTL_DEL,
                (0, _) => libc::EPOLL_CTL_ADD,
                _ => libc::EPOLL_CTL_MOD,
            };
            watch(
                poll,
                self.sockets[side].as_raw_fd(),
                op,
                interests,
                (id << 1) | side as u64,
            )?;
            self.watched[side] = interests;
        }
        Ok(())
    }

    fn step(&mut self, side: usize, flags: u32) -> io::Result<bool> {
        let opposite = side ^ 1;
        if flags & ERROR != 0 {
            if let Some(error) = self.sockets[side].take_error()? {
                return Err(error);
            }
        }
        if flags & (WRITE | HUP) != 0 {
            self.drain(opposite)?;
        }
        let direction = &mut self.directions[side];
        if flags & (READ | HUP) != 0 && direction.can_read() {
            direction.fill(&self.sockets[side])?;
            if direction.closed {
                self.sockets[opposite].shutdown(Shutdown::Write)?;
            } else {
                self.drain(side)?;
            }
        }
        Ok(self.directions.iter().all(|direction| direction.closed))
    }

    fn drain(&mut self, side: usize) -> io::Result<()> {
        let counters = &self.counters;
        let last = &mut self.last;
        self.directions[side].drain(&self.sockets[side ^ 1], |n| {
            *last = Instant::now();
            if side == 0 {
                counters.add_uplink(n as u64);
            } else {
                counters.add_downlink(n as u64);
            }
        })
    }

    fn finish(&mut self, poll: RawFd, result: io::Result<()>) {
        for (socket, interests) in self.sockets.iter().zip(self.watched) {
            if interests != 0 {
                let _ = watch(poll, socket.as_raw_fd(), libc::EPOLL_CTL_DEL, 0, 0);
            }
        }
        if let Some(complete) = self.complete.take() {
            let _ = complete.try_send(result.map_err(|_| OpenError::Transport));
        } else if let Err(error) = result {
            eprintln!("native TCP relay: {error}");
        }
    }
}

struct Direction {
    pipe: Option<(OwnedFd, OwnedFd)>,
    buffer: Vec<u8>,
    remaining: usize,
    offset: usize,
    closed: bool,
}

impl Direction {
    fn new() -> Self {
        Self {
            pipe: pipe().ok(),
            buffer: Vec::new(),
            remaining: 0,
            offset: 0,
            closed: false,
        }
    }

    fn can_read(&self) -> bool {
        !self.closed && self.remaining == 0
    }

    fn fill(&mut self, mut source: &TcpStream) -> io::Result<()> {
        self.offset = 0;
        if let Some((_, input)) = &self.pipe {
            match transfer(source.as_raw_fd(), input.as_raw_fd(), SLICE) {
                Ok(n) if n != 0 => {
                    self.remaining = n;
                    return Ok(());
                }
                Ok(_) => {
                    // splice can stop at an urgent mark as well as at EOF.
                    match source.peek(&mut [0]) {
                        Ok(0) => {
                            self.closed = true;
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(error) if retryable(&error) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                Err(error) if retryable(&error) => return Ok(()),
                Err(error) if unsupported(&error) => {}
                Err(error) => return Err(error),
            }
            self.pipe = None;
        }
        if self.buffer.is_empty() {
            self.buffer.resize(SLICE, 0);
        }
        match source.read(&mut self.buffer) {
            Ok(0) => self.closed = true,
            Ok(n) => self.remaining = n,
            Err(error) if retryable(&error) => {}
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn drain(
        &mut self,
        mut target: &TcpStream,
        mut delivered: impl FnMut(usize),
    ) -> io::Result<()> {
        while self.remaining != 0 {
            let result = if let Some((output, _)) = &self.pipe {
                transfer(output.as_raw_fd(), target.as_raw_fd(), self.remaining)
            } else {
                target.write(&self.buffer[self.offset..self.offset + self.remaining])
            };
            match result {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.remaining -= n;
                    self.offset += n;
                    delivered(n);
                }
                Err(error) if retryable(&error) => return Ok(()),
                Err(error) if self.pipe.is_some() && unsupported(&error) => {
                    // These bytes already left the source. Drain them in order
                    // before the next socket read, even if the target blocks.
                    let (output, _) = self.pipe.take().expect("pending pipe");
                    self.buffer.resize(SLICE, 0);
                    File::from(output).read_exact(&mut self.buffer[..self.remaining])?;
                    self.offset = 0;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
