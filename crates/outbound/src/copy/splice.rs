use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use super::{OpenError, Pace};

mod reactor;
pub(crate) use reactor::reactor;

const SLICE: usize = 1024 * 1024;
const WAIT: Duration = Duration::from_millis(200);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Fallback,
    Stopped,
}

pub(super) fn forward(
    source: &TcpStream,
    target: &TcpStream,
    pace: &Pace,
    coalesce: bool,
    mut count: impl FnMut(usize),
) -> Result<Outcome, OpenError> {
    // F_NONBLOCK makes the pipe nonblocking but some Linux kernels still
    // honor the socket's own timeout. Do not change the shared O_NONBLOCK bit.
    let Ok(Some(_)) = source.read_timeout() else {
        return Ok(Outcome::Fallback);
    };
    let Ok(previous_timeout) = target.write_timeout() else {
        return Ok(Outcome::Fallback);
    };
    if target.set_write_timeout(Some(WAIT)).is_err() {
        return Ok(Outcome::Fallback);
    }
    struct ResetTimeout<'a>(&'a TcpStream, Option<Duration>);
    impl Drop for ResetTimeout<'_> {
        fn drop(&mut self) {
            let _ = self.0.set_write_timeout(self.1);
        }
    }
    let _reset = ResetTimeout(target, previous_timeout);
    let Ok((pipe_out, pipe_in)) = pipe() else {
        return Ok(Outcome::Fallback);
    };
    let mut bulk = coalesce.then_some(BulkRead {
        delivered: 0,
        last: None,
    });
    let mut delivered = |len| {
        pace.mark();
        count(len);
    };
    let stopped = || {
        if pace.idle() {
            pace.halt();
        }
        pace.halted()
    };
    loop {
        if stopped() {
            return Ok(Outcome::Stopped);
        }
        if let Some(bulk) = &bulk {
            if !bulk.ready(source).map_err(|_| OpenError::Transport)? {
                continue;
            }
        }
        let mut remaining = match transfer(source.as_raw_fd(), pipe_in.as_raw_fd(), SLICE) {
            // Let the ordinary socket read disambiguate EOF from a socket
            // condition (such as an urgent mark) that splice cannot pass.
            Ok(0) => return Ok(Outcome::Fallback),
            Ok(n) => n,
            Err(error) if unsupported(&error) => return Ok(Outcome::Fallback),
            Err(error) if retryable(&error) => {
                wait_fd(source.as_raw_fd(), libc::POLLIN)?;
                continue;
            }
            Err(_) => return Err(OpenError::Transport),
        };
        if let Some(bulk) = &mut bulk {
            bulk.observe(remaining);
        }
        while remaining > 0 {
            if stopped() {
                return Ok(Outcome::Stopped);
            }
            match transfer(pipe_out.as_raw_fd(), target.as_raw_fd(), remaining) {
                Ok(n) if n > 0 => {
                    remaining -= n;
                    delivered(n);
                }
                Err(error) if unsupported(&error) => {
                    // Data already left `source` and cannot be read there again.
                    // Copy the remainder in order before using the usual relay.
                    let mut rest = vec![0; remaining];
                    File::from(pipe_out)
                        .read_exact(&mut rest)
                        .map_err(|_| OpenError::Transport)?;
                    let mut socket = target;
                    let mut sent = 0;
                    while sent < rest.len() {
                        if stopped() {
                            return Ok(Outcome::Stopped);
                        }
                        match socket.write(&rest[sent..]) {
                            Ok(n) if n > 0 => {
                                sent += n;
                                delivered(n);
                            }
                            Err(error) if retryable(&error) => {
                                wait_fd(target.as_raw_fd(), libc::POLLOUT)?
                            }
                            _ => return Err(OpenError::Transport),
                        }
                    }
                    return Ok(Outcome::Fallback);
                }
                Err(error) if retryable(&error) => wait_fd(target.as_raw_fd(), libc::POLLOUT)?,
                _ => return Err(OpenError::Transport),
            }
        }
    }
}

fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut ends = [-1; 2];
    // SAFETY: pipe2 writes exactly two descriptors before returning success.
    if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // A restricted worker may keep the default capacity instead.
    // SAFETY: The call takes an integer capacity and does not retain any pointer.
    unsafe { libc::fcntl(ends[1], libc::F_SETPIPE_SZ, SLICE as libc::c_int) };
    // SAFETY: Both successful descriptors are newly created and owned here.
    Ok(unsafe { (OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])) })
}

fn transfer(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    // SAFETY: All descriptors belong to the caller for the duration of the
    // operation; streams cannot seek so neither of their offsets is supplied.
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };
    if n >= 0 {
        Ok(n as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn wait_fd(fd: RawFd, events: libc::c_short) -> Result<(), OpenError> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: poll only updates this live entry during the call.
    if unsafe { libc::poll(&mut pfd, 1, WAIT.as_millis() as _) } < 0
        && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
    {
        return Err(OpenError::Transport);
    }
    Ok(())
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP | libc::EXDEV | libc::EPERM)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, TcpListener};

    fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let peer = TcpStream::connect(listener.local_addr()?)?;
        Ok((peer, listener.accept()?.0))
    }

    #[test]
    fn cancellation_interrupts_an_idle_splice_and_restores_socket_options() -> io::Result<()> {
        let (_origin, source) = tcp_pair()?;
        let (_user, target) = tcp_pair()?;
        source.set_read_timeout(Some(WAIT))?;
        let original = Some(Duration::from_secs(3));
        target.set_write_timeout(original)?;
        let pace = Pace::new();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                forward(&source, &target, &pace, true, |_| {
                    panic!("unexpected bytes")
                })
            });
            std::thread::sleep(Duration::from_millis(30));
            let start = std::time::Instant::now();
            pace.halt();
            assert_eq!(worker.join().unwrap().unwrap(), Outcome::Stopped);
            assert!(start.elapsed() < Duration::from_secs(2));
        });
        assert_eq!(target.write_timeout()?, original);
        assert_eq!(source.read_timeout()?, Some(WAIT));
        Ok(())
    }

    #[test]
    fn a_source_without_a_read_timeout_keeps_the_normal_copy_path() -> io::Result<()> {
        let (_origin, source) = tcp_pair()?;
        let (_user, target) = tcp_pair()?;
        assert_eq!(
            forward(&source, &target, &Pace::new(), true, |_| panic!(
                "unexpected bytes"
            ))
            .unwrap(),
            Outcome::Fallback
        );
        assert_eq!(target.write_timeout()?, None);
        Ok(())
    }

    #[test]
    fn forwards_multiple_pipe_loads_in_order_and_counts_only_delivered_bytes() -> io::Result<()> {
        let (mut origin, source) = tcp_pair()?;
        let (mut user, target) = tcp_pair()?;
        source.set_read_timeout(Some(WAIT))?;
        user.set_read_timeout(Some(Duration::from_secs(4)))?;
        let payload: Vec<u8> = (0..SLICE * 5 + 13).map(|i| (i % 251) as u8).collect();
        std::thread::scope(|scope| -> io::Result<()> {
            let expected = &payload;
            let send = scope.spawn(move || -> io::Result<()> {
                origin.write_all(expected)?;
                origin.shutdown(Shutdown::Write)
            });
            let copy = scope.spawn(|| {
                let mut count = 0;
                let outcome =
                    forward(&source, &target, &Pace::new(), true, |n| count += n).unwrap();
                assert_eq!(outcome, Outcome::Fallback);
                assert_eq!(count, payload.len());
                assert_eq!(target.write_timeout().unwrap(), None);
                assert_eq!((&source).read(&mut [0; 1]).unwrap(), 0);
            });
            let mut actual = vec![0; payload.len()];
            user.read_exact(&mut actual)?;
            assert_eq!(actual, payload);
            send.join().unwrap()?;
            copy.join().unwrap();
            Ok(())
        })
    }
}

// Allow consecutive TCP segments of an active bulk transfer to share a splice.
// Poll before inspecting the queue so a short request after an idle period
// can proceed immediately. The two sockets keep their caller's blocking mode.
struct BulkRead {
    delivered: usize,
    last: Option<std::time::Instant>,
}
impl BulkRead {
    fn observe(&mut self, bytes: usize) {
        self.delivered = self.delivered.saturating_add(bytes);
        self.last = Some(std::time::Instant::now());
    }
    fn ready(&self, source: &TcpStream) -> io::Result<bool> {
        let Some(last) = self.last.filter(|_| self.delivered >= 256 * 1024) else {
            return Ok(true);
        };
        let active = Duration::from_millis(20);
        if last.elapsed() > active {
            return Ok(true);
        }
        let mut entry = libc::pollfd {
            fd: source.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        };
        let count = unsafe { libc::poll(&mut entry, 1, WAIT.as_millis() as _) };
        if count < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(e)
            };
        }
        if count == 0 {
            return Ok(false);
        }
        if entry.revents != libc::POLLIN || last.elapsed() > active {
            return Ok(true);
        }
        let mut available: libc::c_int = 0;
        if unsafe { libc::ioctl(entry.fd, libc::FIONREAD, &mut available) } == 0
            && (8192..49152).contains(&available)
        {
            let pause = libc::timespec {
                tv_sec: 0,
                tv_nsec: 80_000,
            };
            unsafe {
                libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &pause, std::ptr::null_mut());
            }
        }
        Ok(true)
    }
}
