//! One exit, two directions. A stalled direction does not change the exit.

use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use kerlico_shared::{InboundStream, NodeTag, OpenError, PlaneFault, Traffic, UserEmail};

use crate::Exit;

pub trait PipeRead: Send {
    fn read_pipe(&mut self, buf: &mut [u8]) -> Result<usize, OpenError>;
}

pub trait PipeWrite: Send {
    fn write_pipe(&mut self, buf: &[u8]) -> Result<(), OpenError>;
}

pub fn bridge(
    stream: &dyn InboundStream,
    mut toward_exit: impl PipeWrite,
    from_exit: impl PipeRead + 'static,
    user: &UserEmail,
    node: &NodeTag,
    exit: Exit,
    traffic: &dyn Traffic,
) -> Result<(), OpenError> {
    let incoming = spawn_reader(from_exit);
    let (uplink_tx, uplink_rx) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match stream.read_from_user(&mut buf) {
                    Ok(0) | Err(PlaneFault::Closed) => {
                        let _ = uplink_tx.send(Ok(Vec::new()));
                        break;
                    }
                    Ok(n) => {
                        if uplink_tx.send(Ok(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(PlaneFault::Again) => {}
                    Err(PlaneFault::Transport) => {
                        let _ = uplink_tx.send(Err(OpenError::Transport));
                        break;
                    }
                }
            }
        });
        let deadline_idle = Duration::from_secs(300);
        let mut last = Instant::now();
        loop {
            match uplink_rx.recv_timeout(Duration::from_millis(20)) {
                Ok(Ok(chunk)) if chunk.is_empty() => break,
                Ok(Ok(chunk)) => {
                    let n = chunk.len();
                    toward_exit.write_pipe(&chunk)?;
                    traffic.add_uplink(user, node, n as u64);
                    traffic.add_exit_uplink(exit.tag(), n as u64);
                    last = Instant::now();
                }
                Ok(Err(error)) => return Err(error),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            match incoming.recv_timeout(Duration::from_millis(20)) {
                Ok(Ok(chunk)) if chunk.is_empty() => break,
                Ok(Ok(chunk)) => {
                    let n = write_all_user(stream, &chunk)?;
                    traffic.add_downlink(user, node, n as u64);
                    traffic.add_exit_downlink(exit.tag(), n as u64);
                    last = Instant::now();
                }
                Ok(Err(error)) => return Err(error),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if last.elapsed() > deadline_idle {
                break;
            }
        }
        Ok(())
    })
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

fn spawn_reader(mut pipe: impl PipeRead + 'static) -> Receiver<Result<Vec<u8>, OpenError>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match pipe.read_pipe(&mut buf) {
                Ok(0) => {
                    let _ = tx.send(Ok(Vec::new()));
                    break;
                }
                Ok(n) => {
                    if tx.send(Ok(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(OpenError::Again) => continue,
                Err(error) => {
                    let _ = tx.send(Err(error));
                    break;
                }
            }
        }
    });
    rx
}
