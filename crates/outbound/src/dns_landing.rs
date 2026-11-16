//! DNS queries carried by an explicitly selected landing.

use std::{
    cell::Cell,
    net::SocketAddr,
    time::{Duration, Instant},
};

use kerlico_shared::{Destination, InboundStream, OpenError, PlaneFault, ReverseDial, Transport};

const WAIT: Duration = Duration::from_secs(3);

thread_local! { static ACTIVE: Cell<bool> = const { Cell::new(false) }; }

struct Active;

impl Drop for Active {
    fn drop(&mut self) {
        ACTIVE.set(false);
    }
}

pub(crate) fn exchange(
    dial: ReverseDial,
    peer: SocketAddr,
    tcp: bool,
    request: &[u8],
) -> Result<Vec<u8>, OpenError> {
    if ACTIVE.replace(true) {
        return Err(OpenError::Transport);
    }
    let _active = Active;
    let transport = if tcp { Transport::Tcp } else { Transport::Udp };
    let dest = Destination::new(peer.ip().to_string(), peer.port(), transport)
        .map_err(|_| OpenError::Settings)?;
    let stream = dial(&dest)?;
    let deadline = Instant::now() + WAIT;
    if tcp {
        let length = u16::try_from(request.len()).map_err(|_| OpenError::Settings)?;
        let mut framed = Vec::with_capacity(request.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(request);
        let mut tail = &framed[..];
        while !tail.is_empty() {
            let count = retry(deadline, || stream.write_to_user(tail))?;
            if count == 0 || count > tail.len() {
                return Err(OpenError::Transport);
            }
            tail = &tail[count..];
        }
        let mut head = [0; 2];
        read_exact(stream.as_ref(), &mut head, deadline)?;
        let mut data = vec![0; u16::from_be_bytes(head).into()];
        read_exact(stream.as_ref(), &mut data, deadline)?;
        Ok(data)
    } else {
        if retry(deadline, || stream.write_to_user(request))? != request.len() {
            return Err(OpenError::Transport);
        }
        let mut data = vec![0; 65_535];
        let count = retry(deadline, || stream.read_from_user(&mut data))?;
        if count > data.len() {
            return Err(OpenError::Transport);
        }
        data.truncate(count);
        Ok(data)
    }
}

fn read_exact(
    stream: &dyn InboundStream,
    mut data: &mut [u8],
    deadline: Instant,
) -> Result<(), OpenError> {
    while !data.is_empty() {
        let len = retry(deadline, || stream.read_from_user(data))?;
        if len == 0 || len > data.len() {
            return Err(OpenError::Transport);
        }
        data = &mut data[len..];
    }
    Ok(())
}

fn retry<T>(
    deadline: Instant,
    mut attempt: impl FnMut() -> Result<T, PlaneFault>,
) -> Result<T, OpenError> {
    loop {
        match attempt() {
            Ok(result) => return Ok(result),
            Err(PlaneFault::Again) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(_) => return Err(OpenError::Transport),
        }
    }
}
