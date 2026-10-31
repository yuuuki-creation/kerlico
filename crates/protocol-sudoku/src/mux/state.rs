use bytes::{Buf, Bytes};
use kerlico_core::CancellationToken;
use std::{collections::VecDeque, sync::Mutex, task::Waker};
use tokio::sync::OwnedSemaphorePermit;

pub(super) struct Chunk {
    pub bytes: Bytes,
    pub _permit: OwnedSemaphorePermit,
}
pub(super) struct Receive {
    pub queue: VecDeque<Chunk>,
    pub bytes: usize,
    pub remote_fin: bool,
    pub local_fin: bool,
    pub reset: bool,
    pub waker: Option<Waker>,
}
pub(super) struct State {
    pub cancel: CancellationToken,
    pub receive: Mutex<Receive>,
    slot: Mutex<Option<OwnedSemaphorePermit>>,
}
impl State {
    pub fn new(cancel: CancellationToken, slot: OwnedSemaphorePermit) -> Self {
        Self {
            cancel,
            receive: Mutex::new(Receive {
                queue: VecDeque::new(),
                bytes: 0,
                remote_fin: false,
                local_fin: false,
                reset: false,
                waker: None,
            }),
            slot: Mutex::new(Some(slot)),
        }
    }
    pub fn reset(&self) {
        self.cancel.cancel();
        let mut receive = self.receive.lock().unwrap();
        receive.reset = true;
        receive.queue.clear();
        receive.bytes = 0;
        if let Some(waker) = receive.waker.take() {
            waker.wake();
        }
        drop(receive);
        self.slot.lock().unwrap().take();
    }
    pub fn is_reset(&self) -> bool {
        self.cancel.is_cancelled() || self.receive.lock().unwrap().reset
    }
    pub fn read(
        &self,
        output: &mut tokio::io::ReadBuf<'_>,
        waker: &Waker,
    ) -> std::task::Poll<std::io::Result<bool>> {
        use std::task::Poll;
        let mut receive = self.receive.lock().unwrap();
        if receive.reset || self.cancel.is_cancelled() {
            return Poll::Ready(Err(super::stream::broken()));
        }
        if let Some(front) = receive.queue.front_mut() {
            let count = output.remaining().min(front.bytes.len());
            output.put_slice(&front.bytes[..count]);
            front.bytes.advance(count);
            if front.bytes.is_empty() {
                receive.queue.pop_front();
            }
            receive.bytes -= count;
            return Poll::Ready(Ok(receive.local_fin
                && receive.remote_fin
                && receive.bytes == 0));
        }
        if receive.remote_fin {
            return Poll::Ready(Ok(receive.local_fin));
        }
        receive.waker = Some(waker.clone());
        Poll::Pending
    }
}
