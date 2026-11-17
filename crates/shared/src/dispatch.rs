//! Wakes the server after a producer queues a flow or a management command.

use std::sync::{mpsc, Arc, Condvar, Mutex};

#[derive(Clone, Debug, Default)]
pub struct Wake(Arc<(Mutex<bool>, Condvar)>);

impl Wake {
    pub fn notify(&self) {
        let (pending, ready) = &*self.0;
        let mut pending = pending.lock().expect("dispatch wake");
        if !*pending {
            *pending = true;
            ready.notify_one();
        }
    }

    /// A notice made before this call remains pending. The caller checks all
    /// sources again after waking, even if several notices arrived together.
    pub fn wait(&self) {
        let (pending, ready) = &*self.0;
        let pending = pending.lock().expect("dispatch wake");
        *ready
            .wait_while(pending, |pending| !*pending)
            .expect("dispatch wake") = false;
    }
}

#[derive(Clone)]
pub struct Notifying<S> {
    sender: S,
    wake: Option<Wake>,
}

impl<S> Notifying<S> {
    pub fn new(sender: S, wake: Option<&Wake>) -> Self {
        Self {
            sender,
            wake: wake.cloned(),
        }
    }

    pub fn sender(&self) -> &S {
        &self.sender
    }

    pub fn queued<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        if result.is_ok() {
            if let Some(wake) = &self.wake {
                wake.notify();
            }
        }
        result
    }
}

pub type Sender<T> = Notifying<mpsc::Sender<T>>;
pub type SyncSender<T> = Notifying<mpsc::SyncSender<T>>;

impl<T> Sender<T> {
    pub fn send(&self, value: T) -> Result<(), mpsc::SendError<T>> {
        self.queued(self.sender.send(value))
    }
}

impl<T> SyncSender<T> {
    pub fn try_send(&self, value: T) -> Result<(), mpsc::TrySendError<T>> {
        self.queued(self.sender.try_send(value))
    }
}

pub fn channel<T>(wake: Option<&Wake>) -> (Sender<T>, mpsc::Receiver<T>) {
    let (sender, receiver) = mpsc::channel();
    (Notifying::new(sender, wake), receiver)
}

pub fn sync_channel<T>(capacity: usize, wake: Option<&Wake>) -> (SyncSender<T>, mpsc::Receiver<T>) {
    let (sender, receiver) = mpsc::sync_channel(capacity);
    (Notifying::new(sender, wake), receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn an_enqueue_between_scan_and_sleep_is_not_lost() {
        let wake = Wake::default();
        let (flow, flows) = sync_channel(2, Some(&wake));
        let (api, commands) = channel(Some(&wake));
        let (checked, observed) = mpsc::channel();
        let (resume, resume_rx) = mpsc::channel();
        let (done, received) = mpsc::channel();
        let waiter = thread::spawn(move || {
            assert_eq!(flows.try_recv(), Err(mpsc::TryRecvError::Empty));
            checked.send(()).unwrap();
            resume_rx.recv().unwrap();
            wake.wait();
            done.send((commands.try_recv(), flows.try_recv(), flows.try_recv()))
                .unwrap();
        });
        let timeout = Duration::from_secs(2);
        observed.recv_timeout(timeout).unwrap();
        flow.try_send(1).unwrap();
        flow.try_send(2).unwrap();
        api.send(3).unwrap();
        resume.send(()).unwrap();
        assert_eq!(
            received.recv_timeout(timeout).unwrap(),
            (Ok(3), Ok(1), Ok(2))
        );
        waiter.join().unwrap();
    }
}
