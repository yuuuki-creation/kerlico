use super::session::Token;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use kerlico_core::{CancellationToken, StreamLease};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

pub(crate) struct Item {
    pub frame: Frame<Bytes>,
    pub consumed: oneshot::Sender<()>,
}
pub(crate) struct PullState {
    pub token: Arc<Token>,
    pub cancel: CancellationToken,
    pub planned: AtomicBool,
    pub sent: AtomicBool,
}
pub(crate) struct Body {
    full: Option<http_body_util::combinators::UnsyncBoxBody<Bytes, io::Error>>,
    receiver: Option<mpsc::Receiver<Item>>,
    pull: Option<Arc<PullState>>,
    finished: bool,
    failed: bool,
    pub _request: Option<OwnedSemaphorePermit>,
    pub _logical: Option<StreamLease>,
    pub _physical: Option<OwnedSemaphorePermit>,
}
impl Body {
    pub fn full(bytes: impl Into<Bytes>) -> Self {
        Self {
            full: Some(
                Full::new(bytes.into())
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            ),
            receiver: None,
            pull: None,
            finished: false,
            failed: false,
            _request: None,
            _logical: None,
            _physical: None,
        }
    }
    pub fn channel(state: Arc<PullState>) -> (Self, mpsc::Sender<Item>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                full: None,
                receiver: Some(receiver),
                pull: Some(state),
                finished: false,
                failed: false,
                _request: None,
                _logical: None,
                _physical: None,
            },
            sender,
        )
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        if let Some(pull) = self.pull.as_ref()
            && !self.finished {
                pull.cancel.cancel();
                if pull.sent.load(Ordering::Acquire) {
                    pull.token.failed.store(true, Ordering::Release);
                    pull.token.cancel.cancel();
                }
        }
    }
}
impl HttpBody for Body {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        if let Some(full) = this.full.as_mut() {
            return Pin::new(full).poll_frame(cx);
        }
        if this.failed || this.finished {
            return Poll::Ready(None);
        }
        let Some(receiver) = this.receiver.as_mut() else {
            return Poll::Ready(None);
        };
        match receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(item)) => {
                if let Some(pull) = this.pull.as_ref() {
                    if item.frame.is_data() {
                        pull.sent.store(true, Ordering::Release);
                    }
                    if item.frame.is_trailers() {
                        this.finished = true;
                    }
                }
                let _ = item.consumed.send(());
                Poll::Ready(Some(Ok(item.frame)))
            }
            Poll::Ready(None) => {
                if this
                    .pull
                    .as_ref()
                    .is_some_and(|pull| pull.planned.load(Ordering::Acquire))
                {
                    this.finished = true;
                    Poll::Ready(None)
                } else {
                    this.failed = true;
                    Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP下载未完整结束",
                    ))))
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.full
            .as_ref()
            .map_or(self.finished, |full| full.is_end_stream())
    }
    fn size_hint(&self) -> SizeHint {
        self.full
            .as_ref()
            .map_or_else(SizeHint::new, |full| full.size_hint())
    }
}
