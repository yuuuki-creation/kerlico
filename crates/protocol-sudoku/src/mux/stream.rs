use super::{Command, DATA, FIN, Frame, Owner, SEND_CHUNK, Shared, state::State};
use kerlico_core::{BoxFuture, CancellationToken};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tokio_util::sync::PollSender;

pub(super) fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "Sudoku逻辑流已关闭")
}
#[derive(Clone, Copy)]
enum AckKind {
    Flush,
    Fin,
}
pub(crate) struct LogicalStream {
    shared: Arc<Shared>,
    _owner: Arc<Owner>,
    id: u32,
    pub(super) state: Arc<State>,
    sender: PollSender<Command>,
    ack: Option<oneshot::Receiver<io::Result<()>>>,
    ack_kind: AckKind,
    local_fin: bool,
    read_cancel: BoxFuture<'static, ()>,
    write_cancel: BoxFuture<'static, ()>,
}
impl LogicalStream {
    pub(super) fn new(shared: Arc<Shared>, owner: Arc<Owner>, id: u32, state: Arc<State>) -> Self {
        Self {
            sender: PollSender::new(shared.data.clone()),
            shared,
            _owner: owner,
            id,
            ack: None,
            ack_kind: AckKind::Flush,
            local_fin: false,
            read_cancel: Box::pin(state.cancel.clone().cancelled_owned()),
            write_cancel: Box::pin(state.cancel.clone().cancelled_owned()),
            state,
        }
    }
    pub fn cancel_token(&self) -> CancellationToken {
        self.state.cancel.clone()
    }
    fn acknowledged(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(ack) = self.ack.as_mut() {
            let result = ready!(Pin::new(ack).poll(cx)).unwrap_or_else(|_| Err(broken()));
            self.ack = None;
            if result.is_ok() && matches!(self.ack_kind, AckKind::Fin) {
                self.shared.committed_fin(self.id, &self.state);
            }
            return Poll::Ready(result);
        }
        Poll::Ready(Ok(()))
    }
    fn writable(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.shared.cancel.is_cancelled() || self.write_cancel.as_mut().poll(cx).is_ready() {
            return Err(broken());
        }
        Ok(())
    }
}
impl Drop for LogicalStream {
    fn drop(&mut self) {
        let complete = {
            let receive = self.state.receive.lock().unwrap();
            receive.local_fin && receive.remote_fin && receive.bytes == 0
        };
        self.shared.remove(self.id);
        self.state.reset();
        if !complete && !self.shared.cancel.is_cancelled() {
            self.shared.control(super::RESET, self.id);
        }
    }
}
impl AsyncRead for LogicalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remote_finished = {
            let receive = this.state.receive.lock().unwrap();
            !receive.reset && receive.remote_fin
        };
        if (!remote_finished && this.shared.cancel.is_cancelled())
            || this.read_cancel.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Err(broken()));
        }
        let before = output.filled().len();
        let complete = ready!(this.state.read(output, cx.waker()))?;
        if output.filled().len() > before {
            this.shared.touch();
        }
        if complete {
            this.shared.remove(this.id);
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for LogicalStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.writable(cx)?;
        if this.local_fin {
            return Poll::Ready(Err(broken()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.acknowledged(cx))?;
        ready!(this.sender.poll_reserve(cx)).map_err(|_| broken())?;
        let count = bytes.len().min(SEND_CHUNK);
        let frame = Frame {
            kind: DATA,
            id: this.id,
            payload: bytes[..count].to_vec(),
            owner: Some(Arc::downgrade(&this.state)),
            ack: None,
        };
        this.sender
            .send_item(Command::Frame(frame))
            .map_err(|_| broken())?;
        this.shared.touch();
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.writable(cx)?;
        if this.ack.is_some() {
            return this.acknowledged(cx);
        }
        ready!(this.sender.poll_reserve(cx)).map_err(|_| broken())?;
        let (ack, received) = oneshot::channel();
        this.sender
            .send_item(Command::Flush(ack))
            .map_err(|_| broken())?;
        this.ack_kind = AckKind::Flush;
        this.ack = Some(received);
        this.acknowledged(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.writable(cx)?;
        if this.local_fin {
            return this.acknowledged(cx);
        }
        ready!(this.acknowledged(cx))?;
        ready!(this.sender.poll_reserve(cx)).map_err(|_| broken())?;
        let (ack, received) = oneshot::channel();
        let frame = Frame {
            kind: FIN,
            id: this.id,
            payload: Vec::new(),
            owner: Some(Arc::downgrade(&this.state)),
            ack: Some(ack),
        };
        this.sender
            .send_item(Command::Frame(frame))
            .map_err(|_| broken())?;
        this.local_fin = true;
        this.ack_kind = AckKind::Fin;
        this.ack = Some(received);
        this.acknowledged(cx)
    }
}
