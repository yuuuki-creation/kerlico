//! Shared WireGuard administrative protocol over a local byte stream.

use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::Duration;
use std::{future::Future, io};

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::hub::control::Change;
#[cfg(target_os = "linux")]
use crate::linux_uapi::Listener;
#[cfg(windows)]
use crate::windows_uapi::Listener;

const WAIT: Duration = Duration::from_secs(2);
const MAX_REQUEST: u64 = 512 * 1024;
pub(crate) const MAX_CLIENTS: usize = 8;

pub(crate) enum Action {
    Get,
    Set(Change),
}

enum Frame {
    Dispatch(Action),
    Rejected(io::Error),
    End,
}

pub(crate) type Request = (Action, oneshot::Sender<io::Result<String>>);

pub(crate) fn open(
    name: &str,
) -> io::Result<(Receiver<Request>, impl Future<Output = io::Result<()>>)> {
    Ok(serve_on(Listener::open(name)?))
}

pub(crate) fn serve_on(
    mut listener: Listener,
) -> (Receiver<Request>, impl Future<Output = io::Result<()>>) {
    let (send, requests) = mpsc::sync_channel(4);
    (requests, async move {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                next = listener.accept(), if clients.len() < MAX_CLIENTS => {
                    let Some(client) = next? else { return Ok(()) };
                    let send = send.clone();
                    clients.spawn(async move { let _ = serve(client, &send).await; });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    })
}

async fn serve(
    client: impl AsyncRead + AsyncWrite + Unpin,
    requests: &SyncSender<Request>,
) -> io::Result<()> {
    // Clients may send several commands on one stream. Keep any read-ahead.
    let mut client = BufReader::new(client);
    loop {
        let frame = timeout(WAIT, read_frame((&mut client).take(MAX_REQUEST))).await??;
        let answer = match frame {
            Frame::Dispatch(action) => {
                let (send, reply) = oneshot::channel();
                match requests.try_send((action, send)) {
                    Ok(()) => match timeout(WAIT, reply).await {
                        Ok(Ok(answer)) => answer,
                        Ok(Err(_)) => Err(io::ErrorKind::BrokenPipe.into()),
                        Err(_) => Err(io::ErrorKind::TimedOut.into()),
                    },
                    Err(mpsc::TrySendError::Full(_)) => Err(io::ErrorKind::WouldBlock.into()),
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        Err(io::ErrorKind::BrokenPipe.into())
                    }
                }
            }
            Frame::End => return Ok(()),
            Frame::Rejected(error) => Err(error),
        };
        timeout(WAIT, write_reply(&mut client, answer)).await??;
    }
}

async fn read_frame(mut input: impl AsyncBufRead + Unpin) -> io::Result<Frame> {
    let mut first = String::new();
    input.read_line(&mut first).await?;
    let set = match first.as_str() {
        "get=1\n" => false,
        "set=1\n" => true,
        _ => return Ok(Frame::End),
    };
    let mut body = Vec::new();
    loop {
        let mut line = String::new();
        input.read_line(&mut line).await?;
        if line == "\n" {
            break;
        }
        let line = line.strip_suffix('\n').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "unterminated UAPI request")
        })?;
        body.push(line.to_owned());
    }
    Ok(if set {
        match Change::parse(&body) {
            Ok(change) => Frame::Dispatch(Action::Set(change)),
            Err(error) => Frame::Rejected(error),
        }
    } else if body.is_empty() {
        Frame::Dispatch(Action::Get)
    } else {
        Frame::Rejected(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid UAPI get",
        ))
    })
}

async fn write_reply(
    stream: &mut (impl AsyncWrite + Unpin),
    reply: io::Result<String>,
) -> io::Result<()> {
    match reply {
        Ok(body) => {
            stream.write_all(body.as_bytes()).await?;
            stream.write_all(b"errno=0\n\n").await?;
        }
        Err(error) => {
            stream
                .write_all(format!("errno={}\n\n", errno(&error)).as_bytes())
                .await?
        }
    }
    stream.flush().await
}

#[cfg(target_os = "linux")]
fn errno(error: &io::Error) -> i32 {
    // wireguard-tools negates the protocol value to obtain a system errno.
    -error.raw_os_error().unwrap_or(match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => libc::EINVAL,
        io::ErrorKind::WouldBlock => libc::EAGAIN,
        io::ErrorKind::TimedOut => libc::ETIMEDOUT,
        _ => libc::EIO,
    })
}

#[cfg(windows)]
fn errno(error: &io::Error) -> i32 {
    // wireguard-go exposes its own negative Unix-style values on Windows.
    // Winsock error numbers are not wire protocol values.
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => -22,
        io::ErrorKind::AddrInUse => -98,
        _ => -5,
    }
}
