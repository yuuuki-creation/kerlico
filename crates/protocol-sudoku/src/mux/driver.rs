use super::{
    Accepted, Command, DATA, FIN, Frame, MAX_FRAME, OPEN, PING, PONG, RESET, STREAM_QUEUE, Shared,
    state::Chunk,
};
use crate::wire::address;
use bytes::Bytes;
use kerlico_core::{Error, Result};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    time::{Duration, Instant},
};

async fn frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Frame> {
    let mut header = [0; 9];
    reader.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header[5..9].try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(Error::ResourceLimit);
    }
    let mut payload = vec![0; len];
    reader.read_exact(&mut payload).await?;
    Ok(Frame {
        kind: header[0],
        id: u32::from_be_bytes(header[1..5].try_into().unwrap()),
        payload,
        owner: None,
        ack: None,
    })
}
pub(super) async fn read_loop(
    mut reader: impl AsyncRead + Unpin,
    shared: Arc<Shared>,
    accept: Option<mpsc::Sender<Accepted>>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_millis(250));
    let mut frames = 0usize;
    loop {
        if frames == 8 {
            // 载体读取可能连续命中内存缓冲；给同一driver中的写/控制方向机会。
            tokio::task::yield_now().await;
            frames = 0;
        }
        let reading = frame(&mut reader);
        tokio::pin!(reading);
        let frame = loop {
            tokio::select! {biased;_=shared.cancel.cancelled()=>return Err(Error::Cancelled),result=&mut reading=>break result?,_=ticker.tick()=>shared.gc()}
        };
        frames += 1;
        if frame.id == 0
            && !matches!(frame.kind, PING | PONG)
            && !(frame.kind == DATA && frame.payload.is_empty())
        {
            return Err(crate::invalid());
        }
        match frame.kind {
            PING | PONG => {
                if frame.id != 0 || !frame.payload.is_empty() {
                    return Err(crate::invalid());
                }
                if frame.kind == PING {
                    shared.control(PONG, 0);
                }
            }
            OPEN => {
                let Some(accept) = accept.as_ref() else {
                    shared.control(RESET, frame.id);
                    continue;
                };
                if frame.id == 0 || shared.state(frame.id).is_some() {
                    shared.reset(frame.id);
                    continue;
                }
                let (target, _) = match address::decode(&frame.payload) {
                    Ok(v) => v,
                    Err(_) => {
                        shared.control(RESET, frame.id);
                        continue;
                    }
                };
                let lease = match shared.budget.as_ref().map(|b| b.try_acquire()).transpose() {
                    Ok(v) => v,
                    Err(_) => {
                        shared.control(RESET, frame.id);
                        continue;
                    }
                };
                let stream = match shared.make_stream(frame.id, shared.stream_parent.child_token())
                {
                    Ok(v) => v,
                    Err(_) => {
                        shared.control(RESET, frame.id);
                        continue;
                    }
                };
                let incoming = Accepted {
                    target,
                    stream,
                    lease,
                };
                if accept.try_send(incoming).is_err() {
                    shared.reset(frame.id);
                } else {
                    shared.touch();
                }
            }
            DATA => {
                let Some(state) = shared.state(frame.id) else {
                    continue;
                };
                if frame.payload.is_empty() {
                    continue;
                }
                let permit = match shared
                    .receive_budget
                    .clone()
                    .try_acquire_many_owned(frame.payload.len() as u32)
                {
                    Ok(v) => v,
                    Err(_) => {
                        shared.reset(frame.id);
                        continue;
                    }
                };
                let mut receive = state.receive.lock().unwrap();
                if receive.reset
                    || receive.remote_fin
                    || receive.bytes.saturating_add(frame.payload.len()) > STREAM_QUEUE
                {
                    drop(receive);
                    drop(permit);
                    shared.reset(frame.id);
                    continue;
                }
                receive.bytes += frame.payload.len();
                receive.queue.push_back(Chunk {
                    bytes: Bytes::from(frame.payload),
                    _permit: permit,
                });
                if let Some(waker) = receive.waker.take() {
                    waker.wake();
                }
            }
            FIN => {
                if !frame.payload.is_empty() {
                    return Err(crate::invalid());
                }
                if let Some(state) = shared.state(frame.id) {
                    let mut receive = state.receive.lock().unwrap();
                    receive.remote_fin = true;
                    let remove = receive.local_fin && receive.bytes == 0;
                    if let Some(waker) = receive.waker.take() {
                        waker.wake();
                    }
                    drop(receive);
                    if remove {
                        shared.remove(frame.id);
                    }
                }
            }
            RESET => {
                if let Some(state) = shared.state(frame.id) {
                    shared.remove(frame.id);
                    state.reset();
                }
            }
            _ => return Err(crate::invalid()),
        }
    }
}

async fn send(writer: &mut (impl AsyncWrite + Unpin), frame: &Frame) -> std::io::Result<()> {
    let mut header = [0; 9];
    header[0] = frame.kind;
    header[1..5].copy_from_slice(&frame.id.to_be_bytes());
    header[5..9].copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(&frame.payload).await?;
    writer.flush().await
}
pub(super) async fn write_loop(
    mut writer: impl AsyncWrite + Unpin,
    shared: Arc<Shared>,
    mut data: mpsc::Receiver<Command>,
    mut control: mpsc::Receiver<Frame>,
) -> Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.tick().await;
    let mut last = Instant::now();
    let mut controls = 0usize;
    let mut commands = 0usize;
    loop {
        if commands == 8 {
            // 全局发送队列持续就绪时也必须让读方向推进，不能依赖socket偶然阻塞。
            tokio::task::yield_now().await;
            commands = 0;
        }
        let queued = if controls >= 8 {
            data.try_recv().ok()
        } else {
            None
        };
        let command = if let Some(command) = queued {
            controls = 0;
            command
        } else {
            tokio::select! {biased;_=shared.cancel.cancelled()=>return Err(Error::Cancelled),Some(frame)=control.recv()=>{controls+=1;Command::Frame(frame)},Some(command)=data.recv()=>{controls=0;command},_=ticker.tick()=>{if last.elapsed()<Duration::from_secs(15){continue;}controls=0;Command::Frame(Frame {kind:DATA,id:0,payload:Vec::new(),owner:None,ack:None})}}
        };
        commands += 1;
        match command {
            Command::Flush(ack) => {
                let result = tokio::select! {biased;_=shared.cancel.cancelled()=>return Err(Error::Cancelled),result=writer.flush()=>result};
                let failed = result.is_err();
                let _ = ack.send(result);
                if failed {
                    return Err(crate::invalid());
                }
            }
            Command::Frame(mut frame) => {
                if frame
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owner.upgrade().is_none_or(|state| state.is_reset()))
                {
                    if let Some(ack) = frame.ack.take() {
                        let _ = ack.send(Err(super::stream::broken()));
                    }
                    continue;
                }
                // 一旦开始，不因其他逻辑流事件取消半个帧或加密记录。
                let result = tokio::select! {biased;_=shared.cancel.cancelled()=>return Err(Error::Cancelled),result=send(&mut writer,&frame)=>result};
                let failed = result.is_err();
                if !failed && frame.kind == FIN
                    && let Some(state) = frame.owner.as_ref().and_then(std::sync::Weak::upgrade)
                {
                        shared.committed_fin(frame.id, &state);
                }
                if let Some(ack) = frame.ack.take() {
                    let _ = ack.send(result);
                }
                if failed {
                    return Err(crate::invalid());
                }
                last = Instant::now();
            }
        }
    }
}
