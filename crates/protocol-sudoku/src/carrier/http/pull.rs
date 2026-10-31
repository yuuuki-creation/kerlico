use super::{
    body::{Body, Item, PullState},
    codec::Mode,
    session::Token,
};
use crate::scope::Scope;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hyper::body::Frame;
use kerlico_core::{Error, Result};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, oneshot},
};

async fn send(state: &PullState, sender: &mpsc::Sender<Item>, frame: Frame<Bytes>) -> Result<()> {
    let (consumed, received) = oneshot::channel();
    let item = Item { frame, consumed };
    tokio::select! {biased;_=state.cancel.cancelled()=>return Err(Error::Cancelled),_=state.token.cancel.cancelled()=>return Err(Error::Cancelled),result=sender.send(item)=>result.map_err(|_|Error::Cancelled)?};
    tokio::select! {biased;_=state.cancel.cancelled()=>Err(Error::Cancelled),_=state.token.cancel.cancelled()=>Err(Error::Cancelled),result=received=>result.map_err(|_|Error::Cancelled)}
}
pub(crate) fn start(token: Arc<Token>, scope: &Scope) -> Body {
    let cancel = token.begin_pull();
    let state = Arc::new(PullState {
        token: token.clone(),
        cancel,
        planned: AtomicBool::new(false),
        sent: AtomicBool::new(false),
    });
    let (body, sender) = Body::channel(state.clone());
    scope.spawn(async move {
        let run=async {
            let mut down=tokio::select!{biased;_=state.cancel.cancelled()=>return Err(Error::Cancelled),_=token.cancel.cancelled()=>return Err(Error::Cancelled),down=token.down.lock()=>down};
            loop {
                if down.pending.is_none() && !down.eof {
                    let mut bytes=vec![0;32*1024];
                    let read=tokio::select!{biased;_=state.cancel.cancelled()=>return Err(Error::Cancelled),_=token.cancel.cancelled()=>return Err(Error::Cancelled),result=tokio::time::timeout(Duration::from_secs(15),down.reader.read(&mut bytes))=>result};
                    let count=match read {Err(_)=>{state.planned.store(true,Ordering::Release);return Ok(());},Ok(Err(error))=>return Err(Error::Io(error)),Ok(Ok(count))=>count};
                    if count==0{down.eof=true;}else{bytes.truncate(count);down.pending=Some(Bytes::from(bytes));}
                }
                if let Some(payload)=down.pending.as_ref(){
                    let bytes=if token.mode==Mode::Stream{payload.clone()}else{let mut encoded=STANDARD.encode(payload).into_bytes();encoded.push(b'\n');Bytes::from(encoded)};
                    send(&state,&sender,Frame::data(bytes)).await?;down.pending=None;token.touch();continue;
                }
                if down.eof {
                    let mut trailers=http::HeaderMap::new();trailers.insert("x-sudoku-stream-eof",http::HeaderValue::from_static("1"));send(&state,&sender,Frame::trailers(trailers)).await?;state.planned.store(true,Ordering::Release);return Ok(());
                }
            }
        };
        let result=run.await;
        if result.is_err(){
            if state.sent.load(Ordering::Acquire){token.failed.store(true,Ordering::Release);token.cancel.cancel();}else{state.planned.store(true,Ordering::Release);}
        }
    });
    body
}
