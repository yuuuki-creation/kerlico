use crate::{
    config::Protocol,
    handshake::{self, EarlyServer, Negotiated},
    io::Prefix,
};
use kerlico_core::{BoxStream, CredentialSet, CredentialSlot, Error, Result};
use std::sync::Arc;
use tokio::io::AsyncReadExt;

pub(crate) struct Members {
    pub credentials: CredentialSet<Arc<Protocol>>,
    pub local: Arc<Protocol>,
}
#[derive(Clone)]
pub(crate) struct Selected {
    pub slot: Option<CredentialSlot>,
    pub protocol: Arc<Protocol>,
}
pub(crate) enum Opening {
    Deferred(Selected),
    Early {
        selected: Selected,
        prepared: EarlyServer,
    },
}
impl Opening {
    pub fn response(&self) -> Option<&Vec<u8>> {
        match self {
            Self::Early { prepared, .. } => Some(&prepared.response),
            Self::Deferred(_) => None,
        }
    }
    pub async fn finish(self, stream: BoxStream) -> Result<(Negotiated, Selected)> {
        match self {
            Self::Deferred(selected) => Ok((
                handshake::server(stream, &selected.protocol).await?,
                selected,
            )),
            Self::Early { selected, prepared } => Ok((prepared.finish(stream)?, selected)),
        }
    }
}
impl Members {
    fn rows(&self) -> Vec<Selected> {
        if self.credentials.is_empty() {
            vec![Selected {
                slot: None,
                protocol: self.local.clone(),
            }]
        } else {
            self.credentials
                .rows()
                .map(|(slot, protocol)| Selected {
                    slot: Some(slot),
                    protocol: protocol.clone(),
                })
                .collect()
        }
    }
    pub fn protocols(&self) -> Vec<Arc<Protocol>> {
        self.rows().into_iter().map(|row| row.protocol).collect()
    }
    fn unique(&self, mut matches: impl FnMut(&Protocol) -> bool) -> Result<Selected> {
        let mut selected = None;
        for row in self.rows() {
            if matches(&row.protocol) {
                if selected.is_some() {
                    return Err(Error::Rejected);
                }
                selected = Some(row);
            }
        }
        selected.ok_or(Error::Rejected)
    }
    pub fn early(&self, bytes: &[u8]) -> Result<Opening> {
        if bytes.len() < 2 {
            return Err(crate::invalid());
        }
        let selected = self.unique(|protocol| handshake::starts(protocol, bytes))?;
        let prepared = EarlyServer::prepare(selected.protocol.clone(), bytes)?;
        Ok(Opening::Early { selected, prepared })
    }
    pub fn websocket(&self, auth: &str, early: Option<&[u8]>) -> Result<Opening> {
        let now = crate::wire::kip::now()?;
        let selected =
            self.unique(|protocol| crate::carrier::ws::verify(&protocol.material.seed, auth, now))?;
        match early {
            Some(bytes) => {
                let prepared = EarlyServer::prepare(selected.protocol.clone(), bytes)?;
                Ok(Opening::Early { selected, prepared })
            }
            None => Ok(Opening::Deferred(selected)),
        }
    }
    pub async fn negotiate(
        &self,
        mut raw: BoxStream,
        early: Option<Opening>,
    ) -> Result<(Negotiated, Selected)> {
        if let Some(early) = early {
            return early.finish(raw).await;
        }
        let rows = self.rows();
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let mut selected = None;
            let mut possible = false;
            for row in &rows {
                if handshake::starts(&row.protocol, &bytes) {
                    if selected.is_some() {
                        return Err(Error::Rejected);
                    }
                    selected = Some(row.clone());
                }
                possible |= handshake::possible(&row.protocol, &bytes);
            }
            if let Some(selected) = selected {
                let stream = Box::new(Prefix {
                    inner: raw,
                    bytes,
                    used: 0,
                });
                return Ok((
                    handshake::server(stream, &selected.protocol).await?,
                    selected,
                ));
            }
            if !possible || bytes.len() >= 65536 {
                return Err(Error::Rejected);
            }
            let length = chunk.len().min(65536 - bytes.len());
            let count = raw.read(&mut chunk[..length]).await?;
            if count == 0 {
                return Err(Error::Rejected);
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
    }
}
