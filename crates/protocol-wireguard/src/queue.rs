use kerlico_core::{Error, Result};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub(crate) struct PacketBudget {
    packets: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}
pub(crate) struct PacketLease {
    _packet: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}
pub(crate) struct QueuedPacket {
    pub bytes: Vec<u8>,
    pub from_stack: bool,
    pub _lease: PacketLease,
}
impl PacketBudget {
    pub fn new(packets: usize, bytes: usize) -> Self {
        Self {
            packets: Arc::new(Semaphore::new(packets)),
            bytes: Arc::new(Semaphore::new(bytes)),
        }
    }
    pub fn reserve(&self, bytes: usize) -> Result<PacketLease> {
        let bytes = u32::try_from(bytes).map_err(|_| Error::ResourceLimit)?;
        let packet = self.packets.clone().try_acquire_owned().map_err(|_| Error::ResourceLimit)?;
        let bytes = self.bytes.clone().try_acquire_many_owned(bytes).map_err(|_| Error::ResourceLimit)?;
        Ok(PacketLease { _packet: packet, _bytes: bytes })
    }
    pub fn packet(&self, bytes: Vec<u8>, from_stack: bool) -> Result<QueuedPacket> {
        Ok(QueuedPacket { _lease: self.reserve(bytes.len())?, bytes, from_stack })
    }
}
