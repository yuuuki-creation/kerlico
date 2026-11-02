use kerlico_core::{IngressBinding, ServiceContext};

#[derive(Clone)]
pub(crate) enum Carrier {
    Outbound(ServiceContext),
    Node(IngressBinding),
}
impl Carrier {
    pub fn record(&self, sent: usize, received: usize) {
        match self {
            Self::Outbound(owner) => owner.record_carrier(sent as u64, received as u64),
            Self::Node(owner) => owner.record_carrier(sent as u64, received as u64),
        }
    }
}
