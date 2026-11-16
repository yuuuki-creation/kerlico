//! ECH discovery uses the server's DNS when embedded, or OS DNS for the standalone client.

use std::io;
use std::sync::{Arc, Weak};

use kerlico_anytls::tls::{ClientTls, TlsNetwork, TlsNetworkRequest, TlsNetworkResponse};
use kerlico_shared::runtime::RuntimeContext;

#[derive(Debug)]
struct Resolver(Option<Weak<RuntimeContext>>);

pub(super) fn provider(
    tls: &ClientTls,
    runtime: &Option<Weak<RuntimeContext>>,
) -> Option<Arc<dyn TlsNetwork>> {
    tls.ech_dns_name.as_ref().map(|_| Arc::new(Resolver(runtime.clone())) as Arc<dyn TlsNetwork>)
}

impl TlsNetwork for Resolver {
    fn exchange(&self, _: &TlsNetworkRequest) -> io::Result<TlsNetworkResponse> {
        Err(io::ErrorKind::Unsupported.into())
    }

    fn exchange_configured_dns(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        if let Some(owner) = &self.0 {
            let owner = owner.upgrade().ok_or(io::ErrorKind::NotConnected)?;
            return owner.network.exchange_configured_dns(message);
        }
        kerlico_outbound::exchange_system_dns(message)
    }
}
