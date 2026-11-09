mod client;
mod doh;
mod resolver;
mod server;
mod wire;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::TlsNetwork;

use super::{invalid, settings, PacketIo, UdpDial};
use resolver::ResolverConfig;
use wire::{Domain, DomainConfig};

const POLL: Duration = Duration::from_millis(50);

#[derive(Clone)]
pub(super) struct Xdns {
    domains: Arc<[Arc<Domain>]>,
    resolvers: Arc<[resolver::Config]>,
    extra_poll: u8,
    tls_network: Option<Arc<dyn TlsNetwork>>,
    carrier: Option<Arc<crate::runtime::CarrierNetwork>>,
    tls_cache: Option<Arc<crate::AdvancedTlsClientCache>>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    domains: Vec<DomainConfig>,
    resolvers: Vec<ResolverConfig>,
    extra_poll: u8,
}

impl Xdns {
    pub(super) fn set_network(&mut self, network: Arc<crate::runtime::CarrierNetwork>) { self.carrier = Some(network); }
    pub(super) fn parse(
        value: Value,
        tls_network: Option<Arc<dyn TlsNetwork>>,
        tls_cache: Option<Arc<crate::AdvancedTlsClientCache>>,
    ) -> io::Result<Self> {
        let config: Config = settings(value)?;
        if config.extra_poll > 3 {
            return Err(invalid("XDNS extraPoll must be 0 through 3"));
        }
        let mut domains = Vec::new();
        for domain in config.domains {
            domains.extend(domain.domains()?.into_iter().map(Arc::new));
        }
        if domains.is_empty() {
            return Err(invalid("XDNS requires at least one domain name"));
        }
        let mut resolvers = Vec::new();
        for resolver in config.resolvers {
            resolvers.extend(resolver.resolvers()?);
        }
        if resolvers.len() > 64 {
            return Err(invalid("XDNS supports at most 64 resolvers"));
        }
        Ok(Self {
            domains: domains.into(),
            resolvers: resolvers.into(),
            extra_poll: config.extra_poll,
            tls_network,
            carrier: None,
            tls_cache,
        })
    }

    pub(super) fn validate_client(&self) -> io::Result<()> {
        if self.resolvers.is_empty() {
            return Err(invalid("XDNS client requires at least one resolver"));
        }
        Ok(())
    }

    pub(super) fn client(&self, peer: SocketAddr, dial: UdpDial) -> io::Result<Arc<dyn PacketIo>> {
        self.validate_client()?;
        let resolvers = self
            .resolvers
            .iter()
            .map(|config| config.connect(dial.clone(), self.tls_network.clone(), self.carrier.clone(), self.tls_cache.clone()))
            .collect::<io::Result<_>>()?;
        client::open(self.domains.clone(), resolvers, self.extra_poll, peer)
    }

    pub(super) fn server(&self, inner: Arc<dyn PacketIo>) -> io::Result<Arc<dyn PacketIo>> {
        server::open(self.domains.clone(), inner)
    }
}
