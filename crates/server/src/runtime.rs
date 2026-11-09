use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock};

use kerlico_outbound::{Native, Outbound, WeakOutbound};
use kerlico_shared::runtime::{
    AddressFamily, HttpRequest, HttpResponse, Network, NetworkConnection, NetworkDial,
    NetworkRoute, ResolutionSource, RuntimeContext, SrvRecord,
};
use kerlico_shared::{Exit, OutboundChoice};

use crate::{dns, geodata};

pub(super) fn context(
    outbound: &Outbound,
    dns: Arc<RwLock<dns::Config>>,
    catalog: geodata::Catalog,
    landing_allowed: bool,
) -> Arc<RuntimeContext> {
    Arc::new(RuntimeContext {
        network: Arc::new(ServerNetwork {
            outbound: outbound.downgrade(),
            dns,
            landing_allowed,
        }),
        geoip: Arc::new(catalog),
    })
}

struct ServerNetwork {
    outbound: WeakOutbound,
    dns: Arc<RwLock<dns::Config>>,
    landing_allowed: bool,
}

impl std::fmt::Debug for ServerNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerNetwork")
            .field("landing_allowed", &self.landing_allowed)
            .finish_non_exhaustive()
    }
}

impl ServerNetwork {
    fn outbound(&self) -> io::Result<Outbound> {
        self.outbound.upgrade().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "server egress owner was dropped",
            )
        })
    }

    fn resolve_dial(&self, request: &NetworkDial) -> io::Result<NetworkDial> {
        let mut request = request.clone();
        if request.route == NetworkRoute::Selected(OutboundChoice::Manual(Exit::Landing)) {
            if !self.landing_allowed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "landing carrier cannot dial its own Landing exit",
                ));
            }
            return Ok(request);
        }
        if request.addresses.is_empty() {
            let family = match request.route {
                NetworkRoute::Selected(OutboundChoice::Manual(Exit::NativeV4 | Exit::WarpV4)) => {
                    Some(AddressFamily::V4)
                }
                NetworkRoute::Selected(OutboundChoice::Manual(Exit::NativeV6 | Exit::WarpV6)) => {
                    Some(AddressFamily::V6)
                }
                _ => None,
            };
            let source = if request.route == NetworkRoute::Direct {
                ResolutionSource::System
            } else {
                ResolutionSource::Configured
            };
            request.addresses = self.lookup_ip(&request.host, request.port, family, source)?;
        }
        Ok(request)
    }
}

impl Network for ServerNetwork {
    fn lookup_ip(
        &self,
        host: &str,
        port: u16,
        family: Option<AddressFamily>,
        source: ResolutionSource,
    ) -> io::Result<Vec<SocketAddr>> {
        let host = host.trim_matches(['[', ']']);
        if host.is_empty() || port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS endpoint",
            ));
        }
        let addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else if source == ResolutionSource::System {
            (host, port).to_socket_addrs()?.collect()
        } else {
            let mut config = self.dns.read().expect("DNS runtime").clone();
            config.strategy = match (config.strategy, family) {
                (dns::Strategy::UseV4, Some(AddressFamily::V6))
                | (dns::Strategy::UseV6, Some(AddressFamily::V4)) => return Ok(Vec::new()),
                (_, Some(AddressFamily::V4)) => dns::Strategy::UseV4,
                (_, Some(AddressFamily::V6)) => dns::Strategy::UseV6,
                (strategy, None) => strategy,
            };
            config
                .lookup(host, Native::detect(), &self.outbound()?)
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        };
        Ok(addresses
            .into_iter()
            .filter(|address| match family {
                None => true,
                Some(AddressFamily::V4) => address.is_ipv4(),
                Some(AddressFamily::V6) => address.is_ipv6(),
            })
            .collect())
    }

    fn lookup_srv(&self, name: &str) -> io::Result<Vec<SrvRecord>> {
        let config = self.dns.read().expect("DNS runtime").clone();
        config.lookup_srv(name, Native::detect(), &self.outbound()?)
    }
    fn lookup_txt(&self, name: &str) -> io::Result<Vec<String>> {
        let config = self.dns.read().expect("DNS runtime").clone();
        config.lookup_txt(name, Native::detect(), &self.outbound()?)
    }
    fn connect(&self, request: &NetworkDial) -> io::Result<NetworkConnection> {
        self.outbound()?
            .connect_transport(&self.resolve_dial(request)?, Native::detect())
    }
    fn open_datagram(&self, request: &NetworkDial) -> io::Result<NetworkConnection> {
        self.outbound()?.open_datagram_transport(&self.resolve_dial(request)?, Native::detect())
    }
    fn connect_unix(&self, path: &std::path::Path) -> io::Result<NetworkConnection> {
        self.outbound()?.connect_unix_transport(path)
    }
    fn exchange_dns(&self, request: &NetworkDial, message: &[u8]) -> io::Result<Vec<u8>> {
        self.outbound()?.exchange_dns_transport(
            &self.resolve_dial(request)?,
            message,
            Native::detect(),
        )
    }
    fn exchange_http(&self, request: &HttpRequest) -> io::Result<HttpResponse> {
        let mut request = request.clone();
        request.dial = self.resolve_dial(&request.dial)?;
        self.outbound()?
            .exchange_http_transport(&request, Native::detect())
    }
}

#[cfg(test)]
mod tests;
