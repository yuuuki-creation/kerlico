use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use igd_next::{aio, PortMappingProtocol, SearchOptions};
use natpmp::{NatpmpAsync, Response};
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

use super::super::invalid;

const MAPPING: &str = "hysteria-realm";
const NAT_PMP_PORT: u16 = 5351;

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct PortMap {
    enabled: bool,
    timeout: u32,
    lifetime: u32,
}

pub(super) struct Mapping {
    external: watch::Receiver<SocketAddr>,
    _lifetime: watch::Sender<()>,
}

impl Mapping {
    pub(super) fn address(&self) -> SocketAddr {
        *self.external.borrow()
    }
}

impl PortMap {
    pub(super) async fn open(&self, local: SocketAddr) -> Option<Mapping> {
        if !self.enabled {
            return None;
        }
        let config = self.with_defaults();
        match config.acquire(local).await {
            Ok((gateway, external)) => {
                let (update, current) = watch::channel(external);
                let (close, closed) = watch::channel(());
                tokio::spawn(config.keep(gateway, external, update, closed));
                Some(Mapping {
                    external: current,
                    _lifetime: close,
                })
            }
            Err(error) => {
                eprintln!("Realm port mapping: {error}");
                None
            }
        }
    }

    fn with_defaults(&self) -> Self {
        Self {
            enabled: self.enabled,
            timeout: if self.timeout == 0 { 10 } else { self.timeout },
            lifetime: if self.lifetime == 0 {
                600
            } else {
                self.lifetime
            },
        }
    }

    async fn acquire(&self, local: SocketAddr) -> io::Result<(Gateway, SocketAddr)> {
        if !local.is_ipv4() || local.port() == 0 {
            return Err(invalid("Realm port mapping needs a bound IPv4 UDP socket"));
        }
        let limit = Duration::from_secs(u64::from(self.timeout));
        let nat = async {
            let address = natpmp::get_default_gateway().map_err(io::Error::other)?;
            let socket = UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await?;
            socket
                .connect(SocketAddr::new(address.into(), NAT_PMP_PORT))
                .await?;
            let nat = natpmp::new_natpmp_async_with(socket, address);
            let mut gateway = Gateway::NatPmp {
                nat,
                port: local.port(),
            };
            let external = gateway.renew(0, self.lifetime).await?;
            Ok::<_, io::Error>((gateway, external))
        };
        let igd = async {
            let mut options = SearchOptions::default();
            options.timeout = Some(limit);
            if !local.ip().is_unspecified() {
                options.bind_addr = SocketAddr::new(local.ip(), 0);
            }
            let igd = aio::tokio::search_gateway(options)
                .await
                .map_err(io::Error::other)?;
            let inside = if local.ip().is_unspecified() {
                let route = UdpSocket::bind("0.0.0.0:0").await?;
                route.connect(igd.addr).await?;
                SocketAddr::new(route.local_addr()?.ip(), local.port())
            } else {
                local
            };
            let mut gateway = Gateway::Upnp {
                igd: Box::new(igd),
                inside,
            };
            let external = gateway.renew(0, self.lifetime).await?;
            Ok::<_, io::Error>((gateway, external))
        };
        if let Ok(Ok(mapping)) = timeout(limit, nat).await {
            return Ok(mapping);
        }
        timeout(limit, igd)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    async fn keep(
        self,
        mut gateway: Gateway,
        mut external: SocketAddr,
        update: watch::Sender<SocketAddr>,
        mut closed: watch::Receiver<()>,
    ) {
        let limit = Duration::from_secs(u64::from(self.timeout));
        let renew = Duration::from_secs(u64::from(self.lifetime)) / 2;
        loop {
            tokio::select! {
                _ = closed.changed() => break,
                _ = sleep(renew) => {}
            }
            let result = tokio::select! {
                _ = closed.changed() => break,
                result = timeout(limit, gateway.renew(external.port(), self.lifetime)) => result,
            };
            if let Ok(Ok(address)) = result {
                external = address;
                update.send_replace(external);
            }
        }
        let _ = timeout(limit, gateway.delete(external.port())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn nat_pmp_lease_renews_and_deletes_the_mapped_udp_port() {
        crate::finalmask::http_tls::runtime()
            .unwrap()
            .block_on(async {
                let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                client.connect(server.local_addr().unwrap()).await.unwrap();
                let mock = tokio::spawn(async move {
                    let mut buf = [0; 12];
                    for (opcode, suggested, lifetime) in [
                        (0, 0u16, 0u32),
                        (1, 0, 600),
                        (0, 0, 0),
                        (1, 43210, 600),
                        (1, 0, 0),
                    ] {
                        let (len, peer) = server.recv_from(&mut buf).await.unwrap();
                        assert_eq!(&buf[..2], &[0, opcode]);
                        let mut response = vec![0, opcode | 128, 0, 0, 0, 0, 0, 1];
                        if opcode == 0 {
                            assert_eq!(len, 2);
                            response.extend([203, 0, 113, 8]);
                        } else {
                            assert_eq!(len, 12);
                            assert_eq!(&buf[4..6], &40101u16.to_be_bytes());
                            assert_eq!(&buf[6..8], &suggested.to_be_bytes());
                            assert_eq!(&buf[8..12], &lifetime.to_be_bytes());
                            response.extend(&buf[4..6]);
                            response.extend(43210u16.to_be_bytes());
                            response.extend(lifetime.to_be_bytes());
                        }
                        server.send_to(&response, peer).await.unwrap();
                    }
                });
                let nat = natpmp::new_natpmp_async_with(client, Ipv4Addr::LOCALHOST);
                let mut gateway = Gateway::NatPmp { nat, port: 40101 };
                timeout(Duration::from_secs(2), async {
                    let addr = gateway.renew(0, 600).await.unwrap();
                    assert_eq!(addr, "203.0.113.8:43210".parse().unwrap());
                    assert_eq!(gateway.renew(addr.port(), 600).await.unwrap(), addr);
                    gateway.delete(addr.port()).await.unwrap();
                    mock.await.unwrap();
                })
                .await
                .unwrap();
            });
    }

    #[tokio::test]
    async fn upnp_renews_and_deletes_the_gateway_assigned_udp_port() {
        const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let fixture = tokio::spawn(async move {
            for (action, fields) in [
                (
                    "GetExternalIPAddress",
                    "<NewExternalIPAddress>203.0.113.8</NewExternalIPAddress>",
                ),
                (
                    "AddAnyPortMapping",
                    "<NewReservedPort>43210</NewReservedPort>",
                ),
                (
                    "GetExternalIPAddress",
                    "<NewExternalIPAddress>203.0.113.8</NewExternalIPAddress>",
                ),
                ("AddPortMapping", ""),
                ("DeletePortMapping", ""),
            ] {
                let mut conn = BufReader::new(server.accept().await.unwrap().0);
                let mut header = String::new();
                loop {
                    let mut line = String::new();
                    conn.read_line(&mut line).await.unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    header.push_str(&line);
                }
                assert!(header.starts_with("POST /control HTTP/1.1\r\n"));
                assert!(header.contains(&format!("{SERVICE}#{action}")));
                let len: usize = header
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .unwrap()
                    .1
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; len];
                conn.read_exact(&mut body).await.unwrap();
                let body = std::str::from_utf8(&body).unwrap();
                if action.contains("PortMapping") {
                    assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
                    if action != "AddAnyPortMapping" {
                        assert!(body.contains("<NewExternalPort>43210</NewExternalPort>"));
                    }
                    if action.starts_with("Add") {
                        assert!(body.contains("<NewInternalPort>40101</NewInternalPort>"));
                        assert!(body.contains("<NewLeaseDuration>600</NewLeaseDuration>"));
                    }
                }
                let xml = format!(
                    r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:{action}Response xmlns:u="{SERVICE}">{fields}</u:{action}Response></s:Body></s:Envelope>"#
                );
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
                    xml.len()
                );
                conn.get_mut().write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let args = [
            "NewExternalPort",
            "NewProtocol",
            "NewInternalPort",
            "NewLeaseDuration",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let mut gateway = Gateway::Upnp {
            inside: "127.0.0.1:40101".parse().unwrap(),
            igd: Box::new(aio::Gateway {
                addr,
                root_url: "/root".into(),
                control_url: "/control".into(),
                control_schema_url: "/schema".into(),
                control_schema: HashMap::from([
                    ("AddAnyPortMapping".into(), args.clone()),
                    ("AddPortMapping".into(), args),
                    (
                        "DeletePortMapping".into(),
                        vec!["NewExternalPort".into(), "NewProtocol".into()],
                    ),
                ]),
                service_type: SERVICE.into(),
                provider: aio::tokio::Tokio,
            }),
        };
        timeout(Duration::from_secs(2), async {
            let addr = gateway.renew(0, 600).await.unwrap();
            assert_eq!(addr, "203.0.113.8:43210".parse().unwrap());
            assert_eq!(gateway.renew(addr.port(), 600).await.unwrap(), addr);
            gateway.delete(addr.port()).await.unwrap();
            fixture.await.unwrap();
        })
        .await
        .unwrap();
    }
}

enum Gateway {
    NatPmp {
        nat: NatpmpAsync<UdpSocket>,
        port: u16,
    },
    Upnp {
        igd: Box<aio::Gateway<aio::tokio::Tokio>>,
        inside: SocketAddr,
    },
}

impl Gateway {
    async fn renew(&mut self, external: u16, lifetime: u32) -> io::Result<SocketAddr> {
        let usable_ip = |ip: IpAddr| {
            let ip = ip.to_canonical();
            if ip.is_unspecified() || ip.is_loopback() {
                return Err(invalid("Realm gateway returned an unusable external IP"));
            }
            Ok(ip)
        };
        let (ip, port) = match self {
            Gateway::NatPmp { nat, port } => {
                nat.send_public_address_request()
                    .await
                    .map_err(io::Error::other)?;
                let Response::Gateway(reply) = nat
                    .read_response_or_retry()
                    .await
                    .map_err(io::Error::other)?
                else {
                    return Err(invalid("NAT-PMP external address response"));
                };
                let ip = usable_ip((*reply.public_address()).into())?;
                nat.send_port_mapping_request(natpmp::Protocol::UDP, *port, external, lifetime)
                    .await
                    .map_err(io::Error::other)?;
                let Response::UDP(reply) = nat
                    .read_response_or_retry()
                    .await
                    .map_err(io::Error::other)?
                else {
                    return Err(invalid("NAT-PMP UDP lease response"));
                };
                if reply.private_port() != *port {
                    return Err(invalid("NAT-PMP UDP lease port mismatch"));
                }
                (ip, reply.public_port())
            }
            Gateway::Upnp { igd, inside } => {
                let ip = usable_ip(igd.get_external_ip().await.map_err(io::Error::other)?)?;
                let port = if external == 0 {
                    igd.add_any_port(PortMappingProtocol::UDP, *inside, lifetime, MAPPING)
                        .await
                        .map_err(io::Error::other)?
                } else {
                    igd.add_port(
                        PortMappingProtocol::UDP,
                        external,
                        *inside,
                        lifetime,
                        MAPPING,
                    )
                    .await
                    .map_err(io::Error::other)?;
                    external
                };
                (ip, port)
            }
        };
        if port == 0 {
            return Err(invalid("Realm gateway returned an unusable mapping"));
        }
        Ok(SocketAddr::new(ip, port))
    }

    async fn delete(&self, external: u16) -> io::Result<()> {
        match self {
            Gateway::NatPmp { nat, port } => {
                nat.send_port_mapping_request(natpmp::Protocol::UDP, *port, 0, 0)
                    .await
                    .map_err(io::Error::other)?;
                let _ = nat
                    .read_response_or_retry()
                    .await
                    .map_err(io::Error::other)?;
                Ok(())
            }
            Gateway::Upnp { igd, .. } => igd
                .remove_port(PortMappingProtocol::UDP, external)
                .await
                .map_err(io::Error::other),
        }
    }
}
