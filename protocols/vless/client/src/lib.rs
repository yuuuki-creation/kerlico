mod mux;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use kerlico_shared::runtime::NetworkConnection;
use kerlico_vless::runtime::CarrierNetwork;
use kerlico_vless::socket::{AddressFamily, ResolutionSource, SocketKind, SocketOptions, SocketRole, TransportResolver};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use kerlico_shared::{
    DataPlane, Destination, InboundStream, OpenError, Packet, PeerAddr, PlaneFault, Settings, Transport,
};
use kerlico_vless::{
    client_config, client_key, client_keys, connect_native, connect_tls, decode_reality_key, decode_short_id, decode_udp, encode_request, encode_udp, encode_mux, decode_mux, reality_offer_hybrid, reality_reader, reality_writer, take_flight, AppReader, AppWriter, EncReader, EncWriter, RealityDuplex,
    grpc_path, normalize_path, parse_id, Addr, Command, Request, TlsLink,
    Vision, GrpcConnection, GrpcStream, HttpIo, H2Conn, H2Stream, KcpIo, read_packet_ack, read_response_head,
    ChunkReader, ChunkPair, MuxFrame, DATA, KEEP, NEW,
    XhttpBodyWriter, XhttpConfig, XhttpMode, XhttpRequest, XhttpRequestKind,
    HttpPrefaceRead, RawHttpConfig, UpgradeConfig, UpgradeRead, UpgradeWrite, upgrade_pair,
};

pub fn connect(
    _peer: &PeerAddr,
    _settings: &Settings,
) -> Result<Box<dyn DataPlane>, OpenError> {
    Err(OpenError::Settings)
}

pub fn land(
    host: &str,
    port: u16,
    settings: &Settings,
    destination: &Destination,
) -> Result<Box<dyn InboundStream>, OpenError> {
    Ok(match open(host, port, settings, destination)? {
        Opened::Relay(relay) => Box::new(relay),
        Opened::Mux(session) => Box::new(session),
        Opened::Reverse(bridge) => Box::new(Bridge::from_reverse(bridge)),
    })
}

/// Opens a UDP flow whose datagrams may each go to a different destination, as Xray carries
/// a SOCKS or TUN UDP association.
pub fn land_udp(host: &str, port: u16, settings: &Settings, first: &Destination) -> Result<UdpSession, OpenError> {
    if first.transport() != Transport::Udp {
        return Err(OpenError::Settings);
    }
    let carrier = match open(host, port, settings, first)? {
        Opened::Relay(relay) => UdpCarrier::Plain(relay),
        Opened::Mux(session) => UdpCarrier::Mux(session),
        Opened::Reverse(_) => return Err(OpenError::Settings),
    };
    Ok(UdpSession { first: first.clone(), carrier })
}

/// Datagrams to many destinations on one landing UDP flow. An XUDP or Mux session names the
/// destination of every datagram. The plain UDP command, which Xray keeps for ports 53 and
/// 443 without Vision or Mux, reaches only the first destination.
pub struct UdpSession {
    first: Destination,
    carrier: UdpCarrier,
}

enum UdpCarrier {
    Plain(Relay),
    Mux(mux::Session),
}

impl UdpSession {
    pub fn send_to(&self, destination: &Destination, datagram: &[u8]) -> Result<usize, PlaneFault> {
        match &self.carrier {
            UdpCarrier::Mux(session) => {
                let target = mux::target(destination).map_err(|_| PlaneFault::Transport)?;
                session.send_datagram(datagram, Some(&target))
            }
            UdpCarrier::Plain(relay) if destination.host() == self.first.host() && destination.port() == self.first.port() => {
                relay.write_to_user(datagram)
            }
            UdpCarrier::Plain(_) => Err(PlaneFault::Transport),
        }
    }

    /// The source is the first destination when the server names none.
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Destination), PlaneFault> {
        match &self.carrier {
            UdpCarrier::Mux(session) => {
                let (n, source) = session.recv_datagram(buf)?;
                let source = source.and_then(|(address, port)| reverse_destination(Some(&address), port, 2).ok());
                Ok((n, source.unwrap_or_else(|| self.first.clone())))
            }
            UdpCarrier::Plain(relay) => Ok((relay.read_from_user(buf)?, self.first.clone())),
        }
    }
}

/// Accepts reverse requests on the same VLESS carriers used by `land`.
pub fn reverse_bridge(host: &str, port: u16, settings: &Settings) -> Result<ReverseBridge, OpenError> {
    let destination = Destination::new("v1.rvs.cool", 1, Transport::Tcp).map_err(|_| OpenError::Settings)?;
    let (read, write) = dial(host, port, settings, Flow::parse(settings)?, Command::Reverse, &destination)?;
    Ok(ReverseBridge::new(read, write, Vec::new()))
}

enum Opened {
    Relay(Relay),
    Mux(mux::Session),
    Reverse(ReverseBridge),
}

fn open(host: &str, port: u16, settings: &Settings, destination: &Destination) -> Result<Opened, OpenError> {
    let flow = Flow::parse(settings)?;
    let connect = |command| dial(host, port, settings, flow, command, destination);
    if settings.text("reverse").is_ok_and(|text| !text.is_empty() && text != "false") {
        let (read, write) = connect(Command::Reverse)?;
        return Ok(Opened::Reverse(ReverseBridge::new(read, write, Vec::new())));
    }
    let policy = mux::Policy::parse(settings, settings.text("network").ok() == Some("xdrive"))?;
    Ok(match mux::route(flow, policy, destination)? {
        mux::Route::Direct(command) => {
            let (read, write) = connect(command)?;
            Opened::Relay(Relay::new(read, write, command == Command::Udp))
        }
        mux::Route::Xudp => Opened::Mux(mux::Session::xudp(connect(Command::Mux)?, destination)?),
        mux::Route::Pooled(kind, concurrency) => Opened::Mux(
            mux::pool(host, port, settings)?.session(kind, concurrency, destination, || connect(Command::Mux))?,
        ),
    })
}

/// The landing's VLESS flow. The `-udp443` suffix stays local: it only lets Vision send UDP/443.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Plain,
    Vision { udp443: bool },
}

impl Flow {
    fn parse(settings: &Settings) -> Result<Self, OpenError> {
        match settings.text("flow") {
            Err(_) | Ok("") => Ok(Self::Plain),
            Ok("xtls-rprx-vision") => Ok(Self::Vision { udp443: false }),
            Ok("xtls-rprx-vision-udp443") => Ok(Self::Vision { udp443: true }),
            Ok(_) => Err(OpenError::Settings),
        }
    }

    fn vision(self) -> bool {
        matches!(self, Self::Vision { .. })
    }
}

/// Dials one VLESS carrier and sends its request. Vision wraps the carrier when the flow asks.
fn dial(host: &str, port: u16, settings: &Settings, flow: Flow, command: Command, destination: &Destination) -> Result<(Link, Link), OpenError> {
    let encryption = settings.text("encryption")?;
    let native = if encryption == "none" {
        None
    } else {
        Some(client_key(encryption).ok_or(OpenError::Settings)?)
    };
    let xdrive = settings.text("network").ok() == Some("xdrive");
    let hysteria = settings.text("network").ok() == Some("hysteria");
    let (upgrade, websocket, grpc, http, mkcp, xhttp) = match settings.text("network") {
        Err(_) | Ok("tcp") | Ok("raw") => (false, false, false, false, false, false),
        Ok("httpupgrade") => (true, false, false, false, false, false),
        Ok("ws") | Ok("websocket") => (true, true, false, false, false, false),
        Ok("grpc") => (false, false, true, false, false, false),
        Ok("http") => (false, false, false, true, false, false),
        Ok("mkcp") | Ok("kcp") => (false, false, false, false, true, false),
        Ok("xhttp") | Ok("splithttp") => (false, false, false, false, false, true),
        Ok("xdrive") | Ok("hysteria") => (false, false, false, false, false, false),
        Ok(_) => return Err(OpenError::Settings),
    };
    let raw_http = if matches!(settings.text("network").unwrap_or("tcp"), "tcp" | "raw") {
        RawHttpConfig::parse(settings.text("header").ok()).map_err(|_| OpenError::Settings)?
    } else {
        None
    };
    let upgrade_config = if upgrade {
        Some(UpgradeConfig::new(
            websocket,
            settings.text("path").unwrap_or("/"),
            settings.text("host").unwrap_or_default(),
            settings.text("serverName").unwrap_or(host),
            settings.text("headers").ok(),
        ).map_err(|_| OpenError::Settings)?)
    } else {
        None
    };
    let reality = if settings.text("security").ok() == Some("reality") {
        if upgrade || websocket || http || mkcp || xdrive || hysteria {
            return Err(OpenError::Settings);
        }
        let public = decode_reality_key(settings.text("publicKey")?).ok_or(OpenError::Settings)?;
        let short_id = decode_short_id(settings.text("shortId").unwrap_or("")).ok_or(OpenError::Settings)?;
        Some((public, short_id))
    } else {
        None
    };
    let security = match settings.text("security") {
        Err(_) | Ok("none") | Ok("reality") => false,
        Ok("tls") => true,
        Ok(_) => return Err(OpenError::Settings),
    };
    let id = parse_id(settings.text("id")?).map_err(|_| OpenError::Settings)?;
    let address = parse_addr(destination.host())?;
    let vision = flow.vision();
    if xdrive && (native.is_none() || vision) { return Err(OpenError::Settings); }
    if hysteria && (!security || settings.text("version").unwrap_or("2") != "2") { return Err(OpenError::Settings); }
    if vision && native.is_none() && !(security || reality.is_some()) {
        return Err(OpenError::Settings);
    }
    if vision && native.is_none() && (upgrade || grpc || http || xhttp || hysteria || raw_http.is_some()) {
        return Err(OpenError::Settings);
    }
    // Mux and Reverse requests end at the command, so the target below only reaches the wire for TCP and UDP.
    let request = encode_request(&Request {
        id,
        flow: if vision { "xtls-rprx-vision".to_string() } else { String::new() },
        seed: Vec::new(),
        command,
        port: destination.port(),
        address,
    })
    .map_err(|_| OpenError::Settings)?;
    let (mut read, mut write) = if xdrive {
        let options = kerlico_vless::xdrive::XdriveHttpOptions {
            tls: if security { Some(tls_config(settings)?) } else { None },
            quic: if security && alpn(settings) == ["h3"] { Some(quic_tls_config(settings)?) } else { None },
            masks: final_masks(settings)?,
            server_name: settings.text("serverName").ok().map(str::to_string),
            connect_to: settings.text("storageAddress").ok().map(|address| (address.to_string(), settings.text("storagePort").unwrap_or("0").parse().unwrap_or(0))),
        };
        let drive = if let Ok(config) = settings.text("xdriveSettings") {
            kerlico_vless::xdrive::Xdrive::new(config, options)
        } else if settings.text("service").ok() == Some("local") {
            kerlico_vless::xdrive::Xdrive::local(settings.text("remoteFolder")?)
        } else { return Err(OpenError::Settings); }.map_err(|_| OpenError::Settings)?;
        let (read, write) = drive.dial().map_err(|_| OpenError::Transport)?;
        (Link::XdriveRead(read), Link::XdriveWrite(write))
    } else if hysteria {
        let masks = final_masks(settings)?;
        let options = SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?;
        let network = carrier_network(settings, options.clone());
        let (endpoint, masks, _) = udp_endpoint(host, port, network.as_deref(), &options, &masks).map_err(|_| OpenError::Transport)?;
        let (read, write) = kerlico_vless::connect_hysteria_crypto_masked(endpoint, quic_tls_config(settings)?, settings.text("serverName").unwrap_or(host), settings.text("auth")?, &masks).map_err(|_| OpenError::Transport)?;
        (Link::HysteriaRead(read), Link::HysteriaWrite(write))
    } else if xhttp {
        let (read, write) = open_xhttp(host, port, settings, reality, security)?;
        (read, write)
    } else if mkcp {
        let mask = kerlico_vless::kcp_mask(settings.text("header").unwrap_or("none"), settings.text("domain").unwrap_or(""), settings.text("seed").unwrap_or("")).ok_or(OpenError::Settings)?;
        let masks = final_masks(settings)?;
        let options = kerlico_vless::KcpOptions::from_settings(|key| settings.text(key).ok())
            .map_err(|_| OpenError::Settings)?;
        let socket_options = SocketOptions::parse(settings.text("sockopt").ok())
            .map_err(|_| OpenError::Settings)?;
        let network = carrier_network(settings, socket_options.clone());
        let (peer, masks, synthetic) = udp_endpoint(host, port, network.as_deref(), &socket_options, &masks).map_err(|_| OpenError::Transport)?;
        let network = masks.network().cloned();
        let socket = masks.udp_client(peer, move |actual| {
            if let Some(network) = &network {
                return network.packet_with_timeout(actual, options.poll_interval());
            }
            let socket = socket_options.open(SocketKind::Udp, SocketRole::Dialer, actual)?;
            let local: std::net::SocketAddr = if actual.is_ipv6() {
                (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
            } else {
                (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
            };
            socket.bind(&local.into())?;
            let socket: std::net::UdpSocket = socket.into();
            socket.set_read_timeout(Some(options.poll_interval()))?;
            socket.set_write_timeout(Some(Duration::from_millis(200)))?;
            Ok(Arc::new(socket))
        }).map_err(|_| OpenError::Transport)?;
        let io = Arc::new(KcpIo::from_packets(socket, peer, mask, options).map_err(|_| OpenError::Transport)?);
        if !security && native.is_none() && settings.text("trusted").ok() != Some("true") && (synthetic || !masks.preserves_peer_address() || !kerlico_vless::private_peer(peer.ip())) { return Err(OpenError::Settings); }
        let read = Link::Kcp(io.clone());
        let write = Link::Kcp(io);
        let (read, write) = if security { tls_pair(read, write, settings, host)? } else { (read, write) };
        (read, write)
    } else {
        let dial = || {
            let options = SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?;
            let carrier = carrier_network(settings, options.clone());
            let tcp = dial_carrier(host, port, carrier.as_deref(), &options).map_err(|_| OpenError::Transport)?;
            let peer = carrier_peer(&tcp, host, port).map_err(|_| OpenError::Transport)?;
            if !security && reality.is_none() && native.is_none() && settings.text("trusted").ok() != Some("true") && (peer.ip().is_unspecified() || !kerlico_vless::private_peer(peer.ip())) { return Err(OpenError::Settings); }
            let masks = final_masks(settings)?;
            let (read, write) = carrier_pair(tcp, &masks, peer).map_err(|_| OpenError::Transport)?;
            let (mut read, mut write) = if security { tls_pair(read, write, settings, host)? } else { (read, write) };
            if grpc && matches!(&read, Link::TlsRead(tls) if tls.alpn().as_deref().is_some_and(|alpn| alpn != b"h2")) {
                return Err(OpenError::Transport);
            }
            read.set_timeout(Duration::from_secs(10));
            if let Some(config) = upgrade_config {
                let (reader, writer) = upgrade_pair(Box::new(read), Box::new(write), config);
                read = Link::UpgradeRead(Box::new(reader));
                write = Link::UpgradeWrite(Box::new(writer));
            }
            if let Some((public, short_id)) = reality {
                let name = settings.text("serverName").unwrap_or(host);
                let names = reality_alpn(settings);
                let proof = reality_proof(settings)?;
                let offer = kerlico_vless::reality_offer_fingerprint(&public, &short_id, name, &names, settings.text("fingerprint").unwrap_or("chrome")).map_err(|_| OpenError::Settings)?;
                let spider = kerlico_vless::RealitySpiderConfig::parse(settings.text("spiderX").unwrap_or("")).map_err(|_| OpenError::Settings)?;
                let (new_read, new_write, selected) = authenticate_reality(read, write, &offer, name, &public, proof.as_ref(), &spider).map_err(|_| OpenError::Transport)?;
                // Xray runs gRPC over the authenticated REALITY stream using HTTP/2
                // prior knowledge when the server flight omits ALPN.
                if grpc && selected.as_deref().is_some_and(|protocol| protocol != b"h2") {
                    return Err(OpenError::Transport);
                }
                read = new_read;
                write = new_write;
            }
            if let Some(config) = raw_http {
                let (reader, writer) = config.connect(Box::new(read), Box::new(write)).map_err(|_| OpenError::Transport)?;
                read = Link::HttpPrefaceRead(Box::new(reader));
                write = *writer;
            }
            Ok((read, write))
        };
        if grpc {
            open_grpc(host, port, settings, security, reality.is_some(), dial)?
        } else {
            let (mut read, mut write) = dial()?;
            if http {
                let authority = settings
                    .text("host")
                    .unwrap_or_else(|_| settings.text("serverName").unwrap_or(host))
                    .to_string();
                let path = normalize_path(settings.text("path").unwrap_or("/"));
                let method = settings.text("method").unwrap_or("POST").to_string();
                let scheme = if security { "https" } else { "http" };
                let session = HttpIo::offer(Link::Duplex(Box::new(read), Box::new(write)), &authority, &path, &method, scheme, &[]).map_err(|_| OpenError::Transport)?;
                let shared = Arc::new(session.into_shared(split_duplex));
                read = Link::Http(shared.clone());
                write = Link::Http(shared);
            }
            (read, write)
        }
    };
    if let Some((public, mode, reuse, pad)) = native {
        let (reader, writer) = kerlico_vless::connect_encrypted(Box::new(read), Box::new(write), &public, mode, reuse == 1, &pad).map_err(|_| OpenError::Transport)?;
        read = Link::EncRead(Box::new(reader));
        write = Link::EncWrite(Box::new(writer));
    }
    if vision && !read.supports_vision() { return Err(OpenError::Settings); }
    write.write_all(&request).map_err(|_| OpenError::Transport)?;
    read = Link::Response(Box::new(kerlico_vless::ResponseReader::new(read)));
    if vision {
        let (reader, writer) = kerlico_vless::vision_pair(read, write, id, &[]).map_err(|_| OpenError::Transport)?;
        read = Link::Vision(Box::new(reader));
        write = Link::Vision(Box::new(writer));
    }
    Ok((read, write))
}

struct GrpcChannel {
    host: String,
    port: u16,
    settings: Settings,
    connection: Mutex<Option<Arc<GrpcConnection<Link>>>>,
}

fn grpc_channel(host: &str, port: u16, settings: &Settings) -> Arc<GrpcChannel> {
    const CHANNEL_LIMIT: usize = 16;
    static CHANNELS: OnceLock<Mutex<VecDeque<Arc<GrpcChannel>>>> = OnceLock::new();
    let mut channels = CHANNELS.get_or_init(Mutex::default).lock().expect("gRPC pool");
    let channel = match channels.iter().position(|channel| channel.host == host && channel.port == port && channel.settings == *settings) {
        Some(index) => channels.remove(index).expect("gRPC channel"),
        None => Arc::new(GrpcChannel { host: host.into(), port, settings: settings.clone(), connection: Mutex::new(None) }),
    };
    channels.push_back(Arc::clone(&channel));
    if channels.len() > CHANNEL_LIMIT {
        channels.pop_front();
    }
    channel
}

fn open_grpc(
    host: &str,
    port: u16,
    settings: &Settings,
    tls: bool,
    reality: bool,
    dial: impl FnOnce() -> Result<(Link, Link), OpenError>,
) -> Result<(Link, Link), OpenError> {
    let text = |name| settings.text(name).ok().filter(|value| !value.is_empty());
    let authority = text("authority").or_else(|| text("host"))
        .or_else(|| tls.then(|| text("serverName")).flatten())
        .map(str::to_owned)
        .unwrap_or_else(|| match host.parse() {
            Ok(ip) => std::net::SocketAddr::new(ip, port).to_string(),
            Err(_) if reality => format!("{host}:{port}"),
            Err(_) => host.to_owned(),
        });
    let path = grpc_path(
        settings.text("serviceName").unwrap_or(""),
        settings.text("multiMode").unwrap_or("false") == "true",
    );
    let channel = grpc_channel(host, port, settings);
    let mut dial = Some(dial);
    loop {
        let connection = {
            let mut current = channel.connection.lock().expect("gRPC channel");
            if current.as_ref().is_none_or(|connection| !connection.is_open()) {
                let options = kerlico_vless::GrpcOptions::parse(|name| settings.text(name).ok(), false).map_err(|_| OpenError::Settings)?;
                let (mut read, mut write) = dial.take().ok_or(OpenError::Transport)?()?;
                read.set_timeout(Duration::from_millis(200));
                write.set_timeout(Duration::from_millis(200));
                *current = Some(Arc::new(GrpcConnection::connect_with(read, write, options).map_err(|_| OpenError::Transport)?));
            }
            Arc::clone(current.as_ref().expect("gRPC connection"))
        };
        match connection.open(&authority, &path, if tls || reality { "https" } else { "http" }) {
            Ok(stream) => {
                let stream = Arc::new(stream);
                return Ok((Link::Grpc(Arc::clone(&stream)), Link::Grpc(stream)));
            }
            // Reconnect before sending a VLESS request when the peer is draining.
            Err(_) if dial.is_some() && !connection.is_open() => {}
            Err(_) => return Err(OpenError::Transport),
        }
    }
}

fn split_duplex(link: Link) -> (Link, Link) {
    let Link::Duplex(read, write) = link else { unreachable!("duplex transport") };
    (*read, *write)
}

fn tls_pair(read: Link, write: Link, settings: &Settings, host: &str) -> Result<(Link, Link), OpenError> {
    let name = settings.text("serverName").unwrap_or(host);
    let config = tls_config(settings)?;
    let (read, write) = kerlico_vless::connect_advanced_tls_over(Box::new(read), Box::new(write), config, name).map_err(|_| OpenError::Transport)?;
    Ok((Link::TlsRead(Box::new(read)), Link::TlsWrite(Box::new(write))))
}

fn authenticate_reality(mut read: Link, mut write: Link, offer: &kerlico_vless::RealityOffer, name: &str, public: &[u8; 32], proof: Option<&kerlico_vless::RealityMldsa65Verifier>, spider: &kerlico_vless::RealitySpiderConfig) -> std::io::Result<(Link, Link, Option<Vec<u8>>)> {
    static ROOTS: OnceLock<Result<kerlico_vless::RealityDecoyVerifier, String>> = OnceLock::new();
    let roots = ROOTS.get_or_init(|| kerlico_vless::RealityDecoyVerifier::system_roots().map_err(|error| error.to_string())).as_ref().map_err(|error| std::io::Error::other(error.clone()))?;
    write.write_all(&offer.record)?;
    let (flight, decoy) = match kerlico_vless::read_server_flight_or_decoy(&mut read, offer, public, proof, roots, name)? {
        kerlico_vless::RealityClientResult::Verified(flight) => (flight, false),
        kerlico_vless::RealityClientResult::Decoy(flight) => (flight, true),
    };
    write.write_all(&flight.finished)?;
    let read = Link::RealityRead(reality_reader(Box::new(read), flight.read));
    let write = Link::RealityWrite(reality_writer(Box::new(write), flight.write));
    if decoy {
        let delay = spider.return_delay()?;
        if flight.alpn.as_deref() == Some(b"h2") {
            let name = name.to_owned();
            let spider = spider.clone();
            std::thread::spawn(move || { let _ = kerlico_vless::run_reality_spider(read, write, &name, &spider); });
        }
        std::thread::sleep(delay);
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "REALITY authentication failed"));
    }
    Ok((read, write, flight.alpn))
}

fn tls_options(settings: &Settings) -> Result<kerlico_vless::AdvancedTlsOptions, OpenError> {
    let mut options = kerlico_vless::AdvancedTlsOptions::from_settings(|key| settings.text(key).ok(), alpn(settings)).map_err(|_| OpenError::Settings)?;
    options.network_provider = settings.runtime().map(|context| kerlico_vless::runtime::owner_tls(context).network.clone());
    Ok(options)
}

fn tls_config(settings: &Settings) -> Result<Arc<kerlico_vless::AdvancedTlsClientConfig>, OpenError> {
    let options = tls_options(settings)?;
    match settings.runtime() {
        Some(context) => kerlico_vless::runtime::owner_tls(context).cache.get(&options),
        None => default_tls_cache().get(&options),
    }.map_err(|_| OpenError::Settings)
}

fn default_tls_cache() -> &'static kerlico_vless::AdvancedTlsClientCache {
    static CACHE: OnceLock<kerlico_vless::AdvancedTlsClientCache> = OnceLock::new();
    CACHE.get_or_init(kerlico_vless::AdvancedTlsClientCache::new)
}

fn final_masks(settings: &Settings) -> Result<kerlico_vless::finalmask::FinalMask, OpenError> {
    let provider = settings.runtime().map(|context| kerlico_vless::runtime::owner_tls(context).network.clone());
    let masks = kerlico_vless::runtime::parse_finalmask(settings.text("finalmask").unwrap_or("{}"), settings.runtime(), provider).map_err(|_| OpenError::Settings)?;
    let options = SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?;
    Ok(match carrier_network(settings, options) { Some(network) => masks.with_network(network), None => masks })
}

fn carrier_network(settings: &Settings, options: SocketOptions) -> Option<Arc<CarrierNetwork>> {
    settings.runtime().map(|context| Arc::new(CarrierNetwork::new(context.network.clone(), options)))
}

struct SystemResolver;
impl TransportResolver for SystemResolver {
    fn lookup_ip(&self, host: &str, port: u16, family: Option<AddressFamily>, source: ResolutionSource) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        if source == ResolutionSource::Configured { return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "configured DNS requires the server runtime")); }
        Ok((host, port).to_socket_addrs()?.filter(|addr| family.is_none_or(|family| addr.is_ipv4() == (family == AddressFamily::V4))).collect())
    }
}

fn dial_carrier(host: &str, port: u16, network: Option<&CarrierNetwork>, options: &SocketOptions) -> std::io::Result<NetworkConnection> {
    if let Some(network) = network { return network.tcp(host, port); }
    let plan = options.plan(host, port, SocketKind::Tcp, None, &SystemResolver)?.direct()?;
    let mut last = std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "carrier resolved no address");
    for &peer in plan.addresses() {
        let socket = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
        match socket.connect_timeout(&peer.into(), Duration::from_secs(10)) {
            Ok(()) => return Ok(NetworkConnection::Tcp(socket.into())),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn carrier_peer(connection: &NetworkConnection, host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    match connection {
        NetworkConnection::Tcp(socket) => socket.peer_addr(),
        NetworkConnection::Udp(_) => Err(std::io::ErrorKind::InvalidInput.into()),
        NetworkConnection::Stream(_) => Ok(std::net::SocketAddr::new(host.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into()), port)),
    }
}

fn carrier_pair(mut connection: NetworkConnection, masks: &kerlico_vless::finalmask::FinalMask, peer: std::net::SocketAddr) -> std::io::Result<(Link, Link)> {
    connection.set_timeout(Duration::from_secs(10))?;
    let (read, write) = kerlico_vless::mask_network(connection, masks, peer)?;
    Ok((Link::MaskedRead(read), Link::MaskedWrite(write)))
}

fn udp_endpoint(host: &str, port: u16, network: Option<&CarrierNetwork>, options: &SocketOptions, masks: &kerlico_vless::finalmask::FinalMask) -> std::io::Result<(std::net::SocketAddr, kerlico_vless::finalmask::FinalMask, bool)> {
    match network {
        Some(network) => {
            let (network, peer) = network.endpoint(host, port)?;
            let synthetic = network.peer_is_synthetic(peer);
            Ok((peer, masks.clone().with_network(network), synthetic))
        }
        None => {
            let plan = options.plan(host, port, SocketKind::Udp, None, &SystemResolver)?.direct()?;
            let peer = plan.addresses().first().copied().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "UDP carrier resolved no address"))?;
            Ok((peer, masks.clone(), false))
        }
    }
}

fn quic_tls_config(settings: &Settings) -> Result<kerlico_vless::QuicClientCrypto, OpenError> {
    let mut options = tls_options(settings)?;
    options.alpn = vec!["h3".into()];
    let masks = final_masks(settings)?;
    let quic = kerlico_vless::QuicOptions::parse(masks.quic_params()).map_err(|_| OpenError::Settings)?;
    match settings.runtime() {
        Some(context) => kerlico_vless::runtime::owner_tls(context).cache.quic(&options, quic.chrome_parrot(true)),
        None => default_tls_cache().quic(&options, quic.chrome_parrot(true)),
    }.map_err(|_| OpenError::Settings)
}

fn parse_addr(host: &str) -> Result<Addr, OpenError> {
    if let Ok(ip) = host.parse() {
        return Ok(Addr::V4(ip));
    }
    if let Ok(ip) = host.parse() {
        return Ok(Addr::V6(ip));
    }
    if host.is_empty() || host.len() > 255 {
        return Err(OpenError::Settings);
    }
    Ok(Addr::Domain(host.to_string()))
}

enum Link {
    Leased(Box<Link>, Arc<Vec<XhttpLease>>),
    MaskedRead(kerlico_vless::MaskedRead),
    MaskedWrite(kerlico_vless::MaskedWrite),
    XdriveRead(kerlico_vless::xdrive::XdriveRead),
    XdriveWrite(kerlico_vless::xdrive::XdriveWrite),
    HysteriaRead(kerlico_vless::HysteriaRead),
    HysteriaWrite(kerlico_vless::HysteriaWrite),
    H3(Arc<kerlico_vless::H3Stream>),
    Tcp(TcpStream),
    TlsRead(Box<kerlico_vless::AdvancedTlsRead<Box<Link>>>),
    TlsWrite(Box<kerlico_vless::AdvancedTlsWrite<Box<Link>>>),
    HttpPrefaceRead(Box<HttpPrefaceRead<Box<Link>>>),
    UpgradeRead(Box<UpgradeRead<Box<Link>, Box<Link>>>),
    UpgradeWrite(Box<UpgradeWrite<Box<Link>, Box<Link>>>),
    Grpc(Arc<GrpcStream<Link>>),
    Http(Arc<kerlico_vless::SharedHttp<Link, Link>>),
    Kcp(Arc<KcpIo>),
    Xhttp(Arc<XhttpClient>),
    Chunks(Arc<ChunkPair>),
    EncRead(Box<EncReader<Box<Link>>>),
    EncWrite(Box<EncWriter<Box<Link>>>),
    RealityRead(AppReader<Box<Link>>),
    RealityWrite(AppWriter<Box<Link>>),
    Duplex(Box<Link>, Box<Link>),
    Response(Box<kerlico_vless::ResponseReader<Link>>),
    Vision(Box<kerlico_vless::VisionIo<Link>>),
    H2(Arc<H2Stream<Link>>),
}

struct HttpLink { read: Link, write: Link, h2: bool }

impl HttpLink {
    fn h2(&self) -> bool { self.h2 }
    fn split(self) -> std::io::Result<(Link, Link)> { Ok((self.read, self.write)) }
}
impl Read for HttpLink {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> { self.read.read(buf) }
}
impl Write for HttpLink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.write.write(buf) }
    fn flush(&mut self) -> std::io::Result<()> { self.write.flush() }
}

fn tcp_pair(socket: TcpStream, masks: &kerlico_vless::finalmask::FinalMask) -> std::io::Result<(Link, Link)> {
    if masks.has_tcp() {
        let (read, write) = kerlico_vless::mask_tcp(socket, masks, kerlico_vless::finalmask::Side::Client)?;
        Ok((Link::MaskedRead(read), Link::MaskedWrite(write)))
    } else { Ok((Link::Tcp(socket.try_clone()?), Link::Tcp(socket))) }
}

struct HttpDial {
    network: Option<Arc<CarrierNetwork>>,
    socket_options: SocketOptions,
    masks: kerlico_vless::finalmask::FinalMask,
    host: String,
    port: u16,
    name: String,
    tls: Option<Arc<kerlico_vless::AdvancedTlsClientConfig>>,
    quic: Option<kerlico_vless::QuicClientCrypto>,
    fingerprint: String,
    reality: Option<([u8; 32], [u8; 8])>,
    proof: Option<kerlico_vless::RealityMldsa65Verifier>,
    spider: kerlico_vless::RealitySpiderConfig,
    allow_plain: bool,
}

impl HttpDial {
    fn connect(&self) -> std::io::Result<HttpLink> {
        let socket = dial_carrier(&self.host, self.port, self.network.as_deref(), &self.socket_options)?;
        let peer = carrier_peer(&socket, &self.host, self.port)?;
        if self.tls.is_none()
            && self.reality.is_none()
            && !self.allow_plain
            && (peer.ip().is_unspecified() || !kerlico_vless::private_peer(peer.ip()))
        {
            return Err(std::io::Error::other(
                "public plaintext VLESS requires a trusted link or encryption",
            ));
        }
        let (mut read, mut write) = carrier_pair(socket, &self.masks, peer)?;
        if let Some(config) = &self.tls {
            let (read, write) = kerlico_vless::connect_advanced_tls_over(Box::new(read), Box::new(write), config.clone(), &self.name)?;
            let h2 = read.alpn().as_deref() == Some(b"h2");
            return Ok(HttpLink { read: Link::TlsRead(Box::new(read)), write: Link::TlsWrite(Box::new(write)), h2 });
        }
        let Some((public, short_id)) = &self.reality else { return Ok(HttpLink { read, write, h2: false }); };
        let offer = kerlico_vless::reality_offer_fingerprint(public, short_id, &self.name, &["h2".into()], &self.fingerprint)?;
        let (read, write, selected) = authenticate_reality(read, write, &offer, &self.name, public, self.proof.as_ref(), &self.spider)?;
        // Xray uses an HTTP/2 preface over REALITY even when the authenticated
        // server flight carries no ALPN extension.
        if selected
            .as_deref()
            .is_some_and(|protocol| protocol != b"h2")
        {
            return Err(std::io::Error::other("XHTTP REALITY requires h2"));
        }
        Ok(HttpLink { read, write, h2: true })
    }
}

enum XhttpConnection {
    H1(Option<HttpLink>),
    H2(H2Conn<Link>),
    H3(kerlico_vless::H3Conn),
}

struct XhttpCarrier(Mutex<XhttpConnection>);

impl kerlico_vless::xmux::XmuxConnection for XhttpCarrier {
    fn is_closed(&self) -> bool {
        match &*self.0.lock().expect("XHTTP carrier") {
            XhttpConnection::H1(_) => false,
            XhttpConnection::H2(conn) => !conn.is_open(),
            XhttpConnection::H3(conn) => conn.is_closed(),
        }
    }
}

type XhttpLease = Arc<kerlico_vless::xmux::XmuxLease<XhttpCarrier>>;

struct XhttpEndpoint {
    dial: HttpDial,
    config: XhttpConfig,
    authority: String,
    scheme: &'static str,
    pool: kerlico_vless::xmux::XmuxPool<XhttpCarrier>,
}

/// State that `land` calls with the same peer, settings and runtime owner share.
struct Shared<T> {
    host: String,
    port: u16,
    settings: Settings,
    owner: Option<std::sync::Weak<kerlico_shared::runtime::RuntimeContext>>,
    value: Arc<T>,
}

/// Entries die with their runtime owner, and the least recently used beyond 32 are dropped.
fn shared<T>(
    cache: &OnceLock<Mutex<VecDeque<Shared<T>>>>,
    host: &str,
    port: u16,
    settings: &Settings,
    make: impl FnOnce() -> Result<T, OpenError>,
) -> Result<Arc<T>, OpenError> {
    let detached = settings.without_runtime();
    let owner = settings.runtime().map(Arc::downgrade);
    let mut entries = cache.get_or_init(Mutex::default).lock().expect("landing cache");
    entries.retain(|entry| entry.owner.as_ref().is_none_or(|owner| owner.strong_count() != 0));
    if let Some(index) = entries.iter().position(|entry| entry.host == host && entry.port == port && entry.settings == detached
        && match (&entry.owner, &owner) { (None, None) => true, (Some(a), Some(b)) => a.ptr_eq(b), _ => false }) {
        let entry = entries.remove(index).expect("landing cache");
        let value = entry.value.clone();
        entries.push_back(entry);
        return Ok(value);
    }
    let value = Arc::new(make()?);
    entries.push_back(Shared { host: host.into(), port, settings: detached, owner, value: value.clone() });
    if entries.len() > 32 { entries.pop_front(); }
    Ok(value)
}

fn xhttp_endpoint(host: &str, port: u16, settings: &Settings, reality: Option<([u8; 32], [u8; 8])>, tls: bool, allow_plain: bool) -> Result<Arc<XhttpEndpoint>, OpenError> {
    static ENDPOINTS: OnceLock<Mutex<VecDeque<Shared<XhttpEndpoint>>>> = OnceLock::new();
    shared(&ENDPOINTS, host, port, settings, || XhttpEndpoint::new(host, port, settings, reality, tls, allow_plain))
}

impl XhttpEndpoint {
    fn new(
        host: &str,
        port: u16,
        settings: &Settings,
        reality: Option<([u8; 32], [u8; 8])>,
        tls: bool,
        allow_plain: bool,
    ) -> Result<Self, OpenError> {
        let config = XhttpConfig::from_settings(|key| settings.text(key).ok())
            .map_err(|_| OpenError::Settings)?;
        let name = settings
            .text("serverName")
            .ok()
            .filter(|name| !name.is_empty())
            .unwrap_or(host);
        let authority = if config.host().is_empty() {
            name
        } else {
            config.host()
        };
        let authority = if authority.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{authority}]")
        } else {
            authority.to_owned()
        };
        let scheme = if tls || reality.is_some() {
            "https"
        } else {
            "http"
        };
        let socket_options = SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?;
        let dial = HttpDial {
            network: carrier_network(settings, socket_options.clone()),
            socket_options,
            masks: final_masks(settings)?,
            host: host.to_owned(),
            port,
            name: name.to_owned(),
            tls: if tls && alpn(settings) != ["h3"] { Some(tls_config(settings)?) } else { None },
            quic: if tls && alpn(settings) == ["h3"] { Some(quic_tls_config(settings)?) } else { None },
            fingerprint: settings.text("fingerprint").unwrap_or("chrome").to_owned(),
            reality,
            proof: reality_proof(settings)?,
            spider: kerlico_vless::RealitySpiderConfig::parse(settings.text("spiderX").unwrap_or("")).map_err(|_| OpenError::Settings)?,
            allow_plain,
        };
        Ok(Self {
            dial,
            pool: kerlico_vless::xmux::XmuxPool::new(config.xmux().clone()),
            config,
            authority,
            scheme,
        })
    }

    fn acquire(&self) -> std::io::Result<XhttpLease> {
        self.pool.acquire(|| self.connect().map(|conn| XhttpCarrier(Mutex::new(conn)))).map(Arc::new)
    }

    fn count_request(&self, lease: &mut XhttpLease) -> std::io::Result<()> {
        if !lease.request() {
            *lease = self.acquire()?;
            if !lease.request() { return Err(std::io::Error::other("XHTTP connection request budget exhausted")); }
        }
        Ok(())
    }

    fn connect(&self) -> std::io::Result<XhttpConnection> {
        if let Some(tls) = self.dial.quic.as_ref()
        {
            let (endpoint, masks, _) = udp_endpoint(&self.dial.host, self.dial.port, self.dial.network.as_deref(), &self.dial.socket_options, &self.dial.masks)?;
            let options = kerlico_vless::QuicOptions::parse(self.dial.masks.quic_params())?;
            return kerlico_vless::H3Conn::connect_crypto_with_options(endpoint, tls.clone(), &self.dial.name, &masks, &options, kerlico_vless::QuicCarrier::Xhttp, self.config.xmux().keepalive_seconds)
                .map(XhttpConnection::H3);
        }
        let socket = self.dial.connect()?;
        if socket.h2() {
            let (mut read, write) = socket.split()?;
            read.set_timeout(Duration::from_millis(200));
            return H2Conn::connect_with_keepalive(read, write, self.config.xmux().keepalive_seconds).map(XhttpConnection::H2);
        }
        Ok(XhttpConnection::H1(Some(socket)))
    }

    fn request<'a>(
        &self,
        kind: XhttpRequestKind<&str>,
        payload: &'a [u8],
    ) -> std::io::Result<XhttpRequest<'a>> {
        self.config
            .request(kind, &self.authority, self.scheme, payload)
    }

    fn take_h1(&self, slot: &mut Option<HttpLink>) -> std::io::Result<HttpLink> {
        match slot.take() {
            Some(socket) => Ok(socket),
            None => {
                let socket = self.dial.connect()?;
                if socket.h2() {
                    return Err(std::io::Error::other("XHTTP peer changed HTTP versions"));
                }
                Ok(socket)
            }
        }
    }

    fn start_stream(
        &self,
        connection: &mut XhttpConnection,
        request: &XhttpRequest<'_>,
    ) -> std::io::Result<Link> {
        let headers = request.header_pairs();
        match connection {
            XhttpConnection::H1(slot) => {
                let mut socket = self.take_h1(slot)?;
                request.write_h1(&mut socket, &self.authority)?;
                let (read, write) = socket.split()?;
                Ok(Link::Duplex(Box::new(read), Box::new(write)))
            }
            XhttpConnection::H2(conn) => {
                let stream = conn.request(
                    &request.method,
                    &request.target,
                    &self.authority,
                    self.scheme,
                    &headers,
                    false,
                    false,
                )?;
                Ok(Link::H2(Arc::new(stream)))
            }
            XhttpConnection::H3(conn) => {
                let stream = conn.request(
                    &request.method,
                    &request.target,
                    &self.authority,
                    self.scheme,
                    &headers,
                    false,
                )?;
                Ok(Link::H3(Arc::new(stream)))
            }
        }
    }

    fn download(&self, connection: &mut XhttpConnection, session: &str) -> std::io::Result<Xdown> {
        let request = self.request(XhttpRequestKind::Download { session }, &[])?;
        let headers = request.header_pairs();
        match connection {
            XhttpConnection::H1(slot) => {
                let mut socket = self.take_h1(slot)?;
                request.write_h1(&mut socket, &self.authority)?;
                let rest = read_response_head(&mut socket)?;
                Ok(Xdown::H1(ChunkReader::new(socket, rest)))
            }
            XhttpConnection::H2(conn) => conn
                .open(
                    &request.method,
                    &request.target,
                    &self.authority,
                    self.scheme,
                    &headers,
                    true,
                )
                .map(Xdown::H2),
            XhttpConnection::H3(conn) => conn
                .open(
                    &request.method,
                    &request.target,
                    &self.authority,
                    self.scheme,
                    &headers,
                    true,
                )
                .map(Xdown::H3),
        }
    }
}

fn open_xhttp(
    host: &str,
    port: u16,
    settings: &Settings,
    reality: Option<([u8; 32], [u8; 8])>,
    tls: bool,
) -> Result<(Link, Link), OpenError> {
    let allow_plain = settings.text("trusted").ok() == Some("true")
        || settings
            .text("encryption")
            .ok()
            .is_some_and(|encryption| encryption != "none");
    let upload = xhttp_endpoint(host, port, settings, reality, tls, allow_plain)?;
    let download = upload
        .config
        .download_endpoint()
        .map_err(|_| OpenError::Settings)?;
    let mode = upload.config.mode(reality.is_some(), download.is_some());
    let runtime = settings.runtime().cloned();
    let inherited_socket = SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?.penetrate.then(|| settings.text("sockopt").unwrap_or("{}").to_owned());
    let download = download
        .map(|download| {
            let mut settings = Settings::default();
            for (key, value) in download.settings {
                settings.insert_text(key, value);
            }
            if let Some(runtime) = runtime { settings.set_runtime(runtime); }
            if let Some(sockopt) = inherited_socket { settings.insert_text("sockopt", sockopt); }
            let security = settings.text("security")?;
            let reality = if security == "reality" {
                let key =
                    decode_reality_key(settings.text("publicKey")?).ok_or(OpenError::Settings)?;
                let short_id = decode_short_id(settings.text("shortId").unwrap_or(""))
                    .ok_or(OpenError::Settings)?;
                Some((key, short_id))
            } else {
                None
            };
            xhttp_endpoint(
                &download.address,
                download.port,
                &settings,
                reality,
                security == "tls",
                allow_plain,
            )
        })
        .transpose()?;
    let open = || -> std::io::Result<(Link, Link)> {
        let mut upload_connection = upload.acquire()?;
        if mode == XhttpMode::StreamOne {
            let request = upload.request(XhttpRequestKind::StreamOne, &[])?;
            upload.count_request(&mut upload_connection)?;
            let stream = upload.start_stream(&mut upload_connection.connection().0.lock().expect("XHTTP carrier"), &request)?;
            let (read, write) = match stream {
                    Link::Duplex(mut read, write) => {
                        let rest = read_response_head(&mut *read)?;
                        let pair = Arc::new(ChunkPair::split(read, rest, write));
                        (Link::Chunks(pair.clone()), Link::Chunks(pair))
                    }
                    Link::H2(stream) => (Link::H2(stream.clone()), Link::H2(stream)),
                    Link::H3(stream) => (Link::H3(stream.clone()), Link::H3(stream)),
                    _ => unreachable!("XHTTP streaming transport"),
                };
            let leases = Arc::new(vec![upload_connection]);
            return Ok((Link::Leased(Box::new(read), leases.clone()), Link::Leased(Box::new(write), leases)));
        }

        let session = upload.config.session_id()?;
        let (reader, download_connection) = match download {
            Some(download) => {
                let mut lease = download.acquire()?;
                download.count_request(&mut lease)?;
                let reader = download.download(&mut lease.connection().0.lock().expect("XHTTP carrier"), &session)?;
                (reader, lease)
            }
            None => {
                upload.count_request(&mut upload_connection)?;
                let reader = upload.download(&mut upload_connection.connection().0.lock().expect("XHTTP carrier"), &session)?;
                (reader, upload_connection.clone())
            }
        };
        let writer = if mode == XhttpMode::StreamUp {
            let request = upload.request(XhttpRequestKind::StreamUp { session: &session }, &[])?;
            upload.count_request(&mut upload_connection)?;
            let stream = upload.start_stream(&mut upload_connection.connection().0.lock().expect("XHTTP carrier"), &request)?;
            XhttpUpload::Stream(XhttpStreamUpload::new(stream))
        } else {
            let limit = upload.config.upload_limit()?;
            XhttpUpload::Packets(XhttpPacketUpload {
                endpoint: upload,
                connection: upload_connection.clone(),
                session,
                limit,
                sequence: 0,
                last_post: None,
            })
        };
        let client = Arc::new(XhttpClient {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        });
        let leases = Arc::new(vec![upload_connection, download_connection]);
        Ok((Link::Leased(Box::new(Link::Xhttp(client.clone())), leases.clone()), Link::Leased(Box::new(Link::Xhttp(client)), leases)))
    };
    open().map_err(|_| OpenError::Transport)
}

enum Xdown {
    H1(ChunkReader),
    H2(H2Stream<Link>),
    H3(kerlico_vless::H3Stream),
}

impl Xdown {
    fn pull(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(reader) => reader.read(buf),
            Self::H2(io) => io.read(buf),
            Self::H3(io) => io.read(buf),
        }
    }
}

struct XhttpClient {
    reader: Mutex<Xdown>,
    writer: Mutex<XhttpUpload>,
}

enum XhttpUpload {
    Stream(XhttpStreamUpload),
    Packets(XhttpPacketUpload),
}

impl XhttpClient {
    fn pull(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.lock().expect("XHTTP reader").pull(buf)
    }

    fn push(&self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match &mut *self.writer.lock().expect("XHTTP writer") {
            XhttpUpload::Stream(stream) => stream.push(buf),
            XhttpUpload::Packets(packets) => packets.push(buf),
        }
    }

    fn flush(&self) -> std::io::Result<()> {
        match &mut *self.writer.lock().expect("XHTTP writer") {
            XhttpUpload::Stream(stream) => stream.write.flush(),
            XhttpUpload::Packets(_) => Ok(()),
        }
    }
}

struct XhttpStreamUpload {
    write: XhttpBodyWriter<Link>,
    _active: Arc<()>,
}

impl XhttpStreamUpload {
    fn new(stream: Link) -> Self {
        let active = Arc::new(());
        let watching = Arc::downgrade(&active);
        let (read, write, chunked) = match stream {
            Link::Duplex(read, write) => (*read, *write, true),
            Link::H2(stream) => (Link::H2(stream.clone()), Link::H2(stream), false),
            Link::H3(stream) => (Link::H3(stream.clone()), Link::H3(stream), false),
            _ => unreachable!("XHTTP streaming transport"),
        };
        std::thread::spawn(move || {
            let mut read: Box<dyn Read> = if chunked {
                let mut read = read;
                let Ok(rest) = read_response_head(&mut read) else {
                    return;
                };
                Box::new(ChunkReader::new(read, rest))
            } else {
                Box::new(read)
            };
            let mut scratch = [0; 4096];
            while watching.strong_count() != 0 {
                match read.read(&mut scratch) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) if xhttp_retryable(&error) => {}
                    Err(_) => break,
                }
            }
        });
        Self {
            write: XhttpBodyWriter::new(write, chunked),
            _active: active,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write.write(bytes)
    }
}

struct XhttpPacketUpload {
    endpoint: Arc<XhttpEndpoint>,
    connection: XhttpLease,
    session: String,
    limit: usize,
    sequence: u64,
    last_post: Option<std::time::Instant>,
}

impl XhttpPacketUpload {
    fn push(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let packet = &bytes[..bytes.len().min(self.limit)];
        let request = self.endpoint.request(
            XhttpRequestKind::PacketUp {
                session: &self.session,
                seq: self.sequence,
            },
            packet,
        )?;
        if let Some(last) = self.last_post {
            let delay = self
                .endpoint
                .config
                .post_interval()?
                .saturating_sub(last.elapsed());
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
        }
        self.last_post = Some(std::time::Instant::now());
        self.endpoint.count_request(&mut self.connection)?;
        let headers = request.header_pairs();
        let XhttpEndpoint {
            dial,
            authority,
            scheme,
            ..
        } = &*self.endpoint;
        match &mut *self.connection.connection().0.lock().expect("XHTTP carrier") {
            XhttpConnection::H1(slot) => {
                let pooled = slot.is_some();
                let mut socket = self.endpoint.take_h1(slot)?;
                let send = |socket: &mut HttpLink| {
                    request.write_h1(socket, authority)?;
                    read_packet_ack(socket, &request.method)
                };
                let keep = match send(&mut socket) {
                    Err(error) if pooled && error.kind() != std::io::ErrorKind::InvalidData => {
                        socket = dial.connect()?;
                        if socket.h2() {
                            return Err(std::io::Error::other("XHTTP peer changed HTTP versions"));
                        }
                        send(&mut socket)?
                    }
                    result => result?,
                };
                if keep {
                    *slot = Some(socket);
                }
            }
            XhttpConnection::H2(conn) => {
                let empty = request.body.is_empty();
                let stream = conn.request(
                    &request.method,
                    &request.target,
                    authority,
                    scheme,
                    &headers,
                    empty,
                    empty,
                )?;
                if !empty {
                    stream.finish(request.body)?;
                }
            }
            XhttpConnection::H3(conn) => conn
                .request(
                    &request.method,
                    &request.target,
                    authority,
                    scheme,
                    &headers,
                    false,
                )?
                .finish(request.body)?,
        }
        self.sequence += 1;
        Ok(packet.len())
    }
}

fn xhttp_retryable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
    )
}

impl Link {
    fn supports_vision(&self) -> bool {
        match self {
            Self::EncRead(_) | Self::RealityRead(_) => true,
            Self::TlsRead(tls) => tls.is_tls13(),
            _ => false,
        }
    }

    fn set_timeout(&mut self, timeout: Duration) {
        match self {
            Self::Leased(inner, _) => inner.set_timeout(timeout),
            Self::MaskedRead(link) => link.set_timeout(timeout),
            Self::MaskedWrite(link) => link.set_timeout(timeout),
            Self::XdriveRead(io) => io.set_timeout(Some(timeout)),
            Self::XdriveWrite(io) => io.set_timeout(Some(timeout)),
            Self::HysteriaRead(io) => io.set_timeout(timeout),
            Self::HysteriaWrite(io) => io.set_timeout(timeout),
            Self::H3(io) => io.set_timeout(timeout),
            Self::Tcp(tcp) => {
                tcp.set_read_timeout(Some(timeout)).ok();
                tcp.set_write_timeout(Some(timeout)).ok();
            }
            Self::TlsRead(tls) => tls.inner_mut().set_timeout(timeout),
            Self::TlsWrite(tls) => tls.inner_mut().set_timeout(timeout),
            Self::HttpPrefaceRead(read) => read.inner_mut().set_timeout(timeout),
            Self::UpgradeRead(read) => read.map_io(move |inner| inner.set_timeout(timeout)),
            Self::UpgradeWrite(write) => write.map_io(|read| read.set_timeout(timeout), |write| write.set_timeout(timeout)),
            Self::Grpc(grpc) => grpc.set_timeout(timeout),
            Self::Http(http) => http.map_io(|read| read.set_timeout(timeout), |write| write.set_timeout(timeout)),
            Self::Kcp(kcp) => kcp.set_timeout(timeout),
            Self::Xhttp(_) => {}
            Self::Chunks(_) => {}
            Self::EncRead(enc) => enc.inner_mut().set_timeout(timeout),
            Self::EncWrite(enc) => enc.inner_mut().set_timeout(timeout),
            Self::RealityRead(link) => link.inner_mut().set_timeout(timeout),
            Self::RealityWrite(link) => link.inner_mut().set_timeout(timeout),
            Self::Duplex(read, write) => { read.set_timeout(timeout); write.set_timeout(timeout); },
            Self::Response(inner) => inner.inner_mut().set_timeout(timeout),
            Self::Vision(inner) => inner.inner_mut().set_timeout(timeout),
            Self::H2(_) => {}
        }
    }
}

impl Read for Link {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Leased(inner, _) => inner.read(buf),
            Self::MaskedRead(link) => link.read(buf),
            Self::MaskedWrite(_) => Err(std::io::ErrorKind::Unsupported.into()),
            Self::XdriveRead(io) => io.read(buf),
            Self::HysteriaRead(io) => io.read(buf),
            Self::H3(io) => io.read(buf),
            Self::XdriveWrite(_) | Self::HysteriaWrite(_) => Err(std::io::Error::other("write half")),
            Self::Tcp(tcp) => tcp.read(buf),
            Self::TlsRead(tls) => tls.read(buf),
            Self::TlsWrite(_) => Err(std::io::Error::other("write half")),
            Self::HttpPrefaceRead(read) => read.read(buf),
            Self::UpgradeRead(read) => read.read(buf),
            Self::UpgradeWrite(_) => Err(std::io::Error::other("write half")),
            Self::Grpc(grpc) => grpc.read(buf),
            Self::Http(http) => http.read(buf),
            Self::Kcp(kcp) => kcp.pull(buf),
            Self::Xhttp(http) => http.pull(buf),
            Self::Chunks(chunks) => chunks.pull(buf),
            Self::EncRead(enc) => enc.read(buf),
            Self::EncWrite(_) => Err(std::io::Error::other("vlessenc")),
            Self::RealityRead(link) => link.read(buf),
            Self::RealityWrite(_) => Err(std::io::Error::other("reality")),
            Self::Duplex(read, _) => read.read(buf),
            Self::Response(inner) => inner.read(buf),
            Self::Vision(inner) => inner.read(buf),
            Self::H2(link) => link.read(buf),
        }
    }
}

impl Write for Link {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Leased(inner, _) => inner.write(buf),
            Self::MaskedWrite(link) => link.write(buf),
            Self::MaskedRead(_) => Err(std::io::ErrorKind::Unsupported.into()),
            Self::XdriveWrite(io) => io.write(buf),
            Self::HysteriaWrite(io) => io.write(buf),
            Self::H3(io) => io.write(buf),
            Self::XdriveRead(_) | Self::HysteriaRead(_) => Err(std::io::Error::other("read half")),
            Self::Tcp(tcp) => tcp.write(buf),
            Self::TlsWrite(tls) => tls.write(buf),
            Self::TlsRead(_) => Err(std::io::Error::other("read half")),
            Self::UpgradeWrite(write) => write.write(buf),
            Self::HttpPrefaceRead(_) | Self::UpgradeRead(_) => Err(std::io::Error::other("read half")),
            Self::Grpc(grpc) => grpc.write(buf),
            Self::Http(http) => http.write(buf),
            Self::Kcp(kcp) => kcp.push(buf),
            Self::Xhttp(http) => http.push(buf),
            Self::Chunks(chunks) => chunks.push(buf),
            Self::EncRead(_) => Err(std::io::Error::other("vlessenc")),
            Self::EncWrite(enc) => enc.write(buf),
            Self::RealityRead(_) => Err(std::io::Error::other("reality")),
            Self::RealityWrite(link) => link.write(buf),
            Self::Duplex(_, write) => write.write(buf),
            Self::Response(inner) => inner.write(buf),
            Self::Vision(inner) => inner.write(buf),
            Self::H2(link) => link.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Leased(inner, _) => inner.flush(),
            Self::MaskedWrite(link) => link.flush(),
            Self::MaskedRead(_) => Ok(()),
            Self::XdriveWrite(io) => io.flush(),
            Self::HysteriaWrite(io) => io.flush(),
            Self::H3(io) => io.flush(),
            Self::XdriveRead(_) | Self::HysteriaRead(_) => Ok(()),
            Self::Tcp(tcp) => tcp.flush(),
            Self::TlsWrite(tls) => tls.flush(),
            Self::TlsRead(_) => Ok(()),
            Self::UpgradeWrite(write) => write.flush(),
            Self::HttpPrefaceRead(_) | Self::UpgradeRead(_) => Ok(()),
            Self::Grpc(grpc) => grpc.flush(),
            Self::Http(http) => http.flush(),
            Self::Kcp(_) => Ok(()),
            Self::Xhttp(http) => http.flush(),
            Self::Chunks(chunks) => chunks.flush(),
            Self::EncRead(_) => Ok(()),
            Self::EncWrite(enc) => enc.flush(),
            Self::RealityRead(_) => Ok(()),
            Self::RealityWrite(link) => link.flush(),
            Self::Duplex(_, write) => write.flush(),
            Self::Response(inner) => inner.flush(),
            Self::Vision(inner) => inner.flush(),
            Self::H2(link) => link.flush(),
        }
    }
}

impl kerlico_vless::VisionTransport for Link {
    fn read_direct(&mut self) -> std::io::Result<()> {
        match self {
            Self::TlsRead(tls) => tls.start_direct(),
            Self::EncRead(enc) => enc.start_direct(),
            Self::RealityRead(reality) => reality.start_direct(),
            Self::Response(inner) => inner.inner_mut().read_direct(),
            _ => Err(std::io::Error::other("Vision requires a security record layer")),
        }
    }
    fn write_direct(&mut self) -> std::io::Result<()> {
        match self {
            Self::TlsWrite(tls) => tls.start_direct(),
            Self::EncWrite(enc) => enc.start_direct(),
            Self::RealityWrite(reality) => reality.start_direct(),
            _ => Err(std::io::Error::other("Vision requires a security record layer")),
        }
    }
}

fn reality_proof(settings: &Settings) -> Result<Option<kerlico_vless::RealityMldsa65Verifier>, OpenError> {
    match settings.text("mldsa65Verify") {
        Ok(text) if !text.is_empty() => kerlico_vless::RealityMldsa65Verifier::from_base64(text).map(Some).ok_or(OpenError::Settings),
        _ => Ok(None),
    }
}

fn reality_alpn(settings: &Settings) -> Vec<String> {
    let names = alpn(settings);
    if names.is_empty() { vec!["h2".into(), "http/1.1".into()] } else { names }
}

fn alpn(settings: &Settings) -> Vec<String> {
    let names = kerlico_vless::string_list(settings.text("alpn").unwrap_or("")).unwrap_or_default();
    if names.is_empty() && settings.text("network").ok() == Some("xdrive") {
        vec!["h2".to_string(), "http/1.1".to_string()]
    } else if names.is_empty() && matches!(settings.text("network").unwrap_or(""), "http" | "grpc" | "xhttp" | "splithttp") {
        vec!["h2".to_string()]
    } else {
        names
    }
}

const REVERSE_SESSION_LIMIT: usize = 128;
const REVERSE_QUEUE_LIMIT: usize = 1024 * 1024;
const REVERSE_TOTAL_LIMIT: usize = 8 * 1024 * 1024;

/// One reverse destination. UDP streams read and write whole datagrams.
pub struct ReverseFlow {
    destination: Destination,
    stream: Box<dyn InboundStream>,
}

impl ReverseFlow {
    pub fn destination(&self) -> &Destination { &self.destination }
    pub fn stream(&self) -> &dyn InboundStream { self.stream.as_ref() }
    pub fn into_parts(self) -> (Destination, Box<dyn InboundStream>) { (self.destination, self.stream) }
}

/// A multiplexed reverse connection. Accepting a flow never dials its target.
pub struct ReverseBridge {
    shared: Arc<ReverseShared>,
    incoming: Mutex<std::sync::mpsc::Receiver<ReverseFlow>>,
}

impl ReverseBridge {
    fn new(mut read: Link, mut write: Link, prefix: Vec<u8>) -> Self {
        read.set_timeout(Duration::from_millis(200));
        write.set_timeout(Duration::from_millis(200));
        let shared = Arc::new(ReverseShared {
            writer: Mutex::new(Some(MuxOutbox::new(write))),
            sessions: Mutex::new(std::collections::HashMap::new()),
            queued: std::sync::atomic::AtomicUsize::new(0),
            closed: std::sync::atomic::AtomicBool::new(false),
        });
        let (sender, incoming) = std::sync::mpsc::sync_channel(64);
        let worker = shared.clone();
        std::thread::spawn(move || reverse_loop(read, prefix, worker, sender));
        Self { shared, incoming: Mutex::new(incoming) }
    }

    pub fn accept(&self) -> Result<ReverseFlow, OpenError> {
        match self.incoming.lock().expect("reverse").try_recv() {
            Ok(flow) => Ok(flow),
            Err(std::sync::mpsc::TryRecvError::Empty) if !self.shared.closed() => Err(OpenError::Again),
            Err(_) => Err(OpenError::Transport),
        }
    }
}

impl Drop for ReverseBridge {
    fn drop(&mut self) { self.shared.close_all(); }
}

/// The write half of a Mux carrier. END frames wait here until the carrier can take them.
struct MuxOutbox {
    mux: kerlico_vless::MuxWriter<Link>,
    ends: std::collections::VecDeque<MuxFrame>,
}

impl MuxOutbox {
    fn new(write: Link) -> Self {
        Self { mux: kerlico_vless::MuxWriter::new(write), ends: std::collections::VecDeque::new() }
    }

    fn send(&mut self, frame: &MuxFrame) -> std::io::Result<()> {
        self.flush().and_then(|_| self.mux.send(frame))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        while let Some(frame) = self.ends.front() {
            self.mux.send(frame)?;
            self.ends.pop_front();
        }
        self.mux.flush()
    }

    fn end(&mut self, id: u16, failed: bool) -> std::io::Result<()> {
        if !self.ends.iter().any(|frame| frame.id == id) {
            if self.ends.len() >= REVERSE_SESSION_LIMIT { return Err(std::io::Error::other("mux close queue full")); }
            self.ends.push_back(MuxFrame { id, status: kerlico_vless::END, option: if failed { 2 } else { 0 }, network: 0, port: 0, address: None, payload: Vec::new() });
        }
        self.flush()
    }
}

struct ReverseSession {
    destination: Destination,
    lanes: std::collections::HashMap<(String, u16), std::sync::Weak<ReverseLane>>,
}

struct ReverseShared {
    writer: Mutex<Option<MuxOutbox>>,
    sessions: Mutex<std::collections::HashMap<u16, ReverseSession>>,
    queued: std::sync::atomic::AtomicUsize,
    closed: std::sync::atomic::AtomicBool,
}

impl ReverseShared {
    fn closed(&self) -> bool { self.closed.load(std::sync::atomic::Ordering::Acquire) }

    fn flush(&self) -> std::io::Result<()> {
        match self.writer.lock().expect("reverse").as_mut() {
            Some(writer) => writer.flush(),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn send(&self, frame: &MuxFrame) -> std::io::Result<()> {
        let result = {
            let mut writer = self.writer.lock().expect("reverse");
            let writer = writer.as_mut().ok_or(std::io::ErrorKind::BrokenPipe)?;
            writer.send(frame)
        };
        if result.as_ref().is_err_and(|error| !retry_io(error)) { self.close_all(); }
        result
    }

    fn end(&self, id: u16, failed: bool) {
        let result = {
            let mut writer = self.writer.lock().expect("reverse");
            match writer.as_mut() { Some(writer) => writer.end(id, failed), None => return }
        };
        if result.as_ref().is_err_and(|error| !retry_io(error)) { self.close_all(); }
    }

    fn close_session(&self, id: u16) {
        let session = self.sessions.lock().expect("reverse").remove(&id);
        if let Some(session) = session {
            for lane in session.lanes.into_values().filter_map(|lane| lane.upgrade()) { lane.end(); }
        }
    }

    fn close_all(&self) {
        if self.closed.swap(true, std::sync::atomic::Ordering::AcqRel) { return; }
        let sessions = std::mem::take(&mut *self.sessions.lock().expect("reverse"));
        for session in sessions.into_values() {
            for lane in session.lanes.into_values().filter_map(|lane| lane.upgrade()) { lane.end(); }
        }
        self.writer.lock().expect("reverse").take();
    }

    fn route(self: &Arc<Self>, frame: MuxFrame, incoming: &std::sync::mpsc::SyncSender<ReverseFlow>) -> std::io::Result<()> {
        let id = frame.id;
        if frame.status == kerlico_vless::END {
            if !frame.payload.is_empty() {
                let lane = self.sessions.lock().expect("reverse").get(&id).and_then(|session| {
                    let key = (session.destination.host().to_string(), session.destination.port());
                    session.lanes.get(&key).and_then(std::sync::Weak::upgrade)
                });
                if let Some(lane) = lane { lane.push_incoming(frame.payload); }
            }
            self.close_session(id);
            return Ok(());
        }
        if !matches!(frame.status, NEW | KEEP) { return Err(std::io::Error::other("reverse session status")); }
        let (lane, fresh) = {
            let mut sessions = self.sessions.lock().expect("reverse");
            if frame.status == NEW {
                if sessions.contains_key(&id) { return Err(std::io::Error::other("duplicate reverse session")); }
                if sessions.len() >= REVERSE_SESSION_LIMIT {
                    drop(sessions);
                    self.end(id, true);
                    return Ok(());
                }
                let destination = reverse_destination(frame.address.as_ref(), frame.port, frame.network)?;
                sessions.insert(id, ReverseSession { destination, lanes: std::collections::HashMap::new() });
            }
            let Some(session) = sessions.get_mut(&id) else {
                drop(sessions);
                self.end(id, true);
                return Ok(());
            };
            let destination = if frame.status == KEEP && frame.address.is_some() {
                if session.destination.transport() != Transport::Udp || frame.network != 2 { return Err(std::io::Error::other("reverse target changed on TCP")); }
                reverse_destination(frame.address.as_ref(), frame.port, frame.network)?
            } else { session.destination.clone() };
            let key = (destination.host().to_string(), destination.port());
            let lane = session.lanes.get(&key).and_then(std::sync::Weak::upgrade);
            match lane {
                Some(lane) => (lane, false),
                None => {
                    if session.lanes.len() >= 64 {
                        drop(sessions);
                        self.close_session(id);
                        self.end(id, true);
                        return Ok(());
                    }
                    let lane = Arc::new(ReverseLane { id, destination, shared: self.clone(), cv: std::sync::Condvar::new(), queue: Mutex::new(ReverseQueue { bytes: std::collections::VecDeque::new(), packets: std::collections::VecDeque::new(), size: 0, closed: false }) });
                    session.lanes.insert(key, Arc::downgrade(&lane));
                    (lane, true)
                }
            }
        };
        if !lane.push_incoming(frame.payload) {
            self.close_session(id);
            self.end(id, true);
            return Ok(());
        }
        if fresh {
            let flow = ReverseFlow { destination: lane.destination.clone(), stream: Box::new(ReverseStream(lane)) };
            if let Err(error) = incoming.try_send(flow) {
                self.close_session(id);
                self.end(id, true);
                drop(error);
            }
        }
        Ok(())
    }
}

fn retry_io(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted)
}

fn reverse_destination(address: Option<&Addr>, port: u16, network: u8) -> std::io::Result<Destination> {
    let host = match address {
        Some(Addr::V4(ip)) => ip.to_string(), Some(Addr::V6(ip)) => ip.to_string(),
        Some(Addr::Domain(host)) => host.clone(), None => return Err(std::io::Error::other("reverse target missing")),
    };
    let transport = match network { 1 => Transport::Tcp, 2 => Transport::Udp, _ => return Err(std::io::Error::other("reverse network")) };
    Destination::new(host, port, transport).map_err(|_| std::io::Error::other("reverse target"))
}

fn reverse_loop(mut read: Link, mut pending: Vec<u8>, shared: Arc<ReverseShared>, incoming: std::sync::mpsc::SyncSender<ReverseFlow>) {
    let mut controls = std::collections::HashSet::new();
    let mut buf = [0; 8192];
    'connection: loop {
        if shared.closed() { break; }
        if let Err(error) = shared.flush() { if !retry_io(&error) { break; } }
        loop {
            match decode_mux(&pending) {
                Ok((frame, used)) => {
                    pending.drain(..used);
                    if frame.status == kerlico_vless::KEEPALIVE { continue; }
                    if frame.status == NEW && frame.network == 2 && frame.port == 0 && matches!(frame.address, Some(Addr::Domain(ref host)) if host == "reverse") {
                        controls.insert(frame.id);
                        continue;
                    }
                    if controls.contains(&frame.id) {
                        if frame.status == kerlico_vless::END { controls.remove(&frame.id); }
                        continue;
                    }
                    if shared.route(frame, &incoming).is_err() { break 'connection; }
                }
                Err(kerlico_vless::HeaderError::Short) => break,
                Err(kerlico_vless::HeaderError::Bad) => break 'connection,
            }
        }
        match read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(error) if retry_io(&error) => {},
            Err(_) => break,
        }
    }
    shared.close_all();
}

struct ReverseQueue {
    bytes: std::collections::VecDeque<u8>,
    packets: std::collections::VecDeque<Vec<u8>>,
    size: usize,
    closed: bool,
}

struct ReverseLane {
    id: u16,
    destination: Destination,
    shared: Arc<ReverseShared>,
    queue: Mutex<ReverseQueue>,
    cv: std::sync::Condvar,
}

impl ReverseLane {
    fn end(&self) {
        self.queue.lock().expect("reverse").closed = true;
        self.cv.notify_all();
    }

    fn push_incoming(&self, payload: Vec<u8>) -> bool {
        if payload.is_empty() { return true; }
        let mut queue = self.queue.lock().expect("reverse");
        let len = payload.len();
        if queue.closed || queue.size + len > REVERSE_QUEUE_LIMIT || queue.packets.len() >= 64 { return false; }
        if self.shared.queued.try_update(std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire, |size| size.checked_add(len).filter(|size| *size <= REVERSE_TOTAL_LIMIT)).is_err() { return false; }
        queue.size += len;
        if self.destination.transport() == Transport::Udp { queue.packets.push_back(payload); }
        else { queue.bytes.extend(payload); }
        self.cv.notify_all();
        true
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        if buf.is_empty() { return Ok(0); }
        let mut queue = self.queue.lock().expect("reverse");
        loop {
            if queue.size > 0 {
                let n = if self.destination.transport() == Transport::Udp {
                    if queue.packets.front().is_some_and(|packet| packet.len() > buf.len()) { return Err(PlaneFault::Transport); }
                    let packet = queue.packets.pop_front().expect("queued datagram");
                    buf[..packet.len()].copy_from_slice(&packet);
                    packet.len()
                } else {
                    let n = buf.len().min(queue.bytes.len());
                    for (index, byte) in queue.bytes.drain(..n).enumerate() { buf[index] = byte; }
                    n
                };
                queue.size -= n;
                self.shared.queued.fetch_sub(n, std::sync::atomic::Ordering::AcqRel);
                return Ok(n);
            }
            if queue.closed { return Err(PlaneFault::Closed); }
            let (next, waited) = self.cv.wait_timeout(queue, Duration::from_millis(200)).expect("reverse");
            queue = next;
            if waited.timed_out() { return Err(PlaneFault::Again); }
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        if buf.is_empty() { return Ok(0); }
        if self.queue.lock().expect("reverse").closed || self.shared.closed() { return Err(PlaneFault::Closed); }
        let udp = self.destination.transport() == Transport::Udp;
        if udp && buf.len() > u16::MAX as usize { return Err(PlaneFault::Transport); }
        let len = buf.len().min(u16::MAX as usize);
        let frame = MuxFrame { id: self.id, status: KEEP, option: DATA, network: if udp { 2 } else { 0 },
            port: if udp { self.destination.port() } else { 0 },
            address: if udp { Some(parse_addr(self.destination.host()).map_err(|_| PlaneFault::Transport)?) } else { None },
            payload: buf[..len].to_vec(),
        };
        self.shared.send(&frame).map_err(map_io)?;
        Ok(len)
    }
}

impl Drop for ReverseLane {
    fn drop(&mut self) {
        self.shared.queued.fetch_sub(self.queue.get_mut().expect("reverse").size, std::sync::atomic::Ordering::AcqRel);
        let end = {
            let mut sessions = self.shared.sessions.lock().expect("reverse");
            let Some(session) = sessions.get_mut(&self.id) else { return; };
            let key = (self.destination.host().to_string(), self.destination.port());
            if session.lanes.get(&key).is_none_or(|lane| !std::ptr::eq(lane.as_ptr(), self)) { return; }
            session.lanes.remove(&key);
            if session.lanes.is_empty() { sessions.remove(&self.id); true } else { false }
        };
        if end { self.shared.end(self.id, false); }
    }
}

struct ReverseStream(Arc<ReverseLane>);

impl InboundStream for ReverseStream {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> { self.0.read(buf) }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> { self.0.write(buf) }
}

struct Bridge {
    bridge: ReverseBridge,
    first: Mutex<Option<Arc<dyn InboundStream>>>,
}

impl Bridge {
    fn from_reverse(bridge: ReverseBridge) -> Self { Self { bridge, first: Mutex::new(None) } }

    fn first(&self) -> Result<Arc<dyn InboundStream>, PlaneFault> {
        let mut first = self.first.lock().expect("reverse");
        if let Some(stream) = first.as_ref() { return Ok(stream.clone()); }
        match self.bridge.incoming.lock().expect("reverse").recv_timeout(Duration::from_millis(200)) {
            Ok(flow) => {
                let stream: Arc<dyn InboundStream> = Arc::from(flow.into_parts().1);
                *first = Some(stream.clone());
                Ok(stream)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(PlaneFault::Again),
            Err(_) => Err(PlaneFault::Closed),
        }
    }
}

impl InboundStream for Bridge {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> { self.first()?.read_from_user(buf) }
    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> { self.first()?.write_to_user(buf) }
}

struct Relay {
    read: Mutex<Link>,
    write: Mutex<Link>,
    udp: bool,
    pending: Mutex<Vec<u8>>,
    staged: Mutex<Vec<u8>>,
    unsent: Mutex<Vec<u8>>,
}

impl InboundStream for Relay {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        if self.udp {
            return self.read_packet(buf);
        }
        self.fill_pending()?;
        let mut pending = self.pending.lock().expect("pending");
        if pending.is_empty() {
            return Err(PlaneFault::Again);
        }
        let n = pending.len().min(buf.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.drain(..n);
        Ok(n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        if self.finish_unsent()? {
            return Ok(buf.len());
        }
        let payload = if self.udp {
            encode_udp(buf).map_err(|_| PlaneFault::Transport)?
        } else {
            buf.to_vec()
        };
        let mut rest = payload;
        self.write_vec(&mut rest)?;
        if !rest.is_empty() {
            *self.unsent.lock().expect("unsent") = rest;
            return Err(PlaneFault::Again);
        }
        Ok(buf.len())
    }
}

impl Relay {
    fn new(read: Link, write: Link, udp: bool) -> Self {
        Self {
            read: Mutex::new(read), write: Mutex::new(write), udp,
            pending: Mutex::new(Vec::new()), staged: Mutex::new(Vec::new()), unsent: Mutex::new(Vec::new()),
        }
    }

    fn finish_unsent(&self) -> Result<bool, PlaneFault> {
        let mut unsent = self.unsent.lock().expect("unsent");
        if unsent.is_empty() {
            return Ok(false);
        }
        let mut rest = std::mem::take(&mut *unsent);
        drop(unsent);
        self.write_vec(&mut rest)?;
        if rest.is_empty() {
            return Ok(true);
        }
        *self.unsent.lock().expect("unsent") = rest;
        Err(PlaneFault::Again)
    }

    fn write_vec(&self, rest: &mut Vec<u8>) -> Result<(), PlaneFault> {
        let mut socket = self.write.lock().expect("write");
        socket.set_timeout(Duration::from_millis(200));
        while !rest.is_empty() {
            match socket.write(rest) {
                Ok(0) => return Err(PlaneFault::Closed),
                Ok(n) => {
                    rest.drain(..n);
                }
                Err(error) => {
                    let fault = map_io(error);
                    if fault == PlaneFault::Again {
                        return Ok(());
                    }
                    return Err(fault);
                }
            }
        }
        Ok(())
    }

    fn fill_pending(&self) -> Result<(), PlaneFault> {
        if !self.udp && !self.pending.lock().expect("pending").is_empty() {
            return Ok(());
        }
        let mut tmp = [0u8; 8192];
        let n = {
            let mut staged = self.staged.lock().expect("staged");
            if staged.is_empty() {
                drop(staged);
                let mut socket = self.read.lock().expect("read");
                socket.set_timeout(Duration::from_millis(200));
                match socket.read(&mut tmp) {
                    Ok(0) => return Err(PlaneFault::Closed),
                    Ok(n) => n,
                    Err(error) => return Err(map_io(error)),
                }
            } else {
                let n = staged.len().min(tmp.len());
                tmp[..n].copy_from_slice(&staged[..n]);
                staged.drain(..n);
                n
            }
        };
        self.pending.lock().expect("pending").extend_from_slice(&tmp[..n]);
        Ok(())
    }

    fn read_packet(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        loop {
            {
                let mut pending = self.pending.lock().expect("pending");
                match decode_udp(&pending) {
                    Ok((packet, used)) => {
                        if packet.len() > buf.len() {
                            return Err(PlaneFault::Transport);
                        }
                        if packet.is_empty() {
                            pending.drain(..used);
                            continue;
                        }
                        buf[..packet.len()].copy_from_slice(packet);
                        let n = packet.len();
                        pending.drain(..used);
                        return Ok(n);
                    }
                    Err(kerlico_vless::HeaderError::Bad) => return Err(PlaneFault::Transport),
                    Err(kerlico_vless::HeaderError::Short) => {}
                }
            }
            self.fill_pending()?;
            if self.pending.lock().expect("pending").is_empty() {
                return Err(PlaneFault::Again);
            }
        }
    }
}

fn map_io(error: std::io::Error) -> PlaneFault {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => PlaneFault::Again,
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => PlaneFault::Closed,
        _ => PlaneFault::Transport,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_vless::{decode_request, encode_response, Response};
    use std::net::TcpListener;

    fn reverse_fixture() -> (ReverseBridge, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let reader = client.try_clone().unwrap();
        (ReverseBridge::new(Link::Tcp(reader), Link::Tcp(client), Vec::new()), peer)
    }

    fn accept_reverse(bridge: &ReverseBridge) -> ReverseFlow {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match bridge.accept() {
                Ok(flow) => return flow,
                Err(OpenError::Again) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
                Err(error) => panic!("reverse accept: {error:?}"),
            }
        }
    }

    fn reverse_frame(peer: &mut TcpStream, pending: &mut Vec<u8>) -> MuxFrame {
        loop {
            match decode_mux(pending) {
                Ok((frame, used)) => { pending.drain(..used); return frame; },
                Err(kerlico_vless::HeaderError::Short) => {
                    let mut bytes = [0; 8192];
                    let n = peer.read(&mut bytes).unwrap();
                    assert!(n > 0, "EOF within mux frame");
                    pending.extend_from_slice(&bytes[..n]);
                }
                Err(error) => panic!("invalid reverse frame: {error:?}"),
            }
        }
    }

    #[test]
    fn reverse_accepts_interleaved_tcp_and_udp_destinations_and_ends() {
        let (bridge, mut peer) = reverse_fixture();
        let mut frames = encode_mux(&kerlico_vless::control_frame(1));
        frames.extend(encode_mux(&kerlico_vless::session_frame(3, true, 80, "first.test", b"first")));
        frames.extend(encode_mux(&kerlico_vless::session_frame(5, true, 443, "second.test", b"second")));
        frames.extend(encode_mux(&kerlico_vless::session_frame(7, false, 53, "dns-a.test", b"aaaa")));
        frames.extend(encode_mux(&MuxFrame { id: 7, status: KEEP, option: DATA, network: 2, port: 5353, address: Some(Addr::Domain("dns-b.test".into())), payload: b"bbbb".to_vec() }));
        frames.extend(encode_mux(&MuxFrame { id: 3, status: kerlico_vless::END, option: 0, network: 0, port: 0, address: None, payload: Vec::new() }));
        peer.write_all(&frames).unwrap();
        let first = accept_reverse(&bridge);
        let second = accept_reverse(&bridge);
        let udp_a = accept_reverse(&bridge);
        let udp_b = accept_reverse(&bridge);
        assert_eq!(first.destination().host(), "first.test");
        assert_eq!(second.destination().host(), "second.test");
        assert_eq!(udp_a.destination().port(), 53);
        assert_eq!(udp_b.destination().port(), 5353);
        assert_eq!(udp_b.destination().transport(), Transport::Udp);
        let mut buf = [0; 32];
        assert_eq!(first.stream().read_from_user(&mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"first");
        assert_eq!(first.stream().read_from_user(&mut buf), Err(PlaneFault::Closed));
        assert_eq!(second.stream().read_from_user(&mut buf).unwrap(), 6);
        assert_eq!(&buf[..6], b"second");
        assert_eq!(udp_a.stream().read_from_user(&mut [0; 3]), Err(PlaneFault::Transport));
        assert_eq!(udp_a.stream().read_from_user(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"aaaa");
        assert_eq!(udp_b.stream().read_from_user(&mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"bbbb");
        second.stream().write_to_user(b"tcp-reply").unwrap();
        udp_a.stream().write_to_user(b"udp-a-reply").unwrap();
        udp_b.stream().write_to_user(b"udp-b-reply").unwrap();
        let mut pending = Vec::new();
        assert_eq!(reverse_frame(&mut peer, &mut pending).payload, b"tcp-reply");
        let a = reverse_frame(&mut peer, &mut pending);
        let b = reverse_frame(&mut peer, &mut pending);
        assert_eq!(a.address, Some(Addr::Domain("dns-a.test".into())));
        assert_eq!(b.address, Some(Addr::Domain("dns-b.test".into())));
        assert_eq!((a.port, b.port), (53, 5353));
        drop(second);
        assert_eq!(reverse_frame(&mut peer, &mut pending).status, kerlico_vless::END);
        drop(udp_a);
        drop(udp_b);
        let end = reverse_frame(&mut peer, &mut pending);
        assert_eq!((end.id, end.status), (7, kerlico_vless::END));
    }

    #[test]
    fn reverse_response_larger_than_u16_remains_valid_mux() {
        let (bridge, mut peer) = reverse_fixture();
        peer.write_all(&encode_mux(&kerlico_vless::session_frame(3, true, 80, "large.test", b"request"))).unwrap();
        let flow = accept_reverse(&bridge);
        let expected: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let compare = expected.clone();
        let reader = std::thread::spawn(move || {
            let mut pending = Vec::new();
            let mut actual = Vec::new();
            while actual.len() < compare.len() {
                let frame = reverse_frame(&mut peer, &mut pending);
                assert_eq!((frame.id, frame.status), (3, KEEP));
                assert!(!frame.payload.is_empty());
                actual.extend(frame.payload);
            }
            assert_eq!(actual, compare);
        });
        let mut sent = 0;
        while sent < expected.len() {
            match flow.stream().write_to_user(&expected[sent..]) {
                Ok(n) => { assert!(n > 0); sent += n; },
                Err(PlaneFault::Again) => std::thread::yield_now(),
                Err(error) => panic!("reverse write: {error:?}"),
            }
        }
        reader.join().unwrap();
    }

    #[test]
    fn reverse_overflow_closes_only_the_slow_session() {
        let (bridge, mut peer) = reverse_fixture();
        peer.write_all(&encode_mux(&kerlico_vless::session_frame(3, true, 80, "slow.test", b"x"))).unwrap();
        let _slow = accept_reverse(&bridge);
        let frame = encode_mux(&MuxFrame { id: 3, status: KEEP, option: DATA, network: 0, port: 0, address: None, payload: vec![7; 65535] });
        for _ in 0..17 { peer.write_all(&frame).unwrap(); }
        let mut pending = Vec::new();
        let end = reverse_frame(&mut peer, &mut pending);
        assert_eq!((end.id, end.status, end.option), (3, kerlico_vless::END, 2));
        peer.write_all(&encode_mux(&kerlico_vless::session_frame(5, true, 80, "live.test", b"ok"))).unwrap();
        let live = accept_reverse(&bridge);
        let mut got = [0; 2];
        assert_eq!(live.stream().read_from_user(&mut got).unwrap(), 2);
        assert_eq!(&got, b"ok");
    }

    #[test]
    #[ignore = "requires XRAY pointing to Xray 26.10.31 a4a3dff"]
    fn reverse_api_interoperates_with_pinned_xray() {
        for variant in ["raw", "encrypted", "vision", "xdrive"] { reverse_xray_case(variant); }
    }

    fn reverse_xray_case(variant: &str) {
        let binary = std::env::var("XRAY").expect("XRAY");
        let version = std::process::Command::new(&binary).arg("version").output().unwrap();
        let version = String::from_utf8(version.stdout).unwrap();
        assert!(version.contains("26.10.31") && version.contains("a4a3dff"), "{version}");
        let listeners: Vec<_> = (0..3).map(|_| TcpListener::bind("127.0.0.1:0").unwrap()).collect();
        let ports: Vec<_> = listeners.iter().map(|listener| listener.local_addr().unwrap().port()).collect();
        let (peer, tcp_front, udp_front) = (ports[0], ports[1], ports[2]);
        drop(listeners);
        let id = "12345678-1234-4234-8234-123456789012";
        let path = std::env::temp_dir().join(format!("kerlico-reverse-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&path).unwrap();
        let (secret, public) = kerlico_vless::native_pair();
        let decryption = if variant == "raw" { "none".to_string() } else { kerlico_vless::encode_key("mlkem768x25519plus.native.0s.", &secret) };
        let encryption = if variant == "raw" { "none".to_string() } else { kerlico_vless::encode_key("mlkem768x25519plus.native.1rtt.", &public) };
        let flow = if variant == "vision" { "xtls-rprx-vision" } else { "" };
        let folder = path.join("storage").to_string_lossy().replace('\\', "/");
        let stream = if variant == "xdrive" { format!(r#"{{"network":"xdrive","xdriveSettings":{{"service":"local","remoteFolder":"{folder}"}}}}"#) } else { r#"{"network":"raw"}"#.to_string() };
        let config = format!(r#"{{
            "log": {{"loglevel":"info"}},
            "inbounds": [
                {{"protocol":"vless","listen":"127.0.0.1","port":{peer},"settings":{{"decryption":"{decryption}","users":[{{"id":"{id}","flow":"{flow}","reverse":{{"tag":"reverse-test"}}}}]}},"streamSettings":{stream}}},
                {{"tag":"front","protocol":"tunnel","listen":"127.0.0.1","port":{tcp_front},"settings":{{"address":"reverse-target.test","port":8080,"network":"tcp"}}}},
                {{"tag":"front-udp","protocol":"tunnel","listen":"127.0.0.1","port":{udp_front},"settings":{{"address":"reverse-dns.test","port":5353,"network":"udp"}}}}
            ],
            "outbounds":[{{"protocol":"blackhole"}}],
            "routing":{{"rules":[{{"type":"field","inboundTag":["front","front-udp"],"outboundTag":"reverse-test"}}]}}
        }}"#);
        std::fs::write(path.join("xray.json"), config).unwrap();
        struct Process(std::process::Child);
        impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let log = std::fs::File::create(path.join("xray.log")).unwrap();
        let _process = Process(std::process::Command::new(binary).args(["run", "-c"]).arg(path.join("xray.json")).stdout(log.try_clone().unwrap()).stderr(log).spawn().unwrap());
        let mut settings = Settings::default();
        settings.insert_text("id", id);
        settings.insert_text("encryption", encryption);
        settings.insert_text("flow", flow);
        if variant == "xdrive" {
            settings.insert_text("network", "xdrive");
            settings.insert_text("service", "local");
            settings.insert_text("remoteFolder", folder);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let bridge = loop {
            match reverse_bridge("127.0.0.1", peer, &settings) {
                Ok(bridge) => break bridge,
                Err(_) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                Err(error) => panic!("reverse open {error:?}; logs {}", path.display()),
            }
        };
        std::thread::sleep(Duration::from_millis(100));
        let expected: Vec<_> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let compare = expected.clone();
        let large = std::thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", tcp_front)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            socket.write_all(b"alpha").unwrap();
            let mut bytes = vec![0; compare.len()];
            socket.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, compare);
        });
        let small = std::thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", tcp_front)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            socket.write_all(b"beta").unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"beta");
        });
        let udp = std::thread::spawn(move || {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            socket.send_to(b"udp", ("127.0.0.1", udp_front)).unwrap();
            let mut bytes = [0; 32];
            let (n, _) = socket.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..n], b"UDP");
        });
        for _ in 0..3 {
            let flow = accept_reverse(&bridge);
            let mut buf = [0; 64];
            let n = loop {
                match flow.stream().read_from_user(&mut buf) {
                    Ok(n) => break n,
                    Err(PlaneFault::Again) => continue,
                    Err(error) => panic!("reverse input {error:?}"),
                }
            };
            let reply = match &buf[..n] {
                b"alpha" => { assert_eq!(flow.destination().host(), "reverse-target.test"); expected.as_slice() },
                b"beta" => b"beta",
                b"udp" => { assert_eq!(flow.destination().transport(), Transport::Udp); assert_eq!(flow.destination().port(), 5353); b"UDP" },
                other => panic!("unexpected reverse request {other:?}"),
            };
            let mut sent = 0;
            while sent < reply.len() {
                match flow.stream().write_to_user(&reply[sent..]) {
                    Ok(n) => { assert!(n > 0); sent += n; },
                    Err(PlaneFault::Again) => std::thread::sleep(Duration::from_millis(1)),
                    Err(error) => panic!("reverse reply {error:?}"),
                }
            }
        }
        large.join().unwrap();
        small.join().unwrap();
        udp.join().unwrap();
        eprintln!("PASS pinned Xray reverse {variant}: TCP/UDP and 1 MiB response; artifacts {}", path.display());
    }

    #[test]
    fn land_writes_a_tcp_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 128];
            let n = socket.read(&mut buf).unwrap();
            let (request, used) = decode_request(&buf[..n]).unwrap();
            assert_eq!(used, n);
            assert_eq!(request.command, Command::Tcp);
            assert_eq!(request.port, 443);
            socket
                .write_all(
                    &encode_response(&Response {
                        flow: String::new(),
                        seed: Vec::new(),
                    })
                    .unwrap(),
                )
                .unwrap();
            socket.write_all(b"ok").unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 443, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_opens_a_reverse_bridge() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0u8; 128];
            let n = socket.read(&mut buf).unwrap();
            let (request, used) = decode_request(&buf[..n]).unwrap();
            assert_eq!(used, n);
            assert_eq!(request.command, Command::Reverse);
            assert_eq!(request.port, 0);
            assert_eq!(request.address, Addr::Domain("v1.rvs.cool".to_string()));
            socket
                .write_all(
                    &encode_response(&Response {
                        flow: String::new(),
                        seed: Vec::new(),
                    })
                    .unwrap(),
                )
                .unwrap();
            socket.write_all(&encode_mux(&kerlico_vless::control_frame(1))).unwrap();
            socket
                .write_all(&encode_mux(&MuxFrame {
                    id: 3,
                    status: NEW,
                    option: DATA,
                    network: 1,
                    port: 80,
                    address: Some(Addr::Domain("example.com".to_string())),
                    payload: b"ok".to_vec(),
                }))
                .unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("id", "我爱🍉老师1314");
        settings.insert_text("reverse", "true");
        let destination = Destination::new("v1.rvs.cool", 1, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_speaks_vless_inside_native_encryption() {
        let (secret, public) = kerlico_vless::native_pair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let (mut reader, mut writer) = kerlico_vless::accept_native(socket, &[kerlico_vless::NfsKey::X25519(secret)], 0, 0, 0, &kerlico_vless::Pad::empty()).unwrap();
            let mut buf = [0u8; 128];
            let mut got = Vec::new();
            loop {
                let n = reader.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                if let Ok((request, used)) = decode_request(&got) {
                    assert_eq!(used, got.len());
                    assert_eq!(request.port, 443);
                    break;
                }
            }
            writer
                .write_all(&encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap())
                .unwrap();
            writer.write_all(b"ok").unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", &kerlico_vless::encode_key("mlkem768x25519plus.native.1rtt.", &public));
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 443, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_speaks_vless_after_reality_hello() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = socket.try_clone().unwrap();
            let mut writer = socket;
            let record = kerlico_vless::read_tls_record(&mut reader).unwrap();
            let accepted = kerlico_vless::server_flight_with_alpn(&record, &private, &short_id, &["h2"]).unwrap();
            writer.write_all(&accepted.flight).unwrap();
            kerlico_vless::read_client_finished(&mut reader, &accepted.handshake, &accepted.expect).unwrap();
            let (client_app, server_app) = accepted.application_keys();
            let mut reader = kerlico_vless::reality_reader(reader, client_app);
            let mut writer = kerlico_vless::reality_writer(writer, server_app);
            let mut buf = [0u8; 128];
            let mut got = Vec::new();
            loop {
                let n = reader.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                if let Ok((request, used)) = decode_request(&got) {
                    assert_eq!(used, got.len());
                    assert_eq!(request.port, 443);
                    break;
                }
            }
            writer.write_all(&encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap()).unwrap();
            writer.write_all(b"ok").unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("security", "reality");
        settings.insert_text("publicKey", &kerlico_vless::encode_reality_key(&public));
        settings.insert_text("shortId", "0102030405060708");
        settings.insert_text("serverName", "www.example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 443, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_speaks_vless_inside_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = certified.cert.pem();
        let key = certified.key_pair.serialize_pem();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let config = kerlico_vless::server_config(&cert, &key, &[]).unwrap();
            let mut link = kerlico_vless::accept_tls(tcp, config).unwrap();
            let mut buf = [0u8; 128];
            let mut got = Vec::new();
            loop {
                let n = link.read(&mut buf).unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
                if decode_request(&got).is_ok() {
                    break;
                }
            }
            link.write_all(
                &encode_response(&Response {
                    flow: String::new(),
                    seed: Vec::new(),
                })
                .unwrap(),
            )
            .unwrap();
            link.write_all(b"ok").unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("security", "tls");
        settings.insert_text("serverName", "localhost");
        settings.insert_text("allowInsecure", "true");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 443, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_upgrades_before_the_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            let used = loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                match kerlico_vless::take_upgrade_request(&buf) {
                    Ok((path, host, used)) => {
                        assert_eq!(path, "/vless");
                        assert_eq!(host, "localhost");
                        break used;
                    }
                    Err(kerlico_vless::UpgradeError::Short) => {}
                    Err(kerlico_vless::UpgradeError::Bad) => panic!("bad upgrade"),
                }
            };
            socket.write_all(kerlico_vless::upgrade_response()).unwrap();
            let mut rest = buf[used..].to_vec();
            while decode_request(&rest).is_err() {
                let n = socket.read(&mut tmp).unwrap();
                rest.extend_from_slice(&tmp[..n]);
            }
            socket
                .write_all(
                    &encode_response(&Response {
                        flow: String::new(),
                        seed: Vec::new(),
                    })
                    .unwrap(),
                )
                .unwrap();
            socket.write_all(b"ok").unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "httpupgrade");
        settings.insert_text("path", "/vless");
        settings.insert_text("host", "localhost");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_websocket_frames() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            let (key, used) = loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok((path, _, used)) = kerlico_vless::take_upgrade_request(&buf) {
                    assert_eq!(path, "/ws");
                    let head = std::str::from_utf8(&buf[..used]).unwrap();
                    break (kerlico_vless::header_value(head, "sec-websocket-key").unwrap(), used);
                }
            };
            socket.write_all(&kerlico_vless::switch_response(&key)).unwrap();
            let mut decoder = kerlico_vless::FrameDecoder::new(true);
            decoder.push(&buf[used..]).unwrap();
            let mut plain = Vec::new();
            while decode_request(&plain).is_err() {
                let n = socket.read(&mut tmp).unwrap();
                decoder.push(&tmp[..n]).unwrap();
                let mut piece = [0u8; 128];
                loop {
                    let got = decoder.pop(&mut piece);
                    if got == 0 {
                        break;
                    }
                    plain.extend_from_slice(&piece[..got]);
                }
            }
            let mut answer = encode_response(&Response {
                flow: String::new(),
                seed: Vec::new(),
            })
            .unwrap();
            answer.extend_from_slice(b"ok");
            socket.write_all(&kerlico_vless::encode_frame(0x2, &answer, false)).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "ws");
        settings.insert_text("path", "/ws");
        settings.insert_text("host", "localhost");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn landing_reuses_grpc_and_reconnects_after_goaway() {
        fn reply(conn: &GrpcConnection<TcpStream>) -> GrpcStream<TcpStream> {
            let mut rpc = conn.accept(&["/GunService/Tun"]).unwrap();
            assert_eq!(rpc.header(":authority").as_deref(), Some("matrix-authority.example"));
            assert_eq!(rpc.header("user-agent").as_deref(), Some("matrix-grpc/1"));
            let mut request = Vec::new();
            let mut part = [0; 128];
            while decode_request(&request).is_err() {
                let len = rpc.read(&mut part).unwrap();
                assert!(len > 0);
                request.extend_from_slice(&part[..len]);
            }
            rpc.write_all(&[0, 0, b'o', b'k']).unwrap();
            rpc
        }

        fn read(stream: &dyn InboundStream, expected: &[u8]) {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut actual = vec![0; expected.len()];
            let mut offset = 0;
            while offset < actual.len() {
                match stream.read_from_user(&mut actual[offset..]) {
                    Ok(len) if len > 0 => offset += len,
                    Err(PlaneFault::Again) if std::time::Instant::now() < deadline => {}
                    other => panic!("read gRPC: {other:?}"),
                }
            }
            assert_eq!(actual, expected);
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut control = socket.try_clone().unwrap();
            let conn = GrpcConnection::serve(socket.try_clone().unwrap(), socket).unwrap();
            let mut first = reply(&conn);
            let mut second = reply(&conn);
            // GOAWAY keeps streams 1 and 3 alive while forbidding new streams on this carrier.
            control.write_all(&[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0]).unwrap();
            first.write_all(b"drain").unwrap();
            let (socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let conn = GrpcConnection::serve(socket.try_clone().unwrap(), socket).unwrap();
            let _third = reply(&conn);
            second.write_all(b"still active").unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "grpc");
        settings.insert_text("serviceName", "GunService");
        settings.insert_text("authority", "matrix-authority.example");
        settings.insert_text("user_agent", "matrix-grpc/1");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let first = land("127.0.0.1", port, &settings, &destination).unwrap();
        let second = land("127.0.0.1", port, &settings, &destination).unwrap();
        read(first.as_ref(), b"ok");
        read(second.as_ref(), b"ok");
        read(first.as_ref(), b"drain");
        let third = land("127.0.0.1", port, &settings, &destination).unwrap();
        read(third.as_ref(), b"ok");
        read(second.as_ref(), b"still active");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_grpc_over_reality() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut reader = socket.try_clone().unwrap();
            let mut writer = socket;
            let record = kerlico_vless::read_tls_record(&mut reader).unwrap();
            let accepted = kerlico_vless::server_flight_with_alpn(&record, &private, &short_id, &["h2"]).unwrap();
            writer.write_all(&accepted.flight).unwrap();
            kerlico_vless::read_client_finished(&mut reader, &accepted.handshake, &accepted.expect).unwrap();
            let (client_app, server_app) = accepted.application_keys();
            let duplex = kerlico_vless::RealityDuplex::new(
                kerlico_vless::reality_reader(reader, client_app),
                kerlico_vless::reality_writer(writer, server_app),
            );
            let (read, write) = duplex.into_halves();
            let conn = GrpcConnection::serve(read, write).unwrap();
            let mut io = conn.accept(&["/GunService/Tun"]).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&buf).is_err() {
                let n = io.read(&mut tmp).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&tmp[..n]);
            }
            let mut answer = encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap();
            answer.extend_from_slice(b"ok");
            io.write_all(&answer).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "grpc");
        settings.insert_text("serviceName", "GunService");
        settings.insert_text("security", "reality");
        settings.insert_text("publicKey", &kerlico_vless::encode_reality_key(&public));
        settings.insert_text("shortId", "0102030405060708");
        settings.insert_text("serverName", "www.example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_http2() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut io = kerlico_vless::HttpIo::accept(socket, "/vless", "example.com", "POST").unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&buf).is_err() {
                let n = io.read(&mut tmp).unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&tmp[..n]);
            }
            let mut answer = encode_response(&Response {
                flow: String::new(),
                seed: Vec::new(),
            })
            .unwrap();
            answer.extend_from_slice(b"ok");
            io.write_all(&answer).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "http");
        settings.insert_text("path", "/vless");
        settings.insert_text("host", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_mkcp() {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, peer) = listener.recv_from(&mut buf).unwrap();
            let conv = u16::from_be_bytes([buf[0], buf[1]]);
            listener.connect(peer).unwrap();
            let mut session = kerlico_vless::Session::new(conv);
            for reply in session.input(&buf[..n]) {
                listener.send(&reply).unwrap();
            }
            let mut plain = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&plain).is_err() {
                let got = session.read(&mut tmp);
                if got > 0 {
                    plain.extend_from_slice(&tmp[..got]);
                    continue;
                }
                let n = listener.recv(&mut buf).unwrap();
                for reply in session.input(&buf[..n]) {
                    listener.send(&reply).unwrap();
                }
            }
            let mut answer = encode_response(&Response {
                flow: String::new(),
                seed: Vec::new(),
            })
            .unwrap();
            answer.extend_from_slice(b"ok");
            for packet in session.write(&answer).1 {
                listener.send(&packet).unwrap();
            }
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "mkcp");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_xhttp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut download, _) = listener.accept().unwrap();
            let get = kerlico_vless::read_http_request(&mut download).unwrap();
            assert_eq!(get.method, "GET");
            kerlico_vless::write_chunked_ok(&mut download).unwrap();
            let (mut upload, _) = listener.accept().unwrap();
            let post = kerlico_vless::read_http_request(&mut upload).unwrap();
            assert_eq!(post.method, "POST");
            assert!(decode_request(&post.body).is_ok());
            kerlico_vless::write_empty_ok(&mut upload).unwrap();
            let mut answer = encode_response(&Response {
                flow: String::new(),
                seed: Vec::new(),
            })
            .unwrap();
            answer.extend_from_slice(b"ok");
            kerlico_vless::write_chunk(&mut download, &answer).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_xhttp_over_reality() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let accept = |listener: &TcpListener| {
                let (socket, _) = listener.accept().unwrap();
                let mut reader = socket.try_clone().unwrap();
                let mut writer = socket;
                let record = kerlico_vless::read_tls_record(&mut reader).unwrap();
                let accepted = kerlico_vless::server_flight_with_alpn(&record, &private, &short_id, &["h2"]).unwrap();
                writer.write_all(&accepted.flight).unwrap();
                kerlico_vless::read_client_finished(&mut reader, &accepted.handshake, &accepted.expect).unwrap();
                let (client_app, server_app) = accepted.application_keys();
                kerlico_vless::RealityDuplex::new(
                    kerlico_vless::reality_reader(reader, client_app),
                    kerlico_vless::reality_writer(writer, server_app),
                )
            };
            let download = accept(&listener);
            let mut io = kerlico_vless::HttpIo::accept(download, "/xh/", "example.com", "POST").unwrap();
            let mut plain = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&plain).is_err() {
                let n = io.read(&mut tmp).unwrap();
                assert!(n > 0);
                plain.extend_from_slice(&tmp[..n]);
            }
            let mut answer = encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap();
            answer.extend_from_slice(b"ok");
            io.write_all(&answer).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("publicKey", &kerlico_vless::encode_reality_key(&public));
        settings.insert_text("shortId", "0102030405060708");
        settings.insert_text("serverName", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_posts_packets_over_reality_h2() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let accept = |listener: &TcpListener| {
                let (socket, _) = listener.accept().unwrap();
                let mut reader = socket.try_clone().unwrap();
                let mut writer = socket;
                let record = kerlico_vless::read_tls_record(&mut reader).unwrap();
                let accepted = kerlico_vless::server_flight_with_alpn(&record, &private, &short_id, &["h2"]).unwrap();
                writer.write_all(&accepted.flight).unwrap();
                kerlico_vless::read_client_finished(&mut reader, &accepted.handshake, &accepted.expect).unwrap();
                let (client_app, server_app) = accepted.application_keys();
                kerlico_vless::RealityDuplex::new(
                    kerlico_vless::reality_reader(reader, client_app),
                    kerlico_vless::reality_writer(writer, server_app),
                )
            };
            let download_socket = accept(&listener);
            let mut preface = [0u8; 24];
            let (mut reader, writer) = download_socket.into_halves();
            reader.read_exact(&mut preface).unwrap();
            assert_eq!(&preface, kerlico_vless::HTTP2_PREFACE);
            let conn = H2Conn::serve(reader, writer).unwrap();
            let mut download = conn.accept().unwrap();
            assert_eq!(download.header(":method").as_deref(), Some("GET"));
            assert!(download.header(":path").unwrap().starts_with("/xh/"));
            download.reply().unwrap();
            let upload = conn.accept().unwrap();
            assert_eq!(upload.header(":method").as_deref(), Some("POST"));
            let mut plain = Vec::new();
            let mut tmp = [0u8; 128];
            loop {
                let n = upload.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                plain.extend_from_slice(&tmp[..n]);
            }
            assert!(decode_request(&plain).is_ok());
            upload.reply().unwrap();
            let mut answer = encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap();
            answer.extend_from_slice(b"ok");
            download.write_all(&answer).unwrap();
            let _ = release_rx.recv();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "packet-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("publicKey", &kerlico_vless::encode_reality_key(&public));
        settings.insert_text("shortId", "0102030405060708");
        settings.insert_text("serverName", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        let _ = release_tx.send(());
        server.join().unwrap();
    }

    #[test]
    fn land_streams_up_over_reality_h2() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let accept = |listener: &TcpListener| {
                let (socket, _) = listener.accept().unwrap();
                let mut reader = socket.try_clone().unwrap();
                let mut writer = socket;
                let record = kerlico_vless::read_tls_record(&mut reader).unwrap();
                let accepted = kerlico_vless::server_flight_with_alpn(&record, &private, &short_id, &["h2"]).unwrap();
                writer.write_all(&accepted.flight).unwrap();
                kerlico_vless::read_client_finished(&mut reader, &accepted.handshake, &accepted.expect).unwrap();
                let (client_app, server_app) = accepted.application_keys();
                kerlico_vless::RealityDuplex::new(
                    kerlico_vless::reality_reader(reader, client_app),
                    kerlico_vless::reality_writer(writer, server_app),
                )
            };
            let download_socket = accept(&listener);
            let mut preface = [0u8; 24];
            let (mut reader, writer) = download_socket.into_halves();
            reader.read_exact(&mut preface).unwrap();
            let conn = H2Conn::serve(reader, writer).unwrap();
            let mut download = conn.accept().unwrap();
            assert_eq!(download.header(":method").as_deref(), Some("GET"));
            assert!(download.header(":path").unwrap().starts_with("/xh/"));
            download.reply().unwrap();
            let upload = conn.accept().unwrap();
            assert_eq!(upload.header(":method").as_deref(), Some("POST"));
            assert!(upload.header(":path").unwrap().starts_with("/xh/"));
            let mut plain = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&plain).is_err() {
                let n = upload.read(&mut tmp).unwrap();
                assert!(n > 0);
                plain.extend_from_slice(&tmp[..n]);
            }
            let mut answer = encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap();
            answer.extend_from_slice(b"ok");
            download.write_all(&answer).unwrap();
            let _ = release_rx.recv();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("publicKey", &kerlico_vless::encode_reality_key(&public));
        settings.insert_text("shortId", "0102030405060708");
        settings.insert_text("serverName", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        let _ = release_tx.send(());
        server.join().unwrap();
    }

    #[test]
    fn land_uses_xhttp_stream_one() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let head = kerlico_vless::read_http_head(&mut socket).unwrap();
            assert_eq!(head.method, "POST");
            assert_eq!(head.path, "/xh/");
            assert!(head.chunked);
            kerlico_vless::write_chunked_ok(&mut socket).unwrap();
            let pair = kerlico_vless::ChunkPair::open(socket, head.rest).unwrap();
            let mut plain = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&plain).is_err() {
                let n = pair.pull(&mut tmp).unwrap();
                assert!(n > 0);
                plain.extend_from_slice(&tmp[..n]);
            }
            let mut answer = encode_response(&Response {
                flow: String::new(),
                seed: Vec::new(),
            })
            .unwrap();
            answer.extend_from_slice(b"ok");
            pair.push(&answer).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-one");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_xhttp_stream_up() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut download, _) = listener.accept().unwrap();
            let get = kerlico_vless::read_http_request(&mut download).unwrap();
            assert_eq!(get.method, "GET");
            kerlico_vless::write_chunked_ok(&mut download).unwrap();
            let (mut upload, _) = listener.accept().unwrap();
            let head = kerlico_vless::read_http_head(&mut upload).unwrap();
            assert_eq!(head.method, "POST");
            assert!(head.chunked);
            assert!(head.path.starts_with("/xh/"));
            let pair = kerlico_vless::ChunkPair::split(upload, head.rest, download);
            let mut plain = Vec::new();
            let mut tmp = [0u8; 128];
            while decode_request(&plain).is_err() {
                let n = pair.pull(&mut tmp).unwrap();
                assert!(n > 0);
                plain.extend_from_slice(&tmp[..n]);
            }
            let mut answer = encode_response(&Response {
                flow: String::new(),
                seed: Vec::new(),
            })
            .unwrap();
            answer.extend_from_slice(b"ok");
            pair.push(&answer).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    #[test]
    fn land_uses_mux() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 256];
            let request = loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok((request, used)) = decode_request(&buf) {
                    buf.drain(..used);
                    break request;
                }
            };
            assert_eq!(request.command, kerlico_vless::Command::Mux);
            socket
                .write_all(&encode_response(&Response {
                    flow: String::new(),
                    seed: Vec::new(),
                })
                .unwrap())
                .unwrap();
            let frame = loop {
                if let Ok((frame, used)) = kerlico_vless::decode_mux(&buf) {
                    buf.drain(..used);
                    break frame;
                }
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
            };
            assert_eq!(frame.payload, b"ping");
            assert_eq!(frame.address.unwrap(), kerlico_vless::Addr::Domain("example.com".to_string()));
            let reply = kerlico_vless::encode_mux(&kerlico_vless::MuxFrame {
                id: frame.id,
                status: kerlico_vless::KEEP,
                option: kerlico_vless::DATA,
                network: 0,
                port: 0,
                address: None,
                payload: b"ok".to_vec(),
            });
            socket.write_all(&reply).unwrap();
        });
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("mux", "true");
        settings.insert_text("id", "我爱🍉老师1314");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let stream = land("127.0.0.1", port, &settings, &destination).unwrap();
        assert_eq!(stream.write_to_user(b"ping").unwrap(), 4);
        let mut buf = [0u8; 2];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 2);
        assert_eq!(&buf, b"ok");
        server.join().unwrap();
    }

    fn mux_policy(text: &str, xdrive: bool) -> Result<Option<mux::Policy>, OpenError> {
        let mut settings = Settings::default();
        settings.insert_text("mux", text);
        mux::Policy::parse(&settings, xdrive)
    }

    #[test]
    fn routes_follow_the_xray_outbound() {
        use mux::{PoolKind, Route::*};
        let udp = |port| Destination::new("example.com", port, Transport::Udp).unwrap();
        let tcp = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let policy = |text| mux_policy(text, false).unwrap();
        let plain = Flow::Plain;
        let vision = Flow::Vision { udp443: false };
        let cases = [
            (plain, None, tcp.clone(), Ok(Direct(Command::Tcp))),
            (plain, None, udp(8000), Ok(Xudp)),
            (plain, None, udp(53), Ok(Direct(Command::Udp))),
            (plain, None, udp(443), Ok(Direct(Command::Udp))),
            (vision, None, udp(53), Ok(Xudp)),
            (vision, None, udp(443), Err(OpenError::Settings)),
            (Flow::Vision { udp443: true }, None, udp(443), Ok(Xudp)),
            (plain, policy("false"), udp(8000), Ok(Xudp)),
            (plain, policy("true"), tcp.clone(), Ok(Pooled(PoolKind::Mux, 8))),
            (plain, policy("true"), udp(53), Ok(Pooled(PoolKind::Mux, 8))),
            (plain, policy("true"), udp(443), Err(OpenError::Settings)),
            (plain, policy(r#"{"enabled":true,"xudpProxyUDP443":"reject"}"#), udp(443), Err(OpenError::Settings)),
            (plain, policy(r#"{"enabled":true,"xudpProxyUDP443":"allow"}"#), udp(443), Ok(Pooled(PoolKind::Mux, 8))),
            (plain, policy(r#"{"enabled":true,"xudpProxyUDP443":"skip"}"#), udp(443), Ok(Direct(Command::Udp))),
            (plain, policy(r#"{"enabled":true,"concurrency":3,"xudpConcurrency":5}"#), udp(80), Ok(Pooled(PoolKind::Xudp, 5))),
            (plain, policy(r#"{"enabled":true,"concurrency":3,"xudpConcurrency":5}"#), tcp.clone(), Ok(Pooled(PoolKind::Mux, 3))),
            (plain, policy(r#"{"enabled":true,"xudpConcurrency":-1}"#), udp(80), Ok(Xudp)),
            (plain, policy(r#"{"enabled":true,"concurrency":-1}"#), tcp.clone(), Ok(Direct(Command::Tcp))),
            (plain, policy(r#"{"enabled":true,"concurrency":-1}"#), udp(80), Ok(Xudp)),
            (plain, policy(r#"{"enabled":true,"concurrency":-1}"#), udp(443), Err(OpenError::Settings)),
            (plain, policy(r#"{"enabled":true,"concurrency":-1,"xudpConcurrency":2}"#), udp(80), Ok(Pooled(PoolKind::Xudp, 2))),
            (vision, policy("true"), tcp.clone(), Err(OpenError::Settings)),
            (vision, policy(r#"{"enabled":true,"concurrency":-1}"#), tcp.clone(), Ok(Direct(Command::Tcp))),
            (vision, policy(r#"{"enabled":true,"xudpProxyUDP443":"allow"}"#), udp(443), Ok(Pooled(PoolKind::Mux, 8))),
            (vision, policy(r#"{"enabled":true,"xudpProxyUDP443":"skip"}"#), udp(443), Err(OpenError::Settings)),
        ];
        for (index, (flow, policy, destination, expected)) in cases.into_iter().enumerate() {
            assert_eq!(mux::route(flow, policy, &destination), expected, "route case {index}");
        }
    }

    #[test]
    fn mux_settings_follow_the_xray_config() {
        assert_eq!(mux_policy("false", false), Ok(None));
        assert_eq!(mux_policy(r#"{"concurrency":4}"#, false), Ok(None), "enabled defaults to false");
        assert!(mux_policy(r#"{"enabled":true,"xudpProxyUDP443":"drop"}"#, false).is_err());
        assert!(mux_policy(r#"{"enabled":true,"concurrency":40000}"#, false).is_err(), "concurrency is an int16");
        assert!(mux_policy("yes", false).is_err());
        assert!(mux_policy("false", true).unwrap().is_some(), "XDrive always uses Mux");
        for bypass in [
            r#"{"enabled":true,"concurrency":-1}"#,
            r#"{"enabled":true,"xudpConcurrency":-1}"#,
            r#"{"enabled":true,"xudpProxyUDP443":"skip"}"#,
        ] {
            assert!(mux_policy(bypass, true).is_err(), "XDrive refuses {bypass}");
        }
    }

    type Carriers = Arc<Mutex<Vec<Vec<u16>>>>;

    /// A VLESS Mux server that echoes every session and records the session ids each carrier
    /// opens. A session that sends `close` takes its carrier down.
    fn mux_echo_server() -> (u16, Carriers) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let carriers = Carriers::default();
        let seen = carriers.clone();
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(mut socket) = socket else { return };
                let index = {
                    let mut carriers = seen.lock().unwrap();
                    carriers.push(Vec::new());
                    carriers.len() - 1
                };
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        if let Ok((request, used)) = decode_request(&buf) {
                            assert_eq!(request.command, Command::Mux);
                            buf.drain(..used);
                            break;
                        }
                        match socket.read(&mut tmp) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    socket.write_all(&encode_response(&Response { flow: String::new(), seed: Vec::new() }).unwrap()).unwrap();
                    loop {
                        while let Ok((frame, used)) = kerlico_vless::decode_mux(&buf) {
                            buf.drain(..used);
                            if frame.status == NEW {
                                seen.lock().unwrap()[index].push(frame.id);
                            }
                            if frame.payload == b"close" {
                                return;
                            }
                            if frame.payload.is_empty() {
                                continue;
                            }
                            let reply = MuxFrame { id: frame.id, status: KEEP, option: DATA, network: 0, port: 0, address: None, payload: frame.payload };
                            if socket.write_all(&encode_mux(&reply)).is_err() {
                                return;
                            }
                        }
                        match socket.read(&mut tmp) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                });
            }
        });
        (port, carriers)
    }

    fn mux_landing(mux: &str) -> Settings {
        let mut settings = Settings::default();
        settings.insert_text("encryption", "none");
        settings.insert_text("id", "mux-pool");
        settings.insert_text("mux", mux);
        settings
    }

    fn echo(stream: &dyn InboundStream, payload: &[u8]) {
        assert_eq!(stream.write_to_user(payload), Ok(payload.len()));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        while received.len() < payload.len() {
            match stream.read_from_user(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(PlaneFault::Again) if std::time::Instant::now() < deadline => {}
                other => panic!("echo read: {other:?}"),
            }
        }
        assert_eq!(received, payload);
    }

    #[test]
    fn concurrent_lands_share_a_carrier_up_to_the_concurrency() {
        let (port, carriers) = mux_echo_server();
        let settings = mux_landing(r#"{"enabled":true,"concurrency":2}"#);
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let flows: Vec<_> = (0..3).map(|_| land("127.0.0.1", port, &settings, &destination).unwrap()).collect();
        for (index, flow) in flows.iter().enumerate() {
            echo(flow.as_ref(), format!("flow {index}").as_bytes());
        }
        assert_eq!(*carriers.lock().unwrap(), vec![vec![1, 2], vec![1]]);
    }

    #[test]
    fn carrier_retires_after_128_sessions() {
        let (port, carriers) = mux_echo_server();
        let settings = mux_landing("true");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        for _ in 0..129 {
            echo(land("127.0.0.1", port, &settings, &destination).unwrap().as_ref(), b"ping");
        }
        assert_eq!(*carriers.lock().unwrap(), vec![(1..=128).collect::<Vec<u16>>(), vec![1]]);
    }

    #[test]
    fn closed_carrier_is_replaced_on_the_next_land() {
        let (port, carriers) = mux_echo_server();
        let settings = mux_landing("true");
        let destination = Destination::new("example.com", 80, Transport::Tcp).unwrap();
        let first = land("127.0.0.1", port, &settings, &destination).unwrap();
        echo(first.as_ref(), b"before");
        first.write_to_user(b"close").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 16];
        loop {
            match first.read_from_user(&mut buf) {
                Err(PlaneFault::Closed) => break,
                Err(PlaneFault::Again) if std::time::Instant::now() < deadline => {}
                other => panic!("session on a closed carrier: {other:?}"),
            }
        }
        echo(land("127.0.0.1", port, &settings, &destination).unwrap().as_ref(), b"after");
        assert_eq!(carriers.lock().unwrap().len(), 2);
    }
}
