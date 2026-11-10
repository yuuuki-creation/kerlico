use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::num::NonZeroU64;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use kerlico_shared::{
    Accept, Destination, Handoff, InboundStream, ListenAddr, NodeTag, OpenError, PlaneFault, Settings,
    Transport, UserEmail,
};
use kerlico_vless::{
    accept_native, accept_tls, accept_tls_split, decode_reality_key, decode_short_id, decode_udp, encode_response, encode_udp, grpc_path, host_matches, normalize_path, parse_id, read_client_finished, read_tls_record, reality_accept, reality_reader, reality_writer, server_flight, server_key, AppReader, AppWriter, EncReader, EncWriter, RealityDuplex, TlsRead, TlsWrite,
    server_config, Command, Request, Response, TlsLink,
    Vision, WsIo, GrpcConnection, GrpcStream, HttpIo, Session, XhttpBodyWriter, ChunkPair,
    decode_mux, encode_mux, MuxFrame, DATA, END, KEEP, KEEPALIVE, NEW, HTTP2_PREFACE,
    ChunkReader, HttpHead, XhttpConfig, XhttpRequestKind, read_http_head_with_limit, write_xhttp_response,
    HttpPrefaceRead, RawHttpConfig, RawHttpWrite, UpgradeConfig,
};
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Clone)]
struct RealityConfig {
    private: [u8; 32],
    policy: kerlico_vless::RealityPolicy,
    alpn: Vec<String>,
    proof: Option<kerlico_vless::RealityMldsa65Signer>,
    target: Option<FallbackSet>,
}

fn reality_config(settings: &Settings) -> Result<RealityConfig, OpenError> {
    let private = decode_reality_key(settings.text("privateKey")?).ok_or(OpenError::Settings)?;
    let ids = match settings.text("shortIds") {
        Ok(text) => kerlico_vless::string_list(text).map_err(|_| OpenError::Settings)?,
        Err(_) => vec![settings.text("shortId").unwrap_or("").to_string()],
    };
    if ids.is_empty() { return Err(OpenError::Settings); }
    let short_ids = ids.iter().map(|id| decode_short_id(id).ok_or(OpenError::Settings)).collect::<Result<Vec<_>, _>>()?;
    let server_names = kerlico_vless::string_list(settings.text("serverNames").unwrap_or("")).map_err(|_| OpenError::Settings)?;
    let version = |key| -> Result<Option<[u8; 3]>, OpenError> {
        match settings.text(key) { Ok(text) if !text.is_empty() => kerlico_vless::decode_reality_version(text).map(Some).ok_or(OpenError::Settings), _ => Ok(None) }
    };
    let max_time_diff = settings.text("maxTimeDiff").ok().map(|text| text.parse::<u64>().map(Duration::from_millis).map_err(|_| OpenError::Settings)).transpose()?;
    let proof = match settings.text("mldsa65Seed") {
        Ok(seed) if !seed.is_empty() => {
            if decode_reality_key(seed) == Some(private) { return Err(OpenError::Settings); }
            Some(kerlico_vless::RealityMldsa65Signer::from_base64(seed).ok_or(OpenError::Settings)?)
        }
        _ => None,
    };
    let mut names = alpn(settings);
    if names.is_empty() { names = vec!["h2".into(), "http/1.1".into()]; }
    let target = settings.text("target").or_else(|_| settings.text("dest")).ok().map(|target| {
        let (host, port) = parse_fallback(target)?;
        Ok::<_, OpenError>(FallbackSet::build(vec![(String::new(), String::new(), String::new(), Fallback { host, port, xver: 0 })]))
    }).transpose()?;
    Ok(RealityConfig { private, policy: kerlico_vless::RealityPolicy { server_names, short_ids, min_client_ver: version("minClientVer")?, max_client_ver: version("maxClientVer")?, max_time_diff }, alpn: names, proof, target })
}

type Decryption = (Vec<kerlico_vless::NfsKey>, u8, u64, u64, kerlico_vless::Pad);

struct Users {
    masks: kerlico_vless::finalmask::FinalMask,
    node: NodeTag,
    entries: Mutex<BTreeMap<[u8; 16], Account>>,
    encryption: Option<Decryption>,
    allow_plain: bool,
    allow_vision: bool,
    fallback: FallbackSet,
    xudp: XudpSessions,
}

impl Users {
    fn new(encryption: Option<Decryption>, settings: &Settings, node: &NodeTag) -> Result<Self, OpenError> {
        let allow_plain = encryption.is_some() || settings.text("security").unwrap_or("none") != "none" || settings.text("trusted").ok() == Some("true");
        let masks = final_masks(settings)?;
        masks.validate(kerlico_vless::finalmask::Side::Server).map_err(|_| OpenError::Settings)?;
        Ok(Self { masks, node: node.clone(), entries: Mutex::new(BTreeMap::new()), encryption, allow_plain, allow_vision: settings.text("network").ok() != Some("xdrive"), fallback: load_fallbacks(settings)?, xudp: XudpSessions::default() })
    }

    fn allows(&self, peer: SocketAddr) -> bool { self.allow_plain || kerlico_vless::private_peer(peer.ip()) }
}

impl std::ops::Deref for Users {
    type Target = Mutex<BTreeMap<[u8; 16], Account>>;
    fn deref(&self) -> &Self::Target { &self.entries }
}

struct Account {
    email: UserEmail,
    flow: String,
    reverse: String,
    active: Arc<std::sync::atomic::AtomicBool>,
}

struct Ready {
    email: UserEmail,
    destination: Destination,
    peer: SocketAddr,
    read: Link,
    write: Link,
    udp: bool,
    prefix: Vec<u8>,
}

pub struct VlessInbound {
    tag: NodeTag,
    default_flow: String,
    accounts: Arc<Users>,
    ready_rx: Receiver<Ready>,
}

pub fn listen(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
) -> Result<Box<dyn Accept>, OpenError> {
    let decryption = settings.text("decryption")?;
    let native = if decryption == "none" {
        None
    } else {
        Some(server_key(decryption).ok_or(OpenError::Settings)?)
    };
    if native.is_some() && (settings.text("fallback").is_ok() || settings.text("fallbacks").is_ok()) {
        return Err(OpenError::Settings);
    }
    let network = match settings.text("network").unwrap_or("tcp") {
        "kcp" => "mkcp", "websocket" => "ws", "splithttp" => "xhttp", network => network,
    };
    if network == "xdrive" { return listen_xdrive(tag, settings, native); }
    if network == "hysteria" { return listen_hysteria(tag, bind, settings, native); }
    if network == "mkcp" {
        return listen_kcp(tag, bind, settings, native);
    }
    if network == "xhttp" {
        return listen_xhttp(tag, bind, settings, native);
    }
    let raw_http = if matches!(network, "tcp" | "raw") {
        RawHttpConfig::parse(settings.text("header").ok()).map_err(|_| OpenError::Settings)?.map(Arc::new)
    } else {
        None
    };
    let upgrade = match network {
        "tcp" | "raw" | "grpc" | "http" => None,
        "httpupgrade" | "ws" => Some(Arc::new(UpgradeConfig::new(
            network == "ws",
            settings.text("path").unwrap_or("/"),
            settings.text("host").unwrap_or_default(),
            "",
            settings.text("headers").ok(),
        ).map_err(|_| OpenError::Settings)?)),
        _ => return Err(OpenError::Settings),
    };
    let grpc = if network == "grpc" {
        Some(GrpcCfg {
            paths: vec![grpc_path(settings.text("serviceName").unwrap_or(""), false), grpc_path(settings.text("serviceName").unwrap_or(""), true)],
            options: kerlico_vless::GrpcOptions::parse(|name| settings.text(name).ok(), true).map_err(|_| OpenError::Settings)?,
        })
    } else {
        None
    };
    let http = if network == "http" {
        Some(HttpCfg {
            path: normalize_path(settings.text("path").unwrap_or("/")),
            host: settings.text("host").unwrap_or("").to_string(),
            method: settings.text("method").unwrap_or("POST").to_string(),
        })
    } else {
        None
    };
    let reality = if settings.text("security").ok() == Some("reality") {
        if !matches!(network, "tcp" | "raw" | "grpc") {
            return Err(OpenError::Settings);
        }
        Some(reality_config(settings)?)
    } else {
        None
    };
    let tls = match settings.text("security") {
        Err(_) | Ok("none") | Ok("reality") => None,
        Ok("tls") => Some(tls_server_config(settings, &alpn(settings))?),
        Ok(_) => return Err(OpenError::Settings),
    };
    let default_flow = match settings.text("flow") {
        Err(_) => String::new(),
        Ok(flow) => known_flow(flow)?.to_string(),
    };
    let fallback = if settings.text("fallback").is_ok() || settings.text("fallbacks").is_ok() {
        if native.is_some() {
            return Err(OpenError::Settings);
        }
        load_fallbacks(settings)?
    } else {
        FallbackSet::empty()
    };
    let listener = bind_tcp(bind.socket_addr(), settings).map_err(|_| OpenError::Transport)?;
    listener.set_nonblocking(false).ok();
    let accounts = Arc::new(Users::new(native, settings, tag)?);
    let (ready_tx, ready_rx) = mpsc::channel();
    let shared = Arc::clone(&accounts);
    let sockopt = kerlico_vless::socket::SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?;
    let accept_proxy = settings.text("acceptProxyProtocol").ok() == Some("true") || sockopt.accept_proxy_protocol;
    let forwarded_for = sockopt.trusted_forwarded_for;
    thread::spawn(move || accept_loop(listener, shared, ready_tx, tls, upgrade, raw_http, grpc, http, fallback, reality, accept_proxy, forwarded_for));
    Ok(Box::new(VlessInbound {
        tag: tag.clone(),
        default_flow,
        accounts,
        ready_rx,
    }))
}

fn listen_xdrive(tag: &NodeTag, settings: &Settings, native: Option<Decryption>) -> Result<Box<dyn Accept>, OpenError> {
    if native.is_none() || !settings.text("flow").unwrap_or("").is_empty() || settings.text("security").ok() == Some("reality") { return Err(OpenError::Settings); }
    let drive = if let Ok(config) = settings.text("xdriveSettings") {
        let tls_options = tls_options(settings, &alpn(settings))?;
        let security = settings.text("security").ok() == Some("tls");
        let options = kerlico_vless::xdrive::XdriveHttpOptions {
            tls: if security { Some(kerlico_vless::advanced_client_config(&tls_options).map_err(|_| OpenError::Settings)?) } else { None },
            quic: if security && tls_options.alpn == ["h3"] {
                let masks = final_masks(settings)?;
                let quic = kerlico_vless::QuicOptions::parse(masks.quic_params()).map_err(|_| OpenError::Settings)?;
                Some(kerlico_vless::advanced_quic_client_config(&tls_options, quic.chrome_parrot(true)).map_err(|_| OpenError::Settings)?)
            } else { None },
            masks: final_masks(settings)?,
            server_name: settings.text("serverName").ok().map(str::to_string),
            connect_to: settings.text("storageAddress").ok().map(|address| (address.to_string(), settings.text("storagePort").unwrap_or("0").parse().unwrap_or(0))),
        };
        kerlico_vless::xdrive::Xdrive::new(config, options)
    } else if settings.text("service").ok() == Some("local") {
        kerlico_vless::xdrive::Xdrive::local(settings.text("remoteFolder")?)
    } else { return Err(OpenError::Settings); }.map_err(|_| OpenError::Settings)?;
    let mut listener = drive.listen().map_err(|_| OpenError::Transport)?;
    let accounts = Arc::new(Users::new(native, settings, tag)?);
    let (ready_tx, ready_rx) = mpsc::channel();
    let shared = accounts.clone();
    thread::spawn(move || loop {
        let Ok((read, write)) = listener.accept() else { thread::sleep(Duration::from_millis(100)); continue; };
        let accounts = shared.clone();
        let ready_tx = ready_tx.clone();
        thread::spawn(move || {
            if let Some(ready) = handshake(Link::XdriveRead(read), Link::XdriveWrite(write), SocketAddr::from(([127,0,0,1], 0)), None, &accounts, &ready_tx, FallbackSet::empty(), Vec::new(), String::new(), String::new()) {
                ready_tx.send(ready).ok();
            }
        });
    });
    Ok(Box::new(VlessInbound { tag: tag.clone(), default_flow: String::new(), accounts, ready_rx }))
}

fn listen_hysteria(tag: &NodeTag, bind: &ListenAddr, settings: &Settings, native: Option<Decryption>) -> Result<Box<dyn Accept>, OpenError> {
    if settings.text("security").ok() != Some("tls") || settings.text("version").unwrap_or("2") != "2" { return Err(OpenError::Settings); }
    let config = quic_tls_server_config(settings)?;
    let accounts = Arc::new(Users::new(native, settings, tag)?);
    let mut masquerade = kerlico_vless::HysteriaMasquerade::parse(settings.text("masquerade").ok()).map_err(|_| OpenError::Settings)?;
    if let Some(network) = accounts.masks.network() { masquerade = masquerade.with_dialer(network.masquerade_dialer()); }
    let listener = kerlico_vless::HysteriaListener::bind_crypto_with_masquerade(bind.socket_addr(), config, settings.text("auth")?, &accounts.masks, masquerade).map_err(|_| OpenError::Transport)?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let shared = accounts.clone();
    let default_flow = known_flow(settings.text("flow").unwrap_or(""))?.to_string();
    thread::spawn(move || loop {
        let Ok((peer, read, write)) = listener.accept() else { break; };
        let accounts = shared.clone();
        let ready_tx = ready_tx.clone();
        thread::spawn(move || {
            if let Some(ready) = handshake(Link::HysteriaRead(read), Link::HysteriaWrite(write), peer, None, &accounts, &ready_tx, FallbackSet::empty(), Vec::new(), String::new(), String::new()) {
                ready_tx.send(ready).ok();
            }
        });
    });
    Ok(Box::new(VlessInbound { tag: tag.clone(), default_flow, accounts, ready_rx }))
}

fn listen_kcp(tag: &NodeTag, bind: &ListenAddr, settings: &Settings, native: Option<Decryption>) -> Result<Box<dyn Accept>, OpenError> {
    let tls = match settings.text("security").unwrap_or("none") {
        "none" => None,
        "tls" => Some(tls_server_config(settings, &alpn(settings))?),
        _ => return Err(OpenError::Settings),
    };
    let default_flow = match settings.text("flow") {
        Err(_) => String::new(),
        Ok(flow) => known_flow(flow)?.to_string(),
    };
    let mask = kerlico_vless::kcp_mask(
        settings.text("header").unwrap_or("none"),
        settings.text("domain").unwrap_or(""),
        settings.text("seed").unwrap_or(""),
    )
    .ok_or(OpenError::Settings)?;
    let options = kerlico_vless::KcpOptions::from_settings(|key| settings.text(key).ok())
        .map_err(|_| OpenError::Settings)?;
    let accounts = Arc::new(Users::new(native, settings, tag)?);
    let socket = accounts.masks.udp_server(bind.socket_addr(), |addr| {
        let socket = kerlico_vless::socket::SocketOptions::parse(settings.text("sockopt").ok())?.open(kerlico_vless::socket::SocketKind::Udp, kerlico_vless::socket::SocketRole::Listener, addr)?;
        socket.bind(&addr.into())?;
        let socket: UdpSocket = socket.into();
        socket.set_read_timeout(Some(options.poll_interval()))?;
        socket.set_write_timeout(Some(Duration::from_millis(200)))?;
        Ok(Arc::new(socket))
    }).map_err(|_| OpenError::Transport)?;
    let (ready_tx, ready_rx) = mpsc::channel();
    let shared = Arc::clone(&accounts);
    thread::spawn(move || kcp_loop(socket, shared, ready_tx, mask, tls, options));
    Ok(Box::new(VlessInbound {
        tag: tag.clone(),
        default_flow,
        accounts,
        ready_rx,
    }))
}

fn kcp_loop(socket: Arc<dyn kerlico_vless::finalmask::PacketIo>, accounts: Arc<Users>, ready_tx: Sender<Ready>, mask: kerlico_vless::KcpMask, tls: Option<Arc<kerlico_vless::AdvancedTlsServerConfig>>, options: kerlico_vless::KcpOptions) {
    let mut lanes: HashMap<(SocketAddr, u16), Arc<KcpLane>> = HashMap::new();
    let mut buf = [0u8; 65535];
    let mut timer = std::time::Instant::now();
    loop {
        if timer.elapsed() >= options.poll_interval() {
            timer = std::time::Instant::now();
            lanes.retain(|_, lane| {
                let packets = {
                    let mut session = lane.session.lock().expect("kcp");
                    if Arc::strong_count(lane) == 1 { session.close(); }
                    session.poll()
                };
                lane.send(packets);
                let active = !lane.session.lock().expect("kcp").terminated();
                if !active { lane.cv.notify_all(); }
                active
            });
        }
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => continue,
            Err(_) => break,
        };
        if !accounts.allow_plain && (!accounts.masks.preserves_peer_address() || !kerlico_vless::private_peer(peer.ip())) { continue; }
        let Some(plain) = mask.open(&buf[..n]) else { continue; };
        if plain.len() < 4 { continue; }
        let conv = u16::from_be_bytes([plain[0], plain[1]]);
        if !lanes.contains_key(&(peer, conv)) && (plain.len() < 18 || plain[2] != 1 || plain[3] & 1 != 0) { continue; }
        let lane = lanes.entry((peer, conv)).or_insert_with(|| {
            let lane = Arc::new(KcpLane {
                socket: Arc::clone(&socket), peer,
                session: Mutex::new(Session::with_options(conv, options)), mask: Mutex::new(mask.clone()),
                cv: Condvar::new(), timeout_ms: std::sync::atomic::AtomicU64::new(10_000),
            });
            let read = Link::Kcp(Arc::clone(&lane));
            let write = Link::Kcp(Arc::clone(&lane));
            let accounts = Arc::clone(&accounts);
            let ready_tx = ready_tx.clone();
            let tls = tls.clone();
            thread::spawn(move || {
                let (read, write) = if let Some(tls) = tls {
                    let Ok((read, write)) = kerlico_vless::accept_advanced_tls_over(Box::new(read), Box::new(write), tls) else { return; };
                    (Link::TlsRead(Box::new(read)), Link::TlsWrite(Box::new(write)))
                } else { (read, write) };
                if let Some(ready) = handshake(read, write, peer, None, &accounts, &ready_tx, FallbackSet::empty(), Vec::new(), String::new(), String::new()) {
                    ready_tx.send(ready).ok();
                }
            });
            lane
        });
        let replies = lane.session.lock().expect("kcp").input(&plain);
        lane.send(replies);
        lane.cv.notify_all();
    }
}

struct KcpLane {
    socket: Arc<dyn kerlico_vless::finalmask::PacketIo>,
    peer: SocketAddr,
    session: Mutex<Session>,
    mask: Mutex<kerlico_vless::KcpMask>,
    cv: Condvar,
    timeout_ms: std::sync::atomic::AtomicU64,
}

impl KcpLane {
    fn send(&self, packets: Vec<Vec<u8>>) {
        for packet in packets {
            let dressed = self.mask.lock().expect("kcp").seal(&packet);
            if let Err(error) = self.socket.send_to(&dressed, self.peer) {
                if !matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) {
                    self.session.lock().expect("kcp").abort();
                    self.cv.notify_all();
                    break;
                }
            }
        }
    }

    fn pull(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let deadline = std::time::Instant::now() + Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed));
        let mut session = self.session.lock().expect("kcp");
        loop {
            let n = session.read(buf);
            if n > 0 { return Ok(n); }
            if session.read_closed() { return Ok(0); }
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            if wait.is_zero() { return Err(std::io::ErrorKind::WouldBlock.into()); }
            session = self.cv.wait_timeout(session, wait).expect("kcp").0;
        }
    }

    fn push(&self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let deadline = std::time::Instant::now() + Duration::from_millis(self.timeout_ms.load(std::sync::atomic::Ordering::Relaxed));
        let mut session = self.session.lock().expect("kcp");
        loop {
            if session.write_closed() { return Err(std::io::ErrorKind::BrokenPipe.into()); }
            let (accepted, packets) = session.write(buf);
            if accepted != 0 {
                drop(session);
                self.send(packets);
                return Ok(accepted);
            }
            if !packets.is_empty() {
                drop(session);
                self.send(packets);
                session = self.session.lock().expect("kcp");
                continue;
            }
            let wait = deadline.saturating_duration_since(std::time::Instant::now());
            if wait.is_zero() { return Err(std::io::ErrorKind::WouldBlock.into()); }
            session = self.cv.wait_timeout(session, wait).expect("kcp").0;
        }
    }
}

fn listen_xhttp(
    tag: &NodeTag,
    bind: &ListenAddr,
    settings: &Settings,
    native: Option<Decryption>,
) -> Result<Box<dyn Accept>, OpenError> {
    let default_flow = match settings.text("flow") {
        Err(_) => String::new(),
        Ok(flow) => known_flow(flow)?.to_owned(),
    };
    let config = Arc::new(
        XhttpConfig::from_settings(|key| settings.text(key).ok())
            .map_err(|_| OpenError::Settings)?,
    );
    let reality = if settings.text("security").ok() == Some("reality") {
        Some(reality_config(settings)?)
    } else {
        None
    };
    let tls = match settings.text("security") {
        Err(_) | Ok("none") | Ok("reality") => None,
        Ok("tls") => {
            let mut names = alpn(settings);
            if names.is_empty() {
                names.push("h2".to_owned());
            }
            Some(
                tls_server_config(settings, &names)?,
            )
        }
        Ok(_) => return Err(OpenError::Settings),
    };
    let accounts = Arc::new(Users::new(native, settings, tag)?);
    let (ready_tx, ready_rx) = mpsc::channel();
    let h3 = tls.is_some() && alpn(settings) == ["h3"];
    let h2 = if h3 {
        H2Serve::default()
    } else {
        // Go's HTTP/1 limit becomes a header-list size with 32 bytes of overhead for ten typical fields.
        let header_list = config.max_header_bytes() as u32 + 320;
        match config.h2_params() {
            "" => H2Serve { limits: kerlico_vless::H2Limits { header_list: Some(header_list), ..Default::default() }, permit_prohibited_ciphers: false },
            text => {
                let params = kerlico_vless::H2Params::parse(text).map_err(|_| OpenError::Settings)?;
                H2Serve { limits: params.limits(header_list), permit_prohibited_ciphers: params.permit_prohibited_ciphers }
            }
        }
    };
    let shared = Arc::new(XhttpListener {
        accounts: accounts.clone(),
        ready: ready_tx,
        config,
        h2,
        forwarded_for: kerlico_vless::TrustedForwardedFor::from_sockopt(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?,
        sessions: Mutex::new(HashMap::new()),
    });
    if h3 {
        let listener = kerlico_vless::H3Listener::bind_crypto_masked(
            bind.socket_addr(),
            quic_tls_server_config(settings)?,
            shared.config.max_header_bytes() as u64,
            &shared.accounts.masks,
        )
        .map_err(|_| OpenError::Transport)?;
        thread::spawn(move || {
            while let Ok((peer, stream)) = listener.accept() {
                let shared = shared.clone();
                thread::spawn(move || shared.serve_stream(HttpStream::H3(stream), peer));
            }
        });
    } else {
        let listener = bind_tcp(bind.socket_addr(), settings).map_err(|_| OpenError::Transport)?;
        let accept_proxy = settings.text("acceptProxyProtocol").ok() == Some("true") || kerlico_vless::socket::SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?.accept_proxy_protocol;
        thread::spawn(move || xhttp_loop(listener, shared, reality, tls, accept_proxy));
    }
    Ok(Box::new(VlessInbound {
        tag: tag.clone(),
        default_flow,
        accounts,
        ready_rx,
    }))
}

fn xhttp_loop(
    listener: TcpListener,
    shared: Arc<XhttpListener>,
    reality: Option<RealityConfig>,
    tls: Option<Arc<kerlico_vless::AdvancedTlsServerConfig>>,
    accept_proxy: bool,
) {
    while let Ok((mut socket, peer)) = listener.accept() {
        if !shared.accounts.allows(peer) {
            continue;
        }
        let shared = shared.clone();
        let reality = reality.clone();
        let tls = tls.clone();
        thread::spawn(move || {
            let peer = if accept_proxy {
                socket.set_read_timeout(Some(Duration::from_secs(10))).ok();
                let local = socket.local_addr().ok();
                match kerlico_vless::accept_proxy(&mut socket, peer, local) { Ok((peer, _)) => peer, Err(_) => return }
            } else { peer };
            let _ = xhttp_connection(socket, peer, shared, reality, tls);
        });
    }
}

fn xhttp_connection(
    socket: TcpStream,
    peer: SocketAddr,
    shared: Arc<XhttpListener>,
    reality: Option<RealityConfig>,
    tls: Option<Arc<kerlico_vless::AdvancedTlsServerConfig>>,
) -> io::Result<()> {
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let timers = socket.try_clone()?;
    let local = socket.local_addr().ok();
    let (read, write) = tcp_pair(socket, &shared.accounts.masks, peer, local)?;
    let mut tls_security = None;
    let mut socket = if let Some(config) = tls {
        let (read, write) = kerlico_vless::accept_advanced_tls_over(Box::new(read), Box::new(write), config)?;
        tls_security = Some(read.h2_security());
        Xpipe { read: Link::TlsRead(Box::new(read)), write: Link::TlsWrite(Box::new(write)) }
    } else if let Some(config) = reality {
        let connection = open_reality(read, write, &config, &shared.ready, peer, local).ok_or_else(|| io::Error::other("XHTTP REALITY handshake"))?;
        let (read, write) = connection.into_halves();
        Xpipe { read: Link::RealityRead(read), write: Link::RealityWrite(write) }
    } else { Xpipe { read, write } };

    let mut prefix = vec![0; 4];
    socket.read_exact(&mut prefix)?;
    if prefix == b"PRI " {
        prefix.resize(HTTP2_PREFACE.len(), 0);
        socket.read_exact(&mut prefix[4..])?;
        if prefix == HTTP2_PREFACE {
            let limits = shared.h2.limits;
            if let Some((old, cipher)) = tls_security {
                if let Some(reason) = kerlico_vless::h2_tls_rejection(old, cipher, shared.h2.permit_prohibited_ciphers) {
                    socket.write_all(&kerlico_vless::goaway_frame(kerlico_vless::INADEQUATE_SECURITY, &reason))?;
                    socket.flush()?;
                    return Err(io::Error::other(reason));
                }
            }
            if let Some(after) = limits.ping_after {
                let tick = after.min(limits.ping_timeout) / 4;
                timers.set_read_timeout(Some(tick.clamp(Duration::from_millis(5), Duration::from_secs(10))))?;
            }
            if let Some(timeout) = limits.write_timeout {
                timers.set_write_timeout(Some(timeout))?;
            }
            let (read, write) = socket.split()?;
            let conn = kerlico_vless::H2Conn::serve_with_limits(read, write, limits)?;
            loop {
                match conn.accept() {
                    Ok(stream) => {
                        let shared = shared.clone();
                        thread::spawn(move || shared.serve_stream(HttpStream::H2(stream), peer));
                    }
                    Err(error) if xhttp_retryable(&error) => {}
                    Err(error) => return Err(error),
                }
            }
        }
    }
    shared.serve_h1(socket, prefix, peer)
}

struct Lead<T> {
    lead: Vec<u8>,
    inner: T,
}

impl<T: Read> Read for Lead<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.lead.is_empty() {
            let n = self.lead.len().min(buf.len());
            buf[..n].copy_from_slice(&self.lead[..n]);
            self.lead.drain(..n);
            return Ok(n);
        }
        self.inner.read(buf)
    }
}

impl<T: Write> Write for Lead<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct Xpipe { read: Link, write: Link }

impl Xpipe {
    fn split(self) -> io::Result<(Half, Half)> { Ok((self.read, self.write)) }
}
impl Read for Xpipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.read.read(buf) }
}
impl Write for Xpipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> { self.write.write(buf) }
    fn flush(&mut self) -> io::Result<()> { self.write.flush() }
}

fn tcp_pair(socket: TcpStream, masks: &kerlico_vless::finalmask::FinalMask, peer: SocketAddr, local: Option<SocketAddr>) -> io::Result<(Link, Link)> {
    if masks.has_tcp() {
        let local = local.unwrap_or(socket.local_addr()?);
        let (read, write) = kerlico_vless::mask_tcp_at(socket, masks, kerlico_vless::finalmask::Side::Server, local, peer)?;
        Ok((Link::MaskedRead(read), Link::MaskedWrite(write)))
    } else { Ok((Link::Tcp(socket.try_clone()?), Link::Tcp(socket))) }
}

fn open_reality(mut read: Link, mut write: Link, config: &RealityConfig, ready: &Sender<Ready>, peer: SocketAddr, local: Option<SocketAddr>) -> Option<RealityDuplex<AppReader<Box<Link>>, AppWriter<Box<Link>>>> {
    let (record, wire) = kerlico_vless::read_client_hello(&mut read).ok()?;
    if !kerlico_vless::reality_accept_with_policy(&record, &config.private, &config.policy) {
        let (name, alpn) = hello_identity(&record);
        if let Some(target) = &config.target {
            if let Some(handoff) = fall_back(read, write, peer, local, wire, target, &name, &alpn) { ready.send(handoff).ok(); }
        }
        return None;
    }
    let accepted = kerlico_vless::server_flight_with_auth(&record, &config.private, &config.policy, &config.alpn, config.proof.as_ref()).ok()?;
    write.write_all(&accepted.flight).ok()?;
    read_client_finished(&mut read, &accepted.handshake, &accepted.expect).ok()?;
    let (client_app, server_app) = accepted.application_keys();
    Some(RealityDuplex::new(reality_reader(Box::new(read), client_app), reality_writer(Box::new(write), server_app)))
}

#[derive(Default)]
struct H2Serve {
    limits: kerlico_vless::H2Limits,
    permit_prohibited_ciphers: bool,
}

struct XhttpListener {
    config: Arc<XhttpConfig>,
    h2: H2Serve,
    forwarded_for: kerlico_vless::TrustedForwardedFor,
    accounts: Arc<Users>,
    ready: Sender<Ready>,
    sessions: Mutex<HashMap<String, XhttpSession>>,
}

enum XhttpSession {
    Pending(Instant, Arc<XhttpLane>),
    Active(Weak<XhttpLane>),
}

impl XhttpListener {
    fn lane(&self, session: String, connecting: bool) -> Option<Arc<XhttpLane>> {
        let mut sessions = self.sessions.lock().expect("XHTTP sessions");
        let expiry = Duration::from_secs(30);
        if !sessions.contains_key(&session) {
            sessions.retain(|_, entry| match entry {
                XhttpSession::Pending(started, _) => started.elapsed() < expiry,
                XhttpSession::Active(lane) => lane.strong_count() != 0,
            });
        }
        if let Some(XhttpSession::Active(lane)) = sessions.get(&session) {
            if let Some(lane) = lane.upgrade() {
                return if connecting { None } else { Some(lane) };
            }
        }
        let lane = match sessions.get(&session) {
            Some(XhttpSession::Pending(started, lane)) if started.elapsed() < expiry => {
                lane.clone()
            }
            _ => Arc::new(XhttpLane {
                input: Mutex::new(XhttpInput::default()),
                arrived: Condvar::new(),
                down: Mutex::new(None),
                limit: self.config.buffered_posts(),
            }),
        };
        let entry = if connecting {
            XhttpSession::Active(Arc::downgrade(&lane))
        } else {
            XhttpSession::Pending(Instant::now(), lane.clone())
        };
        sessions.insert(session, entry);
        Some(lane)
    }

    fn handoff(&self, read: Link, write: Link, peer: SocketAddr) {
        if let Some(ready) = handshake(
            read,
            write,
            peer,
            None,
            &self.accounts,
            &self.ready,
            FallbackSet::empty(),
            Vec::new(),
            String::new(),
            String::new(),
        ) {
            let _ = self.ready.send(ready);
        }
    }

    fn download(&self, lane: Arc<XhttpLane>, write: XhttpWriter, peer: SocketAddr) {
        *lane.down.lock().expect("XHTTP download") = Some(write);
        self.handoff(Link::Xhttp(lane.clone()), Link::Xhttp(lane), peer);
    }

    fn packet(
        &self,
        session: String,
        seq: u64,
        body: io::Result<Vec<u8>>,
        header: impl Fn(&str) -> Option<String>,
    ) -> u16 {
        let payload = match body.and_then(|body| self.config.packet_payload(body, header)) {
            Ok(payload) => payload,
            Err(error) if error.kind() == io::ErrorKind::FileTooLarge => return 413,
            Err(_) => return 400,
        };
        let lane = self.lane(session, false).expect("XHTTP upload lane");
        if lane.packet(seq, payload) {
            200
        } else {
            409
        }
    }

    fn serve_h1(&self, mut socket: Xpipe, mut prefix: Vec<u8>, peer: SocketAddr) -> io::Result<()> {
        loop {
            let mut lead = Lead {
                lead: prefix,
                inner: socket,
            };
            let limit = self.config.max_header_bytes().saturating_add(4096);
            let mut head = read_http_head_with_limit(&mut lead, limit)?;
            head.rest.extend(lead.lead);
            socket = lead.inner;
            if !self.config.host().is_empty() && !host_matches(&head.host, self.config.host()) {
                return write_xhttp_response(&mut socket, 404, &[("connection", "close")], false);
            }
            let kind = match self
                .config
                .classify(&head.method, &head.target, |name| head.header(name))
            {
                Ok(kind) => kind,
                Err(error) => {
                    return write_xhttp_response(
                        &mut socket,
                        xhttp_error_status(&error),
                        &[("connection", "close")],
                        false,
                    )
                }
            };
            let peer = self.forwarded_for.peer(peer, |name| head.header(name));
            let mut headers = self
                .config
                .response_headers(&kind, &head.method, |name| head.header(name))?;
            let close = head.header("connection").is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("close"))
            }) || head.chunked
                || !matches!(
                    kind,
                    XhttpRequestKind::PacketUp { .. } | XhttpRequestKind::Preflight
                );
            if close {
                headers.push(("connection".to_owned(), "close".to_owned()));
            }
            let headers = xhttp_header_pairs(&headers);
            let length = head.length.unwrap_or(0);
            match kind {
                XhttpRequestKind::StreamOne => {
                    write_xhttp_response(&mut socket, 200, &headers, true)?;
                    let (read, write) = socket.split()?;
                    let reader = xhttp_h1_body(read, &mut head);
                    let pair = Arc::new(ChunkPair::with_reader(reader, write));
                    self.handoff(Link::Chunks(pair.clone()), Link::Chunks(pair), peer);
                    return Ok(());
                }
                XhttpRequestKind::Download { session } => {
                    let Some(lane) = self.lane(session, true) else {
                        return write_xhttp_response(&mut socket, 409, &headers, false);
                    };
                    write_xhttp_response(&mut socket, 200, &headers, true)?;
                    self.download(lane, XhttpWriter::new(Box::new(socket), true), peer);
                    return Ok(());
                }
                XhttpRequestKind::StreamUp { session } => {
                    let lane = self.lane(session, false).expect("XHTTP upload lane");
                    let mut input = lane.input.lock().expect("XHTTP upload");
                    if input.stream.is_some() || input.packet_mode {
                        return write_xhttp_response(&mut socket, 409, &headers, false);
                    }
                    let reply_body = head.method != "HEAD";
                    let keepalive = reply_body
                        && (self.config.obfs_padding()
                            || head
                                .header("referer")
                                .is_some_and(|value| !value.is_empty()));
                    write_xhttp_response(&mut socket, 200, &headers, reply_body)?;
                    let (read, write) = socket.split()?;
                    input.stream = Some(self.stream_up(
                        xhttp_h1_body(read, &mut head),
                        XhttpWriter::new(Box::new(write), reply_body),
                        keepalive,
                    ));
                    lane.arrived.notify_all();
                    return Ok(());
                }
                XhttpRequestKind::PacketUp { session, seq } => {
                    let limit = self.config.packet_limit();
                    if length > limit {
                        return write_xhttp_response(&mut socket, 413, &headers, false);
                    }
                    if head
                        .header("expect")
                        .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
                    {
                        socket.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
                    }
                    if head.chunked {
                        let (read, mut write) = socket.split()?;
                        let body = xhttp_packet_body(xhttp_h1_body(read, &mut head), limit);
                        let status = self.packet(session, seq, body, |name| head.header(name));
                        return write_xhttp_response(&mut write, status, &headers, false);
                    }
                    let mut body = std::mem::take(&mut head.rest);
                    prefix = body.split_off(body.len().min(length));
                    let missing = (length - body.len()) as u64;
                    if Read::by_ref(&mut socket)
                        .take(missing)
                        .read_to_end(&mut body)? as u64
                        != missing
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "XHTTP packet body",
                        ));
                    }
                    let status = self.packet(session, seq, Ok(body), |name| head.header(name));
                    write_xhttp_response(&mut socket, status, &headers, false)?;
                }
                XhttpRequestKind::Preflight => {
                    if head.chunked || length != 0 {
                        return write_xhttp_response(&mut socket, 200, &headers, false);
                    }
                    prefix = std::mem::take(&mut head.rest);
                    write_xhttp_response(&mut socket, 200, &headers, false)?;
                }
            }
            if close {
                return Ok(());
            }
        }
    }

    fn serve_stream(&self, stream: HttpStream, peer: SocketAddr) -> io::Result<()> {
        let authority = stream.header(":authority").unwrap_or_default();
        if !self.config.host().is_empty() && !host_matches(&authority, self.config.host()) {
            return stream.respond(404, &[], true);
        }
        let method = stream.header(":method").unwrap_or_default();
        let target = stream.header(":path").unwrap_or_default();
        let kind = match self
            .config
            .classify(&method, &target, |name| stream.header(name))
        {
            Ok(kind) => kind,
            Err(error) => return stream.respond(xhttp_error_status(&error), &[], true),
        };
        let peer = self.forwarded_for.peer(peer, |name| stream.header(name));
        let headers = self
            .config
            .response_headers(&kind, &method, |name| stream.header(name))?;
        let headers = xhttp_header_pairs(&headers);
        match kind {
            XhttpRequestKind::Preflight => stream.respond(200, &headers, true),
            XhttpRequestKind::StreamOne => {
                stream.respond(200, &headers, false)?;
                let link = Arc::new(stream);
                self.handoff(Link::H2(link.clone()), Link::H2(link), peer);
                Ok(())
            }
            XhttpRequestKind::Download { session } => {
                let Some(lane) = self.lane(session, true) else {
                    return stream.respond(409, &headers, true);
                };
                stream.respond(200, &headers, false)?;
                self.download(lane, XhttpWriter::new(Box::new(stream), false), peer);
                Ok(())
            }
            XhttpRequestKind::StreamUp { session } => {
                let lane = self.lane(session, false).expect("XHTTP upload lane");
                let mut input = lane.input.lock().expect("XHTTP upload");
                if input.stream.is_some() || input.packet_mode {
                    return stream.respond(409, &headers, true);
                }
                let keepalive = method != "HEAD"
                    && (self.config.obfs_padding()
                        || stream
                            .header("referer")
                            .is_some_and(|value| !value.is_empty()));
                stream.respond(200, &headers, false)?;
                let link = Arc::new(stream);
                input.stream = Some(self.stream_up(
                    Box::new(Link::H2(link.clone())),
                    XhttpWriter::new(Box::new(Link::H2(link)), false),
                    keepalive,
                ));
                lane.arrived.notify_all();
                Ok(())
            }
            XhttpRequestKind::PacketUp { session, seq } => {
                let limit = self.config.packet_limit();
                if stream
                    .header("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .is_some_and(|len| len > limit)
                {
                    return stream.respond(413, &headers, true);
                }
                let body = xhttp_packet_body(&stream, limit);
                let status = self.packet(session, seq, body, |name| stream.header(name));
                stream.respond(status, &headers, true)
            }
        }
    }

    fn stream_up(
        &self,
        read: Box<dyn Read + Send>,
        mut write: XhttpWriter,
        keepalive: bool,
    ) -> Box<dyn Read + Send> {
        let interval = if keepalive {
            self.config.stream_up_interval().ok().flatten()
        } else {
            None
        };
        let Some(interval) = interval else {
            return Box::new(XhttpStreamRead {
                read,
                _response: XhttpUploadResponse::Hold { _writer: write },
            });
        };
        let config = self.config.clone();
        let (live, closed) = mpsc::channel::<()>();
        thread::spawn(move || {
            let mut interval = interval;
            loop {
                let Ok(padding) = config.stream_up_padding() else {
                    break;
                };
                if write.write_all(&padding).is_err() {
                    break;
                }
                if !matches!(
                    closed.recv_timeout(interval),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    break;
                }
                let Some(next) = config.stream_up_interval().ok().flatten() else {
                    break;
                };
                interval = next;
            }
        });
        Box::new(XhttpStreamRead {
            read,
            _response: XhttpUploadResponse::Keepalive { _live: live },
        })
    }
}

fn xhttp_error_status(error: &io::Error) -> u16 {
    if error.kind() == io::ErrorKind::NotFound {
        404
    } else {
        400
    }
}

fn xhttp_header_pairs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

fn xhttp_h1_body(read: Half, head: &mut HttpHead) -> Box<dyn Read + Send> {
    let lead = std::mem::take(&mut head.rest);
    if head.chunked {
        Box::new(ChunkReader::new(read, lead))
    } else {
        Box::new(Lead { inner: read, lead }.take(head.length.unwrap_or(0) as u64))
    }
}

fn xhttp_packet_body(read: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    read.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut body)?;
    if body.len() > limit {
        return Err(io::Error::new(io::ErrorKind::FileTooLarge, "XHTTP upload"));
    }
    Ok(body)
}

fn xhttp_retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

struct XhttpStreamRead {
    read: Box<dyn Read + Send>,
    _response: XhttpUploadResponse,
}

enum XhttpUploadResponse {
    Hold { _writer: XhttpWriter },
    Keepalive { _live: Sender<()> },
}

impl Read for XhttpStreamRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read.read(buf)
    }
}

type XhttpWriter = XhttpBodyWriter<Box<dyn Write + Send>>;

#[derive(Default)]
struct XhttpInput {
    next: u64,
    packets: BTreeMap<u64, io::Cursor<Vec<u8>>>,
    packet_mode: bool,
    stream: Option<Box<dyn Read + Send>>,
}

struct XhttpLane {
    down: Mutex<Option<XhttpWriter>>,
    input: Mutex<XhttpInput>,
    arrived: Condvar,
    limit: usize,
}

impl XhttpLane {
    fn packet(&self, seq: u64, payload: Vec<u8>) -> bool {
        let mut input = self.input.lock().expect("XHTTP upload");
        if input.stream.is_some() {
            return false;
        }
        input.packet_mode = true;
        if seq < input.next || input.packets.contains_key(&seq) {
            return true;
        }
        if seq != input.next && input.packets.len() >= self.limit {
            return false;
        }
        input.packets.insert(seq, io::Cursor::new(payload));
        self.arrived.notify_all();
        true
    }

    fn pull(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut input = self.input.lock().expect("XHTTP upload");
        loop {
            if let Some(reader) = input.stream.as_mut() {
                return reader.read(buf);
            }
            let next = input.next;
            if let Some(packet) = input.packets.get_mut(&next) {
                let n = packet.read(buf)?;
                if packet.position() as usize == packet.get_ref().len() {
                    input.packets.remove(&next);
                    input.next = next.saturating_add(1);
                }
                if n != 0 {
                    return Ok(n);
                }
                continue;
            }
            let (guard, waited) = self
                .arrived
                .wait_timeout(input, Duration::from_secs(10))
                .expect("XHTTP upload");
            if waited.timed_out() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            input = guard;
        }
    }

    fn push(&self, buf: &[u8]) -> io::Result<usize> {
        let mut down = self.down.lock().expect("XHTTP download");
        let writer = down
            .as_mut()
            .ok_or_else(|| io::Error::other("XHTTP download unavailable"))?;
        writer.write(buf)
    }

    fn flush(&self) -> io::Result<()> {
        let mut down = self.down.lock().expect("XHTTP download");
        let writer = down.as_mut().ok_or_else(|| io::Error::other("XHTTP download unavailable"))?;
        writer.flush()
    }
}

fn tls_server_config(settings: &Settings, names: &[String]) -> Result<Arc<kerlico_vless::AdvancedTlsServerConfig>, OpenError> {
    let options = tls_options(settings, names)?;
    kerlico_vless::advanced_server_config(&options).map_err(|_| OpenError::Settings)
}

fn quic_tls_server_config(settings: &Settings) -> Result<kerlico_vless::QuicServerCrypto, OpenError> {
    let options = tls_options(settings, &["h3".into()])?;
    kerlico_vless::advanced_quic_server_config(&options).map_err(|_| OpenError::Settings)
}

fn tls_options(settings: &Settings, names: &[String]) -> Result<kerlico_vless::AdvancedTlsOptions, OpenError> {
    let mut options = kerlico_vless::AdvancedTlsOptions::from_settings(|key| settings.text(key).ok(), names.to_vec()).map_err(|_| OpenError::Settings)?;
    options.network_provider = settings.runtime().map(|context| kerlico_vless::runtime::owner_tls(context).network.clone());
    Ok(options)
}

fn final_masks(settings: &Settings) -> Result<kerlico_vless::finalmask::FinalMask, OpenError> {
    let provider = settings.runtime().map(|context| kerlico_vless::runtime::owner_tls(context).network.clone());
    let masks = kerlico_vless::runtime::parse_finalmask(settings.text("finalmask").unwrap_or("{}"), settings.runtime(), provider).map_err(|_| OpenError::Settings)?;
    let options = kerlico_vless::socket::SocketOptions::parse(settings.text("sockopt").ok()).map_err(|_| OpenError::Settings)?;
    Ok(match settings.runtime() {
        Some(context) => masks.with_network(Arc::new(kerlico_vless::runtime::CarrierNetwork::new(context.network.clone(), options))),
        None => masks,
    })
}

fn known_flow(flow: &str) -> Result<&str, OpenError> {
    match flow {
        "" | "xtls-rprx-vision" => Ok(flow),
        _ => Err(OpenError::Settings),
    }
}

fn vision_flow(flow: &str) -> bool {
    flow.starts_with("xtls-rprx-vision")
}

fn account_id(mut id: [u8; 16]) -> [u8; 16] {
    id[6..8].fill(0);
    id
}

impl Accept for VlessInbound {
    fn reverse_landing(&self, tag: &str) -> Result<kerlico_shared::ReverseDial, OpenError> {
        if !self.accounts.lock().expect("accounts").values().any(|account| account.reverse == tag) { return Err(OpenError::Settings); }
        let accounts = self.accounts.clone();
        let tag = tag.to_string();
        let key = (self.tag.clone(), tag.clone());
        Ok(Arc::new(move |destination| {
            let portal = portals().lock().expect("reverse").get(&key).cloned().ok_or(OpenError::Again)?;
            let owned = accounts.lock().expect("accounts").values().any(|account| account.reverse == tag && Arc::ptr_eq(&account.active, &portal.active));
            if !owned { return Err(OpenError::Again); }
            open_reverse_portal(portal, destination.host(), destination.port(), destination.transport() == Transport::Tcp, &[])
        }))
    }

    fn add_user(&mut self, email: &UserEmail, account: &Settings) -> Result<(), OpenError> {
        let id = account_id(parse_id(account.text("id")?).map_err(|_| OpenError::Settings)?);
        let flow = match account.text("flow") {
            Err(_) | Ok("") => self.default_flow.clone(),
            Ok(flow) => known_flow(flow)?.to_string(),
        };
        let reverse = match account.text("reverse") {
            Err(_) | Ok("") => String::new(),
            Ok(tag) => kerlico_vless::reverse_tag(tag).map_err(|_| OpenError::Settings)?,
        };
        if !flow.is_empty() && !self.accounts.allow_vision { return Err(OpenError::Settings); }
        let mut accounts = self.accounts.lock().expect("accounts");
        if !reverse.is_empty() && accounts.values().any(|account| account.reverse == reverse && &account.email != email) { return Err(OpenError::Settings); }
        if accounts.get(&id).is_some_and(|current| &current.email != email) {
            return Err(OpenError::Settings);
        }
        accounts.retain(|_, current| {
            if &current.email == email { current.active.store(false, std::sync::atomic::Ordering::Release); false }
            else { true }
        });
        accounts.insert(
            id,
            Account {
                email: email.clone(),
                flow,
                reverse,
                active: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            },
        );
        Ok(())
    }

    fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
        let mut accounts = self.accounts.lock().expect("accounts");
        let key = accounts
            .iter()
            .find(|(_, account)| &account.email == email)
            .map(|(key, _)| *key);
        let Some(key) = key else {
            return Err(OpenError::Settings);
        };
        if let Some(account) = accounts.remove(&key) { account.active.store(false, std::sync::atomic::Ordering::Release); }
        Ok(())
    }

    fn accept(&mut self) -> Result<Handoff, OpenError> {
        match self.ready_rx.try_recv() {
            Ok(ready) => {
                let mut read = ready.read;
                let mut write = ready.write;
                read.set_timeout(Duration::from_millis(200));
                write.set_timeout(Duration::from_millis(200));
                let udp_destination = ready.destination.transport() == Transport::Udp;
                let mut handoff = Handoff::new(
                    self.tag.clone(),
                    ready.email,
                    ready.destination,
                    Box::new(Stream {
                        read: Mutex::new(read),
                        write: Mutex::new(write),
                        udp: ready.udp,
                        pending: Mutex::new(Vec::new()),
                        staged: Mutex::new(ready.prefix),
                        unsent: Mutex::new(Vec::new()),
                    }),
                );
                if ready.udp || udp_destination {
                    handoff.set_peer(ready.peer);
                }
                Ok(handoff)
            }
            Err(TryRecvError::Empty) => Err(OpenError::Again),
            Err(TryRecvError::Disconnected) => Err(OpenError::Transport),
        }
    }
}

#[derive(Clone)]
struct GrpcCfg {
    paths: Vec<String>,
    options: kerlico_vless::GrpcOptions,
}

#[derive(Clone)]
struct HttpCfg {
    path: String,
    host: String,
    method: String,
}

fn accept_loop(
    listener: TcpListener,
    accounts: Arc<Users>,
    ready_tx: Sender<Ready>,
    tls: Option<std::sync::Arc<kerlico_vless::AdvancedTlsServerConfig>>,
    upgrade: Option<Arc<UpgradeConfig>>,
    raw_http: Option<Arc<RawHttpConfig>>,
    grpc: Option<GrpcCfg>,
    http: Option<HttpCfg>,
    fallback: FallbackSet,
    reality: Option<RealityConfig>,
    accept_proxy: bool,
    forwarded_for: kerlico_vless::TrustedForwardedFor,
) {
    loop {
        let Ok((mut socket, peer)) = listener.accept() else {
            break;
        };
        if !accounts.allows(peer) { continue; }
        let local = socket.local_addr().ok();
        let forwarded_for = forwarded_for.clone();
        let accounts = Arc::clone(&accounts);
        let ready_tx = ready_tx.clone();
        let tls = tls.clone();
        let upgrade = upgrade.clone();
        let raw_http = raw_http.clone();
        let grpc = grpc.clone();
        let http = http.clone();
        let fallback = fallback.clone();
        let reality = reality.clone();
        thread::spawn(move || {
            let ready = (|| {
                socket.set_nodelay(true).ok();
                socket.set_read_timeout(Some(Duration::from_secs(10))).ok();
                socket.set_write_timeout(Some(Duration::from_secs(10))).ok();
                let (peer, local) = if accept_proxy { kerlico_vless::accept_proxy(&mut socket, peer, local).ok()? } else { (peer, local) };
                let mut seen_name = String::new();
                let mut seen_alpn = String::new();
                let (read, write) = tcp_pair(socket, &accounts.masks, peer, local).ok()?;
                let (mut read, mut write) = if let Some(config) = tls {
                    let (read, write) = kerlico_vless::accept_advanced_tls_over(Box::new(read), Box::new(write), config).ok()?;
                    (seen_name, seen_alpn) = read.identity();
                    (Link::TlsRead(Box::new(read)), Link::TlsWrite(Box::new(write)))
                } else { (read, write) };
                if let Some(config) = reality {
                    let (record, wire) = kerlico_vless::read_client_hello(&mut read).ok()?;
                    let (hello_name, hello_alpn) = hello_identity(&record);
                    seen_name = hello_name;
                    seen_alpn = hello_alpn;
                    if !kerlico_vless::reality_accept_with_policy(&record, &config.private, &config.policy) {
                        return fall_back(read, write, peer, local, wire, config.target.as_ref().unwrap_or(&fallback), &seen_name, &seen_alpn);
                    }
                    let accepted = kerlico_vless::server_flight_with_auth(&record, &config.private, &config.policy, &config.alpn, config.proof.as_ref()).ok()?;
                    seen_alpn = String::from_utf8_lossy(accepted.alpn().unwrap_or_default()).into_owned();
                    write.write_all(&accepted.flight).ok()?;
                    read_client_finished(&mut read, &accepted.handshake, &accepted.expect).ok()?;
                    let (client_app, server_app) = accepted.application_keys();
                    read = Link::RealityRead(reality_reader(Box::new(read), client_app));
                    write = Link::RealityWrite(reality_writer(Box::new(write), server_app));
                }
                if let Some(cfg) = grpc {
                    if !seen_alpn.is_empty() && seen_alpn != "h2" {
                        return None;
                    }
                    read.set_timeout(Duration::from_millis(200));
                    write.set_timeout(Duration::from_millis(200));
                    let connection = GrpcConnection::serve_with(read, write, cfg.options).ok()?;
                    let paths = cfg.paths.iter().map(String::as_str).collect::<Vec<_>>();
                    while let Ok(stream) = connection.accept(&paths) {
                        let peer = forwarded_for.peer(peer, |name| stream.header(name));
                        let stream = Arc::new(stream);
                        let read = Link::Grpc(Arc::clone(&stream));
                        let write = Link::Grpc(stream);
                        let accounts = Arc::clone(&accounts);
                        let ready_tx = ready_tx.clone();
                        let (fallback, name, alpn) = (fallback.clone(), seen_name.clone(), seen_alpn.clone());
                        thread::spawn(move || {
                            if let Some(ready) = handshake(read, write, peer, local, &accounts, &ready_tx, fallback, Vec::new(), name, alpn) {
                                let _ = ready_tx.send(ready);
                            }
                        });
                    }
                    return None;
                }
                let (prelude, peer) = match &upgrade {
                    Some(cfg) => {
                        read.set_timeout(Duration::from_secs(4));
                        let (rest, early, head) = cfg.accept(&mut read, &mut write).ok()?;
                        let peer = forwarded_for.peer(peer, |name| kerlico_vless::header_value(&head, name));
                        ((rest, early), peer)
                    }
                    None => ((Vec::new(), Vec::new()), peer),
                };
                let websocket = upgrade.as_ref().is_some_and(|cfg| cfg.websocket());
                let (read, write, prelude) = if let Some(cfg) = raw_http {
                    let (read, write) = cfg.accept(Box::new(read), Box::new(write)).ok()?;
                    (Link::HttpPrefaceRead(Box::new(read)), Link::RawHttpWrite(Box::new(write)), Vec::new())
                } else if let Some(cfg) = http {
                    let session = HttpIo::accept(Link::Duplex(Box::new(read), Box::new(write)), &cfg.path, &cfg.host, &cfg.method).ok()?;
                    let shared = Arc::new(session.into_shared(split_duplex));
                    (Link::Http(shared.clone()), Link::Http(shared), Vec::new())
                } else if websocket {
                    let (read, write) = kerlico_vless::websocket_pair(Box::new(read), Box::new(write), true, false, &prelude.0).ok()?;
                    (Link::WsRead(Box::new(read)), Link::WsWrite(Box::new(write)), prelude.1)
                } else if upgrade.is_some() {
                    let read = HttpPrefaceRead::after_header(Box::new(read), prelude.0);
                    (Link::HttpPrefaceRead(Box::new(read)), write, Vec::new())
                } else {
                    (read, write, prelude.0)
                };
                handshake(read, write, peer, local, &accounts, &ready_tx, fallback, prelude, seen_name, seen_alpn)
            })();
            if let Some(ready) = ready {
                let _ = ready_tx.send(ready);
            }
        });
    }
}

enum Link {
    MaskedRead(kerlico_vless::MaskedRead),
    MaskedWrite(kerlico_vless::MaskedWrite),
    XdriveRead(kerlico_vless::xdrive::XdriveRead),
    XdriveWrite(kerlico_vless::xdrive::XdriveWrite),
    HysteriaRead(kerlico_vless::HysteriaRead),
    HysteriaWrite(kerlico_vless::HysteriaWrite),
    Tcp(TcpStream),
    TlsRead(Box<kerlico_vless::AdvancedTlsRead<Box<Link>>>),
    TlsWrite(Box<kerlico_vless::AdvancedTlsWrite<Box<Link>>>),
    HttpPrefaceRead(Box<HttpPrefaceRead<Box<Link>>>),
    RawHttpWrite(Box<RawHttpWrite<Box<Link>>>),
    WsRead(Box<kerlico_vless::WsRead<Box<Link>, Box<Link>>>),
    WsWrite(Box<kerlico_vless::WsWrite<Box<Link>>>),
    Grpc(Arc<GrpcStream<Link>>),
    Http(Arc<kerlico_vless::SharedHttp<Link, Link>>),
    Kcp(Arc<KcpLane>),
    Xhttp(Arc<XhttpLane>),
    Chunks(Arc<ChunkPair>),
    Mux(Arc<MuxLane>),
    EncRead(Box<EncReader<Box<Link>>>),
    EncWrite(Box<EncWriter<Box<Link>>>),
    RealityRead(AppReader<Box<Link>>),
    RealityWrite(AppWriter<Box<Link>>),
    H2(Arc<HttpStream>),
    Vision(Box<kerlico_vless::VisionIo<Link>>),
    Duplex(Box<Link>, Box<Link>),
    Prefix(Box<Link>, VecDeque<u8>),
}

type Half = Link;

enum HttpStream {
    H2(kerlico_vless::H2Stream<Half>),
    H3(kerlico_vless::H3Stream),
}

impl HttpStream {
    fn header(&self, name: &str) -> Option<String> {
        match self {
            Self::H2(io) => io.header(name),
            Self::H3(io) => io.header(name),
        }
    }
    fn respond(&self, status: u16, headers: &[(&str, &str)], end: bool) -> io::Result<()> {
        match self {
            Self::H2(stream) => stream.reply_with(status, headers, end),
            Self::H3(stream) => {
                stream.reply_with(status, headers)?;
                if end {
                    stream.finish_write()?;
                }
                Ok(())
            }
        }
    }
    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H2(io) => io.read(buf),
            Self::H3(io) => io.read(buf),
        }
    }
    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::H2(io) => io.write(buf),
            Self::H3(io) => io.write(buf),
        }
    }
    fn flush(&self) -> std::io::Result<()> {
        match self {
            Self::H2(io) => io.flush(),
            Self::H3(io) => io.flush(),
        }
    }
}

impl Read for &HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        HttpStream::read(self, buf)
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        HttpStream::write(self, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        HttpStream::flush(self)
    }
}

impl Link {
    fn supports_vision(&self) -> bool {
        match self {
            Self::EncRead(_) | Self::RealityRead(_) => true,
            Self::TlsRead(tls) => tls.is_tls13(),
            Self::Prefix(inner, _) => inner.supports_vision(),
            _ => false,
        }
    }

    fn clone_tcp(&self) -> Option<TcpStream> {
        match self {
            Self::Tcp(tcp) => tcp.try_clone().ok(),
            _ => None,
        }
    }

    fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    fn set_timeout(&mut self, timeout: Duration) {
        match self {
            Self::MaskedRead(link) => link.set_timeout(timeout),
            Self::MaskedWrite(link) => link.set_timeout(timeout),
            Self::XdriveRead(io) => io.set_timeout(Some(timeout)),
            Self::XdriveWrite(io) => io.set_timeout(Some(timeout)),
            Self::HysteriaRead(io) => io.set_timeout(timeout),
            Self::HysteriaWrite(io) => io.set_timeout(timeout),
            Self::Tcp(tcp) => {
                tcp.set_read_timeout(Some(timeout)).ok();
                tcp.set_write_timeout(Some(timeout)).ok();
            }
            Self::TlsRead(tls) => tls.inner_mut().set_timeout(timeout),
            Self::TlsWrite(tls) => tls.inner_mut().set_timeout(timeout),
            Self::HttpPrefaceRead(read) => read.inner_mut().set_timeout(timeout),
            Self::RawHttpWrite(write) => write.inner_mut().set_timeout(timeout),
            Self::WsRead(ws) => ws.inner_mut().set_timeout(timeout),
            Self::WsWrite(ws) => ws.map_io(|inner| inner.set_timeout(timeout)),
            Self::Grpc(grpc) => grpc.set_timeout(timeout),
            Self::Http(http) => http.map_io(|read| read.set_timeout(timeout), |write| write.set_timeout(timeout)),
            Self::Kcp(kcp) => kcp.timeout_ms.store(timeout.as_millis() as u64, std::sync::atomic::Ordering::Relaxed),
            Self::Xhttp(_) => {}
            Self::Chunks(_) => {}
            Self::Mux(_) => {}
            Self::EncRead(enc) => enc.inner_mut().set_timeout(timeout),
            Self::EncWrite(enc) => enc.inner_mut().set_timeout(timeout),
            Self::RealityRead(link) => link.inner_mut().set_timeout(timeout),
            Self::RealityWrite(link) => link.inner_mut().set_timeout(timeout),
            Self::H2(_) => {}
            Self::Vision(link) => link.inner_mut().set_timeout(timeout),
            Self::Duplex(read, write) => { read.set_timeout(timeout); write.set_timeout(timeout); },
            Self::Prefix(inner, _) => inner.set_timeout(timeout),
        }
    }
}

impl Read for Link {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::MaskedRead(link) => link.read(buf),
            Self::MaskedWrite(_) => Err(io::ErrorKind::Unsupported.into()),
            Self::XdriveRead(io) => io.read(buf),
            Self::HysteriaRead(io) => io.read(buf),
            Self::XdriveWrite(_) | Self::HysteriaWrite(_) => Err(std::io::Error::other("write half")),
            Self::Tcp(tcp) => tcp.read(buf),
            Self::TlsRead(tls) => tls.read(buf),
            Self::TlsWrite(_) => Err(std::io::Error::other("write half")),
            Self::HttpPrefaceRead(read) => read.read(buf),
            Self::RawHttpWrite(_) => Err(std::io::Error::other("write half")),
            Self::WsRead(ws) => ws.read(buf),
            Self::WsWrite(_) => Err(std::io::Error::other("write half")),
            Self::Grpc(grpc) => grpc.read(buf),
            Self::Http(http) => http.read(buf),
            Self::Kcp(lane) => lane.pull(buf),
            Self::Xhttp(lane) => lane.pull(buf),
            Self::Chunks(chunks) => chunks.pull(buf),
            Self::Mux(lane) => lane.pull(buf),
            Self::EncRead(enc) => enc.read(buf),
            Self::EncWrite(_) => Err(std::io::Error::other("vlessenc")),
            Self::RealityRead(link) => link.read(buf),
            Self::RealityWrite(_) => Err(std::io::Error::other("reality")),
            Self::H2(link) => link.read(buf),
            Self::Vision(link) => link.read(buf),
            Self::Duplex(read, _) => read.read(buf),
            Self::Prefix(inner, prefix) => {
                if prefix.is_empty() { return inner.read(buf); }
                let n = prefix.len().min(buf.len());
                for (slot, byte) in buf.iter_mut().zip(prefix.drain(..n)) { *slot = byte; }
                Ok(n)
            },
        }
    }
}

impl Write for Link {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::MaskedWrite(link) => link.write(buf),
            Self::MaskedRead(_) => Err(io::ErrorKind::Unsupported.into()),
            Self::XdriveWrite(io) => io.write(buf),
            Self::HysteriaWrite(io) => io.write(buf),
            Self::XdriveRead(_) | Self::HysteriaRead(_) => Err(std::io::Error::other("read half")),
            Self::Tcp(tcp) => tcp.write(buf),
            Self::TlsWrite(tls) => tls.write(buf),
            Self::TlsRead(_) => Err(std::io::Error::other("read half")),
            Self::RawHttpWrite(write) => write.write(buf),
            Self::HttpPrefaceRead(_) => Err(std::io::Error::other("read half")),
            Self::WsWrite(ws) => ws.write(buf),
            Self::WsRead(_) => Err(std::io::Error::other("read half")),
            Self::Grpc(grpc) => grpc.write(buf),
            Self::Http(http) => http.write(buf),
            Self::Kcp(lane) => lane.push(buf),
            Self::Xhttp(lane) => lane.push(buf),
            Self::Chunks(chunks) => chunks.push(buf),
            Self::Mux(lane) => lane.push(buf),
            Self::EncRead(_) => Err(std::io::Error::other("vlessenc")),
            Self::EncWrite(enc) => enc.write(buf),
            Self::RealityRead(_) => Err(std::io::Error::other("reality")),
            Self::RealityWrite(link) => link.write(buf),
            Self::H2(link) => link.write(buf),
            Self::Vision(link) => link.write(buf),
            Self::Duplex(_, write) => write.write(buf),
            Self::Prefix(inner, _) => inner.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::MaskedWrite(link) => link.flush(),
            Self::MaskedRead(_) => Ok(()),
            Self::XdriveWrite(io) => io.flush(),
            Self::HysteriaWrite(io) => io.flush(),
            Self::XdriveRead(_) | Self::HysteriaRead(_) => Ok(()),
            Self::Tcp(tcp) => tcp.flush(),
            Self::TlsWrite(tls) => tls.flush(),
            Self::TlsRead(_) => Ok(()),
            Self::RawHttpWrite(write) => write.flush(),
            Self::HttpPrefaceRead(_) => Ok(()),
            Self::WsWrite(ws) => ws.flush(),
            Self::WsRead(_) => Ok(()),
            Self::Grpc(grpc) => grpc.flush(),
            Self::Http(http) => http.flush(),
            Self::Kcp(_) => Ok(()),
            Self::Xhttp(lane) => lane.flush(),
            Self::Chunks(chunks) => chunks.flush(),
            Self::Mux(lane) => lane.flush(),
            Self::EncRead(_) => Ok(()),
            Self::EncWrite(enc) => enc.flush(),
            Self::RealityRead(_) => Ok(()),
            Self::RealityWrite(link) => link.flush(),
            Self::H2(link) => link.flush(),
            Self::Vision(link) => link.flush(),
            Self::Duplex(_, write) => write.flush(),
            Self::Prefix(inner, _) => inner.flush(),
        }
    }
}

fn split_duplex(link: Link) -> (Link, Link) {
    let Link::Duplex(read, write) = link else { unreachable!("duplex transport") };
    (*read, *write)
}

impl kerlico_vless::VisionTransport for Link {
    fn read_direct(&mut self) -> std::io::Result<()> {
        match self {
            Self::TlsRead(tls) => tls.start_direct(),
            Self::EncRead(enc) => enc.start_direct(),
            Self::RealityRead(reality) => reality.start_direct(),
            Self::Prefix(inner, _) => inner.read_direct(),
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

fn pem(settings: &Settings, inline: &str, file: &str) -> Result<String, OpenError> {
    if let Ok(text) = settings.text(inline) {
        if !text.is_empty() {
            return Ok(text.to_string());
        }
    }
    if let Ok(path) = settings.text(file) {
        return fs::read_to_string(path).map_err(|_| OpenError::Settings);
    }
    Err(OpenError::Settings)
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

type MuxOut = Arc<Mutex<kerlico_vless::MuxWriter<Link>>>;

/// How long Xray's `XUDPManager` keeps an XUDP session that lost its carrier.
const XUDP_DETACHED: Duration = Duration::from_secs(60);

/// Where a mux session's replies go. Only an XUDP session detaches; it waits for a NEW frame
/// with its GlobalID on another carrier.
enum Route {
    Attached(u16, MuxOut),
    Detached(Instant),
}

impl Route {
    fn is(&self, id: u16, writer: &MuxOut) -> bool {
        matches!(self, Self::Attached(own, out) if *own == id && Arc::ptr_eq(out, writer))
    }

    fn expired(&self) -> bool {
        matches!(self, Self::Detached(since) if since.elapsed() >= XUDP_DETACHED)
    }
}

struct MuxSession {
    destination: Destination,
    lanes: HashMap<(String, u16), Weak<MuxLane>>,
    last: Instant,
    route: Arc<Mutex<Route>>,
    global_id: Option<NonZeroU64>,
}

impl MuxSession {
    fn new(destination: Destination, route: Route, global_id: Option<NonZeroU64>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self { destination, lanes: HashMap::new(), last: Instant::now(), route: Arc::new(Mutex::new(route)), global_id }))
    }

    /// Whether a NEW frame with this session's GlobalID can still take it over.
    fn reusable(&self) -> bool {
        match &*self.route.lock().expect("mux") {
            Route::Attached(..) => true,
            Route::Detached(since) => since.elapsed() < XUDP_DETACHED && self.lanes.values().any(|lane| lane.strong_count() > 0),
        }
    }
}

/// One node's XUDP sessions by user and GlobalID. Xray keys its process-wide map by GlobalID
/// alone. The user in the key keeps one user from taking over another user's session.
type XudpSessions = Mutex<HashMap<(UserEmail, NonZeroU64), Arc<Mutex<MuxSession>>>>;

/// Returns the XUDP session for `key`, bound to `route` on this carrier. A known session
/// leaves its earlier carrier and keeps its lanes and the outbound flows behind them.
fn attach_xudp(xudp: &XudpSessions, key: (UserEmail, NonZeroU64), destination: Destination, route: Route) -> Arc<Mutex<MuxSession>> {
    let mut sessions = xudp.lock().expect("xudp");
    sessions.retain(|_, session| session.lock().expect("mux").reusable());
    let Some(session) = sessions.get(&key).cloned() else {
        let session = MuxSession::new(destination, route, Some(key.1));
        sessions.insert(key, session.clone());
        return session;
    };
    let mut found = session.lock().expect("mux");
    found.destination = destination;
    found.last = Instant::now();
    let previous = std::mem::replace(&mut *found.route.lock().expect("mux"), route);
    drop(found);
    drop(sessions);
    if let Route::Attached(id, writer) = previous {
        writer.lock().expect("mux").send(&MuxFrame { id, status: END, ..MuxFrame::default() }).ok();
    }
    session
}

fn mux_destination(address: Option<kerlico_vless::Addr>, port: u16, udp: bool) -> Option<Destination> {
    let host = match address? {
        kerlico_vless::Addr::V4(ip) => ip.to_string(),
        kerlico_vless::Addr::V6(ip) => ip.to_string(),
        kerlico_vless::Addr::Domain(name) => name,
    };
    Destination::new(host, port, if udp { Transport::Udp } else { Transport::Tcp }).ok()
}

fn mux_address(destination: &Destination) -> kerlico_vless::Addr {
    match destination.host().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => kerlico_vless::Addr::V4(ip),
        Ok(std::net::IpAddr::V6(ip)) => kerlico_vless::Addr::V6(ip),
        Err(_) => kerlico_vless::Addr::Domain(destination.host().to_string()),
    }
}

/// Ends session `id` on this carrier and sends END. An XUDP session detaches and keeps its
/// lanes. A session that already moved to another carrier is left alone.
fn release_mux_session(id: u16, session: &Mutex<MuxSession>, writer: &MuxOut) {
    {
        let session = session.lock().expect("mux");
        let mut route = session.route.lock().expect("mux");
        if !route.is(id, writer) { return; }
        if session.global_id.is_some() {
            *route = Route::Detached(Instant::now());
        } else {
            drop(route);
            for lane in session.lanes.values().filter_map(Weak::upgrade) {
                *lane.closed.lock().expect("mux") = true;
                lane.cv.notify_all();
            }
        }
    }
    writer.lock().expect("mux").send(&MuxFrame { id, status: END, ..MuxFrame::default() }).ok();
}

fn demux(mut read: Link, write: Link, peer: SocketAddr, email: UserEmail, mut pending: Vec<u8>, ready_tx: &Sender<Ready>, xudp: &XudpSessions, udp_only: bool, xudp_only: bool) {
    read.set_timeout(Duration::from_millis(200));
    let writer: MuxOut = Arc::new(Mutex::new(kerlico_vless::MuxWriter::new(write)));
    let mut sessions: HashMap<u16, Arc<Mutex<MuxSession>>> = HashMap::new();
    let mut tmp = [0u8; 2048];
    let mut last = Instant::now();
    (|| {
    loop {
        sessions.retain(|&id, session| {
            let ended = {
                let session = session.lock().expect("mux");
                if !session.route.lock().expect("mux").is(id, &writer) { return false; }
                let active = session.lanes.values().any(|lane| lane.strong_count() > 0);
                !active && (session.destination.transport() == Transport::Tcp || session.last.elapsed() >= Duration::from_secs(300))
            };
            if ended { release_mux_session(id, session, &writer); }
            !ended
        });
        let frame = loop {
            match decode_mux(&pending) {
                Ok((frame, used)) => { pending.drain(..used); break frame; }
                Err(kerlico_vless::HeaderError::Short) => {
                    let n = match read.read(&mut tmp) {
                        Ok(n) => n,
                        Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) && last.elapsed() < Duration::from_secs(300) => {
                            writer.lock().expect("mux").flush().ok();
                            break MuxFrame { id: 0, status: KEEPALIVE, option: 0, network: 0, port: 0, address: None, payload: Vec::new(), global_id: None };
                        },
                        Err(_) => return,
                    };
                    if n == 0 { return; }
                    pending.extend_from_slice(&tmp[..n]);
                    last = Instant::now();
                }
                Err(kerlico_vless::HeaderError::Bad) => return,
            }
        };
        if frame.status == KEEPALIVE { continue; }
        if frame.status == END {
            if let Some(session) = sessions.remove(&frame.id) { release_mux_session(frame.id, &session, &writer); }
            continue;
        }
        if frame.status == NEW {
            if sessions.contains_key(&frame.id) || (xudp_only && frame.id != 0) { return; }
            let udp = frame.network == 2;
            if udp_only && !udp { return; }
            let Some(destination) = mux_destination(frame.address.clone(), frame.port, udp) else { return; };
            let route = Route::Attached(frame.id, writer.clone());
            let session = match frame.global_id {
                Some(global_id) => attach_xudp(xudp, (email.clone(), global_id), destination, route),
                None => MuxSession::new(destination, route, None),
            };
            sessions.insert(frame.id, session);
        } else if frame.status != KEEP { return; }
        let Some(session) = sessions.get(&frame.id) else { continue; };
        let mut session = session.lock().expect("mux");
        session.last = Instant::now();
        let udp = session.destination.transport() == Transport::Udp;
        let destination = if frame.status == KEEP && frame.address.is_some() {
            if !udp || frame.network != 2 { return; }
            let Some(destination) = mux_destination(frame.address, frame.port, true) else { return; };
            destination
        } else { session.destination.clone() };
        let key = (destination.host().to_string(), destination.port());
        if let Some(lane) = session.lanes.get(&key).and_then(Weak::upgrade) {
            drop(session);
            if !frame.payload.is_empty() { lane.enqueue(frame.payload); }
            continue;
        }
        if !udp && frame.status != NEW { continue; }
        let lane = Arc::new(MuxLane {
            plain: Mutex::new(if udp { VecDeque::new() } else { frame.payload.clone().into() }),
            packets: Mutex::new(if udp && !frame.payload.is_empty() { VecDeque::from([frame.payload]) } else { VecDeque::new() }),
            datagram: udp, cv: Condvar::new(), closed: Mutex::new(false),
            reply_target: udp.then(|| (mux_address(&destination), destination.port())),
            route: session.route.clone(),
            resumable: session.global_id.is_some(),
        });
        session.lanes.insert(key, Arc::downgrade(&lane));
        session.lanes.retain(|_, lane| lane.strong_count() > 0);
        drop(session);
        if ready_tx.send(Ready { email: email.clone(), destination, peer, read: Link::Mux(lane.clone()), write: Link::Mux(lane), udp: false, prefix: Vec::new() }).is_err() { return; }
    }
    })();
    for (&id, session) in &sessions { release_mux_session(id, session, &writer); }
}

struct MuxLane {
    plain: Mutex<std::collections::VecDeque<u8>>,
    packets: Mutex<std::collections::VecDeque<Vec<u8>>>,
    datagram: bool,
    cv: Condvar,
    closed: Mutex<bool>,
    reply_target: Option<(kerlico_vless::Addr, u16)>,
    route: Arc<Mutex<Route>>,
    /// An XUDP lane outlives its carrier, so a failed carrier write loses one datagram
    /// instead of ending the flow.
    resumable: bool,
}

impl MuxLane {
    /// Closed, or an XUDP session that waited too long for a carrier.
    fn ended(&self) -> bool {
        let closed = *self.closed.lock().expect("mux");
        closed || self.route.lock().expect("mux").expired()
    }

    /// The session id and carrier for replies. `None` while an XUDP session waits for a
    /// carrier; replies in that gap are dropped like any lost datagram.
    fn carrier(&self) -> Option<(u16, MuxOut)> {
        match &*self.route.lock().expect("mux") {
            Route::Attached(id, writer) => Some((*id, writer.clone())),
            Route::Detached(_) => None,
        }
    }

    fn enqueue(self: &Arc<Self>, payload: Vec<u8>) {
        if self.datagram {
            let mut packets = self.packets.lock().expect("mux");
            while packets.len() >= 256 || packets.iter().map(Vec::len).sum::<usize>() + payload.len() > 1024 * 1024 {
                if Arc::strong_count(self) == 1 || self.ended() { return; }
                packets = self.cv.wait_timeout(packets, Duration::from_millis(200)).expect("mux").0;
            }
            packets.push_back(payload);
        } else {
            let mut plain = self.plain.lock().expect("mux");
            while plain.len() + payload.len() > 1024 * 1024 {
                if Arc::strong_count(self) == 1 || self.ended() { return; }
                plain = self.cv.wait_timeout(plain, Duration::from_millis(200)).expect("mux").0;
            }
            plain.extend(payload);
        }
        self.cv.notify_all();
    }
    fn pull(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.datagram {
            loop {
                let mut packets = self.packets.lock().expect("mux");
                if let Some(packet) = packets.pop_front() {
                    if packet.len() > buf.len() { return Err(std::io::Error::other("mux datagram buffer too small")); }
                    let n = packet.len().min(buf.len());
                    buf[..n].copy_from_slice(&packet[..n]);
                    if n < packet.len() {
                        packets.push_front(packet[n..].to_vec());
                    }
                    self.cv.notify_all();
                    return Ok(n);
                }
                if self.ended() {
                    return Ok(0);
                }
                let (guard, timeout) = self.cv.wait_timeout(packets, Duration::from_millis(200)).expect("mux");
                drop(guard);
                if timeout.timed_out() { return Err(std::io::ErrorKind::WouldBlock.into()); }
            }
        }
        loop {
            let mut plain = self.plain.lock().expect("mux");
            if !plain.is_empty() {
                let n = plain.len().min(buf.len());
                for (index, byte) in plain.drain(..n).enumerate() {
                    buf[index] = byte;
                }
                self.cv.notify_all();
                return Ok(n);
            }
            if self.ended() {
                return Ok(0);
            }
            let (guard, timeout) = self.cv.wait_timeout(plain, Duration::from_millis(200)).expect("mux");
            drop(guard);
            if timeout.timed_out() { return Err(std::io::ErrorKind::WouldBlock.into()); }
        }
    }

    fn push(&self, buf: &[u8]) -> std::io::Result<usize> {
        if self.ended() {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        if self.datagram && buf.len() > u16::MAX as usize {
            return Err(std::io::Error::other("mux datagram too large"));
        }
        let buf = &buf[..buf.len().min(u16::MAX as usize)];
        let Some((id, writer)) = self.carrier() else { return Ok(buf.len()) };
        let frame = MuxFrame {
            id,
            status: KEEP,
            option: DATA,
            network: if self.datagram { 2 } else { 0 },
            port: self.reply_target.as_ref().map_or(0, |(_, port)| *port),
            address: self.reply_target.as_ref().map(|(address, _)| address.clone()),
            payload: buf.to_vec(),
            global_id: None,
        };
        let sent = writer.lock().expect("mux").send(&frame);
        match sent {
            Err(_) if self.resumable => Ok(buf.len()),
            sent => sent.map(|()| buf.len()),
        }
    }

    fn flush(&self) -> std::io::Result<()> {
        let Some((_, writer)) = self.carrier() else { return Ok(()) };
        let flushed = writer.lock().expect("mux").flush();
        if self.resumable { Ok(()) } else { flushed }
    }
}

#[derive(Clone)]
struct Fallback {
    host: String,
    port: u16,
    xver: u8,
}

#[derive(Clone)]
struct FallbackSet {
    rules: Vec<Fallback>,
    map: HashMap<String, HashMap<String, HashMap<String, usize>>>,
}

impl FallbackSet {
    fn empty() -> Self {
        Self { rules: Vec::new(), map: HashMap::new() }
    }

    fn build(rules: Vec<(String, String, String, Fallback)>) -> Self {
        let mut map: HashMap<String, HashMap<String, HashMap<String, usize>>> = HashMap::new();
        let stored: Vec<Fallback> = rules
            .iter()
            .enumerate()
            .map(|(index, (name, alpn, path, rule))| {
                map.entry(name.clone()).or_default().entry(alpn.clone()).or_default().insert(path.clone(), index);
                rule.clone()
            })
            .collect();
        if map.contains_key("") {
            let default_alpns: Vec<String> = map.get("").unwrap().keys().cloned().collect();
            let names: Vec<String> = map.keys().filter(|name| !name.is_empty()).cloned().collect();
            for name in names {
                for alpn in &default_alpns {
                    map.get_mut(&name).unwrap().entry(alpn.clone()).or_default();
                }
            }
        }
        let names: Vec<String> = map.keys().cloned().collect();
        for name in names {
            let Some(default_paths) = map.get(&name).and_then(|alpns| alpns.get("")).cloned() else {
                continue;
            };
            let alpns: Vec<String> = map.get(&name).unwrap().keys().filter(|alpn| !alpn.is_empty()).cloned().collect();
            for alpn in alpns {
                let slot = map.get_mut(&name).unwrap().get_mut(&alpn).unwrap();
                for (path, index) in &default_paths {
                    slot.entry(path.clone()).or_insert(*index);
                }
            }
        }
        if map.contains_key("") {
            let default = map.get("").unwrap().clone();
            let names: Vec<String> = map.keys().filter(|name| !name.is_empty()).cloned().collect();
            for name in names {
                for (alpn, paths) in &default {
                    let slot = map.get_mut(&name).unwrap().entry(alpn.clone()).or_default();
                    for (path, index) in paths {
                        slot.entry(path.clone()).or_insert(*index);
                    }
                }
            }
        }
        Self { rules: stored, map }
    }

    fn pick(&self, name: &str, alpn: &str, first: &[u8]) -> Option<&Fallback> {
        if self.map.is_empty() {
            return None;
        }
        let mut name = name.to_ascii_lowercase();
        let mut alpn = alpn.to_ascii_lowercase();
        if self.map.len() > 1 || !self.map.contains_key("") {
            if !name.is_empty() && !self.map.contains_key(&name) {
                let mut matched = String::new();
                for key in self.map.keys() {
                    if !key.is_empty() && name.contains(key) && key.len() > matched.len() {
                        matched = key.clone();
                    }
                }
                name = matched;
            }
        }
        if !self.map.contains_key(&name) {
            name.clear();
        }
        let alpns = self.map.get(&name)?;
        if !alpns.contains_key(&alpn) {
            alpn.clear();
        }
        let paths = alpns.get(&alpn)?;
        let mut path = String::new();
        if paths.len() > 1 || !paths.contains_key("") {
            if first.len() >= 18 && first.get(4) != Some(&b'*') {
                let end = first.len().min(9);
                for index in 4..end {
                    if first[index] == b'/' && first[index - 1] == b' ' {
                        let search = first.len().min(64);
                        for stop in index + 1..search {
                            let byte = first[stop];
                            if byte == b'\r' || byte == b'\n' {
                                break;
                            }
                            if byte == b'?' || byte == b' ' {
                                let candidate = String::from_utf8_lossy(&first[index..stop]).into_owned();
                                if paths.contains_key(&candidate) {
                                    path = candidate;
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
        self.rules.get(*paths.get(&path)?)
    }
}

fn load_fallbacks(settings: &Settings) -> Result<FallbackSet, OpenError> {
    let mut rules = Vec::new();
    if let Ok(text) = settings.text("fallback") {
        let (host, port) = parse_fallback(text)?;
        rules.push((String::new(), String::new(), String::new(), Fallback { host, port, xver: 0 }));
    }
    if let Ok(text) = settings.text("fallbacks") {
        if text.trim_start().starts_with('[') {
            let entries: Vec<serde_json::Value> = serde_json::from_str(text).map_err(|_| OpenError::Settings)?;
            for entry in entries {
                let entry = entry.as_object().ok_or(OpenError::Settings)?;
                let field = |key| -> Result<String, OpenError> {
                    match entry.get(key) { None => Ok(String::new()), Some(serde_json::Value::String(value)) => Ok(value.to_lowercase()), _ => Err(OpenError::Settings) }
                };
                let name = field("name")?;
                let alpn = field("alpn")?;
                let path = match entry.get("path") { None => String::new(), Some(serde_json::Value::String(value)) => value.clone(), _ => return Err(OpenError::Settings) };
                let dest = match entry.get("dest") {
                    Some(serde_json::Value::String(value)) => value.clone(),
                    Some(serde_json::Value::Number(value)) => value.to_string(),
                    _ => return Err(OpenError::Settings),
                };
                let xver = match entry.get("xver") { None => 0, Some(value) => value.as_u64().filter(|value| *value <= 2).ok_or(OpenError::Settings)? as u8 };
                validate_fallback(&alpn, &path)?;
                let (host, port) = parse_fallback(&dest)?;
                rules.push((name, alpn, path, Fallback { host, port, xver }));
            }
        } else { for part in text.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            rules.push(parse_fallback_rule(part)?);
        } }
    }
    Ok(FallbackSet::build(rules))
}

fn parse_fallback_rule(text: &str) -> Result<(String, String, String, Fallback), OpenError> {
    let mut name = String::new();
    let mut alpn = String::new();
    let mut path = String::new();
    let mut dest = String::new();
    let mut xver = 0u8;
    for field in text.split(',') {
        let (key, value) = field.split_once('=').ok_or(OpenError::Settings)?;
        match key.trim() {
            "name" => name = value.trim().to_ascii_lowercase(),
            "alpn" => alpn = value.trim().to_ascii_lowercase(),
            "path" => path = value.trim().to_string(),
            "dest" => dest = value.trim().to_string(),
            "xver" => {
                xver = value.trim().parse().map_err(|_| OpenError::Settings)?;
                if xver > 2 {
                    return Err(OpenError::Settings);
                }
            }
            _ => return Err(OpenError::Settings),
        }
    }
    let (host, port) = parse_fallback(&dest)?;
    validate_fallback(&alpn, &path)?;
    Ok((name, alpn, path, Fallback { host, port, xver }))
}

fn validate_fallback(alpn: &str, path: &str) -> Result<(), OpenError> {
    if (!path.is_empty() && !path.starts_with('/')) || (alpn == "h2" && !path.is_empty()) { return Err(OpenError::Settings); }
    Ok(())
}

struct Portal {
    active: Arc<std::sync::atomic::AtomicBool>,
    write: Arc<Mutex<kerlico_vless::MuxWriter<Link>>>,
    next: Mutex<u16>,
    sessions: Mutex<HashMap<u16, Weak<MuxLane>>>,
}

fn portals() -> &'static Mutex<HashMap<(NodeTag, String), Arc<Portal>>> {
    static PORTALS: std::sync::OnceLock<Mutex<HashMap<(NodeTag, String), Arc<Portal>>>> = std::sync::OnceLock::new();
    PORTALS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn portal_loop(tag: (NodeTag, String), portal: Arc<Portal>, mut read: Link, mut pending: Vec<u8>) {
    read.set_timeout(Duration::from_millis(200));
    let mut counter = 0u32;
    let mut last = std::time::Instant::now();
    let mut buf = [0u8; 2048];
    let mut ended = VecDeque::new();
    'connection: loop {
        if !portal.active.load(std::sync::atomic::Ordering::Acquire) { break; }
        let dropped = {
            let sessions = portal.sessions.lock().expect("reverse");
            sessions.iter().filter_map(|(&id, lane)| (lane.strong_count() == 0 && !ended.contains(&id)).then_some(id)).collect::<Vec<_>>()
        };
        ended.extend(dropped);
        while let Some(&id) = ended.front() {
            let frame = MuxFrame { id, status: END, option: 0, network: 0, port: 0, address: None, payload: Vec::new(), global_id: None };
            match portal.write.lock().expect("reverse").send(&frame) {
                Ok(()) => {
                    ended.pop_front();
                    portal.sessions.lock().expect("reverse").remove(&id);
                }
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                Err(_) => break 'connection,
            }
        }
        if last.elapsed() >= Duration::from_secs(2) {
            let (next, due) = kerlico_vless::heartbeat_due(counter);
            counter = next;
            last = std::time::Instant::now();
            if due {
                if let Err(error) = portal.write.lock().expect("reverse").send(&kerlico_vless::control_keep(1)) {
                    if !matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) { break; }
                }
            }
        }
        loop {
            match decode_mux(&pending) {
                Ok((frame, used)) => {
                    pending.drain(..used);
                    let lane = portal.sessions.lock().expect("reverse").get(&frame.id).and_then(Weak::upgrade);
                    if let Some(lane) = lane {
                        if !frame.payload.is_empty() {
                            lane.enqueue(frame.payload);
                        }
                        if frame.status == END {
                            *lane.closed.lock().expect("mux") = true;
                            portal.sessions.lock().expect("reverse").remove(&frame.id);
                            ended.retain(|id| *id != frame.id);
                        }
                        lane.cv.notify_all();
                    }
                }
                Err(kerlico_vless::HeaderError::Short) => break,
                Err(kerlico_vless::HeaderError::Bad) => break 'connection,
            }
        }
        portal.write.lock().expect("reverse").flush().ok();
        match read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {},
            Err(_) => break,
        }
    }
    for lane in portal.sessions.lock().expect("reverse").values().filter_map(Weak::upgrade) {
        *lane.closed.lock().expect("mux") = true;
        lane.cv.notify_all();
    }
    let mut portals = portals().lock().expect("reverse");
    if portals.get(&tag).is_some_and(|current| Arc::ptr_eq(current, &portal)) { portals.remove(&tag); }
}

/// Opens a bidirectional mux session without dialing its destination here.
pub fn open_reverse(tag: &str, host: &str, port: u16, tcp: bool, payload: &[u8]) -> Result<Box<dyn InboundStream>, OpenError> {
    let portal = {
        let registry = portals().lock().expect("reverse");
        let mut matches = registry.iter().filter(|((_, candidate), portal)| candidate == tag && portal.active.load(std::sync::atomic::Ordering::Acquire)).map(|(_, portal)| portal.clone());
        let portal = matches.next().ok_or(OpenError::Again)?;
        if matches.next().is_some() { return Err(OpenError::Settings); }
        portal
    };
    open_reverse_portal(portal, host, port, tcp, payload)
}

fn open_reverse_portal(portal: Arc<Portal>, host: &str, port: u16, tcp: bool, payload: &[u8]) -> Result<Box<dyn InboundStream>, OpenError> {
    Destination::new(host, port, if tcp { Transport::Tcp } else { Transport::Udp }).map_err(|_| OpenError::Settings)?;
    if payload.len() > u16::MAX as usize { return Err(OpenError::Settings); }
    if !portal.active.load(std::sync::atomic::Ordering::Acquire) { return Err(OpenError::Again); }
    let mut sessions = portal.sessions.lock().expect("reverse");
    let id = {
        let mut next = portal.next.lock().expect("reverse");
        let id = (0..32767).find_map(|_| {
            let id = *next;
            *next = next.wrapping_add(2).max(3);
            (!sessions.contains_key(&id)).then_some(id)
        }).ok_or(OpenError::Again)?;
        id
    };
    let lane = Arc::new(MuxLane {
        plain: Mutex::new(VecDeque::new()), packets: Mutex::new(VecDeque::new()),
        datagram: !tcp, cv: Condvar::new(), closed: Mutex::new(false), reply_target: None,
        route: Arc::new(Mutex::new(Route::Attached(id, portal.write.clone()))), resumable: false,
    });
    sessions.insert(id, Arc::downgrade(&lane));
    drop(sessions);
    let frame = kerlico_vless::session_frame(id, tcp, port, host, payload);
    if portal.write.lock().expect("reverse").send(&frame).is_err() {
        portal.sessions.lock().expect("reverse").remove(&id);
        return Err(OpenError::Transport);
    }
    Ok(Box::new(Stream {
        read: Mutex::new(Link::Mux(lane.clone())), write: Mutex::new(Link::Mux(lane)),
        udp: false, pending: Mutex::new(Vec::new()), staged: Mutex::new(Vec::new()),
        unsent: Mutex::new(Vec::new()),
    }))
}

fn parse_fallback(text: &str) -> Result<(String, u16), OpenError> {
    if let Ok(port) = text.parse::<u16>() {
        return if port > 0 { Ok(("127.0.0.1".into(), port)) } else { Err(OpenError::Settings) };
    }
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        rest.split_once("]:").ok_or(OpenError::Settings)?
    } else {
        text.rsplit_once(':').ok_or(OpenError::Settings)?
    };
    let port = port.parse().map_err(|_| OpenError::Settings)?;
    if host.is_empty() || port == 0 {
        return Err(OpenError::Settings);
    }
    Ok((host.to_string(), port))
}

fn fall_back(
    read: Link,
    write: Link,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    mut prefix: Vec<u8>,
    dest: &FallbackSet,
    name: &str,
    alpn: &str,
) -> Option<Ready> {
    let (name, alpn) = if let Link::TlsRead(link) = &read {
        link.identity()
    } else {
        (name.to_string(), alpn.to_string())
    };
    let rule = dest.pick(&name, &alpn, &prefix)?;
    let destination = Destination::new(rule.host.clone(), rule.port, Transport::Tcp).ok()?;
    if rule.xver != 0 {
        let mut headed = proxy_header(rule.xver, peer, local);
        headed.append(&mut prefix);
        prefix = headed;
    }
    let email = UserEmail::parse("fallback").ok()?;
    Some(Ready {
        email,
        destination,
        peer,
        read,
        write,
        udp: false,
        prefix,
    })
}

fn proxy_header(xver: u8, peer: SocketAddr, local: Option<SocketAddr>) -> Vec<u8> {
    let Some(local) = local else {
        return if xver == 1 {
            b"PROXY UNKNOWN\r\n".to_vec()
        } else {
            b"\r\n\r\n\0\r\nQUIT\n\x20\0\0\0".to_vec()
        };
    };
    match xver {
        1 => {
            let family = if peer.is_ipv4() && local.is_ipv4() { "TCP4" } else { "TCP6" };
            format!("PROXY {family} {} {} {} {}\r\n", peer.ip(), local.ip(), peer.port(), local.port()).into_bytes()
        }
        2 => {
            let mut out = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
            match (peer.ip(), local.ip()) {
                (std::net::IpAddr::V4(remote), std::net::IpAddr::V4(here)) => {
                    out.extend_from_slice(&[0x21, 0x11, 0x00, 0x0c]);
                    out.extend_from_slice(&remote.octets());
                    out.extend_from_slice(&here.octets());
                }
                (std::net::IpAddr::V6(remote), std::net::IpAddr::V6(here)) => {
                    out.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
                    out.extend_from_slice(&remote.octets());
                    out.extend_from_slice(&here.octets());
                }
                _ => {
                    out.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
                    return out;
                }
            }
            out.extend_from_slice(&peer.port().to_be_bytes());
            out.extend_from_slice(&local.port().to_be_bytes());
            out
        }
        _ => Vec::new(),
    }
}

fn hello_identity(record: &[u8]) -> (String, String) {
    let Some(handshake) = record.get(5..) else {
        return (String::new(), String::new());
    };
    if handshake.first() != Some(&1) || handshake.len() < 38 {
        return (String::new(), String::new());
    }
    let mut offset = 38usize;
    let Some(session) = handshake.get(offset).copied() else {
        return (String::new(), String::new());
    };
    offset += 1 + session as usize;
    let Some(cipher_bytes) = handshake.get(offset..offset + 2) else {
        return (String::new(), String::new());
    };
    let ciphers = u16::from_be_bytes([cipher_bytes[0], cipher_bytes[1]]) as usize;
    offset += 2 + ciphers;
    let Some(compression) = handshake.get(offset).copied() else {
        return (String::new(), String::new());
    };
    offset += 1 + compression as usize;
    let Some(ext_bytes) = handshake.get(offset..offset + 2) else {
        return (String::new(), String::new());
    };
    let ext_len = u16::from_be_bytes([ext_bytes[0], ext_bytes[1]]) as usize;
    offset += 2;
    let end = (offset + ext_len).min(handshake.len());
    let mut name = String::new();
    let mut alpn = String::new();
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]);
        let len = u16::from_be_bytes([handshake[offset + 2], handshake[offset + 3]]) as usize;
        offset += 4;
        let body = handshake.get(offset..offset + len).unwrap_or(&[]);
        offset += len;
        if kind == 0 && body.len() >= 5 {
            let host_len = u16::from_be_bytes([body[3], body[4]]) as usize;
            if let Some(host) = body.get(5..5 + host_len) {
                name = String::from_utf8_lossy(host).to_ascii_lowercase();
            }
        }
        if kind == 16 && body.len() >= 3 {
            let proto_len = body[2] as usize;
            if let Some(proto) = body.get(3..3 + proto_len) {
                alpn = String::from_utf8_lossy(proto).to_ascii_lowercase();
            }
        }
    }
    (name, alpn)
}

fn handshake(
    mut read: Link,
    mut write: Link,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    accounts: &Users,
    ready_tx: &Sender<Ready>,
    fallback: FallbackSet,
    prelude: Vec<u8>,
    name: String,
    alpn: String,
) -> Option<Ready> {
    let fallback = if fallback.rules.is_empty() { accounts.fallback.clone() } else { fallback };
    read.set_timeout(Duration::from_secs(10));
    write.set_timeout(Duration::from_secs(10));
    if !prelude.is_empty() { read = Link::Prefix(Box::new(read), prelude.into()); }
    if let Some((secret, mode, from, to, pad)) = &accounts.encryption {
        let (reader, writer) = kerlico_vless::accept_encrypted(Box::new(read), Box::new(write), secret, *mode, *from, *to, pad).ok()?;
        read = Link::EncRead(Box::new(reader));
        write = Link::EncWrite(Box::new(writer));
    }
    let (request, prefix, full) = match read_request(&mut read, Vec::new()) {
        Ok(value) => value,
        Err(buf) => return fall_back(read, write, peer, local, buf, &fallback, &name, &alpn),
    };
    let (email, account_vision, reverse, active) = {
        let accounts = accounts.lock().expect("accounts");
        let Some(account) = accounts.get(&account_id(request.id)) else {
            return fall_back(read, write, peer, local, full, &fallback, &name, &alpn);
        };
        let flow_ok = account.flow == request.flow || (vision_flow(&account.flow) && request.flow.is_empty() && request.command != Command::Tcp);
        if !flow_ok || (!account.reverse.is_empty() && request.command != Command::Reverse) {
            return None;
        }
        (account.email.clone(), vision_flow(&account.flow), account.reverse.clone(), account.active.clone())
    };
    let vision = vision_flow(&request.flow);
    if vision && !read.supports_vision() { return None; }
    if (vision && request.command == Command::Udp) || (request.command == Command::Reverse && reverse.is_empty()) { return None; }
    if matches!(request.command, Command::Tcp | Command::Udp) && request.port == 0 {
        return fall_back(read, write, peer, local, full, &fallback, &name, &alpn);
    }
    let response = encode_response(&Response { flow: String::new(), seed: Vec::new() }).ok()?;
    write.write_all(&response).ok()?;
    let prefix = if vision {
        let (reader, writer) = kerlico_vless::vision_pair(read, write, request.id, &prefix).ok()?;
        read = Link::Vision(Box::new(reader));
        write = Link::Vision(Box::new(writer));
        Vec::new()
    } else { prefix };
    if request.command == Command::Reverse {
        if !active.load(std::sync::atomic::Ordering::Acquire) { return None; }
        write.write_all(&encode_mux(&kerlico_vless::control_frame(1))).ok()?;
        let portal = Arc::new(Portal { active, write: Arc::new(Mutex::new(kerlico_vless::MuxWriter::new(write))), next: Mutex::new(3), sessions: Mutex::new(HashMap::new()) });
        let key = (accounts.node.clone(), reverse);
        {
            let _accounts = accounts.lock().expect("accounts");
            if !portal.active.load(std::sync::atomic::Ordering::Acquire) { return None; }
            portals().lock().expect("reverse").insert(key.clone(), Arc::clone(&portal));
        }
        thread::spawn(move || portal_loop(key, portal, read, prefix));
        return None;
    }
    if request.command == Command::Mux {
        demux(read, write, peer, email, prefix, ready_tx, &accounts.xudp, account_vision, account_vision && !vision);
        return None;
    }
    let host = match request.address {
        kerlico_vless::Addr::V4(ip) => ip.to_string(),
        kerlico_vless::Addr::V6(ip) => ip.to_string(),
        kerlico_vless::Addr::Domain(name) => name,
    };
    let udp = request.command == Command::Udp;
    let destination = Destination::new(host, request.port, if udp { Transport::Udp } else { Transport::Tcp }).ok()?;
    Some(Ready { email, destination, peer, read, write, udp, prefix })
}

fn read_request(socket: &mut Link, prelude: Vec<u8>) -> Result<(Request, Vec<u8>, Vec<u8>), Vec<u8>> {
    let mut buf = prelude;
    let mut tmp = [0u8; 256];
    loop {
        match kerlico_vless::decode_request(&buf) {
            Ok((request, used)) => {
                let prefix = buf[used..].to_vec();
                return Ok((request, prefix, buf));
            }
            Err(kerlico_vless::HeaderError::Short) => {
                if buf.len() > 533 {
                    return Err(buf);
                }
                let n = match socket.read(&mut tmp) {
                    Ok(n) => n,
                    Err(_) => return Err(buf),
                };
                if n == 0 {
                    return Err(buf);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(kerlico_vless::HeaderError::Bad) => return Err(buf),
        }
    }
}

struct Stream {
    read: Mutex<Link>,
    write: Mutex<Link>,
    udp: bool,
    pending: Mutex<Vec<u8>>,
    staged: Mutex<Vec<u8>>,
    unsent: Mutex<Vec<u8>>,
}

impl InboundStream for Stream {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        if self.udp {
            return self.read_packet(buf);
        }
        let plain = {
            self.pending.lock().expect("pending").is_empty() && self.staged.lock().expect("staged").is_empty()
        };
        if plain {
            let mut socket = self.read.lock().expect("read");
            return match socket.read(buf) {
                Ok(0) => Err(PlaneFault::Closed),
                Ok(n) => Ok(n),
                Err(error) => Err(map_io(error)),
            };
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
        if !self.udp {
            let mut socket = self.write.lock().expect("write");
            return match socket.write(buf) {
                Ok(0) => Err(PlaneFault::Closed),
                Ok(n) => Ok(n),
                Err(error) => Err(map_io(error)),
            };
        }
        let payload = encode_udp(buf).map_err(|_| PlaneFault::Transport)?;
        let mut rest = payload;
        self.write_vec(&mut rest)?;
        if !rest.is_empty() {
            *self.unsent.lock().expect("unsent") = rest;
            return Err(PlaneFault::Again);
        }
        Ok(buf.len())
    }

    fn raw_read(&self) -> Option<TcpStream> {
        if !self.splice_read_ready() {
            return None;
        }
        self.read.lock().expect("read").clone_tcp()
    }

    fn raw_write(&self) -> Option<TcpStream> {
        if !self.splice_write_ready() {
            return None;
        }
        self.write.lock().expect("write").clone_tcp()
    }
}

impl Stream {
    fn splice_read_ready(&self) -> bool {
        if self.udp || !self.pending.lock().expect("pending").is_empty() || !self.staged.lock().expect("staged").is_empty() {
            return false;
        }
        self.read.lock().expect("read").is_tcp()
    }

    fn splice_write_ready(&self) -> bool {
        if self.udp || !self.unsent.lock().expect("unsent").is_empty() {
            return false;
        }
        self.write.lock().expect("write").is_tcp()
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

fn bind_tcp(addr: SocketAddr, settings: &Settings) -> std::io::Result<TcpListener> {
    let socket = kerlico_vless::socket::SocketOptions::parse(settings.text("sockopt").ok())?.open(kerlico_vless::socket::SocketKind::Tcp, kerlico_vless::socket::SocketRole::Listener, addr)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from(socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_shared::ListenAddr;
    use kerlico_vless::{decode_mux, decode_udp, encode_request, encode_udp, Addr, Command, Request, Vision, NEW};
    use std::net::Ipv4Addr;

    #[test]
    fn splice_waits_for_an_empty_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let stream = Stream {
            read: Mutex::new(Link::Tcp(server.try_clone().unwrap())),
            write: Mutex::new(Link::Tcp(server)),
            udp: false,
            pending: Mutex::new(Vec::new()),
            staged: Mutex::new(b"left".to_vec()),
            unsent: Mutex::new(Vec::new()),
        };
        assert!(!stream.splice_read_ready());
        let mut buf = [0u8; 8];
        assert_eq!(stream.read_from_user(&mut buf).unwrap(), 4);
        assert!(stream.splice_read_ready());
        assert!(stream.splice_write_ready());
        drop(client);
    }

    #[test]
    fn tcp_request_becomes_a_handoff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();

        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let request = Request {
                id: parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            socket.write_all(b"ping").unwrap();
            let mut got = [0u8; 4];
            socket.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });

        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        assert_eq!(handoff.destination().port(), 80);
        assert_eq!(handoff.destination().transport(), Transport::Tcp);
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn reverse_user_opens_the_control_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        account.insert_text("reverse", "portal");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = Request {
                id: parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Reverse,
                port: 0,
                address: Addr::Domain("v1.rvs.cool".to_string()),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            let mut buf = [0u8; 128];
            let mut got = Vec::new();
            while got.len() < 8 {
                let n = socket.read(&mut buf).unwrap();
                assert!(n > 0);
                got.extend_from_slice(&buf[..n]);
            }
            let (frame, _) = decode_mux(&got).unwrap();
            assert_eq!(frame.status, NEW);
            assert_eq!(frame.network, 2);
            assert_eq!(frame.port, 0);
            assert_eq!(frame.address, Some(Addr::Domain("reverse".to_string())));
            assert_eq!(&frame.payload[..3], &[0x9a, 0x06, 16]);
        });
        client.join().unwrap();
        assert!(matches!(inbound.accept(), Err(OpenError::Again)));
    }

    #[test]
    fn reverse_session_is_returned_to_the_bridge() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        account.insert_text("reverse", "session");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = Request {
                id: parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Reverse,
                port: 0,
                address: Addr::Domain("v1.rvs.cool".to_string()),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 256];
            let control = loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok((frame, used)) = decode_mux(&buf) {
                    buf.drain(..used);
                    break frame;
                }
            };
            assert_eq!(control.address, Some(Addr::Domain("reverse".to_string())));
            ready_tx.send(()).unwrap();
            let session = loop {
                if let Ok((frame, used)) = decode_mux(&buf) {
                    buf.drain(..used);
                    if frame.address.is_some() {
                        break frame;
                    }
                    continue;
                }
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
            };
            assert_eq!(session.address, Some(Addr::Domain("example.com".to_string())));
            assert_eq!(session.port, 80);
            assert_eq!(session.payload, b"ping");
            loop {
                if let Ok((frame, used)) = decode_mux(&buf) {
                    buf.drain(..used);
                    if frame.id == session.id && frame.status == END { break; }
                    continue;
                }
                let n = socket.read(&mut tmp).unwrap();
                assert!(n > 0, "bridge closed before the session END");
                buf.extend_from_slice(&tmp[..n]);
            }
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        open_reverse("session", "example.com", 80, true, b"ping").unwrap();
        client.join().unwrap();
        assert!(matches!(inbound.accept(), Err(OpenError::Again)));
    }

    #[test]
    #[ignore = "requires XRAY pointing to the pinned Xray binary"]
    fn official_xray_reverse_bridge_dials_the_origin() {
        let xray = std::env::var("XRAY").expect("XRAY is required");
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let got = Arc::clone(&seen);
        thread::spawn(move || {
            let (mut socket, _) = origin.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut buf = [0u8; 64];
            if let Ok(n) = socket.read(&mut buf) {
                *got.lock().expect("origin") = buf[..n].to_vec();
                socket.write_all(b"pong").unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        account.insert_text("reverse", "bridge");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let config = std::env::temp_dir().join(format!("kerlico-reverse-{port}.json"));
        fs::write(
            &config,
            format!(
                r#"{{"log":{{"loglevel":"warning"}},"outbounds":[{{"protocol":"freedom","tag":"direct","settings":{{"finalRules":[{{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":"{origin_port}"}}]}}}},{{"protocol":"vless","tag":"proxy","settings":{{"address":"127.0.0.1","port":{port},"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none","reverse":{{"tag":"bridge"}}}}}}],"routing":{{"rules":[{{"type":"field","inboundTag":["bridge"],"outboundTag":"direct"}}]}}}}"#
            ),
        )
        .unwrap();
        let mut child = std::process::Command::new(xray)
            .args(["run", "-c"])
            .arg(&config)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let started = std::time::Instant::now();
        let response = loop {
            if let Ok(stream) = open_reverse("bridge", "127.0.0.1", origin_port, true, b"ping") { break stream; }
            if started.elapsed() > Duration::from_secs(6) {
                let _ = child.kill();
                panic!("reverse portal did not open");
            }
            thread::sleep(Duration::from_millis(100));
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        while seen.lock().expect("origin").is_empty() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let body = seen.lock().expect("origin").clone();
        let mut reply = [0; 4];
        let received = loop {
            match response.read_from_user(&mut reply) {
                Err(PlaneFault::Again) if std::time::Instant::now() < deadline => continue,
                result => break result,
            }
        };
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(config);
        assert_eq!(body, b"ping");
        assert_eq!(received, Ok(4));
        assert_eq!(&reply, b"pong");
    }

    #[test]
    fn reverse_user_refuses_a_forward_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        account.insert_text("reverse", "portal");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let request = Request {
                id: parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut buf = [0u8; 8];
            assert_eq!(socket.read(&mut buf).unwrap(), 0);
        });
        client.join().unwrap();
        assert!(matches!(inbound.accept(), Err(OpenError::Again)));
    }

    #[test]
    fn native_encryption_then_vless() {
        let (secret, public) = kerlico_vless::native_pair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", &kerlico_vless::encode_key("mlkem768x25519plus.native.0s.", &secret));
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (mut reader, mut writer) = kerlico_vless::connect_native(socket, &[kerlico_vless::NfsKey::X25519(public)], 0, false, &kerlico_vless::Pad::empty()).unwrap();
            let request = Request {
                id: parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            writer.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            reader.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        client.join().unwrap();
    }

    #[test]
    fn reality_hello_then_vless() {
        let (private, public) = kerlico_vless::reality_pair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "5783a3e7-e373-51cd-8642-c83782b807c5");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (hello, secret) = kerlico_vless::reality_offer(&public, &short_id, "www.example.com").unwrap();
            let mut writer = socket.try_clone().unwrap();
            writer.write_all(&hello).unwrap();
            let mut reader = socket;
            let flight = kerlico_vless::take_flight(&mut reader).unwrap();
            let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, None, &public).unwrap();
            writer.write_all(&finished).unwrap();
            let mut reader = kerlico_vless::reality_reader(reader, read_key);
            let mut writer = kerlico_vless::reality_writer(writer, write_key);
            let request = Request {
                id: parse_id("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            writer.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            reader.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        client.join().unwrap();
    }

    #[test]
    fn udp_length_prefix_is_one_datagram() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Udp,
                port: 53,
                address: Addr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            socket.write_all(&encode_udp(b"hi").unwrap()).unwrap();
            let mut got = [0u8; 4];
            socket.read_exact(&mut got).unwrap();
            assert_eq!(decode_udp(&got).unwrap().0, b"yo");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().transport(), Transport::Udp);
        assert_eq!(handoff.peer().unwrap().ip().to_string(), "127.0.0.1");
        let stream = handoff.stream();
        let mut buf = [0u8; 8];
        let n = loop {
            match stream.read_from_user(&mut buf) {
                Ok(n) => break n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        };
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(stream.write_to_user(b"yo").unwrap(), 2);
        client.join().unwrap();
    }

    #[test]
    fn unsupported_network_and_flow_are_rejected() {
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "reality");
        let bind = ListenAddr::v4(Ipv4Addr::LOCALHOST, 9).unwrap();
        assert!(listen(&NodeTag::parse("v").unwrap(), &bind, &settings).is_err());
        settings.insert_text("network", "tcp");
        settings.insert_text("flow", "nope");
        assert!(listen(&NodeTag::parse("v").unwrap(), &bind, &settings).is_err());
        settings.insert_text("flow", "");
        settings.insert_text("security", "tls");
        assert!(listen(&NodeTag::parse("v").unwrap(), &bind, &settings).is_err());
    }

    #[test]
    fn tls_carries_the_vless_header() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("security", "tls");
        settings.insert_text("certificate", certified.cert.pem());
        settings.insert_text("key", certified.key_pair.serialize_pem());
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        account.insert_text("flow", "xtls-rprx-vision");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let config = kerlico_vless::client_config(&[], true).unwrap();
            let mut link = kerlico_vless::connect_tls(tcp, config, "localhost").unwrap();
            let id = parse_id("11111111-1111-1111-1111-111111111111").unwrap();
            let request = Request {
                id,
                flow: "xtls-rprx-vision".to_string(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            link.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            link.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            let mut writer = Vision::new(id);
            link.write_all(&writer.seal(b"ping")).unwrap();
            let mut reader = Vision::new(id);
            let mut tmp = [0u8; 2048];
            let mut plain = Vec::new();
            while plain.len() < 4 {
                let n = link.read(&mut tmp).unwrap();
                assert!(n > 0);
                reader.push(&tmp[..n]);
                let mut piece = [0u8; 64];
                loop {
                    let got = reader.pop(&mut piece);
                    if got == 0 {
                        break;
                    }
                    plain.extend_from_slice(&piece[..got]);
                }
            }
            assert_eq!(&plain[..4], b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn vision_padding_is_removed_before_the_handoff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("security", "tls");
        settings.insert_text("certificate", certified.cert.pem());
        settings.insert_text("key", certified.key_pair.serialize_pem());
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        account.insert_text("flow", "xtls-rprx-vision");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let id = parse_id("11111111-1111-1111-1111-111111111111").unwrap();
        let client = thread::spawn(move || {
            let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut socket = kerlico_vless::connect_tls(tcp, kerlico_vless::client_config(&[], true).unwrap(), "localhost").unwrap();
            let request = Request {
                id,
                flow: "xtls-rprx-vision".to_string(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            let mut writer = Vision::new(id);
            socket.write_all(&writer.seal(b"ping")).unwrap();
            let mut reader = Vision::new(id);
            let mut tmp = [0u8; 2048];
            let mut plain = Vec::new();
            while plain.len() < 4 {
                let n = socket.read(&mut tmp).unwrap();
                assert!(n > 0);
                reader.push(&tmp[..n]);
                let mut buf = [0u8; 64];
                loop {
                    let got = reader.pop(&mut buf);
                    if got == 0 {
                        break;
                    }
                    plain.extend_from_slice(&buf[..got]);
                }
            }
            assert_eq!(&plain[..4], b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn httpupgrade_then_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "httpupgrade");
        settings.insert_text("path", "/vless");
        settings.insert_text("host", "localhost");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket
                .write_all(&kerlico_vless::upgrade_request("localhost", "/vless"))
                .unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 256];
            loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok(used) = kerlico_vless::take_upgrade_response(&buf) {
                    assert_eq!(used, buf.len());
                    break;
                }
            }
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            socket.write_all(b"ping").unwrap();
            let mut got = [0u8; 4];
            socket.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn websocket_frames_carry_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "ws");
        settings.insert_text("path", "/vless");
        settings.insert_text("host", "localhost");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let request_bytes = kerlico_vless::upgrade_request("localhost", "/vless");
            let key = kerlico_vless::header_value(std::str::from_utf8(&request_bytes).unwrap(), "sec-websocket-key").unwrap();
            socket.write_all(&request_bytes).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok(used) = kerlico_vless::take_upgrade_response(&buf) {
                    let head = std::str::from_utf8(&buf[..used]).unwrap();
                    assert_eq!(
                        kerlico_vless::header_value(head, "sec-websocket-accept").as_deref(),
                        Some(kerlico_vless::accept_value(&key).as_str())
                    );
                    break;
                }
            }
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            socket
                .write_all(&kerlico_vless::encode_frame(0x2, &encode_request(&request).unwrap(), true))
                .unwrap();
            socket
                .write_all(&kerlico_vless::encode_frame(0x2, b"ping", true))
                .unwrap();
            let mut decoder = kerlico_vless::FrameDecoder::new(false);
            let mut plain = Vec::new();
            while plain.len() < 6 {
                let n = socket.read(&mut tmp).unwrap();
                decoder.push(&tmp[..n]).unwrap();
                let mut piece = [0u8; 64];
                loop {
                    let got = decoder.pop(&mut piece);
                    if got == 0 {
                        break;
                    }
                    plain.extend_from_slice(&piece[..got]);
                }
            }
            assert_eq!(&plain[..2], &[0, 0]);
            assert_eq!(&plain[2..6], b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn grpc_gun_then_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "grpc");
        settings.insert_text("serviceName", "GunService");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let conn = GrpcConnection::connect(socket.try_clone().unwrap(), socket).unwrap();
            let mut io = conn.open("localhost", "/GunService/Tun", "http").unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            io.write_all(&encode_request(&request).unwrap()).unwrap();
            io.write_all(b"ping").unwrap();
            let mut response = [0u8; 2];
            io.read_exact(&mut response).unwrap();
            let mut got = [0u8; 4];
            io.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn grpc_trusted_forwarding_sets_the_udp_session_source() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "grpc");
        settings.insert_text("serviceName", "GunService");
        settings.insert_text("sockopt", r#"{"trustedXForwardedFor":["X-Trusted-CDN"]}"#);
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        ).unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "forwarded");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();

        let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let actual_peer = socket.local_addr().unwrap();
        let connection = kerlico_vless::H2Conn::connect(socket.try_clone().unwrap(), socket).unwrap();
        let request = encode_request(&Request {
            id: parse_id("forwarded").unwrap(),
            flow: String::new(),
            seed: Vec::new(),
            command: Command::Udp,
            port: 53,
            address: Addr::Domain("example.test".into()),
        }).unwrap();
        let mut hunk = vec![0];
        hunk.extend_from_slice(&(request.len() as u32 + 2).to_be_bytes());
        hunk.extend_from_slice(&[10, request.len().try_into().unwrap()]);
        hunk.extend_from_slice(&request);
        let mut headers = vec![
            ("content-type", "application/grpc"),
            ("x-forwarded-for", "203.0.113.7, 192.0.2.9"),
        ];
        let mut first = connection.open("POST", "/GunService/Tun", "localhost", "http", &headers, false).unwrap();
        first.write_all(&hunk).unwrap();
        let first = wait_handoff(&mut *inbound);
        assert_eq!(first.peer(), Some(actual_peer));
        headers.push(("x-trusted-cdn", "1"));
        let mut second = connection.open("POST", "/GunService/TunMulti", "localhost", "http", &headers, false).unwrap();
        second.write_all(&hunk).unwrap();
        let second = wait_handoff(&mut *inbound);
        assert_eq!(second.peer(), Some("203.0.113.7:0".parse().unwrap()));
    }

    #[test]
    fn grpc_over_reality_then_vless() {
        let (private, public) = kerlico_vless::reality_pair();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "grpc");
        settings.insert_text("serviceName", "GunService");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (hello, secret, kem) = kerlico_vless::reality_offer_hybrid(&public, &short_id, "www.example.com").unwrap();
            let mut writer = socket.try_clone().unwrap();
            writer.write_all(&hello).unwrap();
            let mut reader = socket;
            let flight = kerlico_vless::take_flight(&mut reader).unwrap();
            let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, Some(kem.as_slice()), &public).unwrap();
            writer.write_all(&finished).unwrap();
            reader.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let conn = GrpcConnection::connect(reality_reader(reader, read_key), reality_writer(writer, write_key)).unwrap();
            let mut io = conn.open("localhost", "/GunService/Tun", "https").unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            io.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            io.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        client.join().unwrap();
    }

    #[test]
    fn http2_then_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "http");
        settings.insert_text("path", "/vless");
        settings.insert_text("host", "example.com");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut io = kerlico_vless::HttpIo::connect(socket, "example.com", "/vless", "POST", "http").unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            io.write_all(&encode_request(&request).unwrap()).unwrap();
            io.write_all(b"ping").unwrap();
            let mut response = [0u8; 2];
            io.read_exact(&mut response).unwrap();
            let mut got = [0u8; 4];
            io.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn mkcp_then_vless() {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "mkcp");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut io = kerlico_vless::KcpIo::connect("127.0.0.1", port, 7).unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            io.write_all(&encode_request(&request).unwrap()).unwrap();
            io.write_all(b"ping").unwrap();
            let mut response = [0u8; 2];
            io.read_exact(&mut response).unwrap();
            let mut got = [0u8; 4];
            io.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn mkcp_srtp_seed_then_vless() {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "mkcp");
        settings.insert_text("header", "srtp");
        settings.insert_text("seed", "secret");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let mask = kerlico_vless::kcp_mask("srtp", "", "secret").unwrap();
            let mut io = kerlico_vless::KcpIo::connect_with("127.0.0.1", port, 7, mask).unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            io.write_all(&encode_request(&request).unwrap()).unwrap();
            io.write_all(b"ping").unwrap();
            let mut response = [0u8; 2];
            io.read_exact(&mut response).unwrap();
            let mut got = [0u8; 4];
            io.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_packet_up_then_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let session = "abc";
            let mut download = TcpStream::connect(("127.0.0.1", port)).unwrap();
            kerlico_vless::write_get(&mut download, "example.com", &kerlico_vless::session_path("/xh", session, None)).unwrap();
            let leftover = kerlico_vless::read_response_head(&mut download).unwrap();
            let mut reader = kerlico_vless::ChunkReader::new(download, leftover);
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            let mut upload = TcpStream::connect(("127.0.0.1", port)).unwrap();
            kerlico_vless::write_post(
                &mut upload,
                "example.com",
                &kerlico_vless::session_path("/xh", session, Some(0)),
                &encode_request(&request).unwrap(),
            )
            .unwrap();
            kerlico_vless::read_response_head(&mut upload).unwrap();
            let mut ping = TcpStream::connect(("127.0.0.1", port)).unwrap();
            kerlico_vless::write_post(&mut ping, "example.com", &kerlico_vless::session_path("/xh", session, Some(1)), b"ping").unwrap();
            kerlico_vless::read_response_head(&mut ping).unwrap();
            let mut response = [0u8; 2];
            assert_eq!(reader.pull(&mut response).unwrap(), 2);
            let mut got = [0u8; 4];
            let mut filled = 0;
            while filled < 4 {
                filled += reader.pull(&mut got[filled..]).unwrap();
            }
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_over_reality_then_vless() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let wrap = |port: u16| {
                let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
                let (hello, secret, kem) = kerlico_vless::reality_offer_hybrid(&public, &short_id, "example.com").unwrap();
                let mut writer = socket.try_clone().unwrap();
                writer.write_all(&hello).unwrap();
                let mut reader = socket;
                let flight = kerlico_vless::take_flight(&mut reader).unwrap();
                let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, Some(kem.as_slice()), &public).unwrap();
            writer.write_all(&finished).unwrap();
                RealityDuplex::new(reality_reader(reader, read_key), reality_writer(writer, write_key))
            };
            let session = "abc";
            let mut download = wrap(port);
            kerlico_vless::write_get(&mut download, "example.com", &kerlico_vless::session_path("/xh", session, None)).unwrap();
            let leftover = kerlico_vless::read_response_head(&mut download).unwrap();
            let mut reader = kerlico_vless::ChunkReader::new(download, leftover);
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            let mut upload = wrap(port);
            kerlico_vless::write_post(&mut upload, "example.com", &kerlico_vless::session_path("/xh", session, Some(0)), &encode_request(&request).unwrap()).unwrap();
            kerlico_vless::read_response_head(&mut upload).unwrap();
            let mut ping = wrap(port);
            kerlico_vless::write_post(&mut ping, "example.com", &kerlico_vless::session_path("/xh", session, Some(1)), b"ping").unwrap();
            kerlico_vless::read_response_head(&mut ping).unwrap();
            let mut response = [0u8; 2];
            assert_eq!(reader.pull(&mut response).unwrap(), 2);
            let mut got = [0u8; 4];
            let mut filled = 0;
            while filled < 4 {
                filled += reader.pull(&mut got[filled..]).unwrap();
            }
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_h2_over_reality_then_vless() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (hello, secret, kem) = kerlico_vless::reality_offer_hybrid(&public, &short_id, "example.com").unwrap();
            let mut writer = socket.try_clone().unwrap();
            writer.write_all(&hello).unwrap();
            let mut reader = socket;
            let flight = kerlico_vless::take_flight(&mut reader).unwrap();
            let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, Some(kem.as_slice()), &public).unwrap();
            writer.write_all(&finished).unwrap();
            let duplex = RealityDuplex::new(reality_reader(reader, read_key), reality_writer(writer, write_key));
            let referer = format!("https://example.com/xh?x_padding={}", "0".repeat(100));
            let mut io = kerlico_vless::HttpIo::connect_with(
                duplex,
                "example.com",
                "/xh/",
                "POST",
                "https",
                &[("content-type", "application/grpc"), ("referer", referer.as_str())],
            )
            .unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            io.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            io.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            io.write_all(b"ping").unwrap();
            let mut got = [0u8; 4];
            io.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_stream_up_over_reality_then_vless() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let open = |port: u16| {
                let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
                let (hello, secret, kem) = kerlico_vless::reality_offer_hybrid(&public, &short_id, "example.com").unwrap();
                let mut writer = socket.try_clone().unwrap();
                writer.write_all(&hello).unwrap();
                let mut reader = socket;
                let flight = kerlico_vless::take_flight(&mut reader).unwrap();
                let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, Some(kem.as_slice()), &public).unwrap();
            writer.write_all(&finished).unwrap();
                RealityDuplex::new(reality_reader(reader, read_key), reality_writer(writer, write_key))
            };
            let referer = format!("https://example.com/xh/abc?x_padding={}", "0".repeat(100));
            let mut down = kerlico_vless::HttpIo::connect_with(open(port), "example.com", "/xh/abc", "GET", "https", &[("referer", referer.as_str())]).unwrap();
            let mut up = kerlico_vless::HttpIo::offer(
                open(port),
                "example.com",
                "/xh/abc",
                "POST",
                "https",
                &[("content-type", "application/grpc"), ("referer", referer.as_str())],
            )
            .unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            up.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            down.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            up.write_all(b"ping").unwrap();
            let mut got = [0u8; 4];
            down.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_stream_up_shares_one_reality_connection() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (hello, secret, kem) = kerlico_vless::reality_offer_hybrid(&public, &short_id, "example.com").unwrap();
            let mut writer = socket.try_clone().unwrap();
            writer.write_all(&hello).unwrap();
            let mut reader = socket;
            let flight = kerlico_vless::take_flight(&mut reader).unwrap();
            let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, Some(kem.as_slice()), &public).unwrap();
            writer.write_all(&finished).unwrap();
            let duplex = RealityDuplex::new(reality_reader(reader, read_key), reality_writer(writer, write_key));
            let (reader, writer) = duplex.into_halves();
            let conn = kerlico_vless::H2Conn::connect(reader, writer).unwrap();
            let referer = format!("https://example.com/xh/abc?x_padding={}", "0".repeat(100));
            let mut down = conn.open("GET", "/xh/abc", "example.com", "https", &[("referer", referer.as_str())], true).unwrap();
            let mut up = conn
                .open("POST", "/xh/abc", "example.com", "https", &[("content-type", "application/grpc"), ("referer", referer.as_str())], false)
                .unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            up.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            down.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            up.write_all(b"ping").unwrap();
            let mut got = [0u8; 4];
            down.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_packet_up_shares_one_reality_connection() {
        let (private, public) = kerlico_vless::reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "packet-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        settings.insert_text("security", "reality");
        settings.insert_text("privateKey", &kerlico_vless::encode_reality_key(&private));
        settings.insert_text("shortId", "0102030405060708");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let (hello, secret, kem) = kerlico_vless::reality_offer_hybrid(&public, &short_id, "example.com").unwrap();
            let mut writer = socket.try_clone().unwrap();
            writer.write_all(&hello).unwrap();
            let mut reader = socket;
            let flight = kerlico_vless::take_flight(&mut reader).unwrap();
            let (read_key, write_key, finished) = kerlico_vless::client_keys(&hello, &flight, &secret, Some(kem.as_slice()), &public).unwrap();
            writer.write_all(&finished).unwrap();
            let duplex = RealityDuplex::new(reality_reader(reader, read_key), reality_writer(writer, write_key));
            let (reader, writer) = duplex.into_halves();
            let conn = kerlico_vless::H2Conn::connect(reader, writer).unwrap();
            let referer = format!("https://example.com/xh/abc?x_padding={}", "0".repeat(100));
            let mut down = conn.open("GET", "/xh/abc", "example.com", "https", &[("referer", referer.as_str())], true).unwrap();
            let up_referer = format!("https://example.com/xh/abc/0?x_padding={}", "0".repeat(100));
            let up = conn
                .open("POST", "/xh/abc/0", "example.com", "https", &[("referer", up_referer.as_str())], false)
                .unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            up.finish(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            down.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0]);
            let up = conn
                .open("POST", "/xh/abc/1", "example.com", "https", &[("referer", up_referer.as_str())], false)
                .unwrap();
            up.finish(b"ping").unwrap();
            let mut got = [0u8; 4];
            down.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_stream_one_then_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-one");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            kerlico_vless::write_stream_post(&mut socket, "example.com", "/xh/").unwrap();
            let leftover = kerlico_vless::read_response_head(&mut socket).unwrap();
            let pair = kerlico_vless::ChunkPair::open(socket, leftover).unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            pair.push(&encode_request(&request).unwrap()).unwrap();
            pair.push(b"ping").unwrap();
            let mut response = [0u8; 2];
            assert_eq!(pair.pull(&mut response).unwrap(), 2);
            let mut got = [0u8; 4];
            let mut filled = 0;
            while filled < 4 {
                filled += pair.pull(&mut got[filled..]).unwrap();
            }
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn xhttp_stream_up_then_vless() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("network", "xhttp");
        settings.insert_text("mode", "stream-up");
        settings.insert_text("path", "/xh");
        settings.insert_text("host", "example.com");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut download = TcpStream::connect(("127.0.0.1", port)).unwrap();
            kerlico_vless::write_get(&mut download, "example.com", "/xh/abc").unwrap();
            let leftover = kerlico_vless::read_response_head(&mut download).unwrap();
            let mut reader = kerlico_vless::ChunkReader::new(download, leftover);
            let mut upload = TcpStream::connect(("127.0.0.1", port)).unwrap();
            kerlico_vless::write_stream_post(&mut upload, "example.com", "/xh/abc").unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Tcp,
                port: 80,
                address: Addr::Domain("example.com".to_string()),
            };
            kerlico_vless::write_chunk(&mut upload, &encode_request(&request).unwrap()).unwrap();
            kerlico_vless::write_chunk(&mut upload, b"ping").unwrap();
            let mut response = [0u8; 2];
            assert_eq!(reader.pull(&mut response).unwrap(), 2);
            let mut got = [0u8; 4];
            let mut filled = 0;
            while filled < 4 {
                filled += reader.pull(&mut got[filled..]).unwrap();
            }
            assert_eq!(&got, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn mux_frame_becomes_a_handoff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound
            .add_user(&UserEmail::parse("alice").unwrap(), &account)
            .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let request = Request {
                id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                flow: String::new(),
                seed: Vec::new(),
                command: Command::Mux,
                port: 1,
                address: Addr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            };
            socket.write_all(&encode_request(&request).unwrap()).unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            let frame = kerlico_vless::encode_mux(&kerlico_vless::MuxFrame {
                id: 1,
                status: kerlico_vless::NEW,
                option: kerlico_vless::DATA,
                network: 1,
                port: 80,
                address: Some(Addr::Domain("example.com".to_string())),
                payload: b"ping".to_vec(),
                global_id: None,
            });
            socket.write_all(&frame).unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 128];
            let payload = loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok((frame, _)) = kerlico_vless::decode_mux(&buf) {
                    break frame.payload;
                }
            };
            assert_eq!(payload, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "example.com");
        assert_eq!(handoff.destination().port(), 80);
        let stream = handoff.stream();
        let mut buf = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match stream.read_from_user(&mut buf[got..]) {
                Ok(n) => got += n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        }
        assert_eq!(&buf, b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn mux_udp_payload_is_the_datagram() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket
                .write_all(&encode_request(&Request {
                    id: parse_id("11111111-1111-1111-1111-111111111111").unwrap(),
                    flow: String::new(),
                    seed: Vec::new(),
                    command: Command::Mux,
                    port: 0,
                    address: Addr::Domain(String::new()),
                }).unwrap())
                .unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            socket
                .write_all(&kerlico_vless::encode_mux(&kerlico_vless::MuxFrame {
                    id: 0,
                    status: NEW,
                    option: DATA,
                    network: 2,
                    port: 20091,
                    address: Some(Addr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                    payload: b"ping".to_vec(),
                    global_id: None,
                }))
                .unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 128];
            let payload = loop {
                let n = socket.read(&mut tmp).unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Ok((frame, _)) = decode_mux(&buf) {
                    break frame.payload;
                }
            };
            assert_eq!(payload, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().transport(), Transport::Udp);
        assert_eq!(handoff.destination().port(), 20091);
        let stream = handoff.stream();
        let mut buf = [0u8; 16];
        let n = loop {
            match stream.read_from_user(&mut buf) {
                Ok(n) => break n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        };
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn vision_mux_udp_unwraps_the_datagram() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("security", "tls");
        settings.insert_text("certificate", certified.cert.pem());
        settings.insert_text("key", certified.key_pair.serialize_pem());
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let mut account = Settings::default();
        account.insert_text("id", "11111111-1111-1111-1111-111111111111");
        account.insert_text("flow", "xtls-rprx-vision");
        inbound.add_user(&UserEmail::parse("alice").unwrap(), &account).unwrap();
        let client = thread::spawn(move || {
            let id = parse_id("11111111-1111-1111-1111-111111111111").unwrap();
            let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut socket = kerlico_vless::connect_tls(tcp, kerlico_vless::client_config(&[], true).unwrap(), "localhost").unwrap();
            socket
                .write_all(&encode_request(&Request {
                    id,
                    flow: "xtls-rprx-vision".to_string(),
                    seed: Vec::new(),
                    command: Command::Mux,
                    port: 0,
                    address: Addr::Domain(String::new()),
                }).unwrap())
                .unwrap();
            let mut response = [0u8; 2];
            socket.read_exact(&mut response).unwrap();
            let frame = kerlico_vless::encode_mux(&kerlico_vless::MuxFrame {
                id: 0,
                status: NEW,
                option: DATA,
                network: 2,
                port: 20091,
                address: Some(Addr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                payload: b"ping".to_vec(),
                global_id: None,
            });
            let meta_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
            let mut raw = Vec::new();
            raw.extend_from_slice(&((meta_len + 8) as u16).to_be_bytes());
            raw.extend_from_slice(&frame[2..2 + meta_len]);
            raw.extend_from_slice(&[0u8; 8]);
            raw.extend_from_slice(&frame[2 + meta_len..]);
            let mut outbound = Vision::new(id);
            socket.write_all(&outbound.seal(&raw)).unwrap();
            let mut inbound_pad = Vision::new(id);
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            let payload = loop {
                let n = socket.read(&mut tmp).unwrap();
                inbound_pad.push(&tmp[..n]);
                let mut plain = [0u8; 2048];
                loop {
                    let got = inbound_pad.pop(&mut plain);
                    if got == 0 {
                        break;
                    }
                    buf.extend_from_slice(&plain[..got]);
                }
                if let Ok((frame, _)) = decode_mux(&buf) {
                    break frame.payload;
                }
            };
            assert_eq!(payload, b"pong");
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().transport(), Transport::Udp);
        let stream = handoff.stream();
        let mut buf = [0u8; 16];
        let n = loop {
            match stream.read_from_user(&mut buf) {
                Ok(n) => break n,
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("{error:?}"),
            }
        };
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(stream.write_to_user(b"pong").unwrap(), 4);
        client.join().unwrap();
    }

    #[test]
    fn bad_header_falls_back_with_the_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("fallback", "127.0.0.1:9");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "127.0.0.1");
        assert_eq!(handoff.destination().port(), 9);
        let stream = handoff.stream();
        let mut buf = [0u8; 32];
        let n = stream.read_from_user(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"GET / HTTP/1.1\r\n\r\n");
        client.join().unwrap();
    }

    #[test]
    fn fallback_picks_path_and_writes_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        settings.insert_text("fallback", "127.0.0.1:9");
        settings.insert_text("fallbacks", "path=/api,dest=127.0.0.1:10,xver=1");
        let mut inbound = listen(
            &NodeTag::parse("v").unwrap(),
            &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(),
            &settings,
        )
        .unwrap();
        let client = thread::spawn(move || {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket.write_all(b"GET /api HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        });
        let handoff = wait_handoff(&mut *inbound);
        assert_eq!(handoff.destination().host(), "127.0.0.1");
        assert_eq!(handoff.destination().port(), 10);
        let stream = handoff.stream();
        let mut buf = [0u8; 128];
        let n = stream.read_from_user(&mut buf).unwrap();
        let text = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(text.starts_with("PROXY TCP4 127.0.0.1 "));
        assert!(text.contains("\r\nGET /api HTTP/1.1\r\n"));
        client.join().unwrap();
    }

    #[test]
    fn fallback_name_uses_the_longest_substring() {
        let rules = FallbackSet::build(vec![
            (String::new(), String::new(), String::new(), Fallback { host: "default".into(), port: 1, xver: 0 }),
            ("example.com".into(), String::new(), String::new(), Fallback { host: "named".into(), port: 2, xver: 0 }),
            ("example.com".into(), "h2".into(), "/ws".into(), Fallback { host: "both".into(), port: 3, xver: 0 }),
        ]);
        assert_eq!(rules.pick("www.example.com", "", b"").unwrap().host, "named");
        assert_eq!(rules.pick("www.example.com", "h2", b"GET /ws HTTP/1.1\r\n\r\n").unwrap().host, "both");
        assert_eq!(rules.pick("other.test", "h2", b"GET /ws HTTP/1.1\r\n\r\n").unwrap().host, "default");
    }

    const ALICE: &str = "11111111-1111-1111-1111-111111111111";
    const BOB: &str = "22222222-2222-2222-2222-222222222222";

    fn xudp_inbound() -> (Box<dyn Accept>, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut settings = Settings::default();
        settings.insert_text("decryption", "none");
        let mut inbound = listen(&NodeTag::parse("v").unwrap(), &ListenAddr::v4(Ipv4Addr::LOCALHOST, port).unwrap(), &settings).unwrap();
        for (email, id) in [("alice", ALICE), ("bob", BOB)] {
            let mut account = Settings::default();
            account.insert_text("id", id);
            inbound.add_user(&UserEmail::parse(email).unwrap(), &account).unwrap();
        }
        (inbound, port)
    }

    /// Opens a Mux carrier as user `id` and sends one datagram as XUDP session `session`.
    fn xudp_carrier(port: u16, id: &str, session: u16, global_id: Option<u64>, payload: &[u8]) -> TcpStream {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let request = Request { id: parse_id(id).unwrap(), flow: String::new(), seed: Vec::new(), command: Command::Mux, port: 0, address: Addr::Domain(String::new()) };
        socket.write_all(&encode_request(&request).unwrap()).unwrap();
        let mut response = [0u8; 2];
        socket.read_exact(&mut response).unwrap();
        socket.write_all(&kerlico_vless::encode_mux(&kerlico_vless::MuxFrame {
            id: session, status: NEW, option: DATA, network: 2, port: 20091,
            address: Some(Addr::V4(Ipv4Addr::LOCALHOST)), payload: payload.to_vec(),
            global_id: global_id.and_then(NonZeroU64::new),
        })).unwrap();
        socket
    }

    fn read_datagram(stream: &dyn InboundStream) -> Result<Vec<u8>, PlaneFault> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 64];
        while Instant::now() < deadline {
            match stream.read_from_user(&mut buf) {
                Ok(n) => return Ok(buf[..n].to_vec()),
                Err(PlaneFault::Again) => thread::sleep(Duration::from_millis(10)),
                Err(fault) => return Err(fault),
            }
        }
        Err(PlaneFault::Again)
    }

    fn read_frame(socket: &mut TcpStream) -> kerlico_vless::MuxFrame {
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            if let Ok((frame, _)) = decode_mux(&buf) { return frame; }
            let n = socket.read(&mut tmp).unwrap();
            assert!(n > 0, "carrier closed before a frame arrived");
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    #[test]
    fn xudp_global_id_moves_the_session_to_a_new_carrier() {
        let (mut inbound, port) = xudp_inbound();
        let mut first = xudp_carrier(port, ALICE, 3, Some(0x5eed), b"one");
        let stream = wait_handoff(&mut *inbound).stream();
        assert_eq!(read_datagram(&*stream), Ok(b"one".to_vec()));

        let mut second = xudp_carrier(port, ALICE, 9, Some(0x5eed), b"two");
        assert_eq!(read_datagram(&*stream), Ok(b"two".to_vec()), "the open flow receives the datagram from the new carrier");
        assert!(matches!(inbound.accept(), Err(OpenError::Again)), "taking over the session opens no second flow");
        let end = read_frame(&mut first);
        assert_eq!((end.id, end.status), (3, END), "the earlier carrier learns its session left");
        assert_eq!(stream.write_to_user(b"back").unwrap(), 4);
        let reply = read_frame(&mut second);
        assert_eq!((reply.id, reply.payload), (9, b"back".to_vec()), "replies follow the new carrier and session id");

        drop(second);
        // Let the server see the carrier close, so the session detaches rather than moves.
        thread::sleep(Duration::from_millis(300));
        assert_eq!(stream.write_to_user(b"lost").unwrap(), 4, "a detached flow drops replies and stays open");
        let mut third = xudp_carrier(port, ALICE, 4, Some(0x5eed), b"three");
        assert_eq!(read_datagram(&*stream), Ok(b"three".to_vec()), "a closed carrier's session reattaches");
        assert!(matches!(inbound.accept(), Err(OpenError::Again)), "reattaching opens no second flow");
        assert_eq!(stream.write_to_user(b"again").unwrap(), 5);
        let reply = read_frame(&mut third);
        assert_eq!((reply.id, reply.payload), (4, b"again".to_vec()));
    }

    #[test]
    fn mux_udp_without_global_id_closes_with_its_carrier() {
        let (mut inbound, port) = xudp_inbound();
        let carrier = xudp_carrier(port, ALICE, 3, None, b"one");
        let stream = wait_handoff(&mut *inbound).stream();
        assert_eq!(read_datagram(&*stream), Ok(b"one".to_vec()));
        drop(carrier);
        assert_eq!(read_datagram(&*stream), Err(PlaneFault::Closed));
    }

    #[test]
    fn xudp_global_id_belongs_to_one_user() {
        let (mut inbound, port) = xudp_inbound();
        let _alice = xudp_carrier(port, ALICE, 3, Some(0x5eed), b"alice");
        let alice = wait_handoff(&mut *inbound);
        let _bob = xudp_carrier(port, BOB, 3, Some(0x5eed), b"bob");
        let bob = wait_handoff(&mut *inbound);
        assert_eq!(bob.user().as_str(), "bob", "the same GlobalID from another user opens its own flow");
        assert_eq!(read_datagram(&*bob.stream()), Ok(b"bob".to_vec()));
        assert_eq!(read_datagram(&*alice.stream()), Ok(b"alice".to_vec()));
    }

    fn wait_handoff(inbound: &mut dyn Accept) -> Handoff {
        for _ in 0..50 {
            match inbound.accept() {
                Ok(handoff) => return handoff,
                Err(OpenError::Again) => thread::sleep(Duration::from_millis(20)),
                Err(error) => panic!("{error:?}"),
            }
        }
        panic!("no handoff");
    }
}
