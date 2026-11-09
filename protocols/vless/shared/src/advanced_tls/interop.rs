use super::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

struct Xray {
    child: Child,
    directory: PathBuf,
}
impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if thread::panicking() {
            eprintln!(
                "Xray log: {}",
                std::fs::read_to_string(self.directory.join("xray.log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Xray {
    fn start(config: Value) -> Self {
        let mut config = config;
        config["log"]["loglevel"] = json!("debug");
        if let Some(outbounds) = config["outbounds"].as_array_mut() {
            for outbound in outbounds {
                if outbound["protocol"] == "freedom" {
                    outbound["settings"] =
                        json!({"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]});
                }
            }
        }
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "kerlico-tls-interop-{}-{}",
            std::process::id(),
            u64::from_le_bytes(random)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("config.json");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let log = std::fs::File::create(directory.join("xray.log")).unwrap();
        let child = Command::new(
            std::env::var("XRAY_BIN").expect("set XRAY_BIN to the pinned Xray 26.10.31 executable"),
        )
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
        Self { child, directory }
    }
    fn connect(&mut self, port: u16) -> TcpStream {
        for _ in 0..200 {
            if let Ok(socket) = TcpStream::connect(("127.0.0.1", port)) {
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return socket;
            }
            if self.child.try_wait().unwrap().is_some() {
                panic!(
                    "Xray exited: {}",
                    std::fs::read_to_string(self.directory.join("xray.log")).unwrap()
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("Xray startup timeout")
    }
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn xray_tls(options: &AdvancedTlsOptions, server: bool) -> Value {
    let mut tls = json!({"serverName":"localhost","minVersion":options.min_version,"maxVersion":options.max_version,"alpn":options.alpn});
    if server {
        tls["certificates"] = json!([{"certificate":options.certificates[0].certificate.lines().collect::<Vec<_>>(),"key":options.certificates[0].key.lines().collect::<Vec<_>>() }]);
        if !options.ech_server_keys.is_empty() {
            tls["echServerKeys"] = json!(options.ech_server_keys);
        }
    } else {
        let der = rustls_pemfile::certs(&mut options.certificates[0].certificate.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let pin = Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        tls["pinnedPeerCertSha256"] = json!(pin);
        tls["fingerprint"] = json!(options.fingerprint);
        if !options.ech_config_list.is_empty() {
            tls["echConfigList"] = json!(options.ech_config_list);
        }
    }
    tls
}
fn to_xray(options: AdvancedTlsOptions) {
    eprintln!(
        "Kerlico -> Xray TLS {} {} ECH {}",
        options.max_version,
        options.fingerprint,
        !options.ech_config_list.is_empty()
    );
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let destination = echo.local_addr().unwrap();
    let echo = thread::spawn(move || {
        let (mut socket, _) = echo.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut ping = [0; 4];
        socket.read_exact(&mut ping).unwrap();
        assert_eq!(&ping, b"ping");
        socket.write_all(b"pong").unwrap();
    });
    let listen = port();
    let mut xray = Xray::start(
        json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":listen,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"01010101-0101-0101-0101-010101010101"}]},"streamSettings":{"network":"raw","security":"tls","tlsSettings":xray_tls(&options,true)}}],"outbounds":[{"protocol":"freedom"}]}),
    );
    let socket = xray.connect(listen);
    let config = advanced_client_config(&options).unwrap();
    let (mut read, mut write) =
        connect_advanced_tls_over(socket.try_clone().unwrap(), socket, config, "localhost")
            .unwrap();
    let request = crate::Request {
        id: [1; 16],
        flow: String::new(),
        seed: Vec::new(),
        command: crate::Command::Tcp,
        port: destination.port(),
        address: crate::Addr::V4(std::net::Ipv4Addr::LOCALHOST),
    };
    write
        .write_all(&crate::encode_request(&request).unwrap())
        .unwrap();
    write.write_all(b"ping").unwrap();
    let mut response = [0; 6];
    read.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"\0\0pong");
    echo.join().unwrap();
    if !options.ech_config_list.is_empty() {
        assert!(read.ech_accepted());
    }
}
fn from_xray(options: AdvancedTlsOptions) {
    eprintln!(
        "Xray -> Kerlico TLS {} {} ECH {}",
        options.max_version,
        options.fingerprint,
        !options.ech_config_list.is_empty()
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = listener.local_addr().unwrap().port();
    let config = advanced_server_config(&options).unwrap();
    let ech = !options.ech_server_keys.is_empty();
    let server = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (mut read, mut write) =
            accept_advanced_tls_over(socket.try_clone().unwrap(), socket, config).unwrap();
        let mut header = Vec::new();
        loop {
            let mut byte = [0];
            read.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            if crate::decode_request(&header).is_ok() {
                break;
            }
            assert!(header.len() < 1024);
        }
        let mut ping = [0; 4];
        read.read_exact(&mut ping).unwrap();
        assert_eq!(&ping, b"ping");
        write.write_all(b"\0\0pong").unwrap();
        if ech {
            assert!(read.ech_accepted());
        }
    });
    let listen = port();
    let mut xray = Xray::start(
        json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":listen,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1","port":9,"network":"tcp"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":remote,"users":[{"id":"01010101-0101-0101-0101-010101010101","encryption":"none"}]}]},"streamSettings":{"network":"raw","security":"tls","tlsSettings":xray_tls(&options,false)}}]}),
    );
    let mut socket = xray.connect(listen);
    socket.write_all(b"ping").unwrap();
    let mut pong = [0; 4];
    socket.read_exact(&mut pong).unwrap();
    assert_eq!(&pong, b"pong");
    server.join().unwrap();
}

#[test]
#[ignore = "requires pinned XRAY_BIN"]
fn xray_advanced_tls_bidirectional() {
    for version in ["1.0", "1.1", "1.2", "1.3"] {
        let mut options = options();
        options.min_version = version.into();
        options.max_version = version.into();
        to_xray(options.clone());
        from_xray(options);
    }
    for fingerprint in [
        "chrome",
        "firefox",
        "safari",
        "edge",
        "ios",
        "android",
        "360",
        "qq",
        "randomized",
        "randomizednoalpn",
    ] {
        let mut options = options();
        options.fingerprint = fingerprint.into();
        options.alpn = vec!["h2".into(), "http/1.1".into()];
        to_xray(options.clone());
        from_xray(options);
    }
    let mut options = ech_options();
    options.fingerprint = "chrome".into();
    to_xray(options.clone());
    from_xray(options);
}

struct Decoy {
    port: u16,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}
impl Decoy {
    fn start() -> Self {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let mut padding = vec![4, 0x82, 0x10, 0];
        padding.resize(4100, 0);
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 32473, 1],
                padding,
            ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = TlsCertificate {
            certificate: params.self_signed(&key).unwrap().pem(),
            key: key.serialize_pem(),
            ..Default::default()
        };
        let config = crate::server_config(
            &cert.certificate,
            &cert.key,
            &["h2".into(), "http/1.1".into()],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = stop.clone();
        let task = thread::spawn(move || {
            while !signal.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let config = config.clone();
                        thread::spawn(move || {
                            socket
                                .set_read_timeout(Some(Duration::from_secs(3)))
                                .unwrap();
                            if let Ok(mut tls) = crate::accept_tls(socket, config) {
                                let _ = tls.read(&mut [0; 1024]);
                            }
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for Decoy {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.task.take().unwrap().join().unwrap();
    }
}

#[test]
#[ignore = "requires pinned XRAY_BIN"]
fn xray_reality_browser_fingerprints() {
    let decoy = Decoy::start();
    for (fingerprint, mldsa) in [
        ("chrome", false),
        ("firefox", false),
        ("safari", false),
        ("edge", false),
        ("ios", false),
        ("qq", false),
        ("randomized", false),
        ("randomizednoalpn", false),
        ("chrome", true),
        ("firefox", true),
        ("safari", true),
    ] {
        eprintln!("Kerlico -> Xray REALITY {fingerprint} MLDSA={mldsa}");
        let (private, public) = crate::reality_pair();
        let short_id = [0; 8];
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = echo.local_addr().unwrap();
        let listen = port();
        let mut xray_config = json!({"inbounds":[{"listen":"127.0.0.1","port":listen,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":"01010101-0101-0101-0101-010101010101"}]},"streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":format!("127.0.0.1:{}",decoy.port),"serverNames":["localhost"],"privateKey":crate::encode_reality_key(&private),"shortIds":["0000000000000000"]}}}],"outbounds":[{"protocol":"freedom"}]});
        let proof = if mldsa {
            let (seed, _) = crate::reality_pair();
            let seed = crate::encode_reality_key(&seed);
            let signer = crate::RealityMldsa65Signer::from_base64(&seed).unwrap();
            xray_config["inbounds"][0]["streamSettings"]["realitySettings"]["mldsa65Seed"] =
                json!(seed);
            Some(crate::RealityMldsa65Verifier::from_base64(&signer.verification_key()).unwrap())
        } else {
            None
        };
        let mut xray = Xray::start(xray_config);
        let mut socket = xray.connect(listen);
        let offer =
            crate::reality_offer_fingerprint(&public, &short_id, "localhost", &[], fingerprint)
                .unwrap();
        socket.write_all(&offer.record).unwrap();
        let flight =
            crate::read_server_flight_for_offer(&mut socket, &offer, &public, proof.as_ref());
        let profile = super::super::fingerprint::resolve(fingerprint)
            .unwrap()
            .unwrap();
        let hybrid = profile
            .extensions
            .iter()
            .find(|extension| extension.id == 51)
            .unwrap()
            .shares
            .iter()
            .any(|&(group, _)| group == 0x11ec);
        if !hybrid {
            // Pinned REALITY 83f621788ca8 tls.go requires a hybrid share before X25519.
            // Older profiles are preserved verbatim and must reject the decoy certificate.
            assert!(
                flight.is_err(),
                "pinned REALITY unexpectedly accepted {fingerprint}"
            );
            continue;
        }
        let (read, write, finished, _) = flight.unwrap();
        let echo = thread::spawn(move || {
            let (mut socket, _) = echo.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut ping = [0; 4];
            socket.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
            socket.write_all(b"pong").unwrap();
        });
        socket.write_all(&finished).unwrap();
        let mut reader = crate::reality_reader(socket.try_clone().unwrap(), read);
        let mut writer = crate::reality_writer(socket, write);
        let request = crate::Request {
            id: [1; 16],
            flow: String::new(),
            seed: Vec::new(),
            command: crate::Command::Tcp,
            port: destination.port(),
            address: crate::Addr::V4(std::net::Ipv4Addr::LOCALHOST),
        };
        writer
            .write_all(&crate::encode_request(&request).unwrap())
            .unwrap();
        writer.write_all(b"ping").unwrap();
        let mut response = [0; 6];
        reader.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"\0\0pong");
        echo.join().unwrap();
    }
}
