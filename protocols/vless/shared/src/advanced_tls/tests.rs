use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn identity(name: &str) -> TlsCertificate {
    let cert = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    TlsCertificate {
        certificate: cert.cert.pem(),
        key: cert.key_pair.serialize_pem(),
        ..Default::default()
    }
}

pub(super) fn options() -> AdvancedTlsOptions {
    AdvancedTlsOptions {
        certificates: vec![identity("localhost")],
        alpn: vec!["h2".into()],
        allow_insecure: true,
        fingerprint: "unsafe".into(),
        ..Default::default()
    }
}

fn exchange(options: AdvancedTlsOptions, name: &str) -> io::Result<(String, bool)> {
    let server = advanced_server_config(&options)?;
    let client = advanced_client_config(&options)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let task = thread::spawn(move || -> io::Result<()> {
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        let (mut read, mut write) = accept_advanced_tls_over(socket.try_clone()?, socket, server)?;
        let mut request = [0; 4];
        read.read_exact(&mut request)?;
        assert_eq!(&request, b"ping");
        write.write_all(b"pong")
    });
    let socket = TcpStream::connect(address)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let result = (|| {
        let (mut read, mut write) =
            connect_advanced_tls_over(socket.try_clone()?, socket, client, name)?;
        write.write_all(b"ping")?;
        let mut response = [0; 4];
        read.read_exact(&mut response)?;
        assert_eq!(&response, b"pong");
        Ok((read.protocol_version(), read.ech_accepted()))
    })();
    let server_result = task.join().unwrap();
    result.and_then(|value| server_result.map(|_| value))
}

pub(super) fn peer_identity(server: Arc<AdvancedTlsServerConfig>) -> (Vec<u8>, Option<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        accept_advanced_tls_over(socket.try_clone().unwrap(), socket, server).unwrap();
    });
    let mut options = options();
    options.fingerprint = "chrome".into();
    let client = advanced_client_config(&options).unwrap();
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (read, _) =
        connect_advanced_tls_over(socket.try_clone().unwrap(), socket, client, "localhost")
            .unwrap();
    let core = read.core.lock().unwrap();
    let leaf = core.ssl().peer_certificate().unwrap().to_der().unwrap();
    let ocsp = core.ssl().ocsp_status().map(<[u8]>::to_vec);
    task.join().unwrap();
    (leaf, ocsp)
}

#[test]
fn certificate_files_reload_atomically_and_one_time_loading_stays_fixed() {
    let path = std::env::temp_dir().join(format!(
        "kerlico-certificate-reload-{}-{}",
        std::process::id(),
        rand_core::OsRng.next_u64()
    ));
    std::fs::create_dir(&path).unwrap();
    let certificate = path.join("cert.pem");
    let key = path.join("key.pem");
    let first = identity("localhost");
    let second = identity("localhost");
    std::fs::write(&certificate, &first.certificate).unwrap();
    std::fs::write(&key, &first.key).unwrap();
    let mut options = options();
    options.certificates = vec![TlsCertificate {
        certificate_file: certificate.to_str().unwrap().into(),
        key_file: key.to_str().unwrap().into(),
        ..Default::default()
    }];
    let server = advanced_server_config(&options).unwrap();
    options.certificates[0].one_time_loading = true;
    let fixed = advanced_server_config(&options).unwrap();
    let first_der = peer_identity(server.clone()).0;
    std::fs::write(&certificate, &second.certificate).unwrap();
    assert_eq!(
        peer_identity(server.clone()).0,
        first_der,
        "a partial rotation must retain the validated pair"
    );
    std::fs::write(&key, &second.key).unwrap();
    assert_ne!(peer_identity(server.clone()).0, first_der);
    assert_eq!(peer_identity(fixed).0, first_der);
    std::fs::write(&certificate, "invalid PEM").unwrap();
    assert_eq!(
        peer_identity(server).0,
        boring2::x509::X509::from_pem(second.certificate.as_bytes())
            .unwrap()
            .to_der()
            .unwrap()
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn negotiates_tls_10_11_12_13() {
    for (version, expected) in [
        ("1.0", "TLSv1"),
        ("1.1", "TLSv1.1"),
        ("1.2", "TLSv1.2"),
        ("1.3", "TLSv1.3"),
    ] {
        let mut options = options();
        options.min_version = version.into();
        options.max_version = version.into();
        assert_eq!(exchange(options, "localhost").unwrap().0, expected);
    }
}

#[test]
fn separate_factory_calls_resume_tls_and_policy_changes_invalidate_sessions() {
    for version in ["1.2", "1.3"] {
        let mut options = options();
        options.min_version = version.into();
        options.max_version = version.into();
        options.enable_session_resumption = true;
        let server = advanced_server_config(&options).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            for _ in 0..3 {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let (mut read, mut write) =
                    accept_advanced_tls_over(socket.try_clone().unwrap(), socket, server.clone())
                        .unwrap();
                read.read_exact(&mut [0]).unwrap();
                write.write_all(b"x").unwrap();
            }
        });
        let factory = AdvancedTlsClientCache::new();
        for expected_reuse in [false, true, false] {
            let client = factory.get(&options).unwrap();
            let socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (mut read, mut write) =
                connect_advanced_tls_over(socket.try_clone().unwrap(), socket, client, "localhost")
                    .unwrap();
            write.write_all(b"x").unwrap();
            read.read_exact(&mut [0]).unwrap();
            assert_eq!(read.session_reused(), expected_reuse, "TLS {version}");
            if expected_reuse {
                options.pinned_peer_cert_sha256 = Sha256::digest(
                    boring2::x509::X509::from_pem(options.certificates[0].certificate.as_bytes())
                        .unwrap()
                        .to_der()
                        .unwrap(),
                )
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            }
        }
        task.join().unwrap();
    }
}

pub(super) fn ech_options() -> AdvancedTlsOptions {
    let private = x25519_dalek::StaticSecret::from([7; 32]);
    let public = x25519_dalek::PublicKey::from(&private);
    let name = b"outer.example";
    let mut content = vec![7, 0, 0x20, 0, 32];
    content.extend_from_slice(public.as_bytes());
    content.extend_from_slice(&[0, 8, 0, 1, 0, 1, 0, 1, 0, 3, 0, name.len() as u8]);
    content.extend_from_slice(name);
    content.extend_from_slice(&[0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(content.len() as u16).to_be_bytes());
    config.extend(content);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&config);
    let mut keys = vec![0, 32];
    keys.extend_from_slice(&private.to_bytes());
    keys.extend_from_slice(&(config.len() as u16).to_be_bytes());
    keys.extend(config);
    let mut options = options();
    options.min_version = "1.3".into();
    options.ech_config_list = STANDARD.encode(list);
    options.ech_server_keys = STANDARD.encode(keys);
    options
}

#[test]
fn ech_is_accepted_and_rejection_never_returns_plain_tls() {
    let options = ech_options();
    assert!(exchange(options.clone(), "localhost").unwrap().1);
    let mut chrome = options.clone();
    chrome.fingerprint = "chrome".into();
    assert!(exchange(chrome, "localhost").unwrap().1);
    let mut rejected = options;
    rejected.ech_server_keys.clear();
    assert!(exchange(rejected, "localhost").is_err());
}

#[test]
fn sni_selects_the_matching_certificate_and_rejects_unknown() {
    let mut options = options();
    let second = identity("second.test");
    let der = rustls_pemfile::certs(&mut second.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    options.pinned_peer_cert_sha256 = Sha256::digest(&der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    options.certificates.push(second);
    options.reject_unknown_sni = true;
    assert!(exchange(options.clone(), "second.test").is_ok());
    assert!(exchange(options.clone(), "localhost").is_err());
    assert!(exchange(options, "unknown.test").is_err());
}

#[test]
fn named_verification_uses_custom_roots_and_preserves_chain_validation() {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["cert.test".into()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &key)
        .unwrap();
    let mut options = options();
    options.allow_insecure = false;
    options.disable_system_root = true;
    options.verify_peer_cert_by_name = vec!["wrong.test".into(), "cert.test".into()];
    options.certificates = vec![
        TlsCertificate {
            certificate: leaf.pem(),
            key: leaf_key.serialize_pem(),
            ..Default::default()
        },
        TlsCertificate {
            certificate: ca.pem(),
            usage: "verify".into(),
            ..Default::default()
        },
    ];
    assert!(exchange(options.clone(), "sni.test").is_ok());
    options.verify_peer_cert_by_name = vec!["wrong.test".into()];
    assert!(exchange(options, "sni.test").is_err());
}

#[test]
fn issuer_certificate_signs_for_requested_sni() {
    for algorithm in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ED25519] {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
        let ca = params.self_signed(&key).unwrap();
        let mut options = options();
        options.allow_insecure = false;
        options.disable_system_root = true;
        options.certificates = vec![TlsCertificate {
            certificate: ca.pem(),
            key: key.serialize_pem(),
            usage: "issue".into(),
            build_chain: true,
            ..Default::default()
        }];
        super::config::issue_certificate(&options.certificates[0], "issued.test").unwrap();
        let result = exchange(options, "issued.test");
        assert!(result.is_ok(), "issuer {algorithm:?}: {result:?}");
    }
}

#[test]
fn blocked_network_write_does_not_hold_tls_state() {
    struct Gated {
        socket: TcpStream,
        gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }
    impl Write for Gated {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some((enter, release)) = self.gate.take() {
                enter.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            self.socket.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let options = options();
    let server = advanced_server_config(&options).unwrap();
    let client = advanced_client_config(&options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (entered, wait_entered) = mpsc::channel();
    let (release, wait_release) = mpsc::channel();
    let (received, wait_received) = mpsc::channel();
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let writer = Gated {
            socket: socket.try_clone().unwrap(),
            gate: None,
        };
        let (mut read, mut write) = accept_advanced_tls_over(socket, writer, server).unwrap();
        write.inner_mut().gate = Some((entered, wait_release));
        let writer = thread::spawn(move || write.write_all(b"pong").unwrap());
        let mut request = [0; 4];
        read.read_exact(&mut request).unwrap();
        received.send(request).unwrap();
        writer.join().unwrap();
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut read, mut write) =
        connect_advanced_tls_over(socket.try_clone().unwrap(), socket, client, "localhost")
            .unwrap();
    wait_entered.recv_timeout(Duration::from_secs(3)).unwrap();
    write.write_all(b"ping").unwrap();
    let request = wait_received.recv_timeout(Duration::from_secs(1));
    release.send(()).unwrap();
    assert_eq!(request.unwrap(), *b"ping");
    let mut response = [0; 4];
    read.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");
    task.join().unwrap();
}

#[test]
fn partial_ciphertext_retry_and_direct_preserve_the_stream() {
    struct Choppy {
        inner: TcpStream,
        enabled: u8,
    }
    impl Write for Choppy {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self.enabled {
                1 => {
                    self.enabled = 2;
                    self.inner.write(&bytes[..2.min(bytes.len())])
                }
                2 => {
                    self.enabled = 0;
                    Err(io::ErrorKind::WouldBlock.into())
                }
                _ => self.inner.write(bytes),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let options = options();
    let server = advanced_server_config(&options).unwrap();
    let client = advanced_client_config(&options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (mut read, mut write) = accept_advanced_tls_over(
            socket.try_clone().unwrap(),
            Choppy {
                inner: socket,
                enabled: 0,
            },
            server,
        )
        .unwrap();
        write.inner_mut().enabled = 1;
        assert_eq!(
            write.write(b"padded").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(write.start_direct().is_err());
        assert_eq!(
            write.write(b"changed").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        write.write_all(b"padded").unwrap();
        write.start_direct().unwrap();
        write.write_all(b"direct").unwrap();
        let mut request = [0; 4];
        read.read_exact(&mut request).unwrap();
        read.start_direct().unwrap();
        read.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"raw!");
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (mut read, mut write) =
        connect_advanced_tls_over(socket.try_clone().unwrap(), socket, client, "localhost")
            .unwrap();
    let mut response = [0; 6];
    read.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"padded");
    read.start_direct().unwrap();
    read.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"direct");
    write.write_all(b"ping").unwrap();
    write.start_direct().unwrap();
    write.write_all(b"raw!").unwrap();
    task.join().unwrap();
}

fn capture_hello(fingerprint: &str) -> Vec<u8> {
    let config = advanced_client_config(&AdvancedTlsOptions {
        fingerprint: fingerprint.into(),
        ..Default::default()
    })
    .unwrap();
    let mut stream =
        SslStream::new(config.ssl("example.com").unwrap(), MemoryIo::default()).unwrap();
    assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
    stream.get_ref().output.clone()
}

#[test]
fn browser_hello_fields_match_pinned_xray_captures() {
    use serde_json::{json, Value};
    let profiles: Value = serde_json::from_str(include_str!("fingerprints.json")).unwrap();
    let word = |bytes: &[u8]| u16::from_be_bytes([bytes[0], bytes[1]]);
    let grease = |id: u16| {
        if id & 0x0f0f == 0x0a0a && id >> 8 == id & 255 {
            0x0a0a
        } else {
            id
        }
    };
    for name in profiles
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .filter(|name| *name != "unsafe")
    {
        eprintln!("TLS profile {name}");
        let bytes = capture_hello(name);
        assert_eq!(word(&bytes[1..]), 0x0301, "{name} record version");
        let bytes = &bytes[5..];
        let mut p = 38;
        assert_eq!(
            bytes[p] as u64,
            profiles[name]["session_id_length"].as_u64().unwrap(),
            "{name} session ID"
        );
        p += 1 + bytes[p] as usize;
        let length = word(&bytes[p..]) as usize;
        p += 2;
        let ciphers: Vec<_> = bytes[p..p + length]
            .chunks_exact(2)
            .map(|b| grease(word(b)))
            .collect();
        p += length;
        assert_eq!(json!(ciphers), profiles[name]["ciphers"], "{name} ciphers");
        p += 1 + bytes[p] as usize;
        p += 2;
        let mut extensions = Vec::new();
        let mut padding_length = 0;
        while p < bytes.len() {
            let id = grease(word(&bytes[p..]));
            let length = word(&bytes[p + 2..]) as usize;
            let data = &bytes[p + 4..p + 4 + length];
            p += 4 + length;
            let mut extension =
                json!({"id":id,"data":data.iter().map(|v|format!("{v:02x}")).collect::<String>()});
            match id {
                0 => extension = json!({"id":id}),
                10 | 13 | 43 => {
                    let start = if id == 43 { 1 } else { 2 };
                    let values: Vec<_> = data[start..]
                        .chunks_exact(2)
                        .map(|b| grease(word(b)))
                        .collect();
                    extension = json!({"id":id,"values":values});
                }
                21 => {
                    padding_length = length + 4;
                    extension = json!({"id":id,"padding":true});
                }
                51 => {
                    let mut q = 2;
                    let mut shares = Vec::new();
                    while q < data.len() {
                        let length = word(&data[q + 2..]);
                        shares.push((grease(word(&data[q..])), length));
                        q += 4 + length as usize;
                    }
                    extension = json!({"id":id,"shares":shares});
                }
                65037 => {
                    let enc_length = word(&data[6..]) as usize;
                    let payload_length = word(&data[8 + enc_length..]) as usize;
                    assert_eq!(word(&data[1..]), 1);
                    assert!([1, 3].contains(&word(&data[3..])));
                    assert_eq!(enc_length, 32);
                    let reference = profiles[name]["extensions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|extension| extension["id"] == id)
                        .unwrap();
                    if reference["payload_length"] == 239 {
                        assert_eq!(payload_length, 239);
                    } else if fingerprint::resolve(name).unwrap().unwrap().shuffle {
                        assert!([144, 176, 208, 240].contains(&payload_length));
                    } else {
                        assert_eq!(
                            payload_length as u64,
                            reference["payload_length"].as_u64().unwrap()
                        );
                    }
                    extension = profiles[name]["extensions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|e| e["id"] == id)
                        .unwrap()
                        .clone();
                }
                _ => {}
            }
            extensions.push(extension);
        }
        let mut expected = profiles[name]["extensions"].as_array().unwrap().clone();
        if !(256..512).contains(&(bytes.len() - padding_length)) {
            expected.retain(|extension| extension["id"] != 21);
        }
        if fingerprint::resolve(name).unwrap().unwrap().shuffle {
            extensions.sort_by_key(|e| (e["id"].as_u64(), e.to_string()));
            expected.sort_by_key(|e| (e["id"].as_u64(), e.to_string()));
        }
        assert_eq!(extensions, expected, "{name} extensions");
        let mut options = options();
        options.fingerprint = name.into();
        assert!(exchange(options, "localhost").is_ok(), "{name} handshake");
    }
}

mod interop {
    include!("interop.rs");
}

#[test]
fn read_only_tls_flushes_key_update_after_writer_remap_and_partial_write() {
    struct Choppy {
        socket: TcpStream,
        step: u8,
    }
    impl Write for Choppy {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self.step {
                1 => {
                    self.step = 2;
                    self.socket.write(&bytes[..bytes.len().min(2)])
                }
                2 => {
                    self.step = 0;
                    Err(io::ErrorKind::WouldBlock.into())
                }
                _ => self.socket.write(bytes),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let options = options();
    let server = advanced_server_config(&options).unwrap();
    let client = advanced_client_config(&options).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (mut read, mut write) =
            accept_advanced_tls_over(socket.try_clone().unwrap(), socket, server).unwrap();
        write
            .core
            .lock()
            .unwrap()
            .ssl_mut()
            .request_key_update(true)
            .unwrap();
        write.flush().unwrap();
        let mut record = Vec::new();
        read_record(read.inner_mut(), &mut record).unwrap();
        {
            let mut core = read.core.lock().unwrap();
            core.get_mut().input.extend(record);
            assert_eq!(
                core.ssl_read(&mut [0; 1]).unwrap_err().code(),
                ErrorCode::WANT_READ
            );
        }
        write.write_all(b"pong").unwrap();
    });
    let socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (read, write) =
        connect_advanced_tls_over(socket.try_clone().unwrap(), socket, client, "localhost")
            .unwrap();
    let mut read = read.map_inner(Box::new);
    let write = write.map_inner(|socket| Choppy { socket, step: 1 });
    drop(write);
    let mut response = [0; 4];
    assert_eq!(
        read.read(&mut response).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(read.needs_write());
    read.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"pong");
    assert!(!read.needs_write());
    task.join().unwrap();
}
