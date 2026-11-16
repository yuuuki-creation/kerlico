#![cfg(all(feature = "anytls", feature = "landing-anytls"))]

//! Kerlico's AnyTLS client against Kerlico's AnyTLS node, through the real server and outbound.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kerlico_shared::Settings;
use landing_anytls::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

fn certificate() -> (String, String) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (key.cert.pem(), key.key_pair.serialize_pem())
}

fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut tcp = tcp;
                let mut buf = vec![0u8; 65536];
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if tcp.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], peer);
        }
    });
    addr
}

/// Starts an AnyTLS node on a free port with `extra` node settings and one user.
fn node(extra: serde_json::Value, outbound: &str, landing: Option<serde_json::Value>) -> u16 {
    // Tests run in parallel; a probed port can be taken again before the node binds it.
    for _ in 0..5 {
        if let Some(port) = try_node(&extra, outbound, landing.clone()) {
            return port;
        }
    }
    panic!("no free port for the node");
}

fn try_node(extra: &serde_json::Value, outbound: &str, landing: Option<serde_json::Value>) -> Option<u16> {
    let port = free_port();
    let (cert, key) = certificate();
    let mut settings = json!({
        "certificate": cert,
        "private-key": key,
        "users": [{ "email": "a@b.c", "password": "secret" }]
    });
    for (key, value) in extra.as_object().unwrap() {
        if value.is_null() {
            settings.as_object_mut().unwrap().remove(key);
        } else {
            settings[key] = value.clone();
        }
    }
    let mut config = json!({
        "inbounds": [{
            "tag": "any",
            "protocol": "anytls",
            "listen": "127.0.0.1",
            "port": port,
            "outbound": outbound,
            "settings": settings
        }]
    });
    if let Some(landing) = landing {
        config["landing"] = landing;
    }
    let mut loaded = kerlico_server::Server::from_config(&config.to_string()).ok()?;
    thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    Some(port)
}

fn client(port: u16, extra: &[(&str, &str)]) -> Client {
    let mut settings = Settings::default();
    settings.insert_text("password", "secret");
    settings.insert_text("skip-cert-verify", "true");
    for (key, value) in extra {
        settings.insert_text(*key, *value);
    }
    Client::new("127.0.0.1", port, &settings).unwrap()
}

fn read_exact(stream: &landing_anytls::ClientStream, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut have = 0;
    while have < len {
        let n = stream.read_for(&mut out[have..], Duration::from_secs(20)).unwrap();
        assert!(n > 0, "EOF after {have} of {len}");
        have += n;
    }
    out
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[test]
fn shadowtls_fallback_relays_on_the_original_target_socket() {
    for version in [2, 3] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap();
        let port = node(json!({"certificate": null, "private-key": null, "shadow-tls": {
            "enable": true, "version": version, "password": "outer-secret",
            "users": [{"name":"outer-user","password":"outer-secret"}],
            "handshake": {"dest": target.to_string()}, "strict-mode": true
        }}), "native-v4", None);

        let hello = if version == 3 {
            // ClientHello with a 32-byte ShadowTLS session ID keyed by outer-secret.
            let mut hello = vec![0; 76];
            hello[..11].copy_from_slice(&[22, 3, 3, 0, 71, 1, 0, 0, 67, 3, 3]);
            hello[43] = 32;
            hello[72..].copy_from_slice(&[0x74, 0x47, 0xa5, 0x64]);
            assert!(kerlico_anytls::shadow::find_password(&hello, ["outer-secret"]).is_some());
            hello
        } else {
            vec![22, 3, 3, 0, 1, 0]
        };
        // A TLS 1.2 ServerHello with an empty session ID and no extensions.
        let mut response = [0u8; 49];
        response[..11].copy_from_slice(&[22, 3, 3, 0, 44, 2, 0, 0, 40, 3, 3]);
        let mut follow = Vec::new();
        if version == 2 {
            for index in [1, 2, 3] {
                follow.extend_from_slice(&[23, 3, 3, 0, 1, index]);
            }
        }
        follow.extend_from_slice(b"after fallback");
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.write_all(&hello).unwrap();
        let (mut origin, _) = listener.accept().unwrap();
        origin.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = vec![0; hello.len()];
        origin.read_exact(&mut buf).unwrap();
        assert_eq!(buf, hello);
        origin.write_all(&response).unwrap();
        let mut buf = [0; 49];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(buf, response);
        client.write_all(&follow).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut buf = Vec::new();
        origin.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, follow);
        origin.write_all(b"reply after half-close").unwrap();
        origin.shutdown(std::net::Shutdown::Write).unwrap();
        buf.clear();
        client.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"reply after half-close");
    }
}

#[test]
fn plaintext_listener_keeps_authentication_and_carries_real_traffic() {
    use kerlico_anytls::{tls::Established, Family, Scheme, SchemeCell, Session, Target};
    let echo = tcp_echo();
    let port = node(json!({"allow-insecure": true, "certificate": null, "private-key": null}), "native-v4", None);
    let open = |password| {
        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let session = Session::client(
            Established::plaintext(tcp),
            SchemeCell::new(Scheme::default_scheme()),
            "",
            &kerlico_anytls::password_hash(password),
        ).unwrap();
        let stream = session.open_stream().unwrap();
        let mut addr = Vec::new();
        Target::new(echo.ip().to_string(), echo.port()).encode(Family::Socks, &mut addr).unwrap();
        (session, stream, addr)
    };
    let (session, stream, addr) = open("secret");
    stream.write(&addr).unwrap();
    for data in [b"no TLS on this listener".as_slice(), &pattern(48 * 1024, 11)] {
        stream.write(data).unwrap();
        let mut out = vec![0u8; data.len()];
        let mut read = 0;
        while read < out.len() {
            let n = stream.read_for(&mut out[read..], Duration::from_secs(2)).unwrap();
            assert_ne!(n, 0);
            read += n;
        }
        assert_eq!(out, data);
    }
    session.close();
    let (session, stream, addr) = open("wrong");
    if stream.write(&addr).is_ok() && stream.write(b"must not echo").is_ok() {
        assert!(!matches!(stream.read_for(&mut [0; 32], Duration::from_secs(2)), Ok(n) if n > 0));
    }
    session.close();
}

#[test]
fn tcp_streams_and_large_transfers_reach_the_echo() {
    let echo = tcp_echo();
    let port = node(json!({}), "native-v4", None);
    let client = Arc::new(client(port, &[]));
    let workers: Vec<_> = (0..4u8)
        .map(|seed| {
            let client = Arc::clone(&client);
            thread::spawn(move || {
                let stream = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
                for round in 0..20 {
                    let block = pattern(32 * 1024 + round, seed);
                    stream.write_all(&block).unwrap();
                    assert_eq!(read_exact(&stream, block.len()), block);
                }
                let big = pattern(8 << 20, seed);
                let echoed = thread::scope(|scope| {
                    let reader = scope.spawn(|| read_exact(&stream, big.len()));
                    for chunk in big.chunks(100_000) {
                        stream.write_all(chunk).unwrap();
                    }
                    reader.join().unwrap()
                });
                assert_eq!(Sha256::digest(&echoed), Sha256::digest(&big));
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    // mihomo keeps one stream per session: four concurrent streams, four sessions, all idle now.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(client.session_count(), 4);
    assert_eq!(client.idle_count(), 4);
    client.close();
}

#[test]
fn several_streams_share_one_session_on_the_server() {
    use kerlico_anytls::{tls, Family, Scheme, SchemeCell, Session, Target};
    let echo = tcp_echo();
    let port = node(json!({}), "native-v4", None);
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let config = tls::client_config(&tls::ClientTls { insecure: true, ..Default::default() }).unwrap();
    let link = tls::connect(tcp, config, "localhost").unwrap();
    let session = Session::client(link, SchemeCell::new(Scheme::default_scheme()), "", &kerlico_anytls::password_hash("secret")).unwrap();
    let streams: Vec<_> = (0..6u8)
        .map(|seed| {
            let stream = session.open_stream().unwrap();
            let mut addr = Vec::new();
            Target::new(echo.ip().to_string(), echo.port()).encode(Family::Socks, &mut addr).unwrap();
            stream.write(&addr).unwrap();
            (seed, stream)
        })
        .collect();
    let workers: Vec<_> = streams
        .into_iter()
        .map(|(seed, stream)| {
            thread::spawn(move || {
                let block = pattern(1 << 20, seed);
                thread::scope(|scope| {
                    let reader = scope.spawn(|| {
                        let mut out = vec![0u8; block.len()];
                        let mut have = 0;
                        while have < out.len() {
                            let n = stream.read_for(&mut out[have..], Duration::from_secs(20)).unwrap();
                            assert!(n > 0);
                            have += n;
                        }
                        out
                    });
                    stream.write(&block).unwrap();
                    assert_eq!(reader.join().unwrap(), block);
                });
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(session.peer_version(), 2);
    session.close();
}

#[test]
fn udp_over_tcp_reaches_several_destinations() {
    let first = udp_echo();
    let second = udp_echo();
    let port = node(json!({}), "native-v4", None);
    let client = client(port, &[("udp", "true")]);
    let assoc = client.associate().unwrap();
    for (target, payload) in [(first, &b"one"[..]), (second, b"two"), (first, b""), (second, &[7u8; 1400][..])] {
        assoc.send_to(&target.ip().to_string(), target.port(), payload).unwrap();
        let (host, reply_port, reply) = assoc.recv_for(Duration::from_secs(5)).unwrap();
        assert_eq!((host, reply_port), (target.ip().to_string(), target.port()));
        assert_eq!(reply, payload);
    }
    assoc.close();
    let without = self::client(port, &[]);
    assert!(without.associate().is_err(), "udp is off by default, as in mihomo");
}

#[test]
fn server_padding_scheme_reaches_the_client() {
    let echo = tcp_echo();
    let scheme = "stop=4\n0=12-12\n1=150-150\n2=200-300\n3=10-20,c,40-40";
    let port = node(json!({ "padding-scheme": scheme }), "native-v4", None);
    let client = client(port, &[]);
    let before = client.padding_md5();
    let stream = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    stream.write_all(b"ping").unwrap();
    assert_eq!(read_exact(&stream, 4), b"ping");
    let expected = kerlico_anytls::Scheme::parse(scheme.as_bytes()).unwrap().md5().to_string();
    assert_ne!(before, expected);
    assert_eq!(client.padding_md5(), expected);
    // A second session, opened while the first is busy, uses the new scheme and still works.
    let other = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    other.write_all(b"pong").unwrap();
    assert_eq!(read_exact(&other, 4), b"pong");
}

#[test]
fn idle_sessions_are_reused_then_closed() {
    let echo = tcp_echo();
    let port = node(json!({}), "native-v4", None);
    let client = client(port, &[("idle-session-check-interval", "6"), ("idle-session-timeout", "6")]);
    let first = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    first.write_all(b"a").unwrap();
    read_exact(&first, 1);
    let local = first.session().local_addr().unwrap();
    first.close();
    let second = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    second.write_all(b"b").unwrap();
    assert_eq!(read_exact(&second, 1), b"b");
    assert_eq!(second.session().local_addr().unwrap(), local, "the idle session was reused");
    assert_eq!(client.session_count(), 1);
    second.close();
    let started = Instant::now();
    while client.session_count() > 0 && started.elapsed() < Duration::from_secs(20) {
        thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(client.session_count(), 0, "idle session closed after the timeout");
    assert!(started.elapsed() >= Duration::from_secs(5));
}

#[test]
fn wrong_password_reaches_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = node(json!({}), "native-v4", None);
    let mut settings = Settings::default();
    settings.insert_text("password", "wrong");
    settings.insert_text("skip-cert-verify", "true");
    let client = Client::new("127.0.0.1", port, &settings).unwrap();
    let stream = client.open_stream(&target.ip().to_string(), target.port()).unwrap();
    let _ = stream.write_all(b"hello");
    let mut buf = [0u8; 8];
    let result = stream.read_for(&mut buf, Duration::from_secs(5));
    assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
    thread::sleep(Duration::from_millis(300));
    assert!(listener.accept().is_err(), "the target saw no connection");
}

#[test]
fn landing_anytls_carries_a_node_to_another_node() {
    let echo = tcp_echo();
    let back = node(json!({}), "native-v4", None);
    let landing = json!({
        "protocol": "anytls",
        "address": "127.0.0.1",
        "port": back,
        "settings": { "password": "secret", "skip-cert-verify": true, "udp": true }
    });
    let front = node(json!({}), "landing", Some(landing));
    let client = client(front, &[("udp", "true")]);
    let stream = client.open_stream(&echo.ip().to_string(), echo.port()).unwrap();
    let block = pattern(256 * 1024, 3);
    stream.write_all(&block).unwrap();
    assert_eq!(read_exact(&stream, block.len()), block);
    let udp = udp_echo();
    let assoc = client.associate().unwrap();
    assoc.send_to(&udp.ip().to_string(), udp.port(), b"landed").unwrap();
    let (_, _, reply) = assoc.recv_for(Duration::from_secs(5)).unwrap();
    assert_eq!(reply, b"landed");
}
