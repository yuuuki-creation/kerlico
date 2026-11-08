#![cfg(feature = "mieru")]

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use kerlico_mieru::{associate, connect, connect_udp, Account, Target};

#[test]
fn mieru_node_reaches_a_tcp_echo() {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        let (mut tcp, _) = echo.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut buf = [0u8; 16];
        let n = tcp.read(&mut buf).unwrap();
        tcp.write_all(&buf[..n]).unwrap();
    });

    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let text = format!(
        r#"{{
            "inbounds": [{{
                "tag": "m",
                "protocol": "mieru",
                "listen": "127.0.0.1",
                "port": {port},
                "outbound": "native-v4",
                "settings": {{
                    "users": [{{
                        "email": "a@b.c",
                        "username": "alice",
                        "password": "secret"
                    }}]
                }}
            }}]
        }}"#
    );
    let mut loaded = kerlico_server::Server::from_config(&text).unwrap();
    thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
    thread::sleep(Duration::from_millis(200));

    let conn = connect(
        format!("127.0.0.1:{port}").parse().unwrap(),
        &Account {
            username: "alice".into(),
            password: "secret".into(),
        },
        &Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        },
    )
    .unwrap();
    conn.write_user(b"ping").unwrap();
    let mut buf = [0u8; 4];
    let n = conn.read_user(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");
}

#[test]
fn udp_transport_reaches_a_tcp_echo() {
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        let (mut tcp, _) = echo.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(8))).ok();
        let mut buf = [0u8; 16];
        let n = tcp.read(&mut buf).unwrap();
        tcp.write_all(&buf[..n]).unwrap();
    });
    let port = free_port();
    let text = node_config(port, r#""transport": "UDP", "mtu": 1400,"#);
    let mut loaded = kerlico_server::Server::from_config(&text).unwrap();
    thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
    thread::sleep(Duration::from_millis(200));
    let conn = connect_udp(
        format!("127.0.0.1:{port}").parse().unwrap(),
        &Account {
            username: "alice".into(),
            password: "secret".into(),
        },
        &Target {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        },
    )
    .unwrap();
    conn.write_user(b"ping").unwrap();
    let mut buf = [0u8; 4];
    let n = conn.read_user(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping");
}

#[test]
fn udp_associate_reaches_a_udp_echo() {
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 16];
        let (n, peer) = echo.recv_from(&mut buf).unwrap();
        echo.send_to(&buf[..n], peer).unwrap();
    });
    let port = free_port();
    let text = node_config(port, "");
    let mut loaded = kerlico_server::Server::from_config(&text).unwrap();
    thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
    thread::sleep(Duration::from_millis(200));
    let assoc = associate(
        format!("127.0.0.1:{port}").parse().unwrap(),
        &Account {
            username: "alice".into(),
            password: "secret".into(),
        },
        false,
    )
    .unwrap();
    assoc
        .send_to(&echo_addr.ip().to_string(), echo_addr.port(), b"dns")
        .unwrap();
    let (host, reply_port, payload) = assoc.recv_from().unwrap();
    assert_eq!(host, echo_addr.ip().to_string());
    assert_eq!(reply_port, echo_addr.port());
    assert_eq!(payload, b"dns");
}

#[test]
fn port_range_accepts_every_port_in_the_span() {
    let start = free_span(2);
    let text = node_config(
        start,
        &format!(r#""portRange": "{start}-{}","#, start + 1),
    );
    let mut loaded = kerlico_server::Server::from_config(&text).unwrap();
    thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
    thread::sleep(Duration::from_millis(200));
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    let sink_addr = sink.local_addr().unwrap();
    thread::spawn(move || {
        let _ = sink.accept();
    });
    let conn = connect(
        format!("127.0.0.1:{}", start + 1).parse().unwrap(),
        &Account {
            username: "alice".into(),
            password: "secret".into(),
        },
        &Target {
            host: sink_addr.ip().to_string(),
            port: sink_addr.port(),
        },
    );
    assert!(conn.is_ok());
}

#[test]
fn listen_rejects_a_port_range_that_excludes_the_node() {
    let port = free_port();
    let text = node_config(port, &format!(r#""portRange": "{}-{}","#, port + 1, port + 2));
    assert!(kerlico_server::Server::from_config(&text).is_err());
}

#[test]
fn listen_rejects_a_low_port_and_a_bad_mtu() {
    let low = node_config(80, "");
    assert!(kerlico_server::Server::from_config(&low).is_err());
    let port = free_port();
    let mtu = node_config(port, r#""mtu": 100,"#);
    assert!(kerlico_server::Server::from_config(&mtu).is_err());
    let transport = node_config(port, r#""transport": "QUIC","#);
    assert!(kerlico_server::Server::from_config(&transport).is_err());
}

fn free_port() -> u16 {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    port
}

fn free_span(width: u16) -> u16 {
    loop {
        let start = free_port();
        if start < 1025 || u32::from(start) + u32::from(width) > 65535 {
            continue;
        }
        let mut held = Vec::new();
        let mut open = true;
        for port in start..start + width {
            match TcpListener::bind(("127.0.0.1", port)) {
                Ok(listener) => held.push(listener),
                Err(_) => {
                    open = false;
                    break;
                }
            }
        }
        if open {
            return start;
        }
    }
}

#[test]
#[ignore = "runs the official mieru client; needs Go beside target/gotool or on PATH"]
fn official_go_client_uses_this_server() {
    let go = go_bin();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target")
        .join("mieru-official");
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = echo.local_addr().unwrap();
    thread::spawn(move || loop {
        let Ok((mut tcp, _)) = echo.accept() else {
            break;
        };
        thread::spawn(move || {
            tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
            let mut buf = [0u8; 16];
            if let Ok(n) = tcp.read(&mut buf) {
                if n > 0 {
                    let _ = tcp.write_all(&buf[..n]);
                }
            }
        });
    });
    let udp_echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp_echo.local_addr().unwrap();
    thread::spawn(move || loop {
        let mut buf = [0u8; 64];
        if let Ok((n, peer)) = udp_echo.recv_from(&mut buf) {
            let _ = udp_echo.send_to(&buf[..n], peer);
        }
    });

    let tcp_port = free_port();
    let udp_port = free_port();
    start_server(node_config(tcp_port, ""));
    start_server(node_config(udp_port, r#""transport": "UDP","#));
    thread::sleep(Duration::from_millis(300));

    let echo_text = echo_addr.to_string();
    let udp_text = udp_addr.to_string();
    run_probe(&go, &root, "tcp", tcp_port, &echo_text);
    run_probe(&go, &root, "nowait", tcp_port, &echo_text);
    run_probe(&go, &root, "low32", tcp_port, &echo_text);
    run_probe(&go, &root, "low40", tcp_port, &echo_text);
    run_probe(&go, &root, "low48", tcp_port, &echo_text);
    run_probe(&go, &root, "low56", tcp_port, &echo_text);
    run_probe(&go, &root, "udp", udp_port, &echo_text);
    run_probe(&go, &root, "assoc", tcp_port, &udp_text);
}

fn start_server(text: String) {
    let mut loaded = kerlico_server::Server::from_config(&text).unwrap();
    thread::spawn(move || {
        let _ = loaded.server.run(loaded.dns);
    });
}

fn go_bin() -> std::path::PathBuf {
    let bundled = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("target")
        .join("gotool")
        .join("go")
        .join("bin")
        .join("go.exe");
    if bundled.exists() {
        return bundled;
    }
    std::path::PathBuf::from("go")
}

fn run_probe(go: &std::path::Path, root: &std::path::Path, mode: &str, port: u16, echo: &str) {
    let output = std::process::Command::new(go)
        .args([
            "run",
            "./test/cmd/kerlicoprobe",
            "-mode",
            mode,
            "-port",
            &port.to_string(),
            "-echo",
            echo,
        ])
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("go run {mode}: {error}"));
    assert!(
        output.status.success(),
        "{mode} failed\nstdout {}\nstderr {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn node_config(port: u16, extra: &str) -> String {
    format!(
        r#"{{
            "inbounds": [{{
                "tag": "m",
                "protocol": "mieru",
                "listen": "127.0.0.1",
                "port": {port},
                "outbound": "native-v4",
                "settings": {{
                    {extra}
                    "users": [{{
                        "email": "alice",
                        "username": "alice",
                        "password": "secret"
                    }}]
                }}
            }}]
        }}"#
    )
}
