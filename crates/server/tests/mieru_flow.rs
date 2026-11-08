#![cfg(feature = "mieru")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use kerlico_mieru::{connect, Account, Target};

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
