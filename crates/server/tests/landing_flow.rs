#![cfg(all(feature = "mieru", feature = "landing-mieru"))]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_outbound::{DialTarget, Exit, Outbound};
use kerlico_shared::{
    Destination, Handoff, InboundStream, NodeTag, PlaneFault, Settings, Transport, UserEmail,
};

struct Mem {
    pending: Mutex<VecDeque<u8>>,
    wrote: Arc<Mutex<Vec<u8>>>,
}

impl InboundStream for Mem {
    fn read_from_user(&self, buf: &mut [u8]) -> Result<usize, PlaneFault> {
        let mut pending = self.pending.lock().expect("pending");
        if pending.is_empty() {
            return Err(PlaneFault::Closed);
        }
        let n = pending.len().min(buf.len());
        for slot in &mut buf[..n] {
            *slot = pending.pop_front().expect("byte");
        }
        Ok(n)
    }

    fn write_to_user(&self, buf: &[u8]) -> Result<usize, PlaneFault> {
        self.wrote.lock().expect("wrote").extend_from_slice(buf);
        Ok(buf.len())
    }
}

#[test]
fn landing_mieru_reaches_the_echo() {
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
    let dns = loaded.dns.clone();
    thread::spawn(move || {
        let _ = loaded.server.run(dns);
    });
    thread::sleep(Duration::from_millis(200));

    let outbound = Outbound::new();
    let mut settings = Settings::default();
    settings.insert_text("username", "alice");
    settings.insert_text("password", "secret");
    outbound.install_landing(landing_mieru::land, "127.0.0.1".to_string(), port, settings);
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let handoff = Handoff::new(
        NodeTag::parse("user").unwrap(),
        UserEmail::parse("a@b.c").unwrap(),
        Destination::new(echo_addr.ip().to_string(), echo_addr.port(), Transport::Tcp).unwrap(),
        Box::new(Mem {
            pending: Mutex::new(VecDeque::from(b"ping".to_vec())),
            wrote: wrote.clone(),
        }),
    );
    let stats = kerlico_server::Stats::new();
    outbound
        .dispatch(
            handoff,
            Exit::Landing,
            DialTarget {
                host: echo_addr.ip().to_string(),
                port: echo_addr.port(),
                transport: Transport::Tcp,
                addresses: Vec::new(),
            },
            &stats,
        )
        .unwrap();
    assert_eq!(wrote.lock().expect("wrote").as_slice(), b"ping");
}
