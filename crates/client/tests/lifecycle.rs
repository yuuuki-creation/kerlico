use kerlico_client::{LocalEntry, Proxy};
use kerlico_shared::{Association, Stream, Upstream};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The entry's lifecycle does not depend on the protocol behind it.
struct Refusing;
impl Upstream for Refusing {
    fn open_stream(&self, _host: &str, _port: u16) -> io::Result<Box<dyn Stream>> {
        Err(io::ErrorKind::ConnectionRefused.into())
    }
    fn associate(&self) -> io::Result<Box<dyn Association>> {
        Err(io::ErrorKind::ConnectionRefused.into())
    }
    fn close(&self) {}
}

fn upstream() -> Arc<dyn Upstream> {
    Arc::new(Refusing)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn repeated_close_releases_pending_local_handshakes_and_listeners() {
    #[cfg(target_os = "linux")]
    let before = (
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        std::fs::read_dir("/proc/self/task").unwrap().count(),
    );
    for _ in 0..20 {
        let socks = free_port();
        let http = loop {
            let port = free_port();
            if port != socks {
                break port;
            }
        };
        let entry = LocalEntry::new(socks, http, false, false).unwrap();
        let proxy = Proxy::start(upstream(), &entry).unwrap();
        let mut pending = TcpStream::connect(("127.0.0.1", socks)).unwrap();
        pending.write_all(&[5]).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let start = Instant::now();
        proxy.close();
        proxy.close();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "关闭不能等待完整握手期限"
        );
        drop(pending);
        drop(proxy);
        let restarted = Proxy::start(upstream(), &entry).unwrap();
        restarted.close();
        drop(restarted);
    }
    #[cfg(target_os = "linux")]
    {
        let after = (
            std::fs::read_dir("/proc/self/fd").unwrap().count(),
            std::fs::read_dir("/proc/self/task").unwrap().count(),
        );
        assert!(
            after.0 <= before.0,
            "文件描述符未回收：{before:?} -> {after:?}"
        );
        assert!(after.1 <= before.1, "线程未回收：{before:?} -> {after:?}");
    }
}

#[test]
fn lan_listeners_bind_existing_private_interfaces_and_accept_socks() {
    let has_lan = if_addrs::get_if_addrs()
        .unwrap()
        .iter()
        .any(|interface| match interface.ip() {
            std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
            std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
        });
    let socks = free_port();
    let http = loop {
        let p = free_port();
        if p != socks {
            break p;
        }
    };
    let entry = LocalEntry::new(socks, http, true, true).unwrap();
    let result = Proxy::start(upstream(), &entry);
    if !has_lan {
        assert!(result.is_err());
        return;
    }
    let proxy = result.unwrap();
    assert!(!proxy.socks5_addrs().is_empty() && !proxy.http_addrs().is_empty());
    for address in proxy.socks5_addrs() {
        assert!(!address.ip().is_unspecified() && !address.ip().is_loopback());
        let mut stream = TcpStream::connect_timeout(address, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[5, 1, 0]).unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, 0]);
    }
    proxy.close();
}
