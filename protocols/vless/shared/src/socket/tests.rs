use super::*;
use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Default)]
struct Resolver {
    configured: Vec<IpAddr>,
    system: Vec<IpAddr>,
    srv: Vec<SrvRecord>,
    txt: Vec<String>,
    lookups: RefCell<Vec<(String, u16, Option<AddressFamily>, ResolutionSource)>>,
}

impl TransportResolver for Resolver {
    fn lookup_ip(
        &self,
        host: &str,
        port: u16,
        family: Option<AddressFamily>,
        source: ResolutionSource,
    ) -> io::Result<Vec<SocketAddr>> {
        self.lookups
            .borrow_mut()
            .push((host.into(), port, family, source));
        let records = match source {
            ResolutionSource::Configured => &self.configured,
            ResolutionSource::System => &self.system,
        };
        Ok(records
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect())
    }

    fn lookup_srv(&self, _: &str) -> io::Result<Vec<SrvRecord>> {
        Ok(self.srv.clone())
    }

    fn lookup_txt(&self, _: &str) -> io::Result<Vec<String>> {
        Ok(self.txt.clone())
    }
}

fn settings(json: &str) -> SocketOptions {
    SocketOptions::parse(Some(json)).unwrap()
}

#[test]
fn rejects_invalid_settings_and_parses_transport_metadata() {
    assert!(SocketOptions::parse(Some(r#"{"tcpFastOpen":"true"}"#)).is_err());
    assert!(SocketOptions::parse(Some(
        r#"{"tcpKeepAliveIdle":2147483647,"tcpKeepAliveInterval":-9}"#
    ))
    .is_err());
    assert!(SocketOptions::parse(Some(r#"{"domainStrategy":"UseAddress"}"#)).is_err());
    assert!(SocketOptions::parse(Some(r#"{"tcpKeepAliveIntervl":13}"#)).is_err());
    let options = settings(
        r#"{"acceptProxyProtocol":true,"penetrate":true,"trustedXForwardedFor":["X-CDN"],"tproxy":"REDIRECT"}"#,
    );
    assert!(options.accept_proxy_protocol && options.penetrate);
    assert_eq!(options.tproxy, TProxyMode::Redirect);
    let peer = "127.0.0.1:32123".parse().unwrap();
    assert_eq!(
        options.trusted_forwarded_for.peer(peer, |name| match name {
            "x-cdn" => Some("yes"),
            "x-forwarded-for" => Some("2001:db8::8"),
            _ => None,
        }),
        "[2001:db8::8]:0".parse().unwrap()
    );
}

#[test]
fn domain_strategy_uses_preferred_family_and_only_use_falls_back_to_system() {
    let resolver = Resolver {
        configured: vec!["2001:db8::2".parse().unwrap()],
        system: vec!["192.0.2.1".parse().unwrap()],
        ..Default::default()
    };
    let options = settings(r#"{"domainStrategy":"ForceIPv4v6"}"#);
    let plan = options
        .plan("carrier.test", 81, SocketKind::Udp, None, &resolver)
        .unwrap()
        .direct()
        .unwrap();
    assert_eq!(plan.addresses(), &["[2001:db8::2]:81".parse().unwrap()]);
    let lookups = resolver.lookups.take();
    assert_eq!(
        lookups
            .iter()
            .map(|query| (query.2, query.3))
            .collect::<Vec<_>>(),
        [
            (Some(AddressFamily::V4), ResolutionSource::Configured),
            (Some(AddressFamily::V6), ResolutionSource::Configured),
        ]
    );

    let options = settings(r#"{"domainStrategy":"UseIPv4"}"#);
    let plan = options
        .plan(
            "carrier.test",
            82,
            SocketKind::Tcp,
            Some(AddressFamily::V4),
            &resolver,
        )
        .unwrap()
        .direct()
        .unwrap();
    assert_eq!(plan.addresses(), &["192.0.2.1:82".parse().unwrap()]);
    let lookups = resolver.lookups.take();
    assert_eq!(lookups[1].3, ResolutionSource::System);

    let options = settings(r#"{"domainStrategy":"ForceIPv4"}"#);
    assert!(options
        .plan("carrier.test", 83, SocketKind::Tcp, None, &resolver)
        .is_err());
    assert_eq!(resolver.lookups.take().len(), 1);
    let plan = options
        .plan("::ffff:192.0.2.9", 84, SocketKind::Tcp, None, &resolver)
        .unwrap()
        .direct()
        .unwrap();
    assert_eq!(plan.addresses(), &["192.0.2.9:84".parse().unwrap()]);
    assert!(resolver.lookups.borrow().is_empty());
}

#[test]
fn srv_txt_and_dialer_proxy_plan_the_rewritten_endpoint() {
    let resolver = Resolver {
        srv: vec![
            SrvRecord {
                target: "wrong.test".into(),
                port: 711,
                priority: 10,
                weight: 10,
            },
            SrvRecord {
                target: "chosen.test.".into(),
                port: 712,
                priority: 1,
                weight: 1,
            },
        ],
        txt: vec!["invalid".into(), "[2001:db8::6]:143".into()],
        system: vec!["192.0.2.9".parse().unwrap()],
        ..Default::default()
    };
    let name = "_vless._tcp.carrier.test";
    for (strategy, host, port) in [
        ("SrvPortOnly", name, 712),
        ("SrvAddressOnly", "chosen.test.", 443),
        ("SrvPortAndAddress", "chosen.test.", 712),
        ("TxtPortOnly", name, 143),
        ("TxtAddressOnly", "2001:db8::6", 443),
        ("TxtPortAndAddress", "2001:db8::6", 143),
    ] {
        let options = settings(&format!(
            r#"{{"addressPortStrategy":"{strategy}","dialerProxy":"NativeV6"}}"#
        ));
        let plan = options
            .plan(name, 443, SocketKind::Tcp, None, &resolver)
            .unwrap();
        assert_eq!(
            plan.clone().direct().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        let DialPlan::Proxy(plan) = plan else {
            panic!("carrier proxy was ignored")
        };
        assert_eq!(
            (plan.selector.as_str(), plan.host.as_str(), plan.port),
            ("NativeV6", host, port)
        );
    }
    assert!(resolver.lookups.borrow().is_empty());

    let options = settings(r#"{"addressPortStrategy":"SrvPortAndAddress"}"#);
    let plan = options
        .plan(name, 443, SocketKind::Tcp, None, &resolver)
        .unwrap()
        .direct()
        .unwrap();
    assert_eq!(plan.addresses(), &["192.0.2.9:712".parse().unwrap()]);
    assert_eq!(resolver.lookups.take()[0].0, "chosen.test.");
}

#[test]
fn happy_eyeballs_orders_addresses_in_family_blocks() {
    let resolver = Resolver {
        configured: [
            "192.0.2.1",
            "2001:db8::1",
            "192.0.2.2",
            "192.0.2.3",
            "2001:db8::2",
            "2001:db8::3",
        ]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect(),
        ..Default::default()
    };
    let options = settings(
        r#"{"domainStrategy":"ForceIP","happyEyeballs":{"prioritizeIPv6":true,"tryDelayMs":1,"interleave":2}}"#,
    );
    let plan = options
        .plan("carrier.test", 443, SocketKind::Tcp, None, &resolver)
        .unwrap()
        .direct()
        .unwrap();
    assert_eq!(
        plan.addresses()
            .iter()
            .map(|address| address.ip().to_string())
            .collect::<Vec<_>>(),
        [
            "2001:db8::1",
            "2001:db8::2",
            "192.0.2.1",
            "192.0.2.2",
            "2001:db8::3",
            "192.0.2.3",
        ]
    );
    let plan = options
        .plan("carrier.test", 443, SocketKind::Udp, None, &resolver)
        .unwrap()
        .direct()
        .unwrap();
    assert!(!plan.is_racing());
    assert_eq!(plan.addresses().len(), 1);
}

#[test]
fn happy_eyeballs_connects_the_winner_and_cancels_a_pending_attempt() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let resolver = Resolver {
        configured: vec![
            "::1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "192.0.2.100".parse().unwrap(),
        ],
        ..Default::default()
    };
    let options = settings(
        r#"{"domainStrategy":"UseIP","happyEyeballs":{"prioritizeIPv6":true,"tryDelayMs":5,"maxConcurrentTry":2}}"#,
    );
    let plan = options
        .plan("carrier.test", port, SocketKind::Tcp, None, &resolver)?
        .direct()?;
    struct Pending<'a>(&'a AtomicBool);
    impl Drop for Pending<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let cancelled = AtomicBool::new(false);
    let started = Cell::new(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut client = runtime.block_on(async {
        let options = &options;
        let cancelled = &cancelled;
        tokio::time::timeout(
            Duration::from_secs(2),
            plan.dial(|peer| {
                started.set(started.get() + 1);
                async move {
                    if peer.is_ipv6() {
                        let _pending = Pending(cancelled);
                        return std::future::pending().await;
                    }
                    assert!(peer.ip().is_loopback());
                    let socket = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
                    socket.set_nonblocking(true)?;
                    let stream = tokio::net::TcpSocket::from_std_stream(socket.into())
                        .connect(peer)
                        .await?;
                    stream.into_std()
                }
            }),
        )
        .await?
    })?;
    assert!(cancelled.load(Ordering::Relaxed));
    assert_eq!(started.get(), 2);
    assert_eq!(client.peer_addr()?, listener.local_addr()?);
    client.set_nonblocking(false)?;
    client.write_all(b"winner")?;
    let (mut server, _) = listener.accept()?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut received = [0; 6];
    server.read_exact(&mut received)?;
    assert_eq!(&received, b"winner");
    Ok(())
}

#[test]
fn happy_eyeballs_starts_the_next_address_when_an_attempt_fails() -> io::Result<()> {
    let resolver = Resolver {
        configured: vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()],
        ..Default::default()
    };
    let options = settings(
        r#"{"domainStrategy":"UseIP","happyEyeballs":{"prioritizeIPv6":true,"tryDelayMs":30000}}"#,
    );
    let plan = options
        .plan("carrier.test", 443, SocketKind::Tcp, None, &resolver)?
        .direct()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let winner = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(2),
            plan.dial(|address| {
                std::future::ready(if address.is_ipv6() {
                    Err(io::ErrorKind::ConnectionRefused.into())
                } else {
                    Ok(address)
                })
            }),
        )
        .await?
    })?;
    assert_eq!(winner, "127.0.0.1:443".parse().unwrap());
    Ok(())
}

#[cfg(any(target_os = "linux", windows))]
mod native {
    use super::*;

    #[cfg(target_os = "linux")]
    use libc::{IPPROTO_TCP, IPV6_V6ONLY, TCP_FASTOPEN, TCP_KEEPIDLE, TCP_KEEPINTVL};
    #[cfg(windows)]
    use windows_sys::Win32::Networking::WinSock::{
        IPPROTO_TCP, IPV6_V6ONLY, TCP_FASTOPEN, TCP_KEEPIDLE, TCP_KEEPINTVL,
    };

    #[test]
    fn reads_tcp_options_and_connects_configured_sockets() -> io::Result<()> {
        let options =
            settings(r#"{"tcpFastOpen":7,"tcpKeepAliveIdle":17,"tcpKeepAliveInterval":9}"#);
        let local = "127.0.0.1:0".parse().unwrap();
        let listener = options.open(SocketKind::Tcp, SocketRole::Listener, local)?;
        assert!(listener.keepalive()?);
        assert_eq!(get_int(&listener, IPPROTO_TCP, TCP_KEEPIDLE)?, 17);
        assert_eq!(get_int(&listener, IPPROTO_TCP, TCP_KEEPINTVL)?, 9);
        assert_eq!(
            get_int(&listener, IPPROTO_TCP, TCP_FASTOPEN)?,
            if cfg!(windows) { 1 } else { 7 }
        );
        listener.bind(&local.into())?;
        listener.listen(8)?;

        let peer = listener.local_addr()?.as_socket().unwrap();
        let client = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
        #[cfg(target_os = "linux")]
        let dial_fast_open = libc::TCP_FASTOPEN_CONNECT;
        #[cfg(windows)]
        let dial_fast_open = TCP_FASTOPEN;
        assert_eq!(get_int(&client, IPPROTO_TCP, dial_fast_open)?, 1);
        assert!(client.keepalive()?);
        client.connect_timeout(&peer.into(), Duration::from_secs(2))?;
        assert_eq!(get_int(&client, IPPROTO_TCP, TCP_KEEPIDLE)?, 17);
        assert_eq!(get_int(&client, IPPROTO_TCP, TCP_KEEPINTVL)?, 9);
        let (accepted, _) = listener.accept()?;
        assert!(accepted.keepalive()?);
        assert_eq!(get_int(&accepted, IPPROTO_TCP, TCP_KEEPIDLE)?, 17);
        assert_eq!(get_int(&accepted, IPPROTO_TCP, TCP_KEEPINTVL)?, 9);

        let disabled = settings(r#"{"tcpFastOpen":false,"tcpKeepAliveInterval":-1}"#).open(
            SocketKind::Tcp,
            SocketRole::Dialer,
            peer,
        )?;
        assert!(!disabled.keepalive()?);
        assert_eq!(get_int(&disabled, IPPROTO_TCP, dial_fast_open)?, 0);
        Ok(())
    }

    #[test]
    fn custom_option_order_filters_and_v6_listener_family() -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let (socket_level, receive_buffer, ip6_level) =
            (libc::SOL_SOCKET, libc::SO_RCVBUF, libc::IPPROTO_IPV6);
        #[cfg(windows)]
        let (socket_level, receive_buffer, ip6_level) = {
            use windows_sys::Win32::Networking::WinSock::{IPPROTO_IPV6, SOL_SOCKET, SO_RCVBUF};
            (SOL_SOCKET, SO_RCVBUF, IPPROTO_IPV6)
        };
        let options = settings(&format!(
            r#"{{"v6only":false,"customSockopt":[
            {{"system":"future-os","type":"ignored"}},
            {{"network":"tcp4","type":"ignored"}},
            {{"network":"udp","level":"{socket_level}","opt":"{receive_buffer}","type":"int","value":"4096"}},
            {{"network":"udp6","level":"{socket_level}","opt":"{receive_buffer}","type":"int","value":"16384"}},
            {{"network":"udp6","level":"{ip6_level}","opt":"{IPV6_V6ONLY}","type":"int","value":"0"}}
        ]}}"#
        ));
        let local = "[::]:0".parse().unwrap();
        let server = options.open(SocketKind::Udp, SocketRole::Listener, local)?;
        assert!(server.only_v6()?);
        assert_eq!(
            server.recv_buffer_size()?,
            if cfg!(windows) { 16384 } else { 32768 }
        );
        server.bind(&local.into())?;
        let port = server.local_addr()?.as_socket().unwrap().port();
        let other = UdpSocket::bind(("127.0.0.1", port))?;
        let server: UdpSocket = server.into();
        server.set_read_timeout(Some(Duration::from_secs(2)))?;
        let client = UdpSocket::bind("[::1]:0")?;
        client.send_to(b"v6", ("::1", port))?;
        let mut data = [0; 2];
        let (size, source) = server.recv_from(&mut data)?;
        assert_eq!(size, 2);
        assert_eq!(source, client.local_addr()?);
        assert_eq!(&data, b"v6");
        drop(other);

        let options = settings(r#"{"customSockopt":[{"opt":"invalid","type":"int","value":"1"}]}"#);
        let error = options
            .open(SocketKind::Udp, SocketRole::Listener, local)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("customSockopt[0]"));
        let options =
            settings(r#"{"customSockopt":[{"opt":"2147483647","type":"int","value":"1"}]}"#);
        let error = options
            .open(SocketKind::Tcp, SocketRole::Listener, local)
            .unwrap_err();
        assert!(error.to_string().contains("customSockopt[0]"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reads_tuning_and_device_binding() -> io::Result<()> {
        let options = settings(
            r#"{"interface":"lo","tcpCongestion":"reno","tcpWindowClamp":32768,"tcpMaxSeg":1200,"tcpUserTimeout":4500}"#,
        );
        let server = TcpListener::bind("127.0.0.1:0")?;
        let peer = server.local_addr()?;
        let socket = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
        assert_eq!(socket.device()?.as_deref(), Some(b"lo".as_slice()));
        assert!(socket.tcp_congestion()?.starts_with(b"reno"));
        assert_eq!(
            get_int(&socket, IPPROTO_TCP, libc::TCP_WINDOW_CLAMP)?,
            32768
        );
        assert_eq!(get_int(&socket, IPPROTO_TCP, libc::TCP_USER_TIMEOUT)?, 4500);
        socket.connect_timeout(&peer.into(), Duration::from_secs(2))?;
        assert!((500..=1200).contains(&socket.tcp_mss()?));
        let _ = server.accept()?;
        let options = settings(&format!(
            r#"{{"customSockopt":[{{"system":"linux","network":"tcp4","opt":"{}","type":"str","value":"reno"}}]}}"#,
            libc::TCP_CONGESTION
        ));
        let socket = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
        assert!(socket.tcp_congestion()?.starts_with(b"reno"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_transparent_mark_and_mptcp() -> io::Result<()> {
        for (mode, local, level, transparent) in [
            (
                "tproxy",
                "192.0.2.91:0",
                libc::IPPROTO_IP,
                libc::IP_TRANSPARENT,
            ),
            (
                "redirect",
                "[2001:db8::91]:0",
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
            ),
        ] {
            let options = settings(&format!(r#"{{"tproxy":"{mode}","mark":23}}"#));
            let local: SocketAddr = local.parse().unwrap();
            let socket = match options.open(SocketKind::Udp, SocketRole::Listener, local) {
                Ok(socket) => socket,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!("transparent/mark privilege unavailable: {error}");
                    continue;
                }
                Err(error) => return Err(error),
            };
            assert_eq!(get_int(&socket, level, transparent)?, 1);
            assert_eq!(socket.mark()?, 23);
            socket.bind(&local.into())?;
            assert_eq!(socket.local_addr()?.as_socket().unwrap().ip(), local.ip());
        }

        let options = settings(r#"{"tcpMptcp":true}"#);
        let local = "127.0.0.1:0".parse().unwrap();
        let socket = match options.open(SocketKind::Tcp, SocketRole::Listener, local) {
            Ok(socket) => socket,
            Err(error)
                if [libc::EPROTONOSUPPORT, libc::ENOPROTOOPT, libc::EPERM]
                    .contains(&error.raw_os_error().unwrap_or(0)) =>
            {
                eprintln!("MPTCP unavailable: {error}");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        assert_eq!(socket.protocol()?, Some(Protocol::MPTCP));
        socket.bind(&local.into())?;
        socket.listen(8)?;
        let peer = socket.local_addr()?.as_socket().unwrap();
        let client = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
        client.connect_timeout(&peer.into(), Duration::from_secs(2))?;
        assert_eq!(client.protocol()?, Some(Protocol::MPTCP));
        let _ = socket.accept()?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_applies_unicast_interface_and_reports_unavailable_options() -> io::Result<()> {
        use windows_sys::Win32::Networking::WinSock::{IPPROTO_IP, IP_UNICAST_IF};

        let server = TcpListener::bind("127.0.0.1:0")?;
        let peer = server.local_addr()?;
        let options = settings(r#"{"interface":"Loopback Pseudo-Interface 1"}"#);
        let socket = options.open(SocketKind::Tcp, SocketRole::Dialer, peer)?;
        assert_eq!(get_int(&socket, IPPROTO_IP, IP_UNICAST_IF)?, 1);
        socket.connect_timeout(&peer.into(), Duration::from_secs(2))?;
        let _ = server.accept()?;

        for config in [
            r#"{"mark":1}"#,
            r#"{"tproxy":"tproxy"}"#,
            r#"{"tcpMptcp":true}"#,
            r#"{"tcpCongestion":"reno"}"#,
        ] {
            let error = settings(config)
                .open(SocketKind::Tcp, SocketRole::Dialer, peer)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn get_int(socket: &Socket, level: i32, name: i32) -> io::Result<i32> {
        use std::os::fd::AsRawFd;

        let mut value = 0i32;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        // The output buffer is a single initialized integer.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&mut value as *mut i32).cast(),
                &mut len,
            )
        };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    fn get_int(socket: &Socket, level: i32, name: i32) -> io::Result<i32> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{getsockopt, WSAGetLastError};

        let mut value = 0i32;
        let mut len = std::mem::size_of_val(&value) as i32;
        // The output buffer is a single initialized integer.
        let result = unsafe {
            getsockopt(
                socket.as_raw_socket() as usize,
                level,
                name,
                (&mut value as *mut i32).cast(),
                &mut len,
            )
        };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        }
    }
}
