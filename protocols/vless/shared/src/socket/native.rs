use super::{
    invalid, option, unsupported, CustomSockopt, SocketKind, SocketOptions, SocketRole, TProxyMode,
};
use socket2::{Protocol, Socket};
use std::io;
use std::net::SocketAddr;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn mptcp() -> io::Result<Protocol> {
    Ok(Protocol::from(libc::IPPROTO_MPTCP))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn mptcp() -> io::Result<Protocol> {
    Err(platform_unsupported("tcpMptcp"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn check_mptcp(socket: &Socket) -> io::Result<()> {
    if socket.protocol()? != Some(mptcp()?) {
        return Err(invalid("sockopt.tcpMptcp requires an MPTCP socket"));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn check_mptcp(_: &Socket) -> io::Result<()> {
    mptcp().map(|_| ())
}

pub(super) fn configure(
    socket: &Socket,
    settings: &SocketOptions,
    kind: SocketKind,
    role: SocketRole,
    addr: SocketAddr,
) -> io::Result<()> {
    if settings.mark != 0 {
        option("mark", mark(socket, settings.mark))?;
    }
    if !settings.interface.is_empty() {
        if settings.interface.as_bytes().contains(&0) {
            return Err(invalid("sockopt.interface contains NUL"));
        }
        option(
            "interface",
            interface(socket, &settings.interface, kind, role, addr),
        )?;
    }
    if kind == SocketKind::Tcp {
        if let Some(backlog) = settings.tcp_fast_open {
            option("tcpFastOpen", fast_open(socket, role, backlog))?;
        }
        option("TCP keepalive", keepalive(socket, settings, role))?;
        tcp_tuning(socket, settings)?;
    }
    let system = match std::env::consts::OS {
        "macos" => "darwin",
        system => system,
    };
    let network = kind.network(addr.is_ipv6());
    for (index, custom) in settings.custom_sockopt.iter().enumerate() {
        if (custom.system.is_empty() || custom.system == system)
            && network.starts_with(&custom.network)
        {
            option(
                &format!("customSockopt[{index}]"),
                custom_option(socket, custom),
            )?;
        }
    }
    if settings.tproxy != TProxyMode::Off {
        option("tproxy", transparent(socket, addr.is_ipv6()))?;
    }
    Ok(())
}

fn custom_option(socket: &Socket, custom: &CustomSockopt) -> io::Result<()> {
    let number = |value: &str, name: &str| {
        value
            .parse::<i32>()
            .map_err(|_| invalid(format!("{name} must be a decimal int32")))
    };
    let opt = number(&custom.opt, "opt")?;
    let level = if custom.level.is_empty() {
        6
    } else {
        number(&custom.level, "level")?
    };
    match custom.value_type.as_str() {
        "int" => set_int(socket, level, opt, number(&custom.value, "value")?),
        "str" if cfg!(unix) => set_bytes(socket, level, opt, custom.value.as_bytes()),
        "str" => Err(platform_unsupported("customSockopt string values")),
        value_type => Err(invalid(format!(
            "unknown customSockopt type {value_type:?}"
        ))),
    }
}

fn platform_unsupported(name: &str) -> io::Error {
    unsupported(format!("{name} is unsupported on {}", std::env::consts::OS))
}

fn set_int(socket: &Socket, level: i32, name: i32, value: i32) -> io::Result<()> {
    set_bytes(socket, level, name, &value.to_ne_bytes())
}

#[cfg(unix)]
fn set_bytes(socket: &Socket, level: i32, name: i32, value: &[u8]) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let len = libc::socklen_t::try_from(value.len())
        .map_err(|_| invalid("socket option value is too long"))?;
    // The socket owns the descriptor and `value` is readable for `len` bytes.
    let result =
        unsafe { libc::setsockopt(socket.as_raw_fd(), level, name, value.as_ptr().cast(), len) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn set_bytes(socket: &Socket, level: i32, name: i32, value: &[u8]) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, WSAGetLastError};

    let len = i32::try_from(value.len()).map_err(|_| invalid("socket option value is too long"))?;
    // The socket owns the handle and `value` is readable for `len` bytes.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            name,
            value.as_ptr(),
            len,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}

#[cfg(not(any(unix, windows)))]
fn set_bytes(_: &Socket, _: i32, _: i32, _: &[u8]) -> io::Result<()> {
    Err(platform_unsupported("customSockopt"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mark(socket: &Socket, mark: i32) -> io::Result<()> {
    socket.set_mark(mark as u32)
}

#[cfg(target_os = "freebsd")]
fn mark(socket: &Socket, mark: i32) -> io::Result<()> {
    set_int(socket, libc::SOL_SOCKET, libc::SO_USER_COOKIE, mark)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
fn mark(_: &Socket, _: i32) -> io::Result<()> {
    Err(platform_unsupported("socket mark"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn interface(
    socket: &Socket,
    name: &str,
    _: SocketKind,
    _: SocketRole,
    _: SocketAddr,
) -> io::Result<()> {
    socket.bind_device(Some(name.as_bytes()))
}

#[cfg(target_os = "macos")]
fn interface(
    socket: &Socket,
    name: &str,
    _: SocketKind,
    _: SocketRole,
    addr: SocketAddr,
) -> io::Result<()> {
    use std::ffi::CString;
    use std::num::NonZeroU32;

    let name = CString::new(name).map_err(|error| invalid(error.to_string()))?;
    // `name` is a NUL-terminated interface name for the duration of the call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    let index = NonZeroU32::new(index).ok_or_else(io::Error::last_os_error)?;
    if addr.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(windows)]
fn interface(
    socket: &Socket,
    name: &str,
    kind: SocketKind,
    role: SocketRole,
    addr: SocketAddr,
) -> io::Result<()> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, ConvertInterfaceNameToLuidW,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_IF, IPV6_UNICAST_IF, IP_MULTICAST_IF,
        IP_UNICAST_IF,
    };

    if role == SocketRole::Listener {
        return Err(platform_unsupported(
            "binding a VLESS listener to an interface",
        ));
    }
    let name: Vec<_> = name.encode_utf16().chain([0]).collect();
    let mut luid = NET_LUID_LH::default();
    // `name` is terminated and both output arguments point to live values.
    let index = unsafe {
        let mut status = ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid);
        if status != 0 {
            status = ConvertInterfaceNameToLuidW(name.as_ptr(), &mut luid);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut index = 0;
        let status = ConvertInterfaceLuidToIndex(&luid, &mut index);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        index as i32
    };
    let (level, unicast, multicast, index) = if addr.is_ipv4() {
        (IPPROTO_IP, IP_UNICAST_IF, IP_MULTICAST_IF, index.to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, IPV6_MULTICAST_IF, index)
    };
    set_int(socket, level, unicast, index)?;
    if kind == SocketKind::Udp && addr.ip().is_multicast() {
        set_int(socket, level, multicast, index)?;
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn interface(_: &Socket, _: &str, _: SocketKind, _: SocketRole, _: SocketAddr) -> io::Result<()> {
    Err(platform_unsupported("interface binding"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn fast_open(socket: &Socket, role: SocketRole, backlog: i32) -> io::Result<()> {
    let (name, value) = match role {
        SocketRole::Listener => (libc::TCP_FASTOPEN, backlog),
        SocketRole::Dialer => (libc::TCP_FASTOPEN_CONNECT, i32::from(backlog > 0)),
    };
    set_int(socket, libc::IPPROTO_TCP, name, value)
}

#[cfg(target_os = "macos")]
fn fast_open(socket: &Socket, role: SocketRole, backlog: i32) -> io::Result<()> {
    let flag = match (role, backlog > 0) {
        (_, false) => 0,
        (SocketRole::Listener, true) => 1,
        (SocketRole::Dialer, true) => 2,
    };
    set_int(socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, flag)
}

#[cfg(target_os = "freebsd")]
fn fast_open(socket: &Socket, role: SocketRole, backlog: i32) -> io::Result<()> {
    let value = if role == SocketRole::Listener {
        backlog
    } else {
        i32::from(backlog > 0)
    };
    set_int(socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, value)
}

#[cfg(windows)]
fn fast_open(socket: &Socket, _: SocketRole, backlog: i32) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{IPPROTO_TCP, TCP_FASTOPEN};

    set_int(socket, IPPROTO_TCP, TCP_FASTOPEN, i32::from(backlog > 0))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
fn fast_open(_: &Socket, _: SocketRole, _: i32) -> io::Result<()> {
    Err(platform_unsupported("TCP Fast Open"))
}

fn keepalive(socket: &Socket, settings: &SocketOptions, role: SocketRole) -> io::Result<()> {
    let idle = settings.tcp_keep_alive_idle;
    let interval = settings.tcp_keep_alive_interval;
    if idle < 0 || interval < 0 {
        return socket.set_keepalive(false);
    }
    if idle == 0 && interval == 0 && role == SocketRole::Listener {
        return Ok(());
    }
    // Xray's system dialer uses 45 seconds when either value is unspecified.
    let default = if role == SocketRole::Dialer { 45 } else { 0 };
    let result = keepalive_timers(
        socket,
        if idle > 0 { idle } else { default },
        if interval > 0 { interval } else { default },
    );
    match result {
        Err(error) if idle == 0 && interval == 0 && error.kind() == io::ErrorKind::Unsupported => {
            socket.set_keepalive(true)
        }
        result => result,
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
fn keepalive_timers(socket: &Socket, idle: i32, interval: i32) -> io::Result<()> {
    use socket2::TcpKeepalive;
    use std::time::Duration;

    let mut keepalive = TcpKeepalive::new();
    if idle > 0 {
        keepalive = keepalive.with_time(Duration::from_secs(idle as u64));
    }
    if interval > 0 {
        keepalive = keepalive.with_interval(Duration::from_secs(interval as u64));
    }
    socket.set_tcp_keepalive(&keepalive)
}

#[cfg(windows)]
fn keepalive_timers(socket: &Socket, idle: i32, interval: i32) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{IPPROTO_TCP, TCP_KEEPIDLE, TCP_KEEPINTVL};

    if idle > 0 {
        set_int(socket, IPPROTO_TCP, TCP_KEEPIDLE, idle)?;
    }
    if interval > 0 {
        set_int(socket, IPPROTO_TCP, TCP_KEEPINTVL, interval)?;
    }
    socket.set_keepalive(true)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
fn keepalive_timers(_: &Socket, _: i32, _: i32) -> io::Result<()> {
    Err(platform_unsupported("TCP keepalive timers"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn tcp_tuning(socket: &Socket, settings: &SocketOptions) -> io::Result<()> {
    if !settings.tcp_congestion.is_empty() {
        option(
            "tcpCongestion",
            set_bytes(
                socket,
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                settings.tcp_congestion.as_bytes(),
            ),
        )?;
    }
    if settings.tcp_window_clamp > 0 {
        option(
            "tcpWindowClamp",
            set_int(
                socket,
                libc::IPPROTO_TCP,
                libc::TCP_WINDOW_CLAMP,
                settings.tcp_window_clamp,
            ),
        )?;
    }
    if settings.tcp_max_seg > 0 {
        option("tcpMaxSeg", socket.set_tcp_mss(settings.tcp_max_seg as u32))?;
    }
    if settings.tcp_user_timeout > 0 {
        option(
            "tcpUserTimeout",
            set_int(
                socket,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                settings.tcp_user_timeout,
            ),
        )?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn tcp_tuning(_: &Socket, settings: &SocketOptions) -> io::Result<()> {
    for (enabled, name) in [
        (!settings.tcp_congestion.is_empty(), "tcpCongestion"),
        (settings.tcp_window_clamp > 0, "tcpWindowClamp"),
        (settings.tcp_max_seg > 0, "tcpMaxSeg"),
        (settings.tcp_user_timeout > 0, "tcpUserTimeout"),
    ] {
        if enabled {
            return Err(platform_unsupported(name));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn transparent(socket: &Socket, ipv6: bool) -> io::Result<()> {
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::IPPROTO_IP, libc::IP_TRANSPARENT)
    };
    set_int(socket, level, name, 1)
}

#[cfg(target_os = "freebsd")]
fn transparent(socket: &Socket, ipv6: bool) -> io::Result<()> {
    let (level, name) = if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BINDANY)
    } else {
        (libc::IPPROTO_IP, libc::IP_BINDANY)
    };
    set_int(socket, level, name, 1)
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
fn transparent(_: &Socket, _: bool) -> io::Result<()> {
    Err(platform_unsupported("transparent socket binding"))
}
