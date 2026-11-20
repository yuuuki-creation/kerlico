//! Standalone IP peer. Traffic uses the configured OS TUN and host routing.

use std::{io, net::SocketAddr, process::ExitCode};

use kerlico_wg::{bind_tun, parse_endpoint, parse_key, Hub, IpNet};
use serde_json::{Map, Value};

fn invalid(field: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid WireGuard {field}"),
    )
}

fn text<'a>(config: &'a Map<String, Value>, field: &str) -> io::Result<&'a str> {
    config
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(field))
}

fn number(config: &Map<String, Value>, field: &str, default: u16) -> io::Result<u16> {
    match config.get(field) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|number| number.try_into().ok())
            .ok_or_else(|| invalid(field)),
    }
}

fn run(path: std::ffi::OsString) -> io::Result<()> {
    let config: Value =
        serde_json::from_slice(&std::fs::read(path)?).map_err(|_| invalid("document"))?;
    let config = config.as_object().ok_or_else(|| invalid("document"))?;
    if config.keys().any(|key| match key.as_str() {
        "listen" | "privateKey" | "tun" | "mtu" | "peers" => false,
        "egress" => !cfg!(target_os = "linux"),
        _ => true,
    }) {
        return Err(invalid("document field"));
    }
    let bind = parse_endpoint(text(config, "listen")?).map_err(|_| invalid("listen"))?;
    if bind.port() == 0 {
        return Err(invalid("listen port"));
    }
    let mtu = number(config, "mtu", 1420)?;
    let mut hub = Hub::with_mtu(parse_key(text(config, "privateKey")?)?, usize::from(mtu))?;
    let peers = config
        .get("peers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("peers"))?;
    for peer in peers {
        let peer = peer.as_object().ok_or_else(|| invalid("peer"))?;
        if peer.keys().any(|key| {
            !matches!(
                key.as_str(),
                "allowedIPs" | "publicKey" | "presharedKey" | "endpoint" | "persistentKeepalive"
            )
        }) {
            return Err(invalid("peer field"));
        }
        let allowed = peer
            .get("allowedIPs")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("allowedIPs"))?
            .iter()
            .map(|ip| {
                ip.as_str()
                    .and_then(|ip| ip.parse::<IpNet>().ok())
                    .ok_or_else(|| invalid("CIDR"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let key = parse_key(text(peer, "publicKey")?)?;
        let psk = peer
            .get("presharedKey")
            .map(|_| text(peer, "presharedKey").and_then(parse_key))
            .transpose()?;
        let endpoint: Option<SocketAddr> = peer
            .get("endpoint")
            .map(|_| {
                text(peer, "endpoint")
                    .and_then(|addr| parse_endpoint(addr).map_err(|_| invalid("endpoint")))
            })
            .transpose()?;
        if endpoint.is_some_and(|addr| addr.port() == 0 || addr.is_ipv4() != bind.is_ipv4()) {
            return Err(invalid("endpoint"));
        }
        hub.add(
            key,
            psk,
            number(peer, "persistentKeepalive", 0)?,
            allowed,
            endpoint,
        )?;
    }
    let name = text(config, "tun")?;
    #[cfg(target_os = "linux")]
    if let Some(egress) = config.get("egress") {
        let egress = egress.as_object().ok_or_else(|| invalid("egress"))?;
        if egress
            .keys()
            .any(|key| !matches!(key.as_str(), "device" | "class"))
        {
            return Err(invalid("egress field"));
        }
        return kerlico_wg::bind_tun_with_egress(
            bind,
            hub,
            name,
            mtu,
            text(egress, "device")?,
            text(egress, "class")?,
        );
    }
    bind_tun(bind, hub, name, mtu)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        #[cfg(target_os = "linux")]
        [name] if is_interface_argument(name) => background(name),
        #[cfg(windows)]
        [name] if is_interface_argument(name) => name
            .to_str()
            .ok_or_else(|| invalid("interface name"))
            .and_then(kerlico_wg::run_interface),
        [path] if !path.to_string_lossy().starts_with('-') => run(path.clone()),
        #[cfg(any(target_os = "linux", windows))]
        [flag, name] if flag == "-f" || flag == "--foreground" => name
            .to_str()
            .ok_or_else(|| invalid("interface name"))
            .and_then(kerlico_wg::run_interface),
        #[cfg(target_os = "linux")]
        [flag, name] if flag == "--daemon-child" => {
            use std::io::Write;
            name.to_str()
                .ok_or_else(|| invalid("interface name"))
                .and_then(|name| {
                    kerlico_wg::run_interface_ready(name, || {
                        let mut stdout = io::stdout().lock();
                        stdout.write_all(&[1])?;
                        stdout.flush()
                    })
                })
        }
        _ => {
            eprintln!(
                "用法：kerlico-wg <配置文件>，或在 Linux / Windows 上使用 kerlico-wg [-f|--foreground] <接口名>"
            );
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("WireGuard: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
fn is_interface_argument(name: &std::ffi::OsStr) -> bool {
    let path = std::path::Path::new(name);
    !name.to_string_lossy().starts_with('-')
        && path.components().count() == 1
        && !path.is_file()
        && path
            .extension()
            .is_none_or(|extension| !extension.eq_ignore_ascii_case("json"))
        && !path.exists()
}

#[cfg(target_os = "linux")]
fn background(name: &std::ffi::OsStr) -> io::Result<()> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([std::ffi::OsStr::new("--daemon-child"), name])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    // The post-fork hook makes one async-signal-safe system call.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().expect("ready pipe");
    let (ready, wait) = std::sync::mpsc::sync_channel(1);
    let observe = std::thread::Builder::new().spawn(move || {
        let mut byte = [0];
        let _ = ready.send(stdout.read_exact(&mut byte).map(|()| byte[0]));
    });
    let result = observe
        .and_then(|_| {
            wait.recv_timeout(Duration::from_secs(8))
                .map_err(|_| io::ErrorKind::TimedOut.into())
        })
        .and_then(|result| result)
        .and_then(|byte| {
            if byte == 1 {
                Ok(())
            } else {
                Err(invalid("daemon readiness"))
            }
        });
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
