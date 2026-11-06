//! 出站套接字只能经 `kerlico_core::DialerOptions` 创建，否则 `routing_mark`、出口网卡与
//! `detour` 不生效，TUN 防回环随之失效。本测试扫描源码中直接创建操作系统套接字的调用。

use std::{
    fs,
    path::{Path, PathBuf},
};

const FORBIDDEN: &[&str] = &[
    "TcpStream::connect(",
    "UdpSocket::bind(",
    "TcpSocket::new_v4(",
    "TcpSocket::new_v6(",
    "socket2::Socket::new(",
    "Socket::new(domain",
];

/// 不经工厂的已知调用：入站监听、本机回环与用户态协议栈。每项写明原因。
const ALLOWED: &[(&str, &str, &str)] = &[
    ("crates/core-api/src/dialer.rs", "", "套接字工厂本身"),
    ("crates/engine/src/lib.rs", "", "入站与端口转发监听套接字"),
    (
        "crates/dns/src/listener.rs",
        "UdpSocket::bind(",
        "dns.listen 入站 DNS 服务监听",
    ),
    (
        "crates/net/src/ntp.rs",
        "UdpSocket::bind(",
        "NTP 校时请求，由调用方传入绑定地址",
    ),
    (
        "crates/protocol-tun/src/lib.rs",
        "socket2::Socket::new(",
        "TUN auto_redirect 的 TCP 重定向监听",
    ),
    (
        "crates/protocol-socks/src/inbound.rs",
        "UdpSocket::bind(",
        "SOCKS5 入站 UDP ASSOCIATE 监听",
    ),
    (
        "crates/net/src/transparent.rs",
        "socket2::Socket::new(",
        "tproxy 入站回包套接字，以透明方式绑定在原始目标地址",
    ),
    (
        "crates/protocol-shadowtls/src/server.rs",
        "TcpStream::connect(",
        "ShadowTLS 服务端到握手目标的拨号，入站侧没有出站拨号配置",
    ),
    (
        "crates/net/src/fallback.rs",
        "TcpStream::connect(",
        "入站回落到配置的后端，入站侧没有出站拨号配置",
    ),
    (
        "crates/protocol-wireguard/src/client.rs",
        "TcpStream::connect(",
        "用户态 smoltcp 协议栈内的 TCP",
    ),
    (
        "crates/protocol-wireguard/src/ip.rs",
        "TcpStream::connect(",
        "用户态 smoltcp 协议栈内的 TCP",
    ),
    (
        "third_party/xray-transport/src/lib.rs",
        "TcpStream::connect(",
        "传输库未注入 ResolvedTcpConnector 时的默认路径；kerlico 的 VLESS/Trojan/VMess 载体总是注入",
    ),
    (
        "third_party/xray-transport/src/lib.rs",
        "TcpSocket::new_v4(",
        "传输库未注入 ResolvedTcpConnector 时的默认路径；kerlico 的 VLESS/Trojan/VMess 载体总是注入",
    ),
    (
        "third_party/xray-transport/src/lib.rs",
        "TcpSocket::new_v6(",
        "传输库未注入 ResolvedTcpConnector 时的默认路径；kerlico 的 VLESS/Trojan/VMess 载体总是注入",
    ),
    (
        "third_party/xray-transport/src/stream/xhttp/h3.rs",
        "UdpSocket::bind(",
        "未提供 udp_socket_factory 时的默认路径；kerlico 的 VLESS 载体总是提供",
    ),
    (
        "third_party/xray-transport/src/dns.rs",
        "UdpSocket::bind(",
        "传输库自带 DNS 客户端，kerlico 出站不调用",
    ),
    (
        "third_party/xray-transport/src/hysteria/client.rs",
        "UdpSocket::bind(",
        "传输库自带 Hysteria 客户端，kerlico 出站不调用",
    ),
];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !matches!(
                name.as_str(),
                "tests" | "examples" | "benches" | "vendor" | "target"
            ) {
                rust_files(&path, out);
            }
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && name != "tests.rs" {
            out.push(path);
        }
    }
}

/// 去掉 `#[cfg(test)]` 标注的条目（按花括号配对），只留生产代码。
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut kept = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if lines[index].trim_start().starts_with("#[cfg(test)]") {
            let mut depth = 0i32;
            let mut opened = false;
            index += 1;
            while index < lines.len() {
                for ch in lines[index].chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                let ends_item = !opened && lines[index].trim_end().ends_with(';');
                index += 1;
                if (opened && depth <= 0) || ends_item {
                    break;
                }
            }
            continue;
        }
        kept.push((index + 1, lines[index]));
        index += 1;
    }
    kept
}

#[test]
fn outbound_sockets_go_through_dialer_options() {
    let root = workspace();
    let mut files = Vec::new();
    for dir in ["crates", "apps", "third_party/xray-transport/src"] {
        rust_files(&root.join(dir), &mut files);
    }
    let mut violations = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&file).unwrap();
        for (line_no, line) in production_lines(&text) {
            let code = line.split("//").next().unwrap_or_default();
            for token in FORBIDDEN {
                if !code.contains(token) {
                    continue;
                }
                let allowed = ALLOWED.iter().any(|(path, allowed_token, _)| {
                    *path == relative && (allowed_token.is_empty() || allowed_token == token)
                });
                if !allowed {
                    violations.push(format!("{relative}:{line_no}: {}", line.trim()));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "以下位置直接创建了操作系统套接字。出站请改用 kerlico_core::DialerOptions 的 \
         connect / connect_addr / tcp_socket / udp_socket / udp_socket_for / udp_peer，\
         在编译阶段用 current_compile_dialer() 取得选项；入站监听或回环套接字在本测试 ALLOWED \
         中登记原因：\n{}",
        violations.join("\n")
    );
}
