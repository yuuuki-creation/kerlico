//! 每种出站在运行期创建的载体套接字都带编译期注入的 `routing_mark`。
//!
//! 每个 Mihomo 样例改指向本机监听端口，在 `with_compile_dialer` 中编译、在其外启动并发起一次连接，
//! 再按该样例独有的标记取回工厂记录。运行期才去读编译上下文的出站会取到默认选项，在这里失败。
//! 需要 Linux 与 CAP_NET_ADMIN（设置 SO_MARK）。

#![cfg(target_os = "linux")]

#[path = "cases/mihomo.rs"]
mod cases;

use kerlico_config::OutboundFactory;
use kerlico_core::{
    ConnectContext, Destination, DialerOptions, Error, ServiceContext,
    dialer::probe::{self, SocketKind},
};
use serde_json::Value;
use std::time::Duration;

fn factory(kind: &str) -> Box<dyn OutboundFactory> {
    match kind {
        "direct" => Box::new(kerlico_net::DirectFactory),
        "shadowsocks" => Box::new(kerlico_shadowsocks::ShadowsocksFactory),
        "ss2022" => Box::new(kerlico_ss2022::Ss2022Factory),
        "shadowtls" => Box::new(kerlico_shadowtls::ShadowTlsFactory),
        "shadowsocksr" => Box::new(kerlico_shadowsocksr::ShadowsocksRFactory),
        "snell" => Box::new(kerlico_snell::SnellFactory),
        "vmess" => Box::new(kerlico_vmess::VmessFactory),
        "vless" => Box::new(kerlico_vless::VlessFactory),
        "trojan" => Box::new(kerlico_trojan::TrojanFactory),
        "anytls" => Box::new(kerlico_anytls::AnyTlsFactory),
        "http" => Box::new(kerlico_http::HttpFactory),
        "socks" => Box::new(kerlico_socks::SocksFactory),
        "hysteria1" => Box::new(kerlico_hysteria1::Hysteria1Factory),
        "hysteria2" => Box::new(kerlico_hysteria2::Hysteria2Factory),
        "tuic" => Box::new(kerlico_tuic::TuicFactory),
        "shadowquic" => Box::new(kerlico_shadowquic::ShadowQuicFactory),
        "wireguard" => Box::new(kerlico_wireguard::WireGuardFactory),
        "ssh" => Box::new(kerlico_ssh::SshFactory),
        "mieru" => Box::new(kerlico_mieru::MieruFactory),
        "sudoku" => Box::new(kerlico_sudoku::SudokuFactory),
        "trusttunnel" => Box::new(kerlico_trusttunnel::TrustTunnelFactory),
        "gost-relay" => Box::new(kerlico_gost_relay::GostRelayFactory),
        "tailscale" => Box::new(kerlico_tailscale::TailscaleFactory),
        "openvpn" => Box::new(kerlico_openvpn::OpenVpnFactory),
        "easytier" => Box::new(kerlico_easytier::EasyTierFactory),
        "zerotier" => Box::new(kerlico_zerotier::ZeroTierFactory),
        other => panic!("样例类型 {other} 未登记工厂"),
    }
}

/// 把样例中的服务端地址改成本机 `port`；端口跳跃去掉，使 UDP 只发往一个端口。
fn point_at(value: &mut Value, port: u16) {
    match value {
        Value::Object(map) => {
            map.remove("ports");
            for (key, item) in map.iter_mut() {
                match (key.as_str(), &item) {
                    ("host" | "server", Value::String(_)) => *item = "127.0.0.1".into(),
                    ("port", Value::Number(_)) => *item = port.into(),
                    ("control_url", _) => *item = format!("http://127.0.0.1:{port}").into(),
                    ("peers", Value::Array(_)) => {
                        *item = vec![format!("tcp://127.0.0.1:{port}")].into()
                    }
                    _ => point_at(item, port),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| point_at(item, port)),
        _ => {}
    }
}

/// 同一端口号上的 TCP 监听与 UDP 套接字，接受连接后丢弃，不回应任何数据。
async fn sink() -> (u16, tokio::task::JoinHandle<()>) {
    loop {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let Ok(tcp) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await else {
            continue;
        };
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    accepted = tcp.accept() => if let Ok((stream, _)) = accepted { held.push(stream) },
                    _ = udp.recv_from(&mut buffer) => {}
                }
            }
        });
        return (port, task);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_outbound_socket_carries_the_compile_time_mark() {
    let (port, _sink) = sink().await;
    let target = Destination::new("example.com", 80).unwrap();
    // 直连后端只接受调度器选定的字面地址。
    let literal = Destination::new("127.0.0.1", port).unwrap();
    let mut failures = Vec::new();
    for (index, (name, _, kind, mut options)) in cases::cases().into_iter().enumerate() {
        if matches!(kind, "reject" | "dns") {
            continue;
        }
        let mark = 0x4b_0000 + index as u32;
        point_at(&mut options, port);
        let dialer = DialerOptions {
            routing_mark: Some(mark),
            ..DialerOptions::default()
        };
        let factory = factory(kind);
        let compiled = kerlico_core::with_compile_dialer(dialer, || factory.compile(&options));
        if kind == "easytier" {
            match compiled {
                Err(Error::Config(_)) => continue,
                _ => {
                    failures.push(format!("{name}: 上游库无法施加标记，编译应拒绝"));
                    continue;
                }
            }
        }
        let plan = match compiled {
            Ok(plan) => plan,
            Err(error) => {
                failures.push(format!("{name}: 编译失败 {error}"));
                continue;
            }
        };
        // 服务上下文须活到连接结束，丢弃会取消出站的后台任务。
        let host = ServiceContext::for_test();
        let started = tokio::time::timeout(Duration::from_secs(3), plan.start(host.clone())).await;
        let mut outcome = String::new();
        match started {
            Ok(Ok(outbound)) => {
                let context = ConnectContext::new(Duration::from_millis(1500));
                let connected = tokio::time::timeout(
                    Duration::from_secs(2),
                    outbound
                        .connect_tcp(if kind == "direct" { &literal } else { &target }, &context),
                )
                .await;
                if let Ok(Err(error)) = connected {
                    outcome = format!("连接失败 {error}");
                }
                let _ = outbound.shutdown().await;
            }
            Ok(Err(error)) => outcome = format!("启动失败 {error}"),
            Err(_) => outcome = "启动超时".into(),
        }
        let records = probe::take(mark);
        if records.is_empty() {
            failures.push(format!(
                "{name} ({kind}): 没有带标记 {mark:#x} 的套接字；{outcome}"
            ));
        } else {
            let kinds: Vec<SocketKind> = records.iter().map(|r| r.kind).collect();
            eprintln!("{name}: {kinds:?}");
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
