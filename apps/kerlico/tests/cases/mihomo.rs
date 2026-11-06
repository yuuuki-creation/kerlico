//! 每个 Mihomo 代理类型一个节点样例，供 Mihomo 映射测试与拨号选项测试共用。

use serde_json::{Value, json};

pub const WG_PRIVATE: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
pub const WG_PUBLIC: &str = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
pub const REALITY_PUBLIC: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A";
pub const ZT_SECRET: &str = "26fdbcd524:0:ade8db815db56cb544adea61ef3023deacbf7194352d2d353477505b179a0248cbf8091d5f179fe4ea1db72bcea0162c4775f47088aa688f7fc7d70ccb7b74c6:a0ed2afd4e7a3bbaef3887e362496efa83b1c0e32596c09f427afecd6fa60a97bac7c41e0931fb6c64d498d60d0b2f9df24d39283db2eb734693864b7c4399ca";
pub const CA_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBijCCATGgAwIBAgIUfK//AstUDoZotLG2V3iaxpvcvWswCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPa2VybGljby10ZXN0LWNhMCAXDTI2MTEwNjEyMzMyNFoYDzIx\nMjYxMDEzMTIzMzI0WjAaMRgwFgYDVQQDDA9rZXJsaWNvLXRlc3QtY2EwWTATBgcq\nhkjOPQIBBggqhkjOPQMBBwNCAASkE2vrkT2kp3/HU2zfR5s3lhoTNJIUdDJbP1BB\nnh1HDheoGR/F8JNfblZ90x6oxMBv95EeNQAPwnx93xiMibLYo1MwUTAdBgNVHQ4E\nFgQUftkDU4pCoInfXfoGqb3cgUVc1ygwHwYDVR0jBBgwFoAUftkDU4pCoInfXfoG\nqb3cgUVc1ygwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiADVjOc\npza00GmihLOAysp/TvP+Mmz58yxKSS6E+HJ8jQIgHInV7rlulPvbAWK2llCXbUj0\nwCdAAdIof9V5Hi5xcuA=\n-----END CERTIFICATE-----\n";

/// 每个 Mihomo 类型一个取自官方文档示例形状的节点，以及期望映射出的 kerlico 类型与选项。
pub fn cases() -> Vec<(&'static str, String, &'static str, Value)> {
    let uuid = "11111111-2222-3333-4444-555555555555";
    vec![
        (
            "ss-obfs",
            "    type: ss\n    server: 203.0.113.10\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n    udp: true\n    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: bing.com\n".into(),
            "shadowsocks",
            json!({"server":"203.0.113.10","port":8388,"method":"aes-256-gcm","password":"pw","plugin":"obfs","plugin_opts":{"mode":"http","host":"bing.com"}}),
        ),
        (
            "ss-v2ray",
            "    type: ss\n    server: 203.0.113.11\n    port: 443\n    cipher: chacha20-ietf-poly1305\n    password: pw\n    plugin: v2ray-plugin\n    plugin-opts: {mode: websocket, tls: true, host: v.example.com, path: /ws, mux: false}\n".into(),
            "shadowsocks",
            json!({"server":"203.0.113.11","port":443,"method":"chacha20-ietf-poly1305","password":"pw","plugin":"v2ray-plugin","plugin_opts":{"mode":"websocket","tls":true,"mux":false,"host":"v.example.com","path":"/ws"}}),
        ),
        (
            "ss-2022",
            "    type: ss\n    server: 203.0.113.12\n    port: 8388\n    cipher: 2022-blake3-aes-128-gcm\n    password: MDEyMzQ1Njc4OWFiY2RlZg==\n    udp: true\n".into(),
            "ss2022",
            json!({"server":"203.0.113.12","port":8388,"method":"2022-blake3-aes-128-gcm","key":"MDEyMzQ1Njc4OWFiY2RlZg=="}),
        ),
        (
            "ss-shadowtls",
            "    type: ss\n    server: 203.0.113.13\n    port: 443\n    cipher: aes-128-gcm\n    password: pw\n    plugin: shadow-tls\n    plugin-opts:\n      host: cloud.tencent.com\n      password: stpw\n      version: 3\n".into(),
            "shadowtls",
            json!({"version":3,"password":"stpw","tls":{"server_name":"cloud.tencent.com"},"inner":{"type":"shadowsocks","options":{"server":"203.0.113.13","port":443,"method":"aes-128-gcm","password":"pw"}}}),
        ),
        (
            "ssr",
            "    type: ssr\n    server: 203.0.113.14\n    port: 443\n    cipher: chacha20-ietf\n    password: pw\n    obfs: tls1.2_ticket_auth\n    protocol: auth_aes128_md5\n    obfs-param: bing.com\n    protocol-param: \"\"\n    udp: true\n".into(),
            "shadowsocksr",
            json!({"server":{"host":"203.0.113.14","port":443},"method":"chacha20-ietf","password":"pw","protocol":"auth_aes128_md5","obfs":"tls1.2_ticket_auth","obfs_param":"bing.com","protocol_param":"","allow_insecure":true,"udp":true}),
        ),
        (
            "snell",
            "    type: snell\n    server: 203.0.113.15\n    port: 44046\n    psk: yourpsk\n    version: 3\n    obfs-opts:\n      mode: http\n      host: bing.com\n".into(),
            "snell",
            json!({"server":{"host":"203.0.113.15","port":44046},"psk":"yourpsk","version":3,"obfs_mode":"http","obfs_host":"bing.com"}),
        ),
        (
            "vmess-ws",
            format!("    type: vmess\n    server: v.example.com\n    port: 443\n    uuid: {uuid}\n    alterId: 0\n    cipher: auto\n    udp: true\n    tls: true\n    servername: v.example.com\n    network: ws\n    ws-opts:\n      path: /ws\n      headers:\n        Host: v.example.com\n"),
            "vmess",
            json!({"server":{"host":"v.example.com","port":443},"uuid":uuid,"security":"auto","global_padding":false,"tls":{"type":"tls","server_name":"v.example.com"},"transport":{"type":"ws","path":"/ws","host":"v.example.com"}}),
        ),
        (
            "vless-reality",
            format!("    type: vless\n    server: 203.0.113.16\n    port: 443\n    uuid: {uuid}\n    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n    servername: www.example.com\n    reality-opts:\n      public-key: {REALITY_PUBLIC}\n      short-id: 0123abcd\n    client-fingerprint: chrome\n"),
            "vless",
            json!({"server":{"host":"203.0.113.16","port":443},"uuid":uuid,"flow":"xtls-rprx-vision","security":{"type":"reality","server_name":"www.example.com","public_key":REALITY_PUBLIC,"short_id":"0123abcd","fingerprint":"chrome"}}),
        ),
        (
            "vless-ws",
            format!("    type: vless\n    server: vl.example.com\n    port: 443\n    uuid: {uuid}\n    tls: true\n    servername: vl.example.com\n    network: ws\n    ws-opts:\n      path: /vl\n      headers:\n        Host: vl.example.com\n"),
            "vless",
            json!({"server":{"host":"vl.example.com","port":443},"uuid":uuid,"security":{"type":"tls","server_name":"vl.example.com"},"transport":{"type":"ws","path":"/vl","host":"vl.example.com"}}),
        ),
        (
            "trojan-grpc",
            "    type: trojan\n    server: t.example.com\n    port: 443\n    password: pw\n    udp: true\n    sni: t.example.com\n    skip-cert-verify: false\n    network: grpc\n    grpc-opts:\n      grpc-service-name: grpc-svc\n".into(),
            "trojan",
            json!({"server":{"host":"t.example.com","port":443},"password":"pw","security":{"type":"tls","server_name":"t.example.com"},"transport":{"type":"grpc","service_name":"grpc-svc"}}),
        ),
        (
            "anytls",
            "    type: anytls\n    server: a.example.com\n    port: 443\n    password: pw\n    sni: a.example.com\n    idle-session-timeout: 30\n".into(),
            "anytls",
            json!({"server":{"host":"a.example.com","port":443},"password":"pw","tls":{"server_name":"a.example.com"},"idle_session_timeout_ms":30000}),
        ),
        (
            "http-tls",
            "    type: http\n    server: h.example.com\n    port: 443\n    username: u\n    password: p\n    tls: true\n    sni: h.example.com\n".into(),
            "http",
            json!({"server":{"host":"h.example.com","port":443},"auth":{"username":"u","password":"p"},"tls":{"server_name":"h.example.com"}}),
        ),
        (
            "socks",
            "    type: socks5\n    server: s.example.com\n    port: 1080\n    username: u\n    password: p\n    udp: true\n".into(),
            "socks",
            json!({"server":{"host":"s.example.com","port":1080},"version":"5","auth":{"username":"u","password":"p"}}),
        ),
        (
            "hysteria",
            "    type: hysteria\n    server: h1.example.com\n    port: 443\n    auth-str: pw\n    alpn:\n      - hysteria\n    protocol: udp\n    up: \"30 Mbps\"\n    down: \"200 Mbps\"\n    udp: true\n".into(),
            "hysteria1",
            json!({"server":{"host":"h1.example.com","port":443},"auth_str":"pw","up_bps":3_750_000,"down_bps":25_000_000,"transport":"udp","tls":{"server_name":"h1.example.com","alpn":["hysteria"]},"udp":true}),
        ),
        (
            "hysteria2",
            "    type: hysteria2\n    server: h2.example.com\n    port: 443\n    ports: 20000-30000\n    hop-interval: 30\n    password: pw\n    up: \"30 Mbps\"\n    down: \"200 Mbps\"\n    obfs: salamander\n    obfs-password: salamander-pw\n    sni: h2.example.com\n".into(),
            "hysteria2",
            json!({"server":{"host":"h2.example.com","port":443},"ports":"20000-30000","hop_interval":30,"auth":"pw","up":"30 Mbps","down":"200 Mbps","salamander_password":"salamander-pw","tls":{"server_name":"h2.example.com"}}),
        ),
        (
            "tuic",
            "    type: tuic\n    server: tuic.example.com\n    port: 443\n    uuid: 00000000-0000-0000-0000-000000000001\n    password: pw\n    alpn: [h3]\n    heartbeat-interval: 10000\n    udp-relay-mode: native\n    congestion-controller: bbr\n    reduce-rtt: false\n".into(),
            "tuic",
            json!({"server":{"host":"tuic.example.com","port":443},"uuid":"00000000-0000-0000-0000-000000000001","password":"pw","tls":{"server_name":"tuic.example.com","alpn":["h3"]},"heartbeat_interval_secs":10,"udp_relay_mode":"native","congestion_control":"bbr"}),
        ),
        (
            "shadowquic",
            "    type: shadowquic\n    server: 203.0.113.17\n    port: 443\n    username: u\n    password: p\n    sni: sq.example.com\n    alpn: [h3]\n    congestion-controller: bbr\n    udp: true\n".into(),
            "shadowquic",
            json!({"server":{"host":"203.0.113.17","port":443},"username":"u","password":"p","server_name":"sq.example.com","alpn":["h3"],"congestion_control":"bbr"}),
        ),
        (
            "wireguard",
            format!("    type: wireguard\n    server: 203.0.113.20\n    port: 51820\n    ip: 172.16.0.2/32\n    ipv6: fd01::2/128\n    private-key: {WG_PRIVATE}\n    public-key: {WG_PUBLIC}\n    allowed-ips: ['0.0.0.0/0', '::/0']\n    reserved: [1, 2, 3]\n    mtu: 1280\n    persistent-keepalive: 25\n    udp: true\n"),
            "wireguard",
            json!({"tunnel":{"private_key":WG_PRIVATE,"addresses":["172.16.0.2","fd01::2"],"mtu":1280},"endpoint":{"host":"203.0.113.20","port":51820},"peer":{"public_key":WG_PUBLIC,"reserved":[1,2,3],"allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive":25}}),
        ),
        (
            "ssh",
            "    type: ssh\n    server: ssh.example.com\n    port: 22\n    username: root\n    password: pw\n    host-key:\n      - \"ssh-ed25519 a2VybGljby10ZXN0LWhvc3Qta2V5\"\n".into(),
            "ssh",
            json!({"server":{"host":"ssh.example.com","port":22},"username":"root","auth":{"type":"password","password":"pw"},"host_key_sha256":["SHA256:tTRucOhNSKKtpTPEgl/P9YybsLaiKnFmPuWZa+zo0PU"]}),
        ),
        (
            "mieru",
            "    type: mieru\n    server: 203.0.113.21\n    port: 2999\n    transport: TCP\n    username: u\n    password: p\n    multiplexing: MULTIPLEXING_LOW\n".into(),
            "mieru",
            json!({"server":{"host":"203.0.113.21","port":2999},"transport":"tcp","username":"u","password":"p","multiplexing":true}),
        ),
        (
            "sudoku",
            "    type: sudoku\n    server: 203.0.113.22\n    port: 443\n    key: synthetic-sudoku-config-seed\n    aead-method: chacha20-poly1305\n    padding-min: 2\n    padding-max: 7\n    table-type: prefer_entropy\n    httpmask:\n      mode: legacy\n".into(),
            "sudoku",
            json!({"server":{"host":"203.0.113.22","port":443},"protocol":{"key":"synthetic-sudoku-config-seed","aead":"chacha20-poly1305","padding_min":2,"padding_max":7,"table_type":"prefer_entropy"},"http_mask":{"mode":"legacy"}}),
        ),
        (
            "trusttunnel",
            "    type: trusttunnel\n    server: tt.example.com\n    port: 443\n    username: u\n    password: p\n    sni: tt.example.com\n    max-connections: 4\n    udp: true\n".into(),
            "trusttunnel",
            json!({"server":{"host":"tt.example.com","port":443},"auth":{"username":"u","password":"p"},"tls":{"server_name":"tt.example.com"},"limits":{"max_connections":4},"udp":true}),
        ),
        (
            "gost-relay",
            "    type: gost-relay\n    server: relay.example.com\n    port: 8421\n    username: u\n    password: p\n    tls: true\n    sni: relay.example.com\n    mux: true\n".into(),
            "gost-relay",
            json!({"server":{"host":"relay.example.com","port":8421},"username":"u","password":"p","mux":true,"tls":{"server_name":"relay.example.com"}}),
        ),
        (
            "tailscale",
            "    type: tailscale\n    hostname: kerlico-1\n    auth-key: tskey-abc\n    control-url: https://headscale.example.com\n    ephemeral: true\n    accept-routes: true\n".into(),
            "tailscale",
            json!({"auth_key":"tskey-abc","control_url":"https://headscale.example.com","hostname":"kerlico-1","ephemeral":true,"accept_routes":true}),
        ),
        (
            "openvpn",
            format!("    type: openvpn\n    server: vpn.example.com\n    port: 1194\n    proto: udp\n    username: u\n    password: p\n    ca: {}\n", serde_json::to_string(CA_PEM).unwrap()),
            "openvpn",
            json!({"remote":{"host":"vpn.example.com","port":1194},"proto":"udp","username":"u","password":"p","ca_pem":CA_PEM}),
        ),
        (
            "easytier",
            "    type: easytier\n    network-name: n\n    network-secret: s\n    peers:\n      - tcp://public.easytier.top:11010\n    ipv4: 10.126.126.2/24\n".into(),
            "easytier",
            json!({"network_name":"n","network_secret":"s","peers":["tcp://public.easytier.top:11010"],"ipv4":"10.126.126.2/24"}),
        ),
        (
            "zerotier",
            format!("    type: zerotier\n    network: 8a013571a2000001\n    identity-secret: \"{ZT_SECRET}\"\n"),
            "zerotier",
            json!({"network":"8a013571a2000001","identity":ZT_SECRET,"public_planet":true}),
        ),
        ("direct-out", "    type: direct\n    udp: true\n".into(), "direct", json!({})),
        ("reject-out", "    type: reject\n".into(), "reject", json!({})),
        ("dns-out", "    type: dns\n".into(), "dns", json!({})),
    ]
}
