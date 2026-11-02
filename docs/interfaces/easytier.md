# EasyTier 出站接口

更新日期：2026-11-02（Asia/Shanghai）

`kerlico-easytier` 提供命名出站 `easytier`：以普通 peer 身份加入 EasyTier 网络，经配置的对端（`tcp://` 或 `udp://`）入网，访问虚拟 IP 和其他节点通告的子网代理。IP 包由 `kerlico_wireguard::ip::ClientTunnel` 用户态栈处理，不创建系统 TUN。业务能力为 TCP、TCP EOF、固定目标 UDP、同出口多目标 UDP 关联。

## 配置（`outbound.options`）

```json
{
  "network_name": "my-network",
  "network_secret": "<secret>",
  "peers": ["tcp://relay.example.net:11010"],
  "ipv4": "10.144.144.5/24",
  "ipv6": "fd00:144::5/64",
  "hostname": "kerlico",
  "encryption": "aes-gcm"
}
```

| 字段 | 说明 |
| --- | --- |
| `network_name`、`network_secret` | 必填，非空，与其他节点一致。对应 `easytier-core` 的 `--network-name`、`--network-secret`。 |
| `peers` | 必填，1–16 个主动连接的对端，协议只能是 `tcp` 或 `udp`，端口必须写明。域名由上游连接器在本机解析。断线后自动重连。 |
| `ipv4` | 带前缀的虚拟 IPv4。省略时由网络分配（规则同上游 `--dhcp`）。 |
| `ipv6` | 带前缀的虚拟 IPv6，可省略。网络分配只覆盖 IPv4。 |
| `hostname` | 向网络通告的节点名，默认 `kerlico`，不读取本机主机名。 |
| `encryption` | `aes-gcm`（默认，与上游默认一致）、`aes-256-gcm`、`xor`、`none`（对应上游 `--no-encryption`）。须与网络内其他节点相同。 |

## 行为

- **实现方式**：依赖上游库 `easytier` 2.6.4，`default-features = false`，开启 `aes-gcm`、`zstd`。握手、网络密钥校验、数据加解密、压缩解码、OSPF 路由同步和转发都由上游 `PeerManager` 完成，本 crate 只负责把它的 NIC 通道接到用户态栈。
- **许可**：上游根目录与 `easytier/LICENSE` 均为 LGPL-3.0，与本项目 GPL-3.0-only 兼容。上游依赖 `libdbus-sys` 内置的 libdbus（AFL-2.1 或 GPL-2.0-or-later，可选其一）只在构建时编译，release 二进制中没有它的符号。
- **依赖兼容**：与工作区的 `rustls`、`quinn`、`h3` 补丁没有冲突，已有依赖的锁定版本都没有变化。上游的 `http_req` 解析到补丁版 `rustls`，上游 `quic` feature 未开启，因此不使用 `quinn`。
- **路由归属**：`TargetPolicy::Local`。共享调度器先解析网站域名，出站只接受字面 IP。上游 Magic DNS 名称（`*.et.net`）不可用。
- **节点与作用域**：一个出站实例是网络中的一个节点，只有一个虚拟地址，所有来源作用域共用该节点，流之间由用户态栈按连接隔离。这一点与 WireGuard 出站相同，与按作用域建立隧道的 MASQUE 出站不同：EasyTier 的身份是网络内的地址，同一静态地址不能出现两个节点。
- **建立顺序**：出站启动时创建节点并开始连接对端，不等待连接成功。新流先等本机地址就绪（网络分配时）和目标路由出现，受连接超时约束。目标没有路由时返回超时。网络密钥错误时对端拒绝握手、本机持续重试，表现同样是连接超时。对端断开后自动重连，路由恢复后新流可用。
- **网络分配地址**：至少看到一条路由后，从已用地址所在网段取第一个空闲主机地址，每 5 秒复查。发现冲突或网段变化时换地址，已有的流随旧地址结束。网络内没有任何地址时使用 `10.126.126.0/24`，与上游相同。
- **数据面**：内层 MTU 固定为 1360（上游默认 1380 减加密开销 20）。更大的 UDP 由用户态栈分片。入站方向只接受目标为本机虚拟地址的包；其他节点主动发起的连接不会被接受。
- **经中继入网**：`peers` 可以指向名称不同的公共节点（上游 foreign network 模式），流量由该节点转发到同名网络内的节点。
- **对网络的通告**：不监听端口、不打洞（通告 `disable_p2p`）、不接收 KCP/QUIC 代理流量，也不向公共 STUN 服务器探测。其他节点始终经配置的对端转发到本节点。配置多个对端时，本节点可能成为这些对端之间的转发路径，这是上游路由的行为。

## 未实现

- 中继服务端模式、Web 控制台、作为子网代理或出口节点对外提供服务。
- `quic://`、`wg://`、`ws://`、`wss://`、`faketcp://`、`ring://` 对端，以及通过 HTTP、DNS TXT 发现对端。
- 打洞和 P2P 直连：到其他节点的流量都经配置的对端转发。
- 使用其他节点作为出口（上游 `--exit-nodes`）。
- 安全模式（Noise，`--secure-mode`）与凭证节点（`--network-secret` 以外的身份）。
- Magic DNS、`chacha20` 等上游其他算法、TCP/UDP 以外的 IP 协议转发；用户态栈只对 ICMP 做本地控制响应。

## 真实限制

**构建依赖**：上游 `build.rs` 需要 `protoc`。`tools/worker_run.sh`、`worker_gate.sh`、`worker_release.sh` 通过 `tools/fetch_protoc.sh` 取固定版本（Linux x86_64）。其他环境须自行提供 `PROTOC`，或关闭 `protocol-easytier` feature。

**依赖体量**：上游库没有按功能拆分，关闭可选 feature 后仍带来 netlink、`pnet`、`hickory`、`dbus`（`vendored`，构建时编译 C 源码）等依赖。`Cargo.lock` 增加 205 个包。Linux x86_64 release 二进制从 52.2 MB 增加到 68.1 MB；不需要本出站时可关闭 `protocol-easytier`。

**Windows 与 macOS**：本 crate 只在 Linux x86_64 上构建和测试过。上游 `build.rs` 在 Windows 上用相对路径 `easytier/third_party/...` 指定链接搜索路径，作为 Git 依赖时该路径预计不成立，需要关闭 `protocol-easytier` 或另行处理。

**转发依赖对端**：本节点不打洞，到其他节点的流量全靠配置的对端转发。对端开启上游 `disable_relay_data` 时，这部分流量可能走不通。

## 验证

`tools/interop_easytier.py` 运行 `kerlico run`（SOCKS5 本地入站加本出站）对接官方 `easytier-core` 2.6.4 发行版。容器拓扑：公共中继式节点 `relay`（另一个网络名），TUN 节点 `node-a`、`node-b`，以及只连在内部网络、由 `node-a` 子网代理的 `svc`。两个场景分别是静态 IPv4 + IPv6 地址经 `tcp://` 直连 `node-a`，以及网络分配地址经 `udp://` 连 `relay`。每个目标都验证 TCP 回写与半关闭、UDP 回写。

```sh
python3 tools/interop_easytier.py --kerlico target/debug/kerlico \
  --easytier-dir <easytier-linux-x86_64-v2.6.4 解压目录> --work-dir <新目录>
```
