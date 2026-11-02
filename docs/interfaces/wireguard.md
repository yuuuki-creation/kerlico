# WireGuard 原生双端接口

更新日期：2026-11-02（Asia/Shanghai）

本文描述 `kerlico-wireguard` 的原生双端实现契约。海外 worker 包级 17 项、固定官方 peer 双方向 8 配置及 1194 项检查已通过。上游调研见 [WireGuard 原生研究](../../reference/research_notes/wireguard-native.md)，具体输入、扰动强度及后续修订的验证边界见 [测试记录](../testing/wireguard.md) 与 [STATUS.md](../../STATUS.md)。

## 注册与数据能力

`kerlico-wireguard` 导出 `WireGuardFactory`（出站）与 `WireGuardNodeFactory`（服务端入站节点），机器标识均为 `wireguard`：

- **技术栈**：基于 `boringtun 0.7.1`（Noise_IK 握手与加解密）与 `smoltcp 0.14.0`（用户态 TCP/IP 栈），纯用户态运行，不创建系统 TUN 设备、不依赖内核 WireGuard 模块或修改宿主路由表。
- **数据能力**：支持双端 TCP、TCP 半关闭（`tcp_eof = true`）、固定目标 UDP 与多目标 UDP 关联（Full Cone 语义）。
- **实例与作用域**：每个命名出站维护单一 UDP 载体、`Tunn` 与用户态栈；服务端节点使用单一物理 UDP 监听器，为每个已认证成员 peer 维护独立的 `Tunn`、用户态栈、流映射与取消域。

## 出站配置（`outbound.options`）

```json
{
  "tunnel": {
    "private_key": "<private-key-base64>",
    "addresses": ["10.77.0.2", "fd77::2"],
    "mtu": 1420
  },
  "endpoint": {"host": "peer.invalid", "port": 51820},
  "peer": {
    "public_key": "<peer-public-key-base64>",
    "preshared_key": "<optional-preshared-key-base64>",
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "persistent_keepalive": 25
  }
}
```

- **端点与绑定**：可选 `bind` 指定外层 UDP 本地 `SocketAddr`；启动时解析 `endpoint`（按绑定地址族筛选，双栈优先 IPv4）。
- **密钥与参数**：私钥与公钥为标准 Base64 编码的非零 32 字节值（拒绝本机公钥与 Curve25519 低阶点）；`addresses` 包含 1–2 个隧道内字面 IP（每地址族最多 1 个）；`mtu` 范围 `1280`–`9000`（默认 `1420`）；`persistent_keepalive` 范围 `0`–`65535` 秒；`allowed_ips` 包含 1–256 条无重复、无重叠的规范 CIDR。

## 服务端节点与成员配置

- **节点 `options`**：仅包含 `{"tunnel": {...}}`，外层监听地址由节点 `listen` 字段指定。
- **成员 `native_credential`**：采用与出站 `peer` 相同的结构（`public_key`、可选 `preshared_key`、`allowed_ips`、`persistent_keepalive`）。
- **凭据隔离与真实鉴别**：节点内成员公钥唯一且各 peer 的 `allowed_ips` 互不重叠、不包含本节点隧道接口地址。节点私钥、成员公钥（`Authentication`）与 PSK（`Protection`）均纳入 `CredentialManifest` 跨节点隔离校验。仅当同一候选 `Tunn` 成功验证传输包或握手响应后，才通过对应 `CredentialSlot` 签发 `Verified` 与 `PeerSession`。

## 目标策略与 TCP/UDP 隧道处理

1. **目标策略（`TargetPolicy::Local`）**：
   - WireGuard 隧道承载三层 IP 包，不含应用层域名字段，因此出站声明 `TargetPolicy::Local`，由共享 `Dispatcher` 按入站节点 `FamilyMode` 解析目标字面 IP 后送入隧道。
2. **服务端 TCP 连接建立与地址映射**：
   - 服务端收到认证 peer 的内层 SYN 后，先通过 `PeerSession::connect_tcp` 连接原始目标；目标建立成功后再恢复 `smoltcp` 发送 SYN-ACK，若目标失败则直接回送 RST。
   - 针对 `smoltcp` 接口地址限制，模块内部为每个 peer 的每条并发 TCP 流维护有界五元组映射，入站改写为内部接口端点、出站恢复原目标 IP/端口并重算校验和，在 `TIME_WAIT`（10 秒）或排空期内保持映射唯一。
3. **UDP、IP 分片与 ICMP 边界**：
   - 多目标 UDP 关联按认证 peer 与内层源端点复用同一 `PeerSession::associate_udp`，支持未知来源回包（Full Cone）。
   - IPv4 最大 UDP 载荷 `65507` 字节，IPv6 最大 `65527` 字节；超 MTU 数据报执行内层 IPv4/IPv6 分片与有界重组（单包最多 128 片、30 秒超时，拒绝重叠/越界/嵌套分片）。
   - ICMP 仅响应本隧道接口自身的 Echo Request 及必要控制差错，对任意远端 ICMP Echo 返回管理禁止（Administratively Prohibited）差错。

## 资源限制与计量

`tunnel.limits` 可选配置：

| 字段 | 默认值 | 有效范围与作用域 |
| --- | --- | --- |
| `max_flows` | `256` | `1`–`4096`，出站或服务端每 peer 的并发 TCP 流与 UDP 关联上限 |
| `tcp_buffer_bytes` | `65536` | `4096`–`1048576`，每条 TCP 流读/写方向各自的缓冲区大小 |
| `queue_packets` | `128` | `8`–`4096`，单命名出站或单节点共享排队包数上限 |
| `queue_bytes` | `2097152` | `65536`–`67108864`，共享排队字节预算 |
| `fragment_packets` | `64` | `1`–`1024`，同时重组的数据报数量上限 |
| `fragment_bytes` | `2097152` | `65536`–`67108864`，共享分片重组载荷字节预算 |
| `udp_idle_timeout_ms` | `60000` | `100`–`86400000`，UDP 关联与空闲 peer 超时毫秒数 |

- **业务与载体分账**：应用层业务载荷仅通过 `Dispatcher` 的 `TcpFlow` / `FixedUdpFlow` / `UdpAssociation` 计量一次；外层 Socket 实际收发的 WireGuard UDP 载荷字节通过 `ServiceContext::record_carrier` 与 `IngressBinding::record_carrier` 独立累计至载体统计。
