# ZeroTier 原生客户端出站

更新日期：2026-11-02（Asia/Shanghai）

`kerlico-zerotier` 导出 `ZeroTierFactory`，机器标识为 `zerotier`。kerlico 以原生 Rust 节点加入私有 ZeroTier 网络，不启动 `zerotier-one`，不创建系统 TUN 设备，不修改宿主路由。

## 代码与许可证

| 位置 | 许可证 | 内容 |
| --- | --- | --- |
| `third_party/zerotier-node` | `MPL-2.0` | 由 ZeroTierOne tag `1.16.2`（提交 `fc5c3ec22090b5b2a0f274e863651fe9ca489bf4`）的 `node/` 翻译而来的 Rust 代码：身份与工作量证明、VL1 包与分片、握手、网络配置、成员证书、组播、默认 planet。逐文件来源见该目录 `UPSTREAM.md`，MPL 全文见该目录 `LICENSE`，每个源文件头保留 MPL 声明与上游文件名。 |
| `crates/protocol-zerotier` | `GPL-3.0-only` | 自有代码：配置、套接字驱动、ARP/NDP 应答（按 RFC 826、RFC 4861 编写）、到 `kerlico_wireguard::ip::ClientTunnel` 的桥接。 |

上游的 `nonfree/`（含控制器）与 `ext/` 未被读取或翻译。密码学原语与 LZ4 使用 Rust crate（`x25519-dalek`、`ed25519-dalek`、`salsa20`、`poly1305`、`sha2`、`lz4_flex`）。`third_party/zerotier-node` 被根 `Cargo.toml` 排除在 workspace 成员之外，经路径依赖参与构建。

## 出站配置（`outbound.options`）

```json
{
  "network": "8056c2e21c000001",
  "identity_file": "state/zerotier/identity.secret",
  "roots": [
    {"identity": "<address>:0:<public-hex>", "endpoints": ["192.0.2.10:9993"]}
  ],
  "peers": [],
  "public_planet": false
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `network` | 是 | 16 位十六进制网络 ID。高 40 位是控制器地址。拒绝 `ff` 开头的临时网络。 |
| `identity_file` | 二选一 | `identity.secret` 格式文件。不存在时生成，先写入同目录临时文件（Unix 权限 `0600`）并落盘，再原子出现在目标路径，已存在的文件不被覆盖。已有的 `zerotier-one` 身份可直接使用。 |
| `identity` | 二选一 | 内联 `address:0:public:secret` 字符串。 |
| `roots` | 见下 | 上游节点列表：应答 WHOIS、转发尚无直连路径的流量、介绍对端。自建 moon 的节点可填在这里。 |
| `peers` | 见下 | 直接联系的节点，例如控制器或成员的已知端点。 |
| `public_planet` | 否 | `true` 时把 ZeroTierOne 1.16.2 内置的公共 planet 根节点加入 `roots`。 |
| `bind` | 否 | 载体 UDP 绑定地址。设置后只使用这一个地址族。省略时同时打开 IPv4 与 IPv6，端口由节点地址固定推出（20000–64999），被占用时改用随机端口。 |

`roots` 为空时，`peers` 必须包含控制器。`endpoints` 只接受字面 `IP:端口`。

在控制器上授权的节点地址是身份字符串的前 10 位十六进制，即 `identity_file` 第一个冒号之前的部分。

本出站使用 `TargetPolicy::Local`：目标须是调度器解析后的字面 IP，且落在控制器下发的路由或所分配地址的网段内，否则连接被拒绝。

## 已实现范围

- **身份**：生成、持久化与校验，含 2 MiB 内存密集工作量证明。启动时校验本机及全部 `roots`、`peers` 的身份。
- **VL1**：包封装、分片重组（物理 MTU 1432，最多 7 片）、LZ4 解压、HELLO/OK 握手、WHOIS、RENDEZVOUS、ECHO 与路径保活。经 root 转发的流量在收到 RENDEZVOUS 后切换为直连。
- **VL2**：向控制器请求配置，校验控制器对配置分块的签名，60 秒刷新一次，并接受控制器主动推送。
- **成员校验**：私有网络中只接受携带有效成员证书（COM）且与本机证书一致的对端帧；缺少证书时回 `NEED_MEMBERSHIP_CERTIFICATE`。本机证书在发送前及对端要求时推送。
- **以太网**：单播 `FRAME`/`EXT_FRAME` 收发，`MULTICAST_FRAME`、`MULTICAST_LIKE`、`MULTICAST_GATHER`。IPv4 经组播 ARP 解析，IPv6 经 NDP 解析；ZT-RFC4193 与 ZT-6PLANE 地址直接由地址推出 MAC。带 `via` 的受管路由解析网关。
- **数据面**：控制器分配地址后建立用户态 IP 栈，支持 TCP、TCP 半关闭、固定目标 UDP 与多目标 UDP 关联。地址、路由或 MTU 变化时重建 IP 栈，现有连接随之关闭。控制器尚未下发配置时连接等待到连接超时；控制器拒绝时连接立即失败。

## 抗伪造与资源上限

- **未认证来源**：未知发送方的包暂存（最多 64 个，5 秒），发送方地址记入独立的表（最多 64 个，满时淘汰最旧项），伪造流量不占用本机要联系的目标表。
- **WHOIS**：全局每秒最多 64 个，其中为未认证来源发出的最多 8 个。这部分请求 ID 单独存放，不会挤掉本机其他请求。控制器不受目标表上限限制，加入网络不会因此被阻塞。
- **路径学习**：只有来自被询问对端、动词匹配且尚未使用的 OK 才能确认新路径。请求 ID 60 秒过期。网络配置请求的 ID 在过期前可多次匹配，因为控制器在每个配置分块上重复它。
- **重放**：每个对端记住约 2048 个最近的包 ID，重复的包被丢弃。协议的包 ID 是随机数，没有序号或时间可比对，因此早于这个范围的捕获包，以及进程重启或对端被淘汰之前的捕获包，仍可能被接受一次。IP 栈之上的 TCP 序号不受影响；UDP 应用可能收到这样的重复包。
- **工作量校验**：HELLO 先校验 MAC，再消耗按来源网段（IPv4 `/24`、IPv6 `/48`）限制的校验额度。陌生 HELLO 的密钥协商全局每秒最多 256 次。哈希在阻塞线程池执行，最多同时 3 个，其中 1 个留给本机主动查询的身份；超出时丢包，由对端重试。
- **邻居表**：最多 256 项，满时淘汰最旧项。ARP 应答与 NDP 邻居通告只接受本机询问过或已知的地址。网络成员仍可覆盖已知地址的 MAC，这是 ARP/NDP 本身的性质。

## 限制

- **加密套件**：HELLO 宣告协议版本 11 与软件版本 1.4.8，使对端选择 Salsa20/12 + Poly1305。未实现 AES-GMAC-SIV，因此不能与 FIPS 模式节点互通。启用 `encryptedHello` 的 1.16 对端发来的 extended armor HELLO 会被丢弃。
- **流规则**：不执行规则引擎，不校验或推送 capability、tag、certificate of ownership。依赖这些凭据放行的规则会拒绝本节点的流量。入站只按成员证书放行。
- **吊销**：不处理 revocation。被取消授权的成员在其证书超出时间窗后才失去准入。
- **未实现**：桥接、multipath/bonding、moon 与 planet 在线更新、SSO 网络（控制器要求认证时连接被拒绝）、临时网络、TCP fallback relay、`PUSH_DIRECT_PATHS`、充当 root 或转发节点。
- **地址**：每个地址族只使用第一个分配地址。
- **换端口的恢复时间**：对端在旧路径存活期间不学习同一 IP 的新端口。随机端口重启或配置变更后，经路径恢复需要约 30 秒。默认端口由身份固定以避开这段等待。
- **`public_planet`**：内置根节点列表来自上游 1.16.2，已校验签名与身份。公共网络未参与本项目的互通测试。

## 验证

`tools/interop_zerotier.py` 在 worker 上运行，容器使用 `zerotier/zerotier:1.14.2`（仅作测试设施，不进入仓库或产物），全部位于无外网的 Docker 内部网络：一个 moon 根节点、一个自建控制器、一个成员及其 zt 地址上的回显服务。脚本经 `socks` 本地入站与本出站检查：

- 未授权身份的连接被立即拒绝。
- 只配置 `roots`：经 WHOIS 找到控制器与成员，经 RENDEZVOUS 转为直连；IPv4 TCP、UDP（含超过物理 MTU 的数据报）与 IPv6 TCP（`fd77::/64`，走真实 NDP）回显字节一致。
- 只配置 `peers`：不经 root，同样的回显检查。
- 只配置 `roots` 并在加入与转发期间持续向载体端口发送伪造的未认证包和 MAC 错误的 HELLO：同样的回显检查。

真实对端目前只有 1.14.2。代码翻译自 1.16.2，协议版本协商按上述“加密套件”一节回退，未与 1.16 节点实测。

```sh
KERLICO_SSH_CONFIG=<path> KERLICO_WORKER_ROOT=<root> tools/worker_run.sh perf-02 \
  'cargo build --locked -p kerlico && python3 tools/interop_zerotier.py'
```

身份工作量证明与签名的固定向量由 `zerotier-idtool` 产生，位于 `third_party/zerotier-node/src/identity.rs` 的测试中。`zerotier-node` 不是 workspace 成员，`cargo test --workspace` 不覆盖它，需单独运行 `cargo test --locked -p zerotier-node`。
