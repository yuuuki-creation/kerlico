# Tailscale 客户端出站

更新日期：2026-11-02（Asia/Shanghai）

`kerlico-tailscale` 导出 `TailscaleFactory`，机器标识 `tailscale`。它用 pre-auth key 原生加入 tailnet，不内嵌 Go，也不启动 `tailscaled`，纯用户态运行，不创建 TUN、不改系统路由。

互通验证用 `headscale 0.27.1` 作为控制面，官方 `tailscale 1.92.3` 作为对端：`tools/interop_tailscale.py` 在 worker 上起容器，经 `socks` 本地入站跑 TCP、UDP、DERP、直连和出口节点。官方 Tailscale SaaS 控制面没有测试。

## 配置（`outbound.options`）

```json
{
  "control_url": "https://headscale.example.com",
  "auth_key": "<pre-auth-key>",
  "hostname": "kerlico",
  "state_file": "state/tailscale.json",
  "exit_node": "exit-1"
}
```

| 字段 | 必填 | 默认 | 含义 |
| --- | --- | --- | --- |
| `control_url` | 是 | | `http://` 或 `https://` 控制面地址，不含路径 |
| `auth_key` | 是 | | pre-auth key；需要人工批准的节点启动失败 |
| `hostname` | 否 | `kerlico` | 上报的主机名，字母、数字与 `-`，最长 63 |
| `state_file` | 否 | 无 | 保存 machine key 与 node key 的文件，首次启动创建，Unix 权限 `0600` |
| `ephemeral` | 否 | 无 `state_file` 时 `true`，否则 `false` | 注册为临时节点，离线后由控制面清理 |
| `exit_node` | 否 | 无 | 出口节点：tailnet IP、StableID、完整名称或名称第一段 |
| `accept_routes` | 否 | `false` | 使用对端通告并已批准的子网路由 |
| `direct` | 否 | `true` | `false` 时不绑定 UDP，所有对端只走 DERP |
| `ca_pem` | 否 | 无 | 追加到内置公共根证书的 PEM，用于控制面与 DERP 的 TLS |
| `start_timeout_ms` | 否 | `60000` | 启动时等待首个 netmap 的上限，范围 `1000`–`600000` |

使用单次 pre-auth key 时必须配置 `state_file`：重启后 node key 不变，控制面按已有节点放行。

## 实现范围

- **控制面**：`GET /key` 取服务端公钥，`POST /ts2021` 升级为 Noise IK，其上跑 HTTP/2；`/machine/register` 注册，`/machine/map` 流式接收 netmap 并合并 `Peers`、`PeersChanged`、`PeersRemoved`、`PeersChangedPatch`。断线按退避重连，已注册节点被控制面遗忘（map 返回 4xx）时重新注册。
- **数据面**：每个对端一个 `boringtun` 会话，节点身份即 node key，明文 IP 包交给共享的 `kerlico_wireguard::ip::ClientTunnel`。MTU 固定 1280。支持 TCP、TCP 半关闭、固定目标 UDP 与多目标 UDP 关联。
- **路径**：默认走对端首选 DERP 区域；对端活跃时每 5 秒向其端点发 disco Ping，收到 Pong 后切到延迟最低的直连路径，6.5 秒未再确认则退回 DERP。经 DERP 发送 CallMeMaybe 触发对端反向打洞。
- **路由**：目标 IP 按对端 AllowedIPs 最长前缀匹配。对端自身地址总是可达；默认路由仅属于 `exit_node` 选中的对端；其他子网需要 `accept_routes`。无匹配的目标直接拒绝，不回退直连。入站明文的源 IP 必须路由回发送它的对端。
- **目标策略**：`TargetPolicy::Local`。域名由共享调度器在本机解析后再进入 tailnet。

## 限制

- 没有 MagicDNS，tailnet 主机名不能作为目标；请用 tailnet IP。
- 没有 Taildrop、Tailscale SSH，不接受入站连接，不能作为出口节点或子网路由器，不执行控制面下发的 packet filter（本端只主动发起连接）。
- 不响应控制面的 `PingRequest`，不支持 Network Lock（TKA），不支持 `CertName` 的 `sha256-raw:` 证书固定，不支持 DERP 节点的 `InsecureForTests`。
- 首选 DERP 用 TCP 建连速度选择，不做上游 netcheck；端点发现只有 IPv4 STUN 和一个由路由表选出的本机地址，不枚举网卡，也没有 UPnP/NAT-PMP。IPv6 UDP 只用于向对端已知的 IPv6 端点发送。
- 自身 tailnet 地址在运行中变化时出站失败，需要重启。节点被控制面删除后重新注册会分到新地址，属于这种情况。
- `control_url` 用 `http://` 时控制面公钥未经认证，路径上的攻击者可以冒充控制面，应只在可信网络使用。
- 上游协议以 Tailscale 1.92 系列的源码为准，能力版本固定为 131；过低的控制面或上游提高最低版本时注册会被拒绝。
- 互通脚本的流量走 IPv4 tailnet 地址，IPv6 tailnet 地址没有实测。

## 对端差异

- 官方客户端作为出口节点时拒绝转发到自身直连网段，目标须在该网段之外。
- headscale 0.27.1 删除节点后不关闭该节点的 map 流，节点要等连接断开才感知。
