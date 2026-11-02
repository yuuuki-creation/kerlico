# 使用指南

[English](usage.en.md)

`kerlico` 是一个可执行文件，按 JSON 配置充当代理客户端、代理服务端，或两者兼有。

## 安装

从 [Releases](https://github.com/yuuuki-creation/kerlico/releases) 下载 Linux `x86_64` 的 `kerlico`，用 `SHA256SUMS` 校验。运行需要 glibc 2.34 或更高版本，以及 `liblzma`。

从源码构建需要 Rust `1.99.1`：

```sh
export PROTOC="$(tools/fetch_protoc.sh ~/.cache/kerlico)"
cargo build --locked --release -p kerlico
```

`protoc` 只有 EasyTier 出站需要。不需要时用 `--no-default-features` 选择协议。

## 命令

| 命令 | 作用 |
| --- | --- |
| `kerlico run -c <file>` | 启动，收到 `Ctrl-C` 或 `SIGTERM` 后优雅退出 |
| `kerlico check -c <file>` | 校验配置，不监听端口 |
| `kerlico modules` | 列出此构建包含的协议 |
| `kerlico account-new --prefix <name>` | 从标准输入读取管理密码，输出账户 JSON |
| `kerlico history --kind <kind>` | 查询统计历史，`kind` 为 `usage`、`flows`、`bandwidth` 或 `events` |

全局参数 `--lang zh-CN` 或 `--lang en` 指定输出语言。

## 配置

配置是 JSON v2，由这几部分组成：

- `outbounds`：命名出站，流量最终从这里离开。
- `nodes`：对外服务的协议节点，用 `members` 鉴权。
- `local_inbounds`：只监听回环地址的协议入口，如本机 SOCKS。
- `inbounds`：只监听回环地址的固定目标转发。
- `routes`：按规则选择出站。
- `accounts`、`telemetry`、`device`、`dns`、`control`、`limits`：账户、统计、WARP、DNS、控制接口和限额。

字段细节见[配置接口](interfaces/config.md)，各协议的 `options` 见[接口文档](interfaces/README.md)。

## 作为客户端

[examples/client-routes-v2.json](../examples/client-routes-v2.json) 在本机开 SOCKS 入口，默认走远端代理，局域网直连，广告域名拒绝。把 `proxy` 的 `options` 换成你的服务器后运行：

```sh
kerlico run -c client-routes-v2.json
```

## 作为服务端

先创建管理账户：

```sh
printf '%s' 'your-admin-password' | kerlico account-new --prefix alice
```

把输出放进 `accounts`，再用它的 `user_id` 在节点上配置成员。IPv4 和 IPv6 分别建节点，每个节点有独立的凭据和配额。各协议的 `options` 和 `native_credential` 见对应接口文档。

```json
{
  "version": 2,
  "accounts": [{ "user_id": "...", "username": "...", "password_hash": "..." }],
  "outbounds": [{ "tag": "direct", "type": "direct" }],
  "nodes": [{
    "tag": "ss-v4",
    "type": "ss2022",
    "listen": "0.0.0.0:8388",
    "outbound": "direct",
    "options": { "method": "2022-blake3-aes-128-gcm" },
    "members": [{ "user_id": "...", "native_credential": { "key": "<Base64 key>" } }]
  }]
}
```

## 路由

规则按顺序匹配，首条命中生效，未命中走节点绑定的 `outbound`。可按域名、CIDR、端口、网络、节点和用户匹配。路由不查询 DNS，域名目标不会匹配 CIDR。多目标 UDP 关联固定走节点绑定的出站。详见[路由规则](interfaces/config.md)。

## WARP 补齐

机器只有 IPv4 或只有 IPv6 时，配置 `device` 后，`dual-stack` 节点的 `direct` 流量可经 Cloudflare WARP 访问缺失的地址族：

```json
"device": { "state_directory": "/var/lib/kerlico/device" }
```

首次需要时向 Cloudflare 注册一次，身份保存在此目录。目录必须是绝对路径，权限 `0700`。

## 隧道与覆盖网络出站

`masque`、`openvpn`、`openconnect`、`tailscale`、`easytier`、`zerotier` 把远端网络接成出站。在节点或规则里引用它们的 `tag`。目标必须是该网络能到达的地址，域名由本机解析。选项和限制见各[接口文档](interfaces/README.md)。

## TUN

[examples/tun-v2.json](../examples/tun-v2.json) 创建 `kerlico0` 接口，把进入接口的 TCP 和 UDP 交给出站。kerlico 不修改系统路由，需要自己添加路由，并避免回环。TUN 看到的目标都是 IP，域名规则不生效。详见 [TUN 入站](interfaces/tun.md)。

## DNS

`dns` 段为 `direct` 路径配置上游和静态 hosts，支持 UDP、TCP 和 TLS。未配置时使用系统解析器。详见 [DNS](interfaces/dns.md)。

## 控制接口

`control` 段开启只读 HTTP 接口：

```sh
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/v1/usage
```

详见[控制接口](interfaces/control.md)。

## 统计

配置 `telemetry` 后，用量、带宽、访问记录、DNS 与错误事件写入 SQLite：

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```

详见[统计历史](interfaces/history.md)。
