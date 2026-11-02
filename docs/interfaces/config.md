# 配置与命令行接口

更新日期：2026-11-02（Asia/Shanghai）

当前源码使用 **JSON 配置版本 2（v2）**，旧版 v1 配置迁移方式见 [配置 v2 迁移指南](../config-v2-migration.md)。

## 根配置结构

| 字段 | 约束说明 |
| --- | --- |
| `version` | 必填，固定为 `2`（v1 直接拒绝） |
| `epoch` | 默认 `1`，非零正整数，标识配置代次 |
| `accounts` | 管理账户数组，`user_id` 与 `username` 分别全局唯一 |
| `outbounds` | 命名出站数组（`tag` / `type` / `options`）；每条配置编译一次、运行期启动一次 |
| `inbounds` | 回环固定目标转发入口，默认空 |
| `nodes` | 服务端协议节点（需配置真实鉴别成员 `members`），默认空 |
| `local_inbounds` | 协议工厂显式允许的本地回环入口，默认空 |
| `limits` | 全局超时、会话与账本记录上限，省略字段使用默认值 |

- **标签与校验**：`tag` 为 1–64 个 ASCII 字母、数字、`-` 或 `_`；出站拥有独立标签命名空间，所有入站（`inbounds` / `nodes` / `local_inbounds`）共用另一命名空间。未知字段、缺失类型、无效引用或能力不匹配在编译期直接拒绝。
- **管理账户（`accounts`）**：包含持久非零 UUID `user_id`、1–128 字符唯一 `username`、Argon2id v19 PHC 摘要 `password_hash`（参数范围：`m` 19456–262144，`t` 2–10，`p` 1–8）与可选 `enabled`。
- **协议节点（`nodes`）**：包含 `tag`、`type`、`listen`、`outbound`、`options`、`members` 及可选 `mode`、`max_sessions`：
  - `members` 每项包含 `user_id`、`native_credential` 及可选 `credential_epoch`（默认 `1`）、`enabled`；单节点最多 1024 个成员。跨节点复用认证或保护秘密在编译期拒绝。
  - `mode` 取 `ipv4-only`、`ipv6-only` 或 `dual-stack`（默认），仅约束本节点负责目标选择的 `Local` 出站路径（双栈默认 IPv4 优先）；`Remote` 代理出站保留原始目标域名或 IP 透传。

## 固定目标入口与全局限制（`limits`）

固定转发入口（`inbounds`）包含 `tag`、`type`（`tcp-forward` 或 `udp-forward`）、`listen`（必须为回环地址，端口 `0` 表示系统动态分配）、`target.host`/`port`、`outbound` 及可选 `mode`、`require_remote_eof`（默认 `false`；设为 `true` 时要求所选出站具备 `tcp_eof` 能力）。

| `limits` 字段 | 默认值 | 有效范围与说明 |
| --- | --- | --- |
| `connect_timeout_ms` | `10000` | `1`–`300000`，建立链总期限 |
| `idle_timeout_ms` | `60000` | `1`–`86400000`，业务转发空闲超时 |
| `drain_timeout_ms` | `5000` | `1`–`300000`，关闭阶段排空预算 |
| `max_sessions` | `128` | `1`–`65536`，全局并发会话与附加逻辑流配额 |
| `udp_queue_packets` | `32` | `1`–`4096`，每来源固定 UDP 转发排队包数上限 |
| `max_datagram_size` | `65535` | `1`–`65535`，数据报缓冲区上限 |
| `max_flow_records` | `65536` | `max_sessions`–`1048576`，内存账本保留的 `FlowRecord` 上限 |

当内存账本记录达到 `max_flow_records` 上限时，优先淘汰已结束的记录（其累计流量保留在运行期汇总中）；若全部槽位均被活跃流占满，则拒绝新业务流。

## 命令行接口（CLI）

| 命令 | 行为说明 |
| --- | --- |
| `kerlico modules` | 按 `outbound/<kind>` 与 `inbound/<kind>` 列出当前构建实际注册的模块 |
| `kerlico check -c <file>` | 校验配置文件（上限 1 MiB）并编译装配计划，不绑定端口、不拨号或创建状态目录 |
| `kerlico run -c <file>` | 启动唯一共享出站服务并绑定全部入站入口；收到 `Ctrl-C` 或 Unix `SIGTERM` 时停止准入并有限排空 |
| `kerlico account-new --prefix <name>` | 从标准输入读取 12–1024 字节管理密码，输出带 `<prefix>_<uuid>` 用户名与 Argon2id 摘要的账户 JSON |

默认构建注册全部 **23 个协议模块**（其中 `ssh`、`gost-relay`、`tor` 仅注册 `outbound`，其余 20 个协议同时注册 `inbound` 与 `outbound`）。
