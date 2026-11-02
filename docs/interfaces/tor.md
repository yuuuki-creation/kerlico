# Tor 出站接口

更新日期：2026-11-02（Asia/Shanghai）

本文描述 `kerlico-tor` 的实现契约。测试进度见 [测试记录](../testing/tor.md)，上游依赖与局部补丁说明见 [Tor 实现报告](../../reference/reports/tor-implementation-20261102.md)。

## 角色与数据能力

`TorFactory` 注册 `tor` 出站，数据面直接内嵌 `arti-client 0.47.0`（无外部 Tor 守护进程或 SOCKS 桥接）：

| 能力维度 | 实现范围 |
| --- | --- |
| 客户端 TCP 出站 | 支持域名、IPv4/IPv6 字面目标，以及无需 PoW 计算的公开 v3 `.onion` 目标 |
| 入站节点 / Tor Relay / Onion Service | 不支持 |
| 固定目标 UDP / 多目标关联 | 不支持 |
| 目标 TCP 半关闭 (`tcp_eof`) | `false`（Tor `RELAY_END` 关闭整条流，`require_remote_eof = true` 在编译期拒绝） |
| 网站地址策略 | `TargetPolicy::Remote`（保留原始目标与端口交由 Arti 解析与选路） |
| 目标绑定元数据 | `TcpConnectInfo::unknown()` |

## 配置字段与状态目录安全

`options` 仅接受以下字段（未知字段直接拒绝）：

| 字段 | 类型 | 默认值 | 约束说明 |
| --- | --- | --- | --- |
| `data_directory` | 字符串 | 必填 | 项目工作目录内的非空相对路径，禁止包含 `..`、根路径或盘符 |
| `bootstrap_timeout_ms` | 整数 | `120000` | `1000`–`600000`，唯一 bootstrap 任务的固定超时预算 |
| `carrier_timeout_ms` | 整数 | `30000` | `100`–`120000`，单次 Tor relay 或 directory 载体拨号超时预算 |
| `shutdown_timeout_ms` | 整数 | `5000` | `100`–`60000`，首次后端关闭固定的总预算（同时受 `Engine` 外层期限约束） |

配置示例：

```json
{
  "version": 2,
  "outbounds": [
    {
      "tag": "tor-a",
      "type": "tor",
      "options": {
        "data_directory": "state/tor",
        "bootstrap_timeout_ms": 120000
      }
    }
  ],
  "inbounds": [
    {
      "tag": "check-forward",
      "type": "tcp-forward",
      "listen": "127.0.0.1:18080",
      "target": {"host": "check.torproject.org", "port": 443},
      "outbound": "tor-a"
    }
  ],
  "limits": {"connect_timeout_ms": 180000}
}
```

- **排他目录锁**：`Registry::prepare` 仅做纯配置校验；运行期创建 `data_directory/<OutId>/state` 与 `cache` 并持有排他文件锁，拒绝两个实例并发共用同一状态目录。
- **Unix 路径与权限校验**：运行期固定有效 UID，从根目录起使用目录句柄、`openat` 与 `O_NOFOLLOW` 逐级校验全部祖先目录（必须归属 `root` 或当前 UID，且禁止组/其他用户写权限，拒绝 `/tmp` 等含 sticky 位的共享可写目录）。受管子目录权限强制为 `0700`，锁文件权限强制为 `0600`（无符号链接、单硬链接常规文件）。非 Unix 平台在运行期明确拒绝。

## 共享实例、电路隔离与取消

- **单命名实例共享**：每次 `OutboundPlan::start` 构造唯一 `TorClient<TorRuntime>` 并启动单一后台 bootstrap 任务；单个请求超时或取消不会中断共享 bootstrap，而 bootstrap 失败则会标记该命名服务失败。
- **逐流电路隔离**：每次 `connect_tcp` 调用 `isolated_client` 生成独立隔离 token，不跨业务流共用 Tor 电路，也不在内存中维护无界的 `ResourceKey` 映射表。
- **读写取消唤醒**：流建立确认后返回（未启用 optimistic 模式），读写方向各自持有取消等待器，取消时返回携带 `Error::Cancelled` 的 `ConnectionAborted`。

## 后台任务、致命错误回调与关闭

- **任务追踪**：Arti 异步 `Spawn` 任务与 `Blocking::spawn_blocking` 阻塞任务全部登记至所属命名服务的 `ServiceContext`（真实 `JoinSet`），丢弃外层结果句柄不会丢失底层任务所有权。
- **共识致命错误拦截**：通过 `arti-client` 局部补丁注册 fatal 回调，当网络共识要求未实现的必需协议版本时，先调用 `ServiceContext::fail` 记录协议过时首因再触发服务取消，避免直接终止宿主进程。
- **确定性关闭**：关闭时先取消服务并释放 `TorClient`，待全部登记任务完成 `join` 且无遗留状态后释放状态目录锁引用。
- **错误映射與不支持范围**：超时映射 `Error::Timeout`，出口策略拒绝或缺少私有 onion 认证映射 `Error::Rejected`，非法地址映射 `Error::InvalidAddress`，资源耗尽映射 `Error::ResourceLimit`。不支持网桥（Bridge）、可插拔传输（PT）、私有 onion 认证、PoW 计算或外部 Tor 进程调用。
