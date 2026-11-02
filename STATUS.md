# 项目状态

更新日期：2026-11-02（Asia/Shanghai）

## 版本

已发布 [v1.0.0](https://github.com/yuuuki-creation/kerlico/releases/tag/v1.0.0) 源码版。`main` 之后合入了统计持久化、设备所有者库、双语接口和协议修订，下一版本为 `v1.0.1`。

构建基线：Rust `1.99.1`，Linux `x86_64`。

## 完成计划

| 版本 | 交付 | 完成标志 |
| --- | --- | --- |
| `v1.0.1` | `tools/worker_gate.sh` 通过；补齐第三方许可通知；上传二进制 | Release 带 Linux `x86_64` 二进制与 SHA-256 |
| `v1.1` | CLI 接入 `kerlico-device`（同进程 WARP 补齐）；规则路由 `routing`；DNS 与错误事件历史；中英使用文档 | 配置 `dual-stack` 缺族时经 WARP 出网；同一节点可按规则选出站 |
| `v1.2` | `dns`、`tun`、`control` 模块 | TUN 客户端可用；控制接口可查询在线与用量 |
| `v1.3` | MASQUE，随后 OpenVPN、OpenConnect、Tailscale、ZeroTier、EasyTier；VLESS 混合 NFS 链、ML-DSA 验签、XUDP 跨载体迁移 | 每个端点通过一次真实对端互通 |

验证规则见 [0012](docs/decisions/0012-simplified-delivery-and-verification.md)。跨进程设备 daemon/IPC 不在计划内，出现多进程部署需求时再排。

## 能力现状

| 能力 | 现状 |
| --- | --- |
| 协议模块 | 23 个进入默认构建：20 个双端，SSH、Gost Relay、Tor 仅出站 |
| 节点与出站 | 独立节点；单一 `EgressRuntime`/`Dispatcher`；`Local`/`Remote` 分支；`FamilyMode` |
| 路由 | 每个节点固定绑定一个命名出站，暂无规则路由 |
| 用户与统计 | 管理账户与原生凭据分离；唯一计量边界；SQLite 用量/带宽/访问历史；`history` 查询。DNS 与错误事件未实现 |
| WARP | `kerlico-device` 库已实现并有真实双族验证；CLI 未接入，发行二进制不含 WARP |
| 双语 | CLI 帮助、错误和诊断完成；使用文档未完成 |
| 第三方合规 | `GPL-3.0-only` 已声明；统一第三方通知未完成 |

## 最新门禁

提交 `6a9661d`：门禁运行中，结果完成后写入此处。

此前最后一次全工作区测试为 `r116`：745 通过、0 失败、3 忽略。

## 已知互通差异

- **ShadowQUIC v2**：与固定版本 Mihomo 不互通；与受控 Go 参照 24 配置通过。
- **ShadowsocksR**：固定版本 Mihomo 同参数下会向 Rust 与 Python 两种服务端发出坏 MAC 流；Rust→Python 100/100。
- **Sudoku**：494 配置矩阵 18 项失败后已修订，修订后的 20 配置 740 项与 12 条 33MiB 大流通过，全矩阵未重跑。六类生命周期用例的参考客户端在双端同样停滞。
- **Tor**：公网字面 IPv6 未测。
- **MASQUE**：候选未合入，真实 Xray 映射矩阵有 8 项失败。

## 资料导航

[设计导航](docs/README.md) · [实现接口](docs/interfaces/README.md) · [历史测试记录](docs/testing/) · [协议与组合总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
