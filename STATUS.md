# 项目状态

更新日期：2026-11-02（Asia/Shanghai）

## 版本

最新发布：[v1.0.1](https://github.com/yuuuki-creation/kerlico/releases/tag/v1.0.1)，带 Linux `x86_64` 二进制。`main` 正在准备 `v1.1.0`。

构建基线：Rust `1.99.1`，Linux `x86_64`。

## 完成计划

| 版本 | 交付 | 状态 |
| --- | --- | --- |
| `v1.0.1` | 门禁通过；第三方许可通知；Linux 二进制 | 已发布 |
| `v1.1` | CLI 接入 WARP；规则路由；DNS 与错误事件历史；中英使用指南 | 代码完成，门禁中 |
| `v1.2` | `dns`、`tun`、`control` 模块 | 待开始 |
| `v1.3` | MASQUE，随后 OpenVPN、OpenConnect、Tailscale、ZeroTier、EasyTier；VLESS 混合 NFS 链、ML-DSA 验签、XUDP 跨载体迁移 | 待开始 |

验证规则见 [0012](docs/decisions/0012-simplified-delivery-and-verification.md)。跨进程设备 daemon/IPC 不在计划内，出现多进程部署需求时再排。

## 能力现状

| 能力 | 现状 |
| --- | --- |
| 协议模块 | 23 个进入默认构建：20 个双端，SSH、Gost Relay、Tor 仅出站 |
| 节点与出站 | 独立节点；单一 `EgressRuntime`/`Dispatcher`；`Local`/`Remote` 分支；`FamilyMode` |
| 路由 | `routes` 按域名、CIDR、端口、网络、节点和用户选择出站；多目标 UDP 关联走节点绑定的出站 |
| 用户与统计 | 管理账户与原生凭据分离；唯一计量边界；SQLite 用量、带宽、访问记录、DNS 与错误事件；`history` 查询 |
| WARP | `device` 配置启用；数据面用已保存身份在双栈机器上验证过，CLI 在真实单栈机器上的自动补齐未实测 |
| 双语 | CLI 帮助、错误和诊断完成；使用指南中英齐全；接口文档为中文 |
| 第三方合规 | `GPL-3.0-only` 已声明；发行附 `THIRD_PARTY_NOTICES.txt` |

## 最新门禁

`v1.0.1`（提交 `c7d0ef1`，`perf-01`）：fmt、严格 Clippy、release 通过；全量测试 745 通过、0 失败、3 忽略。

## 已知互通差异

- **ShadowQUIC v2**：与固定版本 Mihomo 不互通；与受控 Go 参照 24 配置通过。
- **ShadowsocksR**：固定版本 Mihomo 同参数下会向 Rust 与 Python 两种服务端发出坏 MAC 流；Rust→Python 100/100。
- **Sudoku**：494 配置矩阵 18 项失败后已修订，修订后的 20 配置 740 项与 12 条 33MiB 大流通过，全矩阵未重跑。六类生命周期用例的参考客户端在双端同样停滞。
- **Tor**：公网字面 IPv6 未测。
- **MASQUE**：候选未合入，真实 Xray 映射矩阵有 8 项失败。

## 资料导航

[使用指南](docs/usage.md) · [设计导航](docs/README.md) · [实现接口](docs/interfaces/README.md) · [历史测试记录](docs/testing/) · [协议与组合总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
