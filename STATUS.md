# 项目状态

更新日期：2026-11-02（Asia/Shanghai）

## 版本

最新发布：[v1.2.0](https://github.com/yuuuki-creation/kerlico/releases/tag/v1.2.0)。`main` 正在准备 `v1.3.0`。

构建基线：Rust `1.99.1`，Linux `x86_64`。

## 完成计划

| 版本 | 交付 | 状态 |
| --- | --- | --- |
| `v1.0.1` | 门禁通过；第三方许可通知；Linux 二进制 | 已发布 |
| `v1.1.0` | CLI 接入 WARP；规则路由；DNS 与错误事件历史；中英使用指南 | 已发布 |
| `v1.2.0` | `dns`、`tun`、`control` 模块 | 已发布 |
| `v1.3.0` | MASQUE、OpenVPN、OpenConnect、Tailscale、ZeroTier、EasyTier；VLESS XUDP 迁移 | 门禁中 |

验证规则见 [0012](docs/decisions/0012-simplified-delivery-and-verification.md)。跨进程设备 daemon/IPC 不在计划内，出现多进程部署需求时再排。

## 能力现状

| 能力 | 现状 |
| --- | --- |
| 协议模块 | 30 个进入默认构建。双端 20 个；仅入站：TUN；仅出站：SSH、Gost Relay、Tor、MASQUE、OpenVPN、OpenConnect、Tailscale、EasyTier、ZeroTier |
| 节点与出站 | 独立节点；单一 `EgressRuntime`/`Dispatcher`；`Local`/`Remote` 分支；`FamilyMode` |
| 路由 | `routes` 按域名、CIDR、端口、网络、节点和用户选择出站；多目标 UDP 关联走节点绑定的出站 |
| DNS | `dns` 配置 UDP、TCP、TLS 上游和 hosts；暂无 Fake-IP |
| TUN | Linux 系统接口，不修改路由；目标只有 IP，域名规则不命中 |
| 控制 | 只读 HTTP 接口：健康、用量、在线、访问记录、计数 |
| 用户与统计 | 管理账户与原生凭据分离；唯一计量边界；SQLite 用量、带宽、访问记录、DNS 与错误事件；`history` 查询 |
| WARP | `device` 配置启用；数据面用已保存身份在双栈机器上验证过，CLI 在真实单栈机器上的自动补齐未实测 |
| 双语 | CLI 帮助、错误和诊断完成；使用指南中英齐全；接口文档为中文 |
| 第三方合规 | 发行附 `THIRD_PARTY_NOTICES.txt`；`third_party/zerotier-node` 为 MPL-2.0 |

## 最新门禁

`v1.2.0`（提交 `666d18a`，`perf-01`）：fmt、严格 Clippy、release 通过；全量测试 766 通过、0 失败、4 忽略。

## 已知问题

- **VLESS**：`xhttp-tls-h3-stream-one` 加 Mux 时 UDP 超时，基线同样存在，未定位。出站没有多目标 UDP 关联，不能作为 TUN 或 SOCKS5 UDP 的出站。
- **SS2022 EIH UDP 测试**：整树门禁中无回包失败过 2 次（共 9 次门禁），单独压测 1000 轮与整树 5 轮都未复现，原因未定位。测试已改为带新包序号重发，单个数据报丢失不再让它失败。
- **`Engine::bind`**：用 `connect_timeout_ms` 作为统计库初始化期限，设得很小时可能启动失败（推断，未抓到错误内容）。
- **TUN**：放开来源后，IPv6 链路本地来源发往组播的 UDP（如 mDNS）可能进入出站（读代码推测，未验证）。

## 已知互通差异

- **ShadowQUIC v2**：与固定版本 Mihomo 不互通；与受控 Go 参照 24 配置通过。
- **ShadowsocksR**：固定版本 Mihomo 同参数下会向 Rust 与 Python 两种服务端发出坏 MAC 流；Rust→Python 100/100。
- **Sudoku**：494 配置矩阵 18 项失败后已修订，修订后的 20 配置 740 项与 12 条 33MiB 大流通过，全矩阵未重跑。六类生命周期用例的参考客户端在双端同样停滞。
- **Tor**：公网字面 IPv6 未测。

## 资料导航

[使用指南](docs/usage.md) · [设计导航](docs/README.md) · [实现接口](docs/interfaces/README.md) · [历史测试记录](docs/testing/) · [协议与组合总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
