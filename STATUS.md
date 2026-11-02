# 项目状态

更新日期：2026-11-02（Asia/Shanghai）

## 当前阶段与 1.0.0 发行状态

- **1.0.0 源码先行发布**：[v1.0.0](https://github.com/yuuuki-creation/kerlico/releases/tag/v1.0.0)（提交 `57f036c646d85ff71d78ba10aca8af52d1b7326c`）已于 2026-11-02 03:50 UTC 匿名发布，见[发行说明](docs/releases/1.0.0.md)。当前仅含源码，二进制产物待对应构建完成后补充；后续代码修复将通过新补丁版本发布。
- **恢复整树验证**：`r65` 整树 `all-targets` 检查退出 0；`r66` 构建和 `r67` 测试在上次暂停时主动终止，不计通过。恢复后的同一份 977 文件输入取得以下结果：
  - `perf-02`：`release` 构建（`r68`）退出 0，已冻结该输入二进制，尚未上传正式附件。
  - `perf-03`：整树 `all-targets` 测试（`r69`）已结束，686 通过、11 失败、2 忽略；失败分为 Mieru 7 项、Naive 1 项、SSR 配置回归 1 项、Tor 夹具 2 项。修订后分包复验通过，原失败记录保留。
  - `perf-01`：WireGuard 官方双端 8 配置、1194 项检查通过；Tor 公网双命名实例的域名、v3 onion、字面 IPv4、关闭与同状态重启通过。结果仅适用于各自记录的源码及配置。
- **本轮集成收尾**：统计持久化与历史 CLI、同进程设备所有者、双语接口、共用 IP/HTTP 载体和协议修订已合并。海外整树 `r116` 的 105 个测试程序汇总为 745 通过、0 失败、3 忽略；最后 core/CLI 增量 `r121` 的 8 个程序、39 项通过。11 个相关包的全目标严格检查 `r125`、TrustTunnel UDP 7 项复验 `r124` 及工作区格式检查通过。本轮按用户要求推送后暂停，未完成目标继续保留。
- **构建基线**：Rust `1.99.1`，Linux `x86_64`。

## 核心与近期修订进展

| 模块 / 领域 | 当前源码状态 | 最新验证结果 |
| --- | --- | --- |
| 全局共享出站与多用户账本 (`core-api` / `config` / `egress` / `engine`) | 已合入主工作树：配置 v2、唯一 `EgressRuntime`/`Dispatcher`、节点 `FamilyMode`、`TargetPolicy`、管理账户与内存态 `Telemetry` | `r63` 核心/出站/Engine 共 14 个测试程序、93 项测试全部通过（含回收死锁修复与完成权边界回归） |
| 统计历史与查询 | SQLite 原子初始化、绝对水位提交、访问及带宽保留、只读 JSON 查询已实现；永久写者持有连接至真实关闭，收据保留超期任务 | `r109` 12 个测试程序通过，`r110` 相关核心严格检查通过；`r113` 真实 CLI 重启、字节/FIN、SIGTERM、累计与筛选分页通过；独立 DNS/分类错误事件未完成 |
| 设备所有者与 WARP | `DeviceRuntime` 同进程多 Engine 共用一个原生线程/后端，Direct target 能力与 carrier 分离；已有身份复用模式拒绝缺失或不匹配状态 | 生命周期批次 97 通过、1 真实用例默认忽略；已有身份真实双族 HTTPS 与 UDP DNS 通过。首因/收据修复独立审阅通过；CLI 自动装配及跨进程 daemon/IPC 未完成 |
| 双语 CLI 与诊断 | 显式 `Language` / `RuntimeOptions`、中英帮助/参数错误/运行诊断、历史命令已实现 | 23 协议 CLI 配置错误与 6 feature 裁剪复验通过；最终目录 678/678 静态详情、695 译文键、2 格式模板，5 项目录门回归通过；完整用户文档双语仍待补齐 |
| H3 原生库与消费模块 (`third_party/h3` / `hysteria2` / `trusttunnel` / `naive` / `vless`) | 已合入经典 CONNECT 伪头修正、预算让出与 `GOAWAY` 发送进度修复 | `r48` H3 库 260 项全过；`r53` 四个消费模块共 19 个程序、161 项测试全过 |
| ShadowTLS (`protocol-shadowtls`) | 内层 AEAD 流包装与分域凭据已合入 | 包级 27 项通过；固定 sing-box 矩阵 108/108 通过（见[恢复记录](docs/testing/protocol-restoration-20261102.md)） |
| TrustTunnel (`protocol-trusttunnel`) | TLS H1/H2/H3 双端、固定 UDP 与 H2 无 ALPN 兼容已合入 | 包级 37 项通过；`r62` Mihomo 矩阵 258 通过、54 参考端限制、4 未测、0 失败 |
| ShadowsocksR (`protocol-shadowsocksr`) | 独立 protocol/obfs/cipher 及生成端修订已合入；已修正配置 v2 的旧测试断言并补齐 IPv6 诊断工具 | 新输入库 18 项、集成 9 项通过；固定 Mihomo 同参数可向 Rust 与 Python 发出含重复密文的坏 MAC 流，Rust→Python 100/100。原 `r61` 的 191/192 保留，不追认未抓包的旧失败根因；新 CLI 完整矩阵待跑 |
| Sudoku (`protocol-sudoku`) | 同 token FIN 响应丢失时有限重确认已合入，不重放 DATA；验证工具保留参考端边界 | 原完整 494 配置的 9484 通过/18 失败保留；修订后 20 配置 740 项及 12 条 33MiB 大流通过。六类生命周期参考客户端双端控制同样停滞，明确记为参考边界；新完整矩阵待跑 |
| Tor (`protocol-tor`) | 原生 Arti TCP 出站、目录权限校验与服务回收已合入；修正协议版本夹具 | `r82` 库 26 项、16 项机制测试及 `r85` 限定公网 CLI 范围通过；`r103` 上游嵌入模式两项测试通过，公网字面 IPv6 未验证 |
| WireGuard (`protocol-wireguard`) | 原生双端及共用纯 IP API、UDP 双族上限、载体计量与稳定服务首因已合入 | `r86` 固定官方双端 8 配置、1194 项通过；后续库/纯 IP/生命周期回归通过。最新发行输入仍须重跑真实矩阵，持续高丢包不计通过 |

## 既有协议验证汇总

以下模块已完成各自开发批次的限定范围验证（详见对应接口与测试文档）：

| 协议 / 模块 | 已实现范围与测试记录 | 文档入口 |
| --- | --- | --- |
| 双端框架与多节点联合运行 | 首批 8 模块 16 节点 81 项联合检查通过；第二批 11 模块 22 节点 111 项联合检查通过；凭据隔离契约 7 项通过 | [首批记录](docs/testing/protocol-batch-1.md)、[第二批记录](docs/testing/protocol-batch-2.md)、[凭据隔离](docs/testing/credential-isolation-contract.md) |
| VLESS | RAW/WS/HTTPUpgrade/gRPC/XHTTP、TLS/REALITY、Vision、Encryption、ML-KEM、XDRIVE、packetaddr、客户端 Mux；双端各 394/394 基础矩阵、ML-KEM 44/44、Vision 30/30、Mux 30/30、XHTTP 10/10、XDRIVE 6/6、packetaddr 4/4 通过 | [接口](docs/interfaces/vless.md)、[测试](docs/testing/vless-combinations.md) |
| AnyTLS | 原生 Rust TLS 双端、会话复用、padding、TCP/UoT v2；包级、CLI 集成及 sing-box 双角色测试通过 | [接口](docs/interfaces/anytls.md)、[测试](docs/testing/anytls.md) |
| SS2022 | 三算法双端 TCP/UDP、AES EIH 多用户与客户端身份链；8 项单元、88 项互通与 17 组 CLI 集成通过 | [接口](docs/interfaces/ss2022.md)、[测试](docs/testing/ss2022.md) |
| SOCKS / HTTP | SOCKS 4/4a/5 双端与 UDP（11 项）、HTTP CONNECT/普通转发双端（7 项）；固定 sing-box 52 项通过 | [SOCKS 测试](docs/testing/socks.md)、[HTTP 测试](docs/testing/http-proxy.md) |
| Shadowsocks (AEAD/legacy) | 45 方法自端、9 项单元与 312 项真实对端检查通过 | [接口](docs/interfaces/shadowsocks.md)、[测试](docs/testing/shadowsocks.md) |
| Trojan | 双端 TCP/UDP；11 项单元与固定 Xray 20/20 双向组合通过 | [接口](docs/interfaces/trojan.md)、[测试](docs/testing/trojan.md) |
| VMess | AEAD 双端；11 项单元、Xray 48/48 与 sing-box RAW 16/16 配置通过 | [接口](docs/interfaces/vmess.md)、[测试](docs/testing/vmess.md) |
| Snell | v4 出站、v5 节点与 v6 双端；14 项单元、64 组向量与 36/36 对端组合通过 | [接口](docs/interfaces/snell.md)、[测试](docs/testing/snell.md) |
| TUIC | v4/v5 双端与多目标 UDP 关联；9 项单元、144 项对端与 24 项生命周期检查通过 | [接口](docs/interfaces/tuic.md)、[测试](docs/testing/tuic.md) |
| Hysteria v1 | 双端 TCP/UDP；16 项单元、官方 24/24 与 sing-box 12/12 组合通过 | [接口](docs/interfaces/hysteria1.md)、[测试](docs/testing/hysteria1.md) |
| Hysteria2 | 原生 QUIC/H3 双端、UDP 关联与混淆；19 项库测试与 544 项 CLI 检查通过 | [接口](docs/interfaces/hysteria2.md)、[测试](docs/testing/hysteria2.md) |
| ShadowQUIC | 原生 JLS/QUIC 双端；v1 Mihomo 24 配置通过，v2 受控 Go 参照 24 配置通过（Mihomo v2 差异见测试文档） | [接口](docs/interfaces/shadowquic.md)、[测试](docs/testing/shadowquic.md) |
| SSH | 原生 `direct-tcpip` 出站；6 项单元、OpenSSH 140 项与 HTTP→SSH 200 项检查通过 | [接口](docs/interfaces/ssh.md)、[测试](docs/testing/ssh.md) |
| Gost Relay | 原生 CONNECT 出站（TCP/固定 UDP、TLS/SMUX v1）；15 项单元、官方 64 配置 704 条记录及 28 项 FIN 检查通过 | [接口](docs/interfaces/gost-relay.md)、[测试](docs/testing/gost-relay.md) |
| Mieru | TCP 双端、流复用与 Full Cone UDP 隧道；19 项库测试及官方/Mihomo 对端各 88 配置通过 | [接口](docs/interfaces/mieru.md)、[测试](docs/testing/mieru.md) |
| Naive | H1/H2/H3、padding 与 UoT 双端；32 项库/资产测试、156 配置 900 项检查与 28 项同进程检查通过 | [接口](docs/interfaces/naive.md)、[测试](docs/testing/naive.md) |

## 待完成项

1. **发行输入回归**：完成最新整合源码的验收记录、SSR 新 CLI 全矩阵、Sudoku 完整矩阵、WireGuard 最新输入真实矩阵及剩余组合验证；不以 `v1.0.0` 原构建或分包通过代替新版本验收。
2. **设备共享 CF WARP 自动补齐**：在已实现的同进程设备所有者之上完成 CLI 自动装配、跨进程同 binary daemon/IPC 与设备全局共享（见 [0010](docs/decisions/0010-node-egress-modes-and-warp.md)）。
3. **统计剩余范围**：补齐独立 DNS/分类错误事件日志与查询控制；现有用量/访问/带宽持久化不代表 [0011](docs/decisions/0011-users-statistics-and-access-records.md) 全部完成。
4. **完整多语言支持**：补齐完整使用文档、配置说明与发行说明的中英双语覆盖，整合后继续检查新增诊断。
5. **剩余协议与端点**：OpenVPN、OpenConnect、EasyTier、Tailscale、ZeroTier、MASQUE，以及 VLESS 混合 NFS 链/ML-DSA 验签/XUDP 跨载体迁移、独立 `routing`/`dns`/`tun`/`control` 模块。
6. **正式二进制发布与合规归档**：完成第三方依赖通知与对应源码归档核对（见[许可说明](docs/licensing.md)与[只读审计](docs/releases/1.0.0-readonly-audit.md)），上传与标签匹配的正式构建产物。

MASQUE 隔离候选尚未合入：标准自测通过，真实 Xray 映射矩阵八项失败，CF/L4 业务互通未测。跨进程设备 B 仅有设计快照。两者不登记为已支持。已验证范围及本轮限制见 [恢复批次记录](docs/testing/resume-20261102.md)。

## 资料导航

[设计导航](docs/README.md) · [实现接口](docs/interfaces/README.md) · [协议与组合总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
