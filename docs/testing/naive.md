# Naive 验证记录

日期：2026-10-31。状态：**P-21 本文限定范围已在 perf-03 验收。** `native-r12` 的 26 项 Rust、严格 Clippy、格式检查、Naive-only 实际 CLI 与公开 API 探针构建通过；`interop-full-r1` 156/156 配置、900 条常规检查通过；同进程双端 28 条检查通过。14 条原对端包长/空包限制及 36 条原客户端 EOF 限制分别保留，不能把“156 配置完成”解释为这些负例通过。没有在本地构建、格式检查或测试，也没有验收当前全部工作区。

**1.0.0测试资产迁移增量已在perf-03新冻结复验通过。** `native-assets-r1` 完整26项、严格Clippy、fmt及限定CLI/探针构建终态0。公开CA证书未取得明确再分发许可，原DER已从源码移出，r12原始资产和通过快照仅在私有证据中保留。本次只调整准备工具及 `cfg(test)` 读取路径，生产拒绝集及TLS代码在 `cfg(test)` 之前的字节与r12一致；历史156配置互通仍明确属于r12，不冒充新资产准备步骤的验证。

| 新资产冻结项目 | 结果 |
| --- | --- |
| 正常HTTPS下载 | `application/x-x509-ca-cert`，Content-Length及原始body均876；DER/SPKI双摘要匹配 |
| 资产控制 | 6项通过：缓存只读复用，错误大小/同大小错误摘要缓存拒绝且不覆写，运行测试缺env/缺文件/错误摘要明确失败 |
| 完整Rust | lib9、dual11、h3_headers2、raw_peer4，共26项，0失败、0 ignore |
| 限定检查/构建 | 严格Clippy、fmt；移除资产环境变量后CLI与原生探针构建通过 |
| 新CLI SHA-256 | `0f0a68c6cddc9e9c38106e6c436985d0bd4b83a0f07bc792000d8b295fda5771` |
| 新探针 SHA-256 | `6eb4c665f564687ae2bc34ba449130f793c68466ebd1bced1c2c24f6420aafd6` |
| 新私有Cargo.lock | `9ecbf2b2158363794e17c3a1700c3b65df4227dbe7ee381177061906f5d1d31a`，与r12相同；共享根锁未覆盖 |

## worker测试资产准备

来源元数据为 `crates/protocol-naive/tests/fixtures/SOURCE.json`。固定官方HTTPS响应体必须是原始X.509 DER，恰为876字节，DER SHA-256 `0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19`，SPKI SHA-256 `49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f`。不接受PEM、重新编码或其他证书；工具记录实际HTTP类型和长度，内容变动立即失败。既有缓存仅以只读方式核对大小和两个摘要，不覆盖、修补或改变权限。

在专用worker的源码根目录执行：

```sh
KERLICO_WORKER_ONLY=1 python3 tools/prepare_naive_test_assets.py
export KERLICO_TEST_ASSETS_DIR="$PWD/.private/test-assets"
cargo test -p kerlico-naive
```

准备工具只使用正常TLS校验的固定URL，拒绝非HTTPS或跨主机重定向；资产保存在被忽略的 `source/.private/test-assets/naive/blocked-intermediate.der`。测试只读上述环境变量下的固定相对路径，先验证大小、DER与SPKI摘要，再执行拒绝集断言。环境变量缺失、文件缺失或摘要不符都明确失败，不能ignore、自动联网或使用仓库内编码副本替代。最终整树验证也必须显式先准备并设置该变量；这是测试数据依赖，不是产品运行依赖。再分发边界见[公开证书审计](../releases/public-certificate-review.md)。

## 冻结输入与检查

完整首轮先写齐生产、接口、Rust 测试与独立工具，再统一在 worker 构建、修正和复验。只纳入核心、配置、网络、出口、引擎、HTTP、Naive 与实际 CLI 的必要输入，未拉入其他协议 WIP。Cargo/Go 构建并发 1，顺序执行；参考 Go 构建设置 768 MiB 软内存目标，不改既有服务、系统证书或网络参数。

| 项目 | 结果或 SHA-256 |
| --- | --- |
| Rust 测试 | lib 9、dual 11、h3_headers 2、raw_peer 4，共 26 项通过 |
| 包级检查 | `cargo clippy -p kerlico-naive --all-targets -- -D warnings`、本包 fmt、实际 CLI 与 `naive_probe` 构建通过 |
| 首次及最终 Cargo.lock | 均为 `9ecbf2b2158363794e17c3a1700c3b65df4227dbe7ee381177061906f5d1d31a`；本项私有保存，未覆盖共享根锁 |
| 冻结 CLI | `ac438c0170dd1599b34d1b49f028934afe8f99dce5a2ef9b4346e1ee0697c390` |
| 原生 API 探针 | `1b7f9afcb1af1eac8c967063306450607f1cfd3494c9394a6fb0eb7e35451b36` |
| full 结果 JSON | `8ffd38ed421dff20d97130539e2729877a99c0d8a87e5b8ff3a4732e23b34790` |

共享 `third_party/h3` 原 CONNECT 修正的 perf-01 原语 16 项和旧 Naive r6 的 21 项输入保留。随后唯一性/顺序增量另通过 perf-01 原语 21 项；最终 headers 摘要为 `484e98d6507cc5abc6a7d1d03a8a2e9e36a33ca32258e2170b1fcf583a852805`，51 文件 src 集合为 `bc8781bbbb1dae4552ac663d83b4a622e56e1e51bd5f5d4a87e3bdbcd0e9cc9b`。r12 使用新输入，并通过实际 QUIC/QPACK 负例：请求重复 method/authority、普通头后伪头、响应重复 status，包含有效 TLS 和正常消息控制组。未宣称完整字段角色/trailer 规范覆盖。

## 真实对端与组合

两个方向分别指 **kerlico 客户端→参照服务器** 与 **参照客户端→kerlico 节点**。接入地址为 IPv4/IPv6，网站目标为 IPv4/IPv6/`localhost`；域名 echo 同时提供两族监听，实际解析交给访问服务或对应参照，不从接入地址族推定网站地址族。

| 独立参照 | 角色及组合 | 配置 | 常规检查 | 0/65507 边界 | 目标 EOF 后回包 |
| --- | --- | ---: | ---: | ---: | ---: |
| 固定源码导出 Go peer | 双向 H1/H2/H3，UoT v1/v2 | 72/72 | 468 | 144/144 | 72/72 |
| 原 sing-box v1.14.4 资产 | 其入站 H1/H2/H3、出站 H2/H3，UoT v1/v2 | 60/60 | 360 | 6/20；14 条限制 | 我方出站 36/36；其客户端 0/24 |
| 上游 Naive 服务端发布流程构建 | 原插件、Caddy 与两项固定随附补丁；我方出站 H2/H3，仅 TCP | 12/12 | 36 | 无 UDP | 12/12 |
| 原官方 NaiveProxy 资产 | 其客户端 H2/H3，仅 TCP | 12/12 | 36 | 不登记 UoT | 0/12 |
| 合计 | 限定角色、载体和数据能力 | 156/156 | 900 | 150/164 | 120/156 |

常规检查包含 TCP 257024 字节、适用路径的 12 个并发 TCP、UDP 17/1200/12000、Go 双向 Full Cone，以及 **156 个有界退出与同端口重绑场景**；并发、Full Cone、生命周期分别按语义组计数。不能把生命周期结果称为会话迁移。

Go peer 全部地址/载体/版本组合均实测 0 与 65507 字节。原 sing-box 的边界只在 IPv4 接入/IPv4 网站代表节点逐角色、载体与版本测试，其他地址组合只登记常规包长，避免重复既知限制或外推最大包长。每次静态 UDP 请求使用新本地流；边界后小包控制证明新关联仍可建立，不证明失败的原关联继续可用。

### 原对端限制

- **原 sing-box 服务器方向**：H1/H2/H3、两种 UoT 版本的空包通过；65507 字节超时。常规包长实测到 12000，未逐包长定位精确上限。
- **原 sing-box 客户端方向**：使用已核对固定源码的 `direct` TCP/UDP 入口，避免 SOCKS 额外头导致 65507 字节在本地 UDP 入口本身超过 IP 上限。0 字节超时，65507 字节返回 16384 字节。固定 sing 的 `common/buf/buffer_standard.go` 定义 `UDPBufferSize=16*1024`，其 direct listener 使用该缓冲读取 UDP，与截断观察一致；未把这个参考入口限制写成 Naive 线格式上限。
- **原客户端 EOF**：原 sing-box 客户端 24 个、原官方 Naive 客户端 12 个目标 EOF 后回复探针未通过；探针后新 TCP 控制流通过。Go 客户端→我方节点、我方客户端→全部选定参照服务器的对应路径通过。当前静态 `tcp_eof=false` 仍保守保留，严格 `require_remote_eof` 准入未启用。
- 固定 forwardproxy 的 H1 分支是无流填充转发；本模块 strict padded H1 与其不兼容，未纳入通过组合。Caddy H2/H3 不识别本项 UoT 保留域名，因此不登记 UDP。

## 同进程双端与原生回归

`coexist-r1` 用上述同一个 CLI，同时运行两个独立双族节点与六个 H1/H2/H3 客户端，每个节点各有 CA、私钥和 Basic 凭据；网站地址族与节点族交叉。TCP 257024、UDP 0/12000/65507、跨节点凭据拒绝、拒绝后的合法控制流、退出及四个节点监听端口的重新绑定，共 **28 条检查通过**。由 Rust 业务路径完成，没有 Go/Caddy/官方程序承载内核业务。

原生 26 项还覆盖同会话 24 个 TCP/UDP 并发、邻流释放、慢下载不阻塞其他流、空闲会话回收、实际流数预算/超时、同端口 TCP/UDP 默认监听与 ALPN、来源归一化、真实同一 Full Cone socket 跨目标/地址族及未联系来源回包。真实 Registry 拒绝 HTTP/Naive 复用整组 Basic 凭据，允许不同秘密，并拒绝不具关联能力的目标出口。

## 参照来源与历史失败

- Go peer SHA：`c99a61cf7eea18da948e21d70df2dcc152ad648ac054de201ebb0348ea9e70e6`。固定 sing-box 源码只在 worker 可写副本增加已有 padding codec 的导出函数，UoT 使用固定 sing 包；实际 QUIC 为 mod.12。这一路不冒充原 CLI 资产。
- Caddy SHA：`73a3b466fa68b4d18ab71ffabed3e6aa1ead140dcde937938fac6d17a3147291`。按固定上游发布工作流，对 Caddy v2.11.7 应用该插件仓库随附的 BBR/QUIC 与 idle-timeout 两补丁，实际 QUIC 为 mod.9；插件源码不改。原插件加 stock Caddy 因缺 `IdleTimeoutsFromContext` 的编译失败保留。
- 原官方 NaiveProxy v154.0.8037.49-5 SHA：`f86c52be454eebc9134aad476f3fe91fcf90df7200c3df262a4d0a3d2de85464`；归档按 GitHub release digest 校验。该固定构建 `use_nss_certs=false`，实际参考进程用 `SSL_CERT_FILE` / `SSL_CERT_DIR` 读取项目 CA，保留证书链、名称与签名校验。早先不适用的 NSS 探针和证书 -202 失败留在私有记录，NSS 不是运行依赖。
- 原 sing-box 资产 SHA：`1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`；实际 tags 含 `with_naive_outbound`、`with_quic`，不只凭版本字符串推定。

首轮编译中的 rand/rcgen/探针依赖修正、r4 半关闭 10/11、r8 取消 23/24、r11 来源归一化控制组失败均保留。修正包括 shutdown 等待编码器排空、flush 写入进度确认、永久取消唤醒、只对两个保留域名接受 wire 端口 0、IPv4-mapped 来源和固定目标归一化比较。r12 完整复验后才登记当前冻结范围。

基础矩阵 r3 为 18/26；定向定位 H1 测试会话上限 1 与尚存活的首个 UDP 关联冲突，按并发场景使用合法物理会话上限 16 后，r4 的 26/26 与 full-r1 均完成。H2/H3 仍固定一个物理会话做并发验证；没有把 H1 多物理连接说成复用。研究证据、许可及配置见[研究](../../reference/research_notes/naive.md)和[接口](../interfaces/naive.md)。

Chrome TLS/完整浏览器行为、动态证书政策、ECH、uTLS/REALITY、明文 HTTP/h2c、QUICv2/0-RTT、MASQUE、通用 V2Ray transport/mux 和原生业务 UDP datagram 不在本轮范围。固定范围的通过不外推其他版本、平台、跨地域网络、性能或整个项目。
