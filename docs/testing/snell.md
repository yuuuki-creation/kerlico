# Snell 验证记录

更新日期：2026-10-31。状态：r7 限定实现及同一 CLI 的最终矩阵已在 perf-02 通过；其他并行协议、未列角色及官方 beta 对端不继承本结果。

## 快照与环境

- Git 基线 `6cbb3f94356889ab6d7311253c40af5259e00364` 加本轮未提交增量；以本页源码、锁文件和二进制摘要固定实际快照。
- perf-02、Linux x86_64、Rust/Cargo 1.99.1，构建并发 2。全部编译、格式、静态检查、单元/集成及互通在 worker 执行，没有本地测试。
- 固定参考对端：sing-box 1.14.4，版本输出 Revision 为 `c005f35300ce76427dc285481ec5695f5b179cd2`，Go 1.26.10/Linux amd64；运行二进制摘要见下表。
- 独立向量：sing-snell `bc5a12ac736f235b2de2926ecd2791cc925e6b8c`，使用项目私有工作区的 Go 1.27.3 生成。工具链下载按 [Go 官方下载清单](https://go.dev/dl/?mode=json&include=all) 校验 SHA-256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40`；未改系统 PATH 或基础服务。
- 原始日志、配置、向量、锁副本和调试产物只保存在私有目录与 worker，不作为发行包。

| 对象 | SHA-256 |
| --- | --- |
| protocol-snell 模块树（含 Cargo.toml 与测试） | `80d3635eb48a684cdbe160773597f8afbba2e2a5c384361b446161f872d808aa` |
| 选定集成源码树 | `406a505739254e7783f29a5d55448abdba8a652bfa127066356c7b14abaa6e88` |
| 仅启用 Snell 的正式 CLI | `a3fb2ef0fe936fa2326e1a1bcefec42c5b08de176e875efc22a2bc0d0070005d` |
| 固定 sing-box 对端 | `fe23d7000aaaa91f40b63641a65a1a84d96b5f179c65b63f34893e238884cd5c` |
| worker Cargo.lock | `39e3e25ed0d1b6d94c03f64763849f2d3f83f10c707581b4934a80ac183d41ba` |
| interop_snell.py | `1a30c7d8bf348bf1594e70c0876c1e4b7a527b1cbdcc4e66c13be39f1a6ee174` |
| Go oracle 源码树（含 go.mod/go.sum） | `84aa3d1dd398de24fedd9facf646e710ee11a759040f964e209ae41e0565e704` |
| 64 组独立向量 JSON | `39ae21220c2bb693e01af962f99ef904668128c54fe11372a4bf03c4a98610a6` |

树摘要对相对路径按字典序排序，依次拼接“UTF-8 路径、NUL、文件原始内容、NUL”。选定集成树包含根 Cargo.toml/Cargo.lock，以及 app、core-api、config、net、egress、engine、protocol-snell 的 Cargo.toml 和 src 内 Rust 文件。摘要只证明该次源码与产物，不替代其他特性组合的整树验证。

## Rust、检查与独立向量

`snell-r7` 在 worker 执行：

```sh
cargo fmt -p kerlico-snell
cargo test -p kerlico-snell -- --nocapture
cargo clippy -p kerlico-snell --all-targets -- -D warnings
SNELL_VECTOR_FILE=<本次私有向量文件> cargo test -p kerlico-snell \
  --lib fixed_go_profile_and_cipher_vectors -- --ignored --nocapture
cargo build -p kerlico --no-default-features --features protocol-snell
```

结果：**8 项普通单元测试、6 项集成测试共 14 项通过**；严格 Clippy、格式和仅 Snell 的正式 CLI 构建通过。默认单测明确忽略一项外部向量测试；随后单独显式运行该项并通过 64/64 组 profile 参数及 KDF/AES-GCM 密文对照，未将“忽略”当成通过。实际模块输出包含 `outbound/snell` 与 `inbound/snell`。

向量由 worker 上的固定对端生成：

```sh
# 在项目私有 Go 工具链环境内运行。
gofmt -w tools/snell_oracle/main.go
go -C tools/snell_oracle mod tidy
go -C tools/snell_oracle run . -output <私有向量文件>
```

验证覆盖：

- v4 出站/v5 节点的 none/HTTP obfs，v6 default/unshaped/unsafe-raw，各自 reuse 开/关，共 10 个自端组合。
- 64 个 PSK 的三种 v6 记录模式；完整记录、独立零块、半关闭后继续记录、错误标签/AAD、截断、nonce 耗尽和盐重放/容量。
- 64 KiB TCP；0/17/4096/8192 字节 UDP，大包前按 v4/v5 窗口暖机，不通过拆包隐藏超限。
- 三次完整 TCP 逻辑连接在 reuse=true 时只建立一条物理连接；false 时建立三条；半关闭后继续收取目标回包。
- IPv6、域名目标和实际业务 peer 元数据；一个鉴权 UDP 载体内两个不同目标各自回写，地址与负载不混用。
- 错误 PSK/userkey、取消、角色/模式非法配置、raw 的真实鉴权指纹及跨节点凭据范围拒绝。
- 五种载体/模式的目标先发数据、域名 UDP 的 IPv4 优先结果、活动排空继续收发、有界退出与同端口重绑。
- 目标返回的 UDP 同样遵守节点包长限制：上限为 4 字节时，4 字节回写通过，8 字节回写在编码前拒绝并关闭该关联。
- 完整记录边界的物理 TCP EOF 正常结束业务；帧内 EOF 仍报截断，物理已关闭的载体不得回池。

## 固定 sing-box 双向真实 CLI

`snell-peer-r4` 在同一冻结 CLI 上执行：

```sh
python3 tools/interop_snell.py \
  --kerlico target/debug/kerlico \
  --reference <固定 sing-box 二进制> \
  --work-dir <本次私有结果目录>
```

**36/36 组通过**：

| 范围 | 组数 | 实际覆盖 |
| --- | --- | --- |
| v4 出站/v5 节点 | 16 | 双向 × none/HTTP obfs × reuse 开/关 × 单 PSK/多用户 |
| v6 default/unshaped | 16 | 双向 × 两模式 × reuse 开/关 × 单 PSK/多用户 |
| v6 unsafe-raw | 4 | 双向 × reuse 开/关；显式 userkey 多用户、回环限定 |

每组分别建立 PSK 独立的 IPv4、IPv6 节点；多用户时另配置独立 userkey，访问 IPv4/IPv6 TCP、UDP 和域名 UDP 目标；TCP 负载为 17/4096/65536 字节，另测目标先发数据、四路并发隔离、另一节点 PSK/userkey 拒绝与服务端退出。raw 未把不同 PSK 错当成有效鉴权，负例按实际 userkey 执行。

### v4/v5 固定对端 UDP 边界

首轮 `snell-peer-r1` 的 v6 20 组通过，v4/v5 16 组在 4096 字节 UDP 回写失败；独立诊断保留了实际 1402/1162 字节结果。固定对端 WriterMTU 与缓冲分配的证据见[调研](../../reference/research_notes/snell.md)。

最终矩阵按实际角色验证边界：本项目客户端到 sing-box v5 节点有效负载至 **1402 字节**；sing-box v4 客户端到本项目节点至 **1162 字节**。这些边界包含 literal IPv4、IPv6 与域名目标。none/非复用/单 PSK 的双方向另各在三种目标上保留 4096 字节被固定对端截短的负例，共 6 项；没有把截短回包算作原始数据报成功，也没有在本项目拼包或截断以掩盖限制。

v6 双方向矩阵通过至 8192 字节 UDP。零包已在自端覆盖，外部矩阵没有覆盖零包；固定 v4 客户端源码另有“响应记录至少 8 字节”的检查，不能从自端 IPv4 零包（7 字节地址头）结果外推该对端兼容。

### 失败与修复记录

首轮测试编译曾缺少 AsyncWriteExt 导入，静态检查曾指出 API 写法和测试排版；集中修正后通过。协议测试补充区分了“完整记录后的物理 EOF”和“帧内截断”，并复验已关闭载体不回池。`snell-peer-r2` 曾完成不含目标先发数据的 36 组，`r3` 补该项后通过；收尾又补充目标 UDP 回包的节点包长限制及直接回归，使用 `snell-r7` CLI 全部复跑，最终结果只采用 `snell-peer-r4`。

## 未覆盖范围

没有直接运行 Surge 官方客户端或官方 snell-server beta，也没有其他 OS/架构、性能或长时压力结论。v1–v3、v5 QUIC Proxy Mode、TLS obfs、外加 ShadowTLS/Restls/JLS 未实现；未来 beta 变化、未测数值边界和其他对端不继承本结果。多协议同进程与完整默认特性构建由主任务另行记录。
