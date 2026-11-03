# 编译、测试与专用 Worker 安排

更新日期：2026-11-02（Asia/Shanghai）

## 核心原则

1. **构建与测试统一在海外专用 Worker 执行**：所有 Rust 编译、格式与 Clippy 静态检查、Rustdoc、单元/集成测试、真实对端互通与性能测试均在专用海外性能机的项目独立工作区运行；本机仅用于代码编辑、文档阅读、同步与 Git 管理。
2. **保护本机与远端既有服务**：
   - 本机严禁修改或中断现有 Clash 配置、进程、控制接口、系统代理、DNS 或路由。
   - 远端 worker 仅在项目独立工作区运行测试任务，严禁停用或修改机器上已有的 Runner、Docker、Mesh、监控与 SSH 等基础服务，不使用正式业务机。

## 三台专用 Worker

公开文档统一使用中性别名，真实 IP、端口、用户名与基础设施对应关系仅保存在本地私有目录：

| 别名 | 硬件配置 | 系统与环境 | 主要分工 |
| --- | --- | --- | --- |
| `perf-01` | 8 核 / 12 GB 内存 | Debian 13 (`x86_64`, Rust `1.99.1`, Docker) | 整树静态检查（`cargo check`/`clippy`/`fmt`）、单元与集成测试 |
| `perf-02` | 4 核 / 8 GB 内存 | Debian 12 (`x86_64`, Rust `1.99.1`, Docker) | Release 构建、系统兼容性验证、固定上游对端互通测试分片 |
| `perf-03` | 8 核 / 8 GB 内存 | Debian 13 (`x86_64`, Rust `1.99.1`, Docker) | 整树全目标测试、大流量/高并发回归与隔离性能采样 |

默认构建依赖 `protoc`（上游 EasyTier 的 `build.rs` 需要）。`tools/worker_run.sh`、`worker_gate.sh`、`worker_release.sh` 通过 `tools/fetch_protoc.sh` 把固定版本下载到工作区并设置 `PROTOC`。

启动测试或构建作业前先检查当前机器负载与可用内存，合理控制并发度；性能采样期间避开其他高负载作业并记录环境参数。

## 本地私有凭证隔离（`.private/machines/`）

连接三台 worker 所需的私有资料存放在本地 `.private/machines/` 目录下（目录权限 `0700`，文件权限 `0600`）：

| 文件 | 用途 |
| --- | --- |
| `ssh_key` | 专用 worker 访问私钥 |
| `ssh_config` | `perf-01`、`perf-02`、`perf-03` 的 SSH 别名配置（通过 `ssh -F .private/machines/ssh_config <alias>` 连接） |
| `known_hosts` | 严格校验的主机公钥记录 |
| `inventory.json` | 真实地址、来源映射与机器资源记录 |

- `.private/` 目录已被根 `.gitignore` 忽略，且 `.githooks/privacy-check` 在提交和推送阶段均按路径强制拦截，确保凭证与真实主机信息绝不进入 Git 历史、日志或构建产物。

## 测试执行与记录规范

验证范围见 [0012](decisions/0012-simplified-delivery-and-verification.md)。

发行门禁一条命令：

```sh
tools/worker_gate.sh perf-01 HEAD
```

它把提交同步到 worker 的独立工作区，依次执行 `cargo fmt --check`、严格 Clippy、全工作区测试和 release 构建，结束后打印每步退出码、失败项和二进制 SHA-256。结果写入 [STATUS.md](../STATUS.md)。

日常修改用 `tools/worker_run.sh perf-01 '<命令>'` 在 worker 上运行未提交的工作树，`--pull` 把 fmt、lockfile 等改动拉回本机。

发行二进制用 `tools/worker_release.sh <版本> <提交> <输出目录>` 在 glibc 较低的 `perf-02` 上构建。

## 跨机矩阵

`tools/interop_cross_host.py` 在本机编排，把自身传到三台 worker 常驻，ssh 断开时回收它启动的进程。客户端 A 经本机 SOCKS 入口，节点或真实对端 B，回显目标 C，三种排列轮换。被测二进制放在三台的 xhost 工作目录，用 `perf-02` 构建，`perf-01` 的 glibc 版本更高，它构建的二进制在 `perf-02` 上跑不起来。

```sh
tools/interop_cross_host.py probe --network mesh --out probe.json      # 直连基线
tools/interop_cross_host.py check                                      # 只校验全部配置
tools/interop_cross_host.py run --jobs 2 --out dual.json               # 双端协议
tools/interop_cross_host.py run --only mieru,tuic/v5 --resume --retry-failed --out dual.json
tools/interop_cross_host.py prepare-outbound                           # 准备对端镜像和二进制
tools/interop_cross_host.py run-outbound --only ssh,tun --out out.json # 仅出站协议与 TUN
tools/interop_cross_host.py cleanup-outbound
```

公网入站被机器防火墙拦截，默认 `--network mesh` 走 Mesh 接口地址；`--network public` 走公网地址。`run-outbound` 不要并发多个实例。Windows 的 Git Bash 下运行要设 `MSYS_NO_PATHCONV=1`。结果 JSON 里的地址和路径已替换为别名。结果见 [2026-11-03 跨机矩阵](testing/cross-host-2026-11-03.md)。

## 逐协议深度测试

`tools/protocol_deep.py` 回答“哪里不对”：完整性、并发、鉴权负例、恢复、长连接、UDP、弱网、资源、优雅退出、多用户计量。它复用跨机矩阵的配置表和 agent，工作目录是 worker 的 `/srv/build/kerlico/deep`，只读 xhost 下的二进制。

```sh
tools/test_protocol_deep.py                                     # 工具自身的测试，不需要 worker
tools/protocol_deep.py check                                    # 校验全部载体的深度配置，打印从二进制得出的能力
tools/protocol_deep.py run --only ss2022/aes-128-gcm --placements 0,1,2 --expect-sha 0136fc5e --out deep.json
tools/protocol_deep.py run --only vless --scenarios integrity,auth --controls-from deep.json --out vless.json
tools/protocol_deep.py run --only ss2022/aes-128-gcm --scenarios resources --set resources_after_storm.storms=10 --out diag.json
tools/protocol_deep.py report deep.json --out deep.md           # 按协议分组，不含地址和密钥
```

`--only` 里带 `/` 的词是完整载体名，不带的按子串匹配。判定只有四种：`pass`、`fail`、`na`、`tool-error`。

**怎么读结果。** 每轮先跑全部对照，一个场景至少一个必然通过和一个必然失败的对照，失败对照还要命中预期分类。对照不符时该场景这一轮记 `tool-error`。协议失败后工具再测裸路径，路径不通记 `tool-error`，路径正常再复测一次，复测结果写在 `retest`。`--controls-from` 只在工具和二进制摘要都相同时接受。

**路径事实。** 裸 Mesh 不保留半关闭：客户端关写后连接随即结束，响应丢失（每轮的 `half_close` 基线记录实测值）。半关闭、空连接和配额释放场景所以只在同机回环上判定。弱网场景在两个 netns 之间用 tc netem，只碰工具自建的 veth。
