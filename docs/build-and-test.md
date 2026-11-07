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
| `perf-01` | 8 核 / 12 GB 内存 | Debian 13 (`x86_64`, Rust `1.99.1`, Docker) | 并行测试分片、整树静态检查与集成测试并发分担 |
| `perf-02` | 4 核 / 8 GB 内存 | Debian 12 (`x86_64`, Rust `1.99.1`, Docker) | **主力 Worker**：日常编译检查、发行门禁默认节点（`worker_gate.sh`）、Release 构建（`worker_release.sh`）、系统兼容性与互通测试 |
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
tools/worker_gate.sh perf-02 HEAD
```

它把提交同步到 worker 的独立工作区，依次执行 `cargo fmt --check`、严格 Clippy、全工作区测试、不在 workspace 内的 `zerotier-node` 与 `xray-transport` 测试（后者经 `tools/test_xray_transport.sh`）和 release 构建，结束后打印每步退出码、失败项和二进制 SHA-256。结果写入 [STATUS.md](../STATUS.md)。

日常修改默认用 `tools/worker_run.sh perf-02 '<命令>'` 在主力机 `perf-02` 上运行未提交的工作树，`--pull` 把 fmt、lockfile 等改动拉回本机；多模块或多批次验证可同时向 `perf-02`、`perf-01`、`perf-03` 并发派发不同测试分片以提高效率。

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
