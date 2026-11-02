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
