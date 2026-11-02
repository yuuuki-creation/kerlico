# 项目协作约定

## 格莱斯准则（强制）

所有文档、说明、注释、提示、提交说明及对话遵循格莱斯合作原则：

- **质的准则：真实、有依据。** 区分事实、推测、建议与未验证项。
- **量的准则：信息适量。** 提供完成任务和判断结果所需的信息，省去重复、套话与防御性赘述，保留关键条件与边界。
- **关系准则：紧扣当前任务。** 直接回应当前问题与目标。
- **方式准则：清楚、有条理。** 先说结论与要点，再列依据；术语明确、结构清晰。

## 仓库、许可与语言

- **仓库与发布目标**：`yuuuki-creation/kerlico`。
- **许可证**：自有代码采用 `GPL-3.0-only`（见根 `LICENSE` 与 `docs/licensing.md`）；`third_party/` 与 `vendor/` 保留各自原许可与署名声明。
- **语言**：项目协作、架构文档与提交说明使用简体中文；技术标识、协议名、命令与代码关键字保留原文。正式发行目标支持简体中文与英语（覆盖 CLI 帮助、用户提示/错误、使用文档与发行说明）。

## 强制匿名规则

- Git 作者与提交者固定为 `Anonymous <anonymous@example.invalid>`，关闭 GPG/SSH 签名。
- 提交说明、协作者 trailer、文档、注释、文件名、示例、日志与产物中严禁包含个人姓名、用户名、邮箱、机器绝对路径、主机名或真实凭证。
- 提交前启用仓库级配置（`git config --local include.path ../.gitconfig`），通过 `.githooks/` 校验钩子检查作者身份与内容，禁止使用 `--no-verify` 绕过。详见 `docs/anonymity.md`。

## 架构与核心约束

- **单文件交付、模块化源码**：以 Cargo workspace 按职责和协议拆分库 crate，最终由 `apps/kerlico` 装配编译为单一可执行程序。
- **客户端与服务端一体**：同一可执行程序按配置启用客户端接入、服务端节点或同时启用两者；各协议入站/出站能力分别注册与验收（见 `docs/decisions/0006-unified-client-server-core.md`）。
- **独立节点与全局共享出站**：
  - IPv4 与 IPv6 接入节点分别建立，拥有独立的 `NodeId`、监听地址、凭据域、会话配额与取消域，拒绝跨节点复用认证秘密。
  - 同一个 `Engine` 运行实例只装配一个全局共享出站调度器（`EgressRuntime` / `Dispatcher`），统一持有命名出站实例表（支持多个并列远端代理）。
  - 调度器先区分**本地出网（`Local`）**与**远端分流（`Remote`）**：
    - `Local` 路径按节点配置的 `ipv4-only`、`ipv6-only` 或 `dual-stack`（默认 IPv4 优先）选择目标地址与设备出口；双栈缺少原生地址族时，目标设计由设备级共享 CF WARP（`Warp4` / `Warp6`）自动补齐。
    - `Remote` 路径保留原始网站域名/IP、端口与业务负载交由所选远端代理编码，本机不替远端解析网站域名；远端失败按协议返回或结束会话，不触发本机换族、换代理或回退直连。
  - 详见 `docs/node-egress.md`、`docs/decisions/0009-global-egress-dispatcher.md` 与 `docs/decisions/0010-node-egress-modes-and-warp.md`。
- **多用户与统计记录**：
  - 单节点支持多个独立用户，管理账户具备稳定 `UserId`、默认带 UUID 后缀的唯一用户名及 Argon2id 密码摘要；管理账户与协议原生凭据（`native_credential`）映射分离，保持各协议原生线格式。
  - 鉴权后绑定可信用户归属并贯穿共享 `Dispatcher`；业务流量在唯一计量边界计一次，分别投影至用户、节点、命名出站与 `Engine` 视图，载体与设备开销另列。
  - 目标范围涵盖逐用户流量、当前/平均/采样峰值带宽、在线来源及访问/DNS/错误记录的持久化与查询导出（见 `docs/statistics-and-users.md` 与 `docs/decisions/0011-users-statistics-and-access-records.md`）。

## 开发流程与编译测试环境

- **协议清单与开发循环**：
  - 协议支持范围与任务编号统一维护在 `reference/reports/三核心 协议 组合支持.md`，阶段路线见 `docs/protocol-roadmap.md`。
  - 协议开发固定执行“调研 → 完整首轮编写（代码与接口文档） → 远端测试 → 修改”（`docs/decisions/0007-protocol-development-cycle.md`）。
- **海外 Worker 构建测试与本机保护**：
  - 所有 Rust 构建、格式/静态检查、单元/集成测试、互通与性能验证统一在专用海外 worker（`perf-01`、`perf-02`、`perf-03`）的项目独立工作区执行；本机仅用于编辑、阅读、同步与 Git 管理。
  - 机器连接资料仅保存在被 Git 忽略且由钩子拦截的 `.private/machines/`（目录 `0700`，文件 `0600`），公开文档统一使用 `perf-01` 等中性别名。
  - 严禁修改或中断本机 Clash 配置、进程、系统代理、DNS 或路由，严禁改动海外 worker 上已有的 Runner、Docker、Mesh、监控与 SSH 服务。详见 `docs/build-and-test.md`。

## 当前发行与执行安排

- 按 `STATUS.md` 的完成计划逐版推进；已发布标签不改写，修复走新版本。
- 验证按 `docs/decisions/0012-simplified-delivery-and-verification.md`：发版跑一次 `tools/worker_gate.sh`，日常只测受影响 crate，全协议矩阵不是发版条件。
- 文档写当前事实和下一步，不写“不代表”“不外推”“不计通过”这类证据免责句；真实的协议限制和安全性质照常写明。
