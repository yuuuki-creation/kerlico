# 上游借鉴到本项目设计的映射

更新日期：2026-10-30。本文整理已有固定版本调研，未进行新一轮上游核验、构建或实测。固定基线、许可证观察与来源异常以 [reference/README.md](README.md)为入口。

表中的本项目落点均是**设计草案**。本轮没有把任何条目标为已确认技术决策、已实现或已验证；“借鉴”不表示复制代码，也不表示完全兼容其配置或行为。

## REF-001 元数据与目标演进

**问题：**原始目标、嗅探域名、规则匹配目标和拨号地址怎样保留，避免互相覆盖。

**证据：**[mihomo Metadata](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go)、[Xray session](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/session/session.go)。两者提供区分目标信息的参考，具体字段语义见独立调研。

**Rust 落点：**[核心契约](../docs/core-contracts.md)中的分阶段上下文；借鉴信息责任，不复制一个全局可变上下文。

**待验证：**嗅探只参与路由时不改变拨号目标；Fake-IP 恢复保留原始地址；并发任务不串改会话。

## REF-002 TCP 与 UDP 的不同语义

**问题：**如何统一调度，同时保留流半关闭、包边界、逐包地址和回写上下文。

**证据：**[mihomo adapters](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)、[mihomo UDP/连接管理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/connection.go)、[Xray buffer](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/buf/buffer.go)。

**Rust 落点：**[数据路径](../docs/data-paths.md)中的流/包分离、UDP 关联/目标流/端点与缓冲所有权。这三个层级是本项目的建议表达，不声称上游具有完全相同的模型。

**待验证：**TCP 单向 EOF、首包不丢不重、UDP 多目标回写、并发建立合并、超时与有界队列回收。

## REF-003 工厂、装配与部分失败清理

**问题：**新增协议怎样尽量不改核心，模块启动到一半失败时怎样退出。

**证据：**[sing-box registry](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[Box](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)、[lifecycle](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/lifecycle.go)。

**Rust 落点：**[协议模块](../docs/protocol-modules.md)的显式注册、私有配置构造计划，以及[生命周期](../docs/runtime-lifecycle.md)的依赖顺序与清理责任；不照搬 Go 注册实现。

**待验证：**第二个协议的改动范围、缺失能力的配置错误、依赖环检测、部分资源取得后的清理。

## REF-004 策略组、资源提供器与观测

**问题：**节点从哪里来、如何选择、是否健康，三件事怎样分开。

**证据：**[mihomo provider](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/provider/provider.go)、[sing-box selector](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group/selector.go)。两者不是同一种订阅或 provider 模型，不能直接视为等价。

**Rust 落点：**[总体结构](../docs/architecture.md)的 policy 责任与[生命周期](../docs/runtime-lifecycle.md)的新会话选择视图；是否首批实现仍待产品范围决定。

**待验证：**候选更新失败保留有效视图、健康结果不过期串用、选择变化不自动重放已发送业务数据。

## REF-005 协议、传输与安全边界

**问题：**哪些能力可共用，哪些组合需要显式约束。

**证据：**[Xray 协议配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[stream 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)。

**Rust 落点：**[协议模块](../docs/protocol-modules.md)与 net 的复用边界。可复用连接/安全能力与协议握手分开；不能假定任意代理、传输与安全层都可组合。

**待验证：**支持组合有明确能力约束，不支持组合在建立前被拒绝，协议特有语义不因抽象而丢失。

## REF-006 DNS、Fake-IP 与状态使用期

**问题：**域名恢复和 DNS 路由怎样配合，映射何时可回收。

**证据：**[mihomo enhancer](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/enhancer.go)、[sing-box 路由恢复](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[Xray 路由解析](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/router.go)。

**Rust 落点：**[DNS/Fake-IP 数据路径](../docs/data-paths.md)与[资源生命周期](../docs/runtime-lifecycle.md)。独立映射所有者、lease、缓存分区与宽限是本项目建议，不据这些链接声称已证明其正确性。

**待验证：**解析依赖环、跨代缓存、旧会话映射不被复用、池耗尽与状态迁移。

## REF-007 更新能力需要逐项定义

**问题：**哪些变化可发布新快照，哪些需要替换实例或重启。

**证据：**[mihomo executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[sing-box CLI](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go)。调研发现不同的更新顺序和重建边界，不能合并描述为事务式无损重载。

**Rust 落点：**[配置代次与更新分类](../docs/runtime-lifecycle.md)。固定会话代次、独占资源检查与 RequiresRestart 是本项目的候选规则，不是直接移植来的保证。

**待验证：**更新失败、迟到任务、旧资源保活、连续更新容量和平台补偿失败。

## REF-008 TUN 核心与宿主边界

**问题：**设备、用户态栈、权限、防回环和系统网络设置分别归谁。

**证据：**[sing-box PlatformInterface](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/libbox/platform.go)、[Xray TUN 入口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)。平台差异与源码/网页冲突见 [sing-box](research_notes/Rust%20VPN%20内核参考调研/sing-box.md)、[Xray](research_notes/Rust%20VPN%20内核参考调研/xray.md)独立记录。

**Rust 落点：**[总体结构](../docs/architecture.md)的 tun/platform 分层及[生命周期](../docs/runtime-lifecycle.md)的 FD 所有权。当前不选择上游某个栈，也不把 Go 栈当成已可直接复用的 Rust 组件。

**待验证：**首批目标 OS 的真实接流、FD 移交/复制/借用、MTU/IPv6、退出恢复与网络切换。

## 后续维护

已有条目保持稳定编号；发现证据有误时注明修正，不静默换成另一个上游版本。新版本调研另存记录，映射说明所用基线。用户明确确认某项选择后补上决策链接；实现与验证进展链接到 [STATUS.md](../STATUS.md)，不直接把整篇调研标成“已实现”。
