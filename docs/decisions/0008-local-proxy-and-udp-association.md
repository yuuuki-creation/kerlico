# 0008 本地动态代理与两类 UDP 访问契约

状态：已采用，用户已授权任务内自主决定实现细节。日期：2026-10-31。该记录不表示用户逐项确认了新 API，也不代表全部协议已验收。

## 问题与约束

SOCKS/HTTP 的本机无认证入口与远端节点必须独立认证的要求不同，不能为接入本地应用取消节点认证校验。Snell 的域名 UDP 回包需要统一出口实际选择的业务 IP；TUIC 的 Full Cone association 又要求多个目标保持同一出口 socket，不能把多个固定目标通道拼起来冒充同一关联。所有目标访问仍须经过统一服务，优先 IPv4，不能让协议自己重新解析域名或创建网站 socket。

## 采用的实现

- 本机动态代理放在独立 `local_inbounds` 数组，强制回环监听且工厂必须明确允许；当前 SOCKS/HTTP 使用它。服务端 `nodes` 的非空独立凭据、跨节点去重规则保持有效。
- 原有 `DatagramChannel` 保留固定目标、负载和 EOF 语义，接收器可选报告业务 `peer_addr`。统一出口在解析并选定目标后提供字面 IP，不使用代理载体地址代替。
- 另外提供 `DatagramAssociation`，发送时指定目标、接收时返回业务来源与完整包。默认不支持；需要此能力的节点在配置阶段检查出口，不能回退直连或固定目标通道。
- 直连使用一个双栈 UDP socket，统一出口逐目标解析并保持 IPv4 优先。关联的身份、lease、并发、空闲、关闭归协议及节点生命周期管理；底层取消覆盖关联发送与接收。

备选的“取消节点认证检查”“在协议内解析域名”“每目标新建 socket 然后统称 Full Cone”均不能满足已有边界，因此未采用。该增量不实现路由语言、透明代理或 TUN。

## 影响与证据

核心、配置、net、egress 新增默认兼容的方法，既有固定目标调用者不必改为关联接口。直接出口不能建立双栈 UDP socket 的系统返回运行错误；不据 Linux worker 结果推定所有 OS 可用。协议接口与确切方法见[节点与出口接口](../interfaces/node-egress.md)。

依据为 [0005](0005-separate-nodes-unified-egress.md)、[SOCKS 研究](../../reference/research_notes/socks.md)、[Snell 固定源码研究](../../reference/research_notes/snell.md)、[TUIC 规范与固定源码研究](../../reference/research_notes/tuic.md)。Snell/TUIC 新模块仍各自按完整首轮、远端测试和修复流程推进，不继承公共层通过状态。

本轮 perf-01 已通过相应包级回归与严格 Clippy，包括同一端口跨目标和地址族、未预先联系来源回包、域名优先 IPv4、空包、取消及配置能力拒绝；HTTP 活动连接排空和 SOCKS 来源/目标预算回归也已执行。最终整树与新增协议验收另在 STATUS 和模块测试记录维护。
