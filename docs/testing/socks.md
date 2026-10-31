# SOCKS 验证记录

日期：2026-10-31。基于 `6cbb3f9` 的开发工作树，全部构建与测试在 perf-01，Rust 1.99.1、Linux x86_64；没有本地编译或测试。

首轮被无认证节点校验拒绝后，增加与服务端节点分开的回环 `local_inbounds`。第三快照的 6 项 SOCKS 集成测试、4 项 HTTP 集成与 7 项引擎回归、格式、严格 Clippy 和双协议 CLI 构建通过；新增覆盖节点与 UDP 目标地址族交叉。代码格式化从 worker 取回。

固定 sing-box 互通首轮的 SOCKS TCP 全部通过；UDP 因工具共享函数参数变动产生 TypeError，属于未完成用例。修正后第三轮 SOCKS/HTTP 合并矩阵 52 项检查通过，0 项协议失败，4 项 SOCKS 服务端零长度 UDP 受参考入口限制而未验收。SOCKS 子集为 TCP 16 项、UDP 20 项通过；节点 IPv4/IPv6 与目标 IPv4/IPv6 交叉，4/4a 不安排其不支持的 IPv6 目标。

工具独立运行 sing-box 的 direct 入站→direct 出站→UDP echo，没有 kerlico 参与：两类目标均通过 3/12000 字节，零字节均超时。只在同一角色非零包已通过且独立对照复现的条件下，工具将零包记为 `reference_ingress_limited`，`pass` 为 null，不能算作通过。自端零包、空包与 EOF 区别已由 Rust 用例验证；kerlico 客户端→sing-box SOCKS 服务端的零包也通过。

正式工具为 `tools/interop_local_proxies.py`，参数 `--kerlico <固定双协议CLI> --peer <固定sing-box> --work <私有结果目录>`。最终整树与快照摘要仍待补充，新增业务 peer 元数据已通过出口和相关包级回归。

随后增加来源端口固定、控制连接 EOF 后动态 UDP 端口回收、目标数/全局预算、慢握手、截断、非法地址类型和连接拒绝回复回归；SOCKS 合计 8 项集成测试通过。相关公共层与 HTTP 合计 28 项包级测试和严格 Clippy 通过，包含新多目标关联；最终冻结整树复验独立运行。

固定参考为 sing-box 1.14.4，源码 `c005f35300ce76427dc285481ec5695f5b179cd2`，二进制 SHA256 为 `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`。上述 52+4 互通使用的双协议 CLI SHA256 为 `24780a7a4fbaa1986dfaeccef821b55f90bcc293ba35b3b721bd80bce2ef7006`，不能替代后续整树二进制摘要。

后补回归与修正分开记录：第 5 轮 SOCKS 9 项和 HTTP 7 项、严格 Clippy 与正式 CLI 通过，固定 sing-box 再次为 52 项通过、4 项参考入口限制；其中验证了跨地址族 UDP relay。随后修正控制关联的空闲截止时间，只由成功业务收发推进，非法 UDP 洪泛不续期；目标通道按双方向活动计时，单向持续发送不应关闭原目标 socket。第 7 轮 SOCKS **11 项**及严格 Clippy 通过，包含该资源行为和零端口错误回复。目标接收 future 在写端活动更新时保持固定，不因重设计时器丢掉可能已读半帧的数据。最后两项增量尚未纳入首批 r4 冻结二进制，最终整树复核继续单列。

待 worker 统一执行：`cargo fmt`、`cargo test -p kerlico-socks`、工作区检查及真实对端双向互通。已有测试覆盖三版本 CONNECT/域名/半关闭、UDP 空包与大包、控制退出、错误认证、无支持方法、BIND 拒绝、分片与错误来源丢弃、多目标以及配置边界。未运行的用例不能登记通过。
