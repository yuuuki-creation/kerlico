# AnyTLS 双端实现调研

日期：2026-10-30。总表 P-15。本轮范围为原生 Rust TLS 双端、协议会话池/流复用、认证、TCP 与 UoT v2，不启动外部代理进程承载产品数据。

## 固定证据

- sing-box `c005f35300ce76427dc285481ec5695f5b179cd2`：[出站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/anytls/outbound.go)、[入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/anytls/inbound.go)、[依赖](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod)。出站要求 TLS，禁止 TCP Fast Open，UDP 经 UoT。
- mihomo `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`：[AnyTLS 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/anytls.go)。UoT v2 与自有会话复用，安全模式互斥；不外推任意 V2Ray transport。
- sing-box 所用 sing-anytls v0.0.11，固定提交 `130d2e61b8895727bfed4942c535e91b246a9603`：[握手](https://github.com/anytls/sing-anytls/blob/130d2e61b8895727bfed4942c535e91b246a9603/client.go)、[帧](https://github.com/anytls/sing-anytls/blob/130d2e61b8895727bfed4942c535e91b246a9603/session/frame.go)、[会话](https://github.com/anytls/sing-anytls/blob/130d2e61b8895727bfed4942c535e91b246a9603/session/session.go)、[池](https://github.com/anytls/sing-anytls/blob/130d2e61b8895727bfed4942c535e91b246a9603/session/client.go)、[padding](https://github.com/anytls/sing-anytls/blob/130d2e61b8895727bfed4942c535e91b246a9603/padding/padding.go)。许可 GPL-3.0-or-later；作为协议观察证据，kerlico 未链接或复制 Go 实现。
- sing `5dc452e537bf`：[UoT v2 请求](https://github.com/SagerNet/sing/blob/5dc452e537bf/common/uot/protocol.go)、[包帧](https://github.com/SagerNet/sing/blob/5dc452e537bf/common/uot/conn.go)。connect=false 包头地址编码不同于 SOCKS：IPv4=0、IPv6=1、域名=2；请求中的地址仍为 SOCKS 编码。

## 实现边界与依赖

客户端密码取 SHA-256，后接 u16 长度 padding；服务端仅查询本节点用户表，常量时间比较。会话帧为命令 u8、流 ID u32、长度 u16、负载。设置必须先于 SYN；v2 支持 SYNACK、服务端设置与心跳。FIN 终止全流，不能据此宣传远端 TCP EOF。连接池复用闲会话，活跃会话按实例隔离。

原生实现只新增 `md-5` 0.10（MIT OR Apache-2.0，用于 padding 方案指纹，非认证）和 `subtle` 2（BSD-3-Clause，常量时间比较）；其余沿用工作区 Tokio、rustls/ring、tokio-rustls、sha2、rand、serde。worker 已核对实际解析为 md-5 0.10.6、subtle 2.6.1；精确版本由最终 Cargo.lock 固定。没有新增系统组件或 Go 运行时依赖。

验收矩阵分别记录入/出站、TCP/UoT v2、IPv4/IPv6 地址和错误认证。上游静态支持不等于 kerlico 已验证。接口与结果分别见 [接口](../../docs/interfaces/anytls.md) 和 [验证](../../docs/testing/anytls.md)。

本轮结果：原生双端与固定 sing-box v1.14.4 双向互通已在 perf-03 通过；具体数据包大小、角色与地址族边界见验证记录。尚未执行 mihomo 程序互通。
