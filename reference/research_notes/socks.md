# SOCKS 双端实现研究

日期：2026-10-31。对应总表 P-01、K-L1；本文件记录本轮实现范围，不代表验证通过。

## 规范与范围

直接依据 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)、[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)、[SOCKS4](https://www.openssh.org/txt/socks4.protocol) 和 [SOCKS4a](https://www.openssh.org/txt/socks4a.protocol) 编写线协议，不复制参考项目代码。参考版本与方向边界沿用协议总表 P-01。新增依赖均为工作区已有的 Tokio、Serde、SHA-2 和内部核心；本轮不引入外部 SOCKS 实现或改变项目许可证状态。

本轮首轮完整范围：SOCKS4/4a/5 的 CONNECT 双端，SOCKS5 用户名密码协商与无认证模式，SOCKS5 UDP Associate 双端，IPv4/IPv6/域名地址。SOCKS4 只有 IPv4；4a 允许远端域名解析，二者均不提供 UDP。BIND、GSSAPI、UDP 分片重组不是本轮交付项，明确返回不支持或丢弃，不能由 CONNECT 成功推定支持。

SOCKS5 UDP 关联必须随 TCP 控制连接关闭而结束，按控制连接对端 IP 校验 UDP 来源；请求指定端口时固定端口，零端口时固定首个合法来源端口。每个目标经节点注入的 AccessService 建立独立数据报通道，并持有共享 StreamBudget 名额；目标数、包长、空闲、连接建立、取消与退出均受现有预算限制。FRAG 非零整包丢弃，不拼接或当作独立负载转发。

用户名密码在线路上不加密。无认证节点仅允许回环监听；非回环节点必须配置独立凭据。SOCKS4 userid 只是可伪造的请求字段，不作为公网安全认证，SOCKS4/4a 节点始终仅允许回环。SOCKS 出站可连接可信的远端代理；不将本协议描述为 VPN 加密。

## 验收矩阵

首轮实现及接口写齐后，只在 worker 统一运行：三版本双向 CONNECT、SOCKS5 三地址类型与零长度/大 UDP 包、多目标隔离、远端域名、正确/错误/缺失认证、不支持方法/命令/地址/分片、短读截断、连接失败回复、控制 EOF、来源 IP/端口拒绝、资源上限、空闲超时、取消、半关闭及节点凭据重复检查。真实对端使用固定 sing-box 或 Xray，双向分别记录；自端回环不能取代对端互通。
