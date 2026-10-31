# HTTP 代理双端研究

日期：2026-10-31。对应协议总表 P-02、K-L2。研究依据 [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)、[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)、[Basic 认证 RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html)；上游固定版本与角色差异见唯一总表。

本轮首轮范围为 HTTP/1.1 CONNECT 双端、入口 absolute-form 普通 HTTP 转发、Basic 认证、可选 TLS 代理载体、IPv4/IPv6/域名。HTTP/2/3 代理监听、扩展 CONNECT、CONNECT-UDP、Digest/NTLM 不在本轮交付项；不声明原生 UDP。普通 HTTP 请求体和响应体采用 Hyper 流式解析，不把分块传输当成原始字节隧道。

CONNECT 目标必须为带端口 authority-form，2xx 后保留隧道首包、半关闭和反向数据，非 2xx 不返回成功流。Proxy-Authorization 只用于当前代理鉴权，普通转发必须去掉；Connection 提名字段及其他逐跳字段不得泄漏下游。普通转发拒绝非 HTTP scheme、缺失 authority 和不一致 Host，不通过客户端任意 Host 改变实际目标。禁止歧义 framing；Hyper 负责 HTTP/1.1 消息边界与反走私解析。

无认证节点只允许回环，Basic 不是加密；公网使用还需 TLS 和独立凭据。节点只经 AccessService 建立目标流，接入/目标地址族独立。连接建立、HTTP 头读取、活动空闲、逻辑流预算、升级排空和取消均需可观察的有限边界。复用工作区现有 Hyper/Rustls/Serde/SHA-2/Base64，无新增外部代理实现或许可证选择。

首轮完整编码后统一 worker 验收：双向 CONNECT、明文/TLS、两种地址族、域名、Basic 正负用例、2xx 首包不丢、普通 GET/POST/HEAD/分块请求与响应、逐跳及认证字段剥离、错误 Host/URI/framing、半关闭、慢头、超时/取消、配置去重、活动升级连接排空和固定 Xray/sing-box 对端互通。未执行或未通过时不得登记支持。
