# HTTP 代理双端接口

更新日期：2026-11-02（Asia/Shanghai）。验证结果见 [HTTP 代理测试记录](../testing/http-proxy.md)。本模块采用配置 v2 与全局共享 `Dispatcher`（`TargetPolicy::Remote`）；节点成员凭据 `members[].native_credential` 格式为 `{"username": "<用户名>", "password": "<协议密码>"}`，节点 `options` 仅保留可选 TLS。每个 HTTP 请求独立校验唯一 Basic 头，命中成员后取得 `PeerSession`；无认证入口仅作为回环 `local_inbounds`。

`protocol-http` 注册 `http` 双端。出站选项为 `server: {host, port}`、可选 `auth: {username, password}`、可选 `tls: {server_name, ca_pem}`。入口 `options` 只含可选 `tls: {cert_pem, key_pem}`，认证放在外层 `members`。未知字段、空认证、用户名包含冒号或控制字符均拒绝。Basic 不加密，公网载体应启用 TLS。

出站执行 HTTP/1.1 CONNECT，完整读取最终 2xx 才返回流；响应头上限 16 KiB、临时响应上限 16 个，保留与响应头同时抵达的早期隧道数据。支持半关闭（`tcp_eof = true`），不声明 UDP。TLS 严格验证服务端名称与证书。

节点支持 HTTP/1.1 CONNECT 和 absolute-form 普通 HTTP 请求转发。CONNECT 要求显式端口且不接受请求体；普通请求要求 `http` scheme 且 `Host` 与 URI authority 一致。请求体与响应体由 Hyper 流式传递，剥离代理认证、Connection 提名字段和逐跳（hop-by-hop）字段。不支持普通请求 Upgrade、HTTP/2/3 入站监听、扩展 CONNECT、CONNECT-UDP 或 Digest/NTLM。

## 完成权与写确认契约

- CONNECT 的升级失败、升级超时与任务接纳失败报告给已建立流；节点连接驱动与升级任务登记至 `NodeTasks`。
- 普通 HTTP 请求由单一 owner 持有完成权，同时观察响应 body、目标连接 driver、父连接与取消状态。Hyper 消费末帧或空响应后先登记待写确认；仅当对应前端底层 `flush` 成功且目标 driver 完成时才报告 `ProtocolEnd`（依赖 `hyper 1.12.0` HTTP/1 路径并显式关闭 `pipeline_flush`）。前端 write/flush、body 或目标 driver 失败记为失败；未读完 body 即被释放记为 `ClosedByCaller`。
