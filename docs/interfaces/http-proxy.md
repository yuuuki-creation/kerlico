# HTTP 代理接口

日期：2026-10-31。首轮已编写，待 worker 统一验证。

`protocol-http` 注册 `http` 双端。出站选项为 `server: {host, port}`、可选 `auth: {username, password}`、可选 `tls: {server_name, ca_pem}`。入口选项为可选 `auth` 和 `tls: {cert_pem, key_pem}`。未知字段、空认证、用户名包含冒号或认证控制字符拒绝。`nodes` 中的远端节点必须配置独立认证；无认证本地代理使用单独的 `local_inbounds` 数组，字段与节点相同但必须回环监听。Basic 不加密，公网载体应使用 TLS。节点指纹参与同协议跨节点凭据去重，所有目标通过 AccessService 建立。

出站执行 HTTP/1.1 CONNECT，完整读取最终 2xx 才返回流；头最多 16 KiB、临时响应最多 16 个，不能吞掉与头一起抵达的隧道数据。支持半关闭，不声明 UDP。TLS 验证服务端名称与证书，不提供跳过验证开关。

节点支持 HTTP/1.1 CONNECT 和 absolute-form 普通 HTTP 请求转发。CONNECT 要求显式端口，不接受请求体；普通请求要求 `http` scheme，Host 与 URI authority 一致。请求体、响应体由 Hyper 流式传递，去掉当前代理凭据、Connection 提名字段和逐跳字段，再为下游重建必要的传输边界。普通请求 Upgrade、HTTP/2/3 监听、扩展 CONNECT、CONNECT-UDP、Digest/NTLM 不在本轮交付范围。

TLS、请求头读取与目标建立受 connect_timeout 约束，活动连接由成功读写更新 idle_timeout；升级任务持有节点处理流程直到转发结束，强制取消时统一回收。服务端连接驱动和升级任务有有限跟踪集合，不将脱离节点管理的后台任务当作已完成退出。

研究见[HTTP 代理研究](../../reference/research_notes/http-proxy.md)，实际结果见[测试记录](../testing/http-proxy.md)。
