# HTTP 代理接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"username":"node-user","password":"synthetic-password"}`，`options`只保留可选TLS。每个HTTP请求独立校验唯一Basic头，命中成员后才取得PeerSession。无认证入口只用Local。
出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


日期：2026-10-31。首轮已编写，待 worker 统一验证。

`protocol-http` 注册 `http` 双端。出站选项为 `server: {host, port}`、可选 `auth: {username, password}`、可选 `tls: {server_name, ca_pem}`。入口options只含可选`tls: {cert_pem, key_pem}`，认证放在外层members。未知字段、空认证、用户名包含冒号或认证控制字符拒绝。`nodes` 中的远端节点必须配置独立认证；无认证本地代理使用单独的 `local_inbounds` 数组，字段与节点相同但必须回环监听。Basic 不加密，公网载体应使用 TLS。节点指纹参与同协议跨节点凭据去重，所有目标通过 PeerSession 建立。

出站执行 HTTP/1.1 CONNECT，完整读取最终 2xx 才返回流；头最多 16 KiB、临时响应最多 16 个，不能吞掉与头一起抵达的隧道数据。支持半关闭，不声明 UDP。TLS 验证服务端名称与证书，不提供跳过验证开关。

节点支持 HTTP/1.1 CONNECT 和 absolute-form 普通 HTTP 请求转发。CONNECT 要求显式端口，不接受请求体；普通请求要求 `http` scheme，Host 与 URI authority 一致。请求体、响应体由 Hyper 流式传递，去掉当前代理凭据、Connection 提名字段和逐跳字段，再为下游重建必要的传输边界。普通请求 Upgrade、HTTP/2/3 监听、扩展 CONNECT、CONNECT-UDP、Digest/NTLM 不在本轮交付范围。

TLS、请求头读取与目标建立受 connect_timeout 约束，活动连接由成功读写更新 idle_timeout；升级任务持有节点处理流程直到转发结束，强制取消时统一回收。服务端连接驱动和升级任务有有限跟踪集合，不将脱离节点管理的后台任务当作已完成退出。

研究见[HTTP 代理研究](../../reference/research_notes/http-proxy.md)，实际结果见[测试记录](../testing/http-proxy.md)。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

CONNECT 的升级失败、升级超时与任务接纳失败报告给已建立流。普通 HTTP 请求由一个 owner 保留完成权，分别观察响应 body、目标连接 driver、父连接和取消。Hyper 实际消费末帧或判断空响应后，只登记待写确认；对应前端底层 flush 成功且目标 driver 完成，才登记 `ProtocolEnd`。此前响应头或其他响应的 flush 不确认当前 body。前端 write/flush、body 或目标 driver 失败记录失败；未读完 body 被释放记录调用方关闭。最后一帧被取走或放入 Hyper 缓冲都不等于完成。

写确认依赖当前锁定 Hyper 1.12.0 的 HTTP/1 路径：[dispatcher](https://github.com/hyperium/hyper/blob/v1.12.0/src/proto/h1/dispatch.rs) 先消费响应头或 body，再交给写缓冲；[Buffered::poll_flush](https://github.com/hyperium/hyper/blob/v1.12.0/src/proto/h1/io.rs) 写尽缓冲后才调用底层 flush。本模块显式关闭 pipeline_flush，待确认集合有界，成功 flush 的代次只递增，不能回绕。升级 Hyper 时须保留最后 body 被消费后前端写失败、flush 失败及之前 flush 不提前确认的回归。

节点实际驱动任务登记到 `NodeTasks`，Engine 在外层 handler 被中止后仍能等待它们；这不替代原物理 peer 的取消与资源租约。新回归只已编写，尚未在 worker 运行。
