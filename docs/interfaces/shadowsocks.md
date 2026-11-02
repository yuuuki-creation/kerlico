# Shadowsocks AEAD、基础与旧式流密码接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 AEAD 使用 `{"password":"协议密码"}`。旧式流密码及 none/plain 只作为 Local，members 为空，编码密码保留在 options.password。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


日期：2026-10-31。状态：本轮原生 TCP/UDP 双端已实现，通过完整方法自端矩阵和独立对端限定互通；精确范围见测试记录。

`kerlico-shadowsocks` 提供 `ShadowsocksFactory`、`ShadowsocksNodeFactory`，协议类型均为 `shadowsocks`。客户端与节点共用固定密码/加密依赖，节点持有独立凭据表和重放缓存，通过同一个共享 Dispatcher 访问目标。SS2022 继续使用 `ss2022`，本模块拒绝其方法名称。

## 配置

出站 options：

```json
{"server":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"synthetic-shadowsocks-secret"}
```

节点 options：

```json
{"method":"aes-128-gcm"}
```

每个 IPv4/IPv6 节点单独配置，凭据指纹分别覆盖密码与实际派生 key；跨节点重用同密码或同一有效 key 由注册表拒绝。旧式流方法及 none 额外要求 `allow_insecure:true`。旧式流密码及 none/plain 没有报文认证，不返回占位用户身份，不能放入要求独立凭据的 `nodes`；使用明确的回环 `local_inbounds`，字段相同，不能用 password 字段获得认证。该配置接线增量已通过 worker 配置回归、严格 Clippy、正式 CLI 和 none 的 24 项独立对端复验；密码算法与数据路径未改。字段严格解析，未知 plugin、transport、users、identity_keys 等均拒绝。非 none 的密码不能为空，UTF-8 长度不超过 4096 字节。

## 本轮方法范围

- AEAD：aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、aes-128-ccm、aes-256-ccm、aes-128-gcm-siv、aes-256-gcm-siv、xchacha20-ietf-poly1305、sm4-gcm、sm4-ccm。
- 旧式流：AES、Camellia 各自的 128/192/256 位 ctr、cfb1、cfb8、cfb128、ofb；另有 chacha20-ietf、rc4-md5、rc4、table。`*-cfb` 接受为 `*-cfb128` 别名。
- `none` 与 `plain` 是无加密模式别名。aes-192-gcm、未列方法拒绝。

以上为代码接受范围，验收结果按[测试记录](../testing/shadowsocks.md)逐项登记。旧式流密码没有报文认证，重放检查不会改变这一性质；rc4/table 与 none 没有随机 nonce，不能提供有效 nonce 重放保护。

## 数据与资源语义

TCP 出站在建立预算内解析代理地址、拨号并发送目标首部；返回时不代表远端目标已确认成功。空首部写入允许目标主动先发数据，保留写端 EOF 和反向排空。服务端解码目标后调用统一 `PeerSession::connect_tcp`；公网默认 IPv4 优先的目标策略由服务提供方负责。

UDP 出站每个固定目标通道使用独立连接式 UDP socket；源地址由内核限制为配置节点，返回报文还检查目标地址/端口。域名请求允许返回解析后的 IP。服务端按来源地址和目标分别建立关联，通过 `PeerSession::connect_udp` 访问目标。每个关联占节点和全局预算、32 包有界队列，空闲后回收；取消与关闭有时间上限。

最大业务包 65000 字节，线包不超过 65507 字节；零长度业务包与通道关闭不同。异常认证或目标格式无效的 UDP 包整包丢弃。TCP 上游重放策略设为 Reject；UDP 在成功解码后记录 salt/IV，缓存最多 65536 项、保留 120 秒，未过期满额时拒绝新 nonce。该有限窗口不是永久重放防护。

本轮不实现 SIP003 插件、SS over WS/TLS/REALITY、UoT、sing-mux、多用户 relay 或 SSR；不能机械套用 VLESS 组合。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

TCP 使用 `TcpFlow`。固定 UDP 的空闲分支明确记录 `Timeout`，取消记录 `Cancelled`，上游入队端关闭后仍保留接收窗口。外层加密与回包写失败由同一完成权报告，接收 future 不因上传活动被重新创建。候选认证任务和目标任务登记到 `NodeTasks`，它们不增加业务计量层。
