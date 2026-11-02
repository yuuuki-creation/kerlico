# Gost Relay 出站接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


2026-11-01架构补充：本文描述现有实现。下述网站域名由Egress预解析及固定目标匹配行为尚未迁移到[0010远端原目标透传](../decisions/0010-node-egress-modes-and-warp.md)；迁移时须明确拒绝不能保留目标语义的组合，不能静默本地解析。共享调度器、节点模式和设备WARP也未据此验收。

更新日期：2026-10-31。首轮代码、接口和工具写齐后，15项Rust、严格Clippy、fmt和专用CLI构建已在worker通过；官方64配置704条记录及28项FIN阶段通过，限定范围与官方UDP边界见测试记录。

工厂 `GostRelayFactory`，出站 type `gost-relay`，Cargo feature `protocol-gost-relay`。仅出站 CONNECT；TCP与固定目标UDP经TCP流传输，UDP不是物理原生UDP，不提供多目标Full Cone。没有 Relay 节点工厂、BIND、Unix/串口或外部业务子进程。

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "username": "synthetic-user",
  "password": "synthetic-password",
  "mux": true,
  "response_mode": "eager",
  "tls": {
    "server_name": "relay.test.invalid",
    "ca_pem": "合成测试证书的 PEM"
  }
}
```

`server` 必填；`username`/`password`默认空，各最多255字节，至少一个非空就发送原始认证feature。二者均空省略认证，不能从配置字符串推断服务端已验证身份。TLS严格验证证书和名称，ca_pem可省略而使用内置公共根；示例PEM占位必须替换有效材料。无TLS的非字面回环端点必须明确 `allow_insecure=true`，TLS模式拒绝该标志；不存在skip_verify字段。未知字段拒绝。

`mux` 默认false；true使用SMUX v1，每次连接新建物理会话和单个逻辑流，匹配固定Mihomo出站，不声称跨网站共享会话池。官方MTCP节点默认版本2，不在本轮范围；固定官方JSON配置应使用字符串 `mux.version: "1"` 明确选择v1，数字1会被其GetInt忽略。MTLS默认v1，工具仍显式配置字符串。发送记录最大32768字节，接收最大65535字节，读写保留实际帧进度，满载时背压。

`response_mode` 默认eager，在连接方法内读取成功响应；官方节点需 `nodelay=true`。deferred允许先发送业务，首次TCP读/UDP收包先校验响应，适配官方默认合并成功响应的节点。deferred返回流时鉴权尚未确认，拒绝/超时在响应读取阶段返回，不重放业务；响应阶段只使用建立总预算剩余时间。目标先发数据不被响应解析吞掉。

可选 `forward_target:{host,port}` 必须IP字面量，表示已知固定转发网站。请求目标完全匹配才省略地址feature；不匹配在拨号前拒绝。网站域名由公共Egress默认IPv4优先解析，其实际选中IP也须匹配；不能把server字段当网站目标，不能忽略任意网站请求进行固定转发。

UDP每包两字节大端长度，0字节合法；本项目固定目标IP包上限65507字节，超限拒绝且不截断。来源元数据返回网站目标，不能返回Relay端点。分帧接收支持select取消后继续读取；发送中断毒化整个关联，禁止重发半包。`associate_udp`明确拒绝，不回退直连。节点接入、代理端点、网站地址族仍各自独立。

只有无TLS、无SMUX的原始载体声明TCP半关闭能力；TLS与SMUX保持保守false。实际官方对端的半关闭、零包和大包行为需分别实测，不能由线格式或本项目假对端代替。取消唤醒两方向，所有任务均为调用者持有的I/O future，无后台池；丢弃流/UDP两半释放实际socket。

详细来源与本轮矩阵见[研究](../../reference/research_notes/gost-relay.md)，结果见[验证记录](../testing/gost-relay.md)。

## 连接结果元数据

本轮返回类型迁移已编写，尚未运行新输入。`Outbound::connect_tcp` 返回 `OpenedTcp { stream, info }`。本协议没有可证实的业务目标绑定字段，`info` 明确为 `TcpConnectInfo::unknown()`，不使用 SSH 或 SMUX 载体地址代填。Dispatcher 返回业务层 typed flow 并负责唯一计量；本模块不创建第二份完成权或账本。底层固定 UDP 接口及原有未支持能力保持准确边界。
