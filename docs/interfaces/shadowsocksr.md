# ShadowsocksR 双端接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 `{"password":"基础协议密码","user":{"id":7,"password":"可选原生用户密码"}}`。user 可省略，同基础密码的显式 UID 共享原协议表。无鉴权组合只作为 Local，编码参数保留在 options。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


日期：2026-10-31。状态：完整首轮实现、接口、Rust 测试与工具已编写。r7冻结结果保留，r10标准17项检查后重复矩阵仍有首包EOF，未按完整范围验收。最新IV前缀状态修正已完成包格式、lib检查/严格Clippy及两个精确纯状态回归（各1项通过）；没有运行互通、历史抓包或完整矩阵，尚不能认定已解决记录中的首部HMAC失败。实际边界见测试记录。

`kerlico-shadowsocksr` 导出 ShadowsocksRFactory、ShadowsocksRNodeFactory、ShadowsocksROutbound、ShadowsocksRNode，类型为 `shadowsocksr`。内核业务路径全部为 Rust；Python/mihomo 仅供 worker 独立对端测试，不作为运行依赖或业务转发后端。

## 完整本轮范围

protocol：origin、auth_sha1_v4、auth_aes128_md5、auth_aes128_sha1、auth_chain_a、auth_chain_b。

obfs：plain、http_simple、http_post、random_head、tls1.2_ticket_auth、tls1.2_ticket_fastauth。后两个在所选固定基线共用格式，不额外宣称 fastauth 0-RTT。TCP 的外层为 obfs，其内为 cipher、protocol 和目标地址/业务；UDP 只走 cipher/protocol，不经过 TCP obfs。

cipher 共 39 个：AES 与 Camellia 各自 128/192/256 位 ctr、cfb1、cfb8、cfb128、ofb；chacha20-ietf、rc4-md5、rc4、table；再加 none、chacha20、xchacha20、salsa20、rc4-md5-6。cfb 接受 cfb128 别名。AEAD、SS2022、CBC、其他旧方法与所有 `_compatible` 降级模式拒绝。

具体方法接受范围、角色、组合与真实通过结果分别见[调研](../../reference/research_notes/shadowsocksr.md)及[测试](../testing/shadowsocksr.md)。

## 配置

客户端 options：

```json
{
  "server":{"host":"127.0.0.1","port":8388},
  "method":"aes-128-cfb",
  "password":"synthetic-node-secret",
  "protocol":"auth_aes128_sha1",
  "obfs":"tls1.2_ticket_auth",
  "allow_insecure":true,
  "user":{"id":7,"password":"synthetic-user-secret"}
}
```

服务端公共 options：

```json
{
  "method":"aes-128-cfb",
  "protocol":"auth_aes128_sha1",
  "obfs":"tls1.2_ticket_auth",
  "allow_insecure":true
}
```

同一节点的客户端与服务端材料必须一致；IPv4/IPv6 不同节点分别设置独立材料。所有字段严格解析。公共 method、protocol、obfs 必填，password 在认证节点的成员凭据或 Local 编码配置中必填；兼容旧式协议必须显式 allow_insecure=true。密码为非空、最多 4096 字节；客户端 UID 可用 user，或 protocol_param 的精确 `UID:password` 两段格式，不能同时填写，错误参数不会回退基准 key。服务端用户表最多 1024 个且 UID 不重复，只允许 AES/chain protocol。表非空时未知 UID 立即拒绝；表为空时为传统单密码模式，不承诺独立 UID 身份。

obfs_param：客户端 HTTP 为逗号 Host 列表，可用 `#` 后的文本设置附加头；ticket 模式为 SNI Host 列表。服务端 HTTP 为允许 Host 列表，ticket 模式的非空值为 1–86400 秒时间窗并覆盖相应 limits 值。plain/random_head 不接受非空 obfs_param。混淆不是 HTTP CONNECT，也不是证书 TLS；没有 insecure/CA/证书配置开关。

udp 默认 true，可关闭。客户端 limits 只允许 max_sessions（默认64，1–4096），接收直接使用有界 socket/单包缓冲，不提供无效队列开关。服务端 limits 允许 max_sessions、udp_queue_packets（默认16，1–64）、udp_queue_bytes（默认4194304，65536–16777216），另有 max_replay_entries（默认65536，64–1048576）、auth_window_secs 与 obfs_window_secs（默认86400，1–86400）。回放缓存满额拒绝新项，不驱逐仍有效的已验记录。

## 认证、注册和节点身份

只有实际存在认证的业务路径才可作为 nodes：TCP 需要认证 protocol 或 ticket-auth 混淆，UDP 需要 AES/chain 的追加 MAC。任一启用路径缺少认证时，凭据指纹为空并强制回环，只能放在 local_inbounds；不修改 nodes 必须有真实非空凭据的框架约束。关闭 UDP 后按实际 TCP 层重新判定。

因此，origin+plain/http/random_head 不是公网独立认证节点；auth_sha1_v4 即使 TCP 首部有 HMAC，其原生 UDP 也没有新增 MAC，开启 UDP 时仍按本地接入处理。none 本身不提供加密或认证，但仍必须派生协议 key；table 也按固定 SSR 的 16 字节派生材料进入变换。不得套用普通 SS none 的空 key 或 table 的原始密码路径。

节点指纹覆盖基础密码、实际派生 key 和真实用户材料，不因字段处于 base/user 不同位置而漏查重复。IPv4/IPv6 节点分别构造、分别认证，认证失败不换节点、不重放业务，也不退回 origin/plain。目标访问通过已绑定真实 UID/基础密钥成员的 PeerSession 进入共享调度器；限速和额度仍不属于本模块。

MAC/校验强度保留旧协议事实：V4 后续帧为 CRC/Adler32，AES 数据帧使用截断 MAC，chain UDP MAC 只有一个字节。已有初始认证不代表全程现代密码学完整性，allow_insecure 也不会补足这些协议性质。

## 数据、资源与生命周期

TCP 首部/握手完成写出后返回流，不把请求已发送说成目标已接纳。目标先发、写端 EOF 和反向排空分别验收。原始 socket、编解码状态、双向有界队列直接归流对象所有，随 AsyncRead/AsyncWrite 驱动；没有脱离 engine 的后台业务任务，丢弃即关闭底层流。

最新源码将非空IV单独到达保留在待收前缀中，直到至少有一字节cipher正文才建立接收解码状态；只有IV随后EOF按截断前缀处理，完全没有载体字节的正常空响应语义不变。握手回写先入写队列，缺少新增解密明文时不调用protocol解析。判空对象是协议编码字节，不是空业务帧；空业务帧仍需正常校验MAC和序号。此增量只完成限定lib和无网络状态验证，完整数据路径与历史EOF仍待整体验证。

HTTP 头最多 64 KiB，ticket 握手有明确长度上限，SSR 伪 TLS 业务 record 接受完整 u16 长度，protocol 帧和每方向队列有界。record/CRC/MAC/长度/时间/UID 出错即终止，不回显密钥、原始报文或未可信消息。random_head 的服务器随机回写没有长度和校验，兼容旧实现的首个 read 语义，不能从本机成功外推其任意网络分割行为。

UDP 固定目标通道和多目标关联复用一个节点载体 socket；服务端按来源与已验用户分会话，经 PeerSession::associate_udp 保留统一出口 socket、实际来源和 Full Cone 回写。单包业务最多 65000 字节，线包最多 65507；空包和关联结束不同。队列同时限制包数/字节，活动由双向成功 I/O 推进，空闲、关闭或取消回收会话。

TCP 的已验身份元组、ticket 随机标识和有效 IV 分开登记。UDP 有 IV 时验后记录 IV；none+chain 可识别完整随机认证包重放；none+AES 没有每包独立 nonce，无法把相同合法业务包和重放区分，不能宣称该组合具备完整 UDP 重放保护。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

TCP 使用 `TcpFlow`。UDP 关联明确区分 idle timeout、取消、接收结束和回包失败；入队端关闭不提前丢弃回复窗口。移除外层基于 `seen` 的第二次空闲取消，由真实关联的活动计时决定 `Timeout`，避免清理先改写成 `Cancelled`。关联和候选认证任务登记到 `NodeTasks`。
