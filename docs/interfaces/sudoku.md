# Sudoku 首轮接口记录

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"key":"synthetic-sudoku-seed-kept-secret"}`，认证节点options.protocol不再保存key。raw、legacy和split按候选表完成实际AEAD/KIP鉴别，WS先验证同一候选的MAC再验证KIP；候选失败不写入重放表。none仅用Local，options.protocol保留编码key，不能生成管理用户。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


更新日期：2026-10-31。用户已要求停止修复、保存快照。根/app已接双工厂；r4库49/49、预算1/1、HTTP6/6、Mux4/6及协议11/12通过，仍有三项期限失败。r5补充诊断及Clippy/fmt通过范围见[测试](../testing/sudoku.md)。最后两个性能源码文件未验证，不将当前配置当作完整验收功能。

## 角色与选项结构

双端共用独立protocol配置，出站另加server，节点由外层listen/outbound指定访问服务。已经写入的出站选项结构为：

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "protocol": {
    "key": "synthetic-sudoku-seed-kept-secret",
    "aead": "chacha20-poly1305",
    "table_type": "prefer_entropy",
    "padding_min": 10,
    "padding_max": 30,
    "pure_downlink": true,
    "custom_tables": [],
    "udp_enabled": true,
    "allow_insecure": false
  },
  "http_mask": {"mode": "legacy", "path_root": "", "http_version": "auto"},
  "multiplex": "off",
  "max_mux_streams": 32,
  "max_pool_sessions": 4,
  "pool_idle_ms": 30000
}
```

认证节点protocol使用相同的公开参数，key取自外层members；http_mask可包含mode、path_root及TLS的cert_pem/key_pem。节点另有max_mux_streams（默认32）、max_http_sessions（64）、http_session_ttl_ms（30000）、可选cover_fallback与可选multiplex / mux_option_padding配置。所有结构拒绝未知字段，不兼容Mihomo整份配置或其平铺别名。

key按固定参考规则规范化，不能由名称“公钥”推断可公开：有效seed就是共享秘密。32字节hex先按压缩点解释，随后才尝试主标量；64字节拆分标量恢复共同点。实际seed的指纹用于跨节点隔离，客户端UserHash不获得独立鉴权或配额身份。

aead仅AES-128-GCM、ChaCha20-Poly1305、none。none必须显式allow_insecure，仅回环字面出站和local_inbounds；它没有可靠AEAD鉴权，不能获得nodes准入。节点鉴权集合为空、秘密隔离集合仍包含实际seed，与其他Sudoku入口共享有效seed会在配置阶段拒绝；不能用隔离指纹授予公网鉴权资格。

table_type支持prefer_ascii、prefer_entropy、up_ascii_down_entropy、up_entropy_down_ascii；空值默认entropy。custom_tables最多16个，布局恰有两个x、两个p、四个v；全ASCII方向拒绝无效自定义布局。客户端随机选一表，服务端额外接纳必要的默认上行表，并按已认证hint选择下行。padding为0–100且min≤max；pure_downlink=false时使用packed下行，不等于业务UDP或会话复用。

表优化按64选四组合排名存放解码结果，全部288网格参与歧义判断，仅前256个唯一解可承载字节。每份不可变GridOrder的解码数组固定635376个u16，共1270752字节，随配置实例增长、不随流数量增长；另有puzzle列表。

## 载体与实际数据语义

首轮范围包含raw、legacy、stream、poll、auto、ws。raw/legacy不接受HTTP TLS开关；raw拒绝无效Host/path/HTTP版本字段。legacy仅发送HTTP/1.1伪装首部；stream/poll/auto是分离上传/下载，ws是标准HTTP/1.1升级。TLS仅为后四类，客户端分别给出server_name、可选ca_pem与HTTP Host，不改实际server地址，不跳过证书或名称验证。

Auto节点的legacy探测只匹配本节点path_root加根斜线的安全GET；无tunnel/upgrade字段且无正文才移交KIP。普通session/stream/ws API、其他路径或不安全正文仍交HTTP路由，不能因无tunnel字段就把所有HTTP请求当legacy。该修正待真实双节点回归复验。

http_version为auto/h1/h2；强制h2仅适用于TLS split。path_root必须单个至多64字节ASCII字母、数字、横线或下划线路径段；节点raw/legacy不接受无效路径门槛。WS签名使用固定规范路径/ws，包含时间及method/path；与完整HTTP路径前缀分开，early KIP数据放ed查询及X-Sudoku-Early响应。

multiplex=off关闭跨业务复用，同一split会话内部仍需上传/下载HTTP连接；auto只跨业务复用HTTP split传输；on启用真实Sudoku TCP多流。UDP走独立UoT关联，不把TCP mux开关排列重复计作UDP能力。每个UoT包保留目标/来源地址、包边界和零负载，普通IP包上限65507；节点通过统一DatagramAssociation访问目标，不以逐目标固定通道替代Full Cone。实际出口仍待验证。

每个出站实例在首次实际TCP连接成功后固定解析到的节点IP，后续raw、TLS、WS、split和建立期auto选择均使用该IP；HTTP Host和TLS名称另行验证。DNS变更需要重建出站实例或重启；认证失败不会切换到另一个解析地址或另一节点。

HTTP split的/session授权返回token、可选early响应和upload-seq能力。上传是有界、按token归属的串行任务，最多排队4批、每token最多2个物理上传正文；完整请求正文上限1MiB。只有完全相同的上一seq/正文可幂等重试，缺口、混合旧序号模式、同seq异正文拒绝。上传请求断开不取消已经接管的批次；批次超时或部分写失败关闭token，不重发半批。

HTTP传输池使用显式Tokio计时器和pool_idle_ms回收空闲连接；Hyper要求为pool_idle_timeout提供计时器，见[库接口](https://docs.rs/hyper-util/0.1.21/hyper_util/client/legacy/struct.Builder.html#method.pool_timer)。客户端HTTP头预算32KiB，单个HTTP/2发送缓存128KiB；这些限额仍须通过实际路径验证。

每token最多一个活动下载；尚未交给HTTP正文的原始块保留供下一pull，交付已不确定时关闭token。下载客户端只在正常完整HTTP响应结束后续拉，不重试断裂的部分响应。EOF由x-sudoku-stream-eof trailer单独表示，结束下载后仍可继续上传。fin幂等结束上传，close取消整个token；会话到期、节点退出和预算拒绝另行处理。

客户端发送fin后遇到HTTP传输错误、超时或5xx时，最多向同一token重确认一次，不重复上传业务数据；其他状态直接失败。只有收到200才确认上传EOF，重复失败仍锁存为失败，不把下行EOF当作上传确认。

下载请求显式发送TE: trailers；Hyper的HTTP/1服务端会丢弃未获允许的trailer，不能仅设置响应Trailer头就推定EOF能送达，见[实现](https://github.com/hyperium/hyper/blob/v1.11.1/src/proto/h1/conn.rs#L690)。H1/H2真实EOF路径均待本轮统一验证。

HTTP/1.1下载请求同时发送Connection: close，下载连接不进连接池。官方节点的下载响应声明keep-alive、写完即关闭，放回连接池的连接会让下一个请求收到RST。HTTP/2下Hyper去掉该头，下载继续与上传共用连接。

固定原生Go客户端不声明TE但读取该EOF trailer；H1 split服务端在Hyper前使用有界输入适配器，仅对本节点精确下载路径的HTTP/1.1 GET、唯一stream/poll模式且缺少TE时增加内部能力标记。原有TE不改，Content-Length/chunked正文及pipeline原样透传；拒绝歧义分帧，H2跳过适配器。Auto模式中的WS仅在真实OnUpgrade成功后切换原始透传，被拒升级仍按后续HTTP边界处理。没有修改原生对端或伪造业务EOF；适配器有7项纯状态/实际Hyper回归。

cover_fallback只获取配置网站固定根路径的GET/HEAD，限制3秒和1MiB，仅回写状态、Content-Type和正文。不会携带原请求的Cookie、鉴权头、路径、查询或二进制。legacy仅在尚未完成KIP握手且原HTTP方法安全时允许此页面回退；完成握手后目标连接失败不能触发回退。

## 已写入的状态与资源处理

记录层区分epoch与seq，随机初始化、双向HKDF/AEAD及32MiB更新，校验严格顺序与最多8的epoch跳跃；拒绝计数器回卷。接收保留部分记录，Rekey拒绝丢弃旧密钥明文。pure/packed编解码保留clue/bit进度，发送队列只保留一批，入站非法完整clue使载体失败。

UoT部分头/地址/正文进度保存在接收器。超限发送在写入前拒绝；发送中断取消整个关联，不能重发半包。固定目标包装不把代理端点当回包来源，IP地址规范化后比较；多目标关联保留真实逐包地址。

mux已写帧驱动、真实单载体多流、顺序Data/Fin、独立Reset、共同收包字节预算及每流队列上限。数据发送块32KiB，帧上限256KiB，每流接收队列4MiB、每物理会话接收配额8MiB；控制队列有界且限制连续优先处理，满队列不扩张后台任务。逻辑流取消不关闭其他流；传输结束前已收到Fin的合法尾部数据保留供读取。节点额外逻辑lease在接受前申请，生命周期仍须通过实际节点路径复验。

SudokuNodeFactory提供TCP及虚拟入口：Engine虚拟入口初始化一次全节点Scope、token注册表和后台接纳循环，物理入口通过watch等待就绪，避免丢失启动通知。raw/legacy直接业务占物理入口预算，HTTP token、WS升级和mux额外逻辑流取得同一全局/节点预算。WS升级任务归节点Scope，物理HTTP授权请求结束不取消已经移交的业务。预算关闭后拒绝新逻辑会话，HTTP连接发送排空通知；节点取消与有截止时间的排空清理所有实际任务。

普通raw/legacy/split TCP声明独立EOF；未启用真实mux的WS受Close整连接语义限制，不声明独立EOF。UDP启用时要求出口支持多目标关联；没有该能力的配置不能静默改用多个固定通道。

本接口记录描述源码结构，实际通过范围只见[测试记录](../testing/sudoku.md)，不得合计历史结果外推当前树。最后性能编码增量被中断，具体缓存结构与内存界限仍需恢复后审查/复验；没有继续构建或测试。来源与边界见[研究](../../reference/research_notes/sudoku.md)，后续须用户明确继续指令。

## 完成权与绑定元数据

底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

WebSocket 升级沿用原 peer 取消域，实际升级任务持 `PeerLease` 到退出。物理 HTTP handler 返回不会提前归还仍由升级连接占用的配额，也不会取消已移交的字节流。单 peer 取消仅结束该连接；节点取消仍结束该节点全部升级连接。节点 Runtime 从节点上下文装配，不保存首个 peer 的租约、地址或取消信号。

seed 候选选择验证完整 AEAD 与 KIP，不比较客户端 UserHash 和本地原始密钥字符串的摘要。规范化到同一 seed 的公钥形式、主标量和拆分材料继续服从同一认证与重放域；UserHash 不新增授权。此次移除了共享迁移中误加的 UserHash 相等条件，依据仍是既有固定参考探针与研究记录。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。

服务端虚拟 Runtime 的 Scope 将 HTTP 升级、split 后台任务、cover HTTP 驱动和 Mux 驱动的实际 future 登记到 NodeTasks；H2 服务端与客户端统一使用 ScopeExecutor，客户端 Scope 仍归命名出站 ServiceContext。裸 Mux 启动入口只编译进单元测试。登记拒绝关闭所属 Scope，不能另起未登记任务。Engine 的关闭确认仍要求外层 handler 和实际节点任务均已 join。
