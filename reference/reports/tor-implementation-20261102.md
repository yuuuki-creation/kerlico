# Tor 原生出站研究

记录日期为2026-11-02。对应协议总表P-23。本轮选择嵌入Arti的原生Rust客户端TCP出站。首轮评审修订已经编写，当前修订尚未验证；早期输入的检查与Tor库14项通过单列在[测试记录](../../docs/testing/tor.md)，没有真实Tor网络互通结果。

## 固定来源

| 来源 | 固定输入 | 本轮用途 |
| --- | --- | --- |
| Arti | `arti-client 0.47.0`，发布提交`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087` | 原生Tor客户端、隔离电路、bootstrap与错误语义 |
| Arti runtime | `tor-rtcompat 0.47.0`，同一提交 | `Runtime`、`CompoundRuntime`、`Spawn`、`Blocking`与网络提供方 |
| Tor协议 | [Closing streams](https://spec.torproject.org/tor-spec/closing-streams.html) | `RELAY_END`整流关闭，不能声明目标TCP半关闭 |
| sing-box | `c005f35300ce76427dc285481ec5695f5b179cd2`的[Tor出站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tor/outbound.go) | 核对仅TCP角色及外部或嵌入C Tor路径，不复用其数据面 |

2026-11-02查询crates.io，最新非撤回`arti-client`发布为0.47.0，发布日期2026-10-01。官方[Arti 2.7.0发行说明](https://blog.torproject.org/arti_2_7_0_released/)对应本次库发布，包含安全修复。后续发行前仍须重新核对版本与公告，不能把本次固定版本长期视为最新。

从官方发布包直接读取`.cargo_vcs_info.json`。下载内容只缓存到被忽略的`reference/.upstream/`。已读取的压缩包摘要如下。

| 包 | SHA256 |
| --- | --- |
| `arti-client 0.47.0` | `43e6531f26fe6f44d71dabdc63b7845bae81547cc738aa942f0e3e482f776388` |
| `tor-rtcompat 0.47.0` | `99036f7a4fa9735e0beac7f241592da1a072c94a018e4fa702001700f5922291` |
| `tor-proto 0.47.0` | `fceb9d4017849440584e541054b6a26517655a3ae48942b6e67476c5376262c3` |
| `tor-error 0.47.0` | `ca01de513501849b2298e4f16f8760832ef43344b10fe17600daed9a35128b24` |
| `tor-config 0.47.0` | `b849c69c695b9534cf945c0422b85eaf5760bb6141a73c47b72fd6f95ea4d719` |
| `tor-dirmgr 0.47.0` | `34ea5e77b43bf1ef5fa213a89cb67080f218df6b418c82527e6bb9862a39aef5` |

## 角色与完整首轮范围

选定范围为客户端TCP出站，访问公网域名、IPv4与IPv6字面目标及不需要PoW计算的公开v3 onion。原始目标与端口传给`TorClient::connect_with_prefs`。本机不先解析网站，也不把节点的IPv4 only、IPv6 only模式用于限制Tor载体或替远端选择网站地址。

域名采用Arti默认的IPv4优先远端策略。字面IPv4或IPv6使用对应固定族的`StreamPrefs`，不改变目标。`.onion`保持域名交Arti处理。`optimistic`保持关闭，`connect_with_prefs`只有取得Tor连接确认后才返回流。公开目标绑定无法从本模块可靠观察，返回`TcpConnectInfo::unknown()`。

不包含Tor relay入站、onion服务端、UDP、DNS代理接口、桥、PT、SOCKS后端、私有onion认证、代理链或自定义目录权威。配置不开放这些开关。Tor的TLS链路认证由Arti执行，不能用网站Web PKI验证替代Tor relay的CERTS验证。

## 固定API与所有权

| API | 固定源码位置 | 本项目用途 |
| --- | --- | --- |
| `TorClient::with_runtime`与builder | `arti-client/src/client.rs:1005`、`builder.rs` | 使用服务所有者构造唯一实际运行实例 |
| `TorClientConfigBuilder::from_directories` | `arti-client/src/config.rs:799` | 显式项目状态和cache路径，不读隐式用户Tor配置 |
| `TorClient::isolated_client` | `arti-client/src/client.rs:1501` | 每次业务建立独立隔离token，共享client内部状态，避免来源map无界增长 |
| `TorClient::connect_with_prefs` | `arti-client/src/client.rs:1585` | 原目标传输与非optimistic流建立 |
| `CompoundRuntime` | `tor-rtcompat/src/compound.rs` | 替换真实任务与网络提供方，复用上游时钟和TLS |
| `Runtime`、`Blocking` | `tor-rtcompat/src/traits.rs` | 全部异步及阻塞工作归命名服务，阻塞任务不能假装已被abort |
| `DataWriter`关闭说明 | `tor-proto/src/client/stream/data.rs:240` | `tcp_eof=false`，shutdown是结束整流 |

每个命名出站只有一个Arti client。每个业务请求建立时创建`isolated_client`句柄，隔离比逐用户作用域更细。节点、用户或请求取消只结束其业务流。多个命名出站有不同实际client、状态目录和排他写锁，不混用guard状态或电路池。入站用户名、密码、UUID或其他凭据不进入Tor配置和隔离token。

异步`Spawn`登记真实future。经主任务批准，本轮新增`ServiceContext::spawn_blocking_tracked`，直接由现有JoinSet持阻塞任务。用异步任务等待一个独立tokio阻塞句柄会在abort后失去真实所有权，本轮不采用该形状。

首轮worker metadata归档`8407f68a3fee4b1081c76c7cd2adf2ea0e63fc28733754862c6e6a4fd053430a`产生762个总包、28个工作区包与525个Tor依赖闭包包。该metadata包含开发及平台条件依赖，不等于最终链接范围。所选Arti功能包括原定TCP与onion客户端能力，没有`tor-hsservice`、`hs-pow-full`或onion服务端。本轮开发依赖变更仍需重新解析。

固定官方Git提交中，直接生产`spawn_blocking`调用位于`tor-hsservice/src/pow/v1.rs`，直接`reenter_block_on`调用位于Arti CLI的keys命令和该onion服务端模块。`CompoundRuntime`与opaque只是转发，默认`Blocking::blocking_io`也会转到`spawn_blocking`。这些位置逐项按上述固定包与feature集合核对，没有用单一字符串未命中推定所有调用安全。该范围核对不替代trait行为和最终完整闭包验证。

`tor-hsclient/src/pow/v1.rs:101`在实验feature `hs-pow-full`下直接创建原生线程，本轮未启用；`pow.rs:3`选择无PoW计算版本。不将需要PoW的onion访问登记为完成。若以后增加该feature，必须先处理原生线程所有权。

固定`tor-rtcompat/src/traits.rs:305`要求闭包panic后，等待句柄被poll时也panic。本轮修订通过结果通道把原payload交给句柄恢复panic，并保留实际native任务的失败记录。关闭拒绝不执行callback，不以panic表达正常取消。该拒绝句柄只能保持Pending，不能因此宣称泛型`Blocking`调用在关闭时总能自动结束。不可中断工作由真实join与超时事实处理。

TCP提供方只接收Arti的字面`SocketAddr`并借用`DeviceLease`。没有网站resolver。未启用的Unix socket、UDP和监听能力明确拒绝，不能让默认runtime偷偷绕过设备接口。服务关闭固定首次总期限，真实join未完成时报告超时并保留任务与状态锁。

## 必须保留的协议过时处理

固定`arti-client/src/client.rs:1297`安装`protostatus::enforce_protocol_recommendations`。`protostatus.rs`在新的协议建议事件中忽略早于软件发布时间的数据，重新检查必需协议。缺少必需协议是fatal，只有缺少推荐协议时记录提示。

原版`client.rs:1308`的fatal闭包等待5秒后执行`std::process::exit(1)`。这会结束整个Engine。官方builder没有可替换回调，经主任务批准，本轮增加可信builder回调，将已判定fatal错误交所属Tor服务。默认`None`仍进入原等待与退出路径，初始缓存检查和运行事件检测不变。

kerlico回调先向命名服务同步发布typed首因，再请求取消。失败发布后开始准入的操作拒绝，已准入且重叠的poll或内核I/O在下一观察点停止。callback返回不表示资源已排空，实际join另行完成。该边界采用主任务接受的准入契约，不加入可能在自身任务中死锁的阻塞活动屏障。受控DirProvider回归从生产builder进入真实RunningInner和协议watcher，分别覆盖缓存拒绝与运行fatal，还要在统一Dispatcher路径复验错误首因和服务隔离。

## 状态目录的信任边界

首轮逐路径检查不能阻止不可信祖先在检查后被改名或替换。修订使用`rustix 1.1.6`的目录句柄、`openat`与`NOFOLLOW`，同时强制从根到工作目录的完整可信祖先链。一次打开操作只取一次有效UID，祖先由root或该UID拥有，组和其他用户不得写入；受管子目录由该UID拥有且无组或其他用户权限。此条件在创建下级目录之前检查。锁文件须属于该UID，权限恰为0600且只有一个硬链接。

Arti后续仍使用路径，所以同UID和root属于受信主体。只保留目录句柄不能代替这项后续路径信任。共享可写祖先包括带sticky位的临时目录都拒绝。已编写同时改名与链接替换、组可写及sticky祖先零写入、静态链接、锁文件符号链接和硬链接、权限拒绝与同名排他回归，尚未运行。非Unix尚未实现等价权限检查，明确拒绝运行。

固定官方`rustix 1.1.6`发布包SHA256为`e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa`，与原根锁一致。新增直接依赖只启用`fs`和`process`，主任务仍需重新生成锁并核对最终闭包。官方包保留原声明的`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`许可。

## 构建与许可

`arti-client`和`tor-rtcompat`的官方声明均为`MIT OR Apache-2.0`，MSRV为Rust 1.92。本项目包继承`GPL-3.0-only`与工作区Rust 1.99.1，第三方源码保留原始许可与必要署名。第三方版权信息不能改成匿名作者。

新包关闭默认features，明确启用`tokio`、`rustls`、`compression`、`static-sqlite`、`onion-service-client`和`vanguards`。不启用`native-tls`、PT、bridge、onion服务端、RPC、`hs-pow-full`或experimental总开关。`static-sqlite`避免运行时依赖系统SQLite，但压缩和bundled SQLite仍需要worker的C工具链。最终依赖闭包、原许可、源码与摘要由发行门槛统一核对，当前没有构建产物。

首轮验证目标为Linux x86_64 worker。本机只编辑和阅读；Windows与其他平台不据API可移植性宣称验收。真实Tor网络可达、目录共识新鲜性、exit策略、onion可用性与目标响应均属于待验证项，失败必须保留，不能通过改成直连或放宽认证制造通过。
