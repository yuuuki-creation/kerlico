# Tor 出站双路径详细研究

日期：2026-10-31。对应唯一总表P-23。**本轮仅研究：未创建crate/feature，未修改框架或TrustTunnel，未连接worker、启动Tor、构建或测试。** 下文把固定源码事实、建议首轮范围、公共契约需求与未决项分开；双路径尚未实现或验证，不把已有SOCKS支持当Tor完成。

## 固定证据与版本

| 对象 | 固定版本/commit | 具体证据与边界 |
| --- | --- | --- |
| sing-box总表基线 | `c005f35300ce76427dc285481ec5695f5b179cd2` | [protocol/tor/outbound.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tor/outbound.go)、[option/tor.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/option/tor.go)、[include/registry.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)：仅出站、TCP，实际启动外部C Tor |
| sing-box历史双路径 | v1.10.7，`253b41936ecd6ae17948d49d9c510d7100830927` | [outbound/tor.go](https://github.com/SagerNet/sing-box/blob/253b41936ecd6ae17948d49d9c510d7100830927/outbound/tor.go)、[tor_embed.go](https://github.com/SagerNet/sing-box/blob/253b41936ecd6ae17948d49d9c510d7100830927/outbound/tor_embed.go)、[tor_embed_mobile.go](https://github.com/SagerNet/sing-box/blob/253b41936ecd6ae17948d49d9c510d7100830927/outbound/tor_embed_mobile.go)、[tor_external.go](https://github.com/SagerNet/sing-box/blob/253b41936ecd6ae17948d49d9c510d7100830927/outbound/tor_external.go) |
| C Tor当前稳定源码 | tor-0.4.9.15，`4d8efff53a86670bcda1847b5ab28d2701e6034f`，2026-10-28 | 官方tag API固定完整commit；[man](https://gitlab.torproject.org/tpo/core/tor/-/blob/4d8efff53a86670bcda1847b5ab28d2701e6034f/doc/man/tor.1.txt)、[configure.ac](https://gitlab.torproject.org/tpo/core/tor/-/blob/4d8efff53a86670bcda1847b5ab28d2701e6034f/configure.ac)、[LICENSE](https://gitlab.torproject.org/tpo/core/tor/-/blob/4d8efff53a86670bcda1847b5ab28d2701e6034f/LICENSE)。tag消息含签名，但本轮未验证签名或二进制 |
| Arti当前稳定 | CLI 2.7.0、arti-client/tor-rtcompat等0.47.0；`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`，2026-10-01 | [官方发布](https://blog.torproject.org/arti_2_7_0_released/)、[arti-client Cargo](https://gitlab.torproject.org/tpo/core/arti/-/blob/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/crates/arti-client/Cargo.toml)、[client.rs](https://gitlab.torproject.org/tpo/core/arti/-/blob/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/crates/arti-client/src/client.rs)。crates.io原包VCS信息一致指向该commit |
| 私网验证参考 | Chutney `d6659ac34c36122ed2590714e37269d1b983c336` | Arti同commit的[.gitlab-ci.yml](https://gitlab.torproject.org/tpo/core/arti/-/blob/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/.gitlab-ci.yml)固定此版本；[tests/chutney/network.py](https://gitlab.torproject.org/tpo/core/arti/-/blob/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/tests/chutney/network.py)给出真实权威/中继/出口/服务拓扑 |

Mihomo固定`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`的[adapter/parser.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go)、Xray固定`0afec66085a85191e9dd2a4a6646c7c9a94688d1`的[infra/conf/xray.go](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)与main/distro/all/all.go未登记Tor专用类型；通用SOCKS出站能够连接本机Tor不等于实现Tor管理或原生嵌入。

公开资料与固定源码只读缓存放在`reference/.upstream/tor-research/`，不提交、不纳入本项目构建，没有在其中开发。固定源码归档与crate下载属于资料读取，没有建立Tor网络连接。官方网站部分能力页明确沿用2023内容，仍写无onion/RPC等旧结论，不能压过0.47.0固定源码与2.7.0发布记录。

## sing-box两种方式的真实状态

**事实：**v1.10.7的`with_embedded_tor`并非Rust实现，也非启动已有SOCKS服务。桌面文件使用`berty.tech/go-libtor v1.0.385`的`libtor.Creator`；Android/iOS文件改用`github.com/ooni/go-libtor v1.1.8`，均设置`UseEmbeddedControlConn=true`，通过CGO链接C Tor及C依赖。指定`executable_path`会清空这个creator，优先启动外部程序。未开启tag则返回空StartConf，由bine默认执行Tor。

**事实：**总表固定的当前树只剩`protocol/tor/outbound.go`，直接构造空`tor.StartConf`，没有上述嵌入文件或libtor依赖；v1.11.15固定`bc35aca01704497c179da1a03e45ad8e32f1a51b`也已不见旧文件。文件历史的模块化提交为`e233fd4fe51a76b8f044982def1d269f9d618fd8`。但是当前固定[构建文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/installation/build-from-source.md)及官网仍列`with_embedded_tor`。这是文档与实现证据不一致；本轮未构建该Go树，不推定此tag仍能提供嵌入。总表两条候选仍保留，kerlico不能因此只交付外部SOCKS壳。

当前外部路径的时序：

1. 构造阶段解析executable、args、data directory和torrc；安全策略可通过`adapter.SecurityPolicy`拒绝Tor特性，未注入策略时该检查通过。
2. Start阶段启动自己管理的Tor。固定依赖`github.com/cretz/bine v0.2.0`默认加`CookieAuthentication=1`、`DisableNetwork=1`、`SocksPort=auto`，建立控制连接并认证；不是接管系统Tor服务。
3. [common/proxybridge/bridge.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/common/proxybridge/bridge.go)另建回环SOCKS桥，生成随机用户名/密码，供Tor的**OR连接**经框架dialer出去。它不是用户业务目标的最终出口；torrc里的Socks5Proxy及其凭据不能覆盖这组内部值。
4. 配置完成后EnableNetwork并等待bootstrap，再GETINFO查询Tor自己的SOCKS listener。业务请求通过这个listener发出CONNECT，原目标留在Tor内处理。源实现对这个业务SOCKS listener使用空用户名/密码，并留有TODO；不能说配置里已有远端Tor用户认证。
5. Close只处理自己拥有的实例/控制连接；bine先发HALT，再限时等待、必要时取消自有进程。不会由一个Socks端口推导出对其他Tor进程的控制权。

源码Trace级别会打印内部桥用户名/密码；kerlico不得照搬此日志。torrc/extra_args在上游很宽泛，可启用本轮不包含的监听/relay功能，本项目需要明确客户端字段与保护字段，而不是照单接受后忽略。

## 角色、数据与EOF

| 能力 | 上游事实 | 本轮建议 |
| --- | --- | --- |
| clearnet TCP：IPv4、IPv6、域名 | Tor出口负责实际TCP建立和域名解析；受出口策略/可达性约束 | 两后端都完整实现，不仅接IP |
| v3 `.onion`公开服务 | 经descriptor/intro/rendezvous，不走普通DNS或clearnet exit | 两后端都包含；坏地址、缺descriptor、超时分别报错 |
| v3 `.onion`受限服务 | 客户端X25519 descriptor decryption key；不等于SOCKS用户名/密码 | 两后端都包含缺key/错key/撤销及正确key路径 |
| UDP/BIND/ICMP | [Tor SOCKS规范](https://spec.torproject.org/socks-extensions.html)明确不支持UDP ASSOCIATE和BIND；预留UDP proposal不是已经实现 | 固定UDP/association均Unsupported，不把DNSPort或上层UoT称为Tor UDP |
| Tor inbound/relay/authority/onion hosting | P-23在三核心中只列出站；Arti有onion hosting API及relay开发工作不改变该角色 | 不注册Tor NodeFactory，不建空服务端；可复用既有真实入站→统一Egress→Tor出站 |
| TCP写端EOF | Tor END关闭流，不能保证继续收到反向尾部 | 两后端通用`tcp_eof=false`；正常关闭、立即目标EOF、EOF后回包负例分别实测 |

EOF固定证据：[C Tor connection_edge_reached_eof](https://gitlab.torproject.org/tpo/core/tor/-/blob/4d8efff53a86670bcda1847b5ab28d2701e6034f/src/core/or/connection_edge.c)会发送END并标记关闭；Arti [DataWriter文档/实现](https://gitlab.torproject.org/tpo/core/arti/-/blob/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/crates/tor-proto/src/client/stream/data.rs)明确shutdown是整个流使用结束，可能丢失仍在途的反向数据。只丢DataWriter则要等DataReader也释放才关闭，不能靠名字推断半关闭。本轮没有实际EOF结果。

Tor的链路TLS按Tor身份/CERTS协议认证中继，并非通常的WebPKI域名证书。Arti的专用TLS provider会检查TLS签名并把Tor身份认证留给后续协议；不能用普通网站TLS连接器替代，也不能把这种专用验证复制成通用skip-verification开关。访问clearnet网站是否端到端加密仍由应用TLS决定，不因经Tor就宣称网站链路全程加密或匿名性已实证。

## 四种认证/隔离材料不能混淆

| 材料 | 实际作用 | 项目身份边界 |
| --- | --- | --- |
| SOCKS `<torS0X>0`参数/Arti IsolationToken | 让不相容流不共用电路；Tor对用户名/密码通常用作隔离参数 | 不是接入认证，不生成Node鉴权指纹 |
| ControlPort SAFECOOKIE | 认证自己管理的Tor控制通道 | 仅组件私有控制秘密，不成为公网接入凭据 |
| 内部OR上游SOCKS桥随机凭据 | 真正RFC1929验证本组件对回环桥的访问 | 短期内部资源，不伪造Tor入站身份 |
| v3 onion身份与客户端授权key | onion地址认证服务身份；受限descriptor需对应客户端私钥 | 按实例/服务/凭据版本存储，失败不回退匿名或其他节点 |

[扩展规范](https://spec.torproject.org/socks-extensions.html)要求新客户端优先S0X格式，旧用户名/密码隔离仍是不同语义。外部后端要显式配置IsolateSOCKSAuth，不使用PreferSOCKSNoAuth使隔离参数消失。不能把一次SOCKS用户名/密码协商成功当成Tor验证了一套授权用户表。

v3授权可采用C Tor文档的`.auth_private`格式。Arti固定[tor-keymgr/config.rs](https://gitlab.torproject.org/tpo/core/arti/-/blob/ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087/crates/tor-keymgr/src/config.rs)和client.rs支持只读C Tor client keystore；采用`onion-service-client`、`keymgr`可复用该文件格式，不必为读取key启用所有experimental API。Arti会忽略部分坏文件，因此项目必须先严格验证声明的key/服务匹配，不能把坏配置静默当成未提供授权。

## Arti原生可替代边界与构建

建议固定`arti-client=0.47.0`、`tor-rtcompat=0.47.0`，直接调用库，**不启动arti CLI子进程来冒充原生嵌入**。依赖包MSRV为Rust1.92、edition2024，数值上低于本项目Rust1.99.1基线；依赖图、patched rustls及实际链接仍未经本项目构建。

首轮候选feature集：关闭arti-client默认features，选`tokio`、`rustls`、`compression`、`static-sqlite`、`onion-service-client`、`keymgr`；如首轮确认plain bridge范围再加`bridge-client`。不直接启用full：它还包含服务端onion、多个runtime、PT进程/RPC等其他能力。Arti不是任意C Tor torrc的兼容解释器；PT可执行程序、透明代理、Tor relay/authority等能力不能从嵌入客户端推定。

| 依赖/来源 | 固定事实及许可 | 构建影响 |
| --- | --- | --- |
| Arti系列、fs-mistrust0.16.0 | MIT OR Apache-2.0 | 实例状态/keystore目录权限检查默认保留，不降低为共享可写 |
| Tokio：Arti锁1.53.1；项目锁1.54.1 | MIT | 使用项目已有runtime，不能在其中再嵌套block_on |
| rustls：Arti锁0.23.45、最低依赖0.23.21；项目固定patched0.23.40 | Apache-2.0/ISC/MIT上游声明 | 约束可相交但不能据此宣布编译兼容；不覆盖现有patch或擅自升库 |
| futures-rustls0.26.0 | MIT/Apache-2.0 | 与Arti futures I/O适配；core BoxStream是Tokio I/O且仅Send |
| rusqlite0.39.0、libsqlite3-sys0.37.0 | Rust封装MIT；SQLite实体另按其public-domain声明保留 | static-sqlite需要C工具链；非静态路径需要对应系统库 |
| liblzma0.4.8、zstd0.13.3 | MIT OR Apache-2.0 / MIT；底层C许可另核 | compression带来原生构建依赖，不是无系统条件的纯Rust产物 |
| 默认native-tls0.2.18、openssl0.10.81 | MIT OR Apache-2.0 / Apache-2.0封装 | 本项目建议不用默认native-tls；并不删除C Tor外部程序自身依赖 |
| C Tor0.4.9.15 | Tor BSD条款及LICENSE内第三方通知 | 外部程序需要OpenSSL、libevent、zlib等；完整静态链接另有工具链条件 |
| bine0.2.0 / 旧go-libtor | MIT / BSD-3-Clause封装，Tor及C子库通知单列 | 只作参考，不引入Go/CGO内核；旧README的C子库表不能当当前SBOM |
| sing-box / Chutney | GPL-3.0-or-later及附加命名限制 / 保留通知的宽松许可 | 不复制sing-box实现；Chutney仅作隔离验证工具，不进入内核 |

上游锁不是本项目锁；完整SBOM、原生库实际版本、产物路径匿名化与打包条件只能在将来授权的worker构建中确认。[Arti安全构建文档](https://arti.torproject.org/guides/safer-build-options/)也明确提示编译路径会进入产物，不能把本轮源码读取当发行匿名检查通过。

### 原生路径的两个真实集成门槛

1. **整进程退出。**固定client.rs的create_impl调用protostatus::enforce_protocol_recommendations，fatal回调等待5秒后`std::process::exit(1)`；[当前API文档](https://docs.rs/arti-client/0.47.0/arti_client/)也披露此行为。未找到公开builder参数替换该回调。它会使单个Tor出站结束同一内核的其他协议，不能原样接入后称生命周期完成。建议先选定受审查的最小固定patch/上游API：保留协议过期判断，将该组件置为fatal/unavailable、拒绝新流并取消其任务；不忽略共识安全要求，不通过改sleep或子进程替身绕过问题。
2. **全局crypto provider。**`tor-rtcompat/src/impls/rustls.rs`的RustlsProvider::default要求应用已安装默认CryptoProvider，否则构造会panic，且其配置字段/构造器不能直接从外部注入Arc。现项目多用显式ring provider，不等于全局已安装。需Root确定一次性应用级provider策略，或固定小范围provider注入补丁；不能让协议构造器悄悄改变全局策略。

## 统一Egress的必要公共契约建议

**当前事实：**`crates/egress/src/lib.rs::tcp`先调用candidates，对所有Domain使用系统lookup_host，再向Outbound传字面IP。该路径会把onion当DNS查询，也会把普通Tor目标提前交给本地DNS。不能只让Tor接受IP，或排除onion来绕过缺陷。

**建议，尚未定稿/落盘：**

| 契约需求 | 应保留的责任 |
| --- | --- |
| 出站显式目标解析策略 | 在core增加默认保持旧行为的local/remote/opaque-name能力；Egress先选择策略再解析。Tor两后端保留原始Domain/Onion，整个调用仍经AccessService/Egress，不在engine按协议名分支 |
| onion名称不落系统DNS | 支持该命名空间的远端路径原样传递；不支持者明确拒绝。规则判断/日志也不能为取得IP偷偷预解析onion |
| IPv4优先的实际保证 | 普通域名由Tor侧解析。Arti StreamPrefs默认/显式ipv4_preferred；C Tor SocksPort保持IPv4默认、不启用PreferIPv6并允许IPv6Traffic。字面IP保持原族。这里只保证请求的远端偏好，不宣称本机已拿到完整A/AAAA并按本地候选逐一回退；如策略需要完整IP规则，应另有隐私相容resolver契约或明确拒绝 |
| 后台组件生命周期 | Outbound异步启动/就绪/关闭或等价实例scope，提供owner取消、bootstrap预算、drain和组件fatal状态。Factory构造只解析，不启动网络/进程。请求取消只结束自身流，不停止其他节点的Tor实例 |
| 实例资源归属 | 当前Registry已为每节点重建出站，继续保留；state/cache/guard/key目录、控制cookie、电路及任务不使用全局单例。相同状态路径必须拒绝冲突，不能用isolated_client共享guard状态冒充完全独立实例 |
| 载体连接器 | Tor relay/directory carrier使用明确StreamConnector/transport用途，不能再路由回自身Tor出站。外部C Tor经自有认证桥承接OR连接；原生Arti经自定义NetStreamProvider承接字面SocketAddr |

普通网站、Tor节点/relay bootstrap目标和控制端点是不同用途。不可让Arti默认runtime直接拨网站规避统一访问，也不可把Tor内部relay连接当成网站DNS再送进同一Tor出口形成递归。

`tor-rtcompat::CompoundRuntime`/RuntimeSubstExt、通用RustlsProvider可以复用；其NetStreamProvider只接单个地址以避免额外DNS，并要求Stream为Send+Sync。现core BoxStream仅Send，可在协议内用适当同步/compat适配满足边界，不需全局把IoStream加Sync。StreamOps不支持的socket操作应如接口规定返回Unsupported，不能假装成功。runtime还要求Unix/UDP provider：本轮未选监听/通用UDP能力应明确拒绝，不能因此顺便开放网络路径。后台Spawn需有实例取消/跟踪，单纯丢Arc是否彻底退出不作为已验证事实。

## 完整首轮双路径范围建议

以下是**待Root确认的交付范围，不是当前可用配置**。共同配置应表达backend、每实例私有目录、bootstrap/stream/drain预算、并发/内存界限、远端地址偏好、v3客户端授权；外部路径再有可执行文件与受保护的客户端Tor配置，原生路径使用明确Arti字段。未知/未实现选项拒绝，不做空开关。

| 交付项 | external-managed C Tor | 原生embedded Arti |
| --- | --- | --- |
| 所有本轮目标 | IPv4/IPv6字面、正常域名、v3 public/private onion | 相同；不能删onion换更易实现的IP集合 |
| 启停与bootstrap | 自有子进程、SAFECOOKIE、先DisableNetwork后配置、就绪与限时退出 | 手工bootstrap、受控runtime任务、组件fatal回调、状态锁 |
| 业务连接 | 完整SOCKS5 CONNECT并等待成功；保留域名；S0X隔离 | TorClient.connect_with_prefs；默认非optimistic；隔离token |
| 授权 | 自有ClientOnionAuthDir、严格key检查；不控制系统Tor | 独立keystore，可只读兼容C Tor客户端key格式 |
| 失败/资源 | cookie失败、bootstrap失败、流拒绝、超时、取消、进程退出后不直连 | 同类失败、目录/电路/任务清理、协议过期仅停本组件 |
| 返回能力 | TCP true、tcp_eof false、UDP/association false | 相同 |

本轮不将“连接已有任意SOCKS服务器”作为external路径的完成标准；该功能属于既有SOCKS模块。两后端必须一次写齐代码/接口/测试/工具后才统一构建。桥接/PT、任意torrc、RPC代理、relay/authority/onion hosting、透明代理/系统路由不据此宣称实现；plain bridge是否纳入首轮仍应在最终范围确认中明确，不能暗中接受但忽略配置。

## 项目内可控对端与未来验证条件

目前没有连接worker，不能报告内存、C工具链、Tor二进制、Python包或端口条件已经满足。未来应新建项目隔离工作区，用固定C Tor和独立Arti CLI作为参考；不接管系统Tor、Runner、Docker、DNS或SSH服务，不运行安装脚本。

以Arti固定CI拓扑为可靠起点：4个authority、6个非authority relay、2个exit，再加参考/被测client及C Tor/Arti onion服务；上游特意保留足够中继满足vanguards，不能用削弱保护的极小网络冒充完整onion验证。Chutney匹配pin仅用于参考工具；其Python依赖含cryptography、networkx等，应项目内venv/已有工具使用，不全局安装。需要逐进程CPU/内存/端口预算，构建与多Tor实例验证不并行压满worker；本轮未量测资源。

私有测试profile必须同时替换authority、fallback、relay/exit策略，并只允许项目自有目标；不能只改一项后意外联系公共Tor。测试地址/key/目录全部私有保存，文档使用中性别名。原始上游脚本可能访问公网网站/DNS，不应原样直接执行。普通站点夹具只绑定已授权的本机地址/高端口，不增加worker地址、改系统resolver或放宽已有服务。

| 矩阵 | 必须观察，不能推定 |
| --- | --- |
| 两后端×IPv4/IPv6本地入口×目标族 | 入口族、guard/relay载体族、exit目标族互相独立；统一AccessService仍是入口 |
| 域名/onion | 注入可记录的系统resolver确认调用为零；A/AAAA/双栈的远端选择与onion descriptor路径分列 |
| 两种onion参考服务 | C Tor及独立Arti服务；公开与受限服务，正确/错误/缺少client key及坏onion地址 |
| TCP数据与关闭 | 目标先发、17/4096/65537/262144等跨cell负载、慢流/并发、立即目标EOF；写EOF后等待反向数据作为不支持负例保留 |
| 隔离与清理 | 两实例独立guard/目录/key/token；拒绝状态目录重用；只杀/等待自有进程，取消不跨节点 |
| 不绕路 | 载体connector只允许私网Tor OR/directory端口并拒绝网站夹具端口；坏bootstrap/cookie/onion key不能直接碰网站 |
| 失效回调/feature裁剪 | 模拟不支持的共识协议只停Tor实例，其他协议正常；两后端完整与合理裁剪构建分别检查 |

公共Tor联网只可能是后续另行明确安排的验证，不替代私网可重复矩阵，也不在本轮执行。私网普通域名DNS（尤其仅AAAA/双栈的高端口DNS夹具）、C Tor/libevent resolver端口语法还需固定源码核实；不拿localhost一次成功覆盖完整远端DNS/IPv4优先保证。

## 进入编码前的未决项

1. Root确定remote-resolution/opaque目标与onion保护契约，保持统一Egress及默认非Tor行为；不能先泄露系统DNS再称Tor远端解析。
2. 落实组件生命周期/状态目录归属，区分bootstrap长预算和单请求剩余预算，证明后续停止不会留下后台任务或误杀系统Tor。
3. 选择Arti过期回调最小固定补丁/上游API及crypto-provider策略，保留安全拒绝而取消整进程exit。未解决前不得用arti子进程或仅外部路径冒充双路径交付。
4. 确认common客户端配置的精确集合、plain bridge范围、状态目录冲突校验时机；任意torrc/extra_args不能默默提供其他角色。
5. 在获新授权后复核worker原生依赖、匹配Chutney资源和私网DNS条件；本轮只有源码可行性证据，没有编译/互通/性能结果。

**结论：**双路径范围可设计，Arti是原生候选，当前并非无条件drop-in。研究完成后先交Root决定公共契约和原语处理，不开始编码或worker操作；TrustTunnel原步骤继续停止。
