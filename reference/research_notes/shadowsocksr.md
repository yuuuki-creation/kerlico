# ShadowsocksR 调研与范围

日期：2026-10-31。状态：详细研究与完整首轮编码已完成；worker有冻结的限定通过结果，mihomo坏流与就绪问题已有分类，纯Rust首包EOF仍未确认解决。IV-only修正最新完成包格式、lib检查/严格Clippy及两个精确无网络回归（各1项通过），未运行完整互通、历史抓包或此前中断实验。风险检查中断的具体阶段未知。对应总表P-06，实际边界见测试记录，普通SS结果不继承为SSR结果。

## 固定证据与角色

- mihomo v1.19.33，提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`：[出站适配](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowsocksr.go)、[protocol 目录](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/ssr/protocol)、[obfs 目录](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/ssr/obfs)。该路径只有客户端角色，不能据其解码器推定服务端已实现。
- Python SSR manyuser，固定提交 `fd723a92c488d202b407323f0512987346944136`：[协议实现](https://github.com/shadowsocksrr/shadowsocksr/tree/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin)。包含明确的 client/server 编解码和 UDP 回调；已在 worker 通过限定 Python/OpenSSL API 适配运行，实际角色和限制见下文。
- sing-box、Xray 的固定总表没有可用的 SSR 双端入口，不能将其 Shadowsocks 测试当成 SSR 对端验证。

本次没有找到可以直接满足所选双端与 UDP 语义的完整 Rust SSR 依赖；本轮选择固定密码依赖并独立实现 Rust 协议/I/O 状态机，具体范围见下文。

## 必须分开的维度

mihomo 固定注册表包含六个 protocol：origin、auth_sha1_v4、auth_aes128_md5、auth_aes128_sha1、auth_chain_a、auth_chain_b；六个 obfs：plain、http_simple、http_post、random_head、tls1.2_ticket_auth、tls1.2_ticket_fastauth。不能把 protocol、obfs、cipher 合成一个“ssr 已支持”开关，也不能用 origin+plain 与普通 SS 的重合路径代替其余协议。

TCP 的实际嵌套顺序是网络外层 obfs、其内 stream cipher、其内 protocol、再内 SOCKS 目标地址和业务数据。UDP 走 protocol 加 cipher 的原生包路径，不走 TCP obfs。AEAD 不能因为普通 SS 库支持就加入 SSR 组合。

none 在 SSR 适配中被转为 dummy，同时仍从 password 派生 16 字节协议 key；它不等价于普通 SS none 的空 key。直接复用 SS none 配置会破坏 auth_chain 等认证。不同旧式 cipher 的 key/IV 长度、protocol_param 的 UID/密码解释、obfs_param 的 Host/伪装参数已按下文范围固定。

## 已发现的方向差异

Python 固定源码的 UDP 回调表明：

- origin、auth_sha1_v4 沿用普通包路径，不能继承 TCP 认证帧的能力；none 搭配这些模式时不能宣称公网 UDP 已鉴权。
- auth_aes128 系列客户端包带 UID 和截断 MAC，服务端回包使用服务 key 的另一套校验路径，不是简单反转同一编码器。
- auth_chain 系列的客户端与服务端随机尾部长度、UID 处理、内部 RC4 种子不同；固定源码 UDP MAC 截断至一个字节。它是兼容性事实，不能描述成经过现代安全审查的强认证。

这些区别要求节点同时隔离外层密码/派生 key 和协议用户材料；仅换 UID、共用外层密码不能满足本项目跨节点不得互相接受凭据的约束。多目标 UDP 应接入现有 `DatagramAssociation`，保留同一关联的出口端口与实际来源。没有有效鉴权的组合不能通过为未使用的 password 计算不同指纹，伪装成 IPv4/IPv6 独立身份；应明确限制角色/监听或拒绝该组合。

## 许可证和对端选择

后续验证增补：39种 cipher 的合成字节向量已与原生 OpenSSL/libsodium、固定 Python table 参考一致；这证明密码层格式，不代替全部 protocol/obfs 的独立 CLI 组合。SSR 伪 TLS 接收按实际 u16 record 长度，仍限制每方向总队列128 KiB；另补65535字节分割 record 与 HTTP 括号 IPv6 Host 白名单回归。

Python 多用户列表另有 str/bytes API 差异：TCP 用 str，UDP 用 bytes，而 mu_protocol 返回 str；bootstrap 以兼容容器接受两种表示，保留原名单和算法。该名单不含 auth_chain_b，不能据此宣称其 CLI 服务端显式 UID 可用；协议对象向量与 Rust 自端另验，内核服务端再由 mihomo 原生 UID 客户端验收。

固定 Python UDP 服务端在目标地址解码后执行 `if not data: return`，真实零负载被丢弃。24个相应客户端方向超时保留，非零负载及反向角色分别验收。Mihomo 监听早于代理表发布，工具通过自有监听 inode 和回环只读控制 API 确认代理就绪；测试端口同时检查 TCP/UDP 并避开临时端口范围。首回写延迟实验单独登记，不计作直接互通或内核实现。最终结果见[测试记录](../../docs/testing/shadowsocksr.md)。

Python 固定仓库声明 Apache-2.0，mihomo 为 GPL 项目，独立 native C 参考项目也声明 GPL-3.0。本轮采用独立 Rust 状态机和下述密码依赖，未复制 GPL 项目源码；全项目发行许可仍另行登记。

候选互通需要一个有明确双端的固定参考实现。Python 旧实现的 OpenSSL API、Python 版本兼容及启动参数必须先在 worker 的项目隔离环境核实；不能执行其系统安装、关闭安全服务等脚本，也不能为对端修改 worker 基础服务。mihomo 可作为额外客户端，不能替代独立服务端对端。

## 编码前核对清单

1. 选定完整 protocol/obfs/cipher 白名单及合法组合，区分旧方法、兼容模式和明确拒绝项；补齐每个角色的首部、校验、响应、EOF 与包能力。
2. 明确单用户/UID 用户表的配置、有效凭据指纹与重复拒绝规则，禁止认证失败回退到其他节点或弱兼容模式。
3. 明确时间戳、client ID、connection ID 与重放缓存的有界生命周期；TCP/UDP 分开，不用 checksum 充当认证。
4. 对混淆层逐项确认是否需要握手回写、提前业务缓存、目标先发、写端 EOF 和反向排空；tls1.2_ticket_auth 是协议混淆，不是证书 TLS 验证。
5. 验收矩阵覆盖双端、节点/目标 IPv4/IPv6、TCP/原生 UDP、零包/边界、错误密码/UID/校验/时间戳、截断与部分读写、并发/限额/取消；所有编译和测试仅在 worker 进行。

上述检查项的本轮选择与范围固定如下；实现与测试结果分开登记。

## 详细研究结论与完整首轮范围

日期：2026-10-31。详细研究已完成，本轮范围固定，完整首轮已写齐并进入 worker 验证与修正；不在调研文件另维护一套通过数量。以下取代前文预备阶段的未定状态，前述风险与角色区别继续有效。

本轮一次写齐原生 Rust 客户端/服务端：六个 protocol、六个 obfs、39 个明确 cipher，TCP/原生 UDP、UID 单用户与用户表、严格错误拒绝、节点隔离、统一目标服务、多目标 UDP 关联、重放与有界退出。不会以 origin+plain 最小路径代替本轮完整编码。

39 个 cipher 为普通 SS 模块已列的 34 个旧式 stream 方法，加 none、chacha20、xchacha20、salsa20、rc4-md5-6。cfb 接受 cfb128 别名。AEAD、SS2022、CBC、Blowfish/DES/CAST/IDEA/RC2/SEED 和未列方法明确拒绝，不将“所有 SS 算法”写为支持。none 的协议 key 为 EVP_BytesToKey 16 字节；固定 Python SSR 的 table 同样先派生 16 字节 key，再进入 table 变换，与普通 SS 模块的原始密码 table 路径分开。

### 已追明的协议和混淆状态

- auth_sha1_v4：首部 CRC32、IV+key 的 HMAC-SHA1、时间戳/client ID/connection ID；后续 CRC16/Adler32 帧。UDP 仍为普通包，没有追加认证层。
- auth_aes128_md5/sha1：首部含 UID、AES-128-CBC 单块元数据与两级 MAC，后续包号参与 MAC；显式用户密码先经相应 digest。客户端/服务端 UDP MAC key 和 UID 位置不同。
- auth_chain_a/b：首部 36 字节，UID 由首轮 MD5 掩码处理，AES 元数据绑定用户；数据使用独立方向 RC4 状态和连续 hash，首个服务端数据带 MSS。链 B 根据基础 key 生成两组长度表，padding 长度/位置须与 xorshift128plus 的固定运算一致，不能随机替代。
- plain/HTTP simple/post：按角色编码和解码，HTTP 支持 Host 参数及客户端自定义首部；严格缓存跨 read 的完整头，限制大小。
- random_head：先发随机 CRC 头并等待随机回写，再发缓存的密文。服务端回写无长度/校验，旧协议依赖首个读取边界；不能声称支持其所有任意 TCP 分割情形。
- tls1.2_ticket_auth/fastauth：所选基线共用构造与格式，按角色验证 ClientHello、ServerHello 与 Finished 的 HMAC，处理应用数据 record；这不是证书 TLS，也不额外承诺 fastauth 0-RTT。时间窗与随机标识缓存有界，不允许失败后切到 plain/compatible。

### 真实认证和注册边界

所有 SSR 配置须显式允许兼容旧式密码。是否可作为 nodes 另按实际认证路径决定：TCP 只有认证 protocol 或 ticket-auth 混淆时具备认证；UDP 只有 AES/chain 系列具备追加 MAC，且 MAC 强度按旧协议事实描述。任一启用业务路径没有认证时，指纹为空并强制回环，只允许工厂明确登记的 local_inbounds；nodes 非空凭据检查不修改。关闭 UDP 后再按真实 TCP 层判定。

认证模式同时登记基础密码/有效 key 与实际用户材料的指纹，跨节点重复拒绝；UID 表非空时未知 UID 立即拒绝，不能用基准 key 或接收 IV 回退。没有认证的 password 不能产生“独立节点”标记。未实现每用户独立出口/配额策略；资源与访问策略仍以节点为边界。

### 依赖和许可证选择

复用固定 shadowsocks 1.25.0 的 stream primitive；新增 chacha20 0.10.2（legacy/xchacha）和 salsa20 0.11.0，配合 AES、MD5/SHA1/HMAC、Base64、CRC。前述密码库为 MIT 或 MIT/Apache-2.0；不使用 Python/Go/C SSR 对端承载 kerlico 业务。协议状态机、I/O 与节点访问以 Rust 独立编写，不复制 GPL 项目函数/注释；固定源码仅作格式和行为证据。最终项目发行许可证仍按全项目状态单独处理。

### 参考环境已验证的事实

perf-01 的 Python 3.13.5 能通过进程内 collections.abc 别名和 OpenSSL provider 初始化运行固定 Python SSR，无需修改上游只读文件、全局配置或安装服务。none、AES-CFB/CTR、RC4、RC4-MD5、RC4-MD5-6、ChaCha20-IETF、Salsa20 后端探测通过。

参考实现自身六 protocol × 六 obfs TCP，以及与 obfs 无关的六条 UDP 路径，共 42 项自检通过。初轮被其默认 loopback forbidden_ip 阻止，临时参考配置显式允许测试回环目标后复验通过。这些只是对端可运行性证据，不能登记为 kerlico 互通。

mihomo v1.19.33 参考 binary 已从已核验副本只读同步至本任务 worker 项目区，SHA256 为 `817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f`。它只能证明客户端对端角色；独立服务端验收采用固定 Python 参考或本项目自端矩阵。

### 本轮验收安排

按实际维度分开登记：六 protocol×六 obfs 的 TCP 基线、每 cipher 的原始 TCP/UDP 路径、UID 模式、四类节点/目标地址族、zero/边界、错误认证/UID/校验/重放、缓存/半关闭/预算/取消。UDP 不经过 obfs，不重复把 TCP 混淆排列记成新的 UDP 功能。所有首轮代码和接口写完后，统一在 worker 编译/检查/测试，再集中修改和复验。

## 参考 UID UDP 的后续核验

生成固定向量时确认，Python 参考的 TCP/UDP plugin 对象应分别构造；不能让已初始化 TCP user_key 的对象承担 UDP。进程内仅对两协议模块的 Python2 bytes.split(str) 调用提供字符串兼容，没有修改 MAC 或密码算法。

API 兼容修正后，固定 auth_chain UDP 客户端仍将显式用户 key 取 MD5，而同版服务端和固定 mihomo 客户端使用原始 key。该方向不能作为显式 UID UDP 的成功证据。本轮以服务端/mihomo 一致语义实现，并将向量与互通角色分别登记，保留坏客户端限制。

## 交接时的证据分类

固定mihomo的[配置应用顺序](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)先创建监听与代理表，最后才OnRunning；[TUNNEL接入处理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)在Suspend/Inner阶段拒绝普通接入。因此仅监听或只读代理API成功不足以证明业务已就绪。独立DIRECT问候门槛不预热SSR路径；复验结果和旧失败同时保留在测试记录。

客户端先发的原生抓包还证实：random_head CRC和认证首部可通过，但后续cipher流有额外字节或MAC失败；ticket握手双方Finished可验证，应用数据没有早于Finished，随后却出现非法记录前缀。相同原始字节由固定Python解码器也拒绝；两种原生服务端的规范化重放同样先接受合法握手/地址，再拒绝坏前缀。

源码中的[随机头](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/ssr/obfs/random_head.go)与[ticket](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/ssr/obfs/tls1.2_ticket_auth.go)从Read调用Write(nil)排出待发缓冲，同时应用Writer也可访问这些字段。[Go Conn契约](https://pkg.go.dev/net#Conn)允许并发调用方法；未加同步的缓冲访问可形成重复排出或数据破坏的交错，但本轮未运行Go race检测，不能把源码分析说成已证明唯一内部原因。原生坏字节及两端拒绝结果属于事实，内部具体竞争机制仍是分析。

另有纯Rust有效流在random_head下首包EOF，已定位到服务端首部HMAC检查，但尚未取得该失败的握手原始字节和根因。这与mihomo坏流是不同未决项，不能拿参考端缺陷替代本项目修复。只读交接保存了当前源码/摘要、全部作业退出状态、既有日志和失败抓包；未继续执行中断后的实验。

后续源码审阅发现Reader在IV-only时已清空待收前缀并做空decrypt，使origin客户端的这类截断可变成干净EOF。修正保留该前缀直到正文出现，并避免无新明文时推进protocol解析；对应39种独立cipher向量和纯I/O状态回归已按精确名称各运行1项通过。该修正与既有首部HMAC失败的关系仍属候选，未完成整体数据路径验证；未放宽认证或丢弃坏帧。首包FIFO写偏移、flush握手门槛和关闭排空顺序没有得到足以确认另一根因的证据。
