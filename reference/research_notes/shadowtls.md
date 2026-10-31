# ShadowTLS v1/v2/v3 双端流包装调研

日期：2026-10-31。对应 P-22。状态：只读交接；r9包级21项通过，默认对端尚有9个v2客户端失败。后续HRR安全修复已写待验，不能登记完成；实际证据以测试记录为准。

## 固定证据与许可

- [官方 0.2.25 源码](https://github.com/ihciah/shadow-tls/tree/02dd0bc7bae8a2011729f95021690e694fd8e43e) 固定 02dd0bc7bae8a2011729f95021690e694fd8e43e；[v1/v2 设计](https://github.com/ihciah/shadow-tls/blob/02dd0bc7bae8a2011729f95021690e694fd8e43e/docs/protocol-en.md)、[v3 设计](https://github.com/ihciah/shadow-tls/blob/02dd0bc7bae8a2011729f95021690e694fd8e43e/docs/protocol-v3-en.md) 与 client/server/util/helper_v2 交叉阅读。该版本不再实现 v1，历史文档将最后 v1 标为 0.1.4。清单声明 MIT/Apache-2.0，仓库 LICENSE 实际为 MIT；本项目不引入其 Monoio/forked-rustls 或运行其子进程承载业务。
- [sing-box 1.14.4](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/shadowtls) 固定 c005f35300ce76427dc285481ec5695f5b179cd2，其 sing-shadowtls 依赖为 a9c0127d5c99401c7706b66f3c62473060721997，含 v1/v2/v3 双端。另读 sing-shadowtls 当前 2d5886b68fad10d098af94a6814479c81a0e4129；二者分别缓存，不将当前行为外推固定二进制。sing-shadowtls 为 GPL-3.0-or-later，作为研究与隔离参考对端，不复制 Go 实现入内核。
- [mihomo](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/shadowtls) 固定 3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8，安全连接可嵌入多个协议，不能把内层各自的传输/UDP/认证能力外推成 ShadowTLS 本身能力。
- TLS 复用项目已有 shaped-rustls 0.23.40，固定 3a131beaef0183b0cb61e5a9070a703b6be39ed3；其 ClientHello finalizer 在 transcript 和网络写出前，仅允许等长修改 SessionID，满足 v3 对同一真实 ClientHello 签名的需要。禁用 resumption/0-RTT，不二次生成握手或伪造 TLS 密钥交换。
- 其余原语为 Tokio、hmac 0.12 + sha1 0.10、sha2 0.10、rand 0.8、subtle 2.6.1（BSD-3-Clause）以及既有 SS/SS2022。SHA-1 用于固定协议 HMAC，不把它改成 SHA-256 后仍声称互通。RustCrypto 所列哈希/HMAC crate 声明 MIT OR Apache-2.0，TLS 使用既有依赖许可；最终整体许可仍由总状态维护。

## 版本真实边界

| 版本 | 握手与业务包装 | 身份与数据保护 | 对端条件 |
| --- | --- | --- | --- |
| v1 | 完成真实 TLS 1.2 后直接使用原始 TCP 字节，不再经过 TLS 加密/记录包装 | 外层无密码认证、无业务保密或完整性；TLS 证书只认证握手站点 | 客户端与服务端分别观察 CCS 后 Finished，不能用 TLS 1.3 代替 |
| v2 | 首业务 ApplicationData 加 HMAC-SHA1 的 8 字节前缀，HMAC 覆盖此前收到的全部握手站点字节；后续仅 5 字节 TLS-like 记录头 | 切换点校验确实使用密码，但没有持续业务完整性，不能提供 v3 的抗劫持保证；不加密业务 | TLS 1.2/1.3，上游允许当前与前一握手摘要以容纳晚到记录；本项目按完整记录保存最近 8 个有内容摘要，避免多条晚到票据造成误拒绝 |
| v3 | ClientHello 32 字节 SessionID 的前 28 字节随机、后 4 字节为 HMAC-SHA1；握手返回按 ServerRandom 建立 HMAC 和 XOR；业务按 C/S 方向连续 HMAC | 双向密码证明和逐记录截短 HMAC 完整性，但不提供业务加密或前向安全；4 字节标签不能替代内层 AEAD | strict 默认要求 TLS 1.3；显式兼容模式允许 TLS 1.2，其握手期服务端证明弱于 strict |

v3 签名覆盖 TLS handshake message（含 4 字节握手头、不含 5 字节记录头），将 SessionID 最后 4 字节清零后计算。设计文档个别英文 bits 表述按固定代码实际 bytes 解释。握手返回 XOR key 为 SHA256(password || first ServerRandom)，连续 HMAC 先写同一 ServerRandom；业务 HMAC 分别先写 ServerRandom||C 或 ServerRandom||S，每个记录先累计纯业务、取 4 字节摘要，再把该摘要反馈进状态，抵抗拼切与反射。握手 HMAC 不反馈标签。r9 曾按首次 ServerHello（含 HRR）初始化种子；后续安全复核确认 HRR random 是 RFC 固定常量，旧行为回归已证明它可被错误用于业务切换。当前本地已改为跳过 HRR、等待真正 ServerHello 的新鲜 random，但尚未复验，不能继承原HRR正例的安全结论。后续 ClientHello 仍保留首次 SessionID，服务端只鉴别首次 ClientHello。

错误鉴权/普通浏览器连接可以回退到**配置的握手站点**，但不能进入内层或创建网站目标资源。正常握手没有客户端明文密码；它不代表主动探测不可区分已由本项目证明。v3 客户端在握手成功但未获证明时不能发出内层请求；可用已建立的真实 TLS 发出有界混淆 HTTP 请求并关闭，不回退到 v2/v1。

## 正确的项目接线

ShadowTLS 是代理载体连接器与节点流包装，不能作为忽略目标 Destination 的普通网站 Outbound。客户端仅由内层 SS/SS2022 编码实际网站地址，再将内层配置的代理 endpoint 交给 StreamConnector；连接器完成 ShadowTLS 后返回可写内层密文的流。外层复合 Outbound 委派内层业务接口，原生 UDP 明确关闭，不能绕过包装直接发往同端口。

节点完成 ShadowTLS 后，直接调用已构造内层 InboundProtocol.handle(stream, access, context)。网站 TCP 仍由该内层通过统一 AccessService 访问；不建本地回环转发端口、不调用外部核心。配置的握手站点属于显式载体资源，可以单独拨号，但不会取得网站 Destination 或修改统一出口策略。

本轮只允许既有 Shadowsocks 10 个 AEAD 方法和 SS2022 三方法，保留内层 EIH/多用户配置；拒绝 legacy/none、裸 VLESS/Trojan 等在这个组合中缺少内容保密/完整性的路径。其他具有独立加密的内层在架构上可扩展，但不因能承载字节流就登记已实现。UDP-over-TCP 没有现有合法接线，本轮不伪造 UDP 支持。

节点始终继承内层实际认证指纹，不能用无鉴权的 v1 字段或内层 none 的未参与密码伪造节点身份。v2 切换密码及 v3 实际认证密码也须独立并生成相应材料指纹；同证书、握手站点与 SNI 不代表共享凭据。任一层密码错误都不能调用网站目标接口。

## 首轮完整范围

1. 独立 Rust v1/v2/v3 客户端连接器和节点包装，实际接入 SS 全部 10 个 AEAD 与 SS2022 三方法；双端分别验收，不提供裸伪代理类型。
2. v1 TLS1.2；v2 TLS1.2/1.3；v3 strict TLS1.3 与显式非 strict TLS1.2/1.3。客户端始终校验证书/名称，不提供 insecure。禁用 TLS resumption 和 0-RTT。
3. v2 单密码、v3 单密码或最多 256 个独立用户；每节点独立认证。v2/v3 固定握手目标及有限显式 SNI→目标映射；不实现按任意客户端 SNI 自动拨号的 wildcard 模式。
4. 正确处理 v2 握手尾部残留 TLS 记录、v3 握手残留 HMAC 记录、TCP 拆分/合并、记录边界与多条业务记录；握手总字节/帧/时长有界。首次 ClientHello 需完整位于单条 TLS 记录，非法或不支持的探测仅能转发到固定握手站点，不能误进入内层。
5. 鉴权、HMAC 篡改/乱序/反射/拼切、截断、EOF/Alert、目标先发、双族节点/目标、并发、取消、排空与端口回收。完整记录边界 EOF 与半条记录截断分开；外层 TLS-like Alert 不当作额外加密保证。
6. 自端全方法矩阵；固定 sing-box 双方向 v1/v2/v3 与所列 TLS 条件，逐组合维护真实正例与边界；官方 0.2.25 v2/v3 可作为额外参考，不替代 sing-box 的 v1 验收。通用 tcp_eof 保守 false，真实 FIN 另记录；没有吞吐、隐蔽性、抗封锁或审计结论。

公共 StreamConnector 与 SS/SS2022 注入入口由主任务实现；全部首轮代码、接口、测试、工具写齐后，才同步 perf-02 统一构建。当前限定测试进展见测试记录，未完成分支不继承自端结果。

## 互通后复核的边界（复验中）

包装记录长度是 u16，官方 decoder 接受完整字段范围，不能把真实 TLS 的记录限制直接用于握手后的明文包装。发送继续按 16384 分段；接收已改为最多 65535 字节，同时保持64KiB用户队列及握手总量预算。固定 sing-shadowtls 的 WriteBuffer/WriteVectorised 路径可能发送大于16KiB的包装记录。

固定 sing-shadowtls 的 v2 client 没有官方 Rust client 的 SessionFilter；真实默认 TLS1.3 票据矩阵出现内层 cipher authentication failed。票据泄漏/握手摘要边界是当前调查方向，不能把关联推定写成全部失败的确定原因；num_tickets=0 的合法握手条件将另列实际结果。原始失败保留，不能与关闭票据结果合并成默认全兼容。

## 当前交接边界

只整理既有证据，所有已提交作业均已终止，当前项目作业进程为0。worker源码仍为有意恢复旧HRR常量行为的复现变体；本地新鲜ServerHello修复、并发TLS站点夹具及官方节点接线不能当作已经完成协议验收。独立夹具测量已证实原OpenSSL -www只可串行握手、新夹具可并发握手；尚未证明它是旧v2失败的唯一原因。官方0.2.25只完成下载与版本读取，没有互通结果。完整状态、旧失败、未复验项和摘要见[测试记录](../../docs/testing/shadowtls.md)。
