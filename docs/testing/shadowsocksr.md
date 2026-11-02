# ShadowsocksR 验证记录

更新日期：2026-11-02。完整首轮源码、接口、Rust测试和工具先写齐，再在worker集中验证。当前仍未完成全范围验收，尚未提交或发布。

## IPv6 random_head 剩余失败的三向复现

恢复后的 `ssr-mihomo-shared-r61` 为 191/192，通过数不改写。唯一失败参数是服务端角色、`auth_aes128_md5`、`random_head`、`aes-128-cfb`、IPv6 节点与目标、客户端先发 59392 字节。该轮没有抓包，不能仅凭后续同参数结果确定它的具体坏字节。

`ssr-resume-cli-r2` 在 perf-01 从归档 `bcf21d4c3cf2518ed2b7a1e71f208fdf3f8e1960be547bdbce811d63ceaafb38` 构建 SSR-only CLI，退出 0。冻结产物 SHA-256 为 `edec6b99e6f8ee308e9165be50aa69fdb4b11ee9c84e05f5f5b6843bc6321ccb`。固定 Mihomo SHA-256 为 `817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f`，Python 对照提交为 `fd723a92c488d202b407323f0512987346944136`。

`ssr-diag-ipv6-r2` 保持上述参数，各方向最多 100 次，在该方向首次失败后停止，实际结果如下。不同方向的次数不合并为覆盖矩阵。

| 方向 | 通过 | 失败 | 实际观察 |
| --- | --- | --- | --- |
| Mihomo → 当前 Rust CLI | 10 | 1 | 客户端流含重复的 9152 字节 cipher 片段 |
| Mihomo → 固定 Python 服务端 | 3 | 1 | 客户端流含重复的 53602 字节 cipher 片段 |
| 当前 Rust CLI → 固定 Python 服务端 | 100 | 0 | 业务完整回显，目标累计收到 59392 字节 |

两条失败抓包 SHA-256 分别为 `dea2c91b6c4ea41256a28fd6e48c366779bfb22af3583a47ea86df055df5a256` 和 `e81ecb9ee9ff4e2470c94fa0376ab0ac6edf0ee873ece1743318bc17c972bb9c`。按 TCP 序号去重重组后仍存在重复 cipher，排除了抓包重复记录。独立 Python 解码都先接受认证、IPv6 地址与合法业务前缀，再拒绝后续校验失败；每条流只有一个合法 random_head CRC 边界，未复现旧零后缀歧义。前一轮旧 CLI 同参数对照也在两种服务端复现坏流，Rust → Python 为 100/100。

这些结果证明固定参考客户端能发出不合法的协议流。Rust 保持拒绝坏 MAC，不加入延迟、自动重试或宽松解码。Mihomo `randomHeadConn.Read` 调用 `Write(nil)`，同时业务侧也可进入 `Write`，共享缓冲没有同步；这与重复片段相符，但本轮没有运行其 race detector，不将此源码推测称为唯一内部根因。此组合保留参考端互通限制，不宣称固定 Mihomo 全矩阵通过。

复现工具新增 `--node-host` 与 `--target-host`，只允许回环字面地址；分析工具支持直接 TCP 的 IPv6 PCAP，并列出全部 CRC 边界。两个工具已在 perf-01 通过 Python 语法检查，实际解析合法与失败 IPv6 抓包；IPv6 扩展首部未实现。

本轮还发现旧配置回归仍预期鉴权组合可以移到 `local_inbounds`。现有 v2 工厂将该入口用于无成员的回环接入，鉴权组合必须在 `nodes.members` 中配置。测试现从完整原始 options 构建本地配置，断言无鉴权组合可用、鉴权组合被拒绝，同时保留节点正向验收；没有修改生产配置或鉴权逻辑。

`ssr-resume-regression-r1` 保留原失败，18 项库测试通过、集成 8 通过 1 失败；`ssr-resume-configuration-r3` 精确复现同一旧配置断言。修订后的 `ssr-resume-regression-r4` 归档为 `513e8207be2d06c14b94d0f759512481274c00d9e1162e60122f1114fb9f3f81`，18 项库测试和 9 项集成测试全部通过，整体退出 0。`ssr-resume-format-r5` 在 perf-01 执行包格式化并取回测试文件。本轮未执行严格 Clippy 或完整新 CLI 192 项矩阵；上述三向用例不能代替后者。

## 恢复后的实际验证

旧SDK1独立集成快照的25项SSR包级测试通过；固定Mihomo矩阵192条为177通过、15失败。perf-03对原Rust全协议/混淆、双栈及域名组合测试重复执行，第28轮复现自端首包EOF。另一逐层抓取在第14轮再次复现：客户端发出的15字节random_head，其前14字节也满足CRC残数，服务端把末尾零字节当作IV首字节，导致解密后的协议首字节错位；双端网络字节相同。

生成端修订只发送自身首个有效CRC边界，未放宽接收认证。分片确定性回归实际运行1项通过，修订后全包26项通过；`ssr-crc-repeat-r7`原组合100轮全部通过，终态0，705.978秒。首次精确命令漏写库测试模块前缀，实际为0项，不计通过；修正命令后才取得上述1项结果。Mihomo的15项失败、当前共享SDK2适配及整树结果仍须另验，不能从这个修订推定全部完成。

## 历史记录边界

以下为2026-10-31输入及后续停点。其IV-only两项回归、历史失败和当时未进行的实验均按原范围保留。此前风险检查中断的具体步骤未知，本轮没有重放该未知步骤；以上抓取是新合成自端测试。

## 固定快照与构建

| 已冻结 r7 项目 | SHA-256 |
| --- | --- |
| SSR 模块文件集合 | `152368d8a832865aa46cd58dac4d9502434dcfb7030ea42642f49f4b0fadd35a` |
| SSR-only 正式 CLI | `94559d13f9a1963fe80d5bc2a53376d40f08af6dc9c6829f4a98be120b9aa200` |
| 构建使用的 Cargo.lock | `6bd2ec97530ebc8bc63ab0bed8a35b629846e8fb1b1a1ea83ecb4f8cfa639710` |

模块集合按相对路径排序，每个普通文件输入“路径、NUL、文件内容、NUL”；不含 docs 和 tools。worker 为 Linux x86_64、Rust/Cargo 1.99.1，构建并发1，复用本项目已有 target。格式后的源码已取回，与模块摘要一致。

```sh
cargo fmt -p kerlico-shadowsocksr
cargo test -p kerlico-shadowsocksr --all-targets
cargo clippy -p kerlico-shadowsocksr --all-targets -- -D warnings
cargo fmt -p kerlico-shadowsocksr --check
cargo build -p kerlico --no-default-features --features protocol-shadowsocksr
python3 -m py_compile tools/interop_shadowsocksr.py tools/shadowsocksr_reference.py tools/shadowsocksr_vectors.py tools/shadowsocksr_cipher_vectors.py tools/diagnose_shadowsocksr_peer.py
```

r7 的6项单元、9项集成测试、严格 Clippy、fmt 和 CLI 构建通过。复制正在运行的旧CLI时遇到 Text file busy，未覆盖活动文件；另存 r7 版本路径并核验摘要。工具语法单独检查通过；最终工具增量另记，不能把复制失败称为整条脚本成功。

## Rust 测试范围

- 全39 cipher×六 protocol 的 plain 双端 TCP、原生 UDP、空包，失败保留方法与协议。
- 六 protocol×六 obfs TCP，双栈节点、三类目标编码、目标先发、32768字节、EOF尾包与2 MiB双向并发进度；UDP只在plain基线独立验0/4096/64000字节。
- 错误基础密码、UID、用户密钥不访问目标；真实注册表验证无认证路径仅回环 local_inbounds、nodes拒绝空指纹；base/user密码及有效key跨字段重复也拒绝跨节点复用。
- UDP空闲重建、共享限额、取消、真实统一Egress的跨IPv4/IPv6同源端口、Full Cone未预联系来源和零包。
- 12条固定参考 protocol/overhead 记录的小片输入、双向TCP/UDP、MAC/CRC、AES元数据、chain_B确定性padding；首部重放、容量和到期；六obfs分割读取、65535字节伪TLS record、括号IPv6 Host白名单。
- 39种 cipher 与独立原生字节向量一致，使用17字节编码片和19字节解码片检验连续状态。OpenSSL 3.5.7提供AES/Camellia/RC4，libsodium提供ChaCha/XChaCha/Salsa，固定Python参考提供table；none保持原字节。

## 正式 CLI 互通

主工具 tools/interop_shadowsocksr.py 每条记录区分protocol、TCP obfs、cipher、内核角色、节点/目标地址族、UDP包长、UID、注册位置和流量顺序。UDP记录obfs=null，不把TCP obfs排列重复计作UDP功能。mihomo只有客户端，必须显式选择内核服务端方向。

本轮主矩阵的命令形状如下；变量指向上述固定worker资产和各自独立结果目录，实际执行脚本与逐项JSON保存在本地私有任务记录。

```sh
python3 tools/interop_shadowsocksr.py --kerlico "$SSR_CLI" --peer "$SSR_CLI" --peer-kind kerlico --work "$RESULTS/self" --udp-sizes 0,3,4096,64000
python3 tools/interop_shadowsocksr.py --kerlico "$SSR_CLI" --peer python3 --peer-kind python --reference-source "$PYTHON_REFERENCE" --work "$RESULTS/python" --udp-sizes 3,4096,64000
python3 tools/interop_shadowsocksr.py --kerlico "$SSR_CLI" --peer "$MIHOMO" --peer-kind mihomo --work "$RESULTS/mihomo" --node-hosts 127.0.0.1 --target-hosts 127.0.0.1 --directions server
```

| 当前 r7 验证 | 实际范围 | 结果 |
| --- | --- | --- |
| Rust CLI双端 | 六protocol×六obfs TCP，双栈节点/目标，双角色；UDP plain六protocol、0/3/4096/64000字节 | 480/480 |
| 固定Python独立双端 | 同上TCP；UDP plain 3/4096/64000字节 | 432/432 |
| Python共同cipher双向 | auth_aes128_sha1/plain，26种cipher，IPv4节点→IPv6目标，TCP及UDP 3/2000字节 | 156/156 |
| Python显式UID双向 | AES-MD5/AES-SHA1六obfs，双栈节点→IPv6目标，UDP在plain验3/2000字节 | 64/64 |
| Rust显式UID客户端→Python服务端 | chain_A六obfs，双栈节点→IPv6目标，UDP在plain验3/2000字节 | 16/16 |
| mihomo显式UID客户端→Rust服务端 | AES-MD5/AES-SHA1/chain_A/chain_B，plain，双栈节点→IPv6目标，TCP及UDP 3/2000字节 | 24/24 |
| mihomo XChaCha客户端→Rust服务端 | auth_aes128_sha1/plain/xchacha20，四种节点/目标地址族配对，TCP及UDP 3/2000字节 | 12/12 |

本表各项均使用同一r7版本CLI分别复验；重复覆盖不汇总成独立组合总数。

26 cipher为AES各位数ctr/cfb1/cfb8/cfb128/ofb、Camellia各位数cfb128、none/rc4/rc4-md5/rc4-md5-6/table/chacha20/chacha20-ietf/salsa20。其余12种Camellia模式及XChaCha不因此取得Python CLI验证；全部39种的Rust双端与密码层原生向量独立保留。

## 保留的失败与边界

初轮集中修正测试括号、Address错误映射和四处Clippy提示。首次Python矩阵84/96，12项失败全为Rust服务端两种ticket混淆。参考oracle确认ServerHello两处HMAC正确，进一步定位旧客户端会把握手等待负载合成超过16 KiB的伪TLS record。按SSR u16格式修正后，96/96及当前双栈432/432通过。

固定Python UDP服务端剥离地址后执行 `if not data: return`，丢弃真实零负载。旧完整480条网络检查中，24个Rust客户端方向零包超时，接收方向24个零包通过；另有1个HTTP POST TCP内容失败及1个关闭异常，原始记录保留。当前r7完整非零矩阵432/432通过，不将旧失败改写为通过。空包能力由当前Rust双端480项及对应Rust用例证明。

Python多用户运行需兼容str/bytes判断：原mu_protocol名单保持不变，只让成员判断接受两种字符串表示；原名单不含chain_B，不能宣称其CLI服务端显式UID可用。chain_B协议对象UID线格式向量与Rust自端已验，内核服务端独立UID接收由mihomo原生客户端24项覆盖。

固定Python chain UDP显式用户客户端把密码取MD5，其服务端与固定mihomo客户端使用原文，原版显式UID UDP自端不一致。实现保持服务端/mihomo一致的原文语义，不改坏客户端算法后称原版通过；不把该客户端方向列作已验。

Mihomo全obfs客户端先发矩阵补就绪检查后仍41/48：origin/random_head、origin/ticket_auth、V4/ticket_auth、AES-MD5/random_head、AES-SHA1/random_head、chain_A/random_head、chain_B/random_head未通过。改为目标先发后47/48，仅chain_A/random_head在问候前关闭；该模式单独记录，不把它覆盖到客户端先发。原生plain UID和XChaCha分别通过，不外推这些混淆组合。20ms首回写延迟夹具34/36，仍有两项random_head失败；目标先发加20ms则34/36，V4和chain_B的ticket_fastauth未通过。夹具只定位时序相关性，不算直接互通，生产内核未加入延迟。独立mihomo→固定Python服务端初始对照也仅31/36，仍不足以给所有失败作唯一归因。

独立夹具捕获UDP Address already in use，工具现同时检查TCP/UDP并避开worker临时出口端口范围；这是测试工具修正。Mihomo监听早于代理表发布，工具用自有进程监听inode和回环只读控制API确认代理存在；不把探测TCP连接当作业务就绪。后续流量顺序/延迟实验及最终工具增量按实际结果补记。

random_head缺少可靠回写边界；none+origin+HTTP短首部受固定Python服务端至少13字节限制；none+AES UDP没有独立nonce，chain UDP仅1字节MAC。这些旧协议性质不因测试通过而消失；所有方法显式要求allow_insecure，无认证启用路径只能回环本地接入。

## 上次只读交接时核对的增量与未决项

该交接点的本地SSR模块与worker恢复后的模块逐文件摘要一致，共19个文件，集合SHA-256为 `5c43e3dc854c03c4fc89e9d6fbadf7e320a072a4cfd10d970a8eb9ba1b95646d`。这包含后续测试与诊断注记，不能替换r7快照；也不是下文源码修正后的摘要。r7模块另存私有归档，并复核与原 `152368…` 摘要一致。

| 记录 | 实际结果与边界 |
| --- | --- |
| r8坏TLS记录回归 | 7项单元、9项集成、严格Clippy和fmt通过。验证实际捕获的合法Finished/初始应用数据在77个分割点可解析，随后非法记录前缀被拒绝；Python独立对象也接受前缀、拒绝同一坏记录。 |
| r9 | 手工tar遗漏mtime，Cargo复用r8产物，新增坏MAC测试未实际编入；不得记为17项通过。该轮旧集成矩阵出现首包EOF，原日志保留。 |
| r10标准检查 | 修正同步mtime后明确重新编译；实际列出8项单元（含新增坏MAC重放）及9项集成并全部通过，严格Clippy/fmt通过。坏MAC最短重放为12446字节协议前缀：末字节之前接受认证和4103字节合法明文，补入最后字节后拒绝；不改写捕获首部、业务或MAC。 |
| 纯Rust重复矩阵 | 两组均用aes-128-cfb和显式UID7。第8轮在AES-MD5/random_head、IPv4节点→IPv6目标读banner时UnexpectedEof。随后隔离错误追踪第15轮在chain_B/random_head、IPv6节点→example.invalid目标同样失败；服务端定位到chain.rs首部HMAC检查（用户表和目标访问之前），客户端仅观察到EOF。根因未定，尚无修复或相应复验通过。 |
| 临时诊断状态 | 隔离脚本已exit101；lib.rs/stream.rs的临时诊断代码已由既有EXIT清理恢复，交接时核对无诊断标记。恢复后未再运行标准构建；共享target中的最近测试产物不能视为新的标准验收。未清理共享target。 |
| 本地工具增量 | interop_shadowsocksr.py的启动异常清理调整与worker副本不同，尚未同步、未复验；其余7个SSR工具与归档worker副本一致。Rust源码没有此类本地/worker差异。 |

交接只读核对：76个已创建作业均有退出文件，SSR项目范围未见活动内核、参考端、抓包或驱动进程；退出0的诊断汇总脚本不代表其内部用例全通过。worker限定快照未包含Sudoku源码，没有执行workspace格式化、构建或测试。446个worker源码文件、1104项既有日志/结果/失败抓包材料及各自清单已存本地私有归档；连接资料没有进入公开记录。

### Mihomo固定失败的后续分类

原就绪门槛只确认监听和代理表，不能证明mihomo已进入Running。固定源码先发布监听/代理，随后才OnRunning；非Running阶段会关闭TUNNEL接入。目标先发chain_A/random_head失败抓包中未见mihomo发起SSR连接，只有工具的节点探测。工具改为独立DIRECT回环问候确认可转发，不使用SSR业务预热，也不加入业务延迟。此后该固定用例三向各50/50，完整目标先发矩阵48/48；旧47/48等失败仍保留。

客户端先发完整复验仍为43/48，具体失败为origin/random_head、AES-SHA1/random_head、chain_A/ticket_auth、chain_B/random_head、chain_B/ticket_fastauth。六种random_head及已出现失败的ticket用例分别固定同一cipher、凭据、节点/目标地址族和负载做mihomo→Rust、mihomo→原Python、Rust→原Python对照。原生mihomo向两种服务端均可复现故障；其发出的raw cipher流可超过输入负载，或在合法认证后出现后续MAC错误；TLS抓包显示双方Finished校验正确、应用记录在Finished之后，但后续记录头已被裸字节破坏。固定Python独立解码同一原始字节也报告错误。

`tools/reproduce_shadowsocksr.py`保存三向参数、每次结果和可选本任务端口抓包；`tools/analyze_shadowsocksr_wire.py`仅分析合成抓包，按捕获时钟重放参考校验；`tools/replay_shadowsocksr_wire.py`确定重放非法TLS前缀。两种原生服务端均先验证握手、接纳合法地址，再拒绝同一非法前缀。原生生产者故障仍为概率复现，不能称每次必现；确定性的是捕获字节的拒绝结果。

六组random_head的Rust→Python对照中，五组10/10；chain_A原有一次Address already in use启动失败且没有SSR业务，不能算协议失败或直接改写为成功。增加项目级端口租约后，该组另行20/20。ticket对照中，origin为Rust→Python20/20，V4为20/20，chain_A及chain_B fastauth分别10/10；mihomo向两种服务端的失败抓包逐项保留。

这些证据确认了参考端发出的坏流及就绪窗口，但不解释上文纯Rust自端EOF，也不足以证明mihomo内部唯一并发根因。未用sleep、跳过坏MAC或改写原生参考算法来取得通过；生产解码未放宽。当前任务保持待修，未进入下一协议。

## IV前缀源码修正及限定无网络验证

源码阶段仅修改stream.rs，当时未执行验证的集合SHA-256为 `861cb1fb20db7dc9200f1d8485eb7bfc991eef447afb7c19cec1b26622932711`。新增授权后只同步本包，使用worker当前mtime，保持原隔离workspace和旧归档；未同步其他WIP协议。包格式化后的集合SHA-256为 `7c7613e19a5e4e1fa47ccb1a4db471b601e3b553d5989facf601d1056ba3db8d`，格式化源码已取回，本地与worker一致。worker锁文件仍为前述 `6bd2ec…`。r7/r8/r10与后续失败证据不改写。

源码可确认的缺口：旧Reader在恰好收齐IV而没有cipher正文时就建立state、清空pending并调用空数据decrypt。对origin客户端，若此时收到EOF，drive检查到pending为空、protocol/layer均finished，便会返回干净EOF；还可能在尚无正文时登记IV。这与“IV前缀尚未完成载体正文”的状态不一致。

修正保留IV-only前缀，直到至少有一字节正文才初始化接收解码；这样既不做空decrypt，也让后续EOF保留截断前缀证据。混淆回写仍先进入原FIFO写队列，没有新增解密明文时不调用protocol解析。没有改动MAC校验、随机头回写格式、队列写偏移、半关闭排空或取消域，也没有加入sleep/宽松兼容分支。

新增两个测试均已按完整精确名称单独执行：

| 实际测试名 | 通过 | 失败 | 过滤 | 范围 |
| --- | --- | --- | --- | --- |
| stream::tests::independent_vectors_preserve_iv_only_and_empty_fragments | 1 | 0 | 9 | 既有39种独立cipher向量的IV-only、空片段和正文拼接 |
| stream::tests::iv_only_eof_is_not_a_clean_empty_response | 1 | 0 | 9 | 无网络I/O替身，区分完全空响应与有IV模式的截断前缀 |

环境限定为perf-01原SSR副本、构建并发1、Cargo离线与锁文件固定。包格式、lib check、lib Clippy（-D warnings）和包格式复核的实际退出码均0，命令如下：

```sh
cargo fmt -p kerlico-shadowsocksr
cargo check -p kerlico-shadowsocksr --lib --locked --offline
cargo clippy -p kerlico-shadowsocksr --lib --locked --offline -- -D warnings
cargo fmt -p kerlico-shadowsocksr --check
cargo test -p kerlico-shadowsocksr --lib --locked --offline stream::tests::independent_vectors_preserve_iv_only_and_empty_fragments -- --exact
cargo test -p kerlico-shadowsocksr --lib --locked --offline stream::tests::iv_only_eof_is_not_a_clean_empty_response -- --exact
```

首标签ssr-iv-only-isolated1完成4项格式/lib检查与第一个精确测试；Rust测试返回0并实际打印1项通过，但驱动名称匹配误判使脚本exit1，第二测试尚未运行。原错误和日志保留。后续ssr-iv-only-isolated2只运行剩余第二测试，exit0；未重跑第一测试，也未改变测试名称或扩大范围。核对时SSR项目活动进程0。此次实际执行的是两个新增测试，不是19项全部回归，更不是历史偶发EOF已修复。

确定结论只限于上述IV-only状态路径及本次两个定点回归。已有纯Rust错误定位在服务端chain首部HMAC比较、用户表和目标访问之前；缺少对应失败连接的双向原始字节，尚未证明空decrypt或无进展protocol调用就是该失败的原因。短写恢复、初始首部flush和写端关闭的源码顺序未发现可确认的提前关闭路径；不能据此宣布偶发EOF已解决。本轮没有执行集成测试、完整互通、历史抓包或此前中断的实验。
