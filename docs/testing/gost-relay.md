# Gost Relay 验证记录

日期：2026-10-31。首轮生产代码、接口、Rust测试和官方GOST工具写齐后，已在perf-01通过15项Rust测试、严格Clippy、fmt及仅Relay CLI构建。固定官方GOST完整第二轮64组配置、704条路径/生命周期记录全部通过；原始TCP额外FIN矩阵28/28通过。仅验收下列出站范围，本地没有编译或测试。

独立worker冻结快照的6项单元与9项网络测试全部通过，无忽略项。范围包含独立请求字节、地址/认证/扩展、负状态及截断、两载体族和三类目标、真实TLS证书/名称拒绝、固定转发前置匹配、65537字节TCP与原始FIN、UDP空包/12000/65507及65508拒绝、取消与真实socket回收、部分帧取消后续读、部分发送毒化和SMUX v1记录/FIN顺序。

`tools/interop_gost_relay.py` 要求显式官方GOST v3.3.2路径及其已核验二进制SHA256，在worker内启动隔离回环参考服务和正式CLI。完整配置维度为TLS开关、SMUX v1开关、eager/deferred响应、认证/无认证、两节点地址族、代理/固定转发；每个配置分三类网站目标和客户端/目标先发两类流量。TCP17/4096/65537，UDP17/12000，错误认证、四路并发、预算退出及同配置同端口重启分别记录。

官方节点显式SMUX v1；eager条件显式nodelay=true，deferred保留nodelay=false。固定源码的Pipe只在nr>0时转发数据，且每次读取缓冲32768字节，因此官方零包/65507边界另做直连目标控制和实际观察，不把这些失败计作全包成功，不改内核为截断以通过。独立UDP目标接收上限65535，避免测试夹具默认8192造成误判。

已执行的检查与互通命令形状：

```sh
cargo fmt -p kerlico-gost-relay
cargo test -p kerlico-gost-relay
cargo clippy -p kerlico-gost-relay --all-targets -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-gost-relay
python3 tools/interop_gost_relay.py --kerlico <冻结CLI> --peer <固定GOST> --peer-sha256 <实际摘要> --work-dir <新的私有目录>
```

首轮真实矩阵704条记录中592条成功、112条失败；所有明文SMUX配置的业务及重启失败。固定官方GetInt只接受string/int，不接受JSON解码的float64，工具中数字1被忽略；MTCP因此实际使用默认v2，日志明确invalid protocol。MTLS公共默认v1，其他非SMUX路径也通过。工具改为字符串"1"，内核代码和二进制未变，完整第二轮704/704通过。首轮拒绝路径还可能因版本不匹配关闭，不能将这部分阴性记录单独当作正确鉴权证明。

第二轮64配置每组覆盖6条正向网站/流量路径，认证配置另验6条错误凭据，再分别退出与同端口重启，共704条记录。记录内部2176项功能检查包含TCP三长度、UDP两长度、凭据拒绝及四流并发（并发四流按一项记录），不是与704条相加的独立组合数。单独FIN阶段4配置覆盖两载体族、两响应模式、三类网站与17/65537字节，24条真实EOF后回包及4条退出共28/28通过。配置明确要求require_remote_eof，TLS/SMUX仍不声明该能力。

两个矩阵结束后按本任务独立二进制路径查询，实际存活的自有内核/参考代理进程数为0。没有重启或修改worker的基础服务。

官方零包/大包控制：TLS下SMUX关闭/开启两条路径，直接目标均能完整回写0与65507字节；经GOST零包均超时，65507均只回32768。与固定Pipe的nr>0及32768缓冲一致，未把这些边界记作完整包互通。

| 首轮对象 | SHA256 |
| --- | --- |
| Relay模块10文件有序JSON清单 | `24cdc76c7a7bc130926c07282af8e5226ab8fd1a2fd4bd260febf78611ac419d` |
| 选定集成源码有序JSON清单 | `83345915f8ad7a0305e0eb7acf695765f0ba856d8b9b7c0fe787d18b9007bcbc` |
| worker锁文件 | `24f923a91fb802011c3f0a8645e976e4e6ef8869aea01e098b1a5cd6feba5c2d` |
| Relay-only CLI | `7b57f603f650c13941152a2e1718ff866f010795a68c8a02e7774ee43161181e` |
| 官方GOST二进制 | `19b5d8591ce794dfd0775e7f18f19451f23c01ab69ff18ead25f882a4e6eef28` |
| 完整第二轮工具 | `b86234797f3826ff0b19b7bda0e88a0288acf351364a191fb6bc7a7674b2f73c` |
| 追加FIN阶段工具 | `c3476f34a4d0875f8e6519e2600300c49e9c5a1278eb64d923908a2f19471fc9` |

源码清单按仓库相对路径逐文件SHA256，对有序紧凑JSON再取SHA256。选定集成输入只包含当时十三模块冻结工作区，不是当前含Mieru等在写包的共享整树。官方二进制由已核验发行归档提取，版本gost3.3.2/go1.27.3/linux-amd64。原始结果、完整日志和来源保留私有，历史失败不改写。

没有登记服务端、BIND、多目标UDP、SMUX v2、其他Go-GOST载体、性能或全工作区验收。
