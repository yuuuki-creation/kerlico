# 十一模块冻结工作区集成

日期：2026-10-31。该快照是在首批八模块基础上加入 Snell、TUIC、Hysteria2，覆盖当时已完成的十一模块；后续 SSH、ShadowQUIC、Hysteria v1、SSR、ShadowTLS 及公共增量分别验收。

## 固定输入

perf-01、Linux x86_64、Rust/Cargo 1.99.1。原始源码清单、源码归档、完整日志和逐项结果留在私有目录，源码基线为 6cbb3f9 加本轮增量。不存在本地编译或测试结果。

| 对象 | SHA-256 |
| --- | --- |
| 冻结源码 155 文件有序清单 | `36296e2587361fc83f7bd7db24130f7208803dae4a1c337086b7f43c3173b4eb` |
| Cargo.lock | `39e3e25ed0d1b6d94c03f64763849f2d3f83f10c707581b4934a80ac183d41ba` |
| 默认功能 CLI | `75d49e3169aac10ad619aa448dde3adee4d00c63ccaee60ef42f2379c535c876` |
| 全功能 CLI | `dad115956d0305a99b3a25b8a987901cc3863c3402121103e7e3279e5de5c0f8` |
| 无默认功能 CLI | `9f605069b2b3cf88b5aa33476db5facb31b59275dbf6dd7eb41ba795233d59e3` |

清单取根 Cargo.toml/Cargo.lock 和 crates、apps、third_party 文件，按相对路径逐文件 SHA-256 后对有序紧凑 JSON 映射计算摘要。这里的默认/全功能只指该冻结清单里的功能集合，不描述当前不断加入模块的根 manifest。

## 整树与功能裁剪

写齐对应模块后，在过滤冻结工作区执行格式、工作区测试、严格 Clippy、格式复核及默认/全功能/无默认功能三种构建：**139 项 Rust 测试通过，2 项显式对端/向量用例忽略**，全部命令成功。忽略项不是通过；AnyTLS 独立对端和 Snell 64 组独立向量的显式结果各自记录。

首次解析新增依赖后，Clippy 与后续构建使用 --locked。没有把尚未写齐的新包混入 workspace 测试，也没有用源码存在推定二进制注册。

## 同进程联合运行

同一个全功能 CLI 同时承担十一模块双角色，22 个独立 IPv4/IPv6 节点，经统一出口访问两类目标，**111 项检查通过**。包括注册集合、配置检查、84 条 TCP/UDP 路径、22 条跨节点凭据拒绝、并发收发、按预算退出和全配置同端口重启。

命令为 `tools/interop_combined_core.py --protocols vless,anytls,ss2022,socks,http,shadowsocks,trojan,vmess,snell,tuic,hysteria2 --udp-size 512 --max-sessions 512`，另提供固定 CLI 与私有结果目录。联合测试选各模块一个已实现组合，不替代每模块完整角色/载体矩阵；HTTP 不安排 UDP，512 字节不代表大包性能或全部对端上限。

## 后续增量

该快照之后修正 Shadowsocks none/plain 为真实无认证本地入口，并新增流连接器及包装凭据域，相关结果另记接口/模块记录。不能将本次139项外推这些增量或之后模块。下次完整冻结仍需复核最终源码、锁、功能集合与实际联合路径。
