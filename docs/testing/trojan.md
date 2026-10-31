# Trojan 验证记录

更新日期：2026-10-31。状态：以下限定范围已在 perf-02 验证；整个仓库的其他并行增量不继承这些结果。

## 快照与环境

- 本地 Git 基线为 `6cbb3f94356889ab6d7311253c40af5259e00364` 加本轮未提交增量；构建使用同步到 worker 的源码，未在本地执行编译、格式检查或测试。
- 环境：perf-02、Linux x86_64、Rust/Cargo 1.99.1，构建并发 2。
- 对端：Xray 26.10.29，源码 `0afec66085a85191e9dd2a4a6646c7c9a94688d1`，Go 1.27.3/Linux amd64。
- 原始日志、生成配置、测试证书、锁文件副本及逐项 JSON 留在私有目录和 worker 项目工作区，不提交。

| 对象 | SHA-256 |
| --- | --- |
| protocol-trojan 模块树（含 Cargo.toml 与测试） | `1d054c6f8c69ae401992e35eab8c27531458b36785dffdda7837fe96e9562475` |
| 正式 CLI（仅启用 Trojan 功能） | `9af356a761f6d6a747659aed037d42658a2428d4cdb2821d34541890336fa9e1` |
| 固定 Xray 对端二进制 | `e783b9d2b46ed1ab3617c59b04dfbce38c999322d018c6e060f18d88bf6158aa` |
| worker Cargo.lock | `3633825534d540f542759e2efcf1475c604d485313058c0c1f46470eb45994bf` |
| interop_trojan.py | `8d0feb8b4c3d73ccdb81513edaf1ccea5b2ecbac1a6a2783a413419f9a74c9fc` |

模块树摘要按相对路径字典序，对每个文件依次拼接“UTF-8 相对路径、NUL、原始文件内容、NUL”计算。模块接口或实现变更后必须重新验证，不沿用本摘要。

## Rust 与构建检查

worker 上执行以下命令：

```sh
cargo fmt -p kerlico-trojan
cargo test -p kerlico-trojan -- --nocapture
cargo clippy -p kerlico-trojan --all-targets -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-trojan
```

`trojan-r4`：4 项单元测试、7 项集成测试全部通过；fmt、全部 target 的 Clippy（警告视作错误）通过。正式 CLI 在相同实现的 `trojan-r3` 快照构建通过，`r4` 只追加测试，没有更改协议实现。模块输出实际包含 `outbound/trojan`、`inbound/trojan`。

覆盖内容：

- SHA-224 已知向量、密码边界、IPv4/IPv6/域名编码、头部精确读取、非法认证/命令/CRLF、截断包和长度上限。
- 自端 RAW、WS、HTTPUpgrade、gRPC Tun/TunMulti，各自 TLS/回环明文，共 10 个组合，均验证 64 KiB TCP、0/17/4096/8192 字节 UDP。
- RAW、HTTPUpgrade、gRPC 半关闭后仍接收目标回包；WS 不宣称独立写端 EOF。
- IPv6 接入、域名 TCP 目标和跨地址族 TCP 访问；同一个 UDP 物理连接内两个不同目标的回包。
- 错误密码、错误证书名称、不受信证书、建立前取消、未知配置、跨节点凭据重复拒绝。
- WS、HTTPUpgrade、gRPC 活动连接在引擎排空期继续收发；引擎有界退出后同端口可重新绑定。

首轮 `trojan-r1` 的大负载测试曾失败：测试调用者写入缓冲载体后未 flush；补充显式 flush 后全部载体通过。`trojan-r2` 曾被测试宏内的相邻 if 排版触发 Clippy，修正后 `r3/r4` 通过。没有将失败记录改写成首次通过。

## 固定 Xray 双向互通

worker 上执行：

```sh
python3 tools/interop_trojan.py \
  --kerlico target/debug/kerlico \
  --reference <固定对端二进制> \
  --work-dir <本次私有结果目录>
```

`trojan-peer-r2`：**20/20 组通过**。矩阵为客户端/服务端两方向 × RAW/WS/HTTPUpgrade/gRPC single/gRPC multi 五种载体 × TLS/回环明文。

每组运行独立 IPv4 与 IPv6 接入节点，使用不同密码，分别访问 IPv4、IPv6 的 TCP/UDP 目标。TCP 测试 17/4096/65536 字节；UDP 测试 17/4096 以及经固定对端源码推导的包长边界。每个节点另测四路并发隔离、另一节点密码拒绝，服务端验证有界退出。

### 固定对端的 UDP 负载边界

`trojan-peer-r1` 的全部 20 组在测试 8192 字节 UDP 时失败，已保留原始结果。Xray 日志显示 `buffer is full`；其 Trojan 写包使用 8192 字节总缓冲，其中还要容纳地址头。依据与源码链接见[调研](../../reference/research_notes/trojan.md)。

复测已确认：IPv4 目标的 8181 字节、IPv6 目标的 8169 字节在完整双向矩阵通过。RAW/明文的双方向另各观察两种目标 8192 字节不能完整回写，共 4 个对端限制负例。这个限制没有通过截断或拆包隐藏，不能把 20/20 解释为 Xray 的 8192 字节有效负载兼容。

编解码单测覆盖 65535 字节；真实自端网络到 8192 字节。协议字段上限不替代目标系统原生 UDP 的限制。

## 未验收与后续范围

没有运行 sing-box 对端、其他平台、性能或长期压力。REALITY、XHTTP、mKCP、额外安全包装、通用 mux 与网站 fallback 未实现，不能从本矩阵继承支持。全程序同时启用其他协议的整树构建和联合运行由主任务另行记录。
