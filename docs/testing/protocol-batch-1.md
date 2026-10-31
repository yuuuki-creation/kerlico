# 首批协议与公共契约集成快照

日期：2026-10-31，Asia/Shanghai。该记录覆盖 VLESS、AnyTLS、SS2022、SOCKS、HTTP、Shadowsocks、Trojan、VMess 八个模块的冻结源码；当前工作树中的后续模块及增量分别验收，不继承本记录。

## 环境与固定输入

基线为 `6cbb3f94356889ab6d7311253c40af5259e00364` 加本轮开发内容。所有构建、格式、Clippy、单元/集成和互通在 perf-01 的 Linux x86_64 工作区执行，Rust/Cargo 1.99.1。本地只编辑、阅读、同步与 Git 管理。合成凭据、日志、二进制、完整源码归档与逐文件清单保留在私有目录及 worker。

| 对象 | SHA-256 |
| --- | --- |
| 冻结源码清单摘要，121 个文件 | `6836eca23465909faa9a0f869e536f4f6d8b43cd4ec15db83ca4b24481cfc1d1` |
| 冻结 Cargo.lock | `f53691f44e1e1203d9107f475eca7f76843dcb248256f7c41aba21b07fd40c68` |
| r4 八模块全功能 CLI，联合运行使用 | `420b9ba395bdc4a8f9189cdac47d963e9b671e52752448e00e7ed43cd8e253d3` |
| r3 无默认功能 CLI | `8fad7edbdcea2cf1060e1b9e44c0f721e3a16955a01399cd2895f93f5cc7096a` |

清单包含根 Cargo.toml/Cargo.lock 和 crates、apps、third_party 下的文件。先按相对路径逐文件计算 SHA-256，再对路径排序、紧凑 JSON 映射计算清单摘要；没有机器绝对路径。后续源码清单或根 feature 集合改变后，不将这些摘要描述为当前整树。

## 检查与修正

| 快照/步骤 | 实际结果 |
| --- | --- |
| 恢复时原树 | 整理格式后 55 项测试通过、1 项忽略，Clippy 和构建通过 |
| 首批第一轮冻结 | 96 项工作区测试通过、1 项忽略；严格 Clippy；默认、全功能、无默认功能构建通过 |
| 公共 UDP 关联及额外回归 | 28 项相关包级测试与严格 Clippy 通过 |
| 第三轮冻结 | 104 项工作区测试通过、1 项忽略；严格 Clippy、格式检查、全功能/无默认功能构建通过 |
| 后补协议回归 | SOCKS 9 项与 HTTP 7 项集成测试通过，严格 Clippy、正式 CLI 构建及固定 sing-box 矩阵复跑通过 |
| r4 同进程联合运行 | 81 项检查通过 |

忽略项为 AnyTLS 需显式固定 sing-box 的专用测试，未将忽略登记为通过；该模块已有独立真实对端记录。第三轮命令包括 `cargo test --workspace --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings` 和两种功能构建，均在仅含首批模块的冻结工作区运行。

中间一次归档同步未设置文件时间戳，导致 Cargo 复用旧接口产物并报告新类型不存在；核实源码存在、时间戳为零后修正并重新运行，第三轮才登记通过。后补 HTTP 分块请求测试曾因 Vec 类型推断失败未编译，显式标明字节类型后复验通过。保留失败记录，没有把它们改写成首次成功。

## 同一程序与独立节点

`tools/interop_combined_core.py --protocols vless,anytls,ss2022,socks,http,shadowsocks,trojan,vmess` 使用上述 r4 CLI。一个进程同时承担全部客户端转发与服务端角色，运行 16 个独立 IPv4/IPv6 节点；每个协议两节点凭据不同，均经统一目标访问服务访问 IPv4/IPv6 网站替身。

81 项包括注册集合、配置检查、60 条 TCP/UDP 数据路径、16 条跨节点凭据拒绝、16 节点并发收发、有界退出与完整配置同端口重启。HTTP 不安排其未提供的 UDP 路径。该结果验证限定装配与数据，不是吞吐或长期压力结论。

## 外部互通与边界

各协议独立对端与算法/载体/角色矩阵保留在对应测试记录。SOCKS/HTTP 最新正式 CLI 对 sing-box 为 52 项通过、4 项参考入口零包限制，限制项没有计作通过；独立 direct 入口对照可复现。最新 SOCKS 回归包含 IPv4 控制连接返回 IPv6 UDP relay，HTTP 回归包含普通 GET/HEAD/分块 POST、活动 CONNECT 排空与重绑。

本快照没有完成发行优化、其他 OS/架构、安全审计、长期压力或其余协议，协议总表仍是后续范围的唯一主清单。
