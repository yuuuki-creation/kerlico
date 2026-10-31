# TUIC 验证记录

日期：2026-10-31，Asia/Shanghai。状态：本轮 v4/v5 双端限定范围已远端验证；未列出的扩展、参数及平台不继承结果。

## 快照、工具链与对端来源

- worker：`perf-03`，Linux x86_64，Rust/Cargo 1.99.1，构建并发为 1。所有格式、构建、静态检查、单元/集成及互通均在项目 worker 执行，本地仅编辑、阅读、同步与 Git 管理。
- 模块 9 个文件的清单摘要：`c3ca3c52c72d8c3ea56a7448ff1698c53c95f6a5293372424ea17cf699463f39`。算法为相对路径排序后的逐文件 SHA256 映射，使用紧凑有序 JSON 再计算 SHA256；格式化代码已由 worker 回传。
- 远端锁文件 SHA256：`e82c2068fc5ae5df6548d0a93ebe7512dd20babaf8c9254fb926d08e2748091e`。它属于并行开发快照，最终工作区锁仍由主任务整合。
- TUIC-only 调试二进制 SHA256：`254aa51e7ef7c0ec4959db97221b95feb42baf83c714945eb991b1cb74055827`。补充边界与并发测试后重建，与真实互通所用冻结二进制摘要一致。
- Mihomo：官方 [v1.19.33 发布](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33)的 `mihomo-linux-amd64-compatible-v1.19.33.gz`，使用 [GitHub 官方发布元数据](https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.33)登记的 SHA256 核对下载内容后解压执行。压缩资产摘要为 `386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6`，二进制摘要为 `817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f`，版本输出为 v1.19.33/linux amd64/go1.26.10。没有仅以版本字符串判断来源，也没有声称完成可重复构建。
- sing-box：复用既有固定 1.14.4 对端，本轮核对版本与二进制摘要 `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`。

参考程序只位于项目私有工作区，不安装系统服务，不修改现有基础服务。合成凭据、PEM、配置、原始日志与完整结果留在私有目录；公开记录只保留中性别名和摘要。

## 构建与 Rust 回归

```sh
cargo fmt -p kerlico-tuic --check
cargo test -p kerlico-tuic
cargo clippy -p kerlico-tuic --all-targets -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-tuic
```

四项全部通过。2 项 codec 单元测试覆盖两版本地址/空包/截断、乱序分片、重复片及冲突片；7 项集成测试覆盖：

- v4/v5 × native/quic × IPv4/IPv6 节点 × cubic/newreno/bbr，共 24 个配置，分别访问 IPv4 和 IPv6 TCP 目标并验证 UDP。
- Full Cone：一个 association 跨 IPv4/IPv6、多目标保持同一出口端口，接收未先联系来源的数据报；域名经统一出口按 IPv4 优先解析。
- 使用不同凭据的两个 TUIC 节点形成链，保留上述跨目标同端口及未联系来源语义。
- 同一客户端并行 16 路 TCP 与 8 个独立 UDP association，负载不串流；8 个并存关联使用不同出口端口。
- UDP 空包、17/900/12000/65000/65507 字节的适用路径；65508 字节拒绝。v4 native 超实际 MTU 拒绝整包，随后小包仍能发送；其他模式保留大包。
- 错误凭据、证书名称、预取消；重复用户与 IPv4/IPv6 节点共享 UUID 即使密码不同也拒绝；未声明 Full Cone association 能力的出口在准备阶段拒绝。
- TCP FIN 后继续接收目标回包，以及节点关闭后的同端口复用。

`modules` 实际只注册 `outbound/direct`、`outbound/reject`、`outbound/tuic`、`inbound/tuic`。没有由其他协议的注册项推定本模块能力。

## 真实对端矩阵

| 对端 | 矩阵 | 结果 |
| --- | --- | --- |
| Mihomo v1.19.33 | v4/v5 × native/quic × IPv4/IPv6 节点 × 三种本端拥塞 × 客户端/服务端 | 48/48 配置，96 项 TCP/UDP 检查通过 |
| sing-box v1.14.4 | v5 × native/quic × IPv4/IPv6 节点 × 三种本端拥塞 × 客户端/服务端 | 24/24 配置，48 项 TCP/UDP 检查通过 |
| Mihomo 生命周期附加矩阵 | v4/v5 × native/quic × 两角色，IPv4 节点/cubic | 8/8 场景，24 项检查通过；包含业务互通、有界退出及同端口重启 |

真实 TCP 负载为 257024 字节；v4 native UDP 为 17/900 字节，其他模式为 17/1200/12000 字节。目标均为 IPv4 回环；IPv6 目标、多目标 Full Cone、空包和 65507 上限的结果来自 Rust 自端回归，不外推为第三方相同参数已经通过。三种拥塞配置使用固定 quinn 的真实控制器，但没有性能优劣或与对端同名实现等同的结论。

工具为 `tools/interop_tuic.py`，分别使用 `--backend mihomo --full`、`--backend sing-box --full` 和 `--backend mihomo --lifecycle`。就绪判断读取 Linux `/proc`，核对目标进程拥有的 socket inode 与监听状态，不建立并立即关闭代理探测会话，也不把 TIME_WAIT 当作监听。

初轮夹具曾被 Mihomo 的 SAFE_PATHS 限制拒绝读取案例目录外的合成证书；改用内存 PEM，未修改对端安全策略。另一轮主动 TCP 就绪探测伴随服务端方向复位；改为不创建代理会话后整矩阵通过，随后用进程 socket 所有权判定复验生命周期。上述失败保留为夹具记录，没有计入通过结果或据此推断密码实现缺陷。

## 未交付与未验证范围

0-RTT、UDP-over-stream/UoT、ECH、指纹、其他 QUIC 扩展、跨主机网络、其他系统/架构、长期压力、性能和安全审计均未验收。本轮没有验证所有 ALPN、证书链或数值组合，不能把配置接受外推为互通。

本模块结果不代表并行增量后的整个工作区或最终发行包已验收；主任务须冻结最终整树、锁文件和二进制后另行复核。
