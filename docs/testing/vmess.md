# VMess 验证记录

日期：2026-10-31，Asia/Shanghai。状态：本轮限定双端已通过下列远端检查和真实对端矩阵；未登记的组合及大包外部互通不继承结果。

## 快照与环境

- worker：`perf-03`，Linux x86_64；`rustc 1.99.1 (58cf8f9c3 2026-10-13)`、`cargo 1.99.1 (5f94df478 2026-08-27)`，构建并发为 1。
- Rust 模块清单摘要：`5f18db16f17670116ac2c0b17bef6b73eee6dadbc37fbb5a5af081983bb1c0dc`。算法为模块内全部文件按相对路径排序、逐文件 SHA256，随后对紧凑有序 JSON 映射计算 SHA256。本地回传模块与 worker 逐文件一致。
- 远端锁文件 SHA256：`3633825534d540f542759e2efcf1475c604d485313058c0c1f46470eb45994bf`。锁文件为并行开发快照，最终工作区锁由主任务整合；该摘要不代替最终整树验证。
- VMess-only 调试二进制 SHA256：`08d832aac814c0bb42114867f3974ab8eb9b84e6318fe5df08c3e772af3ea41b`。
- 参考对端：Xray `26.10.29 / 0afec66 / go1.27.3 linux/amd64`、sing-box `1.14.4`。源码证据固定点见[调研](../../reference/research_notes/vmess.md)。

所有构建、格式、静态检查及测试均在 worker 的项目工作区运行。本地只编辑、阅读、同步与 Git 管理；凭据、配置、原始日志和完整结果留在私有目录。

## Rust 检查与根程序

```sh
cargo fmt -p kerlico-vmess --check
cargo test -p kerlico-vmess
cargo clippy -p kerlico-vmess --all-targets -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-vmess
```

四项全部通过。6 项单元测试覆盖固定 Go 向量的 command key/KDF/AuthID/两种 AEAD 与长度格式、认证标签损坏、计数器耗尽、重放、截断和读半帧取消后恢复。5 项集成测试覆盖两 cipher、RAW/WS/HTTPUpgrade/gRPC 单/多模式、none/TLS、TCP/UDP 的 40 个路径，另验掩码/padding/authenticated_length、IPv6 节点与目标、域名、错误 UUID/证书名称、取消、配置拒绝和半关闭后回包。

自端 UDP 包长为 1、1200、12000、65000 字节，未拆包；空包明确拒绝。该结果不能外推到第三方对端的大包行为。

根程序 `modules` 实际列出 `outbound/direct`、`outbound/reject`、`outbound/vmess`、`inbound/vmess`，没有注册其他协议。该构建未完成发行优化、裁剪矩阵及其他平台验收。

## 真实对端

| 对端与角色 | 条件 | 结果 |
| --- | --- | --- |
| Xray 双向 | 两 cipher × none/TLS × RAW、WS、HTTPUpgrade、gRPC 单/多；RAW 另含 authenticated_length 开关 | 48/48 配置通过，96 项 TCP/UDP 检查通过 |
| Xray 数据 | TCP 257024 字节；固定目标 UDP 17、1200 字节；关闭默认 cone/XUDP 转换 | 上述矩阵全部保留数据语义 |
| sing-box 双向 | RAW，两 cipher × none/TLS × authenticated_length 开关 | 16/16 配置通过，32 项 TCP/UDP 检查通过 |
| sing-box 数据 | TCP 257024 字节；UDP 17、1200、12000 字节 | 上述矩阵全部通过 |

工具为 `tools/interop_vmess.py`，分别使用 `--backend xray --full --udp-sizes 17,1200` 与 `--backend sing-box --udp-sizes 17,1200,12000`。Xray 显式设置 `xray.cone.disabled=true`，服务端 freedom 仅允许当前隔离 echo 目标的回环地址和端口。首轮夹具遗漏 freedom 规则导致客户端方向被对端黑洞；补齐后完整矩阵复跑通过，该失败没有登记为协议缺陷或通过结果。

## 大包边界与剩余范围

另行使用 AES-128-GCM、RAW、none 诊断两方向的大包：

- Xray 12000/65000 字节均未取得整包往返。kerlico 客户端方向的 echo 实际收到 `8192+3808`，65000 字节收到多个 8192 字节包及尾包；固定 `common/crypto/auth.go` 的大记录到 `buf.MergeBytes` 路径和 `buf.Size=8192` 与观察一致。服务端方向未取得完整回写，不能按另一方向补填。
- sing-box 12000 字节双向通过；65000 字节双向未通过。参考客户端方向出现多个较小数据报，包含 15000 字节记录，与固定 sing-vmess `WriteChunkSize=15000` 路径一致。不得为了使矩阵显示通过而在 kerlico 内透明拆分 UDP 包。
- 自端支持上限为 65456 字节；第三方仅按上述实测包长登记，不宣称全量大包兼容。
- 尚未实现或验收 Mux/XUDP、REALITY、XHTTP、mKCP、QUIC transport、旧 MD5/alterId 和旧 cipher；没有跨物理载体迁移、性能、安全审计或长期压力结论。真实矩阵的节点和目标均为 IPv4 回环；IPv6/域名的结果来自 Rust 自端回归，不冒充外部互通。

本模块通过不代表并行开发后的整个工作区、最新节点生命周期增量或最终发行包已经验收；整树复核由主任务另记。
