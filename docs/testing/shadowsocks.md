# Shadowsocks 验证记录

日期：2026-10-31。状态：本轮原生 TCP/UDP 双端代码、自端完整方法矩阵及下述独立对端限定矩阵通过。结果仅适用于记录的 worker 快照，不替代当前整树最终回归，也不覆盖插件、UoT、SSR 或多目标同源口关联。

## 环境与来源

专用 worker：perf-01，Debian 13、Linux 6.12.41、x86_64，Rust/Cargo 1.99.1。所有格式、编译、静态检查、Rust 测试、Python 语法检查及互通均在 worker 项目区执行；本地只编辑、阅读和同步。

固定参考对端：sing-box 1.14.4，Xray 26.10.29（`0afec66`）。复用此前已按官方发行资产 SHA256 核验的二进制，没有安装服务或修改基础设施。合成凭据、原始日志、配置和产物留在私有工作区。

快照标识：

| 对象 | SHA256 |
| --- | --- |
| `crates/protocol-shadowsocks/` 文件名与内容聚合 | `f1db5072a83d1cf23c4c60214f4653b6a4c9ee16b761639026fa131ea0bc2693` |
| 互通使用的 SS-only `kerlico` 二进制 | `b172e1887214305c3a225be09869a1470f046bd67a3e20e9791c9fa57d5725b8` |
| worker 当时的 `Cargo.lock` | `3633825534d540f542759e2efcf1475c604d485313058c0c1f46470eb45994bf` |

模块聚合算法：按仓库相对路径排序，依次向 SHA256 写入路径的 UTF-8 字节、一个 NUL 和完整文件内容；模块包含 Cargo.toml、src 与 tests。该值不含其他模块，不能证明整个工作区未变化。

## Rust 与静态检查

首轮完整范围一次写齐后，远端编译成功。最初完整方法矩阵在 camellia-192-cfb1、域名目标、64000 字节 UDP 处超时。单方法复验确认 debug 逐 bit 密码的三类目标矩阵耗时 29.01 秒；将该矩阵的空闲/回包预算分别设为 30/20 秒后，完整方法矩阵通过。生产空闲策略和独立 80 毫秒回收测试没有放宽。

- `cargo test -p kerlico-shadowsocks --all-targets`：2 项单元和 6 项集成测试通过，集成部分耗时 115.29 秒。
- 随后新增 TCP salt/IV 重放回归：42 种带随机 salt/IV 方法均拒绝重放，目标访问次数保持一次；该测试通过。rc4/table 无随机 IV，不套用此结论；none 不提供重放防护。
- 新测试初次 Clippy 发现一处多余 `copied`，修正后相应测试、`cargo clippy -p kerlico-shadowsocks --all-targets -- -D warnings` 和格式检查复验通过。
- Rust 测试共 9 项分上述两轮通过。全部 10 AEAD、34 旧式流方法及 none，分别覆盖 TCP/UDP、域名/IPv4/IPv6 目标编码、目标先发数据、半关闭、跨块数据、零长度与 64000 字节包；另验 IPv6 代理载体、错误 AEAD 密码、UDP 重放/认证失败、预算、空闲与取消。
- `cargo build -p kerlico --no-default-features --features protocol-shadowsocks` 成功；模块输出为 direct/reject 出站及 Shadowsocks 双端。互通二进制立即复制到独立位置，避免被共享 target 的其他 feature 构建替换。
- 两个 Python 工具在 worker 完成语法检查。

## 独立参考对端矩阵

下列每项均通过正式 `kerlico` CLI，目标为实际 IPv4/IPv6 TCP/UDP echo 服务；不同方法、方向、节点和目标地址族分别启动独立配置。TCP 负载跨多个加密块。UDP 每个包长单独记录，不把一个成功包外推到其他长度。

| 参考对端与方法 | 方向 | 节点/目标 | UDP 业务包长 | 结果 |
| --- | --- | --- | --- | --- |
| sing-box：aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、xchacha20-ietf-poly1305 | 双向 | IPv4/IPv6 全组合 | 3、12000 | TCP/UDP 合计 96/96 |
| sing-box：AES 128/192/256 CTR、AES 128/192/256 CFB128、rc4-md5、chacha20-ietf | sing-box 客户端 → kerlico 服务端 | IPv4/IPv6 全组合 | 3、12000 | TCP/UDP 合计 96/96 |
| sing-box：none | 双向，节点均为回环 | IPv4/IPv6 全组合 | 3、12000 | TCP/UDP 合计 24/24 |
| Xray：上述四个 AEAD | 双向 | IPv4/IPv6 全组合 | 3、4096 | TCP/UDP 合计 96/96 |

合计 **312 项限定互通通过**。未列的 AEAD 扩展、Camellia、CFB1/CFB8、OFB、rc4、table 等仍只有自端矩阵，不能称作已通过独立核心互通；sing-box 的 legacy 服务端角色也未由客户端结果补填。

Xray 临时 freedom 配置显式只允许当前 echo 的目标 IP/port。初版工具漏配该项，被其针对 Shadowsocks 私网目标的默认规则阻止；补齐测试对端配置后，四 AEAD 的完整限定矩阵复验通过，没有为此修改 kerlico 协议代码。

## 零包与参考入口包长对照

首轮 sing-box 聚合矩阵 36/48 通过，12 项失败均为 kerlico 服务端方向的 UDP，最先发送零长度包。将负载拆开后，非零包通过而零包超时。以下独立对照完全不经过 kerlico 或 Shadowsocks：

`参考 direct/dokodemo-door 入口 → 参考 direct/freedom 出站 → UDP echo`。

| 参考入口 | 3 字节请求，应答 8 字节 | 12000 字节请求，应答 12005 字节 | 0 字节请求，应答 5 字节 |
| --- | --- | --- | --- |
| sing-box 1.14.4 direct | 收到 8，内容一致 | 收到 12005，内容一致 | 未收到，超时 |
| Xray 26.10.29 dokodemo-door | 收到 8，内容一致 | 只收到 8192，内容不符 | 未收到，超时 |

因此保留这些参考入口失败记录。零包在本模块全部方法自端路径通过，kerlico 客户端至 sing-box 服务端的标准 AEAD 零包也通过；参考入口丢弃的零包不能记为 kerlico 服务端已完成独立对端验收。Xray 的 12000 字节失败也不能靠缩写矩阵消失，4096 字节通过只证明该限定长度。

公开复测入口为 `tools/diagnose_shadowsocks_udp_ingress.py`，输出实际收包长度与超时；它是测量工具，退出状态不代表所有长度都被参考入口支持。

## 集成审查后的无认证入口增量

主任务发现旧 none/plain 配置曾用空 key 的固定哈希满足节点非空指纹校验，但这不代表实际认证。现已改为空指纹，仅通过强制回环 `local_inbounds` 提供无认证服务，`nodes` 仍拒绝；没有修改 cipher、TCP 或 UDP 线格式。该增量在 perf-01 的注册表回归、严格 Clippy 与 SS-only CLI 构建通过，none 对固定 sing-box 的双向/双节点族/双目标族、TCP/UDP 3/12000 字节合计 24/24 项复验通过。它不重写上文旧源码和二进制摘要，属于后续独立快照；不将其称为 none 取得了认证。

## 重现入口

仅在 worker 项目区运行，二进制和工作区路径由私有配置提供：

```sh
cargo fmt -p kerlico-shadowsocks --check
cargo test -p kerlico-shadowsocks --all-targets
cargo clippy -p kerlico-shadowsocks --all-targets -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-shadowsocks
python3 tools/interop_shadowsocks.py --help
python3 tools/diagnose_shadowsocks_udp_ingress.py --help
```

互通工具通过 `--methods`、`--directions`、`--node-hosts`、`--target-hosts`、`--udp-sizes` 精确选择矩阵，`--peer-kind` 指定 xray 或 sing-box。完整默认矩阵仍包含零包；参考入口不支持时如实返回失败，不能为获得全绿而静默忽略。
