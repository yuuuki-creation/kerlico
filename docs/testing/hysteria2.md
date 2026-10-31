# Hysteria2 验证记录

日期：2026-10-31。状态：本轮范围的 8 项 Rust 测试、自端正式 CLI 160 项和三个独立参考对端各 128 项互通通过。仅按下述快照、角色、载体、地址族和包长登记，不代表全部上游扩展或当前整树最终回归已经完成。

## 环境与快照

perf-01，Debian 13、Linux 6.12.41、x86_64，Rust/Cargo 1.99.1。所有格式、构建、Clippy、Rust 测试、Python 语法检查和互通均在 worker 项目区执行。本地只编辑、读取和同步，没有本地编译或测试。

| 对象 | SHA256 |
| --- | --- |
| `crates/protocol-hysteria2/` 文件名与内容聚合 | `509f9228e7afa70e31702798654ce06775278c4bfedbff086ecfdae908ce841e` |
| Hysteria2-only 正式 CLI 二进制 | `7842ad58848b7d33cd0a53fdebfa1bf70217b9ed8ceb6b34ab8a75ecdf4b306b` |
| worker 当时 `Cargo.lock` | `39e3e25ed0d1b6d94c03f64763849f2d3f83f10c707581b4934a80ac183d41ba` |
| 官方 app/v2.13.0 Linux amd64 参考二进制 | `907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691` |

模块聚合算法：按仓库相对路径排序，依次写入路径 UTF-8、一个 NUL 与完整文件内容；包含 Cargo.toml、src、tests。它不包含其他模块，不能代替整个工作区的快照摘要。

独立对端为 sing-box 1.14.4、Xray 26.10.29（`0afec66`）、官方 Hysteria app/v2.13.0（标签提交 `ca8fbd874fd6ca82413948de6dc5924405e103e1`）。前两者复用已核验资产，官方 Hysteria 资产在本任务项目区下载并核对官方 release API 的 SHA256；没有安装全局软件、服务或修改系统网络。

## Rust、格式与构建

首轮源码、接口、测试和工具一次写齐后统一编译。首次发现 H3 适配把原始业务数据当作 HTTP frame 写入的 API 错误，集中改为 SendStreamUnframed，并清理警告。后续严格 Clippy 的一处合并条件修正后复验。

以下命令在同一模块生产代码范围通过：

```sh
cargo fmt -p kerlico-hysteria2
cargo test -p kerlico-hysteria2 --all-targets
cargo clippy -p kerlico-hysteria2 --all-targets -- -D warnings
cargo fmt -p kerlico-hysteria2 --check
python3 -m py_compile tools/interop_hysteria2.py
cargo build -p kerlico --no-default-features --features protocol-hysteria2
```

1 项 wire 单元、7 项集成测试通过，集成部分耗时 2.19 秒。覆盖：

- 普通 QUIC/Salamander、BBR/Reno、IPv4/IPv6 代理载体；三类目标编码，TCP 目标先发、96000 字节与 FIN；UDP 0/1/4096/64000 字节、分片乱序/冲突与多目标。
- 错误 auth、TLS 名称、Salamander 密码不访问目标；UDP 关闭时 TCP 并发仍可用。
- 普通 H3 404、错误/正确 auth、鉴权前特殊流、鉴权后 TCP 与普通 H3 请求共享唯一分流器。
- 共享预算耗尽拒绝新流，关闭新预算后现有流仍排空，取消后所有预算归还。
- 真实统一 Egress/Direct：同一 UDP 关联访问 IPv4 与 IPv6 目标时保持相同出口端口，localhost 走 IPv4 路径，接受未预联系来源的 Full Cone 回包，零包双向保持。
- 严格配置拒绝、独立 auth 指纹、物理 UDP 监听与 TCP/UDP 业务语义区别。

Hysteria2-only 构建模块输出为 direct/reject 出站与 Hysteria2 双端。构建后立即复制到独立 bin 位置，互通期间没有被共享 target 的其他 feature 构建覆盖。

## 正式 CLI 互通

所有场景使用实际 IPv4/IPv6 TCP/UDP echo 目标，客户端、服务端均为正式 CLI；TLS 证书名称为 localhost，严格验证合成证书。每个方向/载体/拥塞/节点/目标分别启动独立配置，UDP 包长分别记录。

| 对端 | 本端角色 | 本端载体与拥塞 | 节点/目标 | UDP 业务包长 | 结果 |
| --- | --- | --- | --- | --- | --- |
| kerlico 自端 | 双向装配 | 普通 QUIC、Salamander；BBR、Reno | IPv4/IPv6 全组合 | 0、3、4096、64000 | TCP/UDP 共 160/160 |
| sing-box 1.14.4 | 客户端与服务端分别验收 | 同上 | IPv4/IPv6 全组合 | 3、2000、4000 | TCP/UDP 共 128/128 |
| Xray 26.10.29 | 客户端与服务端分别验收 | 同上 | IPv4/IPv6 全组合 | 3、2000、4000 | TCP/UDP 共 128/128 |
| 官方 Hysteria app/v2.13.0 | 客户端与服务端分别验收 | 同上 | IPv4/IPv6 全组合 | 3、2000、4000 | TCP/UDP 共 128/128 |

共 **544 项正式 CLI 检查通过，其中独立参考对端 384 项**。表中 BBR/Reno 是 kerlico 的选择，不能据此宣称对端使用相同拥塞实现或得出性能结论。2000/4000 字节分别进入多个 QUIC datagram 的业务分片路径；64000 字节只按自端范围记录，不外推官方 4096 字节缓冲的互通能力。

首次 CLI 自端工具错误地生成 CA:TRUE 证书作为 TLS 叶证书，导致连接失败。确认材料问题后，仅停止本任务失败矩阵及其子进程，改为 CA:FALSE、digitalSignature、serverAuth 并重跑上述完整矩阵；没有放宽生产 TLS 校验或修改握手逻辑。失败原始记录保留在私有工作区。

Xray 临时 freedom 配置仅允许当前 echo 的目标 IP/port。独立参考入口的零包限制另见 [Shadowsocks 对照](shadowsocks.md)，本表没有把未送达的参考零包登记成功。

## 重现工具和边界

`tools/interop_hysteria2.py` 接受 `--kerlico`、`--peer`、`--peer-kind`、`--work`，并用 directions/modes/congestion/node-hosts/target-hosts/udp-sizes 精确选择范围。默认独立对端矩阵即上表的 128 项；自端使用 `--udp-sizes 0,3,4096,64000`。

已验证范围不包含：Hysteria v1、Gecko、Brutal 固定速率、端口跳跃、Realm、noise、ECH、指纹模仿、HTTP/外部认证或反向伪装代理。客户端收到非零固定速率协商会明确拒绝，不接受后忽略。长期压测、丢包性能、跨地域链路、其他 OS/架构和当前整树最终发行验证未由本表证明。
