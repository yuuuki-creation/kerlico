# 在海外worker验证原生WireGuard

本目录在海外worker运行固定wireguard-go内存netstack参考peer，调用本项目生产工厂和Engine，不创建系统TUN，不修改Clash、系统代理、DNS、路由或设备服务。产品不调用本目录的Go程序。实际结果见[WireGuard验证记录](../../docs/testing/wireguard.md)。

`SOURCE.json`固定上游提交、归档SHA256与原始`go.sum`摘要。`prepare_peer.py`逐文件核对解压源码，在指定缓存内构建参考程序，另存实际依赖闭包与模块清单。它不安装软件，不修改全局Go配置，固定`GOTOOLCHAIN=local`，不自动下载工具链。参考程序依赖上游官方gVisor模块，仅用于验证。

固定gVisor默认拒绝从回环源地址到达的内层包，会丢弃本机原生回显响应。准备工具保留原始源码，再建立独立构建副本，仅将IPv4/IPv6工厂配置为 `AllowExternalLoopbackTraffic=true`。它逐文件核对副本除这一工厂参数外与原始输入相同，保存 `netstack-adapter.json` 中的原始及适配文件摘要；结果包含该适配记录。此修改只用于参考peer的回环网络栈，不修改WireGuard握手、加密、重放校验或产品代码。

## worker准备与集中检查

先由主任务集成工作区成员、依赖锁、注册和公共carrier计量契约。然后在分配的海外Linux worker独立工作区执行。需要项目Rust 1.99.1、Go 1.23.1或以上兼容版本，以及Python 3.10或以上。以下为验收命令，实际通过和失败分别记入测试记录。

```sh
export CARGO_TARGET_DIR="$PWD/.audit/worker-wireguard-target"
WG_CACHE="$PWD/.audit/worker-wireguard-peer"
WG_RUN="$PWD/.audit/worker-wireguard-run"

cargo fmt --package kerlico-wireguard -- --check
cargo check -p kerlico-wireguard --all-targets --locked
cargo clippy -p kerlico-wireguard --all-targets --locked -- -D warnings
cargo test -p kerlico-wireguard --all-targets --locked
cargo build -p kerlico-wireguard --example wireguard-peer --locked
python3 tools/wireguard_interop/prepare_peer.py --cache "$WG_CACHE"
python3 tools/wireguard_interop/run.py \
  --rust-peer "$CARGO_TARGET_DIR/debug/examples/wireguard-peer" \
  --go-peer "$WG_CACHE/wireguard-go-peer" \
  --run-dir "$WG_RUN" --jobs 4
```

`WG_RUN`必须是新目录。工具给目录设置0700权限，配置文件为0600，测试密钥只进入该目录，不进入公开结果。原始stderr与构建日志留在对应私有运行目录。发布结果前只取去秘密的`results.json`，另保存实际源码、锁、工具链、程序摘要和完整命令，不能发布配置或整个缓存。

`--jobs`允许1至4个配置并发，默认为1。各配置独占进程、文件、回环端口和断言列表，主线程在全部完成后归并。并发只缩短功能验收的等待时间，不能据此报告吞吐或延迟。

## 双方向业务与真实扰动

默认矩阵为两个角色、两种外层地址族和PSK开关，共8配置。`--role inbound`或`outbound`只运行指定方向，不能把单方向结果登记为全部通过。

每个配置都使用两种内层族及多个目标。TCP向实际回显端写入业务并半关闭，参考端等到EOF才回写端口标记与原载荷。首条TCP业务经过用户态UDP中继的实际丢包、延迟乱序和加密包重放，完整比对回包，并核对扰动计数大于零。中继使用工具自己绑定的空闲回环端口，不操作系统网络规则。

扰动在大于160字节的加密载荷帧中固定丢弃第13帧，延迟第7及21帧各20ms，重放第17帧。每配置保存实际丢弃、延迟和重放计数。这验证有限扰动后的1MiB传输，不表示持续高丢包性能通过。

UDP分别核对空包、1字节、4096字节及族内最大载荷。多目标命令保持一个逻辑关联，每族使用对应内部源IP与端口。Full Cone检查从一个未请求过的UDP来源收到第二个回包，核对载荷和来源端口。UDP阶段关闭丢包注入，不用自动重发掩盖不可靠语义。

官方客户端到本节点方向使用真实配置v2、成员和原生Direct出站，另检查未注册peer、错误PSK、伪造内部源地址不创建业务flow。第二个独立认证peer验证可信用户区分与精确业务计量。双方正常关闭后核对Engine无活动flow，进程真实退出。

## 定时轮换与结果口径

默认每配置观察135秒，并每秒发送独立UDP业务。官方peer的认证握手时间必须前进，外层中继至少观察两次握手发起，随后静默3秒核对keepalive继续出现。低于130秒的`--rotation-seconds`只适合先行诊断，此项记`unverified`，`complete`保持false。

`results.json`逐条记录已实际执行的断言、失败或未验证项，包含参考提交及两个程序SHA256。工具遇到一个配置失败会保存失败并继续其余配置，任何失败使退出码为1。诊断短矩阵没有失败时可退出0，但不表示完整验收，必须同时读取`complete`与`unverified`。

`--case`可重复指定单配置，`--no-impairment`及`--tcp-bytes`只用于定位故障。未运行配置、关闭扰动或更改首条1MiB载荷都会留下 `unverified`，不能得到完整通过。每个失败另存0600权限的私有 `*.failure.log`，公开结果仅保留错误类型。`test_run.py`验证这一结果口径，以及原生UDP回显端实际保留65507字节载荷；机制测试不计为协议互通。

实际结果以测试记录为准。短矩阵、一次握手或自端成功不代替完整官方双方向验收。长时间压力、其他操作系统、系统TUN、设备WARP及任意远端ICMP不在本工具通过结论内。

## 文件与许可

`peer/main.go`是项目自有的JSON控制与测试应用代码，采用工作区GPL-3.0-only许可。下载的wireguard-go保留官方MIT许可，gVisor保留Apache-2.0及其依赖通知。`prepare_peer.py`保留下载归档内的原许可，不把上游材料改授GPL。最终发布工具或产物之前仍须由主任务核对实际依赖闭包和分发通知。
