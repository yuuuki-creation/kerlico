# WireGuard 验证记录

记录日期为2026-11-02。E-01原生双端在海外worker通过17项包级测试及官方peer双方向8配置矩阵，矩阵1194条检查通过、0失败、0未验证。正式发行仍须使用集成输入验收。

## 本轮实际结果

`perf-01` 的 `resumed-tor-wg-r70` 首次专项编译退出101，没有开始运行测试。WireGuard单测引用 `kerlico_egress::testing`，但开发依赖漏开 `test-support` 特性。修订仅为该开发依赖显式启用特性，避免依赖整树特性合并才可编译。

修订输入 `wg-resume-tests-r72` 的归档SHA256为 `65ee5973e01c84fcb12e215aee6a77fb47003441615d68c12c194ea774a93611`。在 `perf-01` 执行 `cargo test -p kerlico-wireguard --all-targets --locked -- --nocapture`，退出0，库17项全部通过，example测试目标0项。该命令涵盖下表包内回归，不代表example可执行程序或官方peer验收。包级构建 `wg-resume-helper-r71` 退出0，后续互通使用独立冻结并计算摘要的helper副本。

严格Clippy作业 `wg-resume-clippy-r74` 退出101，停于公共 `core-api/src/carrier.rs` 的 `AtomicU64::fetch_update` 弃用诊断，尚未检查到WireGuard包。未降低警告标准。

官方参考端初次诊断 `wg-interop-resume-r73` 的8配置均未通过。固定gVisor默认拒绝回环源地址，参考peer构建副本随后只启用回环接收，原始源码继续逐文件校验。`r77`、`r78`、`r80` 证明无扰动TCP与FIN通过后，最大UDP回显被Python默认8192字节缓冲截断；回显设施已修为65535，并添加真实65507字节往返回归。机制回归最初5项在旧工具为3失败、1错误，新工具5项全过；加入受限并发归并后共6项全过。机制结果不计为协议互通。

`wg-interop-resume-r76` 保留了旧持续扰动失败。每13帧持续丢1帧、每7帧持续延迟的1MiB传输在参考端20秒期限内未完成。后续矩阵采用固定一次丢包、两次20ms延迟和一次重放，继续保留1MiB载荷、完整回包及实际注入计数；不能外推持续高丢包性能。

修正上述设施后的 `wg-interop-resume-r81` 短矩阵通过68项、失败4配置、轮换4项未验证。出站4配置基础检查均过；入站均在IPv6的65527字节UDP失败，定位到公共Direct关联发送统一限制65507字节。该输入保留为公共修复前的失败证据。

公共Direct按目标地址族限制修订接回后，`wg-resume-net-tests-r84` 输入归档SHA256为 `b184a8f4bf742f37fd6f48ca7ce198c2c15187e41786fb2610c8768983824e36`。WireGuard all-targets再次退出0，库17项全部通过。`wg-resume-formatted-r82` 的包级 `cargo fmt --check` 退出0。

完整矩阵 `wg-full-resume-r85` 使用r84源码构建并冻结的helper，退出0，1194条检查通过。随后收紧keepalive断言，将计数基线从135秒活动开始前移到轮换结束后。`wg-full-resume-r86` 使用同一helper及收紧后的工具再次退出0，8配置共1194条检查通过，`complete=true`，失败和未验证均为0。每配置均实际丢弃1个载荷帧、延迟2帧、重放1帧；最后3秒静默期分别观察到4或5个新增keepalive。官方peer认证握手时间均前进，实际握手发起至少两次。

| 冻结输入或产物 | SHA256 |
| --- | --- |
| r84完整输入归档 | `b184a8f4bf742f37fd6f48ca7ce198c2c15187e41786fb2610c8768983824e36` |
| 根依赖锁 | `86f446b4269c27b61a68ac1e19897512b4e6fa9f1d9db093503d8a7cf4480c55` |
| Rust helper | `b951be3ba0547b3d77269fba2694e80ec527934142c19b654664d3368a52eeb1` |
| Go参考peer | `54c58b72d3b2102caded22250fe43520845ad9604088ec472c3fe2001c617609` |
| 官方netstack原文件 | `593bfb8df9be328926e2bf245ee8a48290a8a5480100c80002a380ffe7f08453` |
| 仅启用回环接收后的netstack文件 | `97ec1d592e97785025d418cddecf89f1d63cfd195f7b31852e2467022624d1c3` |

验证工具6项机制回归在r86同一工具字节上全部通过。完整矩阵后的checksum迭代写法由 `chunks_exact(2)` 改为 `as_chunks::<2>()`，`wg-checksum-clippy-r88` 再次通过17项包级测试，`wg-final-fmt-r89` 格式检查通过，`wg-final-clippy-r90` 普通Clippy退出0且WireGuard自身无警告；公共依赖仍有弃用及未使用项警告，不登记严格Clippy通过。该等价迭代修订没有重跑官方矩阵，最终发行需在集成输入继续验收。

## 输入与边界

产品固定Boringtun 0.7.1及smoltcp 0.14.0。官方参考peer固定wireguard-go `0.0.20250522`、提交`f333402bd9cbe0f3eeb02507bd14e23d7d639280`，使用上游内存netstack及固定gVisor依赖，不创建系统TUN。固定源码与归档摘要见[工具输入](../../tools/wireguard_interop/SOURCE.json)，设计及许可依据见[研究](../../reference/research_notes/wireguard-native.md)。

验收输入以归档摘要及逐文件清单绑定，r84的978文件在完整矩阵后仍与原始归档逐字节一致。根Cargo、锁、注册和公共carrier契约由主任务统一修改。正式发行必须记录同一冻结整树、锁、工具链、平台及命令，不能使用旧快照外推。

## 已编写回归

| 类别 | 行为断言 | 当前结果 |
| --- | --- | --- |
| 配置与隔离 | 纯编译、Local目标策略、非法MTU、重复或重叠peer、同节点接口冒用、跨节点static与PSK凭据复用拒绝 | r72库测试通过 |
| 加密 | 可选PSK、真实transport确认、重放与篡改拒绝、只有认证包允许endpoint漫游、再次握手后业务 | r72库测试通过 |
| IP与预算 | 双族空包及最大UDP、逆序分片、重叠和嵌套拒绝、全节点重组预算、过期及排队租约释放 | r72库测试通过 |
| TCP映射 | 同一内部源端口并发两个原网站目标，双族SYNACK与RST恢复原来源，失败后回收 | r72库测试通过 |
| TCP业务 | 外层IPv4与IPv6各承载双内层族，256KiB业务上传、FIN后的反向回包、目标拒绝RST | r72库测试通过 |
| UDP业务 | 固定目标、空包、大包、同关联多目标、双族来源及数据边界 | r72库测试通过 |
| 身份和生命周期 | 两个认证peer的可信用户区分、一个请求取消后共享服务继续、伪内源与错PSK不建立业务flow、服务关闭唤醒等待者、节点真实任务join与active flow归零 | r72库测试通过 |
| 唯一计量 | 实际业务用量精确一致，载体字节另列且不混入用户业务 | r72库测试通过 |

## 官方peer矩阵

[工具说明](../../tools/wireguard_interop/README.md)给出worker命令。`run.py`写有两个方向、两种外层族、PSK开关的8配置矩阵。每配置覆盖两个内层族的多个TCP和UDP目标，TCP先真实丢包、延迟乱序与重放，再核对完整载荷及FIN后的回包。UDP核对空包、最大载荷、分片、多目标及未知来源回包。

每配置默认保留135秒实际定时活动，通过官方peer的已认证握手时间与实际外层握手包证明会话轮换，再静默等待keepalive。`--rotation-seconds`低于130时明确输出该项`unverified`，完整结果的`complete`为false。

官方客户端到本节点方向另写有错PSK、未注册peer、伪内源、多peer可信用户及精确业务计量检查。Rust参考helper使用真实Registry、Engine和原生Direct目标访问，不把本机业务socket旁路当成WireGuard成功。双方进程与用户态UDP中继均由工具持有并核对退出。

完整135秒轮换矩阵在r86通过。该结论覆盖固定参考peer及本工具列明的双方向8配置，不能将短矩阵或包级结果外推到其他实现或平台。

## 集中验证顺序

完整首轮冻结后，由主任务在隔离海外worker统一完成根清单、锁和公共carrier接口集成。先执行格式、选定包全目标检查、严格Clippy及Rust测试，集中修改并复验。随后构建参考helper与固定官方peer，运行两方向完整矩阵，再进行整树及功能裁剪验证。

本机只阅读、编辑、同步和仓库管理。上述编译、格式与产品验证均在海外worker运行，没有修改Clash、系统网络或设备服务。长时间压力、动态PMTU、系统TUN、设备WARP、任意远端ICMP、其他平台兼容性、独立审阅、最终依赖许可闭包和正式发行仍未验收。
