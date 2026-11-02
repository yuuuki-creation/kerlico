# WireGuard 验证记录

记录日期为2026-11-02。E-01原生完整首轮已写入隔离工作树，当前没有编译、格式、静态检查、单元测试、自端互通或官方peer互通通过结果。下列内容是已编写的验收设施与计划，不能登记为已支持。

## 输入与边界

产品固定Boringtun 0.7.1及smoltcp 0.14.0。官方参考peer固定wireguard-go `0.0.20250522`、提交`f333402bd9cbe0f3eeb02507bd14e23d7d639280`，使用上游内存netstack及固定gVisor依赖，不创建系统TUN。固定源码与归档摘要见[工具输入](../../tools/wireguard_interop/SOURCE.json)，设计及许可依据见[研究](../../reference/research_notes/wireguard-native.md)。

本轮从中断的950文件partial输入恢复。旧作者11项新增文件的原始字节保留，本轮另有完整before/after清单交主任务集成。根Cargo、锁、注册和公共carrier契约由主任务唯一修改。最终验收必须记录同一冻结整树、锁、工具链、平台及命令，不能使用旧21协议快照外推。

## 已编写回归

| 类别 | 行为断言 | 当前结果 |
| --- | --- | --- |
| 配置与隔离 | 纯编译、Local目标策略、非法MTU、重复或重叠peer、同节点接口冒用、跨节点static与PSK凭据复用拒绝 | 待worker执行 |
| 加密 | 可选PSK、真实transport确认、重放与篡改拒绝、只有认证包允许endpoint漫游、再次握手后业务 | 待worker执行 |
| IP与预算 | 双族空包及最大UDP、逆序分片、重叠和嵌套拒绝、全节点重组预算、过期及排队租约释放 | 待worker执行 |
| TCP映射 | 同一内部源端口并发两个原网站目标，双族SYNACK与RST恢复原来源，失败后回收 | 待worker执行 |
| TCP业务 | 外层IPv4与IPv6各承载双内层族，256KiB业务上传、FIN后的反向回包、目标拒绝RST | 待worker执行 |
| UDP业务 | 固定目标、空包、大包、同关联多目标、双族来源及数据边界 | 待worker执行 |
| 身份和生命周期 | 两个认证peer的可信用户区分、一个请求取消后共享服务继续、伪内源与错PSK不建立业务flow、服务关闭唤醒等待者、节点真实任务join与active flow归零 | 待worker执行 |
| 唯一计量 | 实际业务用量精确一致，载体字节另列且不混入用户业务 | 待worker执行 |

## 官方peer矩阵

[工具说明](../../tools/wireguard_interop/README.md)给出worker命令。`run.py`写有两个方向、两种外层族、PSK开关的8配置矩阵。每配置覆盖两个内层族的多个TCP和UDP目标，TCP先真实丢包、延迟乱序与重放，再核对完整载荷及FIN后的回包。UDP核对空包、最大载荷、分片、多目标及未知来源回包。

每配置默认保留135秒实际定时活动，通过官方peer的已认证握手时间与实际外层握手包证明会话轮换，再静默等待keepalive。`--rotation-seconds`低于130时明确输出该项`unverified`，完整结果的`complete`为false。

官方客户端到本节点方向另写有错PSK、未注册peer、伪内源、多peer可信用户及精确业务计量检查。Rust参考helper使用真实Registry、Engine和原生Direct目标访问，不把本机业务socket旁路当成WireGuard成功。双方进程与用户态UDP中继均由工具持有并核对退出。

当前上述矩阵全部未运行，没有生成真实`results.json`。工具本身也尚未经过Python、Go或Rust检查。不能把计划数量或断言存在写成成功数量。

## 集中验证顺序

完整首轮冻结后，由主任务在隔离海外worker统一完成根清单、锁和公共carrier接口集成。先执行格式、选定包全目标检查、严格Clippy及Rust测试，集中修改并复验。随后构建参考helper与固定官方peer，运行两方向完整矩阵，再进行整树及功能裁剪验证。

本机只阅读、编辑、同步和仓库管理。本任务未连接worker、读取私有凭据、修改Clash、系统网络或设备服务。长时间压力、动态PMTU、系统TUN、设备WARP、任意远端ICMP、平台兼容性、独立审阅、最终依赖许可闭包和正式发行仍未验收。
