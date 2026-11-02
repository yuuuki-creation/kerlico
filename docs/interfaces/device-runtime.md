# 应用设备所有者接口

CLI 在配置 `device` 段且存在 `dual-stack` 本地出网时创建 `DeviceRuntime`，配置见[配置接口](config.md)。

`kerlico-device::DeviceRuntime` 由应用拥有专用执行线程、Tokio runtime、单写者状态锁与唯一 WireGuard 后端。`prepare(DeviceRequirements)` 返回可以交给多个 `Engine::bind_with_device` 的 `DeviceLease`。同一所有者并发准备共用一次有界注册/启动；Engine、节点或等待者退出不退役设备。应用调用 `shutdown_at` 固定首次绝对期限，`DeviceRetirement` 保存原生线程真实 join 收据，超时时线程可能尚未回收。

`DeviceNetwork` 原有 socket 方法继续仅用于载体，target 三个方法返回现有业务通道。Direct 声明 `OutboundPlan::with_native_targets`，计划只有该标记绑定的双栈入口才声明 `auto_warp`。WireGuard 等自带目标隧道保持 `TargetPolicy::Local`，不触发设备准备。Remote 仍由 Dispatcher 原目标透传，不调用设备 target 能力。

原生探测使用不发包的 UDP connect 与实际源地址，只报告内核路由可选择，不等同公网可达。双栈缺族目标才用 WARP；单栈始终借原生能力。混合 UDP 关联保留 Native 与 Warp 两个独立稳定来源绑定，回包保留业务来源；不能声称跨后端拥有同一来源端口。WARP 载体固定选择可用原生族，不调用 target 方法。

私有状态目录必须绝对路径，其祖先可信且不可由其他账户写入，最终目录0700，锁和身份0600且拒绝符号/硬链接。先原子持久化私钥和注册意图，再发一次固定 wgcf v2.3.0 逆向profile注册。未知结果的意图阻止自动新建身份；正常证书和名称验证，不操作系统 WARP/Mesh。此层实现进程内所有权，不提供跨进程共享；后续同一binary daemon/IPC应复用此所有者。

`DeviceOptions::new` 的注册策略是 `CreateOnce`，仅空状态进入独立的 `register_once` 入口。`DeviceOptions::existing` 固定为 `ExistingOnly`，在创建专用 runtime 前验证绝对私有路径、完整响应及其注册公钥与持久私钥的匹配；缺失、不完整或不匹配均直接失败，不调用注册入口。已有 profile 的真实业务验证必须使用此模式。

真实验证中共创建两份独立注册，第二次由测试复用路径复制失败后仍继续启动造成。两份状态均已保留，未删除或继续注册。验证入口已改成已有匹配 profile 必需模式；缺失或不匹配时注册请求数为零。当前通过的真实数据面结果包括双族 HTTPS（正常证书验证、trace `warp=on`）与双族 UDP DNS。跨进程共享仍须由上层 daemon/IPC 实现。

设备服务首因通过 `DeviceRuntime::failure()` 和 `DeviceRetirement::failure()` 查询，沿用核心 `ServiceFailure` 的稳定分类；后端运行与关闭共用同一个只保留首因的 `ServiceStatus`。活动设备发生后台失败后，`phase()` 返回 `Failed`，新的准备或业务开通返回该首因；后续关闭错误不覆盖它。进入显式回收后仍使用 `Retiring` / `Closed` 表示回收进度，失败原因另存并在所有者释放后由收据继续保留。

后端 `shutdown` 返回错误会计入最终失败数，超时会锁存到最终收据的 `timed_out`；设备仍回收真实服务任务并等待原生线程 join，不把后端返回或截止时间当作任务已释放。WireGuard 后台不再以单独布尔值丢失错误，运行错误写入同一服务状态；协议静态首因与 I/O 错误类别保留，动态上游文本不进入服务状态。
