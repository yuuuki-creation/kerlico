# Tor验证记录

更新日期为2026-11-02。P-23首轮评审修订、接口、回归和worker工具已写齐。早期输入已有下列worker检查与包级结果；当前修订尚未执行构建、格式、静态检查或回归，没有真实Tor网络通过结果。

## 早期输入结果

`tor-native-first-check-r52`的源码归档SHA256为`31ecd8a9e0acae43eced009e360f0c22466a6420e2c0e9a5fe5e94a9254cd6e7`，Tor all-targets检查退出0。`tor-native-first-tests-r54`归档SHA256为`740c6da403cf7f770a7ce69d34fd35543a3a65451fd8ce399f9793be53b3e786`，Tor库14项全部通过。该作业整体退出101，core库12项和flow顺序4项通过，service_blocking为2通过1失败，失败项为`interrupted_blocking_shutdown_retains_first_deadline_and_late_panic`。不能把Tor包通过改写成该整作业通过。

以上结果不含本轮完整祖先信任、typed服务失败、Blocking句柄panic传播、实际builder/watch事件接线及worker证据修订。原输入、原始日志和摘要由根任务保留，不用旧结果代替下表的待验修订。

## 固定输入

原生实现使用`arti-client 0.47.0`及局部fatal回调补丁，发布提交`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`。实际依赖闭包须绑定根锁文件，运行CLI与源码清单须分别计算SHA256。固定来源见[研究](../../reference/reports/tor-implementation-20261102.md)。

本轮所有命令只交海外worker执行。本写者没有运行Rust、Python产品脚本、构建、格式或静态工具，也没有连接worker、Tor网络或修改Clash。

## 回归矩阵

| 位置 | 用例 | 要证明的行为 | 状态 |
| --- | --- | --- | --- |
| core-api `service_blocking` | `running_blocking_resource_survives_abort_and_is_joined_after_timeout` | 阻塞socket真实保留，abort不能伪造释放，完成后才能重新绑定 | 待执行 |
| 同上 | `interrupted_blocking_shutdown_retains_first_deadline_and_late_panic` | 短等待及中断不延长首次期限，迟到panic仍计数 | 待执行 |
| 同上 | `closed_service_rejects_blocking_work_without_running_it` | 关闭后不执行闭包 | 待执行 |
| protocol-tor | `tor_config_rejects_unknown_role_backend_and_path_escape` | 不接受伪入站、外部后端、UDP或越界路径 | 待执行 |
| 同上 | `tor_config_accepts_explicit_project_storage_and_bounded_timeouts` | 显式路径与预算边界 | 待执行 |
| 同上 | `tor_storage_has_one_writer_per_named_instance` | 同名排他、不同命名隔离和真实锁释放 | 待执行 |
| 同上 | `tor_storage_rejects_symlinks_and_public_permissions` | Linux目录权限和链接拒绝 | 待执行 |
| 同上 | `tor_storage_rejects_untrusted_ancestor_during_replacement_race` | 可写祖先下同时发生改名和链接替换时，在写入前拒绝，不触碰外部目标 | 待执行 |
| 同上 | `tor_storage_rejects_writable_ancestors_before_creating_state` | 组可写及sticky共享祖先均在创建状态前拒绝，私有叶目录不改变结论 | 待执行 |
| 同上 | `tor_storage_rejects_linked_lock_without_touching_its_target` | 锁文件NOFOLLOW，不修改链接目标 | 待执行 |
| 同上 | `tor_storage_rejects_hardlinked_or_nonprivate_lock_without_modifying_it` | 多硬链接和非0600锁文件均拒绝，原内容保持不变 | 待执行 |
| 同上 | `tor_errors_keep_category_without_upstream_details` | 稳定错误映射和敏感内容不透出 | 待执行 |
| 同上 | `tor_factory_exposes_remote_tcp_without_eof_or_udp` | 能力与远端目标策略一致 | 待执行 |
| 同上 | `tor_async_spawn_registers_nested_real_socket_and_joins_on_shutdown` | 嵌套异步工作归同服务，实际socket关闭 | 待执行 |
| 同上 | `tor_closed_blocking_adapter_rejects_without_running_callback` | 无取消变体的句柄不会触发已拒绝工作 | 待执行 |
| 同上 | `tor_dropped_blocking_waiter_keeps_native_socket_owned_until_real_finish` | 丢弃适配器等待器不失去真实阻塞任务 | 待执行 |
| 同上 | `tor_native_blocking_panic_remains_service_failure` | 原始panic保留失败事实 | 待执行 |
| 同上 | `tor_blocking_handle_rethrows_original_panic_when_polled` | 句柄poll恢复原始panic payload，native失败仍计数 | 待执行 |
| 同上 | `tor_fatal_closes_only_its_named_service_and_cannot_be_reset_ready` | fatal同步停止服务、既有流失败、其他服务存活 | 待执行 |
| 同上 | `tor_service_failure_keeps_first_cause_after_another_failure_and_close` | 重复失败、ready及正常关闭不覆盖已发布的服务首因 | 待执行 |
| 同上 | `tor_carrier_uses_device_literal_address_and_service_cancellation` | carrier只调用设备字面地址能力，取消有类型来源 | 待执行 |
| 同上 | `tor_carrier_rejects_new_admission_and_pending_io_after_fatal` | fatal后现有carrier读失败，新准入不调用设备 | 待执行 |
| 同上 | `tor_request_cancel_wakes_both_pending_halves_without_stopping_service` | 请求取消唤醒读写两半且服务继续 | 待执行 |
| 同上 | `tor_pending_bootstrap_wait_has_request_budget_without_cancelling_service` | 请求预算不关闭共享bootstrap | 待执行 |
| 同上 | `tor_fatal_overlapping_admitted_poll_stops_at_next_observation` | 已准入poll内发布fatal，下一观察点拒绝再次进入底层写 | 待执行 |
| 同上 | `tor_builder_cached_required_protocol_failure_preserves_actual_bootstrap_cause` | 生产builder及RunningInner初始缓存检查保留SoftwareDeprecated首因，未开始目录bootstrap | 待执行 |
| 同上 | `tor_builder_running_watcher_fatal_stops_only_bound_service` | 生产builder注册的实际handler由协议事件watcher触发，等待及之后请求保留失败，另一服务继续 | 待执行 |
| 同上 | `tor_real_request_token_cancels_observed_bootstrap_wait_without_stopping_service` | 观察到真实生产启动的bootstrap Pending后取消ConnectContext，请求结束且共享服务仍能受理后续等待 | 待执行 |
| 同上 | `tor_real_request_budget_expires_during_bootstrap_without_stopping_service` | 生产start的bootstrap等待受真实ConnectContext预算限制，到期不停止共享服务 | 待执行 |
| vendor arti-client | `embedded_protocol_fatal_preserves_required_check_and_synchronous_handler` | 必需协议检查仍产生fatal，嵌入回调同步执行；推荐项不升级为fatal | 待执行 |
| 同上 | `absent_embedded_protocol_handler_preserves_fatal_for_upstream_exit_branch` | 无回调保留原版退出分支的输入 | 待执行 |

本轮Tor库共26项定义，另有原vendor两项及核心所有权回归。受控DirProvider只在测试开发依赖启用`experimental-api`与`error_detail`，生产功能不增加这些入口。受控设备拒绝全部非回环地址，不会为接线回归访问公共Tor网络。运行fatal测试还对另一命名Tor实例建立新请求并观察独立取消。回归包含受控设备、真实回环socket和真实生产builder接线，只验证列明的契约与资源行为，不能冒充Tor端到端互通。

worker工具有16项机制回归，全部待执行。它们覆盖完整清单与原字节变更、产物归属及fresh标记、超时原日志、清单和普通预检summary、同作业目录约束、祖先与链接拒绝、check失败、构建失败和超时记录、Cargo代理入口、旧target拒绝、网络异常清理及HTTP失败原始状态与响应留存。产物JSON、构建和check失败夹具不代表真实CLI构建或互通成功。

## worker命令

根任务先整合核心退休所有者、`ServiceFailure`、只读`ServiceStatus`及Dispatcher失败传播，再生成本轮开发依赖对应的根锁并冻结完整源码。目录祖先须满足接口规定，不能在`/tmp`下面运行状态目录测试。之后集中执行本轮验证。

```sh
export CARGO_TARGET_DIR="$WORKER_JOB_ROOT/check-target"
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test -p kerlico-core --test service_blocking --locked
cargo test -p kerlico-tor --locked
cargo test -p arti-client --lib embedded_protocol_fatal --locked
cargo test -p arti-client --lib absent_embedded_protocol_handler --locked
cargo clippy -p kerlico-core -p kerlico-tor --all-targets --locked -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-tor --locked
KERLICO_WORKER=1 PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tools/tor_interop -p test_worker.py
```

以上命令在本次worker作业的源码目录运行，外置target不进入源码快照。`WORKER_JOB_ROOT`是该worker自己的已授权作业目录。若Cargo对依赖包的测试选择或vendor开发依赖要求不同，应保留原失败并在worker调整实际命令与锁输入，不能把未运行的vendor回归算作通过。完整整树、Rustdoc、功能裁剪和实际CLI运行须由根任务在同一发行输入继续验收。

## 真实网络矩阵

[worker工具](../../tools/tor_interop/README.md)从完整冻结快照构建限定Tor功能CLI，核对Cargo JSON产物归属和源码前后摘要，再使用两个命名Tor实例及动态回环入口。域名请求必须经TLS验证且官方JSON返回`IsTor=true`。公开v3 onion请求固定官方Arti地址，不通过网关网站。正常关闭及相同状态重启需要各自实际CLI结果。

回环就绪探测只记录`loopback-listener-ready`。它的socket关闭不能观察建立期请求取消，不作为该项证据。受控生产启动回归证明真实token取消语义，公网CLI建立期取消继续列为未验证。

字面IPv4和IPv6需传入已独立核对的官方检测站当前地址。未提供或网络不可达时保留未验证或失败，不能外推为支持全部出口族。公开Tor网络共识与exit节点不由本项目固定，运行状态和原始日志只留worker；公开结果不含出口IP或relay地址。

## 未验证边界

- 本轮评审修订、开发依赖变化、实际fatal接线、核心退休所有者及新版工具均未执行验证。
- 真实bootstrap、公开域名、字面IPv4、字面IPv6、公开v3 onion、公网CLI建立期请求取消和关闭重启均未验收。
- 未测试长时间资源上限、目录损坏恢复、不可中断文件系统故障与异常进程退出之后的状态恢复。
- 不提供Tor relay、服务端、UDP、目标半关闭、桥、PT、onion认证、PoW计算或onion服务，不能从客户端TCP结果外推。
- Linux x86_64是本轮验证目标；没有Windows或其他平台结果。
- 作者没有独立审查资格。本轮仍需根任务安排独立源码和决策记录审查。
