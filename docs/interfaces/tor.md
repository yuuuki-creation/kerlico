# Tor出站接口

更新日期为2026-11-02。`kerlico-tor`首轮评审修订已编写，当前修订尚未构建、格式检查、静态检查或执行测试。早期输入的worker结果单列在[测试记录](../testing/tor.md)，不代表本页修订已验收。

## 角色与数据能力

`TorFactory`注册`tor`出站。数据面直接嵌入`arti-client 0.47.0`，没有外部Tor进程或SOCKS转发后端。

| 项目 | 本轮源码范围 |
| --- | --- |
| 客户端TCP出站 | 域名、IPv4与IPv6字面目标、不需要PoW计算的公开v3 onion |
| 入站或Tor relay | 不提供 |
| 固定目标UDP及多目标关联 | 不提供 |
| 目标TCP半关闭 | 不提供，`tcp_eof=false` |
| 网站地址策略 | `TargetPolicy::Remote`，保留原始目标与端口 |
| 目标绑定元数据 | `TcpConnectInfo::unknown()` |

Tor的`RELAY_END`关闭整条流。`shutdown`不能用来向目标发送FIN后继续读取完整反向响应，配置中的`require_remote_eof=true`因此必须在框架能力校验中拒绝。Tor流需要显式`flush`提交缓冲数据。

## 配置字段

`options`拒绝未知字段。只有以下字段有效。

| 字段 | 类型 | 默认值 | 约束 |
| --- | --- | --- | --- |
| `data_directory` | 字符串 | 必填 | 项目工作目录内的非空相对路径，不含上级跳转、根路径或盘符 |
| `bootstrap_timeout_ms` | 整数 | 120000 | 1000至600000，唯一bootstrap任务的固定预算 |
| `carrier_timeout_ms` | 整数 | 30000 | 100至120000，每次Tor relay或directory载体拨号的预算 |
| `shutdown_timeout_ms` | 整数 | 5000 | 100至60000，首次后端关闭固定的总预算，仍受Engine外层期限约束 |

以下是只使用回环转发入口的配置片段。它不改变系统代理、DNS或路由。

```json
{
  "version": 2,
  "outbounds": [
    {
      "tag": "tor-a",
      "type": "tor",
      "options": {
        "data_directory": "state/tor",
        "bootstrap_timeout_ms": 120000
      }
    }
  ],
  "inbounds": [
    {
      "tag": "check-forward",
      "type": "tcp-forward",
      "listen": "127.0.0.1:18080",
      "target": {"host": "check.torproject.org", "port": 443},
      "outbound": "tor-a"
    }
  ],
  "limits": {"connect_timeout_ms": 180000}
}
```

示例端口必须在实际运行前确认空闲。纯配置编译只校验字段，不创建目录、锁、任务或连接。运行阶段才创建`data_directory/<OutId>/state`和`cache`。同一命名目录有排他锁。两个Engine同时使用同一目录及OutId会失败，不自动进入共享写者或只读降级模式。目录不随请求或服务关闭删除。

Unix运行时先固定本次打开操作的有效UID，再从文件系统根开始使用目录句柄、`openat`和`NOFOLLOW`逐级打开祖先。全部祖先必须由root或该UID拥有，且不可被组或其他用户写入。共享可写目录即使有sticky位也拒绝，因此不能把工作目录放在`/tmp`下面。任何祖先不满足条件时，在创建受管目录前失败。

受管子目录必须由本次固定的UID拥有，且没有组或其他用户权限。新目录为`0700`。锁文件须属于同一UID，权限恰为`0600`，并且是无符号链接的常规文件，只有一个硬链接。此设计信任root和同UID进程不恶意改名、换挂载或改权限，因为Arti后续仍通过已验证路径访问文件。它不把叶目录`0700`当成保护不可信祖先的手段。非Unix尚未实现等价信任检查，运行时明确拒绝。

Arti权限检查忽略禁用检查的环境变量。状态根以进程项目工作目录解析，不使用隐式用户Tor配置。测试临时目录也位于worker项目工作目录内，不借修改共享临时目录权限通过校验。

## 共享、隔离与取消

一次`OutboundPlan::start`构造唯一`TorClient<TorRuntime>`。Dispatcher全局持有该命名实例，节点不会另建完整Tor后端。不同命名配置有独立client、guard状态、状态锁与服务取消域。

每次业务建立使用`isolated_client`生成新的隔离token。它共享同一底层client，但不与其他业务共用电路；该隔离强于逐用户隔离，代价是较少复用现有业务电路。没有保存无界的`ResourceKey`到token映射表。入站明文凭据和协议认证UUID不参与Tor认证或日志。用户与用量仍由Dispatcher的唯一FlowLease归集，本模块不重复计量业务字节。

启动创建client后登记唯一bootstrap任务并返回后端。`connect_tcp`等待bootstrap完成，整个等待和目标建立受同一`ConnectContext`绝对期限约束。一个请求超时或取消不会取消共享bootstrap。bootstrap失败会停止该命名实例，恢复需要重新启动服务，不通过换代理或直连重试。

域名与onion由Arti解析和路由。字面目标设置对应固定族的`StreamPrefs`；域名使用Arti的IPv4优先默认策略。节点本地网站模式不改变远端Tor目标。Tor载体TCP只借用`DeviceLease`，接收Arti给出的字面socket地址；它不调用网站resolver。未使用的runtime监听、Unix socket和UDP能力明确拒绝。

`connect_with_prefs`没有开启optimistic，只有Tor确认流建立后才返回。返回流分别持读、写取消等待器，拆分后的两个Pending方向都能唤醒。取消I/O使用`ConnectionAborted`并携带`Error::Cancelled`，不会因`Interrupted`重试造成忙循环。目标地址、上游Debug错误与原始I/O内容不进入本模块用户错误。

## 后台工作与关闭

所有Arti异步`Spawn`登记真实future到该命名`ServiceContext`。`Blocking::spawn_blocking`调用`ServiceContext::spawn_blocking_tracked`，其真实阻塞工作直接登记在原JoinSet中。丢弃结果等待器不丢弃实际工作所有权。

Arti的`ThreadHandle<T>`只能输出`T`，没有取消结果。真实闭包panic时，等待句柄在poll时用原payload恢复panic，真实native任务也保留失败记录。丢弃等待句柄不会消除native失败。正常关闭后的准入拒绝不执行闭包，也不伪造panic；返回句柄保持Pending，调用方仍须受自己的取消或期限管理，不能据此声称所有`Blocking`调用都会自动结束。

`reenter_block_on`保留上游正常运行语义，不注入panic作为取消控制。已准入的不可中断工作若未结束，关闭返回真实超时，由核心退休所有者继续收集实际join。首轮metadata所选范围不含Arti CLI或`tor-hsservice`，其中直接使用的`reenter_block_on`不在本轮生产入口；这项源码范围核对不等于完整trait验收。

第一次关闭固定期限，重复调用不延长。关闭先取消服务和释放后端client，再实际等待服务所有者。只有所有任务完成且无失败才返回成功并释放所有者中的状态锁引用；仍存在的流和实际工作继续持有自己的状态引用。超时或等待中断不能登记资源已回收，首次超时事实保留。

固定上游在网络共识要求未实现的必需协议时会退出进程。本项目的局部vendor补丁增加可信嵌入方fatal回调。初始缓存检查、运行事件检测和缺省等待后退出进程的路径保持不变。kerlico回调先向实际命名`ServiceContext`发布首个typed失败，再取消该服务。Dispatcher和Tor通过同一服务失败状态保留bootstrap超时及协议过时原因，不能用通用`Cancelled`覆盖它们。请求或节点自身已取消时仍按共享契约处理来源优先级。

失败发布是准入边界。此后开始准入的新请求、carrier连接和I/O poll必须拒绝。已通过准入且与fatal重叠的poll或内核I/O不能瞬时撤回，在下一取消观察点停止。回调返回只保证失败已发布且取消已发出，不表示所有既有poll静默、任务排空或资源释放。关闭仍等待真实join，其他命名服务继续独立运行。

## 错误与限制

建立期Tor超时映射`Error::Timeout`，exit策略和缺少onion认证映射`Rejected`，非法目标映射`InvalidAddress`，资源不足映射`ResourceLimit`。协议版本过时使用固定协议错误并停止服务。网络、状态目录和其他协议错误不包含上游地址、凭据或绝对路径。第三方tracing订阅器由宿主统一决定，本模块不安装全局日志runtime或打印网络信息。

不开放桥、PT、私有onion认证、onion服务、relay、RPC、实验性PoW计算、外部可执行程序或任意Tor配置透传。需要PoW的onion组合不在本轮范围。未验证平台、IPv6 exit可达性、长期资源行为及真实网络失败见[测试记录](../testing/tor.md)。固定依赖、局部补丁和许可来源见[研究](../../reference/reports/tor-implementation-20261102.md)。
