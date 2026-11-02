# WireGuard 原生双端接口

本文描述E-01完整首轮源码。当前状态为已编写、待统一海外worker编译与验证。未运行格式、静态检查、测试或产品，不表示已经支持或可以发布。上游固定依据见[原生研究](../../reference/research_notes/wireguard-native.md)，验证入口见[测试记录](../testing/wireguard.md)。

## 注册与数据能力

`kerlico-wireguard`导出`WireGuardFactory`和`WireGuardNodeFactory`。两者均注册机器标识`wireguard`。出站提供TCP、TCP EOF、固定目标UDP及多目标UDP关联。节点只需要一个物理UDP监听器，在其上解码多个独立认证peer，不监听物理TCP。

产品使用Boringtun 0.7.1与smoltcp 0.14.0。一个命名出站只建立一个UDP载体、Tunn与用户态栈，多个来源共享运行服务。多个远端代理通过多个命名出站表达。服务端每个认证peer持有独立Tunn、来源范围、用户态栈、流映射及取消域。

没有系统TUN、内核WireGuard、宿主路由或后台Go进程。官方wireguard-go及gVisor只用于验证工具。此实现不需要网络接管权限，不修改系统代理、DNS、路由或Clash。

## 出站配置

下列JSON只表示字段结构。尖括号值必须替换为有效测试密钥后才能校验。此处没有可用于部署的凭据。

```json
{
  "tunnel": {
    "private_key": "<private-key-base64>",
    "addresses": ["10.77.0.2", "fd77::2"],
    "mtu": 1420
  },
  "endpoint": {"host": "peer.invalid", "port": 51820},
  "peer": {
    "public_key": "<peer-public-key-base64>",
    "preshared_key": "<optional-preshared-key-base64>",
    "allowed_ips": ["0.0.0.0/0", "::/0"],
    "persistent_keepalive": 25
  }
}
```

`bind`是可选的外层UDP本地`SocketAddr`，默认使用选定端点地址族的未指定地址与空闲端口。端点可以是字面IP或域名。运行启动时单独解析代理端点，按绑定族筛选并优先IPv4。启动后固定该端点候选，认证包可以更新同一peer的地址。业务失败不切换peer、代理或直连，也不重放业务数据。

`tunnel.private_key`与peer密钥使用标准Base64编码的非零32字节值。公钥拒绝本机公钥与低阶点。PSK省略表示不启用预共享密钥。`addresses`是一个或两个字面IP，每族最多一个，使用IP而非CIDR。MTU为1280至9000，默认1420。`persistent_keepalive`以秒计，0或省略表示关闭，最大65535。

AllowedIPs使用规范CIDR网络地址，数量为1至256，同一peer内不能重复或重叠。出站目标和返回来源都受该peer的AllowedIPs限制。它不是本机路由表。

## 服务端节点与成员

节点`options`只含`{"tunnel": {...}}`，`tunnel`字段与出站一致。外层监听由配置v2节点的`listen`提供，不能在协议内再次绑定另一个入口。成员的`native_credential`使用上面的peer结构。

每个成员的公钥对应一个可信管理用户。节点内公钥必须唯一，各peer的AllowedIPs不能重叠，也不能包含本节点内部接口地址。节点私钥、公钥认证域及PSK保护域通过`CredentialManifest`参加跨节点凭据隔离校验。IPv4和IPv6节点分别配置独立密钥与成员凭据。

初始握手的匿名公钥解析只选择候选。只有同一候选Tunn成功认证transport包或握手响应后，才通过原`CredentialSlot`签发`Verified`，由`IngressBinding`产生`PeerSession`。配置成员、用户名和管理用户ID不从IP包中读取。错误PSK或仅发起握手不会获得业务访问。

## 目标策略与TCP映射

WireGuard承载IP，不携带应用域名。出站计划因此使用`TargetPolicy::Local`，由共享Dispatcher按节点IPv4 only、IPv6 only或双栈模式选择目标字面IP，再进入隧道。外层载体地址族与内层目标族独立。该模块不伪造远端应用代理的原域名透传，也不提供设备WARP部署能力。

服务端在IP有界重组后，以认证peer与原TCP五元组准入流，先通过`PeerSession.connect_tcp`建立原网站目标。目标成功后才恢复smoltcp暂停的SYNACK。失败会关闭对应socket并发送RST，不确认虚假的目标成功。建立期间的入站RST或栈关闭会取消仍在进行的目标建立，不只等待建立期限。

固定smoltcp版本不接受任意IPv6网站地址作为本接口地址。本模块为服务端每条TCP流分配一个本peer内部地址与唯一虚拟端口，输入时改写完整TCP目的端点，输出时恢复原网站来源IP与端口，并重新计算IP与TCP校验和。映射是模块内部的有界状态，不修改宿主网络。配置、Dispatcher请求、访问记录和ICMP差错引用均保留原目标。

不同peer持独立映射，同peer并发目标不能复用内部端口。映射随socket维持至RST发送、正常关闭或TIME_WAIT结束。正常半关闭后的反向数据继续读取。写端关闭等待FIN确认，正常释放后的socket最多排空60秒，smoltcp的10秒TIME_WAIT期间保留原映射。错误释放尝试发送RST，资源饱和时最多保留1秒后回收。节点和peer强制取消会终止所属流，不关闭共享出站服务。

TCP的重传、Reno拥塞控制、窗口、乱序重组及FIN状态由smoltcp完成。驱动最长20毫秒推进一次定时器，I/O与收包另有通知。没有PLPMTU承诺，配置MTU必须适合外层路径。

## UDP与IP边界

固定目标通道保持目标来源校验。多目标出站关联分配一个虚拟端口，可按包发送不同字面IP，回包保留来源及包边界。同一关联的双族数据使用各自内部源IP。服务端按认证peer与内部UDP源IP、源端口建立真实`PeerSession.associate_udp`，多个目标共用这一关联，不能改成每目标新建固定通道。

真实关联允许未知来源回包，返回原关联与原peer。关联任务结束后关闭原队列，新关联不能接收旧实例的回包。域名形式的UDP返回来源无法编码进IP层，明确失败，不为日志或回包临时本地解析。

IPv4最大UDP载荷为65507字节，IPv6为65527字节。空包保留为空包。超出MTU的UDP包按内层IPv4或IPv6分片，接收端拒绝重叠、越界和嵌套分片，只交付完整数据报。每个重组最多128片，30秒过期。IPv4仅接受无选项或填充选项，IPv6允许有限Hop-by-Hop与Destination Options，不支持路由扩展头、任意IP协议或jumbogram。

ICMP只响应本隧道接口自身echo及必要控制差错。任意远端echo返回管理禁止差错，引用原IP包，不伪造远端成功。控制包不创建用户业务flow。设备WARP、AmneziaWG、非零reserved扩展、运行时密钥热更新及任意远端ICMP不在本轮范围。

## 资源与计量

`tunnel.limits`可选字段如下。所有资源值在纯配置阶段检查，不创建运行任务。

| 字段 | 默认值 | 接受范围与作用域 |
| --- | --- | --- |
| `max_flows` | 256 | 1至4096，出站或服务端每peer的TCP与UDP关联上限，另受Engine预算约束 |
| `tcp_buffer_bytes` | 65536 | 4096至1048576，每TCP读写方向分别分配 |
| `queue_packets` | 128 | 8至4096，一个命名出站或节点全部peer共享的排队包数 |
| `queue_bytes` | 2097152 | 65536至67108864，同一排队域的字节预算，TCP发送token保守预留一个MTU |
| `fragment_packets` | 64 | 1至1024，同时重组的数据报数，节点所有peer共享 |
| `fragment_bytes` | 2097152 | 65536至67108864，共享重组载荷字节预算 |
| `udp_idle_timeout_ms` | 60000 | 100至86400000，UDP关联及无业务peer的空闲期限，业务关联还受Engine空闲预算约束 |

资源耗尽不会隐式放大队列。一次UDP发送必须原子接纳全部分片，否则返回资源错误。TCP输入拥塞按丢包处理，后续由真实TCP重传恢复。请求、peer、节点与命名服务取消分别保持作用域，实际派生业务任务交给Engine注入的`NodeTasks`持有join权。

业务只通过Dispatcher的typed flow计量，TCP重传、IP头、WireGuard头及握手不重复记用户流量。实际UDP发送与接收字节另经`ServiceContext.record_carrier`和`IngressBinding.record_carrier`累计至命名出站或节点。该口径只包括socket确认的UDP载荷，含拒绝包，不包括IP/UDP头或设备网卡总量，不按用户摊分，不与业务量相加。载体接口由主任务统一集成，不能据本模块调用推定其他协议已上报。

配置、运行和验证错误使用公共`Error`分类。无效IP、密钥、重复身份及范围在配置边界拒绝。身份、凭据、密钥与业务载荷不写入日志。当前公共统计的持久历史与多语言完成情况仍由主任务维护。
