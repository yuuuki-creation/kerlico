# 服务端入站和出站

这篇是服务端的决定。代码还没全部跟上的地方，单独标成「代码未跟上」。不要把决定改成去迁就未完成的函数。

客户端不走这篇。隧道协议用 `DataPlane` 收发报文，代理协议在本机 SOCKS5/HTTP 入口后面运行，见 `docs/reference/crates.md`。

## 一个进程里的节点

一个 `Server` 持有多个入站节点、一个 `Outbound`、一份 `Stats`、一个 DNS 模块和至多一条落地。

创建节点用 `listen_node`。必须带一个 `ListenAddr`。这个类型只有 `V4` 和 `V6`。一个节点不能同时听两族。要两族都听，就建两个节点。v6 监听在打开套接字时设置 `IPV6_V6ONLY`。mieru 的监听已经这样做。WireGuard 和 OpenVPN 的 `listen` 仍是 `unimplemented!`。`ListenAddr::v6` 会拒绝 IPv4-mapped 地址，也会拒绝端口 0。

节点同时带一个 `OutboundChoice`。

- `Manual(Exit)` 是创建时写明的一种出口。
- `Default` 是出站留空。

协议 crate 实现 `Accept`。它负责 `add_user`、`remove_user` 和 `accept`。`accept` 交出 `Handoff`。`Handoff` 带着节点、用户、目标和明文流。目标里的主机名用来做域名匹配。协议 crate 不拨号，也不选择 `Exit`。WireGuard 和 OpenVPN 的这些函数体仍是 `unimplemented!`。mieru 的每个会话交出一个 `Handoff`。传输、多路复用和 SOCKS5 的范围在 `docs/reference/mieru.md`。

报文类入站把一条流收成同一个 `Handoff`。目标一开始是 IP。嗅探或 FakeDNS 可以再补上主机名。

节点另有一份有序的分流规则。规则只属于这个节点。没命中时使用节点自己的 `OutboundChoice`。

反向桥也是节点，用 `bridge_node` 创建。它不监听，而是主动连到远端的 VLESS Portal。Portal 送来的每条流交成这个节点的 `Handoff`，同样按这个节点的规则和 `OutboundChoice` 选出口，由出站模块拨号。它没有账号，`add_user` 和 `remove_user` 返回错误。配置写法在「配置和运行时接口」的 `bridges`。

## 节点上的分流

这里的网址指域名，不指带路径的链接。匹配只看目标主机名或目标 IP。端口、来源地址、协议名和用户不参与匹配。

Xray 用一份全局 `routing.rules`。规则用 `inboundTag` 限定入口，再用 `outboundTag` 指向另一个出站对象。这里不采用那两张表。一个节点写下自己的规则。命中结果是一个 `OutboundChoice`，也就是五种出口之一，或 `Default`。拨号仍然只发生在 `crates/outbound`。

规则按书写顺序匹配，先命中的生效。一条规则先写要使用的规则集，再写 `OutboundChoice`。一条规则只有一种条件。

规则集和 Xray 的域名规则、`geosite.dat`、`geoip.dat` 使用同一套写法。一行一条。`#` 开头的行是注释。进程把同一份规则集和同一份 dat 只加载一次，节点只引用它的名字。

| 写法 | 匹配 |
| --- | --- |
| 没有前缀 | 子串。Xray 路由里没有前缀的域名也是这样。 |
| `domain:` | 这个域，以及它的子域。 |
| `full:` | 整个主机名。 |
| `keyword:` | 子串。 |
| `regexp:` | 正则。 |
| `geosite:` | `geosite.dat` 里的一个分类。分类里的每一条仍按它自己的前缀匹配。 |
| `geoip:` | `geoip.dat` 里的一个分类。目标是这个分类中的地址。 |
| `geoip:!` | 目标不在这个分类中。 |
| `ext:` | `ext:文件:分类`。geosite 文件按域名分类读，geoip 文件按网段分类读。 |

`geosite.dat` 和 `geoip.dat` 用 Xray 能读的那一种。文本规则集的每一行就是上表里的一种写法。节点不复制这些行。

一条流的选择顺序是下面这样。

1. 目标是 FakeDNS 地址时，先还原成原来的主机名。后面的规则看这个主机名。拨号目标也改成这个主机名。
2. 嗅探得到主机名时，规则看这个主机名。报文里原来的 IP 仍是拨号目标。这是 Xray 嗅探的 `routeOnly`。
3. 按该节点的规则顺序找第一个命中。域名条件只看主机名。目标还没有主机名时，域名条件错过。`geoip` 只看 IP。目标还是域名、后面又有 `geoip` 规则时，先按 DNS 一节解析一次，再从这条规则继续。解析只做这一次。这是 Xray 路由的 `IPIfNonMatch`。
4. 用户规则都没命中，且目标 IP 落在 `geoip:private`，或等于本机任一接口地址时，使用这一族的原生出口。这一族没有原生地址时，这条流失败。这条内置规则不把流量送进 WARP，也不送去落地。
5. 仍然没有命中时，用节点创建时的 `OutboundChoice`。
6. 得到的是 `Manual` 时，使用指定的那一种出口。
7. 得到的是 `Default` 时，再按下一节的表选择原生或 WARP。

因此节点可以整体走落地，同时让某几个域名走 `Default`。用户规则写在内置私网规则之前，所以一条规则可以把私网地址指到落地。`Default` 仍会按目标地址族和本机有没有原生地址来选。规则不创建新的出站对象。

`geoip:private` 以加载的 `geoip.dat` 里同名分类为准。没有这份文件时，内置规则仍覆盖回环、链路本地、RFC1918、运营商级 NAT、ULA、组播、文档地址，以及 `198.18.0.0/15`。

节点上有规则列表，接受循环会调用 `choose`。配置旁边的 `geosite.dat` 和 `geoip.dat` 会加载一次。`ext:文件:分类` 也从那个目录读。没有 `geoip.dat` 里的 `private` 分类时，内置网段仍然生效。

## 嗅探和 FakeDNS

嗅探挂在节点上，默认关闭。这和 Xray 入站的 `sniffing.enabled` 相同。打开之后可以识别 `http`、`tls`、`quic`。`http` 取 Host。`tls` 和 `quic` 取 ClientHello 里的 SNI。只读握手，不把整条连接缓冲下来。这是 Xray 的 `metadataOnly`。

代理协议已经在目标里带了主机名时，不再嗅探。

FakeDNS 默认关闭。打开后，DNS 模块把本进程要回答的 A 记录放进 `198.18.0.0/15`，AAAA 记录放进 `fc00::/18`。查询和假地址的对应关系留在进程里。入站见到这些地址时先还原主机名，再进入上一节的顺序。假地址不会落到内置私网规则上。

节点打开嗅探时，接受循环读一段握手，用 `http` Host、`tls` ClientHello 或 QUIC Initial 里的 ClientHello 给规则补主机名，拨号仍用原来的 IP。读到的字节会先交回复制循环。FakeDNS 打开后，入站看到本进程分配过的假地址会先还原主机名，拨号目标也改成这个主机名。

## 五种出口

`Exit` 的五个值是 `NativeV4`、`NativeV6`、`WarpV4`、`WarpV6` 和 `Landing`。

`NativeV4` 和 `NativeV6` 用本机这一族的地址出去。

`WarpV4` 和 `WarpV6` 是同一条轻量 WARP 隧道上的两族地址。隧道是用户态 WireGuard，实现在 `crates/wg`。服务端默认带上它。它只承载出站模块的流量，不替换机器的默认路由。

`Landing` 是把这一条流整段交给远端落地节点。只有规则或节点给出 `Manual(Landing)` 时才走这里。缺原生地址时不改走落地。

## 留空时怎么选

先看目标该用哪一族。目标至少有一个 IPv4 时用 v4，包括同时还要 AAAA 的名字。目标只有 IPv6 时用 v6。然后看本机有没有这一族的原生地址。有，就走原生。没有，就走同一族的 WARP。

| 节点上的选择 | 目标 | 本机原生 | 出口 |
| --- | --- | --- | --- |
| Manual | 任意 | 任意 | 指定的那一种 |
| Default | 有 IPv4 | 有 v4 | NativeV4 |
| Default | 有 IPv4 | 没有 v4 | WarpV4 |
| Default | 只有 IPv6 | 有 v6 | NativeV6 |
| Default | 只有 IPv6 | 没有 v6 | WarpV6 |

手动指定之后，不再因为目标地址族或本机缺地址而改口。`Manual(NativeV4)` 或 `Manual(WarpV4)` 的目标若是域名，仍解析一次。结果里没有 IPv4 时，这条流失败。v6 的两种手动出口同样处理。

有原生 v4，指本机有一条 IPv4 默认路由，并且选得出的源地址不是回环，也不是链路本地。源地址在私网里，只要默认路由在，仍算有原生 v4。有原生 v6，指本机有一条 IPv6 默认路由，并且源地址落在 `2000::/3`。只剩 ULA 或链路本地时，算没有原生 v6。

这个判断跟着地址和路由变化重算。一次拨号失败不改变它。

选定出口之后只拨一次。失败就结束这条流。不换另一种出口。WARP 也拨失败时同样结束，不改走落地。落地拨失败时也结束，不改走原生。

域名要得到「有 IPv4」「只有 IPv6」或「没有地址」时，走 DNS 一节。没有地址时失败，不改走 WARP，也不改走落地。

`select_exit` 会看 `Native`。这一族没有原生地址时返回同一族的 WARP。内置私网规则在这一族没有原生地址时让这条流失败。

`Server::run` 持续派发就绪流，每次从上次接入节点的下一个节点开始检查。成功派发后立即继续，只有检查一轮仍没有就绪流时才等待 1 ms；每轮继续处理用户管理命令。节点的路由上下文只在取得 Handoff 后复制。公开的 `dispatch_next` 仍只接受一条就绪流并启动出站处理。就绪队列的总资源预算另见性能记录中的待实施项。

## DNS

DNS 是服务端的一个模块。协议 crate 不解析域名。

`queryStrategy` 默认是 `UseIP`，同时要 A 和 AAAA。`UseIPv4` 只要 A。`UseIPv6` 只要 AAAA。只要 A 的名字若没有 A 记录，按没有地址处理。

`servers` 是一组上游。每一组有 IP、端口、传输和这个查询自己的 `OutboundChoice`。传输是 `udp` 或 `tcp`。默认端口是 53。默认出口是 `Default`。查询的目标就是这台服务器的 IP，地址族已经知道，再按留空时的表出去。这次不做 DoH 和 DoT。

`hosts` 是精确主机名到地址。它先于上游查询。

出口已经是 `Landing` 时，本地不再解析，把原来的主机名交给远端。`Default` 以及手动指定的原生或 WARP，在目标仍是域名时解析一次。

`hosts` 先于上游做精确匹配。上游可以是 UDP 或 TCP。查询按那一台服务器的 `OutboundChoice` 选出出口，再由出站模块拨一次。落地还不能承载这次查询。

`dns` 可以写 `listen`。写了之后，进程在这个地址上同时听 UDP 和 TCP，回答客户端的查询。没写 `port` 时用 53。端口 0 拒绝。v6 套接字打开 `IPV6_V6ONLY`。只回答第一个问题，而且只回答 A 和 AAAA。FakeDNS 打开时，这两个类型从假地址池取，同一个名字一直对应同一个地址。FakeDNS 关闭时，回答走 `hosts` 和上游。

## 落地

进程里至多一条落地。配置写协议、地址、端口和 `settings`。协议必须是服务端叶子用 `landing-<id>` 编进来的客户端协议。`settings` 的字段由那个客户端协议解释。

反向落地也占用这一个 `Landing` 出口，配置为 `"landing": {"node":"入口节点名","reverse":"该节点账号的反向标签"}`。它通过该节点提供的反向拨号函数开一个 Mux 会话，目标的连接和复制仍由出站模块驱动；不增加 Exit、全局路由或 outboundTag。该写法与普通落地的 protocol/address/port/settings 互斥。删除或替换反向账号后，旧 Portal 不再接受新会话。


没有配置落地时，`Manual(Landing)` 使这条流失败。

整条流交给远端，目标保持原样。远端自己解析域名。本地的 DNS 模块不参与这次拨号。

配置里的 `landing` 会装到出站模块。协议必须是这次构建用 `landing-<id>` 编进来的客户端协议。出站模块调用那个 crate 的 `land`，再把用户和远端之间的字节复制完。没有这段配置时，`Manual(Landing)` 使这条流失败。目录规则在 `docs/reference/crates.md`。

## WARP

一条用户态 WireGuard 隧道同时带 v4 和 v6。`WarpV4` 用隧道内的 v4 地址做源。`WarpV6` 用隧道内的 v6 地址做源。配置里缺掉哪一族，选中那一族时这条流失败。

配置字段和 Xray 的 wireguard 出站相同，是 `secretKey`、`address`、`peers`、`reserved`、`mtu`。`peers` 只使用第一条。`reserved` 是三个字节。`mtu` 默认 1280。

配置里没有这段时，向 Cloudflare WARP 的设备注册接口注册一次，把得到的字段写到配置旁边的 `warp.json`。下次启动直接读这个文件。注册接口的版本写进该文件。实现时用 Cloudflare 当时的客户端注册接口。

对端 `endpoint` 用原生出口拨号。它是主机名时用系统解析器。这一族没有原生地址时，WARP 不可用。选中 `WarpV4` 或 `WarpV6` 的流因此失败。

引擎在 `crates/wg`。配置里的 `warp` 段和旁边的 `warp.json` 可以加载。两边都没有 `secretKey` 时，向 `https://api.cloudflareclient.com/v0a4005/reg` 注册一次。请求带 `CF-Client-Version: a-6.30-3596`。得到的私钥、地址、对端和 `reserved` 写成 `warp.json`，`registration` 记为 `v0a4005`。下次启动直接读这个文件。注册失败时不安装隧道，进程仍然启动。

## TCP 和 UDP

TCP 在连接开始时选定出口，这条连接中途不改。

UDP 按源地址和目标组成一个会话。第一个报文选定出口。同一会话的后续报文沿用它。空闲 300 秒后会话结束。这个时间和 Xray `policy` 的 `connIdle` 默认值相同。

拨号失败只结束这一条流或这一个会话。

TCP 复制在 300 秒没有字节时结束。UDP 会话的键包含 `Handoff` 的节点、用户、源地址、目标主机和端口。同一源地址跨节点或用户时分别选择出口。没有源地址的 UDP 流不进这张表。第一个报文选定出口。300 秒内同一键的后续报文沿用这个出口。拨号失败会删掉这个会话。

代码未跟上：`df2e347` 的原生 TCP 出口使用没有写超时的阻塞 `write_all`。另一方向退出后，复制循环的停止标志不能中断正在阻塞的写，因此不能保证这类流按上述空闲期限及时释放。源码依据、派发与计数成本及待实施方案见 [mieru 性能核验](mieru-performance.md#源码核验与优化候选)。本轮只记录缺口，没有修改空闲期限或出口规则。

## 用户和计数

用户挂在一个节点上。稳定的键是 `UserEmail`。空字符串、空白和 `>` 不能做邮箱或节点名。同一个邮箱可以出现在两个节点上，计数按邮箱合并。`remove_user` 只从那个节点去掉用户，不把计数清零。

账号的协议字段放在 `Settings` 里，由那个协议的 `add_user` 解释。叶子不解析 UUID 或密码。节点 `settings` 和用户对象里，除 `users` 与 `email` 以外的字符串、数字和布尔值都原样进入 `Settings`；数组和对象序列化为 JSON 后交给协议解释，`null` 拒绝。这条规则是 `Settings::insert_json`，落地设置和客户端文档也用它。`add_user` 和 `remove_user` 在 `Server` 上会找到节点并转给入站。mieru 的 `add_user` 读取 `username` 和 `password`。vless 的 `add_user` 读取 `id`、`flow` 和可选 `reverse`，详细组合与反向 API 见 `docs/reference/vless.md`。WireGuard 和 OpenVPN 的函数体仍是 `unimplemented!`。

计数的名字是这些形式。

```text
user>>>邮箱>>>traffic>>>uplink
user>>>邮箱>>>traffic>>>downlink
inbound>>>节点>>>traffic>>>uplink
inbound>>>节点>>>traffic>>>downlink
outbound>>>出口>>>traffic>>>uplink
outbound>>>出口>>>traffic>>>downlink
```

出口名是 `native-v4`、`native-v6`、`warp-v4`、`warp-v6` 和 `landing`。

计数口径和 Xray 的连接计数相同。入站的 uplink 是从用户连接读到的字节，downlink 是写回用户连接的字节。出站的 uplink 是写向出口的字节，downlink 是从出口读到的字节。计的是这条连接上的字节。

`Stats` 按用户、入站和出口累加。出口计数在复制字节时写入。

复制开始时，`Traffic::bind` 取得该用户、节点和出口的六个原子计数句柄。随后每个成功复制块直接累加句柄，名称格式化和注册表锁不进入数据路径。API 仍按上述名称查询同一批计数，活跃连接的更新立即可见，不等连接结束才汇总。`Stats` 原有的按名称组成计数的更新方法仍保留。

原生 TCP 的 200 ms 读取轮询超时在建连时设置一次，不随每次读取重复设置。300 秒连接空闲期限以及前述阻塞写的实现缺口不因此改变。

UDP 的 `InboundStream` 一次读写表示一个完整数据报。`Ok(0)` 是有效空包，`PlaneFault::Closed` 才表示关闭；缓冲区容纳不下时返回错误，不拆分。出口内部读事件区分数据与 EOF，UDP 单次写入必须完整；TCP 仍是字节流。嗅探预读保存完整 UDP 包，空包也要交还复制循环。`Settings::optional_text` 区分缺少可选项与已有键类型错误，不把类型错误作为默认值处理。

## 配置和运行时接口

启动时读一份 JSON。节点、规则、DNS、WARP 和落地都来自这份文件。

```json
{
  "inbounds": [
    {
      "tag": "a",
      "protocol": "vless",
      "listen": "0.0.0.0",
      "port": 443,
      "outbound": "default",
      "sniffing": { "enabled": false, "destOverride": ["http", "tls", "quic"] },
      "rules": [
        { "geosite": ["cn"], "outbound": "landing" },
        { "geoip": ["cn"], "outbound": "default" }
      ],
      "settings": {}
    }
  ],
  "landing": { "protocol": "vless", "address": "203.0.113.10", "port": 443, "settings": {} },
  "bridges": [
    {
      "tag": "home",
      "address": "198.51.100.20",
      "port": 443,
      "outbound": "default",
      "rules": [],
      "settings": { "id": "...", "encryption": "none" }
    }
  ],
  "dns": {
    "listen": "127.0.0.1",
    "port": 53,
    "queryStrategy": "UseIP",
    "hosts": {},
    "servers": [
      { "address": "1.1.1.1", "port": 53, "network": "udp", "outbound": "default" }
    ]
  },
  "warp": {},
  "api": { "listen": "127.0.0.1", "port": 10085 }
}
```

`listen` 的地址族就是节点的地址族。`0.0.0.0` 是 v4。`::` 是 v6。端口 0 拒绝。`outbound` 的取值是 `default`、`native-v4`、`native-v6`、`warp-v4`、`warp-v6`、`landing`。

`api` 可以不写。写了之后在 `listen` 和 `port` 上打开 gRPC。端口 0 拒绝。v6 套接字打开 `IPV6_V6ONLY`。`/kerlico.Users/Add` 和 `/kerlico.Users/Remove` 按节点名和邮箱添加或删除用户。添加时可以带一组文本设置，交给那个协议的 `add_user`。`/kerlico.Stats/Get` 按上一节的计数名字查询，回答是这个名字和当前值。节点、规则、DNS、WARP 和落地不在这个接口里改。改它们要重新加载配置。

`bridges` 可以不写。每一项是一个 VLESS 反向桥节点，对应 Xray 带 `reverse.tag` 的 VLESS 出站。`tag` 是节点名，和 `inbounds` 共用一个名字空间；桥上的流在计数里也用它作用户名。`address` 和 `port` 是 Portal。`settings` 是 VLESS 客户端设置，写法和 VLESS 落地相同，例如 `id`、`encryption`、`flow` 以及传输和安全字段。`outbound`、`rules` 和 `sniffing` 的写法和入站节点相同。这一项需要服务端叶子的 `landing-vless` feature；没有它的构建拒绝含 `bridges` 的配置。

桥对 Portal 的连接按 Xray 的方式维护。每 2 秒检查一次。没有活动连接，或活动连接平均承载的会话超过 16 个时，再开一条。会话数包括 Portal 的控制会话，平均值向下取整。Portal 的控制消息改成 DRAIN 后，这条连接不再计入，已有会话继续。断开的连接被移出，下一次检查按同样的条件补开。连 Portal 失败只打日志，2 秒后再试，不让配置加载失败。

启动时会读 `inbounds`、`bridges`、`dns`、`warp`、`landing` 和 `api`。


监听器创建前，服务端先安装 DNS 配置、共享的 GeoIP 目录、WARP 和普通落地；反向落地在节点和账号建立后安装。`Server::from_config_in` 使用配置所在目录准备这些服务，独立的 `from_config` 保持不注册外部 WARP 的嵌入式入口。

协议设置携带有类型的运行时上下文。载体的配置 DNS、系统 DNS、SRV、TXT、ECH DNS 和 TLS 元数据请求都经该上下文交给服务端；协议不另建 DNS 或 GeoIP 解析器。GeoIP 回调携带分类实际含有的地址族，反选仍受该地址族约束。TLS 元数据的默认出口按本篇默认表选择；没有代理选择的传输载体明确请求原生直连。`sockopt.dialerProxy` 只接受本篇已有的出口名字和 `default`，普通落地的上下文禁止再次选择自身的 `landing`。原生套接字专用参数不能应用到用户态 WARP 或落地流时返回错误，不改走原生。

出站打开载体套接字，运行时回调只弱引用出站所有者。原生 TCP/UDP 保留原生句柄，WARP 和落地交出可独立读写的两半；等待读取不占用写侧。本机 Unix 流经 `connect_unix` 打开，Linux 上以 `@` 开头的路径按 Go 的写法表示抽象套接字。TCP 和 Unix 的写半边可以单独半关闭，读半边继续接收。TLS 配置与连接池按运行时所有者复用，池中的设置副本不强持有所有者。
