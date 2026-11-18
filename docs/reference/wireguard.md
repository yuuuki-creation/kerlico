# WireGuard

协议 id 为 `wireguard`。客户端和入站使用 `wireguard` feature，落地使用 `landing-wireguard`。三者以及 WARP 共用 `kerlico-wg`。所有密钥均为 32 字节，可写成标准 Base64、URL 安全 Base64 或十六进制；`AllowedIPs` 采用 IPv4/IPv6 CIDR。

客户端的 `peer` 指向对端 UDP 地址。`settings` 包含 `privateKey`（也可写 `secretKey`）、`publicKey`、可选 `presharedKey`（也可写 `preSharedKey`）、`persistentKeepalive`（也可写 `keepAlive`）、`allowedIPs` 和 `mtu`。默认接受两族前缀，MTU 默认 1420。配置 `reserved` 时传入三个字节，供需要这种 Xray 扩展的 UDP 对端使用；原版 WireGuard 不需要配置。

多 peer 客户端使用 `settings.peers` 数组代替外层的对端字段。各项包含 `publicKey`、`allowedIPs`、可选的预共享密钥、保活和 `endpoint`。第一项未填 `endpoint` 时用顶层 `peer`。其余各项必须提供各自的端点。收发均使用最长前缀匹配；两个 peer 不能配置相同前缀。同一个接口的 peer 共用一个 UDP 端口。系统支持双栈套接字时，IPv4 和 IPv6 共用这个端口，已认证的 peer 可以在两族之间漫游，并保留现有会话。

IPv6 链路本地端点需要带本机接口作用域，例如 `[fe80::2%7]:51820`。Linux 也可写本机接口名，例如 `[fe80::2%eth0]:51820`。客户端的 `peer` 和 WireGuard peer 的 `endpoint` 都保留作用域，独立工具的 `listen` 和在线配置的 `endpoint` 也接受此写法。接口名由本机解析，不发 DNS 查询。

客户端可将完整 IP 包交给 `DataPlane`，或使用 `kerlico-client --tun <接口名> <配置文件>`。后者由本机创建并启动指定的 TUN 设备。在 Linux 上，停用网卡会释放 UDP 载体并清除会话，重新启用时通过出站模块用原端口打开载体并重新握手。客户端 TUN 跟随网卡的 MTU 调整。设备地址和系统路由由管理员配置；Kerlico 不自动重写本机默认路由。

入站节点使用普通的 `listen` 和 `port`，载体为 UDP。节点设置 `privateKey` 和可选 `mtu`，在 `users` 中为每个 peer 配置 `email`、`publicKey`、`allowedIPs`，另可配 `presharedKey`、`persistentKeepalive` 和数字地址的 `endpoint`。每个 peer 可以拥有多个前缀，重叠前缀按最长匹配；不同 peer 不能注册同一个前缀。认证后才接受其源地址及新端点。入站从 IP 中提取 TCP、UDP，再将目标、用户与明文流交给节点的出站规则。该模式不转发 ICMP 或其他 IP 协议。

同一 UDP 接口对握手发起和响应使用同一套 Cookie 检查。握手负载达到阈值时，Cookie 绑定来源 IP 和 UDP 端口，两分钟一轮；切换来源端口要重新获取 Cookie。通过 Cookie 校验的握手按 IPv4 地址或 IPv6 `/64` 限速，持续每秒 20 个，允许瞬时 5 个；同一来源更换端口不重置限额。超额握手被静默丢弃。收到或发出 Cookie 都不会把该来源标为已认证端点。

传输包可以比当前最高序号落后至多 8,128，和 64 位 Linux WireGuard 及 wireguard-go 的接收窗口一致。认证通过的包只接受一次，不会因丢弃过旧包而中断会话。

需要原版 WireGuard 的 IP 隧道行为时，可构建并运行独立工具：

```text
cargo build -p kerlico-wg --features tun-device --bin kerlico-wg
kerlico-wg peer.json
```

独立工具读取 `listen`（数字 UDP 地址和端口）、`privateKey`、`tun`（本机 TUN 名称）、可选 `mtu` 及 `peers` 数组。各 peer 用入站账号同样的字段，省略 `email`。该模式把完整的 IPv4/IPv6 包交给操作系统，允许 ICMP 等协议。地址、路由、转发和防火墙由系统管理，适用于需要内核转发而不需要 Kerlico 节点分流的部署。

Linux TUN 的 UDP 套接字和网卡由同一个线程等待就绪和转发。网卡支持卸载时，线程将从 TUN 收到的 GSO 大包拆成独立 IP 包，再逐包选 peer、填充和认证加密。发往同一端点的等长 WireGuard 数据包可直接加密到同一块 UDP 分段缓冲区，末包可以较短。每次只提交已经就绪的数据。遇到握手消息时先发出前面的数据，再单独发送握手。内核或路由拒绝 UDP 分段时，按原顺序逐包发送。

握手前收到的 IP 包由 peer 排队，握手完成后从 peer 自有的缓冲区发出。该缓冲区随待发包增长，发送批次的缓冲区可以立即复用。回归测试用 9,000 字节首包走完真实握手，并逐字节核对对端收到的内容。

反方向仍按数据报认证、检查重放和源地址。连续的已认证 IP 包可以在写入 TUN 前通过 GRO 合并。网卡暂时不可写时，线程最多保留 128 个待写 IP 包，恢复后从尚未写出的部分继续。内核接口不支持网卡卸载时，使用普通 TUN 包。停用网卡时释放该接口的待写数据。

Linux TUN 会尝试把自身 UDP 套接字的收、发队列各增至内核计入开销后的 14 MiB，即与 wireguard-go 相同的 7 MiB 请求值。进程已有权限时仅对此套接字使用 [Linux 缓冲选项](https://man7.org/linux/man-pages/man7/socket.7.html)；否则在系统上限内尽量增大。不会缩小已有队列，也不修改系统参数。打开新端口或重新启用接口时同样设置。

接收侧每次可以取回多条已到达的 UDP 报文。每条报文保留自己的来源地址和边界，仍按原顺序处理并分别认证；不支持批量接收时逐个读取。

Linux 上，独立工具发布权限为 `0600` 的 [WireGuard 控制套接字](https://www.wireguard.com/xplatform/)，路径为 `/run/wireguard/<接口名>.sock`。可用原版 `wg show` 读统计，`wg set`、`wg setconf` 或 `wg syncconf` 在线改设置。用 `kerlico-wg <接口名>` 可在后台启动未设私钥的双栈接口，`-f` 或 `--foreground` 可让它留在前台。移除控制套接字会关闭接口。JSON 的启动参数仍可用；在线变更只作用于运行中的接口，不回写 JSON。

按接口名启动时，Linux 网卡最初处于停用状态，可以先用 `wg set` 配置，再用 `ip link set dev <接口名> up` 启用。JSON 启动会立即启用网卡。执行 `ip link set dev <接口名> down` 会释放 UDP 端口并清除当前会话和排队的数据，保留配置、统计和最近的握手防重放记录。停用期间可以修改监听端口；再次启用时按保存的端口监听，peer 重新握手。独立工具也跟随 `ip link set ... mtu` 对网卡 MTU 的调整。

Windows 上，用 LocalSystem 身份启动 `kerlico-wg <接口名>` 会在前台运行未设私钥的双栈接口，也可从 JSON 配置启动。控制接口使用 [`wireguard-go` 的本机命名管道](https://git.zx2c4.com/wireguard-go/tree/ipc/uapi_windows.go) `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<接口名>`。管道归 LocalSystem 所有，只允许高完整性管理员和系统访问。管理员会话中的原版 `wg.exe` 可用它读写配置。`fwmark` 可读写，但 Windows 不会给载体数据包设置 Linux 的 `SO_MARK`。

在线更换或清除预共享密钥时，已建立的会话继续使用当前传输密钥，后续握手使用新设置。作为握手响应方时，`wg show` 等到收到用新传输密钥认证通过的数据报或保活包，才更新最近握手时间。

非零私钥按 WireGuard 的 X25519 规则规范化，`wg show` 返回规范化后的值。在线设置等价的私钥时维持已建立的会话；全零私钥仍用于清除接口身份。

一次 `wg set` 可多次指定同一 peer，按顺序应用各段设置。控制接口使用 wireguard-go 的负 errno；端口已占用时，`wg` 因此显示系统的端口占用错误，原监听保持可用。

落地使用与客户端相同的对等节点字段，加 `localAddresses` 指定隧道内源地址（每族最多一个）。落地从服务端 DNS 获得目标 IP，用户态建立 TCP 或 UDP，并复用同一个隧道。标记为同一入站会话的 UDP 目标共用隧道内的一个源端口，IPv4 和 IPv6 都可以使用这个端口。UDP 报文超过隧道 MTU 时按地址族分片和重组。落地不安装本机 TUN，UDP 载体由 `kerlico-outbound` 打开。

从 Xray 的 `remoteDNS` 迁移时，在服务端 `dns.servers` 配置 DNS 服务器的数字地址并将其 `outbound` 设为 `landing`，让 DNS 查询也经过同一隧道。

`tools/verify_wireguard.py` 在隔离的 Linux 网络命名空间运行。夹具覆盖原版内核与 Xray 的双向互通、PSK、IPv4/IPv6 TCP 和 UDP、`AllowedIPs`、源端口变化与重新握手、多 peer、分片、落地 DNS 以及独立 TUN 的 ICMP。`multipeer` 和 `multipeer-landing` 分别验证客户端和落地的两个原版内核 peer 看到同一个 UDP 端口，以及 IPv4 peer 换到 IPv6 地址和新端口时不需要重新握手。`uapi` 模式验证在线换密钥不中断现有会话、旧密钥无法完成新握手，以及失败的握手不更新最近握手时间。使用 `--natural-rekey` 可在持续发送 UDP 时分别验证两种发起端的定时换钥。

`uapi` 和 `uapi-background` 还验证停用期间能保存已占用的端口，再启用时会绑定已释放的端口，旧会话失效，且调整 MTU 后 IPv4 和 IPv6 的大包都能通过。

`outbound` 用原版内核作为对端，验证客户端 TUN 停用后释放载体、重新启用时复用原端口并完成新握手，以及提高 MTU 后的双栈大包。

给 `inbound`、`outbound`、`raw` 或 `uapi` 加 `--link-local name` 或 `--link-local index`，可以在载体仅有 IPv6 链路本地地址的隔离链路上验证接口作用域和隧道内的双栈流量。

脚本的 `portable` 模式在 Windows 或 Linux 上用 Xray 用户态 peer 验证入站和落地。它使用本机私有地址的 TCP/UDP 回显，不创建系统 TUN 网卡。Windows 上的系统 TUN 需要网卡管理权限；将 [官方 Wintun](https://www.wintun.net/) 的 `wintun.dll` 放在相应架构的 Kerlico 可执行文件旁。Kerlico 创建自己的网卡并设置 MTU，IP 地址和路由由管理员配置。

`windows-tun` 模式只在一次性 Windows 虚拟机里以 LocalSystem 身份运行，使用官方 `wg.exe` 通过生产管道执行 `show`、`set` 和 `syncconf`，用 Xray 经实际 Wintun 网卡往返 IPv4/IPv6 TCP 和 UDP。它只配置当前测试网卡的地址和对应的入站防火墙规则，不安装默认路由。

```text
python tools/verify_wireguard.py windows-tun --raw kerlico-wg.exe --wg wg.exe --xray xray.exe --logs wg-check
```

## Linux TUN 的 500 Mbps 对照

2026-11-18 在 perf-01 的隔离 veth 内网比较独立工具、wireguard-go 和 Linux 内核 WireGuard。客户端使用同一内核 peer，8 条持久 TCP 流走同样的双跳路由，隧道 MTU 为 1200。每轮预热 5 秒、计量 30 秒，每个方向分别传输并核对 1,875,000,000 字节。三轮轮换三个实现的次序，18 个正式窗口均满足目标速率 ±1% 和最大送出迟到小于 1 秒。

| 方向 | Kerlico 进程 CPU 中位数 | wireguard-go 进程 CPU 中位数 | 三轮进程 CPU 降幅 |
| --- | ---: | ---: | --- |
| 上行 | 24.23% | 88.87% | 72.93%、73.53%、72.39% |
| 下行 | 29.43% | 46.77% | 36.79%、35.35%、38.71% |

进程占用按用户态加内核态时间计算，一核满载为 100%。下表的整机栏沿用原夹具，将 `/proc/stat` 的 user、nice、system、irq 和 softirq 增量相加。该口径包括客户端、源站、协议栈和中断。

| 方向 | 整机 CPU 相对 wireguard-go 的降幅 | 整机 CPU 相对内核 WireGuard 的降幅 |
| --- | --- | --- |
| 上行 | 50.05%、53.74%、59.56% | 33.91%、38.62%、43.13% |
| 下行 | 6.94%、18.76%、41.95% | −14.43%、19.36%、39.78% |

进程 CPU 两个方向均达到 31%。整机下行只有第三轮同时达到两条基线的目标，第一轮比内核多用 14.43%。Kerlico 工具 SHA-256 为 `cabae50d3fb80afd9621753471c0174fba66c2bbb9fed01535ab265dfb1e0259`，wireguard-go 为 `7033bf18e107de459fd73406a73e15ca7e6335bdb3a6aa3200dbeec9ec8cdef6`。

修复握手前大包排队后，使用相同对端和拓扑复核了工具 `51410b6130470d8fc407cbd957cb3c20dc3f8155278e7b32dd2b957220ae0d12`。18 个计量窗口全部有效。Kerlico 进程 CPU 中位数为上行 21.47%、下行 29.43%，wireguard-go 分别为 84.03%、48.83%。

| 方向 | 进程 CPU 相对 wireguard-go 的降幅 | 整机 CPU 相对 wireguard-go 的降幅 | 整机 CPU 相对内核 WireGuard 的降幅 |
| --- | --- | --- | --- |
| 上行 | 74.19%、72.57%、74.69% | 66.37%、35.82%、53.61% | 54.67%、23.75%、51.60% |
| 下行 | 35.01%、39.89%、35.22% | 62.93%、7.86%、−40.51% | 40.41%、−11.83%、5.95% |

修复版的进程 CPU 六组均达标。按原夹具的整机读数，上行对内核第二组未达标，下行仅第一组同时通过两条基线。负降幅表示原夹具记录的 Kerlico 整机 CPU 时间更长。

在 perf-01 上另做了时钟校准。一个进程每 10 ms 执行一段计算，保持计算量相同，只改变启动相位。四个约 3 秒的窗口中，进程 CPU 时钟记录了 0.173–0.181 秒，`/proc/self/stat` 记录了 0.17–0.19 秒，整机 `/proc/stat` 活跃时间却从 0.01 秒变到 0.70 秒，其中三组甚至低于该进程自身。因此，上表保留整机原始读数，当前无法据此确认相对内核 WireGuard 的 31% 降幅。[Linux 内核对周期负载 CPU 计时偏差的说明](https://docs.kernel.org/5.19/admin-guide/cpu-load.html)

随后在同一工具上以 500 Mbps 逐方向各测一组，三个实现各自核对了 1,875,000,000 字节。在相同的起止点，以在线核数乘以单调墙钟时间，再减去空闲、I/O 等待和被宿主机占用的时间。下表单位为每个 30 秒窗口的整机 CPU 秒。另一种算法使用 `/proc/uptime` 的墙钟和空闲时间，六个结果与下表相差均小于 0.1 秒。

| 方向 | Kerlico | wireguard-go | 内核 WireGuard |
| --- | ---: | ---: | ---: |
| 上行 | 17.27 | 47.63 | 41.60 |
| 下行 | 32.73 | 38.40 | 42.01 |

这一轮整机上行相对 wireguard-go 降低 63.74%，相对内核降低 58.48%。下行分别降低 14.77% 和 22.09%。`/proc/schedstat` 单独累计的任务运行时间也给出相同的达标方向。该诊断每个方向只有一组，三轮正式配对仍见上表。[Linux 内核调度计数说明](https://docs.kernel.org/scheduler/sched-stats.html)
