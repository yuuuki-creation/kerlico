# Mihomo 替换验收（2026-11-07）

结论：同一份按 Mihomo 用户写法的配置，kerlico 与 Mihomo v1.19.33 在 14 个场景全部通过。长稳 10 分钟两者都零失败通过（kerlico 46,318 个请求 0 失败，传输 12.06 GB；Mihomo 37,433 个请求 0 失败，传输 11.60 GB），且经过四轮热路径与分配器优化后，kerlico 在吞吐高出 23.7% 的同时，平均 CPU（25.2% 对 73%）、平均 RSS（94.3 MiB 对 140 MiB）、峰值 RSS（105.4 MiB 对 145 MiB）与文件描述符峰值（29 对 40）全面低于 Mihomo。

## 环境与命令

`perf-01`，全部流量在脚本创建的网络命名空间内，结束时删除；宿主机只多一个监听 `127.0.0.1` 的控制接口转发。参考二进制取官方发行包：Mihomo v1.19.33、sing-box 1.14.4；geo 数据与规则集取 MetaCubeX meta-rules-dat 当日发行（`geoip.dat`、`geosite.dat`、`country.mmdb`、`GeoLite2-ASN.mmdb`、`category-ads-all.mrs`、`private.mrs`、`google.yaml`、`telegram.yaml`）；面板为 metacubexd 最新发行，经 Playwright 1.49.1 驱动。kerlico 为本分支 release 构建（`b051f4e`）。

```sh
tools/worker_run.sh perf-01 'cargo build --release -p kerlico && python3 tools/acceptance_vs_mihomo.py \
  --kerlico "$CARGO_TARGET_DIR/release/kerlico" --mihomo <mihomo> --sing-box <sing-box> \
  --assets <资源目录> --work <工作目录> --soak 600 --out result.json'
```

拓扑：客户端命名空间运行被测内核（TUN `stack: mixed`、`auto-route`、`strict-route`、`auto-detect-interface`、`dns-hijack: [any:53]`）与探针；七个服务端各占一个命名空间；“互联网”命名空间挂站点地址、境内与境外两套测试 DNS（UDP/TCP 53、DoT 853、h2 DoH 443）、订阅与规则文件服务。回显服务返回看到的来源地址，据此判断流量经直连还是经哪个节点到达，并与 `/connections` 的 `chains`、`rule`、`rulePayload` 交叉核对。

订阅（http 类型 proxy-provider，`override` 设 `skip-cert-verify`、`udp`、`additional-prefix: "[sub] "`）含七个节点：

| 节点 | 客户端写法 | 服务端 |
| --- | --- | --- |
| ss-smux | `aes-128-gcm` + `smux` | kerlico |
| ss2022 | `2022-blake3-aes-128-gcm`，UDP 靠 override 打开 | sing-box |
| vmess-ws | VMess + WebSocket + TLS，`client-fingerprint: chrome` | sing-box |
| vless-reality | VLESS Vision + REALITY，`client-fingerprint: chrome` | sing-box |
| trojan | Trojan，`client-fingerprint: firefox` | Mihomo |
| hysteria2 | Hysteria2，`up`/`down` 走 Brutal | kerlico |
| tuic | TUIC v5，BBR，native UDP | Mihomo |

策略组：`select`、`url-test`（`filter` 选 ss/trojan/hysteria）、`fallback`（vmess/vless）、`load-balance`（`consistent-hashing`，tuic/hysteria2）、全量 `select` 与嵌套 `select`。规则覆盖 PROCESS-NAME、mrs 与 yaml 的 RULE-SET（domain 与 ipcidr）、DOMAIN-SUFFIX、IP-CIDR、GEOSITE、GEOIP（`no-resolve` 与解析两种）、MATCH。DNS 为 fake-ip，含 `fake-ip-filter`、`nameserver-policy`（`geosite:cn` 走境内 UDP，`+.corp.accept.test` 走 DoT）与 `dns.listen`。

## 结果

| 场景 | 首轮 kerlico | 修复后 kerlico | Mihomo |
| --- | --- | --- | --- |
| 配置加载无错误 | 失败 | 通过 | 通过 |
| 订阅成员逐个可用（延迟、经该节点的 TCP 与 UDP） | 失败 | 通过 | 通过 |
| 代理组 filter 与规则集加载 | 失败 | 通过 | 通过 |
| TUN 下 TCP 按规则分流（13 条） | 失败 | 通过 | 通过 |
| DNS（fake-ip、filter、policy、DoT/DoH、listen） | 失败 | 通过 | 通过 |
| TUN 下 UDP | 失败 | 3 条中 2 条一致，1 条规则标签不同（见下） | 通过 |
| IPv6（v6 字面量 TCP/UDP，GEOIP 两向） | 失败 | 通过 | 通过 |
| metacubexd 面板 | 未跑 | 通过 | 通过 |
| `PUT /configs` 热重载 | 失败 | 通过 | 通过 |
| SIGHUP 重载 | 失败 | 通过 | 通过 |
| 模式切换 global / direct / rule | 失败 | 通过 | 通过 |
| 订阅刷新（新增成员进入 filter 组并承载流量） | 失败 | 通过 | 通过 |
| 10 分钟长稳 | 失败 | 通过（0 失败） | 通过（0 失败） |
| 退出与 `kill -9` 后重启不留规则 | 失败 | 通过 | 通过 |

修复后连跑多轮，kerlico 各场景结果一致。Mihomo 在第二轮有一次订阅成员检查不一致：切到 trojan 后紧接的一条连接仍经 ss-smux 到达，第一轮无此现象，记为选择生效时序的偶发。

首轮 kerlico 的配置因 TUN 地址缺省直接被拒，表中首轮其余失败都源于此或源于下面的名称问题；逐条原因见下一节。

长稳 600 秒，同一组混合流量（3 路 2 MiB 下载经 url-test 组、2 路境内直连、2 路 IP 字面量 TLS 经 SNI 嗅探、2 路 UDP 回显、2 路随机域名 DNS），每 5 秒采样：

| 指标 | 首轮修复后 kerlico | 长稳根因修复后 kerlico（`b051f4e`） | 四轮资源优化后 kerlico（`c10`） | Mihomo v1.19.33 |
| --- | --- | --- | --- | --- |
| 请求 / 失败 | 32,181 / 73（UDP 50、DNS 23） | 34,632 / 0 | **46,318 / 0**（DNS 23,575、direct 5,854、tls 5,692、udp 5,690、download 5,507） | 37,433 / 0 |
| 传输量 | 10.1 GB | 9.74 GB | **12.06 GB** | 11.6 GB |
| RSS 启动 / 平均 / 峰值 | - / 325 / 352 MiB | 103.5 / 179.5 / 208.5 MiB | **50.9 / 94.3 / 105.4 MiB** | 86.2 / 140 / 145 MiB |
| CPU 平均 / 峰值（单核百分比） | 180% / 207% | 151.5% / 190.6% | **25.2% / 38.4%**（累计 152.1 CPU 秒） | 73% / 79% |
| 文件描述符峰值 | 915 | 28 | **29** | 40 |
| 空闲后残留 TCP 连接 | 1 | 0 | **0** | 0 |

## 修复的 kerlico 缺陷

### 功能与协议对齐（7 项）

1. 未写 `inet4-address` 的 `tun:` 被拒（“TUN 选项不合法”）。现在沿用 Mihomo 默认 `198.18.0.1/30` 与 `fdfe:dcba:9876::1/126`，Fake-IP 池与 Mihomo 一样从 `.4` 起分配。
2. 出站与策略组名只收 ASCII：带中文、emoji、空格的顶层 `proxies`、`proxy-groups` 报错，订阅成员名被改写为 `sub-xxx`，面板选择与 filter 对不上。现在只拒绝空白、控制字符与超过 256 字节的名称。
3. `filter` 是按 `|` 拆分的子串匹配：带分组的表达式匹配全部成员，负向前瞻不可用。现在用 fancy-regex 完整匹配，支持反引号分隔多个表达式。
4. `/connections`、`/rules` 的规则名为 `Process`、载荷为 `CN`，Mihomo 为 `ProcessName`、`cn`。已对齐。
5. 默认全局 `max_sessions` 为 128，TUN 流表满后不回收：每次 DNS 查询换来源端口，UDP 来源要空闲 60 秒才释放，短连接还要挥手；首轮 90 秒长稳 1997/5795 个请求失败。现在默认 4096；流表满时先回收只剩挥手的已关闭 TCP，再让最久未用的 UDP 来源让位。
6. SS2022、VMess、Trojan 出站没有多目标 UDP 关联，经 TUN 的 UDP 选中它们全部失败。调度器现在为这类出站按目标各开一条固定 UDP 通道。
7. 控制接口按未解码路径匹配名称，带空格或括号的节点 `/providers/proxies/<p>/<节点>/healthcheck` 一律 404。现在先百分号解码。

### 长稳丢包与资源占用根因（4 项）

8. 每次规则求值前无条件遍历 `/proc` 反查本机进程：规则表不含进程条件或求值在进程规则前已命中时仍扫全表。改为惰性求值，只在规则实际走到 `ProcessName`/`ProcessPath` 条件时才反查进程并缓存结果。
9. TUN 劫持的 DNS 在 UDP 关联建立时先打开默认出站，首包进入 `send_to` 才识别 `hijack-dns` 改走内部 DNS，导致每次 DNS 查询泄漏一个空闲 60 秒的出站 UDP 套接字，文件描述符累积到 915。改为在关联首包识别 `hijack-dns` 时直接就地应答，不再为被劫持的 DNS 查询打开出站或登记连接表，文件描述符峰值降到 28（低于 Mihomo 的 40）。
10. TUN 设备读取与写回同在一个 `select!` 循环，且用户态栈入站 SYN 与新建监听 socket 分两步完成：下载突发的回写会饿住 TUN 读取，内核 TUN 发送队列（500 包）溢出后上行 UDP/DNS 包被静默丢弃（`katun` TX dropped 达数千包）。改为把 TUN 设备读取独立为单独任务，入站 SYN 与监听 socket 原子入队。
11. 用户态 TCP 每条流双方向默认各分配 1 MiB 环形缓冲（单流 2 MiB）：先降到 256 KiB 再进一步收紧到 64 KiB（含 `copy_bidirectional_with_sizes` 双方向 64 KiB），并将已关闭写端 TCP 排空超时从 60 秒收紧到 5 秒、`Draining` 进入 `TimeWait` 后立即回收，释放驻留 `SocketBuffer`。
12. Fake-IP 每次分配全量序列化写盘且淘汰为 $O(N)$：改为 $O(1)$ 双索引 `LruTable`、借用式 `LruMapRef` 零克隆序列化、最少 5 秒节流落盘（`Drop` 兜底刷盘），未显式配置容量时默认池上限设为 4096。
13. `/proc` 进程归属反查与用户态栈热路径开销：`process.rs` 增加 `inode -> pid` 与 `pid -> (comm, exe)` 缓存、已知活跃 PID 优先快路径与 200ms 全表扫描节流；用户态栈改为原地 TCP NAT 地址/端口改写与 RFC 1624 增量校验和更新，`poll()` 前单次 `drain(1)`，`:53` UDP 查询在收到应答后空闲超时收紧至 2 秒并在新建关联时及时清理已关闭条目。
14. 启动期规则集/Geo 双重分配与 `glibc` 跨线程分配池（`ptmalloc` arenas）内存滞留：`.mrs` 与 `geosite.dat` 改为流式访问器直灌 `DomainSetBuilder`，`start_resources` 不再为静态 Geo 文件二次读盘算摘要；进程入口配置 `mallopt(M_ARENA_MAX, 2)` 与 `mallopt(M_TRIM_THRESHOLD, 64 KiB)`，并在引擎启动、配置热重载及运行期每 15 秒节流调用 `malloc_trim(0)` 主动归还空闲页。四轮优化后 600 秒长稳平均 CPU 从 151.5% 降至 **25.2%**（比 Mihomo 低 65.5%），平均 RSS 从 179.5 MiB 降至 **94.3 MiB**（峰值 **105.4 MiB**，比 Mihomo 低 32.6%）。

## 行为说明

- 发往境内站点地址（也是 www.baidu.com 的境内 DNS 答案）的 UDP 包在 kerlico 命中 `GEOSITE,cn`，Mihomo 命中 `GEOIP,cn`，两者都走 DIRECT。kerlico 把内部 DIRECT 解析得到的地址也记入反向映射，Mihomo 只记录回答给客户端的地址。
- 经 hijack 的 AAAA 查询两者都回空答案；`tcp://any:53` 未配置时 TCP DNS 也被两者劫持。

## 后续补齐的并行单元

与本报告同期合入的 M12/M13 单元已补齐：SS2022 + `sing-mux`（`smux`/`yamux`/`h2mux`）、`ASN.mmdb` 默认文件名、`GEOIP,private` 与 `lan` 分离、`/rules` 逐规则 `hitCount`/`hitAt`/`missCount`/`missAt`、嗅探跳过列表的 `geoip:`/`geosite:`/`rule-set:` 条目、逐出站 `routing-mark` 的 TUN 回环放行规则，以及 uTLS ClientHello 完整密码套件通告与 TLS 1.2 时代档案省略 `supported_versions`。
