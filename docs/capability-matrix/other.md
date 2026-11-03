# 其他

由 `tools/capability_matrix.py build` 生成，不要手改。

## arch

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `layers` | 内核分应用层、代理层、传输层；Dispatcher、Router、DNS、Proxy Manager 为应用层模块 |  |  | 有 | 待标注 | 未测 |  |

## build

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cross-compile` | GOOS/GOARCH 交叉编译 |  |  | 有 | 待标注 | 未测 |  |
| `go-build` | 官方编译命令 CGO_ENABLED=0 go build ... ./main |  |  | 有 | 待标注 | 未测 |  |
| `reproducible` | 可复现构建，MIPS/MIPSLE 使用不同 gcflags |  |  | 有 | 待标注 | 未测 |  |
| `windows7` | Windows 7 构建需 go-win7 工具链 |  |  | 有 | 待标注 | 未测 |  |

## clash-for-android

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `append-system-dns` | CFA 专用：追加系统 DNS（文档未写） | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `ui-subtitle-pattern` | CFA 专用：界面副标题匹配（文档未写） | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |

## dev

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `guide` | 开发规范页：分支、PR、编码规范，无运行时配置 |  |  | 有 | 待标注 | 未测 |  |
| `intro-index` | 开发入门索引页，无运行时配置 |  |  | 有 | 待标注 | 未测 |  |

## docs-page

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `clients-android-features` | Android 客户端功能和可用的 TUN、规则选项，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-android-index` | Android 客户端，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-apple-features` | Apple 客户端功能和可用的 TUN、规则选项，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-apple-index` | Apple 客户端，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-desktop-features` | 桌面客户端功能，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-desktop-index` | 桌面客户端，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-general` | 图形客户端统一功能：Profile、Dashboard、Core，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-index` | 图形客户端列表，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `clients-privacy` | 图形客户端隐私说明，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `installation-docker` | Docker 安装，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |
| `installation-package-manager` | 包管理器安装，图形客户端和安装方式不属于内核协议测试范围 |  | 有 |  | 待标注 | 未测 |  |

## endpoint-common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tag` | 端点的标签。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.11.0 起 |
| `type` | 端点类型 |  | 有 |  | 待标注 | 未测 | 取值：`masque-client`、`masque-server`、`openconnect`、`openvpn-client`、`openvpn-server`、`tailscale`、`wireguard`<br>约束：自 sing-box 1.11.0 起 |

## features

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `env-redirect` | 旧环境变量页，已跳转到 docs/config/env.md |  |  | 有 | 待标注 | 未测 |  |
| `index` | 特性索引页：XTLS、Fallback、Browser Dialer、多文件配置、反向代理 |  |  | 有 | 待标注 | 未测 |  |
| `xtls-wip` | XTLS 深度剖析页，内容为 WIP，配置见 VLESS flow |  |  | 有 | 待标注 | 未测 |  |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `etag-support` | 外部资源下载的 ETag 支持，默认 true | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `global-ua` | 外部资源下载 UA，默认 clash.meta | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `ipv6` | 是否允许内核接受 IPv6 流量，默认 true | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `unified-delay` | 统一延迟，计算 RTT 以消除握手差异 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |

## http-client

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | HTTP 客户端的形式、引擎、版本组合 |  | 有 |  | 待标注 | 未测 | form：`object`、`tag`<br>engine：`apple`、`go`<br>version：`1`、`2`、`3`<br>consumers：`acme`、`api-dashboard`、`derp-verify-url`、`origin-ca`、`realm`、`rule-set`、`tailcat`<br>约束：apple 引擎为实验性，iOS、tvOS 热路径不要用<br>约束：apple 引擎只在 Apple 平台，不支持 version、disable_version_fallback、HTTP2/QUIC 字段、tls.engine、tls.alpn、tls.disable_sni、tls.cipher_suites、tls.curve_preferences、客户端证书、fragment、kernel_*、ech、utls、reality<br>约束：apple 引擎的 tls.server_name 必须匹配请求 host<br>约束：version 3 用 QUIC 字段<br>约束：自 1.14.0 起<br>约束：默认 version 2 |
| `disable-version-fallback` | 禁用自动回退到更低的 HTTP 版本。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `engine` | 要使用的 HTTP 引擎。 |  | 有 |  | 待标注 | 未测 | 取值：`apple`、`go`<br>约束：* `go`（默认）<br>约束：* `tls.server_name`（必须与请求主机匹配）<br>约束：`apple` 使用 NSURLSession，仅在 Apple 平台可用。<br>约束：不支持的字段：<br>约束：仅供实验用途：不应在 iOS 和 tvOS 的热路径中使用。<br>约束：自 sing-box 1.14.0 起 |
| `headers` | 自定义 HTTP 标头。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls` | TLS 配置 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `version` | HTTP 版本。 |  | 有 |  | 待标注 | 未测 | 取值：`1`、`2`、`3`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `2`。 |

## install

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `arch` | 架构 | 有 |  |  | 待标注 | 未测 | 取值：`386`、`amd64`、`arm64`、`armv7`、`loong64`、`mips`、`riscv64`、`s390x` |
| `build-tags` | 构建标识 | 有 |  |  | 待标注 | 未测 | 取值：`abi1`、`abi2`、`alpha`、`go120`、`go123`、`v1`、`v2`、`v3`<br>约束：linux 2.6.32~3.1 内核用 go123 标签 |
| `channels` | 通道 | 有 |  |  | 待标注 | 未测 | 取值：`alpha`、`release` |
| `packages` | 预编译包 | 有 |  |  | 待标注 | 未测 | 取值：`android gz`、`darwin gz`、`freebsd gz`、`linux deb`、`linux gz`、`linux pkg.tar.zst`、`linux rpm`、`windows zip` |

## legacy-reverse

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 旧反向代理角色 |  |  | 已移除 | 待标注 | 未测 | role：`both`、`bridge`、`portal`<br>约束：两端 domain 必须相同<br>约束：建议先启 bridge 再启 portal<br>约束：默认开启 Mux，不要在其 outbound 再开 |
| `bridges` | bridge 列表 |  |  | 已移除 | 待标注 | 未测 | 取值：`domain`、`tag` |
| `portals` | portal 列表 |  |  | 已移除 | 待标注 | 未测 | 取值：`domain`、`tag` |
| `reverse` | 旧版反向代理配置 |  |  | 已移除 | 待标注 | 未测 | 约束：改用 VLESS 反向代理<br>约束：文档标已废弃；源码配置时报错（source:infra/conf/xray.go） |

## llm-prompt

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `docs-index` | 文档首页给用户复制的 AI 提示词与 llms-full.txt 全量文档地址，无运行时配置 |  |  | 有 | 待标注 | 未测 | 取值：`https://xtls.github.io/llms-full.txt` |

## lua

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `data-types` | Lua 数据类型 |  |  | 有 | 待标注 | 未测 | 取值：`IP 列表输入`、`[]net.IP`、`[]uint32`、`error`、`net.IP`<br>约束：slice 下标从 1 开始，越界抛异常<br>约束：slice 不支持 pairs/ipairs |
| `dns-guide` | DNS 脚本：HandleDNSQuery 接管上游选择 |  |  | 有 | 待标注 | 未测 | 约束：domains、skipFallback、finalQuery、disableFallback、disableFallbackIfMatch、enableParallelQuery 失去意义<br>约束：仍先经域名检查、queryStrategy、Hosts |
| `lifecycle` | 池化实例：启动编译一次，并发时新建 |  |  | 有 | 待标注 | 未测 | 约束：修改脚本需重启<br>约束：初始化超时 120 秒<br>约束：状态不跨实例共享<br>约束：调用超时 6 秒 |
| `overview` | Lua 脚本入口与 Hook 对应 |  |  | 有 | 待标注 | 未测 | 取值：`dns.script→HandleDNSQuery`、`routing.script→HandleRoute` |
| `routing-guide` | 路由脚本：HandleRoute 接管，可 PickOutbound、主动解析后按 IP 分流 |  |  | 有 | 待标注 | 未测 | 约束：skipDNSResolve 为 true 时须跳过 DNS 防回环<br>约束：启用后 rules、domainStrategy 不生效 |
| `runtime` | GopherLua：Lua 5.1 语法、5.2 goto、channel |  |  | 有 | 待标注 | 未测 |  |
| `script-path` | 脚本路径查找 |  |  | 有 | 待标注 | 未测 | 取值：`XRAY_LOCATION_CONFDIR`、`XRAY_LOCATION_CONFIG`、`可执行文件目录`、`当前工作目录`、`绝对路径`<br>约束：不以配置文件目录为基准<br>约束：存在但非普通文件时报错 |

## manual-anytls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `client-metadata` | 手册：AnyTLS 客户端元数据默认空，client_metadata 可自定义 |  | 有 |  | 待标注 | 未测 | 约束：1.13.16、1.14.0-beta.5 起默认空 |

## manual-client

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 手册：客户端接入方式和示例 |  | 有 |  | 待标注 | 未测 | mode：`firewall-redirection`、`system-proxy`、`virtual-interface`<br>example：`basic-tun`、`traffic-bypass-with-dns-leak`、`traffic-bypass-without-dns-leak`<br>约束：手册示例面向 TUN<br>约束：系统代理只覆盖走系统代理的 TCP，UDP、ICMP 绕过 |

## manual-hysteria2

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 手册：Hysteria2 示例 |  | 有 |  | 待标注 | 未测 | side：`client`、`server`<br>cert：`acme`、`dns01`、`self-signed`<br>约束：userpass 用 <用户名>:<密码> 作密码<br>约束：被动检测有风险，主动探测可抗<br>约束：需按实际带宽替换 up_mbps、down_mbps |

## manual-server

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inbound-only` | 手册：作为服务端基本只需配置对应入站 |  | 有 |  | 待标注 | 未测 |  |

## manual-shadowsocks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 手册：Shadowsocks 加密族和示例 |  | 有 |  | 待标注 | 未测 | cipher_family：`aead`、`aead-2022`、`stream`<br>side：`client`、`server`<br>约束：不开多路复用直接发 UDP 易被被动检测<br>约束：只推荐 AEAD 2022 走 TCP 并开多路复用 |

## manual-trojan

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 手册：Trojan 实现组合和示例 |  | 有 |  | 待标注 | 未测 | implementation：`basic-go`、`origin`、`with-utls`、`with-v2ray-transport`<br>side：`client`、`server`<br>cert：`acme`、`dns01`、`self-signed`<br>约束：basic-go 与 v2ray 传输被动检测有风险 |

## manual-tunnelvision

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `status` | 手册：TunnelVision（CVE-2024-3661）在各平台的状态 |  | 有 |  | 待标注 | 未测 | 取值：`android`、`apple`、`linux`、`windows`<br>约束：Android 不受影响<br>约束：Apple 开 includeAllNetworks，旧 system、mixed 栈不可用<br>约束：Linux auto_route 规则不受影响<br>约束：Windows 暂无方案 |

## meta

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pinned-sources` | 本清单依据的固定提交 |  |  | 有 | 待标注 | 未测 | 取值：`Xray-core@556767e40baa142641838158d6cba743c879e5c3`、`Xray-docs-next@e9f8a16331af0dd80a7bf8d2793205555d7909d2`<br>约束：Xray-core 该提交版本号为 26.10.31（source:core/core.go） |

## netns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 网络命名空间的类型和引用位置组合 |  | 有 |  | 待标注 | 未测 | type：`default`、`unshare`<br>reference：`dial.netns`、`listen.netns`、`tun.netns`<br>约束：default 的 path 必填<br>约束：tag 必填<br>约束：unshare 需要内核允许非特权 user namespace<br>约束：仅 Linux<br>约束：拨号字段应避免引用 unshare 命名空间 |

## netns-common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tag` | 网络命名空间的标签。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `type` | 网络命名空间的类型，默认使用 `default`。 |  | 有 |  | 待标注 | 未测 | 取值：`default`、`unshare`<br>约束：自 sing-box 1.14.0 起 |

## netns-default

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `path` | 网络命名空间的名称或路径，例如 `sing` 或 `/run/netns/sing`。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |

## netns-unshare

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pid-file` | 如果设置，持有该命名空间的进程 PID 将写入此路径。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |

## protocol-docs

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `index` | 协议详解索引页：VLESS、VMess、Mux.Cool、mKCP |  |  | 有 | 待标注 | 未测 |  |

## rate-limit

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `unsupported` | 配置文档没有按用户或连接限速选项；Hysteria 系的 up、down 是拥塞控制带宽，brutal 同理 |  | 有 |  | 待标注 | 未测 |  |

## service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `systemd` | systemd 单元：Type=simple，ExecStart -d /etc/mihomo，ExecReload HUP，能力集 CAP_NET_ADMIN 等 | 有 |  |  | 待标注 | 未测 | 取值：`enable`、`reload`、`start`、`status` |

## service-ccm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Claude Code 订阅多路复用服务 |  | 有 |  | 待标注 | 未测 | 取值：`ccm`<br>约束：自 sing-box 1.13.0 起<br>约束：需要 with_ccm 构建标签 |
| `credential-path` | Claude Code OAuth 凭据文件的路径。 |  | 有 |  | 待标注 | 未测 | 约束：在 macOS 上，首先从系统钥匙串读取凭据，如果不可用则回退到文件。<br>约束：如果未指定，默认值为：<br>约束：自 sing-box 1.13.0 起 |
| `detour` | 用于连接 Claude API 的出站标签。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `headers` | 发送到 Claude API 的自定义 HTTP 头。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `usages-path` | 用于存储聚合 API 使用统计信息的文件路径。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `users` | 用于令牌身份验证的授权用户列表。 |  | 有 |  | 待标注 | 未测 | 约束：如果为空，则不需要身份验证。<br>约束：自 sing-box 1.13.0 起 |
| `users-name` | 用于跟踪的用户名标识符。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `users-token` | 用于身份验证的 Bearer 令牌。Claude Code 通过设置 `ANTHROPIC_AUTH_TOKEN` 环境变量为其令牌值进行身份验证。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |

## service-common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tag` | 端点的标签。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `type` | 服务类型 |  | 有 |  | 待标注 | 未测 | 取值：`api`、`ccm`、`derp`、`hysteria-realm`、`ocm`、`resolved`、`ssm-api`、`usbip-client`、`usbip-server`<br>约束：自 sing-box 1.12.0 起 |

## service-derp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tailscale DERP 服务 |  | 有 |  | 待标注 | 未测 | 取值：`derp`<br>约束：自 sing-box 1.12.0 起 |
| `combo` | DERP 服务的校验、mesh、STUN 组合 |  | 有 |  | 待标注 | 未测 | client_verify：`none`、`verify_client_endpoint`、`verify_client_inbound`、`verify_client_key`、`verify_client_url`<br>mesh：`mesh_psk`、`mesh_psk_file`、`off`<br>stun：`number`、`object`、`off`<br>home：`blank`、`default`、`url`<br>约束：TLS 必需（source:service/derp/service.go）<br>约束：config_path 必填<br>约束：mesh 需要 psk（source:service/derp/service.go）<br>约束：mesh_with 的 server、server_port 必填<br>约束：verify_client_inbound、verify_client_key 自 1.15.0 起 |
| `config-path` | Derper 配置文件路径。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `home` | 在根路径提供的内容。 |  | 有 |  | 待标注 | 未测 | 约束：可以留空（默认值，显示默认主页）、`blank` 显示空白页面，或一个重定向的 URL。<br>约束：自 sing-box 1.12.0 起 |
| `mesh-psk` | DERP 组网的预共享密钥。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `mesh-psk-file` | DERP 组网的预共享密钥文件。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `mesh-with` | 与其他 DERP 服务器组网。 |  | 有 |  | 待标注 | 未测 | 约束：- `server_port`：必填 DERP 服务器端口。<br>约束：- `server`：必填 DERP 服务器地址。<br>约束：自 sing-box 1.12.0 起 |
| `mesh-with-host` | 自定义 DERP 主机名。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `mesh-with-server` | 必填 DERP 服务器地址。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `mesh-with-server-port` | 必填 DERP 服务器端口。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `mesh-with-tls` | DERP mesh 连接的 TLS 配置 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `stun` | STUN 服务器监听选项。 |  | 有 |  | 待标注 | 未测 | 约束：- `enabled`：必填 启用 STUN 服务器。<br>约束：- `listen_port`：必填 STUN 服务器监听端口，默认为 `3478`。<br>约束：- `listen`：必填 STUN 服务器监听地址，默认为 `::`。<br>约束：自 sing-box 1.12.0 起 |
| `stun-enabled` | 必填 启用 STUN 服务器。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `verify-client-endpoint` | 用于验证客户端的 Tailscale 端点标签。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `verify-client-inbound` | 用于验证客户端的 Tailcat 入站标签。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `verify-client-key` | 用于验证客户端的 Tailcat 公钥。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `verify-client-url` | 用于验证客户端的 URL。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `verify-client-url-url` | `verify_client_url` 对象的 `url` 字段 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.12.0 起 |

## service-hysteria-realm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Hysteria2 NAT 穿透汇合服务 |  | 有 |  | 待标注 | 未测 | 取值：`hysteria-realm`<br>约束：自 sing-box 1.14.0 起 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `users` | 授权用户。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `users-max-realms` | 此用户可同时持有的 realm 槽位数量上限。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `users-name` | 用户名，用于日志记录和配额键。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `users-token` | Hysteria2 入站和出站通过 `Authorization: Bearer <token>` 出示的 Bearer 令牌。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |

## service-ocm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | OpenAI Codex 订阅多路复用服务 |  | 有 |  | 待标注 | 未测 | 取值：`ocm`<br>约束：自 sing-box 1.13.0 起<br>约束：需要 with_ocm 构建标签 |
| `credential-path` | OpenAI OAuth 凭据文件的路径。 |  | 有 |  | 待标注 | 未测 | 约束：如果未指定，默认值为：<br>约束：自 sing-box 1.13.0 起 |
| `detour` | 用于连接 OpenAI API 的出站标签。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `headers` | 发送到 OpenAI API 的自定义 HTTP 头。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `usages-path` | 用于存储聚合 API 使用统计信息的文件路径。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `users` | 用于令牌身份验证的授权用户列表。 |  | 有 |  | 待标注 | 未测 | 约束：如果为空，则不需要身份验证。<br>约束：自 sing-box 1.13.0 起 |
| `users-name` | 用于跟踪的用户名标识符。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `users-token` | 用于身份验证的 Bearer 令牌。客户端通过设置 `Authorization: Bearer <token>` 头进行身份验证。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.13.0 起 |

## service-oom-killer

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 内存超限自动处理服务，文档未列，只在源码 |  | 有 |  | 待标注 | 未测 | 取值：`oom-killer`<br>约束：字段 memory_limit、safety_margin、min_interval、max_interval |
| `max-interval` | oom-killer 服务的 max_interval，文档未列 |  | 有 |  | 待标注 | 未测 | 约束：min_interval、max_interval 必须大于 0，max 不小于 min（source:service/oomkiller/timer.go） |
| `memory-limit` | oom-killer 服务的 memory_limit，文档未列 |  | 有 |  | 待标注 | 未测 |  |
| `min-interval` | oom-killer 服务的 min_interval，文档未列 |  | 有 |  | 待标注 | 未测 | 约束：min_interval、max_interval 必须大于 0，max 不小于 min（source:service/oomkiller/timer.go） |
| `safety-margin` | oom-killer 服务的 safety_margin，文档未列 |  | 有 |  | 待标注 | 未测 |  |

## service-resolved

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 伪 systemd-resolved DBUS 服务 |  | 有 |  | 待标注 | 未测 | 取值：`resolved`<br>约束：自 sing-box 1.12.0 起 |
| `listen` | 监听地址。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.12.0 起<br>约束：默认使用 `127.0.0.53`。 |
| `listen-port` | 监听端口。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.12.0 起<br>约束：默认使用 `53`。 |

## service-usbip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | USB/IP 服务的提供者和设备匹配组合 |  | 有 |  | 待标注 | 未测 | provider：`default`、`dynamic`<br>match：`bus_id`、`product_id`、`serial`、`vendor_id`<br>约束：default 提供者需要 devices，只支持 CLI 运行的 Linux、Windows、macOS，且需提权<br>约束：dynamic 经 sing-box API 客户端提供设备<br>约束：macOS 需要 CGO 构建，iOS 不可用<br>约束：同一对象内字段全部匹配，多对象取并集，至少一个字段<br>约束：客户端服务端口默认 3240，只有 detour 生效 |

## service-usbip-client

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | USB/IP 导入服务 |  | 有 |  | 待标注 | 未测 | 取值：`usbip-client`<br>约束：自 sing-box 1.14.0 起 |
| `devices` | 设备匹配列表，用于选择要导入的远程设备。 |  | 有 |  | 待标注 | 未测 | 约束：在一个对象内，所有指定的字段都必须匹配；多个对象之间取并集。<br>约束：自 sing-box 1.14.0 起<br>约束：至少需要一个字段。 |
| `devices-bus-id` | USB 总线 ID，例如 `1-2`。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `devices-product-id` | USB 产品 ID，为数字。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `devices-serial` | 设备序列号。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `devices-vendor-id` | USB 供应商 ID，为数字。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `server` | 远程 `usbip-server` 地址。 |  | 有 |  | 待标注 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `server-port` | 远程 `usbip-server` 端口。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认为 `3240`。 |

## service-usbip-server

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | USB/IP 导出服务 |  | 有 |  | 待标注 | 未测 | 取值：`usbip-server`<br>约束：自 sing-box 1.14.0 起 |
| `devices` | 使用 `default` 提供者时 ==必填==。 |  | 有 |  | 待标注 | 未测 | 约束：在一个对象内，所有指定的字段都必须匹配；多个对象之间取并集。<br>约束：自 sing-box 1.14.0 起<br>约束：至少需要一个字段。 |
| `devices-bus-id` | USB 总线 ID，例如 `1-2`。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `devices-product-id` | USB 产品 ID，为数字。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `devices-serial` | 设备序列号。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `devices-vendor-id` | USB 供应商 ID，为数字。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `provider` | 设备来源提供者。 |  | 有 |  | 待标注 | 未测 | 取值：`default`、`dynamic`<br>约束：`default` 提供者仅支持通过 CLI 直接运行在 Linux、Windows 和 macOS 上，并且需要提升的权限。<br>约束：自 sing-box 1.14.0 起<br>约束：默认值。 |
