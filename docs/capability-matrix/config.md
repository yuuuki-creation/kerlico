# 配置格式

由 `tools/capability_matrix.py build` 生成，不要手改。

## build-tag

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `badlinkname` | 构建标签：go:linkname 访问 |  | 有 |  | 不适用 | 未测 | 取值：`badlinkname`<br>约束：默认启用 |
| `tfogo-checklinkname0` | 构建标签：-checklinkname=0 链接标志指示 |  | 有 |  | 不适用 | 未测 | 取值：`tfogo_checklinkname0`<br>约束：默认启用 |
| `with-acme` | 构建标签：ACME |  | 有 |  | 不适用 | 未测 | 取值：`with_acme`<br>约束：默认启用 |
| `with-ccm` | 构建标签：CCM 服务 |  | 有 |  | 不适用 | 未测 | 取值：`with_ccm`<br>约束：默认启用 |
| `with-clash-api` | 构建标签：Clash API |  | 有 |  | 不适用 | 未测 | 取值：`with_clash_api`<br>约束：默认启用 |
| `with-cloudflared` | 构建标签：Cloudflare Tunnel 入站 |  | 有 |  | 不适用 | 未测 | 取值：`with_cloudflared`<br>约束：默认启用 |
| `with-dhcp` | 构建标签：DHCP DNS |  | 有 |  | 不适用 | 未测 | 取值：`with_dhcp`<br>约束：默认启用 |
| `with-embedded-tor` | 构建标签：内嵌 Tor，需要 CGO |  | 有 |  | 不适用 | 未测 | 取值：`with_embedded_tor`<br>约束：默认不启用 |
| `with-grpc` | 构建标签：标准 gRPC |  | 有 |  | 不适用 | 未测 | 取值：`with_grpc`<br>约束：默认不启用 |
| `with-gvisor` | 构建标签：gVisor，旧 gvisor、mixed 栈需要 |  | 有 |  | 不适用 | 未测 | 取值：`with_gvisor`<br>约束：默认不启用 |
| `with-naive-outbound` | 构建标签：NaiveProxy 出站 |  | 有 |  | 不适用 | 未测 | 取值：`with_naive_outbound`<br>约束：默认启用 |
| `with-ocm` | 构建标签：OCM 服务 |  | 有 |  | 不适用 | 未测 | 取值：`with_ocm`<br>约束：默认启用 |
| `with-quic` | 构建标签：QUIC 支持 |  | 有 |  | 不适用 | 未测 | 取值：`with_quic`<br>约束：默认启用 |
| `with-tailscale` | 构建标签：Tailscale |  | 有 |  | 不适用 | 未测 | 取值：`with_tailscale`<br>约束：默认启用 |
| `with-utls` | 构建标签：uTLS |  | 有 |  | 不适用 | 未测 | 取值：`with_utls`<br>约束：默认启用 |
| `with-v2ray-api` | 构建标签：V2Ray API |  | 有 |  | 不适用 | 未测 | 取值：`with_v2ray_api`<br>约束：默认不启用 |
| `with-wireguard` | 构建标签：WireGuard |  | 有 |  | 不适用 | 未测 | 取值：`with_wireguard`<br>约束：默认启用 |

## deprecated

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `clash-cache-file` | Clash API 的 cache_file 相关字段迁到独立 cache_file |  | 已移除 |  | 不适用 | 未测 |  |
| `direct-override-fields` | direct 出站 override_address、override_port，1.13.0 移除，改用 route-options |  | 已移除 |  | 不适用 | 未测 |  |
| `dns-rule-strategy` | DNS 规则动作 strategy，1.14.0 废弃，1.16.0 移除 |  | 废弃 |  | 不适用 | 未测 |  |
| `geoip` | GeoIP，1.8.0 废弃，1.12.0 移除，改用规则集 |  | 已移除 |  | 不适用 | 未测 |  |
| `geosite` | Geosite，1.8.0 废弃，1.12.0 移除，改用规则集 |  | 已移除 |  | 不适用 | 未测 |  |
| `go118-119` | 1.10.0 起至少需要 Go 1.20 编译 |  | 已移除 |  | 不适用 | 未测 |  |
| `implicit-default-http-client` | 远程规则集隐式默认 HTTP 客户端，1.14.0 废弃，1.16.0 移除 |  | 废弃 |  | 不适用 | 未测 | 约束：显式配置 http_clients 和 route.default_http_client |
| `independent-cache` | DNS independent_cache，1.14.0 废弃，1.16.0 移除，直接删除字段 |  | 废弃 |  | 不适用 | 未测 |  |
| `inline-acme` | TLS 内联 ACME，1.14.0 废弃，1.16.0 移除，改用证书提供者 |  | 废弃 |  | 不适用 | 未测 |  |
| `legacy-address-filter` | 不带 match_response 的 DNS 地址过滤字段，1.14.0 废弃，1.16.0 移除 |  | 废弃 |  | 不适用 | 未测 | 约束：只含 ip_cidr 的规则集在用了 1.14 新特性时启动被拒 |
| `legacy-dns-server` | 旧版 DNS 服务器格式，1.12.0 废弃，1.14.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `legacy-ech-fields` | ECH 的 pq_signature_schemes_enabled、dynamic_record_sizing_disabled，1.13.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `legacy-inbound-fields` | 入站 sniff、domain_strategy 等，1.11.0 废弃，1.13.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `legacy-special-outbounds` | 旧版特殊出站 block、dns，1.11.0 废弃，1.13.0 移除，改用规则动作 |  | 已移除 |  | 不适用 | 未测 | 约束：source:include/registry.go 仍注册 block，dns 已报错 |
| `outbound-dns-rule` | DNS 规则 outbound 项，1.12.0 废弃，改用拨号字段 domain_resolver |  | 废弃 |  | 不适用 | 未测 | 约束：源码仍读取（source:route/rule/rule_dns.go） |
| `proxy-protocol` | Proxy Protocol，1.6.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `rule-set-download-detour` | 远程规则集 download_detour，1.14.0 废弃，1.16.0 移除，改用 http_client |  | 废弃 |  | 不适用 | 未测 |  |
| `rule-set-ip-cidr-accept-empty` | DNS 规则 rule_set_ip_cidr_accept_empty，1.14.0 废弃，1.16.0 移除 |  | 废弃 |  | 不适用 | 未测 |  |
| `rule-set-ipcidr-match-source` | rule_set_ipcidr_match_source 改名 rule_set_ip_cidr_match_source，1.11.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `shadowsocksr` | ShadowsocksR，1.6.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `store-rdrc` | cache_file.store_rdrc，1.14.0 废弃，1.16.0 移除，改用 store_dns |  | 废弃 |  | 不适用 | 未测 |  |
| `tun-address-fields` | TUN inet4_*、inet6_* 地址字段合并到 address、route_address、route_exclude_address，1.12.0 移除 |  | 已移除 |  | 不适用 | 未测 |  |
| `tun-gso` | TUN gso，1.13.0 移除 |  | 已移除 |  | 不适用 | 未测 | 约束：source:protocol/tun/inbound.go 报错文本写 1.12.0 |
| `tun-stack` | TUN stack 选项，1.15.0 废弃，1.17.0 移除 |  | 废弃 |  | 不适用 | 未测 |  |
| `wireguard-outbound` | WireGuard 出站，1.13.0 移除，改用端点 |  | 已移除 |  | 不适用 | 未测 |  |

## env

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `box-api` | api 子命令默认读取的环境变量 |  | 有 |  | 未实现 | 未测 | 取值：`BOX_API_SECRET`、`BOX_API_URL` |
| `clash-age-secret-key` | 解密配置的 age 密钥 | 有 |  |  | 未实现 | 未测 | 取值：`AGE-SECRET-KEY` |
| `clash-config-file` | 配置文件（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-config-string` | base64 配置（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-home-dir` | 配置目录（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-external-controller` | 覆盖 API 地址（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-external-controller-pipe` | 覆盖 pipe（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-external-controller-routing-mark` | 覆盖 API routing-mark（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-external-controller-tls` | 覆盖 HTTPS API（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-external-controller-unix` | 覆盖 Unix socket（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-external-ui-dir` | 覆盖面板目录（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-override-secret` | 覆盖 secret（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-post-down` | 退出前脚本（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `clash-post-up` | 启动后脚本（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `disable-embed-ca` | 禁用内嵌 CA（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `disable-loopback-detector` | 禁用环回检测（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `disable-nftables` | DISABLE_NFTABLES 环境变量（文档未写，源码 os.Getenv 读取） | 有 |  |  | 不适用 | 未测 | 取值：`字符串` |
| `disable-override-android-vpn` | DISABLE_OVERRIDE_ANDROID_VPN 环境变量（文档未写，源码 os.Getenv 读取） | 有 |  |  | 不适用 | 未测 | 取值：`字符串` |
| `disable-system-ca` | 禁用系统 CA（文档未写） | 有 |  |  | 不适用 | 未测 | 取值：`false`、`true` |
| `disable-system-hosts` | 禁用系统 hosts（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `dot-names` | 源码同时接受点分名与下划线大写名 |  |  | 有 | 不适用 | 未测 | 取值：`XRAY_LOCATION_ASSET`、`xray.location.asset` |
| `enable-deprecated` | 继续使用已废弃功能的环境变量 ENABLE_DEPRECATED_<特性名> |  | 有 |  | 不适用 | 未测 | 取值：`DNS_RULE_RULE_SET_IP_CIDR_ACCEPT_EMPTY`、`IMPLICIT_DEFAULT_HTTP_CLIENT`、`INDEPENDENT_DNS_CACHE`、`INLINE_ACME_OPTIONS`、`LEGACY_DNS_ADDRESS_FILTER`、`LEGACY_DNS_RULE_STRATEGY`、`LEGACY_DOMAIN_STRATEGY_OPTIONS`、`LEGACY_RULE_SET_DOWNLOAD_DETOUR`、`MISSING_DOMAIN_RESOLVER`、`OUTBOUND_DNS_RULE_ITEM`、`STORE_RDRC`、`TUN_STACK`<br>约束：值用 strconv.ParseBool 解析<br>约束：特性名见 source:experimental/deprecated/constants.go |
| `force-anet` | 强制 anet（文档未写） | 有 |  |  | 不适用 | 未测 | 取值：`false`、`true` |
| `host-proc` | HOST_PROC 环境变量（文档未写，源码 os.Getenv 读取） | 有 |  |  | 不适用 | 未测 | 取值：`字符串` |
| `listen-namedpipe-sddl` | LISTEN_NAMEDPIPE_SDDL 环境变量（文档未写，源码 os.Getenv 读取） | 有 |  |  | 不适用 | 未测 | 取值：`字符串` |
| `object` | env 配置块：环境变量名到字符串值的映射，配置合并后、模块构建前写入进程 |  |  | 有 | 未实现 | 未测 | 约束：XRAY_JSON_STRICT、XRAY_LOCATION_CONFIG、XRAY_LOCATION_CONFDIR、GOGC、GOMEMLIMIT、GOMAXPROCS、GOTRACEBACK 写入 env 块无效，必须启动前设置<br>约束：会覆盖进程内同名变量<br>约束：多文件时按键合并，后者覆盖 |
| `quic-go-disable-gso` | 等效 experimental.quic-go-disable-gso | 有 |  |  | 不适用 | 未测 | 取值：`1` |
| `safe-paths` | 额外安全路径 | 有 |  |  | 未实现 | 未测 | 取值：`路径列表`<br>约束：Windows 分号，其他冒号 |
| `skip-safe-path-check` | SKIP_SAFE_PATH_CHECK 环境变量（文档未写，源码 os.Getenv 读取） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `skip-system-ipv6-check` | 强制开启 tun IPv6 地址 | 有 |  |  | 不适用 | 未测 | 取值：`1` |
| `xray-browser-dialer` | 环境变量 XRAY_BROWSER_DIALER：Browser Dialer 监听地址 |  |  | 有 | 未实现 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-buf-readv` | 环境变量 XRAY_BUF_READV：缓冲 readv 开关 |  |  | 有 | 不适用 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-buf-splice` | 环境变量 XRAY_BUF_SPLICE：Freedom splice 开关 |  |  | 有 | 不适用 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-cone-disabled` | 环境变量 XRAY_CONE_DISABLED：关闭 Cone NAT 行为 |  |  | 有 | 未实现 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-json-strict` | 启用标准 JSON 解析器，默认 false |  |  | 有 | 已实现 | 未测 | 约束：写入 env 块无效 |
| `xray-location-asset` | geoip.dat/geosite.dat 目录 |  |  | 有 | 未实现 | 未测 | 取值：`./`、`/usr/local/share/xray`、`/usr/share/xray`<br>约束：未指定时按取值顺序查找 |
| `xray-location-cert` | 环境变量 XRAY_LOCATION_CERT：证书路径 |  |  | 有 | 未实现 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-location-confdir` | 多配置目录，内部 .json 按文件名读取 |  |  | 有 | 未实现 | 未测 | 约束：优先级低于 -confdir<br>约束：写入 env 块无效 |
| `xray-location-config` | 包含 config.json 的目录，默认可执行文件目录 |  |  | 有 | 未实现 | 未测 | 约束：写入 env 块无效 |
| `xray-ray-buffer-size` | 环境变量 XRAY_RAY_BUFFER_SIZE：内部缓存默认值，单位 MB，1 等于 bufferSize 1024 |  |  | 有 | 不适用 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-tun-fd` | 环境变量 XRAY_TUN_FD：外部传入 TUN FD |  |  | 有 | 未实现 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-vmess-padding` | 环境变量 XRAY_VMESS_PADDING：VMess padding 开关 |  |  | 有 | 不适用 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-xudp-basekey` | 环境变量 XRAY_XUDP_BASEKEY：XUDP GlobalID 基础密钥 |  |  | 有 | 未实现 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |
| `xray-xudp-show` | 环境变量 XRAY_XUDP_SHOW：显示 XUDP 日志 |  |  | 有 | 不适用 | 未测 | 约束：文档只列名，含义来自源码常量名（source:common/platform/platform.go） |

## example

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `config-yaml` | 官方完整示例 docs/config.yaml，Alpha 与 Meta 分支各一份 | 有 |  |  | 不适用 | 未测 | 取值：`Alpha`、`Meta` |
| `geox` | GeoX 模板：GEOSITE、GEOIP 规则 | 有 |  |  | 不适用 | 未测 | 取值：`https://wiki.metacubex.one/example/geox` |
| `minimal-vmess` | 快速入门的最小服务端（VMess+Freedom）与客户端（Socks+VMess+路由）配置 |  |  | 有 | 不适用 | 未测 |  |
| `mrs` | RULE-SET 模板：mrs 规则集 | 有 |  |  | 不适用 | 未测 | 取值：`https://wiki.metacubex.one/example/mrs` |
| `stash` | Stash 模板：text 规则集与锚点 | 有 |  |  | 不适用 | 未测 | 取值：`https://wiki.metacubex.one/example/stash` |

## format

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `anchors` | & 锚点、* 别名、<< 合并；合并有重复项不合并 | 有 |  |  | 未实现 | 未测 | 取值：`&`、`*`、`<<` |
| `array-shorthand` | 只有一项时 JSON 数组的 [] 可省略 |  | 有 |  | 未实现 | 未测 | 约束：适用于文档标注该说明的字段 |
| `duration` | 时长字段用 Go Duration 格式 |  | 有 |  | 未实现 | 未测 | 取值：`h`、`m`、`ms`、`ns`、`s`、`us`<br>约束：DNS optimistic、cache rdrc 等示例也用 d 单位，如 3d、7d |
| `extended-json` | 读取时用扩展 JSON 解析，接受注释和尾逗号 |  | 有 |  | 未实现 | 未测 | 约束：UnmarshalExtendedContext；具体语法以 sing/common/json 为准，需实测 |
| `json` | YAML 为 JSON 超集，可写多行、单行或全 JSON | 有 | 有 | 有 | 已实现 | 未测 | 取值：`JSON`、`json`<br>约束：文档只写 JSON，未提供 YAML |
| `jsonc` | JSON 内允许注释：默认自定义解析器会剔除注释及其他非标准字符 |  |  | 有 | 未实现 | 未测 | 约束：XRAY_JSON_STRICT=true 时改用标准 JSON 解析器，不再容忍注释 |
| `merge` | -c 可重复、-C 指定目录，多个配置合并加载 |  | 有 |  | 未实现 | 未测 | 取值：`-C`、`-c`<br>约束：-c stdin 从标准输入读取 |
| `protobuf` | Protobuf 配置，扩展名 .pb，由 xray convert pb 生成 |  |  | 有 | 未实现 | 未测 | 约束：只读取第一个配置源 |
| `toml` | TOML 配置，按扩展名 .toml 或 -format 识别 |  |  | 有 | 未实现 | 未测 |  |
| `unknown-keys` | 不存在的键被忽略，可用来放锚点 | 有 |  |  | 未实现 | 未测 |  |
| `yaml` | 配置文件格式，大小写敏感，缩进只允许空格 | 有 |  | 有 | 未实现 | 未测 | 取值：`YAML` |

## merge

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `confdir` | -confdir 读取目录内全部配置并合并，优先于环境变量 |  |  | 有 | 未实现 | 未测 |  |
| `dump` | xray run -confdir=... -dump 查看合并结果 |  |  | 有 | 未实现 | 未测 |  |
| `inbounds-by-tag` | inbounds 相同 tag 覆盖，否则追加到末尾 |  |  | 有 | 未实现 | 未测 |  |
| `object-override` | 顶级对象后者覆盖或补充前者 |  |  | 有 | 未实现 | 未测 |  |
| `outbounds-by-tag` | outbounds 相同 tag 覆盖，否则添加到最前 |  |  | 有 | 未实现 | 未测 |  |
| `outbounds-tail` | 文件名含 tail（大小写不限）时新 outbound 添加到最后 |  |  | 有 | 未实现 | 未测 |  |

## migration

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `address-filter` | 迁移地址过滤到响应匹配：evaluate 加 match_response |  | 废弃 |  | 不适用 | 未测 |  |
| `bundle-id` | 1.9.5 Apple 客户端 Bundle ID 变更，数据需手动迁移 |  | 有 |  | 不适用 | 未测 |  |
| `clash-cache-file` | 迁移 Clash API 缓存到 cache_file |  | 已移除 |  | 不适用 | 未测 |  |
| `dial-domain-strategy` | 迁移拨号 domain_strategy 到 domain_resolver |  | 废弃 |  | 不适用 | 未测 | 约束：源码仍读取并上报废弃（source:common/dialer/dialer.go） |
| `direct-override` | 迁移 direct 覆盖字段到 route-options |  | 已移除 |  | 不适用 | 未测 |  |
| `domain-suffix` | 1.9.0 domain_suffix 行为：值以点开头时不变，否则匹配 (domain\|.+\.domain) |  | 有 |  | 不适用 | 未测 |  |
| `geoip` | 迁移 GeoIP 到规则集，可用 sing-box geoip 命令转换 |  | 已移除 |  | 不适用 | 未测 |  |
| `geosite` | 迁移 Geosite 到规则集，可用 sing-box geosite 命令转换 |  | 已移除 |  | 不适用 | 未测 |  |
| `inbound-fields` | 迁移入站 sniff 等字段到规则动作 |  | 已移除 |  | 不适用 | 未测 |  |
| `independent-cache` | 迁移 independent_cache：删除字段 |  | 废弃 |  | 不适用 | 未测 |  |
| `inline-acme` | 迁移内联 ACME 到证书提供者，字段大多可平移 |  | 废弃 |  | 不适用 | 未测 |  |
| `ip-version-query-type` | 1.14.0 起 ip_version、query_type 对不指定服务器的内部解析也生效，并与旧字段不兼容 |  | 有 |  | 不适用 | 未测 |  |
| `macos-standalone-data` | 1.14.0 macOS 独立版客户端换开发者账号，配置需用页面命令迁移 |  | 有 |  | 不适用 | 未测 |  |
| `new-dns-server-formats` | 迁移到新 DNS 服务器格式，页面逐类给出对照 |  | 已移除 |  | 不适用 | 未测 |  |
| `outbound-dns-rule` | 迁移 DNS 规则 outbound 项到 domain_resolver |  | 废弃 |  | 不适用 | 未测 |  |
| `process-path-windows` | 1.9.0 Windows process_path 改用 Win32 路径 |  | 有 |  | 不适用 | 未测 |  |
| `special-outbounds` | 迁移 block、dns 出站到 reject、hijack-dns 动作 |  | 已移除 |  | 不适用 | 未测 |  |
| `store-rdrc` | 迁移 store_rdrc 到 store_dns |  | 废弃 |  | 不适用 | 未测 |  |
| `tun-address` | TUN 地址字段合并 |  | 已移除 |  | 不适用 | 未测 |  |
| `tun-stack` | 迁移 TUN stack：删除 stack 选项即用 sing-tun 自研栈 |  | 废弃 |  | 不适用 | 未测 |  |
| `wireguard-outbound` | 迁移 WireGuard 出站到端点 |  | 已移除 |  | 不适用 | 未测 |  |

## overview

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `sections` | 配置总览页索引 | 有 |  |  | 不适用 | 未测 | 取值：`dns`、`inbound`、`proxies`、`proxy-groups`、`rules` |

## reload

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `sighup` | systemd ExecReload 发 SIGHUP 让 mihomo 重载 | 有 |  |  | 未实现 | 未测 | 取值：`SIGHUP` |

## root

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `certificate` | 顶层字段：证书信任配置 |  | 有 |  | 未实现 | 未测 |  |
| `certificate-providers` | 顶层字段：证书提供者列表 |  | 有 |  | 未实现 | 未测 |  |
| `dns` | 顶层字段：DNS 配置 |  | 有 |  | 已实现 | 未测 |  |
| `endpoints` | 顶层字段：端点列表 |  | 有 |  | 部分 | 未测 |  |
| `experimental` | 顶层字段：实验性功能配置 |  | 有 |  | 未实现 | 未测 |  |
| `http-clients` | 顶层字段：共享 HTTP 客户端列表 |  | 有 |  | 未实现 | 未测 |  |
| `inbounds` | 顶层字段：入站列表 |  | 有 |  | 已实现 | 未测 |  |
| `log` | 顶层字段：日志配置 |  | 有 |  | 未实现 | 未测 |  |
| `network-namespaces` | 顶层字段：网络命名空间列表 |  | 有 |  | 未实现 | 未测 |  |
| `ntp` | 顶层字段：NTP 配置 |  | 有 |  | 未实现 | 未测 |  |
| `outbounds` | 顶层字段：出站列表 |  | 有 |  | 已实现 | 未测 |  |
| `route` | 顶层字段：路由配置 |  | 有 |  | 部分 | 未测 |  |
| `schema` | 兼容编辑器使用的 Schema URI。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `services` | 顶层字段：服务列表 |  | 有 |  | 未实现 | 未测 |  |

## schema

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `generate` | JSON Schema Draft 2020-12，可用 sing-box schema 生成，反映当前构建的功能 |  | 有 |  | 未实现 | 未测 | 取值：`https://sing-box.sagernet.org/schema.json`<br>约束：自 sing-box 1.14.0 起 |

## syntax

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `domain-set` | 引入域名集合 | 有 |  |  | 未实现 | 未测 | 取值：`geosite:xxx`、`rule-set:xxx`<br>约束：rule-set 仅 behavior 为 domain、classical |
| `port-range` | 端口范围，- 范围，/ 或 , 分隔 | 有 |  |  | 未实现 | 未测 | 取值：`114-514/810-1919,65530` |
| `wildcard-dot` | . 多级但不含本身 | 有 |  |  | 未实现 | 未测 | 取值：`.baidu.com`<br>约束：只能用于域名前缀 |
| `wildcard-plus` | + 类似 DOMAIN-SUFFIX，多级且含本身 | 有 |  |  | 部分 | 未测 | 取值：`+.baidu.com`<br>约束：只能用于域名前缀 |
| `wildcard-star` | * 一次匹配一级；只匹配无 . 的主机名 | 有 |  |  | 未实现 | 未测 | 取值：`*`、`*.baidu.com`<br>约束：使用通配符应加引号 |

## top

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `api` | 配置文件顶层字段：gRPC API 配置 |  |  | 有 | 部分 | 未测 |  |
| `burst-observatory` | 配置文件顶层字段：突发连接观测 |  |  | 有 | 未实现 | 未测 |  |
| `dns` | 配置文件顶层字段：内置 DNS 配置 |  |  | 有 | 已实现 | 未测 |  |
| `env` | 配置文件顶层字段：环境变量配置块 |  |  | 有 | 未实现 | 未测 |  |
| `fakedns` | 配置文件顶层字段：FakeDNS，对象或数组 |  |  | 有 | 未实现 | 未测 | 约束：源码 JSON 键为 fakeDns，Go JSON 解析大小写不敏感，文档写法 fakedns 可用（source:infra/conf/xray.go） |
| `geodata` | 配置文件顶层字段：地理数据文件定时更新与热重载 |  |  | 有 | 未实现 | 未测 |  |
| `inbounds` | 配置文件顶层字段：入站配置数组 |  |  | 有 | 已实现 | 未测 |  |
| `log` | 配置文件顶层字段：日志配置 |  |  | 有 | 部分 | 未测 |  |
| `metrics` | 配置文件顶层字段：metrics 导出配置 |  |  | 有 | 部分 | 未测 |  |
| `observatory` | 配置文件顶层字段：后台连接观测 |  |  | 有 | 未实现 | 未测 |  |
| `outbounds` | 配置文件顶层字段：出站配置数组 |  |  | 有 | 已实现 | 未测 |  |
| `policy` | 配置文件顶层字段：本地策略配置 |  |  | 有 | 部分 | 未测 |  |
| `routing` | 配置文件顶层字段：路由配置 |  |  | 有 | 部分 | 未测 |  |
| `stats` | 配置文件顶层字段：统计开关 |  |  | 有 | 部分 | 未测 |  |
| `transport` | 全局传输配置 |  |  | 已移除 | 不适用 | 未测 | 约束：存在时启动报错，要求改用 inbounds/outbounds 的 streamSettings |
| `version` | 限制配置可运行的 Xray 版本 |  |  | 有 | 未实现 | 未测 |  |

## types

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `int32range` | Int32Range 取值写法：字符串单值、字符串范围或整数 |  |  | 有 | 不适用 | 未测 | 取值：`""`、`"114"`、`"114-514"`、`114`<br>约束："" 视为 0；部分字段不设置与设为空含义不同<br>约束：From>To 时自动交换 |

## version

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `max` | 允许运行的最高版本，x.y.z 语法 |  |  | 有 | 未实现 | 未测 | 约束：留空不设限 |
| `min` | 允许运行的最低版本，x.y.z 语法 |  |  | 有 | 未实现 | 未测 | 约束：25.8.3 以下无意义<br>约束：留空不设限 |
