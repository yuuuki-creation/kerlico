# 规则集

由 `tools/capability_matrix.py build` 生成，不要手改。

## adguard

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `basic-syntax` | 支持的 AdGuard 基础语法 |  | 有 |  | 未实现 | 未测 | 取值：`*`、`@@`、`^`、`\|`、`\|\|` |
| `convert` | 只能经 sing-box rule-set convert --type adguard 转成二进制规则集，不能直接作源格式 |  | 有 |  | 未实现 | 未测 | 取值：`adguard`<br>约束：自 sing-box 1.10.0 起 |
| `host-syntax` | 支持的 AdGuard 主机语法 |  | 有 |  | 未实现 | 未测 | 取值：`domain`、`regexp`<br>约束：IP 主机、端口、路径不支持<br>约束：Scheme 被忽略 |
| `hosts` | hosts 格式只接受 0.0.0.0 项 |  | 有 |  | 未实现 | 未测 |  |
| `modifier` | 支持的 AdGuard 修饰符 |  | 有 |  | 未实现 | 未测 | 取值：`$important`<br>约束：$dnsrewrite=0.0.0.0 被忽略<br>约束：其他修饰符不支持 |
| `simple` | 全部行为合法域名时按逐行精确域名处理 |  | 有 |  | 未实现 | 未测 |  |

## config

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 规则集的类型、格式、版本和下载方式组合 |  | 有 |  | 部分 | 未测 | type：`inline`、`local`、`remote`<br>format：`binary`、`source`<br>source_version：`1`、`2`、`3`、`4`、`5`<br>tag：`multiple({tag})`、`single`<br>remote_client：`default_http_client`、`download_detour(deprecated)`、`http_client`<br>约束：path 或 url 后缀为 json、srs 时 format 可省略<br>约束：update_interval 默认 1d<br>约束：多 tag 与 inline 冲突，且 path、url、initial_path 必须含 {tag}<br>约束：本地文件修改后自动重载（1.10.0 起）<br>约束：远程规则集在 cache_file 开启时被缓存 |
| `download-detour` | 用于下载规则集的出站的标签。 |  | 废弃 |  | 不适用 | 未测 | 约束：`download_detour` 已在 sing-box 1.14.0 废弃且将在 sing-box 1.16.0 中被移除，请使用 `http_client` 代替。<br>约束：自 sing-box 1.8.0 起 |
| `format` | 规则集格式， `source` 或 `binary`。 |  | 有 |  | 未实现 | 未测 | 取值：`binary`、`source`<br>约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `http-client` | 用于下载规则集的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 | 约束：当 `http_clients` 与 `default_http_client` 均未配置时，将使用通过默认出站连接的隐式 HTTP 客户端。<br>约束：留空时使用默认 HTTP 客户端：即由 `default_http_client`指定的客户端，或当 `default_http_client` 为空时使用顶级 `http_clients` 的第一项。<br>约束：自 sing-box 1.14.0 起<br>约束：该隐式默认已在 sing-box 1.14.0 废弃，并将在 sing-box 1.16.0 移除；请改为定义 `http_clients`。 |
| `initial-path` | 规则集初始内容的文件路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `path` | 规则集的文件路径。 |  | 有 |  | 已实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `rules` | 一组 无头规则. |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.10.0 起 |
| `tag` | 规则集的标签。 |  | 有 |  | 已实现 | 通过 | 约束：`path`、`url` 或 `initial_path` 中的 `{tag}` 占位符将被替换为每个标签，设置多个标签时必填。<br>约束：多个标签与 `type: inline` 冲突。<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `type` | 规则集类型， `local` 或 `remote`。 |  | 有 |  | 部分 | 未测 | 取值：`inline`、`local`、`remote`<br>约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `update-interval` | 规则集的更新间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.8.0 起<br>约束：默认使用 `1d`。 |
| `url` | 规则集的下载 URL。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.8.0 起 |

## content

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `classical` | classical 内容支持全部规则类型，RULE-SET、SUB-RULE 除外 | 有 |  |  | 部分 | 未测 | 取值：`text`、`yaml` |
| `domain` | domain 内容遵守 Clash 通配符 | 有 |  |  | 已实现 | 未测 | 取值：`mrs`、`text`、`yaml` |
| `ipcidr` | ipcidr 内容为 CIDR | 有 |  |  | 已实现 | 未测 | 取值：`mrs`、`text`、`yaml` |

## ext

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `file-tag` | ext:file:tag 外部 dat |  |  | 有 | 未实现 | 未测 | 取值：`ext:file:tag`<br>约束："ext:geoip.dat:cn" 等价 "geoip:cn" |

## geo

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `geo-auto-update` | 自动更新 GEO | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `geo-update-interval` | GEO 更新间隔，单位小时 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `geodata-loader` | GEO 文件加载器，默认 memconservative | 有 |  |  | 未实现 | 未测 | 取值：`memconservative`、`standard` |
| `geodata-mode` | GEOIP 文件类型：true 用 dat，默认 false 用 mmdb | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `geoip-geosite` | GeoIP、Geosite 数据库 1.12.0 移除，改用规则集；CLI geoip、geosite 子命令可转换 |  | 已移除 |  | 不适用 | 未测 | 取值：`geoip`、`geosite`<br>约束：用 sing-box geoip export、sing-box geosite export 转成规则集 |
| `geosite-matcher` | GeoSite 匹配器实现，默认 succinct | 有 |  |  | 未实现 | 未测 | 取值：`mph`、`succinct` |
| `geox-url-asn` | GeoLite2-ASN.mmdb 下载地址 | 有 |  |  | 未实现 | 未测 | 取值：`URL` |
| `geox-url-geoip` | geoip.dat 下载地址 | 有 |  |  | 未实现 | 未测 | 取值：`URL` |
| `geox-url-geosite` | geosite.dat 下载地址 | 有 |  |  | 未实现 | 未测 | 取值：`URL` |
| `geox-url-mmdb` | country.mmdb 下载地址 | 有 |  |  | 未实现 | 未测 | 取值：`URL` |

## geodata

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `assets` | 要下载替换的文件列表 |  |  | 有 | 未实现 | 未测 | 约束：未配置时只重载现有文件<br>约束：重载失败时整体回滚 |
| `cron` | 5 段 cron，本地时区 |  |  | 有 | 未实现 | 未测 | 取值：`0 4 * * *`、`30 3 * * 1`<br>约束：上次未结束时跳过<br>约束：未设置不启用 |
| `file` | 写入文件名 |  |  | 有 | 未实现 | 未测 | 取值：`geoip.dat`、`geosite.dat`<br>约束：不支持绝对路径或跳出目录<br>约束：必须是资源目录内已存在的普通文件 |
| `outbound` | 下载用出站 tag，默认走路由 |  |  | 有 | 未实现 | 未测 |  |
| `url` | 下载地址 |  |  | 有 | 未实现 | 未测 | 取值：`.dat`、`.dat.gz`<br>约束：必须 HTTPS |

## geoip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `geoip` | geoip.dat 预定义 IP 列表 |  |  | 有 | 部分 | 未测 | 取值：`geoip-full.dat`、`geoip-lite.dat` |

## geosite

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `geosite` | geosite.dat 预定义域名列表 |  |  | 有 | 部分 | 未测 | 取值：`geosite-expand.dat`、`geosite.dat` |

## headless

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `default-interface-address` | 匹配默认接口地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.13.0 起 |
| `domain` | 匹配完整域名。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `domain-keyword` | 匹配域名关键字。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `domain-regex` | 匹配域名正则表达式。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `domain-suffix` | 匹配域名后缀。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `invert` | 反选匹配结果。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `ip-cidr` | 匹配 IP CIDR。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `logical-mode` | `and` 或 `or` |  | 有 |  | 未实现 | 未测 | 取值：`and`、`or`<br>约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `logical-rules` | 包括的规则。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `logical-type` | 逻辑规则类型，固定为 logical |  | 有 |  | 未实现 | 未测 | 取值：`logical`<br>约束：自 sing-box 1.8.0 起 |
| `network` | `tcp` 或 `udp`。 |  | 有 |  | 已实现 | 未测 | 取值：`tcp`、`udp`<br>约束：自 sing-box 1.8.0 起 |
| `network-interface-address` | 匹配网络接口（可用值同 `network_type`）地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.13.0 起 |
| `network-is-constrained` | 匹配如果网络在低数据模式下。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `network-is-expensive` | 匹配如果网络被视为计费 (在 Android) 或被视为昂贵，像蜂窝网络或个人热点 (在 Apple 平台)。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `network-type` | 匹配网络类型。 |  | 有 |  | 未实现 | 未测 | 取值：`cellular`、`ethernet`、`other`、`wifi`<br>约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `package-name` | 匹配 Android 应用包名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `package-name-regex` | 使用正则表达式匹配 Android 应用包名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `port` | 匹配端口。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `port-range` | 匹配端口范围。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `process-name` | 匹配进程名称。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS。<br>约束：自 sing-box 1.8.0 起 |
| `process-path` | 匹配进程路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.8.0 起 |
| `process-path-regex` | 使用正则表达式匹配进程路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.10.0 起 |
| `query-type` | DNS 查询类型。 |  | 有 |  | 未实现 | 未测 | 约束：当 DNS 规则引用了包含此字段的规则集时，该 DNS 规则在同一 DNS 配置中不能与旧版地址筛选字段 (DNS 规则)、旧版 DNS 规则动作 `strategy` 选项，或旧版 `rule_set_ip_cidr_accept_empty` DNS 规则项共存。<br>约束：自 sing-box 1.8.0 起 |
| `source-ip-cidr` | 匹配源 IP CIDR。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `source-port` | 匹配源端口。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `source-port-range` | 匹配源端口范围。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `wifi-bssid` | 仅在 Android 与 Apple 平台图形客户端中支持。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.8.0 起 |
| `wifi-ssid` | 匹配 WiFi SSID。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.8.0 起 |

## rule-provider

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 规则集维度 | 有 |  |  | 部分 | 未测 | type：`file`、`http`、`inline`<br>behavior：`classical`、`domain`、`ipcidr`<br>format：`mrs`、`text`、`yaml`<br>约束：http 必须 url<br>约束：inline 用 payload<br>约束：mrs 不支持 classical |
| `behavior` | 行为 | 有 |  |  | 已实现 | 未测 | 取值：`classical`、`domain`、`ipcidr` |
| `format` | 格式，默认 yaml | 有 |  |  | 未实现 | 未测 | 取值：`mrs`、`text`、`yaml`<br>约束：mrs 的 behavior 仅 domain、ipcidr |
| `header` | 自定义请求头 | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `interval` | 更新间隔秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `name` | 必须，不能重复 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `path` | 可选，文件路径，不填用 url MD5 | 有 |  |  | 已实现 | 未测 | 取值：`路径`<br>约束：限制在 HomeDir；其他位置需 SAFE_PATHS |
| `path-in-bundle` | 本地无文件时从 BundleMRS.7z 解压的路径 | 有 |  |  | 未实现 | 未测 | 取值：`路径` |
| `payload` | 内容，仅 inline 生效 | 有 |  |  | 已实现 | 通过 | 取值：`列表` |
| `proxy` | 经指定代理下载 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `size-limit` | 下载大小上限字节，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `type` | 必须 | 有 |  |  | 部分 | 未测 | 取值：`file`、`http`、`inline` |
| `url` | http 类型必须 | 有 |  |  | 未实现 | 未测 | 取值：`URL` |

## source

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `rules` | 一组 无头规则. |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `version` | 规则集版本。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.8.0 起 |
| `version-values` | 源格式规则集版本 |  | 有 |  | 未实现 | 未测 | 取值：`1`、`2`、`3`、`4`、`5`<br>约束：1：1.8.0 初版<br>约束：2：1.10.0 优化 domain_suffix 内存<br>约束：3：1.11.0 增 network_type 等<br>约束：4：1.13.0 增接口地址项<br>约束：5：1.14.0 增 package_name_regex |
