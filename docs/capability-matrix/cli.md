# 命令行

由 `tools/capability_matrix.py build` 生成，不要手改。

## api

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `adi` | 添加入站 |  |  | 有 | 未实现 | 未测 |  |
| `ado` | 添加出站 |  |  | 有 | 未实现 | 未测 |  |
| `adrules` | 添加路由规则 |  |  | 有 | 未实现 | 未测 | 取值：`-append` |
| `adu` | 添加用户 |  |  | 有 | 未实现 | 未测 |  |
| `api` | API 服务客户端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api` |
| `api-connection` | 管理连接 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api connection` |
| `api-connection-close` | 关闭连接 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api connection close` |
| `api-connection-close-all` | api connection close 的 --all：关闭全部 |  | 有 |  | 未实现 | 未测 | 取值：`--all` |
| `api-connection-list` | 列出连接 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api connection list` |
| `api-connection-list-columns` | api connection list 的 --columns：显示列 |  | 有 |  | 未实现 | 未测 | 取值：`--columns` |
| `api-connection-show` | 打印连接详情 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api connection show` |
| `api-group` | 管理策略组 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api group` |
| `api-group-list` | 列出策略组 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api group list` |
| `api-group-select` | 选择组内出站 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api group select` |
| `api-group-show` | 查看策略组 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api group show` |
| `api-group-urltest` | 启动 URL 测试 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api group urltest` |
| `api-logs` | 打印服务日志 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api logs` |
| `api-logs-follow` | api logs 的 --follow：持续输出 |  | 有 |  | 未实现 | 未测 | 取值：`--follow`、`-f` |
| `api-logs-level` | api logs 的 --level：日志级别 |  | 有 |  | 未实现 | 未测 | 取值：`--level` |
| `api-logs-search` | api logs 的 --search：按文本筛选 |  | 有 |  | 未实现 | 未测 | 取值：`--search` |
| `api-mode` | 打印 clash 模式 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api mode` |
| `api-mode-list` | 列出 clash 模式 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api mode list` |
| `api-mode-set` | 设置 clash 模式 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api mode set` |
| `api-networkquality` | 远程网络质量测试 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api networkquality` |
| `api-networkquality-config-url` | api networkquality 的 --config-url：测试配置 URL |  | 有 |  | 未实现 | 未测 | 取值：`--config-url` |
| `api-networkquality-http3` | api networkquality 的 --http3：用 HTTP/3 测量 |  | 有 |  | 未实现 | 未测 | 取值：`--http3` |
| `api-networkquality-max-runtime` | api networkquality 的 --max-runtime：最大运行秒数 |  | 有 |  | 未实现 | 未测 | 取值：`--max-runtime` |
| `api-networkquality-outbound` | api networkquality 的 --outbound：使用指定出站标签 |  | 有 |  | 未实现 | 未测 | 取值：`--outbound`、`-o` |
| `api-networkquality-serial` | api networkquality 的 --serial：顺序执行上下行 |  | 有 |  | 未实现 | 未测 | 取值：`--serial` |
| `api-openconnect` | 管理 OpenConnect 认证 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openconnect` |
| `api-openconnect-auth` | 回答 OpenConnect 认证挑战 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openconnect auth` |
| `api-openconnect-auth-callback-port` | api openconnect auth 的 --callback-port：浏览器 SSO 回调端口，默认 8020 |  | 有 |  | 未实现 | 未测 | 取值：`--callback-port` |
| `api-openconnect-auth-endpoint` | api openconnect auth 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-openconnect-cancel` | 取消 OpenConnect 认证挑战 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openconnect cancel` |
| `api-openconnect-cancel-endpoint` | api openconnect cancel 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-openconnect-status` | 打印 OpenConnect 端点状态 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openconnect status` |
| `api-openvpn` | 管理 OpenVPN 认证 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openvpn` |
| `api-openvpn-auth` | 回答 OpenVPN 认证挑战 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openvpn auth` |
| `api-openvpn-auth-endpoint` | api openvpn auth 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-openvpn-cancel` | 取消 OpenVPN 挑战并停止客户端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openvpn cancel` |
| `api-openvpn-cancel-endpoint` | api openvpn cancel 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-openvpn-status` | 打印 OpenVPN 端点状态 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api openvpn status` |
| `api-outbounds` | 列出出站 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api outbounds` |
| `api-secret` | api 的 --secret：API 密钥，默认 BOX_API_SECRET |  | 有 |  | 未实现 | 未测 | 取值：`--secret` |
| `api-status` | 打印服务状态 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api status` |
| `api-stun` | 远程 STUN 测试 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api stun` |
| `api-stun-outbound` | api stun 的 --outbound：使用指定出站标签 |  | 有 |  | 未实现 | 未测 | 取值：`--outbound`、`-o` |
| `api-stun-server` | api stun 的 --server：STUN 服务器地址 |  | 有 |  | 未实现 | 未测 | 取值：`--server` |
| `api-tailscale` | 管理 Tailscale 端点 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale` |
| `api-tailscale-certificate` | 管理 Tailscale HTTPS 证书 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale certificate` |
| `api-tailscale-certificate-export` | 导出证书和私钥 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale certificate export` |
| `api-tailscale-certificate-export-cert-file` | api tailscale certificate export 的 --cert-file：证书输出文件 |  | 有 |  | 未实现 | 未测 | 取值：`--cert-file` |
| `api-tailscale-certificate-export-key-file` | api tailscale certificate export 的 --key-file：私钥输出文件 |  | 有 |  | 未实现 | 未测 | 取值：`--key-file` |
| `api-tailscale-certificate-export-min-validity` | api tailscale certificate export 的 --min-validity：有效期不足时续期 |  | 有 |  | 未实现 | 未测 | 取值：`--min-validity` |
| `api-tailscale-certificate-list` | 列出可签证书域名 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale certificate list` |
| `api-tailscale-certificate-list-endpoint` | api tailscale certificate list 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-exit-node` | 打印当前出口节点 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale exit-node` |
| `api-tailscale-exit-node-clear` | 清除出口节点 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale exit-node clear` |
| `api-tailscale-exit-node-endpoint` | api tailscale exit-node 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-exit-node-list` | 列出出口节点 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale exit-node list` |
| `api-tailscale-exit-node-set` | 设置出口节点 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale exit-node set` |
| `api-tailscale-logout` | 退出 Tailscale |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale logout` |
| `api-tailscale-logout-endpoint` | api tailscale logout 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-peer` | 管理 Tailscale 对端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale peer` |
| `api-tailscale-peer-list` | 列出对端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale peer list` |
| `api-tailscale-peer-list-endpoint` | api tailscale peer list 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-peer-show` | 打印对端详情 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale peer show` |
| `api-tailscale-peer-show-endpoint` | api tailscale peer show 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-ping` | Ping 对端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale ping` |
| `api-tailscale-ping-endpoint` | api tailscale ping 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-ssh` | SSH 到对端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale ssh` |
| `api-tailscale-ssh-endpoint` | api tailscale ssh 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-status` | 打印 Tailscale 端点状态 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale status` |
| `api-tailscale-taildrop` | 收发 Taildrop 文件 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale taildrop` |
| `api-tailscale-taildrop-delete` | 删除收到的文件 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale taildrop delete` |
| `api-tailscale-taildrop-get` | 保存收到的文件 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale taildrop get` |
| `api-tailscale-taildrop-list` | 列出收到的文件 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale taildrop list` |
| `api-tailscale-taildrop-list-endpoint` | api tailscale taildrop list 的 --endpoint：端点标签 |  | 有 |  | 未实现 | 未测 | 取值：`--endpoint` |
| `api-tailscale-taildrop-send` | 发送文件 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale taildrop send` |
| `api-tailscale-taildrop-targets` | 列出可接收文件的对端 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api tailscale taildrop targets` |
| `api-url` | api 的 --url：API 服务 URL，默认 BOX_API_URL |  | 有 |  | 未实现 | 未测 | 取值：`--url` |
| `api-usbip` | 管理 USB/IP 设备共享 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api usbip` |
| `api-usbip-device` | 管理本地 USB 设备 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api usbip device` |
| `api-usbip-device-list` | 列出本地 USB 设备 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api usbip device list` |
| `api-usbip-device-show` | 打印本地 USB 设备 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api usbip device show` |
| `api-usbip-share` | 经 usbip-server 共享本地设备 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api usbip share` |
| `api-usbip-share-all` | api usbip share 的 --all：共享全部设备 |  | 有 |  | 未实现 | 未测 | 取值：`--all` |
| `api-usbip-share-capture` | api usbip share 的 --capture：共享前解绑驱动，需提权 |  | 有 |  | 未实现 | 未测 | 取值：`--capture` |
| `api-usbip-share-service` | api usbip share 的 --service：usbip-server 标签 |  | 有 |  | 未实现 | 未测 | 取值：`--service` |
| `api-usbip-status` | 打印共享的 USB 设备 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api usbip status` |
| `api-usbip-status-service` | api usbip status 的 --service：限定 usbip-server 标签 |  | 有 |  | 未实现 | 未测 | 取值：`--service` |
| `api-version` | 打印 API 服务版本 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box api version` |
| `bi` | 均衡器信息 |  |  | 有 | 未实现 | 未测 |  |
| `bo` | 强制均衡器选择 |  |  | 有 | 未实现 | 未测 | 取值：`-b`、`-r` |
| `common-flags` | API 子命令通用参数 |  |  | 有 | 未实现 | 未测 | 取值：`--server`、`--timeout`、`-json`、`-s`、`-t`<br>约束：默认 127.0.0.1:8080，超时 3 秒 |
| `inbounduser` | 查询入站用户 |  |  | 有 | 未实现 | 未测 | 取值：`-email`、`-tag` |
| `inboundusercount` | 入站用户数 |  |  | 有 | 未实现 | 未测 | 取值：`-tag` |
| `lsi` | 列入站 |  |  | 有 | 未实现 | 未测 | 取值：`--isOnlyTags` |
| `lso` | 列出站 |  |  | 有 | 未实现 | 未测 |  |
| `lsrules` | 列路由规则 |  |  | 有 | 未实现 | 未测 |  |
| `restartlogger` | 重启日志 |  |  | 有 | 未实现 | 未测 |  |
| `rmi` | 删除入站 |  |  | 有 | 未实现 | 未测 |  |
| `rmo` | 删除出站 |  |  | 有 | 未实现 | 未测 |  |
| `rmrules` | 删除路由规则 |  |  | 有 | 未实现 | 未测 |  |
| `rmu` | 删除用户 |  |  | 有 | 未实现 | 未测 | 取值：`-tag` |
| `sib` | 封来源 IP |  |  | 有 | 未实现 | 未测 | 取值：`-inbound`、`-outbound`、`-reset`、`-ruletag` |
| `stats` | 取统计 |  |  | 有 | 部分 | 通过 | 取值：`-name`、`-reset` |
| `statsgetallonlineusers` | 全部在线用户 |  |  | 有 | 未实现 | 未测 |  |
| `statsonline` | 用户在线会话数 |  |  | 有 | 未实现 | 未测 | 取值：`-email` |
| `statsonlineiplist` | 用户在线 IP |  |  | 有 | 未实现 | 未测 | 取值：`-all`、`-email`、`-include-traffic`、`-reset` |
| `statsquery` | 查询统计 |  |  | 有 | 部分 | 通过 | 取值：`-pattern`、`-reset` |
| `statssys` | 系统统计 |  |  | 有 | 未实现 | 未测 |  |

## base64

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `decode` | Base64 解码 |  |  | 有 | 未实现 | 未测 | 取值：`-gzip`、`<value\|-\|stdin:>`、`[output-file]` |
| `encode` | Base64 编码 |  |  | 有 | 未实现 | 未测 | 取值：`-gzip`、`<input-file\|-\|stdin:>` |

## check

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `check` | 检查配置 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box check` |

## command

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `age-convert-secret-key` | 从 secret key 导出 public key | 有 |  |  | 未实现 | 未测 |  |
| `age-decrypt-secret-key-source-target` | 解密文件，- 为标准输入输出 | 有 |  |  | 未实现 | 未测 |  |
| `age-encrypt-public-key-source-target` | 加密文件，- 为标准输入输出 | 有 |  |  | 未实现 | 未测 |  |
| `age-keygen` | 生成 x25519 key | 有 |  |  | 未实现 | 未测 |  |
| `age-keygen-pq` | 生成 mlkem768-x25519 key | 有 |  |  | 未实现 | 未测 |  |
| `convert-ruleset-behavior-format-source-target` | 转换规则集到 mrs | 有 |  |  | 未实现 | 未测 |  |
| `generate-ech-keypair` | 生成 ECH 配置对 | 有 |  |  | 已实现 | 通过 |  |
| `generate-reality-keypair` | 生成 REALITY 密钥对 | 有 |  |  | 已实现 | 通过 |  |
| `generate-sudoku-keypair` | 生成 Sudoku 密钥对 | 有 |  |  | 已实现 | 未测 |  |
| `generate-uuid` | 生成 UUID | 有 |  |  | 已实现 | 通过 |  |
| `generate-vless-mlkem768` | 生成 vless encryption ML-KEM-768 | 有 |  |  | 未实现 | 未测 |  |
| `generate-vless-x25519` | 生成 vless encryption X25519 | 有 |  |  | 已实现 | 通过 |  |
| `generate-wg-keypair` | 生成 WireGuard 密钥对 | 有 |  |  | 已实现 | 通过 |  |

## convert

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `json` | typedMessage 转 JSON |  |  | 有 | 未实现 | 未测 | 取值：`xray convert json [-type] [stdin:] [file]` |
| `pb` | JSON 合并转 protobuf |  |  | 有 | 未实现 | 未测 | 取值：`xray convert pb [-outpbfile out.pb] [-debug] [-type] [json...]` |

## flag

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `age-secret-key` | 命令行标志 -age-secret-key：age 解密密钥 | 有 |  |  | 未实现 | 未测 | 取值：`-age-secret-key` |
| `config` | 命令行标志 -config：base64 配置字符串 | 有 |  |  | 未实现 | 未测 | 取值：`-config` |
| `d` | 命令行标志 -d：配置目录；非绝对路径相对当前目录 | 有 |  |  | 未实现 | 未测 | 取值：`-d` |
| `ext-ctl` | 命令行标志 -ext-ctl：覆盖 API 地址 | 有 |  |  | 未实现 | 未测 | 取值：`-ext-ctl` |
| `ext-ctl-pipe` | 命令行标志 -ext-ctl-pipe：覆盖 pipe | 有 |  |  | 未实现 | 未测 | 取值：`-ext-ctl-pipe` |
| `ext-ctl-routing-mark` | 命令行标志 -ext-ctl-routing-mark：覆盖 API routing-mark | 有 |  |  | 未实现 | 未测 | 取值：`-ext-ctl-routing-mark` |
| `ext-ctl-tls` | 命令行标志 -ext-ctl-tls：覆盖 HTTPS API 地址 | 有 |  |  | 未实现 | 未测 | 取值：`-ext-ctl-tls` |
| `ext-ctl-unix` | 命令行标志 -ext-ctl-unix：覆盖 Unix socket | 有 |  |  | 未实现 | 未测 | 取值：`-ext-ctl-unix` |
| `ext-ui` | 命令行标志 -ext-ui：覆盖面板目录 | 有 |  |  | 未实现 | 未测 | 取值：`-ext-ui` |
| `f` | 命令行标志 -f：配置文件；- 从标准输入读 | 有 |  |  | 部分 | 未测 | 取值：`-f` |
| `m` | 命令行标志 -m：geodata 模式 | 有 |  |  | 未实现 | 未测 | 取值：`-m` |
| `post-down` | 命令行标志 -post-down：退出前脚本 | 有 |  |  | 未实现 | 未测 | 取值：`-post-down` |
| `post-up` | 命令行标志 -post-up：启动后脚本 | 有 |  |  | 未实现 | 未测 | 取值：`-post-up` |
| `secret` | 命令行标志 -secret：覆盖 secret | 有 |  |  | 未实现 | 未测 | 取值：`-secret` |
| `t` | 命令行标志 -t：测试配置后退出 | 有 |  |  | 已实现 | 通过 | 取值：`-t` |
| `v` | 命令行标志 -v：显示版本 | 有 |  |  | 已实现 | 未测 | 取值：`-v` |

## format

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `format` | 格式化配置 |  | 有 |  | 已实现 | 未测 | 取值：`sing-box format` |
| `format-write` | format 的 --write：写回源文件 |  | 有 |  | 已实现 | 未测 | 取值：`--write`、`-w` |

## generate

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `generate` | 生成工具 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box generate` |
| `generate-ech-keypair` | 生成 ECH 密钥对 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box generate ech-keypair` |
| `generate-rand` | 生成随机字节 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box generate rand`<br>约束：参数 <length> |
| `generate-rand-base64` | generate rand 的 --base64：base64 输出 |  | 有 |  | 已实现 | 通过 | 取值：`--base64` |
| `generate-rand-hex` | generate rand 的 --hex：十六进制输出 |  | 有 |  | 已实现 | 通过 | 取值：`--hex` |
| `generate-reality-keypair` | 生成 REALITY 密钥对 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box generate reality-keypair` |
| `generate-tailcat-keypair` | 生成 Tailcat 密钥对 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box generate tailcat-keypair` |
| `generate-tls-keypair` | 生成 TLS 自签密钥对 |  | 有 |  | 部分 | 未测 | 取值：`sing-box generate tls-keypair` |
| `generate-tls-keypair-months` | generate tls-keypair 的 --months：有效月数 |  | 有 |  | 未实现 | 未测 | 取值：`--months`、`-m` |
| `generate-uuid` | 生成 UUID |  | 有 |  | 已实现 | 通过 | 取值：`sing-box generate uuid` |
| `generate-vapid-keypair` | 生成 VAPID 密钥对 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box generate vapid-keypair` |
| `generate-wg-keypair` | 生成 WireGuard 密钥对 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box generate wg-keypair` |

## geoip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `geoip` | GeoIP 工具 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geoip` |
| `geoip-export` | 导出国家为规则集 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geoip export` |
| `geoip-export-output` | geoip export 的 --output：输出路径 |  | 有 |  | 已实现 | 未测 | 取值：`--output`、`-o` |
| `geoip-file` | geoip 的 --file：geoip 文件，默认 geoip.db |  | 有 |  | 部分 | 未测 | 取值：`--file`、`-f` |
| `geoip-list` | 列出国家代码 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geoip list` |
| `geoip-lookup` | 查询 IP 是否在 GeoIP 库中 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geoip lookup` |

## geosite

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `geosite` | Geosite 工具 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geosite` |
| `geosite-export` | 导出分类为规则集 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geosite export` |
| `geosite-export-output` | geosite export 的 --output：输出路径 |  | 有 |  | 已实现 | 未测 | 取值：`--output`、`-o` |
| `geosite-file` | geosite 的 --file：geosite 文件，默认 geosite.db |  | 有 |  | 部分 | 未测 | 取值：`--file`、`-f` |
| `geosite-list` | 列出分类 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geosite list` |
| `geosite-lookup` | 查询域名是否在 Geosite 中 |  | 有 |  | 部分 | 未测 | 取值：`sing-box geosite lookup` |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `config` | 全局选项：配置文件路径，可重复，stdin 读标准输入 |  | 有 |  | 部分 | 未测 | 取值：`--config`、`-c` |
| `config-directory` | 全局选项：配置目录路径，可重复 |  | 有 |  | 未实现 | 未测 | 取值：`--config-directory`、`-C` |
| `directory` | 全局选项：工作目录 |  | 有 |  | 未实现 | 未测 | 取值：`--directory`、`-D` |
| `disable-color` | 全局选项：关闭彩色输出 |  | 有 |  | 未实现 | 未测 | 取值：`--disable-color` |

## merge

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `merge` | 合并配置 |  | 有 |  | 已实现 | 未测 | 取值：`sing-box merge` |

## netns-holder

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `netns-holder` | 内部隐藏命令：持有网络命名空间 |  | 有 |  | 不适用 | 未测 | 取值：`sing-box netns-holder` |

## rule-set

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `rule-set` | 规则集工具 |  | 有 |  | 部分 | 未测 | 取值：`sing-box rule-set` |
| `rule-set-compile` | 把规则集 JSON 编译为二进制 |  | 有 |  | 未实现 | 未测 | 取值：`sing-box rule-set compile` |
| `rule-set-compile-output` | rule-set compile 的 --output：输出文件 |  | 有 |  | 未实现 | 未测 | 取值：`--output`、`-o` |
| `rule-set-convert` | 把 AdGuard DNS 过滤器转为规则集 |  | 有 |  | 已实现 | 未测 | 取值：`sing-box rule-set convert` |
| `rule-set-convert-output` | rule-set convert 的 --output：输出文件 |  | 有 |  | 部分 | 未测 | 取值：`--output`、`-o` |
| `rule-set-convert-type` | rule-set convert 的 --type：源类型，可用 adguard |  | 有 |  | 已实现 | 未测 | 取值：`--type`、`-t` |
| `rule-set-decompile` | 把二进制规则集反编译为 JSON |  | 有 |  | 未实现 | 未测 | 取值：`sing-box rule-set decompile` |
| `rule-set-decompile-output` | rule-set decompile 的 --output：输出文件 |  | 有 |  | 未实现 | 未测 | 取值：`--output`、`-o` |
| `rule-set-format` | 格式化规则集 JSON |  | 有 |  | 已实现 | 未测 | 取值：`sing-box rule-set format` |
| `rule-set-format-write` | rule-set format 的 --write：写回源文件 |  | 有 |  | 已实现 | 未测 | 取值：`--write`、`-w` |
| `rule-set-match` | 检查 IP 或域名是否匹配规则集 |  | 有 |  | 已实现 | 未测 | 取值：`sing-box rule-set match` |
| `rule-set-match-format` | rule-set match 的 --format：规则集格式，默认 source |  | 有 |  | 已实现 | 未测 | 取值：`--format`、`-f` |
| `rule-set-merge` | 合并规则集源文件 |  | 有 |  | 已实现 | 未测 | 取值：`sing-box rule-set merge` |
| `rule-set-merge-config` | rule-set merge 的 --config：输入文件路径 |  | 有 |  | 已实现 | 未测 | 取值：`--config`、`-c` |
| `rule-set-merge-config-directory` | rule-set merge 的 --config-directory：输入目录路径 |  | 有 |  | 已实现 | 未测 | 取值：`--config-directory`、`-C` |
| `rule-set-upgrade` | 升级规则集 JSON |  | 有 |  | 部分 | 未测 | 取值：`sing-box rule-set upgrade` |
| `rule-set-upgrade-write` | rule-set upgrade 的 --write：写回源文件 |  | 有 |  | 部分 | 未测 | 取值：`--write`、`-w` |

## run

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `confdir` | 多配置目录 |  |  | 有 | 已实现 | 未测 |  |
| `config` | 配置源，可重复，别名 -c |  |  | 有 | 部分 | 未测 | 取值：`http+unix://`、`http://`、`https://`、`stdin:`、`本地路径`<br>约束：http+unix 为弃用前缀，改用 socket 路径（source:main/confloader/external/external.go）<br>约束：stdin 需关闭输入流<br>约束：未指定时查工作目录和资源路径的 config.json<br>约束：远程地址前缀须小写 |
| `dump` | 输出合并后配置 |  |  | 有 | 已实现 | 未测 |  |
| `format` | 配置格式，默认 auto |  |  | 有 | 已实现 | 未测 | 取值：`auto`、`json`、`protobuf`、`toml`、`yaml` |
| `http-unix` | -config 的 http+unix 前缀 |  |  | 废弃 | 不适用 | 未测 | 约束：改用 socket 路径，如 /path/socket.sock:/api |
| `run` | 运行服务 |  | 有 |  | 已实现 | 通过 | 取值：`sing-box run` |
| `test` | 只测试配置 |  |  | 有 | 已实现 | 通过 |  |

## schema

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `schema` | 生成配置 JSON Schema |  | 有 |  | 未实现 | 未测 | 取值：`sing-box schema` |
| `schema-output` | schema 的 --output：写入文件 |  | 有 |  | 未实现 | 未测 | 取值：`--output`、`-o` |

## tls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cert` | 生成 TLS 证书 |  |  | 有 | 部分 | 未测 | 取值：`--ca`、`--domain`、`--expire`、`--file`、`--json`、`--name`、`--org` |
| `cert-chain-hash` | tls hash 旧名 |  |  | 已移除 | 不适用 | 未测 | 约束：源码未注册，用 tls hash |
| `ech` | 生成 ECH 密钥和配置 |  |  | 有 | 未实现 | 未测 | 取值：`--pem`、`--serverName`、`-i`<br>约束：command.md 未列；docs/config/transports/tls.md 有说明 |
| `hash` | 计算证书 SHA256 |  |  | 有 | 已实现 | 通过 | 取值：`--cert`<br>约束：command.md 仍写旧名 certChainHash |
| `ping` | TLS 握手探测，输出证书 SHA256 和后量子支持 |  |  | 有 | 未实现 | 未测 | 取值：`-ip` |

## tools

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tools` | 实验性工具 |  | 实验 |  | 未实现 | 未测 | 取值：`sing-box tools` |
| `tools-connect` | 连接到地址 |  | 实验 |  | 未实现 | 未测 | 取值：`sing-box tools connect` |
| `tools-connect-network` | tools connect 的 --network：网络类型，默认 tcp |  | 实验 |  | 未实现 | 未测 | 取值：`--network`、`-n` |
| `tools-fetch` | 获取 URL |  | 实验 |  | 未实现 | 未测 | 取值：`sing-box tools fetch` |
| `tools-networkquality` | 网络质量测试 |  | 实验 |  | 未实现 | 未测 | 取值：`sing-box tools networkquality` |
| `tools-networkquality-config-url` | tools networkquality 的 --config-url：测试配置 URL |  | 实验 |  | 未实现 | 未测 | 取值：`--config-url` |
| `tools-networkquality-http3` | tools networkquality 的 --http3：用 HTTP/3 测量 |  | 实验 |  | 未实现 | 未测 | 取值：`--http3` |
| `tools-networkquality-max-runtime` | tools networkquality 的 --max-runtime：最大运行秒数 |  | 实验 |  | 未实现 | 未测 | 取值：`--max-runtime` |
| `tools-networkquality-serial` | tools networkquality 的 --serial：顺序执行上下行 |  | 实验 |  | 未实现 | 未测 | 取值：`--serial` |
| `tools-outbound` | tools 的 --outbound：使用指定出站标签 |  | 实验 |  | 未实现 | 未测 | 取值：`--outbound`、`-o` |
| `tools-stun` | STUN 测试 |  | 实验 |  | 未实现 | 未测 | 取值：`sing-box tools stun` |
| `tools-stun-server` | tools stun 的 --server：STUN 服务器地址 |  | 实验 |  | 未实现 | 未测 | 取值：`--server`、`-s` |
| `tools-synctime` | 用 NTP 同步时间 |  | 实验 |  | 未实现 | 未测 | 取值：`sing-box tools synctime` |
| `tools-synctime-format` | tools synctime 的 --format：输出格式 |  | 实验 |  | 未实现 | 未测 | 取值：`--format`、`-f` |
| `tools-synctime-server` | tools synctime 的 --server：NTP 服务器，默认 time.apple.com |  | 实验 |  | 未实现 | 未测 | 取值：`--server`、`-s` |
| `tools-synctime-write` | tools synctime 的 --write：写入系统时间 |  | 实验 |  | 未实现 | 未测 | 取值：`--write`、`-w` |

## version

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `version` | 打印版本 |  | 有 |  | 已实现 | 未测 | 取值：`sing-box version` |
| `version-name` | version 的 --name：只打印版本名 |  | 有 |  | 未实现 | 未测 | 取值：`--name`、`-n` |

## xray

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | CLI 组合 |  |  | 有 | 部分 | 未测 | command：`api`、`base64`、`convert`、`help`、`mldsa65`、`mlkem768`、`run`、`tls`、`uuid`、`version`、`vlessenc`、`wg`、`x25519`<br>config_source：`confdir`、`file`、`http(s)`、`multi-file`、`stdin:`、`unix socket`<br>format：`auto`、`json`、`protobuf`、`toml`、`yaml`<br>约束：Protobuf 只取第一个配置源 |
| `api` | 调用 gRPC API |  |  | 有 | 未实现 | 未测 |  |
| `base64` | Base64 编解码 |  |  | 有 | 未实现 | 未测 | 约束：文档未写 |
| `convert` | 配置转换 |  |  | 有 | 未实现 | 未测 |  |
| `ed25519` | Ed25519 密钥命令，当前未注册 |  |  | 已移除 | 不适用 | 未测 | 取值：`-i` |
| `help` | 显示可用命令 |  |  | 有 | 已实现 | 通过 | 取值：`xray help <command>` |
| `lua` | Lua 脚本签名命令，当前未注册 |  |  | 已移除 | 不适用 | 未测 | 取值：`lua sign [-key seed] [-o file] <input>` |
| `mldsa65` | 生成 ML-DSA-65 密钥对 |  |  | 有 | 未实现 | 未测 | 取值：`-i` |
| `mlkem768` | 生成 ML-KEM-768 密钥对 |  |  | 有 | 未实现 | 未测 | 取值：`-i` |
| `run` | 运行配置，默认命令 |  |  | 有 | 部分 | 通过 | 取值：`xray run [-c config.json] [-confdir dir]` |
| `tls` | TLS 工具 |  |  | 有 | 已实现 | 通过 |  |
| `uuid` | 生成 UUID |  |  | 有 | 已实现 | 通过 | 取值：`-i` |
| `version` | 输出版本 |  |  | 有 | 已实现 | 未测 |  |
| `vlessenc` | 生成 VLESS Encryption 配置对 |  |  | 有 | 未实现 | 未测 |  |
| `wg` | 生成 WireGuard 密钥对 |  |  | 有 | 已实现 | 通过 | 取值：`-i` |
| `x25519` | 生成 X25519 密钥对 |  |  | 有 | 已实现 | 通过 | 取值：`--std-encoding`、`-i` |
