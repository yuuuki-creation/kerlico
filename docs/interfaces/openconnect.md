# OpenConnect 出站

`kerlico-openconnect` 注册出站类型 `openconnect`（Cargo feature `protocol-openconnect`），用原生 Rust 实现 AnyConnect 协议客户端，不启动 `openconnect` 进程。流量只走经 TLS 的 CSTP 隧道，没有 DTLS。对端以 `ocserv` 1.1.6 验证，复现命令见文末。

```json
{
  "tag": "vpn",
  "type": "openconnect",
  "options": {
    "server": { "host": "vpn.example.com", "port": 443 },
    "username": "synthetic-user",
    "password": "synthetic-password",
    "tls": { "server_name": "vpn.example.com", "ca_pem": "可选的 PEM" },
    "mtu": 1406
  }
}
```

| 字段 | 约束说明 |
| --- | --- |
| `server` | 必填。网关地址，域名由操作系统解析 |
| `username`、`password` | 必填。1 至 255 字节，不含控制字符 |
| `tls.server_name` | 校验证书和 SNI 使用的名称，默认取 `server.host` |
| `tls.ca_pem` | 追加到内置公共根证书的 PEM。证书校验不可关闭，没有证书指纹固定选项 |
| `mtu` | 1280 至 9000，默认 1406。写入 `X-CSTP-Base-MTU` 和 `X-CSTP-MTU` 请求头，实际值以服务端返回为准 |

未知字段拒绝。

## 建立流程

1. 建立 TLS，向 `/` 发送 `config-auth type="init"`。
2. 按服务端表单逐轮提交 `username` 和 `password`。`ocserv` 分两轮索取，同一轮索取也可以。隐藏字段原样回传。
3. 从 `Set-Cookie` 取 `webvpn`，另开一条 TLS 连接发起 `CONNECT /CSCOSSLC/tunnel`。
4. 从响应头取 `X-CSTP-Address`、`X-CSTP-Address-IP6`、`X-CSTP-MTU`、`X-CSTP-Keepalive`、`X-CSTP-DPD`。服务端返回的 MTU 低于 1280 时建立失败，因为 IP 数据面不支持。
5. 分配的地址交给 `kerlico_wireguard::ip::ClientTunnel`，由它提供用户态 TCP 和 UDP。

## 运行行为

- **目标策略**：`TargetPolicy::Local`。网站域名由共享调度器在本机解析后以 IP 进入隧道，服务端推送的 `X-CSTP-DNS` 不使用。
- **地址族**：只有服务端分配了对应地址族才能访问该族目标，否则连接被拒绝。
- **路由**：不应用 `X-CSTP-Split-Include` 和 `X-CSTP-Split-Exclude`。选路交给 kerlico 路由规则，服务端推送的路由之外能否到达由服务端决定。
- **会话**：按 `ResourceKey` 懒建立，每个来源用户独占一条隧道和一个隧道地址。同一账号被多个来源使用时受服务端 `max-same-clients` 限制。
- **保活**：发送静默达到 `X-CSTP-Keepalive` 秒时发 keepalive。接收静默达到 `X-CSTP-DPD` 秒时发 DPD 请求，未答复时每半周期重发，接收静默达到两个周期判定对端死亡。收到 DPD 请求时立即回复。
- **结束**：对端断开、DPD 死亡或传输错误会结束该隧道，隧道内现有流随之结束，下一条流重新认证并建立新隧道。不做断线续传。没有活动流满 300 秒时主动断开。主动断开前发送 CSTP 断开帧，服务端可立即释放会话。
- **口令错误**：认证被拒后该来源 60 秒内不再向服务端重试，直接返回拒绝。`ocserv` 会按错误口令累计封禁分，这一限速防止流量驱动的重试封禁本机地址。
- **载体计量**：登记 CSTP 帧字节，不含 TLS 记录开销和认证阶段的 HTTP。

## 未实现

- DTLS。全部流量经 TLS over TCP，隧道内 TCP 叠加外层 TCP，丢包时性能低于 DTLS。
- 客户端证书认证、SAML 和其他单点登录。
- 动态口令等额外认证字段：服务端索取时建立失败并返回明确错误，不猜测。
- 服务端角色。
- 用户组选择（`group_list`）：不提交，由服务端使用默认组。
- URL 路径形式的组入口：认证固定从 `/` 开始，不跟随 HTTP 重定向。
- CSTP 压缩：请求中不声明，收到压缩帧视为协议错误。
- 认证响应只接受 `Content-Length` 定界，分块编码返回明确错误。
- TLS 1.2 重协商：rustls 不支持。TLS 1.3 的 KeyUpdate 由 rustls 处理。`X-CSTP-Rekey-Method: new-tunnel` 不主动换隧道。
- Cisco ASA 只按协议文档兼容，未对真实设备验证；`<opaque>` 字段不回传。

## 验证

```sh
cargo build --locked -p kerlico
cd tools && python3 interop_openconnect.py --kerlico <kerlico 路径>
```

脚本在容器内运行发行版的 `ocserv`，证书和账号都是临时生成的合成材料。流量路径是 SOCKS5、kerlico、TLS/CSTP、ocserv、tun、容器内 NAT，最后到 Docker 网关上的回显服务。回显服务记录的来源必须是 ocserv 容器地址。

脚本依次检查 1 MiB TCP 半关闭往返、1000 字节和分片的 4000 字节 UDP 往返、错误口令被拒、闲置 60 秒后仍是同一次登录、暂停容器后判定死亡并重新登录、退出时 ocserv 记录 `received BYE packet`。`dpd = 5` 时，不发任何帧的客户端约 50 秒被 ocserv 以 `DPD timeout` 断开，所以闲置检查能区分保活是否生效。

另做过一次性检查，未放入脚本：经分配的 IPv6 地址到 ocserv 隧道接口地址的 64 KiB TCP 往返通过；`rekey-time = 8`、`rekey-method = ssl` 且协商 TLS 1.3 时，隧道运行 25 秒保持同一次登录且流量正常。
