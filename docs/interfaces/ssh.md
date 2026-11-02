# SSH 出站接口

`protocol-ssh` 注册 `ssh` 出站（研究见 [ssh.md](../../reference/research_notes/ssh.md)，验证记录见 [ssh.md](../testing/ssh.md)），使用原生 Rust SSH v2 `direct-tcpip`（提供 TCP 与写端 EOF / 反向排空，不提供 SSH 服务端或 UDP）。

- **任务所有权与 russh actor 回收**：每次目标连接独占一个 SSH 连接和 `direct-tcpip` 通道。命名服务登记完整建立驱动，并通过固定 `russh-util 0.52.0` 的作用域适配（见 [PATCHES.md](../../crates/protocol-ssh/vendor/russh-util/PATCHES.md)）直接登记 `russh 0.64.1` 内部 actor。建立超时或请求取消先通知 Transport，再等待 KEX future 或已取得的 `Handle`；服务 `shutdown` 停止登记、取消全部所属连接并等待已登记任务与内部 actor 回收。

```json
{
  "server": {"host": "ssh-node.invalid", "port": 22},
  "username": "proxy-test",
  "host_key_sha256": ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
  "auth": {"type": "password", "password": "synthetic-password"},
  "keepalive_interval_ms": 30000,
  "keepalive_max": 3
}
```

示例指纹只是占位值，实际必须填经可信途径取得的服务器 SHA256 指纹。数组必填，1–16 项且不能重复；不做自动接受或 TOFU，不读取用户的 known_hosts、SSH agent、环境用户名或默认私钥。主机证书不在本轮范围内。

`auth.type` 只接受 password 或 publickey。后者分别选择 `private_key_pem` 或 `private_key_file`，可带 `passphrase`；二者互斥，单份材料最多 1 MiB，Unix 文件不能有组/其他用户访问权限。固定依赖接受的 Ed25519、ECDSA、RSA 私钥可用于本轮显式认证；不接受空密码、其他认证类型或未知字段。账号至多 255 字节且不能含控制字符。错误不回显凭据、文件路径或远端说明。

SSH 主机签名不协商 RSA SHA-1，RSA 用户认证要求对端支持 SHA-2；不启用 DSA、3DES 或压缩。具体算法与固定原语依据见[研究](../../reference/research_notes/ssh.md)，实际验过的类型以[测试](../testing/ssh.md)为准。

每次目标建立使用独立 SSH 连接与一个通道，没有跨节点认证池。拨号、密钥交换、鉴权和通道确认共用一次 ConnectContext 预算；通道成功只确认 SSH 对端接受请求，不证明目标应用握手完成。originator 字段使用未指定地址与零端口，不伪造不可获得的本地应用来源。连接窗口 256 KiB、单包 32 KiB、通道队列 32 条；keepalive 间隔为 1000–3600000 毫秒、最大连续无回复次数 1–8。

写端 shutdown 发送通道 EOF，继续读取反向数据；完整流丢弃、取消、错误或建立超时通过底层 TCP 取消包装回收实际连接。运行需要 Tokio，空闲预算由 engine/调用方管理。没有远端命令执行、PTY、SFTP、远端监听、自动凭据回退或透明重放。

## 连接结果元数据

`Outbound::connect_tcp` 返回 `OpenedTcp { stream, info }`。本协议没有可证实的业务目标绑定字段，`info` 明确为 `TcpConnectInfo::unknown()`，不使用 SSH 或 SMUX 载体地址代填。Dispatcher 返回业务层 typed flow 并负责唯一计量；本模块不创建第二份完成权或账本。底层固定 UDP 接口及原有未支持能力保持准确边界。
