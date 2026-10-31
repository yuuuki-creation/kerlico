# SSH 出站接口

日期：2026-10-31。状态：限定原生出站已通过 worker Rust、严格 Clippy 和独立 OpenSSH 340 项检查，精确来源与边界见测试记录。

`protocol-ssh` 注册 `ssh` 出站，使用原生 Rust SSH v2 direct-tcpip，不调用系统 ssh 命令承载业务。它提供 TCP 和写端 EOF/反向排空，不提供 SSH 服务端、UDP 或多目标数据报关联；同一内核的其他入站仍可经统一出口选择该出站。

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
