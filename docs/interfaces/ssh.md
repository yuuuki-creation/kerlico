# SSH 出站接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。

本轮补齐 SSH 任务所有权，源码与回归已编写，尚未构建或执行。每次目标连接仍独占一个 SSH 连接和 direct-tcpip 通道。命名服务登记完整建立驱动，也通过固定 `russh-util 0.52.0` 的作用域适配直接登记 `russh 0.64.1` 内部 actor。供应来源、许可及最小补丁见[供应记录](../../crates/protocol-ssh/vendor/russh-util/PATCHES.md)。

建立超时或请求取消先通知 Transport，然后继续等待 KEX future 或已取得的 `Handle`。握手、鉴权失败和通道拒绝都保留实际 actor 的等待路径。业务流仅持通道和独立取消租约，释放一个流不取消其他连接。服务关闭停止登记、取消全部所属连接并等待已登记任务；Engine 的最终截止时间和强制回收仍由真实 `ServiceContext` 管理。外层驱动被强制中止时，内部 actor 继续在同一服务集合内等待回收，不能只凭外层 future 结束登记清理成功。


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

## 连接结果元数据

本轮返回类型迁移已编写，尚未运行新输入。`Outbound::connect_tcp` 返回 `OpenedTcp { stream, info }`。本协议没有可证实的业务目标绑定字段，`info` 明确为 `TcpConnectInfo::unknown()`，不使用 SSH 或 SMUX 载体地址代填。Dispatcher 返回业务层 typed flow 并负责唯一计量；本模块不创建第二份完成权或账本。底层固定 UDP 接口及原有未支持能力保持准确边界。
