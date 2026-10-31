# SSH 出站实现研究

日期：2026-10-31。对应协议总表 P-20。状态：详细研究完成，确定本轮范围；尚未构建或验证 SSH 模块。

## 固定证据与依赖

总表固定 mihomo/sing-box 的 SSH 路径仅为 TCP 出站，不据此登记 SSH 服务端或原生 UDP。线协议依据 [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252)、[RFC 4254](https://www.rfc-editor.org/rfc/rfc4254) 的用户鉴权与 direct-tcpip；固定参考实现为独立 OpenSSH 测试容器，版本、镜像和二进制摘要在实际 worker 验证时记录。

选择原生 Rust `russh = 0.64.1`，Apache-2.0，声明 Rust 1.89；官方源码标签固定为 [e5d80a07dc554480b6ea3b2e14adfc190407b627](https://github.com/warp-tech/russh/tree/e5d80a07dc554480b6ea3b2e14adfc190407b627)，注册表 checksum 为 `ba61e87b9ec9a39a59a6bbed4c0b8ff7fb07073405b24a767a1f2c8560ac8f58`。只启用 ring/rsa，不启用压缩、DSA 或 3DES。握手默认算法按固定源码复核，另外排除 RSA SHA-1 主机签名；RSA 用户认证只接受对端支持的 SHA-2 签名。现有 ML-KEM 旧版补丁只匹配 0.2.3，依赖另用注册表 0.3 系列，不改写或替换 VLESS 原语。

本版本 `check_server_key` 参数是 PublicKeyOrCertificate，不能套用缓存旧版文档中的签名。使用必填的 OpenSSH SHA256 主机指纹列表；不做 TOFU、自动接受、SSH agent、环境用户名或认证降级，主机证书另列未提供。

## 完整首轮范围

- SSH v2 direct-tcpip 原生出站，TCP、IPv4/IPv6/域名目标；同一程序仍由其他接入协议解码后经统一 Egress 调用，不增加 SSH 登录或命令执行入口。
- 密码与私钥两种显式认证；OpenSSH/PKCS8 内存或文件私钥，可带解密口令；支持固定依赖接受的 Ed25519、ECDSA、RSA，角色与算法分别验收。
- 主机指纹固定、轮换列表、拒绝未知主机；私钥文件大小和 Unix 权限检查；错误不回显账号、密码、密钥或路径。
- 每次目标建立独立 SSH 连接与一个通道，不共享认证池。建立预算覆盖拨号、密钥交换、鉴权和通道确认；写端 EOF 不关闭反向读取。
- RAII 取消令牌驱动底层 TCP 读写：超时、错误、取消或完整流丢弃都会关闭实际 SSH 连接。不能仅依赖 Handle::drop，因为固定依赖的后台任务不会在该 Drop 中直接 abort。
- 窗口、包与队列固定有界；keepalive 可配置。通道 originator 为未指定地址/端口，不伪造本模块拿不到的本地应用来源。

不提供 SSH 服务端、Shell/SFTP/PTY、远端监听、SSH agent、GSSAPI、keyboard-interactive、主机证书、UDP 或多目标数据报关联；未知配置直接拒绝。它们不是无效开关或待用户猜测的兼容模式。

## 验收

先一次写齐生产代码、接口、Rust 测试与 OpenSSH 工具，再在 worker 统一执行格式、包级测试、Clippy 和正式 CLI。覆盖两种代理地址族、两种网站地址族和域名、密码与各类私钥、正确/错误/轮换主机指纹、错误身份/私钥解密口令、目标拒绝、建立超时/预取消、半关闭后延迟回包、并发身份隔离、完整连接回收，以及仅启用 SSH 的模块集合。真实 OpenSSH 使用项目隔离容器、合成用户/密钥、回环监听；不改 worker 现有 SSH、用户、密码或系统配置。
