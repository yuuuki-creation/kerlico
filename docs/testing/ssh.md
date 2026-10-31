# SSH 出站验证记录

日期：2026-10-31。限定原生 SSH direct-tcpip 出站已在 perf-01 验证；没有登记 SSH 服务端、UDP、Shell 或 SFTP。

## 环境与来源

Linux x86_64、Rust/Cargo 1.99.1，构建并发 1。原语固定 russh 0.64.1，来源与注册表 checksum 见[研究](../../reference/research_notes/ssh.md)。没有本地 Rust 构建、格式检查或测试。

独立对端为项目隔离容器中的 OpenSSH_10.0p2 Debian-7+deb13u4、OpenSSL 3.5.7。镜像 ID 为 `sha256:6b4db2c6c566e91a922355e2f384ef8c2f9f5b9a59ade6dcd17c3163fd2d81ea`，运行使用固定 image ID；合成账户、密钥及回环监听均局限于本次测试。没有修改 worker 现有 SSH、账户、密码或服务，结束后查询本任务标签的运行容器数为 0。

| 对象 | SHA-256 |
| --- | --- |
| SSH 模块 6 文件清单 | `c354fadb0d01f1bd5bf05eee9e88f70587eed1d240aeadce2f4151798cc26754` |
| SSH-only CLI | `b85c3e3057e1265e3bf13e42f9fdb2bfb9ed34cc758d4efca17b13790dd7227b` |
| SSH+HTTP CLI | `b9859a7ca9784e34cbbb8c9d38cbbbbbf37c5b675c20fe89f39537e804993ad8` |
| worker 当时锁文件 | `3f6ba8b13040a30624677cb6b0baa959de962f2fbe5d5dd3cde1eb3181c388f2` |
| interop_ssh.py | `9a92d17c0380fa835ae149c557ef3567e7b8662603ba524c7beb33a6de0eb778` |

模块清单按相对路径逐文件 SHA-256，再对紧凑有序 JSON 映射计算摘要。该锁与二进制是本轮冻结输入，不等于后续并行工作树；原始结果、镜像信息及密钥仅存私有目录和 worker。

## Rust 与构建

完整首轮生产代码、接口、6 项集成和独立 OpenSSH 工具写齐后，统一 worker 执行：

```sh
cargo fmt -p kerlico-ssh
cargo test -p kerlico-ssh
cargo clippy -p kerlico-ssh --all-targets -- -D warnings
cargo build -p kerlico --no-default-features --features protocol-ssh
```

第二快照 6 项集成全部通过，覆盖密码、Ed25519/ECDSA P-256/P-384/P-521/RSA 私钥及带口令材料、代理/目标两地址族与域名、写端 EOF 后延迟回包、主机固定/轮换、错误身份、目标拒绝、建立超时/预取消、实际 TCP 连接回收、并发身份与文件权限。第三快照进一步复验未知主机不得收到密码、私钥失败不转密码，以及实际无占用的测试拒绝端口；对应目标测试、严格 Clippy 和 SSH+HTTP 构建通过。

首轮曾在 HostKey 类型导入失败，实际导出路径为 russh::keys::PublicKeyOrCertificate；核对注册表归档后修正，失败没有记作通过。模块输出只有 direct/reject/ssh 出站，没有 inbound/ssh。

## 独立 OpenSSH 正式 CLI

工具 `tools/interop_ssh.py`，在项目 root 工作区运行。两个独立阶段分别使用 SSH-only 与 SSH+HTTP CLI：

| 阶段 | 条件 | 结果 |
| --- | --- | --- |
| 原生 SSH | 2 类主机密钥 × 2 类代理地址族 × 5 种认证配置 | 140/140 检查通过 |
| 同进程 HTTP→SSH | 上述配置经独立 IPv4/IPv6 HTTP 节点与统一 Egress | 200/200 检查通过 |

主机密钥为 Ed25519、RSA；认证为密码、Ed25519、ECDSA P-256、RSA 3072、带口令 Ed25519。每组验证 IPv4/IPv6/域名目标、约 80 KiB 数据、半关闭后回包、错误用户名/主机指纹拒绝、四路并发与有界退出。HTTP 阶段每个节点凭据独立，SSH 载体和网站地址族不受入口地址族限制。

命令形式：

```sh
python3 tools/interop_ssh.py --kerlico <SSH-only CLI> --work-dir <新的私有结果目录>
python3 tools/interop_ssh.py --kerlico <SSH+HTTP CLI> --work-dir <另一个私有目录> --skip-image-build --via-http
```

工具记录固定镜像、创建容器索引与逐项结果，仅清理本任务容器。生产内核不调用系统 ssh、Docker 或参考服务承载业务。

## 边界

ECDSA P-384/P-521 的结果来自 Rust 自端，没有冒充独立 OpenSSH 实测。没有启用主机证书、SSH agent、GSSAPI、keyboard-interactive、远端命令/监听、UDP、其他 OS/架构或性能/安全审计。该模块通过不等于后续全工作区通过，公共流连接器和凭据域新增后仍按冻结整树另验。
