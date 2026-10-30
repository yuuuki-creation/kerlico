# 项目状态

更新日期：2026-10-31，Asia/Shanghai。

当前阶段：**按用户要求记录并推送开发快照，结束本轮工作。** VLESS 扩展、AnyTLS、SS2022 和双端框架的代码已保存；本提交不是完整验收的发行版。已通过结果属于下表指定的远端快照，最新节点生命周期和 HTTP 升级处理增量尚未复验。

仓库：[yuuuki-creation/kerlico](https://github.com/yuuuki-creation/kerlico)。资料与提交说明使用简体中文；作者、提交者固定为 `Anonymous <anonymous@example.invalid>`，不签名、不添加身份 trailer。凭证、原始日志和产物留在被忽略的 `.private/` 或专用 worker，不能进入 Git。

## 已确认的约束

- Rust 源码按功能和协议拆分，最终同一个可执行程序按配置承担客户端、服务端或两者。
- IPv4、IPv6 服务端节点分别创建，认证凭据独立；同协议跨节点重复凭据在配置阶段拒绝。各协议通过统一 `AccessService` 访问网站目标，由 `egress` 默认优先 IPv4；节点、代理载体和网站的地址族互不绑定。
- 协议流程固定为“调研 → 编写 → 测试 → 修改”，第一次一次写完本轮完整范围，再集中测试与修改。
- 所有新增内容和对话遵循格莱斯准则。编译、格式、静态检查和测试只在专用 worker 执行，本地只编辑、阅读、同步和管理 Git。
- 用户本轮明确安排两个子代理分别处理 AnyTLS、SS2022，主任务继续 VLESS；随后明确要求先记录、推送并结束。

## 已实现与验证范围

| 项目 | 已有结果 | 证据入口 |
| --- | --- | --- |
| 双端框架、独立节点与统一出口 | 同进程三协议、六节点、两类网站目标、凭据隔离、并发、退出与同端口重启，共 35 项联合检查通过 | [节点与访问接口](docs/interfaces/node-egress.md)、[快照记录](docs/testing/vless-combinations.md) |
| AnyTLS | 原生 Rust TLS 双端、会话复用、padding、TCP/UoT v2；19 项 CLI 集成通过；停写回包修正后包级、回归及真实对端合计 11 项测试通过 | [接口](docs/interfaces/anytls.md)、[测试](docs/testing/anytls.md) |
| SS2022 | 三算法双端 TCP/原生 UDP，AES 终端 EIH 多用户及客户端身份链；8 项 Rust 测试、88 项限定互通及 17 组 CLI 集成通过 | [接口](docs/interfaces/ss2022.md)、[测试](docs/testing/ss2022.md) |
| VLESS 普通及扩展组合 | RAW/WS/HTTPUpgrade/gRPC/XHTTP、TLS/REALITY、Vision、Encryption 等基础完整矩阵，客户端与服务端各 394/394 配置通过 | [接口](docs/interfaces/vless.md)、[快照记录](docs/testing/vless-combinations.md) |
| VLESS ML-KEM | TCP 测试矩阵双向各 44/44 配置通过；其中包含未加密基线，不能把 44 项全部称作 ML-KEM 加密场景 | 同上 |
| Vision 记录边界 | 按帧边界读取的独立回归通过，真实 REALITY+Vision 重复测试 30/30 通过 | 同上 |
| XHTTP 上下行分离 | 独立 CA/SNI、IPv4 上传与 IPv6 下载、H1/H2/H3 组合及错误证书/名称共 10/10 场景通过；含 H3 的场景为自端互通 | 同上 |
| XDRIVE | local、HTTP template、S3 模拟服务的双向互通共 6/6 场景通过；没有使用真实云账户 | 同上 |
| packetaddr | 固定 sing-box 双向、两种节点地址族、两类目标及 17/4096/12000 字节，共 4/4 场景通过 | 同上 |
| 构建与检查 | 早期完整工作区 49 项默认 Rust 测试通过；后续 VLESS 包级最新快照 27 项通过，格式、Clippy 和构建通过；另有早期 release 构建成功 | 同上，结果不外推到最新未验证增量 |

## 当前停点与未完成项

1. **最新增量未编译或测试**：`crates/engine/src/lib.rs` 的节点 TCP/UDP 共享取消域、`crates/engine/tests/framework.rs` 的兄弟入口排空回归，以及 `crates/protocol-vless/src/server_http.rs` 的升级会话跟踪、载体空闲时限和 WS 缓冲限制。后续必须先复核这些修改，再全量远端检查；不要把旧快照的通过结果当作当前整树通过。
2. Mux 额外矩阵曾为 29/30，失败发生在 TCP+none 的四路并发。随后修正了并发建连接竞态、关闭时反向数据排空和 UDP 元数据，新增回归在 `r14` 包级快照通过；**完整 30 项额外互通尚未复跑**。
3. 工具已增加 `hybrid` 密钥选项，但混合 NFS 链尚未运行对应互通。ML-DSA 验签、真实 Google Drive/S3 账户、槽环完整互通和长期压力也未完成验收。
4. XUDP 服务端尚无跨物理载体迁移的全局 UDP 会话表。mKCP、反向代理控制面、SOCKS/HTTP 代理入口、TUN/Fake-IP、规则语言、热重载和项目整体许可证不属于本次已验证交付。
5. 当前构建基线为 **Rust 1.99.1、Linux x86_64**。隔离 1.96 容器实际被固定 `rust-reality` 及 `rr-*` 包的 1.99 要求拒绝。旧版 macOS/Rust 1.88 结果仅适用于已发布 0.1。

## 后续继续的顺序

用户重新要求继续后，先读取 `AGENTS.md`、本文和[快照记录](docs/testing/vless-combinations.md)：

1. 在 worker 同步当前源码，完成格式、完整工作区编译/测试、Clippy，集中修正最新生命周期增量。
2. 复跑 Mux 额外矩阵、升级连接的活动排空及 TCP/H3 共用节点回归；再按需要补齐未验证的密码与存储分支。
3. 固定最终源码、锁文件和二进制摘要，完成最终构建裁剪/发行验证，再登记验收完成。本轮只保存快照，不继续自动开发。

## 资料导航

[设计导航](docs/README.md) · [接口](docs/interfaces/README.md) · [协议与组合唯一总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
