# Shadowsocks AEAD、基础与旧式流密码调研

日期：2026-10-31。状态：调研完成，首轮范围确定；实现与验收结果另记。

## 本轮完整范围

对应总表 P-03、P-05：双端原生 TCP 与 UDP，固定目标出站、单密码节点、独立节点身份、统一 `AccessService` 目标访问、取消/超时/半关闭、UDP 限额与重放检测。覆盖固定依赖 `shadowsocks 1.25.0` 与 `shadowsocks-crypto 0.8.0` 的 10 个 AEAD、34 个旧式流方法和 none；旧式流方法及 none 必须显式设置 `allow_insecure=true`。此范围不把 SS2022、SSR、SIP003 插件、UoT 和通用 mux 混入普通 SS。SS2022 使用现有独立模块；SSR 的 protocol/obfs 仍须另行实现。

10 个 AEAD：aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、aes-128/256-ccm、aes-128/256-gcm-siv、xchacha20-ietf-poly1305、sm4-gcm、sm4-ccm。固定库没有 aes-192-gcm，不通过名称猜测补齐。

34 个流方法：AES 与 Camellia 各有 128/192/256 位的 ctr、cfb1、cfb8、cfb128、ofb（各 15）；再加 chacha20-ietf、rc4-md5、rc4、table。cfb 名称接受库提供的 cfb128 别名。none/plain 等价，不提供认证或加密，节点限制回环。

## 规范、源码与依赖

- [官方 AEAD 规范](https://shadowsocks.org/doc/aead.html)：SIP004/SIP007 的分块 TCP 与独立 UDP 盐；TCP 每方向独立状态，UDP 每包独立状态。
- [固定 crate 功能](https://docs.rs/crate/shadowsocks/1.25.0/features)：启用 `aead-cipher`、`aead-cipher-extra`、`stream-cipher`、`security-replay-attack-detect`；关闭默认 DNS 等功能。密码派生、加密与帧处理委托固定库。
- 固定源码 `shadowsocks-crypto 0.8.0/src/kind.rs` 是方法白名单及别名依据；`shadowsocks 1.25.0/src/relay/tcprelay/proxy_stream/{client,server}.rs` 是首部与半关闭适配依据。
- 固定源码 `shadowsocks 1.25.0/src/relay/udprelay/{crypto_io,aead,stream}.rs` 表明普通 SS 返回的 control 为 None，不能套用 SS2022 session/packet ID；AEAD 和 stream UDP 解码中的重放检查被注释，因此适配层在成功解码后自行检查 salt/IV。
- TCP 需设置 `ReplayAttackPolicy::Reject`；仅启用 feature 而沿用 Default 策略不能拒绝旧协议重放。TCP 上游 Bloom 可能有误判，并按容量轮换；UDP 采用有界、到期清理缓存，满额时拒绝新盐而不提前淘汰旧盐。
- 两个直接相关 crate 均声明 MIT；AWS-LC 后端属于传递依赖，已有 SS2022 使用同一后端。最终发行的整体许可证与全部传递依赖清单仍由集成阶段确认，不能据此宣称项目已有完整许可证审计。

## 安全与组合边界

普通 SS 密码按上游传统 KDF 派生，配置字段为 password，不能与 SS2022 Base64 key 混用。节点指纹分别覆盖密码和派生后的实际 key，拒绝同密码跨方法复用及同 key 的跨节点凭据复用。旧式流密码不认证报文，重放缓存不能补足其认证能力；rc4/table 没有每包 IV，无法建立有效 nonce 重放保护；none 没有身份语义。

插件、TLS/REALITY、WS/gRPC/XHTTP 不属于 cipher。总表观察的插件路径不是任意流包装承诺，本轮未知字段直接拒绝。每方法 TCP/UDP、自端双端及独立上游对端结果分别登记；无法找到支持某扩展方法的对端时保留该项未验证，不能从其他方法成功外推。

## 验收矩阵

1. 全部方法配置、默认拒绝旧式/none、未知字段/2022 方法/空密码/超长密码拒绝。
2. 全方法 TCP：域名/IPv4/IPv6 编码、目标先发数据、大数据跨块、双向写端 EOF。
3. 全方法 UDP：零长度/边界包、双向独立盐、畸形与错误密码、重放、不同来源与多目标隔离。
4. 节点 IPv4/IPv6 独立密码、统一出口、限额、空闲回收、取消及关闭。
5. 固定参考对端分角色/方法互通，记录具体可运行方法；扩展方法不得借用基线结果。
