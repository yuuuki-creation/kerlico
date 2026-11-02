# 配置v2迁移

本轮源码只接受v2。迁移代码尚未完成整树验证，不能把下面示例当成已通过的发行配置。历史v1文件可作为证据保留，运行前须显式转换。

最小配置见[config-v2-minimal.json](../examples/config-v2-minimal.json)。它使用Local固定转发，不需要管理账户；监听端口由系统分配，目标是独立启动的回环18080服务。该示例只展示配置结构，尚未执行迁移树check或运行验证。

1. 将version改为2。保留命名outbounds；多个节点引用同一tag会使用同一个运行实例。
2. 使用account-new从标准输入建立一次管理账户，将输出存入accounts。保持user_id稳定，用户名默认带同一个UUID后缀。
3. 将入站协议的用户秘密从options移入members[].native_credential，并填写对应管理user_id。协议载体、证书、混淆保护和限制继续留在options。
4. IPv4和IPv6监听节点分别声明成员及独立协议秘密；相同管理账户只有被各节点明确列入members才取得对应授权。
5. 按本节点负责的目标路径设置mode。可选ipv4-only、ipv6-only、dual-stack。远端代理路径不据此本地解析网站。
6. 用check纯校验，再在项目独立worker目录完成各角色和组合的运行验证。check不部署WARP或改变系统网络。

| 入站 | native_credential形状 |
| --- | --- |
| VLESS | {"uuid":"协议UUID","flow":"可选原生flow"} |
| VMess | {"uuid":"协议UUID"} |
| Trojan、AnyTLS | {"password":"协议密码"} |
| SOCKS、HTTP、ShadowQUIC、Mieru、Naive、TrustTunnel | {"username":"原生用户名","password":"协议密码"} |
| Shadowsocks AEAD | {"password":"协议密码"}，method留在options |
| SS2022 | {"key":"终端key"}，AES EIH的外层身份写options.identity_key |
| Snell | {"psk":"原生PSK","userkey":"可选v6用户key"} |
| TUIC | v4为{"token":"原生token"}，v5为{"uuid":"协议UUID","password":"协议密码"} |
| Hysteria1 | {"auth_str":"文本"}或{"auth":"原生编码材料"}，两者互斥 |
| Hysteria2 | {"auth":"原生认证材料"} |
| SSR | {"password":"基础密码","user":{"id":1,"password":"可选UID密码"}} |
| Sudoku | {"key":"原生key"} |
| ShadowTLS | 使用所选inner协议的形状；外层password/users只属于Protection |

SSH及Gost Relay当前仅出站，它们的远端用户名、密码或key继续归各命名outbound.options，不从入站账户取值。

无真实鉴别的旧stream/none及明确不安全的Local组合不生成管理用户。它们只能在工厂允许的local_inbounds保留必要编码材料。不得为通过v2而给无鉴别组合添加一个占位member。

管理password_hash为Argon2id PHC摘要，不能填写明文或直接复制协议密码。配置中的真实协议秘密应按私有部署资料管理，不进入可提交示例。代码里的测试账户只用于合成夹具。

本轮运行统计有唯一业务计量和有限内存记录。SQLite保存、带宽历史、保留策略和持久查询仍未实现；WARP自动补族也未交付。v2迁移不代表这些发行条件已经满足。


XDRIVE存储载体不再隐式读取HTTP_PROXY、HTTPS_PROXY或NO_PROXY。它只连接明确配置的存储URL，不自动经过环境代理，也不新增代理链。此项是本轮明确接受的配置行为变化。旧固定reqwest依赖图没有HTTP/2，受控HTTP/1实现保留原实际路径；URL/query、模板头、JSON/XML、OAuth与请求期限仍分别验证，不能据代码编写宣称完全兼容。
