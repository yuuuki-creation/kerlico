# Gost Relay 出站实现前调研

日期：2026-10-31。状态：下列限定范围已完成原生实现与worker验证，见[测试](../../docs/testing/gost-relay.md)；其他命令、角色、载体和对端边界保持未交付。

## 固定证据与角色

总表 P-19 的三个参考核心中，仅 Mihomo 提供 `gost-relay` 出站。固定 [Mihomo 传输](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/gost/relay.go)与其 adapter 分别检查；不是策略组 relay、VLESS Mux 或任意 Go-GOST 插件的别名。独立官方对端选 [GOST v3.3.2](https://github.com/go-gost/gost/tree/7dca9e67cb34561d49ea0926fe3d609d23b4fd8c)，其依赖为 go-gost/x v0.27.2、relay v0.7.0、xtaci/smux v1.5.57。

实现后再次从上述固定提交raw来源取回两文件，与本地只读缓存逐字节相等：adapter/outbound/gost_relay.go SHA256为 `a8bbc7e60daa134d5e5d85abbb413ea359dd89f13a8a66ffdc108ee30b4d0b86`；transport/gost/relay.go为 `658bc874acff0e273cb33e777c387df89246df3d5837d9cb34b9efb4aa1b4101`。缓存是源码归档，不依赖在无.git子目录执行git rev-parse所得父仓库提交来证明上游版本。

Mihomo 的 SMUX 固定 metacubex/smux `d0c8756d3141ce2c9aa1046df6a93985441c6033`。源码默认线协议版本 1，禁 keepalive，每次 dial 新建物理会话并打开一个流；没有跨网站复用池。kerlico 本轮完整实现该模式，不把一个流称为已交付多流复用池。单次 open 的首个实际 ID 为 3。官方 GOST v3.3.2 linux_amd64 归档在官方 checksums.txt 登记 SHA256 `162feb43b1c284dbea599cdfe898169931af875233060dedc19432c7a9d18274`；worker 必须先核验归档再提取独立二进制并记录其摘要，不以版本字符串替代来源检查。

GOST 的 [官方说明](https://latest.gost.run/en/tutorials/protocols/relay/)指出 Relay 本身无加密，支持代理、固定转发和其他控制命令；本轮按 P-19 交付出站 CONNECT 的 TCP/UDP、原始 TCP/TLS、SMUX v1 开关与固定转发，不引入原生 Relay 入站、BIND/远程监听、ASSOCIATE 控制面、Unix/串口、其他物理载体或 SMUX v2。它们没有被参考核心此出站范围证明。官方 x 固定为 `6aa2c632fa16d3d3401d4d29f5eb53c18b51d27d`、relay 固定为 `d3237303308bbf9f9d4ae1fb789428a53d04f105`；后者与调研时 master 相同。官方 MTCP 默认 SMUX v2，MTLS 经公共转换器默认 v1；本轮对端均明确字符串 `mux.version="1"`。固定 GetInt 不接受 JSON 解码的 float64，数字1会被忽略，不能仅检查配置文本就声称实际使用v1。

## 线格式与目标语义

- 请求为 `01 || CMD/FLAGS || u16BE(features长度) || features`。CONNECT 为 1；UDP 同时设置 0x80，并发送 network feature 4 的 `0001`，TCP 为 `0000`。
- 每 feature 为 `type:u8 || len:u16BE || body`。认证 type1 为 `ulen:u8 || user || plen:u8 || pass`；两个字段各最多255字节，用户名或密码非空即发送。地址 type2 为 SOCKS 风格 IPv4/IPv6/长度域名和 u16BE 端口。
- 响应同样四字节首部，版本1、status0成功、u16BE扩展长度。状态1–8按原值映射拒绝、超时、不可达或协议错误；完整读取有界扩展，未知feature只按长度跳过，已知地址/认证/network严格验证长度，不能误吞随后业务数据。
- UDP 是固定目标的 TCP 流内 `u16BE长度 || payload`，无逐包来源地址，零长度为合法包。协议线字段最大65535，普通 IP UDP目标本轮统一限制65507并整包拒绝超长，不截断或重放。它不提供 Full Cone；`supports_udp_association=false`，不旁路直连。
- `forward_target` 显式配置已知的 IP 字面固定目标，只有实际请求目标与该地址/端口完全相等才省略地址feature；不忽略网站Destination，也不把代理端点当网站。上层 Egress 解析域名后的字面目标仍必须匹配。未匹配在连接前拒绝，不回退其他目标。

SMUX v1 首部为 `version:u8,command:u8,length:u16LE,stream:u32LE`，SYN0、FIN1、PSH2、NOP3。每个出站拨号持有专属物理连接与流3；严格解析碎片、命令、ID与长度，FIN前数据排空。发送帧最多32768字节，接收最多65535字节，待写队列最多一帧；无后台读写任务或空闲全局池。SMUX的完整关闭不对外承诺半关闭，只有原始无TLS路径声明 `tcp_eof=true`。

## Rust 选择与资源

沿用 Tokio、serde 和已有 TcpConnector 的严格证书验证，不安装 Go 业务内核，不新增全局TLS/QUIC patch。Relay和单流 SMUX v1 原生实现，无新增第三方Rust依赖。查阅 tokilake-smux 0.1.1 注册表归档（checksum `2ae1438643b72dc9622afcca652f42f8880a57ee55d894a41414fea986629349`，MIT）后没有直接采用：其独立读写任务无句柄，close只设置标志，阻塞读未被取消；接收路径还会持流表锁等待满通道，控制帧与数据分队列有顺序风险。本项目不以名称匹配替代生命周期审核。

明文远端必须显式 `allow_insecure=true`；只有实际字面回环代理允许默认明文。域名即便为localhost也不视为字面回环。用户名/密码不打印，不由用户名推导节点身份；本轮只有出站，没有可伪造认证指纹的节点工厂。TLS使用显式server_name及可选ca_pem，不提供跳过证书或伪装指纹选项。

默认 `response_mode=eager` 与参考出站相同，在返回流前等待完整成功响应，配合官方节点 `nodelay=true`。官方默认 `nodelay=false` 会把成功响应与首个业务回包合并；双方都先等响应会死锁。因此另提供 `deferred`，允许先发送首个业务，读方向先按同一建立总期限校验响应再暴露业务；该模式返回流不代表鉴权已确认，错误状态在首次读/UDP收包时报告。没有收到响应时既不声称成功鉴权，也不重放已经发送的业务。

建立预算覆盖载体、SMUX SYN、完整请求和响应；deferred 的响应阶段只使用剩余总预算，取消覆盖返回流/UDP两方向。UDP分帧接收把头/体进度保存在接收器内，select取消后不能重读帧头；发送中断会毒化并取消整个会话，禁止在部分帧之后重新开始。丢弃两半后实际socket回收，不留游离任务。

## 完整首轮与验收

一次写齐独立crate、实际出站工厂、以上全部编码/载体/配置、接口文档、Rust测试和真实官方对端工具，再统一worker构建、集中修改。矩阵为raw/TLS × SMUX关闭/版本1 × 代理/已知固定转发 × 两代理地址族；每种验证TCP及固定UDP、两目标地址族、域名、目标先发、0/17/12000/65507与超长、并发、错误认证/证书/名称、取消/超时/实际连接回收。固定转发目标与域名匹配边界分开，官方对端包长/空包/FIN限制按实际结果记录。

Rust独立假对端检查feature字节与完整负响应、扩展长度、碎片/截断/乱序、错误SMUX ID/命令、最大记录、有界背压、select取消后续读、取消发送不重放、跨节点认证不回退及非固定目标连接前拒绝。测试只在专用worker运行；源码存在、自端通过和官方互通分别登记。
