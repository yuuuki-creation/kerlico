# Sudoku 双端研究记录

日期：2026-10-31。状态：本轮完整首轮范围已在下文固定，开始原生Rust编码；尚无本模块构建或互通验收。研究探针和独立向量只证明固定参考行为。

## 当前固定证据

总表P-17：Mihomo包含独立入站、出站和transport/sudoku，不是Xray FinalMask的同名编码层。固定提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`；实际代码为核心仓库内实现，没有独立的sudoku Go module版本可直接当作协议版本。

从固定官方raw来源重新取回并与只读归档逐字节相等：

| 文件 | SHA256 |
| --- | --- |
| [出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/sudoku.go) | `0442c0ad521b967eb6d50dd08e0170ce626b52c9ba6bf0c5e208e2bca2a237d4` |
| [节点配置](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/config/sudoku.go) | `875af3f3d4f902cd17670ce786a9c6b6aaa460ffd4a0de861823d6bea9d7aab8` |

缓存是忽略的只读源码归档。没有.git的子目录内运行git命令可能向上命中kerlico仓库；父仓库提交不能作为上游固定版本证据。后续其余协议、密码、HTTP和复用文件仍须同样固定来源。

官方v0.5.2.0固定提交归档SHA256为 `feba7fd0770b3af2fbc747b9d55d58764ef0470b5fedbabd21fc917e9d56625a`，410551字节；归档318个普通文件已逐字节与只读缓存匹配。该核对是来源读取，不是构建或协议验收。其go.mod要求Go1.27.2；后续参考构建使用项目内工具链，不修改系统设置。[Go官方清单](https://go.dev/dl/?mode=json&include=all)中go1.27.2.linux-amd64.tar.gz为70590635字节、SHA256 `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5`，尚未下载或执行该工具链。

## 已读到的层次，尚待完整核验

- 出站选项包括AEAD方法、padding范围、四种方向性table类型、纯下行、自定义布局/轮换表、HTTP mask以及独立multiplex选项。HTTP mask包含legacy/stream/poll/auto/ws；平铺和嵌套字段有覆盖关系，不能直接照搬成多个互相矛盾的开关。
- 客户端普通流在完成握手后发送KIP OpenTCP和目标地址；UDP发送StartUoT，再使用带地址的包接口。TCP会话复用是独立MultiplexDialer，不能从HTTP连接复用或UoT成功推断已实现多流。
- init代码区分公钥、64字节拆分私钥、32字节主标量与非hex PSK；32字节hex先按压缩点解释。需要逐层核实真实鉴权参与方和方向，不能只哈希字符串就宣称独立节点凭据隔离。
- KIP客户端Hello生成X25519临时公钥和随机nonce，ServerHello需回显nonce，再由共享秘密派生双方向基密钥并Rekey。用户hash、表hint、特性协商和60秒时间边界的真实保护与重放条件尚须完整阅读，不从ECDH名称推定服务端身份已认证。
- RecordConn格式为u16长度、epoch u32BE、seq u64BE和AEAD密文；12字节epoch/seq同时作为nonce和AAD，源码默认32 MiB触发密钥更新。必须验证独立方向、严格序号、更新边界、计数器溢出、握手重置和残留记录读取。

## 原生参考探针与实际鉴权

`tools/sudoku_reference_probe`已在perf-01用未修改的固定Mihomo包运行。来源归档SHA256为 `ecda5f8c8a8a1d60bc088c2640c85d92c8f002c0686234a26bdf671735afe216`；项目内独立Go1.26.10构建，并发1、堆软预算768MiB，没有安装系统软件或连接网络目标。来源、锁和产物摘要见该目录SOURCE.json，原始日志留私有。

两种AEAD各对私钥材料/仅对应公钥材料、两个由客户端指定的UserHash运行原生early KIP API，8条均完成握手且服务端原样返回所选UserHash；两条保持正确table但使用错误AEAD种子的控制均拒绝。探针不包含管理端用户名单、完整服务程序或网络鉴权攻击，未据此声称绕过任意部署的策略。结合固定ServerHandshake未绑定UserHash的源码，kerlico决定：

- 将规范化后的共同seed视作真正共享秘密，称为seed凭据，不承诺Ed25519签名或私钥所有权证明；形似公钥的值也不能公开。
- 节点指纹使用有效seed，不能使用原始split/private/public字符串来绕过跨节点查重。主标量与其不同拆分、对应压缩点产生相同有效seed时必须拒绝跨节点复用。
- UserHash只作线格式兼容字段，不用作独立鉴权、配额或连接池身份；身份资源始终绑定实际节点和seed。
- `aead=none`仍实现其线格式，但只能显式不安全选项、回环local_inbounds/回环字面出站，返回空认证指纹。HTTP伪装与table混淆不能充当AEAD鉴权，不在公网节点登记none支持。

探针另输出8组四方向table模式×自定义布局有无的独立编码向量、首个puzzle、table hint和Go math/rand v1 Shuffle的288元素结果，供Rust实现逐字节/逐记录验证。fixture中的材料全部合成；数学数独求解crate不能替代代理编解码。

## 记录、表与资源契约

有效seed经SHA256后，初始双向基密钥分别使用HKDF-Expand标签sudoku-psk-c2s/s2c；新会话以X25519共享值和16字节Hello nonce为输入、seed摘要为盐，HKDF-Extract再按sudoku-session-c2s/s2c展开。拒绝低阶X25519共享值、错误nonce、非法长度、时间与特性协商。新连接和Rekey均随机初始化非零epoch与seq，不是从零开始；完整记录内严格序号，epoch前进最多8，发送端溢出拒绝，不能回卷重用nonce。

记录体最多65535，12字节明文header加16字节tag使单记录明文最多65507；大写入分记录但不改变流字节。32MiB密钥更新独立按方向，正文跨阈值后更新epoch并随机seq；最大阈值、强制低阈值向量和真实跨更新负载分别验证。none直接透传，没有记录AEAD保护。

4×4合法网格按固定回溯顺序产生288个，再按SHA256(seed)首8字节有符号BE种子用Go math/rand v1 Shuffle排序。先前256个承载字节，其余32个只参与唯一性判断。四个clue必须唯一确定其中一个承载网格，不能把多解、非法别名或非承载网格误译。Go v1的常量和兼容算法若纳入Rust，随附原BSD许可，不改其算法为v2或Rust随机源。

ASCII提示字节保留0x7f→换行映射；entropy与两x/两p/四v自定义布局按实际位顺序处理，四方向模式分别选择上/下行布局。纯模式四clue还原一字节；packed模式按六位分组，pad marker清除残留bits，padding不会注入业务。接收状态、partial记录、HTTP body和KIP/UoT帧进度跨select保留；中断部分加密写后关闭载体，不重发半帧。

UoT为u16地址长度、u16包长度、SOCKS地址和完整包；0字节合法，普通IP包上限65507，超限整包拒绝。节点统一使用DatagramAssociation实现同socket多目标/跨地址族及来源回写，不在协议层自行拨网站socket。

TCP session mux帧为type u8、id u32BE、长度u32BE；Open/Data/Close/Reset/Ping/Pong分别1–6，零ID只用于控制/空保活。Close是单向EOF，Reset关闭整个逻辑流。实现真实单载体多目标复用、有界发送队列、每流字节预算、独立取消/EOF、慢流隔离、ID耗尽拒绝及空闲回收；不以逐目标新建载体冒充复用。

## 本轮完整首轮交付范围

一次写齐以下全部生产代码、接口、Rust测试和独立参考工具，再统一worker编译/检查/测试，集中修改：

1. 双端TCP/UoT、上述seed规范化、两个AEAD与受限本地none、KIP握手/重放/密钥更新、四table方向/自定义轮换、pure/packed下行和真实TCP session mux。
2. raw、legacy HTTP头，以及HTTP mask stream/poll/auto/ws全部载体。stream/poll/auto和ws支持严格TLS；raw/legacy不接受无效的HTTP TLS开关。客户端字段分别指定实际端点、HTTP Host和TLS名称，不暗改节点地址；不使用环境代理。
3. stream/poll使用/session授权、/api/v1/upload按seq上传、/stream下载及fin/close控制；early KIP在ed查询和X-Sudoku-Early响应中协商。stream为原始body，poll为标准base64逐行；最多一个活动pull，EOF trailer单独处理。HTTP transport reuse(auto)与业务session mux(on)分别实现，不把HTTP keepalive当多目标mux。
4. 相同上传seq仅在完全相同的批次上可幂等重试，缺口/重复body冲突拒绝；不在不确定的部分下行交付后重放字节。auto只在建立阶段、同一节点/凭据内选择stream或poll，业务开始后不切换身份或重放。HTTP各令牌和会话按节点独立、受预算和到期管理。
5. WS按固定HMAC标签、时间、method/path认证并支持early KIP；标准客户端掩码、分片、Ping/Close和大小边界。TLS验证、H2用于HTTP split的实际路径、HTTP/1.1 WS升级分别验收，不声称WS走HTTP/2 Upgrade。
6. 普通HTTP探测的固定网站回退只允许完整受限GET/HEAD，不转发鉴权失败后的Sudoku二进制到另一代理节点。上游推荐的“假key外层→真实代理内层”原始字节回退与项目禁止鉴权失败后回退另一节点的强制规则冲突，不在本轮实现；HTTP回退不能访问解码后的网站目标服务。

节点内额外逻辑会话持有全局与节点共同lease。HTTP token注册及真实复用驱动归节点生命周期管理，不能在物理授权请求结束后留下无主任务；客户端池归单个出站实例，Drop/取消关闭实际连接，单流取消不破坏其余流。认证失败、未知字段和能力不足不回退direct。

Rust原语固定aes-gcm0.10.3、chacha20poly1305 0.10.1、curve25519-dalek4.1.3、x25519-dalek2.0.1、HKDF0.12.4及现有SHA256/Tokio/rustls/Hyper；HTTP split直接使用Hyper帧读取EOF trailer，不经只读取正文的包装。记录密码与X25519不调用Go或外部核心。Go只作为worker独立对端/向量程序。官方当前v0.5.2.0固定 `56ce6f1aeea18aa69b9bc1d57557ed312b59e5f5` 已查阅；其源码标GPLv3-or-later并有命名/关联条款，不能将其整包作为本项目无许可限制的Rust组件。新增反向packed uplink和管理API不从固定Mihomo范围继承，另记未交付。

## 验证安排

基线按合法载体、AEAD、角色分别运行，两节点族/三类网站/目标先发/两数据类型在每组内验证；none结果独立列为本地不安全兼容。table、pure/packed、轮换、HTTP transport reuse与真实mux再做独立完整维度矩阵，不能从单个raw通过继承全部HTTP组合。

固定Mihomo与官方当前版本分别作为对端；独立Go向量覆盖shuffle、clue、packed边界、HKDF/AEAD、epoch和KIP/UoT。补32MiB更新、65507/65508包边界、错误凭据/公开seed语义、跨节点别名重复、UserHash不获独立权限、低阶点、重放/时间、上传幂等/序号缺口、partial下行、HTTP超限/慢头/错误证书/名称、auto建立选择、慢mux流与其他流进度、预算归还、主动排空/重启。组合通过只按实际结果登记。
