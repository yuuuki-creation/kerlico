# 配置与命令行接口

更新日期为2026-11-02。本轮源码只接受JSON v2，完整首轮尚未编译或测试。迁移步骤见[配置v2迁移](../config-v2-migration.md)。配置不是三个参考核心的兼容格式。

## 根配置

| 字段 | 约束 |
| --- | --- |
| version | 必须为2，v1明确拒绝 |
| epoch | 默认1，必须非零，标识配置代次 |
| accounts | 管理账户数组，ID和用户名分别唯一 |
| outbounds | 命名出站数组，tag/type/options；每条编译一次、运行期启动一次 |
| inbounds | 回环固定目标入口，默认空 |
| nodes | 需要真实鉴别成员的协议节点，默认空 |
| local_inbounds | 工厂明确允许的回环本地入口，默认空 |
| limits | 省略字段使用下述默认值 |

标签为1至64个ASCII字母、数字、横线或下划线。出站有独立标签空间，所有入口共用另一个空间。未知字段、缺失类型、失效引用和不兼容能力直接拒绝。

accounts每项包含user_id、username、password_hash和可选enabled。user_id是持久非零UUID；用户名为1至128个非空白、非控制字符，校验唯一。管理密码保存为Argon2id v19 PHC摘要，支持m为19456至262144、t为2至10、p为1至8。账户管理密码不自动成为协议凭据。

节点包含tag/type/listen/outbound/options/members，可选mode和max_sessions。members每项包含user_id、native_credential，可选credential_epoch和enabled，每节点最多1024个原生候选，协议可有更严格边界。凭据代次默认1且非零；账户及成员都启用才允许新鉴别。每个成员必须对应真实认证清单，跨入口秘密复用被拒绝。IPv4和IPv6监听节点分别声明members。

mode取ipv4-only、ipv6-only或dual-stack，默认dual-stack。它只约束本节点负责目标选择的Local路径；双栈先IPv4。Remote代理保留网站域名或字面IP，不应用本地网站模式，不替远端解析或重试。模式不限制代理载体的端点地址族。当前WARP缺族自动准备仍未实现，不能据mode字段宣称设备双栈出网已验证。

## 固定目标与限制

固定入口包含tag、type、listen、target.host/port、outbound，可选mode和require_remote_eof。type为tcp-forward或udp-forward，listen必须回环，端口0用于动态分配。require_remote_eof默认为false，为true时只接受具备目标写端EOF能力的TCP路径。没有动态目标解析协议混入此固定转发格式。

| limits字段 | 默认值 | 范围 |
| --- | --- | --- |
| connect_timeout_ms | 10000 | 1至300000，建立链总期限 |
| idle_timeout_ms | 60000 | 1至86400000，业务空闲预算 |
| drain_timeout_ms | 5000 | 1至300000，每个关闭阶段有限预算 |
| max_sessions | 128 | 1至65536，全局会话与附加逻辑流配额 |
| udp_queue_packets | 32 | 1至4096，每来源固定转发队列 |
| max_datagram_size | 65535 | 1至65535，缓冲上限，不是线上包长承诺 |
| max_flow_records | 65536 | 不小于max_sessions且不大于1048576，运行账本记录上限 |

运行记录满时优先淘汰已结束明细并将其用量归入本次运行累计；仍活跃的账本不被淘汰，全部占满时拒绝新的业务流。淘汰数量对查询可见。这不是持久历史保存策略。

## 命令

| 命令 | 行为 |
| --- | --- |
| kerlico modules | 按inbound/outbound列出本次构建真实注册角色 |
| kerlico check -c 文件 | 限制1MiB，解析并纯编译计划，不启动服务、监听、拨号、创建状态目录或部署设备 |
| kerlico run -c 文件 | 消费计划，启动唯一共享运行服务并绑定入口，失败按同一事务回收 |
| kerlico account-new --prefix 名称 | 从标准输入读管理密码，输出一次生成的账户JSON；默认前缀user，用户名为前缀_UUID |

account-new的输入密码要求12至1024字节，输出只包含管理ID、用户名、密码摘要和启用状态。将输出账户保存到accounts后重启保持同一ID。prepare不会随机改名。协议密码、UUID或key另写入对应成员native_credential。

当前默认仍注册21个协议模块，SSH及Gost Relay只有出站；各角色和组合是否验收以当前测试记录为准。关闭未实现模块不作为本轮验收办法。Ctrl-C和Unix SIGTERM停止入口并有限排空，退出0不代表每条业务会话成功。
