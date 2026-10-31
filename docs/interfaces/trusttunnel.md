# TrustTunnel 双端接口

日期：2026-10-31。对应总表 P-18。**原验证已停止，协议尚未交付完成。最后已验是perf-02 r12的20项Rust、格式、选定包/专用CLI严格Clippy与构建；当前本地H2连接窗口及新增回归未同步/未编译/未测。** 不能据本文扩大互通通过范围；实际状态见[测试记录](../testing/trusttunnel.md)，固定证据见[研究](../../reference/research_notes/trusttunnel.md)。

包 `kerlico-trusttunnel` 导出 `TrustTunnelFactory` 和 `TrustTunnelNodeFactory`，两者 kind 均为 `trusttunnel`。构造只验证配置、读取指定证书文件及构建协议对象，不创建监听或拨号。主程序的根依赖、feature 和注册由公共集成任务维护。

## 本轮接口范围

| 载体 | 安全 | 客户端/节点业务 | 物理节点入口 |
| --- | --- | --- | --- |
| `h1` | TLS1.2、TLS1.3 | TCP、固定目标UDP | TCP，每条CONNECT一连接 |
| `h2`，默认 | TLS1.2、TLS1.3，ALPN `h2` | TCP、固定目标UDP | TCP，HTTP/2多流 |
| `h3` | QUICv1、TLS1.3，ALPN `h3` | TCP、固定目标UDP | UDP，HTTP/3多流 |

不提供明文载体、h2c、任意WS/gRPC包装、自动H3/H2竞速、ECH/指纹/ClientRandom鉴权密钥、订阅或系统VPN管理。未知选项直接拒绝。普通CONNECT保留目标authority；`_udp2`、`_check`、`_icmp` 为独立控制authority。extended CONNECT 不是本轮业务路径。

客户端 `capabilities={tcp:true,tcp_eof:false,udp:<配置>}`；H2/H3自端实现单向EOF，但外部H1/Mihomo等关闭边界尚不能保证，通用能力保守登记false。原始FIN、自端大负载、真实对端FIN分别留证，不能用正常回写代替半关闭验收。`supports_udp_association=false`，不提供Full Cone；节点也不要求统一出口支持多目标关联。

H1读取到头尾即止，CONNECT成功后直接承载字节，不套chunked层；客户端实际请求头不超过官方的1024字节限制。H1节点最多32项头部；H2/H3头部总预算16384字节。H2流初始窗口131072字节。H3禁用QUIC DATAGRAM，UDP只在可靠HTTP DATA里传输。两端禁用0-RTT；普通会话票据保持TLS库默认，不用关闭票据来隐藏问题。

## 出站配置

```json
{
  "server": {"host": "127.0.0.1", "port": 8443},
  "transport": "h2",
  "auth": {"username": "test", "password": "独立测试秘密"},
  "tls": {
    "server_name": "tt.example.invalid",
    "ca_pem": "PEM字符串",
    "version": "auto"
  },
  "udp": true,
  "app_name": "kerlico",
  "limits": {
    "max_connections": 4,
    "max_streams": 64,
    "max_udp_flows": 64,
    "idle_timeout_ms": 30000,
    "health_check_ms": 10000
  }
}
```

`server` 为代理节点接入地址，不是网站目标；网站目标继续传给 `connect_tcp/connect_udp`。TLS校验证书和名称；`ca_pem` 缺省只用内置公共根，指定时只信任指定CA。可选 `certificate_pem`、`private_key_pem` 必须同时提供，用于mTLS客户端证书，仍必须提供Basic。没有跳过校验开关。`version` 为 `auto/tls12/tls13`，H3拒绝tls12。

用户名和密码非空、不含控制字符，用户名不能含冒号，密码允许冒号；两者UTF-8字节总长不超过512。AppName最多255字节UTF-8，不含控制字符，仅为非认证元数据。客户端固定发出规范Base64 Basic，不把Base64当加密。

`max_connections` 为1–32，`max_streams`、`max_udp_flows` 为1–1024；两项时间为100–86400000毫秒。H1物理并发取 `max_connections` 与总逻辑上限的共同约束。H2/H3单连接流上限按总流数除以池大小向上取整，所有连接再共同受总逻辑上限约束；满额立即 `ResourceLimit`。出站`max_udp_flows`还限制本实例的固定UDP通道总数，发送/接收半通道全部释放后归还额度；节点同名字段限制单个HTTP流的四元组数量。出站对象独享池和TLS会话材料，不跨节点、认证或信任配置共用。

H2/H3空闲且无活动业务的物理连接自动关闭；后续重新建立新连接。在空闲达到健康检查间隔但尚未回收时，复用前先发认证 `_check`，不访问网站。GOAWAY、连接关闭和认证失败不重放已发送业务，不切换其他节点或直连。池锁只覆盖选择/建立/健康检查，业务流继续独立受流控驱动。

## 节点配置

```json
{
  "tag": "node4",
  "type": "trusttunnel",
  "listen": "127.0.0.1:8443",
  "outbound": "direct",
  "options": {
    "transport": "h2",
    "users": [{"username": "test", "password": "本节点独立秘密"}],
    "tls": {
      "certificate_file": "server.pem",
      "private_key_file": "server-key.pem",
      "version": "auto"
    },
    "udp": true
  }
}
```

证书和私钥各自选择 `*_pem` 或 `*_file` 一种，大小各不超过1MiB；不接受两种重复来源。可选 `client_ca_pem` 使节点强制验证客户端证书；Basic仍必需。用户表1–256项，拒绝重复完整认证和表内重复密码秘密。

节点 `limits` 只接受 `max_streams`、`max_udp_flows`、`idle_timeout_ms`，默认值和范围同出站；物理会话数由NodeSpec/Engine预算负责。出站池的 `max_connections`、`health_check_ms` 在节点侧拒绝，避免接受不生效的配置。

每条CONNECT独立鉴权，拒绝重复 `proxy-authorization`，按所有用户的固定长度摘要做常量时间比较。完成鉴权和目标解码后才通过注入的 `AccessService` 访问目标。本项目节点等待TCP目标连接成功才发200；普通外部200仅表示代理受理，不能外推最终目标连接已建立。

鉴权指纹来自真实完整Basic，保持 `trusttunnel` 认证域；同时提供与原生HTTP代理一致的 `http` 摘要，因为H1 TCP CONNECT可用同一整组Basic凭据互相认证，不能因配置类型不同绕过查重。额外秘密隔离指纹用 `trusttunnel-password` 域，拒绝两个TrustTunnel节点换用户名重用同一密码。额外秘密只用于查重，不授予节点鉴权资格；证书公共信息、SNI、AppName或虚拟源地址不代替秘密认证。

## 数据、资源和错误

UDP每个Core固定通道独占一个 `_udp2` HTTP流，H2/H3仍可复用底层物理连接。服务端允许一个HTTP流容纳多个四元组，各自 `AccessService::connect_udp`，每个flow独立预算和空闲期限。客户端声明的source仅作回包关联，不是本机bind地址或身份；回包source取自统一出口 `DatagramReceiver::peer_addr`，缺少实际业务来源时明确拒绝，不用代理载体地址补位。

UDP域名由Engine统一Egress先解析、默认IPv4优先；直接调用裸出站的域名UDP明确 `Unsupported`。TCP域名保留到目标统一出口。UDP空包是完整数据报；完整流EOF才返回None。最大业务包65507字节，并遵守节点Core更小限制。收到攻击者声明的超限u32长度时直接拒绝，不分配该长度；每flow发送队列8包，共享回包队列8包，均有界。

线格式把IPv4填入最后4字节、前12字节补零；按规范将 `::1` 特判为IPv6。IPv4 `0.0.0.1` 与部分 `::/96` IPv6不能无歧义往返，发送时拒绝。固定官方端的 `::1`、尾部零包和包长差异见研究，不以自端正确编解码外推对端。

认证失败407并停止该认证载体；TCP目标访问失败502；排空/预算不足503；非法请求400；关闭UDP或认证后的 `_icmp` 返回501。ICMP无能力开关，不调用原始套接字、不借UDP接口承接Echo。后续需要独立统一ICMP契约。`_check`只认证并返回200/EOF，不能创建网站目标。

Engine持有物理会话租约；H2/H3每CONNECT再取逻辑流预算，UDP每flow再取统一预算。排空关闭预算后不接受新网站目标；已有活动业务按统一取消/截止时间退出。TCP和UDP都带取消与双向活动空闲预算；异常分帧/部分发送取消后丢弃整个通道，不能重放剩余片段。

## 当前停止边界

参考端整体兼容未验收：官方回环旁路记录已作废并保留；官方H2 65000字节回写及H3/IPv6节点setup仍有失败，IPv6私有目标条件不足。Mihomo证书路径/信任夹具失败，固定上行unknown source 0:0又与当前Node的source port0拒绝条件冲突，均未修复或复验。

本地`client.rs`的2MiB H2连接窗口和`io.rs`的新atomic credit回归只是待验证增量，不能据代码意图写成已经解决。只读交接保存的源码/锁/二进制和各矩阵终态见测试记录；未启动后续验证。
