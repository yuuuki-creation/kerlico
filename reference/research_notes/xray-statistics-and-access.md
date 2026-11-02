# Xray用户统计与访问记录研究

记录日期：2026-11-02，Asia/Shanghai。静态源码及官方文档核对，无构建、运行或性能结论。网页核对日期为2026-11-01。本项目采用范围见[0011](../../docs/decisions/0011-users-statistics-and-access-records.md)，行为设计见[多用户与统计](../../docs/statistics-and-users.md)。

## 固定来源与阅读边界

本记录单独使用Xray-core `v26.10.31`，完整SHA为`a4a3dff5b20c2faae567b742c172c7b95e75c083`。先前架构研究的`v26.10.29`不被替换。引用固定源码而非主分支，官方滚动文档按2026-11-01读取，不混成同一版本。

## 访问日志字段与写入阶段

[`common/log/access.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/log/access.go)的`AccessMessage`包含From、To、Status、Reason、Email和Detour。输出字符串包含来源、accepted/rejected、目标、可选路径/原因及email。日期时间与微秒由[`common/log/logger.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/log/logger.go)添加。

From记录核心可见的来源地址。To由协议填充，例如VLESS在[`proxy/vless/inbound/inbound.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/inbound/inbound.go)使用请求Destination。通常目标是网络类型、域名或IP与端口，不是同时保存原域名和最终拨号IP的结构。

[`app/dispatcher/default.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/dispatcher/default.go)在routedDispatch确定具体出站后填Detour，先记录访问消息，再调用handler.Dispatch。VLESS可在更早阶段将状态设为accepted。因此accepted不是网站建立成功，更不是应用响应成功。

标准AccessMessage没有会话结束时间、持续时长、上下行字节或速率字段，没有持久关联每次访问和用户用量的完整账本。

## 配置、保存与DNS记录

[`infra/conf/log.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/infra/conf/log.go)有两个默认路径。完全省略log时DefaultLogConfig关闭access，错误输出warning及以上。存在log对象但access为空时，Build选择控制台；access为none关闭，为文件路径则写文件。loglevel为none还会关闭两种日志。

文件输出通过追加方式打开，日志组件没有按天过期或自动轮转配置。控制台日志是否落盘由外部采集决定。地址遮罩可按IPv4/IPv6范围替换日志地址，见固定配置与[`app/log/log.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/log/log.go)。[官方日志文档](https://xtls.github.io/config/log.html)描述文件/控制台/none、级别、dnsLog与maskAddress，但默认值需要按上述源码区分。

[`common/log/dns.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/common/log/dns.go)包括解析器、域名、结果IP列表、缓存或查询状态、耗时和错误，dnsLog开启后经访问日志输出。该结构不带用户或会话键，不能把结果列表当成某次实际连接使用的IP，也不能由共享解析缓存可靠推出某用户的访问。

## 流量与在线统计

用户流量在Dispatcher依据已认证用户Email及level的policy开关注册，命名为`user>>>标识>>>traffic>>>uplink`或`downlink`。没有Email不注册该用户统计。入出站统计按tag注册，由policy system开关控制。基本配置见[统计文档](https://xtls.github.io/config/stats.html)及[策略文档](https://xtls.github.io/config/policy.html)。

计量位置不完全相同。用户量包装业务Link，`SizeStatWriter`在转交WriteMultiBuffer之前增加传入长度；部分入站与出站计数通过载体CounterConnection包装，见[`inbound/worker.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/proxyman/inbound/worker.go)、[`outbound/handler.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/proxyman/outbound/handler.go)和[`dispatcher/stats.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/dispatcher/stats.go)。不能未经逐路径核对就宣称用户字节等于物理入出站字节，或将提交长度一律解释为最终送达。

在线来源IP另由statsUserOnline控制。固定源码`trackOnlineIP`在关联上下文建立时AddIP，并在上下文取消后RemoveIP。[`app/stats/online_map.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/stats/online_map.go)按IP引用计数，最后引用移除时不再在线，排除本地回环。lastSeen由AddIP更新，不是每个业务包更新。

滚动policy文档将在线解释为20秒内连接活动，与本记录固定源码不同。适配时按真实会话生命周期定义，不能照抄该时间描述或把IP数当设备数。

[`app/stats/stats.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/stats/stats.go)保存内存map，Counter是原子int64。没有自动历史落盘和重启恢复。[`command/command.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/stats/command/command.go)支持单项/过滤查询、用户汇总、在线IP、在线用户及读取时清零。没有自动按天/月归档或历史速率序列。

## 导出与运行资源

StatsService另提供运行时长、Go goroutine与内存/GC计数。[`app/metrics/metrics.go`](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/app/metrics/metrics.go)有运行指标及诊断输出入口，配置见[官方Metrics文档](https://xtls.github.io/config/metrics.html)。这些是运行期观测与查询接口，不等于持久访问或带宽历史。

本次没有发现独立保存当前/平均/峰值用户带宽及历史桶的机制，不能把累计字节换个字段名当速率。kerlico需要按实际经过时间采样，并按Rust任务、平台资源能力适配运行指标，不能生成假的goroutine或GC等价值。

## 对kerlico的适用结论

借鉴日志与用量分离、可信用户归属、入出站视图及按需导出。不机械复制Email键、字符串统计名、每路径不同的计量层、清零即丢运行计数或Go运行时指标。原始目标、业务连接IP与代理端点分别保留，远端未知信息不以本地DNS补出。

用户要求存储逐用户用量和带宽，本项目需增加持久历史、稳定标识、统一计量、采样质量、去重和故障边界。这些是本项目设计，不能登记为Xray原生已提供或kerlico已实现。验证目标通过借鉴映射REF-027连接到正式设计。
