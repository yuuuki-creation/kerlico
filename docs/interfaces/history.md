# 统计持久化与只读查询

配置 v2 可增加 `telemetry`。省略时不创建数据库。

```json
{
  "telemetry": {
    "directory": "state/telemetry",
    "sample_interval_ms": 1000,
    "retention_days": 30,
    "mask_source": true,
    "access_records": true,
    "dns_records": true,
    "error_records": true
  }
}
```

`directory` 各级路径拒绝符号链接和上级路径。Linux 祖先不能被组或其他用户写入，文件须为单硬链接且权限为 `0600`。新目录和文件分别使用 `0700`、`0600`；已有不安全权限不会被自动修改。同目录只允许一个写者。访问记录可能含用户、目标和来源元数据，数据库应保存在服务自己的私有目录。

写者按单调时钟采样，在一个 SQLite WAL 事务内更新同一 `RunId` 的累计用量、保留访问记录和带宽样本。用量键为运行、维度及身份，使用绝对水位替换。重复提交不重复累加业务字节。查询跨运行累加各运行最终已提交水位，重启不会把旧用量计入新运行的采样差值。用量使用 JSON 中的无符号整数，数据库整数不承载字节累计值。

Engine 排空业务和出站后在首次关闭的绝对期限内执行最终提交。初始化表结构、版本与应用标识也在同一事务内提交；中途退出可重启恢复。SQLite 写锁冲突立即报告失败，不增加固定的额外等待。初始化、周期和最终提交均由独立 `ServiceContext` 登记真实阻塞任务，丢弃 Engine 或运行 Future 会显式退休该所有者。`Engine::history_retirement()` 返回独立收据，关闭超时后只有收据确认真实 join 才证明原生任务已结束；仍执行的写者继续持有文件锁。不能强杀阻塞文件系统操作，不能在返回非 clean 结果时宣称已完成持久化。

连接从初始化到最终关闭始终位于同一个受管阻塞任务，不在 Engine 与异步结果通道之间移交；最终确认在 SQLite 连接和写者租约真实关闭之后发送，收据还会确认真实 join。取消不发送 SQLite interrupt，避免迟到的中断撤销最终事务；等待仍受同一个绝对期限约束。

崩溃可能丢失最后一次成功事务之后的增量；不保证每个业务字节实时落盘。记录在内存淘汰后保留到事务成功确认；待写队列达到账本容量时拒绝新流，避免静默丢失记录或无界增长。`failure_policy` 默认 `degrade`，周期提交失败累计到 `Engine::stats().history_failures` 并保留内存积压，现有业务继续转发，后续采样重试。可指定 `stop-engine` 在周期提交失败后停止接入。无论哪种策略，最终提交失败或未在期限内真实回收都会返回错误。

上传和下载速率单位为 byte/s。当前速率按前后两次累计值之差与单调时长计算，平均值从本运行写者启动时刻计算，峰值为实际采样窗口的最大速率。每个样本保留运行 ID、窗口时长和墙钟时间；不同运行之间的缺口不能解释为零流量。

访问记录保留原始目标、可信归属、凭据代次、出站、绑定、阶段、终因、字节/包数和 UDP 目标明细。`mask_source=true` 时，IPv4 来源截为 `/24`，IPv6 截为 `/48`，端口不保存。`access_records=false` 关闭访问明细，仍保留独立维度的用量与带宽。历史中断留下的未结束记录不代表当前在线；在线视图只查询当前账本 `Telemetry::online()`。

`retention_days` 控制结束访问记录、旧运行遗留的未结束记录及带宽采样保留，范围为 1 至 3650 天。累计用量长期保留。采样间隔范围为 100 至 60000 毫秒。清理由写者执行，只读查询不重置基线或删除历史。

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind flows --node entry --after 0 --limit 1000
kerlico history --directory state/telemetry --kind bandwidth --since-ms 0 --after 0
```

输出为 JSON。访问和带宽结果每项为 `[cursor, record]`，用最后游标继续分页，单页最多 4096 项；游标不会因保留清理而复用。访问可按 `--user`、`--node`、`--outbound` 和开始时间 `--since-ms` 筛选。持续活动的同一访问会原位更新，此游标是记录分页游标，不是变更订阅。

## 事件

`kerlico history --kind events` 返回 DNS 与错误事件，每项为 `[cursor, record]`，筛选和分页参数与 `flows` 相同。

| 字段 | 含义 |
| --- | --- |
| `kind` | `dns` 或 `error` |
| `ts_ms` | 墙钟时间 |
| `node` / `user` / `outbound` | 可信归属与所选出站 |
| `target` | `dns` 为查询的域名，`error` 为业务目标；多目标 UDP 关联的错误没有目标 |
| `code` | `dns` 成功为 `ok`，其余为稳定错误码，如 `io.failed`、`operation.timeout` |
| `addresses` | `dns` 成功时按选用顺序排列的地址 |
| `dropped_before` | 待写队列已满时，此事件之前被丢弃的事件数 |

`dns` 只记录本机为 `Local` 路径做的域名解析；`Remote` 出站由远端解析，不产生此事件。`error` 记录每条流首个非取消失败。`dns_records` 与 `error_records` 分别控制两类事件，默认开启。事件不含来源地址和业务载荷，按 `retention_days` 清理，待写队列上限 4096 条。

实现使用锁文件单写者和 SQLite 事务；查询通过只读连接，可与写者并存。[SQLite UPSERT](https://www.sqlite.org/lang_upsert.html)规定冲突键覆盖行为，[rusqlite 0.40.2](https://docs.rs/rusqlite/0.40.2/rusqlite/struct.Connection.html)提供事务与只读打开接口。
