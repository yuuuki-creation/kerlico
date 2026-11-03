# smoltcp 补丁

来源：crates.io `smoltcp` 0.14.0，0BSD。除下述改动外与发布包一致。删掉了 `examples`、`benches`、`utils`、`tests`、`CHANGELOG.md`、`CONTRIBUTING.txt`、`ci.sh`、`Cargo.lock`；`Cargo.toml` 取自发布包的 `Cargo.toml.orig`，去掉 `authors`、`dev-dependencies` 和 example、test、bench 段。

## 空段使用已发送的最高序号

`src/socket/tcp.rs` 的 `ack_reply` 和 `dispatch` 让不占序号的段（纯 ACK、窗口更新）沿用 `remote_last_seq`。重传超时把它回退到最后一个 ACK，于是纯 ACK 也带回退后的序号。

对端可能已经收到这段数据。它把这个序号判为窗口外，丢弃整个段，段里的 ACK 也不处理。两端都超时回退时，各自的纯 ACK 和重传都被对方丢弃，双方都等不到确认，退避到空闲超时断开。kerlico 的 WireGuard 节点和出站两端都是 smoltcp，全双工流在丢包路径上会进入这个状态；对端是内核 TCP 时不会，内核的纯 ACK 序号不回退。

新增 `empty_segment_seq`，取 `rtte.max_seq_sent` 和 `remote_last_seq` 的较大值，只用于不占序号的段。`dispatch` 在段不占序号时不再用它更新 `remote_last_seq`，所以重传进度不受影响。

上游 `socket::tcp` 的 205 项单元测试在此补丁上通过（用上游 dev-dependencies 单独运行）。回归测试：`crates/protocol-wireguard/tests/ip_tunnel.rs` 的 `tcp_recovers_when_both_ends_time_out_after_crossing_segments`，去掉补丁后 7 秒失败。

## 接收窗口右边界空段与全双工重复 ACK 计数

1. `src/socket/tcp.rs` 的 `process` 在非零接收窗口 `(true, false)` 分支原本要求 `segment_start < window_end`。配合 `empty_segment_seq` 后，若发送端已发满通告窗口（`max_seq_sent == window_end`）而窗口内存在乱序空洞（`window_start < window_end`），其发出的纯 ACK 序号等于 `window_end`，会被误判为窗口外并触发 Challenge ACK 提前返回，导致段内携带的反向确认与窗口更新被丢弃。改为 `segment_start <= window_end` 允许窗口右沿空段通过校验。
2. `process` 的重复 ACK 判定原本要求 `repr.payload.is_empty()`，且对任何携带反向负载或窗口更新但 `ack_number == last_rx_ack` 的段进入 `_ =>` 分支将 `local_rx_dup_acks` 清零并误采样 RTT。全双工传输时反向数据段穿插在重复 ACK 之间会导致 `local_rx_dup_acks` 永远无法累积到 3。改为：当携带 SACK 区间（`repr.sack_ranges` 非空）且 `ack_number == last_rx_ack < remote_last_seq` 时同样计入重复 ACK；当 `ack_number == last_rx_ack` 但未满足重复 ACK 递增条件（如穿插的普通反向数据或窗口更新）时保持 `local_rx_dup_acks` 不清零且不触发新 ACK 的 RTT 采样。
