# shadowsocks 补丁

来源：crates.io `shadowsocks` 1.25.0，MIT。除下述改动外与发布包一致（去掉了 `Cargo.lock`）。

## 无负载首包的填充不再取 0

`src/relay/mod.rs` 的 `get_aead_2022_padding_size` 在负载为空时从 `0..=900` 随机取填充。同一 crate 的服务端拒绝“首块无负载且填充为 0”的请求，所以空写首部的客户端有 1/901 的概率被服务端拒绝。

kerlico 的 SS2022 出站每条连接都先空写首部，以允许目标先发数据，因此每条连接都有这个概率。范围改为 `1..=900`。

回归测试：`crates/protocol-ss2022/tests/protocol.rs` 的 `empty_first_write_is_never_rejected_for_zero_padding`。

## 写重试只确认已加密的字节

`src/relay/tcprelay/aead_2022.rs`、`aead.rs`、`stream.rs` 的 `Writing` 状态和 `proxy_stream/client.rs` 的 `Connecting` 状态在底层写 Pending 后，下次调用返回本次传入的 `buf.len()`。`tokio::io::copy_bidirectional` 在写 Pending 后会先把更多数据读进同一缓冲，再用更长的切片重试，于是多出的明文被确认却从未加密发送，连接随后停滞，AEAD 不报错。

状态改为记住进入内部缓冲的明文长度（`accepted`），完成时返回它。

回归测试：`crates/protocol-shadowsocks/tests/write_retry.rs`。

## 匿名钩子

`src/config.rs` 的两处注释和一处测试字符串含 URL 内嵌凭据的样例，改写以通过 `.githooks/privacy-check`，不影响行为。
