# russh-util 供应补丁

本目录来自 crates.io 发布归档 `russh-util 0.52.0`，原六个文件的 SHA256 及归档 SHA256 见 `SOURCE.json`。归档内 `.cargo_vcs_info.json` 报告 `3d09c20c52a542ffa327723d3a44cb1edd9b0ca4` 且 `dirty: true`，不能把该 Git 提交签出当成同一发行源码。`.cargo-ok` 是本地缓存标记，不属于发布归档，没有纳入供应目录。

包声明 Apache-2.0，继续保留原许可。发布归档没有附许可全文，`LICENSE-2.0.txt` 单独取自上述固定上游提交，来源和摘要另列于 `SOURCE.json`。本目录不继承 kerlico 自有包的 GPL-3.0-only 声明。

2026-11-02 的修改只涉及 `src/runtime.rs`。新增 `TaskSpawner` 和 `scope`，使显式作用域内 `runtime::spawn` 的真实 wrapper 登记到宿主。wrapper 内再次进入同一作用域，后代 spawn 继承同一所有者。宿主拒绝登记后，返回的 `JoinHandle` 以 `JoinError` 失败，不回退到独立 `tokio::spawn`。

作用域外保留原生和 wasm 的上游 spawn 行为。kerlico SSH 的整个连接驱动显式进入作用域，`russh 0.64.1` 的 `connect_stream` 内部 actor 因而直接登记到命名服务。即使外层 KEX future 被强制取消，真正持有 transport 的 actor 仍在该服务任务集合内，关闭报告须等待该集合的实际 join。

没有修改 SSH 线格式、认证、加密算法、密钥验证或时间原语。`kerlico-ssh` 内已写真实 KEX、鉴权、业务取消、强制中止和嵌套任务回归，尚未执行。根工作区需要将 crates.io 的 russh-util 统一 patch 到本目录，并排除该供应包作为自有工作区成员。锁文件须由海外 worker 重新解析后冻结。
