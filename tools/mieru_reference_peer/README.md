# Mieru 官方 API 测试对端

此目录只在专用 worker 构建回环测试程序，不进入 Rust 内核，不安装服务。固定官方 v3.38.1/v3.39.0 的源码和归档摘要在 `build.py`；原许可 GPL-3.0-or-later 随下载源码保留。它复用官方双角色 API、TCP/UDP 载体、Mux、握手和低熵功能，所有入口和目标都限制回环。

```sh
python3 tools/mieru_reference_peer/build.py \
  --work-dir "$REFERENCE_WORK" --go-root "$PROJECT_GO" \
  --vectors-output "$VECTOR_OUTPUT"
```

只使用项目内已核验 Go 1.26.10，构建并发/GOMAXPROCS=1，Go 堆软预算 768 MiB；可用 `--cache-dir`、`--module-cache-dir` 复用同项目缓存。`--version` 固定选择两个来源之一；不以版本字符串代替来源摘要。输出二进制、来源、向量与模块清单摘要到私有 `provenance.json`。构建比较全部非 `_test.go` Go 文件，运行源码有变化即失败。

`fixtures/export_vectors_test.go` 只加入 worker 测试副本，调用官方 metadata Marshal 和低熵 codec，以固定时间/nonce 及 Go PBKDF2/XChaCha 原语生成 64 段、96 低熵及 8 长度记录。固定 nonce 仅属于独立测试上下文，不用于生产发送。原始缓存不修改，Rust fixture 在 worker 生成后同步回仓库。

参照入口兼容互通工具所需的 Mihomo 风格 JSON 子集；不是完整 Mihomo 程序。`-encode-traffic` 使用官方编码 API 生成同一份对端配置。官方 UDPAssociateWrapper 对零 payload 可能返回 EOF，故测试入口直接调用官方 PacketOverStreamTunnel 和地址解析，用 `io.ReadAll` 保留空包；该入口处理不代表原 Mihomo 客户端也已通过。

原 UDP 的密码学限制仍在：没有修补 nonce/key 规则，只测试显式本地兼容。参数、认证与资源结论见 `docs/interfaces/mieru.md`，实际验收见 `docs/testing/mieru.md`。两个固定版本的 API 小对端与向量已在 worker 构建，非测试 Go 运行源码前后校验未变；构建谱系见 `SOURCE.json`。真实互通结果仍独立记在验证文档，不从构建成功推定通过。
