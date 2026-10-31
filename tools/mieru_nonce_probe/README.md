# Mieru nonce 研究探针

此工具仅在专用 worker 调用固定官方 cipher API，使用合成凭据和数据，复现官方 UDP 段的两次 AEAD 调用顺序。运行期不连接网络，不做认证伪造，不针对真实服务。

两固定版本均验证：同段元数据/负载采用同一 key/nonce 时，两份密文的前 32 字节异或等于两份明文异或；已知合成元数据时可恢复合成负载前缀。TCP 递增 nonce 控制组不满足该关系。这是密码学限制证据，不能据此宣称已完成协议实现或互通。

构建仅在项目私有 worker 目录进行：将 `go.mod` 的相对 replacement 指向已核验的官方源码测试副本，使用项目内 Go 1.26.10，`GOMAXPROCS=1`、`GOMEMLIMIT=768MiB`、`go build -p=1 -trimpath -buildvcs=false`。不得安装服务或更改系统工具链；完整来源、源码与二进制摘要见 `SOURCE.json`。

官方原源码及其 GPL-3.0-or-later 许可保留在只读缓存/worker 测试副本，不加入 Rust 内核运行依赖。源探针同时建立用户名 hint；密码只为合成测试值。探针通过结果不适用于其他版本，也没有证明或尝试认证伪造。
