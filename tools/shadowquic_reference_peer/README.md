# ShadowQUIC 受控 Go 测试参照

此目录只构建专用 worker 的独立测试对端，不被 Rust 内核调用，不安装系统服务。固定 Mihomo v1.19.33 官方二进制及其 v2 失败记录保持原样；本对端结果必须单列。

`main.go` 复用固定 Mihomo 的 `transport/shadowquic` 应用编解码，提供测试所需的双向 TCP/两类 UDP、显式普通 QUIC 回退，以及仅握手的合成身份探测。入口/目标都必须为字面回环地址，身份由互通工具生成；不提供产品路由、系统入口、控制面或性能结论。UDP 监听仅用于测试的单一外部发包者，资源随进程退出回收，不能把它作为正式代理程序使用。

`build.py` 固定并校验：Mihomo 提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`、jls-quic-go 提交 `732f2fc9a34de12a58020a0ca75bf336095aed93`、官方 Go 1.26.10 Linux amd64 压缩包。所有源码和工具链只放在 worker 项目内；构建并发及 GOMAXPROCS 均为 1，Go 堆软预算为 768 MiB，不修改系统软件。命令为：

```sh
python3 tools/shadowquic_reference_peer/build.py --work-dir "$REFERENCE_WORK"
```

可用 `--go-root` 指向已经核验、位于同一项目私有工作区的 Go 工具链。可用 `--cache-dir`、`--module-cache-dir` 复用同项目的测试缓存。输出的 `provenance.json` 保存原包摘要、三个改动文件的前后摘要、补丁与二进制摘要及模块依赖清单摘要。构建使用 `-trimpath`，不把机器绝对路径写入可分享二进制。

`version-information.patch` 只补固定 jls-quic-go 的 0x11 通告、有界解析和受认证一致性验证。当前参照每次固定一个版本，只声明该版本，不做兼容版本切换；空/零/非法列表、重复参数、v2 缺失参数和 Chosen Version 与载体不符均拒绝。保留来源许可，未改上游只读缓存。Mihomo 的 GPLv3、jls-quic-go 的 MIT、jls-tls/Go 的 BSD 三条款许可随下载原包保留，参照只使用现有包 API，未把完整上游源码加入本仓库。

`key-update-label.patch` 单独修正固定 Go 依赖的第二处 v2 缺口：真实更新函数按版本使用 `quic ku` 或 `quicv2 ku`。`fixtures/key_update_vector_test.go` 直接调用该函数；构建先复现 RFC9001/RFC9369 附录 A.5 中旧 v1 通过/v2 失败，再应用补丁并验证两者通过。仅补参数的参照及其完整负载失败记录保持原样，不提高首次更新门槛或缩小负载。

`fault-injection.patch` 是单独的负测试副本改动，使用链接时字符串值构建 `omit` 与 `wrong` 两个恶意对端：分别省略版本信息和在 v2 上发送自洽的 v1 信息。它不进入正常参照二进制，也不进入 Rust 内核。正常与恶意二进制分别记录摘要。`main_test.go` 用独立固定字节检查参数解析，真实负矩阵由 `tools/interop_shadowquic_reference_negative.py` 运行，要求失败为 0x11 并验证同节点合法控制组。

真实正矩阵仍使用 `tools/interop_shadowquic.py --versions v2 --full`，`--reference` 指向受控正常二进制；不得将该结果改写为原官方 Mihomo v2 兼容。具体结果见 `docs/testing/shadowquic.md`。

最终正常参照与两个恶意参数参照均在新目录使用本脚本重建，三个二进制摘要与互通验收版本一致；摘要、前后源码与依赖清单见 `SOURCE.json`。测试结果见主验证记录，不能由构建成功推定互通通过。
