# VLESS 普通流验证记录

更新日期：2026-10-30。当前代码关联任务 `K-F0`、`K-V1`，固定目标 UDP 单独验收。本文件记录实际观察，不把测试文件存在或一次旧缓存运行当成成功证据。

实现提交为 [`6d80350381b80e9dc92fd4105dc1ed5cd3f37e66`](https://github.com/yuuuki-creation/kerlico/commit/6d80350381b80e9dc92fd4105dc1ed5cd3f37e66)。下述输入和工具摘要已与该提交核对，后续纯文档更新不改变这些已测试输入。

## 本次范围

目标为 `version=0`、TCP/RAW 承载、TLS 正常证书校验、空 flow、`encryption=none` 的客户端出站。TCP、固定目标 UDP、域名/IPv6 目的地址、并发隔离、失败路径和有界退出分别验证。当前无 REALITY、Vision、XHTTP、Mux/XUDP 或 Encryption 实现。

本地为 macOS arm64、Rust/Cargo 1.96.0。三台已授权 worker 都经只读确认是 Linux x86_64，宿主工具链 Rust/Cargo 1.99.1；最低 Rust 1.88 另用隔离容器验证。真实地址与连接资料不进入本记录。

## 构建输入与复现

本次 Rust/Cargo 输入摘要为 `74373b2dd937365c18b5df5bd7db6439f3c2927c4090d0c8570d8e78f46cd388`：对 Cargo.lock、所有公开 `.rs`/`.toml` 相对路径排序，逐项拼接 UTF-8 路径、零字节和该文件 SHA-256 的 32 个原始字节，再计算 SHA-256。已核对它们与三台 worker 实际测试的源码一致。

互通工具 SHA-256 为 `e39c54bec8329acce9842e4d73d400c46656f6872e6498cffae04510b5e37bd2`，已与实际执行的远端文件比对。Linux release 二进制 SHA-256 为 `a8c3a5a02b5783d29ef54c5f43289ebd4d433fbf998fe64bfceb5d6ebee3c535`。这些摘要不包含凭证或本地个人路径。

测试归档去除本地 uid/gid/用户名并归一时间戳。复用远端工作区时，先核对内容摘要，再刷新归档中源码/清单的文件时间，使 Cargo 重新检查路径依赖。没有执行这一步的早期缓存运行不计为本次源码验证。

| 环境 | 命令/任务 | 当前记录 |
| --- | --- | --- |
| 本地 macOS arm64 | 工作区测试、Clippy、格式、Rustdoc 和 release 构建 | 22 个 Rust 测试和全部检查通过，默认二进制实际注册 direct/reject/vless |
| perf-01 / Linux | `cargo test --workspace --locked`、Clippy、格式、配置与功能裁剪 | 22 个 Rust 测试通过，零 Clippy 警告；去掉默认 feature 后仅注册 direct/reject |
| perf-02 / Linux | release 构建、实际参考端互通 | Xray 与 sing-box 各 11 项检查通过 |
| perf-03 / Linux + Rust 1.88 | 隔离容器执行 `cargo test --workspace --locked` | 22 个 Rust 测试通过；实际版本 rustc/cargo 1.88.0 已核对 |

最低版本镜像使用本地已拉取的 `rust:1.88-bookworm`，镜像 ID 为 `sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0`。没有修改宿主默认工具链。

## 固定参考端

| 参考端 | 版本 | 发行包 SHA-256 |
| --- | --- | --- |
| Xray-core | v26.10.29 | `8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2` |
| sing-box | v1.14.4，Linux amd64 musl | `8f7c5f0651238850d96a0e488e5473cd77ec1a0098f63942e943f475a12057ca` |

发行包从各自官方 GitHub release 获取，并与 release API 的 digest 比较。程序、生成的证书、对端配置及原始日志仅放在测试机的项目私有工作区，不进入本项目 Git。服务都绑定回环；测试完成会结束本次创建的进程，不修改机器已有服务。

互通入口为 `python3 tools/interop_vless.py --kerlico <本项目二进制> --reference <参考二进制> --backend xray`，第二组使用 `--backend sing-box`。工具验证配置、TCP 首包/64KiB 负载、域名/IPv6、16 路 TCP、非空 UDP/8 路来源隔离、信号退出，以及错误 UUID、证书与名称失败。生成材料和结果只存本地私有目录。

目的地址覆盖中，TCP 实测 IPv4、域名与 IPv6；UDP 实测 IPv4 固定目标。域名/IPv6 UDP 有编解码路径，但本轮没有对这些网络路径单独验收。

## EOF 的接口边界

当前实现把本地逻辑写关闭与 TCP/TLS 载体关闭分开，保留反向读取；普通 flow 不提供远端 EOF 传播保证，能力声明为 `tcp_eof=false`。需要该能力的入口必须配置 `require_remote_eof` 并被当前 VLESS 出站拒绝。

独立线格式客户端对 Xray v26.10.29 服务端做回环 RAW 对照，已明确放行目标端口；发送 19 字节业务后以 TCP FIN 结束写方向，只收到 2 字节响应头，没有完整 EOF 成帧回包。此结果仅描述该基线，不外推所有模式或未来版本。[固定客户端普通 flow 源码](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go)也没有独立请求结束帧。正式互通工具使用有长度边界的测试应用，并仍检查本地写关闭后的完整回写，不声称验证了远端 EOF 传播。

本版本 Xray 的 freedom 默认阻断代理访问私网。测试只在该进程的 `finalRules` 中放行本次回环地址和实际目标端口，没有修改宿主防火墙或其他服务。未配置这项例外的早期结果不作为协议失败或成功证据；[固定策略实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/freedom/freedom.go)与[配置字段](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/freedom.go)保留为复现依据。

## 明确未覆盖

未验证生产网络、丢包长时间稳定性、吞吐排名、Windows、其他 CPU 架构、TUN 或其他 VLESS 组合。TLS 使用参考端与库的默认协商，未逐版本分别验收。线格式测试保留零长度与 u16 最大帧；实际 UDP 互通使用非空负载（1、1024 字节及并发来源），不能由帧测试推定参考端接受所有尺寸。
