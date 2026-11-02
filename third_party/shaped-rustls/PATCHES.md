# shaped-rustls 本地补丁

来源：`aimalygin/shaped-rustls`，固定提交 `3a131beaef0183b0cb61e5a9070a703b6be39ed3`。上游地址：https://github.com/aimalygin/shaped-rustls/tree/3a131beaef0183b0cb61e5a9070a703b6be39ed3

保留该提交 `rustls/src`、`build.rs`、README 与 Apache-2.0 / ISC / MIT 许可证。独立 Cargo manifest 将上游 workspace 依赖原值展开，省去上游测试/示例工作区成员和开发依赖；没有改变库版本或功能依赖。

不分发 `rustls/src/testdata` 中的上游证书、测试密钥及二进制报文；这些素材不参与产品库构建。本目录不作为可独立运行上游测试套件的完整工作区，完整测试环境应取上述固定提交。

功能补丁仅位于 `rustls/src/client/hs.rs::apply_extension_plan`：当有效协议版本包含 TLS1.2 且不包含 TLS1.3，并且调用方显式在 ClientHelloExtensionPlan 禁用 supported_versions(43)，允许省略该扩展。默认路径、TLS1.3 路径、证书/服务器名称验证和握手签名验证保持原行为。该能力用于固定 wgcf 首连 TLS1.2 hello，不是全局禁用版本广告。WARP 的 SHA1 签名 scheme 仅使用已有 ExactExtension 广告接口；没有启用 SHA1 证书或握手签名验证算法。

回归入口：`cargo test -p kerlico-device registration::tests`。应在整合输入额外执行工作区 TLS 消费者的协议回归。
