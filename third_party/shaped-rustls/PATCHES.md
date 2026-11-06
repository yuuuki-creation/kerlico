# shaped-rustls 本地补丁

来源：`aimalygin/shaped-rustls`，固定提交 `3a131beaef0183b0cb61e5a9070a703b6be39ed3`。上游地址：https://github.com/aimalygin/shaped-rustls/tree/3a131beaef0183b0cb61e5a9070a703b6be39ed3

保留该提交 `rustls/src`、`build.rs`、README 与 Apache-2.0 / ISC / MIT 许可证。独立 Cargo manifest 将上游 workspace 依赖原值展开，省去上游测试/示例工作区成员和开发依赖；没有改变库版本或功能依赖。

不分发 `rustls/src/testdata` 中的上游证书、测试密钥及二进制报文；这些素材不参与产品库构建。本目录不作为可独立运行上游测试套件的完整工作区，完整测试环境应取上述固定提交。

功能补丁仅位于 `rustls/src/client/hs.rs::apply_extension_plan`：当有效协议版本包含 TLS1.2 且不包含 TLS1.3，并且调用方显式在 ClientHelloExtensionPlan 禁用 supported_versions(43)，允许省略该扩展。默认路径、TLS1.3 路径、证书/服务器名称验证和握手签名验证保持原行为。该能力用于固定 wgcf 首连 TLS1.2 hello，并供 xray-transport 的 TLS1.2 时代 uTLS 档案（`android` 即 HelloAndroid_11_OkHttp、`hellochrome_58`、`hellofirefox_55` 等不含 supported_versions 的档案）按 uTLS 原样省略该扩展；不是全局禁用版本广告。WARP 的 SHA1 签名 scheme 仅使用已有 ExactExtension 广告接口；没有启用 SHA1 证书或握手签名验证算法。

回归入口：`cargo test -p kerlico-device registration::tests`。应在整合输入额外执行工作区 TLS 消费者的协议回归。

## 未支持：360 7.5 档案的密码套件

`client-fingerprint: 360`（uTLS Hello360_7_5）的 20 个密码套件全是 CBC、RC4 或 3DES：ECDHE/DHE/RSA 密钥交换配 AES-CBC-SHA/SHA256、RC4-SHA/MD5、3DES-EDE-CBC-SHA。本库的 TLS1.2 只实现 6 个 ECDHE AEAD 套件（AES-GCM、ChaCha20-Poly1305），两者没有交集。`ClientHelloAdvertisedCipherSuites` 可以照列这些套件，但服务端只能从中选一个本库不实现的套件，rustls 以 `SelectedUnofferedCipherSuite` 结束握手，所以“只广告不协商”对该档案等于每次连接都失败。xray-transport 因此在建连前拒绝该档案（`UnnegotiableTlsFingerprint`），Mihomo 配置层提示后发送不整形的 hello。

要让 360 真正可用，需要在本库实现 TLS1.2 CBC 套件，工作量超过一天，涉及：

- `crypto/cipher.rs::KeyBlockShape` 只有 `enc_key_len`、`fixed_iv_len`、`explicit_nonce_len`，没有 MAC 密钥长度；`tls12/mod.rs::ConnectionSecrets::make_key_block` 与 `make_cipher_pair` 需要按 RFC 5246 6.3 切出 client/server MAC 密钥。
- `Tls12AeadAlgorithm` 及 `MessageEncrypter`/`MessageDecrypter` 只描述 AEAD；MAC-then-encrypt 需要新的记录层实现，包括逐记录随机 IV、填充校验和常数时间 MAC 比较（防 Lucky13）。
- *ring* 不提供 AES-CBC 原语，只能落在 aws-lc-rs provider；RC4 与 3DES 两个 provider 都不提供。
- 360 的 RSA 密钥交换套件（`TLS_RSA_*`）需要客户端 RSA 加密预主密钥，`KeyExchangeAlgorithm` 只有 ECDHE 与 RFC 7919 DHE。仅 ECDHE-CBC 子集（如 0xc009、0xc013、0xc014）无需改密钥交换。

这些套件在 RFC 9325 中已不推荐使用，补齐后安全性质也要一并评估。
