# 旧版 ML-KEM 接口兼容依赖

来源为 crates.io `ml-kem 0.2.3`，下载时核对注册表 SHA-256。上游为 [RustCrypto/KEMs](https://github.com/RustCrypto/KEMs)，保留原始源码、许可证与署名。

本项目只调整清单中的 `kem` 来源为 [固定旧接口](https://github.com/RustCrypto/traits/tree/25e5654bb0775d255abd937e3b3320b982f13da1)，版本仍为 `0.3.0-pre.0`；删除未随本副本分发的基准与开发依赖。算法源码未修改。本说明替代包级 README，不修改许可证。

原因：服务端 Encryption 原语使用旧 ML-KEM 0.2，新版 REALITY 使用 ML-KEM 0.3。两者要求不同 KEM 接口，而 Cargo 将注册表的 0.3 正式版与同版本预发行接口视为不能并存的选择。固定独立来源后，两套接口分别解析，不降低 REALITY 版本，也不替换密码算法。

该副本排除在 workspace 成员外，由根补丁引用；构建、互通和对应密码依赖均只在 worker 验证。原始版本可从 [crates.io](https://crates.io/crates/ml-kem/0.2.3) 获取。
