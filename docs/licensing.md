# 项目许可与第三方材料

更新日期：2026-11-02（Asia/Shanghai）

## 自有代码许可证

`kerlico` 自有代码采用 **GNU General Public License v3.0 only**（SPDX 标识：`GPL-3.0-only`，仅限第 3 版，不附带“或更高版本”条款）。

- 完整许可证原文位于仓库根目录 [LICENSE](../LICENSE)（取自 [SPDX GPL-3.0-only 官方文本](https://github.com/spdx/license-list-data/blob/main/text/GPL-3.0-only.txt)）。
- 根 `Cargo.toml` 的 `[workspace.package]` 及所有自有 crate 均声明 `license = "GPL-3.0-only"`。

## 第三方代码与内置补丁

本项目的 `GPL-3.0-only` 声明不改变第三方依赖、内置补丁、测试夹具或参考资料的原始许可证：

- `third_party/`（如 `h3`、`xray-transport`、`ml-kem-legacy`）与各协议 crate 下的 `vendor/` 目录（如 `russh-util`、`quinn-jls`、`quinn-proto-jls`、`arti-client`）均保留其上游许可证文本、版权声明及修改记录（`PATCHES.md` / `MODIFICATIONS.md`）。
- 项目的匿名提交规则仅针对本项目提交者身份，不删除上游开源项目要求保留的作者署名与许可证通知。
- `third_party/shadowsocks` 保留 MIT 许可证，补丁见该目录 `PATCHES.md`。
- `third_party/shaped-rustls` 保留固定上游版本的 Apache-2.0 / ISC / MIT 许可证与源码；TLS 1.2 显式扩展省略的补丁和独立清单调整见该目录 `PATCHES.md`。
- `kerlico-easytier` 以 Git 依赖固定使用上游 EasyTier 2.6.4（LGPL-3.0），未内置其源码，见 [EasyTier 出站接口](interfaces/easytier.md)。

## 二进制发行合规要求

在发布正式二进制产物时，须随附或同步提供：

1. 与二进制标签完全对应的完整源码、锁文件（`Cargo.lock`）、本地补丁与构建说明；
2. 实际参与链接的第三方依赖许可证汇总与必要署名通知（前期排查记录见 [1.0.0 只读审计](releases/1.0.0-readonly-audit.md)）；
3. 不将缺少明确再分发许可的外部专有证书或测试资产打包进公开发行物（见 [公共证书审查](releases/public-certificate-review.md)）。
