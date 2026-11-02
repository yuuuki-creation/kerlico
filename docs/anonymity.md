# 强制匿名提交约定

更新日期：2026-11-02（Asia/Shanghai）

本项目所有 Git 提交、标签及可发布内容均须保持匿名，严禁包含任何个人身份或本地机器可识别信息。

## 固定身份与内容约束

- **固定作者与提交者**：`Anonymous <anonymous@example.invalid>`，关闭 GPG/SSH 签名。
- **内容脱敏范围**：提交说明、协作者 trailer、文档、代码注释、文件名、示例配置、测试日志与构建产物中不得包含个人姓名、昵称、邮箱、本机绝对路径、主机名、SSH 详情或真实服务凭证。
- **第三方署名保留**：`third_party/` 与 `vendor/` 下的上游开源代码保留其原始版权与许可证声明（见 [许可说明](licensing.md)），不因本项目匿名提交规则而删除上游合规署名。
- **已审原文校验**：钩子仅对固定 `shaped-rustls` 提交的两份含署名许可证及 README 使用逐字节 SHA-256 白名单；内容变化即拒绝并要求重新审查。自有代码和其他文件仍执行完整匿名及凭据检查，测试证书、密钥和二进制素材不随本地补丁分发。

## 本地仓库配置与提交命令

克隆仓库后，在首次提交前启用仓库级 `.gitconfig`（不修改系统或用户全局 Git 配置）：

```sh
git config --local include.path ../.gitconfig
```

执行提交时显式指定环境变量并关闭签名，防止外部环境覆盖：

```sh
env GIT_AUTHOR_NAME=Anonymous GIT_AUTHOR_EMAIL=anonymous@example.invalid \
    GIT_COMMITTER_NAME=Anonymous GIT_COMMITTER_EMAIL=anonymous@example.invalid \
    git -c commit.gpgSign=false commit --no-gpg-sign
```

合并、变基、拣选（cherry-pick）与补丁应用同样遵守上述规则。

## 自动校验钩子（`.githooks/`）

仓库通过 `.githooks/privacy-check`（需 Git、shell 与 Python 3）在四个阶段强制校验：

入口 `run-privacy` 依次探测 `python3` 与 `python`，确认解释器为 Python 3.8+ 后执行同一检查器；两者均不可用时拒绝操作。此探测避开 Windows 商店占位命令，不跳过任何检查阶段。

- **`pre-commit`** / **`prepare-commit-msg`**：校验实际生效的 author/committer、签名配置、分支名与完整暂存区快照，拒绝 `.private/` 目录、非预期二进制文件及疑似个人路径/邮箱/密钥。
- **`commit-msg`**：校验最终提交说明，拦截非匿名邮箱、身份 trailer 与敏感凭据。
- **`pre-push`**：扫描待推送引用的完整可达历史、提交身份与未签名标签。

禁止禁用、替换校验钩子或使用 `--no-verify` 跳过检查。

## 远端发布边界

用户指定公开发布仓库为 `yuuuki-creation/kerlico`。Git 提交对象中的匿名 `author`/`committer` 与代码托管平台的推送账号及网络访问日志相互独立，推送与发布操作须在符合隐私要求的环境中进行。
