# Naive公开证书资产的只读审阅与最小替代方案

日期：2026-10-31。**本文件仅记录证据和待协调方案，没有修改Naive源码、SOURCE.json、DER、hook或索引，也没有运行测试。** 本地仅用OpenSSL解码公开ASN.1字段及计算摘要，未验证信任链、导入信任库或访问OCSP/CRL。

## 精确资产与用途

| 项目 | 读取结果 |
| --- | --- |
| 当前路径 | `crates/protocol-naive/tests/fixtures/blocked-intermediate.der` |
| 类型/字节数 | 单张X.509 v3 DER证书，876字节 |
| DER SHA256 | `0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19` |
| SPKI DER/SHA256 | 120字节；`49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f` |
| Subject | C=US；O=eMudhra Inc；CN=EM DV TLS CA - G3C |
| Issuer | C=IN；O=eMudhra Technologies Limited；CN=emSign Root TLS CA - G3 |
| 序列号 | `588B2E3C2BB8CDA13E1A1209254321` |
| 有效期字段 | 2025-04-30 15:35:09 UTC至2040-04-28 18:30:00 UTC；不表示当前信任/吊销状态 |
| 公钥/签名 | EC P-384公钥，证书签名算法ECDSA-SHA384；不是私钥结构 |
| 关键约束 | CA=true，pathlen=0；keyCertSign/cRLSign；含serverAuth/clientAuth EKU |
| 索引状态 | 本次读取时尚未入Git索引 |

[SOURCE.json](../../crates/protocol-naive/tests/fixtures/SOURCE.json)固定[官方CA下载URL](https://repository.emsign.com/certs/EMDVTLSCAG3C.crt)、DER摘要及[NaiveProxy d04efe1e...拒绝表](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/net/cert/cert_verify_proc_blocklist.inc)。来源URL可能随时间变化，摘要才是这次所读字节的身份；不允许更新下载内容后默默改期望摘要。

唯一include_bytes调用位于`src/tls.rs`的cfg(test)模块、`invalid_der_is_rejected_and_snapshot_contains_security_update`回归中：它断言真实公开证书SPKI被拒绝，同时保留坏DER、正常生成证书不误拒绝及固定新增SPKI值检查。生产路径使用固定SPKI摘要集合，没有把这张证书配置成信任根。保留回归不等于确认该CA当前经营/安全状态，也不从有效期推导信任。

## 许可证据与不能作出的推定

当前SOURCE.json没有该CA DER再分发许可字段。[官方仓库](https://repository.emsign.com/)法律链接指向[官方Terms of Use](https://emudhra.com/en-in/terms-of-use)：第3节给有限访问/复制条件并限制未经许可再传播；第5节保留站点材料权利。此次没有找到这张DER可随第三方软件公开再分发的明确授权，不据此作“已经获准”或全面法律结论。

固定Chromium blocklist原文件声明BSD式代码许可，但它不是CA证书再分发许可的证据。公开URL、CA Subject、公钥可公开、没有私钥、已有安全测试结果，都不能替代所需权限。是否允许自动获取也应遵守实际来源条件，不通过关闭TLS校验、代理或其他方式绕访问限制。

因此，**当前优先方案是不把许可未知的DER放入Git或发行包**，不是修改匿名钩子准入。也不把它转成PEM/base64/十六进制数组隐藏二进制性质，不删除或ignore必要回归，不擅自给此资产或用户代码授予许可。

## 待Root协调的最小改动（尚未执行）

| 文件/边界 | 精确拟改内容 |
| --- | --- |
| SOURCE.json | 保留现URL、DER SHA及固定blocklist源，补字节数876、SPKI SHA、类型、仅测试用途、许可未证实/不得随包分发状态；只存文本元数据 |
| src/tls.rs的cfg(test) | 用运行时读取替换include_bytes：要求`KERLICO_TEST_ASSETS_DIR`，读取其下固定`naive/blocked-intermediate.der`；先校验大小/DER SHA，再调用原blocked断言，其他断言及测试名保留 |
| 测试准备工具 | 新建通用或Naive专用准备器，在worker准备期读取元数据，从固定HTTPS URL获取同一字节；默认TLS验证，限制大小/时间/重定向，校验后原子写入被忽略的项目测试资产目录 |
| 资产存放 | 默认建议`source/.private/test-assets/naive/blocked-intermediate.der`；已有根.private忽略和强制拒绝继续生效。获得协调后先把本地现文件复制并核对同摘要再从拟发布文件集合排除，当前尚未移动/删除 |
| 构建/测试编排 | worker显式设置测试资产根；可预先人工准备或使用正确缓存离线运行。测试自身不联网，不由cargo/build.rs自动下载 |
| 发行文件集合 | 源码/通知保留来源与摘要及准备说明；Git archive、工作树打包和release bundle均排除实际私有资产。生产二进制不新增证书嵌入或运行时资产依赖 |

Runtime loader缺变量、缺文件、大小不符、摘要不符都明确失败，错误只报类别/公开期望信息，不打印文件内容、私钥或机器绝对路径。不得回退到仓库旧DER、系统证书库、另一个证书或只检查SPKI便接受不同DER。

准备器正确缓存直接复用；坏缓存失败而非当成功，临时文件校验失败即丢弃。网络获取不是测试通过，不改变资产再分发状态。缺网时仍可由操作者准备完全相同的文件；不能将测试标ignore或遇缺资产返回成功。此方案只是分离“供内部验证获取的材料”与“项目对外再分发的材料”。

### 获协调后在worker可复验的步骤

1. 预先记录现有test名、DER/SPKI摘要及Naive冻结输入；准备器取得876字节、相同DER SHA，metadata不含实际证书字节。
2. 正确缓存下离线运行原拒绝集回归：坏DER拒绝、此SPKI拒绝、正常证书不误拒绝及新增固定SPKI检查全部保留；统计不得减少或ignore。
3. 逐项验证缺变量、缺资产、变动一字节、错大小、错摘要、准备下载失败、无效TLS/重定向都失败，失败不污染正确缓存。
4. 核对测试运行时读的是显式资产目录；关闭网络仍能使用正确缓存，缺网又缺资产明确失败；生产构建不要求资产变量。
5. 在同一Naive源码与最终锁上执行必要包级检查/API探针及受影响验证。既有26项/真实矩阵不自动覆盖这个源码增量。
6. 检查拟提交树与发行源包只有文本来源/摘要，没有DER或任何编码副本、私有目录、真实配置或凭证；原hook不修改，未知二进制规则继续有效。

以上没有执行；Naive文件由Root与其负责人协调后再改，避免覆盖收尾工作。

## 只有未来明确再分发许可后才考虑的manifest方案

当前不启用此方案。若另获可靠权限证据，才可由Root审查保留DER的必要性，考虑仅此固定路径+876字节+上述固定DER SHA+固定`x509-certificate-der`类型的记录，同时保存来源、SPKI摘要、许可证据和测试用途。manifest不能替代许可，也不能靠任意新增`reviewed:true`自授准入。

若将来实现，必须满足：

- `.private`、敏感文件名、私钥、子模块、符号链接/非常规mode、未知二进制仍先拒绝；例外只接受指定常规非执行文件，不能扩展为“所有DER/证书都允许”。
- 只信任明确审查过的manifest内容摘要/版本策略锚；改path/SHA/type/size/许可记录必须重新具体审查。否则修改manifest即可塞入私钥DER，是无效方案。该锚/钩子本身可由同一操作者修改，Git hook不是权限隔离，人工评审与禁止绕过规则不能被算法替代。
- commit检查从索引stage-0 blob读取manifest及资产，不能读工作树文件；push对每个可达commit从其对应tree读取，不能把最新manifest套到历史树，也不能只检查tip。
- manifest严格解析、拒绝重复JSON键/未知字段/非UTF-8/异常mode，普通文本仍按匿名规则检查；无manifest或未审核manifest不能获得二进制例外。
- 回归至少覆盖：精确对象允许；复制到另一路径拒绝；改一字节/改size/type拒绝；伪造/未审核manifest拒绝；私钥DER、PEM私钥、其他二进制始终拒绝；.private伪例外拒绝；索引与工作树不同只信索引；历史树与最新不同逐树判定；历史先加未审资产后补manifest仍在push被拒绝。

本轮没有编写或执行这些hook回归，没有改hook、没有生成生效白名单，也没有批准该DER入Git。
