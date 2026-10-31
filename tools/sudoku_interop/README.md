# Sudoku 独立验证工具

状态：固定Mihomo与官方原生CLI已在perf-01用项目内Go1.27.2构建成功，生产源码变更均为0；没有启动监听或互通。纯向量导出与原生构建分别记录于SOURCE.json，CLI配置/矩阵工具仍待执行。仅在专用worker的项目目录运行；所有可执行入口核对Linux、/proc和显式`KERLICO_WORKER_ALIAS=perf-01`（也可perf-02/03），本地直接拒绝。别名只是防误用门禁，不替代实际远端授权。没有本地构建、检查、测试或互通结果。工具不嵌入Rust内核，Python只编排进程/测试目标，Go完整对端始终是固定原生参考程序。

## 固定来源

`SOURCE.json`固定Mihomo提交、归档摘要和涉及的生产文件摘要；官方Sudoku固定v0.5.2.0提交及go.mod/go.sum。主任务已只读核对官方原始归档SHA256及318文件与缓存相同，prepare已强制核对该归档SHA256并完成原生构建；尚未运行原生程序监听或互通。不能把研究用Mihomo向量探针、其他版本的发行二进制或官方Go程序视作同一个对端。

`prepare_peers.py`只把原始固定归档解压到新项目标签，校验固定文件、记录全部源文件和二进制摘要，保留原许可证并构建原程序。使用`go build -mod=readonly`并在构建后复核全源清单，生产源码变更为0；不使用Go/Python承载kerlico业务。现有固定资产满足同一来源和摘要时应直接复用，不重复下载。Go工具链需由worker项目已有路径提供；`GOTOOLCHAIN=local`，不安装或自动下载工具链。官方当前go.mod要求Go1.27.2，SOURCE.json已固定并记录官方Linux amd64工具链URL、SHA256、长度及项目内实际版本/二进制摘要，不能沿用旧研究探针的Go1.26.10而宣称构建成功。

```sh
python3 tools/sudoku_interop/prepare_peers.py --peer mihomo --go "$PROJECT_GO" --archive "$FIXED_MIHOMO_ARCHIVE" --work "$NEW_PEER_JOB"
python3 tools/sudoku_interop/prepare_peers.py --peer official --go "$PROJECT_OFFICIAL_GO" --archive "$FIXED_OFFICIAL_ARCHIVE" --archive-sha256 "$RECORDED_OFFICIAL_SHA256" --work "$NEW_OFFICIAL_PEER_JOB"
```

默认只用已有Go模块缓存；确需从固定go.sum取依赖时，显式`--allow-module-downloads`。网络只用于参考来源/依赖取回，不是互通测试成功证据。所有变量均为worker项目路径；真实路径与原始日志保存在私有目录。

## 纯HKDF、记录、KIP和UoT向量

```sh
python3 tools/sudoku_interop/export_vectors.py --source "$FIXED_MIHOMO_SOURCE" --go "$PROJECT_GO" --work "$NEW_VECTOR_JOB" --output "$PROJECT_ROOT/tools/sudoku_interop/fixtures/mihomo-crypto.json"
```

脚本复制固定源码至新隔离目录，追加`vectors/keys_test.go`和`vectors/record_test.go`两个同包导出桥接；列明生产文件零修改、实际执行的两个测试名、导出桥接和输出摘要。不会修改`reference/.upstream/`，不会启动监听或连接目标，`GOPROXY/GOSUMDB=off`。测试只调用原HKDF、ECDH、RecordConn、KIP和UoT函数；确定epoch/seq只在同包测试对象内赋值，不重写生产密码算法。

导出内容包含初始/会话双向HKDF、X25519合成材料、两种AEAD的四段epoch/seq记录、重放/九级epoch跳跃/坏MAC输入、缩短阈值的原生重钥自检、KIP Hello及控制帧、IPv4/IPv6/域名和0/17/65507字节UoT。参考原UoT可接受65508字节单独登记；Rust普通IP包策略仍限制65507。真实32MiB传输另有Rust集成和CLI重钥套件，不能用缩短阈值自检代替。

Rust直接消费生产私有原语，测试定义位于`crates/protocol-sudoku/tests/vectors/mod.rs`，由lib的cfg(test)模块引入。默认读取上述fixture，也可设置`KERLICO_SUDOKU_VECTORS`。缺失、损坏、错误来源必须明确失败，不自动跳过。fixture已在perf-01生成并核对合成材料和来源，摘要见SOURCE.json；三项Rust消费回归已在rust-r3库快照通过，不外推完整网络互通。

## 原生CLI矩阵

先由主任务完成根/app接线并冻结完整首轮，在worker构建仅相关包与专用CLI，复制二进制到独立bin路径，再运行：

```sh
python3 tools/sudoku_interop/check_configs.py --kerlico "$FIXED_KERLICO_BIN" --work "$NEW_CONFIG_JOB"
python3 tools/sudoku_interop/run.py --peer self --kerlico "$FIXED_KERLICO_BIN" --suite all --cert "$TEST_CERT" --key "$TEST_KEY" --work "$NEW_SELF_JOB"
python3 tools/sudoku_interop/run.py --peer mihomo --kerlico "$FIXED_KERLICO_BIN" --reference "$FIXED_MIHOMO_BIN" --reference-metadata "$MIHOMO_PEER_SOURCE_JSON" --suite all --cert "$TEST_CERT" --key "$TEST_KEY" --work "$NEW_MIHOMO_JOB"
python3 tools/sudoku_interop/run.py --peer official --kerlico "$FIXED_KERLICO_BIN" --reference "$FIXED_OFFICIAL_BIN" --reference-metadata "$OFFICIAL_PEER_SOURCE_JSON" --suite all --cert "$TEST_CERT" --key "$TEST_KEY" --work "$NEW_OFFICIAL_JOB"
```

测试证书只用于合成localhost身份，CA由客户端明确装入，禁止skip-verify。可在worker项目区生成：

```sh
openssl req -x509 -newkey ed25519 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:TRUE -keyout "$TEST_KEY" -out "$TEST_CERT"
```

`--plan-only`仅输出计划，不生成通过记录。`--suite`可独立选择carriers、tables、mux、tls、rekey、credentials、lifecycle，便于按失败维度建立新标签；不以单个基础组合代替全部范围。每标签写入输入二进制摘要、逐组合配置、check/process原始日志、逐负载`results.jsonl`和终态摘要。不覆盖旧日志。失败继续保留，启动失败、入口限制、参考边界、未提供证书分别记录。退出码0只表示没有本次可执行项失败/阻塞；`all_requested_scope_accepted=false`仍表示范围没有全部验收。

- carriers：六载体、三方法、两节点族、两角色、客户端/目标先发分别记录；none只回环显式不安全配置。
- tables：六载体、四方向、pure/packed、默认/单自定义/轮换布局，排除配置本身不合法的全ASCII自定义组合；非法配置由check工具验证。
- mux：六载体on，split另有auto，16流并发及独立FIN。CLI并发只证明并发数据结果；真实单物理载体复用由Rust Engine夹具的物理入口计数另验。
- tls：split的H1/H2和WS H1；自端可强制版本。参考client只有自动版本时另记边界和auto结果，不把它记作强制H1/H2通过。原参考server无证书/私钥字段，工具不添加外部终止器冒充原生服务端TLS。
- rekey：两AEAD、raw/stream/poll/ws、mux on，真实33MiB双向内容和尾部检查，不修改阈值。
- credentials：先用同参数正确seed完成真实TCP控制，再换错误seed，有界拒绝且无目标数据，不得回退到其他身份；配置工具另查双节点独立/重复seed和none门槛。
- lifecycle：有活动流时停止该标签服务进程，观察关闭，再在同端点重启并读写。只终止自身创建的进程组，不接触其他服务。

TCP目标包括IPv4、IPv6和localhost域名，后者只使用本地解析。每包UDP记录0/17/4096/64000/65507字节和来源；参考client经一个原生SOCKS控制连接访问多目标并检查跨族源端口。kerlico client的UDP-forward逐入口固定目标，不把它称为共享多目标关联；真实Full Cone及未预联系来源另由Rust Direct出口集成测试验收。SOCKS入口增加地址首部后可能先超过本地UDP65507上限；该包尚未进入Sudoku，记录entry_limit，不把不发送视作通过。

官方原程序client/server均通配监听。`run.py --peer official`须先创建临时user/net namespace并只启用其中lo；不能创建时停止并保留阻塞，禁止在宿主机回退通配运行。`--isolated-netns`是内部重入标记，必须校验与父namespace不同。该步骤不修改宿主网络配置，也不安装ip/unshare。若worker缺少所需能力，原生官方程序互通继续待验。
