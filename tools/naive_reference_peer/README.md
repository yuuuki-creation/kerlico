# Naive 独立参照工具

仅用于专用 worker，须设置 `KERLICO_WORKER_ONLY=1`。禁止在本地编译、格式检查或运行。已在perf-03完成固定构建与限定互通，结果及原资产限制见[验证记录](../../docs/testing/naive.md)。

`build.py --go <项目Go工具链> --work-dir <本项私有工作区> --output-dir <产物目录> --official` 从固定来源准备参照，保存首个 Go 依赖解析结果、构建模块与二进制摘要。构建并发1；不安装系统组件，不启动服务。Caddy使用固定上游发布工作流的两项随附补丁，原stock Caddy组合的编译失败另保留；Go padding参照与Caddy各用独立模块和resolver锁，避免版本合并改变上游服务端的QUIC依赖。`SOURCE.json` 固定完整版本。sing-box 只在测试副本增加一个导出现有 padding codec 的函数，算法不改；原缓存不改。这一路称“固定源码导出参照”，不能登记为原官方 CLI 资产。

`naive-reference -role server -transport h1|h2|h3 -listen <回环端点> -cert <证书> -key <私钥>` 提供测试服务；TCP转发、UoT两版本及单socket Full Cone。H1路径使用sing-box padding规则，与原Caddy H1不一致。

`naive-reference -role probe -transport h1|h2|h3 -server <代理端点> -ca <测试CA> -server-name proxy.invalid -uot-version 1|2` 从标准输入读取JSON行并输出JSON行。所有身份默认只是合成测试值。支持：

```json
{"network":"tcp","host":"127.0.0.1","port":10000,"payload":"AA==","read_len":1,"shutdown":false}
{"network":"udp","host":"127.0.0.1","port":10000,"payload":"AA==","association":"example"}
{"network":"udp-receive","association":"example"}
```

TCP payload与返回都是原字节；测试驱动自行编码目标echo格式。UDP按association复用固定sing UoT连接并返回真实来源；接收超时由外层驱动终止本次探针，测试服务自己的socket也有12秒预算。输入、日志与进程均限项目临时目录，只监听回环。

`caddy-naive-reference` 是固定原插件、显式Caddy版本与两项固定上游发布补丁构建的Caddy程序，独立于上述导出参照；只用H2/H3测试TCP。官方Naive客户端资产同样另列，不由导出参照的通过结果代替。
