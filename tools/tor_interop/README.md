# 在worker验证Tor出站

本工具在worker从固定完整源码构建kerlico CLI，再通过原生Arti数据路径请求官方`check.torproject.org`和官方Arti v3 onion。不会运行外部Tor、sing-box或Go后端。当前修订已编写，尚未执行。

只在已确认用途与负载的海外Linux worker运行。先完成整轮源码冻结、根注册和锁文件生成，以及本模块和核心阻塞任务回归。源码快照、清单、作业目录和工具链必须由本次已授权作业明确提供。项目目录及全部祖先须由root或当前有效用户拥有，且不可被组或其他用户写入，不接受`/tmp`下的作业目录。

根任务从Git受管非私有文件生成完整原字节清单，并据此传输干净源码快照。清单是JSON数组，每项包含项目相对`path`、原字节数`bytes`和`sha256`。源码快照不含`.audit`、`.private`、`target`、Python缓存或上游缓存。源码、清单及输出都须位于`--worker-root`指定的同一本次作业目录。清单与输出位于源码快照之外，清单本身也不得是符号链接。工具把清单原字节复制到结果目录，枚举快照中的所有文件，仅忽略根`.git`元数据，要求文件集合与清单完全相等，再核对每项大小和摘要。没有`.git`的传输快照也适用。

工具必须从该快照的`tools/tor_interop/worker.py`启动。它使用本次新建的外置target执行`cargo build --locked --package kerlico --no-default-features --features protocol-tor`，拒绝复用任意传入CLI。Cargo JSON必须报告来自该快照`apps/kerlico/Cargo.toml`的新构建产物，且唯一可执行文件位于本作业target。构建前后和验证结束重新核对完整源码，启动及重启前核对实际CLI摘要。

`build-command.json`保存实际命令和工作目录。`build-record.json`记录源码清单、Cargo.lock、Cargo入口文件摘要、Cargo版本日志、构建输出与完整命令。成功构建并核对产物后才加入实际CLI摘要和字节数，失败或超时也保留该记录和已知字段。公开summary记录build-record摘要。它们只证明本作业的限定Tor功能构建，不代替全默认协议或发行输入验收。最终依赖源码、Rust编译器和环境还须由主任务的构建作业记录绑定。

`--cargo`接受该worker已授权工具链的绝对入口。若它是rustup的Cargo代理链接，工具保留这个入口执行，不能将链接解析成rustup后改变命令含义。工具不接收调用方给出的CLI摘要来替代实际构建。

在项目专用worker目录执行以下命令，路径参数均指该worker自己的项目输入或作业目录。

```sh
KERLICO_WORKER=1 PYTHONDONTWRITEBYTECODE=1 python3 -B "$SOURCE_ROOT/tools/tor_interop/worker.py" \
  --source-root "$SOURCE_ROOT" \
  --source-manifest "$SOURCE_MANIFEST" \
  --worker-root "$WORKER_JOB_ROOT" \
  --worker-alias perf-01 \
  --cargo "$WORKER_CARGO" \
  --public-tor
```

`KERLICO_WORKER`是显式作业门禁，不是机器位置的自动证明。不得在本机设置该标记后运行。

`SOURCE_ROOT`可以是作业目录中的`source`，`SOURCE_MANIFEST`可以是同目录中`inputs/source-manifest.json`。工具在`WORKER_JOB_ROOT`内新建`tor-native-*`结果目录，其中保存独立target、配置、状态及证据。不要把源码根本身设为`--worker-root`，否则输出会污染待验证源码，工具会拒绝。后续源码检查命令也使用外置target并禁用Python字节码写入。

默认检查域名经两个命名Tor实例、公开v3 onion、正常关闭和同一配置重启。回环探测只证明监听就绪。关闭探测socket不能证明建立期`ConnectContext`已经取消，因此工具不再输出`cancelled-early-request`。公网建立期请求取消固定留在`unverified`中。另行执行的Rust受控回归使用生产启动路径，在观察到bootstrap等待后取消真实请求token并观察结束，不能把该组件结果称作公网CLI取消互通。

每个业务请求使用新隔离句柄，因此不要求不同请求得到不同出口IP，也不把相同出口IP当作电路混用证据。

字面IPv4和IPv6测试需在独立准备阶段核对官方检测站的当前地址，再通过`--literal-ipv4`和`--literal-ipv6`传入。工具保持HTTPS服务器名与完整证书验证，不把地址写进公开结果。该准备步骤是测试输入的核对，不是kerlico域名出站的解析步骤。未提供的地址族写入`unverified`，不能登记字面目标矩阵完整通过。

所有监听仅绑定动态保留的空闲`127.0.0.1`端口。若释放保留socket到CLI绑定之间发生竞争，CLI启动失败，工具不抢占已有端口。工具只发信号给自身创建的CLI与进程组，不修改Clash、系统代理、DNS、路由或其他服务。没有namespace配置操作，也没有系统软件安装。

作业创建独立`0700`目录，原始CLI日志、完整配置、命令和Tor状态按`0600`或目录权限保存。HTTP响应头和最多`MAX_RESPONSE + 1`字节响应体保存在私有证据文件中；HTTP失败及不完整响应也保留已观察的数据。目录包含隐私网络信息，只能留在worker或被忽略的私有位置。公开摘要仅含中性worker别名、版本、源码与CLI摘要、阶段、退出码、用例名称和结果，不含地址、真实绝对路径、HTTP负载或出口IP。

源码预检、构建、配置check和网络步骤都在同一结果记录范围内。失败时保存`summary.json`与原始`failure.log`，子进程stdout和stderr分别保留。构建失败或超时没有CLI成功摘要。check失败或越权创建状态会保存已知源码、实际CLI摘要和退出码，网络失败保留CLI原日志及异常。只有不满足Linux worker门禁、作业祖先不可信或无法建立证据目录时，没有可信位置可写日志，此时stdout仍给出失败阶段和错误类型。不能将缺失日志视为运行成功。

工具自身16项回归只在worker执行，不访问Tor网络。临时目录建在当前项目目录内，保留真实祖先检查。构建、产物JSON、HTTP及check失败使用明确的受控夹具，验证记录机制，不算真实Rust构建或CLI通过。

```sh
KERLICO_WORKER=1 PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s tools/tor_interop -p test_worker.py
```

bootstrap、Tor出口策略或官方目标不可达时保留失败。工具不会回退直连、替换代理、放宽TLS验证、改用外部Tor或降低请求内容。`passed-selected-scope`只代表所列实际用例完成；它不代表整个协议、全部地址族或正式发行通过。
