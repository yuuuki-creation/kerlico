# CLI 语言与诊断呈现

`kerlico --lang zh-CN ...` 和 `kerlico --lang en ...` 显式选择本次调用的界面语言。该全局选项可放在命令前后。没有显式选择时，按 `LC_ALL`、`LC_MESSAGES`、`LANG` 的顺序读取第一个非空环境变量；`zh` locale 使用简体中文，其余值或缺省使用英语。`--` 之后的内容不参与预选语言。

命令名、参数名、模块标识、配置键和 JSON 字段不翻译。两种语言下 `modules` 输出完全相同。帮助、参数解析错误、配置检查成功、监听就绪和顶层错误按所选语言呈现。`help [COMMAND]` 保留命令帮助入口。

`kerlico-core` 提供显式 `Language` 和借用型 `Error::localized(Language)`。原有错误类型与 `Display` 保持不变，库调用方可对同一个错误同时生成两种语言，不依赖进程全局可变状态。顶层错误带稳定类别码，如 `configuration.invalid`、`operation.timeout`、`shutdown.incomplete`。启动和关闭的主要错误递归翻译，回收超时与失败数量保持结构。系统 I/O 保留 `ErrorKind` 与原生错误码，嵌套的本项目错误继续保留具体原因。

翻译目录覆盖当前 23 个协议及 core/config/net/egress/engine/CLI 的静态业务错误、I/O 错误和服务失败详情，并包括历史记录接口的诊断。未知中文详情显示 `[untranslated detail]` 并保留原文；此回退用于未来新增、外部库或动态系统详情，不能计作已翻译。原生操作系统错误仍保留原始文字与错误码。

运行实例通过 `RuntimeOptions { device, language }` 装配设备能力与不可变语种；`Engine::bind_with_options`、`EgressRuntime::start_with_options` 和 `ServiceContext::with_options` 接收同一选项类型。现有便捷构造入口默认英语。`ServiceStatus`、`ServiceContext` 和所属 `ConnectContext` 读取同一个服务语种，因此多个 Engine 或命名出站可以同时使用不同语言。

VLESS Mux 与 XDRIVE 后台任务通过 `Diagnostic { code, error }` 交付稳定事件标识及借用型错误。入站交给 `NodeObserver::diagnostic`，由 Engine 的观察者呈现；出站诊断 sink 固定所属服务的语种。`NodeEvent` 的统计变体不变，诊断呈现不改动错误类型、统计字段或载荷。调用方可替换 sink，而无须从已翻译字符串反推错误。

目录检查在海外 worker 执行。

```sh
python3 tools/check_i18n.py --scope boundary
python3 tools/check_i18n.py --scope all
python3 tools/test_i18n_catalog.py
```

检查器排除 `#[cfg(test)]` 单项及 `src/tests/` 下的测试文件，保留测试模块声明之后的生产代码，枚举 `Error::Config/Protocol/Unsupported`、`rustls::Error::General`、`io::Error::new/other` 与 `ServiceFailure::Protocol/Io` 字面详情。动态 `Error::Config(format!(...))` 的每段中文固定文本都须有目录译文，已覆盖模板单独列出；动态参数仍保留实际值。未知详情、未覆盖模板、重复目录键或无效英译均使检查退出非零。可用 `--protocol vless` 等选项检查单个协议。这是明确范围的源码覆盖检查，不是 Rust 语义分析器，也不代替实际 CLI 或协议测试。

真实 CLI 回归位于 `apps/kerlico/tests/localization.rs`。它通过 Cargo 本次构建的 CLI 子进程核对两种语言的顶级及子命令帮助、未知参数、必需参数、配置成功/失败、23 个已编译协议的具体配置错误、I/O 分类、locale 优先级、模块稳定输出、真实监听提示和进程退出。core 测试验证服务语种相互独立；XDRIVE 测试令实际后台存储操作失败，并核对两种语言的结构化诊断。所有编译、格式、静态检查与测试仅在海外性能机执行。
