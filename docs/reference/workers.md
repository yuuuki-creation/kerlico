# 历史测试机

此前的远程测试机使用 `perf-01`、`perf-02` 和 `perf-03` 三个别名。历史记录中，`perf-02` 运行服务端，另一台机器运行 mihomo，通过测试机之间可达的地址互通。旧配置使用 `.private/machines/` 存放连接资料，Git 忽略该目录。

新的构建、测试和压测在本机执行。依赖 Linux 内核 WireGuard、TUN 或网络命名空间的检查，在满足这些条件的本机 Linux 环境中执行。macOS 可使用本机 Linux 虚拟机。
