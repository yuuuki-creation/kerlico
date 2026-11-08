# 测试机

三台机器的别名是 `perf-01`、`perf-02`、`perf-03`。地址、端口、私钥和已知主机记录在仓库根目录的 `.private/machines/`。这个目录不进入 git。旧分支的编译说明把同一批资料放在这里，当前工作区已经有这些文件。

连接用这一条。

```text
ssh -F .private/machines/ssh_config perf-02
```

`perf-02` 跑服务端。另一台跑 mihomo。这些机器的公网高位端口默认不通，测试地址用两台之间已经能互通的地址。
