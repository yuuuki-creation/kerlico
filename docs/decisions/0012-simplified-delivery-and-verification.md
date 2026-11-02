# 0012 精简交付与验证

状态：已确认。日期：2026-11-02。

用户要求去除繁杂测试和文档中的防御性表述，按简洁计划完成项目。本决定取代 `0007` 第 3、4 步的验证范围和 `build-and-test.md` 的逐次记录要求。

## 决定

1. **发行门禁只有一个**：`tools/worker_gate.sh` 在一台 worker 上对目标提交执行 `cargo fmt --check`、全工作区严格 Clippy、全工作区测试和 release 构建。四项通过即可发版。
2. **日常修改**：在 worker 运行受影响 crate 的 `cargo test -p` 与 `cargo clippy -p`。
3. **真实对端互通**：只在线格式或握手代码变化时运行该协议的 `tools/interop_*`。全协议矩阵不是发版条件。
4. **记录**：`STATUS.md` 只保留最新门禁结果；`docs/testing/` 保留既有历史，不再按批次追加。参考端差异写进对应接口文档。
5. **一次性诊断脚本**用完即删，不进入仓库。

## 影响

- SSR、Sudoku、WireGuard 的全矩阵不再重跑。它们的既有结果见 `docs/testing/`。
- 跨进程设备 daemon/IPC 移出计划，等出现多进程部署需求再做。
- 排期统一在 `STATUS.md` 的完成计划。
