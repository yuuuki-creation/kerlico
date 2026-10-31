"""阻止在本地工作站误启动构建或测试；不替代worker连接授权。"""
import os
from pathlib import Path
import platform


def require_worker():
    if platform.system() != "Linux" or not Path("/proc/self/status").is_file() or not Path("/proc/self/ns/net").exists():
        raise SystemExit("本工具只允许专用Linux worker的项目工作区运行；禁止本地执行")
    if os.environ.get("KERLICO_WORKER_ALIAS") not in ("perf-01", "perf-02", "perf-03"):
        raise SystemExit("须在已授权worker项目环境明确设置KERLICO_WORKER_ALIAS；别名不是机器身份凭证")
