"""对指定 Linux 进程和整机进行有界采样。"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import time
from typing import Any

_TICKS = os.sysconf("SC_CLK_TCK")
_ALLOWED_LABELS = frozenset(("server", "client", "echo"))
_IO_KEYS = ("rchar", "wchar", "syscr", "syscw", "read_bytes", "write_bytes", "cancelled_write_bytes")
_MAX_INTERVALS = 300


class SampleError(RuntimeError):
    """关键进程或关键字段不可用。"""


def _read_text(path: Path, description: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SampleError(f"无法读取{description}") from exc


def _process(pid: int) -> dict[str, Any]:
    base = Path("/proc") / str(pid)
    stat = _read_text(base / "stat", "进程 stat")
    # comm 可含空格和右括号；字段从最后的右括号之后开始。
    close = stat.rfind(")")
    if close < 0 or "(" not in stat[:close]:
        raise SampleError("进程 stat 格式无效")
    fields = stat[close + 1:].split()
    try:
        user_ticks = int(fields[11])
        system_ticks = int(fields[12])
        start_ticks = int(fields[19])
        if fields[0] in ("Z", "X", "x"):
            raise SampleError("关键进程已退出")
    except (IndexError, ValueError) as exc:
        raise SampleError("进程 CPU 字段缺失或无效") from exc

    status_text = _read_text(base / "status", "进程 status")
    status = dict(line.split(":", 1) for line in status_text.splitlines() if ":" in line)
    try:
        rss_parts = status["VmRSS"].split()
        if len(rss_parts) != 2 or rss_parts[1] != "kB":
            raise ValueError("RSS 单位无效")
        rss_kib = int(rss_parts[0])
        threads = int(status["Threads"].strip())
        if rss_kib < 0 or threads <= 0:
            raise ValueError("进程字段无效")
    except (KeyError, ValueError) as exc:
        raise SampleError("进程 RSS 或线程字段缺失或无效") from exc

    # statm 是额外的可审计原始值；VmRSS 是统计口径。
    try:
        statm_parts = (base / "statm").read_text(encoding="utf-8").split()
        resident_pages = int(statm_parts[1])
    except (OSError, UnicodeError, ValueError, IndexError):
        resident_pages = None

    try:
        fd_count = sum(1 for _ in (base / "fd").iterdir())
    except OSError:
        fd_count = None
    try:
        task_count = sum(1 for _ in (base / "task").iterdir())
    except OSError:
        task_count = None
    try:
        io_text = (base / "io").read_text(encoding="utf-8")
        io_values = dict(line.split(":", 1) for line in io_text.splitlines() if ":" in line)
        io_counters = {}
        for key in _IO_KEYS:
            try:
                io_counters[key] = int(io_values[key].strip())
            except (KeyError, ValueError):
                io_counters[key] = None
    except (OSError, UnicodeError):
        io_counters = {key: None for key in _IO_KEYS}

    return {
        "pid": pid,
        "start_ticks": start_ticks,
        "user_ticks": user_ticks,
        "system_ticks": system_ticks,
        "rss_kib": rss_kib,
        "statm_resident_pages": resident_pages,
        "fd_count": fd_count,
        "threads": threads,
        "task_count": task_count,
        "io": io_counters,
    }


def _system() -> dict[str, Any]:
    text = _read_text(Path("/proc/stat"), "系统 stat")
    line = next((line for line in text.splitlines() if line.startswith("cpu ")), None)
    if line is None:
        raise SampleError("系统 CPU 字段缺失")
    try:
        values = [int(value) for value in line.split()[1:]]
        if len(values) < 8:
            raise ValueError("系统 CPU 字段不足")
        # guest 已包含在 user/nice 中，不能重复计入总量。
        total = sum(values[:8])
        idle, iowait, steal = values[3], values[4], values[7]
    except ValueError as exc:
        raise SampleError("系统 CPU 字段无效") from exc
    load = _read_text(Path("/proc/loadavg"), "系统负载")
    try:
        load_values = [float(value) for value in load.split()[:3]]
        if len(load_values) != 3 or not all(math.isfinite(value) for value in load_values):
            raise ValueError("系统负载字段不足")
    except ValueError as exc:
        raise SampleError("系统负载字段无效") from exc
    return {"total_ticks": total, "idle_ticks": idle, "iowait_ticks": iowait, "steal_ticks": steal, "load": load_values}


def _snapshot(pids: dict[str, int], previous: dict[str, Any] | None) -> dict[str, Any]:
    processes = {}
    for label, pid in pids.items():
        try:
            processes[label] = _process(pid)
        except SampleError as exc:
            raise SampleError(f"{label}：{exc}") from exc
    system = _system()
    wall_ns, monotonic_ns = time.time_ns(), time.monotonic_ns()
    sample = {"time_ns": wall_ns, "monotonic_ns": monotonic_ns, "processes": processes, "system": system}
    if previous is None:
        for value in processes.values():
            value["cpu_percent"] = None
        system.update({"busy_percent": None, "iowait_percent": None, "steal_percent": None})
        return sample
    elapsed = (monotonic_ns - previous["monotonic_ns"]) / 1e9
    if elapsed <= 0:
        raise SampleError("采样时间没有前进")
    for label, value in processes.items():
        before = previous["processes"][label]
        if value["start_ticks"] != before["start_ticks"]:
            raise SampleError(f"关键进程已退出或 PID 已重用：{label}")
        ticks = (value["user_ticks"] - before["user_ticks"] + value["system_ticks"] - before["system_ticks"])
        if ticks < 0:
            raise SampleError(f"进程 CPU 计数回退：{label}")
        value["cpu_percent"] = 100.0 * ticks / _TICKS / elapsed
    old = previous["system"]
    total = system["total_ticks"] - old["total_ticks"]
    idle = system["idle_ticks"] - old["idle_ticks"]
    iowait = system["iowait_ticks"] - old["iowait_ticks"]
    steal = system["steal_ticks"] - old["steal_ticks"]
    if total <= 0 or min(idle, iowait, steal) < 0:
        raise SampleError("系统 CPU 计数无效")
    system["busy_percent"] = 100.0 * (total - idle - iowait) / total
    system["iowait_percent"] = 100.0 * iowait / total
    system["steal_percent"] = 100.0 * steal / total
    return sample


def _peak(values: list[int | float | None]) -> int | float | None:
    available = [value for value in values if value is not None]
    return max(available) if available else None


def _delta(first: int | None, last: int | None) -> int | None:
    if first is None or last is None or last < first:
        return None
    return last - first


def _summary(samples: list[dict[str, Any]], pids: dict[str, int], planned_ns: int, duration: float, interval: float) -> dict[str, Any]:
    first, last = samples[0], samples[-1]
    elapsed = (last["monotonic_ns"] - first["monotonic_ns"]) / 1e9
    processes = {}
    for label in pids:
        rows = [sample["processes"][label] for sample in samples]
        user = (rows[-1]["user_ticks"] - rows[0]["user_ticks"]) / _TICKS
        system = (rows[-1]["system_ticks"] - rows[0]["system_ticks"]) / _TICKS
        processes[label] = {
            "cpu_percent_average": 100.0 * (user + system) / elapsed,
            "cpu_percent_sample_peak": _peak([row["cpu_percent"] for row in rows]),
            "user_cpu_seconds": user,
            "system_cpu_seconds": system,
            "rss_mib_average": sum(row["rss_kib"] for row in rows) / len(rows) / 1024,
            "rss_mib_sample_peak": max(row["rss_kib"] for row in rows) / 1024,
            "fd_sample_peak": None if any(row["fd_count"] is None for row in rows) else _peak([row["fd_count"] for row in rows]),
            "fd_samples_available": sum(row["fd_count"] is not None for row in rows),
            "threads_sample_peak": max(row["threads"] for row in rows),
            "task_sample_peak": None if any(row["task_count"] is None for row in rows) else _peak([row["task_count"] for row in rows]),
            "task_samples_available": sum(row["task_count"] is not None for row in rows),
            "io_delta": {key: _delta(rows[0]["io"][key], rows[-1]["io"][key]) for key in _IO_KEYS},
        }
    start_cpu, end_cpu = first["system"], last["system"]
    cpu_total = end_cpu["total_ticks"] - start_cpu["total_ticks"]
    idle = end_cpu["idle_ticks"] - start_cpu["idle_ticks"]
    iowait = end_cpu["iowait_ticks"] - start_cpu["iowait_ticks"]
    steal = end_cpu["steal_ticks"] - start_cpu["steal_ticks"]
    system = {
        "cpu_busy_percent_average": 100.0 * (cpu_total - idle - iowait) / cpu_total,
        "cpu_busy_percent_sample_peak": _peak([s["system"]["busy_percent"] for s in samples]),
        "iowait_percent_average": 100.0 * iowait / cpu_total,
        "iowait_percent_sample_peak": _peak([s["system"]["iowait_percent"] for s in samples]),
        "steal_percent_average": 100.0 * steal / cpu_total,
        "steal_percent_sample_peak": _peak([s["system"]["steal_percent"] for s in samples]),
        "load_average": [sum(s["system"]["load"][i] for s in samples) / len(samples) for i in range(3)],
        "load_sample_peak": [max(s["system"]["load"][i] for s in samples) for i in range(3)],
    }
    return {
        "planned_start_ns": planned_ns,
        "actual_start_ns": first["time_ns"],
        "actual_end_ns": last["time_ns"],
        "actual_duration_seconds": elapsed,
        "requested_duration_seconds": duration,
        "sampling_interval_seconds": interval,
        "sample_count": len(samples),
        "clock_ticks_per_second": _TICKS,
        "processes": processes,
        "system": system,
    }


def _write(output: Path, payload: dict[str, Any]) -> None:
    output = Path(output)
    temporary = output.with_name(output.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def sample_processes(pids: dict[str, int], start_ns: int, duration: float, output: Path, interval: float = 0.2) -> dict:
    """按计划时间采样；输出 JSON 并返回摘要，关键进程失效时写错误并抛异常。"""
    if not pids or not set(pids).issubset(_ALLOWED_LABELS):
        raise ValueError("进程标签只能是 server、client、echo")
    if any(not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 for pid in pids.values()):
        raise ValueError("进程 PID 必须是正整数")
    if len(set(pids.values())) != len(pids):
        raise ValueError("进程标签必须对应不同 PID")
    if not isinstance(start_ns, int) or isinstance(start_ns, bool) or start_ns <= 0:
        raise ValueError("计划起始时间必须是 Unix 纳秒")
    if not math.isfinite(duration) or not math.isfinite(interval) or duration <= 0 or interval <= 0:
        raise ValueError("持续时间和采样间隔必须是正数")
    actual_interval = max(interval, duration / _MAX_INTERVALS)
    samples: list[dict[str, Any]] = []
    try:
        while True:
            remaining = (start_ns - time.time_ns()) / 1e9
            if remaining <= 0:
                break
            time.sleep(min(remaining, 1.0))
        samples.append(_snapshot(pids, None))
        start_mono = samples[0]["monotonic_ns"]
        end_mono = start_mono + round(duration * 1e9)
        slot = 1
        while True:
            target = min(start_mono + round(slot * actual_interval * 1e9), end_mono)
            while True:
                remaining = (target - time.monotonic_ns()) / 1e9
                if remaining <= 0:
                    break
                time.sleep(remaining)
            samples.append(_snapshot(pids, samples[-1]))
            if target == end_mono:
                break
            # 慢采样跳过已错过的槽，避免瞬时重复采样和无限增长。
            slot = max(slot + 1, int((time.monotonic_ns() - start_mono) / (actual_interval * 1e9)) + 1)
        summary = _summary(samples, pids, start_ns, duration, actual_interval)
        _write(output, {"status": "ok", "summary": summary, "samples": samples})
        return summary
    except SampleError as exc:
        _write(output, {"status": "error", "error": str(exc), "planned_start_ns": start_ns, "samples": samples})
        raise
