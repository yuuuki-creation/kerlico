#!/usr/bin/env python3
"""Turns the JSON lines of `crates/server/tests/vless_perf.rs` into Markdown tables.

usage: report.py RESULTS.jsonl [RESULTS.jsonl ...] > report.md

Per case the three directions are combined into two comparisons that each change one side only:
- server: the Xray server of `xray-control` against the Kerlico server of `xray-to-kerlico`,
  both fed by the same Xray client;
- client: the Xray client of `xray-control` against the Kerlico client of `kerlico-to-xray`,
  both talking to the same Xray server.
Rounds of one case and direction are reduced to their median.
"""
import json
import math
import statistics
import sys
from collections import defaultdict


def load(paths):
    runs = defaultdict(list)
    direct = {}
    failures = []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if row.get("case") == "direct":
                    direct[(row["worker"], row["kind"])] = row["mbps"]
                elif "error" in row:
                    failures.append((row["case"], row["direction"], row["worker"], row["error"]))
                else:
                    runs[(row["case"], row["direction"])].append(row)
    return runs, direct, failures


def median(values):
    values = [value for value in values if value is not None]
    return statistics.median(values) if values else None


def pick(rows, path):
    values = []
    for row in rows:
        node = row
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        values.append(node)
    return median(values)


def summarize(rows, side):
    return {
        "mbps": pick(rows, ["mbps"]),
        "p99": pick(rows, ["probe_p99_us"]),
        "p50": pick(rows, ["probe_p50_us"]),
        "errors": sum(row.get("errors", 0) for row in rows),
        "loss": pick(rows, ["loss_percent"]),
        "cpu": pick(rows, [side, "cpu_percent"]),
        "cpu_gib": pick(rows, [side, "cpu_seconds_per_gib"]),
        "rss": pick(rows, [side, "rss_avg_kb"]),
        "rss_idle": pick(rows, [side, "rss_idle_kb"]),
        "peak": pick(rows, [side, "rss_peak_kb"]),
        "threads": pick(rows, [side, "threads_max"]),
        "fds": pick(rows, [side, "fds_max"]),
        "kind": rows[0].get("kind"),
        "worker": rows[0].get("worker"),
    }


def number(value, digits=0):
    return "-" if value is None else f"{value:,.{digits}f}"


def mib(value):
    return "-" if value is None else f"{value / 1024:.1f}"


def ratio(new, old):
    if new is None or old is None or old == 0:
        return None
    return new / old


def percent(value):
    return "-" if value is None else f"{(value - 1) * 100:+.1f}%"


def geometric_mean(values):
    values = [value for value in values if value]
    return math.exp(sum(math.log(value) for value in values) / len(values)) if values else None


def table(runs, cases, treatment, side, title):
    lines = [f"### {title}", ""]
    lines.append("| 用例 | 机器 | 对照 Mbps | kerlico Mbps | 吞吐比 | 对照 CPU s/GiB | kerlico CPU s/GiB | 对照 CPU% | kerlico CPU% | 对照 RSS MiB | kerlico RSS MiB | RSS 比 | 对照峰值 MiB | kerlico 峰值 MiB | 对照 P99 µs | kerlico P99 µs | 错误 |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    throughput, memory, cpu_gib = [], [], []
    for case in cases:
        control = runs.get((case, "xray-control"))
        other = runs.get((case, treatment))
        if not control or not other:
            continue
        old, new = summarize(control, side), summarize(other, side)
        speed = ratio(new["mbps"], old["mbps"])
        space = ratio(new["rss"], old["rss"])
        work = ratio(new["cpu_gib"], old["cpu_gib"])
        if speed and old["errors"] + new["errors"] == 0:
            throughput.append(speed)
        if space:
            memory.append(space)
        if work:
            cpu_gib.append(work)
        lines.append(
            f"| {case} | {new['worker']} | {number(old['mbps'])} | {number(new['mbps'])} | {percent(speed)} "
            f"| {number(old['cpu_gib'], 2)} | {number(new['cpu_gib'], 2)} | {number(old['cpu'])} | {number(new['cpu'])} "
            f"| {mib(old['rss'])} | {mib(new['rss'])} | {percent(space)} | {mib(old['peak'])} | {mib(new['peak'])} "
            f"| {number(old['p99'])} | {number(new['p99'])} | {old['errors']}/{new['errors']} |"
        )
    lines.append("")
    lines.append(
        f"几何平均：吞吐 {percent(geometric_mean(throughput))}，平均 RSS {percent(geometric_mean(memory))}，"
        f"每 GiB CPU {percent(geometric_mean(cpu_gib))}；"
        f"吞吐高于对照 5% 以上 {sum(1 for r in throughput if r > 1.05)} 个，低于 5% 以上 {sum(1 for r in throughput if r < 0.95)} 个，其余 {sum(1 for r in throughput if 0.95 <= r <= 1.05)} 个。"
    )
    lines.append("")
    return lines


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    runs, direct, failures = load(sys.argv[1:])
    cases = sorted({case for case, _ in runs})
    out = ["# VLESS 压测汇总", ""]
    out.append("直连基线（负载端与回显源在各自核上，不经代理）：")
    out.append("")
    out.append("| 机器 | TCP Mbps | UDP Mbps |")
    out.append("| --- | ---: | ---: |")
    for worker in sorted({worker for worker, _ in direct}):
        out.append(f"| {worker} | {number(direct.get((worker, 'tcp')))} | {number(direct.get((worker, 'udp')))} |")
    out.append("")
    out += table(runs, cases, "xray-to-kerlico", "server", "服务端：Xray 服务端 对 Kerlico 服务端（同一个 Xray 客户端）")
    out += table(runs, cases, "kerlico-to-xray", "client", "客户端：Xray 客户端 对 Kerlico 客户端（同一个 Xray 服务端）")
    if failures:
        out += ["### 没有量出数的组合", ""]
        out += ["| 用例 | 方向 | 机器 | 原因 |", "| --- | --- | --- | --- |"]
        out += [f"| {case} | {direction} | {worker} | {error[:140]} |" for case, direction, worker, error in sorted(failures)]
        out.append("")
    noisy = []
    for (case, direction), rows in sorted(runs.items()):
        if len(rows) > 1:
            values = [row["mbps"] for row in rows if row.get("mbps")]
            if len(values) > 1 and statistics.mean(values):
                noisy.append((case, direction, min(values), max(values), (max(values) - min(values)) / statistics.mean(values) * 100))
    if noisy:
        out += ["### 多轮重复的波动", "", "| 用例 | 方向 | 最小 Mbps | 最大 Mbps | 极差占均值 |", "| --- | --- | ---: | ---: | ---: |"]
        out += [f"| {case} | {direction} | {number(low)} | {number(high)} | {spread:.1f}% |" for case, direction, low, high, spread in noisy]
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
