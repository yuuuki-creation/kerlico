"""Sample a local Linux process and guest during the load fixture's monotonic window."""
import csv
import os
from pathlib import Path
import re
import statistics
import threading
import time


def failure_window(folder,warmup,seconds):
    """Keep measured CPU and RSS after a workload aborts, without assuming any delivered bytes."""
    sender=folder/"send.log"
    if not sender.exists():
        return None
    marker=re.search(r"^start (\d+)$",sender.read_text(errors="replace"),re.MULTILINE)
    if not marker:
        return None
    start=int(marker[1])/1e9+warmup
    end=start+seconds
    result=dict(scheduled_monotonic_start=start,scheduled_seconds=seconds)
    for role in ("server","client"):
        path=folder/(role+"-resources.csv")
        if not path.exists():
            continue
        with path.open() as source:
            rows=list(csv.DictReader(source))
        within=[r for r in rows if start<=float(r["t"])<=end]
        if not within:
            continue
        first=min(rows,key=lambda r:abs(float(r["t"])-start))
        last=min(rows,key=lambda r:abs(float(r["t"])-end))
        wall=float(last["t"])-float(first["t"])
        if wall<=0:
            continue
        cpu=(int(last["cpu_ns"])-int(first["cpu_ns"]))/1e9
        result[role]=dict(cpu_seconds=cpu,process_cpu_percent=100*cpu/wall,sample_window_s=wall,
                          rss_mean_mib=statistics.mean(int(r["rss_kib"]) for r in within)/1024,
                          rss_peak_mib=max(int(r["rss_kib"]) for r in within)/1024,
                          start_offset_ms=1000*(float(first["t"])-start),end_offset_ms=1000*(float(last["t"])-end))
    return result


def snapshot(pid):
    stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    cpu_ns = time.clock_gettime_ns((~pid << 3) | 2)  # Linux process CPU clock, CPUCLOCK_SCHED
    pages = int(Path(f"/proc/{pid}/statm").read_text().split()[1])
    cpu = list(map(int, Path("/proc/stat").read_text().splitlines()[0].split()[1:9]))
    return dict(t=time.monotonic(), cpu_ns=cpu_ns, uticks=int(stat[11]), sticks=int(stat[12]),
                rss_kib=pages * os.sysconf("SC_PAGE_SIZE") // 1024, threads=int(stat[17]),
                minor_faults=int(stat[7]), major_faults=int(stat[9]),
                guest_busy_ticks=sum(cpu[:3]) + sum(cpu[5:7]), guest_steal_ticks=cpu[7])


class Resources:
    def __init__(self, pid, path):
        self.pid = pid
        self.path = Path(path)
        self.rows = []
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.error = None

    def _run(self):
        try:
            while not self.stop.is_set():
                self.rows.append(snapshot(self.pid))
                self.stop.wait(0.1)
        except Exception as error:
            self.error = error

    def __enter__(self):
        self.rows.append(snapshot(self.pid))
        self.worker.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.worker.join()
        self.rows.append(snapshot(self.pid))
        with self.path.open("w", newline="") as output:
            writer = csv.DictWriter(output, self.rows[0].keys())
            writer.writeheader()
            writer.writerows(self.rows)
        if self.error is not None and exc[0] is None:
            raise self.error

    def window(self, start, end):
        first = min(self.rows, key=lambda r: abs(r["t"] - start))
        last = min(self.rows, key=lambda r: abs(r["t"] - end))
        rows = [r for r in self.rows if start <= r["t"] <= end]
        if not rows or first["t"] >= last["t"]:
            raise RuntimeError("resource samples do not cover the load window")
        ticks = os.sysconf("SC_CLK_TCK")
        cpu_seconds = (last["cpu_ns"] - first["cpu_ns"]) / 1e9
        wall = last["t"] - first["t"]
        return dict(cpu_seconds=cpu_seconds, process_cpu_percent=100 * cpu_seconds / wall,
                    user_cpu_s=(last["uticks"] - first["uticks"]) / ticks,
                    system_cpu_s=(last["sticks"] - first["sticks"]) / ticks,
                    rss_mean_mib=statistics.mean(r["rss_kib"] for r in rows) / 1024,
                    rss_peak_mib=max(r["rss_kib"] for r in rows) / 1024,
                    threads_max=max(r["threads"] for r in rows),
                    minor_faults=last["minor_faults"] - first["minor_faults"],
                    major_faults=last["major_faults"] - first["major_faults"],
                    guest_busy_s=(last["guest_busy_ticks"] - first["guest_busy_ticks"]) / ticks,
                    guest_steal_s=(last["guest_steal_ticks"] - first["guest_steal_ticks"]) / ticks,
                    start_offset_ms=1000 * (first["t"] - start), end_offset_ms=1000 * (last["t"] - end),
                    samples=len(rows), sample_window_s=wall)
