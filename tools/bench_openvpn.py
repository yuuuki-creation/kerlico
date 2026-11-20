#!/usr/bin/env python3
"""Compare OpenVPN servers at a fixed application bitrate on a local Linux host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import statistics
import subprocess
import sys
import time

import verify_openvpn as ovpn

TICKS = os.sysconf("SC_CLK_TCK")
UDP_PAYLOAD = 1200

def pinned(cpu, args):
    return ["taskset", "-c", cpu, *args]


def cpu_time(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / TICKS


def record_udp_state(folder, sample, server_pid, client_pid):
    for endpoint, pid in (("server", server_pid), ("client", client_pid)):
        for table in ("snmp", "udp"):
            (folder / f"{endpoint}-{sample}-{table}.txt").write_text(
                Path(f"/proc/{pid}/net/{table}").read_text()
            )


def measure_after_warmup(command, pid, folder, timeout):
    deadline = time.monotonic() + timeout
    startup_samples = []
    stop = None
    result = {}
    pending = b""
    with (folder / "iperf.stderr.log").open("wb") as errors, \
            (folder / "iperf.jsonl").open("wb") as output:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors) as process:
            try:
                with selectors.DefaultSelector() as events:
                    events.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("iperf3 stopped reporting")
                        if stop is None:
                            startup_samples.append((time.monotonic(), cpu_time(pid)))
                            remaining = min(remaining, 0.01)
                        if not events.select(remaining):
                            continue
                        chunk = os.read(process.stdout.fileno(), 65_536)
                        if not chunk:
                            break
                        output.write(chunk)
                        lines = (pending + chunk).split(b"\n")
                        pending = lines.pop()
                        for line in lines:
                            message = json.loads(line)
                            if message["event"] == "interval" and not message["data"]["sum"]["omitted"]:
                                stop = time.monotonic(), cpu_time(pid)
                            elif message["event"] == "end":
                                result["end"] = message["data"]
                            elif message["event"] == "error":
                                raise RuntimeError(message["data"])
                if process.wait(timeout=max(0, deadline - time.monotonic())):
                    raise RuntimeError("iperf3 failed")
            finally:
                if process.poll() is None:
                    process.kill()
    if stop is None or "end" not in result:
        raise RuntimeError("iperf3 omitted a required interval or end event")
    # iperf3 may reset its interval statistics before reporting the last
    # warmup interval. Anchor the CPU window to the receiver's measured duration.
    end = result["end"]
    received = end.get("sum_received") or end["sum"]
    measured_start = stop[0] - received["seconds"]
    start = min(startup_samples, key=lambda sample: abs(sample[0] - measured_start))
    if abs(start[0] - measured_start) > 0.05:
        raise RuntimeError("could not align CPU samples to the iperf3 receive window")
    (folder / "iperf.json").write_text(json.dumps(result) + "\n")
    return result, stop[1] - start[1], stop[0] - start[0]


def run(args, prefix, kind, binary, folder, transport, direction, payload, rate):
    folder.mkdir(mode=0o700, parents=True)
    record_datagrams = transport == "udp" or payload == "udp"
    style = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    port, = ovpn.fixtures.free_ports(1, style, ovpn.SERVER)
    origin, = ovpn.fixtures.free_ports(1, socket.SOCK_STREAM, ovpn.ORIGIN)
    stock_args = ["--tun-mtu", "1400", "--mssfix", "0", "--verb", "3"]
    if transport == "tcp":
        stock_args += ["--socket-flags", "TCP_NODELAY"]
    if binary is None:
        server = ovpn.stock(args, args.output, "server", transport, port) + stock_args
    else:
        server = ovpn.kerlico(argparse.Namespace(server=binary), args.output, folder,
                             "server", transport, port)
    client = ovpn.stock(args, args.output, "client", transport, port) + stock_args
    iperf = [args.iperf, "-c", ovpn.ORIGIN, "-p", str(origin), "-b", f"{rate}M",
             "-t", str(args.seconds), "--pacing-timer", "1000"]
    if args.warmup:
        iperf += ["--omit", str(args.warmup), "--json-stream", "--forceflush"]
    else:
        iperf.append("--json")
    if direction == "download":
        iperf.append("-R")
    if payload == "udp":
        iperf += ["-u", "-l", str(UDP_PAYLOAD)]
    else:
        iperf += ["--no-delay", "-l", "8192"]
    with ovpn.fixtures.managed(pinned(args.server_cpus, server), folder, "server") as listener:
        if binary is None:
            ovpn.fixtures.wait_for(listener, lambda: "Initialization Sequence Completed" in listener.text())
        else:
            ovpn.fixtures.wait_for(listener, lambda: "openvpn" in listener.text().splitlines())
        with ovpn.fixtures.managed(pinned("2", prefix + client), folder, "client") as dialer:
            ovpn.fixtures.wait_for(dialer, lambda: "Initialization Sequence Completed" in dialer.text())
            ovpn.command(*prefix, "ip", "route", "replace", f"{ovpn.ORIGIN}/32", "dev", ovpn.TUN)
            with ovpn.fixtures.managed(
                pinned("4", [args.iperf, "-s", "-B", ovpn.ORIGIN, "-p", str(origin), "--json"]),
                folder, "origin",
            ) as receiver:
                ovpn.fixtures.wait_for(receiver, lambda: f":{origin} " in ovpn.command("ss", "-ltnH"))
                pid = listener.process.pid
                if record_datagrams:
                    record_udp_state(folder, "before", pid, dialer.process.pid)
                profile = None
                if args.profile:
                    profile = subprocess.Popen(["perf", "record", "-q", "-o", folder / "perf.data",
                                                "-e", "cpu-clock", "-F", "299", "-C", args.server_cpus,
                                                "--call-graph", "dwarf,4096",
                                                "--", "sleep", str(args.warmup + args.seconds + 1)],
                                               cwd=folder)
                try:
                    command = pinned("3", prefix + iperf)
                    if args.warmup:
                        result, used, wall = measure_after_warmup(
                            command, pid, folder, args.warmup + args.seconds + 12
                        )
                    else:
                        start = time.monotonic()
                        before = cpu_time(pid)
                        measured = subprocess.run(command, capture_output=True,
                                                  timeout=args.seconds + 12)
                        used = cpu_time(pid) - before
                        wall = time.monotonic() - start
                        (folder / "iperf.json").write_bytes(measured.stdout)
                        (folder / "iperf.stderr.log").write_bytes(measured.stderr)
                        measured.check_returncode()
                        result = json.loads(measured.stdout)
                finally:
                    if profile is not None:
                        profile.wait(timeout=args.warmup + args.seconds + 5)
                if "error" in result:
                    raise RuntimeError(result["error"])
                dialer.ensure_alive()
                listener.ensure_alive()
                if record_datagrams:
                    record_udp_state(folder, "after", pid, dialer.process.pid)
    end = result["end"]
    if payload == "udp" and "sum_received" not in end:
        # iperf3 3.9 reports a combined UDP summary. Its sender byte count
        # includes lost datagrams, so count the fixed-size packets delivered.
        received = end["sum"]
        size = (received["packets"] - received["lost_packets"]) * UDP_PAYLOAD
        goodput = size * 8 / received["seconds"] / 1e6
    else:
        received = end["sum_received"]
        size = received["bytes"]
        goodput = received["bits_per_second"] / 1e6
    gbit = size * 8 / 1e9
    row = dict(server=kind, carrier=transport, direction=direction, payload=payload, rate=rate,
               goodput=goodput, received_bytes=size, cpu_seconds=used, wall_seconds=wall,
               cpu_seconds_per_gbit=used / gbit if gbit else None,
               lost_percent=received.get("lost_percent"),
               retransmits=end.get("sum_sent", {}).get("retransmits"))
    (folder / "result.json").write_text(json.dumps(row) + "\n")
    print(json.dumps(row), flush=True)
    return row


def summarize(rows):
    stock = rows["stock"]
    summary = {}
    for name, samples in rows.items():
        if name == "stock":
            continue
        pairs = list(zip(stock, samples, strict=True))
        invalid = [i for i, (a, b) in enumerate(pairs, 1)
                   if abs(a["goodput"] - b["goodput"]) > a["rate"] * 0.02
                   or any(not 0.98 * r["rate"] <= r["goodput"] <= 1.02 * r["rate"]
                          or (r["lost_percent"] or 0) > 0.1
                          or not r["cpu_seconds_per_gbit"] for r in (a, b))]
        valid = [(a, b) for i, (a, b) in enumerate(pairs, 1) if i not in invalid]
        summary[name] = {"valid_rounds": len(valid), "invalid_rounds": invalid}
        if invalid:
            print(f"{name}: excluded rounds {invalid} for bandwidth, UDP loss or missing CPU samples",
                  flush=True)
        if not valid:
            continue
        reductions = [100 * (1 - b["cpu_seconds_per_gbit"] / a["cpu_seconds_per_gbit"])
                      for a, b in valid]
        median = statistics.median(reductions)
        summary[name].update(median_reduction_percent=median, paired_reductions_percent=reductions)
        print(f"{name}: paired CPU per Gbit reduction {median:.2f}% "
              f"(range {min(reductions):.2f}% to {max(reductions):.2f}%)", flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, type=Path, action="append",
                        help="Kerlico executable, repeat to compare builds")
    parser.add_argument("--openvpn", required=True, type=Path)
    parser.add_argument("--iperf", default="iperf3", help="path to the iperf3 executable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--carrier", choices=["tcp", "udp"], nargs="+", default=["udp", "tcp"])
    parser.add_argument("--direction", choices=["upload", "download"], nargs="+",
                        default=["upload", "download"])
    parser.add_argument("--payload", choices=["tcp", "udp"], nargs="+", default=["tcp"])
    parser.add_argument("--rate", type=int, nargs="+", default=[100], metavar="MBIT")
    parser.add_argument("--seconds", type=int, default=12)
    parser.add_argument("--warmup", type=int, default=0,
                        help="omit startup seconds from CPU and throughput (requires iperf3 --json-stream)")
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--server-cpus", default="0-1", help="taskset CPU list shared by all servers")
    parser.add_argument("--profile", action="store_true", help="sample all selected server CPUs with perf")
    parser.add_argument("--gro", action="store_true", help="enable GRO on both test veth endpoints")
    args = parser.parse_args()
    if min(args.rate) < 1 or args.seconds < 1 or args.rounds < 1:
        parser.error("rate, seconds and rounds must be positive")
    if args.warmup < 0:
        parser.error("warmup must be nonnegative")
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run inside a local Linux test host with TUN privileges")
    if os.environ.get("KERLICO_OPENVPN_BENCH_NS") != "1":
        os.execvp("unshare", ["unshare", "--net", "--mount", "--propagation", "private",
                              "env", "KERLICO_OPENVPN_BENCH_NS=1", sys.executable, *sys.argv])
    args.output = args.output.resolve()
    args.openvpn = args.openvpn.resolve(strict=True)
    iperf = shutil.which(args.iperf)
    if iperf is None:
        parser.error(f"iperf3 executable not found: {args.iperf}")
    args.iperf = Path(iperf).resolve(strict=True)
    if args.warmup and "--json-stream" not in ovpn.command(args.iperf, "--help"):
        parser.error("--warmup requires an iperf3 build with --json-stream")
    binaries = [("stock", None), *((f"kerlico-{i}", binary.resolve(strict=True))
                                   for i, binary in enumerate(args.server, 1))]
    args.output.mkdir(mode=0o700, parents=True)
    ovpn.identities(args.output)
    metadata = {
        "kernel": os.uname().release,
        "openvpn": ovpn.command(args.openvpn, "--version").splitlines()[0],
        "iperf": ovpn.command(args.iperf, "--version").splitlines()[0],
        "server_cpus": args.server_cpus,
        "warmup_seconds": args.warmup,
        "veth_gro": args.gro,
        "servers": {name: {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
                    for name, binary in binaries if binary is not None},
    }
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with ovpn.linux_network() as prefix:
        if args.gro:
            ovpn.command("ethtool", "-K", "ovtest-a", "gro", "on")
            ovpn.command(*prefix, "ethtool", "-K", "ovtest-b", "gro", "on")
        for transport in args.carrier:
            for payload in args.payload:
                for direction in args.direction:
                    for rate in args.rate:
                        case = args.output / f"{transport}-{payload}-{direction}-{rate}"
                        rows = {name: [] for name, _ in binaries}
                        for round_id in range(args.rounds):
                            order = binaries if round_id % 2 == 0 else reversed(binaries)
                            for name, binary in order:
                                row = run(args, prefix, name, binary, case / f"{round_id + 1}-{name}",
                                          transport, direction, payload, rate)
                                rows[name].append(row)
                        (case / "summary.json").write_text(json.dumps(summarize(rows), indent=2) + "\n")


if __name__ == "__main__":
    main()
