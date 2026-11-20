#!/usr/bin/env python3
"""Compare local SOCKS5 servers with byte-verified TCP or UDP traffic."""
import argparse
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_socks import local_port, native


@contextmanager
def child(log, *command):
    with log.open("w") as out:
        proc = subprocess.Popen(command, stdout=out, stderr=out)
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def marker(log, word, process, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for line in log.read_text().splitlines():
            if not line.strip():
                continue
            key, *args = line.split()
            if key == word:
                return list(map(int, args))
        assert process.poll() is None, log.read_text()
        time.sleep(0.002)
    raise TimeoutError((log, word))


def sample(pid):
    before = time.monotonic_ns()
    _, idle = map(float, Path("/proc/uptime").read_text().split())
    after = time.monotonic_ns()
    ticks = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return ((before + after) / 2e9, idle, (int(ticks[11]) + int(ticks[12])) / os.sysconf("SC_CLK_TCK"))


def cpu_result(before, after):
    cores = len(os.sched_getaffinity(0))
    return {
        "process_cpu_seconds": round(after[2] - before[2], 3),
        "guest_cpu_seconds": round(cores * (after[0] - before[0]) - (after[1] - before[1]), 3),
    }


def udp_kernel_counters(namespace):
    if namespace:
        content = subprocess.check_output(
            [*namespace, "cat", "/proc/net/snmp"], text=True,
        )
    else:
        content = Path("/proc/net/snmp").read_text()
    keys, values = [line.split()[1:] for line in content.splitlines() if line.startswith("Udp:")]
    counters = dict(zip(keys, map(int, values)))
    return {key: counters[key] for key in ("InErrors", "RcvbufErrors", "SndbufErrors")}


def udp_result(stack, workload, server, proxy, origin, logs, options):
    echo_log = logs / "echo.log"
    client_log = logs / "roundtrip.log"
    endpoint_buffer = str(options.endpoint_udp_buffer)
    echo = stack.enter_context(workload(echo_log, "3", "udp-echo", origin, endpoint_buffer))
    marker(echo_log, "listening", echo)
    rate = options.packets_per_second
    duration = options.seconds
    endpoint_namespace = ("ip", "netns", "exec", "socks-end") if options.veth else ()
    namespaces = {"proxy": (), "endpoints": endpoint_namespace} if options.veth else {"local": ()}
    kernel_before = {name: udp_kernel_counters(ns) for name, ns in namespaces.items()}
    client = stack.enter_context(workload(client_log, "0", "udp-roundtrip", proxy,
                                          "5", str(duration), origin, str(rate), endpoint_buffer))
    start, = marker(client_log, "start", client)
    start += 5_000_000_000
    time.sleep(max(0, (start - time.monotonic_ns()) / 1e9))
    before = sample(server.pid)
    stop = start + duration * 1_000_000_000
    time.sleep(max(0, (stop - time.monotonic_ns()) / 1e9))
    after = sample(server.pid)
    assert client.wait(timeout=3) == 0, client_log.read_text()
    sent, received, duplicates, lateness, tail_late = marker(client_log, "udp_result", client)
    assert sent == duration * rate and lateness < 1_000_000_000 and tail_late < 3_000_000, client_log.read_text()
    kernel_after = {name: udp_kernel_counters(ns) for name, ns in namespaces.items()}
    kernel_errors = {
        name: {key: value - kernel_before[name][key] for key, value in counts.items()}
        for name, counts in kernel_after.items()
    }
    return {
        "direction": "roundtrip", "offered_packets": sent, "verified_packets": received,
        "duplicates": duplicates, "lost_packets": sent - received,
        "source_late_ms": lateness / 1e6,
        "source_tail_late_ms": tail_late / 1e6,
        "endpoint_udp_buffer_request": options.endpoint_udp_buffer,
        "kernel_udp_errors": kernel_errors,
        "verified_mbps_each_direction": received * 1200 * 8 / (1e6 * duration),
        **cpu_result(before, after),
    }


def check_run(kind, logs, options):
    duration = options.seconds
    direction = options.direction
    veth = options.veth
    proxy = local_port()
    origin = local_port()
    while origin == proxy:
        origin = local_port()
    if veth:
        proxy = ("10.51.0.1", proxy[1])
        origin = ("10.51.0.2", origin[1])
    conf = logs / "proxy.json"
    configuration = native(proxy, False, options.udp)
    if kind == "xray":
        configuration.pop("warp")
        configuration.pop("dns")
        configuration["inbounds"][0].pop("outbound")
        configuration["log"] = {"loglevel": "warning"}
        configuration["outbounds"] = [{"protocol": "freedom"}]
        args = [options.xray.resolve(), "run", "-c", conf]
    else:
        binary = options.baseline_server if kind == "baseline" else options.server
        args = [binary.resolve(), conf]
    conf.write_text(json.dumps(configuration))
    with ExitStack() as stack:
        proxylog = logs / "proxy.log"
        server = stack.enter_context(child(proxylog, "taskset", "-c", "1,2", *args))
        for _ in range(150):
            assert server.poll() is None, proxylog.read_text()
            try:
                with socket.create_connection(proxy, timeout=0.05):
                    break
            except OSError:
                time.sleep(0.025)
        else:
            raise TimeoutError(proxylog)
        def address(addr):
            return f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else addr

        sendlog = logs / "send.log"
        recvlog = logs / "receive.log"
        namespace = ("ip", "netns", "exec", "socks-end") if veth else ()

        def workload(log, cpu, role, endpoint, *args):
            return child(log, *namespace, "taskset", "-c", cpu, options.load.resolve(), role,
                         address(endpoint), *map(address, args))

        if options.udp:
            return {"impl": kind, "transport": "udp",
                    **udp_result(stack, workload, server, proxy, origin, logs, options)}

        timing = ("5", str(duration))

        if direction == "down":
            sender = stack.enter_context(workload(sendlog, "0", "send", origin, *timing))
            marker(sendlog, "listening", sender)
            receiver = stack.enter_context(workload(recvlog, "3", "receive", proxy, *timing, origin))
        else:
            receiver = stack.enter_context(workload(recvlog, "3", "receive", origin, *timing))
            marker(recvlog, "listening", receiver)
            sender = stack.enter_context(workload(sendlog, "0", "send", proxy, *timing, origin))
        start, = marker(sendlog, "start", sender)
        marker(recvlog, "warmed", receiver, 8)
        start += 5_000_000_000
        time.sleep(max(0, (start - time.monotonic_ns()) / 1e9))
        before = sample(server.pid)
        assert receiver.wait(timeout=duration+3) == 0, recvlog.read_text()
        after = sample(server.pid)
        assert sender.wait(timeout=2) == 0, sendlog.read_text()
        sent, lateness = marker(sendlog, "sent", sender)
        received, finished = marker(recvlog, "received", receiver)
        assert received == duration * 62_500_000 and sent == (duration + 5) * 62_500_000
        speed = received * 8e3 / (finished - start)
        assert 495 <= speed <= 505 and lateness < 1_000_000_000
        return {"impl": kind, "transport": "tcp", "direction": direction,
                "verified_bytes": received, "mbps": speed, "source_late_ms": lateness / 1e6,
                **cpu_result(before, after)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--baseline-server", type=Path)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--load", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=12)
    parser.add_argument("--veth", action="store_true")
    parser.add_argument("--direction", choices=("up", "down"), default="down")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--packets-per-second", type=int, default=8000)
    parser.add_argument("--endpoint-udp-buffer", type=int, default=0)
    parser.add_argument("implementations", nargs="+", choices=("kerlico", "xray", "baseline"))
    args = parser.parse_intermixed_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    if args.packets_per_second < 1:
        parser.error("--packets-per-second must be positive")
    if not 0 <= args.endpoint_udp_buffer <= 2**31 - 1:
        parser.error("--endpoint-udp-buffer must be between 0 and 2147483647")
    if "baseline" in args.implementations and args.baseline_server is None:
        parser.error("baseline requires --baseline-server")
    args.output.mkdir(parents=True, exist_ok=False)
    for i, impl in enumerate(args.implementations, 1):
        logs = args.output / f"{i:02}-{impl}"
        logs.mkdir()
        print(json.dumps(check_run(impl, logs, args)), flush=True)


if __name__ == "__main__":
    main()
