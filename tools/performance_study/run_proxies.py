#!/usr/bin/env python3
"""Run paced, byte-verified, role-paired proxy sessions inside socks_bench/veth.sh."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import random
import time
import traceback

from proxies import BUILDERS, ENDPOINT, SERVER, landing_command
from resources import Resources, failure_window
from tls_sample import negotiated
from socks_bench.run import child, marker, udp_kernel_counters

END = ["ip", "netns", "exec", "socks-end"]
PAIRS = ["reference", "kerlico-server", "kerlico-client", "kerlico-landing", "kerlico-both"]


def scheduler_sample():
    before = time.monotonic()
    try:
        lines = Path("/proc/schedstat").read_text().splitlines()
        version = int(lines[0].split()[1])
        cpus = {}
        for line in lines:
            fields = line.split()
            if fields and fields[0].startswith("cpu") and fields[0][3:].isdigit():
                cpus[fields[0]] = int(fields[7])
        if version not in (15, 16, 17) or not cpus:
            raise ValueError("unknown scheduler statistics format")
        return dict(start=before, end=time.monotonic(), version=version, per_cpu_runtime_ns=cpus)
    except (OSError, ValueError, IndexError) as exc:
        return dict(start=before, end=time.monotonic(), error=str(exc))


def wait_front(server, client, folder, port):
    until = time.monotonic() + 12
    while time.monotonic() < until:
        for name, proc in (("server", server), ("client", client)):
            if proc.poll() is not None:
                raise RuntimeError(name + " exited: " + (folder / (name + ".log")).read_text()[-1000:])
        tcp = Path(f"/proc/{client.pid}/net/tcp").read_text()
        tcp6 = Path(f"/proc/{client.pid}/net/tcp6").read_text()
        if any(line.split()[1].endswith(f":{port:04X}") and line.split()[3] == "0A"
               for line in (tcp + tcp6).splitlines() if line.split() and line.split()[0] != "sl"):
            return
        time.sleep(.025)
    raise TimeoutError("client SOCKS listener did not start")


def wait_time(when):
    time.sleep(max(0, when - time.monotonic()))


def network_counts():
    result = {}
    for line in Path("/proc/net/dev").read_text().splitlines():
        name, sep, fields = line.strip().partition(":")
        if sep and name in ("socks-proxy","origin-proxy"):
            values = list(map(int, fields.split()))
            result[name] = dict(rx_bytes=values[0], rx_packets=values[1], rx_drops=values[3],
                                tx_bytes=values[8], tx_packets=values[9], tx_drops=values[11])
    if len(result)!=2:
        raise RuntimeError("dedicated carrier and origin veth counters are unavailable")
    return result


def measure(opts, root, protocol, variant, role, rate, direction):
    # Exclude live listeners and TIME_WAIT on both sides before starting new processes.
    busy = set()
    for ns in ([], END):
        for addr in subprocess.check_output([*ns, "ss", "-H", "-a", "-n", "-t", "-u"], text=True).splitlines():
            fields = addr.split()
            for endpoint in fields[4:6]:
                port = endpoint.rsplit(":", 1)[-1]
                if port.isdigit():
                    busy.add(int(port))
    opts.port, opts.socks, opts.http, opts.aux, opts.chain_port, origin_port = random.sample(
        sorted(set(range(22000, 48000)) - busy), 6)
    origin_addr = f"{opts.origin_ip}:{origin_port}"
    front = f"127.0.0.1:{opts.socks}"
    opts.chain_helpers = []
    landing = role in ("kerlico-landing","kerlico-node-pair")
    server_cmd, client_cmd = BUILDERS[protocol](opts, root, variant, role in ("kerlico-server","kerlico-both","kerlico-node-pair"),
                                                landing or role in ("kerlico-client","kerlico-both"))
    if landing:
        client_cmd = landing_command(opts, root)
    timing = [str(opts.warmup), str(opts.seconds)]
    with ExitStack() as stack:
        def spawn(name, cpu, ns, command):
            return stack.enter_context(child(root / (name + ".log"), *ns, "taskset", "-c", cpu, *command))

        if landing and not opts.separate_origin:
            # The origin lives in the client namespace. Reject a direct local shortcut while allowing traffic arriving via veth.
            rule = ["OUTPUT", "-o", "lo", "-d", ENDPOINT, "-p", "udp" if direction == "udp-echo" else "tcp",
                    "--dport", str(origin_port), "-j", "REJECT"]
            subprocess.run([*END, "iptables", "-A", *rule], check=True)
            stack.callback(subprocess.run, [*END, "iptables", "-D", *rule], check=True)
        helpers = {name: spawn(name, "5", [], command) for name, command in opts.chain_helpers}

        if protocol == "anytls" and variant == "plaintext":
            bridge = Path(__file__).resolve().with_name("tls_bridge.py")
            proc = spawn("tls-bridge", "4", END, [sys.executable, bridge, str(opts.aux), SERVER, str(opts.port),
                                                   root/"cert.pem", root/"key.pem"])
            marker(root/"tls-bridge.log", "listening", proc)
        if protocol == "anytls" and variant.startswith(("shadowtls", "restls", "jls")):
            mode = "tls12" if variant in ("shadowtls1","restls12") else "tls13-no-tickets" if variant=="shadowtls2" else "tls13"
            target = Path(__file__).resolve().with_name("tls_target.py")
            command = [sys.executable, target, str(opts.aux), root/"cert.pem", root/"key.pem", mode]
            if opts.target_fixture:
                command = ["env",f"PERF_TLS_TARGET={opts.aux}",f"PERF_TARGET_TLS_VERSION={mode}",
                           f"PERF_TARGET_CERT={root/'cert.pem'}",f"PERF_TARGET_KEY={root/'key.pem'}",
                           opts.target_fixture,"--ignored","--nocapture","--format","terse","--exact","vless_perf"]
            process = spawn("handshake-target", "5", [], command)
            marker(root/"handshake-target.log", "listening", process)
        tls_capture = protocol == "anytls" and variant in ("official","tls","chrome","ech","padding")
        if tls_capture:
            payload = "((tcp[12] & 0xf0) >> 2)"
            match = f"tcp src port {opts.port} and tcp[{payload}] = 22 and tcp[{payload} + 5] = 2"
            capture = spawn("server-hello", "5", [], ["tcpdump", "-p", "-n", "-U", "-Z", "root", "-c", "1",
                             "-i", "socks-proxy", "-s", "768", "-w", root/"server-hello.pcap", match])
            for _ in range(100):
                if "listening on" in (root/"server-hello.log").read_text():
                    break
                if capture.poll() is not None:
                    raise RuntimeError((root/"server-hello.log").read_text())
                time.sleep(.01)
        if protocol == "hy2" and variant == "port-hop":
            nat = ["iptables", "-t", "nat"]
            rule = ["PREROUTING", "-i", "socks-proxy", "-p", "udp", "--dport", str(opts.aux), "-j", "REDIRECT", "--to-ports", str(opts.port)]
            subprocess.run([*nat, "-A", *rule], check=True)
            stack.callback(subprocess.run, [*nat, "-D", *rule], check=True)
            for port in (opts.port, opts.aux):
                count_rule = ["PREROUTING", "-i", "socks-proxy", "-p", "udp", "--dport", str(port)]
                subprocess.run(["iptables", "-t", "mangle", "-A", *count_rule], check=True)
                stack.callback(subprocess.run, ["iptables", "-t", "mangle", "-D", *count_rule], check=True)
        server = spawn("server", opts.server_cpus, [], server_cmd)
        time.sleep(.15)
        client = spawn("client", opts.client_cpus, END, client_cmd)
        wait_front(server, client, root, opts.socks)
        if opts.io_timeout_ms is not None:
            def carrier_counters():
                return dict(monotonic=time.monotonic(),server_udp=udp_kernel_counters([]),
                            client_udp=udp_kernel_counters(END),interfaces=network_counts())
            initial=carrier_counters()
            def save_carrier_counters():
                (root/"session-counters.json").write_text(json.dumps({"before":initial,"after":carrier_counters()})+"\n")
            stack.callback(save_carrier_counters)
        if opts.perf:
            from perf_events import count_events
            profiling = stack.enter_context(ExitStack())
            profiling.enter_context(count_events(root, server.pid, opts.perf, completed_splices=True))
        def load(name, cpu, command, namespace=END):
            extra=[]
            if opts.tick_hz:
                extra.append(f"KERLICO_BENCH_TICK_HZ={opts.tick_hz}")
            if opts.stagger_tcp_writes:
                extra.append("KERLICO_BENCH_STAGGER_TCP_WRITES=1")
            if opts.io_timeout_ms is not None:
                extra.append(f"KERLICO_BENCH_IO_TIMEOUT_MS={opts.io_timeout_ms}")
                if name=="receive":
                    extra.append(f"KERLICO_BENCH_PROGRESS={root/'verified-blocks.bin'}")
            return spawn(name, cpu, namespace, ["env", f"KERLICO_BENCH_MBPS={rate}", "KERLICO_BENCH_TIMESTAMPS=1", *extra, opts.load, *command])
        origin_ns = ["ip", "netns", "exec", "study-origin"] if opts.separate_origin else END
        if direction == "udp-echo":
            pps = round(rate * 1e6 / (8 * 1200))
            # UDP pattern only requires 1,200 bytes. Use the default fixture buffer at every target rate.
            echo = load("echo", "5", ["udp-echo", origin_addr, "4194304"], origin_ns)
            marker(root / "echo.log", "listening", echo)
            namespaces = {"server": [], "endpoints": END}
            if opts.separate_origin:
                namespaces["origin"] = origin_ns
            before = {key: udp_kernel_counters(ns) for key, ns in namespaces.items()}
            sender = load("send", "4", ["udp-roundtrip", front, *timing, origin_addr, str(pps), "4194304"])
        else:
            first, second = ("send", "receive") if direction == "down" else ("receive", "send")
            a = load(first, "5", [first, origin_addr, *timing], origin_ns)
            marker(root / (first + ".log"), "listening", a)
            b = load(second, "4", [second, front, *timing, origin_addr])
            sender, receiver = (a, b) if direction == "down" else (b, a)
        start, = marker(root / "send.log", "start", sender, 20)
        start = start / 1e9 + opts.warmup
        end = start + opts.seconds
        samplers = {name: Resources(proc.pid, root / (name + "-resources.csv"))
                    for name, proc in {"server": server, "client": client, **helpers}.items()}
        with ExitStack() as sampling:
            for obs in samplers.values():
                sampling.enter_context(obs)
            if opts.separate_origin or opts.scheduler_runtime:
                wait_time(start)
            if opts.scheduler_runtime:
                scheduler_before = scheduler_sample()
            if opts.separate_origin:
                network_start = time.monotonic()
                pre = network_counts()
            wait_time(end)
            if opts.scheduler_runtime:
                scheduler_after = scheduler_sample()
                scheduler = dict(before=scheduler_before, after=scheduler_after, nominal_start=start, nominal_end=end)
                left = scheduler_before.get("per_cpu_runtime_ns", {})
                right = scheduler_after.get("per_cpu_runtime_ns", {})
                if left and left.keys() == right.keys() and all(left[k] <= right[k] for k in left):
                    scheduler["task_runtime_s"] = sum(right[k]-left[k] for k in left)/1e9
                (root/"scheduler-window.json").write_text(json.dumps(scheduler)+"\n")
            if direction == "udp-echo":
                if sender.wait(timeout=4):
                    raise RuntimeError((root / "send.log").read_text()[-1000:])
                sent, verified, duplicates, late, tail = marker(root / "send.log", "udp_result", sender)
                assert sent == pps * opts.seconds
                actual = verified * 1200 * 8 / opts.seconds / 1e6
                row = dict(goodput_mbps=actual, offered_pps=pps, verified_bytes=verified * 1200,
                           lost_packets=sent - verified, sent_packets=sent, duplicates=duplicates,
                           source_late_ms=late / 1e6, tail_late_ms=tail / 1e6)
                for key, ns in namespaces.items():
                    row[key + "_udp_errors"] = {k: v - before[key][k] for k, v in udp_kernel_counters(ns).items()}
                valid_load = duplicates == 0 and (sent - verified) / sent <= .001 and tail <= 3e6 and late < 1e9
            else:
                io_seconds=(opts.io_timeout_ms or 0)/1000
                if receiver.wait(timeout=max(8,io_seconds+5)) or sender.wait(timeout=max(5,io_seconds+2)):
                    raise RuntimeError("load failed: " + (root / "receive.log").read_text()[-500:] +
                                       (root / "send.log").read_text()[-500:])
                sent, late = marker(root / "send.log", "sent", sender)
                received, finish = marker(root / "receive.log", "received", receiver)
                assert received == rate * 125000 * opts.seconds and sent == rate * 125000 * (opts.warmup + opts.seconds)
                actual = received * 8 / 1e6 / (finish / 1e9 - start)
                end = max(end, finish / 1e9)
                row = dict(goodput_mbps=actual, verified_bytes=received, source_late_ms=late / 1e6)
                n, p50, p95, p99, worst = marker(root / "receive.log", "latency_us", receiver)
                row["block_delivery_us"] = dict(samples=n, p50=p50, p95=p95, p99=p99, max=worst)
                assert n == 8 * (opts.tick_hz or 100) * opts.seconds
                valid_load = late < 1e9
            if opts.separate_origin:
                post = network_counts()
                row["network_window_seconds"] = time.monotonic()-network_start
                row["network_start_offset_ms"] = 1000*(network_start-start)
                row["veth"] = {name: {k:v-pre[name][k] for k,v in fields.items()} for name,fields in post.items()}
                row["both_interfaces_observed"] = all(s["rx_packets"]+s["tx_packets"]>0 for s in row["veth"].values())
                valid_load = valid_load and row["both_interfaces_observed"]
        if opts.scheduler_runtime:
            row["scheduler_window"] = scheduler
        if opts.perf:
            profiling.close()
            counts = {}
            for line in (root/"perf-stat.csv").read_text().splitlines():
                fields = line.split(",")
                if len(fields) >= 3 and fields[0][:1].isdigit():
                    counts[fields[2]] = float(fields[0])
            if "syscalls:sys_exit_splice" not in counts or "syscalls:sys_enter_splice" not in counts:
                raise RuntimeError("missing splice event counts")
            row["events_with_warmup_and_connection_setup"] = counts
        for name, obs in samplers.items():
            row[name] = obs.window(start, end)
            row[name]["cpu_s_per_gbit"] = row[name]["cpu_seconds"] / (row["verified_bytes"] * 8e-9) if row["verified_bytes"] else None
        if protocol == "hy2" and variant == "port-hop":
            rules = subprocess.check_output(["iptables","-t","nat","-nvxL","PREROUTING"],text=True)
            (root/"hop-counters.txt").write_text(rules)
            counts = subprocess.check_output(["iptables","-t","mangle","-nvxL","PREROUTING"],text=True)
            (root/"ports-counters.txt").write_text(counts)
            row["carrier_packets_by_port"] = {
                str(port): sum(int(line.split()[0]) for line in counts.splitlines()
                               if f"dpt:{port}" in line.split()) for port in (opts.port,opts.aux)}
            row["both_carrier_ports_observed"] = all(row["carrier_packets_by_port"].values())
        if tls_capture:
            row["tls_server_hello"] = negotiated(root/"server-hello.pcap")
        row["matched_load"] = valid_load and abs(actual / rate - 1) <= .02
        return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--case", action="append", required=True, help="protocol:variant")
    p.add_argument("--rates", nargs="+", type=int, default=[20, 50, 100, 200, 500, 1000])
    p.add_argument("--directions", nargs="+", choices=["up", "down", "udp-echo"], default=["up", "down", "udp-echo"])
    p.add_argument("--roles", nargs="+", choices=[*PAIRS, "kerlico-node-pair"], default=PAIRS)
    p.add_argument("--scheduler-runtime", action="store_true",
                   help="read per-CPU scheduler task time at the two measurement boundaries")
    p.add_argument("--refresh-reference", action="store_true",
                   help="remeasure the reference when resuming an incomplete round for other roles")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--seconds", type=int, default=15)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--bin-dir", type=Path, required=True)
    p.add_argument("--peers", type=Path, required=True)
    p.add_argument("--target-fixture", type=Path, help="use the pinned rustls handshake-target fixture in extension runs")
    p.add_argument("--perf", type=Path, help="profile the listening server in a separate process-event diagnostic")
    p.add_argument("--io-timeout-ms", type=int, help="diagnostic TCP socket timeout and receiver block-completion logging")
    p.add_argument("--tick-hz", type=int, choices=(50,100,200,500,1000), help="application TCP writes per stream per second")
    p.add_argument("--stagger-tcp-writes", action="store_true",
                   help="spread the application TCP writes for each tick across the tick interval")
    p.add_argument("--server-cpus", default="0-1")
    p.add_argument("--client-cpus", default="2-3")
    args = p.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    args.separate_origin = os.environ.get("KERLICO_STUDY_SEPARATE_ORIGIN")=="1"
    args.origin_ip = "10.52.0.2" if args.separate_origin else ENDPOINT
    args.peers = args.peers.resolve()
    args.reference = args.peers
    for name in ("server", "client", "load"):
        setattr(args, name, (args.bin_dir / (name if name == "load" else "kerlico-" + name)).resolve())
    for name in ("xray", "mihomo", "hysteria", "mita", "mieru"):
        setattr(args, name, (args.peers / name).resolve())
    executables = [args.server, args.client, args.load, *args.peers.iterdir()]
    if args.target_fixture:
        args.target_fixture=args.target_fixture.resolve(strict=True)
        executables.append(args.target_fixture)
    if any("chacha8-" in case for case in args.case):
        executables.extend(args.peers.parent / "ss-extra/bin" / n for n in ("sslocal","ssserver"))
    manifest = {"sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in executables if p.is_file()},
                "kernel": os.uname().release, "server_cpus": args.server_cpus, "client_cpus": args.client_cpus,
                "load_cpu": 4, "origin_cpu": 5, "server_ip": SERVER, "origin_ip": args.origin_ip,
                "separate_origin": args.separate_origin,
                "warmup_s": args.warmup, "measured_s": args.seconds}
    meta = args.output / "metadata.json"
    if args.tick_hz:
        if "udp-echo" in args.directions:
            p.error("--tick-hz requires TCP workloads")
        manifest["tcp_ticks_per_second"]=args.tick_hz
    if args.stagger_tcp_writes:
        if "udp-echo" in args.directions:
            p.error("--stagger-tcp-writes requires TCP workloads")
        manifest["stagger_tcp_writes"] = True
        manifest["go_runtime"] = {
            key: os.environ[key] for key in ("GOGC", "GOMEMLIMIT", "GOMAXPROCS") if key in os.environ
        }
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as test_socket:
            manifest["kernel_udp_default_receive_bytes"] = test_socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            manifest["kernel_udp_default_send_bytes"] = test_socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
    if args.io_timeout_ms is not None:
        if args.io_timeout_ms<=0 or "udp-echo" in args.directions:
            p.error("--io-timeout-ms requires a positive timeout and TCP workloads")
        manifest["diagnostic_tcp_io_timeout_ms"]=args.io_timeout_ms
    if args.perf:
        args.perf=args.perf.resolve(strict=True)
        manifest["perf_sha256"]=hashlib.sha256(args.perf.read_bytes()).hexdigest()
        manifest["perf_version"]=subprocess.check_output([args.perf,"--version"],text=True).strip()
    if meta.exists() and json.loads(meta.read_text()) != manifest:
        raise ValueError("existing run has different binaries or parameters")
    meta.write_text(json.dumps(manifest, indent=2) + "\n")
    for label in args.case:
        proto, variant = label.split(":", 1)
        for direction in args.directions:
            for rate in args.rates:
                for r in range(args.rounds):
                    roles = args.roles[r % len(args.roles):] + args.roles[:r % len(args.roles)]
                    base = args.output / label.replace(":", "-").replace("/", "-") / direction / str(rate)
                    def measured(role):
                        path = base / f"{r+1}-{role}" / "result.json"
                        return path.exists() and json.loads(path.read_text())["status"]=="measured"
                    refresh = (args.refresh_reference and "reference" in roles and measured("reference")
                               and any(not measured(role) for role in roles if role!="reference"))
                    for role in roles:
                        root = base / f"{r+1}-{role}"
                        root.mkdir(parents=True, exist_ok=True)
                        prior = root / "result.json"
                        new_reference = role=="reference" and refresh
                        if measured(role) and not new_reference:
                            continue
                        # A fresh attempt always retains earlier process output and samples.
                        attempt = root / f"attempt-{time.time_ns()}"
                        attempt.mkdir()
                        record = dict(protocol=proto, variant=variant, role=role, round=r+1, rate_mbps=rate,
                                      direction=direction, attempt=attempt.name, time_unix=time.time())
                        if new_reference:
                            record["resumed_round_reference"] = True
                        try:
                            record.update(measure(args, attempt, proto, variant, role, rate, direction), status="measured")
                        except Exception as exc:
                            record.update(status="error", error=str(exc), matched_load=False)
                            (attempt / "traceback.txt").write_text(traceback.format_exc())
                            try:
                                failure=failure_window(attempt,args.warmup,args.seconds)
                                if failure is not None:
                                    record["resources_including_time_after_error"]=failure
                            except (OSError,KeyError,ValueError,TypeError) as error:
                                record["failure_resource_error"]=str(error)
                        payload = json.dumps(record, ensure_ascii=False) + "\n"
                        (attempt / "record.json").write_text(payload)
                        tmp = root / "result.tmp"
                        tmp.write_text(payload)
                        tmp.replace(root / "result.json")
                        print(payload, end="", flush=True)


if __name__ == "__main__":
    main()
