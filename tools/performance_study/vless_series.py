"""Run the source-derived VLESS data paths against Xray over a private veth."""
import argparse
import collections
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("output", type=Path)
    for name in ("fixture", "server", "xray", "catalog"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--case", action="append", default=[])
    p.add_argument("--rates", type=int, nargs="+", default=[20, 50, 100, 200, 500, 1000])
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--tcp-flight-blocks", type=int, choices=range(1, 33),
                   help="fixed number of 32 KiB blocks sent by each stream before reading echoes; default scales to 64 ms of traffic")
    args = p.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    catalog = [r["case"] for r in json.loads(args.catalog.read_text()) if r["allowed"]]
    cases = args.case or catalog
    if set(cases) - set(catalog):
        raise ValueError("unknown or non-traffic case")
    tools = Path(__file__).resolve().parents[1]
    pairings = ["xray-control", "xray-to-kerlico", "kerlico-to-xray", "kerlico-control"]
    limits = dict(rounds=args.rounds, pairings=pairings, measure_s=args.seconds, warmup_s=args.warmup,
                  kernel=os.uname().release, cpus=["0-1","2-3","4-5"], streams=8,
                  tcp_flight_blocks=args.tcp_flight_blocks or "64ms-at-target-capped-at-32")
    for key in ("fixture", "server", "xray", "catalog"):
        limits[key + "_sha256"] = digest(getattr(args, key))
    meta = args.output / "metadata.json"
    if meta.exists() and json.loads(meta.read_text()) != limits:
        raise ValueError("existing series used different inputs")
    meta.write_text(json.dumps(limits, indent=2) + "\n")
    for case, rate in itertools.product(cases, args.rates):
        root = args.output / case / str(rate)
        if (root / "complete.json").exists():
            continue
        work = root / f"run-{time.time_ns()}"
        work.mkdir(parents=True)
        rows = work / "results.jsonl"
        bytes_in_64ms = rate * 125_000 * 64 // 1000
        bytes_per_block_across_streams = limits["streams"] * 32 * 1024
        blocks = (bytes_in_64ms + bytes_per_block_across_streams - 1) // bytes_per_block_across_streams
        flight = args.tcp_flight_blocks or min(32, max(1, blocks))
        env = dict(os.environ, XRAY=str(args.xray.resolve()), PERF_KERLICO=str(args.server.resolve()),
                   VLESS_RUN_DIR=str(work), PERF_VETH="1", PERF_BOTH_ENDS="1", PERF_STREAMS="8", PERF_TARGET_MBPS=str(rate),
                   PERF_SECONDS=str(args.seconds), PERF_WARMUP=str(args.warmup), PERF_ROUNDS=str(args.rounds),
                   PERF_TCP_FLIGHT_BLOCKS=str(flight),
                   PERF_LOAD_CPUS="4-5", PERF_SERVER_CPUS="0-1", PERF_CLIENT_CPUS="2-3",
                   PERF_WORKER="local-arm64-veth", PERF_OUT=str(rows), PERF_CASE="="+case)
        # Use a separate mount, network and PID namespace. A timed-out load cannot leave a test process behind.
        command = ["unshare", "--pid", "--fork", "--kill-child", "--mount-proc", "bash", str(tools/"socks_bench/veth.sh"),
                   "bash", "-ec", 'ip address add 10.51.0.3/24 dev socks-proxy; exec "$@"', "study",
                   str(args.fixture.resolve()), "--ignored", "--nocapture"]
        state = dict(case=case, rate=rate, attempt=work.name)
        with (work / "log").open("w") as log:
            try:
                result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=180 + args.rounds * len(pairings) * (args.seconds + args.warmup + 90))
                state["exit"] = result.returncode
            except subprocess.TimeoutExpired:
                state["error"] = "fixture timeout"
        read = [json.loads(line) for line in rows.read_text().splitlines()] if rows.exists() else []
        actual = [r for r in read if r["case"] == case]
        if any(r.get("kind") == "tcp" and r.get("tcp_flight_blocks") != flight for r in actual):
            raise ValueError("fixture did not record the requested TCP flight size")
        expected = {(n, direction) for n in range(args.rounds) for direction in pairings}
        state["records"] = len(actual)
        state["errors"] = [r.get("error") or r.get("error_notes") for r in actual if r.get("error") or r.get("errors")]
        state["matched_windows"] = sum(bool(r.get("verified_bytes")) and not r.get("errors") and
                                       abs(r.get("mbps",0)/rate-1) <= .02 and r.get("loss_percent",0) <= .1 for r in actual)
        complete = (state.get("exit") == 0 and not state["errors"] and len(actual) == len(expected)
                    and {(r["round"],r["direction"]) for r in actual} == expected)
        (work / "status.json").write_text(json.dumps(state, indent=2) + "\n")
        if complete:
            (root / "complete.json").write_text(json.dumps(state) + "\n")
        print(json.dumps(state), flush=True)


if __name__ == "__main__":
    main()
