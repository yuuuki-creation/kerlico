"""Run paired OpenVPN windows independently so a failed rate does not discard the matrix."""
import argparse
import itertools
import json
from pathlib import Path
import subprocess
import sys
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("output", type=Path)
    p.add_argument("--server", required=True)
    p.add_argument("--client-role", help="run the client comparison against a common stock server")
    p.add_argument("--openvpn", required=True)
    p.add_argument("--iperf", required=True)
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--seconds", type=int, default=20)
    p.add_argument("--warmup", type=int, default=3)
    args = p.parse_args()
    axes = itertools.product(("tcp", "udp"), ("tcp", "udp"), ("upload", "download"), (20, 50, 100, 200, 500, 1000))
    for carrier, payload, direction, rate in axes:
        case = args.output / f"{carrier}-{payload}-{direction}-{rate}"
        if (case / "completed.json").exists():
            continue
        attempt = case / f"run-{time.time_ns()}"
        attempt.mkdir(parents=True)
        command = [sys.executable, "-u", str(Path(__file__).resolve().parents[1] / "bench_openvpn.py"),
                   "--server", args.server, "--openvpn", args.openvpn, "--iperf", args.iperf,
                   "--output", str(attempt / "data"), "--resources", "--carrier", carrier, "--payload", payload,
                   "--direction", direction, "--rate", str(rate), "--rounds", str(args.rounds),
                   "--warmup", str(args.warmup), "--seconds", str(args.seconds)]
        if args.client_role:
            command += ["--client-role", args.client_role]
        with (attempt / "log").open("w") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        record = dict(case=case.name, attempt=attempt.name, exit=result.returncode,
                      measured_windows=len(list(attempt.rglob("result.json"))))
        (attempt / "status.json").write_text(json.dumps(record) + "\n")
        if result.returncode == 0 and record["measured_windows"] == 2 * args.rounds:
            (case / "completed.json").write_text(json.dumps(record) + "\n")
        print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
