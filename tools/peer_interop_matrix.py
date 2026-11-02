#!/usr/bin/env python3
"""在 worker 上按表运行真实对端互通脚本：单项限时，失败记录后继续。

对端路径和私有目标地址放在 worker 私有的 peers.json：{"sing-box": "<绝对路径>", ...}。缺对端的作业记为 skipped。
结果写入 <out>/status.jsonl，原始日志和工作目录留在 <out>，不入库。
"""
import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

MINUTE = 60


@dataclass(frozen=True)
class Job:
    name: str
    protocol: str
    machine: str
    argv: tuple[str, ...]
    lane: int = 0
    timeout: int = 20 * MINUTE
    peers: tuple[str, ...] = field(default=())


def job(name, protocol, machine, script, *args, lane=0, timeout=20 * MINUTE):
    argv = (script, *args)
    peers = tuple(sorted({match for arg in argv for match in re.findall(r"\{peer:([\w.-]+)\}", arg)}))
    return Job(name, protocol, machine, argv, lane, timeout, peers)


K = "{kerlico}"
W = "{work}"
JOBS = [
    # perf-03：轻量协议，串行，不在该机构建
    job("shadowsocks-sing-box", "Shadowsocks", "perf-03", "interop_shadowsocks.py", "--kerlico", K, "--peer", "{peer:sing-box}", "--peer-kind", "sing-box", "--work", W),
    job("shadowsocks-xray", "Shadowsocks", "perf-03", "interop_shadowsocks.py", "--kerlico", K, "--peer", "{peer:xray}", "--peer-kind", "xray", "--udp-sizes", "3,4096", "--work", W),
    job("snell-sing-box", "Snell", "perf-03", "interop_snell.py", "--kerlico", K, "--reference", "{peer:sing-box}", "--work-dir", W),
    job("snell-official", "Snell", "perf-03", "interop_snell_official.py", "--kerlico", K, "--server-root", "{peer:snell-official-root}", "--work-dir", W),
    job("hysteria1-sing-box", "Hysteria1", "perf-03", "interop_hysteria1.py", "--kerlico", K, "--reference", "{peer:sing-box}", "--reference-kind", "sing-box", "--work-dir", W),
    job("hysteria1-official", "Hysteria1", "perf-03", "interop_hysteria1.py", "--kerlico", K, "--reference", "{peer:hysteria1}", "--reference-kind", "official", "--work-dir", W),
    job("hysteria2-native", "Hysteria2", "perf-03", "interop_hysteria2.py", "--kerlico", K, "--peer", "{peer:hysteria2}", "--peer-kind", "native", "--work", W),
    job("hysteria2-sing-box", "Hysteria2", "perf-03", "interop_hysteria2.py", "--kerlico", K, "--peer", "{peer:sing-box}", "--peer-kind", "sing-box", "--work", W),
    job("hysteria2-xray", "Hysteria2", "perf-03", "interop_hysteria2.py", "--kerlico", K, "--peer", "{peer:xray}", "--peer-kind", "xray", "--udp-sizes", "3,4096", "--work", W),
    job("tuic-mihomo", "TUIC", "perf-03", "interop_tuic.py", "--kerlico", K, "--reference", "{peer:mihomo}", "--backend", "mihomo", "--work-dir", W, "--full"),
    job("tuic-sing-box", "TUIC", "perf-03", "interop_tuic.py", "--kerlico", K, "--reference", "{peer:sing-box}", "--backend", "sing-box", "--work-dir", W, "--full"),
    job("shadowquic-go-v2", "ShadowQUIC", "perf-03", "interop_shadowquic.py", "--kerlico", K, "--reference", "{peer:shadowquic-reference}", "--cover", "{peer:shadowquic-cover}", "--work-dir", W, "--full", "--versions", "v2"),
    job("shadowquic-negative", "ShadowQUIC", "perf-03", "interop_shadowquic_reference_negative.py", "--kerlico", K, "--reference-root", "{peer:shadowquic-reference-root}", "--cover", "{peer:shadowquic-cover}", "--work-dir", W),
    job("anytls-sing-box", "AnyTLS", "perf-03", "interop_anytls_app.py", "--kerlico", "{peer:kerlico-anytls-only}", "--stripped", "{peer:kerlico-none}", "--reference", "{peer:sing-box}", "--work-dir", W),
    job("shadowtls-sing-box", "ShadowTLS", "perf-03", "interop_shadowtls.py", "--kerlico", K, "--sing-box", "{peer:sing-box}", "--work-dir", W, timeout=30 * MINUTE),
    job("shadowtls-official", "ShadowTLS", "perf-03", "interop_shadowtls.py", "--kerlico", K, "--sing-box", "{peer:sing-box}", "--official-server", "{peer:shadowtls-official}", "--work-dir", W, timeout=30 * MINUTE),
    job("mieru-mihomo", "Mieru", "perf-03", "interop_mieru.py", "--kerlico", K, "--reference", "{peer:mihomo}", "--reference-kind", "mihomo", "--pattern-encoder", "{peer:mieru-reference}", "--work-dir", W),
    job("vmess-xray", "VMess", "perf-03", "interop_vmess.py", "--backend", "xray", "--kerlico", K, "--reference", "{peer:xray}", "--work-dir", W, "--full", "--udp-sizes", "17,1200"),
    job("vmess-sing-box", "VMess", "perf-03", "interop_vmess.py", "--backend", "sing-box", "--kerlico", K, "--reference", "{peer:sing-box}", "--work-dir", W, "--full"),
    # perf-01 通道 0：VLESS 重矩阵
    job("vless-xray", "VLESS", "perf-01", "interop_vless.py", "--kerlico", K, "--reference", "{peer:xray}", "--backend", "xray", "--work-dir", W),
    job("vless-sing-box", "VLESS", "perf-01", "interop_vless.py", "--kerlico", K, "--reference", "{peer:sing-box}", "--backend", "sing-box", "--work-dir", W),
    job("vless-packetaddr", "VLESS", "perf-01", "interop_vless_packetaddr.py", "--kerlico", K, "--reference", "{peer:sing-box}", "--work-dir", W),
    job("vless-split", "VLESS", "perf-01", "interop_vless_split.py", "--kerlico", K, "--reference", "{peer:xray}", "--work-dir", W),
    job("vless-xdrive", "VLESS", "perf-01", "interop_vless_xdrive.py", "--kerlico", K, "--reference", "{peer:xray}", "--work-dir", W),
    job("vless-client-matrix", "VLESS", "perf-01", "interop_vless_matrix.py", "--kerlico", K, "--reference", "{peer:xray}", "--work-dir", W, "--full", "--workers", "3", timeout=45 * MINUTE),
    job("vless-server-matrix", "VLESS", "perf-01", "interop_vless_server.py", "--kerlico", K, "--reference", "{peer:xray}", "--work-dir", W, "--matrix", "--full", "--workers", "3", timeout=45 * MINUTE),
    # perf-01 通道 1：其余本机进程类对端
    job("trojan-xray", "Trojan", "perf-01", "interop_trojan.py", "--kerlico", K, "--reference", "{peer:xray}", "--work-dir", W, lane=1),
    job("ss2022-matrix", "SS2022", "perf-01", "interop_ss2022.py", "--peer", "{peer:ss2022-peer}", "--sing-box", "{peer:sing-box}", "--xray", "{peer:xray}", "--work", W, "--udp-size", "4096", lane=1),
    job("ss2022-chain", "SS2022", "perf-01", "interop_ss2022_chain.py", "--peer", "{peer:ss2022-peer}", "--xray", "{peer:xray}", "--work", W, lane=1),
    job("ss2022-cli", "SS2022", "perf-01", "interop_ss2022_cli.py", "--kerlico", "{peer:kerlico-ss2022-only}", "--minimal", "{peer:kerlico-minimal}", "--probe", "{peer:ss2022-probe}", "--work", W, lane=1),
    job("shadowsocksr-python", "ShadowsocksR", "perf-01", "interop_shadowsocksr.py", "--kerlico", K, "--peer", "{peer:shadowsocksr-python}", "--peer-kind", "python", "--reference-source", "{peer:shadowsocksr-python}", "--work", W, lane=1, timeout=30 * MINUTE),
    job("shadowsocksr-mihomo", "ShadowsocksR", "perf-01", "interop_shadowsocksr.py", "--kerlico", K, "--peer", "{peer:mihomo-ssr}", "--peer-kind", "mihomo", "--directions", "server", "--work", W, lane=1, timeout=30 * MINUTE),
    job("http-socks-sing-box", "HTTP+SOCKS", "perf-01", "interop_local_proxies.py", "--kerlico", K, "--peer", "{peer:sing-box}", "--work", W, lane=1),
    job("gost-relay", "Gost Relay", "perf-01", "interop_gost_relay.py", "--kerlico", K, "--peer", "{peer:gost}", "--peer-sha256", "{sha256:gost}", "--work-dir", W, lane=1),
    job("ssh-openssh", "SSH", "perf-01", "interop_ssh.py", "--kerlico", K, "--work-dir", W, lane=1),
    job("naive-matrix", "Naive", "perf-01", "interop_naive.py", "--kerlico", K, "--go-reference", "{peer:naive-reference}", "--rust-probe", "{peer:naive-probe}", "--sing-box", "{peer:sing-box-naive}", "--caddy", "{peer:caddy-naive}", "--official", "{peer:naive-official}", "--work-dir", W, "--full", "--boundary-representative", "--boundary-sizes", "0", "65507", lane=1, timeout=45 * MINUTE),
    job("naive-coexist", "Naive", "perf-01", "interop_naive_coexist.py", "--kerlico", K, "--work-dir", W, lane=1),
    job("sudoku-mihomo", "Sudoku", "perf-01", "sudoku_interop/run.py", "--peer", "mihomo", "--kerlico", K, "--reference", "{peer:mihomo-sudoku}", "--reference-metadata", "{peer:mihomo-sudoku-metadata}", "--suite", "all", "--work", W, lane=1, timeout=40 * MINUTE),
    job("sudoku-official", "Sudoku", "perf-01", "sudoku_interop/run.py", "--peer", "official", "--kerlico", K, "--reference", "{peer:sudoku-official}", "--reference-metadata", "{peer:sudoku-official-metadata}", "--suite", "all", "--work", W, lane=1, timeout=40 * MINUTE),
    job("wireguard-go", "WireGuard", "perf-01", "wireguard_interop/run.py", "--rust-peer", "{peer:wireguard-rust-peer}", "--go-peer", "{peer:wireguard-go-peer}", "--run-dir", W, "--jobs", "4", lane=1, timeout=30 * MINUTE),
    # perf-02：容器类隧道与官方 TrustTunnel
    job("masque-xray", "MASQUE", "perf-02", "interop_masque.py", "--kerlico", K, "--xray", "{peer:xray-masque}", "--work-dir", W),
    job("openvpn", "OpenVPN", "perf-02", "interop_openvpn.py", "--kerlico", K, "--work-dir", W, timeout=30 * MINUTE),
    job("openconnect-ocserv", "OpenConnect", "perf-02", "interop_openconnect.py", "--kerlico", K),
    job("tailscale-headscale", "Tailscale", "perf-02", "interop_tailscale.py", "--kerlico", K),
    job("easytier", "EasyTier", "perf-02", "interop_easytier.py", "--kerlico", K, "--easytier-dir", "{peer:easytier-dir}", "--work-dir", W),
    job("zerotier", "ZeroTier", "perf-02", "interop_zerotier.py", "--kerlico", K, "--work-dir", W),
    job("trusttunnel-official-endpoint", "TrustTunnel", "perf-02", "interop_trusttunnel.py", "--kerlico", K, "--work-dir", W, "--mode", "official", "--peer-endpoint", "{peer:trusttunnel-endpoint}", "--peer-endpoint-sha256", "{sha256:trusttunnel-endpoint}", "--peer-client", "{peer:trusttunnel-client}", "--peer-client-sha256", "{sha256:trusttunnel-client}", "--target4", "{value:trusttunnel-target4}", timeout=30 * MINUTE),
    job("trusttunnel-mihomo", "TrustTunnel", "perf-02", "interop_trusttunnel.py", "--kerlico", K, "--work-dir", W, "--mode", "mihomo", "--peer", "{peer:mihomo-trusttunnel}", "--peer-sha256", "{sha256:mihomo-trusttunnel}", "--edges", timeout=30 * MINUTE),
]


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def expand(job_row, kerlico, work, peers):
    def replace(arg):
        arg = arg.replace("{kerlico}", kerlico).replace("{work}", str(work))
        arg = re.sub(r"\{peer:([\w.-]+)\}", lambda m: peers[m.group(1)], arg)
        arg = re.sub(r"\{value:([\w.-]+)\}", lambda m: peers[m.group(1)], arg)
        return re.sub(r"\{sha256:([\w.-]+)\}", lambda m: digest(peers[m.group(1)]), arg)
    return [replace(arg) for arg in job_row.argv]


def run_job(job_row, args, peers, tools):
    missing = [name for name in job_row.peers if not Path(peers.get(name, "/nonexistent")).exists()]
    if missing:
        return {"state": "skipped", "missing_peers": missing}
    log_path = args.out / f"{job_row.name}.log"
    work = args.out / job_row.name
    argv = expand(job_row, args.kerlico, work, peers)
    argv[0] = str(tools / argv[0])
    env = dict(os.environ, KERLICO_WORKER="1", KERLICO_WORKER_ONLY="1", KERLICO_WORKER_ALIAS=job_row.machine, PYTHONDONTWRITEBYTECODE="1")
    started = time.monotonic()
    with log_path.open("wb") as log:
        process = subprocess.Popen([sys.executable, "-B", *argv], cwd=tools.parent, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        try:
            code = process.wait(timeout=job_row.timeout)
            state = "pass" if code == 0 else "fail"
        except subprocess.TimeoutExpired:
            state, code = "timeout", None
        try:
            os.killpg(process.pid, signal.SIGTERM if state != "timeout" else signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    return {"state": state, "exit": code, "seconds": round(time.monotonic() - started)}


def count_log(text):
    """各脚本的结果形状不同：优先取汇总字段，否则逐行累计 pass/ok。"""
    passed = failed = 0
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        counts = row.get("counts")
        if isinstance(counts, dict):
            return counts.get("pass", 0), counts.get("fail", 0)
        if isinstance(row.get("passed"), int) and isinstance(row.get("failed"), int):
            return row["passed"], row["failed"]
        verdict = row.get("pass", row.get("ok"))
        if verdict is True:
            passed += row.get("case_count") or 1
        elif verdict is False:
            failed += 1
    return passed, failed


def summarize(out):
    rows = {}
    for line in (out / "status.jsonl").read_text().splitlines():
        row = json.loads(line)
        rows[row["job"]] = row
    for name, row in rows.items():
        log = out / f"{name}.log"
        counted = count_log(log.read_text(errors="replace")) if log.exists() else (0, 0)
        print(json.dumps({**row, "passed": counted[0], "failed": counted[1]}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--machine", required=True)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peers", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--lane", type=int)
    parser.add_argument("--only", help="作业名正则")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()
    args.out = args.out.resolve()
    if args.summary:
        summarize(args.out)
        return
    selected = [row for row in JOBS if row.machine == args.machine and (args.lane is None or row.lane == args.lane) and (not args.only or re.search(args.only, row.name))]
    if args.list:
        for row in selected:
            print(row.name, row.lane, row.timeout)
        return
    peers = json.loads(args.peers.read_text())
    tools = Path(__file__).resolve().parent
    args.out.mkdir(parents=True, exist_ok=True)
    for row in selected:
        outcome = run_job(row, args, peers, tools)
        record = {"job": row.name, "protocol": row.protocol, "machine": row.machine, **outcome}
        with (args.out / "status.jsonl").open("a") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
