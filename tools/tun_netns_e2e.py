#!/usr/bin/env python3
"""TUN 自动路由端到端检查：同一份 Mihomo 配置分别交给 kerlico 与 mihomo，在临时网络命名空间里比较结果。

拓扑（全部在本脚本创建的命名空间内，结束时删除，不改动宿主机路由、规则与防火墙）：

    kt-cli (被测客户端，默认路由经 TUN)  --veth--  kt-srv (SOCKS5 代理，不转发)  --veth--  kt-tgt (回显服务)

kt-cli 到 kt-tgt 没有路由，kt-srv 关闭转发，回显内容带上回显服务看到的来源地址，
来源是 kt-srv 的地址即证明流量经 TUN 进入被测程序、再经代理出站到达，且代理连接没有回环进 TUN。

检查项（每个被测程序各跑一遍）：
- auto-route + strict-route 下 IPv4、IPv6 目标的 TCP 回显都经代理到达；
- dns-hijack（any:53、tcp://any:53）对任意 DNS 服务器地址的 UDP 与 TCP 查询都返回 Fake-IP；
- 只有 IPv4 地址的 TUN 在 strict-route 下让 IPv6 立即不可达，不经主表泄漏；
- kill -9 后重启能正常工作且规则不重复，正常退出后规则、路由表、nft 表与接口回到启动前。

用法：tools/tun_netns_e2e.py --kerlico target/debug/kerlico --mihomo /path/to/mihomo [--out 结果.json]
需要 root、iproute2 与 nft。
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLI, SRV, TGT = "kt-cli", "kt-srv", "kt-tgt"
CLI_IP, SRV_IP = "10.234.0.1", "10.234.0.2"
CLI_IP6, SRV_IP6 = "fd34::1", "fd34::2"
SRV_IP_T, TGT_IP = "10.234.1.1", "10.234.1.2"
SRV_IP6_T, TGT_IP6 = "fd34:1::1", "fd34:1::2"
SOCKS_PORT = 11080
ECHO_PORT = 18080
LEAK_PORT = 18081
TUN = "kt0"
FAKE_RANGE = "198.18.0.0/16"
DNS_PROBE_SERVER = "10.234.9.9"

ECHO = (
    "import socket,sys,threading\n"
    "port=int(sys.argv[1])\n"
    "s=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    "s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)\n"
    "s.bind(('::',port));s.listen(64)\n"
    "def h(c,a):\n"
    " d=c.recv(4096)\n"
    " host=a[0].removeprefix('::ffff:')\n"
    " c.sendall(('peer='+host+'|').encode()+d);c.close()\n"
    "while True:\n"
    " c,a=s.accept();threading.Thread(target=h,args=(c,a),daemon=True).start()\n"
)

PROBE = r'''
import errno, socket, struct, sys, time
mode = sys.argv[1]

def dns_query(name):
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)

def first_a(reply):
    count = struct.unpack("!H", reply[6:8])[0]
    pos = 12
    while reply[pos]:
        pos += 1 + reply[pos]
    pos += 5
    for _ in range(count):
        if reply[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while reply[pos]:
                pos += 1 + reply[pos]
            pos += 1
        rtype, _, _, rlen = struct.unpack("!HHIH", reply[pos:pos + 10])
        pos += 10
        if rtype == 1 and rlen == 4:
            return socket.inet_ntoa(reply[pos:pos + 4])
        pos += rlen
    return ""

if mode == "tcp":
    host, port = sys.argv[2], int(sys.argv[3])
    end = time.time() + 15
    while True:
        try:
            c = socket.create_connection((host, port), timeout=5)
            c.sendall(b"kerlico-tun")
            print(c.recv(256).decode())
            sys.exit(0)
        except OSError as e:
            if time.time() > end:
                print("error=" + str(e))
                sys.exit(1)
            time.sleep(0.5)
elif mode == "unreachable":
    host, port = sys.argv[2], int(sys.argv[3])
    c = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    c.settimeout(5)
    started = time.time()
    try:
        c.connect((host, port))
        print("connected")
        sys.exit(1)
    except OSError as e:
        quick = time.time() - started < 1
        print(f"errno={e.errno} quick={quick}")
        sys.exit(0 if e.errno == errno.ENETUNREACH and quick else 1)
elif mode in ("dns-udp", "dns-tcp"):
    server, name = sys.argv[2], sys.argv[3]
    query = dns_query(name)
    for _ in range(8):
        try:
            if mode == "dns-udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(query, (server, 53))
                reply = s.recv(4096)
            else:
                s = socket.create_connection((server, 53), timeout=3)
                s.sendall(struct.pack("!H", len(query)) + query)
                length = struct.unpack("!H", s.recv(2))[0]
                reply = b""
                while len(reply) < length:
                    reply += s.recv(length - len(reply))
            print(first_a(reply))
            sys.exit(0)
        except OSError:
            time.sleep(0.5)
    print("")
    sys.exit(1)
'''


def sh(*args: str, check: bool = True) -> str:
    return subprocess.run(args, check=check, capture_output=True, text=True).stdout


def in_ns(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]


@contextlib.contextmanager
def namespaces():
    for ns in (CLI, SRV, TGT):
        subprocess.run(["ip", "netns", "del", ns], stderr=subprocess.DEVNULL)
    try:
        for ns in (CLI, SRV, TGT):
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "-n", CLI, "link", "add", "kt-c0", "type", "veth", "peer", "name", "kt-s0",
           "netns", SRV)
        sh("ip", "-n", SRV, "link", "add", "kt-s1", "type", "veth", "peer", "name", "kt-t0",
           "netns", TGT)
        for ns, dev, v4, v6 in (
            (CLI, "kt-c0", CLI_IP, CLI_IP6),
            (SRV, "kt-s0", SRV_IP, SRV_IP6),
            (SRV, "kt-s1", SRV_IP_T, SRV_IP6_T),
            (TGT, "kt-t0", TGT_IP, TGT_IP6),
        ):
            sh("ip", "-n", ns, "addr", "add", f"{v4}/24", "dev", dev)
            sh("ip", "-n", ns, "addr", "add", f"{v6}/64", "dev", dev, "nodad")
            sh("ip", "-n", ns, "link", "set", dev, "up")
        sh("ip", "-n", CLI, "route", "add", "default", "via", SRV_IP)
        sh("ip", "-n", CLI, "-6", "route", "add", "default", "via", SRV_IP6)
        for key in ("net.ipv4.ip_forward=0", "net.ipv6.conf.all.forwarding=0"):
            sh(*in_ns(SRV, "sysctl", "-qw", key))
        yield
    finally:
        for ns in (CLI, SRV, TGT):
            subprocess.run(["ip", "netns", "del", ns], stderr=subprocess.DEVNULL)


@contextlib.contextmanager
def process(args: list[str], log: Path):
    with log.open("ab") as out:
        proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def network_state() -> dict[str, str]:
    """客户端命名空间里会被 TUN 自动化改动的全部状态。"""
    routes = [
        line
        for family in ("-4", "-6")
        for line in sh("ip", "-n", CLI, family, "route", "show", "table", "all").splitlines()
        if " table " in line and " table local" not in line
    ]
    return {
        "rules4": sh("ip", "-n", CLI, "-4", "rule", "show"),
        "rules6": sh("ip", "-n", CLI, "-6", "rule", "show"),
        "routes": "\n".join(routes),
        "nft": sh(*in_ns(CLI, "nft", "list", "ruleset"), check=False),
        "links": sh("ip", "-n", CLI, "-o", "link", "show"),
    }


def tun_up(timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        links = sh("ip", "-n", CLI, "-o", "link", "show", check=False)
        rules = sh("ip", "-n", CLI, "-4", "rule", "show", check=False)
        if f" {TUN}:" in links and len(rules.splitlines()) > 3:
            time.sleep(1.5)
            return True
        time.sleep(0.3)
    return False


def probe(work: Path, *args: str) -> tuple[bool, str]:
    script = work / "probe.py"
    script.write_text(PROBE)
    try:
        result = subprocess.run(in_ns(CLI, sys.executable, str(script), *args),
                                capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print(f"probe {' '.join(args)}: timeout", flush=True)
        return False, "timeout"
    print(f"probe {' '.join(args)}: rc={result.returncode} {result.stdout.strip()}", flush=True)
    return result.returncode == 0, result.stdout.strip()


def client_config(v6: bool, strict: bool, redirect: bool = False) -> str:
    inet6 = '  inet6-address: ["fdfe:dcba:9876::1/126"]\n' if v6 else ""
    return (
        "mode: rule\n"
        "log-level: info\n"
        f"ipv6: {'true' if v6 else 'false'}\n"
        "proxies:\n"
        f"  - {{name: hop, type: socks5, server: {SRV_IP}, port: {SOCKS_PORT}, udp: true}}\n"
        "rules:\n"
        "  - MATCH,hop\n"
        "dns:\n"
        "  enable: true\n"
        "  ipv6: false\n"
        "  enhanced-mode: fake-ip\n"
        f"  fake-ip-range: {FAKE_RANGE}\n"
        f"  nameserver: [\"udp://{SRV_IP}:53\"]\n"
        "tun:\n"
        "  enable: true\n"
        "  stack: system\n"
        f"  device: {TUN}\n"
        "  mtu: 1500\n"
        "  inet4-address: [\"172.19.0.1/30\"]\n"
        f"{inet6}"
        "  auto-route: true\n"
        f"  auto-redirect: {'true' if redirect else 'false'}\n"
        f"  strict-route: {'true' if strict else 'false'}\n"
        "  auto-detect-interface: true\n"
        "  dns-hijack: [\"any:53\", \"tcp://any:53\"]\n"
    )


def command(kind: str, binary: str, config: Path, work: Path) -> list[str]:
    if kind == "kerlico":
        return in_ns(CLI, binary, "run", "-c", str(config))
    home = work / f"mihomo-home-{config.stem}"
    home.mkdir(exist_ok=True)
    return in_ns(CLI, binary, "-d", str(home), "-f", str(config))


def via_proxy(output: str) -> bool:
    return output.startswith(f"peer={SRV_IP_T}|") or output.startswith(f"peer={SRV_IP6_T}|")


def run_client(kind: str, binary: str, work: Path) -> dict[str, object]:
    results: dict[str, object] = {}
    baseline = network_state()
    config = work / f"{kind}-dual.yaml"
    config.write_text(client_config(v6=True, strict=True))
    log = work / f"{kind}.log"
    cmd = command(kind, binary, config, work)

    with process(cmd, log) as proc:
        results["tun up"] = tun_up()
        running = network_state()
        print(f"== {kind} layout\n{running['rules4']}{running['rules6']}{running['routes']}\n"
              f"{running['nft']}", flush=True)
        results["layout"] = {"rules4": running["rules4"], "rules6": running["rules6"],
                             "routes": running["routes"], "nft": running["nft"]}
        ok, out = probe(work, "tcp", TGT_IP, str(ECHO_PORT))
        results["tcp ipv4 via proxy"] = ok and via_proxy(out)
        results["tcp ipv4 output"] = out
        ok, out = probe(work, "tcp", TGT_IP6, str(ECHO_PORT))
        results["tcp ipv6 via proxy"] = ok and via_proxy(out)
        results["tcp ipv6 output"] = out
        for mode in ("dns-udp", "dns-tcp"):
            ok, out = probe(work, mode, DNS_PROBE_SERVER, "echo.test")
            fake = ok and bool(out) and ipaddress.ip_address(out) in ipaddress.ip_network(FAKE_RANGE)
            results[f"{mode} fake-ip"] = fake
            results[f"{mode} answer"] = out
        proc.send_signal(signal.SIGKILL)
        proc.wait()
    crashed = network_state()
    results["kill -9 leaves rules"] = crashed["rules4"] != baseline["rules4"]

    with process(cmd, log) as proc:
        results["restart tun up"] = tun_up()
        restarted = network_state()
        results["restart rules not duplicated"] = (
            restarted["rules4"] == running["rules4"] and restarted["rules6"] == running["rules6"]
        )
        ok, out = probe(work, "tcp", TGT_IP, str(ECHO_PORT))
        results["restart tcp ipv4 via proxy"] = ok and via_proxy(out)
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    time.sleep(1)
    after = network_state()
    results["clean exit restores state"] = after == baseline
    if after != baseline:
        results["leftover"] = {k: after[k] for k in after if after[k] != baseline[k]}

    redirect = work / f"{kind}-redirect.yaml"
    redirect.write_text(client_config(v6=True, strict=True, redirect=True))
    with process(command(kind, binary, redirect, work), work / f"{kind}-redirect.log"):
        tun_up()
        results["auto-redirect nft table"] = "redirect to" in network_state()["nft"]
        ok, out = probe(work, "tcp", TGT_IP, str(ECHO_PORT))
        results["auto-redirect tcp ipv4 via proxy"] = ok and via_proxy(out)
        ok, out = probe(work, "tcp", TGT_IP6, str(ECHO_PORT))
        results["auto-redirect tcp ipv6 via proxy"] = ok and via_proxy(out)
        results["auto-redirect tcp ipv6 output"] = out
        ok, out = probe(work, "dns-tcp", DNS_PROBE_SERVER, "echo.test")
        results["auto-redirect dns-tcp fake-ip"] = ok and bool(out) and (
            ipaddress.ip_address(out) in ipaddress.ip_network(FAKE_RANGE))
    time.sleep(1)
    results["auto-redirect exit restores state"] = network_state() == baseline

    v4_only = work / f"{kind}-v4.yaml"
    for strict in (True, False):
        v4_only.write_text(client_config(v6=False, strict=strict))
        with process(command(kind, binary, v4_only, work), work / f"{kind}-v4.log"):
            tun_up()
            if strict:
                ok, out = probe(work, "unreachable", SRV_IP6, str(LEAK_PORT))
                results["strict v4-only: ipv6 unreachable"] = ok
                results["strict v4-only output"] = out
            else:
                ok, out = probe(work, "tcp", SRV_IP6, str(LEAK_PORT))
                results["non-strict v4-only: ipv6 uses main table"] = ok
        time.sleep(1)
    return results


def kerlico_server() -> dict:
    return {
        "version": 2,
        "lan_allowed_ips": ["10.234.0.0/24"],
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "local_inbounds": [{
            "tag": "hop", "type": "socks", "listen": f"{SRV_IP}:{SOCKS_PORT}",
            "outbound": "direct", "options": {},
        }],
    }


CHECKS = [
    "tun up", "tcp ipv4 via proxy", "tcp ipv6 via proxy", "dns-udp fake-ip", "dns-tcp fake-ip",
    "restart tun up", "restart rules not duplicated",
    "restart tcp ipv4 via proxy", "clean exit restores state",
    "auto-redirect nft table", "auto-redirect tcp ipv4 via proxy",
    "auto-redirect tcp ipv6 via proxy", "auto-redirect dns-tcp fake-ip",
    "auto-redirect exit restores state",
    "strict v4-only: ipv6 unreachable", "non-strict v4-only: ipv6 uses main table",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--mihomo")
    parser.add_argument("--out")
    args = parser.parse_args()
    clients = [("kerlico", str(Path(args.kerlico).resolve()))]
    if args.mihomo:
        clients.append(("mihomo", str(Path(args.mihomo).resolve())))
    report: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="kt-e2e-") as tmp, namespaces():
        work = Path(tmp)
        server = work / "server.json"
        server.write_text(json.dumps(kerlico_server()))
        with contextlib.ExitStack() as stack:
            stack.enter_context(process(in_ns(TGT, sys.executable, "-c", ECHO, str(ECHO_PORT)),
                                        work / "echo.log"))
            stack.enter_context(process(in_ns(SRV, sys.executable, "-c", ECHO, str(LEAK_PORT)),
                                        work / "leak.log"))
            stack.enter_context(process(in_ns(SRV, clients[0][1], "run", "-c", str(server)),
                                        work / "server.log"))
            time.sleep(1.5)
            for kind, binary in clients:
                report[kind] = run_client(kind, binary, work)
        failed = False
        for kind, results in report.items():
            for name in CHECKS:
                ok = bool(results.get(name))
                failed |= not ok
                print(f"{'PASS' if ok else 'FAIL'} {kind}: {name}")
            print(f"INFO {kind}: kill -9 leaves rules = {results.get('kill -9 leaves rules')}")
        if failed:
            for log in sorted(work.glob("*.log")):
                print(f"--- {log.name}\n{log.read_text(errors='replace')[-4000:]}")
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
