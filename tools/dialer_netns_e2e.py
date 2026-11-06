#!/usr/bin/env python3
"""拨号选项端到端检查，在两个临时网络命名空间里运行 kerlico，结束时删除命名空间。

需要 root 与 iproute2，不改动宿主机已有的路由、规则与防火墙。

- fwmark：客户端命名空间里到服务端网段的路由只放在 fwmark 0x2a 对应的路由表；带全局
  routing-mark 的客户端能经 SOCKS5 访问回显服务，不带标记时失败。
- detour：Hysteria2 与 WireGuard 服务端只监听服务端命名空间的回环地址，客户端无法直达；
  客户端出站以 SOCKS5 出站为 detour（dialer-proxy），数据报经 SOCKS5 UDP ASSOCIATE 到达。

用法：tools/dialer_netns_e2e.py --kerlico target/debug/kerlico
"""

from __future__ import annotations

import argparse
import contextlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_vs_mihomo as bench  # noqa: E402

SERVER_NS = "kd-e2e-srv"
CLIENT_NS = "kd-e2e-cli"
SERVER_IP = "10.232.0.2"
CLIENT_IP = "10.232.0.1"
MARK = 0x2A
TABLE = "232"
SOCKS_PORT = 21080
ECHO_PORT = 21081
FORWARD_PORT = 21082
HY2_PORT = 21443
WG_PORT = 21820

ECHO = (
    "import socket,threading\n"
    "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
    f"s.bind(('0.0.0.0',{ECHO_PORT}));s.listen(64)\n"
    "def h(c):\n"
    " while True:\n"
    "  d=c.recv(65536)\n"
    "  if not d: break\n"
    "  c.sendall(d)\n"
    "while True:\n"
    " c,_=s.accept();threading.Thread(target=h,args=(c,),daemon=True).start()\n"
)


def sh(*args: str) -> None:
    subprocess.run(args, check=True)


def in_ns(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]


@contextlib.contextmanager
def namespaces():
    for ns in (SERVER_NS, CLIENT_NS):
        subprocess.run(["ip", "netns", "del", ns], stderr=subprocess.DEVNULL)
    try:
        sh("ip", "netns", "add", SERVER_NS)
        sh("ip", "netns", "add", CLIENT_NS)
        sh("ip", "-n", CLIENT_NS, "link", "add", "kd-c0", "type", "veth", "peer", "name", "kd-s0",
           "netns", SERVER_NS)
        for ns, dev, ip in ((CLIENT_NS, "kd-c0", CLIENT_IP), (SERVER_NS, "kd-s0", SERVER_IP)):
            sh("ip", "-n", ns, "link", "set", "lo", "up")
            sh("ip", "-n", ns, "addr", "add", f"{ip}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
        # 客户端到服务端网段只经 fwmark 路由表可达。
        sh("ip", "-n", CLIENT_NS, "route", "del", "10.232.0.0/24", "dev", "kd-c0", "table", "main")
        sh("ip", "-n", CLIENT_NS, "route", "add", "10.232.0.0/24", "dev", "kd-c0", "table", TABLE)
        sh("ip", "-n", CLIENT_NS, "rule", "add", "fwmark", hex(MARK), "lookup", TABLE)
        yield
    finally:
        for ns in (SERVER_NS, CLIENT_NS):
            subprocess.run(["ip", "netns", "del", ns], stderr=subprocess.DEVNULL)


@contextlib.contextmanager
def process(args: list[str], log: Path):
    with log.open("wb") as out:
        proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)
        try:
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def kerlico(binary: str, ns: str, config: dict, work: Path, name: str):
    path = work / f"{name}.json"
    path.write_text(json.dumps(config, indent=2))
    return process(in_ns(ns, binary, "run", "-c", str(path)), work / f"{name}.log")


def echo_through(port: int, timeout: float = 15.0) -> bool:
    """经客户端命名空间的 TCP 转发入口发一段数据，回显一致即成功。"""
    probe = (
        "import socket,sys,time\n"
        f"end=time.time()+{timeout}\n"
        "while time.time()<end:\n"
        " try:\n"
        f"  c=socket.create_connection(('127.0.0.1',{port}),timeout=3);c.sendall(b'kerlico-dialer');\n"
        "  d=c.recv(64)\n"
        "  if d==b'kerlico-dialer': sys.exit(0)\n"
        " except OSError: pass\n"
        " time.sleep(0.5)\n"
        "sys.exit(1)\n"
    )
    return subprocess.run(in_ns(CLIENT_NS, sys.executable, "-c", probe)).returncode == 0


def socks_server(extra_nodes: list[dict]) -> dict:
    return {
        "version": 2,
        "lan_allowed_ips": ["10.232.0.0/24"],
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "local_inbounds": [{
            "tag": "hop",
            "type": "socks",
            "listen": f"{SERVER_IP}:{SOCKS_PORT}",
            "outbound": "direct",
            "options": {},
        }],
        "nodes": extra_nodes,
    }


def client(outbounds: list[dict], target_host: str, mark: bool) -> dict:
    config = bench.kerlico_client_wrap("socks", {}, FORWARD_PORT, None, ECHO_PORT, 0, target_host)
    config["outbounds"] = outbounds
    if mark:
        config["routing_mark"] = MARK
    return config


def hop_outbound() -> dict:
    return {"tag": "hop", "type": "socks",
            "options": {"server": {"host": SERVER_IP, "port": SOCKS_PORT}, "version": "5"}}


def run_case(binary: str, work: Path, name: str, server: dict, client_config: dict) -> bool:
    with kerlico(binary, SERVER_NS, server, work, f"{name}-server"):
        time.sleep(1.5)
        with kerlico(binary, CLIENT_NS, client_config, work, f"{name}-client"):
            time.sleep(1.5)
            return echo_through(FORWARD_PORT)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    args = parser.parse_args()
    binary = str(Path(args.kerlico).resolve())
    results: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="kd-e2e-") as tmp, namespaces():
        work = Path(tmp)
        m = bench.generate_materials(work / "materials", binary)
        with process(in_ns(SERVER_NS, sys.executable, "-c", ECHO), work / "echo.log"):
            time.sleep(0.5)
            plain = socks_server([])
            direct_socks = [{**hop_outbound(), "tag": "proxy"}]
            results["fwmark: 带标记可达"] = run_case(
                binary, work, "mark-on", plain, client(direct_socks, "127.0.0.1", True))
            results["fwmark: 无标记不可达"] = not run_case(
                binary, work, "mark-off", plain, client(direct_socks, "127.0.0.1", False))

            hy2_node = {"tag": "hy2", "type": "hysteria2", "listen": f"127.0.0.1:{HY2_PORT}",
                        "outbound": "direct",
                        "options": {"tls": {"certificate_pem": m["chain_pem"],
                                            "private_key_pem": m["key_pem"]}, "udp": True}}
            hy2_server = socks_server([hy2_node])
            bench.bind_members(hy2_server, hy2_server["nodes"][0], [{"auth": bench.USER_PASSWORD}])
            hy2_client = client([hop_outbound(), {
                "tag": "proxy", "type": "hysteria2",
                "options": {"detour": "hop", "server": {"host": "127.0.0.1", "port": HY2_PORT},
                            "auth": bench.USER_PASSWORD,
                            "tls": {"server_name": "localhost", "ca_pem": m["ca_pem"]}},
            }], "127.0.0.1", True)
            results["detour: hysteria2 经 SOCKS5 UDP"] = run_case(
                binary, work, "hy2", hy2_server, hy2_client)
            no_detour = json.loads(json.dumps(hy2_client))
            del no_detour["outbounds"][1]["options"]["detour"]
            results["detour: hysteria2 无 detour 时不可达"] = not run_case(
                binary, work, "hy2-direct", hy2_server, no_detour)

            wg_node = {"tag": "wg", "type": "wireguard", "listen": f"127.0.0.1:{WG_PORT}",
                       "outbound": "direct",
                       "options": {"tunnel": {"private_key": m["wg_s_priv"],
                                              "addresses": ["10.77.0.1", "fd77::1"], "mtu": 1280}}}
            wg_server = socks_server([wg_node])
            bench.bind_members(wg_server, wg_server["nodes"][0], [{
                "public_key": m["wg_c_pub"], "allowed_ips": ["10.77.0.2/32", "fd77::2/128"],
                "persistent_keepalive": 25}])
            wg_client = client([hop_outbound(), {
                "tag": "proxy", "type": "wireguard",
                "options": {"detour": "hop", "endpoint": {"host": "127.0.0.1", "port": WG_PORT},
                            "tunnel": {"private_key": m["wg_c_priv"],
                                       "addresses": ["10.77.0.2", "fd77::2"], "mtu": 1280},
                            "peer": {"public_key": m["wg_s_pub"],
                                     "allowed_ips": ["0.0.0.0/0", "::/0"],
                                     "persistent_keepalive": 25}},
            }], "10.77.0.1", True)
            results["detour: wireguard 经 SOCKS5 UDP"] = run_case(
                binary, work, "wg", wg_server, wg_client)
        failed = [name for name, ok in results.items() if not ok]
        for name, ok in results.items():
            print(f"{'PASS' if ok else 'FAIL'} {name}")
        if failed:
            for log in sorted(work.glob("*.log")):
                print(f"--- {log.name}\n{log.read_text(errors='replace')[-3000:]}")
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
