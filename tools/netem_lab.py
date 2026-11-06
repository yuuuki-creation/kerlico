#!/usr/bin/env python3
"""在两个独立 netns 之间用 tc netem 复现真实路径的丢包、延迟和 MTU，跑一条全双工回显。

客户端在 A，节点和回显在 B。netem 只装在脚本自己创建的 veth 上，退出时删除 netns。
需要 root。用法：tools/netem_lab.py --binary <kerlico> --protocol wireguard --loss 2 --delay 30
Hysteria2：--protocol hysteria2 --hy2-up 50 --hy2-down 50 让双方协商为 Brutal；两者为 0 时为 BBR。
"""
import argparse
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_v2 import bind_members  # noqa: E402
from interop_cross_host import LIMITS, b64, payload, socks_connect, x25519_pair  # noqa: E402

A_ADDR, B_ADDR = "10.211.0.1", "10.211.0.2"
NODE_PORT, ECHO_PORT, SOCKS_PORT = 31000, 31001, 31002


def run(script, check=True):
    return subprocess.run(["bash", "-c", script], check=check, capture_output=True, text=True)


def netem_args(args):
    parts = [f"delay {args.delay}ms"]
    if args.jitter:
        parts[0] += f" {args.jitter}ms"
    if args.burst:
        # Gilbert 模型：好状态每包有 p% 进入坏状态，坏状态连续丢包，每包 r% 回到好状态。
        parts.append(f"loss gemodel {args.loss}% {args.burst}% 100% 0%")
    elif args.loss:
        parts.append(f"loss {args.loss}%")
    if args.reorder:
        parts.append(f"reorder {args.reorder}%")
    if args.rate:
        parts.append(f"rate {args.rate}mbit")
    return " ".join(parts) + f" limit {args.queue}"


class Lab:
    def __init__(self, args):
        self.args = args
        tag = uuid.uuid4().hex[:6]
        self.a, self.b = f"stk-{tag}-a", f"stk-{tag}-b"
        self.dev_a, self.dev_b = f"stk{tag}a", f"stk{tag}b"
        self.dir = tempfile.mkdtemp(prefix="netem-lab-", dir=args.workdir)
        self.processes = []

    def up(self):
        a, b, args = self.a, self.b, self.args
        rule = netem_args(args)
        run(f"""set -e
ip netns add {a}; ip netns add {b}
ip link add {self.dev_a} type veth peer name {self.dev_b}
ip link set {self.dev_a} netns {a}; ip link set {self.dev_b} netns {b}
for side in "{a} {self.dev_a} {A_ADDR}" "{b} {self.dev_b} {B_ADDR}"; do set -- $side
  ip -n $1 link set lo up
  ip -n $1 addr add $3/30 dev $2
  ip -n $1 link set $2 mtu {args.mtu} up
  ip netns exec $1 ethtool -K $2 tso off gso off gro off >/dev/null 2>&1 || true
  tc -n $1 qdisc add dev $2 root netem {rule}
done""")

    def spawn(self, ns, name, argv):
        log = open(Path(self.dir) / f"{name}.log", "w")
        process = subprocess.Popen(["ip", "netns", "exec", ns, *argv], stdout=log, stderr=log, start_new_session=True, env={**os.environ, **dict(item.split("=", 1) for item in self.args.env)})
        self.processes.append((name, process))
        return process

    def down(self):
        for _, process in self.processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        for _, process in self.processes:
            try:
                process.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
        run(f"ip netns delete {self.a}; ip netns delete {self.b}", check=False)

    def tail(self, name, lines=8):
        path = Path(self.dir) / f"{name}.log"
        return path.read_text(errors="replace").splitlines()[-lines:] if path.exists() else []


def wireguard_configs(args):
    node_private, node_public = x25519_pair()
    client_private, client_public = x25519_pair()
    tunnel = {"mtu": args.tunnel_mtu}
    limits = {name: value for name, value in (("tcp_buffer_bytes", args.tcp_buffer), ("queue_packets", args.queue_packets)) if value}
    if limits:
        tunnel["limits"] = limits
    node = {"tag": "node", "type": "wireguard", "listen": f"0.0.0.0:{NODE_PORT}", "outbound": "direct", "options": {"tunnel": {"private_key": b64(node_private), "addresses": ["10.77.0.1"], **tunnel}}}
    node_cfg = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [node], "limits": LIMITS}
    bind_members(node_cfg, node, [{"public_key": b64(client_public), "allowed_ips": ["10.77.0.2/32"], "persistent_keepalive": 25}])
    client = {"tunnel": {"private_key": b64(client_private), "addresses": ["10.77.0.2"], **tunnel}, "peer": {"public_key": b64(node_public), "allowed_ips": ["0.0.0.0/0"], "persistent_keepalive": 25}, "endpoint": {"host": B_ADDR, "port": NODE_PORT}}
    client_cfg = {"version": 2, "outbounds": [{"tag": "proxy", "type": "wireguard", "options": client}], "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{SOCKS_PORT}", "outbound": "proxy", "options": {"version": "5"}}], "inbounds": [], "limits": LIMITS}
    return node_cfg, client_cfg


def hysteria2_configs(args, workdir):
    cert, key = Path(workdir) / "cert.pem", Path(workdir) / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth", "-keyout", str(key), "-out", str(cert)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    auth = "synthetic-" + uuid.uuid4().hex
    node = {"tag": "node", "type": "hysteria2", "listen": f"0.0.0.0:{NODE_PORT}", "outbound": "direct", "options": {"tls": {"certificate_file": str(cert), "private_key_file": str(key)}}}
    node_cfg = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [node], "limits": LIMITS}
    bind_members(node_cfg, node, [{"auth": auth}])
    client = {"server": {"host": B_ADDR, "port": NODE_PORT}, "auth": auth, "tls": {"server_name": "localhost", "ca_pem": cert.read_text()}}
    for key_name, value in (("up", args.hy2_up), ("down", args.hy2_down)):
        if value:
            client[key_name] = f"{value} Mbps"
    client_cfg = {"version": 2, "outbounds": [{"tag": "proxy", "type": "hysteria2", "options": client}], "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{SOCKS_PORT}", "outbound": "proxy", "options": {"version": "5"}}], "inbounds": [], "limits": LIMITS}
    return node_cfg, client_cfg


def echo_main(port):
    server = socket.create_server(("0.0.0.0", port), reuse_port=True, backlog=64)

    def handle(stream):
        with stream:
            try:
                while chunk := stream.recv(1 << 18):
                    stream.sendall(chunk)
            except OSError:
                pass

    while True:
        client, _ = server.accept()
        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle, args=(client,), daemon=True).start()


def watch_main(mode, host, port, socks, size, stall):
    stream = socks_connect(socks, host, port, timeout=30) if mode == "socks" else socket.create_connection((host, port), timeout=30)
    data = memoryview(payload(size))
    expected = hashlib.sha256(data).digest()
    digest = hashlib.sha256()
    # 单线程 select：Python 的 sendall 超时是整次调用的总时长，和接收共用 socket 超时会静默终止发送。
    stream.setblocking(False)
    started = last = last_sent = time.monotonic()
    sent, received, longest, longest_at, error = 0, 0, 0.0, 0, None
    marks = []
    next_mark = started + 5
    while received < size:
        now = time.monotonic()
        if now - last > stall:
            error = f"stall@{received},sent={sent}"
            break
        readable, writable, _ = select.select([stream], [stream] if sent < size else [], [], 1.0)
        now = time.monotonic()
        try:
            if writable:
                count = stream.send(data[sent:sent + (1 << 16)])
                if count:
                    sent += count
                    last_sent = now
            if not readable:
                continue
            chunk = stream.recv(min(1 << 18, size - received))
        except BlockingIOError:
            continue
        except OSError as failure:
            error = f"{type(failure).__name__}@{received},sent={sent}"
            break
        if now - last > longest:
            longest, longest_at = now - last, received
        last = now
        if not chunk:
            error = f"eof@{received},sent={sent}"
            break
        digest.update(chunk)
        received += len(chunk)
        if now >= next_mark:
            marks.append([round(now - started), received >> 10])
            next_mark = now + 5
    elapsed = time.monotonic() - started
    ok = error is None and digest.digest() == expected
    print(json.dumps({"ok": ok, "error": error, "received": received, "sent": sent, "elapsed": round(elapsed, 1), "mib_s": round(received / 1048576 / max(elapsed, 1e-3), 2), "longest_gap": round(longest, 1), "longest_gap_at": longest_at, "last_send_age": round(time.monotonic() - last_sent, 1), "kib_at_seconds": marks}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    echo = sub.add_parser("_echo")
    echo.add_argument("port", type=int)
    watch = sub.add_parser("_watch")
    watch.add_argument("mode")
    watch.add_argument("host")
    watch.add_argument("port", type=int)
    watch.add_argument("socks", type=int)
    watch.add_argument("size", type=int)
    watch.add_argument("stall", type=float)
    parser.add_argument("--binary")
    parser.add_argument("--protocol", choices=["kernel", "wireguard", "hysteria2"], default="wireguard")
    parser.add_argument("--hy2-up", type=int, default=0, help="Hysteria2 客户端 up，Mbit/s；0 为不设")
    parser.add_argument("--hy2-down", type=int, default=0, help="Hysteria2 客户端 down，Mbit/s；0 为不设")
    parser.add_argument("--workdir", default="/tmp")
    parser.add_argument("--loss", type=float, default=0.0, help="每个方向的丢包百分比；配 --burst 时是进入坏状态的概率")
    parser.add_argument("--burst", type=float, default=0.0, help="坏状态每包回到好状态的百分比")
    parser.add_argument("--delay", type=int, default=30, help="每个方向的单程延迟，毫秒")
    parser.add_argument("--jitter", type=int, default=0)
    parser.add_argument("--reorder", type=float, default=0.0)
    parser.add_argument("--rate", type=int, default=0, help="每个方向的限速，Mbit/s；0 为不限")
    parser.add_argument("--queue", type=int, default=1000, help="netem 队列长度，超过时丢包")
    parser.add_argument("--mtu", type=int, default=1300)
    parser.add_argument("--tunnel-mtu", type=int, default=1200)
    parser.add_argument("--tcp-buffer", type=int, default=0)
    parser.add_argument("--queue-packets", type=int, default=0)
    parser.add_argument("--size", type=int, default=32 << 20)
    parser.add_argument("--stall", type=float, default=75.0)
    parser.add_argument("--env", action="append", default=[], help="传给 kerlico 的 KEY=VALUE")
    parser.add_argument("--keep-logs", type=int, default=12)
    args = parser.parse_args()
    if args.command == "_echo":
        return echo_main(args.port)
    if args.command == "_watch":
        return watch_main(args.mode, args.host, args.port, args.socks, args.size, args.stall)

    lab = Lab(args)
    me = str(Path(__file__).resolve())
    try:
        lab.up()
        lab.spawn(lab.b, "echo", [sys.executable, me, "_echo", str(ECHO_PORT)])
        if args.protocol in ("wireguard", "hysteria2"):
            node_cfg, client_cfg = wireguard_configs(args) if args.protocol == "wireguard" else hysteria2_configs(args, lab.dir)
            for name, cfg, ns in (("node", node_cfg, lab.b), ("client", client_cfg, lab.a)):
                path = Path(lab.dir) / f"{name}.json"
                path.write_text(json.dumps(cfg))
                lab.spawn(ns, name, [args.binary, "run", "-c", str(path)])
            time.sleep(1.5)
            mode, host = "socks", B_ADDR
        else:
            time.sleep(0.5)
            mode, host = "direct", B_ADDR
        result = subprocess.run(["ip", "netns", "exec", lab.a, sys.executable, me, "_watch", mode, host, str(ECHO_PORT), str(SOCKS_PORT), str(args.size), str(args.stall)], capture_output=True, text=True)
        if result.returncode:
            print(result.stderr[-1500:])
        extra = f" hy2_up={args.hy2_up} hy2_down={args.hy2_down}" if args.protocol == "hysteria2" else ""
        print(f"netem=[{netem_args(args)}] mtu={args.mtu} tunnel_mtu={args.tunnel_mtu} protocol={args.protocol}{extra} {result.stdout.strip()}", flush=True)
        if args.keep_logs and args.protocol != "kernel":
            for name in ("client", "node"):
                for line in lab.tail(name, args.keep_logs):
                    print(f"  [{name}] {line}")
    finally:
        lab.down()


if __name__ == "__main__":
    main()
