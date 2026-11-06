#!/usr/bin/env python3
"""同一份 `sniffer:` 配置分别交给 mihomo 与 kerlico，比较每个夹具连接命中的规则与出站。

用法：tools/sniff_differential.py --kerlico <kerlico 二进制> --mihomo <mihomo 二进制>
两个进程依次运行，只监听回环地址；夹具经 mixed 入站的 SOCKS5 发出。退出码 0 表示全部一致。
"""

import argparse
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "crates", "net", "tests", "fixtures", "sniff")

CONFIG = """\
mixed-port: {port}
allow-lan: false
mode: rule
log-level: info
ipv6: true
sniffer:
  enable: true
  override-destination: false
  force-domain: ["localhost"]
  skip-domain: ["+.skip.test"]
  skip-dst-address: ["127.0.0.2/32"]
  sniff:
    TLS:
      ports: [{tcp}]
    HTTP:
      ports: [{tcp}]
    QUIC:
      ports: [{udp}]
rules:
  - DOMAIN,allowed.test,DIRECT
  - DOMAIN,quic.example.com,DIRECT
  - DOMAIN,www.google.com,DIRECT
  - DOMAIN,localhost,DIRECT
  - DOMAIN-SUFFIX,skip.test,DIRECT
  - MATCH,REJECT
"""


def hex_packets(name):
    with open(os.path.join(FIXTURES, name + ".hex")) as f:
        return [bytes.fromhex(line.strip()) for line in f if line.strip() and not line.startswith("#")]


def client_hello(sni):
    host = sni.encode()
    sni_ext = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    exts = struct.pack("!HH", 0, len(sni_ext)) + sni_ext
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def http_get(host):
    return f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def tcp_echo(ip, port, stop):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, port))
    srv.listen(64)
    srv.settimeout(0.2)

    def serve(conn):
        with conn:
            try:
                while data := conn.recv(65536):
                    conn.sendall(data)
            except OSError:
                pass

    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
    srv.close()


def udp_echo(ip, port, stop):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((ip, port))
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            data, peer = srv.recvfrom(65536)
            srv.sendto(data, peer)
        except OSError:
            continue
    srv.close()


def socks_addr(host, port):
    try:
        return b"\x01" + socket.inet_aton(host) + struct.pack("!H", port)
    except OSError:
        return b"\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", port)


def socks_request(proxy, cmd, host, port):
    s = socket.create_connection(("127.0.0.1", proxy), timeout=3)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    s.sendall(b"\x05" + bytes([cmd]) + b"\x00" + socks_addr(host, port))
    head = s.recv(4)
    atyp = head[3]
    n = {1: 4, 4: 16}.get(atyp) or s.recv(1)[0]
    rest = s.recv(n + 2)
    return s, head[1], atyp, rest


def udp_case(proxy, host, port, packets):
    ctrl, rep, atyp, rest = socks_request(proxy, 3, "0.0.0.0", 0)
    if rep != 0:
        ctrl.close()
        return
    family = socket.AF_INET if atyp == 1 else socket.AF_INET6
    ip = socket.inet_ntop(family, rest[:-2])
    relay_port = struct.unpack("!H", rest[-2:])[0]
    if ip in ("0.0.0.0", "::"):
        ip = "127.0.0.1"
    u = socket.socket(family, socket.SOCK_DGRAM)
    for p in packets:
        u.sendto(b"\x00\x00\x00" + socks_addr(host, port) + p, (ip, relay_port))
    u.settimeout(2)
    try:
        u.recvfrom(65536)
    except OSError:
        pass
    u.close()
    ctrl.close()


LINE = re.compile(r"\[(TCP|UDP)\] (\S+) --> (\S+) (?:match (\S+?)(?:\((.*)\))? using (\S+)|doesn't match any rule using (\S+))")


def decisions(log):
    out = {}
    for line in log.splitlines():
        m = LINE.search(line)
        if not m:
            continue
        net, src, dst, kind, payload, using, unmatched = m.groups()
        # TCP 按客户端源端口对应夹具；UDP 每个夹具用独立目标端口。
        key = src.rsplit(":", 1)[1] if net == "TCP" else dst.rsplit(":", 1)[1]
        rule = "MATCH" if unmatched or (kind or "").lower() == "match" else f"{kind.lower()}({payload})"
        outbound = (using or unmatched).strip('"').split("[")[-1].rstrip("]")
        out[(net, key)] = (rule, outbound)
    return out


def run(binary, args, cases, workdir, port):
    log_path = os.path.join(workdir, os.path.basename(binary) + ".log")
    with open(log_path, "w") as log:
        proc = subprocess.Popen([binary, *args], stdout=log, stderr=subprocess.STDOUT, cwd=workdir)
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise SystemExit(f"{binary} 未在期限内监听：\n{open(log_path).read()}")
        sports = []
        for name, network, action in cases:
            before = time.time()
            sports.append((name, network, action()))
            time.sleep(max(0, 0.3 - (time.time() - before)))
        time.sleep(1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return open(log_path).read(), sports


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--mihomo", required=True)
    args = parser.parse_args()
    stop = threading.Event()
    tcp = free_port()
    udp_ports = [free_port(socket.SOCK_DGRAM) for _ in range(2)]
    for ip in ("127.0.0.1", "127.0.0.2"):
        threading.Thread(target=tcp_echo, args=(ip, tcp, stop), daemon=True).start()
    for udp in udp_ports:
        threading.Thread(target=udp_echo, args=("127.0.0.1", udp, stop), daemon=True).start()
    udp = ",".join(str(p) for p in udp_ports)
    time.sleep(0.3)

    workdir = tempfile.mkdtemp(prefix="sniff-diff-")
    results = {}
    try:
        for label, binary in (("mihomo", args.mihomo), ("kerlico", args.kerlico)):
            port = free_port()
            cfg = os.path.join(workdir, f"{label}.yaml")
            with open(cfg, "w") as f:
                f.write(CONFIG.format(port=port, tcp=tcp, udp=udp))
            cli = ["-d", workdir, "-f", cfg] if label == "mihomo" else ["run", "-c", cfg]
            src_port = {}

            def tcp_fixture(host, payload):
                def go():
                    s, _, _, _ = socks_request(port, 1, host, tcp)
                    sport = s.getsockname()[1]
                    try:
                        s.sendall(payload)
                        s.settimeout(2)
                        s.recv(65536)
                    except OSError:
                        pass
                    s.close()
                    return str(sport)
                return go

            def udp_fixture(index, packets):
                def go():
                    udp_case(port, "127.0.0.1", udp_ports[index], packets)
                    return str(udp_ports[index])
                return go

            cases = [
                ("tls-sni-allowed", "TCP", tcp_fixture("127.0.0.1", client_hello("allowed.test"))),
                ("tls-sni-other", "TCP", tcp_fixture("127.0.0.1", client_hello("other.test"))),
                ("http-host-allowed", "TCP", tcp_fixture("127.0.0.1", http_get("allowed.test"))),
                ("http-host-port", "TCP", tcp_fixture("127.0.0.1", http_get(f"allowed.test:{tcp}"))),
                ("tls-skip-domain", "TCP", tcp_fixture("127.0.0.1", client_hello("a.skip.test"))),
                ("tls-skip-dst", "TCP", tcp_fixture("127.0.0.2", client_hello("allowed.test"))),
                ("ssh-not-sniffed", "TCP", tcp_fixture("127.0.0.1", bytes.fromhex(hex_packets("openssh-client-banner")[0].hex()))),
                ("domain-target-forced", "TCP", tcp_fixture("localhost", client_hello("allowed.test"))),
                ("random-bytes", "TCP", tcp_fixture("127.0.0.1", os.urandom(64))),
                ("quic-curl", "UDP", udp_fixture(0, hex_packets("curl-http3-initial"))),
                ("quic-chrome-3-initials", "UDP", udp_fixture(1, hex_packets("singbox-quic-chrome-new"))),
            ]
            log, ran = run(binary, cli, cases, workdir, port)
            found = decisions(log)
            row = {name: found.get((network, key), ("<无日志>", "")) for name, network, key in ran}
            results[label] = row
            shutil.copy(os.path.join(workdir, os.path.basename(binary) + ".log"), os.path.join(workdir, f"{label}.out"))
    finally:
        stop.set()
        if "kerlico" not in results:
            shutil.rmtree(workdir, ignore_errors=True)
    same = True
    width = max(len(n) for n in results["mihomo"])
    for name in results["mihomo"]:
        m, k = results["mihomo"][name], results["kerlico"][name]
        ok = (m[0].lower(), m[1]) == (k[0].lower(), k[1])
        same &= ok
        print(f"{'OK ' if ok else 'DIFF'} {name:<{width}}  mihomo={m[0]} -> {m[1]}  kerlico={k[0]} -> {k[1]}")
    if not same:
        print(f"日志：{workdir}")
    else:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
