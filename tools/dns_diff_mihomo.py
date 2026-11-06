#!/usr/bin/env python3
"""同一份 Mihomo `dns:` 配置分别交给 mihomo 与 kerlico，对一组查询比较应答来源。

回环权威服务器按身份返回不同地址（主组 10.0.1.x、策略组 10.0.2.x、fallback 10.0.3.x），
由应答地址判断查询走了哪一组上游；hosts 与 Fake-IP 按地址或网段判断。

用法：tools/dns_diff_mihomo.py --kerlico 路径 --mihomo 路径 [--out 结果.json]
"""

import argparse
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ZONES = {
    "main": {"default": "10.0.1.1", "polluted.test": "198.51.100.7", "empty.test": None},
    "policy": {"default": "10.0.2.1"},
    "fallback": {"default": "10.0.3.1"},
    "third": {"default": "10.0.4.1"},
}


def parse_question(msg):
    pos, labels = 12, []
    while msg[pos]:
        n = msg[pos]
        labels.append(msg[pos + 1 : pos + 1 + n].decode().lower())
        pos += 1 + n
    qtype = struct.unpack("!H", msg[pos + 1 : pos + 3])[0]
    return ".".join(labels), qtype, pos + 5


def answer(zone, msg):
    name, qtype, end = parse_question(msg)
    ip = zone.get(name, zone["default"])
    records = b""
    count = 0
    if qtype == 1 and ip:
        records = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        count = 1
    elif qtype == 16:
        text = b"txt-" + name.encode()
        records = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(text) + 1) + bytes([len(text)]) + text
        count = 1
    rcode = 3 if (qtype == 1 and ip is None and name in zone) else 0
    flags = struct.pack("!BB", 0x81, 0x80 | rcode)
    return msg[:2] + flags + struct.pack("!HHHH", 1, count, 0, 0) + msg[12:end] + records


def serve(zone):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def loop():
        while True:
            data, peer = sock.recvfrom(4096)
            try:
                sock.sendto(answer(zone, data), peer)
            except Exception:
                pass

    threading.Thread(target=loop, daemon=True).start()
    return sock.getsockname()[1]


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def query(port, name, qtype, timeout=3.0):
    qid = os.getpid() & 0xFFFF
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, ("127.0.0.1", port))
        data = s.recv(4096)
    except socket.timeout:
        return {"rcode": "timeout", "answers": []}
    finally:
        s.close()
    rcode = data[3] & 0x0F
    ancount = struct.unpack("!H", data[6:8])[0]
    _, _, pos = parse_question(data)
    answers = []
    for _ in range(ancount):
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while data[pos]:
                pos += 1 + data[pos]
            pos += 1
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        rdata = data[pos + 10 : pos + 10 + rdlen]
        pos += 10 + rdlen
        if rtype == 1:
            answers.append(socket.inet_ntoa(rdata))
        elif rtype == 28:
            answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype == 16:
            answers.append(rdata[1:].decode(errors="replace"))
    return {"rcode": rcode, "answers": answers}


FAKE_NET = ipaddress.ip_network("198.18.0.0/16")


def classify(result):
    """把应答归为来源类别，Fake-IP 的具体地址两边各自分配，只比较网段。"""
    if result["rcode"] != 0 or not result["answers"]:
        return {"rcode": result["rcode"], "answers": result["answers"]}
    out = []
    for a in result["answers"]:
        try:
            if ipaddress.ip_address(a) in FAKE_NET:
                out.append("fake-ip")
                continue
        except ValueError:
            pass
        out.append(a)
    return {"rcode": 0, "answers": out}


CASES = [
    ("plain.test", 1, "主组"),
    ("www.policy.test", 1, "nameserver-policy +.policy.test"),
    ("polluted.test", 1, "主组地址落入 fallback-filter ipcidr，改用 fallback"),
    ("x.forced.test", 1, "fallback-filter domain 只查 fallback"),
    ("empty.test", 1, "主组 NXDOMAIN，改用 fallback"),
    ("host.lan", 1, "hosts 精确名"),
    ("a.wild.lan", 1, "hosts 通配 *.wild.lan"),
    ("fake.example", 1, "Fake-IP"),
    ("skip.real.test", 1, "fake-ip-filter 跳过 Fake-IP，走主组"),
    ("plain.test", 16, "TXT 透传主组"),
    ("www.policy.test", 16, "TXT 透传策略组"),
    ("plain.test", 28, "ipv6: false 时 AAAA 空应答"),
    ("a.ord.test", 1, "rule-set 写在域名通配之前，先命中 rule-set"),
    ("a.rev.test", 1, "域名通配写在 rule-set 之前，先命中通配"),
]


def dns_section(main, policy, fallback, third, listen):
    return {
        "enable": True,
        "listen": f"127.0.0.1:{listen}",
        "ipv6": False,
        "use-system-hosts": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": ["+.real.test", "+.policy.test", "plain.test", "polluted.test", "+.forced.test",
                           "empty.test", "+.ord.test", "+.rev.test"],
        "default-nameserver": [f"udp://127.0.0.1:{main}"],
        "nameserver": [f"udp://127.0.0.1:{main}"],
        "fallback": [f"udp://127.0.0.1:{fallback}"],
        "fallback-filter": {"geoip": False, "ipcidr": ["198.51.100.0/24"], "domain": ["+.forced.test"]},
        "nameserver-policy": {
            "+.policy.test": f"udp://127.0.0.1:{policy}",
            "rule-set:ord": f"udp://127.0.0.1:{policy}",
            "+.ord.test": f"udp://127.0.0.1:{third}",
            "+.rev.test": f"udp://127.0.0.1:{third}",
            "rule-set:rev": f"udp://127.0.0.1:{policy}",
        },
    }


def to_yaml(value, indent=0):
    pad = "  " * indent
    lines = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{json.dumps(k)}:")
                lines.append(to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}{json.dumps(k)}: {json.dumps(v)}")
    else:
        for v in value:
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}-")
                lines.append(to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}- {json.dumps(v)}")
    return "\n".join(lines)


def write_yaml(path, value):
    with open(path, "w", encoding="utf-8") as f:
        f.write(to_yaml(value) + "\n")


def wait_answer(port, deadline=15.0):
    end = time.time() + deadline
    while time.time() < end:
        if query(port, "host.lan", 1, timeout=0.5)["rcode"] != "timeout":
            return True
        time.sleep(0.2)
    return False


def run(kind, binary, workdir, dns, hosts):
    providers = {}
    for name in ("ord", "rev"):
        path = os.path.join(workdir, f"{name}.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"payload:\n  - '+.{name}.test'\n")
        providers[name] = {"type": "file", "behavior": "domain", "format": "yaml", "path": path}
    cfg = {"mixed-port": free_port(), "log-level": "warning", "mode": "rule", "hosts": hosts,
           "rule-providers": providers, "dns": dns, "rules": ["MATCH,DIRECT"]}
    path = os.path.join(workdir, f"{kind}.yaml")
    write_yaml(path, cfg)
    if kind == "mihomo":
        argv = [binary, "-d", workdir, "-f", path]
    else:
        argv = [binary, "run", "-c", path]
    log = open(os.path.join(workdir, f"{kind}.log"), "w")
    proc = subprocess.Popen(argv, cwd=workdir, stdout=log, stderr=subprocess.STDOUT)
    return proc, log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kerlico", required=True)
    ap.add_argument("--mihomo", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    ports = {k: serve(z) for k, z in ZONES.items()}
    hosts = {"host.lan": "10.9.0.1", "*.wild.lan": "10.9.0.2"}
    results = {}
    with tempfile.TemporaryDirectory() as work:
        for kind, binary in (("mihomo", args.mihomo), ("kerlico", args.kerlico)):
            listen = free_port()
            dns = dns_section(ports["main"], ports["policy"], ports["fallback"], ports["third"], listen)
            proc, log = run(kind, binary, work, dns, hosts)
            try:
                if not wait_answer(listen):
                    print(open(os.path.join(work, f"{kind}.log")).read(), file=sys.stderr)
                    raise SystemExit(f"{kind} DNS 监听未就绪")
                results[kind] = [classify(query(listen, n, t)) for n, t, _ in CASES]
            finally:
                proc.terminate()
                proc.wait(timeout=10)
                log.close()
    rows, mismatches = [], 0
    for (name, qtype, note), m, k in zip(CASES, results["mihomo"], results["kerlico"]):
        same = m == k
        mismatches += 0 if same else 1
        rows.append({"name": name, "qtype": qtype, "case": note, "mihomo": m, "kerlico": k, "match": same})
        print(f"{'OK ' if same else 'DIFF'} {name:18} {qtype:3} {note}: mihomo={m} kerlico={k}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump({"cases": rows, "mismatches": mismatches}, f, ensure_ascii=False, indent=2)
    print(f"{len(rows) - mismatches}/{len(rows)} 一致")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
