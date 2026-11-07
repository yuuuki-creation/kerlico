#!/usr/bin/env python3
"""Mihomo 替换验收：同一份 Mihomo 用户配置分别交给 kerlico 与 mihomo，在临时网络命名空间里逐场景比较。

拓扑（全部在本脚本创建的命名空间内，结束时删除；宿主机只多一个监听 127.0.0.1 的控制接口转发）：

    ka-cli（被测内核 + TUN，探针进程）──┐
    ka-s1..ka-s7（七个代理服务端）    ──┼── ka-net（网桥；“互联网”站点、DNS、订阅与规则文件）
                                       ┘

站点地址挂在 ka-net 回环上，回显服务返回看到的来源地址：来源是 ka-cli 即直连，是第 i 个服务端即经第 i 个节点。
订阅里七个节点分别由 kerlico、sing-box、mihomo 服务端承载；被测内核按真实用户写法加载订阅、规则集与 geo 数据。

用法（root，在 worker 上）：
  tools/acceptance_vs_mihomo.py --kerlico BIN --mihomo BIN --sing-box BIN --assets DIR --work DIR \
      [--cores kerlico,mihomo] [--soak 600] [--skip-dashboard] --out result.json
assets 目录需含 geo/{geoip.dat,geosite.dat,country.mmdb,GeoLite2-ASN.mmdb}、geo/rules/*、ui/（metacubexd）、pylib/（h2）、
pwlib/（playwright 1.49.1 Python 包，供 Playwright 镜像加载）。
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config_v2 import bind_members  # noqa: E402

NET, CLI = "ka-net", "ka-cli"
BRIDGE = "ka-br"
NET_IP, NET_IP6 = "10.77.0.1", "fd77::1"
CLI_IP, CLI_IP6 = "10.77.0.2", "fd77::2"
LOCAL = "10.77.2.1"
DOM_DNS, FOR_DNS = "223.5.5.5", "1.1.1.1"
BAIDU, GOOGLE, TG, CNIP, US, REAL, MSFT = (
    "220.181.38.148", "142.250.1.100", "91.108.4.10", "114.114.114.114", "8.8.4.4", "10.77.3.10", "10.77.3.11")
CN6, US6 = "2400:3200::1", "2001:4860:4860::8888"
US_LIT = "8.8.8.8"
SITES4 = [LOCAL, BAIDU, GOOGLE, TG, CNIP, US, US_LIT, REAL, MSFT]
SITES6 = [CN6, US6]
HIJACKED_DNS = "10.77.9.9"
FAKE_RANGE = ipaddress.ip_network("198.18.0.0/16")
API_PORT = 29090
TUN = "katun"
PW = "accept-" + secrets.token_hex(8)
UUID = str(uuid.uuid4())
SS2022_KEY = base64.b64encode(secrets.token_bytes(16)).decode()
SHORT_ID = "0123abcd"

DNS_TABLE = {
    "www.baidu.com": {"domestic": {"A": [BAIDU], "AAAA": [CN6]}, "foreign": {"A": [US]}},
    "www.qq.com": {"domestic": {"A": [BAIDU]}, "foreign": {"A": [US]}},
    "www.google.com": {"domestic": {"A": [US]}, "foreign": {"A": [GOOGLE], "AAAA": [US6]}},
    "cn-ip.accept.test": {"*": {"A": [CNIP]}},
    "real.accept.test": {"*": {"A": [REAL]}},
    "www.msftconnecttest.com": {"*": {"A": [MSFT]}},
    "lb.corp.accept.test": {"domestic": {"A": ["10.77.3.98"]}, "foreign": {"A": [US]}},
    "v6.accept.test": {"*": {"A": [US], "AAAA": [US6]}},
    "dl.accept.test": {"*": {"A": [GOOGLE]}},
}

SERVERS = [
    # 名称、服务端实现、协议
    ("ss-smux", "kerlico"),
    ("ss2022", "sing-box"),
    ("vmess-ws", "sing-box"),
    ("vless-reality", "sing-box"),
    ("trojan", "mihomo"),
    ("hysteria2", "kerlico"),
    ("tuic", "mihomo"),
]
PREFIX = "[sub] "


def server_ns(i: int) -> str:
    return f"ka-s{i + 1}"


def server_ip(i: int) -> str:
    return f"10.77.0.{11 + i}"


def server_ip6(i: int) -> str:
    return f"fd77::{11 + i:x}"


PEER_OF = {CLI_IP: "DIRECT", CLI_IP6: "DIRECT"}
for _i, (_name, _) in enumerate(SERVERS):
    PEER_OF[server_ip(_i)] = PREFIX + _name
    PEER_OF[server_ip6(_i)] = PREFIX + _name


# ---------------------------------------------------------------- ka-net 服务

FAKENET = r'''
import asyncio, base64, json, os, socket, ssl, struct, sys, time
import h2.config, h2.connection, h2.events

cfg = json.load(open(sys.argv[1]))
ROOT = cfg["root"]
TABLE = cfg["dns"]
DNSLOG = []

def tls_ctx(alpn):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cfg["cert"], cfg["key"])
    ctx.set_alpn_protocols(alpn)
    def on_sni(obj, name, _ctx):
        obj.ka_sni = name
    ctx.sni_callback = on_sni
    return ctx

def answer(kind, transport, query):
    qid, flags, qd = struct.unpack("!HHH", query[:6])
    pos, labels = 12, []
    while query[pos]:
        labels.append(query[pos + 1:pos + 1 + query[pos]].decode(errors="replace"))
        pos += 1 + query[pos]
    qtype = struct.unpack("!H", query[pos + 1:pos + 3])[0]
    question = query[12:pos + 5]
    name = ".".join(labels).lower()
    tname = {1: "A", 28: "AAAA"}.get(qtype, str(qtype))
    DNSLOG.append({"server": kind, "transport": transport, "name": name, "qtype": tname, "t": time.time()})
    entry = TABLE.get(name)
    if entry is None:
        view = {"A": [cfg["default_a"]]}
    else:
        view = entry.get(kind) or entry.get("*") or {}
    ips = view.get(tname, [])
    out = struct.pack("!HHHHHH", qid, 0x8180 | (flags & 0x0100), 1, len(ips), 0, 0) + question
    for ip in ips:
        raw = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        out += struct.pack("!HHHIH", 0xC00C, qtype, 1, 60, len(raw)) + raw
    return out

class DnsUdp(asyncio.DatagramProtocol):
    def __init__(self, kind):
        self.kind = kind
    def connection_made(self, t):
        self.t = t
    def datagram_received(self, data, addr):
        try:
            self.t.sendto(answer(self.kind, "udp", data), addr)
        except Exception as e:
            print("dns udp", e, flush=True)

def dns_stream(kind, transport):
    async def handle(reader, writer):
        try:
            while True:
                n = struct.unpack("!H", await reader.readexactly(2))[0]
                q = await reader.readexactly(n)
                r = answer(kind, transport, q)
                writer.write(struct.pack("!H", len(r)) + r)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
    return handle

async def doh(reader, writer):
    conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
    conn.initiate_connection()
    writer.write(conn.data_to_send())
    streams = {}
    try:
        while True:
            data = await reader.read(65535)
            if not data:
                break
            for ev in conn.receive_data(data):
                if isinstance(ev, h2.events.RequestReceived):
                    streams[ev.stream_id] = [dict(ev.headers), b""]
                elif isinstance(ev, h2.events.DataReceived):
                    streams[ev.stream_id][1] += ev.data
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    headers, body = streams.pop(ev.stream_id)
                    if headers.get(":method") == "GET":
                        param = headers.get(":path", "").split("dns=", 1)[-1].split("&")[0]
                        body = base64.urlsafe_b64decode(param + "=" * (-len(param) % 4))
                    resp = answer("foreign", "doh", body)
                    conn.send_headers(ev.stream_id, [(":status", "200"), ("content-type", "application/dns-message"),
                                                     ("content-length", str(len(resp)))])
                    conn.send_data(ev.stream_id, resp, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()
    except Exception as e:
        print("doh", type(e).__name__, e, flush=True)
    finally:
        writer.close()

def route(method, path, peer, local, host, sni):
    if path == "/generate_204":
        return 204, b""
    if path == "/dnslog":
        return 200, json.dumps(DNSLOG).encode()
    if path == "/dnslog/clear":
        DNSLOG.clear()
        return 200, b"{}"
    if path.startswith("/bytes/"):
        return 200, bytes(int(path[7:]))
    for prefix in ("/rules/", "/geo/", "/sub"):
        if path.startswith(prefix):
            file = os.path.join(ROOT, path.lstrip("/"))
            if os.path.isfile(file):
                return 200, open(file, "rb").read()
            return 404, b""
    return 200, json.dumps({"peer": peer, "local": local, "host": host, "sni": sni}).encode()

async def http(reader, writer):
    peer = writer.get_extra_info("peername")[0].removeprefix("::ffff:")
    local = writer.get_extra_info("sockname")[0].removeprefix("::ffff:")
    obj = writer.get_extra_info("ssl_object")
    sni = getattr(obj, "ka_sni", None) if obj is not None else None
    try:
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode(errors="replace").split("\r\n")
            method, path = lines[0].split(" ")[:2]
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if int(headers.get("content-length", "0") or 0):
                await reader.readexactly(int(headers["content-length"]))
            status, body = route(method, path, peer, local, headers.get("host", ""), sni)
            reason = {200: "OK", 204: "No Content", 404: "Not Found"}[status]
            writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\n"
                         f"Content-Length: {len(body)}\r\n\r\n".encode())
            for i in range(0, len(body), 1 << 16):
                writer.write(body[i:i + (1 << 16)])
                await writer.drain()
            if headers.get("connection", "").lower() == "close":
                break
    except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError, ssl.SSLError, ValueError):
        pass
    finally:
        writer.close()

class Echo(asyncio.DatagramProtocol):
    def connection_made(self, t):
        self.t = t
    def datagram_received(self, data, addr):
        self.t.sendto(("peer=" + addr[0].removeprefix("::ffff:") + "|").encode() + data, addr)

async def main():
    loop = asyncio.get_running_loop()
    site_tls = tls_ctx(["http/1.1"])
    await asyncio.start_server(http, host=["0.0.0.0", "::"], port=80, reuse_address=True)
    for ip in cfg["tls_sites"]:
        await asyncio.start_server(http, host=ip, port=443, ssl=site_tls, reuse_address=True)
    for ip in cfg["sites4"] + cfg["sites6"]:
        for port in (443, 7):
            await loop.create_datagram_endpoint(Echo, local_addr=(ip, port))
    for kind, ip in (("domestic", cfg["dom_dns"]), ("foreign", cfg["for_dns"])):
        await loop.create_datagram_endpoint(lambda k=kind: DnsUdp(k), local_addr=(ip, 53))
        await asyncio.start_server(dns_stream(kind, "tcp"), host=ip, port=53, reuse_address=True)
    await asyncio.start_server(dns_stream("foreign", "dot"), host=cfg["for_dns"], port=853, ssl=tls_ctx(["dot"]))
    await asyncio.start_server(doh, host=cfg["for_dns"], port=443, ssl=tls_ctx(["h2"]))
    print("fakenet ready", flush=True)
    await asyncio.Event().wait()

asyncio.run(main())
'''

# ---------------------------------------------------------------- 探针

PROBE = r'''
import argparse, json, random, socket, ssl, struct, sys, time

def query(name, qtype):
    q = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", qtype, 1)

def parse(reply):
    count = struct.unpack("!H", reply[6:8])[0]
    pos = 12
    while reply[pos]:
        pos += 1 + reply[pos]
    pos += 5
    out = []
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
            out.append(socket.inet_ntop(socket.AF_INET, reply[pos:pos + 4]))
        elif rtype == 28 and rlen == 16:
            out.append(socket.inet_ntop(socket.AF_INET6, reply[pos:pos + 16]))
        pos += rlen
    return out

def dns(server, port, name, qtype, tcp=False, tries=4):
    q = query(name, qtype)
    last = None
    for _ in range(tries):
        try:
            if tcp:
                s = socket.create_connection((server, port), timeout=3)
                s.sendall(struct.pack("!H", len(q)) + q)
                n = struct.unpack("!H", s.recv(2))[0]
                r = b""
                while len(r) < n:
                    r += s.recv(n - len(r))
                s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(q, (server, port))
                r = s.recv(4096)
                s.close()
            return parse(r)
        except OSError as e:
            last = e
            time.sleep(0.3)
    raise OSError(f"dns {name}: {last}")

def is_ip(text):
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in text else socket.AF_INET, text)
        return True
    except OSError:
        return False

def read_response(s):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(65536)
        if not chunk:
            raise OSError("closed before headers")
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ")[1])
    length = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            length = int(v)
    while len(body) < length:
        chunk = s.recv(min(1 << 20, length - len(body)))
        if not chunk:
            raise OSError("closed in body")
        body += chunk
    return status, body

p = argparse.ArgumentParser()
p.add_argument("mode")
p.add_argument("--target")
p.add_argument("--port", type=int, default=80)
p.add_argument("--host")
p.add_argument("--path", default="/info")
p.add_argument("--tls")
p.add_argument("--v6", action="store_true")
p.add_argument("--dns", default="__HIJACKED__")
p.add_argument("--dns-port", type=int, default=53)
p.add_argument("--tcp", action="store_true")
p.add_argument("--hold", type=float, default=0)
p.add_argument("--qtype", default="A")
a = p.parse_args()
out = {"ok": False}
s = None
try:
    if a.mode == "dns":
        out["answers"] = dns(a.dns, a.dns_port, a.target, 28 if a.qtype == "AAAA" else 1, a.tcp)
        out["ok"] = True
    else:
        ip = a.target if is_ip(a.target) else (dns(a.dns, a.dns_port, a.target, 28 if a.v6 else 1) or [""])[0]
        out["ip"] = ip
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        if a.mode == "http":
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((ip, a.port))
            out["sport"] = s.getsockname()[1]
            if a.tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=a.tls)
            host = a.host or a.target
            s.sendall(f"GET {a.path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ka-probe\r\n\r\n".encode())
            status, body = read_response(s)
            out["status"] = status
            out["body"] = json.loads(body) if a.path == "/info" else len(body)
            out["ok"] = True
        elif a.mode == "udp":
            s = socket.socket(family, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((ip, a.port))
            out["sport"] = s.getsockname()[1]
            for _ in range(4):
                s.send(b"ka-udp")
                try:
                    reply = s.recv(2048).decode(errors="replace")
                    out["peer"] = reply.split("|")[0].removeprefix("peer=")
                    out["ok"] = reply.endswith("|ka-udp")
                    break
                except socket.timeout:
                    pass
except Exception as e:
    out["error"] = f"{type(e).__name__}: {e}"
print(json.dumps(out), flush=True)
if a.hold:
    time.sleep(a.hold)
if s:
    s.close()
'''.replace("__HIJACKED__", HIJACKED_DNS)

SOAK = r'''
import json, os, random, socket, ssl, struct, sys, threading, time
exec(open(sys.argv[1]).read().split("p = argparse.ArgumentParser()")[0])
DURATION = float(sys.argv[2])
end = time.time() + DURATION
stats = {}
lock = threading.Lock()

def record(kind, ok, size=0):
    with lock:
        s = stats.setdefault(kind, {"ok": 0, "fail": 0, "bytes": 0})
        s["ok" if ok else "fail"] += 1
        s["bytes"] += size

def http_get(ip, host, path, sni=None, port=80):
    s = socket.create_connection((ip, port), timeout=10)
    if sni:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=sni)
    s.settimeout(15)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    status, body = read_response(s)
    s.close()
    return status, len(body)

def loop(kind, fn, pause):
    while time.time() < end:
        try:
            size = fn()
            record(kind, True, size)
        except Exception as e:
            record(kind, False)
            with lock:
                stats.setdefault("errors", {}).setdefault(kind, str(e)[:120])
        time.sleep(pause)

def download():
    ip = dns("__HIJACKED__", 53, "dl.accept.test", 1)[0]
    return http_get(ip, "dl.accept.test", "/bytes/2097152")[1]

def direct():
    ip = dns("__HIJACKED__", 53, "www.baidu.com", 1)[0]
    return http_get(ip, "www.baidu.com", "/info")[1]

def tls_sniffed():
    return http_get("__US__", "www.google.com", "/bytes/65536", sni="www.google.com", port=443)[1]

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect(("__GOOGLE__", 443))
    got = 0
    for i in range(20):
        s.send(b"x" * 1200)
        got += len(s.recv(2048))
    s.close()
    return got

def dns_random():
    name = f"r{random.randint(0, 1 << 30)}.soak.accept.test"
    answers = dns("__HIJACKED__", 53, name, 1, tries=1)
    if not answers:
        raise OSError("empty answer")
    return 0

workers = [("download", download, 0.3)] * 3 + [("direct", direct, 0.2)] * 2 + [("tls", tls_sniffed, 0.2)] * 2 + \
    [("udp", udp, 0.2)] * 2 + [("dns", dns_random, 0.05)] * 2
threads = [threading.Thread(target=loop, args=w, daemon=True) for w in workers]
for t in threads:
    t.start()
for t in threads:
    t.join()
print(json.dumps(stats), flush=True)
'''.replace("__HIJACKED__", HIJACKED_DNS).replace("__US__", US).replace("__GOOGLE__", GOOGLE)

# ---------------------------------------------------------------- 配置

CLIENT_YAML = """\
mixed-port: 7890
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
find-process-mode: strict
external-controller: 127.0.0.1:9090
external-ui: ui
profile:
  store-selected: true
  store-fake-ip: true
geodata-mode: true
geo-auto-update: false
geox-url:
  geoip: "http://{LOCAL}/geo/geoip.dat"
  geosite: "http://{LOCAL}/geo/geosite.dat"
  mmdb: "http://{LOCAL}/geo/country.mmdb"
  asn: "http://{LOCAL}/geo/GeoLite2-ASN.mmdb"

sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "Mijia Cloud"
    - "+.push.apple.com"

tun:
  enable: true
  stack: mixed
  device: {TUN}
  auto-route: true
  auto-detect-interface: true
  strict-route: true
  dns-hijack:
    - any:53

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "+.msftconnecttest.com"
    - "+.corp.accept.test"
    - real.accept.test
  default-nameserver:
    - {DOM_DNS}
  nameserver:
    - "https://{FOR_DNS}/dns-query#skip-cert-verify=true"
  proxy-server-nameserver:
    - {DOM_DNS}
  nameserver-policy:
    "geosite:cn":
      - {DOM_DNS}
    "+.corp.accept.test":
      - "tls://{FOR_DNS}:853#skip-cert-verify=true"

proxy-providers:
  sub:
    type: http
    url: "http://{LOCAL}/sub.yaml"
    path: ./providers/sub.yaml
    interval: 3600
    health-check:
      enable: true
      url: "http://{LOCAL}/generate_204"
      interval: 300
      timeout: 5000
    override:
      skip-cert-verify: true
      udp: true
      additional-prefix: "{PREFIX}"

proxy-groups:
  - name: Proxy
    type: select
    proxies: [Auto, Fallback, LB, Manual, DIRECT]
  - name: Auto
    type: url-test
    use: [sub]
    filter: '(?i)(^|\\] )(ss|trojan|hysteria)'
    url: "http://{LOCAL}/generate_204"
    interval: 300
    tolerance: 50
  - name: Fallback
    type: fallback
    use: [sub]
    filter: "vmess|vless"
    url: "http://{LOCAL}/generate_204"
    interval: 300
  - name: LB
    type: load-balance
    use: [sub]
    filter: "tuic|hysteria2"
    strategy: consistent-hashing
    url: "http://{LOCAL}/generate_204"
    interval: 300
  - name: Manual
    type: select
    use: [sub]
  - name: TG
    type: select
    proxies: [Fallback, Proxy]

rule-providers:
  google:
    type: http
    behavior: domain
    format: yaml
    url: "http://{LOCAL}/rules/google.yaml"
    path: ./ruleset/google.yaml
    interval: 86400
  telegram:
    type: http
    behavior: ipcidr
    format: yaml
    url: "http://{LOCAL}/rules/telegram-ip.yaml"
    path: ./ruleset/telegram.yaml
    interval: 86400
  ads:
    type: http
    behavior: domain
    format: mrs
    url: "http://{LOCAL}/rules/category-ads-all.mrs"
    path: ./ruleset/ads.mrs
    interval: 86400
  private:
    type: http
    behavior: ipcidr
    format: mrs
    url: "http://{LOCAL}/rules/private-ip.mrs"
    path: ./ruleset/private.mrs
    interval: 86400

rules:
{EXTRA}  - PROCESS-NAME,ka-special,Manual
  - RULE-SET,ads,REJECT
  - DOMAIN-SUFFIX,corp.accept.test,LB
  - RULE-SET,google,Proxy
  - RULE-SET,telegram,TG,no-resolve
  - IP-CIDR,10.77.3.0/24,Fallback,no-resolve
  - RULE-SET,private,DIRECT,no-resolve
  - GEOSITE,cn,DIRECT
  - GEOIP,US,Auto,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
"""


def client_yaml(extra_rules: list[str] = ()) -> str:
    text = CLIENT_YAML
    for key, value in {"LOCAL": LOCAL, "TUN": TUN, "DOM_DNS": DOM_DNS, "FOR_DNS": FOR_DNS, "PREFIX": PREFIX}.items():
        text = text.replace("{" + key + "}", value)
    return text.replace("{EXTRA}", "".join(f"  - {r}\n" for r in extra_rules))


def subscription(reality_pub: str, extra: bool = False) -> str:
    s = [server_ip(i) for i in range(len(SERVERS))]
    lines = [
        "proxies:",
        f"  - {{name: ss-smux, type: ss, server: {s[0]}, port: 8388, cipher: aes-128-gcm, password: \"{PW}\", udp: true,"
        " smux: {enabled: true, protocol: smux, max-connections: 4, min-streams: 4}}",
        f"  - {{name: ss2022, type: ss, server: {s[1]}, port: 8389, cipher: 2022-blake3-aes-128-gcm, password: \"{SS2022_KEY}\"}}",
        f"  - {{name: vmess-ws, type: vmess, server: {s[2]}, port: 443, uuid: {UUID}, alterId: 0, cipher: auto, tls: true,"
        " servername: vmess.accept.test, client-fingerprint: chrome, network: ws,"
        " ws-opts: {path: /ws, headers: {Host: vmess.accept.test}}, udp: true}",
        f"  - {{name: vless-reality, type: vless, server: {s[3]}, port: 443, uuid: {UUID}, flow: xtls-rprx-vision, tls: true,"
        f" servername: www.apple.com, client-fingerprint: chrome, network: tcp,"
        f" reality-opts: {{public-key: {reality_pub}, short-id: {SHORT_ID}}}, udp: true}}",
        f"  - {{name: trojan, type: trojan, server: {s[4]}, port: 443, password: \"{PW}\", sni: trojan.accept.test,"
        " client-fingerprint: firefox, udp: true}",
        f"  - {{name: hysteria2, type: hysteria2, server: {s[5]}, port: 443, password: \"{PW}\", sni: hy2.accept.test,"
        " up: \"50 Mbps\", down: \"200 Mbps\"}",
        f"  - {{name: tuic, type: tuic, server: {s[6]}, port: 443, uuid: {UUID}, password: \"{PW}\", sni: tuic.accept.test,"
        " alpn: [h3], congestion-controller: bbr, udp-relay-mode: native}",
    ]
    if extra:
        lines.append(f"  - {{name: ss-extra, type: ss, server: {s[0]}, port: 8388, cipher: aes-128-gcm, password: \"{PW}\", udp: true}}")
    return "\n".join(lines) + "\n"


def server_command(i: int, bins: dict, work: Path, cert: Path, key: Path, reality_priv: str) -> list[str]:
    name, impl = SERVERS[i]
    root = work / server_ns(i)
    root.mkdir(exist_ok=True)
    if impl == "kerlico":
        limits = {"connect_timeout_ms": 8000, "idle_timeout_ms": 60000, "drain_timeout_ms": 500,
                  "max_sessions": 1024, "max_datagram_size": 65507}
        if name == "ss-smux":
            node = {"tag": "node", "type": "shadowsocks", "listen": f"{server_ip(i)}:8388", "outbound": "direct",
                    "options": {"method": "aes-128-gcm", "allow_insecure": True,
                                "multiplex": {"enabled": True, "padding": False}}}
            cred = {"password": PW}
        else:
            node = {"tag": "node", "type": "hysteria2", "listen": f"{server_ip(i)}:443", "outbound": "direct",
                    "options": {"tls": {"certificate_file": str(cert), "private_key_file": str(key)},
                                "salamander_password": None, "limits": {"congestion": "bbr"}}}
            cred = {"auth": PW}
        config = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [],
                  "nodes": [node], "limits": limits}
        bind_members(config, node, [cred])
        path = root / "server.json"
        path.write_text(json.dumps(config))
        return [bins["kerlico"], "run", "-c", str(path)]
    if impl == "sing-box":
        tls = {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}
        if name == "ss2022":
            inbound = {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": SS2022_KEY,
                       "listen_port": 8389}
        elif name == "vmess-ws":
            inbound = {"type": "vmess", "listen_port": 443, "users": [{"uuid": UUID, "alterId": 0}], "tls": tls,
                       "transport": {"type": "ws", "path": "/ws"}}
        else:
            inbound = {"type": "vless", "listen_port": 443, "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
                       "tls": {"enabled": True, "server_name": "www.apple.com",
                               "reality": {"enabled": True, "handshake": {"server": LOCAL, "server_port": 443},
                                           "private_key": reality_priv, "short_id": [SHORT_ID]}}}
        inbound.update(tag="in", listen="::")
        config = {"log": {"level": "warn"}, "dns": {"servers": [{"type": "local", "tag": "local"}]},
                  "inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}],
                  "route": {"default_domain_resolver": "local"}}
        path = root / "server.json"
        path.write_text(json.dumps(config))
        return [bins["sing-box"], "run", "-c", str(path)]
    shutil.copy(cert, root / "cert.pem")
    shutil.copy(key, root / "key.pem")
    cert, key = root / "cert.pem", root / "key.pem"
    if name == "trojan":
        listener = {"name": "in", "type": "trojan", "port": 443, "listen": "::",
                    "users": [{"username": "u", "password": PW}], "certificate": str(cert), "private-key": str(key)}
    else:
        listener = {"name": "in", "type": "tuic", "port": 443, "listen": "::", "users": {UUID: PW},
                    "certificate": str(cert), "private-key": str(key), "congestion-controller": "bbr",
                    "alpn": ["h3"]}
    config = {"mode": "rule", "log-level": "warning", "ipv6": True, "allow-lan": True, "geo-auto-update": False,
              "dns": {"enable": False}, "profile": {"store-selected": False}, "rules": ["MATCH,DIRECT"],
              "listeners": [listener]}
    path = root / "config.yaml"
    path.write_text(json.dumps(config))
    return [bins["mihomo"], "-d", str(root), "-f", str(path)]


# ---------------------------------------------------------------- 进程与命名空间

def sh(*args: str, check: bool = True) -> str:
    return subprocess.run(args, check=check, capture_output=True, text=True).stdout


def in_ns(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]


def with_resolv(ns: str, resolv: Path, args: list[str]) -> list[str]:
    """在私有挂载命名空间里把 resolv.conf 与 nsswitch.conf 换成只走测试 DNS 的版本，宿主机文件不变。

    宿主机 nsswitch 的 `resolve` 会经 systemd-resolved 套接字绕过命名空间查真实 DNS。"""
    nss = resolv.with_name("nsswitch.conf")
    nss.write_text("passwd: files\ngroup: files\nhosts: files dns\n")
    return in_ns(ns, "unshare", "-m", "--propagation", "private", "sh", "-c",
                 f'mount --bind "{resolv}" /etc/resolv.conf && mount --bind "{nss}" /etc/nsswitch.conf && exec "$@"',
                 "sh", *args)


ALL_NS = [NET, CLI] + [server_ns(i) for i in range(len(SERVERS))]


def delete_namespaces() -> None:
    for ns in ALL_NS:
        pids = subprocess.run(["ip", "netns", "pids", ns], capture_output=True, text=True).stdout.split()
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, ValueError):
                os.kill(int(pid), signal.SIGKILL)
        subprocess.run(["ip", "netns", "del", ns], stderr=subprocess.DEVNULL)


@contextlib.contextmanager
def namespaces():
    delete_namespaces()
    try:
        for ns in ALL_NS:
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "-n", NET, "link", "add", BRIDGE, "type", "bridge")
        sh("ip", "-n", NET, "addr", "add", f"{NET_IP}/24", "dev", BRIDGE)
        sh("ip", "-n", NET, "addr", "add", f"{NET_IP6}/64", "dev", BRIDGE, "nodad")
        sh("ip", "-n", NET, "link", "set", BRIDGE, "up")
        for ip in SITES4:
            sh("ip", "-n", NET, "addr", "add", f"{ip}/32", "dev", "lo")
        for ip in (DOM_DNS, FOR_DNS):
            sh("ip", "-n", NET, "addr", "add", f"{ip}/32", "dev", "lo")
        for ip in SITES6:
            sh("ip", "-n", NET, "addr", "add", f"{ip}/128", "dev", "lo", "nodad")
        peers = [(CLI, CLI_IP, CLI_IP6)] + [(server_ns(i), server_ip(i), server_ip6(i)) for i in range(len(SERVERS))]
        for idx, (ns, v4, v6) in enumerate(peers):
            outer = f"ka-v{idx}"
            sh("ip", "-n", NET, "link", "add", outer, "type", "veth", "peer", "name", "eth0", "netns", ns)
            sh("ip", "-n", NET, "link", "set", outer, "master", BRIDGE, "up")
            sh("ip", "-n", ns, "addr", "add", f"{v4}/24", "dev", "eth0")
            sh("ip", "-n", ns, "addr", "add", f"{v6}/64", "dev", "eth0", "nodad")
            sh("ip", "-n", ns, "link", "set", "eth0", "up")
            sh("ip", "-n", ns, "route", "add", "default", "via", NET_IP)
            sh("ip", "-n", ns, "-6", "route", "add", "default", "via", NET_IP6)
        yield
    finally:
        delete_namespaces()


class Proc:
    def __init__(self, args: list[str], log: Path, cwd: Path | None = None, env: dict | None = None):
        self.args, self.log, self.cwd, self.env = args, log, cwd, env
        self.out = log.open("ab")
        self.p = subprocess.Popen(args, stdout=self.out, stderr=subprocess.STDOUT, cwd=cwd,
                                  env={**os.environ, **(env or {})})

    def stop(self, sig=signal.SIGTERM, timeout=15) -> int | None:
        if self.p.poll() is None:
            self.p.send_signal(sig)
            try:
                self.p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        self.out.close()
        return self.p.returncode


def network_state() -> dict[str, str]:
    routes = [line for family in ("-4", "-6")
              for line in sh("ip", "-n", CLI, family, "route", "show", "table", "all").splitlines()
              if " table local" not in line]
    links = re.sub(r"^\d+: ", "", sh("ip", "-n", CLI, "-o", "link", "show"), flags=re.M)
    return {"rules4": sh("ip", "-n", CLI, "-4", "rule", "show"), "rules6": sh("ip", "-n", CLI, "-6", "rule", "show"),
            "routes": "\n".join(sorted(routes)), "nft": sh(*in_ns(CLI, "nft", "list", "ruleset"), check=False),
            "links": "\n".join(sorted(re.sub(r"link/\S+ \S+ brd \S+", "", links).splitlines()))}


def tun_up(timeout: float = 30) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if f"{TUN}:" in sh("ip", "-n", CLI, "-o", "link", "show", check=False) and \
                len(sh("ip", "-n", CLI, "-4", "rule", "show", check=False).splitlines()) > 3:
            time.sleep(1)
            return True
        time.sleep(0.3)
    return False


# ---------------------------------------------------------------- 控制接口

def api(method: str, path: str, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{API_PORT}{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw.strip() else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:300]
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        return 0, str(e)


def q(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def wait_until(predicate, timeout: float, step: float = 0.5):
    end = time.time() + timeout
    value = None
    while time.time() < end:
        try:
            value = predicate()
        except Exception as e:  # 记录最后一次失败原因
            value = f"{type(e).__name__}: {e}"
        if value is True:
            return True
        time.sleep(step)
    return value


# ---------------------------------------------------------------- 一个被测内核

class Core:
    def __init__(self, kind: str, binary: str, work: Path, assets: Path, resolv: Path):
        self.kind, self.binary, self.work, self.assets, self.resolv = kind, binary, work, assets, resolv
        self.home = work / f"home-{kind}"
        self.proc: Proc | None = None
        self.log = work / f"{kind}.log"
        self.probe_py = work / "probe.py"
        self.special = work / "bin" / "ka-special"

    def prepare(self) -> None:
        shutil.rmtree(self.home, ignore_errors=True)
        self.home.mkdir(parents=True)
        geo = self.assets / "geo"
        for src, dst in (("geoip.dat", "GeoIP.dat"), ("geosite.dat", "GeoSite.dat"), ("country.mmdb", "Country.mmdb"),
                         ("GeoLite2-ASN.mmdb", "GeoLite2-ASN.mmdb")):
            shutil.copy(geo / src, self.home / dst)
        shutil.copytree(self.assets / "ui", self.home / "ui")
        self.write_config()

    def write_config(self, extra_rules: list[str] = ()) -> Path:
        path = self.home / "config.yaml"
        path.write_text(client_yaml(extra_rules))
        return path

    def start(self) -> None:
        config = self.home / "config.yaml"
        if self.kind == "kerlico":
            args = [self.binary, "run", "-c", str(config)]
        else:
            args = [self.binary, "-d", str(self.home), "-f", str(config)]
        self.proc = Proc(with_resolv(CLI, self.resolv, args), self.log, cwd=self.home,
                         env={"SAFE_PATHS": str(self.work)})

    @property
    def pid(self) -> int:
        """with_resolv 经 sh exec 换成内核本身，Popen 的 pid 即内核。"""
        return self.proc.p.pid

    def ready(self, timeout=60) -> dict:
        checks = {}
        checks["api /version"] = wait_until(lambda: api("GET", "/version")[0] == 200, timeout)
        checks["tun up"] = tun_up(timeout)

        def provider_full():
            status, body = api("GET", "/providers/proxies/sub")
            return status == 200 and len(body.get("proxies", [])) >= len(SERVERS) or f"{status} {str(body)[:200]}"
        checks["provider sub loaded"] = wait_until(provider_full, timeout)

        def rules_loaded():
            status, body = api("GET", "/providers/rules")
            provs = body.get("providers", {}) if status == 200 else {}
            counts = {k: v.get("ruleCount") for k, v in provs.items()}
            return (len(counts) == 4 and all((c or 0) > 0 for c in counts.values())) or f"{status} {counts}"
        checks["rule providers loaded"] = wait_until(rules_loaded, timeout)
        checks["process alive"] = self.proc.p.poll() is None
        return checks

    def probe(self, *args: str, special=False, hold=0.0, timeout=40) -> dict:
        exe = [str(self.special)] if special else [sys.executable]
        cmd = in_ns(CLI, *exe, str(self.probe_py), *args, *(["--hold", str(hold)] if hold else []))
        env = {**os.environ, "PYTHONHOME": sys.base_prefix} if special else None
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            return json.loads(r.stdout.strip().splitlines()[0])
        except Exception as e:
            return {"ok": False, "error": f"probe {type(e).__name__}: {e}"}

    def probe_conn(self, *args: str, special=False, network="tcp") -> tuple[dict, dict | None]:
        """运行探针并在它保持连接期间从 /connections 取出同一来源端口的连接。"""
        exe = [str(self.special)] if special else [sys.executable]
        env = {**os.environ, "PYTHONHOME": sys.base_prefix} if special else None
        p = subprocess.Popen(in_ns(CLI, *exe, str(self.probe_py), *args, "--hold", "4"), stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, env=env)
        try:
            line = p.stdout.readline()
            result = json.loads(line) if line.strip() else {"ok": False, "error": "no output"}
        except json.JSONDecodeError:
            result = {"ok": False, "error": "bad output " + line[:200]}
        conn = None
        sport = result.get("sport")
        end = time.time() + 3
        while sport and time.time() < end and conn is None:
            status, body = api("GET", "/connections")
            for c in (body or {}).get("connections") or [] if status == 200 else []:
                md = c.get("metadata", {})
                if str(md.get("sourcePort")) == str(sport) and md.get("network", "").lower() == network:
                    conn = c
                    break
            if conn is None:
                time.sleep(0.3)
        with contextlib.suppress(subprocess.TimeoutExpired):
            p.wait(timeout=10)
        if p.poll() is None:
            p.kill()
        return result, conn


def route_check(result: dict, conn: dict | None, rule: str | None, payload: str | None, group: str,
                local: str | None = None, udp=False) -> dict:
    """比较一次探针的规则、链路与真实到达的服务端。"""
    checks: dict = {}
    if group == "REJECT":
        checks["rejected"] = not result.get("ok") or result
        return checks
    checks["traffic ok"] = bool(result.get("ok")) or result.get("error", result)
    peer = result.get("peer") if udp else (result.get("body") or {}).get("peer")
    if conn is None:
        checks["connection listed"] = "not found in /connections"
    else:
        chains = conn.get("chains") or []
        checks["chain ends at group"] = (bool(chains) and chains[-1] == group) or chains
        if rule is not None:
            checks["rule"] = (conn.get("rule") == rule and conn.get("rulePayload", "") == payload) or \
                f"{conn.get('rule')}({conn.get('rulePayload')})"
        if chains:
            checks["arrived via chain head"] = PEER_OF.get(peer) == chains[0] or f"peer {peer} -> {PEER_OF.get(peer)} vs {chains[0]}"
    if group == "DIRECT":
        checks["arrived direct"] = PEER_OF.get(peer) == "DIRECT" or f"peer {peer}"
    if local is not None:
        got = (result.get("body") or {}).get("local")
        # 双栈直连可能选境内 DNS 给出的 A 或 AAAA，两者都证明用了 policy 指定的上游。
        checks["target address"] = got in (local if isinstance(local, tuple) else (local,)) or got
    return checks


def passed(checks: dict) -> bool:
    return all(v is True for v in checks.values())


ROUTES = [
    # 名称、探针参数、是否 ka-special、规则、载荷、组、目标地址、UDP
    ("GEOSITE,cn via fake-ip, policy DNS", ["http", "--target", "www.baidu.com"], False, "GeoSite", "cn", "DIRECT", (BAIDU, CN6), False),
    ("RULE-SET google (yaml domain)", ["http", "--target", "www.google.com"], False, "RuleSet", "google", "Proxy", None, False),
    ("RULE-SET telegram (yaml ipcidr, no-resolve)", ["http", "--target", TG], False, "RuleSet", "telegram", "TG", None, False),
    ("RULE-SET ads (mrs domain) -> REJECT", ["http", "--target", "doubleclick.net"], False, None, None, "REJECT", None, False),
    ("DOMAIN-SUFFIX via fake-ip-filter + sniff", ["http", "--target", "lb.corp.accept.test"], False, "DomainSuffix", "corp.accept.test", "LB", US, False),
    ("IP-CIDR no-resolve", ["http", "--target", REAL, "--host", REAL], False, "IPCIDR", "10.77.3.0/24", "Fallback", REAL, False),
    ("RULE-SET private (mrs ipcidr)", ["http", "--target", LOCAL], False, "RuleSet", "private", "DIRECT", LOCAL, False),
    ("GEOIP,CN with resolve", ["http", "--target", "cn-ip.accept.test"], False, "GeoIP", "cn", "DIRECT", CNIP, False),
    ("GEOIP,US no-resolve on IP literal", ["http", "--target", US_LIT, "--host", US_LIT], False, "GeoIP", "us", "Auto", US_LIT, False),
    ("MATCH", ["http", "--target", "other.accept.test"], False, "Match", "", "Proxy", None, False),
    ("PROCESS-NAME", ["http", "--target", "other.accept.test"], True, "ProcessName", "ka-special", "Manual", None, False),
    ("sniff HTTP Host on IP literal", ["http", "--target", US_LIT, "--host", "www.baidu.com"], False, "GeoSite", "cn", "DIRECT", None, False),
    ("sniff TLS SNI on IP literal", ["http", "--target", US_LIT, "--port", "443", "--tls", "www.baidu.com", "--host", "www.baidu.com"], False, "GeoSite", "cn", "DIRECT", None, False),
]
UDP_ROUTES = [
    ("UDP GEOIP,US no-resolve via proxy", ["udp", "--target", GOOGLE, "--port", "443"], False, "GeoIP", "us", "Auto", None, True),
    ("UDP GEOIP,CN direct", ["udp", "--target", BAIDU, "--port", "443"], False, "GeoIP", "cn", "DIRECT", None, True),
    ("UDP PROCESS-NAME via Manual", ["udp", "--target", US, "--port", "7"], True, "ProcessName", "ka-special", "Manual", None, True),
]
V6_ROUTES = [
    ("IPv6 literal GEOIP,US -> Auto", ["http", "--target", US6, "--host", f"[{US6}]"], False, "GeoIP", "us", "Auto", US6, False),
    ("IPv6 literal GEOIP,CN -> DIRECT", ["http", "--target", CN6, "--host", f"[{CN6}]"], False, "GeoIP", "cn", "DIRECT", CN6, False),
    ("IPv6 UDP literal via proxy", ["udp", "--target", US6, "--port", "443"], False, "GeoIP", "us", "Auto", None, True),
    ("AAAA name then connect (info)", ["http", "--target", "v6.accept.test", "--v6"], False, "Match", "", "Proxy", None, False),
]


def run_routes(core: Core, table) -> dict:
    out = {}
    for name, args, special, rule, payload, group, local, udp in table:
        result, conn = core.probe_conn(*args, special=special, network="udp" if udp else "tcp")
        checks = route_check(result, conn, rule, payload, group, local, udp)
        out[name] = {"pass": passed(checks), "checks": checks,
                     "observed": {"rule": conn and conn.get("rule"), "payload": conn and conn.get("rulePayload"),
                                  "chains": conn and conn.get("chains"), "result": result}}
    return out


def scenario(entries: dict) -> dict:
    return {"pass": all(e["pass"] if isinstance(e, dict) and "pass" in e else e is True
                        for k, e in entries.items() if "(info)" not in k),
            "items": entries}


def log_problems(path: Path, start: int = 0) -> list[str]:
    text = path.read_text(errors="replace")[start:]
    return [line[:300] for line in text.splitlines()
            if re.search(r"level=(error|fatal)|\bERROR\b|\bFATAL\b|panicked", line)]


def dnslog(clear=False) -> list:
    status, body = api_net("/dnslog/clear" if clear else "/dnslog")
    return body if isinstance(body, list) else []


def api_net(path: str):
    r = subprocess.run(in_ns(NET, "curl", "-s", f"http://{LOCAL}{path}"), capture_output=True, text=True)
    try:
        return 200, json.loads(r.stdout)
    except json.JSONDecodeError:
        return 0, r.stdout


def run_core(core: Core, args, results: dict) -> None:
    res = results
    core.prepare()
    baseline = network_state()
    log_offset = 0
    core.start()

    # S1 配置加载
    checks = core.ready()
    time.sleep(3)
    problems = log_problems(core.log)
    checks["no error lines at startup"] = not problems or problems[:8]
    res["config loads"] = {"pass": passed(checks), "checks": checks}
    hold = core.work / "hold"
    if args.debug_hold:
        hold.touch()
        print(f"core {core.kind} held; remove {hold} to continue", flush=True)
    while hold.exists():
        time.sleep(1)
    if not checks["api /version"] is True:
        return

    # S2 订阅成员逐个可用
    status, body = api("GET", "/providers/proxies/sub")
    members = [p["name"] for p in body.get("proxies", [])] if status == 200 else []
    items = {}
    for i, (name, _) in enumerate(SERVERS):
        full = PREFIX + name
        entry: dict = {}
        st, d = api("GET", f"/providers/proxies/sub/{q(full)}/healthcheck?url={q('http://' + LOCAL + '/generate_204')}&timeout=5000", timeout=20)
        entry["delay"] = (st == 200 and isinstance(d, dict) and (d.get("delay") or 0) > 0) or f"{st} {d}"
        st, d = api("PUT", "/proxies/Manual", {"name": full})
        entry["select in Manual"] = st in (200, 204) or f"{st} {d}"
        result, conn = core.probe_conn("http", "--target", "other.accept.test", special=True)
        peer = (result.get("body") or {}).get("peer")
        entry["tcp via member"] = (result.get("ok") and PEER_OF.get(peer) == full) or result.get("error") or f"peer {peer}"
        result, conn = core.probe_conn("udp", "--target", US, "--port", "7", special=True, network="udp")
        entry["udp via member"] = (result.get("ok") and PEER_OF.get(result.get("peer")) == full) or result.get("error") or f"peer {result.get('peer')}"
        items[full] = {"pass": passed(entry), "checks": entry}
    items["provider lists all members"] = sorted(members) == sorted(PREFIX + n for n, _ in SERVERS) or members
    res["provider members usable"] = scenario(items)

    # S3 代理组与规则集
    status, proxies = api("GET", "/proxies")
    proxies = proxies.get("proxies", {}) if status == 200 else {}
    expect = {"Auto": ["ss-smux", "ss2022", "trojan", "hysteria2"], "Fallback": ["vmess-ws", "vless-reality"],
              "LB": ["hysteria2", "tuic"], "Manual": [n for n, _ in SERVERS]}
    items = {}
    for group, names in expect.items():
        got = proxies.get(group, {}).get("all", [])
        items[f"{group} filter members"] = sorted(got) == sorted(PREFIX + n for n in names) or got
    items["Auto picked a member"] = proxies.get("Auto", {}).get("now", "").startswith(PREFIX) or proxies.get("Auto", {}).get("now")
    items["Fallback picks first alive"] = proxies.get("Fallback", {}).get("now") == PREFIX + "vmess-ws" or proxies.get("Fallback", {}).get("now")
    items["types"] = [proxies.get(g, {}).get("type") for g in ("Proxy", "Auto", "Fallback", "LB")] == ["Selector", "URLTest", "Fallback", "LoadBalance"] or \
        [proxies.get(g, {}).get("type") for g in ("Proxy", "Auto", "Fallback", "LB")]
    st, d = api("GET", f"/group/Auto/delay?url={q('http://' + LOCAL + '/generate_204')}&timeout=5000", timeout=30)
    items["group delay test"] = (st == 200 and isinstance(d, dict) and len(d) >= 4) or f"{st} {d}"
    st, rp = api("GET", "/providers/rules")
    items["rule providers"] = {k: {"behavior": v.get("behavior"), "format": v.get("format"), "count": v.get("ruleCount")}
                               for k, v in (rp.get("providers", {}) if st == 200 else {}).items()}
    items["rule providers"] = (len(items["rule providers"]) == 4) or items["rule providers"]
    res["groups and rule providers"] = scenario(items)
    api("PUT", "/proxies/Manual", {"name": PREFIX + "trojan"})

    # S4 规则分流
    res["TCP rule routing via TUN"] = scenario(run_routes(core, ROUTES))

    # S5 DNS
    items = {}
    dnslog(clear=True)
    r1 = core.probe("dns", "--target", "other.accept.test")
    r2 = core.probe("dns", "--target", "other.accept.test")
    a1 = (r1.get("answers") or [""])[0]
    items["fake-ip for ordinary name"] = (bool(a1) and ipaddress.ip_address(a1) in FAKE_RANGE) or r1
    items["fake-ip stable"] = (a1 == (r2.get("answers") or [""])[0]) or [r1, r2]
    r = core.probe("dns", "--target", "real.accept.test")
    items["fake-ip-filter exact -> real"] = r.get("answers") == [REAL] or r
    r = core.probe("dns", "--target", "www.msftconnecttest.com")
    items["fake-ip-filter +. -> real"] = r.get("answers") == [MSFT] or r
    r = core.probe("dns", "--target", "dot.corp.accept.test")
    items["nameserver-policy DoT answer"] = r.get("answers") == [US] or r
    log = dnslog()
    items["policy used DoT upstream"] = any(e["name"] == "dot.corp.accept.test" and e["transport"] == "dot" for e in log) or \
        [e for e in log if "corp" in e["name"]]
    r = core.probe("dns", "--target", "www.baidu.com")
    items["geosite:cn name gets fake-ip"] = (bool(r.get("answers")) and ipaddress.ip_address(r["answers"][0]) in FAKE_RANGE) or r
    r = core.probe("dns", "--target", "other.accept.test", "--tcp")
    items["TCP DNS to any:53 (info)"] = {"answers": r.get("answers"), "error": r.get("error")}
    r = core.probe("dns", "--target", "real.accept.test", "--dns", "127.0.0.1", "--dns-port", "1053")
    items["dns.listen 1053"] = r.get("answers") == [REAL] or r
    r = core.probe("dns", "--target", "v6.accept.test", "--qtype", "AAAA")
    items["AAAA answer (info)"] = r.get("answers") or r
    dnslog(clear=True)
    core.probe("http", "--target", "cn-ip.accept.test")
    log = dnslog()
    items["GEOIP resolve uses DoH (nameserver)"] = any(e["name"] == "cn-ip.accept.test" and e["transport"] == "doh" for e in log) or \
        [e for e in log if "cn-ip" in e["name"]]
    dnslog(clear=True)
    core.probe("http", "--target", "www.qq.com")
    log = dnslog()
    items["geosite:cn policy -> domestic UDP"] = any(e["name"] == "www.qq.com" and e["server"] == "domestic" for e in log) and \
        not any(e["name"] == "www.qq.com" and e["server"] == "foreign" for e in log) or [e for e in log if "qq" in e["name"]]
    res["DNS"] = scenario(items)

    # S6 UDP 与 S7 IPv6
    res["UDP via TUN"] = scenario(run_routes(core, UDP_ROUTES))
    res["IPv6"] = scenario(run_routes(core, V6_ROUTES))

    # S8 面板
    if args.skip_dashboard:
        res["dashboard (metacubexd)"] = {"pass": None, "items": {"skipped": True}}
    else:
        res["dashboard (metacubexd)"] = dashboard(core, args)

    # S9 PUT /configs 热重载
    items = {}
    reload_path = core.home / "config-reload.yaml"
    reload_path.write_text(client_yaml(["DOMAIN-SUFFIX,reload.accept.test,DIRECT"]))
    before = core.probe_conn("http", "--target", "reload.accept.test")
    items["before reload: MATCH"] = (before[1] or {}).get("rule") == "Match" or (before[1] or {}).get("rule")
    st, d = api("PUT", "/configs?force=true", {"path": str(reload_path)}, timeout=60)
    items["PUT /configs accepted"] = st in (200, 204) or f"{st} {d}"
    wait_until(lambda: api("GET", "/version")[0] == 200, 30)
    tun_up(30)
    time.sleep(2)
    result, conn = core.probe_conn("http", "--target", "reload.accept.test")
    items["new rule applies"] = passed(route_check(result, conn, "DomainSuffix", "reload.accept.test", "DIRECT")) or \
        route_check(result, conn, "DomainSuffix", "reload.accept.test", "DIRECT")
    result, conn = core.probe_conn("http", "--target", "www.google.com")
    items["proxy path still works"] = passed(route_check(result, conn, "RuleSet", "google", "Proxy")) or route_check(result, conn, "RuleSet", "google", "Proxy")
    items["process alive"] = core.proc.p.poll() is None
    res["hot reload PUT /configs"] = scenario(items)

    # S10 SIGHUP
    items = {}
    core.write_config(["DOMAIN-SUFFIX,reload.accept.test,Fallback"])
    core.proc.p.send_signal(signal.SIGHUP)
    time.sleep(4)
    alive = core.proc.p.poll() is None
    items["process alive after SIGHUP"] = alive or f"exit {core.proc.p.returncode}"
    if alive:
        wait_until(lambda: api("GET", "/version")[0] == 200, 30)
        tun_up(30)
        result, conn = core.probe_conn("http", "--target", "reload.accept.test")
        items["file rule applies"] = passed(route_check(result, conn, "DomainSuffix", "reload.accept.test", "Fallback")) or \
            route_check(result, conn, "DomainSuffix", "reload.accept.test", "Fallback")
    res["hot reload SIGHUP"] = scenario(items)
    core.write_config()
    if not alive:
        core.proc.stop()
        core.start()
        core.ready()
    else:
        api("PUT", "/configs?force=true", {"path": str(core.home / "config.yaml")}, timeout=60)
        wait_until(lambda: api("GET", "/version")[0] == 200, 30)
        tun_up(30)
        time.sleep(2)

    # S11 模式切换
    items = {}
    st, d = api("PATCH", "/configs", {"mode": "global"})
    items["PATCH mode global"] = (st in (200, 204) and api("GET", "/configs")[1].get("mode") == "global") or f"{st} {d}"
    st, d = api("PUT", "/proxies/GLOBAL", {"name": "Fallback"})
    items["select GLOBAL -> Fallback"] = st in (200, 204) or f"{st} {d}"
    time.sleep(0.5)
    result, conn = core.probe_conn("http", "--target", "www.baidu.com")
    c = route_check(result, conn, None, None, "GLOBAL")
    items["global: CN site goes via GLOBAL"] = passed(c) or c
    st, d = api("PATCH", "/configs", {"mode": "direct"})
    items["PATCH mode direct"] = (st in (200, 204) and api("GET", "/configs")[1].get("mode") == "direct") or f"{st} {d}"
    time.sleep(0.5)
    result, conn = core.probe_conn("http", "--target", "www.google.com")
    c = route_check(result, conn, None, None, "DIRECT")
    items["direct: proxied site goes DIRECT"] = passed(c) or c
    st, d = api("PATCH", "/configs", {"mode": "rule"})
    items["PATCH mode rule"] = (st in (200, 204) and api("GET", "/configs")[1].get("mode") == "rule") or f"{st} {d}"
    result, conn = core.probe_conn("http", "--target", "www.google.com")
    c = route_check(result, conn, "RuleSet", "google", "Proxy")
    items["rule mode restored"] = passed(c) or c
    res["mode switch global/direct"] = scenario(items)

    # S12 订阅刷新
    items = {}
    sub = args.served / "sub.yaml"
    original = sub.read_text()
    sub.write_text(subscription(args.reality_pub, extra=True))
    _, before = api("GET", "/providers/proxies/sub")
    st, d = api("PUT", "/providers/proxies/sub", timeout=30)
    items["PUT /providers/proxies/sub"] = st in (200, 204) or f"{st} {d}"
    _, after = api("GET", "/providers/proxies/sub")
    names = [p["name"] for p in (after or {}).get("proxies", [])]
    items["new member listed"] = PREFIX + "ss-extra" in names or names
    items["updatedAt advanced"] = (after or {}).get("updatedAt") != (before or {}).get("updatedAt") or (after or {}).get("updatedAt")
    _, proxies = api("GET", "/proxies")
    items["Auto filter picks new member"] = PREFIX + "ss-extra" in proxies.get("proxies", {}).get("Auto", {}).get("all", []) or \
        proxies.get("proxies", {}).get("Auto", {}).get("all")
    st, d = api("PUT", "/proxies/Manual", {"name": PREFIX + "ss-extra"})
    result, conn = core.probe_conn("http", "--target", "other.accept.test", special=True)
    items["new member carries traffic"] = (result.get("ok") and (conn or {}).get("chains", [""])[0] == PREFIX + "ss-extra"
                                           and PEER_OF.get(result["body"]["peer"]) == PREFIX + "ss-smux") or [result, conn and conn.get("chains")]
    sub.write_text(original)
    api("PUT", "/providers/proxies/sub", timeout=30)
    _, after = api("GET", "/providers/proxies/sub")
    items["member removed after revert"] = PREFIX + "ss-extra" not in [p["name"] for p in (after or {}).get("proxies", [])]
    api("PUT", "/proxies/Manual", {"name": PREFIX + "trojan"})
    res["subscription refresh"] = scenario(items)

    # S13 长稳
    res["soak"] = soak(core, args.soak)

    # S14 重启与残留
    items = {}
    running = network_state()
    rc = core.proc.stop(signal.SIGTERM, timeout=30)
    time.sleep(1.5)
    after = network_state()
    items["SIGTERM exit code"] = rc in (0, -15, 143) or rc
    items["clean exit restores netns"] = after == baseline or {k: after[k] for k in after if after[k] != baseline[k]}
    core.start()
    ok = core.ready()
    first = network_state()
    items["restart ready"] = passed(ok) or ok
    core.proc.stop(signal.SIGKILL)
    time.sleep(1)
    core.start()
    ok = core.ready()
    second = network_state()
    items["start after kill -9 ready"] = passed(ok) or ok
    items["no duplicated rules after kill -9"] = (second["rules4"] == first["rules4"] and second["rules6"] == first["rules6"]) or \
        {"first": first["rules4"] + first["rules6"], "second": second["rules4"] + second["rules6"]}
    result, conn = core.probe_conn("http", "--target", "www.google.com")
    c = route_check(result, conn, "RuleSet", "google", "Proxy")
    items["traffic after restart"] = passed(c) or c
    items["rules same as first run"] = (running["rules4"] == first["rules4"]) or {"running": running["rules4"], "restart": first["rules4"]}
    core.proc.stop(signal.SIGTERM, timeout=30)
    time.sleep(1.5)
    after = network_state()
    items["final exit restores netns"] = after == baseline or {k: after[k] for k in after if after[k] != baseline[k]}
    res["restart leaves no stale rules"] = scenario(items)
    res["log problems (info)"] = log_problems(core.log)[:30]


def proc_sample(pid: int) -> tuple[int, float]:
    status = Path(f"/proc/{pid}/status").read_text()
    rss = int(re.search(r"VmRSS:\s+(\d+)", status).group(1))
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    cpu = (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    return rss, cpu


def soak(core: Core, seconds: int) -> dict:
    script = core.work / "soak.py"
    script.write_text(SOAK)
    p = subprocess.Popen(in_ns(CLI, sys.executable, str(script), str(core.probe_py), str(seconds)),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    samples = []
    start_rss, start_cpu = proc_sample(core.pid)
    t0 = time.time()
    last_cpu, last_t = start_cpu, t0
    while p.poll() is None:
        time.sleep(5)
        with contextlib.suppress(FileNotFoundError, AttributeError):
            rss, cpu = proc_sample(core.pid)
            now = time.time()
            st, conns = api("GET", "/connections", timeout=5)
            n = len((conns or {}).get("connections") or []) if st == 200 else -1
            fds = len(os.listdir(f"/proc/{core.pid}/fd"))
            samples.append({"t": round(now - t0), "rss_kib": rss, "cpu_pct": round(100 * (cpu - last_cpu) / (now - last_t), 1),
                            "connections": n, "fds": fds})
            last_cpu, last_t = cpu, now
    out, err = p.communicate()
    try:
        stats = json.loads(out.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        stats = {"error": err[-500:]}
    time.sleep(15)
    end_rss, end_cpu = proc_sample(core.pid)
    st, conns = api("GET", "/connections")
    idle_conns = len([c for c in (conns or {}).get("connections") or []
                      if c.get("metadata", {}).get("network", "").lower() == "tcp"]) if st == 200 else -1
    total = sum(v.get("ok", 0) + v.get("fail", 0) for k, v in stats.items() if isinstance(v, dict) and "ok" in v)
    fails = sum(v.get("fail", 0) for k, v in stats.items() if isinstance(v, dict) and "ok" in v)
    rss = [s["rss_kib"] for s in samples] or [start_rss]
    cpu = [s["cpu_pct"] for s in samples] or [0]
    summary = {
        "duration_s": seconds, "requests": total, "failures": fails,
        "bytes": sum(v.get("bytes", 0) for v in stats.values() if isinstance(v, dict) and "bytes" in v),
        "rss_mib": {"start": round(start_rss / 1024, 1), "peak": round(max(rss) / 1024, 1),
                    "avg": round(sum(rss) / len(rss) / 1024, 1), "end_idle": round(end_rss / 1024, 1)},
        "cpu_pct": {"avg": round(sum(cpu) / len(cpu), 1), "peak": max(cpu)},
        "cpu_seconds": round(end_cpu - start_cpu, 1),
        "connections_after_idle_10s": idle_conns, "fds_peak": max((s["fds"] for s in samples), default=0),
    }
    checks = {"process alive": core.proc.p.poll() is None,
              "failure rate < 1%": (total > 0 and fails / total < 0.01) or f"{fails}/{total} {stats.get('errors')}",
              "TCP connections drain after idle": (0 <= idle_conns <= 5) or idle_conns}
    return {"pass": passed(checks), "checks": checks, "summary": summary, "stats": stats, "samples": samples}


# ---------------------------------------------------------------- 面板

DASHBOARD = r'''
import json, sys, time, urllib.request
from playwright.sync_api import sync_playwright

base, out, core, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
checks = {}

def api(path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read())

def wait_for(name, predicate, seconds=20):
    deadline = time.time() + seconds
    value = None
    while time.time() < deadline:
        try:
            value = predicate()
        except Exception as error:
            value = f"error: {error}"
        if value is True:
            checks[name] = True
            return True
        time.sleep(0.5)
    checks[name] = f"failed: {value}"[:300]
    return False

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1400, "height": 900})
    sockets, frames, failures = [], {}, []

    def on_socket(ws):
        sockets.append(ws.url)
        key = ws.url.split("?")[0].rsplit("/", 1)[-1]
        ws.on("framereceived", lambda _: frames.__setitem__(key, frames.get(key, 0) + 1))

    page.on("websocket", on_socket)
    page.on("response", lambda r: failures.append((r.status, r.request.method, r.url.replace(base, "")))
            if r.status >= 400 and r.url.startswith(base) else None)
    page.goto(base + f"/ui/#/setup?hostname=127.0.0.1&port={port}&http=1", wait_until="networkidle")
    page.wait_for_timeout(2500)
    root = page.url.split("#")[0] + "#/"

    def visit(name):
        page.goto(root + name, wait_until="networkidle")
        page.wait_for_timeout(2500)

    visit("overview")
    page.wait_for_timeout(3000)
    body = page.inner_text("body")
    checks["overview renders"] = ("Download Total" in body and "Memory Usage" in body) or body[:200]
    page.screenshot(path=f"{out}/{core}-overview.png")

    visit("proxies")
    body = page.inner_text("body")
    checks["proxies page lists groups and provider"] = all(n in body for n in ("Proxy", "Auto", "Fallback", "LB", "Manual")) or body[:300]
    page.get_by_text("Manual", exact=True).first.click()
    page.wait_for_timeout(1000)
    # 折叠的 Fallback 组预览也显示成员名，展开的 Manual 列表在它之后，取最后一处。
    page.get_by_text("[sub] vless-reality", exact=True).last.click()
    wait_for("proxy switch reaches the core", lambda: api("/proxies/Manual")["now"] == "[sub] vless-reality" or api("/proxies/Manual")["now"])
    page.screenshot(path=f"{out}/{core}-proxies.png")

    visit("connections")
    wait_for("connections table shows Manual chain", lambda: "Manual → [sub] vless-reality" in page.inner_text("body") or page.inner_text("body")[:300])
    page.screenshot(path=f"{out}/{core}-connections.png")

    visit("logs")
    wait_for("logs stream [TCP] lines", lambda: "[TCP]" in page.inner_text("body"))
    page.screenshot(path=f"{out}/{core}-logs.png")

    visit("rules")
    body = page.inner_text("body")
    checks["rules page lists rules and providers"] = all(s in body for s in ("corp.accept.test", "ka-special", "google")) or body[:400]
    page.screenshot(path=f"{out}/{core}-rules.png")

    visit("config")
    page.locator("select:has(option[value=global])").first.select_option("global")
    wait_for("mode switch to global reaches the core", lambda: api("/configs")["mode"] == "global" or api("/configs")["mode"])
    visit("logs")
    wait_for("logs show GLOBAL routing", lambda: "GLOBAL" in page.inner_text("body"), 25)
    visit("config")
    page.locator("select:has(option[value=global])").first.select_option("rule")
    wait_for("mode switch back to rule", lambda: api("/configs")["mode"] == "rule" or api("/configs")["mode"])

    visit("overview")
    page.wait_for_timeout(3000)
    checks["websocket feeds delivered frames"] = all(frames.get(k, 0) > 0 for k in ("traffic", "memory", "connections", "logs")) or frames
    browser.close()

summary = {"core": core, "checks": checks, "sockets": sorted(set(s.split("?")[0].replace(base.replace("http", "ws"), "") for s in sockets)),
           "frames": frames, "failures": failures}
json.dump(summary, open(f"{out}/{core}-summary.json", "w"), indent=1)
print(json.dumps(summary))
'''


def dashboard(core: Core, args) -> dict:
    shots = core.work / "shots"
    shots.mkdir(exist_ok=True)
    (core.work / "dashboard.py").write_text(DASHBOARD)
    stop = threading.Event()

    def traffic():
        while not stop.is_set():
            core.probe("http", "--target", "other.accept.test", special=True, hold=1.5)
            core.probe("http", "--target", "www.google.com")
            time.sleep(0.5)
    t = threading.Thread(target=traffic, daemon=True)
    t.start()
    subprocess.run(["docker", "rm", "-f", "ka-accept-pw"], capture_output=True)
    r = subprocess.run(["docker", "run", "--rm", "--name", "ka-accept-pw", "--network", "host", "-v", f"{core.work}:/work",
                        "-v", f"{core.assets / 'pwlib'}:/pwlib:ro", "-e", "PYTHONPATH=/pwlib",
                        "-w", "/work", args.playwright_image, "python3", "/work/dashboard.py",
                        f"http://127.0.0.1:{API_PORT}", "/work/shots", core.kind, str(API_PORT)],
                       capture_output=True, text=True, timeout=600)
    stop.set()
    t.join(timeout=30)
    try:
        summary = json.loads((shots / f"{core.kind}-summary.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {"pass": False, "items": {"playwright": r.stdout[-800:] + r.stderr[-1500:]}}
    items = dict(summary["checks"])
    # metacubexd 启动时探测这两个路径，Mihomo 同样回 404。
    probes = {"/api/control/info", "/ui/configs"}
    failures = [f for f in summary["failures"] if f[2].split("?")[0] not in probes]
    items["no HTTP errors from controller"] = not failures or failures[:10]
    api("PUT", "/proxies/Manual", {"name": PREFIX + "trojan"})
    api("PATCH", "/configs", {"mode": "rule"})
    return {"pass": all(v is True for v in items.values()), "items": items,
            "sockets": summary["sockets"], "frames": summary["frames"]}


# ---------------------------------------------------------------- 主流程

def main() -> int:
    parser = argparse.ArgumentParser(description="Mihomo 替换验收：同一份用户配置对照 kerlico 与 mihomo")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--cores", default="kerlico,mihomo")
    parser.add_argument("--soak", type=int, default=600)
    parser.add_argument("--skip-dashboard", action="store_true")
    parser.add_argument("--debug-hold", action="store_true", help="拓扑与服务端就绪后暂停，删除 work/hold 后继续")
    parser.add_argument("--playwright-image", default="mcr.microsoft.com/playwright/python:v1.49.1-noble")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    bins = {"kerlico": str(Path(args.kerlico).resolve()), "mihomo": str(Path(args.mihomo).resolve()),
            "sing-box": str(Path(args.sing_box).resolve())}
    assets = Path(args.assets).resolve()
    work = Path(args.work).resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    (work / "probe.py").write_text(PROBE)
    (work / "bin").mkdir()
    shutil.copy(os.path.realpath(sys.executable), work / "bin" / "ka-special")

    cert, key = work / "cert.pem", work / "key.pem"
    sans = "DNS:*.accept.test,DNS:www.apple.com,DNS:www.baidu.com,DNS:www.google.com,IP:" + FOR_DNS + ",IP:" + LOCAL
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                    "-subj", "/CN=accept.test", "-addext", "subjectAltName=" + sans, "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    keypair = sh(bins["sing-box"], "generate", "reality-keypair")
    reality_priv = re.search(r"PrivateKey:\s*(\S+)", keypair).group(1)
    args.reality_pub = re.search(r"PublicKey:\s*(\S+)", keypair).group(1)

    served = work / "served"
    (served / "rules").mkdir(parents=True)
    (served / "geo").mkdir()
    for f in (assets / "geo" / "rules").iterdir():
        shutil.copy(f, served / "rules" / f.name)
    for f in (assets / "geo").iterdir():
        if f.is_file():
            os.symlink(f, served / "geo" / f.name)
    (served / "sub.yaml").write_text(subscription(args.reality_pub))
    args.served = served
    fake_cfg = work / "fakenet.json"
    fake_cfg.write_text(json.dumps({"root": str(served), "dns": DNS_TABLE, "default_a": US, "cert": str(cert), "key": str(key),
                                    "tls_sites": [LOCAL, BAIDU, GOOGLE, CNIP, US, US_LIT], "sites4": SITES4, "sites6": SITES6,
                                    "dom_dns": DOM_DNS, "for_dns": FOR_DNS}))
    resolv_server = work / "resolv-server.conf"
    resolv_server.write_text(f"nameserver {FOR_DNS}\n")
    resolv_client = work / "resolv-client.conf"
    resolv_client.write_text(f"nameserver {DOM_DNS}\n")

    report: dict = {"versions": {}, "results": {}}
    report["versions"]["mihomo"] = sh(bins["mihomo"], "-v").splitlines()[0]
    report["versions"]["sing-box"] = sh(bins["sing-box"], "version").splitlines()[0]
    report["versions"]["kerlico"] = sh(bins["kerlico"], "--version", check=False).strip()
    procs: list[Proc] = []
    with namespaces():
        try:
            procs.append(Proc(in_ns(NET, "env", f"PYTHONPATH={assets / 'pylib'}", sys.executable, "-c", FAKENET, str(fake_cfg)),
                              work / "fakenet.log"))
            for i in range(len(SERVERS)):
                procs.append(Proc(with_resolv(server_ns(i), resolv_server,
                                              server_command(i, bins, work, cert, key, reality_priv)),
                                  work / f"server-{SERVERS[i][0]}.log"))
            procs.append(Proc(["socat", f"TCP-LISTEN:{API_PORT},bind=127.0.0.1,reuseaddr,fork",
                               f"SYSTEM:ip netns exec {CLI} socat STDIO TCP4\\:127.0.0.1\\:9090"], work / "socat.log"))
            ready = wait_until(lambda: "fakenet ready" in (work / "fakenet.log").read_text(), 20)
            time.sleep(2)
            base = Core("baseline", sys.executable, work, assets, resolv_client)
            sanity = base.probe("http", "--target", GOOGLE, "--host", "x")
            report["topology"] = {"fakenet": ready, "direct probe": sanity,
                                  "servers alive": {SERVERS[i][0]: procs[i + 1].p.poll() is None for i in range(len(SERVERS))}}
            print(json.dumps(report["topology"]), flush=True)
            hold = work / "hold"
            if args.debug_hold:
                hold.touch()
                print(f"topology held; remove {hold} to continue", flush=True)
            while hold.exists():
                time.sleep(1)
            for kind in args.cores.split(","):
                core = Core(kind, bins[kind], work, assets, resolv_client)
                results: dict = {}
                report["results"][kind] = results
                try:
                    run_core(core, args, results)
                except Exception as e:  # 单个内核的意外错误不影响另一个
                    import traceback
                    results["harness error"] = traceback.format_exc()
                finally:
                    if core.proc:
                        core.proc.stop()
                    time.sleep(2)
                Path(args.out).write_text(json.dumps(report, indent=1, ensure_ascii=False))
                for name, value in results.items():
                    if isinstance(value, dict) and "pass" in value:
                        print(f"{'PASS' if value['pass'] else 'SKIP' if value['pass'] is None else 'FAIL'} {kind}: {name}", flush=True)
        finally:
            report["server alive at end"] = {SERVERS[i][0]: procs[i + 1].p.poll() is None for i in range(len(SERVERS))}
            for p in reversed(procs):
                p.stop()
            subprocess.run(["docker", "rm", "-f", "ka-accept-pw"], capture_output=True)
    Path(args.out).write_text(json.dumps(report, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
