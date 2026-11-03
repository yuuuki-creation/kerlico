#!/usr/bin/env python3
"""控制面能力实测：路由、DNS、用户、统计、控制接口、日志、证书、配置与 CLI。

在 worker 上运行，只依赖标准库和同目录的 interop_cross_host.py、config_v2.py。流量走回环；目标、代理和 DNS 上游
由本工具扮演并记录收到的内容，判定看对端记录，不只看 kerlico 自报。公共解析器只用于 DoT 和内置根证书的验证。

  tools/control_matrix.py --binary <kerlico> --work <目录> --out results.jsonl [--only route,dns] [--case 子串] [--sing-box <路径>]

结果每行一个 {"key","test","evidence","date"}，键对应 docs/capability-matrix。--out 已存在时在其基础上更新，全量复跑前先删除。
"""
import argparse
import base64
import http.client
import json
import os
import random
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import interop_cross_host as ich  # noqa: E402
from config_v2 import _TEST_PASSWORD_HASH  # noqa: E402

DATE = "2026-11-03"
U1 = "00000000-0000-4000-8000-0000000000a1"
U2 = "00000000-0000-4000-8000-0000000000a2"
U3 = "00000000-0000-4000-8000-0000000000a3"
CASES = []
ARGS = None


class Fail(Exception):
    pass


def ensure(condition, message):
    if not condition:
        raise Fail(message)


def case(group, *keys):
    def register(function):
        CASES.append((group, keys, function))
        return function
    return register


def free_port(kind=None):
    for _ in range(200):
        port = random.randint(30000, 60000)
        for family, host, sock_type in (
            (socket.AF_INET, "0.0.0.0", socket.SOCK_STREAM), (socket.AF_INET, "0.0.0.0", socket.SOCK_DGRAM),
            (socket.AF_INET6, "::", socket.SOCK_STREAM), (socket.AF_INET6, "::", socket.SOCK_DGRAM),
        ):
            with socket.socket(family, sock_type) as probe:
                try:
                    probe.bind((host, port))
                except OSError:
                    break
        else:
            return port
    raise RuntimeError("没有空闲端口")


def close_socket(sock):
    """先 shutdown 唤醒阻塞在这个套接字上的线程，否则内核不释放端口。"""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def spawn(target, *args):
    thread = threading.Thread(target=target, args=args, daemon=True)
    thread.start()
    return thread


class Listener:
    """一到多个监听地址上的线程式服务。"""

    def __init__(self, addresses):
        self.sockets = []
        for host, port in addresses:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            sock.listen(256)
            self.sockets.append(sock)
            spawn(self.accept_loop, sock)

    def accept_loop(self, sock):
        while True:
            try:
                conn, peer = sock.accept()
            except OSError:
                return
            spawn(self.guarded, conn, peer)

    def guarded(self, conn, peer):
        try:
            with conn:
                self.handle(conn, peer)
        except OSError:
            pass

    def close(self):
        for sock in self.sockets:
            close_socket(sock)


class Whoami(Listener):
    """先报告被拨的本地地址，再回显，证明连接真的到了哪个 IP。"""

    def __init__(self, port=None):
        self.port = port or free_port()
        self.seen = []
        super().__init__([("0.0.0.0", self.port), ("::", self.port)])

    def handle(self, conn, peer):
        local = conn.getsockname()[0]
        self.seen.append((peer[0], local))
        conn.sendall(local.encode() + b"\n")
        while data := conn.recv(65536):
            conn.sendall(data)


class Exact(Listener):
    """前 16 字节是后续上传长度和要回传的长度；收齐上传后回传并关闭。记录实收字节，用来核对统计。不要求半关闭，部分协议没有 tcp_eof。"""

    def __init__(self):
        self.port = free_port()
        self.flows = []
        super().__init__([("0.0.0.0", self.port), ("::", self.port)])

    def handle(self, conn, peer):
        head = recv_exact(conn, 16)
        upload, download = struct.unpack("!QQ", head)
        received = 16
        while received - 16 < upload:
            data = conn.recv(65536)
            if not data:
                break
            received += len(data)
        chunk = b"x" * 65536
        left = download
        while left:
            size = min(left, len(chunk))
            conn.sendall(chunk[:size])
            left -= size
        self.flows.append((received, download))


class Talker(Listener):
    """读到 EOF 后每 200 毫秒发 1 字节，发完保持连接不关。"""

    def __init__(self, count):
        self.port = free_port()
        self.count = count
        super().__init__([("0.0.0.0", self.port)])

    def handle(self, conn, peer):
        conn.sendall(b"!")
        while conn.recv(4096):
            pass
        for _ in range(self.count):
            conn.sendall(b".")
            time.sleep(0.2)
        time.sleep(30)


class HalfCloser(Listener):
    """接受后立刻关闭写方向，继续读并计数。"""

    def __init__(self):
        self.port = free_port()
        self.received = 0
        super().__init__([("0.0.0.0", self.port)])

    def handle(self, conn, peer):
        conn.shutdown(socket.SHUT_WR)
        while data := conn.recv(4096):
            self.received += len(data)


class UdpEcho:
    def __init__(self):
        self.port = free_port(socket.SOCK_DGRAM)
        self.seen = []
        self.sockets = []
        for family, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, self.port))
            self.sockets.append(sock)
            spawn(self.loop, sock)

    def loop(self, sock):
        while True:
            try:
                data, peer = sock.recvfrom(65535)
                if peer is None:
                    return
                self.seen.append(len(data))
                sock.sendto(data, peer)
            except OSError:
                return

    def close(self):
        for sock in self.sockets:
            close_socket(sock)


def relay(left, right):
    def pump(source, sink):
        try:
            while data := source.recv(65536):
                sink.sendall(data)
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    other = spawn(pump, right, left)
    pump(left, right)
    other.join()


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError(f"对端在 {len(data)}/{count} 字节处关闭")
        data += chunk
    return data


def read_socks_address(sock):
    kind = recv_exact(sock, 1)[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(sock, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    else:
        host = recv_exact(sock, recv_exact(sock, 1)[0]).decode()
    return host, struct.unpack("!H", recv_exact(sock, 2))[0]


def socks_address(host, port):
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, host) + struct.pack("!H", port)
    except OSError:
        pass
    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
    except OSError:
        pass
    encoded = host.encode()
    return b"\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", port)


class Recorder(Listener):
    """无认证 SOCKS5 代理：记录收到的目标，把流量转给固定回显目标。stall 时只收请求不应答。"""

    def __init__(self, tcp_port, udp_port=None, stall=False):
        self.port = free_port()
        self.tcp_port, self.udp_port = tcp_port, udp_port
        self.stall = stall
        self.log = []
        super().__init__([("127.0.0.1", self.port)])

    def handle(self, conn, peer):
        methods = recv_exact(conn, 2)[1]
        recv_exact(conn, methods)
        conn.sendall(b"\x05\x00")
        _, command, _ = recv_exact(conn, 3)
        host, port = read_socks_address(conn)
        if command == 1:
            self.log.append(("tcp", host, port))
            if self.stall:
                while conn.recv(4096):
                    pass
                return
            upstream = socket.create_connection(("127.0.0.1", self.tcp_port), timeout=5)
            upstream.settimeout(None)
            with upstream:
                conn.sendall(b"\x05\x00\x00\x01\0\0\0\0\0\0")
                relay(conn, upstream)
        elif command == 3:
            self.udp_associate(conn)
        else:
            conn.sendall(b"\x05\x07\x00\x01\0\0\0\0\0\0")

    def udp_associate(self, conn):
        relay_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay_socket.bind(("127.0.0.1", 0))
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.sendall(b"\x05\x00\x00" + socks_address("127.0.0.1", relay_socket.getsockname()[1]))
        client = [None, None]

        def forward():
            while True:
                try:
                    data, peer = relay_socket.recvfrom(65535)
                except OSError:
                    return
                head = data[3:]
                if head[0] == 1:
                    host, consumed = socket.inet_ntop(socket.AF_INET, head[1:5]), 7
                elif head[0] == 4:
                    host, consumed = socket.inet_ntop(socket.AF_INET6, head[1:17]), 19
                else:
                    host, consumed = head[2:2 + head[1]].decode(), 4 + head[1]
                client[0], client[1] = peer, head[:consumed]
                self.log.append(("udp", host, struct.unpack("!H", head[consumed - 2:consumed])[0]))
                upstream.sendto(head[consumed:], ("127.0.0.1", self.udp_port))

        def backward():
            while True:
                try:
                    data = upstream.recv(65535)
                    relay_socket.sendto(b"\0\0\0" + client[1] + data, client[0])
                except OSError:
                    return

        spawn(forward)
        spawn(backward)
        while conn.recv(4096):
            pass
        relay_socket.close()
        upstream.close()


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\0"


class FakeDns:
    """按 zones 应答的 DNS 上游，记录每条查询。zones[name] = {"A": [...], "AAAA": [...], "ttl": n, "cname": 名字, "rcode": n}。"""

    def __init__(self, host="127.0.0.1", port=None, zones=None, tls=None):
        self.host = host
        self.port = port or free_port(socket.SOCK_DGRAM)
        self.zones = zones or {}
        self.log = []
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.udp = socket.socket(family, socket.SOCK_DGRAM)
        self.udp.bind((host, self.port))
        self.tcp = socket.socket(family, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((host, self.port))
        self.tcp.listen(64)
        self.tls = tls
        spawn(self.udp_loop)
        spawn(self.tcp_loop)

    def close(self):
        close_socket(self.udp)
        close_socket(self.tcp)

    def queries(self, name=None):
        return [item for item in self.log if name is None or item[1] == name]

    def answer(self, query, transport):
        pos = 12
        labels = []
        while query[pos]:
            labels.append(query[pos + 1:pos + 1 + query[pos]].decode())
            pos += 1 + query[pos]
        name = ".".join(labels).lower()
        qtype = struct.unpack("!H", query[pos + 1:pos + 3])[0]
        self.log.append((transport, name, {1: "A", 28: "AAAA"}.get(qtype, str(qtype))))
        question = query[12:pos + 5]
        zone = self.zones.get(name)
        if zone is not None and zone.get("stall"):
            return None
        if zone is not None and zone.get("truncate") and transport == "udp":
            return query[:2] + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + question
        answers = []
        rcode = 3
        if zone is not None:
            rcode = zone.get("rcode", 0)
            ttl = zone.get("ttl", 60)
            owner = b"\xc0\x0c"
            if "cname" in zone:
                target = encode_name(zone["cname"])
                answers.append(owner + struct.pack("!HHIH", 5, 1, ttl, len(target)) + target)
                owner = target
            for kind, family, size in ((1, socket.AF_INET, "A"), (28, socket.AF_INET6, "AAAA")):
                if qtype == kind:
                    for address in zone.get(size, []):
                        raw = socket.inet_pton(family, address)
                        answers.append(owner + struct.pack("!HHIH", kind, 1, ttl, len(raw)) + raw)
        flags = 0x8180 | rcode
        return query[:2] + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0) + question + b"".join(answers)

    def udp_loop(self):
        while True:
            try:
                query, peer = self.udp.recvfrom(4096)
                if peer is None:
                    return
                reply = self.answer(query, "udp")
                if reply:
                    self.udp.sendto(reply, peer)
            except OSError:
                return

    def tcp_loop(self):
        while True:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            spawn(self.tcp_serve, conn)

    def tcp_serve(self, conn):
        try:
            if self.tls:
                conn = self.tls.wrap_socket(conn, server_side=True)
            with conn:
                while True:
                    size = struct.unpack("!H", recv_exact(conn, 2))[0]
                    reply = self.answer(recv_exact(conn, size), "tls" if self.tls else "tcp")
                    if reply:
                        conn.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, ConnectionError, ssl.SSLError):
            pass


class SocksReply(Exception):
    def __init__(self, code):
        super().__init__(f"SOCKS 应答 {code}")
        self.code = code


def socks5(address, host, port, auth=None, timeout=8, command=1):
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(address)
    if auth:
        sock.sendall(b"\x05\x01\x02")
        ensure(recv_exact(sock, 2) == b"\x05\x02", "代理未选用户名密码认证")
        user, password = auth[0].encode(), auth[1].encode()
        sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
        if recv_exact(sock, 2) != b"\x01\x00":
            raise SocksReply("auth")
    else:
        sock.sendall(b"\x05\x01\x00")
        ensure(recv_exact(sock, 2) == b"\x05\x00", "代理未接受无认证")
    sock.sendall(b"\x05" + bytes([command]) + b"\0" + socks_address(host, port))
    reply = recv_exact(sock, 3)
    bound = read_socks_address(sock)
    if reply[1]:
        sock.close()
        raise SocksReply(reply[1])
    return (sock, bound) if command == 3 else sock


def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("读行时对端关闭")
        data += chunk
    return data[:-1].decode()


def tcp_echo(sock):
    """Whoami 协议一轮：返回被拨的 IP，并验证回显。"""
    with sock:
        ip = recv_line(sock)
        payload = secrets.token_bytes(32)
        sock.sendall(payload)
        ensure(recv_exact(sock, len(payload)) == payload, "回显内容不符")
    return ip


def udp_roundtrip(address, payload=None, timeout=4):
    payload = payload or secrets.token_bytes(32)
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, address)
        data, _ = sock.recvfrom(65535)
    ensure(data == payload, "UDP 回显内容不符")
    return data


def socks_udp_roundtrip(control, relay_address, host, port, payload=None, timeout=4):
    payload = payload or secrets.token_bytes(32)
    family = socket.AF_INET6 if ":" in relay_address[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(b"\0\0\0" + socks_address(host, port) + payload, relay_address)
        data, _ = sock.recvfrom(65535)
    head = data[3]
    offset = {1: 10, 4: 22}.get(head) or 7 + data[4]
    ensure(data[offset:] == payload, "SOCKS UDP 回显内容不符")
    return data


def exact_transfer(sock, upload, download):
    """向 Exact 写 16 字节头加 upload 字节，读满 download 字节；返回客户端实际上下行字节数。"""
    with sock:
        sock.settimeout(30)
        sock.sendall(struct.pack("!QQ", upload, download) + b"u" * upload)
        received = 0
        while received < download:
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += len(chunk)
    ensure(received == download, f"下行字节 {received} != {download}")
    return upload + 16, received


class Kerlico:
    def __init__(self, bench, config, prefix=(), lang="en", cwd=None, env=None, wait=True):
        self.bench, self.config, self.prefix = bench, config, prefix
        self.directory = bench.fresh("k")
        self.path = self.directory / "config.json"
        self.path.write_text(json.dumps(config), encoding="utf-8")
        self.path.chmod(0o600)
        self.log_path = self.directory / "log"
        self.listeners = {}
        self.control = None
        with open(self.log_path, "ab") as log:
            self.process = subprocess.Popen(
                [*prefix, ARGS.binary, "--lang", lang, "run", "-c", str(self.path)],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=cwd or self.directory, start_new_session=True,
                env={**os.environ, **(env or {})},
            )
        if wait:
            self.wait_ready()

    def log(self):
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def wait_ready(self, timeout=30):
        tags = [item["tag"] for section in ("inbounds", "nodes", "local_inbounds") for item in self.config.get(section, []) if item["type"] != "tun"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = self.log()
            found = dict(re.findall(r"Inbound (\S+) is listening on (\S+)", text))
            control = re.search(r"Control interface is listening on (\S+)", text)
            if all(tag in found for tag in tags) and (control or "control" not in self.config):
                self.listeners = {tag: split_address(value) for tag, value in found.items()}
                self.control = split_address(control.group(1)) if control else None
                return self
            if self.process.poll() is not None:
                raise Fail(f"kerlico 启动失败 rc={self.process.returncode}: {text[-400:]}")
            time.sleep(0.02)
        raise Fail(f"kerlico 启动超时: {self.log()[-400:]}")

    def stop(self, sig=signal.SIGTERM, timeout=15):
        if self.process.poll() is None:
            self.process.send_signal(sig)
            try:
                self.process.wait(timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise Fail("kerlico 未在期限内退出")
        return self.process.returncode

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()

    def api(self, path, secret=None, method="GET", headers=None):
        status, body, _ = http_call(self.control, path, secret, method, headers)
        return status, body

    def get(self, path, secret=None):
        status, body = self.api(path, secret)
        ensure(status == 200, f"{path} 返回 {status}: {body}")
        return body


def split_address(text):
    host, port = text.rsplit(":", 1)
    return host.strip("[]"), int(port)


def http_call(address, path, secret=None, method="GET", headers=None):
    conn = http.client.HTTPConnection(address[0], address[1], timeout=8)
    try:
        all_headers = dict(headers or {})
        if secret is not None:
            all_headers["Authorization"] = f"Bearer {secret}"
        conn.request(method, path, headers=all_headers)
        response = conn.getresponse()
        raw = response.read()
        body = json.loads(raw) if raw else None
        return response.status, body, dict(response.getheaders())
    finally:
        conn.close()


def run_cli(*argv, stdin=None, env=None, cwd=None, timeout=60):
    environment = {key: value for key, value in os.environ.items() if key not in ("LC_ALL", "LC_MESSAGES", "LANG")}
    environment.update(env or {})
    done = subprocess.run([ARGS.binary, *argv], input=stdin, capture_output=True, timeout=timeout, env=environment, cwd=cwd)
    return done.returncode, done.stdout.decode(errors="replace"), done.stderr.decode(errors="replace")


class Bench:
    def __init__(self, work):
        self.work = Path(work)
        self.counter = 0
        self.material = None
        self.closers = []

    def fresh(self, prefix):
        self.counter += 1
        path = self.work / f"{prefix}{self.counter}"
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    def kerlico(self, config, **kw):
        return Kerlico(self, config, **kw)

    def check(self, config, raw=None):
        path = self.fresh("c") / "config.json"
        if raw is not None:
            path.write_bytes(raw)
        else:
            path.write_text(json.dumps(config), encoding="utf-8")
        return run_cli("--lang", "en", "check", "-c", str(path))

    def rejected(self, config, raw=None):
        rc, out, err = self.check(config, raw)
        ensure(rc != 0, f"配置应被拒绝却通过: {json.dumps(config)[:200] if config is not None else raw[:80]}")
        return err.strip().splitlines()[0][:80] if err.strip() else out[:80]

    def accepted(self, config):
        rc, out, err = self.check(config)
        ensure(rc == 0, f"配置应通过却被拒绝: {err.strip()[:200]} 配置 {json.dumps(config)[:200]}")

    def tls_material(self):
        if self.material is None:
            self.material = make_material(self.fresh("pki"), ich.SNI)
        return self.material


def openssl(directory, *argv):
    subprocess.run(["openssl", *argv], check=True, capture_output=True, timeout=60, cwd=directory)


def make_material(directory, name, label="control-matrix"):
    openssl(directory, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "3", "-subj", f"/CN={label}-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl(directory, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", f"/CN={name}")
    (directory / "ext").write_text(f"subjectAltName=DNS:{name}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\n", encoding="ascii")
    openssl(directory, "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "3", "-extfile", "ext", "-out", "leaf.pem")
    read = lambda file: (directory / file).read_text(encoding="ascii")
    return ich.Material(read("ca.pem"), read("leaf.pem"), read("leaf.key"))


def account(user, name=None):
    return {"user_id": user, "username": name or f"user_{user[-2:]}", "password_hash": _TEST_PASSWORD_HASH}


def socks_out(tag, port):
    return {"tag": tag, "type": "socks", "options": {"server": {"host": "127.0.0.1", "port": port}, "version": "5"}}


def local_socks(tag, outbound, listen=None, **extra):
    return {"tag": tag, "type": "socks", "listen": listen or f"127.0.0.1:{free_port()}", "outbound": outbound, "options": {"version": "5"}, **extra}


def socks_node(tag, outbound, members, listen=None, **extra):
    """members: [(user_id, username, password), ...]"""
    return {
        "tag": tag, "type": "socks", "listen": listen or f"127.0.0.1:{free_port()}", "outbound": outbound, "options": {"version": "5"},
        "members": [{"user_id": user, "native_credential": {"username": name, "password": password}} for user, name, password in members], **extra,
    }


def control_on(secret=None, listen=None):
    spec = {"listen": listen or f"127.0.0.1:{free_port()}"}
    if secret is not None:
        spec["secret"] = secret
    return spec


# ------------------------------------------------------------------ 路由


class RouteBench:
    """固定一组出站和入口，probe 返回流量实际经过的出站标签。"""

    NODE_USERS = {"edge": {"u1": ("e1a", "pw-edge-a"), "u2": ("e1b", "pw-edge-b")}, "edge2": {"u1": ("e2a", "pw-edge2-a"), "u2": ("e2b", "pw-edge2-b")}}

    def __init__(self):
        self.whoami = Whoami()
        self.udp = UdpEcho()
        self.recorders = {tag: Recorder(self.whoami.port, self.udp.port) for tag in ("a", "b", "c", "dflt")}

    def config(self, rules, forwards=(), **extra):
        config = {
            "version": 2,
            "accounts": [account(U1), account(U2)],
            "outbounds": [
                *[socks_out(tag, recorder.port) for tag, recorder in self.recorders.items()],
                {"tag": "block", "type": "reject"},
                {"tag": "direct", "type": "direct"},
                {"tag": "noudp", "type": "http", "options": {"server": {"host": "127.0.0.1", "port": 1}}},
            ],
            "local_inbounds": [local_socks("in1", "dflt"), local_socks("in2", "dflt"), local_socks("in3", "c"), local_socks("in4", "dflt", f"127.0.0.2:{free_port()}")],
            "nodes": [
                socks_node("edge", "dflt", [(U1, *self.NODE_USERS["edge"]["u1"]), (U2, *self.NODE_USERS["edge"]["u2"])]),
                socks_node("edge2", "dflt", [(U1, *self.NODE_USERS["edge2"]["u1"]), (U2, *self.NODE_USERS["edge2"]["u2"])]),
            ],
            "inbounds": [
                {"tag": tag, "type": f"{net}-forward", "listen": f"127.0.0.1:{free_port(socket.SOCK_DGRAM if net == 'udp' else socket.SOCK_STREAM)}", "target": {"host": host, "port": port}, "outbound": outbound}
                for tag, net, host, port, outbound in forwards
            ],
            "routes": rules,
            "control": control_on(),
        }
        config.update(extra)
        return config

    def probe(self, kerlico, inbound="in1", host="x.example", port=4443, user=None):
        for recorder in self.recorders.values():
            recorder.log.clear()
        address = kerlico.listeners[inbound]
        forward = next((item for item in kerlico.config.get("inbounds", []) if item["tag"] == inbound), None)
        auth = self.NODE_USERS[inbound][user] if user else None
        expected = None
        try:
            if forward and forward["type"] == "udp-forward":
                udp_roundtrip(address)
                expected = forward["target"]["host"]
            elif forward:
                sock = socket.create_connection(address, timeout=5)
                sock.settimeout(5)
                tcp_echo(sock)
                expected = forward["target"]["host"]
            else:
                tcp_echo(socks5(address, host, port, auth))
                expected = host
        except SocksReply as error:
            return f"refused:{error.code}"
        except (OSError, ConnectionError) as error:
            return f"refused:{type(error).__name__}"
        hits = [(tag, recorder.log[-1]) for tag, recorder in self.recorders.items() if recorder.log]
        ensure(len(hits) <= 1, f"多个出站收到流量: {hits}")
        if not hits:
            return "direct"
        tag, (_, seen_host, _) = hits[0]
        ensure(":" in expected or seen_host == expected.lower().rstrip(".") or seen_host == expected, f"{tag} 收到目标 {seen_host}，请求 {expected}")
        return tag

    def table(self, bench, rules, probes, forwards=(), **extra):
        """probes: [(出站标签, probe 关键字参数)]，全部符合才通过，返回可读摘要。"""
        lines = []
        with bench.kerlico(self.config(rules, forwards, **extra)) as kerlico:
            for expected, kwargs in probes:
                got = self.probe(kerlico, **kwargs)
                label = kwargs.get("host", kwargs.get("inbound", ""))
                port = kwargs.get("port")
                ensure(got == expected or (expected == "refused" and got.startswith("refused")), f"{kwargs} 走 {got}，应走 {expected}")
                lines.append(f"{label}{':' + str(port) if port else ''}{'/' + kwargs['user'] if 'user' in kwargs else ''}{'@' + kwargs['inbound'] if 'inbound' in kwargs and 'host' in kwargs else ''}→{got.split(':')[0]}")
        return "，".join(lines)


def route_outcome(summary, rule):
    return f"规则 {rule} 下真实 SOCKS5/转发流量经 Python 记录代理确认走向：{summary}"


ROUTE_TABLES = {
    "route/rule/domain": ([{"outbound": "a", "domain": ["Exact.Example"]}], [("a", {"host": "exact.example"}), ("a", {"host": "EXACT.example"}), ("a", {"host": "exact.example."}), ("dflt", {"host": "www.exact.example"}), ("dflt", {"host": "xexact.example"})]),
    "route/rule/domain-full": ([{"outbound": "a", "domain": ["full.example", "例子.test"]}], [("a", {"host": "full.example"}), ("a", {"host": "xn--fsqu00a.test"}), ("dflt", {"host": "sub.full.example"})]),
    "route/rule/domain-suffix": ([{"outbound": "a", "domain_suffix": ["suffix.example", ".dot.example"]}], [("a", {"host": "suffix.example"}), ("a", {"host": "w.x.suffix.example"}), ("a", {"host": "dot.example"}), ("a", {"host": "a.dot.example"}), ("dflt", {"host": "badsuffix.example"}), ("dflt", {"host": "suffix.example.org"})]),
    "route/rule/domain-keyword": ([{"outbound": "a", "domain_keyword": ["Track"]}], [("a", {"host": "ads.tracker.net"}), ("a", {"host": "TRACK.example"}), ("dflt", {"host": "trac.example"})]),
    "route/rule/ip": ([{"outbound": "a", "ip_cidr": ["192.0.2.7", "2001:db8::7"]}], [("a", {"host": "192.0.2.7"}), ("dflt", {"host": "192.0.2.8"}), ("a", {"host": "2001:db8::7"}), ("dflt", {"host": "2001:db8::8"})]),
    "route/rule/ip-cidr": ([{"outbound": "a", "ip_cidr": ["192.0.2.0/24"]}, {"outbound": "b", "ip_cidr": ["0.0.0.0/0"]}], [("a", {"host": "192.0.2.200"}), ("a", {"host": "::ffff:192.0.2.1"}), ("b", {"host": "198.51.100.1"}), ("dflt", {"host": "cidr.example"}), ("dflt", {"host": "2001:db8::1"})]),
    "route/rule/ip-cidr6": ([{"outbound": "a", "ip_cidr": ["2001:db8::/32"]}, {"outbound": "b", "ip_cidr": ["::/0"]}], [("a", {"host": "2001:db8:1::1"}), ("b", {"host": "2001:db9::1"}), ("dflt", {"host": "192.0.2.1"}), ("dflt", {"host": "cidr6.example"})]),
    "route/rule/dst-port": ([{"outbound": "a", "port": [80, 8443]}], [("a", {"port": 80}), ("a", {"port": 8443}), ("dflt", {"port": 81}), ("dflt", {"port": 443})]),
    "route/rule/port": ([{"outbound": "a", "port": [53, 443]}, {"outbound": "b", "port": [1000]}], [("a", {"port": 53}), ("a", {"port": 443}), ("b", {"port": 1000}), ("dflt", {"port": 1001})]),
    "route/rule/in-name": ([{"outbound": "a", "node": ["in2"]}], [("dflt", {"inbound": "in1"}), ("a", {"inbound": "in2"}), ("dflt", {"inbound": "edge", "user": "u1"})]),
    "route/rule/inbound": ([{"outbound": "a", "node": ["edge", "in1"]}], [("a", {"inbound": "in1"}), ("dflt", {"inbound": "in2"}), ("a", {"inbound": "edge", "user": "u1"}), ("dflt", {"inbound": "edge2", "user": "u1"})]),
    "route/rule/inbound-tag": ([{"outbound": "a", "node": ["fwd"]}], [("a", {"inbound": "fwd"}), ("dflt", {"inbound": "in1"})]),
    "route/rule/in-port": ([{"outbound": "a", "node": ["in2"]}], [("dflt", {"inbound": "in1"}), ("a", {"inbound": "in2"})]),
    "route/rule/local-port": ([{"outbound": "a", "node": ["in2"]}], [("dflt", {"inbound": "in1"}), ("a", {"inbound": "in2"})]),
    "route/rule/local-ip": ([{"outbound": "a", "node": ["in4"]}], [("dflt", {"inbound": "in1"}), ("a", {"inbound": "in4"})]),
    "route/rule/in-user": ([{"outbound": "a", "user": [U1]}], [("a", {"inbound": "edge", "user": "u1"}), ("dflt", {"inbound": "edge", "user": "u2"}), ("a", {"inbound": "edge2", "user": "u1"}), ("dflt", {"inbound": "in1"})]),
    "route/rule/auth-user": ([{"outbound": "a", "user": [U2]}], [("dflt", {"inbound": "edge", "user": "u1"}), ("a", {"inbound": "edge", "user": "u2"})]),
    "route/rule/user": ([{"outbound": "a", "user": [U1, U2]}], [("a", {"inbound": "edge", "user": "u1"}), ("a", {"inbound": "edge", "user": "u2"}), ("dflt", {"inbound": "in2"})]),
    "route/rule/and": ([{"outbound": "a", "domain_suffix": ["and.example"], "port": [443], "network": "tcp", "node": ["edge"], "user": [U1]}], [("a", {"inbound": "edge", "user": "u1", "host": "w.and.example", "port": 443}), ("dflt", {"inbound": "edge", "user": "u1", "host": "w.and.example", "port": 80}), ("dflt", {"inbound": "edge", "user": "u1", "host": "other.example", "port": 443}), ("dflt", {"inbound": "edge", "user": "u2", "host": "w.and.example", "port": 443}), ("dflt", {"inbound": "edge2", "user": "u1", "host": "w.and.example", "port": 443})]),
    "route/rule/or": ([{"outbound": "a", "domain": ["or.example"], "ip_cidr": ["192.0.2.0/24"], "port": [1, 2]}], [("a", {"host": "or.example", "port": 1}), ("a", {"host": "192.0.2.9", "port": 2}), ("dflt", {"host": "or.example", "port": 3}), ("dflt", {"host": "no.example", "port": 1})]),
    "route/rule/order": ([{"outbound": "a", "domain_suffix": ["order.example"]}, {"outbound": "b", "domain_suffix": ["order.example"]}, {"outbound": "b", "port": [9]}], [("a", {"host": "x.order.example"}), ("b", {"port": 9}), ("dflt", {"port": 10})]),
    "route/routing/rules": ([{"outbound": "b", "port": [7]}, {"outbound": "a", "port": [7, 8]}], [("b", {"port": 7}), ("a", {"port": 8}), ("dflt", {"port": 9})]),
    "route/config/rules": ([{"outbound": "c", "domain": ["top.example"]}, {"outbound": "a", "domain_keyword": ["top"]}], [("c", {"host": "top.example"}), ("a", {"host": "stop.example"}), ("dflt", {"host": "none.example"})]),
    "route/action/outbound": ([{"outbound": "b", "domain": ["act.example"]}], [("b", {"host": "act.example"}), ("dflt", {"host": "bct.example"})]),
    "route/action/route": ([{"outbound": "c", "port": [11]}], [("c", {"port": 11}), ("dflt", {"port": 12})]),
    "route/rule/outbound-tag": ([{"outbound": "a", "port": [13]}, {"outbound": "b", "port": [14]}], [("a", {"port": 13}), ("b", {"port": 14})]),
    "route/action/proxy-or-group": ([{"outbound": "a", "port": [15]}], [("a", {"port": 15})]),
    "route/rule/action": ([{"outbound": "a", "port": [16]}, {"outbound": "block", "port": [17]}], [("a", {"port": 16}), ("refused", {"port": 17})]),
    "route/action/reject": ([{"outbound": "block", "domain_suffix": ["ads.example"]}], [("refused", {"host": "x.ads.example"}), ("dflt", {"host": "ok.example"})]),
}
ROUTE_FORWARDS = {"route/rule/inbound-tag": [("fwd", "tcp", "fwd.example", 443, "dflt")]}
ROUTE_NOTES = {
    "route/rule/in-port": "kerlico 无端口条件，同地址不同端口的两个入口按 node 区分",
    "route/rule/local-port": "kerlico 无端口条件，同地址不同端口的两个入口按 node 区分",
    "route/rule/local-ip": "kerlico 无 IP 条件，监听 127.0.0.2 的入口按 node 区分",
    "route/rule/in-user": "匹配 members 绑定的 UUID，跨节点同一账户都命中",
    "route/rule/user": "匹配 UUID；缺按名称、邮箱、regexp",
    "route/action/proxy-or-group": "目标写命名 socks 出站；没有策略组",
}


@case("route", *ROUTE_TABLES)
def route_tables(bench):
    rb = RouteBench()
    out = {}
    for key, (rules, probes) in ROUTE_TABLES.items():
        try:
            summary = rb.table(bench, rules, probes, ROUTE_FORWARDS.get(key, ()))
            note = ROUTE_NOTES.get(key)
            out[key] = route_outcome(summary, json.dumps(rules, ensure_ascii=False)) + (f"。{note}" if note else "")
        except Fail as error:
            out[key] = ("fail", str(error))
    forwards = [("fu", "udp", "cap.example", 53, "dflt")]
    with bench.kerlico(rb.config([{"outbound": "noudp", "network": "udp"}, {"outbound": "a", "network": "udp"}], forwards)) as kerlico:
        got = rb.probe(kerlico, inbound="fu")
        ensure(got.startswith("refused") and not rb.recorders["a"].log, f"无 UDP 能力的出站应让这条 UDP 失败，实际 {got}")
    if isinstance(out["route/rule/order"], str):
        out["route/rule/order"] += "。首条命中的 http 出站没有 UDP 时这条 UDP 直接失败，不继续向下匹配（与 Mihomo 不同，符合接口文档）"
    return out


@case("route", "route/rule/network")
def route_network(bench):
    rb = RouteBench()
    forwards = [("fu", "udp", "net.example", 53, "dflt"), ("ft", "tcp", "net.example", 53, "dflt")]
    first = rb.table(bench, [{"outbound": "a", "network": "udp"}], [("a", {"inbound": "fu"}), ("dflt", {"inbound": "ft"})], forwards)
    second = rb.table(bench, [{"outbound": "a", "network": "tcp"}], [("dflt", {"inbound": "fu"}), ("a", {"inbound": "ft"})], forwards)
    rejected = [bench.rejected(rb.config([{"outbound": "a", "network": value}])) for value in ("icmp", ["tcp", "udp"])]
    return f"network=udp：{first}；network=tcp：{second}。同目标的 udp-forward 与 tcp-forward 对照。icmp 与数组写法 check 拒绝（{rejected[0]}）"


@case("route", "route/rule/match")
def route_match(bench):
    rb = RouteBench()
    bench.rejected(rb.config([{"outbound": "a"}]))
    summary = rb.table(bench, [{"outbound": "a", "network": "tcp"}, {"outbound": "a", "network": "udp"}], [("a", {"host": "any.example"}), ("a", {"port": 1})])
    return f"空条件规则 check 拒绝；全匹配用 network=tcp 与 network=udp 两条等价：{summary}"


@case("route", "route/action/direct")
def route_direct(bench):
    rb = RouteBench()
    with bench.kerlico(rb.config([{"outbound": "direct", "port": [rb.whoami.port]}])) as kerlico:
        rb.whoami.seen.clear()
        got = rb.probe(kerlico, host="127.0.0.1", port=rb.whoami.port)
        ensure(got == "direct" and rb.whoami.seen, f"应直连，实际 {got}")
        other = rb.probe(kerlico, host="127.0.0.1", port=rb.whoami.port + 1)
        ensure(other == "dflt", f"未命中应走 dflt，实际 {other}")
        usage = kerlico.get("/v1/usage")["outbounds"]
        ensure(usage["direct"]["download_bytes"] > 0, "direct 出站无用量")
    return "规则把 127.0.0.1 目标路由到 direct，四个记录代理都没收到请求，目标直接收到连接；/v1/usage 的 direct 出站有用量；未命中走 dflt"


@case("route", "route/config/final")
def route_final(bench):
    rb = RouteBench()
    summary = rb.table(bench, [{"outbound": "a", "port": [1]}], [("dflt", {"inbound": "in1", "host": "f.example", "port": 2}), ("c", {"inbound": "in3", "host": "f.example", "port": 2}), ("a", {"inbound": "in3", "host": "f.example", "port": 1})])
    rejected = bench.rejected({**rb.config([]), "route": {"final": "a"}})
    return f"没有全局 final；未命中走入口绑定的出站：{summary}。顶层 route.final 未知字段 check 拒绝（{rejected}）"


@case("route", "route/config/default-interface")
def route_interface(bench):
    device = subprocess.run(["ip", "-o", "route", "get", "1.1.1.1"], capture_output=True, text=True).stdout
    nic = re.search(r"dev (\S+)", device).group(1)
    rb = RouteBench()

    def attempt(interface):
        config = rb.config([], local_inbounds=[local_socks("in1", "bound")])
        config["outbounds"].append({"tag": "bound", "type": "direct", "options": {"interface": interface}})
        config.pop("nodes")
        config.pop("accounts")
        config["routes"] = []
        with bench.kerlico(config) as kerlico:
            try:
                return tcp_echo(socks5(kerlico.listeners["in1"], "127.0.0.1", rb.whoami.port, timeout=4))
            except (SocksReply, OSError, ConnectionError) as error:
                return f"失败:{type(error).__name__ if not isinstance(error, SocksReply) else error.code}"

    on_lo = attempt("lo")
    on_nic = attempt(nic)
    ensure(on_lo == "127.0.0.1", f"绑定 lo 应到达回环目标：{on_lo}")
    ensure(on_nic.startswith("失败"), f"绑定物理网卡不应到达回环目标：{on_nic}")
    missing = attempt("nosuchif0")
    ensure(missing.startswith("失败"), f"不存在的接口应失败：{missing}")
    return f"direct 的 options.interface：绑定 lo 到达 127.0.0.1，绑定物理网卡后 SO_BINDTODEVICE 使回环目标不可达（{on_nic}），不存在的接口 {missing}。没有全局默认网卡"


@case("route", "route/routing/domain-strategy")
def route_strategy(bench):
    rb = RouteBench()
    dns = FakeDns(zones={"asis.example": {"A": ["192.0.2.50"]}})
    rules = [{"outbound": "a", "ip_cidr": ["192.0.2.0/24"]}]
    extra = {"dns": {"servers": [f"udp://127.0.0.1:{dns.port}"], "hosts": {"hosts.example": ["192.0.2.51"]}}}
    summary = rb.table(bench, rules, [("dflt", {"host": "asis.example"}), ("dflt", {"host": "hosts.example"}), ("a", {"host": "192.0.2.50"})], **extra)
    ensure(not dns.log, f"路由不应查询 DNS: {dns.log}")
    dns.close()
    return f"固定 AsIs：域名目标不解析就不匹配 CIDR，字面 IP 才匹配：{summary}；上游查询日志为空。缺 IPIfNonMatch、IPOnDemand"


@case("route", "route/rule/no-resolve")
def route_no_resolve(bench):
    rb = RouteBench()
    dns = FakeDns(zones={"nr.example": {"A": ["192.0.2.60"]}})
    extra = {"dns": {"servers": [f"udp://127.0.0.1:{dns.port}"]}}
    rules = [{"outbound": "a", "ip_cidr": ["192.0.2.0/24"]}, {"outbound": "b", "domain": ["hit.example"]}]
    summary = rb.table(bench, rules, [("dflt", {"host": "nr.example"}), ("b", {"host": "hit.example"})], **extra)
    ensure(not dns.log, f"不应查询: {dns.log}")
    dns.close()
    return f"ip_cidr 规则对域名目标不触发解析，恒等同 no-resolve：{summary}；FakeDns 查询数 0。不能按规则关闭"


@case("route", "route/rule/combo")
def route_combo(bench):
    rb = RouteBench()
    fields = {
        "domain": ({"domain": ["d.combo.example"]}, {"host": "d.combo.example"}, {"host": "no.combo.test"}),
        "domain_suffix": ({"domain_suffix": ["s.combo.example"]}, {"host": "w.s.combo.example"}, {"host": "no.combo.test"}),
        "domain_keyword": ({"domain_keyword": ["kwd"]}, {"host": "a-kwd-b.test"}, {"host": "no.combo.test"}),
        "ip_cidr": ({"ip_cidr": ["192.0.2.0/24"]}, {"host": "192.0.2.5"}, {"host": "198.51.100.5"}),
        "port": ({"port": [4443]}, {"port": 4443}, {"port": 4444}),
        "node": ({"node": ["edge"]}, {"inbound": "edge", "user": "u1"}, {"inbound": "edge2", "user": "u1"}),
        "user": ({"user": [U1]}, {"inbound": "edge", "user": "u1"}, {"inbound": "edge", "user": "u2"}),
    }
    targets = ("domain", "domain_suffix", "domain_keyword", "ip_cidr")
    names = list(fields)
    pairs = probes = 0
    for i, left in enumerate(names):
        for right in names[i + 1:]:
            lc, lm, lx = fields[left]
            rc, rm, rx = fields[right]
            rules = [{"outbound": "a", **lc, **rc}]
            if left in targets and right in targets:
                table = [("a", dict(lm)), ("a", dict(rm)), ("dflt", {"host": "none.combo.test"})]
            else:
                both = {**lm, **rm}
                if left == "node" and right == "user":
                    table = [("a", {"inbound": "edge", "user": "u1"}), ("dflt", {"inbound": "edge2", "user": "u1"}), ("dflt", {"inbound": "edge", "user": "u2"})]
                else:
                    table = [("a", both), ("dflt", {**lx, **rm}), ("dflt", {**lm, **rx})]
            rb.table(bench, rules, table)
            pairs += 1
            probes += len(table)
    network = 0
    for name, (condition, match, miss) in fields.items():
        if name in ("user",):
            rb.table(bench, [{"outbound": "a", "network": "tcp", **condition}], [("a", match), ("dflt", miss)])
            network += 1
            continue
        if name == "node":
            forwards = [("fu", "udp", "n.example", 1, "dflt"), ("fu2", "udp", "n.example", 1, "dflt"), ("ft", "tcp", "n.example", 1, "dflt")]
            rb.table(bench, [{"outbound": "a", "network": "udp", "node": ["fu"]}], [("a", {"inbound": "fu"}), ("dflt", {"inbound": "fu2"}), ("dflt", {"inbound": "ft"})], forwards)
            network += 1
            continue
        host_hit, port_hit = match.get("host", "n.example"), match.get("port", 1)
        host_miss, port_miss = miss.get("host", "n.example"), miss.get("port", 1)
        forwards = [("hit", "udp", host_hit, port_hit, "dflt"), ("miss", "udp", host_miss, port_miss, "dflt"), ("tcp", "tcp", host_hit, port_hit, "dflt")]
        rb.table(bench, [{"outbound": "a", "network": "udp", **condition}], [("a", {"inbound": "hit"}), ("dflt", {"inbound": "miss"}), ("dflt", {"inbound": "tcp"})], forwards)
        network += 1
    return f"kerlico 已实现的 8 个匹配维度两两展开：非 network 字段 {pairs} 对共 {probes} 次真实探测，每对验证同时命中走 a、任一不命中走 dflt，域名类与 ip_cidr 之间按或；network 与其他 7 个字段各一组，用同目标的 udp-forward、tcp-forward 对照。未实现维度（geoip、process、logical、invert 等）见标注"


# ------------------------------------------------------------------ DNS


class DnsBench:
    def __init__(self, bench):
        self.bench = bench
        self.whoami = Whoami()
        self.udp = UdpEcho()

    def config(self, dns, mode=None, forwards=(), outbound=None, **extra):
        inbound = local_socks("in", "direct")
        if mode:
            inbound["mode"] = mode
        config = {
            "version": 2,
            "outbounds": [outbound or {"tag": "direct", "type": "direct"}],
            "local_inbounds": [inbound],
            "inbounds": [{"tag": tag, "type": f"{net}-forward", "listen": f"127.0.0.1:{free_port(socket.SOCK_DGRAM)}", "target": {"host": host, "port": port}, "outbound": "direct", **({"mode": mode} if mode else {})} for tag, net, host, port in forwards],
            "control": control_on(),
        }
        if dns is not None:
            config["dns"] = dns
        config.update(extra)
        return config

    def resolve(self, kerlico, host, timeout=8):
        """经 direct 出站连接域名，返回实际被拨的 IP；解析失败返回 None。"""
        try:
            return tcp_echo(socks5(kerlico.listeners["in"], host, self.whoami.port, timeout=timeout))
        except (SocksReply, ConnectionError, OSError):
            return None


def zone4(*names, ip="127.0.0.21", ip6=None, ttl=60):
    return {name: {"A": [ip], **({"AAAA": [ip6]} if ip6 else {}), "ttl": ttl} for name in names}


@case("dns", "dns/config/servers", "dns/dns/servers", "dns/global/nameserver", "dns/server/address", "dns/upstream/udp", "dns/server-udp/protocol", "dns/server-udp/server", "dns/global/enable", "dns/server-common/type")
def dns_udp(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones=zone4("a.test", ip="127.0.0.21"))
    with bench.kerlico(db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"]})) as kerlico:
        ip = db.resolve(kerlico, "a.test")
        ensure(ip == "127.0.0.21", f"被拨 IP {ip}")
    with bench.kerlico(db.config(None)) as kerlico:
        before = len(upstream.log)
        ensure(db.resolve(kerlico, "a.test") is None, "未配 dns 时不应解析到伪造上游")
        ensure(len(upstream.log) == before, "未配 dns 时不应查询上游")
    kinds = sorted(item[2] for item in upstream.queries("a.test"))
    ensure(all(item[0] == "udp" for item in upstream.log) and kinds == ["A", "AAAA"], f"查询 {upstream.log}")
    upstream.close()
    base = f"伪造 UDP 上游收到 a.test 的 A 和 AAAA 查询（{len(kinds)} 条），socks 经 direct 拨到上游答的 127.0.0.21，目标报告被拨地址一致"
    return {
        "dns/config/servers": base,
        "dns/dns/servers": base + "；只有字符串形式",
        "dns/global/nameserver": base,
        "dns/server/address": base,
        "dns/upstream/udp": base,
        "dns/server-udp/protocol": base,
        "dns/server-udp/server": base + "；只接受字面 IP，域名上游见 dns/upstream/combo 的拒绝项",
        "dns/global/enable": base + "。同一配置去掉 dns 段后走系统解析，a.test 解析失败且上游无新查询",
        "dns/server-common/type": base + "；udp、tcp、tls 由 URI 协议头决定，其余类型 check 拒绝",
    }


@case("dns", "dns/upstream/tcp", "dns/server-tcp/protocol", "dns/server-tcp/server", "dns/upstream/tcp-local")
def dns_tcp(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones=zone4("t.test", ip="127.0.0.22"))
    nic = re.search(r"dev (\S+)", subprocess.run(["ip", "-o", "route", "get", "1.1.1.1"], capture_output=True, text=True).stdout).group(1)
    with bench.kerlico(db.config({"servers": [f"tcp://127.0.0.1:{upstream.port}"]})) as kerlico:
        ensure(db.resolve(kerlico, "t.test") == "127.0.0.22", "TCP 上游结果未生效")
    transports = {item[0] for item in upstream.log}
    ensure(transports == {"tcp"}, f"传输 {transports}")
    upstream.log.clear()
    outbound = {"tag": "direct", "type": "direct", "options": {"interface": nic}}
    with bench.kerlico(db.config({"servers": [f"tcp://127.0.0.1:{upstream.port}"]}, outbound=outbound)) as kerlico:
        db.resolve(kerlico, "t.test", timeout=4)
    ensure(upstream.queries("t.test"), "绑定物理网卡的 direct 不应影响回环上游")
    upstream.close()
    base = "伪造 TCP 上游只收到 TCP 查询（无 UDP），结果 127.0.0.22 被实际拨号"
    return {
        "dns/upstream/tcp": base,
        "dns/server-tcp/protocol": base,
        "dns/server-tcp/server": base + "；地址写在 URI，只接受字面 IP",
        "dns/upstream/tcp-local": base + "。direct 绑定物理网卡时回环上游仍收到查询，证明上游查询不经命名出站",
    }


@case("dns", "dns/server-udp/server-port", "dns/server-tcp/server-port", "dns/server/port")
def dns_ports(bench):
    db = DnsBench(bench)
    zones = zone4("port.test", ip="127.0.0.23")
    default = FakeDns("127.0.0.77", 53, zones)
    default6 = FakeDns("::1", 53, zones)
    custom = FakeDns(zones=zones)
    rows = []
    for server, upstream, transport in (
        ("udp://127.0.0.77", default, "udp"), ("tcp://127.0.0.77", default, "tcp"), ("udp://[::1]", default6, "udp"), ("tcp://::1", default6, "tcp"),
        (f"udp://127.0.0.1:{custom.port}", custom, "udp"), (f"tcp://127.0.0.1:{custom.port}", custom, "tcp"),
    ):
        upstream.log.clear()
        with bench.kerlico(db.config({"servers": [server]})) as kerlico:
            ensure(db.resolve(kerlico, "port.test") == "127.0.0.23", f"{server} 解析失败")
        ensure({item[0] for item in upstream.log} == {transport}, f"{server} 查询 {upstream.log}")
        rows.append(server.replace(str(custom.port), "<高位端口>"))
    bench.rejected(db.config({"servers": ["udp://127.0.0.1:0"]}))
    for item in (default, default6, custom):
        item.close()
    return f"省略端口的 URI 查询到 53 端口上的伪造上游，显式高位端口也生效：{'、'.join(rows)}；端口 0 check 拒绝"


@case("dns", "dns/upstream/dot", "dns/server-tls/protocol", "dns/server-tls/server", "dns/server-tls/server-port", "dns/server-tls/tls")
def dns_tls(bench):
    db = DnsBench(bench)
    results = {}

    def lookup(server, host="one.one.one.one"):
        with bench.kerlico(db.config({"servers": [server]}, telemetry={"directory": str(bench.fresh("t") / "state")})) as kerlico:
            try:
                sock = socks5(kerlico.listeners["in"], host, 443, timeout=20)
                sock.close()
                outcome = True
            except (SocksReply, OSError, ConnectionError):
                outcome = False
            kerlico.stop()
            telemetry = kerlico.config["telemetry"]["directory"]
        _, out, _ = run_cli("history", "--directory", telemetry, "--kind", "events")
        events = [item[1] for item in json.loads(out)] if out.strip() else []
        return outcome, events

    for server in ("tls://1.1.1.1#cloudflare-dns.com", "tls://1.1.1.1:853#cloudflare-dns.com", "tls://[2606:4700:4700::1111]#cloudflare-dns.com", "tls://8.8.8.8#dns.google"):
        results[server] = lookup(server)
    for server in ("udp://8.8.8.8", "tcp://1.1.1.1"):
        done, events = lookup(server)
        ensure(done and any(item["kind"] == "dns" and item["code"] == "ok" and "1.1.1.1" in item["addresses"] for item in events), f"公共上游 {server} 未解析 one.one.one.one：{events}")
    wrong = lookup("tls://1.1.1.1#wrong-name.example")
    ensure(not wrong[0], "证书名不符仍解析成功")
    ensure(any(item["code"] != "ok" for item in wrong[1] if item["kind"] == "dns"), f"证书名不符事件 {wrong[1]}")
    openssl_dir = bench.fresh("selfsigned")
    make_material(openssl_dir, "dot.test")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(openssl_dir / "leaf.pem", openssl_dir / "leaf.key")
    fake = FakeDns(zones=zone4("self.test"), tls=context)
    with bench.kerlico(db.config({"servers": [f"tls://127.0.0.1:{fake.port}#dot.test"]})) as kerlico:
        ensure(db.resolve(kerlico, "self.test", timeout=12) is None, "自签 DoT 上游不应被信任")
    ensure(not fake.queries("self.test"), f"TLS 握手失败后不应有查询 {fake.log}")
    fake.close()
    bench.rejected(db.config({"servers": ["tls://1.1.1.1"]}))
    ok = [server for server, (done, events) in results.items() if done and any(item["kind"] == "dns" and item["code"] == "ok" for item in events)]
    ensure("tls://1.1.1.1#cloudflare-dns.com" in ok and "tls://8.8.8.8#dns.google" in ok, f"公共 DoT 未通过：{results}")
    v6 = "tls://[2606:4700:4700::1111]#cloudflare-dns.com" in ok
    base = "公共解析器真实 DoT：" + "、".join(ok) + " 解析 one.one.one.one 成功并拨通 443，统计事件 code=ok；同名查询经 udp://8.8.8.8、tcp://1.1.1.1 也得到 1.1.1.1"
    negative = "证书名写错时解析失败（事件 code 非 ok）；本地自签 DoT 上游握手失败且没有收到查询；缺证书名 check 拒绝"
    return {
        "dns/upstream/dot": base + "。" + negative,
        "dns/server-tls/protocol": base + "。" + negative,
        "dns/server-tls/server": base + ("，含 IPv6 字面地址" if v6 else "（本机 IPv6 到公共 DoT 不通）") + "。只接受字面 IP",
        "dns/server-tls/server-port": "tls://1.1.1.1（默认 853）与 tls://1.1.1.1:853 都解析成功；端口写在 URI。" + base,
        "dns/server-tls/tls": negative + "。证书名由 # 后给出，内置 WebPKI 根校验。缺自定义 CA、跳过校验、mTLS",
    }


@case("dns", "dns/config/strategy", "dns/dns/query-strategy", "dns/global/ipv6", "dns/query-options/combo")
def dns_strategy(bench):
    db = DnsBench(bench)
    zones = {
        "both.test": {"A": ["127.0.0.31"], "AAAA": ["::1"], "ttl": 60},
        "v4.test": {"A": ["127.0.0.32"], "ttl": 60},
        "v6.test": {"AAAA": ["::1"], "ttl": 60},
    }
    upstream = FakeDns(zones=zones)
    table = {
        None: {"both.test": "127.0.0.31", "v4.test": "127.0.0.32", "v6.test": "::1"},
        "dual-stack": {"both.test": "127.0.0.31", "v4.test": "127.0.0.32", "v6.test": "::1"},
        "ipv4-only": {"both.test": "127.0.0.31", "v4.test": "127.0.0.32", "v6.test": None},
        "ipv6-only": {"both.test": "::1", "v4.test": None, "v6.test": "::1"},
    }
    rows = []
    for mode, expected in table.items():
        with bench.kerlico(db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"]}, mode=mode)) as kerlico:
            for host, want in expected.items():
                got = db.resolve(kerlico, host, timeout=4)
                ensure(got == want, f"mode={mode} {host} 拨到 {got}，应为 {want}")
            rows.append(f"{mode or '默认'}：both→{expected['both.test']}，v4→{expected['v4.test'] or '失败'}，v6→{expected['v6.test'] or '失败'}")
    qtypes = {item[2] for item in upstream.queries("both.test")}
    ensure(qtypes == {"A", "AAAA"}, f"ipv4-only 也查 AAAA：{qtypes}")
    summary = "；".join(rows)
    upstream.log.clear()
    ttl = FakeDns(zones={"ttl.test": {"A": ["127.0.0.33"], "AAAA": ["::1"], "ttl": 2}})
    with bench.kerlico(db.config({"servers": [f"udp://127.0.0.1:{ttl.port}"]})) as kerlico:
        db.resolve(kerlico, "ttl.test")
        first = len(ttl.queries("ttl.test"))
        db.resolve(kerlico, "ttl.test")
        cached = len(ttl.queries("ttl.test"))
        time.sleep(2.6)
        db.resolve(kerlico, "ttl.test")
        expired = len(ttl.queries("ttl.test"))
    ensure(first == cached and expired > cached, f"TTL 缓存：首次 {first}，复查 {cached}，过期后 {expired}")
    ttl.close()
    upstream.close()
    cache = f"TTL=2 秒的记录：首次 {first} 条查询，立即复查没有新查询，2.6 秒后新增 {expired - cached} 条"
    return {
        "dns/config/strategy": f"按节点 mode 筛选：{summary}。缺 prefer_ipv6",
        "dns/dns/query-strategy": f"不能在 dns 段配置，按节点 mode 筛选：{summary}",
        "dns/global/ipv6": f"mode=ipv4-only 时不用 AAAA 结果：{summary}。上游仍收到 A 和 AAAA，不能全局关闭 AAAA 查询",
        "dns/query-options/combo": f"已实现维度全展开：strategy（ipv4-only、ipv6-only、dual-stack 优先 IPv4）× 三类记录：{summary}；cache 默认 × ttl 上游：{cache}。缺 prefer_ipv6、disable_cache、ECS、rewrite_ttl、按查询超时，见标注",
    }


@case("dns", "dns/dns/hosts", "dns/global/use-hosts", "dns/hosts/mapping", "dns/hosts/predefined-format", "dns/server-hosts/predefined", "dns/server-hosts/protocol", "dns/flow/pipeline")
def dns_hosts(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones={**zone4("over.test", ip="127.0.0.41"), **zone4("plain.test", ip="127.0.0.42")})
    hosts = {"over.test": ["127.0.0.43"], "MiXed.Test": ["127.0.0.44"], "例子.test": ["127.0.0.45"], "two.test": ["::1", "127.0.0.46"]}
    with bench.kerlico(db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"], "hosts": hosts})) as kerlico:
        ensure(db.resolve(kerlico, "over.test") == "127.0.0.43", "hosts 应优先于上游")
        ensure(not upstream.queries("over.test"), "hosts 命中后不应查询上游")
        ensure(db.resolve(kerlico, "mixed.test") == "127.0.0.44", "hosts 键未规范化小写")
        ensure(db.resolve(kerlico, "xn--fsqu00a.test") == "127.0.0.45", "hosts 键未做 IDNA")
        ensure(db.resolve(kerlico, "two.test") == "127.0.0.46", "dual-stack 应选 IPv4")
        ensure(db.resolve(kerlico, "plain.test") == "127.0.0.42", "未命中 hosts 应查询上游")
        ensure(upstream.queries("plain.test"), "未查询上游")
    with bench.kerlico(db.config({"hosts": {"only.test": ["127.0.0.47"]}})) as kerlico:
        ensure(db.resolve(kerlico, "only.test") == "127.0.0.47", "只配 hosts 未生效")
        ensure(db.resolve(kerlico, "other.test") is None, "只配 hosts 时其他域名应失败")
    with bench.kerlico(db.config({"hosts": hosts}, mode="ipv6-only")) as kerlico:
        ensure(db.resolve(kerlico, "two.test") == "::1", "ipv6-only 应选 ::1")
    upstream.close()
    single = bench.rejected(db.config({"hosts": {"x.test": "127.0.0.1"}}))
    wildcard = bench.check(db.config({"hosts": {"*.wild.test": ["127.0.0.1"]}}))
    plus = bench.check(db.config({"hosts": {"+.wild.test": ["127.0.0.1"]}}))
    redirect = bench.rejected(db.config({"hosts": {"x.test": ["other.test"]}}))
    empty = bench.rejected(db.config({"hosts": {"x.test": []}}))
    ensure(wildcard[0] != 0 and plus[0] != 0, f"通配键 check 通过却永远不会命中：*.wild.test rc={wildcard[0]}，+.wild.test rc={plus[0]}")
    base = "hosts 优先于上游（命中时 FakeDns 无查询，被拨地址来自 hosts），键按小写和 IDNA 规范化，多 IP 按 mode 选择；未命中查询上游；只配 hosts 时其他域名失败"
    limits = f"单 IP 字符串、域名重定向、空数组、通配键都被 check 拒绝（{single}）"
    return {
        "dns/dns/hosts": base + "。" + limits,
        "dns/global/use-hosts": base + "。恒启用，不能关闭",
        "dns/hosts/mapping": base + "。" + limits,
        "dns/hosts/predefined-format": limits + "。值只收 IP 数组，没有 path",
        "dns/server-hosts/predefined": base,
        "dns/server-hosts/protocol": base + "。hosts 不是独立上游类型",
        "dns/flow/pipeline": "先 hosts 后 servers：" + base + "。缺按域名选上游和 fallback",
    }


def isolated_prefix(bench, hosts_text, nameserver):
    """私有挂载命名空间里替换 hosts、resolv.conf 和 nsswitch，不改动机器上的文件。"""
    directory = bench.fresh("netetc")
    (directory / "hosts").write_text(hosts_text, encoding="ascii")
    (directory / "resolv.conf").write_text(f"nameserver {nameserver}\noptions timeout:1 attempts:1\n", encoding="ascii")
    (directory / "nsswitch.conf").write_text("hosts: files dns\n", encoding="ascii")
    script = directory / "enter.sh"
    script.write_text(
        "#!/bin/sh\nset -e\n"
        f"mount --bind {directory}/hosts /etc/hosts\n"
        f"mount --bind {directory}/resolv.conf /etc/resolv.conf\n"
        f"mount --bind {directory}/nsswitch.conf /etc/nsswitch.conf\n"
        'exec "$@"\n', encoding="ascii")
    return ["unshare", "-m", "sh", str(script)]


@case("dns", "dns/dns/use-system-hosts", "dns/global/use-system-hosts", "dns/upstream/system", "dns/upstream/localhost", "dns/server-local/protocol")
def dns_system(bench):
    db = DnsBench(bench)
    upstream = FakeDns("127.0.0.77", 53, {**zone4("shadowed.test", ip="127.0.0.51"), **zone4("sysdns.test", ip="127.0.0.52")})
    prefix = isolated_prefix(bench, "127.0.0.1 localhost\n127.0.0.53 shadowed.test\n", "127.0.0.77")
    with bench.kerlico(db.config(None), prefix=prefix) as kerlico:
        files = db.resolve(kerlico, "shadowed.test")
        resolved = db.resolve(kerlico, "sysdns.test")
    ensure(files == "127.0.0.53", f"未配 dns 时应走系统 hosts：{files}")
    ensure(resolved == "127.0.0.52", f"未配 dns 时应走 resolv.conf 上游：{resolved}")
    ensure(not upstream.queries("shadowed.test"), "系统 hosts 命中时不应查询上游")
    with bench.kerlico(db.config({"servers": ["udp://127.0.0.77"]}), prefix=prefix) as kerlico:
        configured = db.resolve(kerlico, "shadowed.test")
    ensure(configured == "127.0.0.51", f"配 dns 后不应读系统 hosts：{configured}")
    with bench.kerlico(db.config({"hosts": {"x.test": ["127.0.0.60"]}}), prefix=prefix) as kerlico:
        hosts_only = db.resolve(kerlico, "shadowed.test", timeout=4)
    ensure(hosts_only is None, f"只配 hosts 时系统 hosts 不应生效：{hosts_only}")
    rejected = [bench.rejected(db.config({"servers": [value]})) for value in ("system://", "localhost", "local")]
    upstream.close()
    system = "私有挂载命名空间替换 /etc/hosts 和 resolv.conf：未配 dns 时 shadowed.test 解析到系统 hosts 的地址，sysdns.test 查询 resolv.conf 指向的伪造上游"
    fixed = "配 dns 后 shadowed.test 解析到配置上游的地址，只配 hosts 时解析失败，系统 hosts 不生效"
    entry = f"不能写进 dns.servers（system://、localhost、local 都被 check 拒绝：{rejected[0]}）"
    return {
        "dns/dns/use-system-hosts": system + "；" + fixed,
        "dns/global/use-system-hosts": system + "；" + fixed,
        "dns/upstream/system": system + "；" + entry,
        "dns/upstream/localhost": system + "；" + entry,
        "dns/server-local/protocol": system + "；" + entry,
    }


@case("dns", "dns/flow/query-types")
def dns_query_types(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones={
        "inline.test": {"cname": "real.test", "A": ["127.0.0.61"]},
        "chase.test": {"cname": "real.test"},
        "real.test": {"A": ["127.0.0.62"]},
        "nx.test": {"rcode": 3},
        "servfail.test": {"rcode": 2},
    })
    with bench.kerlico(db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"]})) as kerlico:
        inline = db.resolve(kerlico, "inline.test")
        chase = db.resolve(kerlico, "chase.test", timeout=6)
        missing = db.resolve(kerlico, "nx.test", timeout=4)
        fail = db.resolve(kerlico, "servfail.test", timeout=6)
    types = sorted({item[2] for item in upstream.log})
    ensure(types == ["A", "AAAA"], f"查询类型 {types}")
    ensure(inline == "127.0.0.61", f"CNAME 内联 A 结果 {inline}")
    ensure(chase == "127.0.0.62" and upstream.queries("real.test"), f"只有 CNAME 的响应应追查目标名：{chase}")
    ensure(missing is None and fail is None, "NXDOMAIN/SERVFAIL 不应连上")
    upstream.close()
    return f"上游日志只有 A、AAAA 两种查询；同一响应带 CNAME 和 A 时拨到 127.0.0.61。只有 CNAME 没有地址的响应会追查目标名，上游收到 real.test 的查询，拨到 {chase}；NXDOMAIN、SERVFAIL 都让连接失败"


@case("dns", "dns/global/direct-nameserver", "dns/resolve/flow")
def dns_direct_only(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones=zone4("local.test", ip="127.0.0.71"))
    recorder = Recorder(db.whoami.port)
    config = db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"], "hosts": {"hosts-remote.test": ["127.0.0.72"]}})
    config["outbounds"].append(socks_out("proxy", recorder.port))
    config["local_inbounds"].append(local_socks("remote", "proxy"))
    with bench.kerlico(config) as kerlico:
        ensure(db.resolve(kerlico, "local.test") == "127.0.0.71", "direct 路径未用 dns 段")
        tcp_echo(socks5(kerlico.listeners["remote"], "remote.test", 80))
        tcp_echo(socks5(kerlico.listeners["remote"], "hosts-remote.test", 80))
    targets = [item[1] for item in recorder.log]
    ensure(targets == ["remote.test", "hosts-remote.test"], f"Remote 目标 {targets}")
    ensure(not upstream.queries("remote.test") and not upstream.queries("hosts-remote.test"), "Remote 路径不应查询")
    upstream.close()
    return "direct 路径的 local.test 查询配置上游并拨号结果；socks 出站把 remote.test、hosts-remote.test 原样交给远端（记录代理收到域名），FakeDns 没有这两个名字的查询，hosts 也不改写。只有 hosts 到 dns.servers 两步，缺 nameserver-policy 和 fallback"


@case("dns", "dns/server/combo", "dns/upstream/combo")
def dns_combo(bench):
    db = DnsBench(bench)
    upstream4 = FakeDns(zones=zone4("c.test", ip="127.0.0.81"))
    upstream6 = FakeDns("::1", zones=zone4("c.test", ip="127.0.0.81"))
    done = []
    for server, fake, transport in (
        (f"udp://127.0.0.1:{upstream4.port}", upstream4, "udp"), (f"tcp://127.0.0.1:{upstream4.port}", upstream4, "tcp"),
        (f"udp://[::1]:{upstream6.port}", upstream6, "udp"), (f"tcp://[::1]:{upstream6.port}", upstream6, "tcp"),
    ):
        fake.log.clear()
        with bench.kerlico(db.config({"servers": [server]})) as kerlico:
            ensure(db.resolve(kerlico, "c.test") == "127.0.0.81", f"{server} 失败")
        ensure({item[0] for item in fake.log} == {transport}, f"{server} {fake.log}")
        done.append(transport + ("/IPv6" if ":" in fake.host else "/IPv4"))
    dead = free_port(socket.SOCK_DGRAM)
    upstream4.log.clear()
    with bench.kerlico(db.config({"servers": [f"udp://127.0.0.1:{dead}", f"udp://127.0.0.1:{upstream4.port}"]})) as kerlico:
        ensure(db.resolve(kerlico, "c.test") == "127.0.0.81", "第一个上游不通时应换下一个")
    upstream4.close()
    upstream6.close()
    rejected = {}
    for value in ("https://1.1.1.1/dns-query", "h3://1.1.1.1", "quic://1.1.1.1", "dhcp://auto", "system://", "rcode://success", "fakeip://x", "udp://dns.google", "tcp://dns.google:53", "1.1.1.1", "tls://dns.google#dns.google", "udp://1.1.1.1#name", "tcp://1.1.1.1#ecs=1.2.3.0/24", "udp+local://1.1.1.1", "tcp+local://1.1.1.1"):
        rc, _, _ = bench.check(db.config({"servers": [value]}))
        rejected[value] = rc != 0
    accepted = [value for value, refused in rejected.items() if not refused]
    ensure(not accepted, f"这些未实现的写法 check 通过：{accepted}")
    return f"udp、tcp 上游 × IPv4、IPv6 地址各真实查询一次（{'、'.join(done)}），tls 见 dns/upstream/dot；两个上游时第一个不通换第二个。未实现的 {len(rejected)} 种写法（https、h3、quic、dhcp、system、rcode、fakeip、域名上游、ECS 参数、+local 前缀等）都被 check 拒绝。缺 detour、bind_interface、domain_resolver、fallback、ECS"


@case("dns")
def dns_events(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones=zone4("udp.test", ip="127.0.0.1"))
    state = bench.fresh("t") / "state"
    config = db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"]}, forwards=[("fu", "udp", "udp.test", db.udp.port)], telemetry={"directory": str(state)})
    with bench.kerlico(config) as kerlico:
        udp_roundtrip(kerlico.listeners["fu"])
        ensure(db.resolve(kerlico, "udp.test") == "127.0.0.1", "TCP 解析失败")
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(state), "--kind", "events")
    events = [item[1] for item in json.loads(out)]
    dns_events = [item for item in events if item["kind"] == "dns" and item["target"] == "udp.test"]
    ensure(dns_events and dns_events[0]["addresses"] == ["127.0.0.1"], f"事件 {events}")
    upstream.close()


# ------------------------------------------------------------------ 用户


def spec_hysteria_base64(material):
    auth = base64.b64encode(secrets.token_bytes(16)).decode()
    return ich.Spec({"tls": ich.tls_node(material), "transport": "udp"}, {"auth": auth}, {"auth": auth, "up_bps": 125000000, "down_bps": 125000000, "tls": ich.tls_client(material), "transport": "udp"})


def spec_snell_userkey(shared={}):
    psk = shared.setdefault("psk", secrets.token_hex(16))

    def build(material):
        key = secrets.token_hex(8)
        return ich.Spec({"version": 6}, {"psk": psk, "userkey": key}, {"version": 6, "psk": psk, "userkey": key})
    return build


# 键 -> [(取值说明, 协议类型, 构造函数, sing-box 名称)]；同一键的多行覆盖 native_credential 的不同字段。
CREDENTIALS = {
    "user/socks/credentials": [("username+password", "socks", ich.spec_socks, "socks")],
    "user/http/credentials": [("username+password", "http", ich.spec_http(False), "http"), ("TLS 载体", "http", ich.spec_http(True), None)],
    "user/shadowsocks/credentials": [("password", "shadowsocks", ich.spec_shadowsocks("aes-128-gcm"), "shadowsocks")],
    "user/trojan/credentials": [("password", "trojan", ich.spec_trojan("tcp"), "trojan")],
    "user/vless/credentials": [("uuid，flow 为空", "vless", ich.spec_vless("tcp"), "vless"), ("uuid，flow=xtls-rprx-vision", "vless", ich.spec_vless("tcp", flow="xtls-rprx-vision"), "vless-vision")],
    "user/vmess/credentials": [("uuid", "vmess", ich.spec_vmess("tcp"), "vmess")],
    "user/anytls/credentials": [("password", "anytls", ich.spec_anytls, "anytls")],
    "user/hysteria/credentials": [("auth_str", "hysteria1", ich.spec_hysteria1("udp", False), "hysteria"), ("auth（base64）", "hysteria1", spec_hysteria_base64, None)],
    "user/hysteria2/credentials": [("auth", "hysteria2", ich.spec_hysteria2(False), "hysteria2")],
    "user/tuic/credentials": [("v5 uuid+password", "tuic", ich.spec_tuic(5, "native"), "tuic"), ("v4 token", "tuic", ich.spec_tuic(4, "native"), None)],
    "user/naive/credentials": [("username+password", "naive", ich.spec_naive("h2"), "naive")],
    "user/snell/credentials": [("每成员独立 psk，v4 客户端到 v5 节点", "snell", ich.spec_snell(4, 5), None), ("同 psk 不同 userkey，v6", "snell", spec_snell_userkey(), "snell")],
    "user/shadowtls/credentials": [("内层 ss2022 key，外层 v3 users", "shadowtls", ich.spec_shadowtls(3), "shadowtls")],
}


def sb_tls(material, **extra):
    return {"enabled": True, "server_name": ich.SNI, "certificate": material.ca.strip().splitlines(), **extra}


def sing_box_outbounds(name, spec, port, material):
    """返回 sing-box 的出站列表，第一项是入口要走的出站。"""
    server = {"server": "127.0.0.1", "server_port": port}
    credential = spec.member
    tls = sb_tls(material)
    if name == "socks":
        return [{"type": "socks", **server, "version": "5", **credential}]
    if name == "http":
        return [{"type": "http", **server, **credential}]
    if name == "shadowsocks":
        return [{"type": "shadowsocks", **server, "method": "aes-128-gcm", **credential}]
    if name == "trojan":
        return [{"type": "trojan", **server, **credential, "tls": tls}]
    if name == "vless":
        return [{"type": "vless", **server, "uuid": credential["uuid"], "tls": tls}]
    if name == "vless-vision":
        return [{"type": "vless", **server, "uuid": credential["uuid"], "flow": "xtls-rprx-vision", "tls": tls}]
    if name == "vmess":
        return [{"type": "vmess", **server, "uuid": credential["uuid"], "security": "aes-128-gcm", "tls": tls}]
    if name == "anytls":
        return [{"type": "anytls", **server, **credential, "tls": tls}]
    if name == "hysteria":
        return [{"type": "hysteria", **server, "up_mbps": 100, "down_mbps": 100, "auth_str": credential["auth_str"], "tls": sb_tls(material, alpn=["hysteria"])}]
    if name == "hysteria2":
        return [{"type": "hysteria2", **server, "password": credential["auth"], "tls": tls}]
    if name == "tuic":
        return [{"type": "tuic", **server, **credential, "congestion_control": "cubic", "tls": sb_tls(material, alpn=["h3"])}]
    if name == "snell":
        return [{"type": "snell", **server, "version": 6, "psk": credential["psk"], "userkey": credential["userkey"]}]
    if name == "naive":
        return [{"type": "naive", **server, **credential, "tls": tls}]
    if name == "shadowtls":
        return [
            {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": credential["key"], "detour": "carrier"},
            {"type": "shadowtls", "tag": "carrier", **server, "version": 3, "password": spec.client["password"], "tls": tls},
        ]
    raise ValueError(name)


class SingBox:
    def __init__(self, bench, outbounds):
        self.port = free_port()
        directory = bench.fresh("sb")
        path = directory / "config.json"
        first, *rest = outbounds
        path.write_text(json.dumps({
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": self.port}],
            "outbounds": [{**first, "tag": "proxy"}, *rest],
            "route": {"final": "proxy"},
        }), encoding="utf-8")
        self.log_path = directory / "log"
        with open(self.log_path, "wb") as log:
            self.process = subprocess.Popen([ARGS.sing_box, "run", "-c", str(path)], stdout=log, stderr=log, start_new_session=True, env={**os.environ, "LD_LIBRARY_PATH": str(Path(ARGS.sing_box).parent)})
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise Fail(f"sing-box 启动失败: {self.log_path.read_text(errors='replace')[-300:]}")
            with socket.socket() as probe:
                probe.settimeout(0.2)
                if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            time.sleep(0.05)
        raise Fail("sing-box 启动超时")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.process.kill()
        self.process.wait()


class TlsOrigin(Listener):
    """ShadowTLS 的握手来源：真实 TLS 1.3 服务。"""

    def __init__(self, directory):
        self.port = free_port()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(directory / "leaf.pem", directory / "leaf.key")
        super().__init__([("127.0.0.1", self.port)])

    def handle(self, conn, peer):
        with self.context.wrap_socket(conn, server_side=True) as tls:
            while tls.recv(4096):
                pass


def client_transfer(bench, kerlico_client_config, exact, upload, download, timeout=20):
    with bench.kerlico(kerlico_client_config) as client:
        return exact_transfer(socks5(client.listeners["socks"], "127.0.0.1", exact.port, timeout=timeout), upload, download)


def proxy_client_config(protocol, client):
    return {"version": 2, "outbounds": [{"tag": "proxy", "type": protocol, "options": client}], "local_inbounds": [local_socks("socks", "proxy")], "limits": {"connect_timeout_ms": 6000, "idle_timeout_ms": 20000, "drain_timeout_ms": 300}}


def transfer_refused(bench, protocol, spec, port, exact):
    try:
        client_transfer(bench, proxy_client_config(protocol, ich.finish_client(spec.client, "127.0.0.1", port)), exact, 10, 10, timeout=8)
    except (SocksReply, OSError, ConnectionError, Fail):
        return True
    return False


def credential_round(bench, label, protocol, build, sing_box_name, material, origin_port, exact):
    """同一节点三个成员：两名启用成员真实传输并核对按账户计量，第三名停用；随机凭据和停用成员的传输都要失败。"""
    first, second, disabled, stranger = build(material), build(material), build(material), build(material)
    if protocol == "shadowtls":
        for spec in (second, disabled, stranger):
            spec.client["password"] = first.client["password"]
    port = free_port()
    node = {
        "tag": "node", "type": protocol, "listen": f"127.0.0.1:{port}", "outbound": "direct",
        "options": ich.resolve_placeholders(first.node, origin_port),
        "members": [{"user_id": U1, "native_credential": first.member}, {"user_id": U2, "native_credential": second.member}, {"user_id": U3, "enabled": False, "native_credential": disabled.member}],
    }
    config = {"version": 2, "accounts": [account(U1), account(U2), account(U3)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [node], "control": control_on(), "limits": {"connect_timeout_ms": 6000, "idle_timeout_ms": 20000, "drain_timeout_ms": 300, "max_sessions": 256}}
    with bench.kerlico(config) as server:
        up1, down1 = client_transfer(bench, proxy_client_config(protocol, ich.finish_client(first.client, "127.0.0.1", port)), exact, 11111, 22222)
        up2, down2 = client_transfer(bench, proxy_client_config(protocol, ich.finish_client(second.client, "127.0.0.1", port)), exact, 3333, 4444)
        time.sleep(0.3)
        users = server.get("/v1/usage")["users"]
        ensure(pair_of(users.get(U1, ZERO)) == (up1, down1), f"{label} U1 用量 {users.get(U1)}，实发 {up1}/{down1}")
        ensure(pair_of(users.get(U2, ZERO)) == (up2, down2), f"{label} U2 用量 {users.get(U2)}，实发 {up2}/{down2}")
        ensure(transfer_refused(bench, protocol, stranger, port, exact), f"{label} 随机凭据未被拒绝")
        ensure(transfer_refused(bench, protocol, disabled, port, exact), f"{label} 停用成员未被拒绝")
        users = server.get("/v1/usage")["users"]
        ensure(U3 not in users and pair_of(users[U1]) == (up1, down1), f"{label} 被拒凭据产生了用量 {users}")
        peer = ""
        if ARGS.sing_box and sing_box_name:
            with SingBox(bench, sing_box_outbounds(sing_box_name, first, port, material)) as box:
                up3, down3 = exact_transfer(socks5(("127.0.0.1", box.port), "127.0.0.1", exact.port, timeout=20), 5555, 6666)
            time.sleep(0.5)
            final = server.get("/v1/usage")["users"][U1]
            ensure(pair_of(final) == (up1 + up3, down1 + down3), f"{label} sing-box 客户端用量 {final}，应为 {up1 + up3}/{down1 + down3}")
            peer = f"，sing-box 1.14.4 客户端 {up3}/{down3} 字节计入同一账户"
    return f"{label}：U1 {up1}/{down1}、U2 {up2}/{down2} 字节与 /v1/usage 相等，随机凭据和停用成员被拒{peer}"


@case("user", *CREDENTIALS, "user/auth/combo")
def user_credentials(bench):
    material = bench.tls_material()
    directory = bench.fresh("origin")
    origin_material = make_material(directory, ich.SNI, "origin")
    origin = TlsOrigin(directory)
    exact = Exact()
    out = {}
    done = []
    for key, variants in CREDENTIALS.items():
        rows = []
        failures = []
        for label, protocol, build, name in variants:
            try:
                rows.append(credential_round(bench, label, protocol, build, name, origin_material if protocol == "shadowtls" else material, origin.port, exact))
                done.append(f"{protocol}/{label}")
            except (Fail, SocksReply, OSError, ConnectionError) as error:
                failures.append(f"{protocol}/{label}：{error}")
        out[key] = ("fail", "；".join(failures)) if failures else "节点多成员实测。" + "；".join(rows)
    bad = [key for key, value in out.items() if isinstance(value, tuple)]
    node = {"tag": "n", "type": "vmess", "listen": "127.0.0.1:0", "outbound": "direct", "options": {"transport": {"type": "tcp"}, "security": {"type": "none"}}, "members": [{"user_id": U1, "native_credential": {"uuid": str(uuid.uuid4()), "alterId": 64}}]}
    bench.rejected({"version": 2, "accounts": [account(U1)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [node]})
    if isinstance(out["user/vmess/credentials"], str):
        out["user/vmess/credentials"] += "。alterId 字段 check 拒绝，只支持 AEAD"
    if isinstance(out["user/shadowtls/credentials"], str):
        out["user/shadowtls/credentials"] += "。外层 options.users[].password 是载体保护，用户归属由内层 ss2022 成员决定"
    out["user/auth/combo"] = ("fail", f"未通过：{bad}") if bad else f"配置定义用户 × 各协议凭据形式全部实测（{'、'.join(done)}），用量按账户归属，错误和停用凭据被拒。缺运行期增删用户（api adu/rmu）和 level；masque 只有出站；wireguard 公钥成员由协议组验证"
    origin.close()
    exact.close()
    return out


@case("user", "user/global/authentication", "user/identity/level-email", "user/inbound/in-user-match", "user/inbound/users-override")
def user_accounts(bench):
    whoami = Whoami()
    recorder = Recorder(whoami.port)
    config = {
        "version": 2,
        "accounts": [account(U1, "alice"), account(U2, "bob")],
        "outbounds": [{"tag": "direct", "type": "direct"}, socks_out("rec", recorder.port)],
        "nodes": [socks_node("n1", "direct", [(U1, "a1", "pw-1"), (U2, "b1", "pw-2")]), socks_node("n2", "direct", [(U1, "a2", "pw-3")])],
        "local_inbounds": [local_socks("open", "direct")],
        "routes": [{"outbound": "rec", "user": [U1]}],
        "control": control_on(),
    }
    with bench.kerlico(config) as kerlico:
        tcp_echo(socks5(kerlico.listeners["n1"], "a.example", 1, ("a1", "pw-1")))
        tcp_echo(socks5(kerlico.listeners["n2"], "a.example", 2, ("a2", "pw-3")))
        ensure(len(recorder.log) == 2, f"两节点的 U1 都应走 rec：{recorder.log}")
        tcp_echo(socks5(kerlico.listeners["n1"], "127.0.0.1", whoami.port, ("b1", "pw-2")))
        ensure(len(recorder.log) == 2, "U2 不应走 rec")
        tcp_echo(socks5(kerlico.listeners["open"], "127.0.0.1", whoami.port))
        flows = kerlico.get("/v1/flows")
        users = {item["user"] for item in flows}
        ensure(users == {U1, U2, None}, f"flows 用户 {users}")
        try:
            socks5(kerlico.listeners["n2"], "a.example", 1, ("a1", "pw-1"))
            raise Fail("n2 不应接受 n1 的凭据")
        except (SocksReply, ConnectionError):
            pass
        usage = kerlico.get("/v1/usage")["users"]
        ensure(usage[U1]["download_bytes"] > 0, "U1 无用量")
    epoch_node = socks_node("n1", "direct", [(U1, "a1", "pw-1"), (U2, "b1", "pw-2")])
    epoch_node["members"][0]["credential_epoch"] = 7
    off_account = {**config, "accounts": [account(U1, "alice"), {**account(U2, "bob"), "enabled": False}], "nodes": [epoch_node], "routes": []}
    with bench.kerlico(off_account) as kerlico:
        tcp_echo(socks5(kerlico.listeners["n1"], "127.0.0.1", whoami.port, ("a1", "pw-1")))
        ensure(kerlico.get("/v1/flows")[-1]["credential_epoch"] == 7, "flows 的 credential_epoch 应为 7")
        try:
            socks5(kerlico.listeners["n1"], "127.0.0.1", whoami.port, ("b1", "pw-2"))
            raise Fail("停用账户的成员不应登录")
        except (SocksReply, ConnectionError):
            pass
    duplicate = {**config, "nodes": [socks_node("n1", "direct", [(U1, "same", "pw-1")]), socks_node("n2", "direct", [(U1, "same", "pw-1")])]}
    reused = bench.rejected(duplicate)
    no_members = {**config, "nodes": [{"tag": "n1", "type": "socks", "listen": "127.0.0.1:0", "outbound": "direct", "options": {"version": "5"}}]}
    empty = bench.rejected(no_members)
    public_open = {**config, "local_inbounds": [local_socks("open", "direct", "0.0.0.0:0")]}
    exposed = bench.rejected(public_open)
    dup_user = bench.rejected({**config, "accounts": [account(U1, "alice"), account(U2, "alice")]})
    unknown = bench.rejected({**config, "nodes": [socks_node("n1", "direct", [("00000000-0000-4000-8000-0000000000ff", "x", "y")])]})
    level = bench.rejected({**config, "accounts": [{**account(U1, "alice"), "level": 1}, account(U2, "bob")]})
    return {
        "user/global/authentication": f"同一账户 U1 在 n1、n2 上用各自凭据登录，流量归同一账户；n2 不接受 n1 的凭据；跨节点复用同一凭据 check 拒绝（{reused}）。没有全局用户表",
        "user/identity/level-email": f"/v1/flows 的 user 字段是账户 UUID，/v1/usage 按 UUID 分项；重复用户名 check 拒绝（{dup_user}），level 字段 check 拒绝（{level}）；accounts[].enabled=false 的成员登录被拒；flows.credential_epoch 等于成员配置的 7",
        "user/inbound/in-user-match": "routes[].user=U1 时，n1、n2 上的 U1 都走 rec 记录代理，U2 和无认证入口不走",
        "user/inbound/users-override": f"nodes 没有 members check 拒绝（{empty}）；local_inbounds 回环无认证可用且 flows.user 为空；非回环 local_inbounds check 拒绝（{exposed}）；成员引用不存在的账户 check 拒绝（{unknown}）。没有全局用户可继承",
    }


def close_time(sock, limit):
    """等到对端关闭，返回秒数；超过 limit 仍未关闭返回 None。"""
    sock.settimeout(limit)
    started = time.monotonic()
    try:
        while sock.recv(4096):
            pass
    except (socket.timeout, TimeoutError):
        return None
    except OSError:
        pass
    return time.monotonic() - started


@case("user", "user/policy/conn-idle", "user/policy/handshake", "user/policy/uplink-only", "user/policy/downlink-only")
def user_policy(bench):
    whoami = Whoami()
    stall = Recorder(whoami.port, stall=True)

    def base(limits, port):
        return {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}, socks_out("stall", port)], "local_inbounds": [local_socks("in", "direct"), local_socks("slow", "stall")], "limits": limits}

    idle = {}
    for milliseconds in (600, 2500):
        with bench.kerlico(base({"idle_timeout_ms": milliseconds}, stall.port)) as kerlico:
            sock = socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port)
            recv_line(sock)
            seconds = close_time(sock, 10)
            ensure(seconds is not None and milliseconds / 1000 * 0.7 <= seconds <= milliseconds / 1000 * 1.6 + 0.5, f"idle={milliseconds} 关闭耗时 {seconds}")
            idle[milliseconds] = round(seconds, 2)
            sock.close()
    handshake = {}
    for milliseconds in (500, 2000):
        with bench.kerlico(base({"connect_timeout_ms": milliseconds}, stall.port)) as kerlico:
            started = time.monotonic()
            try:
                socks5(kerlico.listeners["slow"], "stalled.example", 80, timeout=15).close()
                raise Fail("挂起的上游不应连接成功")
            except (SocksReply, ConnectionError):
                pass
            seconds = time.monotonic() - started
            ensure(milliseconds / 1000 * 0.7 <= seconds <= milliseconds / 1000 * 1.6 + 0.5, f"connect={milliseconds} 失败耗时 {seconds}")
            handshake[milliseconds] = round(seconds, 2)
    talker = Talker(6)
    half = {}
    for milliseconds in (600,):
        with bench.kerlico(base({"idle_timeout_ms": milliseconds}, stall.port)) as kerlico:
            sock = socks5(kerlico.listeners["in"], "127.0.0.1", talker.port)
            recv_exact(sock, 1)
            sock.shutdown(socket.SHUT_WR)
            got = 0
            last = time.monotonic()
            sock.settimeout(10)
            try:
                while chunk := sock.recv(16):
                    got += len(chunk)
                    last = time.monotonic()
            except OSError:
                pass
            gap = time.monotonic() - last
            ensure(got == 6, f"半关闭后只收到 {got} 字节")
            ensure(0.3 <= gap <= 2.0, f"下行结束后关闭耗时 {gap}")
            half["uplink"] = (got, round(gap, 2))
            sock.close()
    closer = HalfCloser()
    with bench.kerlico(base({"idle_timeout_ms": 600}, stall.port)) as kerlico:
        sock = socks5(kerlico.listeners["in"], "127.0.0.1", closer.port)
        sock.settimeout(5)
        ensure(sock.recv(16) == b"", "目标半关闭后应读到 EOF")
        for _ in range(6):
            sock.sendall(b"y" * 100)
            time.sleep(0.2)
        time.sleep(0.2)
        ensure(closer.received == 600, f"目标半关闭后上行应继续：{closer.received}")
        started = time.monotonic()
        try:
            while True:
                sock.sendall(b"")
                time.sleep(0.05)
                if time.monotonic() - started > 3:
                    break
        except OSError:
            pass
        sock.close()
    return {
        "user/policy/conn-idle": f"limits.idle_timeout_ms 600 与 2500：空闲连接分别在 {idle[600]} 秒和 {idle[2500]} 秒后关闭，全局一个值，不分等级",
        "user/policy/handshake": f"limits.connect_timeout_ms 500 与 2000：上游不应答时 SOCKS 分别在 {handshake[500]} 秒和 {handshake[2000]} 秒失败，全局一个值，不分等级",
        "user/policy/uplink-only": f"客户端半关闭上行后目标持续下发，每 200 毫秒 1 字节收齐 {half['uplink'][0]} 字节；下行停止后 {half['uplink'][1]} 秒关闭（idle_timeout_ms=600）。没有单独时限",
        "user/policy/downlink-only": f"目标半关闭下行后客户端读到 EOF，继续上行 1.2 秒，目标实收 {closer.received} 字节，半关闭后活动间隔未超过 idle_timeout_ms=600 时不被切断。没有单独时限",
    }


# ------------------------------------------------------------------ 统计与控制接口


class StatsBench:
    def __init__(self, bench, telemetry=None, secret=None, limits=None):
        self.bench = bench
        self.exact = Exact()
        self.whoami = Whoami()
        self.udp = UdpEcho()
        self.recorder = Recorder(self.exact.port, self.udp.port)
        self.secret = secret
        self.state = None
        self.config = {
            "version": 2,
            "accounts": [account(U1), account(U2)],
            "outbounds": [{"tag": "direct", "type": "direct"}, socks_out("viaproxy", self.recorder.port), {"tag": "block", "type": "reject"}],
            "nodes": [
                socks_node("edge", "direct", [(U1, "e1", "pw-e1"), (U2, "e2", "pw-e2")]),
                socks_node("edge6", "direct", [(U2, "e6", "pw-e6")], listen=f"[::1]:{free_port()}"),
            ],
            "local_inbounds": [local_socks("open", "direct")],
            "inbounds": [{"tag": "fwd", "type": "udp-forward", "listen": f"127.0.0.1:{free_port(socket.SOCK_DGRAM)}", "target": {"host": "127.0.0.1", "port": self.udp.port}, "outbound": "direct"}],
            "routes": [{"outbound": "viaproxy", "user": [U1]}, {"outbound": "block", "port": [9]}],
            "control": control_on(secret),
        }
        if limits:
            self.config["limits"] = limits
        if telemetry is not None:
            self.state = bench.fresh("t") / "state"
            self.config["telemetry"] = {"directory": str(self.state), **telemetry}

    def traffic(self, kerlico):
        """U1 经 viaproxy，U2 经 direct，无认证入口经 direct；返回各维度应有字节。"""
        u1 = exact_transfer(socks5(kerlico.listeners["edge"], "exact.example", 80, ("e1", "pw-e1")), 100000, 200000)
        u2 = exact_transfer(socks5(kerlico.listeners["edge"], "127.0.0.1", self.exact.port, ("e2", "pw-e2")), 30000, 40000)
        u26 = exact_transfer(socks5(kerlico.listeners["edge6"], "127.0.0.1", self.exact.port, ("e6", "pw-e6")), 5000, 6000)
        local = exact_transfer(socks5(kerlico.listeners["open"], "127.0.0.1", self.exact.port), 700, 800)
        time.sleep(0.3)
        return {"u1": u1, "u2": u2, "u26": u26, "local": local}

    def close(self):
        for item in (self.exact, self.whoami, self.udp, self.recorder):
            item.close()


ZERO = {"upload_bytes": 0, "download_bytes": 0}


def add(*pairs):
    return (sum(pair[0] for pair in pairs), sum(pair[1] for pair in pairs))


def pair_of(usage):
    return (usage["upload_bytes"], usage["download_bytes"])


def stored_usage(rows, dimension, key=None):
    """history --kind usage 的行按维度加总，跨运行累加。"""
    pairs = [pair_of(row["usage"]) for row in rows if row["dimension"] == dimension and (key is None or row["key"] == key)]
    return add(*pairs) if pairs else (0, 0)


@case("stats", "stats/counter/inbound-tag-traffic-downlink", "stats/counter/inbound-tag-traffic-uplink", "stats/counter/outbound-tag-traffic-downlink", "stats/counter/outbound-tag-traffic-uplink", "stats/counter/user-email-traffic-downlink", "stats/counter/user-email-traffic-uplink", "stats/connections/totals", "stats/policy/stats-inbound-downlink", "stats/policy/stats-inbound-uplink", "stats/policy/stats-outbound-downlink", "stats/policy/stats-outbound-uplink", "stats/policy/stats-user-downlink", "stats/policy/stats-user-uplink", "stats/stats/enable")
def stats_counters(bench):
    sb = StatsBench(bench)
    with bench.kerlico(sb.config) as kerlico:
        got = sb.traffic(kerlico)
        usage = kerlico.get("/v1/usage")
    third_party = sorted(flow for flow in sb.exact.flows)
    expected_flows = sorted(item for item in got.values())
    ensure(third_party == expected_flows, f"目标实收 {third_party}，客户端 {expected_flows}")
    checks = {
        "edge": (usage["nodes"]["edge"], add(got["u1"], got["u2"])),
        "edge6": (usage["nodes"]["edge6"], got["u26"]),
        "open": (usage["nodes"]["open"], got["local"]),
        "viaproxy": (usage["outbounds"]["viaproxy"], got["u1"]),
        "direct": (usage["outbounds"]["direct"], add(got["u2"], got["u26"], got["local"])),
        "U1": (usage["users"][U1], got["u1"]),
        "U2": (usage["users"][U2], add(got["u2"], got["u26"])),
        "engine": (usage["engine"], add(*got.values())),
    }
    for label, (actual, want) in checks.items():
        ensure(pair_of(actual) == want, f"{label} 用量 {pair_of(actual)}，应为 {want}")
    sb.close()
    note = "目标实收字节与客户端收发一致"
    node = f"节点 edge {pair_of(usage['nodes']['edge'])}、edge6 {pair_of(usage['nodes']['edge6'])}、open {pair_of(usage['nodes']['open'])}（上行, 下行），与四条真实 TCP 流的实收字节完全相等；{note}"
    out_text = f"出站 viaproxy {pair_of(usage['outbounds']['viaproxy'])}、direct {pair_of(usage['outbounds']['direct'])}，与按用户规则分流后的实收字节完全相等；{note}"
    user_text = f"U1 {pair_of(usage['users'][U1])}、U2 {pair_of(usage['users'][U2])}（U2 含 IPv4 和 IPv6 两个节点），与实收字节完全相等；{note}；用账户 UUID 代替 email"
    always = "未配 telemetry 的进程里计数已生效，内存计数恒开，不能按维度或等级关闭。"
    return {
        "stats/counter/inbound-tag-traffic-downlink": node,
        "stats/counter/inbound-tag-traffic-uplink": node,
        "stats/counter/outbound-tag-traffic-downlink": out_text,
        "stats/counter/outbound-tag-traffic-uplink": out_text,
        "stats/counter/user-email-traffic-downlink": user_text,
        "stats/counter/user-email-traffic-uplink": user_text,
        "stats/connections/totals": f"/v1/usage engine {pair_of(usage['engine'])} 等于四条流实收之和；缺内存字段",
        "stats/policy/stats-inbound-downlink": always + node,
        "stats/policy/stats-inbound-uplink": always + node,
        "stats/policy/stats-outbound-downlink": always + out_text,
        "stats/policy/stats-outbound-uplink": always + out_text,
        "stats/policy/stats-user-downlink": always + user_text,
        "stats/policy/stats-user-uplink": always + user_text,
        "stats/stats/enable": always + "配 telemetry 后写 SQLite，见 stats/access-log/connection-record",
    }


@case("stats", "stats/access-log/connection-record", "stats/connections/record", "stats/clash-api/connections", "log/log/access", "log/log/dns-log", "log/log/error", "log/log/mask-address", "config/top/log", "api/connections/get-connections")
def stats_records(bench):
    sb = StatsBench(bench, telemetry={"sample_interval_ms": 200})
    dns = FakeDns(zones=zone4("rec.test", ip="127.0.0.1"))
    sb.config["dns"] = {"servers": [f"udp://127.0.0.1:{dns.port}"]}
    with bench.kerlico(sb.config) as kerlico:
        got = sb.traffic(kerlico)
        tcp_echo(socks5(kerlico.listeners["open"], "rec.test", sb.whoami.port))
        try:
            socks5(kerlico.listeners["open"], "blocked.example", 9).close()
        except (SocksReply, ConnectionError):
            pass
        try:
            socks5(kerlico.listeners["open"], "nx-name.test", 80, timeout=6).close()
        except (SocksReply, ConnectionError):
            pass
        flows_live = kerlico.get("/v1/flows")
        ensure(all(item["observed_source"] in (None, "127.0.0.0/24", "::/48") for item in flows_live), f"/v1/flows 来源未遮罩：{[item['observed_source'] for item in flows_live]}")
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(sb.state), "--kind", "flows")
    stored = [item[1] for item in json.loads(out)]
    _, out, _ = run_cli("history", "--directory", str(sb.state), "--kind", "events")
    events = [item[1] for item in json.loads(out)]
    u1 = next(item for item in stored if item["user"] == U1)
    ensure(u1["outbound"] == "viaproxy" and u1["node"] == "edge" and (u1["usage"]["upload_bytes"], u1["usage"]["download_bytes"]) == got["u1"], f"U1 记录 {u1}")
    ensure(u1["original_host"] == "exact.example" or "exact.example" in str(u1["original"]), f"原始目标 {u1['original']}")
    ensure(u1["observed_source"] == "127.0.0.0/24" and u1["ended_ms"] and u1["started_ms"], f"来源或时间 {u1}")
    dns_events = [item for item in events if item["kind"] == "dns"]
    ok_dns = [item for item in dns_events if item["code"] == "ok" and item["target"] == "rec.test"]
    bad_dns = [item for item in dns_events if item["code"] != "ok" and item["target"] == "nx-name.test"]
    error_events = [item for item in events if item["kind"] == "error"]
    ensure(ok_dns and ok_dns[0]["addresses"] == ["127.0.0.1"], f"dns 事件 {dns_events}")
    ensure(bad_dns, f"失败 dns 事件 {dns_events}")
    ensure(any(item["target"] and "blocked.example" in item["target"] for item in error_events), f"error 事件 {error_events}")
    sb.close()
    # 关闭开关与不遮罩。
    off = StatsBench(bench, telemetry={"access_records": False, "dns_records": False, "error_records": False, "mask_source": False, "sample_interval_ms": 200})
    off.config["dns"] = {"servers": [f"udp://127.0.0.1:{dns.port}"]}
    with bench.kerlico(off.config) as kerlico:
        off.traffic(kerlico)
        tcp_echo(socks5(kerlico.listeners["open"], "rec.test", off.whoami.port))
        try:
            socks5(kerlico.listeners["open"], "blocked.example", 9).close()
        except (SocksReply, ConnectionError):
            pass
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(off.state), "--kind", "flows")
    ensure(json.loads(out) == [], f"access_records=false 仍有记录 {out[:200]}")
    _, out, _ = run_cli("history", "--directory", str(off.state), "--kind", "events")
    ensure(json.loads(out) == [], f"dns_records、error_records=false 仍有事件 {out[:200]}")
    _, out, _ = run_cli("history", "--directory", str(off.state), "--kind", "usage")
    ensure(stored_usage(json.loads(out), "engine")[1] > 0, "access_records=false 时用量也应保留")
    off.close()
    plain = StatsBench(bench, telemetry={"mask_source": False, "sample_interval_ms": 200})
    with bench.kerlico(plain.config) as kerlico:
        plain.traffic(kerlico)
        memory = kerlico.get("/v1/flows")
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(plain.state), "--kind", "flows")
    sources = {item[1]["observed_source"].rsplit(":", 1)[0] for item in json.loads(out) if item[1]["observed_source"]}
    ensure("127.0.0.1" in sources or "[::1]" in sources, f"mask_source=false 来源 {sources}")
    masked_memory = {item["observed_source"] for item in memory if item["observed_source"]}
    ensure(masked_memory <= {"127.0.0.0/24", "::/48"}, f"/v1/flows 恒遮罩，实际 {masked_memory}")
    plain.close()
    dns.close()
    fields = "、".join(k for k in ("node", "user", "outbound", "original", "observed_source", "kind", "stage", "end", "started_ms", "ended_ms", "usage") if k in u1)
    record = f"history --kind flows 与 /v1/flows 各给出 {len(stored)} 条，U1 记录含 {fields}，字节与实收相等，目标 exact.example"
    return {
        "stats/access-log/connection-record": record + "；access_records=false 时 flows 为空、用量仍在",
        "stats/connections/record": record + "；缺 chains、rule",
        "stats/clash-api/connections": f"/v1/flows 列出记录，/v1/usage 给累计；{record}。路径和字段不兼容 Clash，没有 WebSocket",
        "api/connections/get-connections": f"/v1/flows 分页查询内存记录，来源遮罩；{record}。没有 WebSocket 推送",
        "log/log/access": record + "；access_records=false 时 flows 为空。写 SQLite，不写文本文件",
        "log/log/dns-log": f"dns 事件 {len(dns_events)} 条：rec.test 成功带 addresses，nx-name.test 失败 code={bad_dns[0]['code']}；dns_records=false 时无事件",
        "log/log/error": f"reject 目标 blocked.example 产生 error 事件 code={next(item['code'] for item in error_events if item['target'] and 'blocked' in item['target'])}；error_records=false 时无事件。入口失败打印到 stderr 见 api/clash/get。不能写到指定文件",
        "log/log/mask-address": "mask_source=true 时 history 来源为 127.0.0.0/24 和 ::/48，mask_source=false 时为真实地址和端口，/v1/flows 恒遮罩。缺 Xray 其他粒度",
        "config/top/log": "顶层 telemetry 的 access_records、dns_records、error_records、mask_source 都改变了 history 输出。" + "没有日志级别和文本文件",
    }


@case("stats", "stats/policy/stats-user-online", "api/stats-service/get-all-online-users", "api/stats-service/get-stats-online", "api/stats-service/get-stats-online-ip-list")
def stats_online(bench):
    sb = StatsBench(bench)
    with bench.kerlico(sb.config) as kerlico:
        ensure(kerlico.get("/v1/online") == [], "没有连接时 online 应为空")
        first = socks5(kerlico.listeners["edge"], "127.0.0.1", sb.whoami.port, ("e2", "pw-e2"))
        second = socks5(kerlico.listeners["edge"], "127.0.0.1", sb.whoami.port, ("e2", "pw-e2"))
        third = socks5(kerlico.listeners["edge6"], "127.0.0.1", sb.whoami.port, ("e6", "pw-e6"))
        fourth = socks5(kerlico.listeners["open"], "127.0.0.1", sb.whoami.port)
        for sock in (first, second, third, fourth):
            recv_line(sock)
        online = kerlico.get("/v1/online")
        table = {(item["user"], item["node"], item["address"]): item["active_flows"] for item in online}
        ensure(table.get((U2, "edge", "127.0.0.0/24")) == 2, f"online {online}")
        ensure(table.get((U2, "edge6", "::/48")) == 1, f"online {online}")
        ensure(table.get((None, "open", "127.0.0.0/24")) == 1, f"online {online}")
        for sock in (first, second, third, fourth):
            sock.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and kerlico.get("/v1/online"):
            time.sleep(0.05)
        ensure(kerlico.get("/v1/online") == [], "连接关闭后 online 应清空")
        ensure(kerlico.get("/v1/usage")["active_flows"] == 0, "active_flows 应归零")
    sb.close()
    summary = "4 条活动连接时 /v1/online 为 U2@edge 127.0.0.0/24 计 2，U2@edge6 ::/48 计 1，无认证入口 127.0.0.0/24 计 1；关闭后清空"
    return {
        "stats/policy/stats-user-online": summary + "。按活动连接算在线，不是 20 秒窗口",
        "api/stats-service/get-all-online-users": summary + "。HTTP JSON 不是 gRPC",
        "api/stats-service/get-stats-online": summary + "。没有按用户取单项",
        "api/stats-service/get-stats-online-ip-list": summary + "。地址遮罩为 /24、/48",
    }


@case("stats", "stats/traffic/realtime-rate", "stats/clash-api/traffic", "api/traffic/get-traffic")
def stats_rate(bench):
    sb = StatsBench(bench, telemetry={"sample_interval_ms": 200})
    with bench.kerlico(sb.config) as kerlico:
        sock = socks5(kerlico.listeners["open"], "127.0.0.1", sb.exact.port)
        sock.sendall(struct.pack("!QQ", 1 << 60, 0))
        started = time.monotonic()
        rate = 1 << 20
        sent = 0
        while time.monotonic() - started < 3:
            sock.sendall(b"z" * (rate // 20))
            sent += rate // 20
            time.sleep(0.05)
        live = kerlico.get("/v1/usage")["engine"]["upload_bytes"]
        sock.close()
        elapsed = time.monotonic() - started
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(sb.state), "--kind", "bandwidth", "--node", "open", "--limit", "4096")
    samples = [item[1] for item in json.loads(out)]
    ensure(len(samples) >= 10, f"样本 {len(samples)}")
    peak = max(item["peak_upload_bytes_per_second"] for item in samples)
    average = samples[-1]["average_upload_bytes_per_second"]
    current = sorted(item["upload_bytes_per_second"] for item in samples)[len(samples) // 2]
    actual = sent / elapsed
    ensure(actual * 0.5 <= current <= actual * 1.6, f"中位瞬时 {current}，实际 {actual}")
    ensure(peak >= current, f"峰值 {peak} 小于中位 {current}")
    sb.close()
    summary = f"发送端约 {actual / 1e6:.2f} MB/s，采样间隔 200 毫秒，history --kind bandwidth 给出 {len(samples)} 个 open 节点样本：瞬时中位 {current / 1e6:.2f} MB/s，峰值 {peak / 1e6:.2f} MB/s，平均 {average / 1e6:.2f} MB/s；发送期间 /v1/usage 累计量实时增长到 {live} 字节"
    return {
        "stats/traffic/realtime-rate": summary + "。没有每秒推送",
        "stats/clash-api/traffic": summary + "。路径不兼容 Clash，没有流式推送",
        "api/traffic/get-traffic": summary + "。没有每秒 WebSocket 推送",
    }


def control_endpoints(kerlico, secret=None):
    """每个端点返回的结构。"""
    health = kerlico.get("/v1/health", secret)
    usage = kerlico.get("/v1/usage", secret)
    online = kerlico.get("/v1/online", secret)
    flows = kerlico.get("/v1/flows", secret)
    stats = kerlico.get("/v1/stats", secret)
    ensure(set(health) == {"status", "run", "failed_nodes"} and health["status"] == "ok" and health["failed_nodes"] == [], f"health {health}")
    uuid.UUID(health["run"])
    ensure(set(usage) >= {"engine", "users", "nodes", "outbounds", "active_flows", "retained_records", "evicted_records"}, f"usage {set(usage)}")
    ensure(isinstance(online, list) and isinstance(flows, list), "online、flows 应为数组")
    ensure(set(stats) == {"engine", "nodes"} and set(stats["engine"]) == {"accepted", "completed", "failed", "dropped", "forced_cleanup", "history_failures"}, f"stats {stats}")
    return health, usage, online, flows, stats


@case("api", "api/api/combo", "api/api/listen", "api/clash/external-controller", "api/controller/external-controller", "api/metrics/listen", "api/clash/protocol", "api/controller/combo", "api/clash/combo")
def api_listen(bench):
    sb = StatsBench(bench)
    public = {**sb.config, "control": {"listen": f"0.0.0.0:{free_port()}", "secret": "s3cret-value"}}
    local_ip = subprocess.run("ip -o -4 addr show scope global | head -1 | awk '{print $4}' | cut -d/ -f1", shell=True, capture_output=True, text=True).stdout.strip()
    with bench.kerlico(public) as kerlico:
        status, body, _ = http_call((local_ip, kerlico.control[1]), "/v1/health", "s3cret-value")
        ensure(status == 200 and body["status"] == "ok", f"非回环地址 {status}")
        status, _, _ = http_call((local_ip, kerlico.control[1]), "/v1/health")
        ensure(status == 401, f"非回环无密钥 {status}")
    v6 = {**sb.config, "control": {"listen": f"[::1]:{free_port()}"}}
    with bench.kerlico(v6) as kerlico:
        control_endpoints(kerlico)
    default_control = {**sb.config, "control": {"listen": "127.0.0.1:0"}}
    with bench.kerlico(default_control) as kerlico:
        ensure(kerlico.control[1] != 0, "端口 0 应打印实际端口")
        control_endpoints(kerlico)
    no_secret = bench.rejected({**sb.config, "control": {"listen": f"0.0.0.0:{free_port()}"}})
    empty = bench.rejected({**sb.config, "control": {"listen": "127.0.0.1:0", "secret": ""}})
    node_listen = sb.config["nodes"][0]["listen"]
    clash = bench.check({**sb.config, "control": {"listen": node_listen}})
    without = {key: value for key, value in sb.config.items() if key != "control"}
    with bench.kerlico(without) as kerlico:
        ensure(kerlico.control is None, "未配置 control 不应监听")
    unknown = bench.rejected({**sb.config, "control": {"listen": "127.0.0.1:0", "tls": {}}})
    unix = bench.rejected({**sb.config, "control": {"listen": "unix:/tmp/x"}})
    origin_header = http_headers_case(bench, sb)
    sb.close()
    ensure(clash[0] != 0, f"控制接口与入站同地址 check 应拒绝，实际 rc={clash[0]}")
    base = f"control.listen 取回环 IPv4、回环 IPv6、0.0.0.0、端口 0 都真实监听并答复，启动日志打印实际地址；非回环无密钥 check 拒绝（{no_secret}），空密钥拒绝，与入站同地址拒绝；未配置时不监听"
    return {
        "api/api/combo": base + "。只读 HTTP JSON，不是 gRPC；没有写操作和 inbound 路由接入",
        "api/api/listen": base,
        "api/clash/external-controller": base,
        "api/controller/external-controller": base,
        "api/metrics/listen": base + "。和控制接口同一端口",
        "api/clash/protocol": base + f"。路径和字段不兼容 Clash：GET / 返回 404，响应无 CORS 头（{origin_header}）",
        "api/controller/combo": f"listener 只有 external-controller（HTTP）；auth none（回环）与 secret 两种都实测，见 api/auth/bearer。tls 字段和 unix 地址 check 拒绝（{unix}）；" + base,
        "api/clash/combo": f"auth none（回环）与 secret 都实测；ui=none；cors 不支持（响应无 Access-Control-Allow-Origin：{origin_header}）。监听 0.0.0.0 时必须设 secret 已验证。" + base,
    }


def http_headers_case(bench, sb):
    with bench.kerlico(sb.config) as kerlico:
        status, _, headers = http_call(kerlico.control, "/v1/health", headers={"Origin": "https://example.test"})
        ensure(status == 200, f"health {status}")
        root, _, _ = http_call(kerlico.control, "/")
        ensure(root == 404, f"GET / 返回 {root}")
        ensure("Access-Control-Allow-Origin" not in headers, f"不应有 CORS 头 {headers}")
    return "无 Access-Control-Allow-Origin"


@case("api", "api/auth/bearer", "api/clash/secret", "api/controller/secret", "api/singbox/secret")
def api_auth(bench):
    secret = "s3cret-value"
    sb = StatsBench(bench, secret=secret)
    rows = []
    with bench.kerlico(sb.config) as kerlico:
        address = kerlico.control
        for label, headers, want in (
            ("无头", {}, 401),
            ("错密钥", {"Authorization": "Bearer wrong-value!"}, 401),
            ("前缀相同更长", {"Authorization": f"Bearer {secret}x"}, 401),
            ("小写 bearer", {"Authorization": f"bearer {secret}"}, 401),
            ("Basic", {"Authorization": "Basic " + base64.b64encode(f"a:{secret}".encode()).decode()}, 401),
            ("裸密钥", {"Authorization": secret}, 401),
            ("正确", {"Authorization": f"Bearer {secret}"}, 200),
        ):
            for path in ("/v1/health", "/v1/usage", "/v1/online", "/v1/flows", "/v1/stats"):
                status, body, _ = http_call(address, path, headers=headers)
                ensure(status == want, f"{label} {path} 返回 {status}")
                if want == 401:
                    ensure(body == {"error": "unauthorized"}, f"401 响应体 {body}")
            rows.append(f"{label}→{want}")
        status, _, _ = http_call(address, "/nope", headers={})
        ensure(status == 401, f"未认证访问未知路径应 401：{status}")
    local = StatsBench(bench)
    with bench.kerlico(local.config) as kerlico:
        control_endpoints(kerlico)
    sb.close()
    local.close()
    summary = "配 secret 时五个端点都按请求头判定：" + "，".join(rows) + "；未认证的未知路径也 401；回环不配 secret 时无头 200"
    return {key: summary for key in ("api/auth/bearer", "api/clash/secret", "api/controller/secret", "api/singbox/secret")}


@case("api", "api/api/services", "api/clash/get", "api/root/get", "api/metrics/debug-vars", "api/stats-service/overview", "api/stats-service/get-stats", "api/stats-service/get-users-stats", "api/stats-service/query-stats", "api/stats-service/get-sys-stats", "api/v2ray/get-stats", "api/v2ray/get-sys-stats", "api/v2ray/query-stats", "experimental/config/clash-api", "config/top/api", "config/top/metrics")
def api_endpoints(bench):
    sb = StatsBench(bench)
    with bench.kerlico(sb.config) as kerlico:
        got = sb.traffic(kerlico)
        try:
            socks5(kerlico.listeners["open"], "blocked.example", 9).close()
        except (SocksReply, ConnectionError):
            pass
        health, usage, online, flows, stats = control_endpoints(kerlico)
        ensure(kerlico.get("/v1/usage")["engine"] == usage["engine"], "连读 /v1/usage 累计量变化")
        ensure(pair_of(usage["users"][U1]) == got["u1"], "users 视图不符")
        ensure(stats["nodes"]["edge"]["accepted"] >= 2 and stats["nodes"]["open"]["accepted"] >= 2, f"stats {stats}")
        ensure(stats["engine"]["accepted"] == sum(item["accepted"] for item in stats["nodes"].values()), f"引擎 accepted 不等于节点之和 {stats}")
        ensure(stats["nodes"]["open"]["failed"] >= 1, f"reject 应计入失败 {stats['nodes']['open']}")
        ensure(stats["nodes"]["edge"]["completed"] >= 2, f"完成数 {stats['nodes']['edge']}")
        checks = {}
        for path, want in (("/", 404), ("/v1", 404), ("/v1/health/", 404), ("/v1/nope", 404), ("/configs", 404), ("/connections", 404), ("/traffic", 404), ("/stats", 404)):
            status, body, _ = http_call(kerlico.control, path)
            ensure(status == want and body == {"error": "not found"}, f"{path} 返回 {status} {body}")
            checks[path] = status
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
            status, body, _ = http_call(kerlico.control, "/v1/usage", method=method)
            ensure(status == 405, f"{method} 返回 {status}")
        status, body, headers = http_call(kerlico.control, "/v1/health")
        ensure(headers.get("content-type") == "application/json", f"Content-Type {headers}")
    sb.close()
    endpoints = f"/v1/health status=ok；/v1/usage 四个视图字节与实收相等（U1 {got['u1']}）；/v1/online 为数组；/v1/flows {len(flows)} 条；/v1/stats 节点 accepted、completed、failed 随真实连接变化（open failed={stats['nodes']['open']['failed']}），引擎 accepted 等于节点之和；未知路径 404、非 GET 405、Content-Type application/json"
    sys_stats = f"/v1/stats：{stats['engine']}。缺内存和运行时指标"
    return {
        "api/api/services": endpoints + "。相当只读统计服务，缺其余服务；入口失败的 degraded 见 api/clash/get",
        "api/clash/get": health_degraded(bench),
        "api/root/get": "GET / 返回 404，存活检查用 /v1/health；" + endpoints,
        "api/metrics/debug-vars": endpoints + "。缺 observatory",
        "api/stats-service/overview": endpoints + "。HTTP JSON 不是 gRPC",
        "api/stats-service/get-stats": f"/v1/usage 整体返回：{pair_of(usage['engine'])}（engine）。不能按名称取单项，没有 reset；连读两次累计量不变",
        "api/stats-service/get-users-stats": f"/v1/usage 的 users 视图 U1 {pair_of(usage['users'][U1])}、U2 {pair_of(usage['users'][U2])}，与实收相等。没有 reset",
        "api/stats-service/query-stats": "/v1/usage 整体返回四个视图，字节与实收相等；没有 pattern 和 reset",
        "api/stats-service/get-sys-stats": sys_stats,
        "api/v2ray/get-stats": f"/v1/usage 整体返回，字节与实收相等（engine {pair_of(usage['engine'])}），HTTP JSON 不是 gRPC",
        "api/v2ray/get-sys-stats": sys_stats + "，HTTP JSON 不是 gRPC",
        "api/v2ray/query-stats": "/v1/usage 整体返回，没有 pattern；字节与实收相等",
        "experimental/config/clash-api": "control 段启用只读接口，五个端点真实返回；不兼容 Clash（/configs、/connections、/traffic 都 404）",
        "config/top/api": "顶层 control 启用只读 HTTP，不配时不监听；五个端点真实返回。不是 gRPC",
        "config/top/metrics": "顶层 control 提供统计 JSON（/v1/usage、/v1/stats）；没有独立 metrics 监听",
    }


def health_degraded(bench):
    """TUN 入口运行中删接口让入口真实失败，观察 degraded。"""
    directory = bench.fresh("ns")
    port = free_port()
    config = {
        "version": 2,
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "local_inbounds": [
            {"tag": "tun", "type": "tun", "listen": "127.0.0.1:0", "outbound": "direct", "options": {"name": "mx5tun0", "addresses": ["198.18.77.1/24"], "mtu": 1500}},
            local_socks("keep", "direct"),
        ],
        "control": {"listen": f"127.0.0.1:{port}"},
    }
    script = directory / "enter.sh"
    script.write_text('#!/bin/sh\nip link set lo up\nexec "$@"\n', encoding="ascii")
    with bench.kerlico(config, prefix=["unshare", "-n", "sh", str(script)]) as kerlico:
        pid = str(kerlico.process.pid)

        def curl(path):
            done = subprocess.run(["nsenter", "-t", pid, "-n", "curl", "-s", "-m", "5", f"http://127.0.0.1:{port}{path}"], capture_output=True, text=True)
            return json.loads(done.stdout)

        before = curl("/v1/health")
        ensure(before["status"] == "ok", f"初始 {before}")
        subprocess.run(["nsenter", "-t", pid, "-n", "ip", "link", "del", "mx5tun0"], check=True)
        deadline = time.monotonic() + 8
        after = before
        while time.monotonic() < deadline:
            after = curl("/v1/health")
            if after["status"] != "ok":
                break
            time.sleep(0.1)
        ensure(after["status"] == "degraded" and after["failed_nodes"] == ["tun"], f"删接口后 {after}")
        log = kerlico.log()
        ensure(re.search(r"\[[a-z_.]+\].*\btun\b", log), f"标准错误未记录入口停止：{log[-200:]}")
        status, other = 0, curl("/v1/usage")
        ensure("nodes" in other, "其余入口和控制接口应继续运行")
        kerlico.stop()
    return f"GET / 不存在，存活检查用 /v1/health：独立 netns 里运行 TUN 入口，正常时 status=ok；删除接口后 status=degraded，failed_nodes=[tun]，HTTP 200，stderr 打印入口停止"


def control_edges(bench):
    """/v1/flows 分页、limit 边界、连接上限和 keep-alive，不对应单独的矩阵键，失败时写进 api/stats-service/overview 的修复。"""
    sb = StatsBench(bench)
    edges = {}
    with bench.kerlico(sb.config) as kerlico:
        for _ in range(5):
            tcp_echo(socks5(kerlico.listeners["open"], "127.0.0.1", sb.whoami.port))
        time.sleep(0.2)
        all_flows = kerlico.get("/v1/flows")
        sequences = [item["sequence"] for item in all_flows]
        first = kerlico.get("/v1/flows?limit=2")
        ensure([item["sequence"] for item in first] == sequences[:2], f"limit=2 {first}")
        after = kerlico.get(f"/v1/flows?after={sequences[1]}&limit=2")
        ensure([item["sequence"] for item in after] == sequences[2:4], f"after 分页 {after}")
        for query, want in (("limit=0", 400), ("limit=4096", 200), ("limit=4097", 400), ("limit=abc", 400), ("limit=-1", 400), ("after=abc", 400), ("limit=99999999999999999999", 400)):
            status, body, _ = http_call(kerlico.control, f"/v1/flows?{query}")
            edges[query] = status
        conns = []
        for _ in range(64):
            conn = socket.create_connection(kerlico.control)
            conns.append(conn)
        time.sleep(0.2)
        extra = socket.create_connection(kerlico.control)
        extra.settimeout(3)
        extra.sendall(b"GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")
        try:
            data = extra.recv(100)
        except OSError:
            data = b""
        edges["65th"] = data
        extra.close()
        for conn in conns:
            conn.close()
        time.sleep(0.3)
        status, _, _ = http_call(kerlico.control, "/v1/health")
        ensure(status == 200, "释放后应恢复")
        keep = http.client.HTTPConnection(*kerlico.control, timeout=40)
        keep.request("GET", "/v1/health")
        keep.getresponse().read()
        keep.request("GET", "/v1/usage")
        ensure(keep.getresponse().status == 200, "keep-alive 第二个请求失败")
        edges["keepalive"] = True
        sock = keep.sock
        sock.settimeout(40)
        started = time.monotonic()
        try:
            while sock.recv(4096):
                pass
        except OSError:
            pass
        edges["lifetime"] = round(time.monotonic() - started, 1)
    sb.close()
    return edges


@case("api", "api/connections/get-connections")
def api_edges(bench):
    edges = control_edges(bench)
    wanted = {"limit=0": 400, "limit=4096": 200, "limit=4097": 400, "limit=abc": 400, "limit=-1": 400, "after=abc": 400, "limit=99999999999999999999": 400}
    bad = {query: edges[query] for query, want in wanted.items() if edges[query] != want}
    print("control edges", edges, file=sys.stderr)
    ensure(not bad, f"/v1/flows 查询参数：{bad}")
    ensure(edges["65th"] == b"", "第 65 条连接应被关闭")
    ensure(27 <= edges["lifetime"] <= 32, f"连接寿命 {edges['lifetime']}")
    return {"api/connections/get-connections": f"+limit、after 按序号分页不重不漏；limit=0、4097、非数字、负数、溢出和 after 非数字都返回 400；第 65 条并发连接被立即关闭，释放后恢复；同一连接 keep-alive 复用，连接在 {edges['lifetime']} 秒时被关闭"}


# ------------------------------------------------------------------ 证书


def tls_serial(port, host="127.0.0.1"):
    """用独立 TLS 客户端读节点证书的 PEM，并取主题 CN。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as raw, context.wrap_socket(raw, server_hostname=ich.SNI) as tls:
        return ssl.DER_cert_to_PEM_cert(tls.getpeercert(True))


TLS_NODE_PROTOCOLS = {
    "trojan": ("trojan", lambda tls, m: ({"security": {"type": "tls", **tls}, "transport": {"type": "tcp"}}, {"password": "pw-trojan-file"}, {"password": "pw-trojan-file", "security": {"type": "tls", "server_name": ich.SNI, "ca_pem": m.ca}, "transport": {"type": "tcp"}})),
    "vless": ("vless", lambda tls, m: ({"security": {"type": "tls", **tls}, "transport": {"type": "tcp"}}, {"uuid": U1, "flow": ""}, {"uuid": U1, "flow": "", "security": {"type": "tls", "server_name": ich.SNI, "ca_pem": m.ca}, "transport": {"type": "tcp"}})),
    "anytls": ("anytls", lambda tls, m: ({"tls": tls}, {"password": "pw-anytls-file"}, {"password": "pw-anytls-file", "tls": {"server_name": ich.SNI, "ca_pem": m.ca}})),
    "hysteria": ("hysteria1", lambda tls, m: ({"tls": tls, "transport": "udp"}, {"auth_str": "pw-hy-file"}, {"auth_str": "pw-hy-file", "up_bps": 125000000, "down_bps": 125000000, "transport": "udp", "tls": {"server_name": ich.SNI, "ca_pem": m.ca}})),
    "hysteria2": ("hysteria2", lambda tls, m: ({"tls": tls, "udp": True}, {"auth": "pw-hy2-file"}, {"auth": "pw-hy2-file", "tls": {"server_name": ich.SNI, "ca_pem": m.ca}})),
    "tuic": ("tuic", lambda tls, m: ({"version": 5, "tls": {**tls, "alpn": ["h3"]}, "congestion_control": "cubic"}, {"uuid": U2, "password": "pw-tuic-file"}, {"version": 5, "uuid": U2, "password": "pw-tuic-file", "udp_relay_mode": "native", "congestion_control": "cubic", "tls": {"server_name": ich.SNI, "ca_pem": m.ca, "alpn": ["h3"]}})),
    "naive": ("naive", lambda tls, m: ({"tls": tls, "transports": ["h2"], "udp_over_tcp": True}, {"username": "file-user", "password": "pw-naive-file"}, {"username": "file-user", "password": "pw-naive-file", "transport": "h2", "tls": {"server_name": ich.SNI, "ca_pem": m.ca}, "udp_over_tcp": {"enabled": True, "version": 2}, "max_sessions": 1})),
    "trusttunnel": ("trusttunnel", lambda tls, m: ({"transport": "h2", "tls": tls}, {"username": "file-user", "password": "pw-tt-file"}, {"transport": "h2", "auth": {"username": "file-user", "password": "pw-tt-file"}, "tls": {"server_name": ich.SNI, "ca_pem": m.ca}, "app_name": "mx"})),
}


@case("cert", "cert/tls/certificate-file", "cert/tls/key-file", "cert/tls/certificate", "cert/tls/key", "cert/tls/private-key", "cert/store/certificate", "cert/tls/custom-certifactes", "cert/store/store", "cert/system/disable-system-ca")
def cert_files(bench):
    directory = bench.fresh("certfiles")
    material = make_material(directory, ich.SNI)
    other_dir = bench.fresh("certother")
    other = make_material(other_dir, ich.SNI, "other")
    exact = Exact()
    files = {"certificate_file": str(directory / "leaf.pem"), "private_key_file": str(directory / "leaf.key")}
    inline = {"certificate_pem": material.cert, "private_key_pem": material.key}
    file_ok = []
    inline_ok = []
    failures = {}
    for name, (protocol, build) in TLS_NODE_PROTOCOLS.items():
        for label, tls, sink in (("file", files, file_ok), ("pem", inline, inline_ok)):
            node_options, credential, client = build(tls, material)
            port = free_port()
            config = {"version": 2, "accounts": [account(U1)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [{"tag": "n", "type": protocol, "listen": f"127.0.0.1:{port}", "outbound": "direct", "options": node_options, "members": [{"user_id": U1, "native_credential": credential}]}], "limits": {"connect_timeout_ms": 6000, "idle_timeout_ms": 15000, "drain_timeout_ms": 300}}
            try:
                with bench.kerlico(config):
                    client_config = proxy_client_config(protocol, {**client, "server": {"host": "127.0.0.1", "port": port}})
                    client_transfer(bench, client_config, exact, 100, 100)
                    sink.append(name)
            except (Fail, SocksReply, OSError, ConnectionError) as error:
                failures[f"{name}/{label}"] = str(error)[:200]
    both = {"certificate_file": files["certificate_file"], "certificate_pem": material.cert, "private_key_file": files["private_key_file"]}
    node_options, credential, _ = TLS_NODE_PROTOCOLS["trojan"][1](both, material)
    config_both = {"version": 2, "accounts": [account(U1)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [{"tag": "n", "type": "trojan", "listen": "127.0.0.1:0", "outbound": "direct", "options": node_options, "members": [{"user_id": U1, "native_credential": credential}]}]}
    exclusive = bench.rejected(config_both)
    openssl(directory, "pkcs8", "-topk8", "-in", "leaf.key", "-out", "enc.key", "-passout", "pass:secretpass")
    enc_tls = {"certificate_file": files["certificate_file"], "private_key_file": str(directory / "enc.key")}
    node_options, credential, _ = TLS_NODE_PROTOCOLS["trojan"][1](enc_tls, material)
    enc = {**config_both, "nodes": [{**config_both["nodes"][0], "options": node_options, "listen": f"127.0.0.1:{free_port()}"}]}
    rc, _, err = bench.check(enc)
    encrypted = "check 拒绝" if rc else None
    if rc == 0:
        with Kerlico(bench, enc, wait=False) as kerlico:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and kerlico.process.poll() is None:
                time.sleep(0.05)
            ensure(kerlico.process.poll() not in (None, 0), "带密码的私钥应启动失败")
            encrypted = "启动失败"
    wrong_key = {"certificate_file": files["certificate_file"], "private_key_file": str(other_dir / "leaf.key")}
    node_options, credential, _ = TLS_NODE_PROTOCOLS["trojan"][1](wrong_key, material)
    mismatch = {**config_both, "nodes": [{**config_both["nodes"][0], "options": node_options, "listen": f"127.0.0.1:{free_port()}"}]}
    ensure(bench.check(mismatch)[0] != 0, "私钥和证书不匹配应拒绝")
    big = directory / "big.pem"
    big.write_bytes(b"x" * (1024 * 1024 + 1))
    node_options, credential, _ = TLS_NODE_PROTOCOLS["trojan"][1]({"certificate_file": str(big), "private_key_file": files["private_key_file"]}, material)
    oversized = {**config_both, "nodes": [{**config_both["nodes"][0], "options": node_options, "listen": f"127.0.0.1:{free_port()}"}]}
    rc_big, _, _ = bench.check(oversized)
    # 服务端证书信任：ca_pem 决定是否接受；系统 CA 和 SSL_CERT_FILE 不生效。
    port = free_port()
    node_options, credential, client = TLS_NODE_PROTOCOLS["trojan"][1](inline, material)
    server = {**config_both, "nodes": [{**config_both["nodes"][0], "options": node_options, "listen": f"127.0.0.1:{port}"}]}
    trust = {}
    with bench.kerlico(server):
        with_ca = proxy_client_config("trojan", {**client, "server": {"host": "127.0.0.1", "port": port}})
        client_transfer(bench, with_ca, exact, 10, 10)
        trust["ca_pem"] = True
        without_client = {key: value for key, value in client.items()}
        without_client["security"] = {"type": "tls", "server_name": ich.SNI}
        attempts = {}
        hosts = bench.fresh("catrust")
        (hosts / "ca-certificates.crt").write_text(material.ca, encoding="ascii")
        script = hosts / "enter.sh"
        script.write_text(f"#!/bin/sh\nset -e\nmount --bind {hosts}/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\nexec \"$@\"\n", encoding="ascii")
        for label, kwargs in (
            ("无 ca_pem", {}),
            ("SSL_CERT_FILE 指向测试 CA", {"env": {"SSL_CERT_FILE": str(hosts / "ca-certificates.crt"), "SSL_CERT_DIR": str(hosts)}}),
            ("系统 CA 文件替换为测试 CA", {"prefix": ["unshare", "-m", "sh", str(script)]}),
        ):
            config = proxy_client_config("trojan", {**without_client, "server": {"host": "127.0.0.1", "port": port}})
            with bench.kerlico(config, **kwargs) as client_process:
                try:
                    exact_transfer(socks5(client_process.listeners["socks"], "127.0.0.1", exact.port, timeout=8), 10, 10)
                    attempts[label] = "通过"
                except (SocksReply, OSError, ConnectionError, Fail):
                    attempts[label] = "拒绝"
        wrong_ca = {**client, "security": {"type": "tls", "server_name": ich.SNI, "ca_pem": other.ca}, "server": {"host": "127.0.0.1", "port": port}}
        try:
            client_transfer(bench, proxy_client_config("trojan", wrong_ca), exact, 10, 10)
            attempts["错误 CA"] = "通过"
        except (SocksReply, OSError, ConnectionError, Fail):
            attempts["错误 CA"] = "拒绝"
        wrong_name = {**client, "security": {"type": "tls", "server_name": "wrong.test", "ca_pem": material.ca}, "server": {"host": "127.0.0.1", "port": port}}
        try:
            client_transfer(bench, proxy_client_config("trojan", wrong_name), exact, 10, 10)
            attempts["错误名称"] = "通过"
        except (SocksReply, OSError, ConnectionError, Fail):
            attempts["错误名称"] = "拒绝"
    exact.close()
    ensure(all(value == "拒绝" for value in attempts.values()), f"信任决策 {attempts}")
    ensure(rc_big != 0, "超过 1 MiB 的证书文件应拒绝")
    file_text = f"{'、'.join(file_ok)} 入站都用 certificate_file、private_key_file 启动，kerlico 客户端带 ca_pem 真实传输通过"
    inline_text = f"{'、'.join(inline_ok)} 入站用内联 PEM 启动并真实传输通过"
    negative = f"文件和内联同时给 check 拒绝（{exclusive}，与 Xray 的文件优先不同）；带密码私钥 {encrypted}；超过 1 MiB 拒绝"
    trust_text = "；".join(f"{key}：{value}" for key, value in attempts.items())
    out = {
        "cert/tls/certificate-file": file_text + "。" + negative,
        "cert/tls/key-file": file_text + "。" + negative,
        "cert/tls/certificate": inline_text + "；路径形式见 certificate_file。控制接口没有 HTTPS（响应为明文 HTTP）",
        "cert/tls/key": inline_text + "。内容是单个字符串，不是字符串数组",
        "cert/tls/private-key": inline_text + "。控制接口没有 HTTPS",
        "cert/store/certificate": f"出站 ca_pem 追加信任：带 ca_pem 通过；{trust_text}。没有全局信任配置",
        "cert/tls/custom-certifactes": f"各协议 ca_pem：带 ca_pem 通过；{trust_text}。没有全局列表",
        "cert/store/store": f"固定内置 webpki_roots：公共 DoT 校验通过见 dns/upstream/dot；{trust_text}。缺 system、chrome、none 选项",
        "cert/system/disable-system-ca": f"不读系统 CA：{trust_text}",
    }
    for key in list(out):
        if failures:
            relevant = {name: value for name, value in failures.items() if ("file" in name) == ("file" in key) or "file" not in key}
            if relevant and key in ("cert/tls/certificate-file", "cert/tls/key-file", "cert/tls/certificate", "cert/tls/key", "cert/tls/private-key"):
                out[key] = ("fail", f"{relevant}")
    return out


@case("cert", "cert/tls/acme-external", "cert/tls/one-time-loading")
def cert_reload(bench):
    directory = bench.fresh("certreload")
    material = make_material(directory, ich.SNI, "first")
    second_dir = bench.fresh("certreload2")
    make_material(second_dir, ich.SNI, "second")
    live_cert, live_key = directory / "live.pem", directory / "live.key"
    shutil.copy(directory / "leaf.pem", live_cert)
    shutil.copy(directory / "leaf.key", live_key)
    port = free_port()
    options, credential, _ = TLS_NODE_PROTOCOLS["trojan"][1]({"certificate_file": str(live_cert), "private_key_file": str(live_key)}, material)
    config = {"version": 2, "accounts": [account(U1)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [{"tag": "n", "type": "trojan", "listen": f"127.0.0.1:{port}", "outbound": "direct", "options": options, "members": [{"user_id": U1, "native_credential": credential}]}]}
    with bench.kerlico(config) as kerlico:
        before = tls_serial(port)
        shutil.copy(second_dir / "leaf.pem", live_cert)
        shutil.copy(second_dir / "leaf.key", live_key)
        os.utime(live_cert)
        time.sleep(1.5)
        during = tls_serial(port)
        ensure(before == during, "运行中不应重新加载证书")
        kerlico.stop()
    with bench.kerlico(config):
        after = tls_serial(port)
    ensure(after != before, "重启后应加载新证书")
    ensure(after.strip() == (second_dir / "leaf.pem").read_text().strip(), "重启后证书不是新文件")
    summary = "替换证书和私钥文件后，独立 TLS 客户端读到的证书在运行中不变（等 1.5 秒，新连接），重启后才变成新文件的证书"
    return {
        "cert/tls/acme-external": summary + "。外部工具签发的文件可用，更新后要重启，没有热重载和内置 ACME",
        "cert/tls/one-time-loading": summary + "。只加载一次，没有热重载和 OCSP",
    }


@case("cert", "cert/tls/client-auth-cert", "cert/tls/client-auth-type")
def cert_client_auth(bench):
    directory = bench.fresh("mtls")
    material = make_material(directory, ich.SNI)
    other_dir = bench.fresh("mtls2")
    other = make_material(other_dir, ich.SNI, "other")
    port = free_port()
    exact = Exact()
    user = {"username": "mtls-user", "password": "pw-mtls"}
    node = {"tag": "n", "type": "trusttunnel", "listen": f"127.0.0.1:{port}", "outbound": "direct", "options": {"transport": "h2", "tls": {"certificate_pem": material.cert, "private_key_pem": material.key, "client_ca_pem": material.ca}}, "members": [{"user_id": U1, "native_credential": user}]}
    config = {"version": 2, "accounts": [account(U1)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [node], "limits": {"connect_timeout_ms": 5000, "drain_timeout_ms": 300}}
    base = {"transport": "h2", "auth": user, "app_name": "mx", "server": {"host": "127.0.0.1", "port": port}}
    results = {}
    with bench.kerlico(config):
        for label, tls in (
            ("可信客户端证书", {"server_name": ich.SNI, "ca_pem": material.ca, "certificate_pem": material.cert, "private_key_pem": material.key}),
            ("其他 CA 签发的客户端证书", {"server_name": ich.SNI, "ca_pem": material.ca, "certificate_pem": other.cert, "private_key_pem": other.key}),
            ("无客户端证书", {"server_name": ich.SNI, "ca_pem": material.ca}),
        ):
            try:
                client_transfer(bench, proxy_client_config("trusttunnel", {**base, "tls": tls}), exact, 10, 10, timeout=8)
                results[label] = "通过"
            except (SocksReply, OSError, ConnectionError, Fail) as error:
                results[label] = "拒绝"
    exact.close()
    ensure(results == {"可信客户端证书": "通过", "其他 CA 签发的客户端证书": "拒绝", "无客户端证书": "拒绝"}, f"mTLS {results}")
    other_protocol = bench.rejected({**config, "nodes": [{"tag": "n", "type": "trojan", "listen": "127.0.0.1:0", "outbound": "direct", "options": {"security": {"type": "tls", "certificate_pem": material.cert, "private_key_pem": material.key, "client_ca_pem": material.ca}, "transport": {"type": "tcp"}}, "members": [{"user_id": U1, "native_credential": {"password": "pw"}}]}]})
    summary = "TrustTunnel 入站 client_ca_pem：" + "，".join(f"{key}{value}" for key, value in results.items()) + f"。Trojan 的同名字段 check 拒绝（{other_protocol}），其他协议和控制接口没有"
    return {
        "cert/tls/client-auth-cert": summary,
        "cert/tls/client-auth-type": summary + "。配了 client_ca_pem 即 require-and-verify，缺 request、require-any、verify-if-given",
    }


# ------------------------------------------------------------------ 配置


MODULE_KINDS_OUT = {"anytls", "direct", "easytier", "gost-relay", "http", "hysteria1", "hysteria2", "masque", "mieru", "naive", "openconnect", "openvpn", "reject", "shadowquic", "shadowsocks", "shadowsocksr", "shadowtls", "snell", "socks", "ss2022", "ssh", "sudoku", "tailscale", "tor", "trojan", "trusttunnel", "tuic", "vless", "vmess", "wireguard", "zerotier"}
MODULE_KINDS_IN = {"anytls", "http", "hysteria1", "hysteria2", "mieru", "naive", "shadowquic", "shadowsocks", "shadowsocksr", "shadowtls", "snell", "socks", "ss2022", "sudoku", "trojan", "trusttunnel", "tuic", "tun", "vless", "vmess", "wireguard"}


def minimal(**extra):
    return {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "local_inbounds": [local_socks("in", "direct")], **extra}


@case("config", "config/format/json", "config/env/xray-json-strict")
def config_format(bench):
    good = minimal()
    bench.accepted(good)
    bad = {
        "YAML": b"version: 2\noutbounds:\n  - tag: direct\n    type: direct\n",
        "行注释": b'// c\n{"version":2,"outbounds":[{"tag":"direct","type":"direct"}]}',
        "块注释": b'{"version":2,/*c*/"outbounds":[{"tag":"direct","type":"direct"}]}',
        "尾逗号": b'{"version":2,"outbounds":[{"tag":"direct","type":"direct"},]}',
        "TOML": b'version = 2\n[[outbounds]]\ntag = "direct"\n',
        "空文件": b"",
    }
    reasons = {}
    for label, raw in bad.items():
        reasons[label] = bench.rejected(None, raw)
    version = {value: bench.rejected({**good, "version": value}) for value in (1, 3)}
    missing = bench.rejected({"outbounds": []})
    unknown = bench.rejected({**good, "log": {}})
    padded = json.dumps(good).encode()
    within = padded + b" " * (1024 * 1024 - len(padded))
    rc_within, _, _ = bench.check(None, within)
    ensure(rc_within == 0, "正好 1 MiB 应通过")
    over = bench.rejected(None, within + b" ")
    summary = f"标准 JSON 通过；YAML、TOML、行注释、块注释、尾逗号、空文件都被 check 拒绝（{reasons['YAML']}）；version 1 和 3 拒绝；正好 1 MiB 通过，多一字节拒绝（{over}）；未知顶层字段拒绝"
    return {"config/format/json": summary, "config/env/xray-json-strict": "恒为严格 JSON，没有开关：" + summary}


@case("config", "config/root/dns", "config/top/dns", "config/root/inbounds", "config/top/inbounds", "config/root/outbounds", "config/top/outbounds", "config/root/route", "config/top/routing", "config/root/endpoints", "config/top/policy", "config/top/stats", "other/endpoint-common/tag", "other/endpoint-common/type", "other/global/ipv6")
def config_roots(bench):
    whoami = Whoami()
    recorder = Recorder(whoami.port)
    fake = FakeDns(zones=zone4("r.test", ip="127.0.0.95"))
    config = {
        "version": 2,
        "accounts": [account(U1)],
        "outbounds": [{"tag": "direct", "type": "direct"}, socks_out("proxy", recorder.port)],
        "nodes": [socks_node("node", "direct", [(U1, "u", "p")])],
        "local_inbounds": [local_socks("local", "direct")],
        "inbounds": [{"tag": "fwd", "type": "tcp-forward", "listen": f"127.0.0.1:{free_port()}", "target": {"host": "127.0.0.1", "port": whoami.port}, "outbound": "direct"}],
        "routes": [{"outbound": "proxy", "domain": ["routed.test"]}],
        "dns": {"servers": [f"udp://127.0.0.1:{fake.port}"]},
    }
    with bench.kerlico(config) as kerlico:
        ensure(tcp_echo(socks5(kerlico.listeners["local"], "r.test", whoami.port)) == "127.0.0.95", "顶层 dns 未生效")
        ensure(tcp_echo(socks5(kerlico.listeners["node"], "127.0.0.1", whoami.port, ("u", "p"))) == "127.0.0.1", "nodes 未生效")
        sock = socket.create_connection(kerlico.listeners["fwd"], timeout=5)
        ensure(tcp_echo(sock) == "127.0.0.1", "inbounds 未生效")
        tcp_echo(socks5(kerlico.listeners["local"], "routed.test", 1))
        ensure(recorder.log and recorder.log[-1][1] == "routed.test", "routes 未生效")
    fake.close()
    wrong_routes = bench.rejected({**config, "routes": {"rules": []}})
    route_field = bench.rejected({**config, "route": {"rules": []}})
    endpoints = bench.rejected({**config, "endpoints": []})
    dup_tag = bench.rejected({**config, "outbounds": [{"tag": "direct", "type": "direct"}, {"tag": "direct", "type": "direct"}]})
    bad_tag = bench.rejected({**config, "outbounds": [{"tag": "bad tag", "type": "direct"}]})
    long_tag = bench.rejected({**config, "outbounds": [{"tag": "x" * 65, "type": "direct"}]})
    bench.accepted({**minimal(), "outbounds": [{"tag": "x" * 64, "type": "direct"}], "local_inbounds": [local_socks("in", "x" * 64)]})
    unknown_type = bench.rejected({**config, "outbounds": [{"tag": "direct", "type": "nosuch"}]})
    unknown_out = bench.rejected({**config, "routes": [{"outbound": "nosuch", "port": [1]}]})
    # limits 改变行为见 user/policy；这里核对范围。
    limit = bench.rejected({**minimal(), "limits": {"idle_timeout_ms": 0}})
    policy_level = bench.rejected({**minimal(), "limits": {"levels": {}}})
    # 端点类型逐个 check。
    types = {"wireguard", "tailscale", "openconnect", "openvpn", "masque"}
    _, modules, _ = run_cli("modules")
    registered = {line.split("/", 1)[1] for line in modules.splitlines() if line.startswith("outbound/")}
    ensure(types <= registered, f"端点类型未注册 {types - registered}")
    nodes_kind = {line.split("/", 1)[1] for line in modules.splitlines() if line.startswith("inbound/")}
    ensure("wireguard" in nodes_kind, "wireguard 节点未注册")
    v6_whoami = Whoami()
    family = {}
    dual_config = {
        "version": 2,
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "local_inbounds": [local_socks("v4", "direct"), local_socks("v6", "direct", f"[::1]:{free_port()}"), local_socks("v4only", "direct", mode="ipv4-only"), local_socks("v6only", "direct", mode="ipv6-only")],
        "dns": {"hosts": {"both.test": ["::1", "127.0.0.96"]}},
    }
    with bench.kerlico(dual_config) as kerlico:
        family["v4入口"] = tcp_echo(socks5(kerlico.listeners["v4"], "both.test", v6_whoami.port))
        family["v6入口"] = tcp_echo(socks5(kerlico.listeners["v6"], "both.test", v6_whoami.port))
        family["ipv4-only"] = tcp_echo(socks5(kerlico.listeners["v4only"], "both.test", v6_whoami.port))
        family["ipv6-only"] = tcp_echo(socks5(kerlico.listeners["v6only"], "both.test", v6_whoami.port))
        try:
            family["ipv4-only 拨 ::1"] = tcp_echo(socks5(kerlico.listeners["v4only"], "::1", v6_whoami.port, timeout=4))
        except (SocksReply, ConnectionError, OSError):
            family["ipv4-only 拨 ::1"] = "拒绝"
    ensure(family["ipv6-only"] == "::1" and family["ipv4-only"] == "127.0.0.96", f"地址族 {family}")
    v6_whoami.close()
    global_field = bench.rejected({**minimal(), "ipv6": False})
    whoami.close()
    recorder.close()
    live = "同一配置同时用 nodes、local_inbounds、inbounds 三类入口和 dns、routes，四个效果都由真实流量观察到"
    return {
        "config/root/dns": live + "：顶层 dns 让 r.test 解析到上游的地址",
        "config/top/dns": live + "：顶层 dns 让 r.test 解析到上游的地址",
        "config/root/inbounds": live + "：nodes、local_inbounds、inbounds 都转发到目标",
        "config/top/inbounds": live + "：nodes、local_inbounds、inbounds 都转发到目标",
        "config/root/outbounds": live + f"：direct 与 socks 出站都收到流量。tag 重复（{dup_tag}）、非法字符、超过 64 字符拒绝，64 字符通过，未知类型拒绝",
        "config/top/outbounds": live + f"：direct 与 socks 出站都收到流量。未知类型拒绝（{unknown_type}）",
        "config/root/route": live + f"：顶层 routes 把 routed.test 交给记录代理。没有 route 对象（{route_field}），routes 只能是数组",
        "config/top/routing": live + f"：顶层 routes 把 routed.test 交给记录代理。没有 balancers 和 domainStrategy；引用不存在的出站拒绝（{unknown_out}）",
        "config/root/endpoints": f"没有 endpoints 段（{endpoints}）；{'、'.join(sorted(types))} 在 modules 里作为 outbound 注册，wireguard 另有 inbound。隧道出站本身的实测归协议组",
        "config/top/policy": f"顶层 limits 的 idle_timeout_ms、connect_timeout_ms 改变行为，见 user/policy/*；取值超范围拒绝（{limit}），level 字段拒绝（{policy_level}）",
        "config/top/stats": "内存统计恒开，未配 telemetry 时 /v1/usage 仍有用量（见 stats/stats/enable）；配 telemetry 才写 SQLite（见 stats/access-log/connection-record）",
        "other/endpoint-common/tag": f"outbounds[].tag、nodes[].tag 决定路由引用；{live}；非法 tag 拒绝（{bad_tag}），超长拒绝（{long_tag}）",
        "other/endpoint-common/type": f"{'、'.join(sorted(types))} 都能写成 outbounds[].type（modules 列出），wireguard 还可作 nodes 类型；未知类型拒绝。缺 openvpn-server、masque-server",
        "other/global/ipv6": f"入口按 listen 地址族监听（v4、v6 入口都拨到 hosts 里同一 IPv4，IPv6 只由 mode 决定）：{family}。顶层 ipv6 字段拒绝（{global_field}）",
    }


@case("config", "config/syntax/wildcard-plus")
def config_wildcard(bench):
    rb = RouteBench()
    summary = rb.table(bench, [{"outbound": "a", "domain_suffix": ["plus.example"]}], [("a", {"host": "plus.example"}), ("a", {"host": "a.b.plus.example"}), ("dflt", {"host": "xplus.example"})])
    rc_plus, _, err_plus = bench.check(rb.config([{"outbound": "a", "domain_suffix": ["+.plus.example"]}]))
    rc_star, _, err_star = bench.check(rb.config([{"outbound": "a", "domain": ["*.star.example"]}]))
    ensure(rc_plus != 0 and rc_star != 0, f"永远不会命中的通配规则 check 通过：+. rc={rc_plus}，*. rc={rc_star}")
    return f"domain_suffix 语义等同 +.：{summary}。+. 和 *. 写法 check 拒绝"


# ------------------------------------------------------------------ CLI


@case("cli", "cli/flag/v", "cli/version/version", "cli/xray/version", "cli/xray/help")
def cli_version_help(bench):
    version = {}
    for flag in ("--version", "-V"):
        rc, out, _ = run_cli(flag)
        ensure(rc == 0 and re.fullmatch(r"kerlico \d+\.\d+\.\d+\s*", out), f"{flag}: {rc} {out}")
        version[flag] = out.strip()
    helps = {}
    commands = ("history", "help", "account-new", "modules", "check", "run")
    for lang, marker in (("en", "Usage"), ("zh-CN", "用法")):
        rc, out, _ = run_cli("--lang", lang, "help")
        ensure(rc == 0 and marker in out and all(name in out for name in commands), f"{lang} help: {out[:200]}")
        for argv in (("--help",), ("-h",)):
            rc, out, _ = run_cli("--lang", lang, *argv)
            ensure(rc == 0 and marker in out, f"{lang} {argv}: {out[:100]}")
        for name in commands:
            rc, out, _ = run_cli("--lang", lang, "help", name)
            ensure(rc == 0 and marker in out, f"{lang} help {name}: {rc}")
            rc, out, _ = run_cli("--lang", lang, name, "--help")
            ensure(rc == 0 and marker in out, f"{lang} {name} --help: {rc}")
        helps[lang] = True
    rc, _, err = run_cli("--lang", "en", "help", "nosuch")
    ensure(rc == 2 and "cli.invalid_subcommand" in err, f"help nosuch: {rc} {err}")
    rc, _, err = run_cli("--lang", "en")
    ensure(rc == 2, f"无参数 rc={rc}")
    rc, _, err = run_cli("--lang", "en", "nosuch")
    ensure(rc == 2 and "cli.invalid_subcommand" in err, f"未知命令 {rc} {err}")
    rc, _, err = run_cli("--lang", "fr", "modules")
    ensure(rc == 2, f"非法语言 rc={rc}")
    rc, out_zh, _ = run_cli("help", env={"LANG": "zh_CN.UTF-8"})
    rc, out_en, _ = run_cli("help", env={"LANG": "en_US.UTF-8"})
    rc, out_lc, _ = run_cli("help", env={"LANG": "en_US.UTF-8", "LC_ALL": "zh_CN.UTF-8"})
    ensure("用法" in out_zh and "Usage" in out_en and "用法" in out_lc, "环境语言未生效")
    return {
        "cli/flag/v": f"--version、-V 退出码 0，输出 {version['--version']}",
        "cli/version/version": f"--version、-V 退出码 0，输出 {version['--version']}",
        "cli/xray/version": f"--version、-V 退出码 0，输出 {version['--version']}",
        "cli/xray/help": f"help、--help、-h、help <命令>、<命令> --help 对 {len(commands)} 个命令和中英两种语言都退出 0 并给出对应语言用法；help nosuch 退出 2 且码 cli.invalid_subcommand；无参数、未知命令、--lang fr 退出 2；--lang 优先于环境，LC_ALL 优先于 LANG",
    }


@case("cli", "cli/check/check", "cli/flag/t", "cli/run/test")
def cli_check(bench):
    state = bench.fresh("cwd") / "state-dir"
    listen = free_port()
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", listen))
    blocker.listen(1)
    config = minimal(telemetry={"directory": str(state)}, local_inbounds=[local_socks("in", "direct", f"127.0.0.1:{listen}")])
    path = bench.fresh("c") / "good.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    rc, out, err = run_cli("--lang", "en", "check", "-c", str(path))
    ensure(rc == 0 and "Configuration is valid" in out, f"有效配置 {rc} {out} {err}")
    rc2, out2, _ = run_cli("--lang", "zh-CN", "check", "--config", str(path))
    ensure(rc2 == 0 and "配置检查通过" in out2, f"中文 {out2}")
    ensure(not state.exists(), "check 不应创建统计目录")
    blocker.close()
    errors = {}
    for label, config_bad in (("未知字段", {**minimal(), "x": 1}), ("引用不存在的出站", minimal(local_inbounds=[local_socks("in", "nosuch")])), ("端口溢出", {**minimal(), "control": {"listen": "127.0.0.1:99999"}})):
        rc, _, err = bench.check(config_bad)
        ensure(rc == 1 and err.strip(), f"{label}: rc={rc}")
        errors[label] = err.strip().split("]")[0].lstrip("[")
    bad_path = bench.fresh("c") / "bad.json"
    bad_path.write_text(json.dumps({**minimal(), "x": 1}), encoding="utf-8")
    _, _, en_error = run_cli("--lang", "en", "check", "-c", str(bad_path))
    _, _, zh_error = run_cli("--lang", "zh-CN", "check", "-c", str(bad_path))
    ensure("Invalid configuration" in en_error and "配置不合法" in zh_error, f"错误语言 {en_error} {zh_error}")
    rc, _, err = run_cli("--lang", "en", "check", "-c", str(path.parent / "missing.json"))
    ensure(rc == 1 and err.startswith("[io"), f"缺文件 {rc} {err}")
    rc, _, err = run_cli("--lang", "en", "check")
    ensure(rc == 2 and "cli.missing_argument" in err, f"缺参数 {rc} {err}")
    summary = f"有效配置退出 0 并打印通过，配置里的监听端口已被占用也通过（不绑定端口），不创建统计目录；无效配置退出 1 且给错误码（{errors}）；缺文件退出 1；缺 -c 退出 2 且码 cli.missing_argument"
    return {"cli/check/check": summary, "cli/flag/t": summary, "cli/run/test": summary}


@case("cli", "cli/run/run", "cli/xray/run", "cli/flag/f", "cli/global/config", "cli/run/config", "cli/xray/combo")
def cli_run(bench):
    whoami = Whoami()
    config = minimal()
    with bench.kerlico(config) as kerlico:
        ensure(tcp_echo(socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port)) == "127.0.0.1", "run 未转发")
        rc = kerlico.stop(signal.SIGTERM)
        ensure(rc == 0, f"SIGTERM 退出码 {rc}")
    with bench.kerlico(minimal()) as kerlico:
        rc = kerlico.stop(signal.SIGINT)
        ensure(rc == 0, f"SIGINT 退出码 {rc}")
    with bench.kerlico(minimal(), lang="zh-CN", wait=False) as kerlico:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and "已监听" not in kerlico.log():
            time.sleep(0.05)
        ensure("已监听" in kerlico.log(), "中文启动日志")
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = free_port()
    blocker.bind(("127.0.0.1", port))
    blocker.listen(1)
    busy = bench.fresh("c") / "busy.json"
    busy.write_text(json.dumps(minimal(local_inbounds=[local_socks("in", "direct", f"127.0.0.1:{port}")])), encoding="utf-8")
    rc, _, err = run_cli("--lang", "en", "run", "-c", str(busy), timeout=20)
    ensure(rc == 1 and err.strip(), f"端口占用 {rc} {err}")
    blocker.close()
    good = bench.fresh("c") / "good.json"
    good.write_text(json.dumps(minimal()), encoding="utf-8")
    other = bench.fresh("c") / "other.json"
    other.write_text(json.dumps(minimal()), encoding="utf-8")
    rc_dash, _, err_dash = run_cli("--lang", "en", "check", "-c", "-", stdin=json.dumps(minimal()).encode())
    ensure(rc_dash == 1 and "io" in err_dash, f"-c - 应当按文件名失败: {rc_dash} {err_dash}")
    rc_twice, _, err_twice = run_cli("--lang", "en", "check", "-c", str(good), "-c", str(other))
    ensure(rc_twice == 2 and "cli." in err_twice, f"重复 -c {rc_twice} {err_twice}")
    rc_none, _, err_none = run_cli("--lang", "en", "run")
    ensure(rc_none == 2, f"run 缺 -c {rc_none}")
    rc_http, _, _ = run_cli("--lang", "en", "check", "-c", "http://127.0.0.1:1/config.json")
    ensure(rc_http == 1, f"-c http 地址 {rc_http}")
    rc_f, _, err_f = run_cli("--lang", "en", "run", "-f", str(good))
    ensure(rc_f == 2 and "cli.unknown_argument" in err_f, f"-f {rc_f}")
    rc_confdir, _, _ = run_cli("--lang", "en", "run", "-confdir", str(good.parent))
    ensure(rc_confdir == 2, f"-confdir {rc_confdir}")
    whoami.close()
    run_text = "kerlico run -c 真实转发，SIGTERM、SIGINT 都优雅退出码 0，启动日志跟随语言；端口占用退出 1 并报错；缺 -c 退出 2"
    single = f"-c 只收一个本地文件：-c - 把 - 当文件名读取失败（退出 1），重复 -c 退出 2，http 地址当文件名失败。"
    return {
        "cli/run/run": run_text,
        "cli/xray/run": run_text + "。-confdir 退出 2，必须写子命令",
        "cli/flag/f": single + "没有 -f（退出 2）；" + run_text,
        "cli/global/config": single + run_text,
        "cli/run/config": single + run_text,
        "cli/xray/combo": f"已实现的 run、check、modules、history、account-new、help、--version 各自验证，见 cli/run/run、cli/check/check、cli/xray/help、cli/api/stats；config_source 只有单文件，format 只有 JSON。{single}",
    }


@case("cli")
def cli_modules(bench):
    rc, out, _ = run_cli("modules")
    ensure(rc == 0, f"modules {rc}")
    outs = {line.split("/", 1)[1] for line in out.splitlines() if line.startswith("outbound/")}
    ins = {line.split("/", 1)[1] for line in out.splitlines() if line.startswith("inbound/")}
    ensure(outs == MODULE_KINDS_OUT and ins == MODULE_KINDS_IN, f"模块差异 out {outs ^ MODULE_KINDS_OUT} in {ins ^ MODULE_KINDS_IN}")
    password = b"correct horse battery"
    rc, out, err = run_cli("account-new", "--prefix", "alice", stdin=password + b"\n")
    ensure(rc == 0, f"account-new {rc} {err}")
    created = json.loads(out)
    ensure(created["username"].startswith("alice_") and created["password_hash"].startswith("$argon2id$v=19$"), f"账户 {created}")
    uuid.UUID(created["user_id"])
    node = socks_node("n", "direct", [(created["user_id"], "u", "p")])
    bench.accepted({**minimal(), "accounts": [created], "nodes": [node]})
    rc, out_default, _ = run_cli("account-new", stdin=password)
    ensure(rc == 0 and json.loads(out_default)["username"].startswith("user_"), "默认前缀")
    rc, _, short = run_cli("--lang", "en", "account-new", stdin=b"x" * 11)
    ensure(rc == 1, f"11 字节密码 rc={rc}")
    rc, _, _ = run_cli("account-new", stdin=b"x" * 12)
    ensure(rc == 0, "12 字节应通过")
    rc, _, _ = run_cli("account-new", stdin=b"x" * 1024)
    ensure(rc == 0, "1024 字节应通过")
    rc, _, over = run_cli("--lang", "en", "account-new", stdin=b"x" * 1025)
    ensure(rc == 1, f"1025 字节 rc={rc}")
    rc, _, _ = run_cli("account-new", stdin=b"")
    ensure(rc == 1, f"空密码 rc={rc}")


@case("cli", "cli/api/stats", "cli/api/statsquery")
def cli_history(bench):
    sb = StatsBench(bench, telemetry={"sample_interval_ms": 200})
    with bench.kerlico(sb.config) as kerlico:
        got = sb.traffic(kerlico)
        kerlico.stop()
    directory = str(sb.state)

    def history(*argv):
        rc, out, err = run_cli("--lang", "en", "history", "--directory", directory, *argv)
        ensure(rc == 0, f"history {argv}: {rc} {err}")
        return json.loads(out)

    usage = history("--kind", "usage")
    engine = stored_usage(usage, "engine")
    ensure(engine == add(*got.values()), f"history usage {engine}")
    ensure(stored_usage(usage, "user", U1) == got["u1"] and stored_usage(usage, "node", "edge6") == got["u26"] and stored_usage(usage, "outbound", "viaproxy") == got["u1"], f"history 分维度 {usage}")
    scoped_user = history("--kind", "usage", "--user", U1)
    ensure({row["dimension"] for row in scoped_user} == {"user"} and stored_usage(scoped_user, "user") == got["u1"], f"按用户 {scoped_user}")
    flows = history("--kind", "flows")
    ensure(len(flows) == 4, f"flows {len(flows)}")
    by_user = history("--kind", "flows", "--user", U1)
    ensure(len(by_user) == 1 and by_user[0][1]["user"] == U1, f"--user {by_user}")
    by_node = history("--kind", "flows", "--node", "edge6")
    ensure(len(by_node) == 1 and by_node[0][1]["node"] == "edge6", f"--node {by_node}")
    by_out = history("--kind", "flows", "--outbound", "viaproxy")
    ensure(len(by_out) == 1 and by_out[0][1]["outbound"] == "viaproxy", f"--outbound {by_out}")
    page = history("--kind", "flows", "--limit", "2")
    ensure(len(page) == 2, f"--limit {page}")
    rest = history("--kind", "flows", "--after", str(page[-1][0]), "--limit", "2")
    ensure(len(rest) == 2 and rest[0][0] > page[-1][0], f"--after {rest}")
    future = history("--kind", "flows", "--since-ms", str(int(time.time() * 1000) + 3600000))
    ensure(future == [], f"--since-ms {future}")
    bandwidth = history("--kind", "bandwidth", "--limit", "5")
    ensure(bandwidth and "upload_bytes_per_second" in bandwidth[0][1], f"bandwidth {bandwidth[:1]}")
    scoped_band = history("--kind", "bandwidth", "--outbound", "viaproxy", "--limit", "5")
    ensure(all(item[1]["key"] == "viaproxy" for item in scoped_band), f"bandwidth 投影 {scoped_band[:1]}")
    errors = {}
    for label, argv, want in (
        ("--limit 0", ("--limit", "0"), 2), ("--limit 4097", ("--limit", "4097"), 2), ("--after -1", ("--after", "-1"), 2), ("--since-ms 负", ("--since-ms", "-1"), 2),
        ("--kind 未知", ("--kind", "nosuch"), 2), ("usage 带分页", ("--kind", "usage", "--limit", "5"), 1), ("usage 带 since", ("--kind", "usage", "--since-ms", "5"), 1),
        ("usage 双维度", ("--kind", "usage", "--user", U1, "--node", "edge"), 1), ("bandwidth 双维度", ("--kind", "bandwidth", "--user", U1, "--node", "edge"), 1),
        ("--user 非 UUID", ("--user", "alice"), 1), ("--node 非法", ("--node", "bad tag"), 1), ("--outbound 非法", ("--outbound", "bad tag"), 1),
    ):
        rc, _, err = run_cli("--lang", "en", "history", "--directory", directory, *argv)
        ensure(rc == want, f"{label} rc={rc}，应为 {want}: {err[:100]}")
    rc, _, err = run_cli("--lang", "en", "history", "--directory", str(bench.fresh("empty") / "nosuch"))
    ensure(rc == 1 and err.strip(), f"目录不存在 rc={rc}")
    rc, _, err = run_cli("--lang", "en", "history", "--directory", directory, "--kind", "events", "--limit", "1", "--after", "0")
    ensure(rc == 0, f"events {rc}")
    sb.close()
    summary = f"kerlico history 读 SQLite：usage engine {engine} 与实收相等；--user、--node、--outbound 各筛出对应 1 条；--limit、--after 分页不重不漏，--since-ms 未来时间为空；bandwidth 可按维度投影；12 种非法参数和目录不存在都按预期退出 1 或 2"
    return {"cli/api/stats": summary + "。不经 API，没有 reset", "cli/api/statsquery": summary + "。没有 pattern 和 reset"}


# ------------------------------------------------------------------ 边界：结果追加到已有项，失败则覆盖为 fail


@case("route", "route/config/rules", "route/rule/network", "route/action/reject", "route/action/direct")
def route_edges(bench):
    rb = RouteBench()
    invalid = {
        "node 不存在": {"node": ["ghost"]}, "user 不在 accounts": {"user": [U3]}, "user 不是 UUID": {"user": ["alice"]},
        "ip_cidr 前缀为空": {"ip_cidr": ["10.0.0.0/"]}, "IPv4-mapped 网段": {"ip_cidr": ["::ffff:10.0.0.0/104"]}, "前缀超长": {"ip_cidr": ["10.0.0.0/33"]}, "ip_cidr 写域名": {"ip_cidr": ["example.com"]},
        "非 ASCII 关键字": {"domain_keyword": ["例子"]}, "空关键字": {"domain_keyword": [""]}, "domain 写 IP": {"domain": ["192.0.2.1"]}, "domain 空串": {"domain": [""]},
        "端口 0": {"port": [0]}, "端口超范围": {"port": [70000]}, "端口范围字符串": {"port": ["1000-2000"]},
    }
    accepted = []
    for label, condition in invalid.items():
        rc, _, _ = bench.check(rb.config([{"outbound": "a", **condition}]))
        if rc == 0:
            accepted.append(label)
    missing = bench.rejected(rb.config([{"outbound": "ghost", "port": [1]}]))
    ensure(not accepted, f"永远不会命中的规则 check 通过：{accepted}")
    forwards = [("fu", "udp", "drop.example", 53, "dflt")]
    with bench.kerlico(rb.config([{"outbound": "a", "network": "udp"}, {"outbound": "block", "port": [53]}], forwards)) as kerlico:
        sock, bound = socks5(kerlico.listeners["in1"], "0.0.0.0", 0, command=3)
        for recorder in rb.recorders.values():
            recorder.log.clear()
        socks_udp_roundtrip(sock, (bound[0], bound[1]), "assoc.example", 53)
        sock.close()
        ensure(rb.recorders["dflt"].log and not rb.recorders["a"].log, f"多目标 UDP 关联应走节点绑定的出站：a={rb.recorders['a'].log} dflt={rb.recorders['dflt'].log}")
    with bench.kerlico(rb.config([{"outbound": "block", "network": "udp"}], forwards)) as kerlico:
        got = rb.probe(kerlico, inbound="fu")
        ensure(got.startswith("refused"), f"UDP 到 reject 应无回包，实际 {got}")
        flows = kerlico.get("/v1/flows")
        ensure(all(item["usage"]["download_bytes"] == 0 for item in flows), f"reject 不应有下行：{flows}")
    family = {}
    for mode, want in (("ipv4-only", "127.0.0.99"), ("ipv6-only", "::1"), ("dual-stack", "127.0.0.99")):
        config = rb.config([{"outbound": "direct", "domain": ["fam.test"]}], dns={"hosts": {"fam.test": ["::1", "127.0.0.99"]}})
        config["local_inbounds"] = [local_socks("in1", "dflt", mode=mode)]
        with bench.kerlico(config) as kerlico:
            family[mode] = tcp_echo(socks5(kerlico.listeners["in1"], "fam.test", rb.whoami.port))
        ensure(family[mode] == want, f"规则选 direct 时 mode={mode} 拨到 {family[mode]}")
    return {
        "route/action/direct": f"+入口绑定 socks 出站、规则选中 direct 时仍按入口 mode 选地址族：{family}",
        "route/config/rules": f"+{len(invalid)} 种永远不会命中的规则和不存在的出站都被 check 拒绝（{missing}）",
        "route/rule/network": "+SOCKS5 UDP 关联建立时没有单一目标，规则 network=udp→a 不生效，固定走入口绑定的 dflt，与接口文档一致",
        "route/action/reject": "+UDP 规则到 reject：udp-forward 收不到回包，账本下行 0",
    }


@case("dns", "dns/upstream/udp", "dns/server-udp/protocol", "dns/global/nameserver", "dns/hosts/mapping")
def dns_edges(bench):
    db = DnsBench(bench)
    upstream = FakeDns(zones={
        "big.test": {"A": ["127.0.0.97"], "truncate": True},
        "udp.test": {"A": ["127.0.0.1"]},
        "stall.test": {"stall": True},
    })
    state = bench.fresh("t") / "state"
    config = db.config({"servers": [f"udp://127.0.0.1:{upstream.port}"], "hosts": {"dotted.test.": ["127.0.0.98"]}}, telemetry={"directory": str(state)}, limits={"connect_timeout_ms": 1500})
    with bench.kerlico(config) as kerlico:
        ensure(db.resolve(kerlico, "dotted.test") == "127.0.0.98", "hosts 键带结尾点未规范化")
        ensure(db.resolve(kerlico, "dotted.test.") == "127.0.0.98", "目标带结尾点未命中 hosts")
        truncated = db.resolve(kerlico, "big.test", timeout=6)
        transports = {item[0] for item in upstream.queries("big.test")}
        started = time.monotonic()
        stalled = db.resolve(kerlico, "stall.test", timeout=6)
        stall_seconds = time.monotonic() - started
        sock, bound = socks5(kerlico.listeners["in"], "0.0.0.0", 0, command=3)
        reply = socks_udp_roundtrip(sock, (bound[0], bound[1]), "udp.test", db.udp.port)
        sock.close()
        localhost = db.resolve(kerlico, "localhost")
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(state), "--kind", "events")
    events = {item[1]["target"]: item[1]["code"] for item in json.loads(out) if item[1]["kind"] == "dns"}
    upstream.close()
    print("dns edges", truncated, transports, stalled, stall_seconds, reply[:12], localhost, events, file=sys.stderr)
    ensure(truncated == "127.0.0.97" and "tcp" in transports, f"UDP 响应截断后应改用 TCP 取完整答案：结果 {truncated}，传输 {transports}")
    ensure(stalled is None and stall_seconds < 3, f"上游不应答时应按 connect_timeout 失败：{stalled} 耗时 {stall_seconds}")
    ensure(events.get("stall.test") == "dns.aborted", f"不应答的事件码 {events}")
    return {
        "dns/upstream/udp": f"+UDP 响应带 TC 时改用 TCP 取完整答案；上游不应答时 connect_timeout_ms=1500 内失败（{stall_seconds:.1f} 秒），事件 code=dns.aborted；SOCKS5 UDP 域名目标也按上游解析后回显",
        "dns/server-udp/protocol": "+TC 截断回退 TCP 和不应答超时同 dns/upstream/udp",
        "dns/global/nameserver": f"+localhost 由解析器内置返回 {localhost}，不查询上游（RFC 6761）",
        "dns/hosts/mapping": "+键和目标带结尾点都规范化后命中",
    }


@case("stats", "stats/counter/inbound-tag-traffic-uplink", "stats/counter/inbound-tag-traffic-downlink", "stats/connections/totals", "stats/access-log/connection-record", "stats/stats/enable", "config/top/stats")
def stats_edges(bench):
    sb = StatsBench(bench, telemetry={"sample_interval_ms": 200}, limits={"max_sessions": 4, "max_flow_records": 4})
    sizes = [1, 100, 1200]
    with bench.kerlico(sb.config) as kerlico:
        address = kerlico.listeners["fwd"]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            sock.connect(address)
            for size in sizes:
                sock.send(b"p" * size)
                ensure(len(sock.recv(65535)) == size, "UDP 回显长度")
        time.sleep(0.3)
        usage = kerlico.get("/v1/usage")
        fwd = usage["nodes"]["fwd"]
        ensure(pair_of(fwd) == (sum(sizes), sum(sizes)) and fwd["upload_packets"] == 3 and fwd["download_packets"] == 3, f"固定 UDP 用量 {fwd}")
        control, bound = socks5(kerlico.listeners["open"], "0.0.0.0", 0, command=3)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            for size in (77, 33):
                sock.sendto(b"\0\0\0" + socks_address("127.0.0.1", sb.udp.port) + b"q" * size, tuple(bound))
                ensure(len(sock.recv(65535)) == 10 + size, "SOCKS5 UDP 回显长度")
        control.close()
        time.sleep(0.5)
        usage = kerlico.get("/v1/usage")
        open_usage = usage["nodes"]["open"]
        ensure(pair_of(open_usage) == (110, 110) and open_usage["upload_packets"] == 2 and open_usage["download_packets"] == 2, f"UDP 关联用量 {open_usage}")
        for _ in range(6):
            exact_transfer(socks5(kerlico.listeners["open"], "127.0.0.1", sb.exact.port), 10, 10)
        time.sleep(0.3)
        usage = kerlico.get("/v1/usage")
        ensure(usage["retained_records"] <= 4 and usage["evicted_records"] >= 4, f"淘汰 {usage['retained_records']} {usage['evicted_records']}")
        ensure(pair_of(usage["nodes"]["open"]) == (110 + 6 * 26, 110 + 60), f"淘汰后累计 {usage['nodes']['open']}")
        memory_flows = kerlico.get("/v1/flows")
        ensure(len(memory_flows) <= 4, f"/v1/flows 保留 {len(memory_flows)}")
        reader, out, err = run_cli("history", "--directory", str(sb.state), "--kind", "usage")
        ensure(reader == 0, f"写者运行时读失败 {err}")
        second = Kerlico(bench, sb.config, wait=False)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and second.process.poll() is None:
            time.sleep(0.05)
        ensure(second.process.poll() not in (None, 0), "同目录第二个写者应启动失败")
        kerlico.stop()
    _, out, _ = run_cli("history", "--directory", str(sb.state), "--kind", "flows")
    stored = [item[1] for item in json.loads(out)]
    ensure(len(stored) == 8, f"内存淘汰的记录应写入历史，实际 {len(stored)}")
    first_total = stored_usage(json.loads(run_cli("history", "--directory", str(sb.state), "--kind", "usage")[1]), "engine")
    with bench.kerlico(sb.config) as kerlico:
        ensure(pair_of(kerlico.get("/v1/usage")["engine"]) == (0, 0), "新运行内存用量应从零开始")
        exact_transfer(socks5(kerlico.listeners["open"], "127.0.0.1", sb.exact.port), 1000, 2000)
        time.sleep(0.3)
        kerlico.stop()
    rows = json.loads(run_cli("history", "--directory", str(sb.state), "--kind", "usage")[1])
    total = stored_usage(rows, "engine")
    ensure(total == (first_total[0] + 1016, first_total[1] + 2000), f"跨运行累计 {total}，首次 {first_total}")
    sb.close()
    unsafe = bench.fresh("unsafe")
    os.chmod(unsafe, 0o777)
    bad = minimal(telemetry={"directory": str(unsafe / "state")})
    with Kerlico(bench, bad, wait=False) as kerlico:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and kerlico.process.poll() is None:
            time.sleep(0.05)
        ensure(kerlico.process.poll() not in (None, 0), f"组可写祖先目录应启动失败: {kerlico.log()[-200:]}")
    for field, value in (("sample_interval_ms", 99), ("sample_interval_ms", 60001), ("retention_days", 0), ("retention_days", 3651), ("directory", "../x"), ("failure_policy", "nosuch")):
        bench.rejected(minimal(telemetry={"directory": "state", field: value}))
    udp = f"固定 UDP 3 包 {sum(sizes)} 字节和 SOCKS5 UDP 关联 2 包 110 字节，字节数和包数都与实发相等"
    return {
        "stats/counter/inbound-tag-traffic-uplink": "+" + udp,
        "stats/counter/inbound-tag-traffic-downlink": "+" + udp,
        "stats/connections/totals": "+max_flow_records=4 时淘汰旧记录，累计量不变",
        "stats/access-log/connection-record": "+内存淘汰的记录仍写入 SQLite（8 条全在）；写者运行时 history 可读；同目录第二个写者启动失败；不安全祖先目录启动失败；采样间隔和保留天数越界 check 拒绝",
        "stats/stats/enable": "+telemetry 的 sample_interval_ms、retention_days、directory、failure_policy 非法值都被 check 拒绝",
        "config/top/stats": f"+跨运行累加：第二次运行内存从零开始，history 的累计从 {first_total} 增长到 {total}，增量等于第二次运行实发字节",
    }


@case("config", "config/top/policy")
def config_limits(bench):
    whoami = Whoami()
    udp = UdpEcho()
    config = {
        "version": 2,
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "local_inbounds": [local_socks("in", "direct")],
        "inbounds": [{"tag": "fu", "type": "udp-forward", "listen": f"127.0.0.1:{free_port()}", "target": {"host": "127.0.0.1", "port": udp.port}, "outbound": "direct"}],
        "control": control_on(),
    }
    with bench.kerlico({**config, "limits": {"max_sessions": 2}}) as kerlico:
        first = socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port)
        second = socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port)
        recv_line(first)
        recv_line(second)
        try:
            third = socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port, timeout=4)
            third.settimeout(2)
            blocked = recv_line(third) == ""
        except (SocksReply, OSError, ConnectionError):
            blocked = True
        ensure(blocked, "max_sessions=2 时第三条连接应被拒绝")
        first.close()
        second.close()
        time.sleep(0.5)
        ensure(tcp_echo(socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port)) == "127.0.0.1", "释放后应恢复")
    with bench.kerlico({**config, "limits": {"max_datagram_size": 100}}) as kerlico:
        udp_roundtrip(kerlico.listeners["fu"], b"d" * 100)
        try:
            udp_roundtrip(kerlico.listeners["fu"], b"d" * 101, timeout=2)
            raise Fail("max_datagram_size=100 时 101 字节不应回显")
        except TimeoutError:
            pass
    drain = {}
    for milliseconds in (300, 2500):
        with bench.kerlico({**config, "limits": {"drain_timeout_ms": milliseconds}}) as kerlico:
            sock = socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port)
            recv_line(sock)
            started = time.monotonic()
            rc = kerlico.stop(timeout=20)
            drain[milliseconds] = round(time.monotonic() - started, 2)
            sock.close()
            ensure(rc is not None, "应退出")
    ensure(drain[300] < drain[2500], f"drain_timeout_ms 未改变退出耗时 {drain}")
    for limits in ({"max_sessions": 100, "max_flow_records": 50}, {"max_sessions": 0}, {"max_sessions": 65537}, {"connect_timeout_ms": 300001}, {"udp_queue_packets": 0}, {"max_datagram_size": 65536}):
        bench.rejected({**config, "limits": limits})
    bench.rejected({**config, "epoch": 0})
    whoami.close()
    udp.close()
    return {"config/top/policy": f"+max_sessions=2 时第三条连接被拒，释放后恢复；max_datagram_size=100 时 100 字节回显、101 字节丢弃；drain_timeout_ms 300 与 2500 时有活动连接的进程分别 {drain[300]} 秒和 {drain[2500]} 秒退出；越界和 max_flow_records 小于 max_sessions check 拒绝"}


@case("cli", "cli/api/stats", "cli/run/run", "cli/check/check")
def cli_edges(bench):
    cwd = bench.fresh("cwd")
    (cwd / "state").mkdir(mode=0o700)
    config = minimal(telemetry={"directory": "state/telemetry"})
    whoami = Whoami()
    with bench.kerlico(config, cwd=cwd) as kerlico:
        tcp_echo(socks5(kerlico.listeners["in"], "127.0.0.1", whoami.port))
        time.sleep(0.3)
        kerlico.stop()
    rc, out, err = run_cli("history", cwd=cwd)
    ensure(rc == 0 and stored_usage(json.loads(out), "engine")[1] > 0, f"默认目录 {rc} {err}")
    missing = bench.fresh("cwd2") / "nosuch"
    rc, _, _ = run_cli("history", "--directory", str(missing))
    ensure(rc == 1 and not missing.exists(), f"history 不应创建目录 rc={rc}")
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = free_port()
    blocker.bind(("127.0.0.1", port))
    blocker.listen(1)
    path = bench.fresh("c") / "busy.json"
    path.write_text(json.dumps(minimal(control={"listen": f"127.0.0.1:{port}"})), encoding="utf-8")
    rc, _, err = run_cli("--lang", "en", "run", "-c", str(path), timeout=20)
    blocker.close()
    ensure(rc == 1 and err.strip(), f"控制端口占用 rc={rc}")
    rc, _, err = run_cli("--lang", "en", "check", "-c", str(path.parent))
    ensure(rc == 1, f"-c 目录 rc={rc}")
    invalid = bench.fresh("c") / "binary.json"
    invalid.write_bytes(b"\xff\xfe\x00{}")
    rc, _, err = run_cli("--lang", "en", "check", "-c", str(invalid))
    ensure(rc == 1, f"非 UTF-8 配置 rc={rc}")
    rc, out, err = run_cli("account-new", "--prefix", "x" * 200, stdin=b"long-enough-password")
    ensure(rc == 1 or len(json.loads(out)["username"]) <= 128, f"超长前缀生成 {out[:80]}")
    rc, out, _ = run_cli("account-new", "--prefix", "a", stdin=b"long-enough-password\r\n")
    ensure(rc == 0, "CRLF 结尾密码")
    whoami.close()
    return {
        "cli/api/stats": "+默认目录 state/telemetry 相对工作目录可读；目录不存在退出 1 且不创建目录",
        "cli/run/run": "+控制端口被占时退出 1 并报错",
        "cli/check/check": "+-c 指向目录、非 UTF-8 文件都退出 1",
    }


@case("cert", "cert/tls/key-file", "cert/store/certificate")
def cert_edges(bench):
    directory = bench.fresh("certedge")
    material = make_material(directory, ich.SNI)
    other_dir = bench.fresh("certedge2")
    other = make_material(other_dir, ich.SNI, "other")
    port = free_port()
    options, credential, _ = TLS_NODE_PROTOCOLS["trojan"][1]({"certificate_pem": material.cert, "private_key_pem": other.key}, material)
    config = {"version": 2, "accounts": [account(U1)], "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [{"tag": "n", "type": "trojan", "listen": f"127.0.0.1:{port}", "outbound": "direct", "options": options, "members": [{"user_id": U1, "native_credential": credential}]}]}
    mismatch = bench.check(config)
    print("cert mismatch", mismatch, file=sys.stderr)
    ensure(mismatch[0] != 0, f"证书和私钥不匹配 check 应拒绝，实际通过")
    garbage = {"version": 2, "outbounds": [{"tag": "t", "type": "trojan", "options": {"server": {"host": "127.0.0.1", "port": 1}, "password": "p", "security": {"type": "tls", "server_name": ich.SNI, "ca_pem": "not a pem"}}}]}
    bad_ca = bench.rejected(garbage)
    return {"cert/tls/key-file": "+证书和私钥不匹配 check 拒绝", "cert/store/certificate": f"+ca_pem 不是 PEM 时 check 拒绝（{bad_ca}）"}


def write_results(path, results):
    with open(path, "w", encoding="utf-8") as stream:
        for key, (test, evidence) in sorted(results.items()):
            stream.write(json.dumps({"key": key, "test": test, "evidence": evidence, "date": DATE}, ensure_ascii=False) + "\n")


def main():
    global ARGS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--only")
    parser.add_argument("--case")
    parser.add_argument("--sing-box", dest="sing_box")
    ARGS = parser.parse_args()
    groups = set(ARGS.only.split(",")) if ARGS.only else None
    Path(ARGS.work).mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run-", dir=ARGS.work))
    bench = Bench(work)
    results = {}
    if Path(ARGS.out).exists():
        for line in Path(ARGS.out).read_text(encoding="utf-8").splitlines():
            item = json.loads(line)
            results[item["key"]] = (item["test"], item["evidence"])
    for group, keys, function in CASES:
        if groups and group not in groups:
            continue
        if ARGS.case and ARGS.case not in function.__name__:
            continue
        started = time.monotonic()
        try:
            outcome = function(bench)
            if outcome is None:
                outcome = {}
            if isinstance(outcome, str):
                outcome = {key: outcome for key in keys}
            for key in keys:
                if key not in outcome:
                    continue
                value = outcome[key]
                if isinstance(value, str) and value.startswith("+"):
                    if key in results and results[key][0] == "pass":
                        results[key] = ("pass", results[key][1] + "。" + value[1:])
                else:
                    results[key] = value if isinstance(value, tuple) else ("pass", value)
            status = "ok"
        except Exception as error:  # 工具错误和断言失败都按项记录，继续后面的用例。
            detail = str(error) if isinstance(error, Fail) else f"{type(error).__name__}: {error}"
            for key in keys:
                results[key] = ("fail", detail)
            status = f"FAIL: {detail}"
            if not isinstance(error, Fail):
                traceback.print_exc()
        print(f"[{group}] {function.__name__} {time.monotonic() - started:.1f}s {status}", flush=True)
        write_results(ARGS.out, results)
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"pass": sum(v[0] == "pass" for v in results.values()), "fail": sum(v[0] == "fail" for v in results.values()), "blocked": sum(v[0] == "blocked" for v in results.values())}))


if __name__ == "__main__":
    main()
