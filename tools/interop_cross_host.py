#!/usr/bin/env python3
"""三台 worker 上的 kerlico 跨机矩阵：客户端 A、节点或真实对端 B、回显目标 C。

本机只负责编排：把本文件传到 worker，以 `agent` 子命令常驻，经 ssh 的标准输入输出做 JSON-RPC。
ssh 断开时 agent 回收自己启动的全部进程。用法见 docs/build-and-test.md。
"""
import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import http.client
import json
import os
import random
import re
import secrets
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = "/srv/build/kerlico/xhost"
MACHINES = ("perf-01", "perf-02", "perf-03")
SNI = "kerlico.test"
SIZES = {"tcp_small": 64, "tcp_1m": 1 << 20, "tcp_32m": 32 << 20}
UDP_SIZES = (64, 1200, 1252, 1400)
LIMITS = {"connect_timeout_ms": 15000, "idle_timeout_ms": 60000, "drain_timeout_ms": 5000, "max_sessions": 256}
PORT_RANGE = (30000, 32767)
MESH_DEVICE = "CloudflareWARP"
# kerlico 接受的下限；加外层后超过 Mesh 接口 MTU，靠内核分片。
WG_MTU = 1280


# ---------- worker 侧 ----------

def payload(size):
    return random.Random(size).randbytes(size)


def recv_exact(stream, size, stall):
    stream.settimeout(stall)
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(min(1 << 18, size - len(data)))
        if not chunk:
            raise EOFError(len(data))
        data.extend(chunk)
    return data


class Sender:
    """后台发送。socket 保持阻塞：settimeout 对 sendall 是整次调用的总时长，慢路径上发送会被提前终止。"""

    def __init__(self, stream, data):
        self.stream, self.data = stream, data
        self.sent, self.error = 0, None
        stream.settimeout(None)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        view = memoryview(self.data)
        try:
            while self.sent < len(view):
                self.sent += self.stream.send(view[self.sent:self.sent + (1 << 16)])
        except OSError as error:
            self.error = type(error).__name__

    def stop(self):
        try:
            self.stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def recv_or_stall(stream, limit, stall):
    if not select.select([stream], [], [], stall)[0]:
        raise socket.timeout
    return stream.recv(limit)


def exchange(stream, size, stall=40.0):
    """全双工发送并接收回显，不依赖半关闭；stall 是接收无进展的上限，返回结果字典。"""
    data = payload(size)
    started = time.monotonic()
    sender = Sender(stream, data)
    received = bytearray()
    outcome = {"ok": False, "size": size}
    try:
        while len(received) < size:
            chunk = recv_or_stall(stream, min(1 << 18, size - len(received)), stall)
            if not chunk:
                outcome["error"] = f"eof@{len(received)} sent={sender.sent}"
                return outcome
            received.extend(chunk)
    except socket.timeout:
        outcome["error"] = f"stall@{len(received)} sent={sender.sent}"
        return outcome
    except OSError as error:
        outcome["error"] = f"{type(error).__name__}@{len(received)} sent={sender.sent}"
        return outcome
    finally:
        sender.stop()
    elapsed = time.monotonic() - started
    if hashlib.sha256(received).digest() != hashlib.sha256(data).digest():
        diff = next((i for i in range(size) if received[i] != data[i]), -1)
        outcome["error"] = f"digest@{diff}"
        return outcome
    outcome.update(ok=True, elapsed=round(elapsed, 3), mib_s=round(size / 1048576 / max(elapsed, 1e-3), 2))
    return outcome


def socks_connect(port, host, target_port, timeout=30.0):
    stream = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    stream.sendall(b"\x05\x01\x00")
    if bytes(recv_exact(stream, 2, timeout)) != b"\x05\x00":
        stream.close()
        raise ConnectionError("socks_method")
    atyp, raw = (4, socket.inet_pton(socket.AF_INET6, host)) if ":" in host else (1, socket.inet_pton(socket.AF_INET, host))
    stream.sendall(bytes((5, 1, 0, atyp)) + raw + struct.pack(">H", target_port))
    reply = bytes(recv_exact(stream, 4, timeout))
    if reply[1] != 0:
        stream.close()
        raise ConnectionError(f"socks_reply_{reply[1]}")
    recv_exact(stream, {1: 6, 4: 18}.get(reply[3]) or recv_exact(stream, 1, timeout)[0] + 2, timeout)
    return stream


def tcp_socks(socks, host, port, size):
    try:
        stream = socks_connect(socks, host, port)
    except (OSError, EOFError) as error:
        detail = str(error) if isinstance(error, ConnectionError) and str(error).startswith("socks_") else type(error).__name__
        return {"ok": False, "size": size, "error": detail}
    with stream:
        return exchange(stream, size)


def tcp_direct(host, port, size):
    try:
        stream = socket.create_connection((host, port), timeout=10)
    except OSError as error:
        return {"ok": False, "size": size, "error": type(error).__name__}
    with stream:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return exchange(stream, size)


def udp_rounds(sock, send, recv, size, count, wait=1.5, tries=4):
    """逐包往返；一个包重发至多 tries 次，统计未答复的包数和实际重发。"""
    lost, resent, started = 0, 0, time.monotonic()
    sock.settimeout(wait)
    for index in range(count):
        data = struct.pack(">I", index) + random.Random(index + size).randbytes(size - 4)
        for attempt in range(tries):
            if attempt:
                resent += 1
            send(data)
            try:
                deadline = time.monotonic() + wait
                matched = False
                while time.monotonic() < deadline:
                    reply = recv()
                    if reply == data:
                        matched = True
                        break
                    if reply[:4] == data[:4]:
                        return {"ok": False, "size": size, "error": f"content_len{len(reply)}"}
                if matched:
                    break
            except socket.timeout:
                continue
            except OSError as error:
                return {"ok": False, "size": size, "error": type(error).__name__}
        else:
            lost += 1
            if lost == 3:
                return {"ok": False, "size": size, "error": "no_reply", "lost": lost, "answered": index + 1 - lost}
    outcome = {"ok": lost == 0, "size": size, "lost": lost, "resent": resent, "elapsed": round(time.monotonic() - started, 3)}
    if lost:
        outcome["error"] = "loss"
    return outcome


def udp_forward(port, size, count):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("127.0.0.1", port))
        return udp_rounds(sock, sock.send, lambda: sock.recv(65535), size, count)


def udp_direct(host, port, size, count):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.connect((host, port))
        return udp_rounds(sock, sock.send, lambda: sock.recv(65535), size, count)


def udp_socks(socks, host, port, size, count):
    try:
        control = socket.create_connection(("127.0.0.1", socks), timeout=15)
        control.sendall(b"\x05\x01\x00")
        if bytes(recv_exact(control, 2, 15)) != b"\x05\x00":
            return {"ok": False, "size": size, "error": "socks_method"}
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = bytes(recv_exact(control, 4, 15))
        if reply[1] != 0:
            control.close()
            return {"ok": False, "size": size, "error": f"socks_reply_{reply[1]}"}
        if reply[3] != 1:
            control.close()
            return {"ok": False, "size": size, "error": "socks_bind_family"}
        bound = bytes(recv_exact(control, 6, 15))
    except (OSError, EOFError) as error:
        return {"ok": False, "size": size, "error": type(error).__name__}
    relay = (socket.inet_ntoa(bound[:4]), struct.unpack(">H", bound[4:])[0])
    atyp, raw = (4, socket.inet_pton(socket.AF_INET6, host)) if ":" in host else (1, socket.inet_pton(socket.AF_INET, host))
    header = bytes((0, 0, 0, atyp)) + raw + struct.pack(">H", port)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))

        def recv():
            data, _ = sock.recvfrom(65535)
            if data[:3] != b"\0\0\0":
                return b""
            offset = {1: 10, 4: 22}.get(data[3])
            return data[offset:] if offset else b""

        return udp_rounds(sock, lambda data: sock.sendto(header + data, relay), recv, size, count)


def tcp_watch(socks, host, port, size, stall=180.0, deadline=1200.0):
    """大载荷回显，记录最长无进展间隔；用来区分慢和真停住，不沿用 exchange 的 40 秒停滞判定。"""
    try:
        stream = socks_connect(socks, host, port)
    except (OSError, EOFError) as error:
        detail = str(error) if isinstance(error, ConnectionError) and str(error).startswith("socks_") else type(error).__name__
        return {"ok": False, "size": size, "error": detail}
    data = payload(size)
    digest = hashlib.sha256()
    sender = Sender(stream, data)
    started = last = time.monotonic()
    received, longest, longest_at = 0, 0.0, 0
    outcome = {"ok": False, "size": size}
    with stream:
        try:
            while received < size:
                if time.monotonic() - started > deadline:
                    outcome["error"] = f"deadline@{received}"
                    break
                chunk = recv_or_stall(stream, min(1 << 18, size - received), stall)
                now = time.monotonic()
                if now - last > longest:
                    longest, longest_at = now - last, received
                last = now
                if not chunk:
                    outcome["error"] = f"eof@{received}"
                    break
                digest.update(chunk)
                received += len(chunk)
        except socket.timeout:
            outcome["error"] = f"stall@{received}"
        except OSError as error:
            outcome["error"] = f"{type(error).__name__}@{received}"
        finally:
            sender.stop()
    elapsed = time.monotonic() - started
    outcome.update(elapsed=round(elapsed, 3), mib_s=round(received / 1048576 / max(elapsed, 1e-3), 2), received=received, sent=sender.sent, sender_error=sender.error, longest_gap=round(longest, 1), longest_gap_at=longest_at)
    if received == size and "error" not in outcome:
        if digest.digest() == hashlib.sha256(data).digest():
            outcome["ok"] = True
        else:
            outcome["error"] = "digest"
    return outcome


def http_exchange(stream, host, path, contains, limit, started):
    stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept-Encoding: identity\r\nUser-Agent: curl/8.5.0\r\n\r\n".encode())
    response = http.client.HTTPResponse(stream)
    response.begin()
    body = response.read(limit + 1)
    elapsed = time.monotonic() - started
    outcome = {"ok": False, "http_status": response.status, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "elapsed": round(elapsed, 3), "mib_s": round(len(body) / 1048576 / max(elapsed, 1e-3), 3)}
    if response.status != 200:
        outcome["error"] = f"http_{response.status}"
    elif len(body) > limit:
        outcome["error"] = "body_too_large"
    elif contains and contains.encode() not in body:
        outcome["error"] = "content_unexpected"
    else:
        outcome["ok"] = True
    return outcome


def socks_domain(port, host, target_port, timeout):
    stream = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    stream.sendall(b"\x05\x01\x00")
    if bytes(recv_exact(stream, 2, timeout)) != b"\x05\x00":
        stream.close()
        raise ConnectionError("socks_method")
    name = host.encode("ascii")
    stream.sendall(bytes((5, 1, 0, 3, len(name))) + name + struct.pack(">H", target_port))
    reply = bytes(recv_exact(stream, 4, timeout))
    if reply[1] != 0:
        stream.close()
        raise ConnectionError(f"socks_reply_{reply[1]}")
    recv_exact(stream, {1: 6, 4: 18}.get(reply[3]) or recv_exact(stream, 1, timeout)[0] + 2, timeout)
    return stream


def http_socks(socks, host, port, path, tls=True, contains="", limit=1 << 21, stall=120.0):
    """经 SOCKS 域名目标发 HTTP(S) GET，用于目标是公网站点的出站（Tor）。"""
    started = time.monotonic()
    try:
        raw = socks_domain(socks, host, port, stall)
        stream = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
        with stream:
            return http_exchange(stream, host, path, contains, limit, started)
    except (OSError, EOFError, http.client.HTTPException) as error:
        detail = str(error) if isinstance(error, ConnectionError) and str(error).startswith("socks_") else f"{type(error).__name__}: {error}"
        return {"ok": False, "error": detail}


def http_direct(host, port, path, tls=True, limit=1 << 21, stall=60.0):
    started = time.monotonic()
    try:
        raw = socket.create_connection((host, port), timeout=stall)
        stream = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
        with stream:
            return http_exchange(stream, host, path, "", limit, started)
    except (OSError, EOFError, http.client.HTTPException) as error:
        return {"ok": False, "error": f"{type(error).__name__}: {error}"}


class Echo:
    """一个 agent 一组回显端口，v4 与 v6 同端口号。"""

    def __init__(self):
        self.tcp_port = self.udp_port = 0
        for _ in range(50):
            port = random.randint(*PORT_RANGE)
            try:
                self.sockets = [self.bind(socket.AF_INET, socket.SOCK_STREAM, "0.0.0.0", port), self.bind(socket.AF_INET, socket.SOCK_DGRAM, "0.0.0.0", port), self.bind(socket.AF_INET6, socket.SOCK_STREAM, "::", port), self.bind(socket.AF_INET6, socket.SOCK_DGRAM, "::", port)]
                self.port = port
                break
            except OSError:
                continue
        else:
            raise RuntimeError("回显端口分配失败")
        for sock in self.sockets:
            target = self.serve_tcp if sock.type == socket.SOCK_STREAM else self.serve_udp
            threading.Thread(target=target, args=(sock,), daemon=True).start()

    @staticmethod
    def bind(family, kind, host, port):
        sock = socket.socket(family, kind)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        if kind == socket.SOCK_STREAM:
            sock.listen(256)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        return sock

    def serve_tcp(self, server):
        while True:
            client, _ = server.accept()
            threading.Thread(target=self.echo_stream, args=(client,), daemon=True).start()

    @staticmethod
    def echo_stream(client):
        with client:
            try:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                while chunk := client.recv(1 << 18):
                    client.sendall(chunk)
            except OSError:
                pass

    @staticmethod
    def serve_udp(server):
        while True:
            data, peer = server.recvfrom(65535)
            try:
                server.sendto(data, peer)
            except OSError:
                pass


def listening(protocol, port):
    """读 /proc 判断端口是否已监听，不向协议端口发探测流量。"""
    for path in (f"/proc/net/{protocol}", f"/proc/net/{protocol}6"):
        try:
            with open(path, encoding="ascii") as table:
                next(table)
                for line in table:
                    fields = line.split()
                    if int(fields[1].rsplit(":", 1)[1], 16) == port and (protocol == "udp" or fields[3] == "0A"):
                        return True
        except OSError:
            continue
    return False


class AgentState:
    def __init__(self, root, binary):
        self.root, self.binary = Path(root), binary
        self.workdir = self.root / "run" / str(os.getpid())
        self.workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.children = {}
        self.ports = set()
        self.lock = threading.Lock()
        self.echo = None
        self.netns = set()
        self.containers = set()

    def alloc_ports(self, count):
        result = []
        with self.lock:
            while len(result) < count:
                port = random.randint(*PORT_RANGE)
                if port in self.ports or listening("tcp", port) or listening("udp", port):
                    continue
                self.ports.add(port)
                result.append(port)
        return result

    def start_echo(self):
        with self.lock:
            if self.echo is None:
                self.echo = Echo()
        return self.echo.port

    def addrs(self):
        def show(*argv):
            return subprocess.run(["ip", *argv], capture_output=True, text=True, timeout=10).stdout

        device = re.search(r"\bdev (\S+)", show("-4", "route", "show", "default"))
        native6 = re.findall(r"inet6 (\S+)/\d+ scope global", show("-o", "-6", "addr", "show", "dev", device.group(1))) if device else []
        mesh = show("-o", "addr", "show", "dev", MESH_DEVICE)
        mesh4 = re.search(r"inet (\S+)/", mesh)
        mesh6 = re.findall(r"inet6 (\S+)/\d+ scope global", mesh)
        return {
            "public": {"v6": native6[-1] if native6 else None},
            "mesh": {"v4": mesh4.group(1) if mesh4 else None, "v6": next((item for item in mesh6 if not item.endswith(":2000::1")), None)},
        }

    def gen_tls(self):
        directory = self.workdir / "pki"
        directory.mkdir(mode=0o700, exist_ok=True)

        def ssl(*argv):
            subprocess.run(["openssl", *argv], check=True, capture_output=True, timeout=60, cwd=directory)

        ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "3", "-subj", "/CN=xhost-test-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        ssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=" + SNI)
        (directory / "ext").write_text(f"subjectAltName=DNS:{SNI}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n", encoding="ascii")
        ssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "3", "-extfile", "ext", "-out", "leaf.pem")
        result = {name: (directory / file).read_text(encoding="ascii") for name, file in (("ca", "ca.pem"), ("cert", "leaf.pem"), ("key", "leaf.key"))}
        subprocess.run(["rm", "-rf", str(directory)], check=False)
        return result

    def tail(self, path, limit=2000):
        try:
            with open(path, "rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - limit))
                return stream.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def spawn_kerlico(self, name, config, wait_ports, with_ns=None):
        directory = self.workdir / name
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        check = subprocess.run([self.binary, "check", "-c", str(path)], capture_output=True, text=True, timeout=60)
        if check.returncode:
            return {"ok": False, "stage": "check", "log": (check.stderr or check.stdout)[-1500:]}
        return self.spawn_raw(name, [self.binary, "run", "-c", str(path)], wait_ports, directory=directory)

    def spawn_raw(self, name, argv, wait_ports=(), directory=None, wait=25.0, environment=None):
        directory = directory or self.workdir / name
        directory.mkdir(mode=0o700, exist_ok=True)
        log_path = directory / "log"
        with open(log_path, "ab") as log:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=directory, start_new_session=True, env={**os.environ, **(environment or {})})
        with self.lock:
            self.children[name] = (process, directory, log_path)
        deadline = time.monotonic() + wait
        pending = [tuple(item) for item in wait_ports]
        while pending:
            if process.poll() is not None:
                self.children.pop(name, None)
                return {"ok": False, "stage": "start", "rc": process.returncode, "log": self.tail(log_path)}
            pending = [item for item in pending if not listening(*item)]
            if time.monotonic() > deadline:
                return {"ok": False, "stage": "listen", "log": self.tail(log_path)}
            if pending:
                time.sleep(0.1)
        return {"ok": True}

    def spawn_tls_origin(self, name, port, material):
        directory = self.workdir / name
        directory.mkdir(mode=0o700, exist_ok=True)
        (directory / "cert.pem").write_text(material["cert"], encoding="ascii")
        (directory / "key.pem").write_text(material["key"], encoding="ascii")
        argv = [sys.executable, str(Path(__file__).resolve()), "tls-origin", str(port), "cert.pem", "key.pem"]
        return self.spawn_raw(name, argv, [("tcp", port)], directory=directory)

    def alive(self, name):
        entry = self.children.get(name)
        return {"alive": bool(entry) and entry[0].poll() is None, "log": self.tail(entry[2]) if entry else ""}

    def stop(self, name, keep=False, grace=10.0):
        with self.lock:
            entry = self.children.pop(name, None)
        if not entry:
            return {"rc": None, "log": ""}
        process, directory, log_path = entry
        started = time.monotonic()
        rc = process.poll()
        was_running = rc is None
        if was_running:
            try:
                process.send_signal(signal.SIGTERM)
                rc = process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                process.wait(timeout=5)
                rc = "killed"
        log = self.tail(log_path)
        if not keep:
            subprocess.run(["rm", "-rf", str(directory)], check=False)
        return {"rc": rc, "was_running": was_running, "elapsed": round(time.monotonic() - started, 2), "log": log}

    def run_command(self, argv, timeout=120, input_text=None):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input_text)
        return {"rc": result.returncode, "stdout": result.stdout[-6000:], "stderr": result.stderr[-3000:]}

    def write_file(self, relative, text, mode=0o600):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
        return str(path)

    def track_netns(self, name):
        self.netns.add(name)

    def untrack_netns(self, name):
        self.netns.discard(name)

    def track_container(self, name):
        self.containers.add(name)

    def untrack_container(self, name):
        self.containers.discard(name)

    def netns_case(self, netns, kind, host, port, size, count=10):
        argv = ["ip", "netns", "exec", netns, sys.executable, str(Path(__file__).resolve()), "netns-case", kind, host, str(port), str(size), str(count)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=400)
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {"ok": False, "size": size, "error": "netns_case", "log": result.stderr[-500:]}

    def sh(self, script, limit=120, stdin=None):
        # 没有输入时也要接管 stdin：agent 的 stdin 是 RPC 通道，子进程继承后可能读走请求。
        result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=limit, input=stdin or "")
        return {"rc": result.returncode, "stdout": result.stdout[-20000:], "stderr": result.stderr[-3000:]}

    def fixture(self, label, files, mode=0o600, directory_mode=0o755):
        """单次对端启动的材料目录，随 stop 或 agent 退出回收；容器内的非 root 进程要能读时放宽 mode。"""
        directory = self.workdir / "fixtures" / label
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(directory_mode)
        for name, text in files.items():
            path = directory / name
            path.write_text(text, encoding="utf-8")
            path.chmod(mode)
        return str(directory)

    def read_file(self, path):
        return Path(path).read_text(encoding="utf-8")

    def primary_v4(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            return probe.getsockname()[0]

    def wait_ports(self, ports, wait=30.0):
        deadline = time.monotonic() + wait
        pending = [tuple(item) for item in ports]
        while pending and time.monotonic() < deadline:
            pending = [item for item in pending if not listening(*item)]
            if pending:
                time.sleep(0.2)
        return {"ok": not pending, "pending": pending}

    def spawn_relay(self, name, kind, listen, host, port, bind="::"):
        argv = [sys.executable, str(Path(__file__).resolve()), "relay", kind, str(listen), host, str(port), "--bind", bind]
        return self.spawn_raw(name, argv, [("tcp" if kind == "tcp" else "udp", listen)])

    def container_up(self, name, image, flags, command):
        self.track_container(name)
        result = subprocess.run(["docker", "run", "-d", "--name", name, *flags, image, *command], capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
        if result.returncode:
            return {"ok": False, "log": result.stderr[-1500:]}
        inspect = subprocess.run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}}{{end}}", name], capture_output=True, text=True, timeout=30)
        fields = inspect.stdout.split()
        return {"ok": True, "ip": fields[0] if fields else "", "gateway": fields[1] if len(fields) > 1 else ""}

    def container_down(self, name):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        self.untrack_container(name)
        return True

    def container_exec(self, name, argv, limit=60):
        result = subprocess.run(["docker", "exec", name, *argv], capture_output=True, text=True, timeout=limit, stdin=subprocess.DEVNULL)
        return {"rc": result.returncode, "stdout": result.stdout[-20000:], "stderr": result.stderr[-3000:]}

    def container_log(self, name, lines=8):
        result = subprocess.run(["docker", "logs", "--tail", str(lines), name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=30)
        return result.stdout[-1200:]

    def netns_up(self, name):
        self.track_netns(name)
        result = subprocess.run(["ip", "netns", "add", name], capture_output=True, text=True, timeout=30)
        return {"rc": result.returncode, "stderr": result.stderr[-500:]}

    def netns_down(self, name):
        subprocess.run(["ip", "netns", "delete", name], capture_output=True, timeout=30)
        self.untrack_netns(name)
        return True

    def shutdown(self):
        for name in list(self.children):
            self.stop(name, grace=3.0)
        for name in list(self.containers):
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)
        for name in list(self.netns):
            subprocess.run(["ip", "netns", "delete", name], capture_output=True, timeout=30)
        subprocess.run(["rm", "-rf", str(self.workdir)], check=False)


METHODS = {"tcp_socks": tcp_socks, "tcp_direct": tcp_direct, "udp_forward": udp_forward, "udp_direct": udp_direct, "udp_socks": udp_socks, "http_socks": http_socks, "http_direct": http_direct, "tcp_watch": tcp_watch}


def agent_main(args):
    os.umask(0o077)
    state = AgentState(args.root, args.binary)
    output_lock = threading.Lock()
    signal.signal(signal.SIGTERM, lambda *_: (state.shutdown(), os._exit(0)))

    def handle(request):
        try:
            method = METHODS.get(request["method"]) or getattr(state, request["method"])
            reply = {"id": request["id"], "result": method(**request["params"])}
        except BaseException as error:
            reply = {"id": request["id"], "error": f"{type(error).__name__}: {error}"}
        with output_lock:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()

    for line in sys.stdin:
        threading.Thread(target=handle, args=(json.loads(line),), daemon=True).start()
    state.shutdown()
    os._exit(0)


def tls_origin_main(args):
    """ShadowTLS 和 REALITY 的伪装站：完成 TLS 握手后回一个 HTTP 响应。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(["h2", "http/1.1"])
    server = socket.create_server(("127.0.0.1", args.port), backlog=64)

    def serve(raw):
        with raw:
            raw.settimeout(20)
            try:
                with context.wrap_socket(raw, server_side=True) as stream:
                    stream.recv(4096)
                    stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except OSError:
                pass

    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        raw, _ = server.accept()
        threading.Thread(target=serve, args=(raw,), daemon=True).start()


def relay_main(args):
    """用户态端口转发。桥接容器不用 docker -p 发布端口，避免 dockerd 改动主机 iptables。"""
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    family = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    upstream = (args.host, args.port)

    def permissive(sock):
        # 关闭 DF：Mesh 接口 MTU 只有 1300，超长数据报由内核分片，不因 EMSGSIZE 丢弃。
        for level, option in ((socket.IPPROTO_IP, 10), (socket.IPPROTO_IPV6, 23)):
            try:
                sock.setsockopt(level, option, 0)
            except OSError:
                pass

    def bound(kind):
        bind_family = socket.AF_INET6 if ":" in args.bind else socket.AF_INET
        sock = socket.socket(bind_family, kind)
        if bind_family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.bind, args.listen))
        return sock

    if args.kind == "tcp":
        server = bound(socket.SOCK_STREAM)
        server.listen(256)

        def pump(source, sink):
            try:
                while chunk := source.recv(1 << 18):
                    sink.sendall(chunk)
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                for stream in (source, sink):
                    try:
                        stream.close()
                    except OSError:
                        pass

        def serve(client):
            try:
                remote = socket.create_connection(upstream, timeout=15)
                remote.settimeout(None)
            except OSError:
                client.close()
                return
            for stream in (client, remote):
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=pump, args=(client, remote), daemon=True).start()
            pump(remote, client)

        while True:
            client, _ = server.accept()
            threading.Thread(target=serve, args=(client,), daemon=True).start()
    server = bound(socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    permissive(server)
    flows = {}

    def downstream(sock, client):
        while True:
            try:
                data = sock.recv(65535)
                server.sendto(data, client)
            except ConnectionRefusedError:
                continue
            except OSError:
                return

    while True:
        data, client = server.recvfrom(65535)
        sock = flows.get(client)
        if sock is None:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
            permissive(sock)
            sock.connect(upstream)
            flows[client] = sock
            threading.Thread(target=downstream, args=(sock, client), daemon=True).start()
        try:
            sock.send(data)
        except OSError:
            pass


def netns_case_main(args):
    size, count = args.size, args.count
    if args.kind == "tcp":
        result = tcp_direct(args.host, args.port, size)
    else:
        result = udp_direct(args.host, args.port, size, count)
    print(json.dumps(result))


# ---------- 编排侧 ----------

class AgentError(RuntimeError):
    pass


class Agent:
    def __init__(self, alias, ssh_config, binary):
        self.alias, self.ssh_config, self.binary = alias, ssh_config, binary
        self.lock = threading.Lock()
        self.pending = {}
        self.next_id = 0
        self.process = None
        self.echo_port = None
        self.addr = {}

    def ssh_argv(self, *remote):
        return ["ssh", "-F", self.ssh_config, "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=8", self.alias, *remote]

    def start(self):
        source = Path(__file__).read_bytes()
        remote = f"{ROOT}/interop_cross_host.py"
        upload = subprocess.run(self.ssh_argv(f"mkdir -p {ROOT} && chmod 700 {ROOT} && cat > {remote}"), input=source, capture_output=True, timeout=120)
        if upload.returncode:
            raise AgentError(f"{self.alias} 上传失败：{upload.stderr.decode('utf-8', 'replace')[-300:]}")
        self.process = subprocess.Popen(self.ssh_argv(f"exec python3 -u {remote} agent --root {ROOT} --binary {self.binary}"), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        threading.Thread(target=self.reader, args=(self.process,), daemon=True).start()
        self.echo_port = self.call("start_echo")
        self.addr = self.call("addrs")

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def ensure(self):
        with self.lock:
            needed = not self.alive()
        if needed:
            self.start()

    def reader(self, process):
        for line in process.stdout:
            reply = json.loads(line)
            with self.lock:
                slot = self.pending.pop(reply["id"], None)
            if slot:
                slot[1].append(reply)
                slot[0].set()
        with self.lock:
            pending, self.pending = self.pending, {}
        for slot in pending.values():
            slot[1].append({"error": "AgentDied"})
            slot[0].set()

    def call(self, method, timeout=420, **params):
        event, box = threading.Event(), []
        with self.lock:
            self.next_id += 1
            request = {"id": self.next_id, "method": method, "params": params}
            self.pending[self.next_id] = (event, box)
            try:
                self.process.stdin.write((json.dumps(request) + "\n").encode())
                self.process.stdin.flush()
            except OSError as error:
                self.pending.pop(self.next_id, None)
                raise AgentError(f"AgentDied: {error}") from error
        if not event.wait(timeout):
            raise AgentError(f"rpc_timeout:{method}")
        reply = box[0]
        if "error" in reply:
            raise AgentError(reply["error"])
        return reply["result"]

    def close(self):
        if self.alive():
            self.process.stdin.close()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()


class Scrubber:
    """结果和日志离开 worker 前把真实地址换成别名，其他 IP 一律抹去。"""

    IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]*\b|\[[0-9a-fA-F:]+\]")

    def __init__(self):
        self.known = {}

    def add(self, address, alias):
        if address:
            self.known[address] = alias

    def clean(self, text):
        if not isinstance(text, str):
            return text
        for address, alias in self.known.items():
            text = text.replace(address, alias)
        return self.IP.sub("<ip>", text)


def resolve_public_v4(ssh_config, alias):
    out = subprocess.run(["ssh", "-F", ssh_config, "-G", alias], capture_output=True, text=True, timeout=20).stdout
    return re.search(r"^hostname (\S+)$", out, re.M).group(1)


# ---------- 协议表 ----------

def x25519_public(private):
    p, a24 = 2**255 - 19, 121665
    k = int.from_bytes(bytes([private[0] & 248]) + private[1:31] + bytes([(private[31] & 127) | 64]), "little")
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in reversed(range(255)):
        bit = (k >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + a24 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def x25519_pair():
    private = secrets.token_bytes(32)
    private = bytes([private[0] & 248]) + private[1:31] + bytes([(private[31] & 127) | 64])
    return private, x25519_public(private)


def b64(raw):
    return base64.b64encode(raw).decode()


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass(frozen=True)
class Material:
    ca: str
    cert: str
    key: str

    @property
    def chain(self):
        return self.cert + self.ca


@dataclass
class Spec:
    node: dict
    member: dict | None
    client: dict
    origin: bool = False


@dataclass(frozen=True)
class Carrier:
    protocol: str
    name: str
    build: object
    udp: bool = True
    socks_udp: bool = True
    uses_udp_listener: bool = False
    tcp_listener: bool = True
    notes: str = ""

    @property
    def key(self):
        return f"{self.protocol}/{self.name}"


def tls_node(m, **extra):
    return {"certificate_pem": m.chain, "private_key_pem": m.key, **extra}


def tls_client(m, **extra):
    return {"server_name": SNI, "ca_pem": m.ca, **extra}


def typed_tls_node(m):
    return {"type": "tls", **tls_node(m)}


def typed_tls_client(m, **extra):
    return {"type": "tls", **tls_client(m, **extra)}


TRANSPORTS = {
    "tcp": {"type": "tcp"},
    "ws": {"type": "ws", "path": "/xhost", "host": SNI},
    "httpupgrade": {"type": "httpupgrade", "path": "/xhost", "host": SNI},
    "grpc": {"type": "grpc", "service_name": "xhost", "authority": SNI},
}
NODE_TRANSPORTS = {
    "tcp": {"type": "tcp"},
    "ws": {"type": "ws", "path": "/xhost"},
    "httpupgrade": {"type": "httpupgrade", "path": "/xhost"},
    "grpc": {"type": "grpc", "service_name": "xhost"},
}


def spec_socks(m):
    user = {"username": "x" + secrets.token_hex(4), "password": secrets.token_hex(16)}
    return Spec({"version": "5"}, user, {"version": "5", "auth": user})


def spec_http(tls):
    def build(m):
        user = {"username": "x" + secrets.token_hex(4), "password": secrets.token_hex(16)}
        node, client = {}, {"auth": user}
        if tls:
            node["tls"] = {"cert_pem": m.chain, "key_pem": m.key}
            client["tls"] = tls_client(m)
        return Spec(node, user, client)
    return build


def spec_shadowsocks(method):
    def build(m):
        password = secrets.token_hex(16)
        return Spec({"method": method}, {"password": password}, {"$flat": True, "method": method, "password": password})
    return build


def spec_ss2022(method, eih=False):
    def build(m):
        size = 16 if method == "2022-blake3-aes-128-gcm" else 32
        user = b64(secrets.token_bytes(size))
        node = {"method": method}
        client = {"$flat": True, "method": method, "key": user, "identity_keys": []}
        if eih:
            identity = b64(secrets.token_bytes(size))
            node["identity_key"] = identity
            client["identity_keys"] = [identity]
        return Spec(node, {"key": user}, client)
    return build


def spec_ssr(method, protocol, obfs):
    def build(m):
        password = secrets.token_hex(16)
        common = {"method": method, "protocol": protocol, "obfs": obfs, "allow_insecure": True}
        return Spec(dict(common), {"password": password}, {**common, "password": password})
    return build


def spec_trojan(transport):
    def build(m):
        password = secrets.token_hex(16)
        return Spec({"security": typed_tls_node(m), "transport": NODE_TRANSPORTS[transport]}, {"password": password}, {"password": password, "security": typed_tls_client(m), "transport": TRANSPORTS[transport]})
    return build


def spec_vmess(transport, tls=True, cipher="aes-128-gcm"):
    def build(m):
        identity = str(uuid.uuid4())
        client = {"uuid": identity, "security": cipher, "transport": TRANSPORTS[transport]}
        node = {"transport": NODE_TRANSPORTS[transport]}
        if tls:
            node["security"] = typed_tls_node(m)
            client["tls"] = typed_tls_client(m)
        else:
            node["security"] = {"type": "none"}
            client["tls"] = {"type": "none"}
        return Spec(node, {"uuid": identity}, client)
    return build


def spec_vless(transport, flow="", client_extra=None, security="tls", encryption=False, alpn=None):
    def build(m):
        identity = str(uuid.uuid4())
        if isinstance(transport, str):
            client_transport, node_transport = TRANSPORTS[transport], NODE_TRANSPORTS[transport]
        else:
            client_transport, node_transport = transport, transport
        client = {"uuid": identity, "flow": flow, "transport": client_transport, **(client_extra or {})}
        node = {"transport": node_transport}
        origin = False
        if security == "tls":
            node["security"] = typed_tls_node(m)
            client["security"] = typed_tls_client(m, **({"alpn": alpn} if alpn else {}))
        elif security == "reality":
            private, public = x25519_pair()
            short = secrets.token_hex(4)
            node["security"] = {"type": "reality", "cover": {"host": "127.0.0.1", "port": "$origin"}, "private_key": b64url(private), "server_names": [SNI], "short_ids": [short]}
            client["security"] = {"type": "reality", "server_name": SNI, "public_key": b64url(public), "short_id": short}
            origin = True
        else:
            node["security"] = {"type": "none"}
            client["security"] = {"type": "none"}
        if encryption:
            private, public = x25519_pair()
            node["decryption"] = "mlkem768x25519plus.native.600s." + b64url(private)
            client["encryption"] = "mlkem768x25519plus.native.1rtt." + b64url(public)
        return Spec(node, {"uuid": identity, "flow": flow}, client, origin=origin)
    return build


def spec_anytls(m):
    password = secrets.token_hex(16)
    return Spec({"tls": tls_node(m)}, {"password": password}, {"password": password, "tls": tls_client(m)})


def spec_snell(client_version, node_version, **extra):
    def build(m):
        psk = secrets.token_hex(16)
        return Spec({"version": node_version, **extra}, {"psk": psk}, {"version": client_version, "psk": psk, **extra})
    return build


def spec_tuic(version, relay):
    def build(m):
        tls_c = tls_client(m, alpn=["h3"])
        node = {"version": version, "tls": tls_node(m, alpn=["h3"]), "congestion_control": "cubic"}
        client = {"version": version, "tls": tls_c, "udp_relay_mode": relay, "congestion_control": "cubic"}
        if version == 5:
            credential = {"uuid": str(uuid.uuid4()), "password": secrets.token_hex(16)}
        else:
            credential = {"token": secrets.token_hex(16)}
        client.update(credential)
        return Spec(node, credential, client)
    return build


def spec_hysteria1(transport, obfs):
    def build(m):
        auth = secrets.token_hex(16)
        extra = {"transport": transport}
        if obfs:
            extra["obfs"] = secrets.token_hex(12)
        return Spec({"tls": tls_node(m), **extra}, {"auth_str": auth}, {"auth_str": auth, "up_bps": 125000000, "down_bps": 125000000, "tls": tls_client(m), **extra})
    return build


def spec_hysteria2(salamander):
    def build(m):
        auth = secrets.token_hex(16)
        extra = {"salamander_password": secrets.token_hex(12)} if salamander else {}
        return Spec({"tls": tls_node(m), "udp": True, **extra}, {"auth": auth}, {"auth": auth, "tls": tls_client(m), **extra})
    return build


def spec_shadowquic(mode):
    def build(m):
        user = {"username": "x" + secrets.token_hex(4), "password": secrets.token_hex(16)}
        node = {"upstream": {"host": "127.0.0.1", "port": 443}, "server_name": SNI, "alpn": ["h3"], "quic_versions": ["v1"], "congestion_control": "cubic"}
        client = {**user, "server_name": SNI, "alpn": ["h3"], "quic_version": "v1", "udp_mode": mode, "congestion_control": "cubic"}
        return Spec(node, user, client)
    return build


def spec_mieru(mux):
    def build(m):
        user = {"username": "x" + secrets.token_hex(4), "password": secrets.token_hex(16)}
        traffic = {"low_entropy_mode": 0, "mask_rotation": 0, "max_padding": 32}
        return Spec({"transport": "tcp", "traffic": traffic}, user, {**user, "transport": "tcp", "multiplexing": mux, "traffic": traffic})
    return build


def spec_shadowtls(version):
    def build(m):
        outer = secrets.token_hex(16)
        key = b64(secrets.token_bytes(16))
        method = "2022-blake3-aes-128-gcm"
        node = {"version": version, "handshake": {"host": "127.0.0.1", "port": "$origin"}, "inner": {"type": "ss2022", "options": {"method": method}}}
        client = {"version": version, "tls": tls_client(m), "inner": {"type": "ss2022", "options": {"method": method, "key": key}}, "$inner_server": True}
        if version == 2:
            node["password"] = outer
        if version == 3:
            node["users"] = [{"password": outer}]
            client["strict"] = True
            node["strict"] = True
        if version != 1:
            client["password"] = outer
        return Spec(node, {"key": key}, client, origin=True)
    return build


def spec_trusttunnel(transport):
    def build(m):
        user = {"username": "x" + secrets.token_hex(4), "password": secrets.token_hex(16)}
        return Spec({"transport": transport, "tls": tls_node(m)}, user, {"transport": transport, "auth": user, "tls": tls_client(m), "app_name": "xhost"})
    return build


def spec_naive(transport):
    def build(m):
        user = {"username": "x" + secrets.token_hex(4), "password": secrets.token_hex(16)}
        return Spec({"tls": tls_node(m), "transports": [transport], "udp_over_tcp": True}, user, {**user, "tls": tls_client(m), "transport": transport, "udp_over_tcp": {"enabled": True, "version": 2}, "max_sessions": 16 if transport == "h1" else 1})
    return build


def spec_sudoku(mode, tls=False, multiplex="off"):
    def build(m):
        key = secrets.token_hex(16)
        protocol = {"aead": "chacha20-poly1305", "table_type": "prefer_entropy", "padding_min": 10, "padding_max": 30, "udp_enabled": True}
        node_mask, client_mask = {"mode": mode}, {"mode": mode}
        if tls:
            node_mask["tls"] = {"cert_pem": m.chain, "key_pem": m.key}
            client_mask["tls"] = tls_client(m)
            client_mask["host"] = SNI
        return Spec({"protocol": dict(protocol), "http_mask": node_mask}, {"key": key}, {"protocol": {**protocol, "key": key}, "http_mask": client_mask, "multiplex": multiplex})
    return build


def spec_wireguard(m):
    server_private, server_public = x25519_pair()
    client_private, client_public = x25519_pair()
    psk = b64(secrets.token_bytes(32))
    last = random.randint(2, 200)
    node = {"tunnel": {"private_key": b64(server_private), "addresses": ["10.77.0.1", "fd77::1"], "mtu": WG_MTU}}
    member = {"public_key": b64(client_public), "preshared_key": psk, "allowed_ips": [f"10.77.0.{last}/32", f"fd77::{last}/128"], "persistent_keepalive": 25}
    client = {"tunnel": {"private_key": b64(client_private), "addresses": [f"10.77.0.{last}", f"fd77::{last}"], "mtu": WG_MTU}, "peer": {"public_key": b64(server_public), "preshared_key": psk, "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keepalive": 25}, "$endpoint": True}
    return Spec(node, member, client)


def xhttp(mode, version):
    return {"type": "xhttp", "settings": {"path": "/xhost", "mode": mode, "http_version": version, "host": SNI}}


def xhttp_node(mode, version):
    return {"type": "xhttp", "settings": {"path": "/xhost", "mode": mode, "http_version": version}}


def spec_vless_xhttp(mode, version):
    def build(m):
        identity = str(uuid.uuid4())
        return Spec({"security": typed_tls_node(m), "transport": xhttp_node(mode, version)}, {"uuid": identity, "flow": ""}, {"uuid": identity, "flow": "", "security": typed_tls_client(m, alpn=["h3"] if version == "h3" else ["h2"]), "transport": xhttp(mode, version)})
    return build


CARRIERS = [
    Carrier("socks", "socks5-auth", spec_socks),
    Carrier("http", "plain", spec_http(False), udp=False),
    Carrier("http", "tls", spec_http(True), udp=False),
    Carrier("shadowsocks", "aes-128-gcm", spec_shadowsocks("aes-128-gcm"), uses_udp_listener=True),
    Carrier("shadowsocks", "chacha20-ietf-poly1305", spec_shadowsocks("chacha20-ietf-poly1305"), uses_udp_listener=True),
    Carrier("ss2022", "aes-128-gcm", spec_ss2022("2022-blake3-aes-128-gcm"), uses_udp_listener=True),
    Carrier("ss2022", "aes-256-gcm-eih", spec_ss2022("2022-blake3-aes-256-gcm", eih=True), uses_udp_listener=True),
    Carrier("ss2022", "chacha20-poly1305", spec_ss2022("2022-blake3-chacha20-poly1305"), uses_udp_listener=True),
    Carrier("shadowsocksr", "auth_aes128_sha1-tls1.2_ticket", spec_ssr("aes-256-cfb", "auth_aes128_sha1", "tls1.2_ticket_auth"), uses_udp_listener=True),
    Carrier("shadowsocksr", "auth_chain_a-plain", spec_ssr("none", "auth_chain_a", "plain"), uses_udp_listener=True),
    Carrier("trojan", "tcp-tls", spec_trojan("tcp")),
    Carrier("trojan", "ws-tls", spec_trojan("ws")),
    Carrier("trojan", "httpupgrade-tls", spec_trojan("httpupgrade")),
    Carrier("trojan", "grpc-tls", spec_trojan("grpc")),
    Carrier("vmess", "tcp-none", spec_vmess("tcp", tls=False)),
    Carrier("vmess", "tcp-tls", spec_vmess("tcp", cipher="chacha20-poly1305")),
    Carrier("vmess", "ws-tls", spec_vmess("ws")),
    Carrier("vmess", "httpupgrade-tls", spec_vmess("httpupgrade")),
    Carrier("vmess", "grpc-tls", spec_vmess("grpc")),
    Carrier("vless", "raw-tls", spec_vless("tcp")),
    Carrier("vless", "raw-tls-vision", spec_vless("tcp", flow="xtls-rprx-vision")),
    Carrier("vless", "raw-tls-xudp", spec_vless("tcp", client_extra={"packet_encoding": "xudp"})),
    Carrier("vless", "raw-tls-mux", spec_vless("tcp", client_extra={"mux": {"enabled": True, "tcp": True, "udp": True, "concurrency": 8, "max_connections": 4}})),
    Carrier("vless", "raw-reality", spec_vless("tcp", security="reality")),
    Carrier("vless", "raw-encryption", spec_vless("tcp", security="none", encryption=True)),
    Carrier("vless", "ws-tls", spec_vless("ws")),
    Carrier("vless", "httpupgrade-tls", spec_vless("httpupgrade")),
    Carrier("vless", "grpc-tls", spec_vless("grpc", alpn=["h2"])),
    Carrier("vless", "xhttp-h2-tls", spec_vless_xhttp("stream-up", "h2")),
    Carrier("vless", "xhttp-h3-tls", spec_vless_xhttp("stream-one", "h3"), uses_udp_listener=True, tcp_listener=False),
    Carrier("anytls", "tls", spec_anytls),
    Carrier("snell", "v6-default", spec_snell(6, 6)),
    Carrier("snell", "v4client-v5node", spec_snell(4, 5)),
    Carrier("snell", "v6-unshaped", spec_snell(6, 6, mode="unshaped")),
    Carrier("tuic", "v5-native", spec_tuic(5, "native"), uses_udp_listener=True, tcp_listener=False),
    Carrier("tuic", "v5-quic", spec_tuic(5, "quic"), uses_udp_listener=True, tcp_listener=False),
    Carrier("tuic", "v4-native", spec_tuic(4, "native"), uses_udp_listener=True, tcp_listener=False),
    Carrier("tuic", "v4-quic", spec_tuic(4, "quic"), uses_udp_listener=True, tcp_listener=False),
    Carrier("hysteria1", "udp", spec_hysteria1("udp", False), uses_udp_listener=True, tcp_listener=False),
    Carrier("hysteria1", "wechat-video-xplus", spec_hysteria1("wechat-video", True), uses_udp_listener=True, tcp_listener=False),
    Carrier("hysteria2", "quic", spec_hysteria2(False), uses_udp_listener=True, tcp_listener=False),
    Carrier("hysteria2", "salamander", spec_hysteria2(True), uses_udp_listener=True, tcp_listener=False),
    Carrier("shadowquic", "v1-datagram", spec_shadowquic("datagram"), uses_udp_listener=True, tcp_listener=False),
    Carrier("shadowquic", "v1-stream", spec_shadowquic("stream"), uses_udp_listener=True, tcp_listener=False),
    Carrier("mieru", "tcp-mux", spec_mieru(True)),
    Carrier("mieru", "tcp-nomux", spec_mieru(False)),
    Carrier("shadowtls", "v3-ss2022", spec_shadowtls(3), udp=False),
    Carrier("shadowtls", "v2-ss2022", spec_shadowtls(2), udp=False),
    Carrier("shadowtls", "v1-ss2022", spec_shadowtls(1), udp=False),
    Carrier("trusttunnel", "h1-tls", spec_trusttunnel("h1")),
    Carrier("trusttunnel", "h2-tls", spec_trusttunnel("h2")),
    Carrier("trusttunnel", "h3-tls", spec_trusttunnel("h3"), uses_udp_listener=True, tcp_listener=False),
    Carrier("naive", "h1-tls", spec_naive("h1")),
    Carrier("naive", "h2-tls", spec_naive("h2")),
    Carrier("naive", "h3-tls", spec_naive("h3"), uses_udp_listener=True, tcp_listener=False),
    Carrier("sudoku", "raw", spec_sudoku("raw")),
    Carrier("sudoku", "legacy", spec_sudoku("legacy")),
    Carrier("sudoku", "stream-tls", spec_sudoku("stream", tls=True)),
    Carrier("sudoku", "poll-tls", spec_sudoku("poll", tls=True)),
    Carrier("sudoku", "ws-tls", spec_sudoku("ws", tls=True)),
    Carrier("sudoku", "raw-mux", spec_sudoku("raw", multiplex="on")),
    Carrier("wireguard", "udp", spec_wireguard, uses_udp_listener=True, tcp_listener=False),
]


# ---------- 用例 ----------

@dataclass(frozen=True)
class Placement:
    client: str
    node: str
    target: str

    @property
    def label(self):
        return f"A={self.client},B={self.node},C={self.target}"


PLACEMENTS = (
    Placement("perf-01", "perf-02", "perf-03"),
    Placement("perf-02", "perf-03", "perf-01"),
    Placement("perf-03", "perf-01", "perf-02"),
)


def listen_addr(family, port):
    return f"[::]:{port}" if family == "ipv6" else f"0.0.0.0:{port}"


def resolve_placeholders(value, origin):
    if isinstance(value, dict):
        return {key: resolve_placeholders(item, origin) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_placeholders(item, origin) for item in value]
    return origin if value == "$origin" else value


def finish_client(client, host, port):
    client = dict(client)
    if client.pop("$flat", False):
        client.update(server=host, port=port)
    elif client.pop("$endpoint", False):
        client["endpoint"] = {"host": host, "port": port}
    elif client.pop("$inner_server", False):
        client["inner"] = {"type": client["inner"]["type"], "options": {**client["inner"]["options"], "server": host, "port": port}}
    else:
        client["server"] = {"host": host, "port": port}
    return client


def node_config(carrier, spec, port, family, origin):
    from config_v2 import bind_members

    node = {"tag": "node", "type": carrier.protocol, "listen": listen_addr(family, port), "outbound": "direct", "options": resolve_placeholders(spec.node, origin)}
    config = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [node], "limits": LIMITS}
    if spec.member is not None:
        bind_members(config, node, [spec.member])
    return config


def client_config(carrier, spec, host, port, socks_port, udp_port, target):
    inbounds = []
    if carrier.udp:
        inbounds.append({"tag": "udp", "type": "udp-forward", "listen": f"127.0.0.1:{udp_port}", "target": target, "outbound": "proxy"})
    return {
        "version": 2,
        "outbounds": [{"tag": "proxy", "type": carrier.protocol, "options": finish_client(spec.client, host, port)}],
        "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{socks_port}", "outbound": "proxy", "options": {"version": "5"}}],
        "inbounds": inbounds,
        "limits": LIMITS,
    }


def classify(result):
    error = result.get("error", "")
    for prefix, label in (("socks_reply_7", "未声明能力"), ("stall", "超时"), ("rpc_timeout", "超时"), ("eof", "连接中断"), ("digest", "内容不符"), ("content", "内容不符"), ("no_reply", "UDP无回包"), ("loss", "UDP丢包"), ("socks_", "SOCKS错误"), ("Connection", "连接中断"), ("AgentDied", "环境")):
        if error.startswith(prefix):
            return label
    return "其他" if error else ""


class Runner:
    def __init__(self, agents, material, args, scrubber):
        self.agents, self.material, self.args, self.scrubber = agents, material, args, scrubber
        self.results = []
        self.done = set()
        self.lock = threading.Lock()
        self.out = Path(args.out)
        self.unique = 0
        if args.resume and self.out.exists():
            self.results = json.loads(self.out.read_text(encoding="utf-8"))["results"]
            self.done = {self.record_key(item) for item in self.results if item["result"] != "fail" or not args.retry_failed}
            if args.retry_failed:
                self.results = [item for item in self.results if item["result"] != "fail"]

    @staticmethod
    def record_key(item):
        return (item["protocol"], item["carrier"], item["placement"], item["family"], item["case"])

    def record(self, protocol, carrier, placement, family, case, result, direction="kerlico->kerlico"):
        item = {
            "protocol": protocol, "carrier": carrier, "direction": direction, "network": self.args.network, "placement": placement, "family": family, "case": case,
            "result": result.get("status") or ("pass" if result.get("ok") else "fail"),
            "mib_s": result.get("mib_s"), "elapsed": result.get("elapsed"), "class": result.get("class") or classify(result),
            "detail": self.scrubber.clean(result.get("detail") or result.get("error") or ""),
        }
        if result.get("lost") is not None:
            item["lost"], item["resent"] = result.get("lost"), result.get("resent")
        with self.lock:
            self.results.append(item)
            self.flush()
        return item

    def flush(self):
        data = {"tool": "interop_cross_host", "binary_sha256": self.args.binary_sha256, "results": self.results}
        temporary = self.out.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        temporary.replace(self.out)

    def pending(self, protocol, carrier, placement, family, case):
        return (protocol, carrier, placement, family, case) not in self.done

    def name(self, label):
        with self.lock:
            self.unique += 1
            return f"{re.sub(r'[^a-zA-Z0-9]', '-', label)[:40]}-{self.unique}"

    def run_carrier(self, carrier, placement, family):
        cases = [name for name in self.args.tcp_cases if name in SIZES]
        udp_cases = [f"udp_{size}" for size in UDP_SIZES] + ["udp_socks5"] if carrier.udp and not self.args.no_udp else []
        if family == "ipv6":
            cases = [name for name in cases if name != "tcp_32m"]
            udp_cases = [name for name in udp_cases if name in ("udp_64", "udp_1200", "udp_socks5")]
        all_cases = cases + udp_cases + ["shutdown"]
        if not any(self.pending(carrier.protocol, carrier.name, placement.label, family, case) for case in all_cases):
            return
        A, B, C = self.agents[placement.client], self.agents[placement.node], self.agents[placement.target]
        record = lambda case, result: self.record(carrier.protocol, carrier.name, placement.label, family, case, result)
        addr = "v6" if family == "ipv6" else "v4"
        target_host, node_host = C.public[addr], B.public[addr]
        node_name, client_name, origin_name = self.name(carrier.key + "-node"), self.name(carrier.key + "-client"), None
        started_node = started_client = False
        try:
            for agent in (A, B, C):
                agent.ensure()
            spec = carrier.build(self.material)
            node_port, origin_port = B.call("alloc_ports", count=2)
            socks_port, udp_port = A.call("alloc_ports", count=2)
            if spec.origin:
                origin_name = self.name(carrier.key + "-origin")
                started = B.call("spawn_tls_origin", name=origin_name, port=origin_port, material={"cert": self.material.cert, "key": self.material.key})
                if not started["ok"]:
                    self.fail_all(record, all_cases, "环境", "伪装站启动失败", started.get("log", ""))
                    return
            wait = []
            if carrier.tcp_listener:
                wait.append(("tcp", node_port))
            if carrier.uses_udp_listener:
                wait.append(("udp", node_port))
            started = B.call("spawn_kerlico", name=node_name, config=node_config(carrier, spec, node_port, family, origin_port), wait_ports=wait)
            if not started["ok"]:
                self.fail_all(record, all_cases, "配置" if started["stage"] == "check" else "节点启动失败", started["stage"], started.get("log", ""))
                return
            started_node = True
            target = {"host": target_host, "port": C.echo_port}
            config = client_config(carrier, spec, node_host, node_port, socks_port, udp_port, target)
            wait = [("tcp", socks_port)] + ([("udp", udp_port)] if carrier.udp else [])
            started = A.call("spawn_kerlico", name=client_name, config=config, wait_ports=wait)
            if not started["ok"]:
                self.fail_all(record, all_cases, "配置" if started["stage"] == "check" else "客户端启动失败", started["stage"], started.get("log", ""))
                return
            started_client = True
            failed_tcp = 0
            for case in cases:
                if not self.pending(carrier.protocol, carrier.name, placement.label, family, case):
                    continue
                if failed_tcp >= 2 and case == "tcp_32m":
                    record(case, {"status": "skip", "class": "前序失败", "detail": "前两个 TCP 用例已失败"})
                    continue
                if case == "tcp_32m":
                    result = A.call("tcp_watch", socks=socks_port, host=target_host, port=C.echo_port, size=SIZES[case], timeout=1500)
                else:
                    result = A.call("tcp_socks", socks=socks_port, host=target_host, port=C.echo_port, size=SIZES[case], timeout=400)
                if not result["ok"]:
                    failed_tcp += 1
                    result["detail"] = result.get("error", "") + " | " + self.logs_tail(A, client_name, B, node_name)
                record(case, result)
            for case in udp_cases:
                if not self.pending(carrier.protocol, carrier.name, placement.label, family, case):
                    continue
                if case == "udp_socks5":
                    result = A.call("udp_socks", socks=socks_port, host=target_host, port=C.echo_port, size=64, count=5, timeout=120)
                    if result.get("error") == "socks_reply_7":
                        result.update(status="na", detail="出站不提供多目标 UDP 关联，SOCKS5 UDP ASSOCIATE 返回命令不支持")
                else:
                    size = int(case.split("_")[1])
                    result = A.call("udp_forward", port=udp_port, size=size, count=10 if size == 64 else 5, timeout=120)
                if not result["ok"] and "status" not in result:
                    result["detail"] = result.get("error", "") + " | " + self.logs_tail(A, client_name, B, node_name)
                record(case, result)
            stopped_client = A.call("stop", name=client_name, timeout=60)
            started_client = False
            stopped_node = B.call("stop", name=node_name, timeout=60)
            started_node = False
            clean = stopped_client["rc"] == 0 and stopped_node["rc"] == 0
            detail = "" if clean else f"exit client={stopped_client['rc']} node={stopped_node['rc']} | client: {stopped_client['log'][-300:]} ; node: {stopped_node['log'][-300:]}"
            record("shutdown", {"ok": clean, "error": detail, "elapsed": stopped_client["elapsed"] + stopped_node["elapsed"], "class": "" if clean else "退出异常"})
        except AgentError as error:
            self.fail_all(record, all_cases, "环境", str(error), "", only_missing=True)
        finally:
            for agent, name, active in ((A, client_name, started_client), (B, node_name, started_node), (B, origin_name, origin_name is not None)):
                if active and agent.alive():
                    try:
                        agent.call("stop", name=name, timeout=30)
                    except AgentError:
                        pass

    def logs_tail(self, A, client_name, B, node_name):
        try:
            client_log = A.call("alive", name=client_name, timeout=30)
            node_log = B.call("alive", name=node_name, timeout=30)
        except AgentError:
            return ""
        parts = []
        for label, state in (("client", client_log), ("node", node_log)):
            alive = "" if state["alive"] else "(已退出)"
            tail = state["log"].strip().splitlines()[-2:]
            parts.append(f"{label}{alive}: " + " / ".join(line[-240:] for line in tail))
        return " ; ".join(parts)

    def fail_all(self, record, cases, klass, stage, log, only_missing=False):
        detail = f"{stage}: {log.strip()[-400:]}"
        for case in cases:
            record(case, {"ok": False, "class": klass, "detail": detail})


def probe(agents, scrubber, network):
    """直连基线：同一套收发代码走裸路径，给矩阵的吞吐和 UDP 包长一个上限参照。"""
    report = []
    for src, dst in [(a, b) for a in MACHINES for b in MACHINES if a != b]:
        S, D = agents[src], agents[dst]
        for family in ("v4", "v6"):
            host = D.networks[network].get(family)
            if not host or not S.networks[network].get(family):
                report.append({"network": network, "path": f"{src}->{dst}", "family": family, "skip": "无地址"})
                continue
            row = {"network": network, "path": f"{src}->{dst}", "family": family}
            row["tcp_small"] = S.call("tcp_direct", host=host, port=D.echo_port, size=64)
            if row["tcp_small"]["ok"]:
                row["tcp_32m"] = S.call("tcp_direct", host=host, port=D.echo_port, size=32 << 20)
            row["udp_64"] = S.call("udp_direct", host=host, port=D.echo_port, size=64, count=5)
            if row["udp_64"]["ok"]:
                for size in (1200, 1252, 1400):
                    row[f"udp_{size}"] = S.call("udp_direct", host=host, port=D.echo_port, size=size, count=5)
            report.append(row)
            print(scrubber.clean(json.dumps(row, ensure_ascii=False)), flush=True)
    return report


# ---------- 仅出站真实对端与 TUN ----------

PEER_DIR = f"{ROOT}/peers"
IMAGE_SSHD = "xhost-sshd:1"
IMAGE_OPENVPN = "xhost-openvpn:1"
IMAGE_OCSERV = "xhost-ocserv:1"
IMAGE_DEBIAN = "xhost-debian:1"
IMAGE_ZEROTIER = "xhost-zerotier:1"
IMAGE_HEADSCALE = "headscale/headscale:0.27.1"
IMAGE_TAILSCALE = "tailscale/tailscale:v1.92.3"
SSH_PASSWORD = "synthetic-ssh-fixture"
XRAY_COMMIT = "0afec66"
TOR_CHECK_HOST = "check.torproject.org"
TOR_ONION = "hjirlp6fu47kox4cnede4zlvaeq672bibss3oxgmsnsc5mdxygqshbqd.onion"
# 约 1 MiB 的固定版本静态文件，直连与经 Tor 各取一次比对摘要；前者不通就换下一个。
TOR_DOWNLOADS = (("cdn.jsdelivr.net", "/npm/react-dom@18.3.1/umd/react-dom.development.js"), ("unpkg.com", "/react-dom@18.3.1/umd/react-dom.development.js"), ("proof.ovh.net", "/files/1Mb.dat"))
OUTBOUND_UDP = (64, 1200, 1252)
DIRECTION = "kerlico->真实对端"

# 只需在 B 上运行的镜像放 perf-01、perf-02；perf-03 磁盘小，只放体积小的三个。
PREPARE_IMAGES = (
    (IMAGE_SSHD, MACHINES, "FROM debian:13-slim\nRUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/* && useradd --create-home --shell /usr/sbin/nologin proxy-test && printf '%s\\n' 'proxy-test:" + SSH_PASSWORD + "' | chpasswd && mkdir -p /run/sshd\nENTRYPOINT [\"/usr/sbin/sshd\", \"-D\", \"-e\", \"-f\", \"/keys/sshd_config\"]\n"),
    (IMAGE_OPENVPN, MACHINES, "FROM alpine:3.21\nRUN apk add --no-cache openvpn iptables\n"),
    (IMAGE_OCSERV, MACHINES, "FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends ocserv iptables && rm -rf /var/lib/apt/lists/*\n"),
    (IMAGE_DEBIAN, ("perf-01", "perf-02"), "FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*\n"),
    (IMAGE_ZEROTIER, ("perf-01", "perf-02"), "FROM zerotier/zerotier:1.14.2\nENTRYPOINT []\nRUN (apt-get update && apt-get install -y --no-install-recommends iptables) || apk add --no-cache iptables\n"),
)
PREPARE_BASES = ("debian:13-slim", "alpine:3.21", "debian:bookworm-slim", "zerotier/zerotier:1.14.2")
# （文件名, 版本命令, 版本中必须出现的文本, 放到 peers 下的相对路径, 目标机器）；来源从 worker 旧工作目录按版本查找。
PREPARE_BINARIES = (
    ("gost", "-V", "gost", "gost", MACHINES),
    ("xray", "version", XRAY_COMMIT, "xray", ("perf-01", "perf-02")),
    ("easytier-core", "--version", "2.6.4", "easytier/easytier-core", ("perf-01", "perf-02")),
)


class PeerFailed(RuntimeError):
    def __init__(self, klass, detail):
        super().__init__(detail)
        self.klass, self.detail = klass, detail


@dataclass
class Peer:
    kind: str
    options: dict
    udp: bool = False
    limits: dict = field(default_factory=dict)
    ready_wait: float = 40.0
    target: tuple | None = None
    placement: str | None = None
    note: str = ""
    custom: object = None
    diag: object = None
    after: object = None


@dataclass(frozen=True)
class Real:
    protocol: str
    carrier: str
    start: object
    placements: tuple = (0, 1, 2)
    ipv6: bool = False

    @property
    def key(self):
        return f"{self.protocol}/{self.carrier}"


class Bench:
    """一次对端启动占用的资源；close 逆序回收，异常路径也走这里。"""

    def __init__(self, runner, placement, family, label):
        self.material = runner.material
        self.A, self.B, self.C = runner.agents[placement.client], runner.agents[placement.node], runner.agents[placement.target]
        self.placement, self.family = placement, family
        self.addr = "v6" if family == "ipv6" else "v4"
        self.label = re.sub(r"[^a-zA-Z0-9]", "-", label)[:24] + "-" + secrets.token_hex(3)
        self.undo = []
        self.watched = []

    def host(self, agent):
        return agent.public[self.addr]

    def port(self, agent, count=1):
        ports = agent.call("alloc_ports", count=count)
        return ports[0] if count == 1 else ports

    def shell(self, agent, script, limit=120, stdin=None):
        result = agent.call("sh", script=script, limit=limit, stdin=stdin, timeout=limit + 30)
        if result["rc"]:
            raise PeerFailed("环境", f"命令失败 rc={result['rc']}: {script[:120]} | {result['stderr'][-400:]}{result['stdout'][-200:]}")
        return result["stdout"]

    def fixture(self, agent, name, files, mode=0o600):
        directory = agent.call("fixture", label=f"{self.label}-{name}", files=files, mode=mode)
        if not any(entry[1] == "fixture" and entry[2] == directory for entry in self.undo):
            self.undo.append((agent, "fixture", directory))
        return directory

    def process(self, agent, name, argv, wait_ports=(), wait=25.0):
        name = f"{self.label}-{name}"
        self.undo.append((agent, "process", name))
        self.watched.append((agent, "process", name))
        started = agent.call("spawn_raw", name=name, argv=argv, wait_ports=list(wait_ports), wait=wait)
        if not started["ok"]:
            raise PeerFailed("对端启动失败", f"{name} {started.get('stage')}: {started.get('log', '')[-600:]}")
        return name

    def container(self, agent, name, image, flags, command=()):
        name = f"xhost-{self.label}-{name}"
        self.undo.append((agent, "container", name))
        self.watched.append((agent, "container", name))
        started = agent.call("container_up", name=name, image=image, flags=list(flags), command=list(command))
        if not started["ok"]:
            raise PeerFailed("对端启动失败", f"容器 {name}: {started.get('log', '')[-600:]}")
        return name, started["ip"], started["gateway"]

    def relay(self, agent, kind, host, port, bind="::", listen=None):
        listen = listen or self.port(agent)
        name = f"{self.label}-relay-{kind}-{listen}"
        self.undo.append((agent, "process", name))
        started = agent.call("spawn_relay", name=name, kind=kind, listen=listen, host=host, port=port, bind=bind)
        if not started["ok"]:
            raise PeerFailed("环境", f"转发启动失败: {started.get('log', '')[-300:]}")
        return listen

    def wait(self, agent, ports, budget):
        result = agent.call("wait_ports", ports=list(ports), wait=budget, timeout=budget + 30)
        if not result["ok"]:
            raise PeerFailed("对端启动失败", f"端口未就绪 {result['pending']} | {self.peer_log()}")

    def peer_log(self):
        parts = []
        for agent, kind, name in self.watched:
            try:
                if kind == "container":
                    parts.append(agent.call("container_log", name=name, timeout=40)[-500:])
                else:
                    parts.append(agent.call("alive", name=name, timeout=30)["log"][-500:])
            except AgentError:
                pass
        return " ; ".join(item.strip().replace("\n", " / ") for item in parts)[-900:]

    def close(self):
        for agent, kind, name in reversed(self.undo):
            if not agent.alive():
                continue
            try:
                if kind == "process":
                    agent.call("stop", name=name, grace=5.0, timeout=30)
                elif kind == "container":
                    agent.call("container_down", name=name, timeout=70)
                elif kind == "netns":
                    agent.call("netns_down", name=name, timeout=40)
                else:
                    agent.call("sh", script=f"rm -rf '{name}'", timeout=40)
            except AgentError:
                pass
        self.undo = []


def need_v4(bench):
    if bench.addr != "v4":
        raise PeerFailed("环境", "该对端只测 IPv4 路径")


def real_ssh(auth):
    def start(bench):
        B = bench.B
        port = bench.port(B)
        config = f"Port {port}\nListenAddress 0.0.0.0\nListenAddress ::\nHostKey /keys/host\nPidFile /tmp/xhost-sshd.pid\nPasswordAuthentication yes\nPubkeyAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nPermitEmptyPasswords no\nAllowUsers proxy-test\nAuthorizedKeysFile none\nAuthorizedKeysCommand /bin/cat /keys/authorized_keys\nAuthorizedKeysCommandUser root\nAllowTcpForwarding local\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\nForceCommand /bin/false\nUseDNS no\nMaxStartups 50\nPerSourcePenalties no\n"
        directory = bench.fixture(B, "sshd", {"sshd_config": config})
        pin = bench.shell(B, f"cd '{directory}' && ssh-keygen -q -t {auth['host']} -N '' -C '' -f host && ssh-keygen -q -t {auth['user']} -N '' -C '' -f user && cp user.pub authorized_keys && ssh-keygen -l -E sha256 -f host.pub").split()[1]
        bench.container(B, "sshd", IMAGE_SSHD, ["--network", "host", "--mount", f"type=bind,src={directory},dst=/keys,readonly"])
        bench.wait(B, [("tcp", port)], 20)
        credential = {"type": "password", "password": SSH_PASSWORD} if auth["method"] == "password" else {"type": "publickey", "private_key_pem": B.call("read_file", path=f"{directory}/user")}
        return Peer("ssh", {"server": {"host": bench.host(B), "port": port}, "username": "proxy-test", "host_key_sha256": [pin], "auth": credential})
    return start


def real_gost(listener, mux, tls, mode="eager"):
    def start(bench):
        B = bench.B
        port = bench.port(B)
        username, password = "x" + secrets.token_hex(4), secrets.token_hex(16)
        listener_config = {"type": listener}
        if mux:
            # 固定 GOST 的 GetInt 接受 string/int，JSON number 的 float64 会被忽略。
            listener_config["metadata"] = {"mux.version": "1", "mux.keepaliveDisabled": True}
        options = {"server": {"host": bench.host(B), "port": port}, "username": username, "password": password, "mux": mux, "response_mode": mode}
        files = {}
        if tls:
            files = {"cert.pem": bench.material.chain, "key.pem": bench.material.key}
            options["tls"] = {"server_name": SNI, "ca_pem": bench.material.ca}
        else:
            options["allow_insecure"] = True
        directory = bench.fixture(B, "gost", files)
        if tls:
            listener_config["tls"] = {"certFile": f"{directory}/cert.pem", "keyFile": f"{directory}/key.pem"}
        config = {"services": [{"name": "relay", "addr": f":{port}", "handler": {"type": "relay", "auth": {"username": username, "password": password}, "metadata": {"nodelay": mode == "eager"}}, "listener": listener_config}], "log": {"level": "error"}}
        bench.fixture(B, "gost", {"gost.json": json.dumps(config)})
        bench.process(B, "gost", [f"{PEER_DIR}/gost", "-C", f"{directory}/gost.json"], [("tcp", port)])
        return Peer("gost-relay", options, udp=True)
    return start


def tor_cases(runner, bench, socks, record):
    A = bench.A
    result = A.call("http_socks", socks=socks, host=TOR_CHECK_HOST, port=443, path="/api/ip", contains='"IsTor":true', limit=4096, timeout=400)
    record("https_check_torproject", result)
    result = A.call("http_socks", socks=socks, host=TOR_ONION, port=80, path="/", tls=False, contains="Arti", limit=1 << 20, stall=180.0, timeout=400)
    if not result["ok"] and result.get("error", "").startswith("socks_reply"):
        result["class"] = "onion不可达"
    record("onion_v3", result)
    # 每条流独立电路，出口拒绝或超时不代表下一条也失败，所以逐站多试。
    attempts = []
    for host, path in TOR_DOWNLOADS:
        baseline = A.call("http_direct", host=host, port=443, path=path, limit=1 << 21, timeout=120)
        if not baseline["ok"] or baseline["bytes"] < 1 << 19:
            attempts.append(f"{host} 直连不可用 {baseline.get('error', baseline.get('bytes'))}")
            continue
        for _ in range(3):
            started = time.monotonic()
            result = A.call("http_socks", socks=socks, host=host, port=443, path=path, limit=1 << 21, stall=120.0, timeout=420)
            if result["ok"] and result["sha256"] != baseline["sha256"]:
                record("https_download_1m", {**result, "ok": False, "error": "digest_mismatch", "class": "内容不符", "detail": f"{host} 摘要与直连不同"})
                return
            if result["ok"]:
                record("https_download_1m", {**result, "detail": f"{host} {result['bytes']} 字节，摘要与直连一致；此前失败 {attempts}" if attempts else f"{host} {result['bytes']} 字节，摘要与直连一致"})
                return
            attempts.append(f"{host} {result.get('error')} {round(time.monotonic() - started)}s")
    record("https_download_1m", {"ok": False, "class": "Tor出口或站点", "detail": "; ".join(attempts)})


def real_tor(bench):
    need_v4(bench)
    return Peer("tor", {"data_directory": "state/tor", "bootstrap_timeout_ms": 300000}, limits={"connect_timeout_ms": 300000, "idle_timeout_ms": 120000}, custom=tor_cases, placement=f"A={bench.placement.client},B=tor网络,C={TOR_CHECK_HOST}", note="真实 Tor 网络，目标为公网站点")


def real_masque(relayed):
    def start(bench):
        need_v4(bench)
        A, B = bench.A, bench.B
        port = bench.port(B)
        username, password = "x" + secrets.token_hex(4), secrets.token_hex(16)
        directory = bench.fixture(B, "xray", {"cert.pem": bench.material.chain, "key.pem": bench.material.key})
        listen = "127.0.0.1" if relayed else "0.0.0.0"
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": listen, "port": port, "protocol": "masque", "settings": {"users": [{"email": username, "pass": password}], "address": ["10.89.0.1/24", "fd89::1/120"], "mtu": 1280}, "streamSettings": {"network": "masque", "security": "tls", "tlsSettings": {"serverName": SNI, "alpn": ["h3"], "certificates": [{"certificateFile": f"{directory}/cert.pem", "keyFile": f"{directory}/key.pem"}]}, "masqueSettings": {"host": SNI, "path": "/"}}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        }
        bench.fixture(B, "xray", {"xray.json": json.dumps(config)})
        bench.process(B, "xray", [f"{PEER_DIR}/xray", "run", "-config", f"{directory}/xray.json"], [("udp", port)])
        host, note = bench.host(B), "kerlico 直接走 Mesh：QUIC 路径 MTU 下限 1350 高于 Mesh MTU 1300 且置 DF，隧道建立失败属环境限制，本用例用来留存这条证据"
        if relayed:
            # QUIC 路径 MTU 下限 1350，高于 Mesh 的 1300，且 QUIC 套接字置 DF。两端回环套接字接用户态转发，由转发关闭 DF，靠内核分片过 Mesh。
            middle = bench.relay(B, "udp", "127.0.0.1", port, bind=bench.host(B))
            port = bench.relay(A, "udp", bench.host(B), middle, bind="127.0.0.1")
            host, note = "127.0.0.1", "Mesh MTU 1300 低于 QUIC 路径 MTU 下限 1350：A、B 两端回环接用户态转发，Mesh 段由内核 IP 分片"
        return Peer("masque", {"server": {"host": host, "port": port}, "auth": {"username": username, "password": password}, "tls": {"server_name": SNI, "ca_pem": bench.material.ca}}, udp=True, note=note)
    return start


def openvpn_pki(bench, agent, directory):
    script = f"""set -e
cd '{directory}'
ssl() {{ openssl "$@" >/dev/null 2>&1; }}
ssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -subj /CN=xhost-ca -days 3
issue() {{
  ssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1"
  echo "extendedKeyUsage=$2" > "$1.ext"
  ssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 3 -extfile "$1.ext" -out "$1.crt"
}}
issue server serverAuth
issue client clientAuth
"""
    bench.shell(agent, script)
    return {name: agent.call("read_file", path=f"{directory}/{name}") for name in ("ca.crt", "client.crt", "client.key")}


def real_openvpn(proto, wrap, cipher, auth):
    def start(bench):
        need_v4(bench)
        B = bench.B
        username, password = "x" + secrets.token_hex(4), secrets.token_hex(16)
        static = "-----BEGIN OpenVPN Static key V1-----\n" + "\n".join(secrets.token_hex(16) for _ in range(16)) + "\n-----END OpenVPN Static key V1-----\n"
        lines = ["dev tun", "topology subnet", "server 10.8.0.0 255.255.255.0", "port 1194", "proto tcp-server" if proto == "tcp" else "proto udp", "ca /keys/ca.crt", "cert /keys/server.crt", "key /keys/server.key", "dh none", "verb 3", f"data-ciphers {cipher}", "keepalive 10 60"]
        if wrap == "crypt":
            lines.append("tls-crypt /keys/static.key")
        elif wrap == "auth":
            lines.append("tls-auth /keys/static.key 0")
        if auth in ("password", "both"):
            lines += ["script-security 3", "auth-user-pass-verify /keys/check.sh via-env"]
        if auth == "password":
            lines.append("verify-client-cert none")
        entry = "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE\nexec openvpn --config /keys/server.conf\n"
        check = f'#!/bin/sh\n[ "$username" = "{username}" ] && [ "$password" = "{password}" ]\n'
        directory = bench.fixture(B, "openvpn", {"server.conf": "\n".join(lines) + "\n", "static.key": static, "entry.sh": entry, "check.sh": check})
        bench.shell(B, f"chmod 700 '{directory}/check.sh'")
        pki = openvpn_pki(bench, B, directory)
        _, address, _ = bench.container(B, "openvpn", IMAGE_OPENVPN, ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--mount", f"type=bind,src={directory},dst=/keys,readonly"], ["sh", "/keys/entry.sh"])
        port = bench.relay(B, proto, address, 1194)
        # kerlico 的隧道 MTU 默认 1400；用户态栈不处理回传的 ICMP，内层包超过 Mesh MTU 会被丢弃，所以显式降到 1280。
        options = {"remote": {"host": bench.host(B), "port": port}, "proto": proto, "ca_pem": pki["ca.crt"], "ciphers": [cipher], "verify_x509_name": "server", "mtu": 1280}
        if auth in ("certificate", "both"):
            options.update(cert_pem=pki["client.crt"], key_pem=pki["client.key"])
        if auth in ("password", "both"):
            options.update(username=username, password=password)
        if wrap == "crypt":
            options["tls_crypt_key"] = static
        elif wrap == "auth":
            options["tls_auth"] = {"key": static, "direction": 1}
        return Peer("openvpn", options, udp=True, note="OpenVPN 容器在 B 的默认桥接，kerlico 经 B 上的用户态转发接入，隧道出口 NAT 后到 C", ready_wait=45)
    return start


OCSERV_CONFIG = """auth = "plain[passwd=/cfg/passwd]"
tcp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /run/ocserv-socket
server-cert = /cfg/server.pem
server-key = /cfg/server.key
isolate-workers = false
max-clients = 16
max-same-clients = 8
keepalive = 30
dpd = 60
mobile-dpd = 60
try-mtu-discovery = false
auth-timeout = 240
cookie-timeout = 300
rekey-time = 172800
rekey-method = ssl
use-occtl = false
pid-file = /run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = 192.168.77.0/24
ipv6-network = fd77:77::/48
ipv6-subnet-prefix = 64
route = default
ping-leases = false
cisco-client-compat = false
"""


def real_openconnect(bench):
    need_v4(bench)
    B = bench.B
    username, password = "x" + secrets.token_hex(4), secrets.token_hex(16)
    entry = "iptables -t nat -A POSTROUTING -s 192.168.77.0/24 -o eth0 -j MASQUERADE\n# 隧道 MTU 由 ocserv 决定且不低于 1280；用户态栈不处理回传 ICMP，按转发路径钳位 TCP MSS。\niptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200\nexec ocserv -f -d 1 -c /cfg/ocserv.conf\n"
    directory = bench.fixture(B, "ocserv", {"ocserv.conf": OCSERV_CONFIG, "server.pem": bench.material.chain, "server.key": bench.material.key, "entry.sh": entry}, mode=0o644)
    digest = bench.shell(B, "openssl passwd -5 -stdin", stdin=password).strip()
    bench.fixture(B, "ocserv", {"passwd": f"{username}:*:{digest}\n"}, mode=0o644)
    _, address, _ = bench.container(B, "ocserv", IMAGE_OCSERV, ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--mount", f"type=bind,src={directory},dst=/cfg,readonly"], ["sh", "/cfg/entry.sh"])
    port = bench.relay(B, "tcp", address, 443)
    return Peer("openconnect", {"server": {"host": bench.host(B), "port": port}, "username": username, "password": password, "tls": {"server_name": SNI, "ca_pem": bench.material.ca}}, udp=True, note="ocserv 容器在 B 的默认桥接，kerlico 经 B 上的用户态转发接入，隧道出口 NAT 后到 C", ready_wait=45)


def real_tailscale(direct):
    def start(bench):
        need_v4(bench)
        B = bench.B
        control_port, stun_port, metrics_port, grpc_port = bench.port(B, 4)
        host = bench.host(B)
        control = f"https://{host}:{control_port}"
        config = {
            "server_url": control, "listen_addr": f"0.0.0.0:{control_port}", "metrics_listen_addr": f"127.0.0.1:{metrics_port}", "grpc_listen_addr": f"127.0.0.1:{grpc_port}",
            "tls_cert_path": "/work/tls.crt", "tls_key_path": "/work/tls.key", "noise": {"private_key_path": "/var/lib/headscale/noise.key"},
            "prefixes": {"v4": "100.64.0.0/24", "v6": "fd7a:115c:a1e0::/48", "allocation": "sequential"},
            "derp": {"server": {"enabled": True, "region_id": 999, "region_code": "local", "region_name": "local", "stun_listen_addr": f"0.0.0.0:{stun_port}", "private_key_path": "/var/lib/headscale/derp.key", "automatically_add_embedded_derp_region": True}, "urls": [], "paths": [], "auto_update_enabled": False},
            "database": {"type": "sqlite", "sqlite": {"path": "/var/lib/headscale/db.sqlite"}},
            "dns": {"magic_dns": False, "base_domain": "tail.test", "override_local_dns": False, "nameservers": {"global": []}},
            "unix_socket": "/var/lib/headscale/headscale.sock",
            "log": {"level": "info"},
        }
        directory = bench.fixture(B, "tailscale", {"headscale.yaml": json.dumps(config), "ext.cnf": f"subjectAltName=IP:{host}\n"}, mode=0o644)
        bench.shell(B, f"""set -e
cd '{directory}'
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=xhost-ts-ca -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=headscale -keyout tls.key -out tls.csr 2>/dev/null
openssl x509 -req -in tls.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out tls.crt 2>/dev/null
chmod 644 *
""")
        ca = B.call("read_file", path=f"{directory}/ca.pem")
        headscale, _, _ = bench.container(B, "headscale", IMAGE_HEADSCALE, ["--network", "host", "-v", f"{directory}:/work:ro", "--tmpfs", "/var/lib/headscale"], ["serve", "-c", "/work/headscale.yaml"])
        bench.wait(B, [("tcp", control_port)], 40)

        def hs(*argv):
            result = B.call("container_exec", name=headscale, argv=["headscale", "-c", "/work/headscale.yaml", *argv])
            if result["rc"]:
                raise PeerFailed("对端启动失败", f"headscale {argv[:2]}: {result['stderr'][-400:]}")
            return result["stdout"]

        hs("users", "create", "xhost")
        user = json.loads(hs("users", "list", "-o", "json"))[0]["id"]
        peer_key, kerlico_key = [json.loads(hs("preauthkeys", "create", "-u", str(user), "-e", "1h", "-o", "json"))["key"] for _ in range(2)]
        peer, _, _ = bench.container(B, "tspeer", IMAGE_TAILSCALE, ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--sysctl", "net.ipv6.conf.all.forwarding=1", "-e", "SSL_CERT_FILE=/work/ca.pem", "-v", f"{directory}:/work:ro", "--entrypoint", "tailscaled"], ["--state=mem:", "--socket=/tmp/ts.sock"])
        up = None
        for _ in range(10):
            # 官方客户端默认的 ts-input 丢弃非 tailscale0 进来的 CGNAT 来源包，Mesh 地址在该网段，控制面与 DERP 连接都会断，所以关闭它的 netfilter，NAT 由 entry 自行配置。
            up = B.call("container_exec", name=peer, argv=["tailscale", "--socket=/tmp/ts.sock", "up", f"--login-server={control}", f"--authkey={peer_key}", "--hostname=peer", "--advertise-exit-node", "--accept-dns=false", "--netfilter-mode=off", "--timeout=40s"], limit=70, timeout=90)
            if up["rc"] == 0:
                break
            time.sleep(2)
        if up["rc"]:
            raise PeerFailed("对端启动失败", f"tailscale up: {up['stderr'][-500:]}")
        nodes = json.loads(hs("nodes", "list", "-o", "json"))
        node = next(item for item in nodes if item["given_name"] == "peer")
        hs("nodes", "approve-routes", "-i", str(node["id"]), "-r", "0.0.0.0/0,::/0")
        masq = B.call("container_exec", name=peer, argv=["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
        if masq["rc"]:
            raise PeerFailed("对端启动失败", f"iptables: {masq['stderr'][-300:]}")
        # 官方出口节点的包过滤不放行 CGNAT 目标（日志 destination not allowed），Mesh 地址在该网段，所以目标用 B 主地址上的转发，再到 C。
        # UDP 绑定具体地址：通配绑定时回包来源是网桥地址，出口节点的 conntrack 匹配不上。
        target_host, target_port = B.call("primary_v4"), bench.port(B)
        bench.relay(B, "tcp", bench.host(bench.C), bench.C.echo_port, bind=target_host, listen=target_port)
        bench.relay(B, "udp", bench.host(bench.C), bench.C.echo_port, bind=target_host, listen=target_port)
        options = {"control_url": control, "auth_key": kerlico_key, "hostname": "kerlico", "direct": direct, "ca_pem": ca, "state_file": "ts-state.json", "exit_node": "peer"}

        def diag():
            status = json.loads(B.call("container_exec", name=peer, argv=["tailscale", "--socket=/tmp/ts.sock", "status", "--json"])["stdout"])
            views = [{key: item.get(key) for key in ("HostName", "Online", "Relay", "CurAddr", "RxBytes", "TxBytes", "ExitNodeOption")} for item in (status.get("Peer") or {}).values()]
            probe = B.call("container_exec", name=peer, argv=["sh", "-c", f"(echo probe; sleep 2) | timeout 5 nc {target_host} {target_port}"], limit=20)
            nodes = hs("nodes", "list", "-o", "json")
            routes = [(item.get("given_name"), item.get("available_routes"), item.get("approved_routes")) for item in json.loads(nodes)]
            return json.dumps({"peers": views, "self_online": status.get("Self", {}).get("Online"), "probe_echo": probe["stdout"].strip(), "routes": routes})

        def path_observed():
            status = json.loads(B.call("container_exec", name=peer, argv=["tailscale", "--socket=/tmp/ts.sock", "status", "--json"])["stdout"])
            view = next((item for item in (status.get("Peer") or {}).values() if item.get("HostName") == "kerlico"), {})
            current = "直连" if view.get("CurAddr") else f"DERP {view.get('Relay')}"
            matched = bool(view.get("CurAddr")) == direct
            return "path_observed", {"ok": matched, "status": "pass" if matched else "na", "class": "" if matched else "未走到直连", "detail": f"官方客户端观察到 kerlico 路径：{current}"}

        return Peer("tailscale", options, udp=True, target=(target_host, target_port), limits={"connect_timeout_ms": 30000}, ready_wait=90, diag=diag, after=path_observed, note="headscale 与官方出口节点在 B（--netfilter-mode=off，因 Mesh 地址落在 CGNAT 段），kerlico 经 Mesh 接入，目标经 B 主地址转发到 C（官方出口节点不放行 CGNAT 目标）")
    return start


def real_easytier(scheme, static):
    def start(bench):
        need_v4(bench)
        B, C = bench.B, bench.C
        name, secret = "xhost" + secrets.token_hex(3), secrets.token_hex(16)
        target = bench.host(C)
        command = f"/et/easytier-core --network-name {name} --network-secret {secret} -i 10.144.144.1 -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010 -n {target}/32"
        _, address, _ = bench.container(B, "easytier", IMAGE_DEBIAN, ["--cap-add", "NET_ADMIN", "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--device", "/dev/net/tun", "-v", f"{PEER_DIR}/easytier:/et:ro"], ["sh", "-c", command])
        port = bench.relay(B, scheme, address, 11010)
        options = {"network_name": name, "network_secret": secret, "peers": [f"{scheme}://{bench.host(B)}:{port}"]}
        if static:
            options["ipv4"] = "10.144.144.5/24"
        return Peer("easytier", options, udp=True, limits={"connect_timeout_ms": 30000}, ready_wait=90, note="官方 easytier-core 容器在 B，以子网代理通告 C 的 /32，kerlico 经 B 上的用户态转发接入")
    return start


def real_zerotier():
    def start(bench):
        need_v4(bench)
        B = bench.B
        token = secrets.token_hex(12)
        root_port, controller_port = bench.port(B, 2)
        host = bench.host(B)
        target = bench.host(bench.C)
        local_conf = lambda port: json.dumps({"settings": {"primaryPort": port, "allowSecondaryPort": False, "portMappingEnabled": False, "allowTcpFallbackRelay": False}})
        state = "/var/lib/zerotier-one"

        def node(label, flags):
            name, address, gateway = bench.container(B, label, IMAGE_ZEROTIER, flags, ["sleep", "infinity"])
            return name, address, gateway

        def inside(name, script, limit=120):
            result = B.call("container_exec", name=name, argv=["sh", "-c", script], limit=limit, timeout=limit + 30)
            if result["rc"]:
                raise PeerFailed("对端启动失败", f"{name}: {script[:80]} | {result['stderr'][-300:]}{result['stdout'][-200:]}")
            return result["stdout"].strip()

        def prepare(name, port):
            conf = local_conf(port) if port else json.dumps({"settings": {"portMappingEnabled": False, "allowTcpFallbackRelay": False}})
            return inside(name, f"mkdir -p {state}/moons.d && printf %s {token} > {state}/authtoken.secret && chmod 600 {state}/authtoken.secret && printf %s '{conf}' > {state}/local.conf && zerotier-idtool generate {state}/identity.secret {state}/identity.public >/dev/null && cat {state}/identity.public")

        # root 与控制器不加入网络，不创建 tun，可以用主机网络；成员要 tun，只能在桥接里，靠 Docker MASQUERADE 出去。
        shared = ["-v", f"{bench.fixture(B, 'zerotier', {})}:/shared"]
        root, _, _ = node("root", ["--network", "host", *shared])
        controller, _, _ = node("controller", ["--network", "host", *shared])
        member, member_ip, gateway = node("member", ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", *shared])
        root_id, controller_id, member_id = prepare(root, root_port), prepare(controller, controller_port), prepare(member, None)
        moon = inside(root, f"cd /tmp && zerotier-idtool initmoon {state}/identity.public > moon.json && sed -i 's#\"stableEndpoints\": \\[\\]#\"stableEndpoints\": [\"{gateway}/{root_port}\", \"{host}/{root_port}\"]#' moon.json && zerotier-idtool genmoon moon.json >/dev/null && cp *.moon /shared/ && ls *.moon")
        for name in (root, controller, member):
            inside(name, f"cp /shared/{moon} {state}/moons.d/")
            launch =B.call("sh", script=f"docker exec -d {name} zerotier-one {state}")
            if launch["rc"]:
                raise PeerFailed("对端启动失败", f"zerotier-one: {launch['stderr'][-300:]}")
        inside(member, "iptables -t nat -A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE")
        api = f"http://127.0.0.1:{controller_port}"

        def rest(method, path, body=None):
            data = "" if body is None else f" -d '{json.dumps(body)}'"
            text = bench.shell(B, f"curl -s --max-time 10 -X {method} -H 'X-ZT1-Auth: {token}' {api}{path}{data}")
            return json.loads(text) if text.strip() else None

        def poll(description, check, budget=60):
            deadline = time.monotonic() + budget
            last = None
            while time.monotonic() < deadline:
                try:
                    value = check()
                    if value:
                        return value
                except (PeerFailed, ValueError, KeyError) as error:
                    last = error
                time.sleep(1)
            raise PeerFailed("对端启动失败", f"{description} 超时: {last} | {bench.peer_log()}")

        poll("控制器 API", lambda: rest("GET", "/status"))
        controller_addr = controller_id.split(":")[0]
        network = rest("POST", f"/controller/network/{controller_addr}______", {"name": "xhost", "private": True, "v4AssignMode": {"zt": True}, "mtu": 1280, "multicastLimit": 32, "enableBroadcast": True, "ipAssignmentPools": [{"ipRangeStart": "10.77.0.100", "ipRangeEnd": "10.77.0.200"}], "routes": [{"target": "10.77.0.0/24", "via": None}, {"target": f"{target}/32", "via": "10.77.0.20"}], "rules": [{"type": "ACTION_ACCEPT"}]})["id"]
        identity = inside(member, "zerotier-idtool generate /tmp/kerlico.secret /tmp/kerlico.public >/dev/null && cat /tmp/kerlico.secret")
        member_addr = member_id.split(":")[0]
        poll("成员启动", lambda: inside(member, "zerotier-cli -j info >/dev/null && echo up"))
        inside(member, f"zerotier-cli join {network}")
        poll("成员入网请求", lambda: member_addr in rest("GET", f"/controller/network/{network}/member"))
        rest("POST", f"/controller/network/{network}/member/{member_addr}", {"authorized": True, "ipAssignments": ["10.77.0.20"]})
        rest("POST", f"/controller/network/{network}/member/{identity.split(':')[0]}", {"authorized": True, "ipAssignments": ["10.77.0.30"]})
        poll("成员地址", lambda: "10.77.0.20" in inside(member, "zerotier-cli -j listnetworks"), 90)
        # 成员在桥接后，root 只知道它的容器地址；用转发给 kerlico 一条到成员的确定路径，不依赖穿过 Docker NAT 打洞。
        member_port = bench.relay(B, "udp", member_ip, 9993, bind=host)
        options = {"network": network, "identity": identity, "roots": [{"identity": root_id, "endpoints": [f"{host}:{root_port}"]}], "peers": [{"identity": controller_id, "endpoints": [f"{host}:{controller_port}"]}, {"identity": member_id, "endpoints": [f"{host}:{member_port}"]}]}

        def diag():
            views = {}
            for name in (root, controller, member):
                peers = json.loads(inside(name, "zerotier-cli -j peers"))
                views[name[-10:]] = [(item["address"], item.get("role"), item.get("latency"), [path["address"] for path in item.get("paths", []) if path.get("active")]) for item in peers if item.get("role") != "PLANET"]
            networks = inside(member, "zerotier-cli -j listnetworks")
            status = [(item.get("status"), item.get("assignedAddresses"), item.get("routes")) for item in json.loads(networks)]
            return json.dumps({"kerlico": identity.split(":")[0], "peers": views, "member_net": status, "ct": inside(member, "ip -4 addr show | grep inet; ip route").replace("\n", " ; ")})

        return Peer("zerotier", options, udp=True, limits={"connect_timeout_ms": 30000}, ready_wait=200, diag=diag, note="zerotier-one 1.14.2：root 与控制器在 B 主机网络，成员在 B 桥接容器，受管路由把 C 的 /32 指向成员，由成员 NAT 到 C；kerlico 经 B 上的用户态转发直达成员；网络 MTU 设 1280")
    return start


REALS = (
    Real("ssh", "password-ed25519host", real_ssh({"method": "password", "host": "ed25519", "user": "ed25519"}), ipv6=True),
    Real("ssh", "publickey-rsahost", real_ssh({"method": "publickey", "host": "rsa", "user": "ed25519"})),
    Real("gost-relay", "tcp", real_gost("tcp", False, False), ipv6=True),
    Real("gost-relay", "tls", real_gost("tls", False, True)),
    Real("gost-relay", "mtcp", real_gost("mtcp", True, False)),
    Real("gost-relay", "mtls", real_gost("mtls", True, True)),
    Real("gost-relay", "tcp-deferred", real_gost("tcp", False, False, mode="deferred"), placements=(0,)),
    Real("tor", "arti", real_tor),
    Real("masque", "h3-connect-ip-mesh", real_masque(False), placements=(0,)),
    Real("masque", "h3-connect-ip", real_masque(True), placements=(0, 2)),
    Real("openvpn", "udp-tls-crypt-aes256-cert", real_openvpn("udp", "crypt", "AES-256-GCM", "certificate"), placements=(0, 2)),
    Real("openvpn", "tcp-tls-auth-aes128-both", real_openvpn("tcp", "auth", "AES-128-GCM", "both"), placements=(0, 2)),
    Real("openvpn", "udp-plain-chacha-password", real_openvpn("udp", None, "CHACHA20-POLY1305", "password"), placements=(0,)),
    Real("openconnect", "cstp-tls", real_openconnect),
    Real("tailscale", "derp-exit", real_tailscale(False), placements=(0, 2)),
    Real("tailscale", "direct-exit", real_tailscale(True), placements=(0,)),
    Real("easytier", "tcp-static", real_easytier("tcp", True), placements=(0, 2)),
    Real("easytier", "udp-dhcp", real_easytier("udp", False), placements=(0,)),
    Real("zerotier", "root", real_zerotier(), placements=(0, 2)),
)
TUN_CARRIERS = ("hysteria2/quic", "socks/socks5-auth", "ss2022/aes-128-gcm")
TUN_TCP_ONLY = ("ss2022/aes-128-gcm",)


class OutboundRunner(Runner):
    def record(self, protocol, carrier, placement, family, case, result, direction=DIRECTION):
        # 对端日志里带 worker 工作目录，结果文件不留机器路径。
        detail = (result.get("detail") or result.get("error") or "").replace(ROOT, "<root>")
        return super().record(protocol, carrier, placement, family, case, {**result, "detail": detail}, direction=direction)

    def forget(self, protocol, carrier, client, family):
        """--resume 把多次运行写进同一文件；同一组合重跑时新结果取代旧结果。"""
        with self.lock:
            self.results = [item for item in self.results if not (item["protocol"] == protocol and item["carrier"] == carrier and item["family"] == family and item["placement"].startswith(f"A={client},"))]

    def run_real(self, real, placement, family):
        bench = Bench(self, placement, family, real.protocol)
        label, note = placement.label, ""
        record = lambda case, result: self.record(real.protocol, real.carrier, label, family, case, {**result, "detail": " | ".join(item for item in (result.get("detail") or result.get("error") or "", note) if item)}, direction=DIRECTION)
        client_name = f"{bench.label}-client"
        started_client = False
        try:
            for agent in (bench.A, bench.B, bench.C):
                agent.ensure()
            peer = real.start(bench)
            label, note = peer.placement or label, peer.note
            host, port = peer.target or (bench.host(bench.C), bench.C.echo_port)
            socks_port, udp_port = bench.port(bench.A, 2)
            inbounds = [{"tag": "udp", "type": "udp-forward", "listen": f"127.0.0.1:{udp_port}", "target": {"host": host, "port": port}, "outbound": "proxy"}] if peer.udp else []
            config = {"version": 2, "outbounds": [{"tag": "proxy", "type": peer.kind, "options": peer.options}], "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{socks_port}", "outbound": "proxy", "options": {"version": "5"}}], "inbounds": inbounds, "limits": {**LIMITS, **peer.limits}}
            wait = [("tcp", socks_port)] + ([("udp", udp_port)] if peer.udp else [])
            started = bench.A.call("spawn_kerlico", name=client_name, config=config, wait_ports=wait)
            if not started["ok"]:
                record("start", {"ok": False, "class": "配置" if started["stage"] == "check" else "客户端启动失败", "detail": f"{started['stage']}: {started.get('log', '').strip()[-500:]}"})
                return
            started_client = True
            if peer.custom:
                peer.custom(self, bench, socks_port, record)
            else:
                self.run_payload_cases(bench, peer, socks_port, udp_port, host, port, client_name, record, family)
            if peer.after:
                record(*peer.after())
            stopped = bench.A.call("stop", name=client_name, timeout=60)
            started_client = False
            clean = stopped["rc"] == 0
            record("shutdown", {"ok": clean, "elapsed": stopped["elapsed"], "class": "" if clean else "退出异常", "detail": "" if clean else f"exit={stopped['rc']} {stopped['log'][-300:]}"})
        except PeerFailed as error:
            record("start", {"ok": False, "class": error.klass, "detail": error.detail})
        except AgentError as error:
            record("start", {"ok": False, "class": "环境", "detail": str(error)})
        finally:
            if started_client and bench.A.alive():
                try:
                    bench.A.call("stop", name=client_name, timeout=30)
                except AgentError:
                    pass
            bench.close()

    def diagnosis(self, bench, client_name):
        try:
            state = bench.A.call("alive", name=client_name, timeout=30)
        except AgentError:
            return ""
        tail = " / ".join(line[-240:] for line in state["log"].strip().splitlines()[-2:])
        return f"client{'' if state['alive'] else '(已退出)'}: {tail} ; peer: {bench.peer_log()}"

    def run_payload_cases(self, bench, peer, socks, udp_port, host, port, client_name, record, family):
        A = bench.A
        deadline = time.monotonic() + peer.ready_wait
        last = {}
        while time.monotonic() < deadline:
            last = A.call("tcp_socks", socks=socks, host=host, port=port, size=64, timeout=120)
            if last["ok"]:
                break
            time.sleep(1)
        if not last.get("ok"):
            extra = ""
            if peer.diag:
                try:
                    extra = " | 对端诊断: " + peer.diag()
                except (AgentError, PeerFailed) as error:
                    extra = f" | 诊断失败: {error}"
            record("tcp_small", {**last, "class": "隧道未就绪", "detail": f"{last.get('error')} 等待 {peer.ready_wait}s 后 | {self.diagnosis(bench, client_name)}{extra}"})
            return
        cases = [name for name in self.args.tcp_cases if name in SIZES]
        if family == "ipv6":
            cases = [name for name in cases if name != "tcp_32m"]
        failed = 0
        for case in cases:
            if failed >= 2 and case == "tcp_32m":
                record(case, {"status": "skip", "class": "前序失败", "detail": "前两个 TCP 用例已失败"})
                continue
            result = A.call("tcp_watch", socks=socks, host=host, port=port, size=SIZES[case], timeout=1500)
            gap = f"最长无进展 {result.get('longest_gap')}s（已收 {result.get('longest_gap_at')} 字节时）"
            if not result["ok"]:
                failed += 1
                result["detail"] = f"{result.get('error')} {gap} | {self.diagnosis(bench, client_name)}"
            elif result["longest_gap"] > 10:
                result["detail"] = gap
            record(case, result)
        if not peer.udp or self.args.no_udp:
            return
        for size in OUTBOUND_UDP:
            result = A.call("udp_forward", port=udp_port, size=size, count=10 if size == 64 else 5, timeout=120)
            if not result["ok"]:
                result["detail"] = f"{result.get('error')} | {self.diagnosis(bench, client_name)}"
            record(f"udp_{size}", result)
        result = A.call("udp_socks", socks=socks, host=host, port=port, size=64, count=5, timeout=120)
        if result.get("error") == "socks_reply_7":
            result.update(status="na", detail="出站不提供多目标 UDP 关联，SOCKS5 UDP ASSOCIATE 返回命令不支持")
        elif not result["ok"]:
            result["detail"] = f"{result.get('error')} | {self.diagnosis(bench, client_name)}"
        record("udp_socks5", result)

    def run_tun(self, carrier, placement):
        """kerlico 留在主 netns 走 Mesh，只把 TUN 接口移进独立 netns，用例在 netns 内以内核协议栈发起。"""
        bench = Bench(self, placement, "ipv4", "tun")
        tag = secrets.token_hex(2)
        tcp_only = carrier.key in TUN_TCP_ONLY
        device, netns, second = f"kx{tag}", f"xhost-{tag}", random.randint(1, 250)
        record = lambda case, result: self.record("tun", carrier.key.replace("/", "-"), placement.label, "ipv4", case, result, direction="内核TUN->kerlico->kerlico节点")
        A, B, C = bench.A, bench.B, bench.C
        client_name = f"{bench.label}-client"
        started_client = False
        try:
            for agent in (A, B, C):
                agent.ensure()
            spec = carrier.build(self.material)
            node_port, origin_port = bench.port(B, 2)
            if spec.origin:
                raise PeerFailed("配置", "TUN 用例不选需要伪装站的载体")
            wait = ([("tcp", node_port)] if carrier.tcp_listener else []) + ([("udp", node_port)] if carrier.uses_udp_listener else [])
            node_name = f"{bench.label}-node"
            bench.undo.append((B, "process", node_name))
            started = B.call("spawn_kerlico", name=node_name, config=node_config(carrier, spec, node_port, "ipv4", origin_port), wait_ports=wait)
            if not started["ok"]:
                raise PeerFailed("配置" if started["stage"] == "check" else "节点启动失败", f"{started['stage']}: {started.get('log', '')[-400:]}")
            bench.watched.append((B, "process", node_name))
            config = {
                "version": 2,
                "outbounds": [{"tag": "proxy", "type": carrier.protocol, "options": finish_client(spec.client, B.public["v4"], node_port)}],
                "local_inbounds": [{"tag": "tun", "type": "tun", "listen": "127.0.0.1:0", "outbound": "direct" if tcp_only else "proxy", "options": {"name": device, "addresses": [f"198.18.{second}.1/30"], "mtu": 1280}}],
                "limits": LIMITS,
            }
            if tcp_only:
                # TUN 节点绑定的出站必须支持多目标 UDP 关联，ss2022 不支持（kerlico check 拒绝），所以节点绑 direct，TCP 由规则走 ss2022。
                config["outbounds"].append({"tag": "direct", "type": "direct"})
                config["routes"] = [{"outbound": "proxy", "network": "tcp"}]
            started = A.call("spawn_kerlico", name=client_name, config=config, wait_ports=[])
            if not started["ok"]:
                raise PeerFailed("配置" if started["stage"] == "check" else "客户端启动失败", f"{started['stage']}: {started.get('log', '')[-400:]}")
            started_client = True
            created = False
            for _ in range(50):
                if A.call("sh", script=f"ip link show {device}")["rc"] == 0:
                    created = True
                    break
                time.sleep(0.2)
            if not created:
                raise PeerFailed("客户端启动失败", f"TUN 接口未出现 | {A.call('alive', name=client_name)['log'][-400:]}")
            bench.undo.append((A, "netns", netns))
            made = A.call("netns_up", name=netns)
            if made["rc"]:
                raise PeerFailed("环境", f"netns 创建失败 {made['stderr']}")
            bench.shell(A, f"set -e\nip link set {device} netns {netns}\nip -n {netns} link set lo up\nip -n {netns} addr add 198.18.{second}.1/30 dev {device}\nip -n {netns} link set {device} mtu 1280 up\nip -n {netns} route add default dev {device}")
            time.sleep(1)
            state = A.call("alive", name=client_name)
            if not state["alive"]:
                raise PeerFailed("实现或环境", f"接口移动后 kerlico 退出: {state['log'][-400:]}")
            host, port = C.public["v4"], C.echo_port
            for case in self.args.tcp_cases:
                if case in SIZES:
                    result = A.call("netns_case", netns=netns, kind="tcp", host=host, port=port, size=SIZES[case], timeout=420)
                    if not result["ok"]:
                        result["detail"] = f"{result.get('error')} | {self.diagnosis(bench, client_name)}"
                    record(case, result)
            if tcp_only:
                # direct 也能到 C，停掉节点后 TCP 必须失败，才能确认前面的流量确实走了规则选中的出站。
                B.call("stop", name=node_name, timeout=60)
                result = A.call("netns_case", netns=netns, kind="tcp", host=host, port=port, size=SIZES["tcp_small"], timeout=120)
                record("tcp_stops_with_node", {"ok": not result["ok"], "class": "" if not result["ok"] else "绕过出站", "detail": result.get("error", "节点停止后 TCP 仍然通")})
            for size in () if tcp_only else (64, 1200):
                result = A.call("netns_case", netns=netns, kind="udp", host=host, port=port, size=size, count=10 if size == 64 else 5, timeout=420)
                if not result["ok"]:
                    result["detail"] = f"{result.get('error')} | {self.diagnosis(bench, client_name)}"
                record(f"udp_{size}", result)
            stopped = A.call("stop", name=client_name, timeout=60)
            started_client = False
            record("shutdown", {"ok": stopped["rc"] == 0, "elapsed": stopped["elapsed"], "class": "" if stopped["rc"] == 0 else "退出异常", "detail": "" if stopped["rc"] == 0 else f"exit={stopped['rc']} {stopped['log'][-300:]}"})
        except PeerFailed as error:
            record("start", {"ok": False, "class": error.klass, "detail": error.detail})
        except AgentError as error:
            record("start", {"ok": False, "class": "环境", "detail": str(error)})
        finally:
            if started_client and A.alive():
                try:
                    A.call("stop", name=client_name, timeout=30)
                except AgentError:
                    pass
            bench.close()


def run_outbound(agents, material, args, scrubber):
    runner = OutboundRunner(agents, material, args, scrubber)
    words = args.only.split(",") if args.only else None
    chosen = {int(item) for item in args.placements.split(",")}
    ipv6_chosen = {int(item) for item in args.ipv6_placements.split(",") if item}

    def summarise(title, before):
        with runner.lock:
            items = runner.results[before:]
        print(title + ": " + ",".join(f"{item['case']}={item['result']}" + (f"({item['mib_s']})" if item.get("mib_s") and item["case"] == "tcp_32m" else "") for item in items), flush=True)

    if args.layout:
        # 对照用：把任意两角放到同一台，定位问题在跨机路径还是实现。
        fixed = Placement(*args.layout.split(","))
        for real in REALS:
            if words and any(word in real.key for word in words):
                runner.forget(real.protocol, real.carrier, fixed.client, "ipv4")
                before = len(runner.results)
                runner.run_real(real, fixed, "ipv4")
                summarise(f"{real.key} {fixed.label} ipv4", before)
        runner.flush()
        return

    for real in REALS:
        if words and not any(word in real.key for word in words):
            continue
        for index in real.placements:
            if index not in chosen:
                continue
            runner.forget(real.protocol, real.carrier, PLACEMENTS[index].client, "ipv4")
            before = len(runner.results)
            runner.run_real(real, PLACEMENTS[index], "ipv4")
            summarise(f"{real.key} {PLACEMENTS[index].label} ipv4", before)
        if real.ipv6 and "ipv6" in args.families:
            for index in ipv6_chosen:
                runner.forget(real.protocol, real.carrier, PLACEMENTS[index].client, "ipv6")
                before = len(runner.results)
                runner.run_real(real, PLACEMENTS[index], "ipv6")
                summarise(f"{real.key} {PLACEMENTS[index].label} ipv6", before)
    if not words or any("tun" in word for word in words):
        for carrier in CARRIERS:
            if carrier.key not in TUN_CARRIERS:
                continue
            for index in sorted(chosen):
                runner.forget("tun", carrier.key.replace("/", "-"), PLACEMENTS[index].client, "ipv4")
                before = len(runner.results)
                runner.run_tun(carrier, PLACEMENTS[index])
                summarise(f"tun/{carrier.key} {PLACEMENTS[index].label}", before)
    runner.flush()


def ssh_pipe(config, source_alias, source_command, target_alias, target_command, timeout=900):
    """机器之间不互信，文件走本机中继。"""
    base = ["ssh", "-F", config, "-o", "BatchMode=yes"]
    source = subprocess.Popen([*base, source_alias, source_command], stdout=subprocess.PIPE)
    target = subprocess.run([*base, target_alias, target_command], stdin=source.stdout, capture_output=True, timeout=timeout)
    source.stdout.close()
    source.wait(timeout=60)
    return source.returncode == 0 and target.returncode == 0, target.stderr.decode("utf-8", "replace")[-400:]


def prepare_outbound(args):
    """幂等：已有的对端二进制与镜像不重复准备；记下本次新拉的基础镜像，cleanup 时只删它们。"""
    base = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes"]

    def remote(alias, command, stdin=None, timeout=900):
        return subprocess.run([*base, alias, command], input=stdin, capture_output=True, timeout=timeout)

    def locate(filename, version_flag, expect):
        finder = f"find {ROOT.rsplit('/', 1)[0]} -maxdepth 5 -type f -name {filename} -perm -u+x -not -path '*/xhost/*' 2>/dev/null | while read -r item; do \"$item\" {version_flag} 2>&1 | grep -q '{expect}' && echo \"$item\" && break; done"
        for alias in MACHINES:
            found = remote(alias, finder).stdout.decode().strip()
            if found:
                return alias, found
        return None, None

    def binaries(alias):
        for filename, version_flag, expect, name, machines in PREPARE_BINARIES:
            target = f"{PEER_DIR}/{name}"
            if alias not in machines or remote(alias, f"test -x {target}").returncode == 0:
                continue
            source, path = locate(filename, version_flag, expect)
            if not source:
                print(f"{alias} {name}: 三台都没有符合版本 {expect} 的二进制", flush=True)
                continue
            remote(alias, f"mkdir -p $(dirname {target})")
            if source == alias:
                ok, detail = remote(alias, f"cp {path} {target}").returncode == 0, "cp 失败"
            else:
                ok, detail = ssh_pipe(args.ssh_config, source, f"gzip -c {path}", alias, f"gunzip > {target}.tmp && chmod +x {target}.tmp && mv {target}.tmp {target}")
            print(f"{alias} {name}: {'ok' if ok else detail}", flush=True)

    def images(alias):
        existing = set(remote(alias, "docker images --format '{{.Repository}}:{{.Tag}}'").stdout.decode().split())
        new_bases = [image for image in PREPARE_BASES if image not in existing]
        recorded = remote(alias, f"cat {PEER_DIR}/pulled-images.txt 2>/dev/null").stdout.decode().split()
        for tag, machines, dockerfile in PREPARE_IMAGES:
            if alias not in machines or tag in existing:
                continue
            result = remote(alias, f"docker build -q -t {tag} -", stdin=dockerfile.encode(), timeout=900)
            print(f"{alias} {tag}: {'ok' if result.returncode == 0 else result.stderr.decode('utf-8', 'replace')[-400:]}", flush=True)
        after = set(remote(alias, "docker images --format '{{.Repository}}:{{.Tag}}'").stdout.decode().split())
        pulled = sorted(set(recorded) | {image for image in new_bases if image in after})
        remote(alias, f"mkdir -p {PEER_DIR} && cat > {PEER_DIR}/pulled-images.txt", stdin="\n".join(pulled).encode())

    with ThreadPoolExecutor(max_workers=6) as pool:
        for future in [pool.submit(work, alias) for alias in MACHINES for work in (binaries, images)]:
            future.result()


def cleanup_outbound(args):
    base = ["ssh", "-F", args.ssh_config, "-o", "BatchMode=yes"]
    tags = " ".join(item[0] for item in PREPARE_IMAGES)
    for alias in MACHINES:
        script = f"docker ps -aq --filter name=^xhost- | xargs -r docker rm -f; docker rmi {tags} 2>/dev/null; if [ -f {PEER_DIR}/pulled-images.txt ]; then xargs -r docker rmi < {PEER_DIR}/pulled-images.txt 2>/dev/null; fi; rm -rf {PEER_DIR}; ip netns list | grep -o '^xhost-[0-9a-f]*' | xargs -r -n1 ip netns delete; docker images --format '{{{{.Repository}}}}:{{{{.Tag}}}}' | grep -c xhost-"
        result = subprocess.run([*base, alias, script], capture_output=True, timeout=300)
        print(f"{alias}: rc={result.returncode} 残留 xhost 镜像 {result.stdout.decode().strip().splitlines()[-1:]}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="kerlico 跨机协议矩阵")
    sub = parser.add_subparsers(dest="command", required=True)
    agent = sub.add_parser("agent")
    agent.add_argument("--root", required=True)
    agent.add_argument("--binary", required=True)
    case = sub.add_parser("netns-case")
    case.add_argument("kind", choices=["tcp", "udp"])
    case.add_argument("host")
    case.add_argument("port", type=int)
    case.add_argument("size", type=int)
    case.add_argument("count", type=int)
    origin = sub.add_parser("tls-origin")
    origin.add_argument("port", type=int)
    origin.add_argument("cert")
    origin.add_argument("key")
    relay = sub.add_parser("relay")
    relay.add_argument("kind", choices=["tcp", "udp"])
    relay.add_argument("listen", type=int)
    relay.add_argument("host")
    relay.add_argument("port", type=int)
    relay.add_argument("--bind", default="::")
    for name in ("probe", "run", "check", "list", "run-outbound", "prepare-outbound", "cleanup-outbound"):
        command = sub.add_parser(name)
        command.add_argument("--ssh-config", default=".private/machines/ssh_config")
        command.add_argument("--binary", default=f"{ROOT}/kerlico")
        command.add_argument("--out", default="cross-host-results.json")
        command.add_argument("--only", help="只跑 protocol 或 protocol/carrier 含此文本的项，逗号分隔")
        command.add_argument("--placements", default="0,1,2")
        command.add_argument("--families", default="ipv4,ipv6")
        command.add_argument("--network", choices=["public", "mesh"], default="mesh")
        command.add_argument("--ipv6-placements", default="0")
        command.add_argument("--tcp-cases", default="tcp_small,tcp_1m,tcp_32m")
        command.add_argument("--no-udp", action="store_true")
        command.add_argument("--jobs", type=int, default=1)
        command.add_argument("--resume", action="store_true")
        command.add_argument("--retry-failed", action="store_true")
        command.add_argument("--layout", help="run-outbound 的对照排列：A,B,C 机器别名")
    args = parser.parse_args()
    if args.command == "agent":
        agent_main(args)
        return
    if args.command == "netns-case":
        netns_case_main(args)
        return
    if args.command == "tls-origin":
        tls_origin_main(args)
        return
    if args.command == "relay":
        relay_main(args)
        return
    if args.command == "prepare-outbound":
        prepare_outbound(args)
        return
    if args.command == "cleanup-outbound":
        cleanup_outbound(args)
        return
    selected =[c for c in CARRIERS if not args.only or any(word in c.key for word in args.only.split(","))]
    if args.command == "list":
        for carrier in selected:
            print(carrier.key)
        return
    args.tcp_cases = args.tcp_cases.split(",")
    scrubber = Scrubber()
    agents = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        def bring_up(alias):
            agent = Agent(alias, args.ssh_config, args.binary)
            agent.start()
            agent.networks = {"public": {"v4": resolve_public_v4(args.ssh_config, alias), "v6": agent.addr["public"]["v6"]}, "mesh": agent.addr["mesh"]}
            agent.public = agent.networks[args.network]
            for network, addresses in agent.networks.items():
                for family, address in addresses.items():
                    scrubber.add(address, f"{alias}-{network}-{family}")
            return alias, agent
        agents = dict(pool.map(bring_up, MACHINES))
    try:
        if args.command == "probe":
            report = probe(agents, scrubber, args.network)
            Path(args.out).write_text(scrubber.clean(json.dumps(report, ensure_ascii=False, indent=1)), encoding="utf-8")
            return
        tls = agents[MACHINES[0]].call("gen_tls")
        material = Material(tls["ca"], tls["cert"], tls["key"])
        if args.command == "check":
            return check_configs(agents, selected, material, scrubber)
        args.binary_sha256 = agents[MACHINES[0]].call("run_command", argv=["sha256sum", args.binary])["stdout"].split()[0]
        if args.command == "run-outbound":
            return run_outbound(agents, material, args, scrubber)
        runner = Runner(agents, material, args, scrubber)
        placements = [PLACEMENTS[int(i)] for i in args.placements.split(",")]
        ipv6_placements = [PLACEMENTS[int(i)] for i in args.ipv6_placements.split(",") if i]
        work = []
        for carrier in selected:
            for placement in placements:
                if "ipv4" in args.families:
                    work.append((carrier, placement, "ipv4"))
            for placement in ipv6_placements:
                if "ipv6" in args.families and all(agents[m].public["v6"] for m in (placement.client, placement.node, placement.target)):
                    work.append((carrier, placement, "ipv6"))

        def run_item(item):
            carrier, placement, family = item
            before = len(runner.results)
            try:
                runner.run_carrier(carrier, placement, family)
            except Exception as error:
                print(f"异常 {carrier.key} {placement.label} {family}: {scrubber.clean(repr(error))}", flush=True)
            with runner.lock:
                items = [r for r in runner.results[before:] if r["carrier"] == carrier.name and r["protocol"] == carrier.protocol and r["placement"] == placement.label and r["family"] == family]
            summary = ",".join(f"{r['case']}={r['result']}" + (f"({r['mib_s']})" if r.get("mib_s") and r["case"] == "tcp_32m" else "") for r in items)
            print(f"{carrier.key} {placement.label} {family}: {summary}", flush=True)

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            list(pool.map(run_item, work))
        text = (Path(args.out)).read_text(encoding="utf-8")
        for name in MACHINES:
            agents[name].call("write_file", relative=f"results/{Path(args.out).name}", text=text)
    finally:
        for item in agents.values():
            item.close()


def check_configs(agents, selected, material, scrubber):
    agent = agents[MACHINES[0]]
    bad = 0
    for carrier in selected:
        spec = carrier.build(material)
        ports = agent.call("alloc_ports", count=4)
        for label, config in (("node", node_config(carrier, spec, ports[0], "ipv4", ports[1])), ("client", client_config(carrier, spec, "192.0.2.1", ports[0], ports[2], ports[3], {"host": "192.0.2.2", "port": 9}))):
            path = agent.call("write_file", relative=f"run/check/{ports[0]}-{label}.json", text=json.dumps(config))
            result = agent.call("run_command", argv=[agent.binary, "check", "-c", path])
            agent.call("run_command", argv=["rm", "-f", path])
            if result["rc"]:
                bad += 1
                print(f"{carrier.key} {label}: {scrubber.clean((result['stderr'] or result['stdout']).strip())[-400:]}", flush=True)
    print(f"检查 {len(selected)} 个配置，失败 {bad} 处", flush=True)


if __name__ == "__main__":
    main()
