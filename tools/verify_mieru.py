#!/usr/bin/env python3
"""官方与 Rust mieru 的真实互通验收，仅在指定 worker 执行。

本工具不构建二进制、不下载模块、不注册 WARP。验收目标只绑定回环，
并使用文档声明的合成测试账号。
"""

import argparse
import concurrent.futures
import contextlib
import http.client
import http.server
import ipaddress
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback


SHA = "1367cf2d2dd81c5f27d455be7cea691d7948c420"
IO_BUDGET = 25
MUX = ["MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH"]
HANDSHAKES = ["HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"]
FACTORS = [["TCP", "UDP"], MUX, HANDSHAKES, list(range(5)), [1280, 1400]]


class Failure(Exception):
    pass


class PacketFailure(Failure):
    def __init__(self, message, evidence):
        super().__init__(message)
        self.evidence = evidence


def require(condition, message):
    if not condition:
        raise Failure(message)


def run_phase(name, function):
    try:
        return function()
    except PacketFailure as error:
        error.evidence.setdefault("phase", name)
        raise
    except Exception as error:
        raise PacketFailure("互通阶段失败", {"phase": name, "error_type": type(error).__name__,
                                             "error": str(error)}) from error


def exact(conn, length):
    chunks = bytearray()
    while len(chunks) < length:
        part = conn.recv(length - len(chunks))
        if not part:
            raise Failure("意外 EOF")
        chunks.extend(part)
    return bytes(chunks)


def authority(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def encode_address(host, port):
    try:
        address = b"\x01" + socket.inet_pton(socket.AF_INET, host)
    except OSError:
        try:
            address = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
        except OSError:
            encoded = host.encode("ascii")
            require(0 < len(encoded) <= 255, "测试域名非法")
            address = b"\x03" + bytes([len(encoded)]) + encoded
    return address + struct.pack("!H", port)


def decode_address(read):
    kind = read(1)[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, read(4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(16))
    elif kind == 3:
        host = read(read(1)[0]).decode("ascii")
    else:
        raise Failure("未知 SOCKS 地址类型")
    return host, struct.unpack("!H", read(2))[0]


def socks_connect(port, host, target_port, command=1):
    conn = socket.create_connection(("127.0.0.1", port), 5)
    conn.settimeout(IO_BUDGET)
    try:
        conn.sendall(b"\x05\x01\x00")
        require(exact(conn, 2) == b"\x05\x00", "SOCKS 认证方法不符")
        conn.sendall(b"\x05" + bytes([command]) + b"\x00" + encode_address(host, target_port))
        header = exact(conn, 3)
        require(header == b"\x05\x00\x00", "SOCKS 命令被拒绝")
        bound = decode_address(lambda n: exact(conn, n))
        return conn, bound
    except BaseException:
        conn.close()
        raise


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class ThreadedUDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True
    # socketserver 默认只收 8192 字节，会让大包在到达代理之前被夹具截断。
    max_packet_size = 65535


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(IO_BUDGET)
        state = {"fixture": self.server.label, "peer": list(self.client_address),
                 "read_bytes": 0, "write_bytes": 0, "idle_budget": IO_BUDGET,
                 "started": time.monotonic(), "error": None}
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                state["read_bytes"] += len(data)
                self.server.mark()
                self.request.sendall(data)
                state["write_bytes"] += len(data)
        except (OSError, TimeoutError):
            error = sys.exc_info()[1]
            state.update(error=str(error), error_type=type(error).__name__)
        finally:
            state["seconds"] = round(time.monotonic() - state["started"], 6)
            with self.server.lock:
                self.server.events.append(state)


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        self.server.mark()
        sock.sendto(data, self.client_address)


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond(b"")

    def do_POST(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks = bytearray()
            while True:
                line = self.rfile.readline(100)
                size = int(line.strip().split(b";", 1)[0], 16)
                if size == 0:
                    require(self.rfile.readline(100) == b"\r\n", "验收目标的 HTTP 尾部非法")
                    break
                chunks.extend(self.rfile.read(size))
                require(self.rfile.read(2) == b"\r\n", "验收目标的 HTTP 块边界非法")
            body = bytes(chunks)
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.respond(body)

    def respond(self, body):
        self.server.mark()
        result = self.server.label.encode() + b"|" + self.path.encode() + b"|" + body
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


class Fixtures:
    def __init__(self):
        self.servers = []

    def add(self, kind, host, handler, label, port=0):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        cls = type("LoopbackFixture", (kind,), {"address_family": family})
        server = cls((host, port), handler)
        server.label = label
        server.count = 0
        server.events = []
        server.lock = threading.Lock()

        def mark():
            with server.lock:
                server.count += 1

        server.mark = mark
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return server

    def __enter__(self):
        try:
            self.tcp4 = self.add(ThreadedTCP, "127.0.0.1", EchoTCP, "tcp4")
            self.tcp6 = self.add(ThreadedTCP, "::1", EchoTCP, "tcp6")
            self.udp4 = self.add(ThreadedUDP, "127.0.0.1", EchoUDP, "udp4")
            self.udp4b = self.add(ThreadedUDP, "127.0.0.1", EchoUDP, "udp4b")
            self.udp6 = self.add(ThreadedUDP, "::1", EchoUDP, "udp6")
            # UDP 不会失败后切换连接；localhost 选到任一地址族都必须
            # 到达相同的回显端口，避免平台 hosts 顺序影响结果。
            self.udp_domain6 = self.add(ThreadedUDP, "::1", EchoUDP, "udp-domain6",
                                        self.udp4.server_address[1])
            self.http4 = self.add(ThreadedTCP, "127.0.0.1", Origin, "origin-a")
            self.http4b = self.add(ThreadedTCP, "127.0.0.1", Origin, "origin-b")
            self.http6 = self.add(ThreadedTCP, "::1", Origin, "origin-v6")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *args):
        for server, _ in reversed(self.servers):
            server.shutdown()
            server.server_close()
        for _, thread in self.servers:
            thread.join(1)

    def tcp_targets(self):
        return [("127.0.0.1", self.tcp4.server_address[1]),
                ("::1", self.tcp6.server_address[1]),
                ("localhost", self.tcp4.server_address[1])]

    def udp_targets(self):
        return [("127.0.0.1", self.udp4.server_address[1]),
                ("127.0.0.1", self.udp4b.server_address[1]),
                ("::1", self.udp6.server_address[1]),
                ("localhost", self.udp4.server_address[1])]

    def udp_count(self):
        return sum(s.count for s in [self.udp4, self.udp4b, self.udp6, self.udp_domain6])

    def tcp_events(self, since):
        records = []
        for server in [self.tcp4, self.tcp6]:
            with server.lock:
                records.extend(dict(row) for row in server.events if row["started"] >= since)
        return records


def free_ports(count, kind=socket.SOCK_STREAM, host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(family, kind)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, 0))
            sockets.append(sock)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for sock in sockets:
            sock.close()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


class Process:
    def __init__(self, command, folder, name):
        self.name = name
        self.path = folder / f"{name}.log"
        self.log = self.path.open("wb")
        self.process = subprocess.Popen(command, cwd=folder, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        self.forced_kill = False

    def text(self):
        return self.path.read_text(errors="replace")

    def ensure_alive(self):
        require(self.process.poll() is None, "验收进程提前退出，请查看相对路径日志")

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(3)
            except subprocess.TimeoutExpired:
                self.forced_kill = True
                # Go 对端的 SIGQUIT 会留下 goroutine 堆栈；仍判退出失败，
                # 不能把诊断退出当作正常清理。
                if self.name == "official-server":
                    os.kill(self.process.pid, signal.SIGQUIT)
                    try:
                        self.process.wait(1)
                    except subprocess.TimeoutExpired:
                        pass
                if self.process.poll() is None:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(3)
        self.log.close()


@contextlib.contextmanager
def managed(command, folder, name):
    process = Process(command, folder, name)
    try:
        yield process
    finally:
        process.close()


def wait_for(process, predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        process.ensure_alive()
        if predicate():
            return
        time.sleep(0.03)
    raise Failure("启动超时")


def ports_ready(ports):
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                pass
        except OSError:
            return False
    return True


def assert_released(ports, host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for port, kind in ports:
        with socket.socket(family, kind) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                sock.bind((host, port))
                if kind == socket.SOCK_STREAM:
                    sock.listen(1)
            except OSError as error:
                rows = []
                # Linux 的 TIME_WAIT 没有所属进程；保留状态证据供调用者
                # 区分残留监听和立即重绑策略，原始重绑断言仍然失败。
                name = ("tcp" if kind == socket.SOCK_STREAM else "udp") + ("6" if family == socket.AF_INET6 else "")
                table = Path("/proc/net") / name
                if table.is_file():
                    for line in table.read_text().splitlines()[1:]:
                        fields = line.split()
                        if int(fields[1].split(":")[1], 16) == port:
                            rows.append({"table": name, "state": fields[3], "inode": fields[9]})
                raise PacketFailure("退出后端口不能立即重绑", {"phase": "cleanup-rebind", "host": host,
                                    "address_family": int(family), "port": port,
                                    "socket_kind": int(kind), "error": str(error), "socket_rows": rows}) from error


def matrix(quick):
    if quick:
        return [(FACTORS[0][i % 2], MUX[i % 4], HANDSHAKES[(i // 2) % 2], i % 5,
                 FACTORS[4][(i // 4) % 2]) for i in range(8)]
    candidates = list(itertools.product(*FACTORS))

    def pairs(row):
        return {(i, row[i], j, row[j]) for i in range(len(row)) for j in range(i + 1, len(row))}

    missing = set().union(*(pairs(row) for row in candidates))
    selected = []
    while missing:
        row = max(candidates, key=lambda r: len(pairs(r) & missing))
        selected.append(row)
        missing.difference_update(pairs(row))
        candidates.remove(row)
    return selected


def client_settings(row, socks, http):
    transport, mux, handshake, low, mtu = row
    return {"username": "test-user", "password": "test-password", "transport": transport,
            "mtu": mtu, "multiplexing": mux, "handshakeMode": handshake, "lowEntropyMode": low,
            "socks5Port": socks, "httpProxyPort": http,
            "socks5ListenLAN": False, "httpProxyListenLAN": False}


def peer_options(row, port, host="127.0.0.1"):
    transport, mux, handshake, low, mtu = row
    return ["--listen", host, "--port", str(port), "--transport", transport,
            "--mtu", str(mtu), "--low", str(low), "--multiplexing", mux, "--handshake", handshake]


def tcp_check(socks, targets):
    records = []
    lock = threading.Lock()

    def one(index):
        host, port = targets[index % len(targets)]
        payload = (f"flow-{index}:".encode() * 12000) + bytes(range(256))
        state = {"flow": index, "target": authority(host, port), "phase": "socks",
                 "expected_bytes": len(payload), "read_bytes": 0, "write_bytes": 0,
                 "error": None}
        started = time.monotonic()
        conn, thread = None, None
        try:
            conn = socks_connect(socks, host, port)[0]
            state["phase"] = "payload"
            errors = []

            def write():
                try:
                    while state["write_bytes"] < len(payload):
                        sent = conn.send(payload[state["write_bytes"]:])
                        require(sent > 0, "TCP 写入返回零字节")
                        state["write_bytes"] += sent
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=write, daemon=True)
            thread.start()
            got = bytearray()
            while len(got) < len(payload):
                data = conn.recv(len(payload) - len(got))
                require(bool(data), "意外 EOF")
                got.extend(data)
                state["read_bytes"] += len(data)
            thread.join(IO_BUDGET)
            require(not thread.is_alive() and not errors, "TCP 并发写入未完成")
            require(got == payload, "TCP 内容不符")
            state["phase"] = "complete"
        except Exception as error:
            state.update(error=str(error), error_type=type(error).__name__)
            raise PacketFailure("TCP 流失败", dict(state)) from error
        finally:
            if conn is not None:
                conn.close()
            if thread is not None:
                thread.join(2)
            state["seconds"] = round(time.monotonic() - started, 6)
            with lock:
                records.append(dict(state))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(one, index) for index in range(8)]
        failure = None
        for future in futures:
            try:
                future.result()
            except PacketFailure as error:
                failure = failure or error
        if failure:
            failure.evidence["flows"] = sorted(records, key=lambda row: row["flow"])
            raise failure
    return {"flows": sorted(records, key=lambda row: row["flow"])}


def unpack_udp(packet):
    require(packet[:3] == b"\x00\x00\x00", "UDP SOCKS 头部不符")
    cursor = 3

    def read(length):
        nonlocal cursor
        result = packet[cursor:cursor + length]
        require(len(result) == length, "UDP 头部过短")
        cursor += length
        return result

    source = decode_address(read)
    return source, packet[cursor:]


def udp_check(socks, fixtures, negatives=False):
    control, bound = socks_connect(socks, "0.0.0.0", 0, 3)
    if bound[0] in ("0.0.0.0", "::"):
        bound = ("127.0.0.1", bound[1])
    with contextlib.closing(control), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(IO_BUDGET)
        targets = fixtures.udp_targets()
        lengths = [0, 1, 1279, 1400, 8192, 32000, 3, 0]
        for index, length in enumerate(lengths):
            host, port = targets[index % len(targets)]
            payload = bytes([index + 1]) * length
            evidence = {"index": index, "expected_length": length, "actual_length": None,
                        "target": authority(host, port), "source": None, "relay": list(bound), "error": None}
            try:
                udp.sendto(b"\x00\x00\x00" + encode_address(host, port) + payload, bound)
                packet, sender = udp.recvfrom(65535)
                evidence["sender"] = list(sender)
                evidence["raw_length"] = len(packet)
                source, got = unpack_udp(packet)
                evidence.update(actual_length=len(got), source=list(source), actual_prefix=got[:24].hex())
            except Exception as error:
                evidence["error"] = str(error)
                raise PacketFailure("UDP 收发或解码失败", evidence) from error
            if sender[1] != bound[1] or source[1] != port or got != payload:
                raise PacketFailure("UDP 内容、来源或边界不符", evidence)
        # 连发多个不同包后才读取，不能让字节流适配器仅靠一问一答通过。
        host, port = targets[0]
        pending = [b"order-a", b"order-b" * 19, b"order-c" * 300]
        for payload in pending:
            udp.sendto(b"\x00\x00\x00" + encode_address(host, port) + payload, bound)
        for index, payload in enumerate(pending):
            source, got = unpack_udp(udp.recvfrom(65535)[0])
            if source[1] != port or got != payload:
                raise PacketFailure("UDP 顺序或边界不符", {"index": index, "phase": "burst",
                                    "expected_length": len(payload), "actual_length": len(got),
                                    "target": authority(host, port), "source": list(source),
                                    "actual_prefix": got[:24].hex(), "error": None})
        if negatives:
            before = fixtures.udp_count()
            udp.sendto(b"\x00\x00\x01" + encode_address(host, port) + b"fragment", bound)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as spoof:
                spoof.sendto(b"\x00\x00\x00" + encode_address(host, port) + b"wrong-source", bound)
            time.sleep(0.3)
            require(fixtures.udp_count() == before, "非法 UDP 包到达了目标")
            udp.sendto(b"\x00\x00\x00" + encode_address(host, port) + b"still-live", bound)
            require(unpack_udp(udp.recvfrom(65535)[0])[1] == b"still-live", "非法 UDP 包破坏了关联")
        # TCP 控制连接 EOF 必须撤销 UDP 转发并关闭对应监听。
        control.close()
        time.sleep(0.25)
        before = fixtures.udp_count()
        udp.sendto(b"\x00\x00\x00" + encode_address(*targets[0]) + b"after-close", bound)
        udp.settimeout(0.35)
        try:
            udp.recvfrom(65535)
        except socket.timeout:
            pass
        else:
            raise Failure("控制连接 EOF 后 UDP 关联仍然存活")
        require(fixtures.udp_count() == before, "已关闭的 UDP 关联仍在转发")


def read_http_response(conn):
    response = http.client.HTTPResponse(conn)
    response.begin()
    body = response.read()
    return response.status, body


def http_check(http, fixtures, negatives=False):
    origins = [("127.0.0.1", fixtures.http4), ("127.0.0.1", fixtures.http4b),
               ("::1", fixtures.http6), ("localhost", fixtures.http4)]
    # 同一 HTTP 代理连接连续访问不同目标。
    with socket.create_connection(("127.0.0.1", http), 5) as conn:
        conn.settimeout(IO_BUDGET)
        for index, (host, server) in enumerate(origins):
            target = authority(host, server.server_address[1])
            path = f"/target-{index}?case=keepalive"
            request = f"GET http://{target}{path} HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n\r\n"
            conn.sendall(request.encode())
            status, body = read_http_response(conn)
            require(status == 200 and body == server.label.encode() + b"|" + path.encode() + b"|", "HTTP GET 或 keepalive 目标不符")
    target = authority("127.0.0.1", fixtures.http4.server_address[1])
    body = b"post-body\x00with-bytes"
    with socket.create_connection(("127.0.0.1", http), 5) as conn:
        conn.settimeout(IO_BUDGET)
        conn.sendall((f"POST http://{target}/post HTTP/1.1\r\nHost: {target}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        status, got = read_http_response(conn)
        require(status == 200 and got == b"origin-a|/post|" + body, "HTTP POST 正文不符")
    with socket.create_connection(("127.0.0.1", http), 5) as conn:
        conn.settimeout(IO_BUDGET)
        conn.sendall((f"POST http://{target}/chunked HTTP/1.1\r\nHost: {target}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode() + b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n")
        status, got = read_http_response(conn)
        require(status == 200 and got == b"origin-a|/chunked|abcdefg", "HTTP chunked 正文不符")
    for host, port in fixtures.tcp_targets():
        with socket.create_connection(("127.0.0.1", http), 5) as conn:
            conn.settimeout(IO_BUDGET)
            target = authority(host, port)
            payload = b"connect-pipelined-prefix\x00" * 100
            conn.sendall((f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").encode() + payload)
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                require(len(header) < 16384, "CONNECT 应答头部超限")
                header.extend(exact(conn, 1))
            require(header.split(b"\r\n", 1)[0].split()[1] == b"200", "CONNECT 状态不符")
            require(exact(conn, len(payload)) == payload, "CONNECT 预读字节丢失")
    if negatives:
        target = authority("127.0.0.1", fixtures.http4.server_address[1])
        before = sum(server.count for _, server in origins)
        malformed = [b"CONNECT missing-port HTTP/1.1\r\nHost: invalid\r\n\r\n",
                     (f"POST http://{target}/bad HTTP/1.1\r\nHost: {target}\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx").encode()]
        for request in malformed:
            with socket.create_connection(("127.0.0.1", http), 5) as conn:
                conn.settimeout(4)
                conn.sendall(request)
                try:
                    data = conn.recv(4096)
                except ConnectionResetError:
                    data = b""
                require(not data or (data.startswith(b"HTTP/") and data.split(b" ", 2)[1].startswith(b"4")), "非法 HTTP 被接受")
        require(sum(server.count for _, server in origins) == before, "非法 HTTP 到达了源站")


def official_to_rust(args, folder, row, fixtures, negative=False):
    kind = socket.SOCK_STREAM if row[0] == "TCP" else socket.SOCK_DGRAM
    port = free_ports(1, kind, args.node_host)[0]
    config = {"warp": {"secretKey": "invalid"},
              "dns": {"hosts": {"localhost": ["127.0.0.1", "::1"]}},
              "inbounds": [{"tag": "fixture", "protocol": "mieru", "listen": args.node_host, "port": port,
                            "outbound": "default", "rules": [],
                            "settings": {"transport": row[0], "mtu": row[4],
                                         "users": [{"email": "test-user", "username": "test-user", "password": "test-password"}]}}]}
    config_path = folder / "server.json"
    write_json(config_path, config)
    # 显式非法 secretKey 使 load_profile 在注册之前解析失败；本地非法文件
    # 同样防止后续实现退回到自动注册。
    write_json(folder / "warp.json", {"secretKey": "invalid"})
    with managed([args.server_bin, str(config_path)], folder, "rust-server") as server:
        wait_for(server, lambda: "mieru" in server.text().splitlines())
        command = [args.peer_bin, "probe"] + peer_options(row, port, args.node_host) + [
            "--tcp-targets", ",".join(authority(*x) for x in fixtures.tcp_targets()),
            "--udp-targets", ",".join(authority(*x) for x in fixtures.udp_targets()), "--timeout", "25s"]
        result = subprocess.run(command, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        (folder / "official-probe.log").write_bytes(result.stdout)
        records = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
        if result.returncode != 0:
            raise PacketFailure("官方探测失败，请查看 official-probe.log", records[-1] if records else {"error": "无 JSON 证据"})
        require(any(r.get("status") == "pass" and r.get("upstream_sha") == SHA for r in records), "官方探测缺少成功记录")
        if negative:
            bad = command[:-2] + ["--timeout", "3s", "--password", "wrong-test-password"]
            result = subprocess.run(bad, cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=6)
            (folder / "official-negative.log").write_bytes(result.stdout)
            require(result.returncode != 0, "官方客户端的错误凭证被接受")
            records = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
            require(any(r.get("status") == "fail" and r.get("stage") in ("tcp-dial", "tcp-bytes") for r in records), "错误凭证未到达认证路径")
        server.ensure_alive()
    require(not server.forced_kill, "Rust 服务端未按时退出")
    assert_released([(port, kind)], args.node_host)


def rust_to_official(args, folder, row, fixtures, negative=False):
    kind = socket.SOCK_STREAM if row[0] == "TCP" else socket.SOCK_DGRAM
    upstream = free_ports(1, kind, args.node_host)[0]
    socks, http = free_ports(2)
    settings = client_settings(row, socks, http)
    config = {"protocol": "mieru", "peer": authority(args.node_host, upstream), "settings": settings}
    path = folder / "client.json"
    write_json(path, config)
    with managed([args.peer_bin, "server"] + peer_options(row, upstream, args.node_host), folder, "official-server") as official:
        wait_for(official, lambda: '"status":"ready"' in official.text())
        with managed([args.client_bin, "--mieru-proxy", str(path)], folder, "rust-client") as client:
            wait_for(client, lambda: ports_ready([socks, http]))
            tcp_result = run_phase("tcp", lambda: tcp_check(socks, fixtures.tcp_targets()))
            write_json(folder / "tcp-flows.json", tcp_result)
            run_phase("udp", lambda: udp_check(socks, fixtures, negatives=negative))
            run_phase("http", lambda: http_check(http, fixtures, negatives=negative))
            official.ensure_alive()
            client.ensure_alive()
        require(not client.forced_kill, "Rust 客户端未按时退出")
        assert_released([(socks, socket.SOCK_STREAM), (http, socket.SOCK_STREAM)])
        if negative:
            settings["password"] = "wrong-test-password"
            write_json(path, config)
            before = fixtures.tcp4.count
            with managed([args.client_bin, "--mieru-proxy", str(path)], folder, "rust-negative") as client:
                wait_for(client, lambda: ports_ready([socks, http]))
                denied = False
                try:
                    conn, _ = socks_connect(socks, "127.0.0.1", fixtures.tcp4.server_address[1])
                    with conn:
                        conn.settimeout(3)
                        conn.sendall(b"must-not-reach-echo")
                        denied = not conn.recv(64)
                except (Failure, OSError):
                    denied = True
                require(denied and fixtures.tcp4.count == before, "Rust 客户端错误凭证到达了回显目标")
    require(not official.forced_kill, "官方服务端未正常停止")
    assert_released([(upstream, kind)], args.node_host)


def configuration_negatives(args, folder):
    socks, http = free_ports(2)
    row = ("TCP", MUX[1], HANDSHAKES[0], 0, 1400)
    base = client_settings(row, socks, http)
    for index, change in enumerate([
            {"socks5Port": 1024}, {"httpProxyPort": 65536}, {"httpProxyPort": socks},
            {"mtu": 1279}, {"mtu": 1401}, {"transport": "invalid"},
            {"multiplexing": "invalid"}, {"handshakeMode": "invalid"},
            {"portRange": "5000-4999"}, {"portRange": "1024-5000"}]):
        settings = dict(base, **change)
        path = folder / f"invalid-{index:02d}.json"
        write_json(path, {"protocol": "mieru", "peer": "127.0.0.1:6000", "settings": settings})
        result = subprocess.run([args.client_bin, "--mieru-proxy", str(path)], cwd=folder,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=4)
        (folder / f"invalid-{index:02d}.log").write_bytes(result.stdout)
        require(result.returncode != 0, "非法客户端配置被接受")
    # 第二个端口绑定失败时必须回滚第一个端口；失败进程退出后应可立即重绑。
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", http))
        blocker.listen()
        path = folder / "bind-rollback.json"
        write_json(path, {"peer": "127.0.0.1:6000", "settings": base})
        result = subprocess.run([args.client_bin, "--mieru-proxy", str(path)], cwd=folder,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=4)
        (folder / "bind-rollback.log").write_bytes(result.stdout)
        require(result.returncode != 0, "被占用的第二个代理端口未触发失败")
    assert_released([(socks, socket.SOCK_STREAM), (http, socket.SOCK_STREAM)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--client-bin", required=True)
    parser.add_argument("--peer-bin", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--node-host", default="127.0.0.1", help="节点承载 IP，支持 127.0.0.1 或 ::1；本机代理入口保持 IPv4 回环")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--quick", action="store_true", help="八行 smoke 覆盖，结果明确标注 smoke")
    modes.add_argument("--full", action="store_true", help="所有因素的两两覆盖，默认启用")
    parser.add_argument("--case-index", type=int, help="仅复现指定矩阵行，coverage 标为 partial")
    parser.add_argument("--case-timeout", type=float, default=90)
    parser.add_argument("--suite-timeout", type=float, default=2400)
    args = parser.parse_args()
    try:
        args.node_host = str(ipaddress.ip_address(args.node_host))
    except ValueError:
        parser.error("node-host 必须是 IPv4 或 IPv6 地址")
    rows = list(enumerate(matrix(args.quick)))
    if args.case_index is not None:
        if not 0 <= args.case_index < len(rows):
            parser.error("case-index 超出所选矩阵范围")
        rows = [rows[args.case_index]]
    for name in ("server_bin", "client_bin", "peer_bin"):
        value = Path(getattr(args, name)).resolve()
        if not value.is_file() or not os.access(value, os.X_OK):
            parser.error(f"{name} 不是可执行文件")
        setattr(args, name, str(value))
    require(args.case_timeout > 0 and args.suite_timeout > 0, "期限配置非法")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root = Path(tempfile.mkdtemp(prefix=output.stem + "-cases-", dir=output.parent))
    result = {"status": "fail", "upstream_sha": SHA,
              "coverage": "partial" if args.case_index is not None else ("smoke" if args.quick else "pairwise"), "cases": [],
              "case_index": args.case_index,
              "node_host": args.node_host,
              "limitations": ["黑盒进程清理不能证明进程内 Arc 或 FD 已全部回收",
                              "线协议互通成功不能证明官方复用概率分布",
                              "只验证原生回环出口；显式非法配置使 WARP 在解析阶段停止"]}
    started = time.monotonic()

    def timeout(_signum, _frame):
        raise Failure("当前 case 超时")

    previous = signal.signal(signal.SIGALRM, timeout)

    def run_case(name, row, function):
        folder = run_root / name
        folder.mkdir(mode=0o700)
        record = {"name": name, "status": "fail", "logs": str(folder.relative_to(output.parent))}
        if row:
            record["options"] = dict(zip(["transport", "multiplexing", "handshake", "low", "mtu"], row))
        before = time.monotonic()
        remaining = args.suite_timeout - (before - started)
        try:
            require(remaining > 0, "整套验收超时")
            signal.setitimer(signal.ITIMER_REAL, min(args.case_timeout, remaining))
            function(folder)
            record["status"] = "pass"
        except Exception as error:
            record["error"] = str(error) if isinstance(error, Failure) else type(error).__name__
            if isinstance(error, PacketFailure):
                record["evidence"] = error.evidence
            else:
                record["evidence"] = {"error_type": type(error).__name__, "error": str(error),
                                      "frames": [{"file": Path(frame.filename).name,
                                                  "line": frame.lineno, "function": frame.name}
                                                 for frame in traceback.extract_tb(error.__traceback__)]}
            record["evidence"]["fixture_tcp_events"] = fixtures.tcp_events(before)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        record["seconds"] = round(time.monotonic() - before, 3)
        result["cases"].append(record)
        write_json(output, result)
        print(f"{record['status']}: {name}", flush=True)

    try:
        with Fixtures() as fixtures:
            for index, row in rows:
                if time.monotonic() - started > args.suite_timeout:
                    result["error"] = "整套验收超时"
                    break
                run_case(f"{index:02d}-official-to-rust", row,
                         lambda folder, r=row, n=index == 0: official_to_rust(args, folder, r, fixtures, n))
                run_case(f"{index:02d}-rust-to-official", row,
                         lambda folder, r=row, n=index == 0: rust_to_official(args, folder, r, fixtures, n))
            if args.case_index is None:
                run_case("configuration-negative", None, lambda folder: configuration_negatives(args, folder))
        if result["cases"] and all(case["status"] == "pass" for case in result["cases"]) and "error" not in result:
            result["status"] = "pass"
    except Exception as error:
        result["error"] = str(error) if isinstance(error, Failure) else type(error).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        result["seconds"] = round(time.monotonic() - started, 3)
        write_json(output, result)
    print(f"{result['status']}: {result['coverage']} 互通验收", flush=True)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
