#!/usr/bin/env python3
import argparse
import base64
import ctypes
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import hashlib
import errno
import ipaddress
import json
import os
import random
import re
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import struct
import sys
import threading
import subprocess
import time
import interop_vless as h

METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]
MODES = [(1, False, "1.2"), (2, False, "1.2"), (2, False, "1.3"), (3, True, "1.3"), (3, False, "1.2"), (3, False, "1.3")]
class Banner(h.TcpEcho):
    def handle(self):
        self.request.sendall(b"server-first")
        super().handle()
class AfterEof(h.TcpEcho):
    def handle(self):
        self.request.settimeout(4)
        try:
            while self.request.recv(16384):
                pass
            self.request.sendall(b"after-eof")
        except OSError:
            pass

def exact(sock, length):
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length-len(result))
        if not part:
            break
        result.extend(part)
    return bytes(result)

def tcp(port, payload, banner=False):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
        stream.settimeout(5)
        if banner and exact(stream, 12) != b"server-first":
            raise RuntimeError("目标先发数据未到达")
        stream.sendall(len(payload).to_bytes(4, "big") + payload)
        return exact(stream, len(payload))

def eof(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=4) as stream:
            stream.settimeout(2)
            stream.sendall(b"fin-probe")
            stream.shutdown(socket.SHUT_WR)
            return exact(stream, 9) == b"after-eof"
    except OSError:
        return False

def configure_ports(selection, listen_port_range=None):
    # 避开自动连接的临时端口段；两方向分段，且每个作业不重复分配。
    low, high = (10000, 15000) if selection == "client" else (15000, 20000) if selection == "server" else (10000, 30000)
    if listen_port_range:
        try:
            low, high = map(int, listen_port_range.split(":"))
        except ValueError:
            raise RuntimeError("监听端口段必须为起始:结束，结束值不包含") from None
        if not 1024 <= low < high <= 65536:
            raise RuntimeError("监听端口段超出非特权 TCP 端口范围")
    dynamic = []
    if os.name == "nt":
        for family in ("ipv4", "ipv6"):
            result = subprocess.run(["netsh", "int", family, "show", "dynamicport", "tcp"], capture_output=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            values = re.findall(rb":\s*(\d+)\s*$", result.stdout, re.MULTILINE)
            if result.returncode or len(values) != 2:
                raise RuntimeError("无法读取 Windows TCP 动态端口段，未启动参考程序")
            start, count = map(int, values)
            dynamic.append((start, start+count-1))
    elif Path("/proc/sys/net/ipv4/ip_local_port_range").is_file():
        dynamic.append(tuple(map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())))
    for start, end in dynamic:
        if max(low, start) < min(high, end+1):
            raise RuntimeError("测试监听端口段与系统临时端口段冲突")
    candidates = list(range(low, high))
    random.SystemRandom().shuffle(candidates)
    def allocate():
        while candidates:
            port = candidates.pop()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as four, socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as six:
                    if os.name == "nt":
                        four.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        six.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    four.bind(("127.0.0.1", port))
                    six.bind(("::1", port))
                    return port
            except OSError:
                continue
        raise RuntimeError("当前作业的可用测试监听端口耗尽")
    h.free_port = allocate
    return {"listen_range": [low, high], "dynamic_ranges": dynamic, "allocation": "每个作业不重复，分配前检查两族回环绑定"}

def resolve_openssl(explicit=None):
    candidate = explicit or os.environ.get("SHADOWTLS_OPENSSL") or shutil.which("openssl")
    if candidate is None or not Path(candidate).is_file():
        raise RuntimeError("找不到 OpenSSL，请用 --openssl 显式指定独立工具路径")
    return str(Path(candidate).resolve())

@contextmanager
def process(command, directory, label, env=None):
    with (directory/(label+".log")).open("wb") as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=directory, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        failed = False
        try:
            yield child
        except BaseException:
            failed = True
            raise
        finally:
            before = child.poll()
            unexpected = before is not None and not getattr(child, "_shadowtls_stop_requested", False)
            forced = False
            if before is None:
                child.terminate()
                try:
                    child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    forced = True
                    child.kill()
                    child.wait(timeout=3)
            h.write_json(directory/(label+"-cleanup.json"), {"unexpected_exit": unexpected, "force_killed_after_timeout": forced, "returncode": child.returncode, "graceful_drain_verified": False})
            if unexpected and not failed:
                raise RuntimeError(label+"在请求停止前已意外退出，退出码"+str(before))
            if forced:
                raise RuntimeError(label+"终止超时后已强制清理")

def stop_process(child, role):
    code = child.poll()
    if code is not None:
        raise RuntimeError(role+"在请求停止前已意外退出，退出码"+str(code))
    child.terminate()
    child._shadowtls_stop_requested = True
    try:
        code = child.wait(timeout=4)
    except subprocess.TimeoutExpired:
        raise RuntimeError(role+"未在4秒内完成请求的终止") from None
    if os.name == "nt":
        return role+"4秒内清理，Windows强制终止，未验证优雅排空，退出码"+str(code)
    if code != 0:
        raise RuntimeError(role+"退出码不为0："+str(code))
    return role+"4秒内退出，退出码0"

def close_owned_connection(connection):
    errors = []
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError as error:
        if error.errno not in (errno.ENOTCONN, errno.EBADF, errno.EINVAL, 10022, 10038, 10057):
            errors.append("shutdown:"+type(error).__name__+":"+str(error.errno))
    try:
        connection.close()
    except OSError as error:
        errors.append("close:"+type(error).__name__+":"+str(error.errno))
    return errors


class OwnedTcpServer(socketserver.ThreadingTCPServer):
    """登记本任务连接和非daemon线程，退出时关闭并有界join所有handler。"""
    allow_reuse_address = False
    block_on_close = False

    def __init__(self, endpoint, handler, max_handlers=256):
        if not ipaddress.ip_address(endpoint[0]).is_loopback:
            raise RuntimeError("测试目标只允许字面回环地址")
        self.address_family = socket.AF_INET6 if ":" in endpoint[0] else socket.AF_INET
        self.access = threading.Lock()
        self.connections, self.handlers, self.workers = set(), [], []
        self.errors, self.connection_errors = [], []
        self.closing = False
        self.max_handlers = max_handlers
        self.pid = os.getpid()
        self.cleanup = None
        super().__init__(endpoint, handler)
        self.thread = threading.Thread(target=self.run_listener, daemon=False)

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()

    def run_listener(self):
        try:
            self.serve_forever(poll_interval=0.05)
        except BaseException as error:
            with self.access:
                self.errors.append("listener:"+type(error).__name__)

    def process_request(self, request, client_address):
        with self.access:
            rejected = self.closing or len(self.handlers) >= self.max_handlers
            if not rejected:
                self.connections.add(request)
                handler = threading.Thread(target=self.run_handler, args=(request, client_address), daemon=False)
                self.handlers.append(handler)
            elif not self.closing:
                self.errors.append("handler数量超过夹具上限")
        if rejected:
            errors = close_owned_connection(request)
            with self.access:
                self.errors.extend(errors)
            return
        try:
            handler.start()
        except BaseException:
            with self.access:
                self.handlers.remove(handler)
                self.connections.discard(request)
                self.errors.extend(close_owned_connection(request))
            raise

    def run_handler(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except BaseException as error:
            with self.access:
                self.errors.append("handler:"+type(error).__name__)
        finally:
            errors = close_owned_connection(request)
            with self.access:
                self.connections.discard(request)
                self.errors.extend(errors)

    def track_connection(self, connection, replaced=None):
        with self.access:
            if replaced is not None:
                self.connections.discard(replaced)
            if self.closing:
                return False
            self.connections.add(connection)
            return True

    def release_connection(self, connection):
        with self.access:
            self.connections.discard(connection)

    def start_worker(self, target):
        def guarded():
            try:
                target()
            except BaseException as error:
                with self.access:
                    self.errors.append("worker:"+type(error).__name__)
        with self.access:
            if self.closing or len(self.workers) >= self.max_handlers:
                raise RuntimeError("夹具正在关闭或辅助线程超过上限")
            worker = threading.Thread(target=guarded, daemon=False)
            self.workers.append(worker)
            try:
                worker.start()
            except BaseException:
                self.workers.remove(worker)
                raise
        return worker

    def __enter__(self):
        try:
            self.thread.start()
        except BaseException:
            self.server_close()
            raise
        return self

    def poll(self):
        return None if self.thread.is_alive() else 1

    def __exit__(self, *_):
        errors = []
        with self.access:
            self.closing = True
        if self.thread.is_alive():
            self.shutdown()
        try:
            self.server_close()
        except OSError as error:
            errors.append("listener-close:"+type(error).__name__+":"+str(error.errno))
        self.thread.join(timeout=2)
        with self.access:
            connections, handlers, workers = list(self.connections), list(self.handlers), list(self.workers)
        for connection in connections:
            errors.extend(close_owned_connection(connection))
        deadline = time.monotonic()+3
        for thread in handlers+workers:
            thread.join(timeout=max(0, deadline-time.monotonic()))
        with self.access:
            self.errors.extend(errors)
            alive = sum(handler.is_alive() for handler in handlers)
            worker_alive = sum(worker.is_alive() for worker in workers)
            self.cleanup = {"handler_threads_started": len(handlers), "handler_threads_joined": len(handlers)-alive, "handler_threads_alive": alive, "auxiliary_threads_started": len(workers), "auxiliary_threads_joined": len(workers)-worker_alive, "auxiliary_threads_alive": worker_alive, "connections_remaining": len(self.connections), "listener_alive": self.thread.is_alive(), "connection_error_types": list(self.connection_errors), "errors": list(self.errors)}
        if self.cleanup["listener_alive"] or alive or worker_alive or self.cleanup["connections_remaining"] or self.cleanup["errors"]:
            raise RuntimeError("夹具未完成无错误的有界回收："+json.dumps(self.cleanup, ensure_ascii=False))


class ConcurrentOrigin(OwnedTcpServer):
    """每条真实 TLS 连接独立处理，错误鉴权的遗留连接不阻塞下一次握手。"""
    def __init__(self, cert, key, port, tls_version, tickets, curve):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if tls_version == "1.2" else ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert), str(key))
        context.set_alpn_protocols(["http/1.1"])
        context.num_tickets = tickets
        if curve:
            context.set_ecdh_curve(curve)
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                connection = None
                try:
                    connection = context.wrap_socket(self.request, server_side=True, do_handshake_on_connect=False)
                    connection.settimeout(5)
                    if not self.server.track_connection(connection, self.request):
                        return
                    connection.do_handshake()
                    request = connection.recv(4096)
                    if request.startswith(b"GET "):
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin")
                except (OSError, ssl.SSLError) as error:
                    with self.server.access:
                        self.server.connection_errors.append(type(error).__name__)
                finally:
                    if connection is not None:
                        self.server.release_connection(connection)
                        connection.close()
        super().__init__(("127.0.0.1", port), Handler)


def windows_listening(pid, host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    api = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
    word = ctypes.c_uint32
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(word), ctypes.c_int, word, word, word]
    api.restype = word
    size = word(0)
    result = api(None, ctypes.byref(size), False, family, 3, 0)
    if result not in (0, 122):
        raise OSError(result, "无法读取任务监听表")
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        result = api(buffer, ctypes.byref(size), False, family, 3, 0)
        if result == 122:
            continue
        if result:
            raise OSError(result, "无法读取任务监听表")
        data = buffer.raw
        count = struct.unpack_from("<I", data)[0]
        width = 56 if family == socket.AF_INET6 else 24
        if 4+count*width > len(data):
            raise RuntimeError("任务监听表长度不合法")
        for index in range(count):
            row = 4+index*width
            if family == socket.AF_INET6:
                address = socket.inet_ntop(family, data[row:row+16])
                local_port = socket.ntohs(struct.unpack_from("<I", data, row+20)[0] & 0xffff)
                state, owner = struct.unpack_from("<II", data, row+48)
            else:
                state = struct.unpack_from("<I", data, row)[0]
                address = socket.inet_ntop(family, data[row+4:row+8])
                local_port = socket.ntohs(struct.unpack_from("<I", data, row+8)[0] & 0xffff)
                owner = struct.unpack_from("<I", data, row+20)[0]
            if state == 2 and owner == pid and local_port == port and ipaddress.ip_address(address) == ipaddress.ip_address(host):
                return True
        return False
    raise RuntimeError("任务监听表在查询期间持续变化")


def linux_listening(pid, host, port):
    inodes = set()
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            link = os.readlink(descriptor)
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
        except FileNotFoundError:
            continue
    table = "tcp6" if ":" in host else "tcp"
    for line in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
        fields = line.split()
        address, number = fields[1].rsplit(":", 1)
        raw = bytes.fromhex(address)
        raw = b"".join(raw[index:index+4][::-1] for index in range(0, len(raw), 4))
        actual = socket.inet_ntop(socket.AF_INET6 if table == "tcp6" else socket.AF_INET, raw)
        if fields[3] == "0A" and int(number, 16) == port and fields[9] in inodes and ipaddress.ip_address(actual) == ipaddress.ip_address(host):
            return True
    return False


def owned_listener(pid, endpoint):
    host, port = endpoint
    if not ipaddress.ip_address(host).is_loopback:
        raise RuntimeError("只允许查询任务回环监听")
    if os.name == "nt":
        return windows_listening(pid, host, port)
    if sys.platform.startswith("linux"):
        return linux_listening(pid, host, port)
    raise RuntimeError("当前平台尚无可归属的监听检查")

def wait_listener(child, endpoint, timeout=10):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("服务端在就绪前退出")
        if owned_listener(child.pid, endpoint):
            return
        time.sleep(0.03)
    raise RuntimeError("指定地址族的监听器未在预算内就绪")

def material(root, openssl=None):
    cert, key = root/"certificate.pem", root/"private-key.pem"
    result = subprocess.run([resolve_openssl(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=shadowtls.example.invalid", "-addext", "subjectAltName=DNS:shadowtls.example.invalid", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("生成测试证书失败")
    return cert, key

def password(method, index, service=False):
    if method.startswith("2022-"):
        length = 16 if method == "2022-blake3-aes-128-gcm" else 32
        return base64.b64encode(bytes([index + (40 if service else 0)])*length).decode()
    return "inner-test-"+str(index)+"-"+method

def inner(method, index, eih=False, endpoint=None, node=False):
    modern = method.startswith("2022-")
    user, service = password(method, index), password(method, index, True)
    options = {"method": method, "key" if modern else "password": service if eih and node else user}
    if eih:
        options["users" if node else "identity_keys"] = [user if node else service]
    if endpoint:
        options.update(server=endpoint[0], port=endpoint[1])
    return {"type": "ss2022" if modern else "shadowsocks", "options": options}

def shadow_client(version, strict, tls_version, cert, method, index, eih, endpoint):
    value = {"version": version, "tls": {"server_name": "shadowtls.example.invalid", "ca_pem": cert.read_text(), "version": tls_version}, "inner": inner(method, index, eih, endpoint)}
    if version != 1:
        value["password"] = "outer-test-"+str(index)
    if version == 3:
        value["strict"] = strict
    return value

def shadow_node(version, strict, method, index, eih, origin):
    value = {"version": version, "handshake": {"host": "127.0.0.1", "port": origin}, "inner": inner(method, index, eih, node=True)}
    if version != 1:
        value["password"] = "outer-test-"+str(index)
    if version == 3:
        value["strict"] = strict
    return value

def reference_shadow(version, strict, endpoint, origin=None, cert=None, tls_version=None, index=11):
    value = {"type": "shadowtls", "version": version}
    if origin is not None:
        value.update(listen=endpoint[0], listen_port=endpoint[1], handshake={"server": "127.0.0.1", "server_port": origin})
        if version == 3:
            value.update(users=[{"password": "outer-test-"+str(index)}], strict_mode=strict)
        elif version == 2:
            value["password"] = "outer-test-"+str(index)
    else:
        value.update(server=endpoint[0], server_port=endpoint[1], tls={"enabled": True, "server_name": "shadowtls.example.invalid", "certificate": [cert.read_text()], "min_version": tls_version, "max_version": tls_version, "alpn": ["http/1.1"]})
        if version != 1:
            value["password"] = "outer-test-"+str(index)
    return value

def verify(args, root, cert, key, method, eih, version, strict, tls_version, direction, label):
    directory = root/label
    directory.mkdir(mode=0o700)
    checks = []
    official_nodes = []
    endpoints = [("127.0.0.1", h.free_port()), ("::1", h.free_port())]
    with ExitStack() as stack:
        origin_port = h.free_port()
        origin_command = [args.openssl, "s_server", "-quiet", "-accept", "127.0.0.1:"+str(origin_port), "-cert", str(cert), "-key", str(key), "-www", "-tls1_2" if tls_version == "1.2" else "-tls1_3"]
        if args.v2_no_tickets and version == 2 and tls_version == "1.3":
            origin_command.extend(["-num_tickets", "0"])
        if args.origin_kind == "concurrent":
            origin = stack.enter_context(ConcurrentOrigin(cert, key, origin_port, tls_version, 0 if args.v2_no_tickets and version == 2 and tls_version == "1.3" else 2, args.origin_curve))
        else:
            if args.origin_curve:
                origin_command.extend(["-groups", args.origin_curve])
            origin = stack.enter_context(process(origin_command, directory, "origin"))
        wait_listener(origin, ("127.0.0.1", origin_port))
        target4 = stack.enter_context(OwnedTcpServer(("127.0.0.1", 0), h.TcpEcho)).server_address[1]
        target6 = stack.enter_context(OwnedTcpServer(("::1", 0), h.TcpEcho)).server_address[1]
        banner = stack.enter_context(OwnedTcpServer(("127.0.0.1", 0), Banner)).server_address[1]
        fin = stack.enter_context(OwnedTcpServer(("127.0.0.1", 0), AfterEof)).server_address[1]
        if direction == "server":
            server = {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node"+str(n), "type": "shadowtls", "listen": ("["+host+"]" if ":" in host else host)+":"+str(port), "outbound": "direct", "options": shadow_node(version, strict, method, 11+n, eih, origin_port)} for n, (host, port) in enumerate(endpoints)], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 6000, "drain_timeout_ms": 400, "max_sessions": 128}}
            binary = args.kerlico
        else:
            inbounds = []
            for n, endpoint in enumerate(endpoints):
                outer = reference_shadow(version, strict, endpoint, origin=origin_port, index=11+n)
                outer.update(tag="outer"+str(n), detour="inner"+str(n))
                child = {"type": "shadowsocks", "tag": "inner"+str(n), "listen": "127.0.0.1", "listen_port": h.free_port(), "method": method, "password": password(method, 11+n, eih), "network": "tcp"}
                if eih:
                    child["users"] = [{"name": "test", "password": password(method, 11+n)}]
                if args.official_server and version >= 2:
                    inbounds.append(child)
                    official_nodes.append((n, endpoint, child["listen_port"]))
                else:
                    inbounds.extend([outer, child])
            server = {"log": {"level": "error"}, "inbounds": inbounds, "outbounds": [{"type": "direct"}]}
            binary = args.sing_box
        path = directory/"server.json"
        h.write_json(path, server)
        server_process = stack.enter_context(process([binary, "run", "-c", str(path)], directory, "server"))
        server_processes = [(server_process, "本项目节点" if direction == "server" else "sing-box节点")]
        front_processes = {}
        for n, endpoint, inner_port in official_nodes:
            wait_listener(server_process, ("127.0.0.1", inner_port))
            command = [args.official_server, "--threads", "1"]
            if version == 3:
                command.append("--v3")
                if strict:
                    command.append("--strict")
            host = "["+endpoint[0]+"]" if ":" in endpoint[0] else endpoint[0]
            command.extend(["server", "--listen", host+":"+str(endpoint[1]), "--server", "127.0.0.1:"+str(inner_port), "--tls", "127.0.0.1:"+str(origin_port), "--password", "outer-test-"+str(11+n)])
            child = stack.enter_context(process(command, directory, "official-node"+str(n), env={**os.environ, "MONOIO_FORCE_LEGACY_DRIVER": "1", "RUST_LOG": "error"}))
            front_processes[endpoint] = child
            server_processes.append((child, "官方ShadowTLS节点"+str(n)))
        for endpoint in endpoints:
            wait_listener(front_processes.get(endpoint, server_process), endpoint)
        for n, endpoint in enumerate(endpoints):
            mutations = ("valid", "wrong-inner") if version == 1 else ("valid", "wrong-inner", "wrong-outer")
            for mutation in mutations:
                case_root = directory/("node"+str(n)+"-"+mutation)
                case_root.mkdir(mode=0o700)
                rules = [("tcp4", h.free_port(), "127.0.0.1", target4), ("tcp6", h.free_port(), "::1", target6), ("domain", h.free_port(), "localhost", target4), ("banner", h.free_port(), "127.0.0.1", banner), ("fin", h.free_port(), "127.0.0.1", fin)]
                if direction == "client":
                    options = shadow_client(version, strict, tls_version, cert, method, 11+n, eih, endpoint)
                    if mutation == "wrong-inner":
                        options["inner"] = inner(method, 23+n, eih, endpoint)
                    elif mutation == "wrong-outer":
                        options["password"] = "other-node-outer-test"
                    client = {"version": 1, "outbounds": [{"tag": "proxy", "type": "shadowtls", "options": options}], "inbounds": [{"tag": tag, "type": "tcp-forward", "listen": "127.0.0.1:"+str(port), "target": {"host": host, "port": target}, "outbound": "proxy"} for tag, port, host, target in rules], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 6000, "drain_timeout_ms": 400, "max_sessions": 128}}
                    binary = args.kerlico
                else:
                    outer = reference_shadow(version, strict, endpoint, cert=cert, tls_version=tls_version, index=11+n)
                    outer["tag"] = "carrier"
                    if mutation == "wrong-outer":
                        outer["password"] = "other-node-outer-test"
                    index = 23+n if mutation == "wrong-inner" else 11+n
                    credential = password(method, index, True)+":"+password(method, index) if eih else password(method, index)
                    proxy = {"type": "shadowsocks", "tag": "proxy", "server": endpoint[0], "server_port": endpoint[1], "method": method, "password": credential, "detour": "carrier", "network": "tcp"}
                    client = {"log": {"level": "error"}, "inbounds": [{"type": "direct", "tag": tag, "listen": "127.0.0.1", "listen_port": port, "network": "tcp", "override_address": host, "override_port": target} for tag, port, host, target in rules], "outbounds": [proxy, outer], "route": {"final": "proxy"}}
                    binary = args.sing_box
                path = case_root/"client.json"
                h.write_json(path, client)
                with process([binary, "run", "-c", str(path)], case_root, "client") as child:
                    for _, port, _, _ in rules:
                        wait_listener(child, ("127.0.0.1", port))
                    if mutation != "valid":
                        try:
                            result = tcp(rules[0][1], b"must-not-reach-site")
                        except (OSError, TimeoutError):
                            result = b""
                        if result:
                            raise RuntimeError("错误层凭据得到业务回写")
                        checks.append("节点"+str(n)+mutation+"拒绝")
                        continue
                    for tag, port, _, _ in rules[:3]:
                        for size in (17, 4096, 65536):
                            payload = b"t"*size
                            stage = "节点"+str(n)+"/"+tag+"/TCP"+str(size)
                            try:
                                received = tcp(port, payload)
                            except (OSError, TimeoutError) as error:
                                raise RuntimeError(stage+"："+type(error).__name__) from None
                            if received != payload:
                                raise RuntimeError(stage+"回写不一致，收到"+str(len(received)))
                    checks.append("节点"+str(n)+"双族及域名TCP至65536")
                    if tcp(rules[3][1], b"greeting-first", True) != b"greeting-first":
                        raise RuntimeError("目标先发数据后的回写不一致")
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        payloads = [("flow-"+str(i)).encode()*1024 for i in range(4)]
                        try:
                            replies = list(pool.map(lambda data: tcp(rules[0][1], data), payloads))
                        except (OSError, TimeoutError) as error:
                            raise RuntimeError("节点"+str(n)+"四路并发："+type(error).__name__) from None
                        if replies != payloads:
                            raise RuntimeError("四路并发内层数据混用")
                    checks.append("节点"+str(n)+"目标先发与四流隔离")
                    if n == 0 and method == METHODS[0] and not eih:
                        checks.append("本对端FIN后回包"+("已观察" if eof(rules[4][1]) else "未保证，tcp_eof=false"))
        for child, role in reversed(server_processes):
            checks.append(stop_process(child, role))
    if args.origin_kind == "concurrent":
        h.write_json(directory/"origin-cleanup.json", origin.cleanup)
        checks.append("并发站点全部handler已join，自有连接已关闭")
    return checks

def main():
    parser = argparse.ArgumentParser(description="ShadowTLS真实内层组合，仅使用项目隔离目录和空闲回环端口")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--openssl", help="独立OpenSSL可执行文件，优先于SHADOWTLS_OPENSSL与现有PATH")
    parser.add_argument("--listen-port-range", help="可选测试监听段，起始:结束，结束值不包含")
    parser.add_argument("--origin-kind", choices=("concurrent", "openssl-serial"), default="concurrent")
    parser.add_argument("--origin-curve", help="可选受控TLS组，例如prime256v1用于真实HRR对照")
    parser.add_argument("--official-server", help="可选官方0.2.25节点；只替换v2/v3参考外层，内层仍用固定sing-box")
    parser.add_argument("--methods", default=",".join(METHODS))
    parser.add_argument("--only")
    parser.add_argument("--v2-no-tickets", action="store_true", help="仅v2/TLS1.3明确关闭握手站点票据，结果与默认条件分列")
    args = parser.parse_args()
    os.umask(0o077)
    ports = configure_ports(args.only, args.listen_port_range)
    args.openssl = resolve_openssl(args.openssl)
    args.kerlico, args.sing_box = str(Path(args.kerlico).resolve()), str(Path(args.sing_box).resolve())
    if args.official_server:
        args.official_server = str(Path(args.official_server).resolve())
        version = subprocess.run([args.official_server, "--version"], capture_output=True, text=True, timeout=5)
        if version.returncode or "0.2.25" not in version.stdout:
            raise RuntimeError("官方参考版本不符")
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = material(root, args.openssl)
    results = []
    for method in args.methods.split(","):
        for eih in ((False, True) if method in ("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm") else (False,)):
            for version, strict, tls_version in MODES:
                for direction in ("client", "server"):
                    label = "-".join((method, "eih" if eih else "single", "v"+str(version), "strict" if strict else "compat", "tls"+tls_version, direction))
                    label += "-no-tickets" if args.v2_no_tickets and version == 2 and tls_version == "1.3" else "-default-tickets"
                    label += "-official-node" if args.official_server and direction == "client" and version >= 2 else "-sing-box"
                    label += "-origin-"+args.origin_kind+("-"+args.origin_curve if args.origin_curve else "")
                    if args.only and args.only not in label:
                        continue
                    try:
                        result = {"case": label, "ok": True, "checks": verify(args, root, cert, key, method, eih, version, strict, tls_version, direction, label)}
                    except Exception as error:
                        result = {"case": label, "ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
                    print(json.dumps(result, ensure_ascii=False), flush=True)
                    results.append(result)
                    h.write_json(root/"results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "reference_sha256": hashlib.sha256(Path(args.sing_box).read_bytes()).hexdigest(), "v2_no_tickets": args.v2_no_tickets, "origin_kind": args.origin_kind, "origin_curve": args.origin_curve, "origin_ssl_version": ssl.OPENSSL_VERSION, "ports": ports, "listener_readiness": "只读核对任务PID、回环地址与端口，不做TCP业务探测", "process_exit_scope": "先拒绝提前退出，Windows只记录请求后的强制清理，不计优雅排空" if os.name == "nt" else "先拒绝提前退出，再检查SIGTERM退出码0的有界退出", "official_server_sha256": hashlib.sha256(Path(args.official_server).read_bytes()).hexdigest() if args.official_server else None, "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "helper_sha256": hashlib.sha256(Path(h.__file__).read_bytes()).hexdigest(), "results": results})
    if not results or not all(result["ok"] for result in results):
        raise SystemExit(1)
if __name__ == "__main__":
    main()
