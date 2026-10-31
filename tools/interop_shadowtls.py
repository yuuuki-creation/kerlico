#!/usr/bin/env python3
"""仅在 worker 验收 ShadowTLS 包装与真实 SS/SS2022 内层，不把裸流当网站代理。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
import random
from pathlib import Path
import socket
import socketserver
import ssl
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

def configure_ports(selection):
    # 避开自动连接的临时端口段；两方向分段，且每个作业不重复分配。
    low, high = (10000, 15000) if selection == "client" else (15000, 20000) if selection == "server" else (10000, 30000)
    temporary = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
    start, end = map(int, temporary)
    if max(low, start) < min(high, end+1):
        raise RuntimeError("测试监听端口段与 worker 临时端口段冲突")
    candidates = list(range(low, high))
    random.SystemRandom().shuffle(candidates)
    def allocate():
        while candidates:
            port = candidates.pop()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as four, socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as six:
                    four.bind(("127.0.0.1", port))
                    six.bind(("::1", port))
                    return port
            except OSError:
                continue
        raise RuntimeError("当前作业的可用测试监听端口耗尽")
    h.free_port = allocate

class ConcurrentOrigin:
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
                    with self.server.access:
                        if self.server.closing:
                            return
                        self.server.connections.add(connection)
                    connection.do_handshake()
                    request = connection.recv(4096)
                    if request.startswith(b"GET "):
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\norigin")
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    if connection is not None:
                        with self.server.access:
                            self.server.connections.discard(connection)
                        connection.close()
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True
        self.server = Server(("127.0.0.1", port), Handler)
        self.server.access = threading.Lock()
        self.server.connections = set()
        self.server.closing = False
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    def __enter__(self):
        self.thread.start()
        return self
    def poll(self):
        return None if self.thread.is_alive() else 1
    def __exit__(self, *_):
        self.server.shutdown()
        with self.server.access:
            self.server.closing = True
            connections = list(self.server.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("并发 TLS 站点未有界退出")

def wait_listener(child, endpoint):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("服务端在就绪前退出")
        try:
            with socket.create_connection(endpoint, timeout=0.2):
                return
        except OSError:
            time.sleep(0.03)
    raise RuntimeError("指定地址族的监听器未在预算内就绪")

def material(root):
    cert, key = root/"certificate.pem", root/"private-key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=shadowtls.example.invalid", "-addext", "subjectAltName=DNS:shadowtls.example.invalid", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=30)
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
        origin_command = ["openssl", "s_server", "-quiet", "-accept", "127.0.0.1:"+str(origin_port), "-cert", str(cert), "-key", str(key), "-www", "-tls1_2" if tls_version == "1.2" else "-tls1_3"]
        if args.v2_no_tickets and version == 2 and tls_version == "1.3":
            origin_command.extend(["-num_tickets", "0"])
        if args.origin_kind == "concurrent":
            origin = stack.enter_context(ConcurrentOrigin(cert, key, origin_port, tls_version, 0 if args.v2_no_tickets and version == 2 and tls_version == "1.3" else 2, args.origin_curve))
        else:
            if args.origin_curve:
                origin_command.extend(["-groups", args.origin_curve])
            origin = stack.enter_context(h.process(origin_command, directory, "origin"))
        h.wait_ready(origin, origin_port)
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        banner = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), Banner)))
        fin = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), AfterEof)))
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
        server_process = stack.enter_context(h.process([binary, "run", "-c", str(path)], directory, "server"))
        server_processes = [(server_process, "本项目节点" if direction == "server" else "sing-box节点")]
        front_processes = {}
        for n, endpoint, inner_port in official_nodes:
            h.wait_ready(server_process, inner_port)
            command = ["env", "MONOIO_FORCE_LEGACY_DRIVER=1", "RUST_LOG=error", args.official_server, "--threads", "1"]
            if version == 3:
                command.append("--v3")
                if strict:
                    command.append("--strict")
            host = "["+endpoint[0]+"]" if ":" in endpoint[0] else endpoint[0]
            command.extend(["server", "--listen", host+":"+str(endpoint[1]), "--server", "127.0.0.1:"+str(inner_port), "--tls", "127.0.0.1:"+str(origin_port), "--password", "outer-test-"+str(11+n)])
            child = stack.enter_context(h.process(command, directory, "official-node"+str(n)))
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
                with h.process([binary, "run", "-c", str(path)], case_root, "client") as child:
                    h.wait_ready(child, rules[0][1])
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
            child.terminate()
            code = child.wait(timeout=4)
            if code != 0:
                raise RuntimeError(role+"退出码不为0："+str(code))
            checks.append(role+"4秒内退出，退出码0")
    return checks

def main():
    parser = argparse.ArgumentParser(description="ShadowTLS真实内层组合，禁止本地运行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--origin-kind", choices=("concurrent", "openssl-serial"), default="concurrent")
    parser.add_argument("--origin-curve", help="可选受控TLS组，例如prime256v1用于真实HRR对照")
    parser.add_argument("--official-server", help="可选官方0.2.25节点；只替换v2/v3参考外层，内层仍用固定sing-box")
    parser.add_argument("--methods", default=",".join(METHODS))
    parser.add_argument("--only")
    parser.add_argument("--v2-no-tickets", action="store_true", help="仅v2/TLS1.3明确关闭握手站点票据，结果与默认条件分列")
    args = parser.parse_args()
    os.umask(0o077)
    configure_ports(args.only)
    args.kerlico, args.sing_box = str(Path(args.kerlico).resolve()), str(Path(args.sing_box).resolve())
    if args.official_server:
        args.official_server = str(Path(args.official_server).resolve())
        version = subprocess.run([args.official_server, "--version"], capture_output=True, text=True, timeout=5)
        if version.returncode or "0.2.25" not in version.stdout:
            raise RuntimeError("官方参考版本不符")
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = material(root)
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
                    h.write_json(root/"results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "reference_sha256": hashlib.sha256(Path(args.sing_box).read_bytes()).hexdigest(), "v2_no_tickets": args.v2_no_tickets, "origin_kind": args.origin_kind, "origin_curve": args.origin_curve, "origin_ssl_version": ssl.OPENSSL_VERSION, "official_server_sha256": hashlib.sha256(Path(args.official_server).read_bytes()).hexdigest() if args.official_server else None, "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "helper_sha256": hashlib.sha256(Path(h.__file__).read_bytes()).hexdigest(), "results": results})
    if not results or not all(result["ok"] for result in results):
        raise SystemExit(1)
if __name__ == "__main__":
    main()
