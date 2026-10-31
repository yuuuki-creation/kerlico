#!/usr/bin/env python3
"""Sudoku原生CLI对端矩阵；仅在专用worker运行，逐负载保留真实结果。"""
import argparse
import concurrent.futures
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
SOURCE = json.loads((HERE / "SOURCE.json").read_text())
MODES = ["raw", "legacy", "stream", "poll", "auto", "ws"]
METHODS = ["aes-128-gcm", "chacha20-poly1305", "none"]
KEY = "synthetic-sudoku-cli-node-a-secret"
TIMEOUT = 12


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def free_port(host, kind=socket.SOCK_STREAM):
    with socket.socket(family(host), kind) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def exact(stream, length):
    data = bytearray()
    while len(data) < length:
        piece = stream.recv(min(length - len(data), 65536))
        if not piece:
            raise EOFError(f"目标提前EOF: {len(data)}/{length}")
        data.extend(piece)
    return bytes(data)


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack("!H", port)
    except ValueError:
        name = host.encode("ascii")
        return bytes([3, len(name)]) + name + struct.pack("!H", port)


def read_address(read):
    kind = read(1)[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, read(4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(16))
    elif kind == 3:
        host = read(read(1)[0]).decode("ascii")
    else:
        raise ValueError("SOCKS地址类型不合法")
    return host, struct.unpack("!H", read(2))[0]


def socks(proxy, host, port, udp=False):
    stream = socket.create_connection(proxy, TIMEOUT)
    stream.settimeout(TIMEOUT)
    stream.sendall(b"\x05\x01\x00")
    if exact(stream, 2) != b"\x05\x00":
        stream.close()
        raise ValueError("原生参考SOCKS协商拒绝")
    stream.sendall(bytes([5, 3 if udp else 1, 0]) + address(host, port))
    reply = exact(stream, 3)
    if reply != b"\x05\x00\x00":
        stream.close()
        raise ValueError("原生参考SOCKS请求拒绝")
    bound = read_address(lambda n: exact(stream, n))
    if udp and bound[0] in ("0.0.0.0", "::"):
        bound = (proxy[0], bound[1])
    return stream, bound


class Echo:
    """只承担测试目标和流量激励，不解释或实现Sudoku协议。"""
    def __init__(self, host, udp=False, server_first=True):
        self.udp, self.first = udp, server_first
        self.stop = threading.Event()
        self.sources = []
        self.sock = socket.socket(family(host), socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(.2)
        self.host, self.port = host, self.sock.getsockname()[1]
        if not udp:
            self.sock.listen(32)
        self.children = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def tcp(self, stream):
        with stream:
            stream.settimeout(TIMEOUT)
            try:
                if self.first:
                    stream.sendall(b"ready")
                while not self.stop.is_set():
                    data = stream.recv(65536)
                    if not data:
                        stream.sendall(b"tail")
                        stream.shutdown(socket.SHUT_WR)
                        return
                    stream.sendall(data)
            except OSError:
                return

    def run(self):
        while not self.stop.is_set():
            try:
                if self.udp:
                    data, source = self.sock.recvfrom(65535)
                    self.sources.append(source)
                    self.sock.sendto(data, source)
                else:
                    stream, _ = self.sock.accept()
                    thread = threading.Thread(target=self.tcp, args=(stream,), daemon=True)
                    self.children.append(thread)
                    thread.start()
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(2)
        for thread in self.children:
            thread.join(.1)


class Process:
    def __init__(self, command, directory, env=None):
        self.log = (directory / "process.log").open("wb")
        self.process = subprocess.Popen(command, cwd=directory, env=env, stdout=self.log,
                                        stderr=subprocess.STDOUT, start_new_session=True)

    def ready(self, host, port):
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("对端启动退出，检查本标签process.log")
            try:
                with socket.create_connection((host, port), .1):
                    return
            except OSError:
                time.sleep(.02)
        raise TimeoutError("对端监听未就绪")

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(TIMEOUT)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
        code = self.process.returncode
        self.log.close()
        return code


def protocol(case, key=KEY):
    return {"key": key, "aead": case["aead"], "table_type": case["table"], "padding_min": 5,
            "padding_max": 15, "pure_downlink": case["pure"], "custom_tables": case["custom"],
            "udp_enabled": True, "allow_insecure": case["aead"] == "none"}


def kernel_node(case, host, port, tls):
    mask = {"mode": case["mode"]}
    if case["mode"] in ("stream", "poll", "auto", "ws"):
        mask["path_root"] = "sudoku-gate"
    if case["tls"]:
        mask["tls"] = {"cert_pem": tls["cert"], "key_pem": tls["key"]}
    node = {"tag": "node", "type": "sudoku", "listen": endpoint(host, port), "outbound": "exit",
            "options": {"protocol": protocol(case), "http_mask": mask}}
    return {"version": 1, "outbounds": [{"tag": "exit", "type": "direct"}], "inbounds": [],
            "local_inbounds" if case["aead"] == "none" else "nodes": [node],
            "limits": {"max_sessions": 256, "connect_timeout_ms": 5000, "idle_timeout_ms": 30000,
                       "drain_timeout_ms": 1000, "max_datagram_size": 65507}}


def kernel_client(case, host, port, tcp_targets, udp_targets, tls, key=KEY):
    mask = {"mode": case["mode"]}
    if case["mode"] in ("stream", "poll", "auto", "ws"):
        mask.update({"path_root": "sudoku-gate", "http_version": case["http_version"]})
    if case["tls"]:
        mask.update({"tls": {"server_name": "localhost", "ca_pem": tls["cert"]}, "host": "localhost"})
    options = {"server": {"host": host, "port": port}, "protocol": protocol(case, "synthetic-wrong-sudoku-cli-secret" if case["axis"] == "credentials" else key),
               "http_mask": mask, "multiplex": case["mux"], "max_mux_streams": 32}
    entries, ports = [], {"tcp": [], "udp": []}
    for kind, targets in [("tcp", tcp_targets), ("udp", udp_targets)]:
        for index, target in enumerate(targets):
            listen = free_port("127.0.0.1", socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
            entries.append({"tag": f"{kind}-{index}", "type": kind + "-forward", "listen": endpoint("127.0.0.1", listen),
                            "target": {"host": target.host, "port": target.port}, "outbound": "proxy"})
            ports[kind].append(listen)
    return {"version": 1, "outbounds": [{"tag": "proxy", "type": "sudoku", "options": options}],
            "inbounds": entries, "limits": {"max_sessions": 256, "connect_timeout_ms": 5000,
                                            "drain_timeout_ms": 1000, "max_datagram_size": 65507}}, ports


def native_config(peer, case, server, host, port, socks_port):
    key = KEY if server or case["axis"] != "credentials" else "synthetic-wrong-sudoku-cli-secret"
    raw = case["mode"] == "raw"
    mode = "legacy" if raw else case["mode"]
    if peer == "official":
        return {"mode": "server" if server else "client", "transport": "tcp", "local_port": port if server else socks_port,
                "server_address": endpoint(host, port), "key": key, "aead": case["aead"], "ascii": case["table"],
                "padding_min": 5, "padding_max": 15, "enable_pure_downlink": case["pure"],
                "custom_tables": case["custom"], "multiplex": case["mux"], "suspicious_action": "silent",
                "rule_urls": ["global"], "fallback_address": "", "external_controller": "",
                "httpmask": {"disable": raw, "mode": mode, "tls": case["tls"], "host": "localhost" if case["tls"] else "",
                             "path_root": "sudoku-gate" if mode in ("stream", "poll", "auto", "ws") else ""}}
    fields = {"key": key, "aead-method": case["aead"], "table-type": case["table"], "padding-min": 5,
              "padding-max": 15, "enable-pure-downlink": case["pure"], "custom-tables": case["custom"],
              "http-mask-mode": mode, "path-root": "sudoku-gate" if mode in ("stream", "poll", "auto", "ws") else ""}
    config = {"mode": "rule", "log-level": "warning", "allow-lan": False, "ipv6": True,
              "external-controller": "", "rules": ["MATCH,DIRECT"]}
    if server:
        fields.update({"name": "sudoku-reference", "type": "sudoku", "listen": host, "port": port,
                       "disable-http-mask": raw})
        config["listeners"] = [fields]
    else:
        fields.update({"name": "proxy", "type": "sudoku", "server": host, "port": port,
                       "http-mask": not raw, "http-mask-tls": case["tls"], "http-mask-host": "localhost" if case["tls"] else "",
                       "multiplex": case["mux"]})
        config.update({"socks-port": socks_port, "bind-address": "127.0.0.1", "proxies": [fields], "rules": ["MATCH,proxy"]})
    return config


def start(binary, peer, config, directory, env):
    directory.mkdir()
    path = directory / "config.json"
    path.write_text(json.dumps(config, indent=2) + "\n")
    if peer == "self":
        check, run = [binary, "check", "-c", str(path.resolve())], [binary, "run", "-c", str(path.resolve())]
    elif peer == "mihomo":
        check, run = [binary, "-t", "-f", str(path.resolve()), "-d", str(directory.resolve())], [binary, "-f", str(path.resolve()), "-d", str(directory.resolve())]
    else:
        check, run = [binary, "-test", "-c", str(path.resolve())], [binary, "-c", str(path.resolve())]
    with (directory / "check.log").open("wb") as log:
        result = subprocess.run(check, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("原生配置校验失败，保留check.log")
    return Process(run, directory, env)


def tcp_check(connect, size, first, eof):
    stream = connect()
    with stream:
        stream.settimeout(TIMEOUT)
        if first and exact(stream, 5) != b"ready":
            raise AssertionError("目标先发内容不符")
        payload = bytes([size % 251]) * size
        errors = []
        def send():
            try:
                for offset in range(0, len(payload), 32768):
                    stream.sendall(payload[offset:offset + 32768])
                if eof:
                    stream.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)
        writer = threading.Thread(target=send, daemon=True)
        writer.start()
        if exact(stream, size) != payload:
            raise AssertionError("TCP内容不符")
        if eof:
            if exact(stream, 4) != b"tail" or stream.recv(1) != b"":
                raise AssertionError("FIN尾部或EOF不符")
        writer.join(TIMEOUT)
        if writer.is_alive():
            raise TimeoutError("TCP写入线程未退出")
        if errors:
            raise errors[0]


def execute(case, args, directory, emit, tls):
    processes, targets = [], []
    env = os.environ.copy()
    if tls:
        env["SSL_CERT_FILE"] = str(Path(args.cert).resolve())
    host = "::1" if case["node_ipv6"] else "127.0.0.1"
    port, proxy_port = free_port(host), free_port("127.0.0.1")
    first = case["first"]
    tcp_targets = [Echo("127.0.0.1", server_first=first), Echo("::1", server_first=first), Echo("localhost", server_first=first)]
    udp_targets = [Echo("127.0.0.1", udp=True), Echo("::1", udp=True), Echo("localhost", udp=True)]
    targets.extend(tcp_targets + udp_targets)
    try:
        client_case = dict(case, axis="credential-positive") if case["axis"] == "credentials" else case
        if case["role"] == "kernel-client":
            if args.peer == "self":
                server_config = kernel_node(case, host, port, tls)
            else:
                server_config = native_config(args.peer, case, True, host, port, proxy_port)
            server = start(args.kerlico if args.peer == "self" else args.reference, args.peer, server_config, directory / "server", env)
            processes.append(server)
            server.ready(host, port)
            config, ports = kernel_client(client_case, host, port, tcp_targets, udp_targets, tls)
            client = start(args.kerlico, "self", config, directory / "client", env)
            processes.append(client)
            client.ready("127.0.0.1", ports["tcp"][0])
            connectors = [lambda p=p: socket.create_connection(("127.0.0.1", p), TIMEOUT) for p in ports["tcp"]]
        else:
            server = start(args.kerlico, "self", kernel_node(case, host, port, tls), directory / "server", env)
            processes.append(server)
            server.ready(host, port)
            peer = args.peer
            if peer == "self":
                config, ports = kernel_client(client_case, host, port, tcp_targets, udp_targets, tls)
                client = start(args.kerlico, "self", config, directory / "client", env)
                connectors = [lambda p=p: socket.create_connection(("127.0.0.1", p), TIMEOUT) for p in ports["tcp"]]
                ready_port = ports["tcp"][0]
            else:
                client = start(args.reference, peer, native_config(peer, client_case, False, host, port, proxy_port), directory / "client", env)
                connectors = [lambda t=t: socks(("127.0.0.1", proxy_port), t.host, t.port)[0] for t in tcp_targets]
                ready_port = proxy_port
            processes.append(client)
            client.ready("127.0.0.1", ready_port)
        if case["axis"] == "credentials":
            tcp_check(connectors[0],17,first,case["mode"]!="ws" or case["mux"]=="on")
            emit(case,"correct-key-control","pass")
            client.close()
            negative = json.loads((directory/"client"/"config.json").read_text())
            client_peer = "self" if case["role"]=="kernel-client" or args.peer=="self" else args.peer
            wrong = "synthetic-wrong-sudoku-cli-secret"
            if client_peer=="self":
                negative["outbounds"][0]["options"]["protocol"]["key"]=wrong
            elif client_peer=="mihomo":
                negative["proxies"][0]["key"]=wrong
            else:
                negative["key"]=wrong
            client = start(args.kerlico if client_peer=="self" else args.reference,client_peer,negative,directory/"client-wrong-key",env)
            processes.append(client)
            client.ready("127.0.0.1",ports["tcp"][0] if client_peer=="self" else proxy_port)
            for connect in connectors:
                try:
                    with connect() as rejected:
                        rejected.settimeout(TIMEOUT)
                        rejected.sendall(b"wrong-key-probe")
                        received = rejected.recv(1)
                    emit(case, "wrong-key", "fail" if received else "pass")
                except socket.timeout:
                    emit(case, "wrong-key", "fail", reason="等待拒绝超时，不能证明有界关闭")
                except (OSError, EOFError, ValueError):
                    emit(case, "wrong-key", "pass")
            return
        eof = case["mode"] != "ws" or case["mux"] == "on"
        sizes = [17, 96000] + ([33 * 1024 * 1024] if case["axis"] == "rekey" else [])
        for index, connect in enumerate(connectors):
            for size in sizes:
                try:
                    tcp_check(connect, size, first, eof)
                    emit(case, "tcp", "pass", target_family=("domain" if index == 2 else 4 if index == 0 else 6), size=size, remote_eof=eof)
                except Exception as error:
                    emit(case, "tcp", "fail", target_family=("domain" if index == 2 else 4 if index == 0 else 6), size=size, error=type(error).__name__ + ": " + str(error))
        if case["axis"] == "mux":
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results = [pool.submit(tcp_check, connectors[i % 2], 32768 + i, first, eof) for i in range(16)]
                for i, result in enumerate(results):
                    try:
                        result.result(TIMEOUT * 2)
                        emit(case, "tcp-concurrent", "pass", stream=i)
                    except Exception as error:
                        emit(case, "tcp-concurrent", "fail", stream=i, error=type(error).__name__ + ": " + str(error))
        if case["axis"] == "lifecycle":
            with connectors[0]() as held:
                held.settimeout(TIMEOUT)
                if first and exact(held, 5) != b"ready":
                    raise AssertionError("取消前目标数据不符")
                started = time.monotonic()
                server.close()
                try:
                    ended = held.recv(1) == b""
                except (ConnectionResetError, BrokenPipeError):
                    ended = True
                emit(case, "server-stop-live-stream", "pass" if ended else "fail", elapsed_ms=int((time.monotonic()-started)*1000))
            restarted = start(args.kerlico if args.peer == "self" or case["role"] == "kernel-server" else args.reference,
                              "self" if args.peer == "self" or case["role"] == "kernel-server" else args.peer,
                              kernel_node(case,host,port,tls) if args.peer == "self" or case["role"] == "kernel-server" else native_config(args.peer,case,True,host,port,proxy_port),
                              directory / "server-restart", env)
            processes.append(restarted)
            restarted.ready(host,port)
            tcp_check(connectors[0],4096,first,eof)
            emit(case,"restart-same-endpoint","pass")
        native_udp = case["role"] == "kernel-server" and args.peer != "self"
        control = None
        relay = None
        if native_udp:
            control, relay = socks(("127.0.0.1", proxy_port), "0.0.0.0", 0, udp=True)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(("127.0.0.1", 0))
        udp_socket.settimeout(TIMEOUT)
        try:
            for index, target in enumerate(udp_targets):
                for size in [0, 17, 4096, 64000, 65507]:
                    if native_udp and size + 3 + len(address(target.host, target.port)) > 65507:
                        emit(case, "udp", "entry_limit", size=size, target_family=("domain" if index == 2 else 4 if index == 0 else 6),
                             reason="SOCKS5入口封装后超过本机IPv4 UDP负载上限；尚未送达Sudoku，不计通过")
                        continue
                    payload = bytes([size % 251]) * size
                    packet = b"\0\0\0" + address(target.host, target.port) + payload if native_udp else payload
                    destination = relay if native_udp else ("127.0.0.1", ports["udp"][index])
                    try:
                        udp_socket.sendto(packet, destination)
                        data, _ = udp_socket.recvfrom(65535)
                        if native_udp:
                            if data[:3] != b"\0\0\0":
                                raise AssertionError("SOCKS UDP保留位/分片不符")
                            offset = 3
                            def read(n):
                                nonlocal offset
                                result = data[offset:offset + n]
                                if len(result) != n:
                                    raise EOFError("SOCKS UDP地址截断")
                                offset += n
                                return result
                            source = read_address(read)
                            if source != ("127.0.0.1" if target.host == "localhost" else target.host, target.port):
                                raise AssertionError("UDP来源元数据不符")
                            data = data[offset:]
                        if data != payload:
                            raise AssertionError("UDP边界或内容不符")
                        emit(case, "udp", "pass", size=size, target_family=("domain" if index == 2 else 4 if index == 0 else 6),
                             association="same_socks_control" if native_udp else "fixed_target_per_forwarder")
                    except Exception as error:
                        emit(case, "udp", "fail", size=size, target_family=("domain" if index == 2 else 4 if index == 0 else 6), error=type(error).__name__ + ": " + str(error))
            if native_udp and all(t.sources for t in udp_targets):
                same = udp_targets[0].sources[-1][1] == udp_targets[1].sources[-1][1]
                emit(case, "udp-same-source-port-cross-family", "pass" if same else "fail")
        finally:
            udp_socket.close()
            if control:
                control.close()
    except Exception as error:
        emit(case, "setup", "fail", error=type(error).__name__ + ": " + str(error))
    finally:
        for process in reversed(processes):
            emit(case, "process-exit", "observed", returncode=process.close())
        for target in targets:
            target.close()


def matrix(suite):
    base = {"mode": "raw", "aead": "chacha20-poly1305", "table": "prefer_entropy", "pure": True,
            "custom": [], "mux": "off", "node_ipv6": False, "tls": False, "http_version": "auto", "first": True}
    selected = ["carriers", "tables", "mux", "tls", "rekey", "credentials", "lifecycle"] if suite == "all" else [suite]
    cases = []
    def append(axis, **patch):
        for role in ["kernel-client", "kernel-server"]:
            cases.append(dict(base, axis=axis, role=role, **patch))
    for axis in selected:
        if axis == "carriers":
            for mode in MODES:
                for method in METHODS:
                    for ipv6 in [False, True]:
                        for first in [False, True]:
                            append(axis, mode=mode, aead=method, node_ipv6=ipv6, first=first)
        elif axis == "tables":
            for mode in MODES:
                for table in ["prefer_ascii", "prefer_entropy", "up_ascii_down_entropy", "up_entropy_down_ascii"]:
                    for pure in [False, True]:
                        for custom in ([[]] if table == "prefer_ascii" else [[], ["xpxvvpvv"], ["xpxvvpvv", "pxxvvpvv"]]):
                            append(axis, mode=mode, table=table, pure=pure, custom=custom)
        elif axis == "mux":
            for mode in MODES:
                for mux in (["auto", "on"] if mode in ("stream", "poll", "auto") else ["on"]):
                    append(axis, mode=mode, mux=mux)
        elif axis == "tls":
            for mode in ["stream", "poll", "auto", "ws"]:
                for version in (["h1"] if mode == "ws" else ["h1", "h2"]):
                    for ipv6 in [False, True]:
                        append(axis, mode=mode, tls=True, http_version=version, node_ipv6=ipv6)
        elif axis in ("credentials","lifecycle"):
            for mode in MODES:
                for ipv6 in [False,True]:
                    append(axis,mode=mode,node_ipv6=ipv6,mux="on" if axis=="lifecycle" else "off")
        elif axis == "rekey":
            for method in METHODS[:2]:
                for mode in ["raw", "stream", "poll", "ws"]:
                    append(axis, mode=mode, aead=method, mux="on")
    return cases


def main():
    from worker import require_worker
    require_worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", choices=["self", "mihomo", "official"], required=True)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference")
    parser.add_argument("--reference-metadata", type=Path)
    parser.add_argument("--suite", choices=["all", "carriers", "tables", "mux", "tls", "rekey", "credentials", "lifecycle"], default="all")
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--isolated-netns", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    cases = matrix(args.suite)
    if args.plan_only:
        print(json.dumps({"cases": cases, "status": "planned_only"}, ensure_ascii=False, indent=2))
        return
    if args.peer == "official" and not args.isolated_netns:
        # 原始Go程序只接受端口而非回环地址；不在宿主机通配启动。
        command = ["unshare", "--user", "--map-root-user", "--net", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--isolated-netns"]
        env = os.environ.copy()
        env["KERLICO_PARENT_NETNS"] = os.readlink("/proc/self/ns/net")
        raise SystemExit(subprocess.run(command, env=env).returncode)
    if args.isolated_netns:
        if os.readlink("/proc/self/ns/net") == os.environ.get("KERLICO_PARENT_NETNS") or not os.environ.get("KERLICO_PARENT_NETNS"):
            raise SystemExit("未进入独立网络命名空间，不启动通配参考监听")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    if args.work.exists():
        raise SystemExit("必须用新标签，不能覆盖旧互通日志")
    args.kerlico = str(Path(args.kerlico).resolve())
    if args.peer != "self":
        if not args.reference or not args.reference_metadata:
            raise SystemExit("真实对端要求固定原生二进制及peer-source.json")
        args.reference = str(Path(args.reference).resolve())
        meta = json.loads(args.reference_metadata.read_text())
        if meta["commit"] != SOURCE[args.peer]["commit"] or meta["binary_sha256"] != sha(args.reference) or meta["production_source_changes"] != 0:
            raise SystemExit("参考来源、原生源码或二进制摘要不符")
    tls = {"cert": Path(args.cert).read_text(), "key": Path(args.key).read_text()} if args.cert and args.key else {}
    args.work.mkdir(parents=True, mode=0o700)
    (args.work / "inputs.json").write_text(json.dumps({"kerlico_sha256": sha(args.kerlico), "peer": args.peer,
        "reference_sha256": sha(args.reference) if args.reference else None, "suite": args.suite,
        "planned_cases": cases, "reference_commit": SOURCE[args.peer]["commit"] if args.peer != "self" else None}, indent=2) + "\n")
    records = []
    def emit(case, phase, status, **extra):
        record = {"case": case, "phase": phase, "status": status, **extra}
        records.append(record)
        with (args.work / "results.jsonl").open("a") as output:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
    for index, case in enumerate(cases):
        if case["tls"] and not tls:
            emit(case, "setup", "blocked", reason="未提供测试证书和私钥；不关闭TLS校验")
            continue
        if case["tls"] and args.peer != "self" and case["role"] == "kernel-client":
            emit(case, "setup", "reference_boundary", reason="固定原生参考server配置没有TLS证书选项，未加外部终止器冒充原生TLS")
            continue
        if case["tls"] and args.peer != "self" and case["role"] == "kernel-server" and case["http_version"] != "auto":
            emit(case, "setup", "reference_boundary", reason="参考client没有强制HTTP版本选项，本组合不计H1/H2验证；另跑auto版本")
            case = dict(case, http_version="auto")
        directory = args.work / f"case-{index:05d}"
        directory.mkdir()
        execute(case, args, directory, emit, tls)
    counts = {status: sum(row["status"] == status for row in records) for status in sorted({row["status"] for row in records})}
    (args.work / "summary.json").write_text(json.dumps({"records": len(records), "counts": counts,
        "all_requested_scope_accepted": not any(row["status"] in ("fail", "blocked", "entry_limit", "reference_boundary") for row in records)}, indent=2) + "\n")
    print(json.dumps(counts))
    if counts.get("fail") or counts.get("blocked"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
