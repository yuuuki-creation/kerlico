#!/usr/bin/env python3
"""专用worker的Naive双角色互通；独立保存原资产、固定源码导出参照与包长结果。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time
import interop_vless as h

USERNAME = "test-user"
PASSWORD = "synthetic-secret"
class UdpServer(h.UdpServer):
    max_packet_size = 65535
class UdpServer6(UdpServer):
    address_family = socket.AF_INET6

class EofEcho(h.socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(6)
        size = 0
        try:
            while True:
                data = self.request.recv(16384)
                if not data:
                    self.request.sendall(b"after EOF")
                    return
                size += len(data)
                if size > 65536:
                    return
        except OSError:
            return

def address(host, port):
    return ("[" + host + "]" if ":" in host else host) + ":" + str(port)

def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise RuntimeError("响应提前结束")
        data.extend(part)
    return bytes(data)

@contextmanager
def process(command, work, label, environment=None, probe=False):
    with (work / (label + ".log")).open("wb") as log:
        child = subprocess.Popen(command, stdin=subprocess.PIPE if probe else subprocess.DEVNULL, stdout=subprocess.PIPE if probe else log, stderr=log, env=environment)
        try:
            yield child
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            if child.stdin:
                child.stdin.close()
            if probe and child.stdout:
                child.stdout.close()

def wait_listener(child, port, protocol):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("对端在监听就绪前退出")
        owned = set()
        for descriptor in Path("/proc", str(child.pid), "fd").glob("*"):
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            if target.startswith("socket:["):
                owned.add(target[8:-1])
        for family in ("", "6"):
            table = Path("/proc/net", protocol + family)
            for row in table.read_text().splitlines()[1:]:
                fields = row.split()
                if fields[9] in owned and int(fields[1].split(":")[1], 16) == port and (protocol == "udp" or fields[3] == "0A"):
                    return
        time.sleep(0.03)
    raise RuntimeError("监听未在预算内就绪")

def socks_address(host, port):
    try:
        packed = socket.inet_pton(socket.AF_INET, host)
        prefix = b"\x01" + packed
    except OSError:
        try:
            packed = socket.inet_pton(socket.AF_INET6, host)
            prefix = b"\x04" + packed
        except OSError:
            encoded = host.encode()
            prefix = b"\x03" + bytes([len(encoded)]) + encoded
    return prefix + port.to_bytes(2, "big")

def decode_address(reader):
    family = exact(reader, 1)[0]
    if family == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(reader, 4))
    elif family == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(reader, 16))
    elif family == 3:
        host = exact(reader, exact(reader, 1)[0]).decode()
    else:
        raise RuntimeError("SOCKS地址族不合法")
    return host, int.from_bytes(exact(reader, 2), "big")

def socks_command(port, command, target_host, target_port):
    stream = socket.create_connection(("127.0.0.1", port), timeout=6)
    stream.settimeout(6)
    stream.sendall(b"\x05\x01\x00")
    if exact(stream, 2) != b"\x05\x00":
        stream.close()
        raise RuntimeError("SOCKS协商失败")
    stream.sendall(bytes([5, command, 0]) + socks_address(target_host, target_port))
    status = exact(stream, 3)
    if status[:2] != b"\x05\x00":
        stream.close()
        raise RuntimeError("SOCKS请求失败")
    bound = decode_address(stream)
    return stream, bound

def tcp_request(port, payload, socks_target=None, shutdown=False):
    stream = socks_command(port, 1, *socks_target)[0] if socks_target else socket.create_connection(("127.0.0.1", port), timeout=6)
    with stream:
        stream.settimeout(8)
        stream.sendall(len(payload).to_bytes(4, "big") + payload)
        if shutdown:
            stream.shutdown(socket.SHUT_WR)
        return exact(stream, len(payload))

def eof_request(port, socks_target=None):
    stream = socks_command(port, 1, *socks_target)[0] if socks_target else socket.create_connection(("127.0.0.1", port), timeout=6)
    with stream:
        stream.settimeout(3)
        stream.sendall(b"eof-request")
        stream.shutdown(socket.SHUT_WR)
        return exact(stream, 9)

def udp_request(port, payload, socks_target=None):
    control = None
    if socks_target:
        control, endpoint = socks_command(port, 3, "0.0.0.0", 0)
        if endpoint[0] in ("0.0.0.0", "::"):
            endpoint = ("127.0.0.1", endpoint[1])
        wire = b"\x00\x00\x00" + socks_address(*socks_target) + payload
    else:
        endpoint, wire = ("127.0.0.1", port), payload
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.settimeout(5)
            stream.sendto(wire, endpoint)
            result = stream.recv(65535)
            if not socks_target:
                return result
            if result[:3] != b"\x00\x00\x00":
                raise RuntimeError("SOCKS UDP分片或头不合法")
            family = result[3]
            skip = 10 if family == 1 else 22 if family == 4 else 7 + result[4] if family == 3 else 0
            if not skip:
                raise RuntimeError("SOCKS UDP地址族不合法")
            return result[skip:]
    finally:
        if control:
            control.close()

def probe(child, command):
    child.stdin.write((json.dumps(command) + "\n").encode())
    child.stdin.flush()
    if not select.select([child.stdout], [], [], 10)[0]:
        raise RuntimeError("独立探针超时")
    line = child.stdout.readline()
    if not line:
        raise RuntimeError("独立探针提前退出")
    result = json.loads(line)
    if not result.get("ok"):
        raise RuntimeError("独立探针返回失败")
    return base64.b64decode(result.get("payload", "")), result

def full_cone(child):
    with ExitStack() as stack:
        first = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        second = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
        third = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        first.bind(("127.0.0.1", 0))
        second.bind(("::1", 0))
        third.bind(("127.0.0.1", 0))
        remote_port = None
        with ThreadPoolExecutor(max_workers=1) as executor:
            for endpoint in (first, second):
                endpoint.settimeout(8)
                destination = endpoint.getsockname()
                future = executor.submit(probe, child, {"network": "udp", "host": destination[0], "port": destination[1], "payload": base64.b64encode(b"port-check").decode(), "association": "full-cone"})
                data, source = endpoint.recvfrom(65535)
                if data != b"port-check" or remote_port is not None and source[1] != remote_port:
                    raise RuntimeError("Full Cone跨目标或地址族未保留同一远端端口")
                remote_port = source[1]
                endpoint.sendto(b"reply", source)
                reply, metadata = future.result(timeout=10)
                if reply != b"reply" or metadata.get("port") != destination[1]:
                    raise RuntimeError("Full Cone响应来源不符")
        third.sendto(b"uncontacted", ("127.0.0.1", remote_port))
        reply, metadata = probe(child, {"network": "udp-receive", "association": "full-cone"})
        if reply != b"uncontacted" or metadata.get("port") != third.getsockname()[1]:
            raise RuntimeError("Full Cone不能接收未联系来源或来源被替换")

def certificates(root):
    cert, key, ca = root / "server.pem", root / "server.key", root / "ca.pem"
    commands = [
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "ca.key"), "-out", str(ca), "-days", "2", "-subj", "/CN=protocol-test-root", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(root / "server.csr"), "-subj", "/CN=proxy.invalid"],
    ]
    extension = root / "server.ext"
    extension.write_text("subjectAltName=DNS:proxy.invalid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    commands.append(["openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(ca), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-out", str(cert), "-days", "2", "-extfile", str(extension)])
    with (root / "certificate.log").open("wb") as log:
        for command in commands:
            subprocess.run(command, stdout=log, stderr=log, check=True)
    return cert, key, ca

def run_case(args, root, cert, key, ca, xdg, kind, direction, transport, host, target_host, version):
    label = "-".join([kind, direction, transport, "node6" if ":" in host else "node4", "domain" if target_host == "localhost" else "target6" if ":" in target_host else "target4", "uot" + str(version)])
    work = root / label
    work.mkdir(mode=0o700)
    checks, boundaries = [], []
    def stage(name):
        h.write_json(work / "stage.json", {"stage": name, "checks": checks, "boundaries": boundaries})
    stage("prepare")
    ports = set()
    def free():
        while True:
            port = h.free_port()
            if port in ports:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as four, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as six:
                    four.bind(("127.0.0.1", port))
                    six.bind(("::1", port))
                ports.add(port)
                return port
            except OSError:
                continue
    with ExitStack() as stack:
        tcp_port = stack.enter_context(h.serve((h.TcpServer6 if ":" in target_host else h.TcpServer)((target_host, 0), h.TcpEcho)))
        udp_port = stack.enter_context(h.serve((UdpServer6 if ":" in target_host else UdpServer)((target_host, 0), h.UdpEcho)))
        eof_port = stack.enter_context(h.serve((h.TcpServer6 if ":" in target_host else h.TcpServer)((target_host, 0), EofEcho)))
        if target_host == "localhost":
            stack.enter_context(h.serve(h.TcpServer6(("::1", tcp_port), h.TcpEcho)))
            stack.enter_context(h.serve(UdpServer6(("::1", udp_port), h.UdpEcho)))
            stack.enter_context(h.serve(h.TcpServer6(("::1", eof_port), EofEcho)))
        node_port, tcp_local, udp_local, eof_local = free(), free(), free(), free()
        own = {"version": 1, "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 10000, "drain_timeout_ms": 500, "max_sessions": 128}, "outbounds": [], "inbounds": []}
        auth = {"username": USERNAME, "password": PASSWORD}
        if direction == "client":
            options = {"server": {"host": host, "port": node_port}, "tls": {"server_name": "proxy.invalid", "ca_pem": ca.read_text()}, "transport": transport, "udp_over_tcp": {"enabled": kind != "caddy", "version": version}, "max_sessions": 16 if transport == "h1" else 1, **auth}
            own["outbounds"] = [{"tag": "proxy", "type": "naive", "options": options}]
            own["inbounds"] = [{"tag": "tcp", "type": "tcp-forward", "listen": address("127.0.0.1", tcp_local), "target": {"host": target_host, "port": tcp_port}, "outbound": "proxy"}]
            own["inbounds"].append({"tag": "eof", "type": "tcp-forward", "listen": address("127.0.0.1", eof_local), "target": {"host": target_host, "port": eof_port}, "outbound": "proxy"})
            if kind != "caddy":
                own["inbounds"].append({"tag": "udp", "type": "udp-forward", "listen": address("127.0.0.1", udp_local), "target": {"host": target_host, "port": udp_port}, "outbound": "proxy"})
        else:
            own["outbounds"] = [{"tag": "direct", "type": "direct"}]
            own["nodes"] = [{"tag": "node", "type": "naive", "listen": address(host, node_port), "outbound": "direct", "options": {"users": [auth], "tls": {"certificate_file": str(cert), "private_key_file": str(key)}, "transports": [transport], "udp_over_tcp": True}}]
        h.write_json(work / "own.json", own)
        own_command = [args.kerlico, "run", "-c", str(work / "own.json")]
        probe_process = None
        socks = False
        if direction == "client":
            if kind == "go":
                command = [args.go_reference, "-role", "server", "-transport", transport, "-listen", address(host, node_port), "-cert", str(cert), "-key", str(key)]
            elif kind == "sing-box":
                peer = {"log": {"level": "warn"}, "inbounds": [{"type": "naive", "tag": "node", "listen": host, "listen_port": node_port, "network": "udp" if transport == "h3" else "tcp", "users": [auth], "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}}], "outbounds": [{"type": "direct", "tag": "direct"}]}
                h.write_json(work / "peer.json", peer)
                command = [args.sing_box, "run", "-c", str(work / "peer.json")]
            elif kind == "caddy":
                caddyfile = work / "Caddyfile"
                caddyfile.write_text("{\n auto_https off\n admin off\n}\n:" + str(node_port) + " {\n bind " + host + "\n tls " + str(cert) + " " + str(key) + "\n route {\n forward_proxy {\n basic_auth " + USERNAME + " " + PASSWORD + "\n hide_ip\n hide_via\n acl {\n allow all\n }\n }\n }\n}\n")
                command = [args.caddy, "run", "--config", str(caddyfile), "--adapter", "caddyfile"]
            else:
                raise RuntimeError("参考服务器类型不合法")
            reference = stack.enter_context(process(command, work, "reference"))
            wait_listener(reference, node_port, "udp" if transport == "h3" else "tcp")
            kernel = stack.enter_context(process(own_command, work, "kernel"))
            wait_listener(kernel, tcp_local, "tcp")
            tcp_call = lambda data: tcp_request(tcp_local, data)
            udp_call = lambda data: udp_request(udp_local, data)
        else:
            kernel = stack.enter_context(process(own_command, work, "kernel"))
            wait_listener(kernel, node_port, "udp" if transport == "h3" else "tcp")
            if kind == "go":
                command = [args.go_reference, "-role", "probe", "-transport", transport, "-server", address(host, node_port), "-ca", str(ca), "-server-name", "proxy.invalid", "-uot-version", str(version)]
                probe_process = stack.enter_context(process(command, work, "reference", probe=True))
                def tcp_call(data):
                    wire = len(data).to_bytes(4, "big") + data
                    return probe(probe_process, {"network": "tcp", "host": target_host, "port": tcp_port, "payload": base64.b64encode(wire).decode(), "read_len": len(data)})[0]
                def udp_call(data):
                    return probe(probe_process, {"network": "udp", "host": target_host, "port": udp_port, "payload": base64.b64encode(data).decode(), "association": "matrix"})[0]
            else:
                socks = True
                if kind == "sing-box":
                    socks = False
                    peer = {"log": {"level": "warn"}, "dns": {"servers": [{"type": "local", "tag": "local"}]}, "route": {"default_domain_resolver": "local"}, "inbounds": [{"type": "direct", "tag": "tcp", "listen": "127.0.0.1", "listen_port": tcp_local, "network": "tcp", "override_address": target_host, "override_port": tcp_port}, {"type": "direct", "tag": "udp", "listen": "127.0.0.1", "listen_port": udp_local, "network": "udp", "override_address": target_host, "override_port": udp_port}, {"type": "direct", "tag": "eof", "listen": "127.0.0.1", "listen_port": eof_local, "network": "tcp", "override_address": target_host, "override_port": eof_port}], "outbounds": [{"type": "naive", "tag": "proxy", "server": host, "server_port": node_port, **auth, "quic": transport == "h3", "udp_over_tcp": {"enabled": True, "version": version}, "tls": {"enabled": True, "server_name": "proxy.invalid", "certificate_path": str(ca)}}]}
                    h.write_json(work / "peer.json", peer)
                    command = [args.sing_box, "run", "-c", str(work / "peer.json")]
                    environment = None
                elif kind == "official":
                    peer = {"listen": "socks://127.0.0.1:" + str(tcp_local), "proxy": ("quic" if transport == "h3" else "https") + "://" + USERNAME + ":" + PASSWORD + "@proxy.invalid:" + str(node_port), "host-resolver-rules": "MAP proxy.invalid " + ("[" + host + "]" if ":" in host else host)}
                    h.write_json(work / "peer.json", peer)
                    command = [args.official, str(work / "peer.json")]
                    environment = dict(os.environ, XDG_DATA_HOME=str(xdg), SSL_CERT_FILE=str(ca), SSL_CERT_DIR=str(xdg))
                else:
                    raise RuntimeError("参考客户端类型不合法")
                reference = stack.enter_context(process(command, work, "reference", environment))
                wait_listener(reference, tcp_local, "tcp")
                tcp_call = lambda data: tcp_request(tcp_local, data, (target_host, tcp_port) if socks else None)
                udp_call = lambda data: udp_request(tcp_local if socks else udp_local, data, (target_host, udp_port) if socks else None)
        stage("tcp257024")
        data = bytes(range(251)) * 1024
        if tcp_call(data) != data:
            raise RuntimeError("TCP长度或内容不符")
        checks.append("TCP257024")
        if not probe_process:
            stage("tcp-concurrency")
            with ThreadPoolExecutor(max_workers=12) as executor:
                replies = list(executor.map(tcp_call, [b"parallel" + bytes([n]) * 4096 for n in range(12)]))
            if replies != [b"parallel" + bytes([n]) * 4096 for n in range(12)]:
                raise RuntimeError("并发流内容不符")
            checks.append("并发12TCP")
        if kind not in ("caddy", "official"):
            for size in [17, 1200, 12000]:
                stage("udp-" + str(size))
                data = bytes([size % 251]) * size
                if udp_call(data) != data:
                    raise RuntimeError("UDP长度或内容不符")
                checks.append("UDP" + str(size))
            boundary_sizes = args.boundary_sizes if kind == "go" or not getattr(args, "boundary_representative", False) or host == "127.0.0.1" and target_host == "127.0.0.1" else []
            for size in boundary_sizes:
                stage("udp-boundary-" + str(size))
                data = bytes([size % 251]) * size
                try:
                    received = udp_call(data)
                    boundary = {"size": size, "ok": received == data, "received": len(received)}
                except Exception as error:
                    boundary = {"size": size, "ok": False, "error": type(error).__name__}
                boundaries.append(boundary)
                if udp_call(b"after-boundary") != b"after-boundary":
                    raise RuntimeError("边界探测后小包未恢复")
        stage("target-eof")
        try:
            if probe_process:
                received = probe(probe_process, {"network": "tcp", "host": target_host, "port": eof_port, "payload": base64.b64encode(b"eof-request").decode(), "read_len": 9, "shutdown": True})[0]
            else:
                received = eof_request(tcp_local if socks else eof_local, (target_host, eof_port) if socks else None)
            eof_result = {"ok": received == b"after EOF", "received": len(received)}
        except Exception as error:
            eof_result = {"ok": False, "error": type(error).__name__}
        if tcp_call(b"after-eof") != b"after-eof":
            raise RuntimeError("EOF探测后新流不能恢复")
        if kind == "go" and not eof_result["ok"]:
            raise RuntimeError("固定源码导出参照的目标EOF后回包未通过")
        if kind == "go":
            stage("full-cone")
            if direction == "server":
                full_cone(probe_process)
            elif args.rust_probe:
                h.write_json(work / "probe-options.json", options)
                native_probe = stack.enter_context(process([args.rust_probe, str(work / "probe-options.json")], work, "native-probe", probe=True))
                full_cone(native_probe)
            else:
                raise RuntimeError("Full Cone验收需要实际Rust公开API探针")
            checks.append("Full Cone跨目标跨地址族与未联系来源")
        if args.lifecycle:
            stage("lifecycle")
            kernel.send_signal(signal.SIGTERM)
            if kernel.wait(timeout=4) != 0:
                raise RuntimeError("kernel退出状态异常")
            restarted = stack.enter_context(process(own_command, work, "restarted"))
            wait_listener(restarted, tcp_local if direction == "client" else node_port, "tcp" if direction == "client" or transport != "h3" else "udp")
            restarted.send_signal(signal.SIGTERM)
            if restarted.wait(timeout=4) != 0:
                raise RuntimeError("重绑后退出状态异常")
            checks.append("退出与同端口重绑")
        result = {"case": label, "checks": checks, "boundary_probes": boundaries, "eof_probe": eof_result, "source_kind": kind, "direction": direction, "transport": transport, "uot_version": version, "socks_ingress": socks}
        h.write_json(work / "result.json", result)
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--go-reference", required=True)
    parser.add_argument("--rust-probe", required=True)
    parser.add_argument("--sing-box")
    parser.add_argument("--caddy")
    parser.add_argument("--official")
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--lifecycle", action="store_true")
    parser.add_argument("--boundary-representative", action="store_true")
    parser.add_argument("--boundary-sizes", nargs="+", type=int, default=[0, 65507])
    args = parser.parse_args()
    if os.environ.get("KERLICO_WORKER_ONLY") != "1":
        raise SystemExit("只允许专用worker执行")
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for variable, directory in {"XDG_DATA_HOME": "reference-data", "XDG_CACHE_HOME": "reference-cache", "XDG_CONFIG_HOME": "reference-config", "TMPDIR": "tmp"}.items():
        location = root / directory
        location.mkdir(mode=0o700, exist_ok=True)
        os.environ[variable] = str(location)
    cert, key, ca = certificates(root)
    xdg = root / "official-trust"
    xdg.mkdir(mode=0o700, exist_ok=True)
    kinds = ["go"] + (["sing-box"] if args.sing_box else []) + (["caddy"] if args.caddy else []) + (["official"] if args.official else [])
    cases = []
    for kind in kinds:
        for direction in (["client"] if kind == "caddy" else ["server"] if kind == "official" else ["client", "server"]):
            for transport in (["h2", "h3"] if kind in ("caddy", "official") or kind == "sing-box" and direction == "server" else ["h1", "h2", "h3"]):
                for host in (["127.0.0.1", "::1"] if args.full else ["127.0.0.1"]):
                    for target_host in (["127.0.0.1", "::1", "localhost"] if args.full else ["127.0.0.1"]):
                        for version in ([1, 2] if kind in ("go", "sing-box") else [2]):
                            cases.append((kind, direction, transport, host, target_host, version))
    results, failures = [], []
    for case in cases:
        try:
            result = run_case(args, root, cert, key, ca, xdg, *case)
            results.append(result)
            if case[0] == "go" and any(not p["ok"] for p in result["boundary_probes"]):
                failures.append({"case": case, "error": "固定源码导出参照的声明包长未通过"})
        except Exception as error:
            failures.append({"case": case, "error": str(error) if isinstance(error, RuntimeError) else type(error).__name__})
        h.write_json(root / "progress.json", {"results": results, "failures": failures})
    binaries = {name: hashlib.sha256(Path(value).read_bytes()).hexdigest() for name, value in {"kerlico": args.kerlico, "go_reference": args.go_reference, "rust_probe": args.rust_probe, "sing_box": args.sing_box, "caddy": args.caddy, "official": args.official}.items() if value}
    result = {"ok": not failures, "configurations": len(cases), "results": results, "failures": failures, "binaries": binaries}
    h.write_json(root / "result.json", result)
    print(json.dumps({"ok": result["ok"], "configurations": len(cases), "completed": len(results), "failures": len(failures)}, ensure_ascii=False), flush=True)
    if failures:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
