#!/usr/bin/env python3
"""使用真实参考核心验证 VLESS；配置、证书和日志只存放于指定私有目录。"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
import json
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time


USER_ID = "00000000-0000-0000-0000-000000000000"


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        chunks = []
        size = 0
        try:
            prefix = bytearray()
            while len(prefix) < 4:
                part = self.request.recv(4 - len(prefix))
                if not part:
                    return
                prefix.extend(part)
            expected = int.from_bytes(prefix, "big")
            if expected > 2 * 1024 * 1024:
                return
            while size < expected:
                part = self.request.recv(min(16_384, expected - size))
                if not part:
                    return
                chunks.append(part)
                size += len(part)
            self.request.sendall(b"".join(chunks))
        except (OSError, TimeoutError):
            return


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TcpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class TcpServer6(TcpServer):
    address_family = socket.AF_INET6


class UdpServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextmanager
def serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def process(args, directory, label):
    with (directory / (label + ".log")).open("wb") as log:
        child = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        try:
            yield child
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)


def wait_ready(child, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("子进程在就绪前退出")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.03)
    raise RuntimeError("监听器未在预算内就绪")


def tcp_request(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        sock.shutdown(socket.SHUT_WR)
        result = bytearray()
        while True:
            chunk = sock.recv(16_384)
            if not chunk:
                return bytes(result)
            result.extend(chunk)


def udp_request(port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.sendto(payload, ("127.0.0.1", port))
        return sock.recv(65_535)


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)


def verify(args, directory):
    certificate, key = directory / "certificate.pem", directory / "key.pem"
    result = subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(certificate), "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError("测试证书生成失败")
    key.chmod(0o600)
    certificate.chmod(0o600)
    remote_port = free_port()
    if args.backend == "xray":
        reference = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": remote_port, "protocol": "vless",
                "settings": {"clients": [{"id": USER_ID}], "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                    "certificates": [{"certificateFile": str(certificate), "keyFile": str(key)}]}}}],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
        }
        reference_args = [args.reference, "run", "-config"]
    else:
        reference = {
            "log": {"level": "warn"},
            "dns": {"servers": [{"type": "local", "tag": "local"}]},
            "inbounds": [{"type": "vless", "tag": "entry", "listen": "127.0.0.1", "listen_port": remote_port,
                "users": [{"uuid": USER_ID}], "tls": {"enabled": True, "certificate_path": str(certificate), "key_path": str(key)}}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct", "default_domain_resolver": "local"},
        }
        reference_args = [args.reference, "run", "-c"]
    reference_path = directory / "reference.json"
    write_json(reference_path, reference)
    cases = []
    with ExitStack() as stack:
        tcp_target = stack.enter_context(serve(TcpServer(("127.0.0.1", 0), TcpEcho)))
        udp_target = stack.enter_context(serve(UdpServer(("127.0.0.1", 0), UdpEcho)))
        try:
            ipv6_target = stack.enter_context(serve(TcpServer6(("::1", 0), TcpEcho)))
        except OSError:
            ipv6_target = None
        if args.backend == "xray":
            # 新版参考端默认阻断代理访问私网；仅给本次隔离目标开例外。
            ports = [tcp_target, udp_target] + ([ipv6_target] if ipv6_target else [])
            reference["outbounds"][0]["settings"] = {"finalRules": [{
                "action": "allow", "ip": ["127.0.0.1/32", "::1/128"],
                "port": ",".join(str(value) for value in ports),
            }]}
            write_json(reference_path, reference)
        with process(reference_args + [str(reference_path)], directory, "reference") as backend:
            wait_ready(backend, remote_port)
            tcp_port, domain_port, udp_port = free_port(), free_port(), free_port()
            options = {"server": {"host": "127.0.0.1", "port": remote_port}, "uuid": USER_ID,
                "transport": "tcp", "flow": "", "encryption": "none",
                "security": {"type": "tls", "server_name": "localhost", "ca_pem": certificate.read_text()}}
            config = {"version": 1, "outbounds": [{"tag": "proxy", "type": "vless", "options": options}],
                "inbounds": [
                    {"tag": "tcp", "type": "tcp-forward", "listen": "127.0.0.1:" + str(tcp_port), "target": {"host": "127.0.0.1", "port": tcp_target}, "outbound": "proxy"},
                    {"tag": "domain", "type": "tcp-forward", "listen": "127.0.0.1:" + str(domain_port), "target": {"host": "localhost", "port": tcp_target}, "outbound": "proxy"},
                    {"tag": "udp", "type": "udp-forward", "listen": "127.0.0.1:" + str(udp_port), "target": {"host": "127.0.0.1", "port": udp_target}, "outbound": "proxy"}],
                "limits": {"connect_timeout_ms": 2000, "idle_timeout_ms": 5000, "drain_timeout_ms": 300, "max_sessions": 64}}
            if ipv6_target:
                ipv6_port = free_port()
                config["inbounds"].append({"tag": "ipv6", "type": "tcp-forward", "listen": "127.0.0.1:" + str(ipv6_port), "target": {"host": "::1", "port": ipv6_target}, "outbound": "proxy"})
            path = directory / "kerlico.json"
            write_json(path, config)
            check = subprocess.run([args.kerlico, "check", "-c", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            if check.returncode:
                raise RuntimeError("有效配置检查失败")
            cases.append("配置校验")
            with process([args.kerlico, "run", "-c", str(path)], directory, "kerlico") as client:
                wait_ready(client, tcp_port)
                for payload in [b"first-write-before-response", bytes(range(256)) * 256]:
                    if tcp_request(tcp_port, payload) != payload:
                        raise RuntimeError("TCP 半关闭或大负载回写失败")
                cases.append("TCP 首包与半关闭及 64KiB 负载")
                if tcp_request(domain_port, b"domain-target") != b"domain-target":
                    raise RuntimeError("域名目的地址失败")
                cases.append("域名目的地址")
                if ipv6_target:
                    if tcp_request(ipv6_port, b"ipv6-target") != b"ipv6-target":
                        raise RuntimeError("IPv6 目的地址失败")
                    cases.append("IPv6 目的地址")
                with ThreadPoolExecutor(max_workers=16) as pool:
                    payloads = [("tcp-flow-" + str(i)).encode() * 20 for i in range(16)]
                    if list(pool.map(lambda payload: tcp_request(tcp_port, payload), payloads)) != payloads:
                        raise RuntimeError("并发 TCP 数据串流")
                cases.append("16 路并发 TCP 隔离")
                for payload in [b"u", b"datagram" * 128]:
                    if udp_request(udp_port, payload) != payload:
                        raise RuntimeError("UDP 分帧或回写失败")
                cases.append("非空固定目标 UDP")
                with ThreadPoolExecutor(max_workers=8) as pool:
                    payloads = [("udp-flow-" + str(i)).encode() for i in range(8)]
                    if list(pool.map(lambda payload: udp_request(udp_port, payload), payloads)) != payloads:
                        raise RuntimeError("UDP 来源映射串流")
                cases.append("8 路 UDP 来源隔离")
                started = time.monotonic()
                client.send_signal(signal.SIGTERM)
                if client.wait(timeout=3) != 0 or time.monotonic() - started > 2:
                    raise RuntimeError("信号关闭或排空预算失败")
                cases.append("SIGTERM 有界退出")
            for label, mutate in [
                ("错误 UUID 不回退直连", lambda value: value.update(uuid="11111111-1111-1111-1111-111111111111")),
                ("错误 TLS 名称被拒绝", lambda value: value["security"].update(server_name="wrong.invalid")),
                ("未信任的证书被拒绝", lambda value: value["security"].pop("ca_pem")),
            ]:
                candidate = json.loads(json.dumps(config))
                candidate["inbounds"] = [candidate["inbounds"][0]]
                port = free_port()
                candidate["inbounds"][0]["listen"] = "127.0.0.1:" + str(port)
                mutate(candidate["outbounds"][0]["options"])
                negative = directory / ("negative-" + str(len(cases)) + ".json")
                write_json(negative, candidate)
                with process([args.kerlico, "run", "-c", str(negative)], directory, "negative-" + str(len(cases))) as client:
                    wait_ready(client, port)
                    try:
                        returned = tcp_request(port, b"must-not-be-echoed")
                    except (OSError, TimeoutError):
                        returned = b""
                    if returned:
                        raise RuntimeError(label)
                cases.append(label)
    return cases


def main():
    parser = argparse.ArgumentParser(description="VLESS 普通流与真实参考端的隔离互通验证")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--backend", choices=["xray", "sing-box"], required=True)
    parser.add_argument("--work-dir", default=".private/interop")
    args = parser.parse_args()
    args.kerlico = str(Path(args.kerlico).resolve())
    args.reference = str(Path(args.reference).resolve())
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    work.chmod(0o700)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=work))
    try:
        cases = verify(args, directory)
    except Exception as error:
        # 保留本地失败证据，不回显配置或凭证。
        reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        summary = {"backend": args.backend, "ok": False, "reason": reason}
        write_json(work / (args.backend + "-result.json"), summary)
        print(json.dumps(summary, ensure_ascii=False))
        raise SystemExit(1)
    shutil.rmtree(directory)
    summary = {"backend": args.backend, "ok": True, "cases": cases, "case_count": len(cases)}
    write_json(work / (args.backend + "-result.json"), summary)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
