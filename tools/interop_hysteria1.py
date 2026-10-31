#!/usr/bin/env python3
"""仅在专用 worker 验证独立 Hysteria v1，不使用 Hysteria2 对端冒充。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
import signal
from pathlib import Path
import socket
import subprocess
import time
import interop_vless as h

class UdpServer6(h.UdpServer):
    address_family = socket.AF_INET6
class Banner(h.TcpEcho):
    def handle(self):
        self.request.sendall(b"server-first")
        super().handle()
class AfterEof(h.TcpEcho):
    def handle(self):
        self.request.settimeout(5)
        try:
            while self.request.recv(16384):
                pass
            time.sleep(0.1)
            self.request.sendall(b"after-eof")
        except OSError:
            pass

def exact(sock, length):
    value = bytearray()
    while len(value) < length:
        part = sock.recv(length-len(value))
        if not part:
            break
        value.extend(part)
    return bytes(value)

def tcp(port, payload, banner=False):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(6)
        if banner and exact(sock, 12) != b"server-first":
            raise RuntimeError("目标先发数据未到达")
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        return exact(sock, len(payload))

def eof_probe(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.settimeout(2)
            sock.sendall(b"must-reach-write-eof")
            sock.shutdown(socket.SHUT_WR)
            return exact(sock, 9)
    except OSError:
        return b""

def material(root):
    cert, key = root/"certificate.pem", root/"private-key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=hy1.example.invalid", "-addext", "subjectAltName=DNS:hy1.example.invalid", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("生成测试证书失败")
    return cert, key

def command(binary, kind, path, role):
    if kind == "official":
        return [binary, "--no-check", "--log-level", "error", "-c", str(path), role]
    return [binary, "run", "-c", str(path)]

def wait_udp_process(child):
    time.sleep(0.25)
    if child.poll() is not None:
        raise RuntimeError("QUIC 对端就绪前退出")

def auth_fields(value, encoded=False):
    return {"auth": base64.b64encode(value).decode()} if encoded else {"auth_str": value.decode()}

def node_options(auth, encoded, cert, key, carrier, obfs, congestion):
    return {**auth_fields(auth, encoded), "up_bps": 10000000, "down_bps": 10000000, "transport": carrier, "obfs": "xplus-test-only-key" if obfs else None, "tls": {"certificate_file": str(cert), "private_key_file": str(key)}, "limits": {"congestion_control": congestion, "idle_timeout_ms": 8000}}

def client_options(host, port, auth, encoded, cert, carrier, obfs, congestion):
    return {**auth_fields(auth, encoded), "server": {"host": host, "port": port}, "up_bps": 10000000, "down_bps": 10000000, "transport": carrier, "obfs": "xplus-test-only-key" if obfs else None, "tls": {"server_name": "hy1.example.invalid", "ca_pem": cert.read_text()}, "limits": {"congestion_control": congestion, "idle_timeout_ms": 8000}}

def hostport(host, port):
    return ("["+host+"]" if ":" in host else host) + ":" + str(port)

def udp_sequence(port, sizes, limit=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        for size in sizes:
            payload = bytes([size % 251]) * size
            sock.sendto(payload, ("127.0.0.1", port))
            received = sock.recv(65535)
            if received != payload:
                raise RuntimeError("UDP 长度 "+str(size)+" 不一致，收到 "+str(len(received)))
        if limit is not None:
            payload = b"b" * (8192 if limit == 4096 else 12000)
            sock.sendto(payload, ("127.0.0.1", port))
            received = sock.recv(65535)
            if received != payload[:limit]:
                raise RuntimeError("固定对端"+str(limit)+"字节缓冲负例不一致，收到"+str(len(received)))

def verify(args, root, cert, key, carrier, obfs, congestion, direction):
    label = "-".join((args.reference_kind, direction, carrier, "xplus" if obfs else "plain", congestion))
    directory = root/label
    directory.mkdir(mode=0o700)
    hosts, ports = ["127.0.0.1", "::1"], [h.free_port(), h.free_port()]
    credentials = [b"hy1-node4-test-token", b"hy1-node6-test-token" if args.reference_kind == "official" else bytes([0, 255, 1, 128, 2, 127])]
    checks = []
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        udp4 = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        udp6 = stack.enter_context(h.serve(UdpServer6(("::1", 0), h.UdpEcho)))
        banner = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), Banner)))
        after_eof = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), AfterEof)))
        servers = []
        if direction == "server":
            server = {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node"+str(index), "type": "hysteria1", "listen": hostport(hosts[index], ports[index]), "outbound": "direct", "options": node_options(credentials[index], index == 1, cert, key, carrier, obfs, congestion)} for index in range(2)], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 8000, "drain_timeout_ms": 400, "max_sessions": 128}}
            path = directory/"kerlico-server.json"
            h.write_json(path, server)
            servers.append(stack.enter_context(h.process(command(args.kerlico, "kerlico", path, "server"), directory, "server")))
        elif args.reference_kind == "sing-box":
            server = {"log": {"level": "error"}, "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"}, "inbounds": [{"type": "hysteria", "tag": "node"+str(index), "listen": hosts[index], "listen_port": ports[index], "up_mbps": 80, "down_mbps": 80, "obfs": "xplus-test-only-key" if obfs else "", "users": [{"name": "test", **auth_fields(credentials[index], index == 1)}], "tls": {"enabled": True, "alpn": ["hysteria"], "certificate_path": str(cert), "key_path": str(key)}} for index in range(2)], "outbounds": [{"type": "direct", "domain_resolver": {"server": "local", "strategy": "ipv4_only"}}]}
            path = directory/"reference-server.json"
            h.write_json(path, server)
            servers.append(stack.enter_context(h.process(command(args.reference, "sing-box", path, "server"), directory, "server")))
        else:
            for index in range(2):
                server = {"listen": hostport(hosts[index], ports[index]), "protocol": carrier, "up_mbps": 80, "down_mbps": 80, "obfs": "xplus-test-only-key" if obfs else "", "cert": str(cert), "key": str(key), "alpn": "hysteria", "auth": {"mode": "passwords", "config": [credentials[index].decode()]}, "resolve_preference": "46", "disable_mtu_discovery": True, "max_conn_client": 128}
                path = directory/("reference-server-"+str(index)+".json")
                h.write_json(path, server)
                servers.append(stack.enter_context(h.process(command(args.reference, "official", path, "server"), directory, "server-"+str(index))))
        for server in servers:
            wait_udp_process(server)
        for index in range(2):
            for bad in (False, True):
                case_root = directory/("node"+str(index)+("-wrong-auth" if bad else "-valid"))
                case_root.mkdir(mode=0o700)
                rules = [("tcp4", "tcp", h.free_port(), "127.0.0.1", target4), ("tcp6", "tcp", h.free_port(), "::1", target6), ("udp4", "udp", h.free_port(), "127.0.0.1", udp4), ("udp6", "udp", h.free_port(), "::1", udp6), ("udp-domain", "udp", h.free_port(), "localhost", udp4), ("banner", "tcp", h.free_port(), "127.0.0.1", banner), ("eof", "tcp", h.free_port(), "127.0.0.1", after_eof)]
                auth = credentials[1-index] if bad else credentials[index]
                encoded = (1-index if bad else index) == 1
                if direction == "client":
                    options = client_options(hosts[index], ports[index], auth, encoded, cert, carrier, obfs, congestion)
                    client = {"version": 1, "outbounds": [{"tag": "proxy", "type": "hysteria1", "options": options}], "inbounds": [{"tag": tag, "type": network+"-forward", "listen": "127.0.0.1:"+str(local), "target": {"host": host, "port": port}, "outbound": "proxy"} for tag, network, local, host, port in rules], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 8000, "drain_timeout_ms": 400, "max_sessions": 128}}
                    binary, kind = args.kerlico, "kerlico"
                elif args.reference_kind == "sing-box":
                    client = {"log": {"level": "error"}, "inbounds": [{"type": "direct", "tag": tag, "listen": "127.0.0.1", "listen_port": local, "network": network, "override_address": host, "override_port": port} for tag, network, local, host, port in rules], "outbounds": [{"type": "hysteria", "server": hosts[index], "server_port": ports[index], "up_mbps": 80, "down_mbps": 80, "obfs": "xplus-test-only-key" if obfs else "", **auth_fields(auth, encoded), "tls": {"enabled": True, "server_name": "hy1.example.invalid", "certificate": [cert.read_text()], "alpn": ["hysteria"]}}]}
                    binary, kind = args.reference, "sing-box"
                else:
                    client = {"server": hostport(hosts[index], ports[index]), "protocol": carrier, "up_mbps": 80, "down_mbps": 80, "obfs": "xplus-test-only-key" if obfs else "", **auth_fields(auth, encoded), "server_name": "hy1.example.invalid", "ca": str(cert), "alpn": "hysteria", "resolve_preference": "46", "handshake_timeout": 5, "idle_timeout": 10, "retry": 0, "quit_on_disconnect": True, "disable_mtu_discovery": True, "relay_tcps": [{"listen": "127.0.0.1:"+str(local), "remote": hostport(host, port), "timeout": 5} for _, network, local, host, port in rules if network == "tcp"], "relay_udps": [{"listen": "127.0.0.1:"+str(local), "remote": hostport(host, port), "timeout": 5} for _, network, local, host, port in rules if network == "udp"]}
                    binary, kind = args.reference, "official"
                path = case_root/"client.json"
                h.write_json(path, client)
                with h.process(command(binary, kind, path, "client"), case_root, "client") as child:
                    try:
                        h.wait_ready(child, rules[0][2])
                    except RuntimeError:
                        log = (case_root/"client.log").read_text(errors="replace").lower()
                        if bad and child.poll() is not None and any(word in log for word in ("wrong password", "authentication", "auth error", "server rejected")):
                            checks.append("节点"+str(index)+"错误凭据拒绝")
                            continue
                        raise
                    if bad:
                        try:
                            result = tcp(rules[0][2], b"must-not-pass-auth")
                        except (OSError, TimeoutError):
                            result = b""
                        if result:
                            raise RuntimeError("跨节点错误凭据被接受")
                        checks.append("节点"+str(index)+"错误凭据拒绝")
                        continue
                    for rule in rules[:2]:
                        for size in (17, 4096, 65536):
                            payload = b"t"*size
                            if tcp(rule[2], payload) != payload:
                                raise RuntimeError(rule[0]+" 长度 "+str(size)+" 的TCP回写不一致")
                    checks.append("节点"+str(index)+"双族TCP载荷")
                    if tcp(rules[5][2], b"after-server-greeting", True) != b"after-server-greeting":
                        raise RuntimeError("目标先发数据后回写不一致")
                    checks.append("节点"+str(index)+"目标先发数据")
                    for rule in rules[2:5]:
                        limit = 4096 if args.reference_kind == "official" else 8192
                        sizes = (17, 512, limit) if args.reference_kind == "official" else (17, 4096, limit)
                        probe = carrier == "udp" and not obfs and congestion == "cubic" and index == 0
                        udp_sequence(rule[2], sizes, limit if probe else None)
                    checks.append("节点"+str(index)+"双族/域名UDP与分片；至"+str(limit)+"字节")
                    if probe:
                        checks.append("三个目标的超限UDP返回固定对端"+str(limit)+"字节前缀；不计完整大包通过")
                    if carrier == "udp" and not obfs and congestion == "cubic" and index == 0:
                        result = eof_probe(rules[6][2])
                        checks.append("本对端FIN后回包"+("已观察" if result == b"after-eof" else "不保证，保持tcp_eof=false"))
                    with ThreadPoolExecutor(max_workers=4) as pool:
                        payloads = [("flow-"+str(n)).encode()*1024 for n in range(4)]
                        if list(pool.map(lambda value: tcp(rules[0][2], value), payloads)) != payloads:
                            raise RuntimeError("四路并发流混用负载")
                    checks.append("节点"+str(index)+"四路并发隔离")
        for server in servers:
            server.terminate()
            code = server.wait(timeout=4)
            allowed = (0, -signal.SIGTERM) if direction == "client" and args.reference_kind == "official" else (0,)
            if code not in allowed:
                raise RuntimeError("服务端退出码不符合本对端约定："+str(code))
            checks.append(("本项目服务端" if direction == "server" else "参考服务端")+"有界退出，退出码"+str(code))
    return checks

def main():
    parser = argparse.ArgumentParser(description="Hysteria v1真实对端矩阵，仅在worker运行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--reference-kind", choices=("sing-box", "official"), required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--only")
    args = parser.parse_args()
    os.umask(0o077)
    args.kerlico, args.reference = str(Path(args.kerlico).resolve()), str(Path(args.reference).resolve())
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = material(root)
    results = []
    for carrier in (("udp",) if args.reference_kind == "sing-box" else ("udp", "wechat-video")):
        for obfs in (False, True):
            for congestion in ("cubic", "newreno", "bbr"):
                for direction in ("client", "server"):
                    label = "-".join((args.reference_kind, direction, carrier, "xplus" if obfs else "plain", congestion))
                    if args.only and args.only not in label:
                        continue
                    try:
                        result = {"case": label, "ok": True, "checks": verify(args, root, cert, key, carrier, obfs, congestion, direction)}
                    except Exception as error:
                        result = {"case": label, "ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
                    print(json.dumps(result, ensure_ascii=False), flush=True)
                    results.append(result)
                    h.write_json(root/"results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "reference_sha256": hashlib.sha256(Path(args.reference).read_bytes()).hexdigest(), "results": results})
    if not results or not all(result["ok"] for result in results):
        raise SystemExit(1)
if __name__ == "__main__":
    main()
