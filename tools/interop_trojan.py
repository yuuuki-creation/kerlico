#!/usr/bin/env python3
"""只在专用 worker 运行 Trojan 正式 CLI 与固定 Xray 的双向矩阵。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import os
import socket
import ssl
import subprocess
import interop_vless as h

PASSWORDS = ("trojan-node4-test-only", "trojan-node6-test-only")
class UdpServer6(h.UdpServer):
    address_family = socket.AF_INET6

def material(root):
    cert, key = root / "certificate.pem", root / "private-key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("生成测试证书失败")
    return cert, key

def tcp(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
        stream.settimeout(6)
        stream.sendall(len(payload).to_bytes(4, "big") + payload)
        output = bytearray()
        while len(output) < len(payload):
            packet = stream.recv(len(payload) - len(output))
            if not packet:
                break
            output.extend(packet)
        return bytes(output)

def stream_settings(transport, tls, multi, cert, key, server):
    stream = {"network": "raw" if transport == "tcp" else transport, "security": "tls" if tls else "none"}
    alpn = "h2" if transport == "grpc" else "http/1.1"
    if tls:
        stream["tlsSettings"] = {"alpn": [alpn]}
        if server:
            stream["tlsSettings"]["certificates"] = [{"certificateFile": str(cert), "keyFile": str(key)}]
        else:
            stream["tlsSettings"].update(serverName="localhost", pinnedPeerCertSha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest())
    if transport in ("ws", "httpupgrade"):
        stream[transport + "Settings"] = {"path": "/trojan", "host": "localhost"}
    if transport == "grpc":
        stream["grpcSettings"] = {"serviceName": "trojan", "multiMode": multi}
    return stream

def verify(args, root, cert, key, transport, tls, multi, direction):
    label = "-".join((direction, transport, "tls" if tls else "none", "multi" if multi else "single"))
    directory = root / label
    directory.mkdir(mode=0o700)
    checks = []
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        udp4 = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        udp6 = stack.enter_context(h.serve(UdpServer6(("::1", 0), h.UdpEcho)))
        ports = [h.free_port(), h.free_port()]
        hosts = ["127.0.0.1", "::1"]
        transport_options = {"type": transport}
        if transport in ("ws", "httpupgrade"):
            transport_options.update(path="/trojan", host="localhost")
        if transport == "grpc":
            transport_options.update(service_name="trojan", authority="localhost", multi_mode=multi)
        security = {"type": "tls", "certificate_file": str(cert), "private_key_file": str(key)} if tls else {"type": "none"}
        client_security = {"type": "tls", "server_name": "localhost", "ca_pem": cert.read_text()} if tls else {"type": "none"}
        if direction == "client":
            server_config = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": host, "port": port, "protocol": "trojan", "settings": {"clients": [{"password": PASSWORDS[i]}]}, "streamSettings": stream_settings(transport, tls, multi, cert, key, True)} for i, (host, port) in enumerate(zip(hosts, ports))], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32", "::1/128"], "port": ",".join(map(str, [target4, target6, udp4, udp6]))}]}}]}
            server_binary = args.reference
        else:
            server_config = {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node" + str(i), "type": "trojan", "listen": ("[::1]:" if i else "127.0.0.1:") + str(port), "outbound": "direct", "options": {"password": PASSWORDS[i], "security": security, "transport": transport_options}} for i, port in enumerate(ports)], "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 8000, "drain_timeout_ms": 300, "max_sessions": 128}}
            server_binary = args.kerlico
        server_path = directory / "server.json"
        h.write_json(server_path, server_config)
        command = [server_binary, "run", "-config" if direction == "client" else "-c", str(server_path)]
        with h.process(command, directory, "server") as server:
            h.wait_ready(server, ports[0])
            for i in range(2):
                for wrong in (False, True):
                    case_root = directory / ("node" + str(i) + ("-wrong" if wrong else "-valid"))
                    case_root.mkdir(mode=0o700)
                    rules = [("tcp4", "tcp", h.free_port(), "127.0.0.1", target4), ("tcp6", "tcp", h.free_port(), "::1", target6), ("udp4", "udp", h.free_port(), "127.0.0.1", udp4), ("udp6", "udp", h.free_port(), "::1", udp6)]
                    password = PASSWORDS[1-i] if wrong else PASSWORDS[i]
                    if direction == "client":
                        client_config = {"version": 1, "outbounds": [{"tag": "proxy", "type": "trojan", "options": {"server": {"host": hosts[i], "port": ports[i]}, "password": password, "security": client_security, "transport": transport_options}}], "inbounds": [{"tag": name, "type": network + "-forward", "listen": "127.0.0.1:" + str(local), "target": {"host": host, "port": target}, "outbound": "proxy"} for name, network, local, host, target in rules], "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 8000, "drain_timeout_ms": 300, "max_sessions": 64}}
                        binary = args.kerlico
                    else:
                        client_config = {"log": {"loglevel": "warning"}, "inbounds": [{"tag": name, "protocol": "tunnel", "listen": "127.0.0.1", "port": local, "settings": {"address": host, "port": target, "network": network}} for name, network, local, host, target in rules], "outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": hosts[i], "port": ports[i], "password": password}]}, "streamSettings": stream_settings(transport, tls, multi, cert, key, False)}]}
                        binary = args.reference
                    path = case_root / "client.json"
                    h.write_json(path, client_config)
                    with h.process([binary, "run", "-c" if direction == "client" else "-config", str(path)], case_root, "client") as client:
                        h.wait_ready(client, rules[0][2])
                        if wrong:
                            try:
                                result = tcp(rules[0][2], b"must-not-pass")
                            except (OSError, TimeoutError):
                                result = b""
                            if result:
                                raise RuntimeError("跨节点错误凭据被接受")
                            checks.append("节点" + str(i) + "错误凭据拒绝")
                            continue
                        for rule in rules[:2]:
                            for size in (17, 4096, 65536):
                                payload = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
                                if tcp(rule[2], payload) != payload:
                                    raise RuntimeError("TCP 回写不一致")
                        checks.append("节点" + str(i) + "到双族 TCP 目标")
                        for rule in rules[2:]:
                            for size in (17, 4096, 8181 if rule[3] == "127.0.0.1" else 8169):
                                payload = b"u" * size
                                try:
                                    received = h.udp_request(rule[2], payload)
                                except (OSError, TimeoutError) as error:
                                    raise RuntimeError(rule[0] + " 长度 " + str(size) + " 的 UDP 未取得回包") from error
                                if received != payload:
                                    raise RuntimeError(rule[0] + " 长度 " + str(size) + " 的 UDP 回写不一致")
                            if transport == "tcp" and not tls and i == 0:
                                try:
                                    oversized = h.udp_request(rule[2], b"b" * 8192)
                                except (OSError, TimeoutError):
                                    oversized = None
                                if oversized == b"b" * 8192:
                                    raise RuntimeError("固定 Xray 的 8192 字节边界与已核对源码不一致，需重新调查")
                                checks.append(rule[0] + "：8192 字节固定对端限制负例已观察")
                        checks.append("节点" + str(i) + "到双族 UDP 目标")
                        payloads = [("parallel-" + str(n)).encode() * 1024 for n in range(4)]
                        with ThreadPoolExecutor(max_workers=4) as pool:
                            if list(pool.map(lambda data: tcp(rules[0][2], data), payloads)) != payloads:
                                raise RuntimeError("并发连接串流")
                        checks.append("节点" + str(i) + "四路并发隔离")
            server.terminate()
            if server.wait(timeout=4) != 0:
                raise RuntimeError("服务端未在预算内退出")
            checks.append("服务端有界退出")
    return label, checks

def main():
    parser = argparse.ArgumentParser(description="Trojan 双向载体与独立节点互通，仅在 worker 执行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--only")
    args = parser.parse_args()
    os.umask(0o077)
    args.kerlico = str(Path(args.kerlico).resolve())
    args.reference = str(Path(args.reference).resolve())
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = material(root)
    results = []
    for transport in ("tcp", "ws", "httpupgrade", "grpc"):
        for multi in ((False, True) if transport == "grpc" else (False,)):
            for tls in (False, True):
                for direction in ("client", "server"):
                    label = "-".join((direction, transport, "tls" if tls else "none", "multi" if multi else "single"))
                    if args.only and args.only not in label:
                        continue
                    try:
                        _, checks = verify(args, root, cert, key, transport, tls, multi, direction)
                        result = {"case": label, "ok": True, "checks": checks}
                    except Exception as error:
                        result = {"case": label, "ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
                    print(json.dumps(result, ensure_ascii=False), flush=True)
                    results.append(result)
                    h.write_json(root / "results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "reference_sha256": hashlib.sha256(Path(args.reference).read_bytes()).hexdigest(), "results": results})
    if not results or not all(result["ok"] for result in results):
        raise SystemExit(1)
if __name__ == "__main__":
    main()
