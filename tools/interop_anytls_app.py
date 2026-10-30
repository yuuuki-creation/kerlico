#!/usr/bin/env python3
"""在专用 worker 验证同一程序的 AnyTLS 双端和构建裁剪。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess

import interop_vless as h


class UdpEchoServer(h.UdpServer):
    max_packet_size = 65535


def receive(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def tcp(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        return receive(sock, len(payload))


def socks_request(port, host, target, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        sock.sendall(b"\x05\x01\x00")
        if receive(sock, 2) != b"\x05\x00":
            raise RuntimeError("参考端 SOCKS 方法协商失败")
        address = socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        sock.sendall(bytes([5, 1, 0, 4 if ":" in host else 1]) + address + target.to_bytes(2, "big"))
        reply = receive(sock, 4)
        if len(reply) != 4 or reply[1] != 0:
            raise RuntimeError("参考端 SOCKS 目标连接失败")
        receive(sock, (16 if reply[3] == 4 else 4) + 2)
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        return receive(sock, len(payload))


def checked(command, root, label, success=True):
    result = subprocess.run(command, capture_output=True, timeout=15)
    (root / (label + ".log")).write_bytes(result.stdout + result.stderr)
    if (result.returncode == 0) != success:
        raise RuntimeError(label + "：退出状态不符合预期")
    return result.stdout.decode()


def verify(args, root):
    checks = []
    modules = checked([args.kerlico, "modules"], root, "modules")
    if set(modules.splitlines()) != {"outbound/anytls", "inbound/anytls", "outbound/direct", "outbound/reject"}:
        raise RuntimeError("AnyTLS 构建注册项不符合裁剪范围")
    checks.append("AnyTLS-only CLI 双端注册")
    for kind in ("vless", "ss2022"):
        excluded = root / ("excluded-" + kind + ".json")
        h.write_json(excluded, {"version": 1, "inbounds": [], "outbounds": [{"tag": "excluded", "type": kind}]})
        checked([args.kerlico, "check", "-c", str(excluded)], root, "excluded-" + kind, False)
    checks.append("AnyTLS-only 构建拒绝未编译协议配置")
    cert, key = root / "certificate.pem", root / "key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError("测试证书生成失败")
    cert.chmod(0o600)
    key.chmod(0o600)
    ca = cert.read_text()
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        udp_target = stack.enter_context(h.serve(UdpEchoServer(("127.0.0.1", 0), h.UdpEcho)))
        node_ports = [h.free_port(), h.free_port()]
        passwords = ["independent-node-four", "independent-node-six"]
        hosts = ["127.0.0.1", "::1"]
        reference_port = h.free_port()
        reference = {"log": {"level": "error"}, "inbounds": [{"type": "anytls", "listen": "127.0.0.1", "listen_port": reference_port, "users": [{"name": "test", "password": "reference-password"}], "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}}], "outbounds": [{"type": "direct"}]}
        reference_path = root / "reference-server.json"
        h.write_json(reference_path, reference)
        reference_server = stack.enter_context(h.process([args.reference, "run", "-c", str(reference_path)], root, "reference-server"))
        h.wait_ready(reference_server, reference_port)
        outbounds = [{"tag": "direct", "type": "direct"}]
        nodes = []
        forwards = []
        cases = []
        for i in range(2):
            nodes.append({"tag": "node" + str(i), "type": "anytls", "listen": ("127.0.0.1:" if i == 0 else "[::1]:") + str(node_ports[i]), "outbound": "direct", "options": {"passwords": [passwords[i]], "tls": {"certificate_file": str(cert), "private_key_file": str(key)}}})
        for i, (host, port, password) in enumerate(list(zip(hosts, node_ports, passwords)) + [("127.0.0.1", reference_port, "reference-password")]):
            tag = "proxy" + str(i)
            outbounds.append({"tag": tag, "type": "anytls", "options": {"server": {"host": host, "port": port}, "password": password, "tls": {"server_name": "localhost", "ca_pem": ca}}})
            for label, network, target_host, target_port in [("tcp4", "tcp-forward", "127.0.0.1", target4), ("tcp6", "tcp-forward", "::1", target6), ("udp", "udp-forward", "127.0.0.1", udp_target)]:
                local = h.free_port()
                forwards.append({"tag": tag + label, "type": network, "listen": "127.0.0.1:" + str(local), "target": {"host": target_host, "port": target_port}, "outbound": tag})
                cases.append((i, label, local))
        config = {"version": 1, "outbounds": outbounds, "nodes": nodes, "inbounds": forwards, "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 6000, "drain_timeout_ms": 500, "max_sessions": 64}}
        path = root / "combined.json"
        h.write_json(path, config)
        checked([args.kerlico, "check", "-c", str(path)], root, "combined-check")
        duplicate = json.loads(json.dumps(config))
        duplicate["nodes"][1]["options"]["passwords"] = [passwords[0]]
        duplicate_path = root / "duplicate.json"
        h.write_json(duplicate_path, duplicate)
        checked([args.kerlico, "check", "-c", str(duplicate_path)], root, "duplicate-check", False)
        checks.append("配置拒绝跨节点重复凭据")
        server = stack.enter_context(h.process([args.kerlico, "run", "-c", str(path)], root, "kerlico-combined"))
        h.wait_ready(server, cases[0][2])
        for i, label, local in cases:
            payload = bytes(range(256)) * (48 if label == "udp" else 1024)
            try:
                result = h.udp_request(local, payload) if label == "udp" else tcp(local, payload)
            except OSError as error:
                raise RuntimeError("双端回写异常：" + str(i) + label + "：" + type(error).__name__) from error
            if result != payload:
                raise RuntimeError("双端/目标访问回写失败：" + str(i) + label)
            if label == "udp" and h.udp_request(local, b"") != b"":
                raise RuntimeError("根程序未保留空数据报")
            checks.append(("kerlico-v4", "kerlico-v6", "sing-box-server")[i] + "：" + label)
        with ThreadPoolExecutor(max_workers=4) as pool:
            payloads = [bytes([i]) * 4096 for i in range(4)]
            if list(pool.map(lambda data: tcp(cases[0][2], data), payloads)) != payloads:
                raise RuntimeError("根程序并发会话发生串流")
        checks.append("根程序四路并发隔离")
        for i in range(2):
            socks_port = h.free_port()
            client_config = {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": socks_port}], "outbounds": [{"type": "anytls", "server": hosts[i], "server_port": node_ports[i], "password": passwords[i], "tls": {"enabled": True, "server_name": "localhost", "certificate": [ca]}}]}
            client_path = root / ("reference-client" + str(i) + ".json")
            h.write_json(client_path, client_config)
            client = stack.enter_context(h.process([args.reference, "run", "-c", str(client_path)], root, "reference-client" + str(i)))
            h.wait_ready(client, socks_port)
            for host, target in [("127.0.0.1", target4), ("::1", target6)]:
                payload = b"reference-to-node" * 8192
                if socks_request(socks_port, host, target, payload) != payload:
                    raise RuntimeError("真实参考客户端到独立节点失败")
            checks.append("sing-box-client→node" + str(i) + "：双目标地址族")
            bad = {"version": 1, "outbounds": [{"tag": "bad", "type": "anytls", "options": {"server": {"host": hosts[i], "port": node_ports[i]}, "password": passwords[1-i], "tls": {"server_name": "localhost", "ca_pem": ca}}}], "inbounds": [{"tag": "bad-local", "type": "tcp-forward", "listen": "127.0.0.1:" + str(h.free_port()), "target": {"host": "127.0.0.1", "port": target4}, "outbound": "bad"}]}
            bad_path = root / ("wrong" + str(i) + ".json")
            h.write_json(bad_path, bad)
            bad_local = int(bad["inbounds"][0]["listen"].split(":")[-1])
            bad_process = stack.enter_context(h.process([args.kerlico, "run", "-c", str(bad_path)], root, "wrong" + str(i)))
            h.wait_ready(bad_process, bad_local)
            try:
                result = tcp(bad_local, b"must-not-pass")
            except OSError:
                result = b""
            if result:
                raise RuntimeError("节点接受另一节点凭据")
            checks.append("node" + str(i) + "：拒绝另一节点口令")
        if args.stripped:
            modules = checked([args.stripped, "modules"], root, "stripped-modules")
            if "anytls" in modules:
                raise RuntimeError("裁剪构建仍注册 AnyTLS")
            checked([args.stripped, "check", "-c", str(path)], root, "stripped-check", False)
            node_only = root / "stripped-node-only.json"
            h.write_json(node_only, {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": nodes})
            checked([args.stripped, "check", "-c", str(node_only)], root, "stripped-node-check", False)
            checks.append("无协议构建不注册 AnyTLS 并分别拒绝入/出站配置")
        server.send_signal(signal.SIGTERM)
        if server.wait(timeout=3) != 0:
            raise RuntimeError("根程序未在预算内退出")
        checks.append("根程序双端有界退出")
    return checks


def main():
    parser = argparse.ArgumentParser(description="AnyTLS 根程序集成验收")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--stripped")
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    result = {"ok": True}
    try:
        result["checks"] = verify(args, root)
    except Exception as error:
        result = {"ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
    result["binary_sha256"] = hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest()
    h.write_json(root / "result.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
