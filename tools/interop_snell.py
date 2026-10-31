#!/usr/bin/env python3
"""专用 worker 的 Snell 双向版本/模式/复用与多用户矩阵。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import interop_vless as h

class UdpServer6(h.UdpServer):
    address_family = socket.AF_INET6

class BannerEcho(h.TcpEcho):
    def handle(self):
        self.request.sendall(b"server-first")
        super().handle()

MODES = (("v4", "none"), ("v4", "http"), ("default", "none"), ("unshaped", "none"), ("unsafe-raw", "none"))

def options(mode, obfs, psk, userkey, server, reference, reuse):
    version = (5 if server else 4) if mode == "v4" else 6
    result = {"version": version, "psk": psk, "obfs_mode": obfs}
    if mode != "v4":
        result.pop("obfs_mode")
        result["mode"] = mode
    if userkey:
        if server:
            result["users"] = [{"userkey": userkey, **({"name": "test"} if reference else {})}]
        else:
            result["userkey"] = userkey
    if not server:
        result["reuse"] = reuse
    return result

def banner_tcp(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        greeting = bytearray()
        while len(greeting) < 12:
            part = sock.recv(12 - len(greeting))
            if not part:
                raise RuntimeError("目标首包之前连接已结束")
            greeting.extend(part)
        if greeting != b"server-first":
            raise RuntimeError("目标首包不一致")
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        sock.shutdown(socket.SHUT_WR)
        output = bytearray()
        while part := sock.recv(65536):
            output.extend(part)
        if output != payload:
            raise RuntimeError("目标先发数据后的回写不一致")

def peer_base():
    return {"log": {"level": "error"}, "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"}}

def udp_sequence(port, sizes, truncated_probe=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        for size in sizes:
            payload = b"u" * size
            sock.sendto(payload, ("127.0.0.1", port))
            received = sock.recv(65535)
            if received != payload:
                raise RuntimeError("UDP 长度 " + str(size) + " 的回写不一致，实际 " + str(len(received)) + " 字节")
        if truncated_probe is not None:
            payload = b"b" * 4096
            sock.sendto(payload, ("127.0.0.1", port))
            received = sock.recv(65535)
            if len(received) != truncated_probe or received != payload[:truncated_probe]:
                raise RuntimeError("固定对端 MTU 截断负例与已核对源码不一致")

def tcp(port, payload):
    return h.tcp_request(port, payload)

def case(args, root, mode, obfs, reuse, multi, direction):
    label = "-".join((direction, mode, obfs, "reuse" if reuse else "single", "multiuser" if multi else "psk"))
    directory = root / label
    directory.mkdir(mode=0o700)
    passwords = ["snell-node4-test-psk-" + ("multi" if multi else "single"), "snell-node6-test-psk-" + ("multi" if multi else "single")]
    users = ["node4-test-userkey", "node6-test-userkey"] if multi else ["", ""]
    hosts, ports = ["127.0.0.1", "::1"], [h.free_port(), h.free_port()]
    checks = []
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        banner = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), BannerEcho)))
        udp4 = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        udp6 = stack.enter_context(h.serve(UdpServer6(("::1", 0), h.UdpEcho)))
        if direction == "client":
            server = peer_base()
            server["inbounds"] = [{"type": "snell", "tag": "node" + str(i), "listen": hosts[i], "listen_port": ports[i], **options(mode, obfs, passwords[i], users[i], True, True, reuse)} for i in range(2)]
            server["outbounds"] = [{"type": "direct", "domain_resolver": {"server": "local", "strategy": "ipv4_only"}}]
            server_binary = args.reference
        else:
            server = {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node" + str(i), "type": "snell", "listen": ("[::1]:" if i else "127.0.0.1:") + str(ports[i]), "outbound": "direct", "options": options(mode, obfs, passwords[i], users[i], True, False, reuse)} for i in range(2)], "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 8000, "drain_timeout_ms": 300, "max_sessions": 128}}
            server_binary = args.kerlico
        server_path = directory / "server.json"
        h.write_json(server_path, server)
        with h.process([server_binary, "run", "-c", str(server_path)], directory, "server") as process:
            h.wait_ready(process, ports[0])
            for index in range(2):
                bad_cases = [None]
                if mode != "unsafe-raw":
                    bad_cases.append("psk")
                if multi:
                    bad_cases.append("userkey")
                for bad in bad_cases:
                    case_root = directory / ("node" + str(index) + ("-wrong-" + bad if bad else "-valid"))
                    case_root.mkdir(mode=0o700)
                    rules = [("tcp4", "tcp", h.free_port(), "127.0.0.1", target4), ("tcp6", "tcp", h.free_port(), "::1", target6), ("udp4", "udp", h.free_port(), "127.0.0.1", udp4), ("udp6", "udp", h.free_port(), "::1", udp6), ("udp-domain", "udp", h.free_port(), "localhost", udp4), ("banner", "tcp", h.free_port(), "127.0.0.1", banner)]
                    psk = passwords[1-index] if bad == "psk" else passwords[index]
                    user = users[1-index] if bad == "userkey" else users[index]
                    client_options = options(mode, obfs, psk, user, False, direction == "server", reuse)
                    if direction == "client":
                        client_options["server"] = {"host": hosts[index], "port": ports[index]}
                        client = {"version": 1, "outbounds": [{"tag": "proxy", "type": "snell", "options": client_options}], "inbounds": [{"tag": tag, "type": network + "-forward", "listen": "127.0.0.1:" + str(port), "target": {"host": host, "port": target}, "outbound": "proxy"} for tag, network, port, host, target in rules], "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 8000, "drain_timeout_ms": 300, "max_sessions": 128}}
                        binary = args.kerlico
                    else:
                        client_options.update(type="snell", server=hosts[index], server_port=ports[index])
                        client = peer_base()
                        client["inbounds"] = [{"tag": tag, "type": "direct", "listen": "127.0.0.1", "listen_port": port, "network": network, "override_address": host, "override_port": target} for tag, network, port, host, target in rules]
                        client["outbounds"] = [client_options]
                        binary = args.reference
                    path = case_root / "client.json"
                    h.write_json(path, client)
                    with h.process([binary, "run", "-c", str(path)], case_root, "client") as child:
                        h.wait_ready(child, rules[0][2])
                        if bad:
                            try:
                                received = tcp(rules[0][2], b"must-not-cross-identity")
                            except (OSError, TimeoutError):
                                received = b""
                            if received:
                                raise RuntimeError("跨节点错误 " + bad + " 被接受")
                            checks.append("节点" + str(index) + "错误 " + bad + " 拒绝")
                            continue
                        for rule in rules[:2]:
                            for size in (17, 4096, 65536):
                                if tcp(rule[2], b"t" * size) != b"t" * size:
                                    raise RuntimeError(rule[0] + " 长度 " + str(size) + " 的 TCP 回写不一致")
                        checks.append("节点" + str(index) + "双族 TCP 与完整 EOF")
                        banner_tcp(rules[-1][2], b"after-server-first")
                        checks.append("节点" + str(index) + "目标先发数据")
                        for rule in rules[2:5]:
                            try:
                                if mode == "v4":
                                    native_limit = 1402 if direction == "client" else 1162
                                    probe = native_limit if obfs == "none" and not reuse and not multi and index == 0 else None
                                    udp_sequence(rule[2], [17] * 10 + [512, 1000, native_limit], probe)
                                else:
                                    udp_sequence(rule[2], [17] * 10 + [512, 1000, 4096, 8192])
                            except (OSError, TimeoutError) as error:
                                raise RuntimeError(rule[0] + " 数据报未完成") from error
                        checks.append("节点" + str(index) + "双族及域名 UDP 独立记录" + ("；固定对端有效负载至" + str(native_limit) if mode == "v4" else "；至8192字节"))
                        if mode == "v4" and obfs == "none" and not reuse and not multi and index == 0:
                            checks.append("4096字节固定对端MTU截断负例已独立观察，未拼包或改写成功")
                        payloads = [("flow-" + str(n)).encode() * 1024 for n in range(4)]
                        with ThreadPoolExecutor(max_workers=4) as pool:
                            if list(pool.map(lambda payload: tcp(rules[0][2], payload), payloads)) != payloads:
                                raise RuntimeError("并发流数据混用")
                        checks.append("节点" + str(index) + "四路并发隔离")
            process.terminate()
            if process.wait(timeout=4) != 0:
                raise RuntimeError("服务端未在预算内退出")
            checks.append("服务端有界退出")
    return checks

def main():
    parser = argparse.ArgumentParser(description="Snell 双向角色/版本/模式矩阵，仅在专用 worker 执行")
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
    results = []
    for mode, obfs in MODES:
        for reuse in (False, True):
            for multi in ((True,) if mode == "unsafe-raw" else (False, True)):
                for direction in ("client", "server"):
                    label = "-".join((direction, mode, obfs, "reuse" if reuse else "single", "multiuser" if multi else "psk"))
                    if args.only and args.only not in label:
                        continue
                    try:
                        checks = case(args, root, mode, obfs, reuse, multi, direction)
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
