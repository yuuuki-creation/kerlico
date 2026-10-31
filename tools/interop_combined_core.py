#!/usr/bin/env python3
"""在 worker 验证指定协议集合由同一程序承载双角色。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

import interop_vless as h
from interop_vless_matrix import material, tcp


class Udp6(h.UdpServer):
    address_family = socket.AF_INET6


def verify(args, root):
    protocols = args.protocols.split(",")
    supported = {"vless", "anytls", "ss2022", "socks", "http", "shadowsocks", "trojan", "vmess", "snell", "tuic", "hysteria2"}
    if not protocols or len(set(protocols)) != len(protocols) or not set(protocols) <= supported:
        raise RuntimeError("联合测试的协议集合不合法")
    if not 1 <= args.udp_size <= 65507 or not 1 <= args.max_sessions <= 65536:
        raise RuntimeError("联合测试的包长或会话预算不合法")
    used_ports = set()
    def fresh_port():
        for _ in range(100):
            value = h.free_port()
            if value not in used_ports:
                used_ports.add(value)
                return value
        raise RuntimeError("无法为联合测试分配独立端口")
    modules = subprocess.check_output([args.kerlico, "modules"], timeout=10).decode().splitlines()
    expected = {"outbound/direct", "outbound/reject"} | {role+"/"+protocol for protocol in protocols for role in ("inbound", "outbound")}
    if set(modules) != expected:
        raise RuntimeError("默认构建的协议注册集合不正确")
    checks = ["程序注册指定协议双端"]
    cert, key, _, _, _ = material(root)
    with ExitStack() as stack:
        targets = [("tcp", "127.0.0.1", stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))), ("tcp", "::1", stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))), ("udp", "127.0.0.1", stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))), ("udp", "::1", stack.enter_context(h.serve(Udp6(("::1", 0), h.UdpEcho))))]
        outbounds = [{"tag": "direct", "type": "direct"}]
        nodes, inbounds, cases, wrong, concurrent = [], [], [], [], []
        for protocol in protocols:
            secrets = (["00000000-0000-0000-0000-000000000041", "00000000-0000-0000-0000-000000000042"] if protocol in {"vless", "vmess", "tuic"} else [base64.b64encode(os.urandom(16)).decode() for _ in range(2)] if protocol == "ss2022" else ["combined-"+os.urandom(16).hex() for _ in range(2)])
            for family, host in enumerate(("127.0.0.1", "::1")):
                port = fresh_port()
                tag = protocol+str(family)
                listen = ("["+host+"]" if ":" in host else host)+":"+str(port)
                if protocol == "vless":
                    node = {"uuid": secrets[family], "security": {"type": "tls", "certificate_file": str(cert), "private_key_file": str(key)}}
                    client = {"server": {"host": host, "port": port}, "uuid": secrets[family], "security": {"type": "tls", "server_name": "localhost", "ca_pem": cert.read_text()}}
                    bad = dict(client, uuid=secrets[1-family])
                elif protocol == "anytls":
                    node = {"passwords": [secrets[family]], "tls": {"certificate_file": str(cert), "private_key_file": str(key)}}
                    client = {"server": {"host": host, "port": port}, "password": secrets[family], "tls": {"server_name": "localhost", "ca_pem": cert.read_text()}}
                    bad = dict(client, password=secrets[1-family])
                elif protocol == "ss2022":
                    node = {"method": "2022-blake3-aes-128-gcm", "key": secrets[family]}
                    client = dict(node, server=host, port=port)
                    bad = dict(client, key=secrets[1-family])
                elif protocol in {"socks", "http"}:
                    node = {"auth": {"username": "combined", "password": secrets[family]}}
                    client = dict(node, server={"host": host, "port": port})
                    bad = dict(client, auth={"username": "combined", "password": secrets[1-family]})
                elif protocol == "shadowsocks":
                    node = {"method": "aes-128-gcm", "password": secrets[family]}
                    client = dict(node, server=host, port=port)
                    bad = dict(client, password=secrets[1-family])
                elif protocol == "trojan":
                    node = {"password": secrets[family], "security": {"type": "tls", "certificate_file": str(cert), "private_key_file": str(key)}}
                    client = {"server": {"host": host, "port": port}, "password": secrets[family], "security": {"type": "tls", "server_name": "localhost", "ca_pem": cert.read_text()}}
                    bad = dict(client, password=secrets[1-family])
                elif protocol == "snell":
                    node = {"version": 6, "psk": secrets[family], "mode": "default"}
                    client = dict(node, server={"host": host, "port": port}, reuse=True)
                    bad = dict(client, psk=secrets[1-family])
                elif protocol == "tuic":
                    node = {"version": 5, "uuid": secrets[family], "password": "combined-"+secrets[family], "tls": {"certificate_file": str(cert), "private_key_file": str(key)}}
                    client = {"version": 5, "server": {"host": host, "port": port}, "uuid": secrets[family], "password": "combined-"+secrets[family], "tls": {"server_name": "localhost", "ca_pem": cert.read_text()}}
                    bad = dict(client, uuid=secrets[1-family], password="combined-"+secrets[1-family])
                elif protocol == "hysteria2":
                    node = {"auth": secrets[family], "tls": {"certificate_file": str(cert), "private_key_file": str(key)}}
                    client = {"server": {"host": host, "port": port}, "auth": secrets[family], "tls": {"server_name": "localhost", "ca_pem": cert.read_text()}}
                    bad = dict(client, auth=secrets[1-family])
                else:
                    node = {"uuid": secrets[family], "security": {"type": "tls", "certificate_file": str(cert), "private_key_file": str(key)}}
                    client = {"server": {"host": host, "port": port}, "uuid": secrets[family], "security": "aes-128-gcm", "tls": {"type": "tls", "server_name": "localhost", "ca_pem": cert.read_text()}}
                    bad = dict(client, uuid=secrets[1-family])
                nodes.append({"tag": tag, "type": protocol, "listen": listen, "outbound": "direct", "max_sessions": 24, "options": node})
                outbounds.extend([{"tag": tag, "type": protocol, "options": client}, {"tag": tag+"bad", "type": protocol, "options": bad}])
                for index, (network, target_host, target_port) in enumerate(targets):
                    if protocol == "http" and network == "udp":
                        continue
                    local = fresh_port()
                    label = tag+"-target"+str(index)
                    inbounds.append({"tag": label, "type": network+"-forward", "listen": "127.0.0.1:"+str(local), "target": {"host": target_host, "port": target_port}, "outbound": tag})
                    cases.append((label, network, local))
                    if index == 0:
                        concurrent.append((tag, local))
                local = fresh_port()
                inbounds.append({"tag": tag+"bad", "type": "tcp-forward", "listen": "127.0.0.1:"+str(local), "target": {"host": "127.0.0.1", "port": targets[0][2]}, "outbound": tag+"bad"})
                wrong.append((tag, local))
        config = {"version": 1, "outbounds": outbounds, "nodes": nodes, "inbounds": inbounds, "limits": {"connect_timeout_ms": 2000, "idle_timeout_ms": 6000, "drain_timeout_ms": 200, "max_sessions": args.max_sessions}}
        path = root / "combined.json"
        h.write_json(path, config)
        checked = subprocess.run([args.kerlico, "check", "-c", str(path)], capture_output=True, timeout=10)
        if checked.returncode:
            raise RuntimeError("指定协议组合配置检查失败")
        checks.append("指定协议组合配置检查")
        with h.process([args.kerlico, "run", "-c", str(path)], root, "combined") as child:
            h.wait_ready(child, cases[0][2])
            for label, network, local in cases:
                payload = bytes(range(256))*256 if network == "tcp" else (bytes(range(256))*((args.udp_size+255)//256))[:args.udp_size]
                value = tcp(local, payload) if network == "tcp" else h.udp_request(local, payload)
                if value != payload:
                    raise RuntimeError(label+"：回写不一致")
                checks.append(label+"："+network)
            for tag, local in wrong:
                try:
                    value = tcp(local, b"cross-node-credentials-must-fail")
                except (OSError, TimeoutError):
                    value = b""
                if value:
                    raise RuntimeError(tag+"：错误接受另一节点凭据")
                checks.append(tag+"：凭据隔离")
            with ThreadPoolExecutor(max_workers=len(concurrent)) as pool:
                payloads = [tag.encode()*4096 for tag, _ in concurrent]
                values = list(pool.map(lambda item: tcp(item[0][1], item[1]), zip(concurrent, payloads)))
                if values != payloads:
                    raise RuntimeError("联合节点并发串流")
            checks.append("联合节点同时收发")
            child.terminate()
            if child.wait(timeout=3) != 0:
                raise RuntimeError("组合程序未按预算退出")
            checks.append("全协议排空退出")
        with h.process([args.kerlico, "run", "-c", str(path)], root, "rebind") as child:
            h.wait_ready(child, cases[0][2])
            if tcp(cases[0][2], b"same-ports-rebound") != b"same-ports-rebound":
                raise RuntimeError("组合配置端口重用失败")
            checks.append("全配置同端口重启")
        return checks


def main():
    parser = argparse.ArgumentParser(description="单程序指定协议集合的双端装配验收")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--protocols", default="vless,anytls,ss2022")
    parser.add_argument("--udp-size", type=int, default=4096)
    parser.add_argument("--max-sessions", type=int, default=128)
    args = parser.parse_args()
    args.kerlico = str(Path(args.kerlico).resolve())
    root = Path(args.work_dir).resolve()
    os.umask(0o077)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        result = {"ok": True, "checks": verify(args, root)}
    except Exception as error:
        result = {"ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
    result["binary_sha256"] = hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest()
    h.write_json(root / "result.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
