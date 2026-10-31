#!/usr/bin/env python3
"""专用 worker 的 VMess/Xray 双向矩阵，配置与原始日志留在私有目录。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import interop_vless as h

ID = "00000000-0000-4000-8000-000000000001"

class UdpServer(h.UdpServer):
    max_packet_size = 65535

def tcp(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        result = bytearray()
        while len(result) < len(payload):
            part = sock.recv(min(65535, len(payload)-len(result)))
            if not part:
                break
            result.extend(part)
        return bytes(result)

def stream_config(network, tls, multi, cert, key, client):
    result = {"network": "raw" if network == "tcp" else network, "security": "tls" if tls else "none"}
    if tls:
        result["tlsSettings"] = {"serverName": "localhost", "allowInsecure": False, "alpn": ["h2"] if network == "grpc" else ["http/1.1"] if network != "tcp" else []}
        if client:
            result["tlsSettings"]["certificates"] = [{"certificateFile": str(cert), "usage": "verify"}]
        else:
            result["tlsSettings"]["certificates"] = [{"certificateFile": str(cert), "keyFile": str(key)}]
    if network in ("ws", "httpupgrade"):
        result[network + "Settings"] = {"path": "/vmess", "host": "localhost"}
    if network == "grpc":
        result["grpcSettings"] = {"serviceName": "proxy", "multiMode": multi}
    return result

def transport(network, multi):
    value = {"type": network}
    if network in ("ws", "httpupgrade"):
        value.update(path="/vmess", host="localhost")
    if network == "grpc":
        value.update(service_name="proxy", multi_mode=multi, authority="localhost")
    return value

def run_case(args, root, cert, key, cipher, network, tls, multi, direction, auth):
    label = "-".join([direction, cipher, network, "tls" if tls else "none", "multi" if multi else "single", "authlen" if auth else "mask"])
    work = root / label
    work.mkdir(mode=0o700)
    checks = []
    with ExitStack() as stack:
        tcp_target = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        udp_target = stack.enter_context(h.serve(UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        node_port = h.free_port()
        tcp_local, udp_local = h.free_port(), h.free_port()
        limits = {"connect_timeout_ms": 4000, "idle_timeout_ms": 10000, "drain_timeout_ms": 500}
        if direction == "client":
            peer = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": node_port, "protocol": "vmess", "settings": {"clients": [{"id": ID}]}, "streamSettings": stream_config(network, tls, multi, cert, key, False)}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": str(tcp_target)+","+str(udp_target)}]}}]}
            options = {"server": {"host": "127.0.0.1", "port": node_port}, "uuid": ID, "security": cipher, "transport": transport(network, multi), "authenticated_length": auth}
            if tls:
                options["tls"] = {"type": "tls", "server_name": "localhost", "ca_pem": cert.read_text()}
            own = {"version": 1, "limits": limits, "outbounds": [{"tag": "proxy", "type": "vmess", "options": options}], "inbounds": [{"tag": "tcp", "type": "tcp-forward", "listen": "127.0.0.1:"+str(tcp_local), "target": {"host": "127.0.0.1", "port": tcp_target}, "outbound": "proxy"}, {"tag": "udp", "type": "udp-forward", "listen": "127.0.0.1:"+str(udp_local), "target": {"host": "127.0.0.1", "port": udp_target}, "outbound": "proxy"}]}
        else:
            node = {"uuid": ID, "transport": transport(network, multi)}
            if tls:
                node["security"] = {"type": "tls", "certificate_file": str(cert), "private_key_file": str(key)}
            own = {"version": 1, "limits": limits, "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [{"tag": "node", "type": "vmess", "listen": "127.0.0.1:"+str(node_port), "outbound": "direct", "options": node}], "inbounds": []}
            user = {"id": ID, "security": cipher}
            if auth:
                user["experiments"] = "AuthenticatedLength"
            peer = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": tcp_local, "protocol": "tunnel", "settings": {"address": "127.0.0.1", "port": tcp_target, "network": "tcp"}}, {"listen": "127.0.0.1", "port": udp_local, "protocol": "tunnel", "settings": {"address": "127.0.0.1", "port": udp_target, "network": "udp"}}], "outbounds": [{"protocol": "vmess", "settings": {"vnext": [{"address": "127.0.0.1", "port": node_port, "users": [user]}]}, "streamSettings": stream_config(network, tls, multi, cert, key, True), "mux": {"enabled": False}}]}
        if args.backend == "sing-box":
            if direction == "client":
                inbound = {"type": "vmess", "listen": "127.0.0.1", "listen_port": node_port, "users": [{"uuid": ID}]}
                if tls:
                    inbound["tls"] = {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}
                peer = {"log": {"level": "warn"}, "inbounds": [inbound], "outbounds": [{"type": "direct"}]}
            else:
                outbound = {"type": "vmess", "server": "127.0.0.1", "server_port": node_port, "uuid": ID, "security": cipher, "global_padding": True, "authenticated_length": auth, "packet_encoding": ""}
                if tls:
                    outbound["tls"] = {"enabled": True, "server_name": "localhost", "certificate": [cert.read_text()]}
                peer = {"log": {"level": "warn"}, "inbounds": [{"type": "direct", "listen": "127.0.0.1", "listen_port": tcp_local, "network": "tcp", "override_address": "127.0.0.1", "override_port": tcp_target}, {"type": "direct", "listen": "127.0.0.1", "listen_port": udp_local, "network": "udp", "override_address": "127.0.0.1", "override_port": udp_target}], "outbounds": [outbound]}
            if network != "tcp":
                item = peer["inbounds"][0] if direction == "client" else peer["outbounds"][0]
                item["transport"] = {"type": network}
                if network == "grpc":
                    item["transport"]["service_name"] = "proxy"
                else:
                    item["transport"]["path"] = "/vmess"
        h.write_json(work / "own.json", own)
        h.write_json(work / "peer.json", peer)
        reference = [args.reference, "run", "-config" if args.backend == "xray" else "-c", str(work / "peer.json")]
        first = reference if direction == "client" else [args.kerlico, "run", "-c", str(work / "own.json")]
        second = [args.kerlico, "run", "-c", str(work / "own.json")] if direction == "client" else reference
        first_process = stack.enter_context(h.process(first, work, "first"))
        h.wait_ready(first_process, node_port)
        second_process = stack.enter_context(h.process(second, work, "second"))
        h.wait_ready(second_process, tcp_local)
        payload = bytes(range(251))*1024
        if tcp(tcp_local, payload) != payload:
            raise RuntimeError(label + "：TCP 回写失败")
        checks.append(label + "：TCP")
        h.write_json(work / "progress.json", checks)
        # 参考核心对普通端口默认可能改用 XUDP。禁用该行为后才能验 command 2。
        for size in (int(value) for value in args.udp_sizes.split(",")):
            payload = bytes([size % 251])*size
            if h.udp_request(udp_local, payload) != payload:
                raise RuntimeError(label + "：UDP 回写失败：" + str(size))
            h.write_json(work / "progress.json", checks + [label + "：UDP：" + str(size)])
        checks.append(label + "：UDP")
    return checks

def main():
    parser = argparse.ArgumentParser(description="VMess 真实 Xray 双向互通")
    parser.add_argument("--backend", choices=("xray", "sing-box"), default="xray")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--direction", choices=("client", "server", "both"), default="both")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--udp-sizes", default="17,1200,12000")
    args = parser.parse_args()
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key = root / "certificate.pem", root / "key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError("测试证书生成失败")
    # core/xray.go 在 xray.cone.disabled=true 时关闭 VMess 默认 XUDP 转换。
    os.environ["xray.cone.disabled"] = "true"
    checks, failures = [], []
    for direction in (("client", "server") if args.direction == "both" else (args.direction,)):
        for cipher in ("aes-128-gcm", "chacha20-poly1305"):
            for network in (("tcp", "ws", "httpupgrade", "grpc") if args.full else ("tcp",)):
                for tls in (False, True):
                    for multi in ((False, True) if network == "grpc" else (False,)):
                        for auth in ((False, True) if network == "tcp" else (False,)):
                            try:
                                checks.extend(run_case(args, root, cert, key, cipher, network, tls, multi, direction, auth))
                            except Exception as error:
                                failures.append({"direction": direction, "cipher": cipher, "network": network, "tls": tls, "multi": multi, "authenticated_length": auth, "error": str(error) if isinstance(error, RuntimeError) else type(error).__name__})
    result = {"ok": not failures, "checks": checks, "failures": failures, "binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest()}
    h.write_json(root / "result.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    if failures:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
