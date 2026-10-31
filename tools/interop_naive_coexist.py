#!/usr/bin/env python3
"""专用worker：同一kerlico进程同时运行独立双族Naive节点与三载体客户端。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import interop_naive as h

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    if os.environ.get("KERLICO_WORKER_ONLY") != "1":
        raise SystemExit("只允许专用worker执行")
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    config = {"version": 1, "limits": {"max_sessions": 256, "idle_timeout_ms": 5000, "drain_timeout_ms": 500}, "outbounds": [{"tag": "direct", "type": "direct"}], "nodes": [], "inbounds": []}
    used, endpoints, checks = set(), [], []
    def free():
        while True:
            port = h.h.free_port()
            if port in used:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as four, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as six:
                    four.bind(("127.0.0.1", port))
                    six.bind(("::1", port))
            except OSError:
                continue
            used.add(port)
            return port
    with ExitStack() as stack:
        for identity, host, site in [("four", "127.0.0.1", "::1"), ("six", "::1", "127.0.0.1")]:
            certificate_dir = root / identity
            certificate_dir.mkdir(mode=0o700)
            certificate, key, ca = h.certificates(certificate_dir)
            node_port = free()
            user, password = "node-" + identity, "synthetic-" + identity
            options = {"users": [{"username": user, "password": password}], "tls": {"certificate_file": str(certificate), "private_key_file": str(key)}, "udp_over_tcp": True}
            config["nodes"].append({"tag": "node-" + identity, "type": "naive", "listen": h.address(host, node_port), "outbound": "direct", "options": options, "max_sessions": 64})
            tcp_site = stack.enter_context(h.h.serve((h.h.TcpServer6 if ":" in site else h.h.TcpServer)((site, 0), h.h.TcpEcho)))
            udp_site = stack.enter_context(h.h.serve((h.UdpServer6 if ":" in site else h.UdpServer)((site, 0), h.h.UdpEcho)))
            for transport in ["h1", "h2", "h3"]:
                tag = identity + "-" + transport
                outbound = {"server": {"host": host, "port": node_port}, "username": user, "password": password, "tls": {"server_name": "proxy.invalid", "ca_pem": ca.read_text()}, "transport": transport, "udp_over_tcp": {"enabled": True, "version": 2}, "max_sessions": 16 if transport == "h1" else 1}
                config["outbounds"].append({"tag": tag, "type": "naive", "options": outbound})
                tcp_local, udp_local = free(), free()
                config["inbounds"].extend([{"tag": tag + "-tcp", "type": "tcp-forward", "listen": h.address("127.0.0.1", tcp_local), "target": {"host": site, "port": tcp_site}, "outbound": tag}, {"tag": tag + "-udp", "type": "udp-forward", "listen": h.address("127.0.0.1", udp_local), "target": {"host": site, "port": udp_site}, "outbound": tag}])
                endpoints.append((tag, tcp_local, udp_local))
        correct = config["outbounds"][-1]
        wrong = json.loads(json.dumps(correct))
        wrong["tag"] = "wrong-node"
        wrong["options"]["username"] = "node-four"
        wrong["options"]["password"] = "synthetic-four"
        config["outbounds"].append(wrong)
        bad_port = free()
        config["inbounds"].append({"tag": "wrong-tcp", "type": "tcp-forward", "listen": h.address("127.0.0.1", bad_port), "target": {"host": "127.0.0.1", "port": tcp_site}, "outbound": "wrong-node"})
        h.h.write_json(root / "config.json", config)
        command = [args.kerlico, "run", "-c", str(root / "config.json")]
        kernel = stack.enter_context(h.process(command, root, "kernel"))
        for node in config["nodes"]:
            port = int(node["listen"].rsplit(":", 1)[1])
            for protocol in ["tcp", "udp"]:
                h.wait_listener(kernel, port, protocol)
        for tag, tcp_local, udp_local in endpoints:
            data = bytes(range(251)) * 1024
            if h.tcp_request(tcp_local, data) != data:
                raise RuntimeError("同进程TCP内容不符")
            checks.append(tag + ":TCP257024")
            for size in [0, 12000, 65507]:
                data = bytes([size % 251]) * size
                if h.udp_request(udp_local, data) != data:
                    raise RuntimeError("同进程UDP内容不符")
                checks.append(tag + ":UDP" + str(size))
        try:
            h.tcp_request(bad_port, b"wrong-node")
        except (OSError, RuntimeError):
            checks.append("交叉凭据拒绝")
        else:
            raise RuntimeError("独立节点错误地接受其他节点凭据")
        for tag, tcp_local, _ in [endpoints[0], endpoints[-1]]:
            if h.tcp_request(tcp_local, b"after-rejection") != b"after-rejection":
                raise RuntimeError("认证失败后合法节点不可用")
            checks.append(tag + ":认证失败后合法控制流")
        kernel.send_signal(signal.SIGTERM)
        if kernel.wait(timeout=4) != 0:
            raise RuntimeError("同进程双端退出状态异常")
        restarted = stack.enter_context(h.process(command, root, "restarted"))
        for node in config["nodes"]:
            port = int(node["listen"].rsplit(":", 1)[1])
            for protocol in ["tcp", "udp"]:
                h.wait_listener(restarted, port, protocol)
        restarted.send_signal(signal.SIGTERM)
        if restarted.wait(timeout=4) != 0:
            raise RuntimeError("同端口重绑后退出状态异常")
        checks.append("同进程双端退出与同端口重绑")
    result = {"ok": True, "checks": checks, "binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "nodes": 2, "client_transports": 6}
    h.h.write_json(root / "result.json", result)
    print(json.dumps({"ok": True, "checks": len(checks)}, ensure_ascii=False), flush=True)

if __name__ == "__main__":
    main()
