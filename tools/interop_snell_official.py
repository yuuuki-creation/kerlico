#!/usr/bin/env python3
"""kerlico Snell 出站接官方 snell-server。官方没有 Linux 客户端，所以只测出站方向。只在 worker 运行。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import socket

import interop_snell as snell
import interop_vless as h

CASES = (
    ("v4.1.1", 4, {}, "off"),
    ("v4.1.1", 4, {"obfs_mode": "http"}, "http"),
    ("v5.0.1", 4, {}, "off"),
    ("v6.0.0", 6, {"mode": "default"}, "off"),
    ("v6.0.0", 6, {"mode": "default", "reuse": True}, "off"),
)
PSK = "snell-official-test-only-psk"


def echo(port, payload, greeting=b""):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        received = bytearray()
        while len(received) < len(greeting):
            part = sock.recv(len(greeting) - len(received))
            if not part:
                raise RuntimeError("目标首包之前连接已结束")
            received.extend(part)
        if received != greeting:
            raise RuntimeError("目标首包不一致")
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        received = bytearray()
        while len(received) < len(payload):
            part = sock.recv(65536)
            if not part:
                break
            received.extend(part)
    return bytes(received)


def check_case(args, root, server_version, wire, extra, obfs, checks):
    label = "-".join((server_version, "wire" + str(wire), obfs, "reuse" if extra.get("reuse") else "single"))
    directory = root / label
    directory.mkdir(mode=0o700)
    binary = args.server_root / server_version / "snell-server"
    port = h.free_port()
    ini = directory / "server.conf"
    ini.write_text(f"[snell-server]\nlisten = 127.0.0.1:{port}\npsk = {PSK}\nipv6 = true\nobfs = {obfs}\n")
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        banner = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), snell.BannerEcho)))
        udp4 = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        udp6 = stack.enter_context(h.serve(snell.UdpServer6(("::1", 0), h.UdpEcho)))
        server = stack.enter_context(h.process([str(binary), "-c", str(ini)], directory, "server"))
        h.wait_ready(server, port)
        # snell-server 开启 ipv6 后把 localhost 解析到 ::1，域名目标两族都要有回显。
        domain_target = h.free_port()
        stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", domain_target), h.TcpEcho)))
        stack.enter_context(h.serve(h.TcpServer6(("::1", domain_target), h.TcpEcho)))
        rules = [
            ("tcp4", "tcp", h.free_port(), "127.0.0.1", target4),
            ("tcp6", "tcp", h.free_port(), "::1", target6),
            ("domain", "tcp", h.free_port(), "localhost", domain_target),
            ("banner", "tcp", h.free_port(), "127.0.0.1", banner),
            ("udp4", "udp", h.free_port(), "127.0.0.1", udp4),
            ("udp6", "udp", h.free_port(), "::1", udp6),
        ]
        client = {
            "version": 1,
            "outbounds": [{"tag": "proxy", "type": "snell", "options": {"server": {"host": "127.0.0.1", "port": port}, "version": wire, "psk": PSK, **extra}}],
            "inbounds": [{"tag": tag, "type": network + "-forward", "listen": "127.0.0.1:" + str(local), "target": {"host": host, "port": target}, "outbound": "proxy"} for tag, network, local, host, target in rules],
            "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 8000, "drain_timeout_ms": 400, "max_sessions": 128},
        }
        config = directory / "client.json"
        h.write_json(config, client)
        with h.process([args.kerlico, "run", "-c", str(config)], directory, "client") as child:
            h.wait_ready(child, rules[0][2])
            payload = bytes(range(256)) * 512
            for rule in rules[:3]:
                if echo(rule[2], payload) != payload:
                    raise RuntimeError(rule[0] + " TCP 回写不一致")
                checks.append(rule[0] + " 131072 字节")
            if echo(rules[3][2], b"after-server-greeting", b"server-first") != b"after-server-greeting":
                raise RuntimeError("目标先发后回写不一致")
            checks.append("目标先发")
            udp_error = None
            for rule in rules[4:]:
                try:
                    snell.udp_sequence(rule[2], [17, 512, 1000])
                    checks.append(rule[0] + " 17/512/1000 字节")
                except (OSError, RuntimeError) as error:
                    udp_error = rule[0] + " 无回包：" + type(error).__name__
        bad = dict(client)
        bad["outbounds"] = [{"tag": "proxy", "type": "snell", "options": {"server": {"host": "127.0.0.1", "port": port}, "version": wire, "psk": PSK + "-wrong", **extra}}]
        config = directory / "client-wrong.json"
        h.write_json(config, bad)
        with h.process([args.kerlico, "run", "-c", str(config)], directory, "client-wrong") as child:
            h.wait_ready(child, rules[0][2])
            try:
                echoed = echo(rules[0][2], b"must-not-pass")
            except (OSError, RuntimeError):
                echoed = b""
            if echoed:
                raise RuntimeError("错误 PSK 收到了回写")
            checks.append("错误 PSK 无回写")
    if udp_error:
        raise RuntimeError(udp_error)
    return label


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--server-root", required=True, type=Path, help="含 <版本>/snell-server 的目录")
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    args.kerlico = str(Path(args.kerlico).resolve())
    args.server_root = args.server_root.resolve()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    digests = {version: hashlib.sha256((args.server_root / version / "snell-server").read_bytes()).hexdigest() for version in sorted({row[0] for row in CASES})}
    h.write_json(root / "reference.json", digests)
    failed = False
    for server_version, wire, extra, obfs in CASES:
        name = f"{server_version}-wire{wire}-{obfs}"
        checks = []
        try:
            label = check_case(args, root, server_version, wire, extra, obfs, checks)
            print(json.dumps({"case": label, "ok": True, "checks": checks}, ensure_ascii=False), flush=True)
        except (OSError, RuntimeError, socket.timeout) as error:
            failed = True
            print(json.dumps({"case": name, "ok": False, "reason": type(error).__name__ + ": " + str(error), "passed_checks": checks}, ensure_ascii=False), flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
