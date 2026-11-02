#!/usr/bin/env python3
"""kerlico MASQUE 出站经 HTTP/3 CONNECT-IP 连接真实 Xray 服务端，验证 TCP 与 UDP 回写。

业务路径：SOCKS5 -> kerlico run -> Xray masque 入站 -> Xray freedom -> 回环 echo。
Xray 的 gVisor 栈丢弃回环源/目标的 IP 包，因此隧道内目标用文档地址，由 Xray 的
freedom redirect 转到本机 echo，不依赖公网。
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess

import interop_vless as h

TARGET_V4 = "192.0.2.5"
TARGET_V6 = "2001:db8::5"
SERVER_NAME = "masque.example.invalid"
USER = "interop-member"
PASSWORD = "synthetic-masque-secret"
XRAY_COMMIT = "0afec66"


class UdpServer6(h.UdpServer):
    address_family = socket.AF_INET6


def bind_echo(stack, tcp_server, udp_server, host):
    return (
        stack.enter_context(h.serve(tcp_server((host, 0), h.TcpEcho))),
        stack.enter_context(h.serve(udp_server((host, 0), h.UdpEcho))),
    )


def certificate(work):
    cert, key = work / "certificate.pem", work / "key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=" + SERVER_NAME,
         "-addext", "subjectAltName=DNS:" + SERVER_NAME, "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"],
        check=True, capture_output=True, timeout=30)
    return cert, key


def xray_config(port, cert, key, targets):
    outbounds, rules = [], []
    for index, (network, virtual, actual_host, actual_port) in enumerate(targets):
        tag = "echo-" + str(index)
        redirect = ("[" + actual_host + "]" if ":" in actual_host else actual_host) + ":" + str(actual_port)
        outbounds.append({"tag": tag, "protocol": "freedom", "settings": {"redirect": redirect}})
        rules.append({"type": "field", "ip": [virtual], "port": str(actual_port), "network": network, "outboundTag": tag})
    outbounds.append({"tag": "blocked", "protocol": "blackhole"})
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "blocked"})
    return {
        "log": {"loglevel": "info"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "masque",
            "settings": {"users": [{"email": USER, "pass": PASSWORD}],
                         "address": ["10.89.0.1/24", "fd89::1/120"], "mtu": 1280},
            "streamSettings": {
                "network": "masque", "security": "tls",
                "tlsSettings": {"serverName": SERVER_NAME, "alpn": ["h3"],
                                "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]},
                "masqueSettings": {"host": SERVER_NAME, "path": "/"},
            },
        }],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


def kerlico_config(port, socks_port, cert):
    return {
        "version": 2,
        "limits": {"connect_timeout_ms": 8000, "idle_timeout_ms": 20000, "drain_timeout_ms": 1000},
        "outbounds": [{"tag": "proxy", "type": "masque", "options": {
            "server": {"host": "127.0.0.1", "port": port},
            "auth": {"username": USER, "password": PASSWORD},
            "tls": {"server_name": SERVER_NAME, "ca_pem": cert.read_text()},
        }}],
        "local_inbounds": [{"tag": "socks", "type": "socks", "listen": "127.0.0.1:" + str(socks_port),
                            "outbound": "proxy", "options": {"version": "5"}}],
    }


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise RuntimeError("连接提前结束，已收 " + str(len(data)) + " 字节")
        data.extend(part)
    return bytes(data)


def socks_address(host, port):
    if ":" in host:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
    return b"\x01" + socket.inet_pton(socket.AF_INET, host) + struct.pack("!H", port)


def socks_open(port, command, host, target_port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=20)
    sock.settimeout(20)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS 协商失败")
    sock.sendall(b"\x05" + bytes([command, 0]) + socks_address(host, target_port))
    reply = recv_exact(sock, 4)
    if reply[1] != 0:
        raise RuntimeError("SOCKS 请求被拒绝，REP=" + str(reply[1]))
    bound = recv_exact(sock, {1: 4, 4: 16}[reply[3]] + 2)
    return sock, bound


def tcp_round_trip(socks_port, host, port, payload):
    sock, _ = socks_open(socks_port, 1, host, port)
    with sock:
        sock.sendall(struct.pack("!I", len(payload)) + payload)
        if recv_exact(sock, len(payload)) != payload:
            raise RuntimeError("TCP 回写内容不一致：" + host)


def udp_round_trip(socks_port, targets, payload):
    control, bound = socks_open(socks_port, 3, "0.0.0.0", 0)
    relay_port = struct.unpack("!H", bound[-2:])[0]
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(20)
        for host, port in targets:
            header = b"\x00\x00\x00" + socks_address(host, port)
            sock.sendto(header + payload, ("127.0.0.1", relay_port))
            reply = sock.recv(65535)
            if reply != header + payload:
                raise RuntimeError("UDP 回写内容或来源不一致：" + host)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--xray", required=True, help="固定提交 " + XRAY_COMMIT + " 的 Xray 二进制")
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    version = subprocess.check_output([args.xray, "version"], text=True, timeout=10).splitlines()[0]
    if XRAY_COMMIT not in version:
        raise SystemExit("Xray 版本不是固定提交：" + version)
    cert, key = certificate(work)
    port, socks_port = h.free_port(), h.free_port()
    with ExitStack() as stack:
        tcp4, udp4 = bind_echo(stack, h.TcpServer, h.UdpServer, "127.0.0.1")
        tcp6, udp6 = bind_echo(stack, h.TcpServer6, UdpServer6, "::1")
        targets = [("tcp", TARGET_V4 + "/32", "127.0.0.1", tcp4), ("udp", TARGET_V4 + "/32", "127.0.0.1", udp4),
                   ("tcp", TARGET_V6 + "/128", "::1", tcp6), ("udp", TARGET_V6 + "/128", "::1", udp6)]
        h.write_json(work / "xray.json", xray_config(port, cert, key, targets))
        h.write_json(work / "kerlico.json", kerlico_config(port, socks_port, cert))
        xray = stack.enter_context(h.process([args.xray, "run", "-config", str(work / "xray.json")], work, "xray"))
        kerlico = stack.enter_context(h.process([args.kerlico, "run", "-c", str(work / "kerlico.json")], work, "kerlico"))
        h.wait_ready(kerlico, socks_port)
        if xray.poll() is not None:
            raise RuntimeError("Xray 启动后退出")
        checks = []
        for name, host, tcp_port in (("IPv4", TARGET_V4, tcp4), ("IPv6", TARGET_V6, tcp6)):
            for size in (1, 1300, 256 * 1024):
                tcp_round_trip(socks_port, host, tcp_port, bytes(n % 251 for n in range(size)))
            checks.append(name + " TCP 1/1300/262144 字节")
        for size in (17, 1200, 4000):
            udp_round_trip(socks_port, ((TARGET_V4, udp4), (TARGET_V6, udp6)), bytes([size % 251]) * size)
            checks.append("同一关联 IPv4+IPv6 UDP " + str(size) + " 字节")
    result = {"ok": True, "peer": version, "checks": checks,
              "kerlico_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest()}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
