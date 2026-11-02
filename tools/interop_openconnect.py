#!/usr/bin/env python3
"""在 worker 上用容器内真实 ocserv 验证 OpenConnect 出站：经本机 SOCKS5 收发 TCP 与 UDP。

路径：SOCKS5 -> kerlico -> TLS/CSTP -> ocserv -> tun -> 容器内 NAT -> Docker 网关上的回显服务。
回显服务记录的来源必须是 ocserv 容器地址，以此确认流量没有绕过隧道。
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time

import interop_vless as h

CONTAINER = "kerlico-agent-openconnect-ocserv"
USERNAME = "synthetic-user"
PASSWORD = "synthetic-oc-pass"
SERVER_NAME = "vpn.test.invalid"
VPN_NETWORK = "192.168.77.0/24"
DPD_SECONDS = 5
IDLE_HOLD_SECONDS = 60
OCSERV_CONFIG = f"""\
auth = "plain[passwd=/cfg/passwd]"
tcp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /run/ocserv-socket
server-cert = /cfg/server.pem
server-key = /cfg/server.key
isolate-workers = false
max-clients = 16
max-same-clients = 8
keepalive = 3
dpd = 5
mobile-dpd = 5
try-mtu-discovery = false
auth-timeout = 240
cookie-timeout = 300
rekey-time = 172800
rekey-method = ssl
use-occtl = false
pid-file = /run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = {VPN_NETWORK}
ipv6-network = fd77:77::/48
ipv6-subnet-prefix = 64
route = default
ping-leases = false
cisco-client-compat = false
"""
PEER_SOURCES = []


class RawEcho(h.TcpEcho):
    def handle(self):
        PEER_SOURCES.append(self.client_address[0])
        self.request.settimeout(20)
        data = bytearray()
        while chunk := self.request.recv(65536):
            data.extend(chunk)
        self.request.sendall(data)


def run(*command, **options):
    return subprocess.run(command, check=True, capture_output=True, timeout=120, **options).stdout.decode()


def create_material(root):
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem"), "-days", "2", "-subj", "/CN=synthetic-ca", "-addext", "basicConstraints=critical,CA:TRUE")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"), "-subj", "/CN=" + SERVER_NAME)
    (root / "ext").write_text(f"subjectAltName=DNS:{SERVER_NAME}\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    run("openssl", "x509", "-req", "-in", str(root / "server.csr"), "-CA", str(root / "ca.pem"), "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-days", "2", "-out", str(root / "server.pem"), "-extfile", str(root / "ext"))
    digest = run("openssl", "passwd", "-5", "-stdin", input=PASSWORD.encode()).strip()
    (root / "passwd").write_text(f"{USERNAME}:*:{digest}\n")
    (root / "ocserv.conf").write_text(OCSERV_CONFIG)
    os.chmod(root, 0o755)
    for name in ["server.key", "server.pem", "passwd", "ocserv.conf"]:
        os.chmod(root / name, 0o644)


def start_ocserv(root, image):
    setup = (
        "apt-get update -qq >/dev/null 2>&1; "
        "apt-get install -y -qq --no-install-recommends ocserv iptables >/dev/null 2>&1; "
        f"iptables -t nat -A POSTROUTING -s {VPN_NETWORK} -o eth0 -j MASQUERADE; "
        "exec ocserv -f -d 2 -c /cfg/ocserv.conf"
    )
    run("docker", "run", "-d", "--name", CONTAINER, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1", "--mount", f"type=bind,src={root},dst=/cfg,readonly", image, "sh", "-c", setup)
    address = run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", CONTAINER).strip()
    gateway = run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", CONTAINER).strip()
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        try:
            socket.create_connection((address, 443), timeout=1).close()
            return address, gateway
        except OSError:
            time.sleep(1)
    raise RuntimeError("ocserv 未在预算内就绪")


def container_log():
    return subprocess.run(["docker", "logs", CONTAINER], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30).stdout.decode(errors="replace")


def logins():
    return container_log().count("user logged in")


def socks_greet(port):
    stream = socket.create_connection(("127.0.0.1", port), timeout=20)
    stream.sendall(b"\x05\x01\x00")
    if read_exact(stream, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 协商失败")
    return stream


def read_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise RuntimeError("SOCKS5 连接提前关闭")
        data.extend(chunk)
    return bytes(data)


def socks_request(stream, command, host, number):
    stream.sendall(b"\x05" + bytes([command]) + b"\x00\x01" + socket.inet_aton(host) + struct.pack("!H", number))
    head = read_exact(stream, 4)
    if head[3] != 1:
        raise RuntimeError(f"SOCKS5 回复类型 {head[3]}")
    bound = read_exact(stream, 6)
    return head[1], socket.inet_ntoa(bound[:4]), struct.unpack("!H", bound[4:])[0]


def tcp_round_trip(port, host, number, payload):
    with socks_greet(port) as stream:
        status, _, _ = socks_request(stream, 1, host, number)
        if status:
            raise RuntimeError(f"SOCKS5 CONNECT 状态 {status}")
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        data = bytearray()
        while chunk := stream.recv(65536):
            data.extend(chunk)
        return bytes(data)


def udp_round_trip(port, host, number, payloads):
    with socks_greet(port) as control:
        status, relay_host, relay_port = socks_request(control, 3, "0.0.0.0", 0)
        if status:
            raise RuntimeError(f"SOCKS5 UDP 状态 {status}")
        prefix = b"\0\0\0\x01" + socket.inet_aton(host) + struct.pack("!H", number)
        replies = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            for payload in payloads:
                sock.sendto(prefix + payload, (relay_host, relay_port))
                reply, _ = sock.recvfrom(65535)
                replies.append(reply[len(prefix):])
        return replies


def tcp_refused(port, host, number):
    with socks_greet(port) as stream:
        return socks_request(stream, 1, host, number)[0] != 0


def outbound(tag, address, password, ca_pem):
    return {
        "tag": tag,
        "type": "openconnect",
        "options": {
            "server": {"host": address, "port": 443},
            "username": USERNAME,
            "password": password,
            "tls": {"server_name": SERVER_NAME, "ca_pem": ca_pem},
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--image", default="debian:bookworm-slim")
    args = parser.parse_args()
    binary = str(Path(args.kerlico).resolve())
    records = {}
    with tempfile.TemporaryDirectory(prefix="oc-interop-") as directory, ExitStack() as stack:
        root = Path(directory)
        create_material(root)
        subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True, timeout=30)
        stack.callback(subprocess.run, ["docker", "rm", "-f", CONTAINER], capture_output=True, timeout=30)
        address, gateway = start_ocserv(root, args.image)
        tcp_target = stack.enter_context(h.serve(h.TcpServer((gateway, 0), RawEcho)))
        udp_target = stack.enter_context(h.serve(h.UdpServer((gateway, 0), h.UdpEcho)))
        good, bad = h.free_port(), h.free_port()
        ca_pem = (root / "ca.pem").read_text()
        config = {
            "version": 2,
            "outbounds": [outbound("proxy", address, PASSWORD, ca_pem), outbound("denied", address, "wrong-" + PASSWORD, ca_pem)],
            "local_inbounds": [
                {"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{good}", "outbound": "proxy", "options": {}},
                {"tag": "socks-denied", "type": "socks", "listen": f"127.0.0.1:{bad}", "outbound": "denied", "options": {}},
            ],
        }
        path = root / "kerlico.json"
        path.write_text(json.dumps(config))
        with h.process([binary, "run", "-c", str(path)], root, "kerlico") as child:
            h.wait_ready(child, good)
            payload = os.urandom(1 << 20)
            records["tcp_1mib_half_close"] = tcp_round_trip(good, gateway, tcp_target, payload) == payload
            records["tcp_source_is_ocserv_nat"] = PEER_SOURCES == [address]
            datagrams = [os.urandom(1000), os.urandom(4000)]
            records["udp_1000_and_fragmented_4000"] = udp_round_trip(good, gateway, udp_target, datagrams) == datagrams
            records["wrong_password_refused"] = tcp_refused(bad, gateway, tcp_target)
            records["one_login_after_traffic"] = logins() == 1
            # dpd=5 时 ocserv 约 50 秒断开不发任何帧的客户端（reason: DPD timeout）；闲置超过它仍是同一次登录才说明保活有效。
            time.sleep(IDLE_HOLD_SECONDS)
            payload = os.urandom(1 << 16)
            records["tcp_after_idle_hold"] = tcp_round_trip(good, gateway, tcp_target, payload) == payload
            records["same_login_after_idle_hold"] = logins() == 1
            run("docker", "pause", CONTAINER)
            time.sleep(2 * DPD_SECONDS + 3)
            run("docker", "unpause", CONTAINER)
            records["tcp_after_dead_peer"] = tcp_round_trip(good, gateway, tcp_target, payload) == payload
            records["new_login_after_dead_peer"] = logins() == 2
            child.terminate()
            records["clean_exit"] = child.wait(timeout=10) == 0
        time.sleep(1)
        peer_log = container_log()
        records["ocserv_honored_disconnect_frame"] = "reason: user disconnected" in peer_log
        print(json.dumps(records, ensure_ascii=False, indent=1))
        print("\n".join(line for line in peer_log.splitlines() if "logged in" in line or "disconnected" in line or "BYE" in line)[-3000:])
        print("\n--- kerlico\n" + (root / "kerlico.log").read_text(errors="replace")[-2000:])
    if not all(records.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
