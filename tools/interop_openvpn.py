#!/usr/bin/env python3
"""在 worker 容器内运行官方 OpenVPN 服务端，经 kerlico SOCKS5 入站与 OpenVPN 出站收发真实 TCP/UDP。"""
import argparse
import ipaddress
import threading
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import uuid

import interop_vless as h

ECHO_PORT = 7000
SERVER_V4 = "10.8.0.1"
SERVER_V6 = "fd42:8::1"
USERNAME = "vpn-user"
PASSWORD = "synthetic-vpn-password"
IMAGES = {"current": "alpine:3.21", "legacy": "alpine:3.12"}

ECHO_SERVER = f"""
import socket, socketserver, threading
class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)
class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request[1].sendto(self.request[0], self.client_address)
class Tcp4(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
class Udp4(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
class V6Only:
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()
class Tcp6(V6Only, Tcp4):
    pass
class Udp6(V6Only, Udp4):
    pass
servers = [Tcp4(("0.0.0.0", {ECHO_PORT}), Tcp), Udp4(("0.0.0.0", {ECHO_PORT}), Udp), Tcp6(("::", {ECHO_PORT}), Tcp), Udp6(("::", {ECHO_PORT}), Udp)]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
"""

# 每个用例验证一项对外声明的能力；server 为追加的服务端配置行。
CASES = [
    {"name": "udp-tls-crypt-aes256-certificate", "proto": "udp", "wrap": "crypt", "cipher": "AES-256-GCM", "auth": "certificate", "ipv6": True, "server": ["keepalive 2 10"], "restart": True},
    {"name": "tcp-tls-auth-aes128-certificate-and-password", "proto": "tcp", "wrap": "auth", "cipher": "AES-128-GCM", "auth": "both"},
    {"name": "udp-plain-chacha-password-only", "proto": "udp", "wrap": None, "cipher": "CHACHA20-POLY1305", "auth": "password"},
    {"name": "udp-tls-crypt-v2-certificate", "proto": "udp", "wrap": "crypt-v2", "cipher": "AES-256-GCM", "auth": "certificate"},
    {"name": "legacy-2.4-prf-key-derivation", "image": "legacy", "proto": "udp", "wrap": "crypt", "cipher": "AES-256-GCM", "auth": "certificate"},
    {"name": "server-initiated-rekey", "proto": "udp", "wrap": "crypt", "cipher": "AES-256-GCM", "auth": "certificate", "server": ["keepalive 2 10", "reneg-sec 8", "tran-window 4"], "rekey": True},
    {"name": "client-initiated-rekey", "proto": "tcp", "wrap": "crypt", "cipher": "AES-256-GCM", "auth": "certificate", "server": ["keepalive 2 10", "reneg-sec 0", "tran-window 4"],"client": {"reneg_secs": 8}, "rekey": True},
    {"name": "wrong-password-is-rejected", "proto": "udp", "wrap": None, "cipher": "AES-256-GCM", "auth": "password", "client": {"password": "wrong"}, "refused": True},
    {"name": "untrusted-server-certificate-is-rejected", "proto": "udp", "wrap": None, "cipher": "AES-256-GCM", "auth": "certificate", "untrusted": True, "refused": True},
    {"name": "wrong-x509-name-is-rejected", "proto": "udp", "wrap": None, "cipher": "AES-256-GCM", "auth": "certificate", "client": {"verify_x509_name": "other"}, "refused": True},
    {"name": "server-auth-certificate-without-name-check", "proto": "udp", "wrap": None, "cipher": "AES-256-GCM", "auth": "certificate", "client": {"verify_x509_name": None}},
    {"name": "certificate-without-eku-is-rejected", "proto": "udp", "wrap": None, "cipher": "AES-256-GCM", "auth": "certificate", "client": {"verify_x509_name": None}, "server_cert": "server-no-eku", "refused": True},
]


def run(command, log, stdin=None):
    with log.open("ab") as output:
        subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, input=stdin, timeout=600, check=True)


def create_pki(root):
    def certificate(name, issuer, usage):
        run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", root / f"{name}.key", "-out", root / f"{name}.csr", "-subj", f"/CN={name}"], root / "pki.log")
        extensions = root / f"{name}.ext"
        extensions.write_text(usage + "\n")
        run(["openssl", "x509", "-req", "-in", root / f"{name}.csr", "-CA", root / f"{issuer}.crt", "-CAkey", root / f"{issuer}.key", "-CAcreateserial", "-days", "30", "-extfile", extensions, "-out", root / f"{name}.crt"], root / "pki.log")

    for authority in ["ca", "other-ca"]:
        run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", root / f"{authority}.key", "-out", root / f"{authority}.crt", "-subj", f"/CN={authority}", "-days", "30"], root / "pki.log")
    certificate("server", "ca", "extendedKeyUsage=serverAuth")
    certificate("server-no-eku", "ca", "basicConstraints=CA:FALSE")
    certificate("client", "ca", "extendedKeyUsage=clientAuth")
    lines = [os.urandom(16).hex() for _ in range(16)]
    (root / "static.key").write_text("-----BEGIN OpenVPN Static key V1-----\n" + "\n".join(lines) + "\n-----END OpenVPN Static key V1-----\n")
    check = root / "check.sh"
    check.write_text(f'#!/bin/sh\n[ "$username" = "{USERNAME}" ] && [ "$password" = "{PASSWORD}" ]\n')
    check.chmod(0o700)
    (root / "echo.py").write_text(ECHO_SERVER)
    (root / "start.sh").write_text("#!/bin/sh\npython3 /keys/echo.py &\nwhile true; do openvpn --config /keys/$CASE.conf; sleep 0.2; done\n")


def build_image(root, label):
    tag = f"kerlico-agent-openvpn-peer:{label}"
    dockerfile = f"FROM {IMAGES[label]}\nRUN apk add --no-cache openvpn python3\n".encode()
    run(["docker", "build", "-t", tag, "-"], root / "image.log", stdin=dockerfile)
    return tag


def server_config(case, label):
    certificate = case.get("server_cert", "server")
    lines = [
        "dev tun", "topology subnet", "server 10.8.0.0 255.255.255.0", "port 1194",
        "proto tcp-server" if case["proto"] == "tcp" else "proto udp",
        "ca /keys/ca.crt", f"cert /keys/{certificate}.crt", f"key /keys/{certificate}.key", "dh none", "verb 4",
    ]
    if label == "legacy":
        lines += [f"ncp-ciphers {case['cipher']}", f"cipher {case['cipher']}"]
    else:
        lines.append(f"data-ciphers {case['cipher']}")
    if case.get("ipv6"):
        lines.append("server-ipv6 fd42:8::/64")
    if case["wrap"] == "crypt":
        lines.append("tls-crypt /keys/static.key")
    elif case["wrap"] == "crypt-v2":
        lines.append("tls-crypt-v2 /keys/v2-server.key")
    elif case["wrap"] == "auth":
        lines.append("tls-auth /keys/static.key 0")
    if case["auth"] in ["password", "both"]:
        lines += ["script-security 3", "auth-user-pass-verify /keys/check.sh via-env"]
    if case["auth"] == "password":
        lines.append("verify-client-cert none")
    lines += case.get("server", ["keepalive 10 60"])
    return "\n".join(lines) + "\n"


def client_options(case, root, address):
    options = {
        "remote": {"host": address, "port": 1194},
        "proto": case["proto"],
        "ca_pem": (root / ("other-ca.crt" if case.get("untrusted") else "ca.crt")).read_text(),
        "ciphers": [case["cipher"]],
    }
    if case["auth"] in ["certificate", "both"]:
        options.update(cert_pem=(root / "client.crt").read_text(), key_pem=(root / "client.key").read_text())
    if case["auth"] in ["password", "both"]:
        options.update(username=USERNAME, password=PASSWORD)
    key = (root / "static.key").read_text()
    if case["wrap"] == "crypt":
        options["tls_crypt_key"] = key
    elif case["wrap"] == "crypt-v2":
        options["tls_crypt_v2"] = (root / "v2-client.key").read_text()
    elif case["wrap"] == "auth":
        options["tls_auth"] = {"key": key, "direction": 1}
    options["verify_x509_name"] = "server"
    options.update(case.get("client", {}))
    return options


def socks_handshake(sock):
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 协商失败")


def socks_address(host, port):
    address = ipaddress.ip_address(host)
    return (b"\x01" if address.version == 4 else b"\x04") + address.packed + struct.pack(">H", port)


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("SOCKS5 对端提前关闭")
        data.extend(chunk)
    return bytes(data)


def socks_reply(sock):
    head = receive_exact(sock, 4)
    if head[1] != 0:
        raise ConnectionRefusedError(f"SOCKS5 回复 {head[1]}")
    size = {1: 4, 4: 16}[head[3]]
    address = receive_exact(sock, size)
    port = struct.unpack(">H", receive_exact(sock, 2))[0]
    return str(ipaddress.ip_address(address)), port


def open_stream(socks_port, host, timeout=12):
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    sock.settimeout(timeout)
    socks_handshake(sock)
    sock.sendall(b"\x05\x01\x00" + socks_address(host, ECHO_PORT))
    socks_reply(sock)
    return sock


def echo_on_stream(sock, payload):
    sock.sendall(payload)
    return receive_exact(sock, len(payload)) == payload


def tcp_round_trip(socks_port, host, payload):
    with open_stream(socks_port, host) as sock:
        sender = threading.Thread(target=lambda: (sock.sendall(payload), sock.shutdown(socket.SHUT_WR)))
        sender.start()
        received = bytearray()
        while chunk := sock.recv(65536):
            received.extend(chunk)
        sender.join()
    return bytes(received) == payload


def udp_round_trip(socks_port, host, payload, timeout=5):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as control:
        control.settimeout(timeout)
        socks_handshake(control)
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        relay = socks_reply(control)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            header = b"\x00\x00\x00" + socks_address(host, ECHO_PORT)
            sock.sendto(header + payload, relay)
            reply = sock.recv(65535)
    return reply[len(header):] == payload


def wait_for_tunnel(socks_port, host, budget):
    deadline = time.monotonic() + budget
    error = None
    while time.monotonic() < deadline:
        try:
            with open_stream(socks_port, host, timeout=8) as sock:
                if echo_on_stream(sock, b"ready"):
                    return True
        except (OSError, EOFError, RuntimeError) as failure:
            error = failure
        time.sleep(0.25)
    raise TimeoutError(f"隧道未就绪：{type(error).__name__}")


def exercise(case, socks_port, container):
    checks = {}
    wait_for_tunnel(socks_port, SERVER_V4, 20)
    payload = os.urandom(1024 * 1024)
    checks["tcp-1MiB-with-half-close"] = tcp_round_trip(socks_port, SERVER_V4, payload)
    checks["udp-1200"] = udp_round_trip(socks_port, SERVER_V4, os.urandom(1200))
    checks["udp-4000-fragmented"] = udp_round_trip(socks_port, SERVER_V4, os.urandom(4000))
    if case.get("ipv6"):
        checks["tcp-ipv6-inner"] = tcp_round_trip(socks_port, SERVER_V6, os.urandom(65536))
        checks["udp-ipv6-inner"] = udp_round_trip(socks_port, SERVER_V6, os.urandom(1200))
    if case.get("rekey"):
        with open_stream(socks_port, SERVER_V4, timeout=30) as stream:
            for index in range(3):
                checks[f"same-stream-round-{index}"] = echo_on_stream(stream, os.urandom(32768))
                time.sleep(11)
            logs = subprocess.run(["docker", "logs", container], capture_output=True, timeout=20).stdout
            checks["server-completed-soft-reset"] = logs.count(b"Outgoing Data Channel: Cipher") >= 2
            checks["udp-after-rekey"] = udp_round_trip(socks_port, SERVER_V4, os.urandom(1200))
    if case.get("restart"):
        subprocess.run(["docker", "exec", container, "pkill", "openvpn"], capture_output=True, timeout=20, check=True)
        checks["reconnect-after-server-restart"] = wait_for_tunnel(socks_port, SERVER_V4, 45)
        checks["tcp-after-reconnect"] = tcp_round_trip(socks_port, SERVER_V4, os.urandom(65536))
        checks["udp-after-reconnect"] = udp_round_trip(socks_port, SERVER_V4, os.urandom(1200))
    return checks


def expect_refused(socks_port):
    try:
        with open_stream(socks_port, SERVER_V4, timeout=12) as sock:
            return not echo_on_stream(sock, b"must-not-pass")
    except (OSError, EOFError):
        return True


def run_case(case, root, image):
    label = case.get("image", "current")
    (root / f"{case['name']}.conf").write_text(server_config(case, label))
    container = "kerlico-agent-openvpn-" + uuid.uuid4().hex[:12]
    subprocess.run([
        "docker", "run", "-d", "--name", container, "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "-e", f"CASE={case['name']}",
        "--mount", f"type=bind,src={root},dst=/keys,readonly", image, "sh", "/keys/start.sh",
    ], capture_output=True, timeout=60, check=True)
    try:
        address = subprocess.check_output(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container], timeout=20).decode().strip()
        socks_port = h.free_port()
        config = {
            "version": 2,
            "outbounds": [{"tag": "vpn", "type": "openvpn", "options": client_options(case, root, address)}],
            "inbounds": [],
            "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{socks_port}", "outbound": "vpn", "options": {"version": "5"}}],
            "limits": {"connect_timeout_ms": 8000, "idle_timeout_ms": 60000, "drain_timeout_ms": 500, "max_sessions": 64},
        }
        path = root / f"{case['name']}.json"
        h.write_json(path, config)
        with h.process([args.kerlico, "run", "-c", str(path)], root, case["name"] + ".kerlico") as child:
            h.wait_ready(child, socks_port)
            time.sleep(0.5)
            if case.get("refused"):
                checks = {"refused": expect_refused(socks_port)}
            else:
                checks = exercise(case, socks_port, container)
            child.terminate()
            code = child.wait(timeout=5)
            # 已失败的命名出站在关闭时报告非零退出码，与 WireGuard 出站一致。
            if not case.get("refused"):
                checks["clean-shutdown"] = code == 0
        return checks
    finally:
        with (root / f"{case['name']}.server.log").open("wb") as log:
            subprocess.run(["docker", "logs", container], stdout=log, stderr=subprocess.STDOUT, timeout=20)
        subprocess.run(["docker", "rm", "--force", container], capture_output=True, timeout=30)


def main():
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    create_pki(root)
    images = {label: build_image(root, label) for label in IMAGES}
    # 客户端 tls-crypt-v2 密钥由官方 openvpn 生成，检验 kerlico 按上游格式读取 WKc。
    run(["docker", "run", "--rm", "--mount", f"type=bind,src={root},dst=/keys", images["current"], "sh", "-c",
         "cd /keys && openvpn --genkey tls-crypt-v2-server v2-server.key && openvpn --tls-crypt-v2 v2-server.key --genkey tls-crypt-v2-client v2-client.key && chmod 644 v2-*.key"],
        root / "pki.log")
    versions = {label: subprocess.check_output(["docker", "run", "--rm", tag, "sh", "-c", "openvpn --version | head -1 || true"], timeout=60).decode().strip() for label, tag in images.items()}
    results = {}
    for case in CASES:
        if args.case and case["name"] not in args.case:
            continue
        try:
            results[case["name"]] = run_case(case, root, images[case.get("image", "current")])
        except Exception as error:
            results[case["name"]] = {"error": f"{type(error).__name__}: {error}"}
    failed = [name for name, checks in results.items() if "error" in checks or not all(checks.values())]
    summary = {"reference": versions, "results": results, "failed": failed}
    h.write_json(root / "result.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=1), flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OpenVPN 出站与容器内官方服务端互通，仅在 worker 运行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--case", action="append", help="只运行指定用例，可重复")
    args = parser.parse_args()
    main()
