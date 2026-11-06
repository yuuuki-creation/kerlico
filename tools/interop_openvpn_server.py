#!/usr/bin/env python3
"""在 worker 上让官方 OpenVPN 客户端（容器）连接 kerlico OpenVPN 服务端入站，验证认证、推送地址与真实收发。

kerlico 监听 Docker 默认网桥的网关地址。服务端把回显容器的地址作为 /32 路由推送给客户端，
客户端经隧道访问回显容器；回显服务回报看到的源地址，等于网桥网关时说明流量确实经 kerlico 转出。
"""
import argparse
import json
import os
import re
import socket
import subprocess
import time
import uuid
from pathlib import Path

import interop_vless as h
from config_v2 import bind_members

ECHO_TCP = 7000
ECHO_UDP = 7001
USERNAME = "vpn-user"
PASSWORD = "synthetic-vpn-password"
IMAGES = {"current": "alpine:3.21", "legacy": "alpine:3.12"}
PREFIX = "kerlico-agent-ovpnsrv-"

ECHO_SERVER = f"""
import socket, socketserver, threading
class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(("peer=" + self.client_address[0] + "\\n").encode())
        while data := self.request.recv(65536):
            self.request.sendall(data)
class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request[1].sendto(("peer=" + self.client_address[0] + ";").encode() + self.request[0], self.client_address)
class TcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
servers = [TcpServer(("0.0.0.0", {ECHO_TCP}), Tcp), socketserver.ThreadingUDPServer(("0.0.0.0", {ECHO_UDP}), Udp)]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
"""

# 在客户端容器内运行：经隧道访问回显服务，打印一行 JSON。
PROBE = f"""
import json, os, socket, sys
host = sys.argv[1]
result = {{}}
payload = os.urandom(262144)
with socket.create_connection((host, {ECHO_TCP}), timeout=10) as sock:
    sock.settimeout(10)
    line = b""
    while not line.endswith(b"\\n"):
        line += sock.recv(1)
    result["tcp_peer"] = line.decode().strip().split("=", 1)[-1]
    sock.sendall(payload)
    received = bytearray()
    while len(received) < len(payload):
        chunk = sock.recv(65536)
        if not chunk:
            break
        received.extend(chunk)
    result["tcp_echo"] = bytes(received) == payload
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    datagram = os.urandom(1200)
    sock.sendto(datagram, (host, {ECHO_UDP}))
    reply = sock.recv(65535)
    head, _, body = reply.partition(b";")
    result["udp_peer"] = head.decode().split("=", 1)[-1]
    result["udp_echo"] = body == datagram
print(json.dumps(result))
"""

# 每个用例声明服务端选项、客户端配置与期望。
CASES = [
    {"name": "udp-tls-crypt-certificate", "proto": "udp", "wrap": "tls-crypt", "auth": "certificate"},
    {"name": "tcp-password-only", "proto": "tcp", "wrap": None, "auth": "password"},
    {"name": "udp-tls-crypt-v2-certificate-and-password", "proto": "udp", "wrap": "tls-crypt-v2", "auth": "both"},
    {"name": "udp-ncp-picks-server-order", "proto": "udp", "wrap": None, "auth": "certificate",
     "server": {"data_ciphers": ["CHACHA20-POLY1305", "AES-256-GCM"]}, "expect_cipher": "CHACHA20-POLY1305"},
    {"name": "legacy-2.4-client-prf-keys", "image": "legacy", "proto": "udp", "wrap": "tls-crypt", "auth": "certificate"},
    {"name": "client-initiated-rekey", "proto": "udp", "wrap": "tls-crypt", "auth": "certificate", "client": ["reneg-sec 8"], "rekey": True},
    {"name": "two-clients-get-distinct-addresses", "proto": "udp", "wrap": "tls-crypt", "auth": "certificate", "second": "client2"},
    {"name": "max-clients-1-released-on-exit", "proto": "udp", "wrap": "tls-crypt", "auth": "certificate",
     "server": {"max_clients": 1}, "second": "client2", "release": True},
    {"name": "untrusted-client-certificate-is-refused", "proto": "udp", "wrap": "tls-crypt", "auth": "certificate", "cert": "stranger", "refused": True},
    {"name": "wrong-password-is-refused", "proto": "tcp", "wrap": None, "auth": "password", "password": "wrong", "refused": True},
]


def run(command, log, stdin=None):
    with log.open("ab") as output:
        subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, input=stdin, timeout=600, check=True)


def create_pki(root):
    def certificate(name, issuer, extensions):
        run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", root / f"{name}.key", "-out", root / f"{name}.csr", "-subj", f"/CN={name}"], root / "pki.log")
        path = root / f"{name}.ext"
        path.write_text(extensions + "\n")
        run(["openssl", "x509", "-req", "-in", root / f"{name}.csr", "-CA", root / f"{issuer}.crt", "-CAkey", root / f"{issuer}.key", "-CAcreateserial", "-days", "30", "-extfile", path, "-out", root / f"{name}.crt"], root / "pki.log")

    for authority in ["ca", "other-ca"]:
        run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", root / f"{authority}.key", "-out", root / f"{authority}.crt", "-subj", f"/CN={authority}", "-days", "30"], root / "pki.log")
    certificate("server", "ca", "keyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
    for client in ["client", "client2"]:
        certificate(client, "ca", "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth")
    certificate("stranger", "other-ca", "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth")
    lines = [os.urandom(16).hex() for _ in range(16)]
    (root / "static.key").write_text("-----BEGIN OpenVPN Static key V1-----\n" + "\n".join(lines) + "\n-----END OpenVPN Static key V1-----\n")
    for password in [PASSWORD, "wrong"]:
        (root / f"pass-{password}.txt").write_text(f"{USERNAME}\n{password}\n")
    (root / "echo.py").write_text(ECHO_SERVER)
    (root / "probe.py").write_text(PROBE)


def build_image(root, label):
    tag = f"{PREFIX}peer:{label}"
    dockerfile = f"FROM {IMAGES[label]}\nRUN apk add --no-cache openvpn python3 iproute2\n".encode()
    run(["docker", "build", "-t", tag, "-"], root / "image.log", stdin=dockerfile)
    return tag


def generate_crypt_v2(root, image):
    """用官方 openvpn 生成 tls-crypt-v2 服务端与客户端密钥，验证 kerlico 读取上游格式。"""
    run(["docker", "run", "--rm", "--mount", f"type=bind,src={root},dst=/keys", image, "sh", "-c",
         "cd /keys && openvpn --genkey tls-crypt-v2-server v2-server.key && openvpn --tls-crypt-v2 v2-server.key --genkey tls-crypt-v2-client v2-client.key && chmod 644 v2-*.key"],
        root / "pki.log")


def container(name, image, args, command, root):
    subprocess.run(["docker", "run", "-d", "--name", name, *args, "--mount", f"type=bind,src={root},dst=/keys,readonly", image, *command],
                   capture_output=True, timeout=60, check=True)
    return subprocess.check_output(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name], timeout=20).decode().strip()


def bridge_gateway():
    return subprocess.check_output(["docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"], timeout=20).decode().strip()


def node_config(case, root, gateway, port, echo_ip):
    tls = {
        "certificate": (root / "server.crt").read_text(),
        "key": (root / "server.key").read_text(),
    }
    if case["auth"] in ["certificate", "both"]:
        tls.update(client_certificate=(root / "ca.crt").read_text(), verify_client_certificate="require")
    if case["wrap"] == "tls-crypt":
        tls["control_wrap"] = {"type": "tls_crypt", "key": (root / "static.key").read_text()}
    elif case["wrap"] == "tls-crypt-v2":
        tls["control_wrap"] = {"type": "tls_crypt_v2", "key": (root / "v2-server.key").read_text()}
    options = {
        "address": ["10.8.0.1/24"],
        "network": [case["proto"]],
        "tls": tls,
        "push": {"routes": [f"{echo_ip}/32"]},
    }
    options.update(case.get("server", {}))
    if case["auth"] == "certificate":
        members = [{"name": "client"}, {"name": "client2"}]
    elif case["auth"] == "password":
        members = [{"name": USERNAME, "password": PASSWORD}]
    else:
        members = [{"name": USERNAME, "password": PASSWORD}]
    node = {"tag": "ovpn", "type": "openvpn", "listen": f"{gateway}:{port}", "outbound": "direct", "max_sessions": 32, "options": options}
    config = {
        "version": 2,
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "inbounds": [],
        "nodes": [node],
        "limits": {"connect_timeout_ms": 8000, "idle_timeout_ms": 60000, "drain_timeout_ms": 500, "max_sessions": 64},
    }
    bind_members(config, node, members)
    return config


def client_config(case, gateway, port, cert):
    lines = [
        "client", "dev tun", "nobind", "verb 4", "connect-retry 1 2",
        "proto tcp-client" if case["proto"] == "tcp" else "proto udp",
        f"remote {gateway} {port}",
        "ca /keys/ca.crt", "remote-cert-tls server", "verify-x509-name server name",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305" if case.get("image") != "legacy" else "ncp-ciphers AES-256-GCM:AES-128-GCM",
    ]
    if case["proto"] == "udp":
        lines.append("explicit-exit-notify 1")
    if case["auth"] in ["certificate", "both"]:
        lines += [f"cert /keys/{cert}.crt", f"key /keys/{cert}.key"]
    if case["auth"] in ["password", "both"]:
        lines.append(f"auth-user-pass /keys/pass-{case.get('password', PASSWORD)}.txt")
    if case["wrap"] == "tls-crypt":
        lines.append("tls-crypt /keys/static.key")
    elif case["wrap"] == "tls-crypt-v2":
        lines.append("tls-crypt-v2 /keys/v2-client.key")
    lines += case.get("client", [])
    return "\n".join(lines) + "\n"


def tunnel_address(name):
    output = subprocess.run(["docker", "exec", name, "ip", "-4", "-o", "addr", "show", "dev", "tun0"], capture_output=True, timeout=20).stdout.decode()
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", output)
    return match.group(1) if match else None


def wait_address(name, budget):
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        if address := tunnel_address(name):
            return address
        time.sleep(0.5)
    return None


def probe(name, echo_ip):
    output = subprocess.run(["docker", "exec", name, "python3", "/keys/probe.py", echo_ip], capture_output=True, timeout=60).stdout.decode()
    try:
        return json.loads(output.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {}


def logs(name):
    return subprocess.run(["docker", "logs", name], capture_output=True, timeout=20).stdout.decode(errors="replace")


def start_client(case, root, images, gateway, port, cert, label):
    name = PREFIX + label + "-" + uuid.uuid4().hex[:8]
    (root / f"{name}.conf").write_text(client_config(case, gateway, port, cert))
    container(name, images[case.get("image", "current")], ["--cap-add", "NET_ADMIN", "--device", "/dev/net/tun"],
              ["openvpn", "--config", f"/keys/{name}.conf"], root)
    return name


def traffic_checks(checks, name, echo_ip, gateway, label=""):
    result = probe(name, echo_ip)
    checks[f"{label}tcp-256KiB-echo"] = result.get("tcp_echo") is True
    checks[f"{label}udp-1200-echo"] = result.get("udp_echo") is True
    checks[f"{label}tcp-source-is-kerlico"] = result.get("tcp_peer") == gateway
    checks[f"{label}udp-source-is-kerlico"] = result.get("udp_peer") == gateway


def exercise(case, root, images, gateway, port, echo_ip, started):
    checks = {}
    first = start_client(case, root, images, gateway, port, case.get("cert", "client"), "c1")
    started.append(first)
    if case.get("refused"):
        checks["no-tunnel-address"] = wait_address(first, 15) is None
        text = logs(first)
        checks["client-saw-refusal"] = any(marker in text for marker in ["AUTH_FAILED", "TLS Error", "TLS handshake failed", "alert"])
        return checks
    address = wait_address(first, 30)
    checks["pushed-address-10.8.0.2"] = address == "10.8.0.2"
    if not address:
        return checks
    traffic_checks(checks, first, echo_ip, gateway)
    if cipher := case.get("expect_cipher"):
        checks[f"negotiated-{cipher}"] = f"Data Channel: Cipher '{cipher}'" in logs(first)
    if case.get("rekey"):
        time.sleep(20)
        checks["client-renegotiated"] = logs(first).count("Outgoing Data Channel: Cipher") >= 2
        traffic_checks(checks, first, echo_ip, gateway, "after-rekey-")
    if second_cert := case.get("second"):
        second = start_client(case, root, images, gateway, port, second_cert, "c2")
        started.append(second)
        if case.get("release"):
            checks["second-held-off-by-max-clients"] = wait_address(second, 12) is None
            subprocess.run(["docker", "stop", "-t", "5", first], capture_output=True, timeout=30)
            checks["second-gets-released-address"] = wait_address(second, 30) == "10.8.0.2"
            traffic_checks(checks, second, echo_ip, gateway, "second-")
        else:
            checks["second-address-10.8.0.3"] = wait_address(second, 30) == "10.8.0.3"
            traffic_checks(checks, second, echo_ip, gateway, "second-")
            traffic_checks(checks, first, echo_ip, gateway, "first-still-")
    return checks


def run_case(case, root, images, gateway, echo_ip):
    port = h.free_port()
    config = node_config(case, root, gateway, port, echo_ip)
    path = root / f"{case['name']}.json"
    path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
    path.chmod(0o600)
    started = []
    try:
        with h.process([args.kerlico, "run", "-c", str(path)], root, case["name"] + ".kerlico") as child:
            time.sleep(1.5)
            if child.poll() is not None:
                raise RuntimeError("kerlico 在就绪前退出")
            return exercise(case, root, images, gateway, port, echo_ip, started)
    finally:
        for name in started:
            (root / f"{case['name']}.{name[len(PREFIX):]}.log").write_text(logs(name))
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=30)


def main():
    os.umask(0o022)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    create_pki(root)
    images = {label: build_image(root, label) for label in IMAGES}
    generate_crypt_v2(root, images["current"])
    versions = {label: subprocess.check_output(["docker", "run", "--rm", tag, "sh", "-c", "openvpn --version | head -1 || true"], timeout=60).decode().strip() for label, tag in images.items()}
    gateway = bridge_gateway()
    echo = PREFIX + "echo-" + uuid.uuid4().hex[:8]
    echo_ip = container(echo, images["current"], [], ["python3", "/keys/echo.py"], root)
    results = {}
    try:
        for case in CASES:
            if args.case and case["name"] not in args.case:
                continue
            try:
                results[case["name"]] = run_case(case, root, images, gateway, echo_ip)
            except Exception as error:
                results[case["name"]] = {"error": f"{type(error).__name__}: {error}"}
    finally:
        subprocess.run(["docker", "rm", "--force", echo], capture_output=True, timeout=30)
    failed = [name for name, checks in results.items() if "error" in checks or not all(checks.values())]
    summary = {"reference": versions, "worker": os.environ.get("KERLICO_WORKER_ALIAS", "worker"), "results": results, "failed": failed}
    (root / "result.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=1), flush=True)
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="官方 OpenVPN 客户端连接 kerlico OpenVPN 服务端入站，仅在 worker 运行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--case", action="append", help="只运行指定用例，可重复")
    args = parser.parse_args()
    main()
