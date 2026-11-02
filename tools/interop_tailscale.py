#!/usr/bin/env python3
"""在 worker 上用 headscale 与官方 tailscale 容器验证 Tailscale 出站：TCP/UDP 经 DERP、直连和出口节点。"""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

PREFIX = "kerlico-agent-tailscale"
NETWORK = PREFIX + "-net"
SUBNET = "172.29.71.0/24"
HEADSCALE_IP = "172.29.71.10"
PEER_IP = "172.29.71.11"
CONTROL = f"https://{HEADSCALE_IP}:8443"
ECHO_PORT = 7001
ECHO = """
import socket, threading
def tcp(conn, peer):
    with conn:
        first = True
        while data := conn.recv(65536):
            if first and data.startswith(b"whoami"):
                conn.sendall(peer[0].encode())
                return
            first = False
            conn.sendall(data)
listener = socket.create_server(("0.0.0.0", 7001))
def serve():
    while True:
        conn, peer = listener.accept()
        threading.Thread(target=tcp, args=(conn, peer), daemon=True).start()
threading.Thread(target=serve, daemon=True).start()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("0.0.0.0", 7001))
while True:
    data, peer = udp.recvfrom(65536)
    udp.sendto(data, peer)
"""


def run(*command, check=True, timeout=120):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"命令失败 {' '.join(command[:4])}: {result.stderr[-2000:]}")
    return result.stdout


def remove_containers():
    for name in ("headscale", "peer", "peer-echo"):
        run("docker", "rm", "-f", f"{PREFIX}-{name}", check=False)
    run("docker", "network", "rm", NETWORK, check=False)


def make_certificate(work):
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-days", "2", "-subj", "/CN=kerlico-agent-tailscale-ca", "-keyout", str(work / "ca.key"), "-out", str(work / "ca.pem"))
    run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-subj", "/CN=headscale", "-keyout", str(work / "tls.key"), "-out", str(work / "tls.csr"))
    (work / "ext.cnf").write_text(f"subjectAltName=IP:{HEADSCALE_IP}\n")
    run("openssl", "x509", "-req", "-in", str(work / "tls.csr"), "-CA", str(work / "ca.pem"), "-CAkey", str(work / "ca.key"),
        "-CAcreateserial", "-days", "2", "-extfile", str(work / "ext.cnf"), "-out", str(work / "tls.crt"))


def start_headscale(work, image):
    config = {
        "server_url": CONTROL,
        "listen_addr": "0.0.0.0:8443",
        "metrics_listen_addr": "127.0.0.1:9090",
        "grpc_listen_addr": "127.0.0.1:50443",
        "tls_cert_path": "/work/tls.crt",
        "tls_key_path": "/work/tls.key",
        "noise": {"private_key_path": "/var/lib/headscale/noise.key"},
        "prefixes": {"v4": "100.64.0.0/10", "v6": "fd7a:115c:a1e0::/48", "allocation": "sequential"},
        "derp": {
            "server": {"enabled": True, "region_id": 999, "region_code": "local", "region_name": "local",
                       "stun_listen_addr": "0.0.0.0:3478", "private_key_path": "/var/lib/headscale/derp.key",
                       "automatically_add_embedded_derp_region": True},
            "urls": [], "paths": [], "auto_update_enabled": False,
        },
        "database": {"type": "sqlite", "sqlite": {"path": "/var/lib/headscale/db.sqlite"}},
        "dns": {"magic_dns": False, "base_domain": "tail.test", "override_local_dns": False, "nameservers": {"global": []}},
        "log": {"level": "info"},
    }
    (work / "headscale.yaml").write_text(json.dumps(config))
    run("docker", "run", "-d", "--name", f"{PREFIX}-headscale", "--network", NETWORK, "--ip", HEADSCALE_IP,
        "-v", f"{work}:/work:ro", "--tmpfs", "/var/lib/headscale", image, "serve", "-c", "/work/headscale.yaml")
    for _ in range(60):
        probe = subprocess.run(["curl", "-sk", "--max-time", "1", f"{CONTROL}/key?v=131"], capture_output=True, text=True)
        if "publicKey" in probe.stdout:
            return
        time.sleep(0.5)
    raise RuntimeError("headscale 未就绪：" + run("docker", "logs", f"{PREFIX}-headscale", check=False))


def headscale(*arguments):
    return run("docker", "exec", f"{PREFIX}-headscale", "headscale", "-c", "/work/headscale.yaml", *arguments)


def auth_keys(count):
    headscale("users", "create", "agent")
    user = json.loads(headscale("users", "list", "-o", "json"))[0]["id"]
    return [json.loads(headscale("preauthkeys", "create", "-u", str(user), "-e", "1h", "-o", "json"))["key"] for _ in range(count)]


def start_peer(work, image, key, python_image):
    run("docker", "run", "-d", "--name", f"{PREFIX}-peer", "--network", NETWORK, "--ip", PEER_IP,
        "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun", "--sysctl", "net.ipv4.ip_forward=1",
        "--sysctl", "net.ipv6.conf.all.forwarding=1",
        "-e", "SSL_CERT_FILE=/work/ca.pem", "-v", f"{work}:/work:ro", "--entrypoint", "tailscaled", image,
        "--state=mem:", "--socket=/tmp/ts.sock")
    time.sleep(1)
    run("docker", "exec", f"{PREFIX}-peer", "tailscale", "--socket=/tmp/ts.sock", "up",
        f"--login-server={CONTROL}", f"--authkey={key}", "--hostname=peer", "--advertise-exit-node", "--accept-dns=false")
    (work / "echo.py").write_text(ECHO)
    run("docker", "run", "-d", "--name", f"{PREFIX}-peer-echo", "--network", f"container:{PREFIX}-peer",
        "-v", f"{work}:/work:ro", python_image, "python", "-u", "/work/echo.py")
    nodes = json.loads(headscale("nodes", "list", "-o", "json"))
    peer = next(node for node in nodes if node["given_name"] == "peer")
    headscale("nodes", "approve-routes", "-i", str(peer["id"]), "-r", "0.0.0.0/0,::/0")
    return next(address for address in peer["ip_addresses"] if ":" not in address)


def peer_status():
    text = run("docker", "exec", f"{PREFIX}-peer", "tailscale", "--socket=/tmp/ts.sock", "status", "--json")
    return json.loads(text)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise RuntimeError("SOCKS 连接提前关闭")
        data += chunk
    return data


def socks_handshake(sock):
    sock.sendall(b"\x05\x01\x00")
    if receive_exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS 协商失败")


def socks_reply(sock):
    head = receive_exact(sock, 4)
    if head[1] != 0:
        raise RuntimeError(f"SOCKS 拒绝：{head[1]}")
    size = {1: 4, 4: 16}[head[3]]
    bound = receive_exact(sock, size + 2)
    return socket.inet_ntop(socket.AF_INET if size == 4 else socket.AF_INET6, bound[:size]), struct.unpack("!H", bound[size:])[0]


def tcp_exchange(port, host, target, payload, half_close=True):
    with socket.create_connection(("127.0.0.1", port), timeout=30) as sock:
        socks_handshake(sock)
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", target))
        socks_reply(sock)
        sock.sendall(payload)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        data = b""
        while chunk := sock.recv(65536):
            data += chunk
            if not half_close and len(data) >= len(payload):
                break
        return data


def udp_exchange(port, host, target, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=30) as control:
        socks_handshake(control)
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        relay = socks_reply(control)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            frame = b"\x00\x00\x00\x01" + socket.inet_aton(host) + struct.pack("!H", target) + payload
            for _ in range(8):
                sock.sendto(frame, ("127.0.0.1", relay[1]))
                try:
                    data = sock.recv(65536)
                except TimeoutError:
                    continue
                return data[10:]
    raise RuntimeError("UDP 回包超时")


def kerlico_config(port, key, work, direct, exit_node=None):
    options = {"control_url": CONTROL, "auth_key": key, "hostname": "kerlico", "direct": direct,
               "ca_pem": (work / "ca.pem").read_text(), "state_file": str(work / "kerlico-state.json")}
    if exit_node:
        options["exit_node"] = exit_node
    return {"version": 2, "outbounds": [{"tag": "tailnet", "type": "tailscale", "options": options}],
            "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{port}", "outbound": "tailnet", "options": {}}],
            "limits": {"connect_timeout_ms": 20000, "idle_timeout_ms": 30000, "drain_timeout_ms": 1000}}


def wait_listening(child, port, log):
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("kerlico 提前退出：" + log.read_text(errors="replace")[-2000:])
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("kerlico 未就绪")


class Kerlico:
    def __init__(self, binary, work, label, config):
        self.path = work / f"{label}.json"
        self.path.write_text(json.dumps(config))
        self.path.chmod(0o600)
        self.log = work / f"{label}.log"
        self.port = config["local_inbounds"][0]["listen"].rsplit(":", 1)[1]
        self.command = [binary, "run", "-c", str(self.path)]

    def __enter__(self):
        self.output = self.log.open("wb")
        self.child = subprocess.Popen(self.command, stdout=self.output, stderr=subprocess.STDOUT)
        wait_listening(self.child, int(self.port), self.log)
        return self

    def __exit__(self, kind, *_):
        self.child.send_signal(signal.SIGTERM)
        try:
            status = self.child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait()
            status = "超时"
        self.output.close()
        if kind is None and status != 0:
            raise RuntimeError(f"kerlico 关闭状态 {status}：" + self.log.read_text(errors="replace")[-1000:])


def local_echo():
    """官方出口节点拒绝转发到自身直连网段，因此目标放在容器网段之外的本机主地址。"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    listener = socket.create_server(("0.0.0.0", 0))
    number = listener.getsockname()[1]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 绑定具体地址：通配绑定的回包源地址会被内核改成网桥地址，出口节点的 conntrack 匹配不上。
    udp.bind((address, number))

    def tcp():
        while True:
            conn, peer = listener.accept()
            with conn:
                conn.recv(64)
                conn.sendall(peer[0].encode())

    def datagram():
        while True:
            data, peer = udp.recvfrom(65536)
            udp.sendto(data, peer)
    threading.Thread(target=tcp, daemon=True).start()
    threading.Thread(target=datagram, daemon=True).start()
    return address, number


def peer_view_of_kerlico():
    peers = peer_status().get("Peer") or {}
    return next((peer for peer in peers.values() if peer.get("HostName") == "kerlico"), None)


def exercise(port, tailnet_ip, label, expect_direct):
    payload = bytes(range(251)) * 400
    if tcp_exchange(port, tailnet_ip, ECHO_PORT, payload) != payload:
        raise RuntimeError(label + "：TCP 回写不一致")
    print(label, "TCP 100400 字节回写一致")
    for size in (17, 1100):
        data = bytes([size % 251]) * size
        if udp_exchange(port, tailnet_ip, ECHO_PORT, data) != data:
            raise RuntimeError(label + f"：UDP {size} 回写不一致")
    print(label, "UDP 17/1100 字节回写一致")
    deadline = time.monotonic() + 20
    view = None
    while time.monotonic() < deadline:
        tcp_exchange(port, tailnet_ip, ECHO_PORT, b"keep-active")
        view = peer_view_of_kerlico()
        if view and bool(view.get("CurAddr")) == expect_direct and (expect_direct or view.get("Relay")):
            print(label, "官方客户端观察到路径：", "直连 " + view["CurAddr"] if expect_direct else "中继 " + view["Relay"])
            return
        time.sleep(1)
    raise RuntimeError(f"{label}：路径不符合预期：{view}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--headscale-image", default="headscale/headscale:0.27.1")
    parser.add_argument("--tailscale-image", default="tailscale/tailscale:v1.92.3")
    parser.add_argument("--python-image", default="python:3.13-alpine")
    arguments = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="kerlico-tailscale-"))
    work.chmod(0o755)
    with ExitStack() as stack:
        stack.callback(shutil.rmtree, work, True)
        stack.callback(remove_containers)
        remove_containers()
        run("docker", "network", "create", "--subnet", SUBNET, NETWORK)
        make_certificate(work)
        for name in work.iterdir():
            name.chmod(0o644)
        start_headscale(work, arguments.headscale_image)
        peer_key, key = auth_keys(2)
        tailnet_ip = start_peer(work, arguments.tailscale_image, peer_key, arguments.python_image)
        print("官方客户端已加入 tailnet：", tailnet_ip)

        port = free_port()
        with Kerlico(arguments.kerlico, work, "derp", kerlico_config(port, key, work, False)):
            exercise(port, tailnet_ip, "DERP", False)

        port = free_port()
        with Kerlico(arguments.kerlico, work, "direct", kerlico_config(port, key, work, True)):
            exercise(port, tailnet_ip, "直连", True)

        target_host, target_port = local_echo()
        port = free_port()
        with Kerlico(arguments.kerlico, work, "exit", kerlico_config(port, key, work, True, "peer")):
            seen = tcp_exchange(port, target_host, target_port, b"whoami").decode()
            if seen != PEER_IP:
                raise RuntimeError(f"出口节点未生效：目标看到来源 {seen}")
            print("出口节点 TCP：目标看到来源", seen)
            data = b"exit-udp" * 40
            if udp_exchange(port, target_host, target_port, data) != data:
                raise RuntimeError("出口节点 UDP 回写不一致")
            print("出口节点 UDP 回写一致")

        port = free_port()
        with Kerlico(arguments.kerlico, work, "noexit", kerlico_config(port, key, work, True)):
            try:
                tcp_exchange(port, target_host, target_port, b"whoami")
            except (RuntimeError, OSError):
                print("未选择出口节点时非 tailnet 目标被拒绝")
            else:
                raise RuntimeError("未选择出口节点时不应放行非 tailnet 目标")
    print("通过")


if __name__ == "__main__":
    main()
