#!/usr/bin/env python3
"""仅在 worker 运行：kerlico 经 ZeroTier 出站，穿过自建控制器与真实成员到达成员后方的回显服务。

容器使用 zerotier/zerotier:1.14.2，全部接在无外网的 Docker 内部网络上，不接触公共 planet。
场景：
  root    只配置 root（moon），控制器与成员都靠 WHOIS 发现
  direct  不配置 root，直接配置控制器与成员的端点
  denied  未授权身份应被控制器拒绝，SOCKS 连接立即失败
  flood   只配置 root，加入和转发期间持续向载体端口发送伪造的未认证包与 MAC 错误的 HELLO
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

IMAGE = "zerotier/zerotier:1.14.2"
SERVICE_IMAGE = "python:3.12-alpine"
PREFIX = "kerlico-agent-zerotier"
NETWORK = PREFIX + "-net"
SUBNET = "172.30.77.0/24"
TOKEN = "kerlico-interop-token"
MEMBER_ZT_IP = "10.77.0.20"
KERLICO_ZT_IP = "10.77.0.30"
MEMBER_ZT_IP6 = "fd77::20"
KERLICO_ZT_IP6 = "fd77::30"
TCP_PORT = 7001
UDP_PORT = 7002
HOSTS = {"root": "172.30.77.10", "controller": "172.30.77.11", "member": "172.30.77.12"}

ECHO_SERVICE = r"""
import socket, threading
def tcp(c):
    with c:
        while d := c.recv(65536):
            c.sendall(d)
def dual(kind):
    s = socket.socket(socket.AF_INET6, kind)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s
t = dual(socket.SOCK_STREAM)
t.bind(("::", %d)); t.listen(16)
def accept():
    while True:
        threading.Thread(target=tcp, args=(t.accept()[0],), daemon=True).start()
threading.Thread(target=accept, daemon=True).start()
u = dual(socket.SOCK_DGRAM); u.bind(("::", %d))
while True:
    d, a = u.recvfrom(65535); u.sendto(d, a)
""" % (TCP_PORT, UDP_PORT)


def run(*args, check=True, capture=True, timeout=120):
    result = subprocess.run(args, check=False, text=True, timeout=timeout,
                            stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {result.stdout}")
    return result.stdout.strip() if capture else ""


def docker(*args, **kwargs):
    return run("docker", *args, **kwargs)


def container(name):
    return f"{PREFIX}-{name}"


def cleanup():
    names = docker("ps", "-aq", "--filter", f"name=^{PREFIX}-", check=False).split()
    if names:
        docker("rm", "-f", *names, check=False)
    docker("network", "rm", NETWORK, check=False)


def start_node(name):
    local_conf = {"settings": {"allowManagementFrom": ["0.0.0.0/0"], "portMappingEnabled": False, "allowTcpFallbackRelay": False}}
    docker("run", "-d", "--name", container(name), "--network", NETWORK, "--ip", HOSTS[name],
           "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
           "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
           "--entrypoint", "sleep", IMAGE, "infinity")
    script = (
        "mkdir -p /var/lib/zerotier-one/moons.d && "
        f"printf %s {TOKEN} > /var/lib/zerotier-one/authtoken.secret && "
        "chmod 600 /var/lib/zerotier-one/authtoken.secret && "
        f"printf %s '{json.dumps(local_conf)}' > /var/lib/zerotier-one/local.conf && "
        "zerotier-idtool generate /var/lib/zerotier-one/identity.secret /var/lib/zerotier-one/identity.public >/dev/null"
    )
    docker("exec", container(name), "sh", "-c", script)
    return docker("exec", container(name), "cat", "/var/lib/zerotier-one/identity.public")


def launch(name):
    docker("exec", "-d", container(name), "zerotier-one", "/var/lib/zerotier-one")


def make_moon(root_public):
    script = (
        "cd /tmp && zerotier-idtool initmoon /var/lib/zerotier-one/identity.public > moon.json && "
        f"sed -i 's#\"stableEndpoints\": \\[\\]#\"stableEndpoints\": [\"{HOSTS['root']}/9993\"]#' moon.json && "
        "zerotier-idtool genmoon moon.json >/dev/null && ls *.moon"
    )
    moon_file = docker("exec", container("root"), "sh", "-c", script)
    with tempfile.TemporaryDirectory() as directory:
        local = Path(directory) / moon_file
        docker("cp", f"{container('root')}:/tmp/{moon_file}", str(local))
        for name in HOSTS:
            docker("cp", str(local), f"{container(name)}:/var/lib/zerotier-one/moons.d/{moon_file}")
    return root_public


def api(method, path, body=None):
    url = f"http://{HOSTS['controller']}:9993{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={"X-ZT1-Auth": TOKEN})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def wait_for(description, predicate, timeout=60):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:
            last_error = error
        time.sleep(0.5)
    raise RuntimeError(f"timed out waiting for {description}: {last_error}")


def create_network(controller_address):
    wait_for("controller API", lambda: api("GET", "/status"))
    network = api("POST", f"/controller/network/{controller_address}______", {
        "name": "kerlico-interop",
        "private": True,
        "v4AssignMode": {"zt": True},
        "mtu": 2800,
        "multicastLimit": 32,
        "enableBroadcast": True,
        "ipAssignmentPools": [{"ipRangeStart": "10.77.0.100", "ipRangeEnd": "10.77.0.200"}],
        "routes": [{"target": "10.77.0.0/24", "via": None}, {"target": "fd77::/64", "via": None}],
        "rules": [{"type": "ACTION_ACCEPT"}],
    })
    return network["id"]


def authorize(network, address, *ips):
    api("POST", f"/controller/network/{network}/member/{address}", {"authorized": True, "ipAssignments": list(ips)})


def member_status(network):
    output = docker("exec", container("member"), "zerotier-cli", "-j", "listnetworks")
    for item in json.loads(output):
        if item["id"] == network:
            return item
    return None


def start_service():
    docker("run", "-d", "--name", container("service"), "--network", f"container:{container('member')}",
           SERVICE_IMAGE, "python", "-c", ECHO_SERVICE)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def socks_connect(port, host, target_port, timeout):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise RuntimeError("socks method refused")
    target = b"\x04" + socket.inet_pton(socket.AF_INET6, host) if ":" in host else b"\x01" + socket.inet_aton(host)
    sock.sendall(b"\x05\x01\x00" + target + struct.pack("!H", target_port))
    reply = sock.recv(22)
    if len(reply) < 2 or reply[1] != 0:
        sock.close()
        raise ConnectionRefusedError(f"socks reply {reply.hex()}")
    return sock


def tcp_round_trip(port, size, host=MEMBER_ZT_IP):
    payload = os.urandom(size)
    with socks_connect(port, host, TCP_PORT, 45) as sock:
        sock.sendall(payload)
        received = bytearray()
        while len(received) < size:
            part = sock.recv(65536)
            if not part:
                break
            received.extend(part)
    if bytes(received) != payload:
        raise RuntimeError(f"tcp echo mismatch: sent {size}, received {len(received)}")


def udp_round_trip(port, size):
    control = socket.create_connection(("127.0.0.1", port), timeout=5)
    control.settimeout(30)
    control.sendall(b"\x05\x01\x00")
    if control.recv(2) != b"\x05\x00":
        raise RuntimeError("socks method refused")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = control.recv(10)
    if len(reply) < 10 or reply[1] != 0:
        raise RuntimeError(f"udp associate refused: {reply.hex()}")
    relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])
    if relay[0] == "0.0.0.0":
        relay = ("127.0.0.1", relay[1])
    payload = os.urandom(size)
    header = b"\x00\x00\x00\x01" + socket.inet_aton(MEMBER_ZT_IP) + struct.pack("!H", UDP_PORT)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            udp.sendto(header + payload, relay)
            try:
                data, _ = udp.recvfrom(65535)
            except socket.timeout:
                continue
            if data[len(header):] == payload:
                return
            raise RuntimeError("udp echo mismatch")
    raise RuntimeError("udp echo timed out")


class Kerlico:
    def __init__(self, binary, directory, label, options):
        self.socks = free_port()
        self.log_path = Path(directory) / f"{label}.log"
        config = {
            "version": 2,
            "outbounds": [{"tag": "proxy", "type": "zerotier", "options": options}],
            "local_inbounds": [
                {"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{self.socks}", "outbound": "proxy", "options": {}}
            ],
            "limits": {"connect_timeout_ms": 20000, "idle_timeout_ms": 60000, "drain_timeout_ms": 1000},
        }
        path = Path(directory) / f"{label}.json"
        path.write_text(json.dumps(config))
        self.log = open(self.log_path, "wb")
        self.child = subprocess.Popen([binary, "run", "-c", str(path)], stdout=self.log, stderr=subprocess.STDOUT)

    def close(self):
        self.child.terminate()
        try:
            self.child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.child.kill()
        self.log.close()

    def wait_listening(self):
        def ready():
            if self.child.poll() is not None:
                raise SystemExit(f"kerlico exited: {self.log_path.read_text(errors='replace')}")
            with socket.create_connection(("127.0.0.1", self.socks), timeout=1):
                return True
        wait_for("kerlico socks listener", ready, 30)


def retry_round_trip(check, description, timeout=90):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            check()
            return
        except Exception as error:
            last = error
            time.sleep(1)
    raise RuntimeError(f"{description} failed: {last}")


def verify_data_path(kerlico, label):
    started = time.monotonic()
    retry_round_trip(lambda: tcp_round_trip(kerlico.socks, 256), f"{label} first TCP round trip")
    first = time.monotonic() - started
    tcp_round_trip(kerlico.socks, 1 << 20)
    udp_round_trip(kerlico.socks, 1200)
    udp_round_trip(kerlico.socks, 4000)
    retry_round_trip(lambda: tcp_round_trip(kerlico.socks, 4096, MEMBER_ZT_IP6), f"{label} IPv6 TCP round trip", 30)
    print(f"{label}: TCP 256 B and 1 MiB, UDP 1200 B and 4000 B, IPv6 TCP 4096 B echoed; first round trip after {first:.1f}s", flush=True)


def peer_paths(address):
    output = docker("exec", container("member"), "zerotier-cli", "-j", "peers")
    for peer in json.loads(output):
        if peer["address"] == address:
            return [path["address"] for path in peer.get("paths", []) if path.get("active")]
    return []


class ForgedFlood:
    """向节点的载体端口持续发送随机来源的 28 字节包和 MAC 错误的 HELLO。"""

    def __init__(self, address):
        self.destination = bytes.fromhex(address)
        self.target = ("127.0.0.1", 20000 + int(address, 16) % 45000)
        self.stop = threading.Event()
        self.sent = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def packet(self, source, verb, body=b""):
        return os.urandom(8) + self.destination + source + b"\x00" + os.urandom(8) + bytes([verb]) + body

    def hello(self):
        source = os.urandom(5)
        identity = source + b"\x00" + os.urandom(64) + b"\x00"
        return self.packet(source, 0x01, bytes([11, 1, 4, 0, 8]) + os.urandom(8) + identity)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while not self.stop.is_set():
                sock.sendto(self.packet(os.urandom(5), 0x06), self.target)
                sock.sendto(self.hello(), self.target)
                self.sent += 2
                time.sleep(0.002)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", default=os.path.join(os.environ.get("CARGO_TARGET_DIR", "target"), "debug", "kerlico"))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--work-dir", default=os.environ.get("CARGO_TARGET_DIR", "."))
    args = parser.parse_args()
    cleanup()
    docker("pull", "-q", IMAGE, timeout=300)
    docker("pull", "-q", SERVICE_IMAGE, timeout=300)
    docker("network", "create", "--internal", "--subnet", SUBNET, NETWORK)
    work = Path(args.work_dir) / "interop-zerotier"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    directory = str(work)
    kerlico = None
    try:
        identities = {name: start_node(name) for name in HOSTS}
        make_moon(identities["root"])
        for name in HOSTS:
            launch(name)
        controller = identities["controller"].split(":")[0]
        member = identities["member"].split(":")[0]
        network = create_network(controller)
        print(f"network {network} on controller {controller}, member {member}, root {identities['root'].split(':')[0]}", flush=True)

        docker("exec", container("member"), "zerotier-cli", "join", network)
        wait_for("member join request", lambda: api("GET", f"/controller/network/{network}/member"), 30)
        authorize(network, member, MEMBER_ZT_IP, MEMBER_ZT_IP6)
        wait_for("member address", lambda: MEMBER_ZT_IP + "/24" in (member_status(network) or {}).get("assignedAddresses", []), 90)
        start_service()

        secret = str(Path(directory) / "identity.secret")
        base = {"network": network, "identity_file": secret}
        root_seed = {"identity": identities["root"], "endpoints": [f"{HOSTS['root']}:9993"]}
        controller_seed = {"identity": identities["controller"], "endpoints": [f"{HOSTS['controller']}:9993"]}
        member_seed = {"identity": identities["member"], "endpoints": [f"{HOSTS['member']}:9993"]}

        kerlico = Kerlico(args.kerlico, directory, "denied", dict(base, roots=[root_seed]))
        kerlico.wait_listening()
        address = wait_for("identity file", lambda: Path(secret).read_text().split(":")[0], 60)
        print(f"kerlico node {address}", flush=True)
        deadline = time.monotonic() + 30
        while True:
            started = time.monotonic()
            try:
                socks_connect(kerlico.socks, MEMBER_ZT_IP, TCP_PORT, 25).close()
                raise RuntimeError("an unauthorized node reached the service")
            except (OSError, ConnectionRefusedError) as error:
                elapsed = time.monotonic() - started
                if elapsed < 15:
                    print(f"denied: unauthorized node refused after {elapsed:.1f}s ({error})", flush=True)
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError("no prompt refusal for an unauthorized node") from error
        kerlico.close()
        kerlico = None

        authorize(network, address, KERLICO_ZT_IP, KERLICO_ZT_IP6)

        kerlico = Kerlico(args.kerlico, directory, "root", dict(base, roots=[root_seed]))
        kerlico.wait_listening()
        verify_data_path(kerlico, "root")
        print(f"root: member sees kerlico at {peer_paths(address)}", flush=True)
        kerlico.close()
        kerlico = None

        kerlico = Kerlico(args.kerlico, directory, "direct", dict(base, peers=[controller_seed, member_seed]))
        kerlico.wait_listening()
        verify_data_path(kerlico, "direct")
        print(f"direct: member sees kerlico at {peer_paths(address)}", flush=True)
        kerlico.close()
        kerlico = None

        with ForgedFlood(address) as flood:
            time.sleep(1)
            kerlico = Kerlico(args.kerlico, directory, "flood", dict(base, roots=[root_seed]))
            kerlico.wait_listening()
            verify_data_path(kerlico, "flood")
            print(f"flood: {flood.sent} forged packets sent during the run", flush=True)
        print("zerotier interop passed", flush=True)
    except Exception:
        for path in Path(directory).glob("*.log"):
            print(f"--- {path.name}", file=sys.stderr)
            print(path.read_text(errors="replace")[-4000:], file=sys.stderr)
        for name in HOSTS:
            print(f"--- {name} peers", file=sys.stderr)
            print(docker("exec", container(name), "zerotier-cli", "peers", check=False), file=sys.stderr)
        raise
    finally:
        if kerlico:
            kerlico.close()
        if not args.keep:
            cleanup()


if __name__ == "__main__":
    main()
