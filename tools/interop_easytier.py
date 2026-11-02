#!/usr/bin/env python3
"""kerlico EasyTier 出站加入官方 easytier-core 组成的网络，验证 TCP 与 UDP 回写。

拓扑（均为容器，宿主只运行 kerlico）：
  relay   公共中继式节点，自身是另一个网络，不开 TUN。
  node-a  TUN 节点，10.144.144.1，经 relay 入网，代理内部子网 lan。
  node-b  TUN 节点，10.144.144.2，经 relay 入网。
  svc     只连在 lan 上，kerlico 只能经 node-a 的子网代理到达。
场景一：静态地址，tcp:// 直连 node-a。场景二：网络分配地址，udp:// 连 relay。
"""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time

import interop_vless as h

VERSION = "2.6.4"
PREFIX = "kerlico-agent-easytier-"
IMAGE = "debian:bookworm-slim"
NETWORK = "interop-net"
SECRET = "synthetic-easytier-secret"
ECHO_PORT = 7001
VIRTUAL_A = "10.144.144.1"
VIRTUAL_A6 = "fd00:144::1"
VIRTUAL_B = "10.144.144.2"
STATIC_ADDRESSES = {"ipv4": "10.144.144.5/24", "ipv6": "fd00:144::5/64"}
ECHO = r"""
use Socket qw(:DEFAULT pack_sockaddr_in6 IN6ADDR_ANY);
$SIG{CHLD} = "IGNORE";
sub bound {
    socket(my $socket, AF_INET6, $_[0], 0) or die;
    setsockopt($socket, SOL_SOCKET, SO_REUSEADDR, 1);
    bind($socket, pack_sockaddr_in6(7001, IN6ADDR_ANY)) or die;
    return $socket;
}
if (fork() == 0) {
    my $udp = bound(SOCK_DGRAM);
    while (my $from = recv($udp, my $data, 65535, 0)) { send($udp, $data, 0, $from); }
    exit;
}
my $tcp = bound(SOCK_STREAM);
listen($tcp, 16) or die;
while (accept(my $conn, $tcp)) {
    if (fork() == 0) {
        while (sysread($conn, my $data, 65536)) { syswrite($conn, $data); }
        exit;
    }
    close($conn);
}
"""


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=120, **kwargs).stdout.strip()


@contextmanager
def docker_network(name, *flags):
    docker("network", "create", *flags, PREFIX + name)
    try:
        yield PREFIX + name
    finally:
        subprocess.run(["docker", "network", "rm", PREFIX + name], capture_output=True, timeout=60)


@contextmanager
def container(name, network, core_dir, command):
    docker("run", "-d", "--name", PREFIX + name, "--network", network, "--cap-add", "NET_ADMIN",
           "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--device", "/dev/net/tun", "-v", str(core_dir) + ":/et:ro", IMAGE, "sh", "-c", command)
    try:
        yield PREFIX + name
    finally:
        subprocess.run(["docker", "rm", "-f", PREFIX + name], capture_output=True, timeout=60)


def address(name, network):
    return docker("inspect", "-f", '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}', name)


def subnet(network):
    return docker("network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}", network)


def echo_command():
    return "perl -e '" + ECHO.replace("'", "'\\''") + "' & "


def peers_of(name):
    return json.loads(docker("exec", name, "/et/easytier-cli", "-o", "json", "peer"))


def wait_for_virtual(name, wanted, timeout=60):
    deadline = time.monotonic() + timeout
    seen = None
    while time.monotonic() < deadline:
        try:
            seen = peers_of(name)
            if all(any(peer.get("ipv4") == ip for peer in seen) for ip in wanted):
                return seen
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(1)
    raise RuntimeError(name + " 未在限时内看到 " + str(wanted) + "，最后结果：" + str(seen))


def kerlico_config(peer, socks_port, addresses):
    options = {"network_name": NETWORK, "network_secret": SECRET, "peers": [peer], **addresses}
    return {
        "version": 2,
        "limits": {"connect_timeout_ms": 30000, "idle_timeout_ms": 30000, "drain_timeout_ms": 1000},
        "outbounds": [{"tag": "overlay", "type": "easytier", "options": options}],
        "local_inbounds": [{"tag": "socks", "type": "socks", "listen": "127.0.0.1:" + str(socks_port),
                            "outbound": "overlay", "options": {"version": "5"}}],
    }


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(min(65536, count - len(data)))
        if not part:
            raise RuntimeError("连接提前结束，已收 " + str(len(data)) + " 字节")
        data.extend(part)
    return bytes(data)


def socks_address(host, port):
    if ":" in host:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
    return b"\x01" + socket.inet_aton(host) + struct.pack("!H", port)


def socks_open(port, command, host, target_port):
    sock = socket.create_connection(("127.0.0.1", port), timeout=45)
    sock.settimeout(45)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS 协商失败")
    sock.sendall(b"\x05" + bytes([command, 0]) + socks_address(host, target_port))
    reply = recv_exact(sock, 4)
    if reply[1] != 0:
        raise RuntimeError("SOCKS 请求被拒绝，REP=" + str(reply[1]) + "，目标 " + host)
    bound = recv_exact(sock, {1: 4, 4: 16}[reply[3]] + 2)
    return sock, bound


def tcp_round_trip(socks_port, host, size):
    payload = bytes(n % 251 for n in range(size))
    sock, _ = socks_open(socks_port, 1, host, ECHO_PORT)
    with sock:
        received = bytearray()
        for start in range(0, size, 16384):
            chunk = payload[start:start + 16384]
            sock.sendall(chunk)
            received.extend(recv_exact(sock, len(chunk)))
        if bytes(received) != payload:
            raise RuntimeError("TCP 回写内容不一致：" + host)
        sock.shutdown(socket.SHUT_WR)
        if sock.recv(1) != b"":
            raise RuntimeError("半关闭后对端未结束连接：" + host)


def udp_round_trip(socks_port, host, size):
    payload = bytes([size % 251]) * size
    control, bound = socks_open(socks_port, 3, "0.0.0.0", 0)
    relay_port = struct.unpack("!H", bound[-2:])[0]
    header = b"\x00\x00\x00" + socks_address(host, ECHO_PORT)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        for _ in range(10):
            sock.sendto(header + payload, ("127.0.0.1", relay_port))
            try:
                reply = sock.recv(65535)
            except TimeoutError:
                continue
            if reply != header + payload:
                raise RuntimeError("UDP 回写内容或来源不一致：" + host)
            return
    raise RuntimeError("UDP 无回写：" + host)


def run_scenario(name, work, kerlico_binary, peer, addresses, targets, node_a):
    socks_port = h.free_port()
    config = work / (name + ".json")
    h.write_json(config, kerlico_config(peer, socks_port, addresses))
    checks = []
    with ExitStack() as stack:
        kerlico = stack.enter_context(h.process([kerlico_binary, "run", "-c", str(config)], work, "kerlico-" + name))
        h.wait_ready(kerlico, socks_port)
        for label, host in targets:
            for size in (1, 1300, 256 * 1024):
                tcp_round_trip(socks_port, host, size)
            checks.append(name + " " + label + " TCP 1/1300/262144 字节并半关闭")
            for size in (17, 1200, 4000):
                udp_round_trip(socks_port, host, size)
            checks.append(name + " " + label + " UDP 17/1200/4000 字节")
        joined = [peer for peer in peers_of(node_a) if peer.get("hostname") == "kerlico"]
        if not joined or not joined[0].get("ipv4"):
            raise RuntimeError("node-a 未看到 kerlico 节点地址：" + str(peers_of(node_a)))
        checks.append(name + " node-a 看到 kerlico 地址 " + joined[0]["ipv4"])
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--easytier-dir", required=True, help="官方 easytier-linux-x86_64-v" + VERSION + " 解压目录")
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    core_dir = Path(args.easytier_dir).resolve()
    version = subprocess.check_output([core_dir / "easytier-core", "--version"], text=True, timeout=10).strip()
    if VERSION not in version:
        raise SystemExit("easytier-core 版本不是固定版本：" + version)
    if shutil.which("docker") is None:
        raise SystemExit("需要 Docker")
    core = "/et/easytier-core --network-name {name} --network-secret {secret} "
    with ExitStack() as stack:
        net = stack.enter_context(docker_network("net"))
        lan = stack.enter_context(docker_network("lan", "--internal"))
        lan_subnet = subnet(lan)
        relay = stack.enter_context(container("relay", net, core_dir, core.format(name="public-relay", secret="relay-secret")
                                              + "--no-tun -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010"))
        relay_ip = address(relay, net)
        node_b = stack.enter_context(container("node-b", net, core_dir, echo_command() + core.format(name=NETWORK, secret=SECRET)
                                               + "-i " + VIRTUAL_B + " -p tcp://" + relay_ip + ":11010"))
        node_a = stack.enter_context(container("node-a", net, core_dir, echo_command() + core.format(name=NETWORK, secret=SECRET)
                                               + "-i " + VIRTUAL_A + " --ipv6 " + VIRTUAL_A6 + "/64 -l tcp://0.0.0.0:11010 -l udp://0.0.0.0:11010"
                                               + " -n " + lan_subnet + " -p tcp://" + relay_ip + ":11010"))
        docker("network", "connect", lan, node_a)
        svc = stack.enter_context(container("svc", lan, core_dir, echo_command() + "wait"))
        svc_ip = address(svc, lan)
        node_a_ip = address(node_a, net)
        wait_for_virtual(node_a, [VIRTUAL_B])
        targets = [("虚拟 IP node-a", VIRTUAL_A), ("虚拟 IP node-b", VIRTUAL_B), ("子网代理 svc", svc_ip)]
        checks = run_scenario("static-tcp", work, args.kerlico, "tcp://" + node_a_ip + ":11010", STATIC_ADDRESSES,
                              targets + [("虚拟 IPv6 node-a", VIRTUAL_A6)], node_a)
        checks += run_scenario("dhcp-udp-relay", work, args.kerlico, "udp://" + relay_ip + ":11010", {}, targets, node_a)
    result = {"ok": True, "peer": version, "checks": checks,
              "kerlico_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest()}
    print(json.dumps(result, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
