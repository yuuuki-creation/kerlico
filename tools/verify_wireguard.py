#!/usr/bin/env python3
"""Compare Kerlico and kernel WireGuard in throwaway Linux network namespaces."""

import argparse
import contextlib
import errno
import json
import ipaddress
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import base64

from verify_mieru import SequentialUDP, ThreadedTCP, encode_address, exact, socks_connect, unpack_udp
import verify_mieru as fixtures

LEFT = "198.18.0.1"
RIGHT = "198.18.0.2"
HOST4 = "10.201.0.1"
CLIENT4 = "10.201.0.2"
HOST6 = "fd72:38ab:1::1"
CLIENT6 = "fd72:38ab:1::2"
PORT = 51820
ECHO = 28080
DNS = 28053
UDP_PORTS = (28081, 28082, 28083, 28084)
SOCKS = 1080


def call(*args, input=None):
    return subprocess.check_output(args, input=input, text=True).strip()


def json_doc(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def keypair(root, label):
    secret = call("wg", "genkey")
    path = root / label
    path.write_text(secret + "\n")
    return str(path), secret, call("wg", "pubkey", input=secret + "\n")


def expect(p, probe):
    until = time.monotonic() + 10
    while time.monotonic() < until and p.poll() is None:
        if probe():
            return
        time.sleep(0.05)
    raise RuntimeError(f"Process or interface was not ready, exit={p.poll()}")


@contextlib.contextmanager
def process(argv, root, label):
    with (root / (label + ".log")).open("w") as out:
        proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT)
        try:
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)


def kernel(prefix, name, key, peer_key, psk, listen, allowed, endpoint=None):
    call(*prefix, "ip", "link", "add", name, "type", "wireguard")
    args = ["wg", "set", name, "listen-port", str(listen), "private-key", key,
            "peer", peer_key, "preshared-key", psk, "allowed-ips", allowed]
    if endpoint:
        args.extend(("endpoint", endpoint, "persistent-keepalive", "2"))
    call(*prefix, *args)
    call(*prefix, "ip", "link", "set", name, "mtu", "1420", "up")


def address(prefix, iface, v4, v6):
    call(*prefix, "ip", "addr", "add", f"{v4}/24", "dev", iface)
    call(*prefix, "ip", "-6", "addr", "add", f"{v6}/64", "dev", iface, "nodad")


def canonical_private_key(name, right, original, root, script):
    equivalent = bytearray(base64.b64decode(original))
    equivalent[0] ^= 7
    equivalent[31] ^= 0xc0
    variant = root / "equivalent-private-key"
    variant.write_bytes(base64.b64encode(equivalent) + b"\n")
    reference = "wg-clamp"
    call(*right, "ip", "link", "add", reference, "type", "wireguard")
    try:
        call(*right, "wg", "set", reference, "private-key", str(variant))
        expected_private = call(*right, "wg", "show", reference, "private-key")
        expected_public = call(*right, "wg", "show", reference, "public-key")
        established = call("wg", "show", name, "latest-handshakes")
        # A fresh handshake has a distinguishable timestamp even at wg's 1s precision.
        time.sleep(1.1)
        call("wg", "set", name, "private-key", str(variant))
        assert call("wg", "show", name, "private-key") == expected_private == original
        assert call("wg", "show", name, "public-key") == expected_public
        call(*right, sys.executable, script, "keepalive")
        assert call("wg", "show", name, "latest-handshakes") == established, "equivalent key reset the session"
    finally:
        call(*right, "ip", "link", "del", reference)


def occupied_listen_port(name):
    original = call("wg", "show", name, "listen-port")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("0.0.0.0", 0))
        occupied = str(busy.getsockname()[1])
        result = subprocess.run(["wg", "set", name, "listen-port", occupied],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode != 0 and os.strerror(errno.EADDRINUSE) in result.stderr, result.stderr
    assert call("wg", "show", name, "listen-port") == original


def wait_for(probe, description):
    deadline = time.monotonic() + 3
    while not probe():
        if time.monotonic() >= deadline:
            raise RuntimeError(description)
        time.sleep(0.02)


def udp_port_open(port, prefix=()):
    return socket_open(prefix, "udp", port) or socket_open(prefix, "udp6", port)


def link_lifecycle(name, right, local_peer, remote_peer, psk, script, old_port):
    before = call("wg", "show", name, "transfer")
    stamp = call("wg", "show", name, "latest-handshakes")
    call("ip", "link", "set", "dev", name, "down")
    wait_for(lambda: not udp_port_open(old_port), "down left an active UDP port")
    assert call("wg", "show", name, "listen-port") == str(old_port)
    assert call("wg", "show", name, "transfer") == before
    assert call("wg", "show", name, "latest-handshakes") == stamp
    assert call("wg", "show", name, "peers") == local_peer
    call("ip", "link", "set", "dev", name, "mtu", "1000")
    call("wg", "set", name, "peer", local_peer, "allowed-ips", f"{CLIENT4}/32,{CLIENT6}/128")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("0.0.0.0", 0))
        port = busy.getsockname()[1]
        # The saved port can be changed while down, even if currently occupied.
        call("wg", "set", name, "listen-port", str(port))
        assert call("wg", "show", name, "listen-port") == str(port)
    assert not udp_port_open(port), "down bound the new port"
    call("ip", "link", "set", "dev", name, "mtu", "9000", "up")
    wait_for(lambda: udp_port_open(port), "up did not bind the saved port")
    # Link down can remove routes; restore the OS-managed routes before probing keys.
    call("ip", "route", "replace", f"{CLIENT4}/32", "dev", name)
    call("ip", "-6", "route", "replace", f"{CLIENT6}/128", "dev", name)
    call(*right, "wg", "set", "wg-test", "peer", remote_peer, "endpoint", f"{LEFT}:{port}")
    call(*right, sys.executable, script, "blocked")
    assert call("wg", "show", name, "latest-handshakes") == stamp
    assert call("wg", "show", name, "transfer") == before
    call(*right, "wg", "set", "wg-test", "peer", remote_peer, "remove")
    call(*right, "wg", "set", "wg-test", "peer", remote_peer, "preshared-key", str(psk),
         "endpoint", f"{LEFT}:{port}", "allowed-ips", "0.0.0.0/0,::/0")
    call(*right, sys.executable, script, "keepalive")
    for prefix, interface in (([], "veth-left"), (right, "veth-right"), (right, "wg-test")):
        call(*prefix, "ip", "link", "set", "dev", interface, "mtu", "9000")
    for address, af in ((HOST4, "-4"), (HOST6, "-6")):
        call(*right, "ping", af, "-c", "2", "-W", "2", "-s", "4096", address)
    print("PASS Linux TUN: down releases UDP and keys, up rebinds saved port and uses the new MTU", flush=True)


def client_link_lifecycle(right):
    endpoint = call("wg", "show", "wg-test", "endpoints").split()[1]
    port = int(endpoint.rsplit(":", 1)[1])
    first = int(call("wg", "show", "wg-test", "latest-handshakes").split()[1])
    assert first > 0 and udp_port_open(port, right)
    call(*right, "ip", "link", "set", "dev", "wg-test", "down")
    wait_for(lambda: not udp_port_open(port, right), "client down left its UDP carrier bound")
    for prefix, interface in (([], "veth-left"), (right, "veth-right"), ([], "wg-test")):
        call(*prefix, "ip", "link", "set", "dev", interface, "mtu", "9000")
    time.sleep(1.05)
    call(*right, "ip", "link", "set", "dev", "wg-test", "mtu", "9000", "up")
    wait_for(lambda: udp_port_open(port, right), "client up did not rebind its previous port")
    call(*right, "ip", "addr", "replace", f"{CLIENT4}/24", "dev", "wg-test")
    call(*right, "ip", "-6", "addr", "replace", f"{CLIENT6}/64", "dev", "wg-test", "nodad")
    for host, af in ((HOST4, "-4"), (HOST6, "-6")):
        call(*right, "ping", af, "-c", "2", "-W", "2", "-s", "4096", host)
    assert int(call("wg", "show", "wg-test", "latest-handshakes").split()[1]) > first
    assert call("wg", "show", "wg-test", "endpoints").split()[1] == endpoint
    print("PASS Linux client TUN: down releases carrier, up reuses source port and new MTU with fresh keys", flush=True)


def rotate_preshared(name, right, local_peer, remote_peer, old_psk, endpoint, root, script):
    new_psk = root / "rotated-psk"
    new_psk.write_text(call("wg", "genpsk") + "\n", encoding="ascii")

    def readd_kernel_peer(psk):
        call(*right, "wg", "set", "wg-test", "peer", remote_peer, "remove")
        call(*right, "wg", "set", "wg-test", "peer", remote_peer, "preshared-key", str(psk),
             "endpoint", endpoint, "allowed-ips", "0.0.0.0/0,::/0")

    established = call("wg", "show", name, "latest-handshakes")
    call("wg", "set", name, "peer", local_peer, "preshared-key", str(new_psk))
    # Only Kerlico knows the new PSK; any reply must use the established session.
    call(*right, sys.executable, script, "traffic")
    assert call("wg", "show", name, "latest-handshakes") == established

    # wg reports whole seconds; make a wrong-key attempt distinguishable from the old stamp.
    time.sleep(1.1)
    readd_kernel_peer(old_psk)
    call(*right, sys.executable, script, "blocked")
    assert call(*right, "wg", "show", "wg-test", "latest-handshakes").split() == [remote_peer, "0"]
    assert call("wg", "show", name, "latest-handshakes") == established, "unconfirmed response changed handshake time"
    readd_kernel_peer(new_psk)
    call(*right, sys.executable, script, "traffic")
    assert int(call("wg", "show", name, "latest-handshakes").split()[1]) > int(established.split()[1])

    # With an active session, clearing the PSK must also leave the session usable.
    established = call("wg", "show", name, "latest-handshakes")
    call("wg", "set", name, "peer", local_peer, "preshared-key", os.devnull)
    call(*right, sys.executable, script, "traffic")
    assert call("wg", "show", name, "latest-handshakes") == established
    readd_kernel_peer(os.devnull)
    call(*right, sys.executable, script, "traffic")
    print("PASS PSK update and removal preserve live traffic; new handshakes use the new setting", flush=True)


def uapi_stream(path, port):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stalled:
        stalled.connect(str(path))
        stalled.sendall(b"set=1\n")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as active:
            active.settimeout(1)
            active.connect(str(path))
            active.sendall(b"get=1\n\nset=1\ninvalid_key=0\n\nget=1\n\n")
            with active.makefile("rb") as reply:
                def frame():
                    lines = []
                    while (line := reply.readline()) != b"\n":
                        assert line, "UAPI closed before the end of a frame"
                        lines.append(line)
                    return lines
                before, bad, after = frame(), frame(), frame()
            assert before == after and before[-1] == b"errno=0\n"
            assert f"listen_port={port}\n".encode() in before
            assert bad == [f"errno={-errno.EINVAL}\n".encode()]


def start_origins(stack):
    class TcpEcho(socketserver.BaseRequestHandler):
        def handle(self):
            while data := self.request.recv(65536):
                self.request.sendall(data)

    class UdpEcho(socketserver.BaseRequestHandler):
        def handle(self):
            data, reply = self.request
            reply.sendto(data, self.client_address)

    for host in (HOST4, HOST6):
        for base, handler in ((ThreadedTCP, TcpEcho), (SequentialUDP, UdpEcho)):
            kind = type("Origin", (base,), {"address_family": socket.AF_INET6 if ":" in host else socket.AF_INET})
            origin = stack.enter_context(kind((host, ECHO), handler))
            threading.Thread(target=origin.serve_forever, daemon=True).start()
            stack.callback(origin.shutdown)


def start_dns(stack):
    def answer(query, tcp):
        suffix = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(HOST4) if tcp else b""
        flags = b"\x81\x80" if tcp else b"\x83\x80"
        return query[:2] + flags + struct.pack("!4H", 1, int(tcp), 0, 0) + query[12:] + suffix

    class DnsTcp(socketserver.BaseRequestHandler):
        def handle(self):
            self.server.hits += 1
            n = struct.unpack("!H", exact(self.request, 2))[0]
            response = answer(exact(self.request, n), True)
            self.request.sendall(struct.pack("!H", len(response)) + response)

    class DnsUdp(socketserver.BaseRequestHandler):
        def handle(self):
            self.server.hits += 1
            data, socket = self.request
            socket.sendto(answer(data, False), self.client_address)

    servers = []
    for base, handler in ((ThreadedTCP, DnsTcp), (SequentialUDP, DnsUdp)):
        server = stack.enter_context(base((HOST4, DNS), handler))
        server.hits = 0
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stack.callback(server.shutdown)
        servers.append(server)
    return servers


def start_udp_port_origins(stack, dual=False):
    alternate = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    alternate.bind((HOST4, UDP_PORTS[3]))

    class ReportPort(socketserver.BaseRequestHandler):
        def handle(self):
            data, reply = self.request
            if self.server.server_address[1] == UDP_PORTS[2]:
                reply = alternate
            reply.sendto(struct.pack("!H", self.client_address[1]) + data, self.client_address)

    for index, port in enumerate(UDP_PORTS[:3]):
        use_v6 = dual and index == 1
        kind = type("PortOrigin", (SequentialUDP,), {"address_family": socket.AF_INET6 if use_v6 else socket.AF_INET})
        server = stack.enter_context(kind((HOST6 if use_v6 else HOST4, port), ReportPort))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stack.callback(server.shutdown)


def check_udp_ports(dual=False):
    control, bound = socks_connect(SOCKS, "0.0.0.0", 0, 3)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            source_ports = []
            for index, port in enumerate(UDP_PORTS[:3]):
                data = bytes([index])
                host = HOST6 if dual and index == 1 else HOST4
                sock.sendto(b"\0\0\0" + encode_address(host, port) + data, ("127.0.0.1", bound[1]))
                origin, got = unpack_udp(sock.recv(65535))
                assert origin == (host, UDP_PORTS[3] if index == 2 else port) and got[2:] == data
                source_ports.append(struct.unpack("!H", got[:2])[0])
            assert len(set(source_ports)) == 1, "one authenticated session used multiple tunnel ports"
    finally:
        control.close()


def load(host, require_udp_failure=False, fragments=False):
    af = socket.AF_INET6 if ":" in host else socket.AF_INET
    if not require_udp_failure:
        with socket.socket(af, socket.SOCK_STREAM) as conn:
            conn.settimeout(8)
            conn.connect((host, ECHO))
            for size in (128, 16_384, 65_536):
                message = bytes(i % 251 for i in range(size))
                conn.sendall(message)
                received = bytearray()
                while len(received) < size:
                    data = conn.recv(size - len(received))
                    if not data:
                        raise RuntimeError("short TCP reply")
                    received.extend(data)
                assert received == message
    with socket.socket(af, socket.SOCK_DGRAM) as conn:
        conn.settimeout(0.65 if require_udp_failure else 5)
        if require_udp_failure:
            conn.bind(("10.201.0.112", 0))
        sizes = [53, 1024, 1372 if af == socket.AF_INET6 else 1392]
        if fragments:
            if af == socket.AF_INET6:
                conn.setsockopt(socket.IPPROTO_IPV6, 23, 0)  # IPV6_MTU_DISCOVER: permit local fragmentation
            else:
                conn.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER
            sizes.append(4151)
        for size in sizes:
            data = bytes(i % 251 for i in range(size))
            conn.sendto(data, (host, ECHO))
            try:
                received, _ = conn.recvfrom(65536)
            except TimeoutError:
                if require_udp_failure:
                    return
                raise
            assert not require_udp_failure and received == data


def through_socks(host, fragments=False):
    conn, _ = socks_connect(SOCKS, host, ECHO)
    with conn:
        data = bytes(i % 251 for i in range(65_536))
        conn.sendall(data)
        assert exact(conn, len(data)) == data
    control, bound = socks_connect(SOCKS, "0.0.0.0", 0, 3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        target = ("127.0.0.1", bound[1])
        sizes = [2, 1000, 4151] if fragments else [2, 1000]
        for size in sizes:
            data = bytes(i % 251 for i in range(size))
            sock.sendto(b"\0\0\0" + encode_address(host, ECHO) + data, target)
            origin, got = unpack_udp(sock.recv(65535))
            assert origin == (host, ECHO) and got == data


def socket_open(prefix, name, port):
    return any(row.split()[1].endswith(f":{port:04X}") for row in
               call(*prefix, "cat", f"/proc/net/{name}").splitlines()[1:])


def portable(args):
    """Exercise Windows or Linux proxy paths using Xray's userspace peer."""
    version = subprocess.check_output([args.xray, "version"], text=True, timeout=10)
    assert "26.10.31" in version and "a4a3dff" in version
    # Published X25519 vectors, used only for loopback fixtures (RFC 7748 §6.1).
    skey = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    spub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    ckey = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    cpub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    psk = base64.b64encode(os.urandom(32)).decode()
    ip, inner = "127.0.0.1", "10.122.0.2"
    # The Xray userspace IP stack handles 127/8 inside its tunnel. The real
    # origin therefore uses this machine's private IPv4 interface address.
    host = args.origin_host
    if host is None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            host = probe.getsockname()[0]
    assert ipaddress.IPv4Address(host).is_private and not ipaddress.IPv4Address(host).is_loopback

    def udp_ready(port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                probe.bind((ip, port))
            except OSError:
                return True
        return False

    def check(socks, tcp, udp):
        conn, _ = socks_connect(socks, *tcp.server_address)
        with conn:
            payload = bytes(i % 251 for i in range(65_536))
            conn.sendall(payload)
            assert exact(conn, len(payload)) == payload
        control, bound = socks_connect(socks, "0.0.0.0", 0, 3)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            for origin in udp:
                payload = bytes(i % 251 for i in range(1000))
                target = origin.server_address[:2]
                client.sendto(b"\0\0\0" + encode_address(*target) + payload, (ip, bound[1]))
                remote, got = unpack_udp(client.recv(65535))
                assert remote == target and got == payload

    args.logs.mkdir(parents=True, exist_ok=True)
    with fixtures.Fixtures() as origins, tempfile.TemporaryDirectory() as working:
        tcp = origins.add(ThreadedTCP, host, fixtures.EchoTCP, "portable-wg-tcp")
        udp = [origins.add(SequentialUDP, host, fixtures.EchoUDP, f"portable-wg-udp-{n}") for n in range(2)]
        root = Path(working)
        port, socks, app = fixtures.free_ports(3)
        config = json_doc(root / "kerlico-inbound.json", {"warp": {"secretKey": "invalid"}, "inbounds": [
            {"tag": "wg", "protocol": "wireguard", "listen": ip, "port": port, "outbound": "native-v4",
             "settings": {"privateKey": skey, "users": [{"email": "xray", "publicKey": cpub,
                           "presharedKey": psk, "allowedIPs": [inner + "/32"]}]}}]})
        outbound = {"secretKey": ckey, "address": [inner], "noKernelTun": True,
                    "peers": [{"publicKey": spub, "preSharedKey": psk, "endpoint": f"{ip}:{port}"}]}
        reference = json_doc(root / "xray-client.json", {"log": {"loglevel": "warning"},
            "inbounds": [{"protocol": "socks", "listen": ip, "port": socks, "settings": {"udp": True}}],
            "outbounds": [{"protocol": "wireguard", "settings": outbound}]})
        with process([args.server, config], args.logs, "kerlico-inbound") as server:
            expect(server, lambda: udp_ready(port))
            with process([args.xray, "run", "-c", reference], args.logs, "xray-outbound") as peer:
                expect(peer, lambda: fixtures.ports_ready([socks]))
                check(socks, tcp, udp)
        print(f"PASS {sys.platform}: Xray WireGuard client to Kerlico inbound", flush=True)

        reference = json_doc(root / "xray-inbound.json", {"log": {"loglevel": "warning"},
            "inbounds": [{"protocol": "wireguard", "listen": ip, "port": port, "settings": {
                "secretKey": skey, "address": ["10.122.0.1"], "noKernelTun": True,
                "peers": [{"publicKey": cpub, "preSharedKey": psk, "allowedIPs": [inner + "/32"], "email": "peer"}]}}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "network": "tcp,udp", "ip": [host + "/32"]}]}}]})
        password = base64.b64encode(os.urandom(16)).decode()
        method = "2022-blake3-aes-128-gcm"
        settings = {"secretKey": ckey, "publicKey": spub, "preSharedKey": psk, "localAddresses": [inner]}
        config = json_doc(root / "kerlico-landing.json", {"warp": {"secretKey": "invalid"},
            "landing": {"protocol": "wireguard", "address": ip, "port": port, "settings": settings},
            "inbounds": [{"protocol": "ss2022", "tag": "ss", "listen": ip, "port": app,
                "rules": [{"geoip": ["private"], "outbound": "landing"}],
                "settings": {"method": method, "users": [{"email": "test", "password": password}]}}]})
        upstream = json_doc(root / "ss-client.json", {"protocol": "ss2022", "peer": f"{ip}:{app}",
                       "settings": {"method": method, "password": password, "socks5Port": socks,
                                    "httpProxyPort": fixtures.free_ports(1)[0]}})
        with process([args.xray, "run", "-c", reference], args.logs, "xray-inbound") as server:
            expect(server, lambda: udp_ready(port))
            with process([args.server, config], args.logs, "kerlico-landing") as leaf:
                expect(leaf, lambda: fixtures.ports_ready([app]))
                with process([args.ss_client, upstream], args.logs, "ss-outbound") as proxy:
                    expect(proxy, lambda: fixtures.ports_ready([socks]))
                    check(socks, tcp, udp)
        print(f"PASS {sys.platform}: Kerlico WireGuard landing to Xray inbound", flush=True)


def windows_tun(args):
    """Use a disposable Windows VM to exercise the production pipe and the Wintun packet path."""
    if os.name != "nt":
        raise RuntimeError("windows-tun requires Windows")

    def powershell(command):
        return call("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; " + command)

    if powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value") != "S-1-5-18":
        raise RuntimeError("windows-tun requires LocalSystem in a disposable Windows VM")
    assert args.raw.with_name("wintun.dll").is_file(), "place the official wintun.dll beside kerlico-wg.exe"
    assert "wireguard-tools" in call(args.wg, "--version")
    version = call(args.xray, "version")
    assert "26.10.31" in version and "a4a3dff" in version

    name = f"kcw{os.urandom(4).hex()}"
    bases = ((HOST4, CLIENT4, 24, socket.AF_INET), (HOST6, CLIENT6, 64, socket.AF_INET6))
    args.logs.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kerlico-wintun-") as tmp, contextlib.ExitStack() as stack:
        root = Path(tmp)
        skey, ckey = (call(args.wg, "genkey") for _ in range(2))
        spub, cpub = (call(args.wg, "pubkey", input=key + "\n") for key in (skey, ckey))
        psk = call(args.wg, "genpsk")
        spath, ppath = root / "server.key", root / "peer.psk"
        spath.write_text(skey + "\n", encoding="ascii")
        ppath.write_text(psk + "\n", encoding="ascii")
        allowed = f"{CLIENT4}/32,{CLIENT6}/128"
        port, = fixtures.free_ports(1, kind=socket.SOCK_DGRAM)
        socks, = fixtures.free_ports(1)
        server = stack.enter_context(process([args.raw, "--foreground", name], args.logs, "wintun"))

        def show(field):
            return call(args.wg, "show", name, field)

        def ready():
            return subprocess.run([args.wg, "show", name, "listen-port"], capture_output=True,
                                  timeout=3).returncode == 0

        expect(server, ready)
        call(args.wg, "set", name, "private-key", spath, "listen-port", str(port),
             "peer", cpub, "preshared-key", ppath, "allowed-ips", allowed)
        assert show("public-key") == spub and int(show("listen-port")) == port

        origins = stack.enter_context(fixtures.Fixtures())
        targets = []
        for host, _, prefix, family in bases:
            powershell(f"New-NetIPAddress -InterfaceAlias '{name}' -IPAddress '{host}' "
                       f"-PrefixLength {prefix} -PolicyStore ActiveStore | Out-Null")
            def has_address(host=host, family=family):
                with socket.socket(family, socket.SOCK_DGRAM) as probe:
                    try:
                        probe.bind((host, 0))
                    except OSError:
                        return False
                    return True
            expect(server, has_address)
            tcp = type("WinTcpEcho", (ThreadedTCP,), {"address_family": family})
            udp = type("WinUdpEcho", (SequentialUDP,), {"address_family": family})
            targets.append((origins.add(tcp, host, fixtures.EchoTCP, "wintun-tcp"),
                            origins.add(udp, host, fixtures.EchoUDP, "wintun-udp")))
        rule = f"Kerlico QA {name}"
        powershell(f"New-NetFirewallRule -DisplayName '{rule}' -Direction Inbound -Action Allow "
                   f"-InterfaceAlias '{name}' -LocalAddress '{HOST4}','{HOST6}' | Out-Null")
        stack.callback(powershell, f"Remove-NetFirewallRule -DisplayName '{rule}'")

        config = json_doc(root / "xray.json", {"log": {"loglevel": "warning"},
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": socks, "settings": {"udp": True}}],
            "outbounds": [{"protocol": "wireguard", "settings": {
                "secretKey": ckey, "address": [CLIENT4, CLIENT6], "noKernelTun": True,
                "peers": [{"publicKey": spub, "preSharedKey": psk, "endpoint": f"127.0.0.1:{port}"}]}}]})
        peer = stack.enter_context(process([args.xray, "run", "-c", config], args.logs, "xray"))
        expect(peer, lambda: fixtures.ports_ready([socks]))

        def traffic():
            for tcp, udp in targets:
                conn, _ = socks_connect(socks, *tcp.server_address[:2])
                with conn:
                    payload = bytes(i % 251 for i in range(32_768))
                    conn.sendall(payload)
                    assert exact(conn, len(payload)) == payload
                control, bound = socks_connect(socks, "0.0.0.0", 0, 3)
                with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(5)
                    endpoint = udp.server_address[:2]
                    data = b"windows-wintun-udp" * 53
                    client.sendto(b"\0\0\0" + encode_address(*endpoint) + data, ("127.0.0.1", bound[1]))
                    assert unpack_udp(client.recv(65_535)) == (endpoint, data)

        traffic()
        identity, rx, tx = show("transfer").split()
        assert identity == cpub and int(rx) > 0 and int(tx) > 0
        stamp = show("latest-handshakes")
        assert int(stamp.split()[1]) > 0
        editable = root / "sync.conf"
        editable.write_text(f"[Interface]\nPrivateKey = {skey}\nListenPort = {port}\n"
                            f"[Peer]\nPublicKey = {cpub}\nPresharedKey = {psk}\nAllowedIPs = {allowed}\n"
                            "PersistentKeepalive = 3\n", encoding="ascii", newline="\n")
        call(args.wg, "syncconf", name, editable)
        assert show("persistent-keepalive").split() == [cpub, "3"]
        traffic()
        assert show("latest-handshakes") == stamp
        print("PASS Windows Wintun: IPv4 and IPv6 TCP/UDP, production wg.exe show, set and syncconf", flush=True)


def egress_queue(stack):
    commands = ["tc", "-j", "qdisc", "show", "dev", "veth-left"]
    original = json.loads(call(*commands))
    assert [queue["kind"] for queue in original] == ["noqueue"]
    call("tc", "qdisc", "add", "dev", "veth-left", "root", "handle", "1:", "prio",
         "bands", "2", "priomap", *("0",) * 16)

    def restore():
        call("tc", "qdisc", "del", "dev", "veth-left", "root")
        assert json.loads(call(*commands)) == original

    stack.callback(restore)
    call("tc", "qdisc", "add", "dev", "veth-left", "parent", "1:2", "handle", "20:",
         "netem", "limit", "1024", "slot", "250us", "250us")

    def packets():
        stats = json.loads(call("tc", "-j", "-s", "qdisc", "show", "dev", "veth-left"))
        netem, = [queue for queue in stats if queue["kind"] == "netem"]
        assert netem["drops"] == 0, netem
        return netem["packets"]

    return packets


def run(args):
    outer = os.readlink("/proc/self/ns/net")
    if outer == os.readlink("/proc/1/ns/net"):
        raise SystemExit("run the WireGuard fixture inside a disposable network namespace (unshare --net)")
    with tempfile.TemporaryDirectory(prefix="kerlico-wireguard-keys-") as working, contextlib.ExitStack() as stack:
        root = Path(working)
        print(f"Fixture process logs: {args.logs}", flush=True)
        args.logs.mkdir(parents=True, exist_ok=True)
        call("ip", "link", "set", "lo", "up")
        ns = stack.enter_context(process(["unshare", "--net", "sleep", "220" if args.natural_rekey else "120"], args.logs, "namespace"))
        expect(ns, lambda: os.readlink(f"/proc/{ns.pid}/ns/net") != outer)
        right = ["nsenter", "-t", str(ns.pid), "-n"]
        call(*right, "ip", "link", "set", "lo", "up")
        call("ip", "link", "add", "veth-left", "type", "veth", "peer", "name", "veth-right")
        call("ip", "link", "set", "veth-right", "netns", str(ns.pid))
        if args.link_local:
            zones = []
            for prefix, iface, addr in (([], "veth-left", "fe80::a"), (right, "veth-right", "fe80::b")):
                call(*prefix, "ip", "link", "set", "dev", iface, "addrgenmode", "none", "up")
                call(*prefix, "ip", "-6", "addr", "add", f"{addr}/64", "dev", iface, "nodad")
                index = json.loads(call(*prefix, "ip", "-j", "link", "show", iface))[0]["ifindex"]
                zones.append(str(index) if args.link_local == "index" else iface)
            # Native exit detection requires non-loopback source addresses. Supply
            # them on a disconnected device so the carrier remains IPv6 link-local.
            call("ip", "link", "add", "native-test", "type", "dummy")
            call("ip", "link", "set", "native-test", "up")
            call("ip", "addr", "add", "192.0.2.1/24", "dev", "native-test")
            call("ip", "-6", "addr", "add", "2001:db8:38::1/64", "dev", "native-test", "nodad")
            call("ip", "route", "add", "default", "dev", "native-test")
            call("ip", "-6", "route", "add", "default", "dev", "native-test")
            scoped_peer = f"[fe80::b%{zones[0]}]:{PORT + 1}"
            raw_bind = f"[fe80::a%{zones[0]}]:{PORT}"
            endpoint = f"[fe80::a%{zones[1]}]:{PORT}"
        else:
            for prefix, iface, underlay in (([], "veth-left", LEFT), (right, "veth-right", RIGHT)):
                call(*prefix, "ip", "addr", "add", f"{underlay}/30", "dev", iface)
                call(*prefix, "ip", "link", "set", iface, "up")
            call("ip", "route", "add", "default", "via", RIGHT)
            call(*right, "ip", "route", "add", "default", "via", LEFT)
            call("ip", "-6", "addr", "add", "2001:db8:37::1/64", "dev", "veth-left", "nodad")
            call("ip", "-6", "route", "add", "default", "via", "2001:db8:37::2")
            call(*right, "ip", "-6", "addr", "add", "2001:db8:37::2/64", "dev", "veth-right", "nodad")
            call(*right, "ip", "-6", "route", "add", "default", "via", "2001:db8:37::1")
            endpoint = raw_bind = f"{LEFT}:{PORT}"
        spath, skey, spub = keypair(root, "server")
        cpath, ckey, cpub = keypair(root, "client")
        psk = call("wg", "genpsk")
        ppath = root / "psk"
        ppath.write_text(psk + "\n")
        allowed = f"{CLIENT4}/32,{CLIENT6}/128"
        address([], "lo", HOST4, HOST6)
        start_origins(stack)
        script = str(Path(__file__).resolve())
        uapi = args.direction in ("uapi", "uapi-background")
        multipeer = args.direction in ("multipeer", "multipeer-landing")
        landing = args.direction in ("landing", "multipeer-landing")
        paced_packets = None
        if args.direction in ("inbound", "xray-client", "raw") or uapi:
            settings = {"privateKey": skey, "users": [{"email": "kernel-peer", "publicKey": cpub,
                         "presharedKey": psk, "allowedIPs": allowed.split(",")}]}
            if args.link_local:
                settings["users"][0].update(endpoint=scoped_peer, persistentKeepalive=2)
            cfg = json_doc(root / "inbound.json", {"warp": {"secretKey": "invalid"}, "inbounds": [{"protocol": "wireguard", "tag": "test",
                           "listen": "::" if args.link_local else LEFT, "port": PORT, "outbound": "default", "settings": settings}]})
            if uapi:
                name = f"ktu{os.urandom(4).hex()}"
                control = Path(f"/run/wireguard/{name}.sock")
                def online():
                    return subprocess.run(["ip", "link", "show", name], stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL).returncode == 0
                if args.direction == "uapi-background":
                    call(args.raw, name)
                    server = None
                    stack.callback(lambda: control.unlink(missing_ok=True))
                    assert control.is_socket() and online(), "launcher exited before interface readiness"
                else:
                    server = stack.enter_context(process([args.raw, "--foreground", name], args.logs, "server"))
                    expect(server, lambda: control.is_socket() and online())
                assert control.stat().st_mode & 0o777 == 0o600
                assert "UP" not in json.loads(call("ip", "-j", "link", "show", name))[0]["flags"]
                assert call("wg", "show", name, "listen-port") == "0"
                peer_options = ["endpoint", scoped_peer, "persistent-keepalive", "2"] if args.link_local else []
                call("wg", "set", name, "private-key", spath, "listen-port", str(PORT),
                     "peer", cpub, "preshared-key", str(ppath), "allowed-ips", allowed, *peer_options)
                if args.link_local:
                    # wg may resolve the zone before sending it. Also exercise the
                    # production control reader with the zone exactly as configured.
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                        conn.settimeout(2)
                        conn.connect(str(control))
                        peer_hex = base64.b64decode(cpub).hex()
                        conn.sendall(f"set=1\npublic_key={peer_hex}\nendpoint={scoped_peer}\n\n".encode())
                        with conn.makefile("rb") as reply:
                            assert reply.readline() == b"errno=0\n" and reply.readline() == b"\n"
                    shown = call("wg", "show", name, "endpoints").split()[1]
                    assert shown.startswith("[fe80::b%") and shown.endswith(f"]:{PORT + 1}"), shown
                assert call("wg", "show", name, "public-key") == spub
                assert int(call("wg", "show", name, "listen-port")) == PORT
                assert not udp_port_open(PORT)
                call("ip", "link", "set", "dev", name, "up")
                wait_for(lambda: udp_port_open(PORT), "up did not bind configured port")
                uapi_stream(control, PORT)
                call("ip", "route", "add", f"{CLIENT4}/32", "dev", name)
                call("ip", "-6", "route", "add", f"{CLIENT6}/128", "dev", name)
            elif args.direction == "raw":
                who = dict(settings["users"][0])
                del who["email"]
                raw_options = {"privateKey": skey, "listen": raw_bind, "tun": "raw-wg", "peers": [who]}
                if args.linux_egress:
                    paced_packets = egress_queue(stack)
                    family = socket.AF_INET6 if args.link_local else socket.AF_INET
                    endpoint_plain = (
                        ("fe80::b", 53021, 0, socket.if_nametoindex("veth-left"))
                        if args.link_local else (RIGHT, 53021)
                    )
                    with socket.socket(family, socket.SOCK_DGRAM) as plain:
                        assert plain.sendto(b"ordinary", endpoint_plain) == 8
                    assert paced_packets() == 0
                    raw_options["egress"] = {"device": "veth-left", "class": "1:2"}
                cfg = json_doc(root / "raw.json", raw_options)
                server = stack.enter_context(process([args.raw, cfg], args.logs, "server"))
                expect(server, lambda: udp_port_open(PORT) and subprocess.run(
                    ["ip", "link", "show", "raw-wg"], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL).returncode == 0)
                call("ip", "route", "add", f"{CLIENT4}/32", "dev", "raw-wg")
                call("ip", "-6", "route", "add", f"{CLIENT6}/128", "dev", "raw-wg")
            else:
                server = stack.enter_context(process([args.server, cfg], args.logs, "server"))
                expect(server, lambda: udp_port_open(PORT))
            if args.direction == "xray-client":
                cfg = json_doc(root / "xray-client.json", {"log": {"loglevel": "warning"},
                    "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": SOCKS, "settings": {"udp": True}}],
                    "outbounds": [{"protocol": "wireguard", "settings": {"secretKey": ckey, "address": [CLIENT4, CLIENT6],
                        "noKernelTun": True, "peers": [{"publicKey": spub, "preSharedKey": psk, "endpoint": endpoint}]}}]})
                client = stack.enter_context(process([*right, args.xray, "run", "-c", cfg], args.logs, "client"))
                expect(client, lambda: socket_open(right, "tcp", SOCKS))
            else:
                kernel(right, "wg-test", cpath, spub, str(ppath), PORT + 1 if args.link_local else 0,
                       "0.0.0.0/0,::/0", None if args.link_local else endpoint)
                address(right, "wg-test", CLIENT4, CLIENT6)
                if args.link_local:
                    expect(server, lambda: int(call(*right, "wg", "show", "wg-test", "latest-handshakes").split()[1]) > 0)
                call(*right, "ip", "addr", "add", "10.201.0.112/32", "dev", "wg-test")
                call(*right, sys.executable, script, "reject")
                if args.direction == "raw" or uapi:
                    for host, af in ((HOST4, "-4"), (HOST6, "-6")):
                        call(*right, "ping", af, "-c", "2", "-W", "2", host)
        else:
            if args.direction == "xray-server":
                cfg = json_doc(root / "xray-server.json", {"log": {"loglevel": "warning"},
                    "inbounds": [{"protocol": "wireguard", "listen": LEFT, "port": PORT, "settings": {
                        "secretKey": skey, "address": ["10.201.0.253", "fd72:38ab:1::fd"], "noKernelTun": True,
                        "peers": [{"publicKey": cpub, "preSharedKey": psk, "allowedIPs": allowed.split(","),
                                   "email": "kerlico-peer"}]}}],
                    "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                        {"action": "allow", "network": "tcp,udp", "ip": [f"{HOST4}/32", f"{HOST6}/128"]}]}}]})
                server = stack.enter_context(process([args.xray, "run", "-c", cfg], args.logs, "server"))
                expect(server, lambda: socket_open([], "udp", PORT))
            elif multipeer:
                kernel([], "wg-test", spath, cpub, str(ppath), PORT, f"{CLIENT4}/32")
                v6path, _, v6pub = keypair(root, "server-v6")
                kernel([], "wg-v6", v6path, cpub, str(ppath), PORT + 1, f"{CLIENT6}/128")
                call("ip", "route", "add", f"{CLIENT4}/32", "dev", "wg-test")
                call("ip", "-6", "route", "add", f"{CLIENT6}/128", "dev", "wg-v6")
            else:
                kernel([], "wg-test", spath, cpub, "/dev/null" if args.direction == "warp" else str(ppath), PORT, allowed)
                # The addresses already live on lo, so only the return path uses wg-test.
                call("ip", "route", "add", f"{CLIENT4}/32", "dev", "wg-test")
                call("ip", "-6", "route", "add", f"{CLIENT6}/128", "dev", "wg-test")
            settings = {"secretKey": ckey, "publicKey": spub, "preSharedKey": psk,
                        "keepAlive": 2, "allowedIPs": [f"{HOST4}/32", f"{HOST6}/128"]}
            if multipeer:
                settings = {"secretKey": ckey, "peers": [
                    {"publicKey": spub, "preSharedKey": psk, "allowedIPs": ["0.0.0.0/0", "::/0"]},
                    {"publicKey": v6pub, "preSharedKey": psk, "allowedIPs": [f"{HOST6}/128"],
                     "endpoint": f"[2001:db8:37::1]:{PORT + 1}"}]}
            if landing or args.direction == "warp":
                password = base64.b64encode(os.urandom(16)).decode()
                ss = {"method": "2022-blake3-aes-128-gcm", "password": password}
                settings["localAddresses"] = [CLIENT4, CLIENT6]
                choice = "warp-v4" if args.direction == "warp" else "landing"
                document = {"inbounds": [{"protocol": "ss2022", "tag": "ingress", "listen": "127.0.0.1", "port": 9080,
                        "rules": [{"geoip": ["private"], "outbound": choice}],
                        "settings": {"method": ss["method"], "users": [{"email": "test", "password": password}]}}]}
                if args.direction == "warp":
                    start_udp_port_origins(stack)
                    document["warp"] = {"secretKey": ckey, "address": [CLIENT4, CLIENT6],
                                        "peers": [{"publicKey": spub, "endpoint": endpoint}]}
                else:
                    dns = start_dns(stack)
                    start_udp_port_origins(stack, dual=True)
                    document["warp"] = {"secretKey": "invalid"}
                    document["dns"] = {"queryStrategy": "UseIPv4",
                                       "servers": [{"address": HOST4, "port": DNS, "outbound": "landing"}]}
                    document["landing"] = {"protocol": "wireguard", "address": LEFT, "port": PORT, "settings": settings}
                cfg = json_doc(root / "landing.json", document)
                server = stack.enter_context(process([*right, args.server, cfg], args.logs, "landing"))
                expect(server, lambda: socket_open(right, "tcp", 9080))
                cfg = json_doc(root / "ss-client.json", {"protocol": "ss2022", "peer": "127.0.0.1:9080",
                               "settings": {**ss, "socks5Port": SOCKS}})
                client = stack.enter_context(process([*right, args.ss_client, cfg], args.logs, "client"))
                expect(client, lambda: socket_open(right, "tcp", SOCKS))
            else:
                if args.link_local == "index":
                    settings.update(address=endpoint[1:endpoint.index("]")], port=PORT)
                cfg = json_doc(root / "client.json", {"protocol": "wireguard", "peer": endpoint, "settings": settings})
                client = stack.enter_context(process([*right, args.client, "--tun", "wg-test", cfg], args.logs, "client"))
                expect(client, lambda: subprocess.run([*right, "ip", "link", "show", "wg-test"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
                address(right, "wg-test", CLIENT4, CLIENT6)
        mode = "landing-traffic" if landing else {
            "inbound": "fragments", "raw": "fragments", "uapi": "fragments", "uapi-background": "fragments",
            "warp": "warp-traffic", "xray-client": "socks"}.get(args.direction, "traffic")
        call(*right, sys.executable, script, mode)
        if paced_packets is not None:
            before_rebind = paced_packets()
            assert before_rebind > 0
            handles = (fd.readlink().name for fd in Path(f"/proc/{server.pid}/fd").iterdir())
            assert "anon_inode:bpf_link" in handles
            port = PORT + 6
            call("wg", "set", "raw-wg", "listen-port", str(port))
            assert call("wg", "show", "raw-wg", "listen-port") == str(port)
            endpoint = f"{endpoint.rsplit(':', 1)[0]}:{port}"
            call(*right, "wg", "set", "wg-test", "peer", spub, "endpoint", endpoint)
            call(*right, sys.executable, script, mode)
            assert paced_packets() > before_rebind
            print("PASS egress: ordinary UDP bypassed the slot; WireGuard used it before and after port change",
                  flush=True)
        if args.link_local:
            print(f"PASS {args.direction}: native peer over IPv6 link-local UDP with {args.link_local} zone", flush=True)
            return
        if args.direction == "outbound" and not args.natural_rekey:
            client_link_lifecycle(right)
        if uapi:
            stamp = call("wg", "show", name, "latest-handshakes")
            peer, rx, tx = call("wg", "show", name, "transfer").split()
            assert peer == cpub and int(rx) > 0 and int(tx) > 0 and int(stamp.split()[1]) > 0
            canonical_private_key(name, right, skey, root, script)
            occupied_listen_port(name)
            call("wg", "set", name, "peer", cpub, "allowed-ips", f"{allowed},10.219.7.0/24",
                 "peer", cpub, "persistent-keepalive", "3")
            assert "10.219.7.0/24" in call("wg", "show", name, "allowed-ips")
            assert call("wg", "show", name, "persistent-keepalive").split() == [cpub, "3"]
            call(*right, sys.executable, script, "keepalive")
            assert call("wg", "show", name, "latest-handshakes") == stamp
            call("wg", "set", name, "listen-port", str(PORT + 6), "fwmark", "0x12345")
            assert int(call("wg", "show", name, "listen-port")) == PORT + 6
            assert call("wg", "show", name, "fwmark") == "0x12345"
            call(*right, "wg", "set", "wg-test", "peer", spub, "endpoint", f"{LEFT}:{PORT + 6}")
            call(*right, sys.executable, script, "keepalive")
            rotate_preshared(name, right, cpub, spub, ppath, f"{LEFT}:{PORT + 6}", root, script)
            call("wg", "set", name, "peer", cpub, "remove")
            assert not call("wg", "show", name, "peers")
            call(*right, sys.executable, script, "blocked")
            cfg = root / "sync.conf"
            cfg.write_text(f"[Interface]\nPrivateKey = {skey}\nListenPort = {PORT+6}\n"
                           f"FwMark = 0x12345\n[Peer]\nPublicKey = {cpub}\nPresharedKey = {psk}\nAllowedIPs = {allowed}\n")
            call("wg", "syncconf", name, str(cfg))
            assert call("wg", "show", name, "peers") == cpub
            call(*right, "wg", "set", "wg-test", "peer", spub, "remove")
            call(*right, "wg", "set", "wg-test", "peer", spub, "preshared-key", str(ppath),
                 "endpoint", f"{LEFT}:{PORT + 6}", "allowed-ips", "0.0.0.0/0,::/0")
            call(*right, sys.executable, script, "traffic")
            link_lifecycle(name, right, cpub, spub, ppath, script, PORT + 6)
            control.unlink()
            if server:
                assert server.wait(timeout=3) == 0
            else:
                until = time.monotonic() + 3
                while online() and time.monotonic() < until:
                    time.sleep(0.02)
                assert not online(), "background TUN survived control socket removal"
            print(f"PASS {args.direction}: wg show, set, syncconf, live port and route changes, and shutdown", flush=True)
        if landing:
            assert all(server.hits > 0 for server in dns)
            print("PASS landing: dual-stack UDP port reuse, alternate reply, and remote DNS TCP fallback", flush=True)
        if args.direction == "warp":
            print("PASS warp: IPv4 TCP/UDP, single UDP source port and alternate reply", flush=True)
        if args.direction in ("inbound", "raw"):
            # Keep the established Noise session but switch its authenticated UDP endpoint.
            call(*right, "wg", "set", "wg-test", "listen-port", str(PORT + 4))
            call(*right, sys.executable, script, "traffic")
            # Replacing the native peer discards its session and forces a fresh handshake.
            call(*right, "wg", "set", "wg-test", "peer", spub, "remove")
            call(*right, "wg", "set", "wg-test", "peer", spub, "preshared-key", str(ppath),
                 "allowed-ips", "0.0.0.0/0,::/0", "endpoint", endpoint, "persistent-keepalive", "2")
            call(*right, sys.executable, script, "traffic")
            print(f"PASS {args.direction}: authenticated endpoint roaming and fresh handshake", flush=True)
        if landing or args.direction in ("inbound", "outbound", "multipeer", "raw", "warp"):
            wg_prefix = right if args.direction in ("inbound", "raw") else []
            assert int(call(*wg_prefix, "wg", "show", "wg-test", "latest-handshakes").split()[1]) > 0
        if multipeer:
            assert int(call("wg", "show", "wg-v6", "latest-handshakes").split()[1]) > 0
            endpoint_v4 = call("wg", "show", "wg-test", "endpoints").split()[1]
            endpoint_v6 = call("wg", "show", "wg-v6", "endpoints").split()[1]
            host_v4, _, port_v4 = endpoint_v4.rpartition(":")
            host_v6, _, port_v6 = endpoint_v6.rpartition(":")
            assert host_v4 == RIGHT and host_v6 == "[2001:db8:37::2]", (endpoint_v4, endpoint_v6)
            assert port_v4 == port_v6, "IPv4 and IPv6 peers saw different WireGuard listen ports"
            stamp = call("wg", "show", "wg-test", "latest-handshakes")
            time.sleep(1.1)
            # The original IPv4 endpoint stops listening. The kernel peer sends
            # authenticated traffic from an IPv6 address and its new port.
            call("wg", "set", "wg-test", "listen-port", str(PORT + 4),
                 "peer", cpub, "endpoint", endpoint_v6, "persistent-keepalive", "1")
            if not landing:
                call("ping", "-4", "-I", HOST4, "-c", "2", "-W", "2", CLIENT4)
            call(*right, sys.executable, script, mode)
            assert call("wg", "show", "wg-test", "latest-handshakes") == stamp, "roaming forced a new handshake"
            assert call("wg", "show", "wg-test", "endpoints").split()[1] == endpoint_v6
            print(f"PASS {args.direction}: shared listen port and authenticated IPv4 to IPv6 roaming", flush=True)
        if args.natural_rekey:
            wg_prefix = right if args.direction == "inbound" else []
            def stamp():
                return int(call(*wg_prefix, "wg", "show", "wg-test", "latest-handshakes").split()[1])
            initial = stamp()
            until = time.monotonic() + 155
            while stamp() <= initial and time.monotonic() < until:
                call(*right, sys.executable, script, "keepalive")
                time.sleep(2)
            assert stamp() > initial, "the initiator did not rekey while sending"
            print(f"PASS {args.direction}: natural rekey with live UDP", flush=True)
        if args.direction != "warp":
            print(f"PASS {args.direction}: PSK, TCP and UDP over IPv4 and IPv6", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("direction", choices=("inbound", "outbound", "landing", "xray-server", "xray-client", "multipeer", "multipeer-landing", "raw", "uapi", "uapi-background", "warp", "portable", "windows-tun",
                                              "traffic", "reject", "socks", "fragments", "landing-traffic", "warp-traffic", "keepalive", "blocked"))
    parser.add_argument("--client", type=Path)
    parser.add_argument("--server", type=Path)
    parser.add_argument("--xray", type=Path)
    parser.add_argument("--wg", type=Path)
    parser.add_argument("--ss-client", type=Path)
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--logs", type=Path)
    parser.add_argument("--origin-host", help="local private IPv4 address for the portable origin")
    parser.add_argument("--natural-rekey", action="store_true")
    parser.add_argument("--link-local", nargs="?", const="name", choices=("name", "index"))
    parser.add_argument("--linux-egress", action="store_true")
    options = parser.parse_args()
    if options.linux_egress and options.direction != "raw":
        parser.error("--linux-egress requires raw")
    if options.natural_rekey and options.direction not in ("inbound", "outbound"):
        parser.error("--natural-rekey requires inbound or outbound")
    if options.link_local and (options.natural_rekey or options.direction not in ("inbound", "outbound", "raw", "uapi")):
        parser.error("--link-local requires inbound, outbound, raw or uapi without --natural-rekey")
    if options.direction == "windows-tun":
        for arg in ("raw", "wg", "xray", "logs"):
            value = getattr(options, arg)
            if value is None:
                parser.error(f"windows-tun requires --{arg}")
            setattr(options, arg, value.resolve())
        windows_tun(options)
    elif options.direction == "portable":
        for arg in ("xray", "server", "ss_client", "logs"):
            value = getattr(options, arg)
            if value is None:
                parser.error(f"portable requires --{arg.replace('_', '-')}")
            setattr(options, arg, value.resolve())
        portable(options)
    elif options.direction in ("traffic", "fragments"):
        load(HOST4, fragments=options.direction == "fragments")
        load(HOST6, fragments=options.direction == "fragments")
    elif options.direction in ("socks", "landing-traffic"):
        through_socks(HOST4, options.direction == "landing-traffic")
        through_socks(HOST6, options.direction == "landing-traffic")
        if options.direction == "landing-traffic":
            check_udp_ports(dual=True)
            conn, _ = socks_connect(SOCKS, "origin.test", ECHO)
            with conn:
                conn.sendall(b"dns-via-wireguard")
                assert exact(conn, 17) == b"dns-via-wireguard"
    elif options.direction == "reject":
        load(HOST4, require_udp_failure=True)
    elif options.direction == "warp-traffic":
        through_socks(HOST4, fragments=True)
        check_udp_ports()
    elif options.direction in ("keepalive", "blocked"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.65 if options.direction == "blocked" else 3)
            data = b"live-wireguard-rekey"
            sock.sendto(data, (HOST4, ECHO))
            try:
                assert sock.recv(256) == data and options.direction != "blocked"
            except TimeoutError:
                if options.direction != "blocked":
                    raise
    else:
        run(options)
