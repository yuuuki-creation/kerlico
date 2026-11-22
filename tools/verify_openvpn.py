#!/usr/bin/env python3
"""Check real OpenVPN peers on Linux TUN devices or macOS pseudo-terminals."""
import argparse
import contextlib
import hashlib
import json
import os
import pty
from pathlib import Path
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import time
import tty

import verify_mieru as fixtures

SERVER = "10.73.10.1"
CLIENT = "10.73.10.2"
ORIGIN = "192.0.2.17"
NETWORK = "10.73.11.0"
GATEWAY = "10.73.11.1"
TUN = "tun-ovtest"
NS = "ovpn-client"


def command(*args):
    return subprocess.check_output(args, text=True, timeout=15)


def identities(root):
    def run(*args):
        subprocess.run(["openssl", *args], cwd=root, check=True, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    run("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=kerlico-openvpn-test-ca", "-addext", "basicConstraints=critical,CA:true",
        "-keyout", "ca.key", "-out", "ca.pem")
    for role, purpose in [("server", "serverAuth"), ("client", "clientAuth"), ("other", "clientAuth")]:
        (root / "leaf.ext").write_text(
            f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
            f"extendedKeyUsage={purpose}\nsubjectAltName=DNS:localhost,IP:{SERVER}\n"
        )
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={role}",
            "-keyout", f"{role}.key", "-out", f"{role}.csr")
        run("x509", "-req", "-in", f"{role}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "2", "-extfile", "leaf.ext", "-out", f"{role}.pem")


def settings(root, role, transport):
    return {
        "certificate": (root / f"{role}.pem").read_text(),
        "privateKey": (root / f"{role}.key").read_text(),
        "ca": (root / "ca.pem").read_text(),
        "transport": transport,
    }


def stock(args, root, role, transport, port, cert=None, host=SERVER, device=None):
    cert = cert or role
    network = transport + ("6" if ":" in host else "")
    proto = f"{network}-{role}" if transport == "tcp" else network
    common = [args.openvpn, "--proto", proto, "--dev", TUN, "--ca", root / "ca.pem",
              "--cert", root / f"{cert}.pem", "--key", root / f"{cert}.key",
              "--data-ciphers", "AES-256-GCM", "--disable-dco", "--reneg-sec", "0", "--verb", "4"]
    if device:
        common += ["--dev-node", device, "--ifconfig-noexec", "--route-noexec"]
    if role == "server":
        return common + ["--local", host, "--port", str(port), "--server", NETWORK, "255.255.255.0",
                         "--topology", "subnet", "--dh", "none", "--remote-cert-tls", "client",
                         "--keepalive", "10", "60"]
    return common + ["--client", "--remote", host, str(port), "--nobind", "--route-noexec",
                     "--remote-cert-tls", "server", "--connect-retry-max", "1"]


def kerlico(args, root, folder, role, transport, port, host=SERVER):
    setup = settings(root, role, transport)
    path = folder / f"kerlico-{role}.json"
    if role == "client":
        setup["serverName"] = "localhost"
        fixtures.write_json(path, {"protocol": "openvpn", "peer": fixtures.authority(host, port), "settings": setup})
        return [args.client, "--tun", TUN, path]
    if transport == "udp" and getattr(args, "udp_client_receive_buffer", None) is not None:
        setup["udpClientReceiveBuffer"] = args.udp_client_receive_buffer
    der = ssl.PEM_cert_to_DER_cert((root / "client.pem").read_text())
    setup.update(subnet=f"{GATEWAY}/24", users=[{
        "email": "client", "address": "10.73.11.2", "certificateSha256": hashlib.sha256(der).hexdigest(),
    }])
    fixtures.write_json(path, {"warp": {"secretKey": "invalid"}, "inbounds": [{
        "tag": "test", "protocol": "openvpn", "listen": host, "port": port,
        "outbound": "native-v4", "settings": setup,
    }]})
    return [args.server, path]


def probe(tcp, udp):
    with socket.create_connection((ORIGIN, tcp), timeout=5) as conn:
        payload = bytes(range(251)) * 257
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        assert fixtures.exact(conn, len(payload)) == payload
        assert conn.recv(1) == b""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        for size in (1, 511, 1200, 0, 16):
            payload = bytes(i % 251 for i in range(size))
            sock.sendto(payload, (ORIGIN, udp))
            got, source = sock.recvfrom(4096)
            assert (got, source) == (payload, (ORIGIN, udp))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.settimeout(5)
            sock.sendto(b"first source port", (ORIGIN, udp))
            other.sendto(b"second source port", (ORIGIN, udp))
            assert sock.recvfrom(4096) == (b"first source port", (ORIGIN, udp))
            assert other.recvfrom(4096) == (b"second source port", (ORIGIN, udp))


def interface_ready(*prefix):
    result = subprocess.run([*prefix, "ip", "-j", "address", "show", "dev", TUN],
                            capture_output=True, text=True, timeout=5)
    if result.returncode:
        return False
    info = json.loads(result.stdout)[0]
    return any(address["family"] == "inet" for address in info.get("addr_info", []))


def run(args, root, origins, transport, stock_client):
    label = f"{'stock-client' if stock_client else 'stock-server'}-{transport}"
    folder = root / label
    folder.mkdir(mode=0o700)
    kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    port, = fixtures.free_ports(1, kind, SERVER)
    if stock_client:
        server = kerlico(args, root, folder, "server", transport, port)
        client = stock(args, root, "client", transport, port)
    else:
        server = stock(args, root, "server", transport, port)
        client = kerlico(args, root, folder, "client", transport, port)
    prefix = ["ip", "netns", "exec", NS]
    with fixtures.managed(server, folder, "server") as listener:
        if stock_client:
            fixtures.wait_for(listener, lambda: "openvpn" in listener.text().splitlines())
        else:
            fixtures.wait_for(listener, lambda: interface_ready() and "Initialization Sequence Completed" in listener.text())
        with fixtures.managed(prefix + client, folder, "client") as dialer:
            fixtures.wait_for(dialer, lambda: interface_ready(*prefix))
            command(*prefix, "ip", "route", "replace", f"{ORIGIN}/32", "dev", TUN)
            command(*prefix, sys.executable, str(Path(__file__).resolve()), "--probe",
                    str(origins.tcp.server_address[1]), str(origins.udp.server_address[1]))
            dialer.ensure_alive()
        if stock_client:
            bad = stock(args, root, "client", transport, port, "other")
            with fixtures.managed(prefix + bad + ["--hand-window", "5"], folder, "unregistered") as rejected:
                try:
                    status = rejected.process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    raise AssertionError("unregistered client did not terminate")
                assert status != 0 and "Initialization Sequence Completed" not in rejected.text()
        listener.ensure_alive()
    print(f"PASS {label}: TCP payload and FIN, UDP payload and source", flush=True)


@contextlib.contextmanager
def packet_device():
    master, slave = pty.openpty()
    try:
        tty.setraw(slave)
        yield master, os.ttyname(slave)
    finally:
        os.close(master)
        os.close(slave)


def ip_udp(source, destination, source_port, dest_port, payload):
    source, destination = socket.inet_aton(source), socket.inet_aton(destination)
    datagram = struct.pack("!4H", source_port, dest_port, len(payload) + 8, 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(datagram), 7, 0, 64, 17, 0, source, destination)
    checksum = sum(struct.unpack("!10H", header))
    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = (checksum & 0xffff) + (checksum >> 16)
    return header[:10] + struct.pack("!H", ~checksum & 0xffff) + header[12:] + datagram


def read_ip(device):
    packet = bytearray()
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        length = struct.unpack_from("!H", packet, 2)[0] if len(packet) >= 4 else 4
        if 20 <= length == len(packet):
            return bytes(packet)
        ready, _, _ = select.select([device], [], [], max(0, deadline - time.monotonic()))
        if ready:
            packet.extend(os.read(device, length - len(packet)))
    raise TimeoutError("no complete IP packet from official OpenVPN")


def macos(args, root):
    identities(root)
    carrier = "::1"
    address = "127.0.0.1"
    tunnel_ip = "10.73.11.2"
    source_port = 40123
    payload = b"encrypted IPv4 datagram" * 8
    with fixtures.Fixtures() as origins:
        echo = origins.add(socketserver.UDPServer, address, fixtures.EchoUDP, "openvpn-udp")
        for transport in ("tcp", "udp"):
            kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
            for stock_client in (True, False):
                label = f"{'stock-client' if stock_client else 'stock-server'}-{transport}"
                folder = root / label
                folder.mkdir(mode=0o700)
                port, = fixtures.free_ports(1, kind, carrier)
                dest_port = echo.server_address[1]
                outgoing = ip_udp(tunnel_ip, address, source_port, dest_port, payload)
                reply = ip_udp(address, tunnel_ip, dest_port, source_port, payload)
                with packet_device() as (device, path):
                    if stock_client:
                        server = kerlico(args, root, folder, "server", transport, port, carrier)
                        client = stock(args, root, "client", transport, port, host=carrier, device=path)
                        with fixtures.managed(server, folder, "server") as listener:
                            fixtures.wait_for(listener, lambda: "openvpn" in listener.text().splitlines())
                            with fixtures.managed(client, folder, "client") as dialer:
                                fixtures.wait_for(dialer, lambda: "Initialization Sequence Completed" in dialer.text(),
                                                  seconds=15)
                                assert os.write(device, outgoing) == len(outgoing)
                                response = read_ip(device)
                                assert response[12:20] == reply[12:20] and response[20:24] == reply[20:24]
                                assert response[28:] == payload
                                dialer.ensure_alive()
                    else:
                        server = stock(args, root, "server", transport, port, host=carrier, device=path)
                        kerlico(args, root, folder, "client", transport, port, carrier)
                        (folder / "outgoing.ip").write_bytes(outgoing)
                        (folder / "expected.ip").write_bytes(reply)
                        env = {**os.environ, "KERLICO_OPENVPN_PACKET_FIXTURE": str(folder)}
                        with fixtures.managed(server, folder, "server") as listener:
                            fixtures.wait_for(listener, lambda: "Initialization Sequence Completed" in listener.text())
                            with fixtures.managed([args.packet_probe, "--ignored", "--nocapture"], folder, "client", env=env) as dialer:
                                assert read_ip(device) == outgoing
                                assert os.write(device, reply) == len(reply)
                                assert dialer.process.wait(timeout=7) == 0, dialer.text()
                print(f"PASS {label}: authenticated UDP payload and source via the native packet plane", flush=True)


@contextlib.contextmanager
def linux_network():
    command("ip", "link", "set", "lo", "up")
    command("ip", "address", "add", f"{ORIGIN}/32", "dev", "lo")
    command("mount", "-t", "tmpfs", "tmpfs", "/run/netns")
    command("ip", "netns", "add", NS)
    try:
        command("ip", "link", "add", "ovtest-a", "type", "veth", "peer", "name", "ovtest-b", "netns", NS)
        command("ip", "-n", NS, "link", "set", "lo", "up")
        for prefix, address, interface, gateway in [
            (["ip"], SERVER, "ovtest-a", CLIENT),
            (["ip", "-n", NS], CLIENT, "ovtest-b", SERVER),
        ]:
            command(*prefix, "address", "add", f"{address}/30", "dev", interface)
            command(*prefix, "link", "set", interface, "up")
            command(*prefix, "route", "add", "default", "via", gateway)
        yield ["ip", "netns", "exec", NS]
    finally:
        command("ip", "netns", "delete", NS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path)
    parser.add_argument("--server", type=Path)
    parser.add_argument("--openvpn", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--udp-client-receive-buffer", type=int, help="rcvbuf byte count pushed by the Kerlico UDP server")
    parser.add_argument("--packet-probe", type=Path, help="ignored openvpn_packets test executable for macOS")
    parser.add_argument("--probe", nargs=2, type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.udp_client_receive_buffer is not None and not 0 <= args.udp_client_receive_buffer < 2**31:
        parser.error("--udp-client-receive-buffer must be between 0 and 2147483647 bytes")
    if args.probe:
        probe(*args.probe)
        return
    if not all([args.client, args.server, args.openvpn, args.output]):
        parser.error("client, server, openvpn and output are required")
    for name in ["client", "server", "openvpn", "output"]:
        setattr(args, name, getattr(args, name).resolve())
    if sys.platform == "darwin" and args.packet_probe:
        args.packet_probe = args.packet_probe.resolve()
        args.output.mkdir(mode=0o700, parents=True)
        macos(args, args.output)
        return
    if sys.platform != "linux":
        parser.error("macOS needs --packet-probe or run on Linux with TUN privileges")
    if os.environ.get("KERLICO_OPENVPN_TEST_NS") != "1":
        os.execvp("unshare", ["unshare", "--net", "--mount", "--propagation", "private",
                  "env", "KERLICO_OPENVPN_TEST_NS=1", sys.executable, *sys.argv])
    with linux_network(), fixtures.Fixtures() as origins:
        args.output.mkdir(mode=0o700, parents=True)
        identities(args.output)
        origins.tcp = origins.add(fixtures.ThreadedTCP, ORIGIN, fixtures.EchoTCP, "openvpn-tcp")
        origins.udp = origins.add(socketserver.UDPServer, ORIGIN, fixtures.EchoUDP, "openvpn-udp")
        for transport in ("tcp", "udp"):
            for stock_client in (True, False):
                run(args, args.output, origins, transport, stock_client)


if __name__ == "__main__":
    main()
