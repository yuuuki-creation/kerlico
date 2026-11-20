#!/usr/bin/env python3
"""Run the two Kerlico leaves against the pinned Hysteria 2 release on loopback."""

import argparse
import contextlib
import hashlib
import select
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import verify_mieru as fixtures
from verify_vless_client import associate, exchange

VERSION = "v2.14.0"
COMMIT = "c2b181e0b0e72b077e4b0b7297735af14d1f9929"
PASSWORD = "test-user:interop-secret"


def verify_peer(path):
    version = subprocess.check_output([path, "version"], text=True, timeout=10)
    fixtures.require(VERSION in version and COMMIT in version, "unexpected Hysteria peer version")


def make_identity(folder):
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-pkeyopt", "ec_param_enc:named_curve",
                    "-nodes", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                    "-days", "1", "-out", cert, "-keyout", key], check=True, timeout=10,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    return cert, key, hashlib.sha256(der).hexdigest()


def official_server(paths, config, port, identity, udp=True, extra=None, listen="127.0.0.1"):
    cert, key, _ = identity
    fixtures.write_json(config, {
        "listen": f"[{listen}]:{port}" if ":" in listen else f"{listen}:{port}",
        "tls": {"cert": str(cert), "key": str(key)},
        "auth": {"type": "userpass", "userpass": {"test-user": "interop-secret"}}, "disableUDP": not udp,
        **(extra or {}),
    })
    return [paths.hysteria, "server", "-c", config]


def kerlico_server(paths, config, port, identity, udp=True, landing=None, extra=None):
    cert, key, pin = identity
    settings = {"certificateFile": str(cert), "privateKeyFile": str(key), "udp": udp,
                "users": [{"email": "test-user", "password": PASSWORD}], **(extra or {})}
    inbound = {"tag": "test", "protocol": "hy2", "listen": "127.0.0.1", "port": port,
               "outbound": "native-v4", "settings": settings}
    root = {"inbounds": [inbound], "warp": {"secretKey": "invalid"}}
    if landing is not None:
        inbound["rules"] = [{"geoip": ["private"], "outbound": "landing"}]
        root["landing"] = {"protocol": "hy2", "address": "127.0.0.1", "port": landing,
                           "settings": {"serverName": "localhost", "password": PASSWORD,
                                        "tls": {"pinnedPeerCertSha256": pin}}}
    fixtures.write_json(config, root)
    return [paths.server, config]


def official_client(paths, config, upstream, socks, http, identity, password, extra=None):
    cert, _, _ = identity
    fixtures.write_json(config, {
        "server": f"127.0.0.1:{upstream}", "auth": password, "tls": {"sni": "localhost", "ca": str(cert)},
        "socks5": {"listen": f"127.0.0.1:{socks}"}, "http": {"listen": f"127.0.0.1:{http}"},
        "lazy": True, **(extra or {}),
    })
    return [paths.hysteria, "client", "-c", config]


def kerlico_client(paths, config, upstream, socks, http, identity, password, extra=None, peer="127.0.0.1"):
    _, _, pin = identity
    fixtures.write_json(config, {
        "protocol": "hy2", "peer": f"{peer}:{upstream}", "settings": {
            "serverName": "localhost", "password": password, "socks5Port": socks, "httpProxyPort": http,
            "tls": {"pinnedPeerCertSha256": pin}, **(extra or {}),
        },
    })
    return [paths.client, config]


def tcp_payload(port, origin):
    with contextlib.closing(fixtures.socks_connect(port, "127.0.0.1", origin)[0]) as conn:
        payload = bytes(i % 251 for i in range(192 * 1024 + 5))
        conn.sendall(payload)
        fixtures.require(fixtures.exact(conn, len(payload)) == payload, "TCP payload differs")


def http_connect(port, origin):
    with socket.create_connection(("127.0.0.1", port), 5) as conn:
        target = f"127.0.0.1:{origin}"
        conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        reply = bytearray()
        while not reply.endswith(b"\r\n\r\n"):
            fixtures.require(len(reply) < 16384, "HTTP CONNECT response headers too large")
            reply.extend(fixtures.exact(conn, 1))
        fixtures.require(reply.split(b"\r\n", 1)[0].split()[1] == b"200", "HTTP CONNECT failed")
        payload = b"HTTP CONNECT over Hy2\0and a binary byte\xff"
        conn.sendall(payload)
        fixtures.require(fixtures.exact(conn, len(payload)) == payload, "HTTP CONNECT payload differs")


class ReplyAfterFin(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytearray()
        try:
            while chunk := self.request.recv(4096):
                data.extend(chunk)
            self.request.sendall(b"after FIN: " + data)
        except ConnectionResetError:
            # A peer without half-close can reset the socket before the reply.
            pass


def tcp_half_close(port, origin):
    with contextlib.closing(fixtures.socks_connect(port, "127.0.0.1", origin)[0]) as conn:
        data = b"request with a write close"
        conn.sendall(data)
        conn.shutdown(socket.SHUT_WR)
        answer = b"after FIN: " + data
        fixtures.require(fixtures.exact(conn, len(answer)) == answer, "TCP half-close lost the reply")
        fixtures.require(conn.recv(1) == b"", "TCP half-close lost the final FIN")


def udp_payload(port, origins):
    control, client, addr = associate(port)
    with control, client:
        for size, target in [(32, origins[0]), (3_900, origins[0]), (48, origins[1]), (4_000, origins[1]), (18, origins[0])]:
            exchange(client, addr, "127.0.0.1", target, bytes(i % 251 for i in range(size)))


class SourcePort(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(struct.pack("!H", self.client_address[1]) + data, self.client_address)


@contextlib.contextmanager
def datagram_origins(origins):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as alternate:
        class AlternateReply(socketserver.BaseRequestHandler):
            def handle(self):
                alternate.sendto(self.request[0], self.client_address)

        alternate.bind(("127.0.0.1", 0))
        origins.udp_alternate = alternate
        origins.udp_relay = origins.add(fixtures.SequentialUDP, "127.0.0.1", AlternateReply, "udp-alternate")
        origins.udp_source = [origins.add(fixtures.SequentialUDP, "127.0.0.1", SourcePort, f"udp-source-{index}")
                              for index in range(2)]
        yield


def udp_source_port(socks, origins):
    control, udp, bound = associate(socks)
    with control, udp:
        udp.settimeout(4)
        ports = []
        for index, target in enumerate(origins.udp_source):
            host, port = target.server_address
            data = bytes([index])
            udp.sendto(b"\0\0\0" + fixtures.encode_address(host, port) + data, bound)
            source, reply = fixtures.unpack_udp(udp.recv(65535))
            fixtures.require(source == (host, port) and reply[2:] == data, "incorrect UDP source or payload")
            ports.append(struct.unpack("!H", reply[:2])[0])
        return ports[0] == ports[1]


def udp_alternate_reply(socks, origins):
    control, udp, bound = associate(socks)
    with control, udp:
        udp.settimeout(4)
        data = b"reply-from-another-port"
        udp.sendto(b"\0\0\0" + fixtures.encode_address(*origins.udp_relay.server_address) + data, bound)
        source, got = fixtures.unpack_udp(udp.recv(65535))
        fixtures.require(source == origins.udp_alternate.getsockname() and got == data,
                         "the alternate UDP reply did not keep its real source")


def rejected(port, target):
    with socket.create_connection(("127.0.0.1", port), 3) as conn:
        conn.settimeout(12)
        conn.sendall(b"\x05\x01\x00")
        fixtures.require(fixtures.exact(conn, 2) == b"\x05\x00", "SOCKS frontend unavailable")
        conn.sendall(b"\x05\x01\x00" + fixtures.encode_address("127.0.0.1", target))
        answer = conn.recv(3)
        fixtures.require(not answer or answer[:2] != b"\x05\x00", "SOCKS accepted a rejected request")


class UdpRelay:
    """Loopback port forwarding. Keep one upstream socket per client address."""

    def __init__(self, upstream):
        self.ingress = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ingress.bind(("127.0.0.1", 0))
        self.port = self.ingress.getsockname()[1]
        self.upstream = upstream
        self.hits = set()
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        sockets = {}
        reverse = {}
        try:
            while not self.closed.is_set():
                ready, _, _ = select.select([self.ingress, *reverse], [], [], 0.1)
                for incoming in ready:
                    if incoming == self.ingress:
                        wire, client = incoming.recvfrom(65536)
                        self.hits.add(client)
                        if client not in sockets:
                            socket_ = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            socket_.connect(("127.0.0.1", self.upstream))
                            sockets[client] = socket_
                            reverse[socket_] = client
                        sockets[client].send(wire)
                    else:
                        self.ingress.sendto(incoming.recv(65536), reverse[incoming])
        finally:
            for socket_ in reverse:
                socket_.close()

    def close(self):
        self.closed.set()
        self.thread.join(2)
        self.ingress.close()


def hop_case(paths, root, identity, origins):
    folder = root / "port-hopping"
    folder.mkdir()
    upstream, = fixtures.free_ports(1, kind=socket.SOCK_DGRAM)
    socks, http = fixtures.free_ports(2)
    server_cmd = official_server(paths, folder / "server.json", upstream, identity)
    with fixtures.managed(server_cmd, folder, "server") as server, \
            contextlib.closing(UdpRelay(upstream)) as first, contextlib.closing(UdpRelay(upstream)) as second:
        fixtures.wait_for(server, lambda: "server up" in server.text().lower())
        client_cmd = kerlico_client(paths, folder / "client.json", first.port, socks, http, identity, PASSWORD,
                                    extra={"hopPorts": f"{first.port},{second.port}", "hopInterval": 5})
        with fixtures.managed(client_cmd, folder, "client") as client:
            fixtures.wait_for(client, lambda: fixtures.ports_ready([socks, http]))
            origin = origins.tcp4.server_address[1]
            with contextlib.closing(fixtures.socks_connect(socks, "127.0.0.1", origin)[0]) as conn:
                for i in range(14):
                    token = f"round {i}".encode()
                    conn.sendall(token)
                    fixtures.require(fixtures.exact(conn, len(token)) == token, "stream lost across a port hop")
                    time.sleep(0.6)
            fixtures.require(first.hits and second.hits and first.hits.isdisjoint(second.hits),
                             "the same QUIC stream did not migrate to a new local and remote port")
    print("PASS port-hopping", flush=True)


def run(paths, root, identity, origins, name, server_factory, client_factory, *, landing=None, udp=True,
        server_extra=None, client_extra=None, wrong_password=True, half_close=False, ipv6=False, udp_session=False):
    folder = root / name
    folder.mkdir()
    family, listen = (socket.AF_INET6, "::1") if ipv6 else (socket.AF_INET, "127.0.0.1")
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.bind((listen, 0))
        upstream = probe.getsockname()[1]
    socks, http = fixtures.free_ports(2)
    target = origins.tcp4.server_address[1]
    server_config = folder / "server.json"
    command = server_factory(paths, server_config, upstream, identity, udp=udp, extra=server_extra,
                             **({"landing": landing} if landing else {}), **({"listen": listen} if ipv6 else {}))
    with fixtures.managed(command, folder, "server") as server:
        def bound():
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind((listen, upstream))
                    return False
                except OSError:
                    return True
        fixtures.wait_for(server, bound)
        peer_options = {}
        if ipv6:
            for hostname in ("localhost", "ip6-localhost"):
                try:
                    addresses = socket.getaddrinfo(hostname, upstream, type=socket.SOCK_DGRAM)
                except socket.gaierror:
                    continue
                if any(address[4][0] == "::1" for address in addresses):
                    peer_options["peer"] = hostname
                    break
            fixtures.require(peer_options, "no hostname resolves to IPv6 loopback")
        command = client_factory(paths, folder / "client.json", upstream, socks, http, identity, PASSWORD,
                                 extra=client_extra, **peer_options)
        with fixtures.managed(command, folder, "client") as client:
            fixtures.wait_for(client, lambda: fixtures.ports_ready([socks, http]))
            tcp_payload(socks, target)
            http_connect(http, target)
            if half_close:
                fin = origins.add(fixtures.ThreadedTCP, "127.0.0.1", ReplyAfterFin, "after-fin")
                try:
                    tcp_half_close(socks, fin.server_address[1])
                except (fixtures.Failure, OSError):
                    if server_factory is not official_server:
                        raise
                    print(f"OBSERVED {name}: official peer did not preserve half-close", flush=True)
            unused, = fixtures.free_ports(1)
            rejected(socks, unused)
            if udp:
                udp_payload(socks, [origins.udp4.server_address[1], origins.udp4b.server_address[1]])
                if udp_session:
                    fixtures.require(udp_source_port(socks, origins), "Hy2 UDP session split across source ports")
                    udp_alternate_reply(socks, origins)
            else:
                try:
                    control, client_udp, _ = associate(socks)
                except fixtures.Failure:
                    pass
                else:
                    control.close()
                    client_udp.close()
                    raise fixtures.Failure("server advertised UDP despite disabling it")
        if wrong_password:
            wrong_socks, wrong_http = fixtures.free_ports(2)
            command = client_factory(paths, folder / "wrong.json", upstream, wrong_socks, wrong_http,
                                     identity, "wrong-password", extra=client_extra)
            with fixtures.managed(command, folder, "wrong") as client:
                fixtures.wait_for(client, lambda: fixtures.ports_ready([wrong_socks]))
                hits = origins.tcp4.count
                rejected(wrong_socks, target)
                fixtures.require(origins.tcp4.count == hits, "invalid credentials reached the origin")
    print(f"PASS {name}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hysteria", "client", "server"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).resolve(), required=True)
    parser.add_argument("--obfs-only", action="store_true")
    args = parser.parse_args()
    verify_peer(args.hysteria)
    root = Path(tempfile.mkdtemp(prefix="kerlico-hy2-peer-"))
    print(f"Logs: {root}", flush=True)
    identity = make_identity(root)
    with fixtures.Fixtures() as origins, datagram_origins(origins):
        for mode in ("salamander", "gecko"):
            key = "obfs-test-password"
            official = {"obfs": {"type": mode, mode: {"password": key}}}
            kerlico = {"obfs": {"type": mode, "password": key}}
            run(args, root, identity, origins, f"{mode}-official-to-kerlico", kerlico_server, official_client,
                server_extra=kerlico, client_extra=official, wrong_password=False)
            run(args, root, identity, origins, f"{mode}-kerlico-to-official", official_server, kerlico_client,
                server_extra=official, client_extra=kerlico, wrong_password=False)
        if args.obfs_only:
            return
        run(args, root, identity, origins, "official-control", official_server, official_client,
            udp_session=True, half_close=True)
        run(args, root, identity, origins, "official-to-kerlico", kerlico_server, official_client, udp_session=True)
        run(args, root, identity, origins, "kerlico-to-official", official_server, kerlico_client, half_close=True)
        run(args, root, identity, origins, "hostname-to-ipv6-official", official_server, kerlico_client,
            ipv6=True, wrong_password=False)
        run(args, root, identity, origins, "kerlico-udp-disabled", kerlico_server, kerlico_client, udp=False)
        run(args, root, identity, origins, "kerlico-half-close", kerlico_server, kerlico_client,
            half_close=True, wrong_password=False)
        run(args, root, identity, origins, "brutal-kerlico-to-official", official_server, kerlico_client,
            server_extra={"bandwidth": {"up": "50 mbps", "down": "50 mbps"}},
            client_extra={"sendRate": 5_000_000, "receiveRate": 5_000_000}, wrong_password=False)
        back, = fixtures.free_ports(1, kind=socket.SOCK_DGRAM)
        with fixtures.managed(official_server(args, root / "origin.json", back, identity), root, "landing-target") as peer:
            fixtures.wait_for(peer, lambda: "server up" in peer.text().lower())
            run(args, root, identity, origins, "kerlico-hy2-landing", kerlico_server, official_client,
                landing=back, udp_session=True)
        hop_case(args, root, identity, origins)


if __name__ == "__main__":
    main()
