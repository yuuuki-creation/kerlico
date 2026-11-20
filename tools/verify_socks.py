#!/usr/bin/env python3
"""Exercise SOCKS5 on local loopback with independent TCP and UDP endpoints."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import ipaddress
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from verify_mieru import use_loopback_v6


def exact(conn, size):
    out = bytearray()
    while len(out) < size:
        item = conn.recv(size - len(out))
        if not item:
            raise EOFError("short SOCKS5 message")
        out.extend(item)
    return bytes(out)


def address(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        domain = host.encode("ascii")
        return bytes((3, len(domain))) + domain + port.to_bytes(2, "big")
    return bytes((1 if ip.version == 4 else 4,)) + ip.packed + port.to_bytes(2, "big")


def reply(conn):
    version, status, reserved, kind = exact(conn, 4)
    assert (version, reserved) == (5, 0)
    if kind == 3:
        host = exact(conn, exact(conn, 1)[0]).decode("ascii")
    else:
        host = str(ipaddress.ip_address(exact(conn, {1: 4, 4: 16}[kind])))
    return status, (host, int.from_bytes(exact(conn, 2), "big"))


def negotiate(endpoint, auth=False):
    conn = socket.create_connection(endpoint, timeout=3)
    conn.sendall(bytes((5, 1, 2 if auth else 0)))
    assert exact(conn, 2) == bytes((5, 2 if auth else 0))
    if auth:
        conn.sendall(b"\x01\x04test\x04pass")
        assert exact(conn, 2) == b"\x01\x00"
    return conn


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        with self.request.makefile("rb") as stream:
            payload = stream.read()
        self.request.sendall(payload)


class StreamingEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        self.request.sendall(exact(self.request, 18))


class DuplexEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.request.sendall(b"hello")
        while chunk := self.request.recv(65536):
            self.request.sendall(chunk)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        packet, relay = self.request
        relay.sendto(packet, self.client_address)


class TcpServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class Tcp6Server(TcpServer):
    address_family = socket.AF_INET6


class Udp6Server(socketserver.UDPServer):
    address_family = socket.AF_INET6


@contextmanager
def echo(kind, bind, handler):
    with kind(bind, handler) as server:
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            yield server.server_address[:2]
        finally:
            server.shutdown()
            worker.join()


@contextmanager
def process(args, directory, config, label, endpoint):
    path = directory / f"{label}.json"
    path.write_text(json.dumps(config))
    with (directory / f"{label}.log").open("w") as log:
        proc = subprocess.Popen([*args, str(path)], stdout=log, stderr=log)
        try:
            for _ in range(80):
                assert proc.poll() is None, (directory / f"{label}.log").read_text()
                try:
                    with socket.create_connection(endpoint, timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.025)
            else:
                raise TimeoutError(f"{label} did not listen")
            yield
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def local_port(family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as listen:
        bind = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        listen.bind((bind, 0))
        return listen.getsockname()[:2]


def native(endpoint, auth, udp):
    host, port = endpoint
    settings = {"auth": "password" if auth else "noauth", "udp": udp}
    if auth:
        settings["users"] = [{"user": "test", "pass": "pass"}]
    return {"warp": {"secretKey": "invalid"}, "dns": {"hosts": {"socks.fixture": ["127.0.0.1"]}}, "inbounds": [{
        "tag": "socks", "protocol": "socks", "listen": host, "port": port,
        "outbound": "default", "settings": settings,
    }]}


def request(endpoint, target, auth, command=1, payload=b""):
    conn = negotiate(endpoint, auth)
    conn.sendall(bytes((5, command, 0)) + address(*target) + payload)
    return conn


def streaming_roundtrip(endpoint, origin, auth=False):
    with request(endpoint, origin, auth) as conn:
        assert reply(conn)[0] == 0
        conn.sendall(b"SOCKS5 round trip!")
        assert exact(conn, 18) == b"SOCKS5 round trip!"


def udp_roundtrip(endpoint, origin, auth=False):
    with request(endpoint, ("0.0.0.0", 0), auth, command=3) as conn:
        status, relay = reply(conn)
        assert status == 0 and relay[1] > 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(2)
            header = b"\0\0\0" + address(*origin)
            for payload in (b"udp round trip", b"second datagram"):
                udp.sendto(header + payload, relay)
                try:
                    packet, _ = udp.recvfrom(512)
                except TimeoutError as error:
                    raise AssertionError(f"UDP from {endpoint} via {relay} timed out") from error
                assert packet == header + payload


def verify_shared_udp_port(endpoint, auth):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as application, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as alternate, \
        request(endpoint, ("0.0.0.0", 0), auth, command=3) as control:
        status, relay = reply(control)
        assert status == 0
        application.settimeout(2)
        for origin in (first, second, alternate):
            origin.bind(("127.0.0.1", 0))
            origin.settimeout(2)
        outbound = None
        for destination, responder, message in (
            (first, first, b"first"),
            (second, alternate, b"reply from another port"),
            (second, second, b"second"),
        ):
            application.sendto(b"\0\0\0" + address(*destination.getsockname()) + message, relay)
            data, source = destination.recvfrom(512)
            assert data == message
            if outbound is None:
                outbound = source
            assert source == outbound
            responder.sendto(message, source)
            response = b"\0\0\0" + address(*responder.getsockname()) + message
            assert application.recvfrom(512)[0] == response


def verify_connect_bound(endpoint, auth):
    for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        with socket.socket(family, socket.SOCK_STREAM) as origin:
            origin.bind((address, 0))
            origin.listen(1)
            origin.settimeout(2)
            with request(endpoint, origin.getsockname()[:2], auth) as control:
                status, bound = reply(control)
                assert status == 0
                connection, source = origin.accept()
                with connection:
                    assert bound == source[:2]


def verify_backpressure(endpoint, origin):
    payload = bytes(range(256)) * 16384
    with request(endpoint, origin, False, payload=payload[:197]) as conn:
        assert reply(conn)[0] == 0
        assert exact(conn, 5) == b"hello"
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        conn.settimeout(5)

        def send():
            conn.sendall(payload[197:])
            conn.shutdown(socket.SHUT_WR)

        with ThreadPoolExecutor(max_workers=1) as pool:
            writer = pool.submit(send)
            time.sleep(0.05)
            assert exact(conn, len(payload)) == payload
            assert conn.recv(1) == b""
            writer.result()


def verify_outgoing(args, root, origin, udp):
    endpoint = local_port()
    config = native(endpoint, True, True)
    config.pop("warp")
    config.pop("dns")
    del config["inbounds"][0]["outbound"]
    config["log"] = {"loglevel": "warning"}
    config["outbounds"] = [{"protocol": "freedom"}]
    with process([args.xray.resolve(), "run", "-c"], root, config, "xray-inbound", endpoint):
        remote = {"user": "test", "pass": "pass"}
        if args.client:
            local = local_port()
            http = local_port()
            while http == local:
                http = local_port()
            client = {
                "protocol": "socks", "peer": f"{endpoint[0]}:{endpoint[1]}",
                "settings": {**remote, "socks5Port": local[1], "httpProxyPort": http[1]},
            }
            with process([args.client.resolve()], root, client, "kerlico-client", local):
                streaming_roundtrip(local, origin)
                udp_roundtrip(local, udp)
            print("PASS Kerlico SOCKS client to Xray SOCKS inbound over TCP and UDP")
        if args.landing_server:
            local = local_port()
            landing = native(local, False, True)
            landing["inbounds"][0]["outbound"] = "landing"
            landing["landing"] = {
                "protocol": "socks", "address": endpoint[0], "port": endpoint[1], "settings": remote,
            }
            with process([args.landing_server.resolve()], root, landing, "kerlico-landing", local):
                streaming_roundtrip(local, origin)
                udp_roundtrip(local, udp)
            print("PASS Kerlico SOCKS landing to Xray SOCKS inbound over TCP and UDP")


def verify_ipv6_relay(args, root, origin):
    endpoint = local_port(socket.AF_INET6)
    config = native(endpoint, False, True)
    use_loopback_v6(root, config["inbounds"][0])
    config["inbounds"][0]["settings"]["ip"] = "::1"
    with process([args.server.resolve()], root, config, "kerlico-v6", endpoint), \
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.bind(("::1", 0))
        udp.settimeout(2)
        source = udp.getsockname()[:2]
        with request(endpoint, source, False, command=3) as conn:
            status, relay = reply(conn)
            assert status == 0 and relay[0] == "::1" and relay[1] > 0
            header = b"\0\0\0" + address(*origin)
            for payload in (b"", b"ipv6 datagram"):
                udp.sendto(header + payload, relay)
                assert udp.recvfrom(512)[0] == header + payload
    print("PASS IPv6 UDP relay, declared source and empty datagram")


def validate(endpoint, targets, udp_target, auth, udp_enabled):
    payload = bytes(range(256)) * 1024
    for target in targets:
        with request(endpoint, target, auth, payload=payload[:511]) as conn:
            try:
                status, bound = reply(conn)
            except TimeoutError as error:
                raise AssertionError(f"CONNECT to {target} timed out") from error
            assert status == 0, (target, status, bound)
            conn.sendall(payload[511:])
            conn.shutdown(socket.SHUT_WR)
            assert exact(conn, len(payload)) == payload
            assert conn.recv(1) == b""
    with request(endpoint, local_port(), auth) as conn:
        assert reply(conn)[0] != 0
    with request(endpoint, targets[0], auth, command=2) as conn:
        assert reply(conn)[0] == 7
    peer = "0.0.0.0" if ":" not in endpoint[0] else "::"
    with request(endpoint, (peer, 0), auth, command=3) as conn:
        status, relay = reply(conn)
        if not udp_enabled:
            assert status == 7
            return
        assert status == 0 and relay[1] > 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(2)
            header = b"\0\0\0" + address(*udp_target)
            udp.sendto(header + b"one", relay)
            assert udp.recvfrom(512)[0] == header + b"one"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unrelated:
                unrelated.sendto(header + b"second-source", relay)
                unrelated.settimeout(0.15)
                try:
                    unrelated.recvfrom(512)
                except TimeoutError:
                    pass
                else:
                    raise AssertionError("different UDP source accepted")
            udp.sendto(b"\0\0\x01" + header[3:] + b"fragment", relay)
            udp.sendto(header + b"two", relay)
            assert udp.recvfrom(512)[0] == header + b"two"
            conn.close()
            time.sleep(0.1)
            udp.sendto(header + b"closed", relay)
            udp.settimeout(0.15)
            try:
                udp.recvfrom(512)
            except TimeoutError:
                pass
            else:
                raise AssertionError("UDP association survived its TCP control")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--client", type=Path)
    parser.add_argument("--landing-server", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="socks-local-") as directory, \
        echo(TcpServer, ("127.0.0.1", 0), TcpEcho) as v4, \
        echo(Tcp6Server, ("::1", 0), TcpEcho) as v6, \
        echo(Udp6Server, ("::1", 0), UdpEcho) as udp6, \
        echo(socketserver.UDPServer, ("127.0.0.1", 0), UdpEcho) as udp:
        root = Path(directory)
        targets = [v4, v6, ("socks.fixture", v4[1])]
        endpoint = local_port()
        for auth, udp_enabled in ((False, False), (True, True)):
            config = native(endpoint, auth, udp_enabled)
            use_loopback_v6(root, config["inbounds"][0])
            with process([args.server.resolve()], root, config, "kerlico", endpoint):
                validate(endpoint, targets, udp, auth, udp_enabled)
                verify_connect_bound(endpoint, auth)
                if udp_enabled:
                    verify_shared_udp_port(endpoint, auth)
                if not auth:
                    with echo(TcpServer, ("127.0.0.1", 0), DuplexEcho) as duplex:
                        verify_backpressure(endpoint, duplex)
                if auth:
                    with socket.create_connection(endpoint, timeout=3) as conn:
                        conn.sendall(b"\x05\x01\x00")
                        assert exact(conn, 2) == b"\x05\xff"
                    with socket.create_connection(endpoint, timeout=3) as conn:
                        conn.sendall(b"\x05\x01\x02")
                        assert exact(conn, 2) == b"\x05\x02"
                        conn.sendall(b"\x01\x04test\x04fail")
                        assert exact(conn, 2) == b"\x01\x01"
                    host, port = local_port()
                    xray = {"log": {"loglevel": "warning"}, "inbounds": [{
                        "protocol": "socks", "listen": host, "port": port,
                        "settings": {"auth": "noauth", "udp": True},
                    }], "outbounds": [{"protocol": "socks", "settings": {
                        "address": endpoint[0], "port": endpoint[1], "user": "test", "pass": "pass",
                    }}]}
                    with process([args.xray.resolve(), "run", "-c"], root, xray, "xray", (host, port)), \
                        echo(TcpServer, ("127.0.0.1", 0), StreamingEcho) as streaming:
                        streaming_roundtrip((host, port), streaming)
                        udp_roundtrip((host, port), udp)
        print("PASS SOCKS5 IPv4/IPv6/domain CONNECT, bound endpoint, backpressure, half-close, authentication and UDP association")
        print("PASS Xray SOCKS outbound to Kerlico SOCKS inbound over TCP and UDP")
        config = native(endpoint, True, False)
        settings = config["inbounds"][0]["settings"]
        settings["accounts"] = settings.pop("users")
        with echo(TcpServer, ("127.0.0.1", 0), StreamingEcho) as streaming:
            with process([args.server.resolve()], root, config, "kerlico-accounts", endpoint):
                streaming_roundtrip(endpoint, streaming, auth=True)
            print("PASS legacy SOCKS accounts configuration")
            if args.client or args.landing_server:
                verify_outgoing(args, root, streaming, udp)
        verify_ipv6_relay(args, root, udp6)
        config = native(endpoint, False, True)
        config["inbounds"][0]["sniffing"] = {"enabled": True, "destOverride": ["http", "quic"]}
        with process([args.server.resolve()], root, config, "kerlico-sniffing", endpoint), \
            echo(TcpServer, ("127.0.0.1", 0), DuplexEcho) as duplex:
            verify_backpressure(endpoint, duplex)
            verify_shared_udp_port(endpoint, False)
        print("PASS pre-read TCP and UDP payload, shared UDP port and alternate reply source")


if __name__ == "__main__":
    main()
