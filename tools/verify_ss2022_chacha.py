#!/usr/bin/env python3
"""Independent SIP022 wire fixture for the ChaCha suites. Uses only the Python stdlib."""

import argparse
import contextlib
import hmac
import secrets
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import verify_mieru as fixtures
import verify_ss2022 as peer
from verify_vless_client import associate, exchange


MASK32 = 0xffffffff
COLUMN = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
DIAGONAL = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
IV = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)


def rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def blake3_short(key, message, flags):
    # Key derivation here needs exactly one block, for both the context and the key material.
    assert len(message) <= 64
    m = struct.unpack("<16I", message.ljust(64, b"\0"))
    v = list(key + IV[:4] + (0, 0, len(message), flags | 1 | 2 | 8))
    for _ in range(7):
        for p, (a, b, c, d) in enumerate(COLUMN + DIAGONAL):
            v[a] = (v[a] + v[b] + m[2 * p]) & MASK32
            v[d] = rotate(v[d] ^ v[a], 16)
            v[c] = (v[c] + v[d]) & MASK32
            v[b] = rotate(v[b] ^ v[c], 20)
            v[a] = (v[a] + v[b] + m[2 * p + 1]) & MASK32
            v[d] = rotate(v[d] ^ v[a], 24)
            v[c] = (v[c] + v[d]) & MASK32
            v[b] = rotate(v[b] ^ v[c], 25)
        m = tuple(m[i] for i in (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8))
    return struct.pack("<8I", *(x ^ y for x, y in zip(v[:8], v[8:])))


def derive(key, salt):
    context = blake3_short(IV, b"shadowsocks 2022 session subkey", 32)
    return blake3_short(struct.unpack("<8I", context), key + salt, 64)


def rounds(state, count):
    v = list(state)
    for _ in range(count // 2):
        for a, b, c, d in COLUMN + DIAGONAL:
            v[a] = (v[a] + v[b]) & MASK32
            v[d] = rotate(v[d] ^ v[a], 16)
            v[c] = (v[c] + v[d]) & MASK32
            v[b] = rotate(v[b] ^ v[c], 12)
            v[a] = (v[a] + v[b]) & MASK32
            v[d] = rotate(v[d] ^ v[a], 8)
            v[c] = (v[c] + v[d]) & MASK32
            v[b] = rotate(v[b] ^ v[c], 7)
    return v


class Aead:
    def __init__(self, key, nonce, count):
        self.count = count
        self.prefix = struct.unpack("<12I", b"expand 32-byte k" + key)
        if len(nonce) == 24:
            state = rounds(self.prefix + struct.unpack("<4I", nonce[:16]), count)
            self.prefix = self.prefix[:4] + tuple(state[:4] + state[12:])
            nonce = b"\0" * 4 + nonce[16:]
        self.nonce = struct.unpack("<3I", nonce)

    def block(self, counter):
        state = self.prefix + (counter,) + self.nonce
        return struct.pack("<16I", *((a + b) & MASK32 for a, b in zip(state, rounds(state, self.count))))

    def crypt(self, payload):
        return b"".join(bytes(a ^ b for a, b in zip(payload[i:i + 64], self.block(i // 64 + 1)))
                        for i in range(0, len(payload), 64))

    def tag(self, data):
        key = self.block(0)[:32]
        r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
        s = int.from_bytes(key[16:], "little")
        padded = data + bytes((-len(data)) % 16) + struct.pack("<QQ", 0, len(data))
        h = 0
        for i in range(0, len(padded), 16):
            h = (h + int.from_bytes(padded[i:i + 16] + b"\x01", "little")) * r % ((1 << 130) - 5)
        return ((h + s) % (1 << 128)).to_bytes(16, "little")

    def seal(self, payload):
        data = self.crypt(payload)
        return data + self.tag(data)

    def open(self, packet):
        assert len(packet) >= 16
        data, tag = packet[:-16], packet[-16:]
        assert hmac.compare_digest(tag, self.tag(data)), "wire authentication failed"
        return self.crypt(data)


class Stream:
    def __init__(self, key, salt, count):
        self.key = derive(key, salt)
        self.count = count
        self.nonce = 0

    def cipher(self):
        nonce = self.nonce.to_bytes(12, "little")
        self.nonce += 1
        return Aead(self.key, nonce, self.count)

    def read(self, sock, size):
        return self.cipher().open(fixtures.exact(sock, size + 16))

    def write(self, data):
        return self.cipher().seal(data)

    def read_payload(self, sock):
        return self.read(sock, int.from_bytes(self.read(sock, 2), "big"))

    def write_payload(self, data):
        return self.write(len(data).to_bytes(2, "big")) + self.write(data)


def header(role, suffix=b""):
    return struct.pack("!BQ", role, int(time.time())) + suffix


def check_header(data, role):
    got, now = struct.unpack("!BQ", data[:9])
    assert got == role and abs(int(time.time()) - now) <= 30
    return data[9:]


def ipv4(port):
    return b"\x01\x7f\0\0\x01" + struct.pack("!H", port)


def udp_packet(body, key, count):
    nonce = secrets.token_bytes(24)
    return nonce + Aead(key, nonce, count).seal(body)


def udp_open(wire, key, count):
    return Aead(key, wire[:24], count).open(wire[24:])


def udp_session_isolation(port, key, origins):
    """Two SIP022 sessions share one outer socket and target the same pair of UDP origins."""
    clients = [secrets.token_bytes(8), secrets.token_bytes(8)]
    targets = [ipv4(target.server_address[1]) for target in origins.udp_source]
    observed = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        for sequence, target in enumerate(targets):
            for index, client in enumerate(clients):
                message = bytes((index, sequence))
                wire = udp_packet(client + sequence.to_bytes(8, "big") + header(0, b"\0\0" + target + message), key, 20)
                udp.sendto(wire, ("127.0.0.1", port))
        for _ in range(len(clients) * len(targets)):
            body = udp_open(udp.recv(65535), key, 20)
            reply = check_header(body[16:], 1)
            index = clients.index(reply[:8])
            header_size = 10 + int.from_bytes(reply[8:10], "big")
            source, payload = reply[header_size:header_size + 7], reply[header_size + 7:]
            sequence = targets.index(source)
            fixtures.require((index, sequence) not in observed and len(payload) == 4 and
                             payload[2:] == bytes((index, sequence)), "UDP response crossed authenticated sessions")
            observed[index, sequence] = int.from_bytes(payload[:2], "big")
    fixtures.require(all(observed[index, 0] == observed[index, 1] for index in range(2)),
                     "UDP targets on one authenticated session saw different origin ports")
    fixtures.require(observed[0, 0] != observed[1, 0], "distinct authenticated sessions shared an origin port")


def test_server(paths, root, origins, count, stock):
    method = f"2022-blake3-chacha{count}-poly1305"
    port, = fixtures.free_ports(1)
    password = peer.secret(32, 31)
    key = bytes(range(31, 63))
    server = peer.server(paths, root / "server.json", port, method, None, [("test", password)], stock)
    message = b"independent SIP022 first payload\0"
    second = bytes(range(256)) * 4
    with fixtures.managed(server, root, "server") as proc:
        fixtures.wait_for(proc, lambda: fixtures.ports_ready([port]))
        with socket.create_connection(("127.0.0.1", port), 4) as tcp:
            salt = secrets.token_bytes(32)
            tx = Stream(key, salt, count)
            request = ipv4(origins.tcp4.server_address[1]) + b"\0\0" + message
            tcp.sendall(salt + tx.write(header(0, struct.pack("!H", len(request)))) + tx.write(request))
            rx = Stream(key, fixtures.exact(tcp, 32), count)
            h = check_header(rx.read(tcp, 43), 1)
            assert h[:32] == salt
            assert rx.read(tcp, int.from_bytes(h[32:], "big")) == message
            tcp.sendall(tx.write_payload(second))
            received = bytearray()
            while len(received) < len(second):
                received.extend(rx.read_payload(tcp))
            assert received == second
        client = secrets.token_bytes(8)
        target = ipv4(origins.udp4.server_address[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(4)
            udp.sendto(udp_packet(client + bytes(8) + header(0, b"\0\0" + target + message), key, count),
                       ("127.0.0.1", port))
            body = udp_open(udp.recv(65535), key, count)
            assert body[:8] != client
            reply = check_header(body[16:], 1)
            assert reply[:8] == client
            padding = int.from_bytes(reply[8:10], "big")
            assert reply[10 + padding:] == target + message
    print(f"PASS independent ChaCha{count} client -> {stock or 'Kerlico'} TCP/UDP", flush=True)


def test_client(paths, root, origins, count, stock, landing=False):
    method = f"2022-blake3-chacha{count}-poly1305"
    password = peer.secret(32, 95)
    key = bytes(range(95, 127))
    message = b"independent ChaCha peer echo\0"
    target_port = 32123
    target = ipv4(target_port)
    second_target = ipv4(target_port + 1)
    clients = []

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(4)
            salt = fixtures.exact(sock, 32)
            rx = Stream(key, salt, count)
            h = check_header(rx.read(sock, 11), 0)
            request = rx.read(sock, int.from_bytes(h, "big"))
            assert request.startswith(target)
            padding = int.from_bytes(request[7:9], "big")
            assert padding <= 900 and (padding or len(request) > 9)
            data = request[9 + padding:]
            if not data:
                data = rx.read_payload(sock)
            assert data == message
            second_salt = secrets.token_bytes(32)
            tx = Stream(key, second_salt, count)
            sock.sendall(second_salt + tx.write(header(1, salt + struct.pack("!H", len(data)))) + tx.write(data))

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            wire, udp = self.request
            packet = udp_open(wire, key, count)
            client = packet[:8]
            reply = check_header(packet[16:], 0)
            padding = int.from_bytes(reply[:2], "big")
            request = reply[2 + padding:]
            assert request[:7] in (target, second_target) and request[7:] == message
            clients.append(client)
            server = bytes(b ^ 0xff for b in client)
            body = server + (len(clients) - 1).to_bytes(8, "big") + header(1, client + b"\0\0" + request)
            udp.sendto(udp_packet(body, key, count), self.client_address)

    port = origins.add(fixtures.ThreadedTCP, "127.0.0.1", TCP, "oracle-tcp").server_address[1]
    origins.add(fixtures.SequentialUDP, "127.0.0.1", UDP, "oracle-udp", port)
    socks, http = fixtures.free_ports(2)
    with contextlib.ExitStack() as stack:
        if landing:
            front, = fixtures.free_ports(1)
            password_front = peer.secret(32, 63)
            config = {"protocol": "ss2022", "address": "127.0.0.1", "port": port,
                      "settings": {"method": method, "password": password}}
            server = peer.server(paths, root / "landing.json", front, method, None,
                                 [("test", password_front)], False, landing=config)
            proc = stack.enter_context(fixtures.managed(server, root, "landing"))
            fixtures.wait_for(proc, lambda: fixtures.ports_ready([front]))
            port, password = front, password_front
        client = peer.client(paths, root / "client.json", port, socks, http, method, password, stock)
        proc = stack.enter_context(fixtures.managed(client, root, "client"))
        fixtures.wait_for(proc, lambda: fixtures.ports_ready([socks, http]))
        with fixtures.socks_connect(socks, "127.0.0.1", target_port)[0] as tcp:
            tcp.sendall(message)
            assert fixtures.exact(tcp, len(message)) == message
        control, udp, bound = associate(socks)
        with control, udp:
            exchange(udp, bound, "127.0.0.1", target_port, message)
            exchange(udp, bound, "127.0.0.1", target_port + 1, message)
        assert len(clients) == 2 and clients[0] == clients[1], "targets did not share a UDP session"
    kind = stock or ("Kerlico via Kerlico landing" if landing else "Kerlico")
    print(f"PASS {kind} -> independent ChaCha{count} server TCP/UDP", flush=True)


def udp_server_limit(paths, folder, origins, stock, host, wire_limit):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(31, 63))
    target = ipv4(origins.udp4.server_address[1])
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    port, = fixtures.free_ports(1, host=host)
    command = peer.server(paths, folder / "server.json", port, method, None,
                          [("test", peer.secret(32, 31))], stock, listen=host)
    sid = secrets.token_bytes(8)
    expected = bytes(i % 251 for i in range(wire_limit - 82))
    with fixtures.managed(command, folder, "server") as process:
        def ready():
            try:
                with socket.create_connection((host, port), 0.2):
                    return True
            except OSError:
                return False
        fixtures.wait_for(process, ready)
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            def request(seq, payload):
                body = sid + seq.to_bytes(8, "big") + header(0, b"\0\0" + target + payload)
                udp.sendto(udp_packet(body, key, 20), (host, port))
            def reply(payload, phase, size=None):
                udp.settimeout(5)
                try:
                    wire = udp.recv(65_535)
                except socket.timeout as error:
                    raise fixtures.Failure(f"no {phase} reply") from error
                if size is not None:
                    assert len(wire) == size, "relay truncated maximum-size reply"
                opened = check_header(udp_open(wire, key, 20)[16:], 1)
                assert opened[:8] == sid
                pad = int.from_bytes(opened[8:10], "big")
                assert opened[10 + pad:] == target + payload
            request(0, b"before size limit")
            reply(b"before size limit", "initial")
            request(1, expected)
            reply(expected, "maximum-sized", wire_limit)
            request(2, expected + b"+")
            udp.settimeout(0.5)
            with contextlib.suppress(socket.timeout):
                udp.recv(65_535)
                raise AssertionError("oversized relay reply unexpectedly arrived")
            request(3, b"after oversized reply")
            reply(b"after oversized reply", "post-oversize")


def udp_client_limit(paths, folder, origins, stock, host, wire_limit):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(95, 127))
    target_port = 32123
    target = ipv4(target_port)
    expected = bytes(i % 251 for i in range(wire_limit - 74))
    seen = []

    class Wire(socketserver.BaseRequestHandler):
        def handle(self):
            wire, udp = self.request
            packet = udp_open(wire, key, 20)
            client_id = packet[:8]
            opened = check_header(packet[16:], 0)
            padding = int.from_bytes(opened[:2], "big")
            assert opened[2 + padding:].startswith(target)
            payload = opened[2 + padding + len(target):]
            seen.append((client_id, len(wire), payload))
            server_id = bytes(b ^ 0xff for b in client_id)
            body = server_id + (len(seen) - 1).to_bytes(8, "big") + header(1, client_id + b"\0\0" + target + b"ack")
            udp.sendto(udp_packet(body, key, 20), self.client_address)

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    origin = type("WireSocket", (fixtures.SequentialUDP,), {"address_family": family})
    port = origins.add(origin, host, Wire, "wire-limit").server_address[1]
    socks, http = fixtures.free_ports(2)
    command = peer.client(paths, folder / "client.json", port, socks, http, method,
                          peer.secret(32, 95), stock, host=host)
    with fixtures.managed(command, folder, "client") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([socks, http]))
        control, udp, bound = associate(socks)
        with control, udp:
            def send(payload):
                udp.sendto(b"\0\0\0" + target + payload, bound)
            def ack(phase):
                udp.settimeout(5)
                try:
                    wire = udp.recv(65_535)
                except socket.timeout as error:
                    raise fixtures.Failure(f"no {phase} acknowledgement") from error
                assert fixtures.unpack_udp(wire) == (("127.0.0.1", target_port), b"ack")
            send(b"before size limit")
            ack("initial")
            send(expected)
            ack("maximum-sized")
            send(expected + b"+")
            udp.settimeout(0.5)
            with contextlib.suppress(socket.timeout):
                udp.recv(65_535)
                raise AssertionError("oversized client datagram unexpectedly arrived")
            send(b"after oversized request")
            ack("post-oversize")
        assert len(seen) == 3 and seen[0][0] == seen[1][0] == seen[2][0]
        assert seen[1][1:] == (wire_limit, expected)
        assert seen[2][2] == b"after oversized request"


REORDER_CASES = ((8193, b"new", True), (65, b"edge", True),
                 (64, b"too old", False), (65, b"duplicate", False),
                 (8194, b"still active", True))


def udp_server_reorder(paths, folder, origins, stock):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(31, 63))
    echo = origins.udp4
    target = ipv4(echo.server_address[1])
    port, = fixtures.free_ports(1)
    command = peer.server(paths, folder / "server.json", port, method, None,
                          [("test", peer.secret(32, 31))], stock)
    sid = secrets.token_bytes(8)
    with fixtures.managed(command, folder, "server") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([port]))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            for seq, label, accepted in REORDER_CASES:
                before = echo.count
                body = sid + seq.to_bytes(8, "big") + header(0, b"\0\0" + target + label)
                udp.sendto(udp_packet(body, key, 20), ("127.0.0.1", port))
                udp.settimeout(4 if accepted else 0.35)
                try:
                    wire = udp.recv(65_535)
                except socket.timeout:
                    assert not accepted, f"valid UDP counter {seq} was dropped"
                    assert echo.count == before, f"rejected UDP counter {seq} reached the origin"
                    continue
                assert accepted, f"invalid UDP counter {seq} reached the client"
                opened = check_header(udp_open(wire, key, 20)[16:], 1)
                assert opened[:8] == sid
                pad = int.from_bytes(opened[8:10], "big")
                assert opened[10 + pad:] == target + label


def udp_client_reorder(paths, folder, origins, stock):
    udp_client_replies(paths, folder, origins, stock,
                       [(1, seq, label, accepted) for seq, label, accepted in REORDER_CASES])


def udp_client_sessions(paths, folder, origins, stock):
    udp_client_replies(paths, folder, origins, stock, (
        (1, 8193, b"first session", True),
        (2, 0, b"first reply after restart", True),
        (1, 65, b"late old reply", True),
        (1, 65, b"duplicate old packet", False),
        (1, 64, b"too old in previous session", False),
        (3, 0, b"third session before old one expires", False),
        (2, 1, b"current session stays active", True),
    ))


def udp_client_replies(paths, folder, origins, stock, cases):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(95, 127))
    target_port = 32123
    target = ipv4(target_port)

    class Wire(socketserver.BaseRequestHandler):
        def handle(self):
            wire, udp = self.request
            client = udp_open(wire, key, 20)[:8]
            for session, seq, label, _ in cases:
                server = (int.from_bytes(client, "big") ^ session).to_bytes(8, "big")
                body = server + seq.to_bytes(8, "big") + header(1, client + b"\0\0" + target + label)
                udp.sendto(udp_packet(body, key, 20), self.client_address)
                time.sleep(0.03)

    port = origins.add(fixtures.SequentialUDP, "127.0.0.1", Wire, "wire-reordering").server_address[1]
    socks, http = fixtures.free_ports(2)
    command = peer.client(paths, folder / "client.json", port, socks, http, method, peer.secret(32, 95), stock)
    with fixtures.managed(command, folder, "client") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([socks, http]))
        control, udp, bound = associate(socks)
        with control, udp:
            udp.sendto(b"\0\0\0" + target + b"open", bound)
            for session, seq, label, accepted in cases:
                if accepted:
                    udp.settimeout(4)
                    try:
                        wire = udp.recv(65_535)
                    except socket.timeout as error:
                        raise fixtures.Failure(f"no reply for valid UDP counter {session}:{seq}") from error
                    _, actual = fixtures.unpack_udp(wire)
                    assert actual == label, f"unexpected UDP reply before {label!r}: {actual!r}"
                    assert fixtures.unpack_udp(wire)[0] == ("127.0.0.1", target_port)
            udp.settimeout(0.35)
            with contextlib.suppress(socket.timeout):
                udp.recv(65_535)
                raise AssertionError("an invalid UDP reply reached the SOCKS socket")


def udp_server_roaming(paths, folder, origins, stock):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(31, 63))
    seen = []

    class Origin(socketserver.BaseRequestHandler):
        def handle(self):
            body, reply = self.request
            seen.append(self.client_address)
            reply.sendto(body, self.client_address)

    origin = origins.add(fixtures.SequentialUDP, "127.0.0.1", Origin, "roaming-origin")
    target = ipv4(origin.server_address[1])
    port, = fixtures.free_ports(1)
    command = peer.server(paths, folder / "server.json", port, method, None,
                          [("test", peer.secret(32, 31))], stock)
    sid = secrets.token_bytes(8)

    def send(sock, seq, label):
        body = sid + seq.to_bytes(8, "big") + header(0, b"\0\0" + target + label)
        sock.sendto(udp_packet(body, key, 20), ("127.0.0.1", port))

    def receive(sock, label):
        sock.settimeout(4)
        body = udp_open(sock.recv(65_535), key, 20)
        opened = check_header(body[16:], 1)
        assert opened[:8] == sid
        pad = int.from_bytes(opened[8:10], "big")
        assert opened[10 + pad:] == target + label
        return body[:8]

    with fixtures.managed(command, folder, "server") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([port]))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as before, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as after:
            before.bind(("127.0.0.1", 0))
            after.bind(("127.0.0.1", 0))
            assert before.getsockname() != after.getsockname()
            send(before, 0, b"before roaming")
            server = receive(before, b"before roaming")
            send(after, 1, b"after roaming")
            assert receive(after, b"after roaming") == server
            assert len(seen) == 2 and seen[0] == seen[1]
            send(before, 0, b"duplicate at old port")
            before.settimeout(0.35)
            with contextlib.suppress(socket.timeout):
                before.recv(65_535)
                raise AssertionError("a duplicate packet restored the old endpoint")
            assert len(seen) == 2
            origin.socket.sendto(b"reply from origin after roaming", seen[0])
            assert receive(after, b"reply from origin after roaming") == server


def udp_server_downlink_idle(paths, logs, origins, seconds):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(31, 63))
    with contextlib.ExitStack() as stack:
        running = []
        for stock in ([True] if paths.xray else []) + [False]:
            label = "xray" if stock else "kerlico"
            folder = logs / label
            folder.mkdir()
            listener, = fixtures.free_ports(1)
            command = peer.server(paths, folder / "server.json", listener, method, None,
                                  [("test", peer.secret(32, 31))], stock)
            process = stack.enter_context(fixtures.managed(command, folder, "server"))
            fixtures.wait_for(process, lambda: fixtures.ports_ready([listener]))
            origin = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            origin.bind(("127.0.0.1", 0))
            origin.settimeout(4)
            client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            client.settimeout(4)
            sid = secrets.token_bytes(8)
            target = ipv4(origin.getsockname()[1])
            data = sid + bytes(8) + header(0, b"\0\0" + target + b"start downlink-only session")
            client.sendto(udp_packet(data, key, 20), ("127.0.0.1", listener))
            first, source = origin.recvfrom(4096)
            assert first == b"start downlink-only session", label
            running.append([label, client, origin, source, sid, target, None, None])

        begin = time.monotonic()
        failures = []
        for age in [0, *range(30, seconds, 30), seconds]:
            time.sleep(max(0, begin + age - time.monotonic()))
            for row in running:
                label, client, origin, source, sid, target, previous, last_seq = row
                if label in failures:
                    continue
                payload = f"downlink-only-{age}".encode()
                origin.sendto(payload, source)
                try:
                    reply = client.recv(65_535)
                except socket.timeout:
                    failures.append(label)
                    print(f"FAIL {label}: downlink stopped after {age}s without uplink", flush=True)
                    continue
                plain = udp_open(reply, key, 20)
                server_id, seq = plain[:8], int.from_bytes(plain[8:16], "big")
                body = check_header(plain[16:], 1)
                assert body[:8] == sid and (previous is None or previous == server_id), label
                assert last_seq is None or seq > last_seq, label
                pad = int.from_bytes(body[8:10], "big")
                assert body[10 + pad:] == target + payload, label
                row[6:] = [server_id, seq]
                if not age or age == seconds or age % 60 == 0:
                    print(f"OK {label}: downlink at {age}s without uplink", flush=True)
        for row in running:
            if row[0] not in failures:
                print(f"PASS {row[0]}: {seconds}s downlink-only, unchanged server session", flush=True)
        assert not failures, ", ".join(failures)


def tcp_client_bad_response_salt(paths, folder, origins, stock):
    method, key = "2022-blake3-chacha20-poly1305", bytes(range(95, 127))
    sent = threading.Event()
    release = threading.Event()

    class Origin(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(4)
            request_salt = fixtures.exact(sock, 32)
            rx = Stream(key, request_salt, 20)
            h = check_header(rx.read(sock, 11), 0)
            rx.read(sock, int.from_bytes(h, "big"))
            response_salt = secrets.token_bytes(32)
            tx = Stream(key, response_salt, 20)
            wrong = bytes([request_salt[0] ^ 1]) + request_salt[1:]
            # Only send the authenticated fixed header. Failure must not wait for its body.
            sock.sendall(response_salt + tx.write(header(1, wrong + b"\0\x01")))
            sent.set()
            release.wait(4)

    origin = origins.add(fixtures.ThreadedTCP, "127.0.0.1", Origin, "wrong-salt")
    socks, http = fixtures.free_ports(2)
    command = peer.client(paths, folder / "client.json", origin.server_address[1], socks, http,
                          method, peer.secret(32, 95), stock)
    try:
        with fixtures.managed(command, folder, "client") as process:
            fixtures.wait_for(process, lambda: fixtures.ports_ready([socks, http]))
            sock, _ = fixtures.socks_connect(socks, "127.0.0.1", 32123)
            with sock:
                assert sent.wait(3), "fixture did not send its response header"
                sock.settimeout(1)
                try:
                    assert sock.recv(1) == b""
                except ConnectionResetError:
                    pass
                except socket.timeout as error:
                    raise fixtures.Failure("client waited for payload with invalid echoed salt") from error
    finally:
        release.set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--reference", type=Path, help="Unmodified Shadowsocks Rust with ChaCha8 enabled")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--udp-size", action="store_true", help="Check the largest IPv4 and IPv6 outer UDP packets")
    mode.add_argument("--udp-window", action="store_true", help="Check the UDP packet reordering boundary")
    mode.add_argument("--udp-sessions", action="store_true", help="Check UDP server session changes and client roaming")
    mode.add_argument("--udp-downlink-idle", type=int, metavar="SECONDS", help="Keep sending origin replies with no uplink")
    mode.add_argument("--tcp-salt", action="store_true", help="Check response salt before payload read")
    parser.add_argument("--xray", type=Path, help="Pinned Xray peer for UDP wire comparisons")
    args = parser.parse_args()
    if (args.udp_window or args.udp_sessions or args.tcp_salt or args.udp_downlink_idle) and args.xray:
        version = subprocess.check_output([args.xray, "version"], text=True, timeout=10)
        assert "26.10.31" in version and "a4a3dff" in version
    assert blake3_short(IV, b"", 0).hex() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    logs = Path(tempfile.mkdtemp(prefix="kerlico-sip022-chacha-"))
    print(f"Logs: {logs}", flush=True)
    with fixtures.Fixtures() as origins:
        if args.udp_downlink_idle is not None:
            if args.udp_downlink_idle < 1:
                parser.error("--udp-downlink-idle requires a positive duration")
            udp_server_downlink_idle(args, logs, origins, args.udp_downlink_idle)
            return
        if args.udp_sessions or args.tcp_salt:
            for stock in ([True] if args.xray else []) + [False]:
                label = "xray" if stock else "kerlico"
                directory = logs / label
                directory.mkdir()
                checks = (tcp_client_bad_response_salt,) if args.tcp_salt else (udp_client_sessions, udp_server_roaming)
                for verify in checks:
                    verify(args, directory, origins, stock)
                    print(f"PASS {label}: {verify.__name__}", flush=True)
            return
        if args.udp_window:
            choices = (["shadowsocks-rust"] if args.reference else []) + ([True] if args.xray else []) + [False]
            for stock in choices:
                label = "xray" if stock is True else stock or "kerlico"
                directory = logs / label
                directory.mkdir()
                for verify in (udp_server_reorder, udp_client_reorder):
                    verify(args, directory, origins, stock)
                    print(f"PASS {label}: {verify.__name__} boundary and duplicates", flush=True)
            return
        if args.udp_size:
            failed = []
            for stock in (["shadowsocks-rust", False] if args.reference else [False]):
                for host, limit in [("127.0.0.1", 65_507), ("::1", 65_527)]:
                    for verify in (udp_server_limit, udp_client_limit):
                        label = f"{stock or 'kerlico'}-udp{6 if ':' in host else 4}-{verify.__name__}"
                        directory = logs / label
                        directory.mkdir()
                        try:
                            verify(args, directory, origins, stock, host, limit)
                            print(f"PASS {label}", flush=True)
                        except (AssertionError, OSError, fixtures.Failure) as error:
                            failed.append(label)
                            print(f"FAIL {label}: {error}", flush=True)
            assert not failed, ", ".join(failed)
            return
        for stock, counts in [("shadowsocks-rust", (8, 20)), (False, (8, 12, 20))]:
            if stock and not args.reference:
                continue
            for count in counts:
                folder = logs / f"{stock or 'kerlico'}-{count}"
                folder.mkdir()
                test_server(args, folder, origins, count, stock)
                test_client(args, folder, origins, count, stock)
        landing = logs / "kerlico-12-landing"
        landing.mkdir()
        test_client(args, landing, origins, 12, False, landing=True)


if __name__ == "__main__":
    main()
