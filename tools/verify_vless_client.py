#!/usr/bin/env python3
"""kerlico-client 的 VLESS 本机入口与官方 Xray 的真实互通验收，仅在 worker 执行。

每行配置先用 Xray 服务端加 kerlico-client 运行，再用 Xray 客户端（socks 与 http 入站加
vless 出站）运行同一组检查作对照。夹具、SOCKS 编解码和进程管理来自 verify_mieru.py。
53 和 443 端口的 UDP 夹具需要 root。不构建二进制，不下载模块，只绑定回环。
"""

import argparse
import collections
import contextlib
import hashlib
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback

import verify_mieru as mieru
from verify_mieru import Failure, PacketFailure, authority, encode_address, require, unpack_udp

XRAY_VERSION = "Xray 26.10.31"
XRAY_BUILD = "a4a3dff"
ID = "5783a3e7-e373-51cd-8642-c83782b807c5"
WRONG_ID = "0f6b2d4c-0000-4000-8000-000000000001"
NAME = "localhost"
PATH = "/matrix"
SHORT_ID = "12ab34cd"
COMMANDS = {1: "tcp", 2: "udp", 3: "mux"}

# Each row runs with both clients. `policy` gives, per client, whether a datagram to port 53 or
# 443 sent after the association's first datagram gets an echo. Xray picks the carrier and the
# UDP/443 rule from an association's first destination only; Kerlico decides per datagram.
ROWS = {
    "raw-none": {"network": "raw", "security": "none", "tap": "udp-lanes",
                 "policy": {"kerlico": {53: True, 443: True}, "xray": {53: True, 443: True}}},
    "raw-tls": {"network": "raw", "security": "tls"},
    "raw-reality-vision": {"network": "raw", "security": "reality", "flow": "xtls-rprx-vision",
                           "policy": {"kerlico": {53: True, 443: False}, "xray": {53: True, 443: True}}},
    "ws-tls": {"network": "ws", "security": "tls", "alpn": "http/1.1"},
    "grpc-reality": {"network": "grpc", "security": "reality"},
    "xhttp-tls-h2": {"network": "xhttp", "security": "tls", "alpn": "h2"},
    "raw-none-mux": {"network": "raw", "security": "none", "mux": {"enabled": True}, "tap": "all-mux",
                     "policy": {"kerlico": {53: True, 443: False}, "xray": {53: True, 443: True}}},
}

# Carriers a UDP association opens in `raw-none`, by VLESS command. Kerlico gives 53 and 443 a
# plain UDP link each; Xray carries every destination in the XUDP link of the first one.
UDP_LANES = {"kerlico": {"mux": 1, "udp": 2}, "xray": {"mux": 1}}


class Recorder(socketserver.BaseRequestHandler):
    """UDP echo that keeps the source port of every datagram it receives."""

    def handle(self):
        data, sock = self.request
        self.server.mark()
        with self.server.lock:
            self.server.sources.append(self.client_address[1])
        sock.sendto(data, self.client_address)


class Reflector(socketserver.BaseRequestHandler):
    """Answers from a second port, so the reply source differs from the destination."""

    def handle(self):
        data, _ = self.request
        self.server.mark()
        self.server.answer.sendto(data, self.client_address)


class Fixtures(mieru.Fixtures):
    def __enter__(self):
        super().__enter__()
        try:
            self.recorder = self.add(mieru.ThreadedUDP, "127.0.0.1", Recorder, "recorder")
            self.udp53 = self.add(mieru.ThreadedUDP, "127.0.0.1", Recorder, "udp53", 53)
            self.udp443 = self.add(mieru.ThreadedUDP, "127.0.0.1", Recorder, "udp443", 443)
            for server in (self.recorder, self.udp53, self.udp443):
                server.sources = []
            self.reflector = self.add(mieru.ThreadedUDP, "127.0.0.1", Reflector, "reflector")
            self.reflector.answer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.reflector.answer.bind(("127.0.0.1", 0))
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *args):
        if hasattr(self, "reflector"):
            self.reflector.answer.close()
        super().__exit__(*args)


class Keys:
    def __init__(self, xray, folder):
        prefix = folder / "cert"
        subprocess.run([xray, "tls", "cert", f"--domain={NAME}", f"--file={prefix}"], check=True,
                       stdout=subprocess.DEVNULL, timeout=20)
        self.cert, self.key = f"{prefix}.crt", f"{prefix}.key"
        # Xray writes a PKCS#8 EC key under an "RSA PRIVATE KEY" label; Python's ssl reads the
        # label, Go does not.
        key = Path(self.key).read_text()
        Path(self.key).write_text(key.replace("RSA PRIVATE KEY", "PRIVATE KEY"))
        der = ssl.PEM_cert_to_DER_cert(Path(self.cert).read_text())
        self.pin = hashlib.sha256(der).hexdigest()
        lines = subprocess.run([xray, "x25519"], check=True, stdout=subprocess.PIPE, text=True,
                               timeout=20).stdout.splitlines()
        values = dict(line.split(": ", 1) for line in lines if ": " in line)
        self.private = values["PrivateKey"]
        self.public = values["Password (PublicKey)"]


class Decoy:
    """The TLS 1.3 server an Xray REALITY inbound borrows its handshake from."""

    def __init__(self, keys):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(keys.cert, keys.key)
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        with contextlib.suppress(OSError, ssl.SSLError):
            conn.settimeout(10)
            with self.context.wrap_socket(conn, server_side=True) as tls:
                while tls.recv(4096):
                    pass
        conn.close()

    def close(self):
        self.listener.close()


class Tap:
    """Forwards every client carrier to the server, keeps its first bytes, and can cut them all."""

    def __init__(self, upstream):
        self.upstream = upstream
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.lock = threading.Lock()
        self.heads = []
        self.live = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            try:
                server = socket.create_connection(("127.0.0.1", self.upstream), 5)
            except OSError:
                client.close()
                continue
            with self.lock:
                self.heads.append(bytearray())
                index = len(self.heads) - 1
                self.live.append((client, server))
            threading.Thread(target=self.pump, args=(client, server, index), daemon=True).start()
            threading.Thread(target=self.pump, args=(server, client, None), daemon=True).start()

    def pump(self, source, sink, index):
        with contextlib.suppress(OSError):
            while True:
                data = source.recv(65536)
                if not data:
                    break
                if index is not None:
                    with self.lock:
                        head = self.heads[index]
                        head.extend(data[:max(0, 64 - len(head))])
                sink.sendall(data)
        with contextlib.suppress(OSError):
            sink.shutdown(socket.SHUT_WR)

    def commands(self, since=0):
        """VLESS command of each carrier after `since`: version, UUID, addons length, addons, command."""
        with self.lock:
            heads = [bytes(head) for head in self.heads[since:]]
        found = []
        for head in heads:
            require(len(head) >= 19 and head[0] == 0, "分路器没有看到明文 VLESS 请求头")
            found.append(COMMANDS.get(head[18 + head[17]], f"unknown-{head[18 + head[17]]}"))
        return found

    def count(self):
        with self.lock:
            return len(self.heads)

    def cut(self):
        with self.lock:
            live, self.live = self.live, []
        for pair in live:
            for sock in pair:
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                sock.close()

    def close(self):
        self.listener.close()
        self.cut()


def xray_stream(row, keys, server, decoy=None):
    stream = {"network": row["network"], "security": row["security"]}
    alpn = [row["alpn"]] if row.get("alpn") else None
    if row["security"] == "tls":
        tls = ({"certificates": [{"certificateFile": keys.cert, "keyFile": keys.key}]} if server
               else {"serverName": NAME, "pinnedPeerCertSha256": keys.pin})
        if alpn:
            tls["alpn"] = alpn
        stream["tlsSettings"] = tls
    elif row["security"] == "reality":
        stream["realitySettings"] = (
            {"target": f"127.0.0.1:{decoy.port}", "serverNames": [NAME], "privateKey": keys.private,
             "shortIds": [SHORT_ID]} if server
            else {"fingerprint": "chrome", "serverName": NAME, "password": keys.public, "shortId": SHORT_ID})
    if row["network"] == "ws":
        stream["wsSettings"] = {"path": PATH, "host": NAME}
    elif row["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": "matrix"}
    elif row["network"] == "xhttp":
        stream["xhttpSettings"] = {"path": PATH, "host": NAME, "mode": "auto"}
    return stream


def xray_server(row, keys, decoy, port):
    return {"log": {"loglevel": "info"},
            "inbounds": [{"protocol": "vless", "listen": "127.0.0.1", "port": port,
                          "settings": {"decryption": "none", "users": [{"id": ID, "flow": row.get("flow", "")}]},
                          "streamSettings": xray_stream(row, keys, True, decoy)}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32", "::1/128"]}]}}]}


def xray_client(row, keys, peer, socks, http, uuid):
    outbound = {"protocol": "vless",
                "settings": {"address": "127.0.0.1", "port": peer, "id": uuid, "encryption": "none",
                             "flow": row.get("flow", "")},
                "streamSettings": xray_stream(row, keys, False)}
    if row.get("mux"):
        outbound["mux"] = row["mux"]
    return {"log": {"loglevel": "info"},
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": socks,
                          "settings": {"udp": True, "ip": "127.0.0.1"}},
                         {"protocol": "http", "listen": "127.0.0.1", "port": http}],
            "outbounds": [outbound]}


def kerlico_client(row, keys, peer, socks, http, uuid):
    settings = {"id": uuid, "encryption": "none", "flow": row.get("flow", ""),
                "network": row["network"], "security": row["security"],
                "socks5Port": socks, "httpProxyPort": http,
                "socks5ListenLAN": False, "httpProxyListenLAN": False}
    if row.get("alpn"):
        settings["alpn"] = row["alpn"]
    if row["security"] == "tls":
        settings.update(serverName=NAME, pinnedPeerCertSha256=keys.pin)
    elif row["security"] == "reality":
        settings.update(serverName=NAME, publicKey=keys.public, shortId=SHORT_ID, fingerprint="chrome")
    if row["network"] in ("ws", "xhttp"):
        settings.update(path=PATH, host=NAME)
    if row["network"] == "xhttp":
        settings["mode"] = "auto"
    if row["network"] == "grpc":
        settings["serviceName"] = "matrix"
    if row.get("mux"):
        settings["mux"] = row["mux"]
    return {"protocol": "vless", "peer": f"127.0.0.1:{peer}", "settings": settings}


def kerlico_server(port):
    return {"warp": {"secretKey": "invalid"},
            "dns": {"hosts": {"localhost": ["127.0.0.1", "::1"]}},
            "inbounds": [{"tag": "fixture", "protocol": "vless", "listen": "127.0.0.1", "port": port,
                          "outbound": "default", "rules": [],
                          "settings": {"decryption": "none", "network": "raw", "security": "none",
                                       "users": [{"email": "test-user", "id": ID, "flow": ""}]}}]}


@contextlib.contextmanager
def server_process(args, folder, kind, row, keys, decoy, port):
    if kind == "xray":
        path = folder / "xray-server.json"
        mieru.write_json(path, xray_server(row, keys, decoy, port))
        with mieru.managed([args.xray_bin, "run", "-c", str(path)], folder, "xray-server") as server:
            mieru.wait_for(server, lambda: f"{XRAY_VERSION} started" in server.text())
            yield server
    else:
        path = folder / "kerlico-server.json"
        mieru.write_json(path, kerlico_server(port))
        mieru.write_json(folder / "warp.json", {"secretKey": "invalid"})
        with mieru.managed([args.server_bin, str(path)], folder, "kerlico-server") as server:
            mieru.wait_for(server, lambda: "vless" in server.text().splitlines())
            yield server


@contextlib.contextmanager
def client_process(args, folder, kind, row, keys, peer, uuid=ID, name="client"):
    socks, http = mieru.free_ports(2)
    if kind == "xray":
        path = folder / f"{name}.json"
        mieru.write_json(path, xray_client(row, keys, peer, socks, http, uuid))
        command = [args.xray_bin, "run", "-c", str(path)]
    else:
        path = folder / f"{name}.json"
        mieru.write_json(path, kerlico_client(row, keys, peer, socks, http, uuid))
        command = [args.client_bin, str(path)]
    with mieru.managed(command, folder, f"{kind}-{name}") as client:
        mieru.wait_for(client, lambda: mieru.ports_ready([socks, http]))
        yield client, socks, http


def associate(socks):
    control, bound = mieru.socks_connect(socks, "0.0.0.0", 0, 3)
    if bound[0] in ("0.0.0.0", "::"):
        bound = ("127.0.0.1", bound[1])
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    return control, udp, bound


def exchange(udp, bound, host, port, payload, source_port=None, timeout=mieru.IO_BUDGET):
    """Sends one datagram and checks the echo and the source the SOCKS reply names."""
    evidence = {"target": authority(host, port), "expected_length": len(payload), "expected_source": source_port or port}
    udp.settimeout(timeout)
    udp.sendto(b"\x00\x00\x00" + encode_address(host, port) + payload, bound)
    try:
        packet, sender = udp.recvfrom(65535)
    except socket.timeout as error:
        raise PacketFailure("UDP 没有回复", evidence) from error
    source, got = unpack_udp(packet)
    evidence.update(source=list(source), actual_length=len(got), sender=list(sender))
    if sender[1] != bound[1] or source[1] != (source_port or port) or got != payload:
        raise PacketFailure("UDP 内容或回复来源不符", evidence)


def dropped(udp, bound, fixture, payload):
    before = fixture.count
    udp.settimeout(1.5)
    udp.sendto(b"\x00\x00\x00" + encode_address("127.0.0.1", fixture.server_address[1]) + payload, bound)
    try:
        udp.recvfrom(65535)
        return False
    except socket.timeout:
        return fixture.count == before


def udp_check(socks, fixtures, row, kind, tap):
    control, udp, bound = associate(socks)
    with contextlib.closing(control), contextlib.closing(udp):
        since = tap.count() if tap else 0
        port4, port4b, port6 = (fixtures.udp4.server_address[1], fixtures.udp4b.server_address[1],
                                fixtures.udp6.server_address[1])
        for index, (host, port, source, length) in enumerate([
                ("127.0.0.1", port4, None, 1), ("127.0.0.1", port4b, None, 1279), ("::1", port6, None, 1400),
                ("localhost", port4, None, 7000),
                ("127.0.0.1", fixtures.reflector.server_address[1], fixtures.reflector.answer.getsockname()[1], 3)]):
            mieru.run_phase(f"udp-{index}", lambda: exchange(udp, bound, host, port, bytes([index + 1]) * length, source))
        pending = [b"order-a", b"order-b" * 19, b"order-c" * 300]
        for payload in pending:
            udp.sendto(b"\x00\x00\x00" + encode_address("127.0.0.1", port4) + payload, bound)
        udp.settimeout(mieru.IO_BUDGET)
        for payload in pending:
            require(unpack_udp(udp.recvfrom(65535)[0])[1] == payload, "UDP 连发的顺序或边界不符")
        expected = row.get("policy", {}).get(kind, {})
        for port, fixture in ((53, fixtures.udp53), (443, fixtures.udp443)):
            if port not in expected:
                continue
            if expected[port]:
                mieru.run_phase(f"udp-{port}", lambda: exchange(udp, bound, "127.0.0.1", port, f"to-{port}".encode()))
            else:
                require(dropped(udp, bound, fixture, f"to-{port}".encode()), f"UDP/{port} 应被丢弃，却到达了目标")
        lanes = None
        if tap and row.get("tap") == "udp-lanes":
            lanes = dict(collections.Counter(tap.commands(since)))
            require(lanes == UDP_LANES[kind], f"UDP 关联的承载命令不符：{lanes}")
        control.close()
        time.sleep(0.3)
        before = fixtures.udp_count()
        require(dropped(udp, bound, fixtures.udp4, b"after-close") and fixtures.udp_count() == before,
                "控制连接关闭后 UDP 关联仍在转发")
        return lanes


def http_check(http, fixtures):
    # Xray's http inbound keeps the connection only when the request says Proxy-Connection.
    with socket.create_connection(("127.0.0.1", http), 5) as conn:
        conn.settimeout(mieru.IO_BUDGET)
        for index, server in enumerate([fixtures.http4, fixtures.http4b]):
            target = authority("127.0.0.1", server.server_address[1])
            path = f"/keepalive-{index}"
            conn.sendall(f"GET http://{target}{path} HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n"
                         f"Proxy-Connection: keep-alive\r\n\r\n".encode())
            status, body = mieru.read_http_response(conn)
            require(status == 200 and body == server.label.encode() + b"|" + path.encode() + b"|",
                    "同一 HTTP 连接上第二个目标的应答不符" if index else "HTTP GET 应答不符")
    target = authority("127.0.0.1", fixtures.tcp4.server_address[1])
    payload = b"connect-pipelined-prefix\x00" * 100
    with socket.create_connection(("127.0.0.1", http), 5) as conn:
        conn.settimeout(mieru.IO_BUDGET)
        conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode() + payload)
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            require(len(header) < 16384, "CONNECT 应答头部超限")
            header.extend(mieru.exact(conn, 1))
        require(header.split(b"\r\n", 1)[0].split()[1] == b"200", "CONNECT 状态不符")
        require(mieru.exact(conn, len(payload)) == payload, "CONNECT 预读字节丢失")


def wrong_id_check(args, folder, kind, row, keys, peer, fixtures):
    before = fixtures.tcp4.count
    with client_process(args, folder, kind, row, keys, peer, WRONG_ID, "wrong-id") as (_, socks, _http):
        denied = False
        try:
            conn, _ = mieru.socks_connect(socks, "127.0.0.1", fixtures.tcp4.server_address[1])
            with conn:
                conn.settimeout(5)
                conn.sendall(b"must-not-reach-echo")
                denied = not conn.recv(64)
        except (Failure, OSError):
            denied = True
    require(denied and fixtures.tcp4.count == before, "错误 UUID 的流到达了回显目标")


def row_case(args, folder, name, kind, fixtures):
    row = ROWS[name]
    keys = Keys(args.xray_bin, folder)
    decoy = Decoy(keys) if row["security"] == "reality" else None
    peer = mieru.free_ports(1)[0]
    tap = Tap(peer) if row.get("tap") else None
    record = {}
    try:
        with server_process(args, folder, "xray", row, keys, decoy, peer) as server:
            with client_process(args, folder, kind, row, keys, tap.port if tap else peer) as (client, socks, http):
                record["tcp_flows"] = len(mieru.run_phase("tcp", lambda: mieru.tcp_check(socks, fixtures.tcp_targets()))["flows"])
                record["udp_lanes"] = mieru.run_phase("udp", lambda: udp_check(socks, fixtures, row, kind, tap))
                mieru.run_phase("http", lambda: http_check(http, fixtures))
                client.ensure_alive()
            if tap and row.get("tap") == "all-mux":
                commands = set(tap.commands())
                record["commands"] = sorted(commands)
                require(commands == {"mux"}, f"启用 Mux 后仍有其他承载命令：{sorted(commands)}")
            mieru.run_phase("wrong-id", lambda: wrong_id_check(args, folder, kind, row, keys, tap.port if tap else peer, fixtures))
            server.ensure_alive()
    finally:
        if tap:
            tap.close()
        if decoy:
            decoy.close()
    return record


def resend_until_echo(udp, bound, port, payload, seconds=15):
    """After a cut the first datagrams may meet the dead carrier, as UDP may lose them."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            exchange(udp, bound, "127.0.0.1", port, payload, timeout=0.4)
            return
        except PacketFailure:
            continue
    raise Failure("切断承载后再发送的数据报始终没有回复")


def reattach_case(args, folder, server_kind, client_kind, fixtures):
    """GlobalID keeps the origin's view of the source port across carriers; a plain UDP link,
    which has no GlobalID, shows the check would see a change."""
    row = ROWS["raw-none"]
    keys = Keys(args.xray_bin, folder)
    peer = mieru.free_ports(1)[0]
    tap = Tap(peer)
    record = {}
    try:
        with server_process(args, folder, server_kind, row, keys, None, peer), \
                client_process(args, folder, client_kind, row, keys, tap.port) as (client, socks, _http):
            for label, fixture, same in (("xudp", fixtures.recorder, True), ("plain-udp", fixtures.udp53, False)):
                control, udp, bound = associate(socks)
                with contextlib.closing(control), contextlib.closing(udp):
                    port = fixture.server_address[1]
                    since = tap.count()
                    exchange(udp, bound, "127.0.0.1", port, f"{label}-before".encode())
                    before = fixture.sources[-1]
                    command = tap.commands(since)
                    tap.cut()
                    time.sleep(0.5)
                    resend_until_echo(udp, bound, port, f"{label}-after".encode())
                    after = fixture.sources[-1]
                    record[label] = {"commands": command, "before": before, "after": after}
                    require(command == (["mux"] if same else ["udp"]), f"{label} 的承载命令不符：{command}")
                    if same:
                        require(after == before, f"GlobalID 续接后源站看到的源端口从 {before} 变成 {after}")
                    else:
                        require(after != before, "独立 UDP 承载切断后源端口未变，这项检查无法区分续接")
            client.ensure_alive()
    finally:
        tap.close()
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray-bin", required=True)
    parser.add_argument("--client-bin", required=True, help="kerlico-client，启用 vless feature")
    parser.add_argument("--server-bin", required=True, help="kerlico-server，启用 vless feature")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", default=",".join(ROWS), help="逗号分隔的行名")
    parser.add_argument("--clients", default="kerlico,xray", help="kerlico、xray 或两者")
    parser.add_argument("--skip-reattach", action="store_true")
    parser.add_argument("--case-timeout", type=float, default=120)
    args = parser.parse_args()
    rows = [row for row in args.rows.split(",") if row]
    clients = [kind for kind in args.clients.split(",") if kind]
    for row in rows:
        if row not in ROWS:
            parser.error(f"未知行 {row}")
    for kind in clients:
        if kind not in ("kerlico", "xray"):
            parser.error(f"未知客户端 {kind}")
    for name in ("xray_bin", "client_bin", "server_bin"):
        value = Path(getattr(args, name)).resolve()
        if not value.is_file() or not os.access(value, os.X_OK):
            parser.error(f"{name} 不是可执行文件")
        setattr(args, name, str(value))
    version = subprocess.run([args.xray_bin, "version"], stdout=subprocess.PIPE, text=True, timeout=20).stdout
    if not version.startswith(XRAY_VERSION + " ") or XRAY_BUILD not in version.split("\n", 1)[0]:
        parser.error(f"需要固定版本 {XRAY_VERSION} {XRAY_BUILD}")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_root = Path(tempfile.mkdtemp(prefix=output.stem + "-cases-", dir=output.parent))
    result = {"status": "fail", "xray": version.split("\n", 1)[0], "cases": []}

    def timeout(_signum, _frame):
        raise Failure("当前 case 超时")

    signal.signal(signal.SIGALRM, timeout)

    def run_case(name, function):
        folder = run_root / name
        folder.mkdir(mode=0o700, parents=True)
        record = {"name": name, "status": "fail", "logs": str(folder.relative_to(output.parent))}
        started = time.monotonic()
        try:
            signal.setitimer(signal.ITIMER_REAL, args.case_timeout)
            record["observed"] = function(folder)
            record["status"] = "pass"
        except Exception as error:
            record["error"] = str(error)
            record["evidence"] = getattr(error, "evidence", None) or {
                "error_type": type(error).__name__,
                "frames": [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                           for frame in traceback.extract_tb(error.__traceback__)]}
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        record["seconds"] = round(time.monotonic() - started, 3)
        result["cases"].append(record)
        mieru.write_json(output, result)
        print(f"{record['status']}: {name}" + (f" ({record['error']})" if record["status"] != "pass" else ""), flush=True)

    with Fixtures() as fixtures:
        for row in rows:
            for kind in clients:
                run_case(f"{row}/{kind}-client", lambda folder, r=row, k=kind: row_case(args, folder, r, k, fixtures))
        if not args.skip_reattach:
            for server_kind in ("xray", "kerlico"):
                for kind in clients:
                    run_case(f"reattach/{server_kind}-server/{kind}-client",
                             lambda folder, s=server_kind, k=kind: reattach_case(args, folder, s, k, fixtures))
    passed = sum(case["status"] == "pass" for case in result["cases"])
    if result["cases"] and passed == len(result["cases"]):
        result["status"] = "pass"
    mieru.write_json(output, result)
    print(f"{result['status']}: {passed}/{len(result['cases'])} VLESS 客户端入口互通验收", flush=True)
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
