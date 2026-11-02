#!/usr/bin/env python3
from config_v2 import bind_members
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from enum import Enum
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import time

import interop_vless as h
from mihomo_ready import add_probe, wait_running

NAME = "tt.example.invalid"
PASSWORDS = ("tt-node4-only-secret", "tt-node6-only-secret")
ALLOCATED_PORTS = set()


class SetupFailure(RuntimeError):
    def __init__(self, phase, directory, error):
        super().__init__("本任务独立夹具准备失败")
        self.phase = phase
        self.directory = directory
        self.error_type = type(error).__name__
        self.os_error = getattr(error, "winerror", None) or getattr(error, "errno", None)


@contextmanager
def setup(phase, directory):
    try:
        yield
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SetupFailure(phase, directory, error) from error


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    path.chmod(0o600)


def diagnostics(directory):
    result = []
    patterns = {
        "certificate-path-rejected": ("safe_paths", "not subpath"),
        "certificate-authority-rejected": ("unknown authority", "unknown ca", "unknownissuer"),
        "certificate-pin-rejected": ("certificate fingerprints do not match",),
        "certificate-name-rejected": ("certificate is valid for", "not valid for", "hostname mismatch"),
        "certificate-client-rejected": ("certificate required", "bad certificate"),
        "listen-address-unavailable": ("address already in use", "only one usage", "cannot assign requested address"),
        "authentication-rejected": ("status code: 407", "authentication failed"),
    }
    for path in sorted(directory.glob("*.log")):
        data = path.read_bytes()
        lower = data.decode("utf-8", errors="replace").lower()
        result.append({"log": path.name, "sha256": hashlib.sha256(data).hexdigest(),
                       "categories": [name for name, fragments in patterns.items() if any(part in lower for part in fragments)]})
    return result


@contextmanager
def process(command, directory, label):
    environment = os.environ.copy()
    environment["SAFE_PATHS"] = ""
    flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    with (directory/(label+".log")).open("xb") as log:
        child = subprocess.Popen(command, cwd=directory, env=environment, stdout=log,
                                 stderr=subprocess.STDOUT, creationflags=flags)
        try:
            yield child
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)


class Udp4(h.UdpServer):
    max_packet_size = 65535


class Udp6(Udp4):
    address_family = socket.AF_INET6


class Greeting(h.TcpEcho):
    def handle(self):
        self.request.sendall(b"hello|")
        super().handle()


class DnsReject(socketserver.BaseRequestHandler):
    def handle(self):
        data, stream = self.request
        if len(data) >= 12:
            stream.sendto(data[:2]+b"\x81\x83"+data[4:6]+b"\0"*6+data[12:], self.client_address)


def address(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def port(host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for _ in range(256):
        number = 16000 + int.from_bytes(os.urandom(2), "big") % 12000
        key = (host, number)
        if key in ALLOCATED_PORTS:
            continue
        try:
            with socket.socket(family) as tcp, socket.socket(family, socket.SOCK_DGRAM) as udp:
                if os.name == "nt":
                    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                tcp.bind((host, number))
                udp.bind((host, number))
                ALLOCATED_PORTS.add(key)
                return number
        except OSError:
            continue
    raise RuntimeError("本任务回环端口分配失败")


def exact(stream, length):
    result = bytearray()
    while len(result) < length:
        part = stream.recv(length-len(result))
        if not part:
            raise RuntimeError("目标数据提前结束")
        result.extend(part)
    return bytes(result)


def ready(child, host, number):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("本任务进程在就绪前退出")
        try:
            if socket_owned(child, host, number, "tcp"):
                with socket.create_connection((host, number), timeout=0.2):
                    return
        except OSError:
            pass
        time.sleep(0.02)
    raise RuntimeError("本任务监听就绪超时")


def live(child):
    # QUIC 没有 TCP 探针；实际业务 CONNECT 是其握手就绪检查。
    if child.poll() is not None:
        raise RuntimeError("本任务 QUIC 进程已退出")


def socket_owned(child, host, number, protocol):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        library = ctypes.WinDLL("iphlpapi", use_last_error=True)
        query = library.GetExtendedUdpTable if protocol == "udp" else library.GetExtendedTcpTable
        query.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
                          wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
        query.restype = wintypes.ULONG
        size = wintypes.ULONG()
        table_class = 1 if protocol == "udp" else 3
        status = query(None, ctypes.byref(size), False, family, table_class, 0)
        if status != 122:
            raise RuntimeError("本任务监听所有者查询失败")
        buffer = ctypes.create_string_buffer(size.value)
        status = query(buffer, ctypes.byref(size), False, family, table_class, 0)
        if status == 122:
            return False
        if status:
            raise RuntimeError("本任务监听所有者查询失败")
        rows = buffer.raw
        count = struct.unpack_from("=I", rows)[0]
        if protocol == "udp":
            stride, address_offset, port_offset = (28, 0, 20) if family == socket.AF_INET6 else (12, 0, 4)
        else:
            stride, address_offset, port_offset = (56, 0, 20) if family == socket.AF_INET6 else (24, 4, 8)
        if 4+count*stride > len(rows):
            raise RuntimeError("本任务监听所有者表长度不合法")
        packed = ipaddress.ip_address(host).packed
        for index in range(count):
            start = 4+index*stride
            owner = struct.unpack_from("=I", rows, start+stride-4)[0]
            local_port = socket.ntohs(struct.unpack_from("=I", rows, start+port_offset)[0] & 0xffff)
            begin = start+address_offset
            if owner == child.pid and local_port == number and rows[begin:begin+len(packed)] == packed:
                return True
        return False
    if not sys.platform.startswith("linux"):
        raise RuntimeError("当前平台尚无本任务监听所有者查询实现")
    own = set()
    for fd in Path(f"/proc/{child.pid}/fd").iterdir():
        try:
            link = os.readlink(fd)
            if link.startswith("socket:["):
                own.add(link[8:-1])
        except OSError:
            pass
    for table in [f"/proc/net/{protocol}", f"/proc/net/{protocol}6"]:
        for line in Path(table).read_text(encoding="ascii").splitlines()[1:]:
            values = line.split()
            if (protocol == "udp" or values[3] == "0A") and int(values[1].split(":")[1], 16) == number and values[9] in own:
                return True
    return False


def ready_udp(child, host, number):
    deadline = time.monotonic()+8
    while time.monotonic() < deadline:
        live(child)
        if socket_owned(child, host, number, "udp"):
            return
        time.sleep(0.02)
    raise RuntimeError("本任务 QUIC 监听未在预算内就绪")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked(path, expected):
    if not path or not expected or digest(path) != expected:
        raise RuntimeError("固定对端缺失或二进制摘要不符")
    return str(Path(path).resolve())


def material(root, openssl):
    def run(*args):
        result = subprocess.run([openssl, *args], cwd=root, capture_output=True, timeout=30,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if result.returncode:
            raise RuntimeError("生成测试 CA/证书失败")
    ca, cakey = root/"ca.pem", root/"ca-key.pem"
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cakey), "-out", str(ca), "-days", "1", "-subj", "/CN=TrustTunnel-test-CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    output = {"ca": ca}
    for role in ("server", "client"):
        key, csr, cert, ext = (root/(role+suffix) for suffix in ("-key.pem", ".csr", ".pem", ".ext"))
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN="+NAME)
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+("serverAuth" if role == "server" else "clientAuth")+"\nsubjectAltName=DNS:"+NAME+"\n", encoding="ascii")
        run("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(ext))
        output[role], output[role+"_key"] = cert, key
    chain = root/"server-chain.pem"
    chain.write_text(output["server"].read_text(encoding="ascii")+ca.read_text(encoding="ascii"), encoding="ascii")
    output["server_chain"] = chain
    return output


def own_options(host, number, password, transport, version, certs, server, mtls):
    # 工具同时保留两条UDP flow并发四条TCP；测试需求6条物理H1连接，显式提供8个名额。
    common = {"transport": transport, "limits": {"idle_timeout_ms": 6000, "max_connections": 8, "max_streams": 64, "health_check_ms": 1000}}
    if server:
        common["limits"].pop("max_connections")
        common["limits"].pop("health_check_ms")
        tls = {"certificate_file": str(certs["server_chain"]), "private_key_file": str(certs["server_key"]), "version": version}
        if mtls:
            tls["client_ca_pem"] = certs["ca"].read_text()
        return {**common, "users": [{"username": "test", "password": password}], "tls": tls}
    tls = {"server_name": NAME, "ca_pem": certs["ca"].read_text(), "version": version}
    if mtls:
        tls.update(certificate_pem=certs["client"].read_text(), private_key_pem=certs["client_key"].read_text())
    return {**common, "server": {"host": host, "port": number}, "auth": {"username": "test", "password": password}, "tls": tls, "app_name": "worker-test"}


def own_node(host, number, password, transport, version, certs, mtls):
    config = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node", "type": "trusttunnel", "listen": address(host, number), "outbound": "direct", "options": own_options(host, number, password, transport, version, certs, True, mtls)}], "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 6000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65507}}
    node = config["nodes"][0]
    bind_members(config, node, node["options"].pop("users"))
    return config


def official_node(directory, host, number, password, transport, certs, log_level):
    clients, settings, tls = directory/"credentials.toml", directory/"endpoint.toml", directory/"tls.toml"
    clients.write_text('[[client]]\nusername = "test"\npassword = '+json.dumps(password)+'\n')
    # 未设置 icmp、反向站点、metrics、Sentry；默认无对应资源。
    kind = {"h1": "http1", "h2": "http2", "h3": "quic"}[transport]
    settings.write_text("listen_address = "+json.dumps(address(host, number))+"\nipv6_available = true\nallow_private_network_connections = true\ncredentials_file = "+json.dumps(str(clients))+"\nconnection_establishment_timeout_secs = 3\nclient_listener_timeout_secs = 6\ntcp_connections_timeout_secs = 6\nudp_connections_timeout_secs = 6\n[listen_protocols."+kind+"]\n")
    tls.write_text('[[main_hosts]]\nhostname = '+json.dumps(NAME)+'\ncert_chain_path = '+json.dumps(str(certs["server_chain"]))+'\nprivate_key_path = '+json.dumps(str(certs["server_key"]))+'\n', encoding="utf-8")
    return [str(settings), str(tls), "--jobs", "1", "--loglvl", log_level]


def mihomo_common():
    return {"mode": "rule", "log-level": "warning", "allow-lan": False, "ipv6": True, "dns": {"enable": False}, "tun": {"enable": False}, "ntp": {"enable": False}, "profile": {"store-selected": False}}


def mihomo_node(host, number, password, transport, certs, mtls):
    config = mihomo_common()
    listener = {"name": "node", "type": "trusttunnel", "listen": host, "port": str(number), "users": [{"username": "test", "password": password}], "certificate": certs["server_chain"].read_text(encoding="ascii"), "private-key": certs["server_key"].read_text(encoding="ascii"), "network": ["udp" if transport == "h3" else "tcp"]}
    if mtls:
        listener.update({"client-auth-cert": certs["ca"].read_text(encoding="ascii")})
    config.update({"listeners": [listener], "rules": ["MATCH,DIRECT"]})
    return add_probe(config)


def official_client(directory, host, number, password, transport, certs, socks, dns):
    path = directory/"client.toml"
    path.write_text('loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = true\npost_quantum_group_enabled = false\nexclusions_preresolve_enabled = false\nexclusions = []\n[endpoint]\nhostname = '+json.dumps(NAME)+'\naddresses = ['+json.dumps(address(host, number))+']\nhas_ipv6 = true\nusername = "test"\npassword = '+json.dumps(password)+'\nskip_verification = false\ncertificate = '+json.dumps(certs["ca"].read_text())+'\nupstream_protocol = '+json.dumps("http3" if transport == "h3" else "http2")+'\nanti_dpi = false\ndns_upstreams = ['+json.dumps(address("127.0.0.1", dns))+']\n[listener.socks]\naddress = '+json.dumps(address("127.0.0.1", socks))+'\n')
    return ["--config", str(path)]


def mihomo_client(host, number, password, transport, certs, socks, mtls):
    config = mihomo_common()
    # 非叶CA指纹分支仍验证证书链、名称和有效期，不依赖解析后重置的全局CA池。
    ca_der = ssl.PEM_cert_to_DER_cert(certs["ca"].read_text(encoding="ascii"))
    proxy = {"name": "proxy", "type": "trusttunnel", "server": host, "port": number, "username": "test", "password": password, "sni": NAME, "fingerprint": hashlib.sha256(ca_der).hexdigest(), "skip-cert-verify": False, "udp": True, "quic": transport == "h3", "max-connections": 4, "max-streams": 64}
    if mtls:
        proxy.update(certificate=certs["client"].read_text(encoding="ascii"), **{"private-key": certs["client_key"].read_text(encoding="ascii")})
    config.update({"socks-port": socks, "proxies": [proxy], "rules": ["MATCH,proxy"]})
    return add_probe(config)


def socks_open(number, target, command=1):
    stream = socket.create_connection(("127.0.0.1", number), timeout=5)
    try:
        stream.settimeout(5)
        stream.sendall(b"\x05\x01\x00")
        if exact(stream, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS 方法不符")
        host, number = target
        ip = ipaddress.ip_address(host)
        packed = bytes([1 if ip.version == 4 else 4])+ip.packed+struct.pack("!H", number)
        stream.sendall(b"\x05"+bytes([command])+b"\x00"+packed)
        prefix = exact(stream, 4)
        if prefix[:2] != b"\x05\x00":
            raise RuntimeError("SOCKS 目标被拒绝")
        size = {1: 4, 4: 16}.get(prefix[3])
        if size is None:
            raise RuntimeError("SOCKS 绑定地址不合法")
        ip = str(ipaddress.ip_address(exact(stream, size)))
        bind = (ip, struct.unpack("!H", exact(stream, 2))[0])
        return stream, bind
    except BaseException:
        stream.close()
        raise


def socks_udp(number, target, payload, on_reply=None):
    control, bind = socks_open(number, ("0.0.0.0", 0), 3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        ip = ipaddress.ip_address(target[0])
        head = b"\0\0\0"+bytes([1 if ip.version == 4 else 4])+ip.packed+struct.pack("!H", target[1])
        if bind[0] in ("0.0.0.0", "::"):
            bind = ("127.0.0.1", bind[1])
        udp.sendto(head+payload, bind)
        result = udp.recv(65535)
        if on_reply is not None:
            on_reply()
        length = {1: 4, 4: 16}.get(result[3]) if len(result) > 3 else None
        if length is None or result[:3] != b"\0\0\0":
            raise RuntimeError("SOCKS UDP 回包不合法")
        source = (str(ipaddress.ip_address(result[4:4+length])), struct.unpack("!H", result[4+length:6+length])[0])
        if source != target:
            raise RuntimeError("SOCKS UDP 来源不符")
        return result[6+length:]


def wire_open(host, number, authority, password, version, certs, mtls):
    context = ssl.create_default_context(cafile=str(certs["ca"]))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if version == "tls12" else ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["http/1.1"])
    if mtls:
        context.load_cert_chain(str(certs["client"]), str(certs["client_key"]))
    raw = socket.create_connection((host, number), timeout=5)
    stream = context.wrap_socket(raw, server_hostname=NAME)
    try:
        auth = base64.b64encode(("test:"+password).encode()).decode()
        stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: linux wire-test\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            if len(response) == 1024:
                raise RuntimeError("H1 响应头超限")
            response.extend(exact(stream, 1))
        if not response.startswith(b"HTTP/1.1 200 "):
            raise RuntimeError("H1 CONNECT 被拒绝")
        return stream
    except BaseException:
        stream.close()
        raise


def padded(host):
    ip = ipaddress.ip_address(host)
    return b"\0"*12+ip.packed if ip.version == 4 else ip.packed


def wire_udp(host, number, password, version, certs, mtls, target, payload):
    with wire_open(host, number, "_udp2", password, version, certs, mtls) as stream:
        record = b"\0"*18+padded(target[0])+struct.pack("!H", target[1])+b"\0"+payload
        stream.sendall(struct.pack("!I", len(record))+record)
        length = struct.unpack("!I", exact(stream, 4))[0]
        if not 36 <= length <= 36+65507:
            raise RuntimeError("H1 UDP 回包长度不合法")
        record = exact(stream, length)
        if record[:18] != padded(target[0])+struct.pack("!H", target[1]):
            raise RuntimeError("H1 UDP 真实来源不符")
        if record[18:36] != b"\0"*18:
            raise RuntimeError("H1 UDP 未保留未知源关联标记")
        return record[36:]


def record(records, case, action, boundary=False, rejected=False, phase="business", directory=None):
    output = {"case": case, "phase": phase, "boundary": boundary, "expected_rejection": rejected}
    try:
        action()
        output["outcome"] = "pass"
    except (OSError, RuntimeError, TimeoutError, AssertionError) as error:
        output.update(outcome="observed-limit" if boundary else "fail", error_type=type(error).__name__)
    if directory is not None:
        output["diagnostics"] = diagnostics(directory)
    records.append(output)
    return output["outcome"] != "fail"


def check_equal(actual, expected):
    if actual != expected:
        raise RuntimeError("回包内容不符")


class ProbeState(str, Enum):
    REQUEST_FAILED = "request-failed"
    TUNNEL_ESTABLISHED = "tunnel-established"
    BUSINESS_SUCCESS = "business-success"
    SETUP_FAILED = "setup-failed"


class TlsNegativeState(str, Enum):
    REJECTED = "tls-rejected"
    ACCEPTED = "business-accepted"
    UNRELATED_FAILURE = "unrelated-failure"
    INSUFFICIENT_EVIDENCE = "insufficient-evidence"


@dataclass(frozen=True)
class TlsProbe:
    state: ProbeState
    client_running: bool
    server_running: bool
    listener_owned: bool
    log: bytes = b""
    log_start: int = 0
    error_type: str | None = None

    def summary(self, log_name="client.log"):
        return {"state": self.state.value, "client_running": self.client_running,
                "server_running": self.server_running, "listener_owned": self.listener_owned,
                "log": log_name, "log_start": self.log_start,
                "log_end": self.log_start+len(self.log),
                "log_segment_sha256": hashlib.sha256(self.log).hexdigest(),
                "error_type": self.error_type}


def tls_negative_verdict(variant, network, target, positive, negative):
    text = negative.log.decode("utf-8", errors="replace")
    established = re.compile(r"\["+network.upper()+r"\] [^\r\n]* --> "+re.escape(address(*target))+r" (?:match [^\r\n]* )?using proxy(?:[\"\s]|$)")
    if negative.state in (ProbeState.TUNNEL_ESTABLISHED, ProbeState.BUSINESS_SUCCESS) or established.search(text):
        return TlsNegativeState.ACCEPTED, "负例已取得隧道或业务回包"
    if not all((negative.client_running, negative.server_running, negative.listener_owned)) or negative.state == ProbeState.SETUP_FAILED:
        return TlsNegativeState.UNRELATED_FAILURE, "负例进程、监听或准备失败"
    if positive.state != ProbeState.BUSINESS_SUCCESS or not all((positive.client_running, positive.server_running, positive.listener_owned)):
        return TlsNegativeState.INSUFFICIENT_EVIDENCE, "同目标同数据类型的正向对照无效"
    prefix = re.compile(r"\["+network.upper()+r"\] dial proxy(?: \(match [^\r\n]*\))? [^\r\n]* --> "+re.escape(address(*target))+r" error: (.*)")
    errors = [match.group(1).lower() for line in text.splitlines()
              if (match := prefix.search(line))]
    expected = {"wrong-ca": "certificate fingerprints do not match",
                "wrong-name": "x509: certificate is valid for "+NAME+", not wrong.example.invalid"}[variant]
    if errors and all(expected in error for error in errors):
        return TlsNegativeState.REJECTED, "本次目标拨号明确因预期证书检查被拒绝"
    if errors:
        return TlsNegativeState.UNRELATED_FAILURE, "目标拨号错误不符合本用例预期类别"
    return TlsNegativeState.INSUFFICIENT_EVIDENCE, "仅EOF、超时或无对应TLS拨号错误不足以证明拒绝"


def wait_for_failed_request_log_window(client):
    deadline = time.monotonic()+1
    while time.monotonic() < deadline:
        if client.poll() is not None:
            return
        time.sleep(0.02)


def observe_tls_probe(args, directory, server, host, number, password, transport, certs, target, network, variant):
    directory.mkdir(mode=0o700)
    socks = port()
    config = mihomo_client(host, number, password, transport, certs, socks, args.mtls)
    config["log-level"] = "info"
    if variant == "wrong-ca":
        config["proxies"][0]["fingerprint"] = "00"*32
    elif variant == "wrong-name":
        config["proxies"][0]["sni"] = "wrong.example.invalid"
    path = directory/"client.json"
    write_json(path, config)
    client = None
    state = ProbeState.SETUP_FAILED
    start = 0
    error_type = None
    log_path = directory/"client.log"
    try:
        with process([args.peer, "-d", str(directory/"reference-state"), "-f", str(path)], directory, "client") as client:
            try:
                ready(client, "127.0.0.1", socks)
                wait_running(client, config)
                start = log_path.stat().st_size
                state = ProbeState.REQUEST_FAILED
                if network == "tcp":
                    stream, _ = socks_open(socks, target)
                    # Mihomo先回复本地SOCKS成功；目标问候才证明远端隧道已建立。
                    with stream:
                        check_equal(exact(stream, 6), b"hello|")
                        state = ProbeState.TUNNEL_ESTABLISHED
                        payload = b"tls-control"
                        stream.sendall(struct.pack("!I", len(payload))+payload)
                        check_equal(exact(stream, len(payload)), payload)
                else:
                    def received():
                        nonlocal state
                        state = ProbeState.TUNNEL_ESTABLISHED
                    check_equal(socks_udp(socks, target, b"tls-control", received), b"tls-control")
                state = ProbeState.BUSINESS_SUCCESS
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                error_type = type(error).__name__
            if state == ProbeState.REQUEST_FAILED:
                wait_for_failed_request_log_window(client)
            running = client.poll() is None
            owned = running and socket_owned(client, "127.0.0.1", socks, "tcp")
            return TlsProbe(state, running, server.poll() is None, owned,
                            log_path.read_bytes()[start:], start, error_type)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        return TlsProbe(ProbeState.SETUP_FAILED, False, server.poll() is None, False,
                        error_type=type(error).__name__)


def record_tls_negative(records, case, variant, network, target, positive, negative):
    state, reason = tls_negative_verdict(variant, network, target, positive, negative)
    records.append({"case": case, "phase": "tls-control", "boundary": False,
                    "expected_rejection": True, "outcome": "pass" if state == TlsNegativeState.REJECTED else "fail",
                    "tls_negative_state": state.value, "reason": reason,
                    "positive_control": positive.summary(network+"/positive/client.log"),
                    "negative_probe": negative.summary(network+"/negative/client.log")})


def save_result(args, root, records):
    write_json(root/"result.json", {
        "mode": args.mode,
        "platform": sys.platform,
        "mihomo_trust": "task-ca-chain-pin" if args.mode == "mihomo" else None,
        "mihomo_h2_alpn_mode": {"kerlico_client": "explicit-allow-missing", "kerlico_node": "strict"} if args.mode == "mihomo" else None,
        "kerlico_sha256": args.kerlico_sha256,
        "peer_sha256": args.peer_hashes,
        "records": records,
    })


def tcp_stream(stream, payload, greeting=False):
    with stream:
        if greeting:
            check_equal(exact(stream, 6), b"hello|")
        stream.sendall(struct.pack("!I", len(payload))+payload)
        check_equal(exact(stream, len(payload)), payload)


def verify(args, root, certs, direction, transport, version, host, index, records):
    label = f"{args.mode}-{direction}-{transport}-{version}-node{'6' if index else '4'}"+("-mtls" if args.mtls else "")
    directory = root/label
    with setup("case-directory", directory):
        directory.mkdir(mode=0o700)
        number = port(host)
    password = PASSWORDS[index]
    with ExitStack() as stack:
        with setup("target-prepare", directory):
            dns = stack.enter_context(h.serve(Udp4(("127.0.0.1", 0), DnsReject)))
            targets = []
            for site, tcp_class, udp_class in [(args.target4, h.TcpServer, Udp4), (args.target6, h.TcpServer6, Udp6)]:
                tcp = stack.enter_context(h.serve(tcp_class((site, 0), Greeting)))
                udp = stack.enter_context(h.serve(udp_class((site, 0), h.UdpEcho)))
                targets.append((site, tcp, udp))
        if direction == "client" and args.mode != "self":
            if args.mode == "official":
                command = [args.peer_endpoint, *official_node(directory, host, number, password, transport, certs,args.reference_log_level)]
            else:
                config = mihomo_node(host, number, password, transport, certs, args.mtls)
                path = directory/"reference.json"
                write_json(path, config)
                command = [args.peer, "-d", str(directory/"reference-state"), "-f", str(path)]
        else:
            path = directory/"node.json"
            write_json(path, own_node(host, number, password, transport, version, certs, args.mtls))
            command = [args.kerlico, "run", "-c", str(path)]
        with setup("server-launch", directory):
            server = stack.enter_context(process(command, directory, "server"))
        with setup("server-ready", directory):
            if transport != "h3":
                ready(server, host, number)
            else:
                ready_udp(server, host, number)
            if direction == "client" and args.mode == "mihomo":
                wait_running(server, config)
        variants = ["wrong", "valid"]
        if args.mode == "mihomo" and direction == "node":
            variants += ["wrong-ca", "wrong-name"]
        for variant in variants:
            wrong = variant != "valid"
            sub = directory/variant
            sub.mkdir(mode=0o700)
            if variant in ("wrong-ca", "wrong-name"):
                for network, target_port in [("tcp", targets[0][1]), ("udp", targets[0][2])]:
                    probe_directory = sub/network
                    probe_directory.mkdir(mode=0o700)
                    target = (targets[0][0], target_port)
                    positive = observe_tls_probe(args, probe_directory/"positive", server, host, number,
                                                 password, transport, certs, target, network, "valid")
                    negative = observe_tls_probe(args, probe_directory/"negative", server, host, number,
                                                 password, transport, certs, target, network, variant)
                    suffix = "-auth" if network == "tcp" else "-udp-auth"
                    record_tls_negative(records, label+"-"+variant+suffix, variant, network, target, positive, negative)
                continue
            supplied = PASSWORDS[1-index] if variant == "wrong" else password
            forwards = []
            socks = None
            udp_sockets = {}
            if direction == "client" or args.mode == "self":
                options = own_options(host, number, supplied, transport, version, certs, False, args.mtls)
                if args.mode == "mihomo" and transport == "h2":
                    options["tls"]["h2_allow_missing_alpn"] = True
                for i, (site, tcp, udp) in enumerate(targets):
                    for network, target in [("tcp", tcp), ("udp", udp)]:
                        local = port()
                        forwards.append({"tag": f"{network}{i}", "type": network+"-forward", "listen": address("127.0.0.1", local), "target": {"host": site, "port": target}, "outbound": "proxy"})
                config = {"version": 2, "outbounds": [{"tag": "proxy", "type": "trusttunnel", "options": options}], "inbounds": forwards, "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 6000, "drain_timeout_ms": 500, "max_datagram_size": 65507}}
                path = sub/"client.json"
                write_json(path, config)
                with setup("client-launch", sub):
                    client = stack.enter_context(process([args.kerlico, "run", "-c", str(path)], sub, "client"))
                with setup("client-ready", sub):
                    ready(client, "127.0.0.1", int(forwards[0]["listen"].rsplit(":", 1)[1]))
            elif args.mode != "wire":
                socks = port()
                if args.mode == "official":
                    command = [args.peer_client, *official_client(sub, host, number, supplied, transport, certs, socks, dns)]
                else:
                    path = sub/"client.json"
                    config = mihomo_client(host, number, supplied, transport, certs, socks, args.mtls)
                    write_json(path, config)
                    command = [args.peer, "-d", str(sub/"reference-state"), "-f", str(path)]
                with setup("client-launch", sub):
                    client = stack.enter_context(process(command, sub, "client"))
                with setup("client-ready", sub):
                    ready(client, "127.0.0.1", socks)
                    if args.mode == "mihomo":
                        wait_running(client, config)
            def open_tcp(site_index):
                target = (targets[site_index][0], targets[site_index][1])
                if forwards:
                    local = int(forwards[2*site_index]["listen"].rsplit(":", 1)[1])
                    return socket.create_connection(("127.0.0.1", local), timeout=5)
                if socks:
                    return socks_open(socks, target)[0]
                return wire_open(host, number, address(*target), supplied, version, certs, args.mtls)
            def udp(site_index, payload):
                target = (targets[site_index][0], targets[site_index][2])
                if forwards:
                    local = int(forwards[2*site_index+1]["listen"].rsplit(":", 1)[1])
                    stream = udp_sockets.get(site_index)
                    if stream is None:
                        stream = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
                        stream.settimeout(3)
                        udp_sockets[site_index] = stream
                    stream.sendto(payload, ("127.0.0.1", local))
                    return stream.recv(65535)
                if socks:
                    return socks_udp(socks, target, payload)
                return wire_udp(host, number, supplied, version, certs, args.mtls, target, payload)
            if wrong:
                suffix = "-cross-node" if variant == "wrong" else "-"+variant
                phase = "authentication" if variant == "wrong" else "tls-control"
                def rejection():
                    try:
                        with open_tcp(0) as stream:
                            stream.settimeout(2)
                            stream.sendall(b"must-not-pass")
                            data = stream.recv(1)
                            if data:
                                raise AssertionError("跨节点凭据被接受")
                    except (OSError, RuntimeError):
                        return
                record(records, label+suffix+"-auth", rejection, rejected=True, phase=phase, directory=sub)
                def udp_rejection():
                    try:
                        udp(0, b"must-not-pass")
                    except (OSError, RuntimeError):
                        return
                    raise AssertionError("跨节点凭据取得UDP业务回包")
                record(records, label+suffix+"-udp-auth", udp_rejection, rejected=True, phase=phase, directory=sub)
                continue
            payloads = [bytes([i+1])*65537 for i in range(4)]
            def parallel():
                with ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(lambda p: tcp_stream(open_tcp(0), p, True), payloads))
            record(records, label+"-parallel", parallel)
            udp_eligible = []
            for i, (site, _, _) in enumerate(targets):
                site_label="site6" if ipaddress.ip_address(site).version==6 else "site4"
                if args.mode=="official" and direction=="node" and ipaddress.ip_address(site).is_loopback:
                    records.append({"case":label+"-"+site_label,"outcome":"not-tested","reason":"固定官方客户端强制旁路回环目标；没有已存在的相应私有目标地址，不记代理成功"})
                    continue
                for size in [17, 4096, 65536, 262144]:
                    payload = bytes([size % 251])*size
                    record(records, label+f"-tcp-{site_label}-{size}", lambda i=i, p=payload: tcp_stream(open_tcp(i), p, True))
                if args.mode == "official" and site == "::1":
                    records.append({"case": label+"-udp-ipv6", "outcome": "not-tested", "reason": "固定官方源码::1编码歧义，未修改worker地址"})
                    continue
                udp_eligible.append((i,site_label))
                for size in [17, 4096, 12000]+([65000] if args.mode=="official" else []):
                    payload = bytes([size % 251])*size
                    # 官方 endpoint 的 H3 回写丢弃 16000 字节及以上的数据报；官方客户端接它同样超时。
                    record(records, label+f"-udp-{site_label}-{size}", lambda i=i, p=payload: check_equal(udp(i, p), p),
                           boundary=args.mode == "official" and direction == "client" and transport == "h3" and size == 65000)
                if args.mode == "wire":
                    def isolated_unknown_flows(i=i):
                        target = (targets[i][0], targets[i][2])
                        def exchange(payload):
                            check_equal(wire_udp(host, number, supplied, version, certs, args.mtls, target, payload), payload)
                        with ThreadPoolExecutor(max_workers=2) as pool:
                            list(pool.map(exchange, [b"unknown-first", b"unknown-second"]))
                    record(records, label+f"-udp-unknown-same-target-{site_label}", isolated_unknown_flows)
            # 边界探针放在正常数据/并发之后；旧官方端的超限丢弃器会损坏解析状态。
            if args.edges:
                for i,site_label in udp_eligible:
                    for size in [0,65434,65507]:
                        payload=bytes([size%251])*size
                        record(records,label+f"-udp-boundary-{site_label}-{size}",lambda i=i,p=payload:check_equal(udp(i,p),p),boundary=args.mode in ("official","mihomo"))
        with setup("server-stop", directory):
            server.terminate()
            code = server.wait(timeout=4)
            if os.name == "nt":
                records.append({"case": label+"-bounded-cleanup", "phase": "cleanup", "outcome": "pass", "exit_code": code})
                records.append({"case": label+"-bounded-exit", "phase": "shutdown", "outcome": "not-tested", "reason": "Windows无控制台子进程仅作定向清理，未验证优雅排空"})
            else:
                if (direction == "node" or args.mode == "self") and code != 0:
                    raise RuntimeError("本项目服务端退出状态异常")
                records.append({"case": label+"-bounded-exit", "phase": "shutdown", "outcome": "pass", "exit_code": code})


def main():
    parser = argparse.ArgumentParser(description="TrustTunnel 独立双向互通，不修改系统网络或已有代理")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--mode", choices=["official", "mihomo", "wire", "self"], required=True)
    parser.add_argument("--role", choices=["client", "node", "both"], default="both")
    parser.add_argument("--transport", choices=["h1", "h2", "h3", "all"], default="all")
    parser.add_argument("--tls", choices=["tls12", "tls13", "all"], default="all")
    parser.add_argument("--peer-endpoint")
    parser.add_argument("--peer-endpoint-sha256")
    parser.add_argument("--peer-client")
    parser.add_argument("--peer-client-sha256")
    parser.add_argument("--peer")
    parser.add_argument("--peer-sha256")
    parser.add_argument("--mtls", action="store_true")
    parser.add_argument("--edges", action="store_true")
    parser.add_argument("--target4",default="127.0.0.1")
    parser.add_argument("--target6",default="::1")
    parser.add_argument("--reference-log-level",choices=["info","debug","trace"],default="info")
    args = parser.parse_args()
    if ipaddress.ip_address(args.target4).version!=4 or ipaddress.ip_address(args.target6).version!=6:
        parser.error("目标地址族必须分别为IPv4/IPv6，且只允许任务授权的既有本机地址")
    if args.mode=="official" and args.role in ("node","both") and ipaddress.ip_address(args.target4).is_loopback:
        parser.error("官方客户端硬编码旁路回环；节点方向必须提供本任务既有私有IPv4目标")
    os.umask(0o077)
    args.kerlico = str(Path(args.kerlico).resolve())
    args.kerlico_sha256 = digest(args.kerlico)
    openssl = shutil.which(args.openssl)
    if openssl is None:
        parser.error("缺少本任务可调用的OpenSSL，使用--openssl指定独立可执行文件")
    args.openssl = str(Path(openssl).resolve())
    if args.mode == "official":
        if args.mtls:
            parser.error("官方默认端不提供本轮mTLS对照条件")
        if args.role in ("client", "both"):
            args.peer_endpoint = checked(args.peer_endpoint, args.peer_endpoint_sha256)
        if args.role in ("node", "both"):
            args.peer_client = checked(args.peer_client, args.peer_client_sha256)
    elif args.mode == "mihomo":
        args.peer = checked(args.peer, args.peer_sha256)
    elif args.mode == "wire" and (args.role != "node" or args.transport != "h1"):
        parser.error("受控wire peer仅验证本项目H1节点，必须显式--role node --transport h1")
    args.peer_hashes = {name: digest(value) for name, value in [
        ("endpoint", args.peer_endpoint), ("client", args.peer_client), ("mihomo", args.peer)
    ] if value}
    root = Path(args.work_dir).resolve()
    if root.exists() and any(root.iterdir()):
        parser.error("测试目录必须为空，不能覆盖已有配置、证书或记录")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    records = []
    with setup("certificate-material", root):
        certs = material(root, args.openssl)
    directions = ["client", "node"] if args.role == "both" else [args.role]
    transports = ["h1", "h2", "h3"] if args.transport == "all" else [args.transport]
    versions = ["tls12", "tls13"] if args.tls == "all" else [args.tls]
    for direction, transport, version in itertools.product(directions, transports, versions):
        if transport == "h3" and version == "tls12":
            continue
        if (args.mode == "official" and direction == "node" and transport == "h1") or (args.mode == "mihomo" and transport == "h1"):
            records.append({"case": f"{args.mode}-{direction}-{transport}-{version}", "outcome": "not-tested", "reason": "固定对端无H1上游，不能强制回退冒充"})
            continue
        for index, host in enumerate(["127.0.0.1", "::1"]):
            try:
                verify(args, root, certs, direction, transport, version, host, index, records)
            except SetupFailure as error:
                records.append({"case": f"{direction}-{transport}-{version}-node{index}", "outcome": "fail", "phase": error.phase, "error_type": error.error_type, "os_error": error.os_error, "diagnostics": diagnostics(error.directory)})
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                records.append({"case": f"{direction}-{transport}-{version}-node{index}", "outcome": "fail", "phase": "case-setup", "error_type": type(error).__name__})
            save_result(args, root, records)
    save_result(args, root, records)
    counts = {name: sum(record["outcome"] == name for record in records) for name in ["pass", "fail", "observed-limit", "not-tested"]}
    print(json.dumps({"mode": args.mode, "counts": counts}, ensure_ascii=False))
    raise SystemExit(1 if counts["fail"] else 0)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        output = {"outcome": "fail", "phase": getattr(error, "phase", "setup"), "error_type": getattr(error, "error_type", type(error).__name__)}
        if isinstance(error, SetupFailure):
            output["os_error"] = error.os_error
            output["diagnostics"] = diagnostics(error.directory)
            try:
                write_json(error.directory/"setup-result.json", output)
            except OSError:
                output["result_write_failed"] = True
        print(json.dumps(output, ensure_ascii=False))
        raise SystemExit(1)
