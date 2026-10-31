#!/usr/bin/env python3
"""仅在 worker 检查 TrustTunnel 双向对端；受控 H1 wire peer 单独标识。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import hashlib
import ipaddress
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import time

import interop_vless as h

NAME = "tt.example.invalid"
PASSWORDS = ("tt-node4-only-secret", "tt-node6-only-secret")


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
        try:
            with socket.socket(family) as tcp, socket.socket(family, socket.SOCK_DGRAM) as udp:
                tcp.bind((host, number))
                udp.bind((host, number))
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
            with socket.create_connection((host, number), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("本任务监听就绪超时")


def live(child):
    # QUIC 没有 TCP 探针；实际业务 CONNECT 是其握手就绪检查。
    if child.poll() is not None:
        raise RuntimeError("本任务 QUIC 进程已退出")


def ready_udp(child, number):
    deadline = time.monotonic()+8
    while time.monotonic() < deadline:
        live(child)
        own = set()
        for fd in Path(f"/proc/{child.pid}/fd").iterdir():
            try:
                link = os.readlink(fd)
                if link.startswith("socket:["):
                    own.add(link[8:-1])
            except OSError:
                pass
        for table in ["/proc/net/udp", "/proc/net/udp6"]:
            for line in Path(table).read_text().splitlines()[1:]:
                values = line.split()
                if int(values[1].split(":")[1], 16) == number and values[9] in own:
                    return
        time.sleep(0.02)
    raise RuntimeError("本任务 QUIC 监听未在预算内就绪")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked(path, expected):
    if not path or not expected or digest(path) != expected:
        raise RuntimeError("固定对端缺失或二进制摘要不符")
    return str(Path(path).resolve())


def material(root):
    def run(*args):
        result = subprocess.run(["openssl", *args], capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("生成测试 CA/证书失败")
    ca, cakey = root/"ca.pem", root/"ca-key.pem"
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cakey), "-out", str(ca), "-days", "1", "-subj", "/CN=TrustTunnel-test-CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    output = {"ca": ca}
    for role in ("server", "client"):
        key, csr, cert, ext = (root/(role+suffix) for suffix in ("-key.pem", ".csr", ".pem", ".ext"))
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN="+NAME)
        ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+("serverAuth" if role == "server" else "clientAuth")+"\nsubjectAltName=DNS:"+NAME+"\n")
        run("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(ext))
        output[role], output[role+"_key"] = cert, key
    return output


def own_options(host, number, password, transport, version, certs, server, mtls):
    # 工具同时保留两条UDP flow并发四条TCP；测试需求6条物理H1连接，显式提供8个名额。
    common = {"transport": transport, "limits": {"idle_timeout_ms": 6000, "max_connections": 8, "max_streams": 64, "health_check_ms": 1000}}
    if server:
        common["limits"].pop("max_connections")
        common["limits"].pop("health_check_ms")
        tls = {"certificate_file": str(certs["server"]), "private_key_file": str(certs["server_key"]), "version": version}
        if mtls:
            tls["client_ca_pem"] = certs["ca"].read_text()
        return {**common, "users": [{"username": "test", "password": password}], "tls": tls}
    tls = {"server_name": NAME, "ca_pem": certs["ca"].read_text(), "version": version}
    if mtls:
        tls.update(certificate_pem=certs["client"].read_text(), private_key_pem=certs["client_key"].read_text())
    return {**common, "server": {"host": host, "port": number}, "auth": {"username": "test", "password": password}, "tls": tls, "app_name": "worker-test"}


def own_node(host, number, password, transport, version, certs, mtls):
    return {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node", "type": "trusttunnel", "listen": address(host, number), "outbound": "direct", "options": own_options(host, number, password, transport, version, certs, True, mtls)}], "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 6000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65507}}


def official_node(directory, host, number, password, transport, certs, log_level):
    clients, settings, tls = directory/"credentials.toml", directory/"endpoint.toml", directory/"tls.toml"
    clients.write_text('[[client]]\nusername = "test"\npassword = '+json.dumps(password)+'\n')
    # 未设置 icmp、反向站点、metrics、Sentry；默认无对应资源。
    kind = {"h1": "http1", "h2": "http2", "h3": "quic"}[transport]
    settings.write_text("listen_address = "+json.dumps(address(host, number))+"\nipv6_available = true\nallow_private_network_connections = true\ncredentials_file = "+json.dumps(str(clients))+"\nconnection_establishment_timeout_secs = 3\nclient_listener_timeout_secs = 6\ntcp_connections_timeout_secs = 6\nudp_connections_timeout_secs = 6\n[listen_protocols."+kind+"]\n")
    tls.write_text('[[main_hosts]]\nhostname = '+json.dumps(NAME)+'\ncert_chain_path = '+json.dumps(str(certs["server"]))+'\nprivate_key_path = '+json.dumps(str(certs["server_key"]))+'\n')
    return [str(settings), str(tls), "--jobs", "1", "--loglvl", log_level]


def mihomo_common(certs):
    # 此固定 Mihomo 配置字段的上游拼写确实是 custom-certifactes。
    return {"mode": "rule", "log-level": "warning", "allow-lan": False, "ipv6": True, "dns": {"enable": False}, "tun": {"enable": False}, "ntp": {"enable": False}, "profile": {"store-selected": False}, "tls": {"custom-certifactes": [certs["ca"].read_text()]}}


def mihomo_node(host, number, password, transport, certs, mtls):
    config = mihomo_common(certs)
    listener = {"name": "node", "type": "trusttunnel", "listen": host, "port": str(number), "users": [{"username": "test", "password": password}], "certificate": str(certs["server"]), "private-key": str(certs["server_key"]), "network": ["udp" if transport == "h3" else "tcp"]}
    if mtls:
        listener.update({"client-auth-cert": str(certs["ca"])})
    config.update({"listeners": [listener], "rules": ["MATCH,DIRECT"]})
    return config


def official_client(directory, host, number, password, transport, certs, socks, dns):
    path = directory/"client.toml"
    path.write_text('loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = true\npost_quantum_group_enabled = false\nexclusions_preresolve_enabled = false\nexclusions = []\n[endpoint]\nhostname = '+json.dumps(NAME)+'\naddresses = ['+json.dumps(address(host, number))+']\nhas_ipv6 = true\nusername = "test"\npassword = '+json.dumps(password)+'\nskip_verification = false\ncertificate = '+json.dumps(certs["ca"].read_text())+'\nupstream_protocol = '+json.dumps("http3" if transport == "h3" else "http2")+'\nanti_dpi = false\ndns_upstreams = ['+json.dumps(address("127.0.0.1", dns))+']\n[listener.socks]\naddress = '+json.dumps(address("127.0.0.1", socks))+'\n')
    return ["--config", str(path)]


def mihomo_client(host, number, password, transport, certs, socks, mtls):
    config = mihomo_common(certs)
    proxy = {"name": "proxy", "type": "trusttunnel", "server": host, "port": number, "username": "test", "password": password, "sni": NAME, "udp": True, "quic": transport == "h3", "max-connections": 4, "max-streams": 64}
    if mtls:
        proxy.update(certificate=str(certs["client"]), **{"private-key": str(certs["client_key"])})
    config.update({"socks-port": socks, "proxies": [proxy], "rules": ["MATCH,proxy"]})
    return config


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


def socks_udp(number, target, payload):
    control, bind = socks_open(number, ("0.0.0.0", 0), 3)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(3)
        ip = ipaddress.ip_address(target[0])
        head = b"\0\0\0"+bytes([1 if ip.version == 4 else 4])+ip.packed+struct.pack("!H", target[1])
        if bind[0] in ("0.0.0.0", "::"):
            bind = ("127.0.0.1", bind[1])
        udp.sendto(head+payload, bind)
        result = udp.recv(65535)
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
        record = padded("0.0.0.0")+struct.pack("!H", 4231)+padded(target[0])+struct.pack("!H", target[1])+b"\0"+payload
        stream.sendall(struct.pack("!I", len(record))+record)
        length = struct.unpack("!I", exact(stream, 4))[0]
        if not 36 <= length <= 36+65507:
            raise RuntimeError("H1 UDP 回包长度不合法")
        record = exact(stream, length)
        if record[:18] != padded(target[0])+struct.pack("!H", target[1]):
            raise RuntimeError("H1 UDP 真实来源不符")
        return record[36:]


def record(records, case, action, boundary=False, rejected=False):
    output = {"case": case, "boundary": boundary, "expected_rejection": rejected}
    try:
        action()
        output["outcome"] = "pass"
    except (OSError, RuntimeError, TimeoutError, AssertionError) as error:
        output.update(outcome="observed-limit" if boundary else "fail", error_type=type(error).__name__)
    records.append(output)
    return output["outcome"] != "fail"


def check_equal(actual, expected):
    if actual != expected:
        raise RuntimeError("回包内容不符")


def tcp_stream(stream, payload, greeting=False):
    with stream:
        if greeting:
            check_equal(exact(stream, 6), b"hello|")
        stream.sendall(struct.pack("!I", len(payload))+payload)
        check_equal(exact(stream, len(payload)), payload)


def verify(args, root, certs, direction, transport, version, host, index):
    label = f"{args.mode}-{direction}-{transport}-{version}-node{'6' if index else '4'}"+("-mtls" if args.mtls else "")
    directory = root/label
    directory.mkdir(mode=0o700)
    records = []
    number = port(host)
    password = PASSWORDS[index]
    with ExitStack() as stack:
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
                h.write_json(path, config)
                command = [args.peer, "-d", str(directory/"reference-state"), "-f", str(path)]
        else:
            path = directory/"node.json"
            h.write_json(path, own_node(host, number, password, transport, version, certs, args.mtls))
            command = [args.kerlico, "run", "-c", str(path)]
        server = stack.enter_context(h.process(command, directory, "server"))
        if transport != "h3":
            ready(server, host, number)
        else:
            ready_udp(server, number)
        for wrong in (True, False):
            sub = directory/("wrong" if wrong else "valid")
            sub.mkdir(mode=0o700)
            supplied = PASSWORDS[1-index] if wrong else password
            forwards = []
            socks = None
            udp_sockets = {}
            if direction == "client" or args.mode == "self":
                options = own_options(host, number, supplied, transport, version, certs, False, args.mtls)
                for i, (site, tcp, udp) in enumerate(targets):
                    for network, target in [("tcp", tcp), ("udp", udp)]:
                        local = port()
                        forwards.append({"tag": f"{network}{i}", "type": network+"-forward", "listen": address("127.0.0.1", local), "target": {"host": site, "port": target}, "outbound": "proxy"})
                config = {"version": 1, "outbounds": [{"tag": "proxy", "type": "trusttunnel", "options": options}], "inbounds": forwards, "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 6000, "drain_timeout_ms": 500, "max_datagram_size": 65507}}
                path = sub/"client.json"
                h.write_json(path, config)
                client = stack.enter_context(h.process([args.kerlico, "run", "-c", str(path)], sub, "client"))
                ready(client, "127.0.0.1", int(forwards[0]["listen"].rsplit(":", 1)[1]))
            elif args.mode != "wire":
                socks = port()
                if args.mode == "official":
                    command = [args.peer_client, *official_client(sub, host, number, supplied, transport, certs, socks, dns)]
                else:
                    path = sub/"client.json"
                    h.write_json(path, mihomo_client(host, number, supplied, transport, certs, socks, args.mtls))
                    command = [args.peer, "-d", str(sub/"reference-state"), "-f", str(path)]
                client = stack.enter_context(h.process(command, sub, "client"))
                ready(client, "127.0.0.1", socks)
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
                record(records, label+"-cross-node-auth", rejection, rejected=True)
                def udp_rejection():
                    try:
                        udp(0, b"must-not-pass")
                    except (OSError, RuntimeError):
                        return
                    raise AssertionError("跨节点凭据取得UDP业务回包")
                record(records, label+"-cross-node-udp-auth", udp_rejection, rejected=True)
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
                    record(records, label+f"-udp-{site_label}-{size}", lambda i=i, p=payload: check_equal(udp(i, p), p))
            # 边界探针放在正常数据/并发之后；旧官方端的超限丢弃器会损坏解析状态。
            if args.edges:
                for i,site_label in udp_eligible:
                    for size in [0,65434,65507]:
                        payload=bytes([size%251])*size
                        record(records,label+f"-udp-boundary-{site_label}-{size}",lambda i=i,p=payload:check_equal(udp(i,p),p),boundary=args.mode in ("official","mihomo"))
        server.terminate()
        try:
            code = server.wait(timeout=4)
            if (direction == "node" or args.mode == "self") and code != 0:
                raise RuntimeError("本项目服务端退出状态异常")
            records.append({"case": label+"-bounded-exit", "outcome": "pass", "exit_code": code})
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("服务端有界退出失败") from error
    return records


def main():
    parser = argparse.ArgumentParser(description="TrustTunnel 完整双向互通，仅在专用 worker 执行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
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
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    certs = material(root)
    records = []
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
                records.extend(verify(args, root, certs, direction, transport, version, host, index))
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                records.append({"case": f"{direction}-{transport}-{version}-node{index}", "outcome": "fail", "error_type": type(error).__name__})
            h.write_json(root/"result.json", {"mode": args.mode, "kerlico_sha256": digest(args.kerlico), "peer_sha256": {name: digest(value) for name, value in [("endpoint", args.peer_endpoint), ("client", args.peer_client), ("mihomo", args.peer)] if value}, "records": records})
    counts = {name: sum(record["outcome"] == name for record in records) for name in ["pass", "fail", "observed-limit", "not-tested"]}
    print(json.dumps({"mode": args.mode, "counts": counts}, ensure_ascii=False))
    raise SystemExit(1 if counts["fail"] else 0)


if __name__ == "__main__":
    main()
