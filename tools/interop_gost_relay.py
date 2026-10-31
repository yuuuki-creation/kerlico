#!/usr/bin/env python3
"""仅在 worker 用固定官方 GOST 检查原生 Relay 出站，原始结果留私有目录。"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import subprocess
import time

import interop_vless as h


class Udp4(h.UdpServer):
    max_packet_size = 65535


class Udp6(Udp4):
    address_family = socket.AF_INET6


class Greeting(h.TcpEcho):
    def handle(self):
        self.request.sendall(b"ready|")
        super().handle()


class FinEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        payload = bytearray()
        try:
            while part := self.request.recv(65536):
                payload.extend(part)
                if len(payload) > 1048576:
                    return
            self.request.sendall(payload)
        except OSError:
            return


def address(host, number):
    return f"[{host}]:{number}" if ":" in host else f"{host}:{number}"


def port(host="127.0.0.1"):
    # 使用本任务回环端口，并同时检查两个网络，避开常见临时出口端口区间。
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
    raise RuntimeError("无法为本任务分配隔离回环端口")


def ready(child, host, number):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("本任务子进程在就绪前退出")
        try:
            with socket.create_connection((host, number), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("本任务监听未在预算内就绪")


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.recv(count - len(result))
        if not part:
            raise RuntimeError("TCP 回包提前结束")
        result.extend(part)
    return bytes(result)


def tcp(number, payload, greeting=False, rejected=False):
    try:
        with socket.create_connection(("127.0.0.1", number), timeout=4) as stream:
            stream.settimeout(4)
            if greeting:
                if exact(stream, 6) != b"ready|":
                    raise RuntimeError("目标先发内容不符")
            stream.sendall(len(payload).to_bytes(4, "big") + payload)
            if rejected:
                if stream.recv(1):
                    raise RuntimeError("拒绝路径返回了业务数据")
                return
            if exact(stream, len(payload)) != payload:
                raise RuntimeError("TCP 内容不符")
    except (ConnectionResetError, BrokenPipeError):
        if not rejected:
            raise


def udp(number, payload, host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as stream:
        stream.settimeout(3)
        stream.sendto(payload, (host, number))
        return stream.recv(65535)


def terminate(child):
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
        try:
            return child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
            raise RuntimeError("本项目未在排空预算内退出")
    return child.returncode


def fin_only(args):
    """原始载体声明半关闭，必须用实际官方转发路径验证延迟回包。"""
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    peer = Path(args.peer).resolve()
    if hashlib.sha256(peer.read_bytes()).hexdigest() != args.peer_sha256:
        raise RuntimeError("GOST 对端二进制摘要不符")
    records = []
    with ExitStack() as active_targets:
        target4 = active_targets.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), FinEcho)))
        target6 = active_targets.enter_context(h.serve(h.TcpServer6(("::1", 0), FinEcho)))
        targets = [("127.0.0.1", target4), ("::1", target6), ("localhost", target4)]
        for host, mode in itertools.product(["127.0.0.1", "::1"], ["eager", "deferred"]):
            label = f"fin-node{'6' if ':' in host else '4'}-{mode}"
            directory = root / label
            directory.mkdir(mode=0o700)
            number = port(host)
            option = {"server": {"host": host, "port": number}, "username": "fin-user", "password": "synthetic-fin-password", "response_mode": mode}
            peer_config = {"services": [{"name": "relay", "addr": address(host, number), "handler": {"type": "relay", "auth": {"username": option["username"], "password": option["password"]}, "metadata": {"nodelay": mode == "eager"}}, "listener": {"type": "tcp"}}], "log": {"level": "error"}}
            forwards, used = [], set()
            for index, (site, target_port) in enumerate(targets):
                local = port()
                while local in used or (host == "127.0.0.1" and local == number):
                    local = port()
                used.add(local)
                forwards.append({"tag": "target" + str(index), "type": "tcp-forward", "listen": address("127.0.0.1", local), "target": {"host": site, "port": target_port}, "outbound": "proxy", "require_remote_eof": True})
            config = {"version": 1, "outbounds": [{"tag": "proxy", "type": "gost-relay", "options": option}], "inbounds": forwards, "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 7000, "drain_timeout_ms": 500}}
            peer_path, path = directory / "reference.json", directory / "kernel.json"
            h.write_json(peer_path, peer_config)
            h.write_json(path, config)
            with ExitStack() as processes:
                reference = processes.enter_context(h.process([str(peer), "-C", str(peer_path)], directory, "reference"))
                ready(reference, host, number)
                own = processes.enter_context(h.process([args.kerlico, "run", "-c", str(path)], directory, "kernel"))
                for index, forward in enumerate(forwards):
                    local = int(forward["listen"].rsplit(":", 1)[1])
                    ready(own, "127.0.0.1", local)
                    for size in [17, 65537]:
                        record = {"case": label, "target": targets[index][0], "size": size}
                        try:
                            payload = b"f" * size
                            with socket.create_connection(("127.0.0.1", local), timeout=4) as stream:
                                stream.settimeout(4)
                                stream.sendall(payload)
                                stream.shutdown(socket.SHUT_WR)
                                if exact(stream, size) != payload or stream.recv(1):
                                    raise RuntimeError("写端EOF后回包内容不符")
                            record["pass"] = True
                        except Exception as error:
                            record.update({"pass": False, "error": type(error).__name__, "detail": str(error)})
                        records.append(record)
                        h.write_json(root / "results.json", records)
                records.append({"case": label, "path": "shutdown", "pass": terminate(own) == 0})
    summary = {"passed": sum(r["pass"] for r in records), "failed": sum(not r["pass"] for r in records)}
    h.write_json(root / "results.json", records)
    h.write_json(root / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    if summary["failed"]:
        raise SystemExit(1)


def create_targets(stack, host, greeting):
    tcp_class = h.TcpServer6 if ":" in host else h.TcpServer
    udp_class = Udp6 if ":" in host else Udp4
    for _ in range(32):
        tcp_server = tcp_class((host, 0), Greeting if greeting else h.TcpEcho)
        number = tcp_server.server_address[1]
        try:
            udp_server = udp_class((host, number), h.UdpEcho)
        except OSError:
            tcp_server.server_close()
            continue
        stack.enter_context(h.serve(tcp_server))
        stack.enter_context(h.serve(udp_server))
        return number
    raise RuntimeError("目标 TCP/UDP 隔离端口分配失败")


def main(args):
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    peer = Path(args.peer).resolve()
    digest = hashlib.sha256(peer.read_bytes()).hexdigest()
    if digest != args.peer_sha256:
        raise RuntimeError("GOST 对端二进制摘要不符")
    result = subprocess.run([str(peer), "-V"], capture_output=True, timeout=10, check=True)
    h.write_json(root / "reference.json", {"sha256": digest, "version": (result.stdout + result.stderr).decode().strip(), "release": "v3.3.2"})
    cert, key = root / "peer.crt", root / "peer.key"
    with (root / "certificate.log").open("wb") as log:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=relay.test.invalid", "-addext", "subjectAltName=DNS:relay.test.invalid", "-addext", "basicConstraints=critical,CA:FALSE", "-days", "1"], stdout=log, stderr=log, check=True)
    records, boundaries = [], []
    with ExitStack() as target_stack:
        targets = []
        for host, greeting in itertools.product(["127.0.0.1", "::1"], [False, True]):
            number = create_targets(target_stack, host, greeting)
            targets.append((host, number, greeting))
            if host == "127.0.0.1":
                targets.append(("localhost", number, greeting))
        for secure, mux, mode, auth, host, forward in itertools.product([False, True], [False, True], ["eager", "deferred"], [False, True], ["127.0.0.1", "::1"], [False, True]):
            label = f"tls{int(secure)}-mux{int(mux)}-{mode}-auth{int(auth)}-node{'6' if ':' in host else '4'}-forward{int(forward)}"
            case_root = root / label
            case_root.mkdir(mode=0o700)
            services, outbounds, inbounds, checks = [], [], [], []
            used = set()

            def allocate(value="127.0.0.1"):
                while True:
                    number = port(value)
                    if (value, number) not in used:
                        used.add((value, number))
                        return number

            for index, (target_host, target_port, greeting) in enumerate(targets):
                number, local = allocate(host), allocate()
                tag = "path" + str(index)
                username, password = "synthetic-user", "synthetic-" + label
                handler = {"type": "relay", "metadata": {"nodelay": mode == "eager"}}
                if auth:
                    handler["auth"] = {"username": username, "password": password}
                listener = {"type": ("mtls" if secure else "mtcp") if mux else ("tls" if secure else "tcp")}
                if mux:
                    # 固定 GOST 的 GetInt 接受 string/int，JSON number 的 float64 会被忽略。
                    listener["metadata"] = {"mux.version": "1", "mux.keepaliveDisabled": True}
                if secure:
                    listener["tls"] = {"certFile": str(cert), "keyFile": str(key)}
                service = {"name": tag, "addr": address(host, number), "handler": handler, "listener": listener}
                option = {"server": {"host": host, "port": number}, "mux": mux, "response_mode": mode}
                if auth:
                    option.update(username=username, password=password)
                if secure:
                    option["tls"] = {"server_name": "relay.test.invalid", "ca_pem": cert.read_text()}
                if forward:
                    literal = "127.0.0.1" if target_host == "localhost" else target_host
                    service["forwarder"] = {"nodes": [{"name": "fixed", "addr": address(literal, target_port)}]}
                    option["forward_target"] = {"host": literal, "port": target_port}
                services.append(service)
                outbounds.append({"tag": tag, "type": "gost-relay", "options": option})
                for network in ["tcp", "udp"]:
                    inbounds.append({"tag": tag + network, "type": network + "-forward", "listen": address("127.0.0.1", local), "target": {"host": target_host, "port": target_port}, "outbound": tag})
                checks.append({"label": tag, "port": local, "greeting": greeting, "target": target_host, "target_port": target_port})
                if auth:
                    bad_tag, bad_port = tag + "wrong", allocate()
                    outbounds.append({"tag": bad_tag, "type": "gost-relay", "options": dict(option, password="synthetic-denied")})
                    inbounds.append({"tag": bad_tag, "type": "tcp-forward", "listen": address("127.0.0.1", bad_port), "target": {"host": target_host, "port": target_port}, "outbound": bad_tag})
                    checks.append({"label": bad_tag, "port": bad_port, "rejected": True})
            peer_path, own_path = case_root / "reference.json", case_root / "kernel.json"
            h.write_json(peer_path, {"services": services, "log": {"level": "error"}})
            h.write_json(own_path, {"version": 1, "outbounds": outbounds, "inbounds": inbounds, "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 10000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65507}})
            try:
                with ExitStack() as active:
                    reference = active.enter_context(h.process([str(peer), "-C", str(peer_path)], case_root, "reference"))
                    ready(reference, host, outbounds[0]["options"]["server"]["port"])
                    own = active.enter_context(h.process([args.kerlico, "run", "-c", str(own_path)], case_root, "kernel"))
                    for check in checks:
                        ready(own, "127.0.0.1", check["port"])
                    for check in checks:
                        record = {"case": label, "path": check["label"], "checks": []}
                        try:
                            if check.get("rejected"):
                                tcp(check["port"], b"must-be-denied", rejected=True)
                                record["checks"].append("wrong-credential")
                            else:
                                for size in [17, 4096, 65537]:
                                    tcp(check["port"], b"t" * size, greeting=check["greeting"])
                                    record["checks"].append("tcp-" + str(size))
                                for size in [17, 12000]:
                                    if udp(check["port"], b"u" * size) != b"u" * size:
                                        raise RuntimeError("UDP 内容不符")
                                    record["checks"].append("udp-" + str(size))
                                if check["label"] == "path0":
                                    with ThreadPoolExecutor(max_workers=4) as pool:
                                        list(pool.map(lambda n: tcp(check["port"], bytes([n]) * 65537), range(4)))
                                    record["checks"].append("parallel-4")
                                if secure and auth and host == "127.0.0.1" and not forward and mode == "eager" and check["label"] == "path0":
                                    for size in [0, 65507]:
                                        boundary = {"case": label, "size": size}
                                        payload = b"b" * size
                                        boundary["direct_exact"] = udp(check["target_port"], payload) == payload
                                        try:
                                            observed = udp(check["port"], payload)
                                            boundary.update(received=len(observed), exact=observed == payload)
                                        except (OSError, TimeoutError) as error:
                                            boundary.update(received=None, exact=False, error=type(error).__name__)
                                        boundaries.append(boundary)
                            record["pass"] = True
                        except Exception as error:
                            record.update({"pass": False, "error": type(error).__name__, "detail": str(error)})
                        records.append(record)
                        h.write_json(root / "results.json", {"records": records, "boundaries": boundaries})
                    exit_code = terminate(own)
                    records.append({"case": label, "path": "shutdown", "pass": exit_code == 0, "exit": exit_code})
                    # 全配置同端口重启，不以进程已经退出替代端口释放证明。
                    restarted = active.enter_context(h.process([args.kerlico, "run", "-c", str(own_path)], case_root, "kernel-restart"))
                    ready(restarted, "127.0.0.1", checks[0]["port"])
                    tcp(checks[0]["port"], b"restart")
                    records.append({"case": label, "path": "restart", "pass": terminate(restarted) == 0})
            except Exception as error:
                records.append({"case": label, "path": "setup-or-lifecycle", "pass": False, "error": type(error).__name__, "detail": str(error)})
            h.write_json(root / "results.json", {"records": records, "boundaries": boundaries})
    summary = {"passed": sum(r["pass"] for r in records), "failed": sum(not r["pass"] for r in records), "functional_checks": sum(len(r.get("checks", [])) for r in records if r["pass"]), "boundary_observations": len(boundaries)}
    h.write_json(root / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--peer-sha256", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--fin-only", action="store_true", help="单独验证官方原始载体的EOF后回包")
    arguments = parser.parse_args()
    if arguments.fin_only:
        fin_only(arguments)
    else:
        main(arguments)
