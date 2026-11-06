#!/usr/bin/env python3
"""sing-mux（smux / yamux / h2mux）与 sing-box、Mihomo 的回环互通矩阵；仅在专用 worker 执行。

每格三项检查：经 SOCKS5 CONNECT 的 1 MiB TCP 回显、经 SOCKS5 UDP ASSOCIATE 的多尺寸 UDP 回显、
32 路并发流同时打开时载体 TCP 连接数不超过客户端 max_connections。
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from config_v2 import bind_members
import mihomo_ready

HOST = "127.0.0.1"
PROTOCOLS = ["smux", "yamux", "h2mux"]
CARRIERS = ["ss", "vless"]
KERLICO_PAIRS = [("kerlico", "sing-box"), ("kerlico", "mihomo"), ("sing-box", "kerlico"), ("mihomo", "kerlico")]
BASELINE_PAIRS = [("sing-box", "mihomo"), ("mihomo", "sing-box")]
CHECKS = ["tcp", "udp", "mux"]
METHOD = "aes-128-gcm"
MAX_CONNECTIONS = 4
MIN_STREAMS = 4
TCP_BYTES = 1 << 20
UDP_SIZES = [1, 2, 7, 16, 64, 128, 255, 256, 512, 777, 1000, 1024, 1200, 1300, 1350, 1380, 1400, 3, 99, 1399]
STREAMS = 32
STREAM_BYTES = 64 << 10
LOG_TAIL = 6000


@dataclass(frozen=True)
class Cell:
    protocol: str
    padding: bool
    carrier: str
    client: str
    server: str

    @property
    def row(self):
        return f"{self.protocol}/{'pad' if self.padding else 'nopad'}/{self.carrier}"

    @property
    def pair(self):
        return f"{self.client}->{self.server}"

    @property
    def label(self):
        return f"{self.row}/{self.pair}"


class Children:
    """登记全部子进程，异常、Ctrl-C 与 SIGTERM/SIGHUP 时统一回收。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.items = []

    def spawn(self, command, log, env=None):
        handle = log.open("wb")
        process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True,
                                   env=None if env is None else {**os.environ, **env})
        with self.lock:
            self.items.append((process, handle))
        return process

    def stop(self, process):
        with self.lock:
            entries = [entry for entry in self.items if entry[0] is process]
            self.items = [entry for entry in self.items if entry[0] is not process]
        for child, handle in entries:
            terminate(child)
            handle.close()

    def stop_all(self):
        with self.lock:
            entries, self.items = self.items, []
        for child, handle in entries:
            terminate(child)
            handle.close()


def terminate(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


CHILDREN = Children()
PORT_LOCK = threading.Lock()
PORTS = set()


def free_port():
    with PORT_LOCK:
        while True:
            with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                tcp.bind((HOST, 0))
                number = tcp.getsockname()[1]
                try:
                    udp.bind((HOST, number))
                except OSError:
                    continue
            if number not in PORTS:
                PORTS.add(number)
                return number


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class ThreadingTcp(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def recv_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        part = sock.recv(min(1 << 16, count - len(data)))
        if not part:
            raise RuntimeError(f"连接提前结束，已收 {len(data)}/{count} 字节")
        data += part
    return bytes(data)


def socks_reply(sock):
    head = recv_exact(sock, 4)
    if head[0] != 5 or head[1] != 0:
        raise RuntimeError(f"SOCKS5 回复码 {head[1]}")
    kind = head[3]
    if kind == 1:
        address = socket.inet_ntoa(recv_exact(sock, 4))
    elif kind == 4:
        address = socket.inet_ntop(socket.AF_INET6, recv_exact(sock, 16))
    elif kind == 3:
        address = recv_exact(sock, recv_exact(sock, 1)[0]).decode()
    else:
        raise RuntimeError(f"SOCKS5 地址类型 {kind}")
    return address, struct.unpack("!H", recv_exact(sock, 2))[0]


def socks_open(socks_port, command, target_port, timeout):
    sock = socket.create_connection((HOST, socks_port), timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 方法协商失败")
        address = b"\x00\x00\x00\x00" if command == 3 else socket.inet_aton(HOST)
        sock.sendall(bytes([5, command, 0, 1]) + address + struct.pack("!H", target_port if command == 1 else 0))
        return sock, socks_reply(sock)
    except BaseException:
        sock.close()
        raise


def check_tcp(socks_port, target):
    payload = os.urandom(TCP_BYTES)
    sock, _ = socks_open(socks_port, 1, target, 10)
    with sock:
        sock.settimeout(20)
        failure = []

        def send():
            try:
                sock.sendall(payload)
            except OSError as error:
                failure.append(error)

        sender = threading.Thread(target=send, daemon=True)
        sender.start()
        got = recv_exact(sock, len(payload))
        sender.join(5)
        if failure:
            raise RuntimeError(f"发送失败：{failure[0]}")
        if got != payload:
            index = next(i for i, (a, b) in enumerate(zip(got, payload)) if a != b)
            raise RuntimeError(f"1 MiB 回显内容在偏移 {index} 处不符")
    return {"bytes": len(payload)}


def check_udp(socks_port, target):
    control, (relay_host, relay_port) = socks_open(socks_port, 3, 0, 10)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        if relay_host in ("0.0.0.0", "::", ""):
            relay_host = HOST
        udp.bind((HOST, 0))
        udp.settimeout(1.0)
        header = b"\x00\x00\x00\x01" + socket.inet_aton(HOST) + struct.pack("!H", target)
        retries = 0
        for index, size in enumerate(UDP_SIZES):
            payload = (struct.pack("!H", index) + os.urandom(size))[:size] if size >= 2 else os.urandom(size)
            for attempt in range(3):
                udp.sendto(header + payload, (relay_host, relay_port))
                try:
                    while True:
                        packet, _ = udp.recvfrom(65536)
                        if len(packet) < 10 or packet[3] != 1:
                            raise RuntimeError(f"UDP 回复首部无效：{packet[:10].hex()}")
                        if packet[10:] == payload:
                            break
                except socket.timeout:
                    retries += 1
                    continue
                break
            else:
                raise RuntimeError(f"第 {index} 个数据报（{size} 字节）三次均未回显，此前 {index} 个已通过")
    return {"datagrams": len(UDP_SIZES), "retries": retries}


def carrier_count(server_port):
    out = subprocess.run(["ss", "-Htn", "state", "established", f"( dport = :{server_port} )"], capture_output=True, text=True, timeout=5)
    return len([line for line in out.stdout.splitlines() if line.strip()])


def check_mux(socks_port, target, server_port):
    opened = threading.Barrier(STREAMS + 1, timeout=20)
    release = threading.Barrier(STREAMS + 1, timeout=20)
    errors = [None] * STREAMS

    def stream(index):
        try:
            sock, _ = socks_open(socks_port, 1, target, 10)
            with sock:
                sock.settimeout(20)
                hello = f"stream-{index:02d}".encode()
                sock.sendall(hello)
                if recv_exact(sock, len(hello)) != hello:
                    raise RuntimeError("首包回显不符")
                opened.wait()
                release.wait()
                payload = os.urandom(STREAM_BYTES)
                sock.sendall(payload)
                if recv_exact(sock, len(payload)) != payload:
                    raise RuntimeError("64 KiB 回显内容不符")
        except threading.BrokenBarrierError:
            errors[index] = errors[index] or "其他流失败，屏障中止"
        except Exception as error:
            errors[index] = f"{type(error).__name__}: {error}"
            opened.abort()
            release.abort()

    threads = [threading.Thread(target=stream, args=(index,), daemon=True) for index in range(STREAMS)]
    for thread in threads:
        thread.start()
    samples = []
    try:
        opened.wait()
        for _ in range(6):
            samples.append(carrier_count(server_port))
            time.sleep(0.05)
        release.wait()
    except threading.BrokenBarrierError:
        pass
    for thread in threads:
        thread.join(30)
    failed = [(index, error) for index, error in enumerate(errors) if error and "屏障中止" not in error]
    if failed or any(errors):
        first = failed[0] if failed else next((index, error) for index, error in enumerate(errors) if error)
        raise RuntimeError(f"{sum(1 for error in errors if error)}/{STREAMS} 路失败，首个流 {first[0]}：{first[1]}；载体连接采样 {samples}")
    peak = max(samples)
    detail = {"streams": STREAMS, "carrier_samples": samples, "peak_carrier_connections": peak}
    if not 1 <= peak <= MAX_CONNECTIONS:
        raise RuntimeError(f"{STREAMS} 路并发时载体 TCP 连接峰值 {peak}，期望 1..{MAX_CONNECTIONS}；采样 {samples}")
    return detail


def wait_port(process, port, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"进程启动后退出，状态 {process.returncode}")
        try:
            socket.create_connection((HOST, port), 0.3).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"端口 {port} 未就绪")


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    os.chmod(path, 0o600)
    return path


@dataclass
class Secrets:
    password: str
    uuid: str


def kerlico_mux(cell):
    return {"enabled": True, "protocol": cell.protocol, "max_connections": MAX_CONNECTIONS, "min_streams": MIN_STREAMS, "padding": cell.padding}


def singbox_mux(cell):
    return {"enabled": True, "protocol": cell.protocol, "max_connections": MAX_CONNECTIONS, "min_streams": MIN_STREAMS, "padding": cell.padding}


def mihomo_mux(cell):
    return {"enabled": True, "protocol": cell.protocol, "max-connections": MAX_CONNECTIONS, "min-streams": MIN_STREAMS, "padding": cell.padding}


LIMITS = {"connect_timeout_ms": 8000, "idle_timeout_ms": 30000, "drain_timeout_ms": 500, "max_sessions": 512, "max_datagram_size": 65507}


def kerlico_client(cell, secrets, server_port, socks_port):
    if cell.carrier == "ss":
        options = {"server": HOST, "port": server_port, "method": METHOD, "password": secrets.password}
    else:
        options = {"server": {"host": HOST, "port": server_port}, "uuid": secrets.uuid, "flow": "", "security": {"type": "none"}, "transport": {"type": "tcp"}}
    options["multiplex"] = kerlico_mux(cell)
    return {
        "version": 2,
        "outbounds": [{"tag": "proxy", "type": "shadowsocks" if cell.carrier == "ss" else "vless", "options": options}],
        "inbounds": [],
        "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"{HOST}:{socks_port}", "outbound": "proxy", "options": {"version": "5"}}],
        "limits": LIMITS,
    }


def kerlico_server(cell, secrets, server_port):
    mux = {"enabled": True, "padding": cell.padding}
    if cell.carrier == "ss":
        options, credential = {"method": METHOD, "allow_insecure": True, "multiplex": mux}, {"password": secrets.password}
    else:
        options, credential = {"security": {"type": "none"}, "transport": {"type": "tcp"}, "multiplex": mux}, {"uuid": secrets.uuid, "flow": ""}
    node = {"tag": "node", "type": "shadowsocks" if cell.carrier == "ss" else "vless", "listen": f"{HOST}:{server_port}", "outbound": "direct", "options": options}
    config = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [node], "limits": LIMITS}
    bind_members(config, node, [credential])
    return config


def singbox_client(cell, secrets, server_port, socks_port):
    if cell.carrier == "ss":
        outbound = {"type": "shadowsocks", "method": METHOD, "password": secrets.password}
    else:
        outbound = {"type": "vless", "uuid": secrets.uuid, "flow": ""}
    outbound.update(tag="proxy", server=HOST, server_port=server_port, multiplex=singbox_mux(cell))
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "socks", "tag": "socks", "listen": HOST, "listen_port": socks_port}],
        "outbounds": [outbound],
    }


def singbox_server(cell, secrets, server_port):
    if cell.carrier == "ss":
        inbound = {"type": "shadowsocks", "method": METHOD, "password": secrets.password}
    else:
        inbound = {"type": "vless", "users": [{"name": "user", "uuid": secrets.uuid, "flow": ""}]}
    inbound.update(tag="node", listen=HOST, listen_port=server_port, multiplex={"enabled": True, "padding": cell.padding})
    return {"log": {"level": "info", "timestamp": True}, "inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}]}


def mihomo_base(rules):
    return {
        "mode": "rule", "log-level": "info", "allow-lan": False, "ipv6": True, "geo-auto-update": False,
        "dns": {"enable": False}, "tun": {"enable": False}, "ntp": {"enable": False},
        "profile": {"store-selected": False},
        "port": 0, "socks-port": 0, "mixed-port": 0, "redir-port": 0, "tproxy-port": 0,
        "rules": rules,
    }


def mihomo_client(cell, secrets, server_port, socks_port):
    if cell.carrier == "ss":
        proxy = {"type": "ss", "cipher": METHOD, "password": secrets.password}
    else:
        proxy = {"type": "vless", "uuid": secrets.uuid, "flow": ""}
    proxy.update(name="proxy", server=HOST, port=server_port, udp=True, smux=mihomo_mux(cell))
    config = mihomo_base(["MATCH,proxy"])
    config["proxies"] = [proxy]
    config["listeners"] = [{"name": "socks-in", "type": "socks", "listen": HOST, "port": socks_port, "udp": True}]
    return mihomo_ready.add_probe(config, free_port())


def mihomo_server(cell, secrets, server_port):
    if cell.carrier == "ss":
        listener = {"type": "shadowsocks", "cipher": METHOD, "password": secrets.password}
    else:
        listener = {"type": "vless", "users": [{"username": "user", "uuid": secrets.uuid, "flow": ""}], "allow-insecure": True}
    listener.update({"name": "node", "listen": HOST, "port": server_port, "udp": True, "mux-option": {"padding": cell.padding}})
    config = mihomo_base(["MATCH,DIRECT"])
    config["listeners"] = [listener]
    return mihomo_ready.add_probe(config, free_port())


CLIENT_CONFIG = {"kerlico": kerlico_client, "sing-box": singbox_client, "mihomo": mihomo_client}
SERVER_CONFIG = {"kerlico": kerlico_server, "sing-box": singbox_server, "mihomo": mihomo_server}


def launch(kind, binaries, config, directory, role, port):
    path = write_json(directory / f"{role}-{kind}.json", config)
    if kind == "mihomo":
        home = directory / f"{role}-home"
        home.mkdir(mode=0o700)
        command = [binaries[kind], "-d", str(home), "-f", str(path)]
    else:
        command = [binaries[kind], "run", "-c", str(path)]
    # 回环上客户端载体复用了 Mihomo 先前拨号用过的临时端口时，其回环检测会误拒 DIRECT 拨号。
    env = {"DISABLE_LOOPBACK_DETECTOR": "true"} if kind == "mihomo" else None
    process = CHILDREN.spawn(command, directory / f"{role}.log", env)
    if kind == "mihomo":
        mihomo_ready.wait_running(process, config, timeout=15)
    wait_port(process, port)
    return process


def tail(path, work):
    try:
        data = path.read_bytes()[-LOG_TAIL:]
    except OSError:
        return ""
    return data.decode("utf-8", "replace").replace(str(work), "<work>")


def run_cell(cell, binaries, work, targets):
    directory = Path(tempfile.mkdtemp(prefix="cell-", dir=work))
    secrets = Secrets(password="synthetic-" + os.urandom(12).hex(), uuid=str(uuid.uuid4()))
    server_port, socks_port = free_port(), free_port()
    result = {"cell": cell.label, "protocol": cell.protocol, "padding": cell.padding, "carrier": cell.carrier,
              "client": cell.client, "server": cell.server, "checks": {}, "failed_check": None}
    processes = []
    started = time.monotonic()
    try:
        try:
            processes.append(launch(cell.server, binaries, SERVER_CONFIG[cell.server](cell, secrets, server_port), directory, "server", server_port))
            processes.append(launch(cell.client, binaries, CLIENT_CONFIG[cell.client](cell, secrets, server_port, socks_port), directory, "client", socks_port))
        except Exception as error:
            result["checks"]["startup"] = {"pass": False, "error": f"{type(error).__name__}: {error}"}
            result["failed_check"] = "startup"
        else:
            runners = {"tcp": lambda: check_tcp(socks_port, targets[0]),
                       "udp": lambda: check_udp(socks_port, targets[1]),
                       "mux": lambda: check_mux(socks_port, targets[0], server_port)}
            for name in CHECKS:
                try:
                    result["checks"][name] = {"pass": True, **runners[name]()}
                except Exception as error:
                    result["checks"][name] = {"pass": False, "error": f"{type(error).__name__}: {error}"}
                    result["failed_check"] = result["failed_check"] or name
            for role, process in zip(("server", "client"), processes):
                if process.poll() is not None:
                    result["checks"][f"{role}-alive"] = {"pass": False, "error": f"检查结束时进程已退出，状态 {process.returncode}"}
                    result["failed_check"] = result["failed_check"] or f"{role}-alive"
    finally:
        for process in reversed(processes):
            CHILDREN.stop(process)
        result["pass"] = result["failed_check"] is None
        result["seconds"] = round(time.monotonic() - started, 2)
        if not result["pass"]:
            result["logs"] = {role: tail(directory / f"{role}.log", work) for role in ("server", "client")}
        shutil.rmtree(directory, ignore_errors=True)
    return result


def version(binary, flag):
    try:
        out = subprocess.run([binary, flag], capture_output=True, text=True, timeout=10)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.SubprocessError):
        return None


def table(cells, results):
    rows = list(dict.fromkeys(cell.row for cell in cells))
    pairs = list(dict.fromkeys(cell.pair for cell in cells))
    found = {(cell.row, cell.pair): results.get(cell.label) for cell in cells}
    grid = [["cell"] + pairs]
    for row in rows:
        line = [row]
        for pair in pairs:
            outcome = found.get((row, pair))
            line.append("-" if outcome is None else "pass" if outcome["pass"] else "FAIL:" + outcome["failed_check"])
        grid.append(line)
    widths = [max(len(line[index]) for line in grid) for index in range(len(grid[0]))]
    return "\n".join("  ".join(value.ljust(width) for value, width in zip(line, widths)).rstrip() for line in grid)


def on_signal(number, _frame):
    raise KeyboardInterrupt(f"signal {number}")


def main():
    parser = argparse.ArgumentParser(description="sing-mux 与 sing-box、Mihomo 的回环互通矩阵")
    parser.add_argument("--kerlico")
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--only", help="只运行格名包含该子串的格，例如 smux/pad/ss 或 kerlico->mihomo")
    parser.add_argument("--out")
    parser.add_argument("--baseline", action="store_true", help="追加 sing-box 与 Mihomo 互连的对照格")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    binaries = {"sing-box": str(Path(args.sing_box).resolve()), "mihomo": str(Path(args.mihomo).resolve())}
    pairs = []
    if args.kerlico:
        binaries["kerlico"] = str(Path(args.kerlico).resolve())
        pairs += KERLICO_PAIRS
    if args.baseline:
        pairs += BASELINE_PAIRS
    if not pairs:
        parser.error("需要 --kerlico 或 --baseline")
    cells = [Cell(protocol, padding, carrier, client, server)
             for protocol in PROTOCOLS for padding in (False, True) for carrier in CARRIERS for client, server in pairs]
    cells = [cell for cell in cells if not args.only or args.only in cell.label]
    if not cells:
        parser.error("--only 没有匹配任何格")
    for number in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, on_signal)
    os.umask(0o077)
    work = Path(tempfile.mkdtemp(prefix="kerlico-sing-mux-"))
    results = {}
    pool = ThreadPoolExecutor(max_workers=max(1, args.jobs))
    try:
        tcp_target = serve(ThreadingTcp((HOST, 0), TcpEcho))
        udp_target = serve(socketserver.ThreadingUDPServer((HOST, 0), UdpEcho))
        targets = (tcp_target.server_address[1], udp_target.server_address[1])
        futures = {pool.submit(run_cell, cell, binaries, work, targets): cell for cell in cells}
        for future in as_completed(futures):
            outcome = future.result()
            results[outcome["cell"]] = outcome
            status = "pass" if outcome["pass"] else "FAIL " + outcome["failed_check"] + " " + outcome["checks"][outcome["failed_check"]]["error"]
            print(f"[{len(results)}/{len(cells)}] {outcome['cell']} {outcome['seconds']}s {status}", flush=True)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        CHILDREN.stop_all()
        shutil.rmtree(work, ignore_errors=True)
    print()
    print(table(cells, results))
    failed = [label for label, outcome in results.items() if not outcome["pass"]]
    print(f"\n{len(results) - len(failed)}/{len(results)} 格通过")
    if args.out:
        report = {
            "versions": {"sing-box": version(binaries["sing-box"], "version"), "mihomo": version(binaries["mihomo"], "-v"),
                         "kerlico": version(binaries["kerlico"], "--version") if "kerlico" in binaries else None},
            "settings": {"max_connections": MAX_CONNECTIONS, "min_streams": MIN_STREAMS, "tcp_bytes": TCP_BYTES,
                         "udp_sizes": UDP_SIZES, "streams": STREAMS, "stream_bytes": STREAM_BYTES, "method": METHOD},
            "passed": len(results) - len(failed), "failed": len(failed),
            "cells": [results[cell.label] for cell in cells if cell.label in results],
        }
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    if failed or len(results) != len(cells):
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        CHILDREN.stop_all()
        sys.exit(130)
