#!/usr/bin/env python3
"""逐协议深度测试。interop_cross_host.py 回答“能不能通”，这里回答“哪里不对”。

数据形状：
  Scenario  名字、分组、适用条件、参数、执行函数、判定函数。判定是纯函数：度量 -> Judgement。
  Control   某场景的对照：用哪种台架、覆盖哪些参数、预期判定和预期失败分类。
  Result    协议、载体、排列、地址族、场景、判定（pass、fail、na、tool-error）、度量、证据。

工具自身要能证伪：一轮先跑全部对照，任何对照不符（包括“失败了但分类不对”）时，该场景这一轮
的结论全部降为 tool-error。协议失败后再测裸路径，路径坏了同样降为 tool-error。

用法见 docs/build-and-test.md。
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import interop_cross_host as xh  # noqa: E402
from config_v2 import bind_members  # noqa: E402

ROOT = "/srv/build/kerlico/deep"
UPLOADS = ("protocol_deep.py", "interop_cross_host.py", "netem_lab.py", "config_v2.py")
PASS, FAIL, NA, TOOL_ERROR = "pass", "fail", "na", "tool-error"
LONG = 86400
MIB = 1 << 20
BOUNDARY_SIZES = (1, 2, 1023, 1024, 1025, 1399, 1400, 1401, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537, 131071, 131072, 131073)
UDP_SIZES = (1, 64, 512, 1200, 1252, 1400, 4096, 8192, 16384, 32768, 65507)
UDP_LOSS_TOLERANCE = 0.25
FD_SLACK = 32
THREAD_SLACK = 8
RSS_SLACK_KIB = 96 << 10
RSS_TREND_KIB = 48 << 10
IDLE_SLACK = 5.0
# 协议自己的转发空闲限额（秒），低于全局 idle_timeout_ms 时生效。依据 docs/interfaces 和各协议的默认 limits。
DOCUMENTED_IDLE = {"hysteria1": 30.0, "hysteria2": 30.0, "trusttunnel": 30.0, "shadowquic": 30.0}
# 编排侧可能在 Windows 上，那里的 signal 模块没有这两个名字；数值是 worker（Linux x86_64）的。
DISRUPT_SIGNALS = {"kill": 9, "freeze": 19}


def pattern(size, seed=0):
    """每条连接一份内容，串流才会被摘要发现。"""
    return random.Random(f"{seed}/{size}").randbytes(size)


# ---------- worker 侧：受控目标 ----------

class DeepTarget:
    """回显目标，可注入故障。TCP 与 UDP 同端口，统计收到的连接和字节。"""

    def __init__(self, tcp_mode="echo", udp_mode="echo", arg=0, tag="", loopback_only=False, rcvbuf=0):
        self.tcp_mode, self.udp_mode, self.arg, self.tag = tcp_mode, udp_mode, arg, tag.encode()
        self.conns = self.bytes_in = self.datagrams = 0
        self.lock = threading.Lock()
        self.closing = threading.Event()
        v4, v6 = ("127.0.0.1", "::1") if loopback_only else ("0.0.0.0", "::")
        for _ in range(50):
            port = random.randint(*xh.PORT_RANGE)
            try:
                self.sockets = [xh.Echo.bind(socket.AF_INET, socket.SOCK_STREAM, v4, port), xh.Echo.bind(socket.AF_INET, socket.SOCK_DGRAM, v4, port), xh.Echo.bind(socket.AF_INET6, socket.SOCK_STREAM, v6, port), xh.Echo.bind(socket.AF_INET6, socket.SOCK_DGRAM, v6, port)]
                self.port = port
                break
            except OSError:
                continue
        else:
            raise RuntimeError("目标端口分配失败")
        for sock in self.sockets:
            if rcvbuf and sock.type == socket.SOCK_STREAM:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
            target = self.serve_tcp if sock.type == socket.SOCK_STREAM else self.serve_udp
            threading.Thread(target=target, args=(sock,), daemon=True).start()

    def stats(self):
        return {"conns": self.conns, "bytes_in": self.bytes_in, "datagrams": self.datagrams}

    def stop(self):
        self.closing.set()
        for sock in self.sockets:
            sock.close()

    def serve_tcp(self, server):
        while not self.closing.is_set():
            try:
                if not select.select([server], [], [], 0.5)[0]:
                    continue
                client, _ = server.accept()
            except (OSError, ValueError):
                return
            with self.lock:
                self.conns += 1
                index = self.conns
            threading.Thread(target=self.serve_stream, args=(client, index), daemon=True).start()

    def serve_stream(self, client, index):
        mode, arg = self.tcp_mode, self.arg
        with client:
            try:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if mode == "flaky" and index % arg == 0:
                    return
                if mode == "idle_close":
                    client.settimeout(arg)
                echoed = 0
                while chunk := client.recv(1 << 14 if mode == "throttle" else 1 << 18):
                    with self.lock:
                        self.bytes_in += len(chunk)
                    if mode == "blackhole":
                        continue
                    if mode in ("truncate", "stall_after"):
                        chunk = chunk[:max(0, arg - echoed)]
                    if mode == "corrupt" and echoed <= arg < echoed + len(chunk):
                        chunk = bytearray(chunk)
                        chunk[arg - echoed] ^= 0xff
                    if chunk:
                        client.sendall(chunk)
                        echoed += len(chunk)
                    if mode == "truncate" and echoed >= arg:
                        client.shutdown(socket.SHUT_WR)
                        mode = "blackhole"
                    if mode == "throttle":
                        time.sleep(len(chunk) / arg)
                if mode == "no_eof":
                    self.closing.wait()
            except OSError:
                pass

    def serve_udp(self, server):
        index, held = 0, None
        while not self.closing.is_set():
            try:
                if not select.select([server], [], [], 0.5)[0]:
                    continue
                data, peer = server.recvfrom(65535)
            except (OSError, ValueError):
                return
            index += 1
            with self.lock:
                self.datagrams += 1
            replies = [data]
            if self.udp_mode == "drop_half" and index % 2:
                replies = []
            elif self.udp_mode == "dup":
                replies = [data, data]
            elif self.udp_mode == "reorder":
                if held is None:
                    held, replies = data, []
                else:
                    replies, held = [data, held], None
            elif self.udp_mode == "limit" and len(data) > self.arg:
                replies = []
            elif self.udp_mode == "tag":
                replies = [self.tag + data]
            for reply in replies:
                try:
                    server.sendto(reply, peer)
                except OSError:
                    pass


# ---------- worker 侧：探针。每个探针只测量，判定在编排侧的纯函数里 ----------

def open_stream(route, host, port, timeout=30.0):
    if route["kind"] == "socks":
        return xh.socks_connect(route["port"], host, port, timeout=timeout)
    stream = socket.create_connection(tuple(route.get("via") or (host, port)), timeout=timeout)
    stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return stream


def connect_class(error):
    if isinstance(error, ConnectionError) and str(error).startswith("socks_"):
        return str(error)
    if isinstance(error, EOFError):
        return "connect_eof"
    if isinstance(error, ConnectionRefusedError):
        return "connect_refused"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "connect_timeout"
    return f"connect_{type(error).__name__}"


def stream_class(error):
    if isinstance(error, socket.timeout):
        return "stall"
    if isinstance(error, ConnectionResetError):
        return "reset"
    return type(error).__name__


class TimedSender(xh.Sender):
    """记下发送结束的时间：慢流对照要证明发送确实阻塞得比停滞窗口还久。"""

    finished_at = None

    def __init__(self, stream, data):
        self.done = threading.Event()
        super().__init__(stream, data)

    def run(self):
        super().run()
        self.finished_at = time.monotonic()
        self.done.set()


def duplex_on(stream, size, stall, seed=0):
    """全双工回显。停滞只看接收进度；发送线程独立，错误会写进结果，不会静默消失。"""
    data = pattern(size, seed)
    view = memoryview(data)
    digest = hashlib.sha256()
    started = last = time.monotonic()
    sender = TimedSender(stream, data)
    received, longest, longest_at, first_diff, klass = 0, 0.0, 0, None, ""
    try:
        while received < size:
            chunk = xh.recv_or_stall(stream, min(1 << 18, size - received), stall)
            now = time.monotonic()
            if now - last > longest:
                longest, longest_at = now - last, received
            last = now
            if not chunk:
                klass = "eof"
                break
            if first_diff is None and view[received:received + len(chunk)] != chunk:
                first_diff = received + next(index for index, byte in enumerate(chunk) if byte != data[received + index])
            digest.update(chunk)
            received += len(chunk)
    except OSError as error:
        klass = stream_class(error)
    elapsed = time.monotonic() - started
    sender_error = sender.error
    if klass:
        sender.stop()
    else:
        sender.done.wait(1.0)
        if digest.digest() != hashlib.sha256(data).digest():
            klass = "digest"
    if klass == "stall" and sender_error:
        klass = "send_error"
    send_elapsed = round(sender.finished_at - started, 3) if sender.finished_at else None
    return {"ok": not klass, "klass": klass, "size": size, "stall": stall, "send_elapsed": send_elapsed, "sent": sender.sent, "received": received, "first_diff": first_diff, "elapsed": round(elapsed, 3), "mib_s": round(received / MIB / max(elapsed, 1e-3), 3), "longest_gap": round(longest, 2), "longest_gap_at": longest_at, "sender_error": sender_error}


def duplex_probe(route, host, port, size, stall, seed=0, sndbuf=0):
    try:
        stream = open_stream(route, host, port)
    except (OSError, EOFError) as error:
        return {"ok": False, "klass": connect_class(error), "size": size, "sent": 0, "received": 0}
    with stream:
        if sndbuf:
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        return duplex_on(stream, size, stall, seed)


class HalfCloser(xh.Sender):
    write_closed = False

    def run(self):
        super().run()
        if self.error is None:
            try:
                self.stream.shutdown(socket.SHUT_WR)
                self.write_closed = True
            except OSError as error:
                self.error = type(error).__name__


def half_close_round(route, host, port, size, stall, eof_wait):
    try:
        stream = open_stream(route, host, port)
    except (OSError, EOFError) as error:
        return {"size": size, "klass": connect_class(error), "sent": 0, "received": 0, "eof_seen": False}
    data = pattern(size, size)
    digest = hashlib.sha256()
    received, klass, eof_seen = 0, "", False
    with stream:
        sender = HalfCloser(stream, data)
        try:
            while True:
                chunk = xh.recv_or_stall(stream, 1 << 18, stall if received < size else eof_wait)
                if not chunk:
                    eof_seen = True
                    break
                digest.update(chunk)
                received += len(chunk)
        except OSError as error:
            klass = stream_class(error)
            if klass == "stall" and received >= size:
                klass = "no_eof"
        if not klass and received != size:
            klass = "eof" if received < size else "surplus"
        if klass in ("", "no_eof") and digest.digest() != hashlib.sha256(data).digest():
            klass = "digest"
        result = {"size": size, "klass": klass, "sent": sender.sent, "received": received, "eof_seen": eof_seen, "write_closed": sender.write_closed, "sender_error": sender.error}
        sender.stop()
    return result


def half_close_probe(route, host, port, sizes, stall, eof_wait):
    return {"rounds": [half_close_round(route, host, port, size, stall, eof_wait) for size in sizes]}


def empty_probe(route, host, port, rounds, eof_wait, stall):
    """不发数据：一组直接关，一组关写后等 EOF。之后同一入口必须还能传。"""
    connect_failures, no_eof, classes = 0, 0, Counter()
    for _ in range(rounds):
        try:
            open_stream(route, host, port).close()
        except (OSError, EOFError) as error:
            connect_failures += 1
            classes[connect_class(error)] += 1
    latencies = []
    for _ in range(rounds):
        try:
            with open_stream(route, host, port) as stream:
                started = time.monotonic()
                stream.shutdown(socket.SHUT_WR)
                if xh.recv_or_stall(stream, 4096, eof_wait):
                    classes["data_on_empty"] += 1
                latencies.append(round(time.monotonic() - started, 3))
        except (socket.timeout, TimeoutError):
            no_eof += 1
        except (OSError, EOFError) as error:
            connect_failures += 1
            classes[connect_class(error)] += 1
    return {"rounds": rounds, "connect_failures": connect_failures, "no_eof": no_eof, "classes": dict(classes), "eof_latency_max": max(latencies, default=None), "followup": duplex_probe(route, host, port, 1024, stall)}


def boundary_probe(route, host, port, sizes, stall):
    rounds = [duplex_probe(route, host, port, size, stall, seed=size) for size in sizes]
    failed = [{"size": item["size"], "klass": item["klass"], "sent": item["sent"], "received": item["received"]} for item in rounds if not item["ok"]]
    return {"sizes": len(rounds), "failed": failed}


def parallel_probe(route, host, port, conns, size, stall):
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=conns) as pool:
        rounds = list(pool.map(lambda index: duplex_probe(route, host, port, size, stall, seed=index), range(conns)))
    elapsed = time.monotonic() - started
    failures = [item for item in rounds if not item["ok"]]
    received = sum(item["received"] for item in rounds)
    return {"conns": conns, "size": size, "failed": len(failures), "classes": dict(Counter(item["klass"] for item in failures)), "samples": [{"klass": item["klass"], "sent": item["sent"], "received": item["received"], "elapsed": item.get("elapsed")} for item in failures[:5]], "sent": sum(item["sent"] for item in rounds), "received": received, "elapsed": round(elapsed, 3), "mib_s": round(received / MIB / max(elapsed, 1e-3), 3), "longest_gap": max((item.get("longest_gap", 0) for item in rounds), default=0)}


def short_probe(route, host, port, count, size, stall):
    failed, classes, samples, latencies = 0, Counter(), [], []
    for index in range(count):
        started = time.monotonic()
        result = duplex_probe(route, host, port, size, stall, seed=index)
        latencies.append(time.monotonic() - started)
        if not result["ok"]:
            failed += 1
            classes[result["klass"]] += 1
            if len(samples) < 5:
                samples.append({"index": index, "klass": result["klass"], "sent": result["sent"], "received": result["received"]})
    latencies.sort()
    return {"count": count, "failed": failed, "classes": dict(classes), "samples": samples, "p50_ms": round(latencies[len(latencies) // 2] * 1000), "p99_ms": round(latencies[int(len(latencies) * 0.99)] * 1000)}


def churn_probe(route, host, port, count, workers, size, stall):
    """短连接以较高速率开关：关闭后的流如果不归还配额，后面的连接会被拒。"""
    failed, classes, samples = 0, Counter(), []
    lock = threading.Lock()
    indexes = iter(range(count))

    def worker():
        nonlocal failed
        while True:
            with lock:
                index = next(indexes, None)
            if index is None:
                return
            result = duplex_probe(route, host, port, size, stall, seed=index)
            if not result["ok"]:
                with lock:
                    failed += 1
                    classes[result["klass"]] += 1
                    if len(samples) < 5:
                        samples.append({"index": index, "klass": result["klass"]})

    started = time.monotonic()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started
    return {"count": count, "failed": failed, "classes": dict(classes), "samples": samples, "elapsed": round(elapsed, 2), "per_second": round(count / max(elapsed, 1e-3), 1)}


def idle_probe(route, host, port, idle, size, stall):
    """同一条连接：先传一次，空闲，再传一次。"""
    try:
        stream = open_stream(route, host, port)
    except (OSError, EOFError) as error:
        return {"klass": connect_class(error), "first": None, "second": None}
    with stream:
        first = duplex_on(stream, 1024, stall, seed=1)
        if not first["ok"]:
            return {"klass": first["klass"], "first": first, "second": None}
        started = time.monotonic()
        try:
            if not xh.recv_or_stall(stream, 4096, idle):
                return {"klass": "eof", "first": first, "second": None, "closed_after": round(time.monotonic() - started, 1)}
            return {"klass": "unexpected_data", "first": first, "second": None, "closed_after": None}
        except (socket.timeout, TimeoutError):
            pass
        except OSError as error:
            return {"klass": stream_class(error), "first": first, "second": None, "closed_after": round(time.monotonic() - started, 1)}
        second = duplex_on(stream, size, stall, seed=2)
        return {"klass": second["klass"], "first": first, "second": second, "closed_after": None, "idle": idle}


def idle_limit_probe(route, host, port, wait_max, stall):
    """传一次后不再动，测节点或入口多久主动关闭。"""
    try:
        stream = open_stream(route, host, port)
    except (OSError, EOFError) as error:
        return {"klass": connect_class(error), "closed_after": None}
    with stream:
        first = duplex_on(stream, 1024, stall, seed=1)
        if not first["ok"]:
            return {"klass": first["klass"], "closed_after": None}
        started = time.monotonic()
        try:
            xh.recv_or_stall(stream, 4096, wait_max)
        except (socket.timeout, TimeoutError):
            return {"klass": "", "closed_after": None, "wait_max": wait_max}
        except OSError:
            pass
        return {"klass": "", "closed_after": round(time.monotonic() - started, 1), "wait_max": wait_max}


class Inflight:
    """一条持续收发的流，用来观察中途发生的事。"""

    def __init__(self, route, host, port):
        self.sent = self.received = 0
        self.klass = ""
        self.ended = False
        self.halt = threading.Event()
        threading.Thread(target=self.run, args=(route, host, port), daemon=True).start()

    def run(self, route, host, port):
        block = pattern(1 << 16, 7)
        try:
            with open_stream(route, host, port) as stream:
                stream.setblocking(False)
                next_send = time.monotonic()
                while not self.halt.is_set():
                    wants_write = time.monotonic() >= next_send
                    readable, writable, _ = select.select([stream], [stream] if wants_write else [], [], 0.05)
                    try:
                        if readable:
                            chunk = stream.recv(1 << 18)
                            if not chunk:
                                self.klass = "eof"
                                break
                            self.received += len(chunk)
                        if writable:
                            self.sent += stream.send(block)
                            next_send = time.monotonic() + 0.05
                    except BlockingIOError:
                        continue
        except (OSError, EOFError) as error:
            self.klass = connect_class(error) if not self.sent else stream_class(error)
        self.ended = True

    def status(self):
        return {"sent": self.sent, "received": self.received, "ended": self.ended, "klass": self.klass}


def udp_socket(route):
    family = socket.AF_INET6 if ":" in route.get("host", "") else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
    sock.connect((route["host"], route["port"]) if route["kind"] == "direct" else ("127.0.0.1", route["port"]))
    return sock


def udp_size_round(route, size, count, wait, tries):
    lost, resent, klass = 0, 0, ""
    with udp_socket(route) as sock:
        sock.settimeout(wait)
        for index in range(count):
            data = pattern(size, index)
            answered = False
            for attempt in range(tries):
                resent += bool(attempt)
                try:
                    sock.send(data)
                    deadline = time.monotonic() + wait
                    while time.monotonic() < deadline and not answered:
                        reply = sock.recv(65535)
                        answered = reply == data
                        if not answered and len(reply) < size and data.startswith(reply):
                            klass = "truncated"
                except (socket.timeout, TimeoutError):
                    pass
                except OSError as error:
                    klass = type(error).__name__
                if answered or (klass and klass != "truncated"):
                    break
            if not answered:
                lost += 1
                if lost == 2 or klass:
                    break
    ok = lost == 0
    return {"size": size, "ok": ok, "lost": lost, "resent": resent, "klass": "" if ok else klass or "no_reply"}


def udp_sizes_probe(route, sizes, count=3, wait=1.0, tries=3):
    return {"rounds": [udp_size_round(route, size, count, wait, tries) for size in sizes]}


def udp_burst_probe(route, count, size, pps, drain):
    body = pattern(size - 4, 3)
    state = {"send_errors": 0, "done": False}
    with udp_socket(route) as sock:

        def send():
            started = time.monotonic()
            for index in range(count):
                delay = started + index / pps - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                try:
                    sock.send(struct.pack(">I", index) + body)
                except OSError:
                    state["send_errors"] += 1
            state["done"] = True

        thread = threading.Thread(target=send, daemon=True)
        thread.start()
        seen, duplicates, reordered, corrupt, highest = set(), 0, 0, 0, -1
        last = time.monotonic()
        sock.settimeout(0.2)
        while not (state["done"] and time.monotonic() - last > drain):
            try:
                reply = sock.recv(65535)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                time.sleep(0.05)
                continue
            last = time.monotonic()
            if len(reply) != size or reply[4:] != body:
                corrupt += 1
                continue
            seq = struct.unpack(">I", reply[:4])[0]
            if seq in seen:
                duplicates += 1
                continue
            seen.add(seq)
            if seq < highest:
                reordered += 1
            highest = max(highest, seq)
    return {"count": count, "size": size, "pps": pps, "received": len(seen), "lost": count - len(seen), "loss": round((count - len(seen)) / count, 4), "duplicates": duplicates, "reordered": reordered, "corrupt": corrupt, "send_errors": state["send_errors"]}


def udp_multi_probe(socks, targets, rounds, wait, tries):
    """SOCKS5 UDP 关联向多个目标发送，核对回包的来源地址和目标写入的标签。"""
    try:
        control = socket.create_connection(("127.0.0.1", socks), timeout=15)
        control.sendall(b"\x05\x01\x00")
        if bytes(xh.recv_exact(control, 2, 15)) != b"\x05\x00":
            return {"klass": "socks_method"}
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = bytes(xh.recv_exact(control, 4, 15))
        if reply[1] != 0:
            control.close()
            return {"klass": f"socks_reply_{reply[1]}"}
        if reply[3] != 1:
            control.close()
            return {"klass": "socks_bind_family"}
        bound = bytes(xh.recv_exact(control, 6, 15))
    except (OSError, EOFError) as error:
        return {"klass": connect_class(error)}
    relay = (socket.inet_ntoa(bound[:4]), struct.unpack(">H", bound[4:])[0])
    counters = Counter()
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(wait)
        for index in range(rounds):
            for host, port, tag in targets:
                atyp, raw = (4, socket.inet_pton(socket.AF_INET6, host)) if ":" in host else (1, socket.inet_pton(socket.AF_INET, host))
                header = bytes((0, 0, 0, atyp)) + raw + struct.pack(">H", port)
                data = pattern(64, f"{index}/{port}")
                expected = tag.encode() + data
                outcome = "loss"
                for _ in range(tries):
                    sock.sendto(header + data, relay)
                    deadline = time.monotonic() + wait
                    try:
                        while time.monotonic() < deadline:
                            packet = sock.recv(65535)
                            offset = {1: 10, 4: 22}.get(packet[3] if len(packet) > 3 else 0)
                            if offset is None:
                                continue
                            body = packet[offset:]
                            if not body.endswith(data):
                                continue
                            if packet[4:offset - 2] != raw or packet[offset - 2:offset] != struct.pack(">H", port):
                                outcome = "wrong_source"
                            elif body != expected:
                                outcome = "cross_talk"
                            else:
                                outcome = "ok"
                            break
                    except (socket.timeout, TimeoutError):
                        continue
                    if outcome != "loss":
                        break
                counters[outcome] += 1
    return {"klass": "", **dict(counters)}


# ---------- worker 侧：常驻状态 ----------

DEEP_METHODS = {
    "duplex_probe": duplex_probe, "half_close_probe": half_close_probe, "empty_probe": empty_probe, "boundary_probe": boundary_probe,
    "parallel_probe": parallel_probe, "short_probe": short_probe, "churn_probe": churn_probe, "idle_probe": idle_probe, "idle_limit_probe": idle_limit_probe,
    "udp_sizes_probe": udp_sizes_probe, "udp_burst_probe": udp_burst_probe, "udp_multi_probe": udp_multi_probe,
}


class DeepState(xh.AgentState):
    def __init__(self, root, binary):
        super().__init__(root, binary)
        self.targets, self.flows, self.weak = {}, {}, set()

    def __getattr__(self, name):
        try:
            return DEEP_METHODS[name]
        except KeyError:
            raise AttributeError(name) from None

    def target_start(self, **options):
        target = DeepTarget(**options)
        self.targets[target.port] = target
        return target.port

    def target_stats(self, port):
        return self.targets[port].stats()

    def target_stop(self, port):
        self.targets.pop(port).stop()
        return True

    def port_in_use(self, port):
        return xh.listening("tcp", port) or xh.listening("udp", port)

    def inflight_start(self, route, host, port):
        flow = Inflight(route, host, port)
        self.flows[id(flow)] = flow
        return id(flow)

    def inflight_status(self, flow):
        return self.flows[flow].status()

    def inflight_stop(self, flow):
        item = self.flows.pop(flow)
        item.halt.set()
        return item.status()

    def signal_child(self, name, signum):
        self.children[name][0].send_signal(signum)
        return True

    def child_pid(self, name):
        return self.children[name][0].pid

    def proc_sample(self, name):
        entry = self.children.get(name)
        if entry is None or entry[0].poll() is not None:
            return {"alive": False}
        pid = entry[0].pid
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii", errors="replace")
        rss = re.search(r"^VmRSS:\s+(\d+)", status, re.M)
        threads = re.search(r"^Threads:\s+(\d+)", status, re.M)
        return {"alive": True, "rss_kib": int(rss.group(1)) if rss else 0, "threads": int(threads.group(1)), "fds": len(os.listdir(f"/proc/{pid}/fd"))}

    def control_get(self, port, path):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return {"status": response.status, "body": json.loads(response.read())}
        finally:
            connection.close()

    def check_config(self, config):
        path = self.workdir / f"check-{threading.get_ident()}-{random.getrandbits(32):x}.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        try:
            result = subprocess.run([self.binary, "check", "-c", str(path)], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        finally:
            path.unlink(missing_ok=True)
        return {"rc": result.returncode, "log": (result.stderr or result.stdout)[-600:]}

    def spawn_script(self, name, argv, wait_ports=()):
        """启动本脚本的辅助子命令（桩进程、泄漏进程）。"""
        return self.spawn_raw(name, [sys.executable, str(Path(__file__).resolve()), *argv], wait_ports)

    def weak_case(self, request):
        """netem 用子进程跑：Lab 的子进程会继承 stdin，不能碰 agent 的 RPC 通道。"""
        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_weak", "--binary", self.binary, "--workdir", str(self.workdir)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        self.weak.add(process)
        try:
            stdout, stderr = process.communicate(json.dumps(request))
        finally:
            self.weak.discard(process)
        try:
            return json.loads(stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {"ok": False, "klass": "weak_tool", "error": stderr[-600:]}

    def shutdown(self):
        for process in list(self.weak):
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
        for target in list(self.targets.values()):
            target.stop()
        for flow in self.flows.values():
            flow.halt.set()
        super().shutdown()


def parse_listening(text, protocol, port):
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 3 and ":" in fields[1] and fields[1].rsplit(":", 1)[1] != "local_address":
            try:
                if int(fields[1].rsplit(":", 1)[1], 16) == port and (protocol == "udp" or fields[3] == "0A"):
                    return True
            except ValueError:
                continue
    return False


def ns_listening(namespace, protocol, port):
    result = subprocess.run(["ip", "netns", "exec", namespace, "cat", f"/proc/net/{protocol}", f"/proc/net/{protocol}6"], capture_output=True, text=True, timeout=10)
    return parse_listening(result.stdout, protocol, port)


def weak_main(args):
    """一条弱网用例：两个 netns、一对 veth、netem 只装在这对 veth 上。"""
    import netem_lab

    request = json.loads(sys.stdin.read())
    options = SimpleNamespace(delay=request["delay"], jitter=0, burst=0, loss=request["loss"], reorder=0, rate=0, queue=5000, mtu=1500, workdir=args.workdir, env=[])
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    lab = netem_lab.Lab(options)
    lab_script = str(Path(netem_lab.__file__).resolve())
    result = {"ok": False, "klass": "weak_tool"}
    try:
        lab.up()
        lab.spawn(lab.b, "echo", [sys.executable, lab_script, "_echo", str(netem_lab.ECHO_PORT)])
        configs = request.get("configs")
        if configs:
            directory = Path(lab.dir)
            if configs.get("origin"):
                (directory / "cert.pem").write_text(configs["origin"]["cert"], encoding="ascii")
                (directory / "key.pem").write_text(configs["origin"]["key"], encoding="ascii")
                lab.spawn(lab.b, "origin", [sys.executable, str(Path(xh.__file__).resolve()), "tls-origin", str(configs["origin"]["port"]), str(directory / "cert.pem"), str(directory / "key.pem")])
            for name, config, namespace in (("node", configs["node"], lab.b), ("client", configs["client"], lab.a)):
                path = directory / f"{name}.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                lab.spawn(namespace, name, [args.binary, "run", "-c", str(path)])
            deadline = time.monotonic() + 20
            waits = [(lab.b, *item) for item in configs["node_ports"]] + [(lab.a, "tcp", netem_lab.SOCKS_PORT)]
            while waits and time.monotonic() < deadline:
                waits = [item for item in waits if not ns_listening(*item)]
                if waits:
                    time.sleep(0.2)
            if waits:
                result.update(klass="setup", error="监听未就绪", node_log=lab.tail("node"), client_log=lab.tail("client"))
                return
            mode, host = "socks", netem_lab.B_ADDR
        else:
            deadline = time.monotonic() + 5
            while not ns_listening(lab.b, "tcp", netem_lab.ECHO_PORT) and time.monotonic() < deadline:
                time.sleep(0.1)
            mode, host = "direct", netem_lab.B_ADDR
        if request.get("blackout_bytes"):
            def blackout():
                """按实际流量触发：按时间触发可能落在建连阶段，或者传输已经结束。"""
                while True:
                    shown = subprocess.run(["tc", "-n", lab.a, "-s", "qdisc", "show", "dev", lab.dev_a], capture_output=True, text=True).stdout
                    sent = re.search(r"Sent (\d+) bytes", shown)
                    if sent and int(sent.group(1)) >= request["blackout_bytes"]:
                        break
                    time.sleep(0.02)
                for namespace, device in ((lab.a, lab.dev_a), (lab.b, lab.dev_b)):
                    subprocess.run(["tc", "-n", namespace, "qdisc", "change", "dev", device, "root", "netem", "loss", "100%"], capture_output=True)
            threading.Thread(target=blackout, daemon=True).start()
        watched = subprocess.run(["ip", "netns", "exec", lab.a, sys.executable, lab_script, "_watch", mode, host, str(netem_lab.ECHO_PORT), str(netem_lab.SOCKS_PORT), str(request["size"]), str(request["stall"])], capture_output=True, text=True)
        try:
            result = json.loads(watched.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            result = {"ok": False, "error": "connect", "detail": watched.stderr[-400:]}
        error = result.get("error") or ""
        result["klass"] = "" if result["ok"] else re.split(r"[@,]", error)[0] or "digest"
        if configs and not result["ok"]:
            result.update(node_log=lab.tail("node"), client_log=lab.tail("client"))
    finally:
        print(json.dumps(result), flush=True)
        lab.down()
        subprocess.run(["rm", "-rf", lab.dir], check=False)


def stub_main(args):
    """对照用的假进程：不理 SIGTERM，或用错误的退出码退出。"""
    signal.signal(signal.SIGTERM, signal.SIG_IGN if args.behavior == "ignore-term" else lambda *_: os._exit(3))
    while True:
        time.sleep(60)


def leak_main(args):
    """对照用的泄漏进程：回显，但连接和内存都不释放。"""
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    server = socket.create_server(("0.0.0.0", args.port), backlog=512)
    hoard = []

    def handle(client):
        hoard.append(client)
        hoard.append(bytearray(1 << 18))
        try:
            while chunk := client.recv(1 << 18):
                client.sendall(chunk)
        except OSError:
            pass

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


# ---------- 编排侧：能力 ----------

@dataclass(frozen=True)
class Caps:
    udp: bool = True
    tcp_eof: bool = True
    multi_member: bool = True
    disabled_member: bool = True
    netns: bool = True
    idle_limit: float | None = None


REFERENCE_CAPS = Caps()


@dataclass(frozen=True)
class Judgement:
    verdict: str
    klass: str = ""
    reason: str = ""


def good(reason=""):
    return Judgement(PASS, "", reason)


def bad(klass, reason=""):
    return Judgement(FAIL, klass, reason)


def graft_client(carrier, spec, fresh):
    """把 spec 的客户端换成 fresh 成员的凭据，节点级密钥和载体参数不变。"""
    client = copy.deepcopy(spec.client)
    if carrier.protocol == "wireguard":
        client["tunnel"]["private_key"] = fresh.client["tunnel"]["private_key"]
        client["tunnel"]["addresses"] = fresh.client["tunnel"]["addresses"]
        client["peer"]["preshared_key"] = fresh.member["preshared_key"]
        return client
    mapping = {value: fresh.member[key] for key, value in spec.member.items() if isinstance(value, str) and value and value != fresh.member[key]}

    def walk(value):
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return mapping.get(value, value) if isinstance(value, str) else value

    return walk(client)


# ---------- 编排侧：台架 ----------

class SetupError(RuntimeError):
    def __init__(self, stage, log=""):
        super().__init__(f"{stage}: {log.strip()[-400:]}")
        self.stage, self.log = stage, log


class Bench:
    """一个场景的运行环境。子类决定路径上有没有 kerlico、“节点”是什么。"""

    route = {"kind": "direct"}
    node_name = None

    def __init__(self, ctx, placement, family="ipv4", loopback=False):
        self.ctx, self.placement, self.family, self.loopback = ctx, placement, family, loopback
        self.A, self.B, self.C = ctx.agents[placement.client], ctx.agents[placement.node], ctx.agents[placement.target]
        self.targets = []
        self.intended_stop = set()

    def host_of(self, agent):
        if self.loopback:
            return "::1" if self.family == "ipv6" else "127.0.0.1"
        return agent.public["v6" if self.family == "ipv6" else "v4"]

    def target(self, agent=None, **options):
        agent = agent or self.C
        port = agent.call("target_start", **options)
        self.targets.append((agent, port))
        return self.host_of(agent), port

    def start(self):
        pass

    def udp_path(self, **options):
        host, port = self.target(**options)
        return {"kind": "direct", "host": host, "port": port}

    def bare_udp_path(self):
        host, port = self.target()
        return {"kind": "direct", "host": host, "port": port}

    def burst_hops(self):
        return [(self.A, self.bare_udp_path())]

    def make_loopback(self, **mode):
        machine = self.placement.target
        return BareBench(self.ctx, xh.Placement(machine, machine, machine), self.family, loopback=True)

    def disrupt(self, how):
        raise SetupError("disrupt", f"{type(self).__name__} 没有节点")

    def restart_node(self):
        raise SetupError("restart", f"{type(self).__name__} 没有节点")

    def restart_client(self):
        pass

    def stop_role(self, role, grace):
        raise SetupError("stop_role", f"{type(self).__name__} 没有 {role}")

    def sample(self):
        return {}

    def usage(self):
        return None

    def weak_request(self):
        return {}

    def evidence(self):
        record = {}
        for label, agent, name in self.processes():
            if name in self.intended_stop:
                continue
            state = agent.call("alive", name=name, timeout=30)
            record[f"{label}_alive"] = state["alive"]
            record[f"{label}_log"] = state["log"][-600:]
        return record

    def processes(self):
        return []

    def stop(self):
        result = {}
        for label, agent, name in self.processes():
            if name in self.intended_stop:
                continue
            try:
                stopped = agent.call("stop", name=name, timeout=60)
                result[f"{label}_rc"] = stopped["rc"]
            except xh.AgentError as error:
                result[f"{label}_rc"] = str(error)
        for agent, port in self.targets:
            try:
                agent.call("target_stop", port=port, timeout=30)
            except xh.AgentError:
                pass
        self.targets = []
        return result


class BareBench(Bench):
    """裸路径：客户端直连目标，没有 kerlico。"""


class SocksDirectBench(Bench):
    """A 上的 kerlico：本地 SOCKS 入口接 direct 出站，没有节点。"""

    def __init__(self, ctx, placement, family="ipv4", limits=None):
        super().__init__(ctx, placement, family)
        self.limits = limits or {}

    def processes(self):
        return [("client", self.A, self.client_name)]

    def start(self):
        self.client_name = self.ctx.name("socks-direct")
        socks = self.A.call("alloc_ports", count=1)[0]
        config = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "local_inbounds": [{"tag": "socks", "type": "socks", "listen": f"127.0.0.1:{socks}", "outbound": "direct", "options": {"version": "5"}}], "inbounds": [], "limits": {**xh.LIMITS, **self.limits}}
        started = self.A.call("spawn_kerlico", name=self.client_name, config=config, wait_ports=[("tcp", socks)])
        if not started["ok"]:
            raise SetupError(started["stage"], started.get("log", ""))
        self.route = {"kind": "socks", "port": socks}


class RelayBench(Bench):
    """“节点”是 B 上的 Python TCP 转发：杀掉它，内核一定发 RST；冻结它，流一定挂住。"""

    node_name = None

    def processes(self):
        return [("node", self.B, self.node_name)] if self.node_name else []

    def start(self):
        self.upstream = self.target()
        self.listen = self.B.call("alloc_ports", count=1)[0]
        self.node_name = self.ctx.name("relay")
        self.spawn()
        self.route = {"kind": "direct", "via": [self.host_of(self.B), self.listen]}

    def spawn(self):
        started = self.B.call("spawn_relay", name=self.node_name, kind="tcp", listen=self.listen, host=self.upstream[0], port=self.upstream[1])
        if not started["ok"]:
            raise SetupError(started["stage"], started.get("log", ""))

    def disrupt(self, how):
        self.B.call("signal_child", name=self.node_name, signum=DISRUPT_SIGNALS[how])

    def restart_node(self):
        self.B.call("stop", name=self.node_name, timeout=60)
        self.spawn()

    def target(self, agent=None, **options):
        if self.targets and not options:
            return self.upstream
        return super().target(agent, **options)


class StubBench(Bench):
    """节点和客户端都是对照用的假进程。"""

    def __init__(self, ctx, placement, behavior, family="ipv4"):
        super().__init__(ctx, placement, family)
        self.behavior = behavior

    def processes(self):
        return [("node", self.B, self.node_name), ("client", self.A, self.client_name)]

    def spawn(self, role):
        agent, name = (self.B, self.node_name) if role == "node" else (self.A, self.client_name)
        started = agent.call("spawn_script", name=name, argv=["_stub", self.behavior])
        if not started["ok"]:
            raise SetupError(started["stage"], started.get("log", ""))
        time.sleep(0.5)

    def start(self):
        self.node_name, self.client_name = self.ctx.name("stub-node"), self.ctx.name("stub-client")
        self.spawn("node")
        self.spawn("client")

    def stop_role(self, role, grace):
        agent, name = (self.B, self.node_name) if role == "node" else (self.A, self.client_name)
        return agent.call("stop", name=name, grace=grace, timeout=grace + 30)

    def restart_client(self):
        self.spawn("client")


class LeakBench(Bench):
    """“节点”是对照用的泄漏进程，路径直连它。"""

    def processes(self):
        return [("node", self.B, self.node_name)] if self.node_name else []

    def start(self):
        self.node_name = self.ctx.name("leak")
        port = self.B.call("alloc_ports", count=1)[0]
        started = self.B.call("spawn_script", name=self.node_name, argv=["_leak", str(port)], wait_ports=[("tcp", port)])
        if not started["ok"]:
            raise SetupError(started["stage"], started.get("log", ""))
        self.route = {"kind": "direct", "via": [self.host_of(self.B), port]}

    def sample(self):
        return {"node": self.B.call("proc_sample", name=self.node_name)}


class Identity:
    """一个成员：节点侧的 native_credential 和客户端配置。member 为 None 时节点不认识它。"""

    def __init__(self, label, client, member, enabled=True):
        self.label, self.client, self.member, self.enabled = label, client, member, enabled
        self.route = None
        self.client_name = None
        self.config = None
        self.ports = None


class KerlicoBench(Bench):
    """被测路径：A 上的客户端 kerlico、B 上的节点 kerlico、C 上的目标。"""

    def __init__(self, ctx, carrier, placement, family="ipv4", members=1, disabled=0, wrong=0, wrong_is_right=False, disabled_is_enabled=False, control=False, limits=None, loopback=False, lazy=False):
        super().__init__(ctx, placement, family, loopback)
        self.carrier = carrier
        self.members, self.disabled, self.wrong = members, disabled, wrong
        self.wrong_is_right, self.disabled_is_enabled = wrong_is_right, disabled_is_enabled
        self.control, self.limits, self.lazy = control, limits or {}, lazy
        self.node_name = None
        self.identities = []
        self.control_port = None

    def processes(self):
        items = [("node", self.B, self.node_name)] if self.node_name else []
        for identity in self.identities:
            if identity.client_name:
                items.append(("client" if identity.label == "good" else f"client_{identity.label}", self.A, identity.client_name))
        if getattr(self, "origin_name", None):
            items.append(("origin", self.B, self.origin_name))
        return items

    def build_identities(self):
        material, carrier = self.ctx.material, self.carrier
        self.spec = spec = carrier.build(material)
        identities = [Identity("good", spec.client, spec.member)]
        for index in range(1, self.members):
            fresh = carrier.build(material)
            identities.append(Identity(f"member{index}", graft_client(carrier, spec, fresh), fresh.member))
        for index in range(self.disabled):
            fresh = carrier.build(material)
            identities.append(Identity(f"disabled{index}", graft_client(carrier, spec, fresh), fresh.member, enabled=self.disabled_is_enabled))
        for index in range(self.wrong):
            fresh = carrier.build(material)
            client = spec.client if self.wrong_is_right else graft_client(carrier, spec, fresh)
            identities.append(Identity(f"wrong{index}", client, None))
        self.identities = identities

    def build_node_config(self, node_port, origin_port):
        config = xh.node_config(self.carrier, self.spec, node_port, self.family, origin_port)
        node = config["nodes"][0]
        registered = [item for item in self.identities if item.member is not None]
        config["accounts"] = []
        bind_members(config, node, [item.member for item in registered])
        for member, identity in zip(node["members"], registered):
            identity.user_id = member["user_id"]
            if not identity.enabled:
                member["enabled"] = False
        config["limits"] = {**xh.LIMITS, **self.limits}
        return config

    def node_wait(self, port):
        wait = []
        if self.carrier.tcp_listener:
            wait.append(("tcp", port))
        if self.carrier.uses_udp_listener:
            wait.append(("udp", port))
        return wait

    def build_client_config(self, identity, node_port, socks_port, udp_port, udp_target):
        spec = replace(self.spec, client=identity.client)
        config = xh.client_config(self.carrier, spec, self.host_of(self.B), node_port, socks_port, udp_port, udp_target)
        config["limits"] = {**xh.LIMITS, **self.limits}
        return config

    def spawn_node(self):
        started = self.B.call("spawn_kerlico", name=self.node_name, config=self.node_cfg, wait_ports=self.node_wait(self.node_port))
        if not started["ok"]:
            raise SetupError(started["stage"], started.get("log", ""))

    def spawn_client(self, identity):
        wait = [("tcp", identity.ports[0])] + ([("udp", identity.ports[1])] if self.carrier.udp else [])
        started = self.A.call("spawn_kerlico", name=identity.client_name, config=identity.config, wait_ports=wait)
        if not started["ok"]:
            raise SetupError(started["stage"], started.get("log", ""))

    def start(self):
        self.build_identities()
        if self.lazy:
            return
        self.node_port, origin_port = self.B.call("alloc_ports", count=2)
        if self.spec.origin:
            self.origin_name = self.ctx.name(self.carrier.key + "-origin")
            started = self.B.call("spawn_tls_origin", name=self.origin_name, port=origin_port, material={"cert": self.ctx.material.cert, "key": self.ctx.material.key})
            if not started["ok"]:
                raise SetupError("origin", started.get("log", ""))
        self.node_cfg = self.build_node_config(self.node_port, origin_port)
        if self.control:
            self.control_port = self.B.call("alloc_ports", count=1)[0]
            self.node_cfg["control"] = {"listen": f"127.0.0.1:{self.control_port}"}
        self.node_name = self.ctx.name(self.carrier.key + "-node")
        self.spawn_node()
        self.udp_target = self.target() if self.carrier.udp else ("127.0.0.1", 9)
        for identity in self.identities:
            socks_port, udp_port = self.A.call("alloc_ports", count=2)
            identity.ports = (socks_port, udp_port)
            identity.config = self.build_client_config(identity, self.node_port, socks_port, udp_port, {"host": self.udp_target[0], "port": self.udp_target[1]})
            identity.client_name = self.ctx.name(self.carrier.key + "-" + identity.label)
            identity.route = {"kind": "socks", "port": socks_port}
            self.spawn_client(identity)
        self.route = self.identities[0].route

    def identity(self, label):
        return next(item for item in self.identities if item.label == label)

    def udp_path(self, **options):
        return {"kind": "forward", "port": self.identities[0].ports[1]}

    def bare_udp_path(self):
        return {"kind": "direct", "host": self.udp_target[0], "port": self.udp_target[1]}

    def burst_hops(self):
        """协议路径是 A-B-C，基线要逐跳测，只测 A-C 会漏掉经过 B 的丢包。"""
        host, port = self.target(self.B)
        return [(self.A, {"kind": "direct", "host": host, "port": port}), (self.B, self.bare_udp_path())]

    def make_loopback(self, **mode):
        machine = self.placement.client
        return KerlicoBench(self.ctx, self.carrier, xh.Placement(machine, machine, machine), self.family, loopback=True)

    def disrupt(self, how):
        self.B.call("signal_child", name=self.node_name, signum=DISRUPT_SIGNALS[how])

    def restart_node(self):
        self.B.call("stop", name=self.node_name, timeout=60)
        for attempt in range(10):
            try:
                self.spawn_node()
                return
            except SetupError:
                if attempt == 9:
                    raise
                time.sleep(3)

    def restart_client(self):
        identity = self.identities[0]
        self.spawn_client(identity)
        self.intended_stop.discard(identity.client_name)

    def stop_role(self, role, grace):
        agent, name = (self.B, self.node_name) if role == "node" else (self.A, self.identities[0].client_name)
        self.intended_stop.add(name)
        return agent.call("stop", name=name, grace=grace, timeout=grace + 30)

    def sample(self):
        result = {"node": self.B.call("proc_sample", name=self.node_name), "client": self.A.call("proc_sample", name=self.identities[0].client_name)}
        if self.control_port:
            result["active_flows"] = self.usage()["active_flows"]
        return result

    def usage(self):
        reply = self.B.call("control_get", port=self.control_port, path="/v1/usage")
        if reply["status"] != 200:
            raise SetupError("control", json.dumps(reply))
        return reply["body"]

    def weak_request(self):
        import netem_lab

        node_port, origin_port = netem_lab.NODE_PORT, netem_lab.NODE_PORT + 10
        node = xh.node_config(self.carrier, self.spec, node_port, "ipv4", origin_port)
        target = {"host": netem_lab.B_ADDR, "port": netem_lab.ECHO_PORT}
        client = xh.client_config(self.carrier, self.spec, netem_lab.B_ADDR, node_port, netem_lab.SOCKS_PORT, netem_lab.SOCKS_PORT + 1, target)
        origin = {"port": origin_port, "cert": self.ctx.material.cert, "key": self.ctx.material.key} if self.spec.origin else None
        return {"configs": {"node": node, "client": client, "origin": origin, "node_ports": self.node_wait(node_port)}}


# ---------- 场景：执行 ----------

def wait_progress(agent, flow, budget):
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        status = agent.call("inflight_status", flow=flow)
        if status["received"] > 0 or status["ended"]:
            return status
        time.sleep(0.2)
    return agent.call("inflight_status", flow=flow)


def wait_ended(agent, flow, budget):
    started = time.monotonic()
    while time.monotonic() - started < budget:
        status = agent.call("inflight_status", flow=flow)
        if status["ended"]:
            return status, round(time.monotonic() - started, 2)
        time.sleep(0.25)
    return agent.call("inflight_status", flow=flow), None


def run_duplex(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("duplex_probe", route=bench.route, host=host, port=port, size=p["size"], stall=p["stall"], sndbuf=p.get("sndbuf", 0), timeout=LONG)


def run_half_close(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("half_close_probe", route=bench.route, host=host, port=port, sizes=p["sizes"], stall=p["stall"], eof_wait=p["eof_wait"], timeout=LONG)


def run_empty(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("empty_probe", route=bench.route, host=host, port=port, rounds=p["rounds"], eof_wait=p["eof_wait"], stall=p["stall"], timeout=LONG)


def run_boundaries(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("boundary_probe", route=bench.route, host=host, port=port, sizes=p["sizes"], stall=p["stall"], timeout=LONG)


def run_parallel(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("parallel_probe", route=bench.route, host=host, port=port, conns=p["conns"], size=p["size"], stall=p["stall"], timeout=LONG)


def run_short(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("short_probe", route=bench.route, host=host, port=port, count=p["count"], size=p["size"], stall=p["stall"], timeout=LONG)


def run_churn(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("churn_probe", route=bench.route, host=host, port=port, count=p["count"], workers=p["workers"], size=p["size"], stall=p["stall"], timeout=LONG)


def run_auth_wrong(bench, p):
    good_host, good_port = bench.target()
    wrong_host, wrong_port = bench.target()
    before = bench.A.call("duplex_probe", route=bench.route, host=good_host, port=good_port, size=4096, stall=p["stall"], timeout=LONG)
    flow = bench.A.call("inflight_start", route=bench.route, host=good_host, port=good_port)
    progress = wait_progress(bench.A, flow, 30)
    wrong = bench.identity("wrong0").route
    attempts = [bench.A.call("duplex_probe", route=wrong, host=wrong_host, port=wrong_port, size=1024, stall=p["wrong_stall"], timeout=LONG) for _ in range(p["attempts"])]
    during = bench.A.call("inflight_stop", flow=flow)
    after = bench.A.call("duplex_probe", route=bench.route, host=good_host, port=good_port, size=4096, stall=p["stall"], timeout=LONG)
    return {"before": before, "attempts": attempts, "flow_progress": progress["received"] > 0, "flow_during": during, "after": after, "wrong_target": bench.C.call("target_stats", port=wrong_port), "node": bench.B.call("alive", name=bench.node_name)["alive"]}


def run_auth_disabled(bench, p):
    good_host, good_port = bench.target()
    wrong_host, wrong_port = bench.target()
    enabled = bench.A.call("duplex_probe", route=bench.route, host=good_host, port=good_port, size=4096, stall=p["stall"], timeout=LONG)
    disabled = bench.identity("disabled0").route
    attempts = [bench.A.call("duplex_probe", route=disabled, host=wrong_host, port=wrong_port, size=1024, stall=p["wrong_stall"], timeout=LONG) for _ in range(p["attempts"])]
    after = bench.A.call("duplex_probe", route=bench.route, host=good_host, port=good_port, size=4096, stall=p["stall"], timeout=LONG)
    return {"before": enabled, "attempts": attempts, "flow_progress": True, "flow_during": {"ended": False, "klass": ""}, "after": after, "wrong_target": bench.C.call("target_stats", port=wrong_port), "node": bench.B.call("alive", name=bench.node_name)["alive"]}


def run_recovery(bench, p):
    host, port = bench.target()
    flow = bench.A.call("inflight_start", route=bench.route, host=host, port=port)
    progress = wait_progress(bench.A, flow, 30)
    if not progress["received"]:
        return {"flow_progress": False, "flow": progress}
    bench.disrupt(p["disrupt"])
    status, time_to_error = wait_ended(bench.A, flow, p["error_budget"])
    bench.A.call("inflight_stop", flow=flow)
    if p["disrupt"] == "kill":
        bench.restart_node()
    started = time.monotonic()
    attempts, new_ok, last = 0, None, None
    while time.monotonic() - started < p["new_budget"]:
        attempts += 1
        last = bench.A.call("duplex_probe", route=bench.route, host=host, port=port, size=4096, stall=p["probe_stall"], timeout=LONG)
        if last["ok"]:
            new_ok = round(time.monotonic() - started, 2)
            break
        time.sleep(1)
    return {"flow_progress": True, "flow": status, "time_to_error": time_to_error, "error_budget": p["error_budget"], "new_conn_after": new_ok, "attempts": attempts, "last_klass": (last or {}).get("klass", ""), "sent": status["sent"], "received": status["received"]}


def run_unreachable(bench, p):
    a, stall = bench.A, p["stall"]
    closed_port = bench.C.call("alloc_ports", count=1)[0]
    closed = a.call("duplex_probe", route=bench.route, host=bench.host_of(bench.C), port=closed_port, size=1024, stall=stall, timeout=LONG)
    canary_port = a.call("target_start", loopback_only=True)
    bench.targets.append((a, canary_port))
    if bench.B.call("port_in_use", port=canary_port):
        raise SetupError("canary", "节点机上该端口已被占用")
    loop_host = "::1" if bench.family == "ipv6" else "127.0.0.1"
    via_canary = a.call("duplex_probe", route=bench.route, host=loop_host, port=canary_port, size=1024, stall=stall, timeout=LONG)
    host, port = bench.target()
    followup = a.call("duplex_probe", route=bench.route, host=host, port=port, size=1024, stall=stall, timeout=LONG)
    down_host, down_port = bench.target()
    node_down = None
    if bench.node_name:
        bench.stop_role("node", 10)
        node_down = a.call("duplex_probe", route=bench.route, host=down_host, port=down_port, size=1024, stall=stall, timeout=LONG)
    return {"closed": closed, "via_canary": via_canary, "canary": a.call("target_stats", port=canary_port), "followup": followup, "node_down": node_down, "node_down_target": bench.C.call("target_stats", port=down_port), "stall": stall}


def run_idle(bench, p):
    host, port = bench.target(**p.get("target", {}))
    return bench.A.call("idle_probe", route=bench.route, host=host, port=port, idle=p["idle"], size=p["size"], stall=p["stall"], timeout=LONG)


def run_idle_limit(bench, p):
    host, port = bench.target()
    result = bench.A.call("idle_limit_probe", route=bench.route, host=host, port=port, wait_max=p["wait_max"], stall=p["stall"], timeout=LONG)
    result["limit"] = p["limits"]["idle_timeout_ms"] / 1000
    result["expect_upper"] = p["expect_upper"]
    return result


def run_udp_sizes(bench, p):
    sizes = p["sizes"]
    bare = bench.A.call("udp_sizes_probe", route=bench.bare_udp_path(), sizes=sizes, timeout=LONG)
    path = bench.A.call("udp_sizes_probe", route=bench.udp_path(**p.get("target", {})), sizes=sizes, timeout=LONG)
    failed = [item["size"] for item in path["rounds"] if not item["ok"]]
    loop = None
    if failed:
        loopback = bench.make_loopback()
        try:
            loopback.start()
            loop = loopback.A.call("udp_sizes_probe", route=loopback.udp_path(**p.get("target", {})), sizes=failed, timeout=LONG)
        finally:
            loopback.stop()
    return {"bare": bare["rounds"], "path": path["rounds"], "loop": loop["rounds"] if loop else []}


def run_udp_burst(bench, p):
    kwargs = {"count": p["count"], "size": p["size"], "pps": p["pps"], "drain": p["drain"], "timeout": LONG}
    hops = [agent.call("udp_burst_probe", route=route, **kwargs) for agent, route in bench.burst_hops()]
    survived = 1.0
    for hop in hops:
        survived *= 1 - hop["loss"]
    bare = {"loss": round(1 - survived, 4), "received": min(hop["received"] for hop in hops), "duplicates": sum(hop["duplicates"] for hop in hops), "hops": [hop["loss"] for hop in hops]}
    path = bench.A.call("udp_burst_probe", route=bench.udp_path(**p.get("target", {})), **kwargs)
    loop = None
    if path["loss"] - bare["loss"] > UDP_LOSS_TOLERANCE:
        loopback = bench.make_loopback()
        try:
            loopback.start()
            loop = loopback.A.call("udp_burst_probe", route=loopback.udp_path(**p.get("target", {})), **kwargs)
        finally:
            loopback.stop()
    return {"bare": bare, "path": path, "loop": loop}


def run_udp_multi(bench, p):
    first = bench.target(udp_mode="tag", tag="first:")
    second = bench.target(udp_mode="tag", tag="second:" if not p.get("swap_tag") else "first:")
    targets = [[first[0], first[1], "first:"], [second[0], second[1], "second:"]]
    return bench.A.call("udp_multi_probe", socks=bench.route["port"], targets=targets, rounds=p["rounds"], wait=p["wait"], tries=p["tries"], timeout=LONG)


def run_weak(bench, p):
    base = {"loss": p["loss"], "delay": p["delay"], "size": p["size"], "stall": p["stall"]}
    kernel = bench.ctx.kernel_baseline(bench.A, base)
    request = {**base, **bench.weak_request()}
    if p.get("blackout_bytes"):
        request["blackout_bytes"] = p["blackout_bytes"]
    result = bench.A.call("weak_case", request=request, timeout=LONG)
    result["kernel_mib_s"] = kernel.get("mib_s")
    result["kernel_ok"] = kernel.get("ok")
    return result


def wait_no_flows(bench, budget):
    """无 tcp_eof 的出站，客户端关闭后流要等到空闲超时才结束；预算要大于 idle_timeout_ms。"""
    started = time.monotonic()
    while bench.sample().get("active_flows") and time.monotonic() - started < budget:
        time.sleep(1)
    return round(time.monotonic() - started, 1)


def settle(bench, base, budget):
    """等连接和文件描述符回落；到期后取最后一次采样。"""
    started = time.monotonic()
    sample = bench.sample()
    while time.monotonic() - started < budget:
        node_fds = sample.get("node", {}).get("fds", 0)
        client_fds = sample.get("client", {}).get("fds", 0)
        flows = sample.get("active_flows", 0)
        if not flows and node_fds <= base.get("node", {}).get("fds", 0) + FD_SLACK // 2 and client_fds <= base.get("client", {}).get("fds", 0) + FD_SLACK // 2:
            break
        time.sleep(3)
        sample = bench.sample()
    sample["settled_after"] = round(time.monotonic() - started, 1)
    return sample


def run_resources(bench, p):
    host, port = bench.target()
    a = bench.A
    warm = a.call("parallel_probe", route=bench.route, host=host, port=port, conns=8, size=1 << 16, stall=p["stall"], timeout=LONG)
    wait_no_flows(bench, p["settle"])
    time.sleep(3)
    base = bench.sample()
    storms, samples = [], []
    for _ in range(p["storms"]):
        burst = a.call("parallel_probe", route=bench.route, host=host, port=port, conns=p["conns"], size=p["size"], stall=p["stall"], timeout=LONG)
        short = a.call("short_probe", route=bench.route, host=host, port=port, count=p["short"], size=64, stall=p["stall"], timeout=LONG)
        storms.append({"parallel_failed": burst["failed"], "short_failed": short["failed"], "classes": {**burst["classes"], **short["classes"]}, "samples": burst["samples"][:2] + short["samples"][:2]})
        samples.append(settle(bench, base, p["settle"]))
    return {"warm_failed": warm["failed"], "base": base, "samples": samples, "storms": storms}


def run_exit(bench, p):
    result = {"budget": p["budget"]}
    for role in ("client", "node"):
        host, port = bench.target()
        flow = bench.A.call("inflight_start", route=bench.route, host=host, port=port)
        progress = wait_progress(bench.A, flow, 30)
        stopped = bench.stop_role(role, p["budget"])
        status, ended_after = wait_ended(bench.A, flow, p["flow_end_budget"])
        bench.A.call("inflight_stop", flow=flow)
        result[role] = {"rc": stopped["rc"], "elapsed": stopped["elapsed"], "flow_progress": progress["received"] > 0, "flow_ended_after": ended_after, "sent": status["sent"], "received": status["received"], "log": stopped.get("log", "")[-300:]}
        if role == "client":
            bench.restart_client()
    return result


def run_accounting(bench, p):
    host, port = bench.target()
    first, second = bench.identities[0], bench.identities[1]
    sizes = {first.label: p["first_size"], second.label: p["second_size"]}
    transfers = {}
    for identity in (first, second):
        transfers[identity.label] = bench.A.call("duplex_probe", route=identity.route, host=host, port=port, size=sizes[identity.label], stall=p["stall"], seed=identity.label, timeout=LONG)
    cleared_after = wait_no_flows(bench, p["settle"])
    usage = bench.usage()
    expected = {first.user_id: sizes[first.label], second.user_id: sizes[second.label]}
    if p.get("swap_expected"):
        expected = {first.user_id: sizes[second.label], second.user_id: sizes[first.label]}
    return {
        "transfers": {key: {"ok": value["ok"], "klass": value["klass"], "sent": value["sent"], "received": value["received"]} for key, value in transfers.items()},
        "expected": expected,
        "users": usage["users"],
        "engine": usage["engine"],
        "active_flows": usage["active_flows"],
        "flows_cleared_after": cleared_after,
    }


# ---------- 场景：判定。纯函数，单元测试直接喂度量 ----------

def transfer_detail(m):
    text = f"已发 {m.get('sent')}，已收 {m.get('received')}/{m.get('size')}"
    if m.get("first_diff") is not None:
        text += f"，首个不同字节 {m['first_diff']}"
    if m.get("sender_error"):
        text += f"，发送错误 {m['sender_error']}"
    return text


def judge_duplex(m, caps):
    if m["ok"]:
        return good(f"{m['mib_s']} MiB/s，最长间隔 {m['longest_gap']} 秒，耗时 {m['elapsed']} 秒")
    return bad(m["klass"], transfer_detail(m))


def judge_half_close(m, caps):
    for item in m["rounds"]:
        if item["klass"] == "no_eof" and not caps.tcp_eof:
            continue
        if item["klass"]:
            return bad(item["klass"], f"{item['size']} 字节：已发 {item['sent']}，已收 {item['received']}，EOF {item['eof_seen']}")
    note = "" if caps.tcp_eof else "，出站无 tcp_eof，不要求 EOF"
    return good(f"{len(m['rounds'])} 档完整{note}")


def judge_empty(m, caps):
    if m["connect_failures"]:
        return bad("connect", f"{m['connect_failures']} 次连接失败：{m['classes']}")
    if m["no_eof"] and caps.tcp_eof:
        return bad("no_eof", f"{m['no_eof']}/{m['rounds']} 次关写后等不到 EOF")
    if m["classes"].get("data_on_empty"):
        return bad("data_on_empty", "空连接收到了数据")
    if not m["followup"]["ok"]:
        return bad("followup", f"之后的 1 KiB 失败：{m['followup']['klass']}")
    if m["no_eof"]:
        return good(f"{m['rounds']} 次直接关闭正常；{m['no_eof']} 次关写后没有 EOF，出站无 tcp_eof，不要求")
    return good(f"{m['rounds']} 次直接关闭、{m['rounds']} 次关写，EOF 最慢 {m['eof_latency_max']} 秒")


def judge_boundaries(m, caps):
    if m["failed"]:
        first = m["failed"][0]
        return bad(first["klass"], f"{len(m['failed'])}/{m['sizes']} 档失败，首个 {first['size']} 字节：已发 {first['sent']}，已收 {first['received']}")
    return good(f"{m['sizes']} 档全部一致")


def judge_parallel(m, caps):
    if m["failed"]:
        return bad("conn_failures", f"{m['failed']}/{m['conns']} 条失败：{m['classes']}，首例 {m['samples'][0]}")
    return good(f"{m['conns']} 条全部一致，合计 {m['mib_s']} MiB/s，最长间隔 {m['longest_gap']} 秒")


def judge_short(m, caps):
    if m["failed"]:
        return bad("conn_failures", f"{m['failed']}/{m['count']} 次失败：{m['classes']}")
    return good(f"{m['count']} 次全部成功，P50 {m['p50_ms']} 毫秒，P99 {m['p99_ms']} 毫秒")


def judge_churn(m, caps):
    if m["failed"]:
        return bad("conn_failures", f"{m['failed']}/{m['count']} 次失败：{m['classes']}，{m['per_second']} 次/秒")
    return good(f"{m['count']} 次全部成功，{m['per_second']} 次/秒")


def judge_auth(m, caps):
    if m["wrong_target"]["conns"] or m["wrong_target"]["bytes_in"]:
        return bad("auth_bypass", f"被拒身份的目标收到 {m['wrong_target']['conns']} 条连接、{m['wrong_target']['bytes_in']} 字节")
    if any(item["ok"] for item in m["attempts"]):
        return bad("auth_bypass", "被拒身份的回显成功")
    if not m["node"]:
        return bad("node_died", "节点在负例后退出")
    for label in ("before", "after"):
        if not m[label]["ok"]:
            return bad("good_user_failed", f"正常用户 {label} 失败：{m[label]['klass']}")
    if not m["flow_progress"] or m["flow_during"]["ended"]:
        return bad("good_user_failed", f"负例期间正常用户的流中断：{m['flow_during']['klass']}")
    classes = Counter(item["klass"] for item in m["attempts"])
    return good(f"{len(m['attempts'])} 次被拒：{dict(classes)}，正常用户不受影响")


def judge_recovery(m, caps):
    if not m["flow_progress"]:
        return bad("no_flow", f"断开前的流没有进展：{m['flow']}")
    if m["time_to_error"] is None:
        return bad("hang", f"{m['error_budget']} 秒内在途连接没有报错，已发 {m['sent']}，已收 {m['received']}")
    if m["new_conn_after"] is None:
        return bad("no_recovery", f"节点恢复后 {m['attempts']} 次新连接都失败，最后 {m['last_klass']}")
    return good(f"在途连接 {m['time_to_error']} 秒报错（{m['flow']['klass']}），新连接 {m['new_conn_after']} 秒恢复")


def judge_unreachable(m, caps):
    if m["canary"]["conns"]:
        return bad("fallback_direct", f"本机回环金丝雀收到 {m['canary']['conns']} 条连接")
    if m["node_down_target"]["conns"]:
        return bad("fallback_direct", f"节点停止后目标收到 {m['node_down_target']['conns']} 条连接")
    for label in ("closed", "via_canary"):
        item = m[label]
        if item["ok"]:
            return bad("unexpected_success", f"{label} 意外成功")
        if item["klass"] == "stall":
            return bad("hang", f"{label} 在 {m['stall']} 秒内没有报错")
    if not m["followup"]["ok"]:
        return bad("followup", f"之后的正常目标失败：{m['followup']['klass']}")
    if m["node_down"] is not None:
        if m["node_down"]["ok"]:
            return bad("unexpected_success", "节点停止后回显成功")
        if m["node_down"]["klass"] == "stall":
            return bad("hang", f"节点停止后 {m['stall']} 秒内没有报错")
    down = m["node_down"]["klass"] if m["node_down"] else "无节点"
    return good(f"关闭端口 {m['closed']['klass']}，回环 {m['via_canary']['klass']}，节点停止 {down}")


def judge_idle(m, caps):
    closed = m.get("closed_after")
    if closed is not None:
        if caps.idle_limit and abs(closed - caps.idle_limit) <= IDLE_SLACK:
            return good(f"按协议文档的 {caps.idle_limit} 秒空闲限额，{closed} 秒关闭")
        return bad("idle_closed", f"空闲 {closed} 秒时连接被关闭（{m['klass']}），协议文档限额 {caps.idle_limit}")
    second = m.get("second")
    if second is None:
        return bad(m["klass"] or "first_failed", f"空闲前失败：{m['klass']}")
    if not second["ok"]:
        return bad("idle_closed", f"空闲 {m.get('idle')} 秒后 {second['klass']}，{transfer_detail(second)}")
    return good(f"空闲 {m['idle']} 秒后传输 {second['mib_s']} MiB/s")


def judge_idle_limit(m, caps):
    if m["klass"]:
        return bad(m["klass"], "空闲前的传输失败")
    closed, limit = m["closed_after"], m["limit"]
    if closed is None:
        return bad("idle_not_enforced", f"限额 {limit} 秒，等了 {m.get('wait_max')} 秒没有关闭")
    if closed < limit * 0.5:
        return bad("idle_early", f"限额 {limit} 秒，{closed} 秒就关闭")
    if closed > m["expect_upper"]:
        return bad("idle_late", f"限额 {limit} 秒，{closed} 秒才关闭")
    return good(f"限额 {limit} 秒，{closed} 秒关闭")


def largest_ok(rounds):
    return max((item["size"] for item in rounds if item["ok"]), default=0)


def join_sizes(sizes):
    """不写成 Python 列表：Scrubber 的 IPv6 正则会把 [65507] 当成地址抹掉。"""
    return "、".join(str(size) for size in sizes)


def judge_udp_sizes(m, caps):
    bare = {item["size"]: item for item in m["bare"]}
    if any(not bare[size]["ok"] for size in bare if size <= 64):
        return Judgement(TOOL_ERROR, "path_down", "裸路径小包不通")
    loop = {item["size"]: item for item in m["loop"]}
    path_limited, protocol_limited = [], []
    for item in m["path"]:
        if item["ok"]:
            continue
        size = item["size"]
        if size <= 64:
            return bad("udp_small_fail", f"{size} 字节失败：{item['klass']}")
        if loop.get(size, {}).get("ok"):
            path_limited.append(size)
        elif size <= 1200:
            return bad("udp_below_1200", f"{size} 字节在路径和回环都失败：{item['klass']}")
        else:
            protocol_limited.append(size)
    text = f"路径最大 {largest_ok(m['path'])}，裸路径最大 {largest_ok(m['bare'])}"
    if path_limited:
        text += f"，路径受限 {join_sizes(path_limited)}"
    if protocol_limited:
        text += f"，回环也不通 {join_sizes(protocol_limited)}"
    return good(text)


def judge_udp_burst(m, caps):
    bare, path, loop = m["bare"], m["path"], m["loop"]
    if bare["received"] == 0:
        return Judgement(TOOL_ERROR, "path_down", "裸路径突发全部丢失")
    if path["corrupt"]:
        return bad("udp_corrupt", f"{path['corrupt']} 个包内容不符")
    if path["duplicates"] > bare["duplicates"]:
        return bad("udp_dup", f"重复 {path['duplicates']}，裸路径 {bare['duplicates']}")
    text = f"丢失 {path['loss']:.1%}（裸路径 {bare['loss']:.1%}），乱序 {path['reordered']}，重复 {path['duplicates']}"
    if path["received"] == 0:
        return bad("udp_no_reply", "全部丢失，" + text)
    if loop is not None:
        if loop["loss"] > UDP_LOSS_TOLERANCE:
            return bad("udp_loss", text + f"，回环丢失 {loop['loss']:.1%}")
        return bad("udp_loss_with_rtt", text + f"，回环丢失 {loop['loss']:.1%}，裸路径逐跳 {bare.get('hops')}")
    return good(text)


def judge_udp_multi(m, caps):
    if m["klass"] == "socks_reply_7":
        return Judgement(NA, "", "出站不提供多目标 UDP 关联")
    if m["klass"]:
        return bad(m["klass"], "UDP 关联建立失败")
    if m.get("cross_talk"):
        return bad("cross_talk", f"{m['cross_talk']} 个回包来自错误目标")
    if m.get("wrong_source"):
        return bad("wrong_source", f"{m['wrong_source']} 个回包的来源地址不符")
    if m.get("loss"):
        return bad("udp_loss", f"重试后仍有 {m['loss']} 个包没有回包")
    return good(f"{m.get('ok', 0)} 个回包的来源和标签都正确")


def judge_weak(m, caps):
    if m.get("kernel_ok") is False and m.get("klass") != "stall":
        return Judgement(TOOL_ERROR, "baseline_failed", "内核 TCP 基线也没完成")
    if m["ok"]:
        kernel = m.get("kernel_mib_s") or 0
        ratio = f"，内核 {kernel}，比值 {m['mib_s'] / kernel:.2f}" if kernel else ""
        return good(f"{m['mib_s']} MiB/s{ratio}，最长间隔 {m.get('longest_gap')} 秒")
    if m.get("klass") in ("setup", "weak_tool"):
        return Judgement(TOOL_ERROR, m["klass"], str(m.get("error") or m.get("detail"))[-300:])
    return bad(m.get("klass") or "weak_failed", f"{m.get('error')}，已发 {m.get('sent')}，已收 {m.get('received')}，最长间隔 {m.get('longest_gap')} 秒")


def judge_resources(m, caps):
    base, samples, storms = m["base"], m["samples"], m["storms"]
    failed = sum(item["parallel_failed"] + item["short_failed"] for item in storms)
    if m["warm_failed"]:
        return bad("storm_failed", f"预热有 {m['warm_failed']} 条失败")
    last = samples[-1]
    notes = []
    for role in ("node", "client"):
        if role not in base:
            continue
        before, after = base[role], last[role]
        if not after.get("alive"):
            return bad("process_died", f"{role} 在风暴后退出")
        if after["fds"] > before["fds"] + FD_SLACK:
            return bad("fd_leak", f"{role} fd {before['fds']} -> {after['fds']}")
        if after["threads"] > before["threads"] + THREAD_SLACK:
            return bad("thread_leak", f"{role} 线程 {before['threads']} -> {after['threads']}")
        if len(samples) > 1:
            trend = after["rss_kib"] - samples[0][role]["rss_kib"]
            if trend > RSS_TREND_KIB and after["rss_kib"] > before["rss_kib"] + RSS_SLACK_KIB:
                return bad("rss_growth", f"{role} RSS {before['rss_kib']} -> {samples[0][role]['rss_kib']} -> {after['rss_kib']} KiB")
        notes.append(f"{role} fd {before['fds']}->{after['fds']}，RSS {before['rss_kib'] >> 10}->{after['rss_kib'] >> 10} MiB")
    if last.get("active_flows"):
        return bad("flows_leak", f"active_flows 停在 {last['active_flows']}")
    if failed:
        classes = Counter()
        for item in storms:
            classes.update(item.get("classes", {}))
        return bad("storm_failed", f"风暴中有 {failed} 条失败：{dict(classes)}，每轮 {[item['parallel_failed'] + item['short_failed'] for item in storms]}")
    return good("；".join(notes) + f"，{last.get('settled_after')} 秒回落")


def judge_exit(m, caps):
    for role in ("client", "node"):
        item = m[role]
        if not item["flow_progress"]:
            return bad("no_flow", f"{role} 停止前流没有进展")
        if item["rc"] != 0:
            return bad("exit_not_clean", f"{role} 退出码 {item['rc']}，耗时 {item['elapsed']} 秒，预算 {m['budget']} 秒，日志 {item['log'][-160:]}")
        if item["flow_ended_after"] is None:
            return bad("flow_hang", f"{role} 退出后在途连接没有结束")
    return good(f"客户端 {m['client']['elapsed']} 秒，节点 {m['node']['elapsed']} 秒，退出码都是 0")


def judge_accounting(m, caps):
    for label, item in m["transfers"].items():
        if not item["ok"]:
            return bad("transfer_failed", f"{label} 传输失败：{item['klass']}")
    if m["active_flows"]:
        return bad("flows_leak", f"传输结束后 active_flows={m['active_flows']}")
    total_up = total_down = 0
    for user, size in m["expected"].items():
        usage = m["users"].get(user)
        if usage is None:
            return bad("usage_missing", "用量里没有该成员")
        if usage["upload_bytes"] != size or usage["download_bytes"] != size:
            return bad("usage_mismatch", f"预期 {size}，上传 {usage['upload_bytes']}，下载 {usage['download_bytes']}")
        total_up += usage["upload_bytes"]
        total_down += usage["download_bytes"]
    if m["engine"]["upload_bytes"] != total_up or m["engine"]["download_bytes"] != total_down:
        return bad("usage_mismatch", f"Engine 视图 {m['engine']} 与成员合计 {total_up}/{total_down} 不符")
    return good(f"两个成员 {join_sizes(sorted(m['expected'].values()))} 字节，用量逐字节相符，流 {m.get('flows_cleared_after')} 秒后结束")


# ---------- 场景表 ----------

def requires_udp(caps):
    return None if caps.udp else "协议不支持 UDP"


def requires_multi_member(caps):
    return None if caps.multi_member else "kerlico check 拒绝第二个成员"


def requires_disabled_member(caps):
    return None if caps.disabled_member else "kerlico check 拒绝停用成员"


def requires_netns(caps):
    return None if caps.netns else "worker 没有 root 或 tc"


def always(caps):
    return None


@dataclass(frozen=True)
class Scenario:
    name: str
    applies: object
    run: object
    judge: object
    params: dict = field(default_factory=dict)
    bench: dict = field(default_factory=dict)
    single_host: bool = False
    # 丢包统计对机器负载敏感，这类场景在其他场景跑完后逐个单独跑。
    exclusive: bool = False
    # 裸 Mesh 不保留半关闭（基线 half_close 实测），这些场景只能在回环路径上判定协议。
    loopback: bool = False


STALL = 120.0
SCENARIOS = (
    Scenario("integrity_duplex_32m", always, run_duplex, judge_duplex, {"size": 32 * MIB, "stall": STALL}),
    Scenario("integrity_half_close", always, run_half_close, judge_half_close, {"sizes": [1, 65536, 4 * MIB], "stall": STALL, "eof_wait": 30.0}, single_host=True, loopback=True),
    Scenario("integrity_empty", always, run_empty, judge_empty, {"rounds": 5, "eof_wait": 15.0, "stall": STALL}, single_host=True, loopback=True),
    Scenario("integrity_boundaries", always, run_boundaries, judge_boundaries, {"sizes": list(BOUNDARY_SIZES), "stall": STALL}),
    Scenario("concurrent_parallel_64", always, run_parallel, judge_parallel, {"conns": 64, "size": MIB, "stall": STALL}),
    Scenario("concurrent_short_500", always, run_short, judge_short, {"count": 500, "size": 64, "stall": 30.0}),
    Scenario("concurrent_quota_release", always, run_churn, judge_churn, {"count": 400, "workers": 16, "size": 64, "stall": 30.0}, {"limits": {"max_sessions": 64}}, single_host=True, loopback=True),
    Scenario("auth_wrong_credential", always, run_auth_wrong, judge_auth, {"attempts": 3, "stall": 30.0, "wrong_stall": 15.0}, {"wrong": 1}),
    Scenario("auth_disabled_member", requires_disabled_member, run_auth_disabled, judge_auth, {"attempts": 3, "stall": 30.0, "wrong_stall": 15.0}, {"disabled": 1}),
    Scenario("recovery_node_restart", always, run_recovery, judge_recovery, {"disrupt": "kill", "error_budget": 150.0, "new_budget": 60.0, "probe_stall": 15.0}),
    Scenario("recovery_unreachable", always, run_unreachable, judge_unreachable, {"stall": 45.0}),
    Scenario("idle_120s", always, run_idle, judge_idle, {"idle": 120.0, "size": MIB, "stall": STALL}, {"limits": {"idle_timeout_ms": 300000}}),
    Scenario("idle_limit_enforced", always, run_idle_limit, judge_idle_limit, {"wait_max": 60.0, "stall": 30.0, "limits": {"idle_timeout_ms": 10000}, "expect_upper": 40.0}, {"limits": {"idle_timeout_ms": 10000}}),
    Scenario("udp_sizes", requires_udp, run_udp_sizes, judge_udp_sizes, {"sizes": list(UDP_SIZES)}),
    Scenario("udp_burst_1000", requires_udp, run_udp_burst, judge_udp_burst, {"count": 1000, "size": 512, "pps": 500, "drain": 3.0}, exclusive=True),
    Scenario("udp_multi_target", requires_udp, run_udp_multi, judge_udp_multi, {"rounds": 10, "wait": 1.5, "tries": 3}),
    Scenario("weak_loss1_rtt100", requires_netns, run_weak, judge_weak, {"loss": 1.0, "delay": 50, "size": 8 * MIB, "stall": STALL}, {"lazy": True}, single_host=True),
    Scenario("weak_loss5", requires_netns, run_weak, judge_weak, {"loss": 5.0, "delay": 10, "size": 8 * MIB, "stall": STALL}, {"lazy": True}, single_host=True),
    Scenario("resources_after_storm", always, run_resources, judge_resources, {"conns": 64, "size": 1 << 18, "short": 100, "storms": 3, "settle": 90.0, "stall": STALL}, {"control": True}),
    Scenario("graceful_exit", always, run_exit, judge_exit, {"budget": 10.0, "flow_end_budget": 60.0}),
    Scenario("accounting_two_users", requires_multi_member, run_accounting, judge_accounting, {"first_size": 3 * MIB, "second_size": MIB, "stall": STALL, "settle": 90.0}, {"members": 2, "control": True}),
)
SCENARIO_BY_NAME = {item.name: item for item in SCENARIOS}


@dataclass(frozen=True)
class Control:
    scenario: str
    label: str
    bench: str
    params: dict
    expect: str
    expect_class: tuple = ()
    bench_options: dict = field(default_factory=dict)
    # 判定相符之外还要成立的条件，证明这个对照确实走到了它要测的情形。
    premise: object = None


def sender_outlasted_stall(metrics):
    """发送阻塞得比停滞窗口久。否则共用超时的旧缺陷在这条对照上也不会暴露。"""
    return (metrics.get("send_elapsed") or 0) > metrics["stall"]


CONTROLS = (
    Control("integrity_duplex_32m", "good-bare", "bare", {}, PASS),
    Control("integrity_duplex_32m", "good-slow-progress", "bare", {"size": 4 * MIB, "stall": 3.0, "sndbuf": 1 << 14, "target": {"tcp_mode": "throttle", "arg": MIB // 2, "rcvbuf": 1 << 14}}, PASS, premise=sender_outlasted_stall),
    Control("integrity_duplex_32m", "bad-truncate", "bare", {"size": 4 * MIB, "stall": 15.0, "target": {"tcp_mode": "truncate", "arg": MIB}}, FAIL, ("eof",)),
    Control("integrity_duplex_32m", "bad-corrupt", "bare", {"size": 4 * MIB, "stall": 15.0, "target": {"tcp_mode": "corrupt", "arg": 123456}}, FAIL, ("digest",)),
    Control("integrity_duplex_32m", "bad-stall", "bare", {"size": 4 * MIB, "stall": 5.0, "target": {"tcp_mode": "stall_after", "arg": MIB}}, FAIL, ("stall",)),
    Control("integrity_half_close", "good-bare", "bare", {}, PASS),
    Control("integrity_half_close", "bad-no-eof", "bare", {"sizes": [65536], "eof_wait": 5.0, "target": {"tcp_mode": "no_eof"}}, FAIL, ("no_eof",)),
    Control("integrity_half_close", "bad-truncate", "bare", {"sizes": [65536], "stall": 15.0, "target": {"tcp_mode": "truncate", "arg": 1024}}, FAIL, ("eof",)),
    Control("integrity_empty", "good-bare", "bare", {}, PASS),
    Control("integrity_empty", "bad-no-eof", "bare", {"rounds": 2, "eof_wait": 3.0, "target": {"tcp_mode": "no_eof"}}, FAIL, ("no_eof",)),
    Control("integrity_boundaries", "good-bare", "bare", {}, PASS),
    Control("integrity_boundaries", "bad-truncate", "bare", {"stall": 15.0, "target": {"tcp_mode": "truncate", "arg": 70000}}, FAIL, ("eof",)),
    Control("concurrent_parallel_64", "good-bare", "bare", {}, PASS),
    Control("concurrent_parallel_64", "bad-flaky", "bare", {"target": {"tcp_mode": "flaky", "arg": 8}, "stall": 15.0}, FAIL, ("conn_failures",)),
    Control("concurrent_short_500", "good-bare", "bare", {}, PASS),
    Control("concurrent_short_500", "bad-flaky", "bare", {"count": 100, "target": {"tcp_mode": "flaky", "arg": 10}, "stall": 15.0}, FAIL, ("conn_failures",)),
    Control("concurrent_quota_release", "good-socks", "socks", {}, PASS),
    Control("concurrent_quota_release", "bad-target-holds-flows", "socks", {"target": {"tcp_mode": "no_eof"}, "count": 200}, FAIL, ("conn_failures",)),
    Control("auth_wrong_credential", "good-socks", "socks", {}, PASS),
    Control("auth_wrong_credential", "bad-right-credential", "socks", {}, FAIL, ("auth_bypass",), {"wrong_is_right": True}),
    Control("auth_disabled_member", "good-socks", "socks", {}, PASS),
    Control("auth_disabled_member", "bad-member-enabled", "socks", {}, FAIL, ("auth_bypass",), {"disabled_is_enabled": True}),
    Control("recovery_node_restart", "good-relay", "relay", {}, PASS),
    Control("recovery_node_restart", "bad-frozen-relay", "relay", {"disrupt": "freeze", "error_budget": 15.0, "new_budget": 6.0, "probe_stall": 3.0}, FAIL, ("hang",)),
    Control("recovery_unreachable", "good-socks", "socks", {}, PASS),
    Control("recovery_unreachable", "bad-direct", "socks-direct", {"stall": 10.0}, FAIL, ("fallback_direct",)),
    Control("idle_120s", "good-bare", "bare", {}, PASS),
    Control("idle_120s", "bad-target-closes", "bare", {"idle": 8.0, "stall": 15.0, "target": {"tcp_mode": "idle_close", "arg": 3}}, FAIL, ("idle_closed",)),
    Control("idle_limit_enforced", "good-socks", "socks", {}, PASS),
    Control("idle_limit_enforced", "bad-limit-too-long", "socks", {"wait_max": 25.0, "limits": {"idle_timeout_ms": 3600000}}, FAIL, ("idle_not_enforced",), {"limits": {"idle_timeout_ms": 3600000}}),
    Control("udp_sizes", "good-bare", "bare", {"sizes": [1, 64, 1200]}, PASS),
    Control("udp_sizes", "bad-target-limit", "bare", {"sizes": [1, 64, 1200], "target": {"udp_mode": "limit", "arg": 100}}, FAIL, ("udp_below_1200",)),
    Control("udp_burst_1000", "good-bare", "bare", {}, PASS),
    Control("udp_burst_1000", "bad-drop-half", "bare", {"target": {"udp_mode": "drop_half"}}, FAIL, ("udp_loss",)),
    Control("udp_burst_1000", "bad-duplicate", "bare", {"target": {"udp_mode": "dup"}}, FAIL, ("udp_dup",)),
    Control("udp_multi_target", "good-socks-direct", "socks-direct", {}, PASS),
    Control("udp_multi_target", "bad-wrong-tag", "socks-direct", {"swap_tag": True, "rounds": 2}, FAIL, ("cross_talk",)),
    Control("weak_loss1_rtt100", "good-kernel", "bare", {}, PASS),
    Control("weak_loss1_rtt100", "bad-blackout", "bare", {"size": 64 * MIB, "blackout_bytes": MIB, "stall": 15.0}, FAIL, ("stall",)),
    Control("weak_loss5", "good-kernel", "bare", {}, PASS),
    Control("weak_loss5", "bad-blackout", "bare", {"size": 64 * MIB, "blackout_bytes": MIB, "stall": 15.0}, FAIL, ("stall",)),
    Control("resources_after_storm", "good-socks", "socks", {}, PASS),
    Control("resources_after_storm", "bad-leak", "leak", {"short": 50, "settle": 10.0, "storms": 1}, FAIL, ("fd_leak",)),
    Control("graceful_exit", "good-socks", "socks", {}, PASS),
    Control("graceful_exit", "bad-ignores-sigterm", "stub", {"budget": 3.0}, FAIL, ("exit_not_clean",), {"behavior": "ignore-term"}),
    Control("graceful_exit", "bad-exit-code", "stub", {"budget": 3.0}, FAIL, ("exit_not_clean",), {"behavior": "exit-3"}),
    Control("accounting_two_users", "good-socks", "socks", {}, PASS),
    Control("accounting_two_users", "bad-swapped-expectation", "socks", {"swap_expected": True}, FAIL, ("usage_mismatch",)),
)


def control_matches(control, judgement, metrics=None):
    """失败了但分类不对也算不符：红色不等于测到了预期的东西。"""
    if judgement.verdict != control.expect:
        return False
    if control.premise and not control.premise(metrics or {}):
        return False
    return control.expect != FAIL or judgement.klass in control.expect_class


def untrusted_scenarios(records):
    return sorted({item["scenario"] for item in records if not item["matched"]})


def apply_trust(record, untrusted):
    if record["scenario"] in untrusted and record["verdict"] in (PASS, FAIL, NA):
        return {**record, "verdict": TOOL_ERROR, "klass": "control_mismatch", "raw_verdict": record["verdict"], "raw_klass": record.get("klass", "")}
    return record


def apply_liveness(judgement, evidence):
    """非故意的进程退出不能被算作通过。"""
    if judgement.verdict != PASS:
        return judgement
    dead = [key[:-6] for key, value in evidence.items() if key.endswith("_alive") and value is False]
    return bad("process_died", f"{','.join(dead)} 在场景中退出") if dead else judgement


# ---------- 编排侧：运行 ----------

class DeepAgent(xh.Agent):
    """同一套 RPC，但脚本和工作目录都在 deep 下，不动 xhost 的编排状态。"""

    def start(self):
        here = Path(__file__).resolve().parent
        for name in UPLOADS:
            remote = f"{ROOT}/{name}"
            upload = subprocess.run(self.ssh_argv(f"mkdir -p {ROOT} && chmod 700 {ROOT} && cat > {remote}.{os.getpid()} && mv {remote}.{os.getpid()} {remote}"), input=(here / name).read_bytes(), capture_output=True, timeout=120)
            if upload.returncode:
                raise xh.AgentError(f"{self.alias} 上传失败：{upload.stderr.decode('utf-8', 'replace')[-300:]}")
        self.process = subprocess.Popen(self.ssh_argv(f"exec python3 -u {ROOT}/protocol_deep.py agent --root {ROOT} --binary {self.binary}"), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        threading.Thread(target=self.reader, args=(self.process,), daemon=True).start()
        self.addr = self.call("addrs")

    def close(self):
        try:
            super().close()
        except OSError:
            self.process.kill()


PATH_RE = re.compile(r"/(?:srv|root|home|tmp|var|proc)/[^\s\"':,;)]+")


def scrub(value, scrubber):
    text = PATH_RE.sub("<path>", scrubber.clean(json.dumps(value, ensure_ascii=False)))
    return json.loads(text)


class Context:
    def __init__(self, agents, material, scrubber, args, tool_sha):
        self.agents, self.material, self.scrubber, self.args, self.tool_sha = agents, material, scrubber, args, tool_sha
        self.lock = threading.Lock()
        self.unique = 0
        self.caps_cache, self.kernel = {}, {}
        self.document = {"tool": "protocol_deep", "tool_sha256": tool_sha, "binary_sha256": args.binary_sha256, "network": args.network, "controls": [], "untrusted": [], "results": [], "baselines": []}
        self.out = Path(args.out)
        if getattr(args, "resume", False) and self.out.exists():
            previous = json.loads(self.out.read_text(encoding="utf-8"))
            if previous.get("tool_sha256") == tool_sha and previous.get("binary_sha256") == args.binary_sha256:
                self.document = previous

    def name(self, label):
        with self.lock:
            self.unique += 1
            return f"{re.sub(r'[^a-zA-Z0-9]', '-', label)[:40]}-{self.unique}"

    def flush(self):
        temporary = self.out.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.document, ensure_ascii=False, indent=1), encoding="utf-8")
        temporary.replace(self.out)

    def add(self, section, record):
        cleaned = scrub(record, self.scrubber)
        with self.lock:
            self.document[section].append(cleaned)
            self.flush()
        return cleaned

    def caps(self, carrier):
        with self.lock:
            cached = self.caps_cache.get(carrier.key)
        if cached:
            return cached
        result = probe_caps(self, carrier)
        with self.lock:
            self.caps_cache[carrier.key] = result
        return result

    def kernel_baseline(self, agent, request):
        key = (agent.alias, request["loss"], request["delay"], request["size"], request["stall"])
        with self.lock:
            cached = self.kernel.get(key)
        if cached:
            return cached
        result = agent.call("weak_case", request=dict(request), timeout=LONG)
        with self.lock:
            self.kernel[key] = result
        self.add("baselines", {"kind": "weak_kernel", "machine": agent.alias, "detail": f"丢包 {request['loss']}%，单向延迟 {request['delay']} 毫秒，{request['size'] >> 20} MiB：{result.get('mib_s')} MiB/s {result.get('error') or ''}".rstrip()})
        return result


def probe_caps(ctx, carrier):
    """能力从二进制自己的 check 得出，不在工具里维护第二份。"""
    agent = ctx.agents[xh.MACHINES[0]]
    bench = KerlicoBench(ctx, carrier, xh.PLACEMENTS[0], members=2, disabled=0)
    bench.build_identities()
    ports = agent.call("alloc_ports", count=4)
    two = bench.build_node_config(ports[0], ports[1])
    multi = agent.call("check_config", config=two)["rc"] == 0
    bench = KerlicoBench(ctx, carrier, xh.PLACEMENTS[0], members=1, disabled=1, disabled_is_enabled=False)
    bench.build_identities()
    disabled = agent.call("check_config", config=bench.build_node_config(ports[0], ports[1]))["rc"] == 0
    client = bench.build_client_config(bench.identities[0], ports[0], ports[2], ports[3], {"host": "192.0.2.2", "port": 9})
    client["inbounds"].append({"tag": "eof", "type": "tcp-forward", "listen": "127.0.0.1:0", "target": {"host": "192.0.2.2", "port": 9}, "outbound": "proxy", "require_remote_eof": True})
    eof = agent.call("check_config", config=client)["rc"] == 0
    privileged = agent.call("run_command", argv=["sh", "-c", "[ \"$(id -u)\" = 0 ] && command -v tc >/dev/null && command -v ip >/dev/null"])["rc"] == 0
    return Caps(udp=carrier.udp, tcp_eof=eof, multi_member=multi, disabled_member=disabled, netns=privileged, idle_limit=DOCUMENTED_IDLE.get(carrier.protocol))


def scenario_failure(exception):
    return Judgement(TOOL_ERROR, type(exception).__name__, str(exception)[-400:])


def execute(ctx, scenario, bench, params, caps):
    """跑一个场景。任何工具层面的异常都记 tool-error，不算协议失败。"""
    started = time.monotonic()
    metrics, evidence = {}, {}
    judgement = Judgement(TOOL_ERROR, "not_run")
    try:
        try:
            bench.start()
            metrics = scenario.run(bench, params)
            evidence = bench.evidence()
            judgement = scenario.judge(metrics, caps)
            judgement = apply_liveness(judgement, evidence)
        except (SetupError, xh.AgentError, KeyError, TypeError, ValueError, OSError) as error:
            judgement = scenario_failure(error)
            try:
                evidence = bench.evidence()
            except (xh.AgentError, OSError):
                pass
    finally:
        try:
            evidence.update(bench.stop())
        except (xh.AgentError, OSError) as error:
            evidence["stop_error"] = str(error)
    for key in ("sent", "received"):
        if key in metrics:
            evidence[key] = metrics[key]
    if judgement.verdict == PASS:
        evidence = {key: value for key, value in evidence.items() if not key.endswith("_log")}
    return {"scenario": scenario.name, "verdict": judgement.verdict, "klass": judgement.klass, "reason": judgement.reason, "metrics": metrics, "evidence": evidence, "elapsed": round(time.monotonic() - started, 1)}


def same_machine(placement):
    return xh.Placement(placement.client, placement.client, placement.client)


def bench_for_control(ctx, control, scenario, placement):
    options = {**scenario.bench, **control.bench_options}
    limits = {"limits": options["limits"]} if "limits" in options else {}
    if control.bench == "bare":
        return BareBench(ctx, same_machine(placement), loopback=True) if scenario.loopback else BareBench(ctx, placement)
    if control.bench == "socks":
        options = {key: value for key, value in options.items() if key != "lazy"}
        if scenario.loopback:
            return KerlicoBench(ctx, ctx.reference, same_machine(placement), loopback=True, **options)
        return KerlicoBench(ctx, ctx.reference, placement, **options)
    if control.bench == "socks-direct":
        return SocksDirectBench(ctx, placement, **limits)
    if control.bench == "relay":
        return RelayBench(ctx, placement)
    if control.bench == "stub":
        return StubBench(ctx, placement, control.bench_options["behavior"])
    if control.bench == "leak":
        return LeakBench(ctx, placement)
    raise ValueError(control.bench)


def run_control(ctx, control, placement):
    scenario = SCENARIO_BY_NAME[control.scenario]
    params = {**scenario.params, **control.params}
    record = execute(ctx, scenario, bench_for_control(ctx, control, scenario, placement), params, REFERENCE_CAPS)
    judgement = Judgement(record["verdict"], record["klass"], record["reason"])
    record.update(label=control.label, expect=control.expect, expect_class=list(control.expect_class), placement=placement.label, matched=control_matches(control, judgement, record["metrics"]))
    stored = ctx.add("controls", record)
    print(f"对照 {control.scenario}/{control.label}: {record['verdict']} {record['klass']} 预期 {control.expect} {'符合' if record['matched'] else '不符'} | {ctx.scrubber.clean(record['reason'])[:120]}", flush=True)
    return stored


def path_ok(ctx, placement, family="ipv4"):
    """协议失败后测同一排列的裸路径，路径坏了不算协议的账。"""
    bench = BareBench(ctx, placement, family)
    try:
        hops = [(bench.A, bench.C), (bench.A, bench.B), (bench.B, bench.C)]
        for source, sink in hops:
            host, port = bench.target(sink)
            if not source.call("duplex_probe", route={"kind": "direct"}, host=host, port=port, size=1 << 16, stall=30.0, timeout=120)["ok"]:
                return False
        return True
    except xh.AgentError:
        return False
    finally:
        bench.stop()


def parse_overrides(items):
    """--set udp_burst_1000.pps=100 -> {"udp_burst_1000": {"pps": 100}}。值按 JSON 解析。"""
    overrides = {}
    for item in items or ():
        key, _, value = item.partition("=")
        scenario, _, name = key.partition(".")
        if scenario not in SCENARIO_BY_NAME or name not in SCENARIO_BY_NAME[scenario].params:
            raise SystemExit(f"--set 指向不存在的场景参数：{key}")
        overrides.setdefault(scenario, {})[name] = json.loads(value)
    return overrides


def run_scenario_record(ctx, carrier, placement, family, scenario, caps):
    options = dict(scenario.bench)
    params = {**scenario.params, **ctx.overrides.get(scenario.name, {})}
    if scenario.loopback:
        bench = KerlicoBench(ctx, carrier, same_machine(placement), family, loopback=True, **options)
    else:
        bench = KerlicoBench(ctx, carrier, placement, family, **options)
    return execute(ctx, scenario, bench, params, caps)


def run_item(ctx, carrier, placement, family, scenario):
    base = {"protocol": carrier.protocol, "carrier": carrier.name, "placement": placement.label, "family": family}
    done = {(r["protocol"], r["carrier"], r["placement"], r["family"], r["scenario"]) for r in ctx.document["results"] if r["verdict"] != TOOL_ERROR}
    if (carrier.protocol, carrier.name, placement.label, family, scenario.name) in done:
        return
    try:
        caps = ctx.caps(carrier)
    except (xh.AgentError, OSError, KeyError) as error:
        ctx.add("results", {**base, "scenario": scenario.name, "verdict": TOOL_ERROR, "klass": "caps", "reason": str(error), "metrics": {}, "evidence": {}})
        return
    missing = scenario.applies(caps)
    if missing:
        ctx.add("results", {**base, "scenario": scenario.name, "verdict": NA, "klass": "", "reason": missing, "metrics": {}, "evidence": {}, "elapsed": 0})
        print(f"{carrier.key} {placement.label} {scenario.name}: na {missing}", flush=True)
        return
    record = run_scenario_record(ctx, carrier, placement, family, scenario, caps)
    if record["verdict"] == FAIL:
        if not path_ok(ctx, placement, family):
            record.update(verdict=TOOL_ERROR, klass="path_down", raw_klass=record["klass"])
        elif ctx.args.confirm:
            again = run_scenario_record(ctx, carrier, placement, family, scenario, caps)
            record["retest"] = {"verdict": again["verdict"], "klass": again["klass"], "reason": again["reason"]}
    record = apply_trust({**base, **record}, set(ctx.document["untrusted"]))
    stored = ctx.add("results", record)
    print(f"{carrier.key} {placement.label} {scenario.name}: {stored['verdict']} {stored['klass']} | {stored['reason'][:160]}", flush=True)


def select_carriers(only):
    """带 / 的词要求整个载体名相同：vless/raw-tls 不包括 vless/raw-tls-mux。"""
    words = [word for word in (only or "").split(",") if word]
    return [carrier for carrier in xh.CARRIERS if not words or any(word == carrier.key if "/" in word else word in carrier.key for word in words)]


def select_scenarios(only):
    words = [word for word in (only or "").split(",") if word]
    return [item for item in SCENARIOS if not words or any(word in item.name for word in words)]


def tool_sha():
    digest = hashlib.sha256()
    here = Path(__file__).resolve().parent
    for name in UPLOADS:
        digest.update((here / name).read_bytes())
    return digest.hexdigest()


def bring_up(args):
    scrubber = xh.Scrubber()

    def start(alias):
        agent = DeepAgent(alias, args.ssh_config, args.binary)
        agent.start()
        agent.networks = {"public": {"v4": xh.resolve_public_v4(args.ssh_config, alias), "v6": agent.addr["public"]["v6"]}, "mesh": agent.addr["mesh"]}
        agent.public = agent.networks[args.network]
        for network, addresses in agent.networks.items():
            for family, address in addresses.items():
                scrubber.add(address, f"{alias}-{network}-{family}")
        return alias, agent

    with ThreadPoolExecutor(max_workers=3) as pool:
        agents = dict(pool.map(start, xh.MACHINES))
    return agents, scrubber


def verify_binary(agents, args):
    digests = {alias: agent.call("run_command", argv=["sha256sum", args.binary])["stdout"].split()[0] for alias, agent in agents.items()}
    if len(set(digests.values())) != 1:
        raise SystemExit(f"三台的二进制不一致：{digests}")
    digest = next(iter(digests.values()))
    if args.expect_sha and not digest.startswith(args.expect_sha):
        raise SystemExit(f"二进制摘要 {digest} 不是预期的 {args.expect_sha}")
    return digest


def make_context(agents, scrubber, args):
    args.binary_sha256 = verify_binary(agents, args)
    tls = agents[xh.MACHINES[0]].call("gen_tls")
    material = xh.Material(tls["ca"], tls["cert"], tls["key"])
    ctx = Context(agents, material, scrubber, args, tool_sha())
    ctx.reference = next(carrier for carrier in xh.CARRIERS if carrier.key == "socks/socks5-auth")
    ctx.overrides = parse_overrides(getattr(args, "set", None))
    ctx.document["overrides"] = ctx.overrides
    return ctx


def run_controls(ctx, scenarios):
    names = {item.name for item in scenarios}
    selected = [item for item in CONTROLS if item.scenario in names]
    with ThreadPoolExecutor(max_workers=ctx.args.control_jobs) as pool:
        records = list(pool.map(lambda control: run_control(ctx, control, xh.PLACEMENTS[0]), selected))
    measure_half_close_paths(ctx)
    return records


def measure_half_close_paths(ctx):
    """记下裸 Mesh 和回环对半关闭的实际表现，这是半关闭场景只在回环上跑的依据。"""
    placement = xh.PLACEMENTS[0]
    for label, bench in (("mesh", BareBench(ctx, placement)), ("loopback", BareBench(ctx, same_machine(placement), loopback=True))):
        host, port = bench.target()
        try:
            result = bench.A.call("half_close_probe", route=bench.route, host=host, port=port, sizes=[65536], stall=15.0, eof_wait=10.0, timeout=120)["rounds"][0]
            ctx.add("baselines", {"kind": "half_close", "machine": placement.client, "detail": f"{label}：发 {result['sent']}，收 {result['received']}，分类 {result['klass'] or '完整'}"})
        finally:
            bench.stop()


def adopt_controls(ctx, scenarios):
    """复用上一轮对照要求工具和二进制都没变。"""
    source = json.loads(Path(ctx.args.controls_from).read_text(encoding="utf-8"))
    if source["tool_sha256"] != ctx.tool_sha or source["binary_sha256"] != ctx.args.binary_sha256:
        raise SystemExit("--controls-from 的工具或二进制摘要与本轮不同，不能复用")
    names = {item.name for item in scenarios}
    covered = {item["scenario"] for item in source["controls"]}
    if not names <= covered:
        raise SystemExit(f"--controls-from 缺少场景的对照：{sorted(names - covered)}")
    return [item for item in source["controls"] if item["scenario"] in names]


def command_controls(args):
    agents, scrubber = bring_up(args)
    try:
        ctx = make_context(agents, scrubber, args)
        scenarios = select_scenarios(args.scenarios)
        records = run_controls(ctx, scenarios)
        ctx.document["untrusted"] = untrusted_scenarios(records)
        ctx.flush()
        print(f"对照 {len(records)} 项，不符 {sum(not item['matched'] for item in records)} 项，不可信场景 {ctx.document['untrusted']}", flush=True)
        return 1 if ctx.document["untrusted"] else 0
    finally:
        for agent in agents.values():
            agent.close()


def command_run(args):
    agents, scrubber = bring_up(args)
    try:
        ctx = make_context(agents, scrubber, args)
        scenarios = select_scenarios(args.scenarios)
        carriers = select_carriers(args.only)
        placements = [xh.PLACEMENTS[int(index)] for index in args.placements.split(",")]
        if ctx.document["controls"]:
            records = ctx.document["controls"]
        elif args.controls_from:
            records = adopt_controls(ctx, scenarios)
            ctx.document["controls"] = records
        else:
            records = run_controls(ctx, scenarios)
        ctx.document["untrusted"] = untrusted_scenarios(records)
        ctx.flush()
        if ctx.document["untrusted"]:
            print(f"对照不符，这些场景本轮记 tool-error：{ctx.document['untrusted']}", flush=True)
        work = []
        for carrier in carriers:
            for family in args.families.split(","):
                for index, placement in enumerate(placements):
                    for scenario in scenarios:
                        if scenario.single_host and index:
                            continue
                        work.append((carrier, placement, family, scenario))

        def task(item):
            try:
                run_item(ctx, *item)
            except Exception as error:
                carrier, placement, family, scenario = item
                ctx.add("results", {"protocol": carrier.protocol, "carrier": carrier.name, "placement": placement.label, "family": family, "scenario": scenario.name, "verdict": TOOL_ERROR, "klass": type(error).__name__, "reason": str(error), "metrics": {}, "evidence": {}})

        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            list(pool.map(task, [item for item in work if not item[3].exclusive]))
        for item in work:
            if item[3].exclusive:
                task(item)
        counts = Counter(item["verdict"] for item in ctx.document["results"])
        print(f"结果 {dict(counts)}", flush=True)
        return 0
    finally:
        for agent in agents.values():
            agent.close()


def command_check(args):
    """校验全部载体的深度配置：多成员、停用成员、错误凭据、半关闭能力。"""
    agents, scrubber = bring_up(args)
    try:
        ctx = make_context(agents, scrubber, args)
        agent = agents[xh.MACHINES[0]]
        bad_count = 0
        for carrier in select_carriers(args.only):
            caps = probe_caps(ctx, carrier)
            bench = KerlicoBench(ctx, carrier, xh.PLACEMENTS[0], members=1, wrong=1)
            bench.build_identities()
            ports = agent.call("alloc_ports", count=4)
            configs = [("node", bench.build_node_config(ports[0], ports[1]))]
            for identity in bench.identities:
                configs.append((identity.label, bench.build_client_config(identity, ports[0], ports[2], ports[3], {"host": "192.0.2.2", "port": 9})))
            failures = []
            for label, config in configs:
                result = agent.call("check_config", config=config)
                if result["rc"]:
                    failures.append(f"{label}: {scrubber.clean(result['log'])[-200:]}")
            bad_count += bool(failures)
            print(f"{carrier.key}: {caps} {'; '.join(failures) if failures else '配置通过'}", flush=True)
        print(f"配置失败的载体 {bad_count} 个", flush=True)
        return 1 if bad_count else 0
    finally:
        for agent in agents.values():
            agent.close()


# ---------- 报告 ----------

def forbid_leaks(text):
    """Markdown 要入库，残留地址和路径直接报错。"""
    cleaned = xh.Scrubber().clean(text)
    if cleaned != text:
        found = xh.Scrubber.IP.search(text).group(0)
        raise ValueError(f"报告含地址样式的文本：{found}")
    if PATH_RE.search(text):
        raise ValueError(f"报告含机器路径：{PATH_RE.search(text).group(0)}")
    return text


def cell_text(text, limit=150):
    text = str(text).replace("|", "/").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


def placement_short(label):
    return f"P{[item.label for item in xh.PLACEMENTS].index(label)}" if label in [item.label for item in xh.PLACEMENTS] else label


def render_report(document):
    lines = ["# 深度测试结果", "", f"二进制 SHA-256 `{document['binary_sha256'][:16]}…`，工具摘要 `{document['tool_sha256'][:12]}`，网络 `{document['network']}`。", ""]
    if document.get("overrides"):
        lines += [f"诊断覆盖：`{json.dumps(document['overrides'], ensure_ascii=False)}`。", ""]
    controls = document["controls"]
    mismatched = [item for item in controls if not item["matched"]]
    lines += [f"## 对照（{len(controls)} 项，不符 {len(mismatched)} 项）", "", "| 场景 | 对照 | 预期 | 实际 | 分类 | 符合 | 说明 |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for item in sorted(controls, key=lambda entry: ([s.name for s in SCENARIOS].index(entry["scenario"]) if entry["scenario"] in SCENARIO_BY_NAME else 99, entry["label"])):
        expected = item["expect"] + (f" {'/'.join(item['expect_class'])}" if item.get("expect_class") else "")
        lines.append(f"| {item['scenario']} | {item['label']} | {expected} | {item['verdict']} | {item['klass']} | {'是' if item['matched'] else '**否**'} | {cell_text(item['reason'])} |")
    if document["untrusted"]:
        lines += ["", f"对照不符的场景本轮记 tool-error：{', '.join(document['untrusted'])}。"]
    baselines = document.get("baselines") or []
    if baselines:
        lines += ["", "## 基线", "", "| 项 | 机器 | 结果 |", "| --- | --- | --- |"]
        for item in baselines:
            lines.append(f"| {item['kind']} | {item['machine']} | {item['detail']} |")
    protocols = {}
    for item in document["results"]:
        protocols.setdefault(item["protocol"], []).append(item)
    for protocol, records in protocols.items():
        counts = Counter(item["verdict"] for item in records)
        lines += ["", f"## {protocol}", "", "判定：" + "，".join(f"{key} {counts[key]}" for key in (PASS, FAIL, NA, TOOL_ERROR) if counts[key]) + "。", "", "| 载体 | 排列 | 场景 | 判定 | 分类 | 度量 |", "| --- | --- | --- | --- | --- | --- |"]
        order = {scenario.name: index for index, scenario in enumerate(SCENARIOS)}
        records = sorted(records, key=lambda entry: (entry["carrier"], entry["placement"], order.get(entry["scenario"], len(order))))
        for item in records:
            verdict = f"**{item['verdict']}**" if item["verdict"] in (FAIL, TOOL_ERROR) else item["verdict"]
            retest = item.get("retest")
            reason = item["reason"] + (f"（复测 {retest['verdict']}）" if retest else "")
            lines.append(f"| {item['carrier']} | {placement_short(item['placement'])} | {item['scenario']} | {verdict} | {item['klass']} | {cell_text(reason)} |")
        failures = [item for item in records if item["verdict"] in (FAIL, TOOL_ERROR)]
        if failures:
            lines += ["", "失败证据：", ""]
            for item in failures:
                evidence = item.get("evidence", {})
                brief = {key: evidence[key] for key in ("node_rc", "client_rc", "node_alive", "client_alive", "sent", "received") if key in evidence}
                log = next((evidence[key] for key in ("node_log", "client_log") if evidence.get(key)), "")
                last = log.strip().splitlines()[-1] if log.strip() else ""
                lines.append(f"- `{item['carrier']}` {placement_short(item['placement'])} `{item['scenario']}`：{json.dumps(brief, ensure_ascii=False)} {cell_text(last, 200)}")
    return forbid_leaks("\n".join(lines) + "\n")


def command_report(args):
    document = json.loads(Path(args.path).read_text(encoding="utf-8"))
    text = render_report(document)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))
    return 0


def add_common(parser):
    parser.add_argument("--ssh-config", default=".private/machines/ssh_config")
    parser.add_argument("--binary", default="/srv/build/kerlico/xhost/kerlico-1.3.2")
    parser.add_argument("--expect-sha", default="")
    parser.add_argument("--network", choices=["public", "mesh"], default="mesh")
    parser.add_argument("--out", default="deep-results.json")
    parser.add_argument("--only", default="", help="逗号分隔。带 / 的词是完整载体名，不带的按子串匹配")
    parser.add_argument("--scenarios", default="", help="只跑名字含此文本的场景，逗号分隔")
    parser.add_argument("--control-jobs", type=int, default=4)


def main():
    parser = argparse.ArgumentParser(description="kerlico 逐协议深度测试")
    sub = parser.add_subparsers(dest="command", required=True)
    agent = sub.add_parser("agent")
    agent.add_argument("--root", required=True)
    agent.add_argument("--binary", required=True)
    weak = sub.add_parser("_weak")
    weak.add_argument("--binary", required=True)
    weak.add_argument("--workdir", required=True)
    stub = sub.add_parser("_stub")
    stub.add_argument("behavior")
    leak = sub.add_parser("_leak")
    leak.add_argument("port", type=int)
    add_common(sub.add_parser("check"))
    add_common(sub.add_parser("controls"))
    run = sub.add_parser("run")
    add_common(run)
    run.add_argument("--placements", default="0")
    run.add_argument("--families", default="ipv4")
    run.add_argument("--jobs", type=int, default=2)
    run.add_argument("--confirm", type=int, default=1, help="失败后复测次数，0 不复测")
    run.add_argument("--resume", action="store_true")
    run.add_argument("--controls-from", default="")
    run.add_argument("--set", action="append", help="诊断用：覆盖场景参数，如 udp_burst_1000.pps=100。结果 JSON 记下覆盖项")
    report = sub.add_parser("report")
    report.add_argument("path")
    report.add_argument("--out", default="")
    args = parser.parse_args()
    if args.command == "agent":
        xh.agent_main(args, DeepState)
    elif args.command == "_weak":
        weak_main(args)
    elif args.command == "_stub":
        stub_main(args)
    elif args.command == "_leak":
        leak_main(args)
    else:
        return {"check": command_check, "controls": command_controls, "run": command_run, "report": command_report}[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
