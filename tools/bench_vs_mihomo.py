#!/usr/bin/env python3
"""kerlico vs mihomo 全协议与全组合同工况性能基准测试工具。

在海外专用性能机（perf-01 / perf-02 / perf-03）上对每个协议与每种传输/安全/复用组合
执行相同负载下的对照测试，采集：
- 机器硬件与系统基线（CPU 型号、物理/逻辑核心数、主频、缓存、内存总量、内核与 glibc 版本、二进制 SHA-256 与体积）
- 内存占用：空闲/活跃/峰值 RSS（VmRSS / VmHWM）、PSS（smaps_rollup）、Private_Dirty（kB）
- CPU 占用：基于 /proc/<pid>/schedstat 的纳秒级精确 CPU 时间（ms）、user/sys 拆分、平均 CPU 占用率（%CPU）、每 MiB 传输耗费 CPU 毫秒数（CPU-ms/MiB）
- 吞吐与时延：TCP 首包握手 RTT（ms，5 次中位数/P95）、TCP 单流吞吐（MiB/s）、TCP 8 并发流吞吐（MiB/s）、UDP 首包 RTT（ms）、UDP 吞吐（MiB/s 与 PPS）及丢包率
- 系统资源：线程数（Threads）、打开文件描述符数（FDs）、自愿/非自愿上下文切换次数
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import socketserver
import ssl
import statistics
import struct
import subprocess
import sys
import threading
import time
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from config_v2 import bind_members
from mihomo_ready import add_probe, wait_running

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
USER_UUID = "00000000-0000-4000-8000-000000000001"
USER_PASSWORD = "bench-synthetic-password-2026"
USER_NAME = "bench-user"
SUDOKU_KEY = "synthetic-sudoku-cli-node-a-secret"
ALLOCATED_PORTS: set[int] = set()
PORT_LOCK = threading.Lock()


def allocate_port(host: str = "127.0.0.1") -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with PORT_LOCK:
        for _ in range(512):
            candidate = 14000 + int.from_bytes(os.urandom(2), "big") % 18000
            if candidate in ALLOCATED_PORTS:
                continue
            try:
                with socket.socket(family, socket.SOCK_STREAM) as tcp, socket.socket(
                    family, socket.SOCK_DGRAM
                ) as udp:
                    tcp.bind((host, candidate))
                    udp.bind((host, candidate))
                    ALLOCATED_PORTS.add(candidate)
                    return candidate
            except OSError:
                continue
    raise RuntimeError("无法分配空闲测试回环端口")


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def collect_machine_info(alias: str, kerlico_bin: str, mihomo_bin: str) -> dict[str, Any]:
    cpuinfo = Path("/proc/cpuinfo").read_text( errors="replace") if Path("/proc/cpuinfo").exists() else ""
    model_name = "unknown"
    cpu_mhz = None
    cache_size = None
    flags: list[str] = []
    for line in cpuinfo.splitlines():
        if ":" not in line:
            continue
        k, v = [p.strip() for p in line.split(":", 1)]
        if k == "model name" and model_name == "unknown":
            model_name = v
        elif k == "cpu MHz" and cpu_mhz is None:
            try:
                cpu_mhz = round(float(v), 2)
            except ValueError:
                pass
        elif k == "cache size" and cache_size is None:
            cache_size = v
        elif k == "flags" and not flags:
            interesting = {"aes", "avx", "avx2", "avx512f", "sha_ni", "vaes", "vpclmulqdq", "pclmulqdq"}
            flags = sorted(interesting.intersection(v.split()))

    lscpu_map: dict[str, str] = {}
    try:
        out = subprocess.check_output(["lscpu"], text=True, timeout=5)
        for line in out.splitlines():
            if ":" in line:
                k, v = [p.strip() for p in line.split(":", 1)]
                lscpu_map[k] = v
    except Exception:
        pass

    mem_total_kb = 0
    mem_avail_kb = 0
    if Path("/proc/meminfo").exists():
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem_total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                mem_avail_kb = int(line.split()[1])

    os_pretty = platform.platform()
    if Path("/etc/os-release").exists():
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                os_pretty = line.split("=", 1)[1].strip().strip('"')

    glibc_ver = "unknown"
    try:
        ldd_out = subprocess.check_output(["ldd", "--version"], text=True, timeout=5).splitlines()[0]
        glibc_ver = ldd_out.strip()
    except Exception:
        pass

    kerlico_ver = "unknown"
    try:
        kerlico_ver = subprocess.check_output([kerlico_bin, "--version"], text=True, timeout=5).strip()
    except Exception:
        pass

    mihomo_ver = "unknown"
    try:
        mihomo_ver = subprocess.check_output([mihomo_bin, "-v"], text=True, timeout=5).splitlines()[0].strip()
    except Exception:
        pass

    load1, load5, load15 = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return {
        "machine_alias": alias,
        "cpu_model": lscpu_map.get("Model name", model_name),
        "cpu_vendor": lscpu_map.get("Vendor ID", "unknown"),
        "cpu_cores_logical": os.cpu_count() or 1,
        "cpu_sockets": lscpu_map.get("Socket(s)", "1"),
        "cpu_cores_per_socket": lscpu_map.get("Core(s) per socket", "unknown"),
        "cpu_threads_per_core": lscpu_map.get("Thread(s) per core", "1"),
        "cpu_mhz": cpu_mhz,
        "cpu_cache_size": cache_size or lscpu_map.get("L3 cache", "unknown"),
        "cpu_crypto_simd_flags": flags,
        "mem_total_mib": round(mem_total_kb / 1024.0, 1),
        "mem_available_mib": round(mem_avail_kb / 1024.0, 1),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "os": os_pretty,
        "glibc": glibc_ver,
        "loadavg_initial": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "kerlico": {
            "version": kerlico_ver,
            "sha256": sha256_file(kerlico_bin),
            "size_bytes": Path(kerlico_bin).stat().st_size,
            "size_mib": round(Path(kerlico_bin).stat().st_size / (1024 * 1024), 2),
        },
        "mihomo": {
            "version": mihomo_ver,
            "sha256": sha256_file(mihomo_bin),
            "size_bytes": Path(mihomo_bin).stat().st_size,
            "size_mib": round(Path(mihomo_bin).stat().st_size / (1024 * 1024), 2),
        },
    }


def read_proc_snapshot(pid: int | None) -> dict[str, Any]:
    if pid is None:
        return {
            "rss_kb": 0,
            "hwm_kb": 0,
            "vsz_kb": 0,
            "pss_kb": 0,
            "private_dirty_kb": 0,
            "threads": 0,
            "fds": 0,
            "vol_cs": 0,
            "nonvol_cs": 0,
            "user_ms": 0.0,
            "sys_ms": 0.0,
            "sched_cpu_ms": 0.0,
        }
    proc = Path(f"/proc/{pid}")
    rss_kb = hwm_kb = vsz_kb = threads = vol_cs = nonvol_cs = 0
    try:
        for line in (proc / "status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
            elif line.startswith("VmHWM:"):
                hwm_kb = int(line.split()[1])
            elif line.startswith("VmSize:"):
                vsz_kb = int(line.split()[1])
            elif line.startswith("Threads:"):
                threads = int(line.split()[1])
            elif line.startswith("voluntary_ctxt_switches:"):
                vol_cs = int(line.split()[1])
            elif line.startswith("nonvoluntary_ctxt_switches:"):
                nonvol_cs = int(line.split()[1])
    except OSError:
        pass

    pss_kb = private_dirty_kb = 0
    try:
        smaps = proc / "smaps_rollup"
        if smaps.exists():
            for line in smaps.read_text().splitlines():
                if line.startswith("Pss:"):
                    pss_kb = int(line.split()[1])
                elif line.startswith("Private_Dirty:"):
                    private_dirty_kb = int(line.split()[1])
    except OSError:
        pass

    if pss_kb == 0:
        pss_kb = rss_kb

    fds = 0
    try:
        fds = sum(1 for _ in (proc / "fd").iterdir())
    except OSError:
        pass

    user_ms = sys_ms = 0.0
    try:
        stat_text = (proc / "stat").read_text()
        rparen = stat_text.rfind(")")
        fields = stat_text[rparen + 2 :].split()
        utime_ticks = int(fields[11])
        stime_ticks = int(fields[12])
        user_ms = (utime_ticks * 1000.0) / CLK_TCK
        sys_ms = (stime_ticks * 1000.0) / CLK_TCK
    except (OSError, ValueError, IndexError):
        pass

    sched_cpu_ms = 0.0
    try:
        # Sum exec_runtime across all threads in /proc/<pid>/task/*/schedstat for exact ns CPU usage
        total_ns = 0
        task_dir = proc / "task"
        if task_dir.exists():
            for tid_dir in task_dir.iterdir():
                sched_file = tid_dir / "schedstat"
                if sched_file.exists():
                    total_ns += int(sched_file.read_text().split()[0])
        else:
            sched_file = proc / "schedstat"
            if sched_file.exists():
                total_ns = int(sched_file.read_text().split()[0])
        sched_cpu_ms = total_ns / 1_000_000.0
    except (OSError, ValueError, IndexError):
        sched_cpu_ms = user_ms + sys_ms

    return {
        "rss_kb": rss_kb,
        "hwm_kb": hwm_kb,
        "vsz_kb": vsz_kb,
        "pss_kb": pss_kb,
        "private_dirty_kb": private_dirty_kb,
        "threads": threads,
        "fds": fds,
        "vol_cs": vol_cs,
        "nonvol_cs": nonvol_cs,
        "user_ms": user_ms,
        "sys_ms": sys_ms,
        "sched_cpu_ms": sched_cpu_ms if sched_cpu_ms > 0 else (user_ms + sys_ms),
    }


class FastTcpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.request.settimeout(120)
            while True:
                data = self.request.recv(262144)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass


class FastTcpEchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class FastUdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        try:
            sock.sendto(data, self.client_address)
        except OSError:
            pass


class FastUdpEchoServer(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 65535


@contextmanager
def start_echo_servers():
    tcp_srv = FastTcpEchoServer(("127.0.0.1", 0), FastTcpEchoHandler)
    udp_srv = FastUdpEchoServer(("127.0.0.1", 0), FastUdpEchoHandler)
    t1 = threading.Thread(target=tcp_srv.serve_forever, daemon=True)
    t2 = threading.Thread(target=udp_srv.serve_forever, daemon=True)
    t1.start()
    t2.start()
    try:
        yield tcp_srv.server_address[1], udp_srv.server_address[1]
    finally:
        tcp_srv.shutdown()
        udp_srv.shutdown()
        tcp_srv.server_close()
        udp_srv.server_close()


def generate_materials(root: Path, kerlico_bin: str) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    cert = root / "cert.pem"
    key = root / "key.pem"
    ca = root / "ca.pem"
    cakey = root / "ca-key.pem"
    client_cert = root / "client.pem"
    client_key = root / "client-key.pem"

    cover_names = ",".join([f"DNS:cover-{i}.invalid" for i in range(60)])
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cakey), "-out", str(ca), "-days", "2",
            "-subj", "/CN=Bench-Test-CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        check=True, capture_output=True, timeout=30,
    )
    csr = root / "server.csr"
    ext = root / "server.ext"
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost",
        ],
        check=True, capture_output=True, timeout=30,
    )
    ext.write_text(
        f"basicConstraints=critical,CA:FALSE\n"
        f"keyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:localhost,IP:127.0.0.1,{cover_names}\n"
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(csr),
            "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial",
            "-out", str(cert), "-days", "2", "-extfile", str(ext),
        ],
        check=True, capture_output=True, timeout=30,
    )
    # Client cert for mTLS
    ccsr = root / "client.csr"
    cext = root / "client.ext"
    subprocess.run(
        [
            "openssl", "req", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(client_key), "-out", str(ccsr), "-subj", "/CN=localhost",
        ],
        check=True, capture_output=True, timeout=30,
    )
    cext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n"
        "subjectAltName=DNS:localhost\n"
    )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-in", str(ccsr),
            "-CA", str(ca), "-CAkey", str(cakey), "-CAcreateserial",
            "-out", str(client_cert), "-days", "2", "-extfile", str(cext),
        ],
        check=True, capture_output=True, timeout=30,
    )
    chain = root / "server-chain.pem"
    chain.write_text(cert.read_text() + ca.read_text())

    # X25519 keypair for REALITY
    x_pem = root / "reality.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", str(x_pem)], check=True, capture_output=True)
    r_priv = subprocess.check_output(["openssl", "pkey", "-in", str(x_pem), "-outform", "DER"])[-32:]
    r_pub = subprocess.check_output(["openssl", "pkey", "-in", str(x_pem), "-pubout", "-outform", "DER"])[-32:]
    reality_priv = base64.urlsafe_b64encode(r_priv).rstrip(b"=").decode()
    reality_pub = base64.urlsafe_b64encode(r_pub).rstrip(b"=").decode()

    # WireGuard keys (standard base64)
    wg_s_pem = root / "wg_s.pem"
    wg_c_pem = root / "wg_c.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", str(wg_s_pem)], check=True, capture_output=True)
    subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", str(wg_c_pem)], check=True, capture_output=True)
    wg_s_priv = base64.b64encode(subprocess.check_output(["openssl", "pkey", "-in", str(wg_s_pem), "-outform", "DER"])[-32:]).decode()
    wg_s_pub = base64.b64encode(subprocess.check_output(["openssl", "pkey", "-in", str(wg_s_pem), "-pubout", "-outform", "DER"])[-32:]).decode()
    wg_c_priv = base64.b64encode(subprocess.check_output(["openssl", "pkey", "-in", str(wg_c_pem), "-outform", "DER"])[-32:]).decode()
    wg_c_pub = base64.b64encode(subprocess.check_output(["openssl", "pkey", "-in", str(wg_c_pem), "-pubout", "-outform", "DER"])[-32:]).decode()

    vless_dec = f"mlkem768x25519plus.native.600s.{reality_priv}"
    vless_enc = f"mlkem768x25519plus.native.1rtt.{reality_pub}"

    cert_fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    ca_fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest()

    for p in [cert, key, ca, cakey, client_cert, client_key, chain]:
        p.chmod(0o600)

    return {
        "cert": cert,
        "key": key,
        "ca": ca,
        "chain": chain,
        "client_cert": client_cert,
        "client_key": client_key,
        "cert_pem": cert.read_text(),
        "key_pem": key.read_text(),
        "ca_pem": ca.read_text(),
        "chain_pem": chain.read_text(),
        "client_cert_pem": client_cert.read_text(),
        "client_key_pem": client_key.read_text(),
        "cert_fp": cert_fp,
        "ca_fp": ca_fp,
        "reality_priv": reality_priv,
        "reality_pub": reality_pub,
        "wg_s_priv": wg_s_priv,
        "wg_s_pub": wg_s_pub,
        "wg_c_priv": wg_c_priv,
        "wg_c_pub": wg_c_pub,
        "vless_dec": vless_dec,
        "vless_enc": vless_enc,
    }


class TlsCoverHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.settimeout(5)
            tls_sock = self.server.ssl_ctx.wrap_socket(self.request, server_side=True)
            req = tls_sock.recv(4096)
            if req:
                tls_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            tls_sock.close()
        except Exception:
            pass


class TlsCoverServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextmanager
def start_tls_cover(cert: Path, key: Path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.load_cert_chain(str(cert), str(key))
    srv = TlsCoverServer(("127.0.0.1", 0), TlsCoverHandler)
    srv.ssl_ctx = ctx
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def wait_port_owned(pid: int, port: int, proto: str = "tcp", timeout: float = 8.0, log_file: Path | None = None) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status_p = Path(f"/proc/{pid}/status")
        dead = not status_p.exists()
        if not dead:
            try:
                st_txt = status_p.read_text(errors="replace")
                if "\nState:\tZ" in st_txt or "\nState:\tX" in st_txt:
                    dead = True
            except OSError:
                dead = True
        if dead:
            tail = ""
            if log_file and log_file.exists():
                tail = " | log: " + log_file.read_text(errors="replace")[-400:].strip().replace("\n", " ")
            raise RuntimeError(f"进程 {pid} 在监听端口 {port}/{proto} 就绪前退出{tail}")
        owned: set[str] = set()
        try:
            for fd in Path(f"/proc/{pid}/fd").iterdir():
                try:
                    target = os.readlink(fd)
                    if target.startswith("socket:[") and target.endswith("]"):
                        owned.add(target[8:-1])
                except OSError:
                    continue
        except OSError:
            pass
        for suffix in ("", "6"):
            net_file = Path(f"/proc/net/{proto}{suffix}")
            if not net_file.exists():
                continue
            for line in net_file.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[9] in owned:
                    local_port = int(fields[1].split(":")[-1], 16)
                    if local_port == port and (proto == "udp" or fields[3] == "0A"):
                        return
        time.sleep(0.02)
    tail = ""
    if log_file and log_file.exists():
        tail = " | log: " + log_file.read_text(errors="replace")[-400:].strip().replace("\n", " ")
    raise TimeoutError(f"进程 {pid} 监听 {port}/{proto} 超时{tail}")


@contextmanager
def managed_process(cmd: list[str], cwd: Path, label: str, extra_env: dict[str, str] | None = None):
    env = os.environ.copy()
    env["SAFE_PATHS"] = ""
    env["DISABLE_LOOPBACK_DETECTOR"] = "true"
    if extra_env:
        env.update(extra_env)
    log_path = cwd / f"{label}.log"
    with log_path.open("wb") as log_f:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            yield proc
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=2)


def tcp_roundtrip(port: int, payload: bytes, timeout: float = 10.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        mv = memoryview(payload)
        total = len(payload)
        received = bytearray(total)
        rec_mv = memoryview(received)
        send_err: list[ BaseException] = []

        def sender():
            try:
                offset = 0
                step = 65536
                while offset < total:
                    end = min(offset + step, total)
                    sock.sendall(mv[offset:end])
                    offset = end
            except BaseException as e:
                send_err.append(e)

        if total <= 65536:
            sock.sendall(mv)
            pos = 0
            while pos < total:
                n = sock.recv_into(rec_mv[pos:], total - pos)
                if n == 0:
                    raise EOFError(f"TCP echo short read {pos}/{total}")
                pos += n
        else:
            t = threading.Thread(target=sender, daemon=True)
            t.start()
            pos = 0
            while pos < total:
                n = sock.recv_into(rec_mv[pos:], min(262144, total - pos))
                if n == 0:
                    break
                pos += n
            t.join(timeout=timeout)
            if send_err:
                raise send_err[0]
            if pos != total:
                raise EOFError(f"TCP bulk short read {pos}/{total}")
        return bytes(received)


BULK_PATTERN_256K = (bytes(range(251)) * ((262144 // 251) + 1))[:262144]


def tcp_roundtrip_bulk(port: int, total: int, timeout: float = 600.0, progress_counter: list[int] | None = None) -> int:
    with socket.create_connection(("127.0.0.1", port), timeout=30.0) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(timeout)
        chunk_mv = memoryview(BULK_PATTERN_256K)
        rec_buf = bytearray(262144)
        rec_mv = memoryview(rec_buf)
        send_err: list[BaseException] = []

        init_len = min(64, total)
        first_64 = bytearray()
        if init_len > 0:
            sock.sendall(chunk_mv[:init_len])
            while len(first_64) < init_len:
                n = sock.recv_into(rec_mv, init_len - len(first_64))
                if n <= 0:
                    raise EOFError(f"TCP bulk handshake short read {len(first_64)}/{init_len}")
                first_64.extend(rec_mv[:n])
                if progress_counter is not None:
                    progress_counter[0] += n

        def sender():
            try:
                offset = init_len
                while offset < total:
                    step = min(262144, total - offset)
                    sock.sendall(chunk_mv[:step])
                    offset += step
            except BaseException as e:
                send_err.append(e)

        t = threading.Thread(target=sender, daemon=True)
        t.start()
        pos = len(first_64)
        while pos < total:
            n = sock.recv_into(rec_mv, min(262144, total - pos))
            if n == 0:
                break
            pos += n
            if progress_counter is not None:
                progress_counter[0] += n
        t.join(timeout=timeout)
        if send_err:
            raise send_err[0]
        if pos != total or bytes(first_64) != BULK_PATTERN_256K[: len(first_64)]:
            raise EOFError(f"TCP bulk short/corrupt read {pos}/{total}")
        return pos


def tcp_roundtrip_timed(port: int, duration_sec: float, streams: int = 1, label: str = "") -> tuple[int, float]:
    stop_evt = threading.Event()
    prog = [[0] for _ in range(streams)]
    socks: list[socket.socket] = []
    socks_lock = threading.Lock()
    errors: list[BaseException] = []
    ready_bar = threading.Barrier(streams + 1, timeout=30.0)

    def worker(idx: int) -> None:
        s: socket.socket | None = None
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=30.0)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(30.0)
            with socks_lock:
                socks.append(s)

            chunk_mv = memoryview(BULK_PATTERN_256K)
            rec_buf = bytearray(262144)
            rec_mv = memoryview(rec_buf)
            first_64 = bytearray()
            s.sendall(chunk_mv[:64])
            while len(first_64) < 64:
                n = s.recv_into(rec_mv, 64 - len(first_64))
                if n <= 0:
                    raise EOFError(f"TCP timed handshake short read {len(first_64)}/64")
                first_64.extend(rec_mv[:n])
            if bytes(first_64) != BULK_PATTERN_256K[:64]:
                raise RuntimeError("TCP timed echo content mismatch")

            try:
                ready_bar.wait()
            except threading.BrokenBarrierError:
                return

            def sender() -> None:
                try:
                    while not stop_evt.is_set():
                        s.sendall(chunk_mv)
                except OSError:
                    pass

            tx_t = threading.Thread(target=sender, daemon=True)
            tx_t.start()

            while not stop_evt.is_set():
                try:
                    n = s.recv_into(rec_mv, 262144)
                except OSError:
                    if stop_evt.is_set():
                        break
                    raise
                if n <= 0:
                    break
                prog[idx][0] += n
        except BaseException as e:
            if not stop_evt.is_set():
                errors.append(e)
            try:
                ready_bar.abort()
            except BaseException:
                pass
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(streams)]
    for t in threads:
        t.start()
    ready_bar.wait()
    t0 = time.perf_counter()
    last_bytes = 0
    last_t = t0
    while True:
        rem = duration_sec - (time.perf_counter() - t0)
        if rem <= 0:
            break
        if errors and sum(x[0] for x in prog) == 0:
            stop_evt.set()
            break
        step = min(5.0, rem)
        time.sleep(step)
        now = time.perf_counter()
        el = max(1e-3, now - t0)
        cur_bytes = sum(x[0] for x in prog)
        if duration_sec >= 10.0 and (now - last_t >= 4.5 or rem <= 5.0):
            done_mib = cur_bytes / (1024.0 * 1024.0)
            avg_rate = done_mib / el
            win_rate = ((cur_bytes - last_bytes) / (1024.0 * 1024.0)) / max(1e-3, now - last_t)
            tag = f"{label} " if label else ""
            print(
                f"[progress {tag}{streams}-stream] {el:.1f}/{duration_sec:.0f}s: "
                f"{done_mib:.1f} MiB (avg={avg_rate:.2f} MiB/s = {avg_rate*8.388608:.1f} Mbps | "
                f"win={win_rate:.2f} MiB/s = {win_rate*8.388608:.1f} Mbps)",
                flush=True,
            )
            last_bytes = cur_bytes
            last_t = now

    t1 = time.perf_counter()
    total_bytes = sum(x[0] for x in prog)
    stop_evt.set()
    with socks_lock:
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass
    for t in threads:
        t.join(timeout=3.0)
    if errors and total_bytes == 0:
        raise errors[0]
    if total_bytes == 0:
        raise EOFError("TCP timed transfer received 0 bytes")
    return total_bytes, max(1e-6, t1 - t0)


def run_workload(
    tcp_port: int,
    udp_port: int | None,
    client_pid: int,
    server_pid: int | None,
    bulk_mib: int = 8,
    streams: int = 8,
    udp_packets: int = 160,
    udp_size: int = 1200,
    server_snap_fn: Any = None,
    duration_sec: float = 0.0,
    label: str = "",
) -> dict[str, Any]:
    snap_server = server_snap_fn if server_snap_fn is not None else (lambda: read_proc_snapshot(server_pid))

    # 1. Idle memory snapshot before any traffic
    idle_client = read_proc_snapshot(client_pid)
    idle_server = snap_server()

    # 2. Warmup 1 connection (4 KiB)
    warm_payload = b"W" * 4096
    got = tcp_roundtrip(tcp_port, warm_payload, timeout=15.0)
    if got != warm_payload:
        raise RuntimeError("TCP 预热回写内容不匹配")

    # 3. TCP First-Byte / Handshake RTT (5 sequential probes of 64 bytes)
    probe_payload = b"P" * 64
    rtts_ms: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        res = tcp_roundtrip(tcp_port, probe_payload, timeout=10.0)
        t1 = time.perf_counter()
        if res != probe_payload:
            raise RuntimeError("TCP RTT 探针回写不匹配")
        rtts_ms.append((t1 - t0) * 1000.0)

    # 4. Snapshot CPU before TCP bulk
    pre_tcp_client = read_proc_snapshot(client_pid)
    pre_tcp_server = snap_server()
    t_tcp_start = time.perf_counter()
    bulk_timeout = max(60.0, bulk_mib * 0.5)

    if duration_sec > 0.0:
        got_1s, el_1s = tcp_roundtrip_timed(tcp_port, duration_sec, streams=1, label=label)
        single_mib = got_1s / (1024.0 * 1024.0)
        tcp_1stream_mib_s = single_mib / el_1s
        time.sleep(0.3)
        got_ms, el_ms = tcp_roundtrip_timed(tcp_port, duration_sec, streams=streams, label=label)
        total_multi_mib = got_ms / (1024.0 * 1024.0)
        tcp_8stream_mib_s = total_multi_mib / el_ms
        total_tcp_mib = single_mib + total_multi_mib
    else:
        # 4a. Single-stream TCP bulk transfer
        single_bytes = bulk_mib * 1024 * 1024
        prog_1s = [0]
        stop_prog_1s = threading.Event()
        t_1s_0 = time.perf_counter()
        if bulk_mib >= 256:
            def _log_1s():
                while not stop_prog_1s.wait(5.0):
                    el = max(1e-3, time.perf_counter() - t_1s_0)
                    done_mib = prog_1s[0] / (1024.0 * 1024.0)
                    rate = done_mib / el
                    print(f"[progress 1-stream] {done_mib:.1f}/{bulk_mib} MiB ({el:.1f}s, {rate:.2f} MiB/s = {rate*8.388608:.1f} Mbps)", flush=True)
            threading.Thread(target=_log_1s, daemon=True).start()
        try:
            got_1s = tcp_roundtrip_bulk(tcp_port, single_bytes, timeout=bulk_timeout, progress_counter=prog_1s)
        finally:
            stop_prog_1s.set()
        t_1s_1 = time.perf_counter()
        if got_1s != single_bytes:
            raise RuntimeError("TCP 单流大负载回写校验失败")
        tcp_1stream_mib_s = (single_bytes / (1024.0 * 1024.0)) / max(1e-6, t_1s_1 - t_1s_0)

        # 4b. Multi-stream (8 concurrent streams) TCP bulk transfer
        per_stream_bytes = max(262144, (bulk_mib * 1024 * 1024) // streams)
        prog_ms = [[0] for _ in range(streams)]
        stop_prog_ms = threading.Event()
        t_ms_0 = time.perf_counter()
        if bulk_mib >= 256:
            def _log_ms():
                while not stop_prog_ms.wait(5.0):
                    el = max(1e-3, time.perf_counter() - t_ms_0)
                    done_mib = sum(x[0] for x in prog_ms) / (1024.0 * 1024.0)
                    rate = done_mib / el
                    print(f"[progress {streams}-stream] {done_mib:.1f}/{bulk_mib} MiB ({el:.1f}s, {rate:.2f} MiB/s = {rate*8.388608:.1f} Mbps)", flush=True)
            threading.Thread(target=_log_ms, daemon=True).start()
        try:
            with ThreadPoolExecutor(max_workers=streams) as pool:
                futures = [pool.submit(tcp_roundtrip_bulk, tcp_port, per_stream_bytes, bulk_timeout, prog_ms[i]) for i in range(streams)]
                for fut in futures:
                    res = fut.result()
                    if res != per_stream_bytes:
                        raise RuntimeError("TCP 并发流回写长度不匹配")
        finally:
            stop_prog_ms.set()
        t_ms_1 = time.perf_counter()
        total_multi_mib = (per_stream_bytes * streams) / (1024.0 * 1024.0)
        tcp_8stream_mib_s = total_multi_mib / max(1e-6, t_ms_1 - t_ms_0)
        total_tcp_mib = (single_bytes / (1024.0 * 1024.0)) + total_multi_mib

    t_tcp_end = time.perf_counter()
    post_tcp_client = read_proc_snapshot(client_pid)
    post_tcp_server = snap_server()

    tcp_wall_ms = (t_tcp_end - t_tcp_start) * 1000.0
    c_tcp_cpu_ms = max(0.0, post_tcp_client["sched_cpu_ms"] - pre_tcp_client["sched_cpu_ms"])
    s_tcp_cpu_ms = max(0.0, post_tcp_server["sched_cpu_ms"] - pre_tcp_server["sched_cpu_ms"])
    c_tcp_user_ms = max(0.0, post_tcp_client["user_ms"] - pre_tcp_client["user_ms"])
    c_tcp_sys_ms = max(0.0, post_tcp_client["sys_ms"] - pre_tcp_client["sys_ms"])
    s_tcp_user_ms = max(0.0, post_tcp_server["user_ms"] - pre_tcp_server["user_ms"])
    s_tcp_sys_ms = max(0.0, post_tcp_server["sys_ms"] - pre_tcp_server["sys_ms"])

    # 5. UDP Latency & Throughput (if supported)
    udp_rtt_median_ms: float | None = None
    udp_mib_s: float | None = None
    udp_pps: float | None = None
    udp_loss_pct: float | None = None
    c_udp_cpu_ms = 0.0
    s_udp_cpu_ms = 0.0

    if udp_port is not None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as usock:
            usock.settimeout(4.0)
            # Warmup + 5 RTT probes
            u_rtts: list[float] = []
            for seq in range(6):
                pkt = f"ping-{seq:04d}".encode().ljust(64, b"u")
                u0 = time.perf_counter()
                usock.sendto(pkt, ("127.0.0.1", udp_port))
                reply, _ = usock.recvfrom(65535)
                u1 = time.perf_counter()
                if reply != pkt:
                    raise RuntimeError("UDP 探针回写不匹配")
                if seq > 0:
                    u_rtts.append((u1 - u0) * 1000.0)
            udp_rtt_median_ms = round(statistics.median(u_rtts), 3)

            # Burst throughput with window=16
            pre_udp_client = read_proc_snapshot(client_pid)
            pre_udp_server = snap_server()
            usock.settimeout(2.0)
            window = 16
            received_count = 0
            u_burst_0 = time.perf_counter()
            body = bytes(range(251)) * ((udp_size // 251) + 1)
            for base in range(0, udp_packets, window):
                batch = min(window, udp_packets - base)
                for idx in range(batch):
                    seq_id = base + idx
                    pkt = seq_id.to_bytes(4, "big") + body[: udp_size - 4]
                    usock.sendto(pkt, ("127.0.0.1", udp_port))
                for _ in range(batch):
                    try:
                        data, _ = usock.recvfrom(65535)
                        if len(data) == udp_size:
                            received_count += 1
                    except socket.timeout:
                        break
            u_burst_1 = time.perf_counter()
            post_udp_client = read_proc_snapshot(client_pid)
            post_udp_server = snap_server()

            u_elapsed = max(1e-6, u_burst_1 - u_burst_0)
            udp_mib_s = round((received_count * udp_size / (1024.0 * 1024.0)) / u_elapsed, 2)
            udp_pps = round(received_count / u_elapsed, 1)
            udp_loss_pct = round((udp_packets - received_count) * 100.0 / udp_packets, 2)
            c_udp_cpu_ms = max(0.0, post_udp_client["sched_cpu_ms"] - pre_udp_client["sched_cpu_ms"])
            s_udp_cpu_ms = max(0.0, post_udp_server["sched_cpu_ms"] - pre_udp_server["sched_cpu_ms"])

    # 6. Final active & peak memory snapshot
    final_client = read_proc_snapshot(client_pid)
    final_server = snap_server()

    total_cpu_ms = c_tcp_cpu_ms + s_tcp_cpu_ms + c_udp_cpu_ms + s_udp_cpu_ms
    return {
        "tcp_rtt_median_ms": round(statistics.median(rtts_ms), 3),
        "tcp_rtt_min_ms": round(min(rtts_ms), 3),
        "tcp_rtt_p95_ms": round(sorted(rtts_ms)[-1], 3),
        "tcp_1stream_mib_s": round(tcp_1stream_mib_s, 2),
        "tcp_8stream_mib_s": round(tcp_8stream_mib_s, 2),
        "udp_rtt_median_ms": udp_rtt_median_ms,
        "udp_mib_s": udp_mib_s,
        "udp_pps": udp_pps,
        "udp_loss_pct": udp_loss_pct,
        "client": {
            "idle_rss_kb": idle_client["rss_kb"],
            "active_rss_kb": final_client["rss_kb"],
            "peak_rss_kb": max(idle_client["hwm_kb"], final_client["hwm_kb"], final_client["rss_kb"]),
            "idle_pss_kb": idle_client["pss_kb"],
            "active_pss_kb": final_client["pss_kb"],
            "private_dirty_kb": final_client["private_dirty_kb"],
            "vsz_kb": final_client["vsz_kb"],
            "threads": final_client["threads"],
            "fds": final_client["fds"],
            "tcp_cpu_ms": round(c_tcp_cpu_ms, 2),
            "tcp_user_ms": round(c_tcp_user_ms, 2),
            "tcp_sys_ms": round(c_tcp_sys_ms, 2),
            "tcp_cpu_pct": round((c_tcp_cpu_ms / max(1.0, tcp_wall_ms)) * 100.0, 2),
            "udp_cpu_ms": round(c_udp_cpu_ms, 2),
            "vol_ctxt_switches": max(0, final_client["vol_cs"] - idle_client["vol_cs"]),
            "nonvol_ctxt_switches": max(0, final_client["nonvol_cs"] - idle_client["nonvol_cs"]),
        },
        "server": {
            "idle_rss_kb": idle_server["rss_kb"],
            "active_rss_kb": final_server["rss_kb"],
            "peak_rss_kb": max(idle_server["hwm_kb"], final_server["hwm_kb"], final_server["rss_kb"]),
            "idle_pss_kb": idle_server["pss_kb"],
            "active_pss_kb": final_server["pss_kb"],
            "private_dirty_kb": final_server["private_dirty_kb"],
            "vsz_kb": final_server["vsz_kb"],
            "threads": final_server["threads"],
            "fds": final_server["fds"],
            "tcp_cpu_ms": round(s_tcp_cpu_ms, 2),
            "tcp_user_ms": round(s_tcp_user_ms, 2),
            "tcp_sys_ms": round(s_tcp_sys_ms, 2),
            "tcp_cpu_pct": round((s_tcp_cpu_ms / max(1.0, tcp_wall_ms)) * 100.0, 2),
            "udp_cpu_ms": round(s_udp_cpu_ms, 2),
            "vol_ctxt_switches": max(0, final_server["vol_cs"] - idle_server["vol_cs"]),
            "nonvol_ctxt_switches": max(0, final_server["nonvol_cs"] - idle_server["nonvol_cs"]),
        },
        "combined": {
            "idle_rss_kb": idle_client["rss_kb"] + idle_server["rss_kb"],
            "peak_rss_kb": max(idle_client["hwm_kb"], final_client["hwm_kb"], final_client["rss_kb"])
            + max(idle_server["hwm_kb"], final_server["hwm_kb"], final_server["rss_kb"]),
            "active_pss_kb": final_client["pss_kb"] + final_server["pss_kb"],
            "tcp_cpu_ms": round(c_tcp_cpu_ms + s_tcp_cpu_ms, 2),
            "tcp_cpu_pct": round(((c_tcp_cpu_ms + s_tcp_cpu_ms) / max(1.0, tcp_wall_ms)) * 100.0, 2),
            "tcp_cpu_ms_per_mib": round((c_tcp_cpu_ms + s_tcp_cpu_ms) / max(0.1, total_tcp_mib), 3),
            "client_cpu_ms_per_mib": round(c_tcp_cpu_ms / max(0.1, total_tcp_mib), 3),
            "total_cpu_ms": round(total_cpu_ms, 2),
        },
    }



def kerlico_client_wrap(
    out_type: str,
    out_opts: dict[str, Any],
    tcp_port: int,
    udp_port: int | None,
    target_tcp: int,
    target_udp: int,
    target_host: str = "127.0.0.1",
) -> dict[str, Any]:
    inbounds: list[dict[str, Any]] = [
        {
            "tag": "tcp-in",
            "type": "tcp-forward",
            "listen": f"127.0.0.1:{tcp_port}",
            "target": {"host": target_host, "port": target_tcp},
            "outbound": "proxy",
        }
    ]
    if udp_port is not None:
        inbounds.append(
            {
                "tag": "udp-in",
                "type": "udp-forward",
                "listen": f"127.0.0.1:{udp_port}",
                "target": {"host": target_host, "port": target_udp},
                "outbound": "proxy",
            }
        )
    return {
        "version": 2,
        "outbounds": [{"tag": "proxy", "type": out_type, "options": out_opts}],
        "inbounds": inbounds,
        "limits": {
            "connect_timeout_ms": 8000,
            "idle_timeout_ms": 30000,
            "drain_timeout_ms": 500,
            "max_sessions": 512,
            "max_datagram_size": 65507,
        },
    }


def kerlico_server_wrap(
    node_type: str,
    node_opts: dict[str, Any],
    node_port: int,
    credentials: list[dict[str, Any]] | None,
    use_local_inbound: bool = False,
) -> dict[str, Any]:
    entry = {
        "tag": "node",
        "type": node_type,
        "listen": f"127.0.0.1:{node_port}",
        "outbound": "direct",
        "options": copy.deepcopy(node_opts),
    }
    field = "local_inbounds" if use_local_inbound else "nodes"
    cfg: dict[str, Any] = {
        "version": 2,
        "outbounds": [{"tag": "direct", "type": "direct"}],
        "inbounds": [],
        field: [entry],
        "limits": {
            "connect_timeout_ms": 8000,
            "idle_timeout_ms": 30000,
            "drain_timeout_ms": 500,
            "max_sessions": 512,
            "max_datagram_size": 65507,
        },
    }
    if not use_local_inbound and credentials is not None:
        bind_members(cfg, cfg["nodes"][0], credentials)
    return cfg


def mihomo_base() -> dict[str, Any]:
    return {
        "mode": "rule",
        "log-level": "error",
        "allow-lan": False,
        "ipv6": True,
        "geo-auto-update": False,
        "dns": {"enable": False},
        "tun": {"enable": False},
        "ntp": {"enable": False},
        "profile": {"store-selected": False},
        "port": 0,
        "socks-port": 0,
        "mixed-port": 0,
        "redir-port": 0,
        "tproxy-port": 0,
        "rules": ["MATCH,DIRECT"],
    }


def mihomo_client_wrap(
    proxy_dict: dict[str, Any],
    tcp_port: int,
    udp_port: int | None,
    target_tcp: int,
    target_udp: int,
    target_host: str = "127.0.0.1",
) -> dict[str, Any]:
    cfg = mihomo_base()
    cfg["proxies"] = [{**proxy_dict, "name": "relay"}]
    listeners: list[dict[str, Any]] = [
        {
            "name": "tcp-in",
            "type": "tunnel",
            "listen": "127.0.0.1",
            "port": str(tcp_port),
            "network": ["tcp"],
            "target": f"{target_host}:{target_tcp}",
            "proxy": "relay",
        }
    ]
    if udp_port is not None:
        listeners.append(
            {
                "name": "udp-in",
                "type": "tunnel",
                "listen": "127.0.0.1",
                "port": str(udp_port),
                "network": ["udp"],
                "target": f"{target_host}:{target_udp}",
                "proxy": "relay",
            }
        )
    cfg["listeners"] = listeners
    return add_probe(cfg, allocate_port())


def mihomo_server_wrap(
    listener_dict: dict[str, Any] | None = None,
    top_level: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cfg = mihomo_base()
    cfg["listeners"] = [listener_dict] if listener_dict else []
    if top_level:
        cfg.update(top_level)
    return add_probe(cfg, allocate_port())


def build_protocol_cases(m: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    ss_key16 = base64.b64encode(b"0123456789abcdef").decode()
    ss_key32 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    ss_id32 = base64.b64encode(b"fedcba9876543210fedcba9876543210").decode()

    # 1. SOCKS5 (noauth, auth)
    for combo, auth_on, tls_on in [
        ("socks5-noauth", False, False),
        ("socks5-auth", True, False),
    ]:
        def make_socks(auth_on=auth_on, tls_on=tls_on):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                k_s_opts: dict[str, Any] = {"version": "5"}
                k_c_opts: dict[str, Any] = {"version": "5", "server": {"host": "127.0.0.1", "port": np}}
                m_l: dict[str, Any] = {"name": "node", "type": "socks", "listen": "127.0.0.1", "port": np, "udp": True}
                m_p: dict[str, Any] = {"type": "socks5", "server": "127.0.0.1", "port": np, "udp": True}
                creds = None
                if auth_on:
                    creds = [{"username": USER_NAME, "password": USER_PASSWORD}]
                    k_c_opts["auth"] = {"username": USER_NAME, "password": USER_PASSWORD}
                    m_l["users"] = [{"username": USER_NAME, "password": USER_PASSWORD}]
                    m_p.update(username=USER_NAME, password=USER_PASSWORD)
                if tls_on:
                    k_s_opts["tls"] = {"cert_pem": m["chain_pem"], "key_pem": m["key_pem"]}
                    k_c_opts["tls"] = {"server_name": "localhost", "ca_pem": m["ca_pem"]}
                    m_l.update({"certificate": m["chain_pem"], "private-key": m["key_pem"]})
                    m_p.update({"tls": True, "sni": "localhost", "fingerprint": m["cert_fp"], "skip-cert-verify": True})
                return {
                    "k_server": kerlico_server_wrap("socks", k_s_opts, np, creds, use_local_inbound=not auth_on),
                    "k_client": kerlico_client_wrap("socks", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "socks",
            "combination": combo,
            "mode": "dual_end",
            "udp": not tls_on,
            "proto_listen": "tcp",
            "build": make_socks(),
        })

    # 2. HTTP / HTTPS (plain, auth, tls+auth)
    for combo, auth_on, tls_on in [
        ("http-plain", False, False),
        ("http-auth", True, False),
        ("https-tls", True, True),
    ]:
        def make_http(auth_on=auth_on, tls_on=tls_on):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                k_s_opts: dict[str, Any] = {}
                k_c_opts: dict[str, Any] = {"server": {"host": "127.0.0.1", "port": np}}
                m_l: dict[str, Any] = {"name": "node", "type": "http", "listen": "127.0.0.1", "port": np}
                m_p: dict[str, Any] = {"type": "http", "server": "127.0.0.1", "port": np}
                creds = None
                if auth_on:
                    creds = [{"username": USER_NAME, "password": USER_PASSWORD}]
                    k_c_opts["auth"] = {"username": USER_NAME, "password": USER_PASSWORD}
                    m_l["users"] = [{"username": USER_NAME, "password": USER_PASSWORD}]
                    m_p.update(username=USER_NAME, password=USER_PASSWORD)
                if tls_on:
                    k_s_opts["tls"] = {"cert_pem": m["chain_pem"], "key_pem": m["key_pem"]}
                    k_c_opts["tls"] = {"server_name": "localhost", "ca_pem": m["ca_pem"]}
                    m_l.update({"certificate": m["chain_pem"], "private-key": m["key_pem"]})
                    m_p.update({"tls": True, "sni": "localhost", "fingerprint": m["cert_fp"], "skip-cert-verify": True})
                return {
                    "k_server": kerlico_server_wrap("http", k_s_opts, np, creds, use_local_inbound=not auth_on),
                    "k_client": kerlico_client_wrap("http", k_c_opts, tp, None, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, None, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "http",
            "combination": combo,
            "mode": "dual_end",
            "udp": False,
            "proto_listen": "tcp",
            "build": make_http(),
        })

    # 3. Shadowsocks (AEAD + none + mux variants)
    for combo, method, mux_proto in [
        ("aes-128-gcm", "aes-128-gcm", None),
        ("aes-256-gcm", "aes-256-gcm", None),
        ("chacha20-ietf-poly1305", "chacha20-ietf-poly1305", None),
        ("none", "none", None),
        ("aes-128-gcm-smux", "aes-128-gcm", "smux"),
        ("aes-128-gcm-yamux", "aes-128-gcm", "yamux"),
        ("aes-128-gcm-h2mux", "aes-128-gcm", "h2mux"),
    ]:
        def make_ss(method=method, mux_proto=mux_proto):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                is_none = method == "none"
                k_s_opts: dict[str, Any] = {"method": method, "allow_insecure": True}
                if is_none:
                    k_s_opts["password"] = ""
                k_c_opts: dict[str, Any] = {
                    "server": "127.0.0.1",
                    "port": np,
                    "method": method,
                    "password": "" if is_none else USER_PASSWORD,
                    "allow_insecure": True,
                }
                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "shadowsocks",
                    "listen": "127.0.0.1",
                    "port": np,
                    "cipher": "none" if is_none else method,
                    "password": "" if is_none else USER_PASSWORD,
                    "udp": True,
                }
                m_p: dict[str, Any] = {
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": np,
                    "cipher": "none" if is_none else method,
                    "password": "" if is_none else USER_PASSWORD,
                    "udp": True,
                }
                if mux_proto:
                    k_s_opts["multiplex"] = {"enabled": True, "padding": False}
                    k_c_opts["multiplex"] = {"enabled": True, "protocol": mux_proto, "max_connections": 2, "min_streams": 4}
                    m_p["smux"] = {"enabled": True, "protocol": mux_proto, "max-connections": 2, "min-streams": 4}
                return {
                    "k_server": kerlico_server_wrap(
                        "shadowsocks",
                        k_s_opts,
                        np,
                        None if is_none else [{"password": USER_PASSWORD}],
                        use_local_inbound=is_none,
                    ),
                    "k_client": kerlico_client_wrap("shadowsocks", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "shadowsocks",
            "combination": combo,
            "mode": "dual_end",
            "udp": mux_proto is None,
            "proto_listen": "tcp",
            "build": make_ss(),
        })

    # 4. SS2022
    for combo, method, key_val, eih in [
        ("2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm", ss_key16, False),
        ("2022-blake3-aes-256-gcm", "2022-blake3-aes-256-gcm", ss_key32, False),
        ("2022-blake3-chacha20-poly1305", "2022-blake3-chacha20-poly1305", ss_key32, False),
        ("2022-blake3-aes-256-gcm-eih", "2022-blake3-aes-256-gcm", ss_key32, True),
    ]:
        def make_ss2022(method=method, key_val=key_val, eih=eih):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                k_s_opts: dict[str, Any] = {"method": method}
                k_c_opts: dict[str, Any] = {
                    "server": "127.0.0.1",
                    "port": np,
                    "method": method,
                    "key": key_val,
                    "identity_keys": [ss_id32] if eih else [],
                }
                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "shadowsocks",
                    "listen": "127.0.0.1",
                    "port": np,
                    "cipher": method,
                    "password": f"{ss_id32}:{key_val}" if eih else key_val,
                    "udp": True,
                }
                m_p: dict[str, Any] = {
                    "type": "ss",
                    "server": "127.0.0.1",
                    "port": np,
                    "cipher": method,
                    "password": f"{ss_id32}:{key_val}" if eih else key_val,
                    "udp": True,
                }
                if eih:
                    k_s_opts["identity_key"] = ss_id32
                return {
                    "k_server": kerlico_server_wrap("ss2022", k_s_opts, np, [{"key": key_val}]),
                    "k_client": kerlico_client_wrap("ss2022", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": None if eih else mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "ss2022",
            "combination": combo,
            "mode": "client_vs_kserver" if eih else "dual_end",
            "udp": True,
            "proto_listen": "tcp",
            "build": make_ss2022(),
        })

    # 5. Trojan (tcp-tls, ws-tls, httpupgrade-tls, grpc-tls, tcp-tls-smux)
    for combo, tr_type, sec_type, mux_proto in [
        ("tcp-tls", "tcp", "tls", None),
        ("ws-tls", "ws", "tls", None),
        ("httpupgrade-tls", "httpupgrade", "tls", None),
        ("grpc-tls", "grpc", "tls", None),
        ("tcp-tls-smux", "tcp", "tls", "smux"),
    ]:
        def make_trojan(tr_type=tr_type, sec_type=sec_type, mux_proto=mux_proto):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                if tr_type == "tcp":
                    k_tr_s, k_tr_c = {"type": "tcp"}, {"type": "tcp"}
                elif tr_type == "ws":
                    k_tr_s, k_tr_c = {"type": "ws", "path": "/bench"}, {"type": "ws", "path": "/bench", "host": "localhost"}
                elif tr_type == "httpupgrade":
                    k_tr_s, k_tr_c = {"type": "httpupgrade", "path": "/bench"}, {"type": "httpupgrade", "path": "/bench", "host": "localhost"}
                else:
                    k_tr_s, k_tr_c = {"type": "grpc", "service_name": "bench"}, {"type": "grpc", "service_name": "bench", "authority": "localhost"}
                k_sec_s = {"type": "tls", "certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"]}
                k_sec_c = {"type": "tls", "server_name": "localhost", "ca_pem": m["ca_pem"]}
                k_s_opts: dict[str, Any] = {"security": k_sec_s, "transport": k_tr_s}
                k_c_opts: dict[str, Any] = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "password": USER_PASSWORD,
                    "security": k_sec_c,
                    "transport": k_tr_c,
                }
                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "trojan",
                    "listen": "127.0.0.1",
                    "port": np,
                    "users": [{"username": USER_NAME, "password": USER_PASSWORD}],
                    "udp": True,
                    "certificate": m["chain_pem"],
                    "private-key": m["key_pem"],
                }
                m_p: dict[str, Any] = {
                    "type": "trojan",
                    "server": "127.0.0.1",
                    "port": np,
                    "password": USER_PASSWORD,
                    "sni": "localhost",
                    "udp": True,
                    "skip-cert-verify": True,
                    "fingerprint": m["cert_fp"],
                }
                if tr_type == "ws":
                    m_l["ws-path"] = "/bench"
                    m_p.update({"network": "ws", "ws-opts": {"path": "/bench", "headers": {"Host": "localhost"}}})
                elif tr_type == "httpupgrade":
                    m_l["ws-path"] = "/bench"
                    m_p.update({"network": "ws", "ws-opts": {"path": "/bench", "headers": {"Host": "localhost"}, "v2ray-http-upgrade": True}})
                elif tr_type == "grpc":
                    m_l["grpc-service-name"] = "bench"
                    m_p.update({"network": "grpc", "grpc-opts": {"grpc-service-name": "bench"}})
                if mux_proto:
                    k_s_opts["multiplex"] = {"enabled": True, "padding": False}
                    k_c_opts["multiplex"] = {"enabled": True, "protocol": mux_proto, "max_connections": 2, "min_streams": 4}
                    m_p["smux"] = {"enabled": True, "protocol": mux_proto, "max-connections": 2, "min-streams": 4}
                return {
                    "k_server": kerlico_server_wrap("trojan", k_s_opts, np, [{"password": USER_PASSWORD}]),
                    "k_client": kerlico_client_wrap("trojan", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "trojan",
            "combination": combo,
            "mode": "dual_end",
            "udp": mux_proto is None and tr_type != "grpc",
            "needs_cover": False,
            "proto_listen": "tcp",
            "build": make_trojan(),
        })

    # 6. VMess
    for combo, tr_type, tls_on, cipher, mux_proto in [
        ("tcp-none-aes128gcm", "tcp", False, "aes-128-gcm", None),
        ("tcp-none-chacha20", "tcp", False, "chacha20-poly1305", None),
        ("tcp-none-zero", "tcp", False, "zero", None),
        ("tcp-tls-aes128gcm", "tcp", True, "aes-128-gcm", None),
        ("ws-none", "ws", False, "aes-128-gcm", None),
        ("ws-tls", "ws", True, "aes-128-gcm", None),
        ("httpupgrade-tls", "httpupgrade", True, "aes-128-gcm", None),
        ("grpc-tls", "grpc", True, "aes-128-gcm", None),
        ("tcp-tls-smux", "tcp", True, "aes-128-gcm", "smux"),
    ]:
        def make_vmess(tr_type=tr_type, tls_on=tls_on, cipher=cipher, mux_proto=mux_proto):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                if tr_type == "tcp":
                    k_tr_s, k_tr_c = {"type": "tcp"}, {"type": "tcp"}
                elif tr_type == "ws":
                    k_tr_s, k_tr_c = {"type": "ws", "path": "/bench"}, {"type": "ws", "path": "/bench", "host": "localhost"}
                elif tr_type == "httpupgrade":
                    k_tr_s, k_tr_c = {"type": "httpupgrade", "path": "/bench"}, {"type": "httpupgrade", "path": "/bench", "host": "localhost"}
                elif tr_type == "h2":
                    k_tr_s, k_tr_c = {"type": "h2", "path": "/bench"}, {"type": "h2", "path": "/bench", "host": "localhost"}
                else:
                    k_tr_s, k_tr_c = {"type": "grpc", "service_name": "bench"}, {"type": "grpc", "service_name": "bench", "authority": "localhost"}

                k_sec_s = {"type": "tls", "certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"]} if tls_on else {"type": "none"}
                k_sec_c = {"type": "tls", "server_name": "localhost", "ca_pem": m["ca_pem"]} if tls_on else {"type": "none"}

                k_s_opts: dict[str, Any] = {"security": k_sec_s, "transport": k_tr_s}
                k_c_opts: dict[str, Any] = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "uuid": USER_UUID,
                    "security": cipher,
                    "tls": k_sec_c,
                    "transport": k_tr_c,
                }
                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "vmess",
                    "listen": "127.0.0.1",
                    "port": np,
                    "users": [{"username": USER_NAME, "uuid": USER_UUID, "alterId": 0}],
                    "udp": True,
                }
                m_p: dict[str, Any] = {
                    "type": "vmess",
                    "server": "127.0.0.1",
                    "port": np,
                    "uuid": USER_UUID,
                    "alterId": 0,
                    "cipher": cipher,
                    "udp": True,
                }
                if tls_on:
                    m_l.update({"certificate": m["chain_pem"], "private-key": m["key_pem"]})
                    m_p.update({"tls": True, "servername": "localhost", "fingerprint": m["cert_fp"], "skip-cert-verify": True})
                if tr_type == "ws":
                    m_l["ws-path"] = "/bench"
                    m_p.update({"network": "ws", "ws-opts": {"path": "/bench", "headers": {"Host": "localhost"}}})
                elif tr_type == "httpupgrade":
                    m_l["ws-path"] = "/bench"
                    m_p.update({"network": "ws", "ws-opts": {"path": "/bench", "headers": {"Host": "localhost"}, "v2ray-http-upgrade": True}})
                elif tr_type == "h2":
                    m_p.update({"network": "h2", "h2-opts": {"path": "/bench", "host": ["localhost"]}})
                elif tr_type == "grpc":
                    m_l["grpc-service-name"] = "bench"
                    m_p.update({"network": "grpc", "grpc-opts": {"grpc-service-name": "bench"}})
                if mux_proto:
                    k_s_opts["multiplex"] = {"enabled": True, "padding": False}
                    k_c_opts["multiplex"] = {"enabled": True, "protocol": mux_proto, "max_connections": 2, "min_streams": 4}
                    m_p["smux"] = {"enabled": True, "protocol": mux_proto, "max-connections": 2, "min-streams": 4}
                return {
                    "k_server": kerlico_server_wrap("vmess", k_s_opts, np, [{"uuid": USER_UUID}]),
                    "k_client": kerlico_client_wrap("vmess", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": None if tr_type == "h2" else mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "vmess",
            "combination": combo,
            "mode": "client_vs_kserver" if tr_type == "h2" else "dual_end",
            "udp": mux_proto is None and tr_type not in ("grpc", "h2"),
            "proto_listen": "tcp",
            "build": make_vmess(),
        })

    # 7. VLESS
    vless_specs = [
        ("tcp-tls", "tcp", "tls", "", None, False, None),
        ("tcp-tls-vision", "tcp", "tls", "xtls-rprx-vision", None, False, None),
        ("tcp-tls-xudp", "tcp", "tls", "", "xudp", False, None),
        ("tcp-reality", "tcp", "reality", "", None, False, None),
        ("tcp-reality-vision", "tcp", "reality", "xtls-rprx-vision", None, False, None),
        ("tcp-encryption-mlkem768", "tcp", "none", "", None, True, None),
        ("ws-tls", "ws", "tls", "", None, False, None),
        ("httpupgrade-tls", "httpupgrade", "tls", "", None, False, None),
        ("grpc-tls", "grpc", "tls", "", None, False, None),
        ("xhttp-h2-tls", "xhttp-h2", "tls", "", None, False, None),
        ("xhttp-h3-tls", "xhttp-h3", "tls", "", None, False, None),
        ("tcp-tls-smux", "tcp", "tls", "", None, False, "smux"),
    ]

    for combo, tr_type, sec_type, flow, pkt_enc, enc_on, mux_proto in vless_specs:
        def make_vless(tr_type=tr_type, sec_type=sec_type, flow=flow, pkt_enc=pkt_enc, enc_on=enc_on, mux_proto=mux_proto):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                if tr_type == "tcp":
                    k_tr_s, k_tr_c = {"type": "tcp"}, {"type": "tcp"}
                elif tr_type == "ws":
                    k_tr_s, k_tr_c = {"type": "ws", "path": "/bench"}, {"type": "ws", "path": "/bench", "host": "localhost"}
                elif tr_type == "httpupgrade":
                    k_tr_s, k_tr_c = {"type": "httpupgrade", "path": "/bench"}, {"type": "httpupgrade", "path": "/bench", "host": "localhost"}
                elif tr_type == "grpc":
                    k_tr_s, k_tr_c = {"type": "grpc", "service_name": "bench"}, {"type": "grpc", "service_name": "bench", "authority": "localhost"}
                elif tr_type == "xhttp-h2":
                    k_tr_s = {"type": "xhttp", "settings": {"path": "/bench", "mode": "stream-up", "http_version": "h2"}}
                    k_tr_c = {"type": "xhttp", "settings": {"path": "/bench", "mode": "stream-up", "http_version": "h2", "host": "localhost"}}
                else:
                    k_tr_s = {"type": "xhttp", "settings": {"path": "/bench", "mode": "stream-one", "http_version": "h3"}}
                    k_tr_c = {"type": "xhttp", "settings": {"path": "/bench", "mode": "stream-one", "http_version": "h3", "host": "localhost"}}

                if sec_type == "tls":
                    alpn = ["h3"] if tr_type == "xhttp-h3" else (["h2"] if tr_type in ("grpc", "xhttp-h2") else ["h2", "http/1.1"])
                    k_sec_s = {"type": "tls", "certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"]}
                    k_sec_c = {"type": "tls", "server_name": "localhost", "ca_pem": m["ca_pem"], "alpn": alpn}
                elif sec_type == "reality":
                    k_sec_s = {
                        "type": "reality",
                        "cover": {"host": "127.0.0.1", "port": cover_port},
                        "private_key": m["reality_priv"],
                        "server_names": ["localhost"],
                        "short_ids": ["01020304"],
                    }
                    k_sec_c = {
                        "type": "reality",
                        "server_name": "localhost",
                        "public_key": m["reality_pub"],
                        "short_id": "01020304",
                    }
                else:
                    k_sec_s = {"type": "none"}
                    k_sec_c = {"type": "none"}

                k_s_opts: dict[str, Any] = {"security": k_sec_s, "transport": k_tr_s}
                k_c_opts: dict[str, Any] = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "uuid": USER_UUID,
                    "flow": flow,
                    "security": k_sec_c,
                    "transport": k_tr_c,
                }
                if pkt_enc:
                    k_c_opts["packet_encoding"] = pkt_enc
                if enc_on:
                    k_s_opts["decryption"] = m["vless_dec"]
                    k_c_opts["encryption"] = m["vless_enc"]

                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "vless",
                    "listen": "127.0.0.1",
                    "port": np,
                    "users": [{"username": USER_NAME, "uuid": USER_UUID, "flow": flow}],
                    "udp": True,
                }
                m_p: dict[str, Any] = {
                    "type": "vless",
                    "server": "127.0.0.1",
                    "port": np,
                    "uuid": USER_UUID,
                    "flow": flow,
                    "udp": True,
                }
                if pkt_enc:
                    m_p["packet-encoding"] = pkt_enc
                if enc_on:
                    m_l["decryption"] = m["vless_dec"]
                    m_p["encryption"] = m["vless_enc"]
                if sec_type == "tls":
                    m_l.update({"certificate": m["chain_pem"], "private-key": m["key_pem"]})
                    m_p.update({"tls": True, "servername": "localhost", "fingerprint": m["cert_fp"], "skip-cert-verify": True})
                    if tr_type == "xhttp-h3":
                        m_p["alpn"] = ["h3"]
                    elif tr_type in ("grpc", "h2", "xhttp-h2"):
                        m_p["alpn"] = ["h2"]
                elif sec_type == "reality":
                    m_l["reality-config"] = {
                        "dest": f"127.0.0.1:{cover_port}",
                        "private-key": m["reality_priv"],
                        "server-names": ["localhost"],
                        "short-id": ["01020304"],
                    }
                    m_p.update({
                        "tls": True,
                        "servername": "localhost",
                        "client-fingerprint": "chrome",
                        "reality-opts": {"public-key": m["reality_pub"], "short-id": "01020304"},
                    })
                if tr_type == "ws":
                    m_l["ws-path"] = "/bench"
                    m_p.update({"network": "ws", "ws-opts": {"path": "/bench", "headers": {"Host": "localhost"}}})
                elif tr_type == "httpupgrade":
                    m_l["ws-path"] = "/bench"
                    m_p.update({"network": "ws", "ws-opts": {"path": "/bench", "headers": {"Host": "localhost"}, "v2ray-http-upgrade": True}})
                elif tr_type == "h2":
                    m_p.update({"network": "h2", "h2-opts": {"path": "/bench", "host": ["localhost"]}})
                elif tr_type == "grpc":
                    m_l["grpc-service-name"] = "bench"
                    m_p.update({"network": "grpc", "grpc-opts": {"grpc-service-name": "bench"}})
                elif tr_type in ("xhttp-h2", "xhttp-h3"):
                    mode_val = "stream-up" if tr_type == "xhttp-h2" else "stream-one"
                    m_l["xhttp-config"] = {"path": "/bench", "mode": mode_val, "host": "localhost"}
                    m_p.update({"network": "xhttp", "xhttp-opts": {"path": "/bench", "mode": mode_val, "host": "localhost"}})
                if mux_proto:
                    k_s_opts["multiplex"] = {"enabled": True, "padding": False}
                    k_c_opts["multiplex"] = {"enabled": True, "protocol": mux_proto, "max_connections": 2, "min_streams": 4}
                    m_p["smux"] = {"enabled": True, "protocol": mux_proto, "max-connections": 2, "min-streams": 4}

                client_only = tr_type in ("h2", "xhttp-h2", "xhttp-h3")
                return {
                    "k_server": kerlico_server_wrap("vless", k_s_opts, np, [{"uuid": USER_UUID, "flow": flow}]),
                    "k_client": kerlico_client_wrap("vless", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": None if client_only else mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "vless",
            "combination": combo,
            "mode": "client_vs_kserver" if tr_type in ("h2", "xhttp-h2", "xhttp-h3") else "dual_end",
            "udp": mux_proto is None and tr_type not in ("grpc", "h2", "xhttp-h2", "xhttp-h3"),
            "needs_cover": sec_type == "reality",
            "proto_listen": "udp" if tr_type == "xhttp-h3" else "tcp",
            "build": make_vless(),
        })

    # 8. AnyTLS
    def make_anytls():
        def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
            k_s_opts = {"tls": {"certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"]}}
            k_c_opts = {
                "server": {"host": "127.0.0.1", "port": np},
                "password": USER_PASSWORD,
                "tls": {"server_name": "localhost", "ca_pem": m["ca_pem"]},
            }
            m_l = {
                "name": "node",
                "type": "anytls",
                "listen": "127.0.0.1",
                "port": np,
                "users": {USER_NAME: USER_PASSWORD},
                "certificate": m["chain_pem"],
                "private-key": m["key_pem"],
            }
            m_p = {
                "type": "anytls",
                "server": "127.0.0.1",
                "port": np,
                "password": USER_PASSWORD,
                "sni": "localhost",
                "fingerprint": m["cert_fp"],
                "skip-cert-verify": True,
                "udp": True,
            }
            return {
                "k_server": kerlico_server_wrap("anytls", k_s_opts, np, [{"password": USER_PASSWORD}]),
                "k_client": kerlico_client_wrap("anytls", k_c_opts, tp, up, t_tcp, t_udp),
                "m_server": mihomo_server_wrap(m_l),
                "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
            }
        return builder
    cases.append({
        "protocol": "anytls",
        "combination": "tls-uot",
        "mode": "dual_end",
        "udp": True,
        "proto_listen": "tcp",
        "build": make_anytls(),
    })

    # 9. Hysteria2 (quic, salamander)
    for combo, salamander in [("quic", False), ("salamander", True)]:
        def make_hy2(salamander=salamander):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                obfs_pw = "bench-salamander-secret" if salamander else None
                k_s_opts: dict[str, Any] = {
                    "tls": {"certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"]},
                    "udp": True,
                }
                k_c_opts: dict[str, Any] = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "auth": USER_PASSWORD,
                    "tls": {"server_name": "localhost", "ca_pem": m["ca_pem"]},
                }
                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "hysteria2",
                    "listen": "127.0.0.1",
                    "port": np,
                    "users": {USER_NAME: USER_PASSWORD},
                    "certificate": m["chain_pem"],
                    "private-key": m["key_pem"],
                }
                m_p: dict[str, Any] = {
                    "type": "hysteria2",
                    "server": "127.0.0.1",
                    "port": np,
                    "password": USER_PASSWORD,
                    "sni": "localhost",
                    "fingerprint": m["cert_fp"],
                    "skip-cert-verify": True,
                    "udp": True,
                }
                if obfs_pw:
                    k_s_opts["salamander_password"] = obfs_pw
                    k_c_opts["salamander_password"] = obfs_pw
                    m_l["obfs"] = "salamander"
                    m_l["obfs-password"] = obfs_pw
                    m_p["obfs"] = "salamander"
                    m_p["obfs-password"] = obfs_pw
                return {
                    "k_server": kerlico_server_wrap("hysteria2", k_s_opts, np, [{"auth": USER_PASSWORD}]),
                    "k_client": kerlico_client_wrap("hysteria2", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "hysteria2",
            "combination": combo,
            "mode": "dual_end",
            "udp": True,
            "proto_listen": "udp",
            "build": make_hy2(),
        })

    # 10. TUIC (v5-native, v5-quic, v4-native, v4-quic)
    for combo, ver, relay_mode in [
        ("v5-native", 5, "native"),
        ("v5-quic", 5, "quic"),
        ("v4-native", 4, "native"),
        ("v4-quic", 4, "quic"),
    ]:
        def make_tuic(ver=ver, relay_mode=relay_mode):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                cred = {"uuid": USER_UUID, "password": USER_PASSWORD} if ver == 5 else {"token": USER_PASSWORD}
                k_s_opts = {
                    "version": ver,
                    "tls": {"certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"], "alpn": ["h3"]},
                    "congestion_control": "cubic",
                }
                k_c_opts = {
                    "version": ver,
                    "server": {"host": "127.0.0.1", "port": np},
                    "tls": {"server_name": "localhost", "ca_pem": m["ca_pem"], "alpn": ["h3"]},
                    "udp_relay_mode": relay_mode,
                    "congestion_control": "cubic",
                    **cred,
                }
                m_srv: dict[str, Any] = {
                    "enable": True,
                    "listen": f"127.0.0.1:{np}",
                    "certificate": m["chain_pem"],
                    "private-key": m["key_pem"],
                    "congestion-controller": "cubic",
                    "authentication-timeout": 4000,
                    "alpn": ["h3"],
                }
                if ver == 5:
                    m_srv["users"] = {USER_UUID: USER_PASSWORD}
                else:
                    m_srv["token"] = [USER_PASSWORD]
                m_p = {
                    "type": "tuic",
                    "server": "127.0.0.1",
                    "port": np,
                    "sni": "localhost",
                    "fingerprint": m["cert_fp"],
                    "skip-cert-verify": True,
                    "udp-relay-mode": relay_mode,
                    "congestion-controller": "cubic",
                    "alpn": ["h3"],
                    "udp": True,
                    **cred,
                }
                return {
                    "k_server": kerlico_server_wrap("tuic", k_s_opts, np, [cred]),
                    "k_client": kerlico_client_wrap("tuic", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(None, top_level={"tuic-server": m_srv}),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "tuic",
            "combination": combo,
            "mode": "dual_end",
            "udp": True,
            "proto_listen": "udp",
            "build": make_tuic(),
        })

    # 11. TrustTunnel (h2-tls, h3-quic, h2-mtls)
    for combo, tr, mtls in [
        ("h2-tls", "h2", False),
        ("h3-quic", "h3", False),
        ("h2-mtls", "h2", True),
    ]:
        def make_tt(tr=tr, mtls=mtls):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                k_tls_s: dict[str, Any] = {"certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"]}
                k_tls_c: dict[str, Any] = {"server_name": "localhost", "ca_pem": m["ca_pem"]}
                if mtls:
                    k_tls_s["client_ca_pem"] = m["ca_pem"]
                    k_tls_c["certificate_pem"] = m["client_cert_pem"]
                    k_tls_c["private_key_pem"] = m["client_key_pem"]
                k_s_opts = {"transport": tr, "tls": k_tls_s}
                k_c_opts = {
                    "transport": tr,
                    "server": {"host": "127.0.0.1", "port": np},
                    "auth": {"username": USER_NAME, "password": USER_PASSWORD},
                    "tls": k_tls_c,
                    "app_name": "bench",
                }
                m_l: dict[str, Any] = {
                    "name": "node",
                    "type": "trusttunnel",
                    "listen": "127.0.0.1",
                    "port": str(np),
                    "users": [{"username": USER_NAME, "password": USER_PASSWORD}],
                    "certificate": m["chain_pem"],
                    "private-key": m["key_pem"],
                    "network": ["udp" if tr == "h3" else "tcp"],
                }
                if mtls:
                    m_l["client-auth-cert"] = m["ca_pem"]
                m_p: dict[str, Any] = {
                    "type": "trusttunnel",
                    "server": "127.0.0.1",
                    "port": np,
                    "username": USER_NAME,
                    "password": USER_PASSWORD,
                    "sni": "localhost",
                    "fingerprint": m["ca_fp"],
                    "skip-cert-verify": True,
                    "udp": True,
                    "quic": tr == "h3",
                }
                if mtls:
                    m_p["certificate"] = m["client_cert_pem"]
                    m_p["private-key"] = m["client_key_pem"]
                return {
                    "k_server": kerlico_server_wrap("trusttunnel", k_s_opts, np, [{"username": USER_NAME, "password": USER_PASSWORD}]),
                    "k_client": kerlico_client_wrap("trusttunnel", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "trusttunnel",
            "combination": combo,
            "mode": "dual_end",
            "udp": True,
            "proto_listen": "udp" if tr == "h3" else "tcp",
            "build": make_tt(),
        })

    # 12. Mieru (tcp-mux, tcp-nomux, udp-mux)
    for combo, tr, mux_on in [
        ("tcp-mux", "tcp", True),
        ("tcp-nomux", "tcp", False),
        ("udp-mux", "udp", True),
    ]:
        def make_mieru(tr=tr, mux_on=mux_on):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                traffic = {"low_entropy_mode": 0, "mask_rotation": 0, "max_padding": 32}
                k_s_opts = {
                    "transport": tr,
                    "unsafe_udp_compatibility": tr == "udp",
                    "allow_insecure": True,
                    "traffic": traffic,
                }
                if tr == "udp":
                    k_s_opts.update(username=USER_NAME, password=USER_PASSWORD)
                k_c_opts = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "username": USER_NAME,
                    "password": USER_PASSWORD,
                    "transport": tr,
                    "unsafe_udp_compatibility": tr == "udp",
                    "allow_insecure": True,
                    "multiplexing": mux_on,
                    "traffic": traffic,
                }
                m_l = {
                    "name": "node",
                    "type": "mieru",
                    "listen": "127.0.0.1",
                    "port": str(np),
                    "transport": tr.upper(),
                    "users": {USER_NAME: USER_PASSWORD},
                }
                m_p = {
                    "type": "mieru",
                    "server": "127.0.0.1",
                    "port": np,
                    "transport": tr.upper(),
                    "username": USER_NAME,
                    "password": USER_PASSWORD,
                    "udp": True,
                    "multiplexing": "MULTIPLEXING_HIGH" if mux_on else "MULTIPLEXING_OFF",
                }
                return {
                    "k_server": kerlico_server_wrap(
                        "mieru",
                        k_s_opts,
                        np,
                        None if tr == "udp" else [{"username": USER_NAME, "password": USER_PASSWORD}],
                        use_local_inbound=(tr == "udp"),
                    ),
                    "k_client": kerlico_client_wrap("mieru", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "mieru",
            "combination": combo,
            "mode": "dual_end",
            "udp": True,
            "proto_listen": tr,
            "build": make_mieru(),
        })

    # 13. Sudoku (raw, legacy, stream, poll, ws, raw-mux)
    for combo, mode_name, mux_val in [
        ("raw", "raw", "off"),
        ("legacy", "legacy", "off"),
        ("stream", "stream", "off"),
        ("poll", "poll", "off"),
        ("ws", "ws", "off"),
        ("raw-mux", "raw", "on"),
    ]:
        def make_sudoku(mode_name=mode_name, mux_val=mux_val):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                is_raw = mode_name == "raw"
                m_mode = "legacy" if is_raw else mode_name
                path_root = "sudoku-bench" if m_mode in ("stream", "poll", "ws") else ""
                proto_dict = {
                    "aead": "chacha20-poly1305",
                    "table_type": "prefer_entropy",
                    "padding_min": 5,
                    "padding_max": 15,
                    "pure_downlink": True,
                    "custom_tables": [],
                    "udp_enabled": True,
                }
                mask_s: dict[str, Any] = {"mode": mode_name}
                mask_c: dict[str, Any] = {"mode": mode_name}
                if path_root:
                    mask_s["path_root"] = path_root
                    mask_c["path_root"] = path_root
                k_s_opts = {"protocol": proto_dict, "http_mask": mask_s}
                k_c_opts = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "protocol": {**proto_dict, "key": SUDOKU_KEY},
                    "http_mask": mask_c,
                    "multiplex": mux_val,
                }
                m_common = {
                    "key": SUDOKU_KEY,
                    "aead-method": "chacha20-poly1305",
                    "table-type": "prefer_entropy",
                    "padding-min": 5,
                    "padding-max": 15,
                    "enable-pure-downlink": True,
                    "http-mask-mode": m_mode,
                    "path-root": path_root,
                }
                m_l = {
                    **m_common,
                    "name": "node",
                    "type": "sudoku",
                    "listen": "127.0.0.1",
                    "port": np,
                    "disable-http-mask": is_raw,
                }
                m_p = {
                    **m_common,
                    "name": "relay",
                    "type": "sudoku",
                    "server": "127.0.0.1",
                    "port": np,
                    "http-mask": not is_raw,
                    "multiplex": mux_val,
                    "udp": True,
                }
                return {
                    "k_server": kerlico_server_wrap("sudoku", k_s_opts, np, [{"key": SUDOKU_KEY}]),
                    "k_client": kerlico_client_wrap("sudoku", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": mihomo_server_wrap(m_l),
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "sudoku",
            "combination": combo,
            "mode": "dual_end",
            "udp": True,
            "proto_listen": "tcp",
            "build": make_sudoku(),
        })

    # 14. Snell (v3-aes-128-gcm, v3-chacha20-ietf-poly1305 — client_vs_kserver)
    for combo, cipher in [
        ("v3-aes-128-gcm", "aes-128-gcm"),
        ("v3-chacha20-ietf-poly1305", "chacha20-ietf-poly1305"),
    ]:
        def make_snell(cipher=cipher):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                k_s_opts = {"version": 3, "cipher": cipher}
                k_c_opts = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "version": 3,
                    "cipher": cipher,
                    "psk": USER_PASSWORD,
                }
                m_p = {
                    "type": "snell",
                    "server": "127.0.0.1",
                    "port": np,
                    "psk": USER_PASSWORD,
                    "version": 3,
                    "cipher": cipher,
                    "udp": True,
                }
                return {
                    "k_server": kerlico_server_wrap("snell", k_s_opts, np, [{"psk": USER_PASSWORD}]),
                    "k_client": kerlico_client_wrap("snell", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": None,
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "snell",
            "combination": combo,
            "mode": "client_vs_kserver",
            "udp": True,
            "proto_listen": "tcp",
            "build": make_snell(),
        })

    # 15. ShadowsocksR (client_vs_kserver)
    for combo, method, proto, obfs in [
        ("aes-256-cfb-auth_aes128_sha1-plain", "aes-256-cfb", "auth_aes128_sha1", "plain"),
        ("aes-256-cfb-auth_aes128_sha1-tls1.2_ticket_auth", "aes-256-cfb", "auth_aes128_sha1", "tls1.2_ticket_auth"),
        ("chacha20-ietf-auth_chain_a-plain", "chacha20-ietf", "auth_chain_a", "plain"),
        ("none-auth_chain_a-plain", "none", "auth_chain_a", "plain"),
    ]:
        def make_ssr(method=method, proto=proto, obfs=obfs):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                common = {"method": method, "protocol": proto, "obfs": obfs, "allow_insecure": True}
                k_c_opts = {**common, "server": {"host": "127.0.0.1", "port": np}, "password": USER_PASSWORD}
                m_p = {
                    "type": "ssr",
                    "server": "127.0.0.1",
                    "port": np,
                    "cipher": method,
                    "password": USER_PASSWORD,
                    "protocol": proto,
                    "obfs": obfs,
                    "udp": True,
                }
                return {
                    "k_server": kerlico_server_wrap("shadowsocksr", common, np, [{"password": USER_PASSWORD}]),
                    "k_client": kerlico_client_wrap("shadowsocksr", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": None,
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "shadowsocksr",
            "combination": combo,
            "mode": "client_vs_kserver",
            "udp": True,
            "proto_listen": "tcp",
            "build": make_ssr(),
        })

    # 16. Hysteria v1 (client_vs_kserver)
    for combo, obfs_on in [("udp-plain", False), ("udp-xplus", True)]:
        def make_hy1(obfs_on=obfs_on):
            def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
                obfs_str = "bench-hy1-xplus" if obfs_on else None
                k_s_opts: dict[str, Any] = {
                    "tls": {"certificate_pem": m["chain_pem"], "private_key_pem": m["key_pem"], "alpn": ["h3"]},
                    "transport": "udp",
                }
                k_c_opts: dict[str, Any] = {
                    "server": {"host": "127.0.0.1", "port": np},
                    "auth_str": USER_PASSWORD,
                    "up_bps": 1_250_000_000,
                    "down_bps": 1_250_000_000,
                    "tls": {"server_name": "localhost", "ca_pem": m["ca_pem"], "alpn": ["h3"]},
                    "transport": "udp",
                }
                m_p: dict[str, Any] = {
                    "type": "hysteria",
                    "server": "127.0.0.1",
                    "port": np,
                    "auth-str": USER_PASSWORD,
                    "up": "10000 Mbps",
                    "down": "10000 Mbps",
                    "sni": "localhost",
                    "fingerprint": m["cert_fp"],
                    "skip-cert-verify": True,
                    "alpn": ["h3"],
                    "udp": True,
                }
                if obfs_str:
                    k_s_opts["obfs"] = obfs_str
                    k_c_opts["obfs"] = obfs_str
                    m_p["obfs"] = obfs_str
                return {
                    "k_server": kerlico_server_wrap("hysteria1", k_s_opts, np, [{"auth_str": USER_PASSWORD}]),
                    "k_client": kerlico_client_wrap("hysteria1", k_c_opts, tp, up, t_tcp, t_udp),
                    "m_server": None,
                    "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp),
                }
            return builder
        cases.append({
            "protocol": "hysteria1",
            "combination": combo,
            "mode": "client_vs_kserver",
            "udp": True,
            "proto_listen": "udp",
            "build": make_hy1(),
        })

    # 17. WireGuard (client_vs_kserver)
    def make_wg():
        def builder(np: int, tp: int, up: int | None, t_tcp: int, t_udp: int, cover_port: int | None):
            k_s_opts = {
                "tunnel": {
                    "private_key": m["wg_s_priv"],
                    "addresses": ["10.77.0.1", "fd77::1"],
                    "mtu": 1400,
                }
            }
            member = {
                "public_key": m["wg_c_pub"],
                "allowed_ips": ["10.77.0.2/32", "fd77::2/128"],
                "persistent_keepalive": 25,
            }
            k_c_opts = {
                "endpoint": {"host": "127.0.0.1", "port": np},
                "tunnel": {
                    "private_key": m["wg_c_priv"],
                    "addresses": ["10.77.0.2", "fd77::2"],
                    "mtu": 1400,
                },
                "peer": {
                    "public_key": m["wg_s_pub"],
                    "allowed_ips": ["0.0.0.0/0", "::/0"],
                    "persistent_keepalive": 25,
                },
            }
            m_p = {
                "type": "wireguard",
                "server": "127.0.0.1",
                "port": np,
                "ip": "10.77.0.2",
                "ipv6": "fd77::2",
                "private-key": m["wg_c_priv"],
                "public-key": m["wg_s_pub"],
                "mtu": 1400,
                "udp": True,
                "remote-dns-resolve": False,
            }
            return {
                "k_server": kerlico_server_wrap("wireguard", k_s_opts, np, [member]),
                "k_client": kerlico_client_wrap("wireguard", k_c_opts, tp, up, t_tcp, t_udp, target_host="10.77.0.1"),
                "m_server": None,
                "m_client": mihomo_client_wrap(m_p, tp, up, t_tcp, t_udp, target_host="10.77.0.1"),
            }
        return builder
    cases.append({
        "protocol": "wireguard",
        "combination": "udp-l3",
        "mode": "client_vs_kserver",
        "udp": True,
        "proto_listen": "udp",
        "build": make_wg(),
    })

    return cases


def summarize_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    if not runs:
        return {}
    if len(runs) == 1:
        return runs[0]

    def med(vals: list[float | int]) -> float:
        return round(statistics.median(vals), 3)

    def rng(vals: list[float | int]) -> list[float]:
        return [round(min(vals), 3), round(max(vals), 3)]

    first = runs[0]
    out: dict[str, Any] = {}
    for k in ("tcp_rtt_median_ms", "tcp_rtt_min_ms", "tcp_rtt_p95_ms", "tcp_1stream_mib_s", "tcp_8stream_mib_s", "udp_rtt_median_ms", "udp_mib_s", "udp_pps", "udp_loss_pct"):
        vals = [r[k] for r in runs if r.get(k) is not None]
        out[k] = med(vals) if vals else None
        if vals:
            out[f"{k}_range"] = rng(vals)

    for section in ("client", "server", "combined"):
        sec_out: dict[str, Any] = {}
        for k in first[section].keys():
            vals = [r[section][k] for r in runs if r[section].get(k) is not None]
            if vals:
                sec_out[k] = med(vals)
                sec_out[f"{k}_range"] = rng(vals)
        out[section] = sec_out

    return out


def allocate_wan_port() -> int:
    with PORT_LOCK:
        for _ in range(512):
            candidate = 30000 + int.from_bytes(os.urandom(2), "big") % 2600
            if candidate in ALLOCATED_PORTS or candidate == 31999:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM
                ) as udp:
                    tcp.bind(("0.0.0.0", candidate))
                    udp.bind(("0.0.0.0", candidate))
                    ALLOCATED_PORTS.add(candidate)
                    return candidate
            except OSError:
                continue
    raise RuntimeError("无法分配空闲 WAN 端口 (30000..32600)")


def rewrite_built_for_wan(built: dict[str, Any], wan_host: str, np: int) -> None:
    k_s = built.get("k_server")
    if k_s:
        for field in ("nodes", "local_inbounds"):
            if field in k_s and k_s[field]:
                k_s[field][0]["listen"] = f"0.0.0.0:{np}"
    m_s = built.get("m_server")
    if m_s:
        for lst in m_s.get("listeners", []):
            if lst.get("name") == "node":
                lst["listen"] = "0.0.0.0"
        if "tuic-server" in m_s:
            m_s["tuic-server"]["listen"] = f"0.0.0.0:{np}"
    k_c = built.get("k_client")
    if k_c and k_c.get("outbounds"):
        opts = k_c["outbounds"][0].get("options", {})
        if isinstance(opts.get("server"), dict):
            opts["server"]["host"] = wan_host
        elif isinstance(opts.get("server"), str):
            opts["server"] = wan_host
        elif isinstance(opts.get("endpoint"), dict):
            opts["endpoint"]["host"] = wan_host
    m_c = built.get("m_client")
    if m_c and m_c.get("proxies"):
        m_c["proxies"][0]["server"] = wan_host


def wan_rpc(wan_addr: str, req: dict[str, Any], timeout: float = 25.0) -> dict[str, Any]:
    host, port_s = wan_addr.rsplit(":", 1)
    with socket.create_connection((host, int(port_s)), timeout=timeout) as sock:
        sock.settimeout(timeout)
        data = json.dumps(req).encode("utf-8")
        sock.sendall(struct.pack("!I", len(data)) + data)
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                raise EOFError("WAN RPC 响应头断开")
            hdr += chunk
        (resp_len,) = struct.unpack("!I", hdr)
        body = bytearray()
        while len(body) < resp_len:
            chunk = sock.recv(min(65536, resp_len - len(body)))
            if not chunk:
                raise EOFError("WAN RPC 响应体断开")
            body.extend(chunk)
        resp = json.loads(body.decode("utf-8"))
        if not resp.get("ok"):
            raise RuntimeError(f"WAN Server Agent 错误: {resp.get('error')}")
        return resp


def run_server_agent(port: int, alias: str, kerlico_bin: str, mihomo_bin: str, work: Path) -> None:
    state: dict[str, Any] = {
        "proc": None,
        "stack": None,
        "cover_stack": None,
        "cover_port": None,
        "t_tcp": None,
        "t_udp": None,
        "lock": threading.Lock(),
    }

    def stop_current_server() -> None:
        st = state.get("stack")
        if st is not None:
            try:
                st.close()
            except Exception:
                pass
            state["stack"] = None
            state["proc"] = None

    class AgentHandler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                self.request.settimeout(30.0)
                hdr = b""
                while len(hdr) < 4:
                    c = self.request.recv(4 - len(hdr))
                    if not c:
                        return
                    hdr += c
                (req_len,) = struct.unpack("!I", hdr)
                body = bytearray()
                while len(body) < req_len:
                    c = self.request.recv(min(65536, req_len - len(body)))
                    if not c:
                        return
                    body.extend(c)
                req = json.loads(body.decode("utf-8"))
                cmd = req.get("cmd")
                with state["lock"]:
                    if cmd == "init":
                        stop_current_server()
                        if state["cover_stack"] is not None:
                            state["cover_stack"].close()
                            state["cover_stack"] = None
                        pki = work / "agent-pki"
                        pki.mkdir(parents=True, exist_ok=True)
                        cert_p = pki / "cert.pem"
                        key_p = pki / "key.pem"
                        cert_p.write_text(req["cert_pem"])
                        key_p.write_text(req["key_pem"])
                        cert_p.chmod(0o600)
                        key_p.chmod(0o600)
                        cstack = ExitStack()
                        cport = cstack.enter_context(start_tls_cover(cert_p, key_p))
                        state["cover_stack"] = cstack
                        state["cover_port"] = cport
                        resp = {
                            "ok": True,
                            "t_tcp": state["t_tcp"],
                            "t_udp": state["t_udp"],
                            "cover_port": cport,
                            "machine": collect_machine_info(alias, kerlico_bin, mihomo_bin),
                        }
                    elif cmd == "alloc_port":
                        resp = {"ok": True, "np": allocate_wan_port()}
                    elif cmd == "start_server":
                        stop_current_server()
                        s_dir = work / f"srv-{int(time.time()*1000)}"
                        s_dir.mkdir(parents=True, exist_ok=True)
                        s_cfg = req["cfg"]
                        s_engine = req["engine"]
                        np = req["np"]
                        proto_listen = req["proto_listen"]
                        st = ExitStack()
                        try:
                            if s_engine == "kerlico":
                                s_cfg_path = s_dir / "server.json"
                                s_cfg_path.write_text(json.dumps(s_cfg, indent=2))
                                s_proc = st.enter_context(
                                    managed_process([kerlico_bin, "run", "-c", str(s_cfg_path)], s_dir, "server")
                                )
                                wait_port_owned(s_proc.pid, np, proto_listen, timeout=10.0, log_file=s_dir / "server.log")
                            else:
                                for row in s_cfg.get("listeners", []):
                                    if row.get("name") == "tunnel-probe":
                                        row["port"] = allocate_port("127.0.0.1")
                                s_cfg_path = s_dir / "server.json"
                                s_cfg_path.write_text(json.dumps(s_cfg, indent=2))
                                s_proc = st.enter_context(
                                    managed_process([mihomo_bin, "-d", str(s_dir), "-f", str(s_cfg_path)], s_dir, "server")
                                )
                                wait_running(s_proc, s_cfg, timeout=12.0)
                                wait_port_owned(s_proc.pid, np, proto_listen, timeout=10.0, log_file=s_dir / "server.log")
                            state["stack"] = st
                            state["proc"] = s_proc
                            resp = {"ok": True, "pid": s_proc.pid}
                        except Exception as e:
                            st.close()
                            resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    elif cmd == "snap":
                        p = state.get("proc")
                        resp = {"ok": True, "snap": read_proc_snapshot(p.pid if p else None)}
                    elif cmd == "stop_server":
                        stop_current_server()
                        resp = {"ok": True}
                    else:
                        resp = {"ok": False, "error": f"未知命令: {cmd}"}
            except Exception as e:
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            out = json.dumps(resp).encode("utf-8")
            self.request.sendall(struct.pack("!I", len(out)) + out)

    with start_echo_servers() as (t_tcp, t_udp):
        state["t_tcp"] = t_tcp
        state["t_udp"] = t_udp
        srv = FastTcpEchoServer(("0.0.0.0", port), AgentHandler)
        print(f"WAN Server Agent Ready on 0.0.0.0:{port} (t_tcp={t_tcp}, t_udp={t_udp})", flush=True)
        try:
            srv.serve_forever()
        finally:
            stop_current_server()
            if state["cover_stack"] is not None:
                state["cover_stack"].close()


def run_single_side(
    engine: str,
    case: dict[str, Any],
    work_dir: Path,
    kerlico_bin: str,
    mihomo_bin: str,
    t_tcp: int,
    t_udp: int,
    cover_port: int | None,
    bulk_mib: int,
    streams: int,
    udp_packets: int,
    wan_server: str = "",
    duration_sec: float = 0.0,
) -> dict[str, Any]:
    tp = allocate_port()
    up = allocate_port() if case["udp"] else None
    if wan_server:
        wan_host = wan_server.rsplit(":", 1)[0]
        np = wan_rpc(wan_server, {"cmd": "alloc_port"})["np"]
        built = case["build"](np, tp, up, t_tcp, t_udp, cover_port)
        rewrite_built_for_wan(built, wan_host, np)
    else:
        np = allocate_port()
        built = case["build"](np, tp, up, t_tcp, t_udp, cover_port)

    side_dir = work_dir / f"{engine}-{int(time.time()*1000)}"
    side_dir.mkdir(parents=True, exist_ok=True)

    with ExitStack() as stack:
        s_engine = "kerlico" if (engine == "kerlico" or case["mode"] == "client_vs_kserver") else "mihomo"
        if wan_server and built.get("k_server", {}).get("local_inbounds"):
            s_engine = "mihomo"
        s_cfg = built["k_server"] if s_engine == "kerlico" else built["m_server"]
        if wan_server:
            wan_rpc(
                wan_server,
                {
                    "cmd": "start_server",
                    "engine": s_engine,
                    "cfg": s_cfg,
                    "np": np,
                    "proto_listen": case["proto_listen"],
                },
            )
            stack.callback(lambda: wan_rpc(wan_server, {"cmd": "stop_server"}))
            s_pid = None
            server_snap_fn = lambda: wan_rpc(wan_server, {"cmd": "snap"})["snap"]
        else:
            if s_engine == "kerlico":
                s_cfg_path = side_dir / "server.json"
                s_cfg_path.write_text(json.dumps(s_cfg, indent=2))
                s_proc = stack.enter_context(
                    managed_process([kerlico_bin, "run", "-c", str(s_cfg_path)], side_dir, "server")
                )
                wait_port_owned(s_proc.pid, np, case["proto_listen"], timeout=10.0, log_file=side_dir / "server.log")
            else:
                s_cfg_path = side_dir / "server.json"
                s_cfg_path.write_text(json.dumps(s_cfg, indent=2))
                s_proc = stack.enter_context(
                    managed_process([mihomo_bin, "-d", str(side_dir), "-f", str(s_cfg_path)], side_dir, "server")
                )
                wait_running(s_proc, s_cfg, timeout=12.0)
                wait_port_owned(s_proc.pid, np, case["proto_listen"], timeout=10.0, log_file=side_dir / "server.log")
            s_pid = s_proc.pid
            server_snap_fn = None

        if engine == "kerlico":
            c_cfg_path = side_dir / "client.json"
            c_cfg_path.write_text(json.dumps(built["k_client"], indent=2))
            c_proc = stack.enter_context(
                managed_process([kerlico_bin, "run", "-c", str(c_cfg_path)], side_dir, "client")
            )
            wait_port_owned(c_proc.pid, tp, "tcp", timeout=10.0, log_file=side_dir / "client.log")
            if up is not None:
                wait_port_owned(c_proc.pid, up, "udp", timeout=10.0, log_file=side_dir / "client.log")
        else:
            c_cfg_path = side_dir / "client.json"
            c_cfg_path.write_text(json.dumps(built["m_client"], indent=2))
            c_proc = stack.enter_context(
                managed_process([mihomo_bin, "-d", str(side_dir), "-f", str(c_cfg_path)], side_dir, "client")
            )
            wait_running(c_proc, built["m_client"], timeout=12.0)
            wait_port_owned(c_proc.pid, tp, "tcp", timeout=10.0, log_file=side_dir / "client.log")

        return run_workload(
            tcp_port=tp,
            udp_port=up,
            client_pid=c_proc.pid,
            server_pid=s_pid,
            bulk_mib=bulk_mib,
            streams=streams,
            udp_packets=udp_packets,
            server_snap_fn=server_snap_fn,
            duration_sec=duration_sec,
            label=f"{engine}:{case['combination']}",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="kerlico vs mihomo benchmark")
    parser.add_argument("--alias", required=True, help="Worker alias (e.g. perf-01, perf-03)")
    parser.add_argument("--kerlico", required=True, help="Path to release kerlico binary")
    parser.add_argument("--mihomo", required=True, help="Path to mihomo binary")
    parser.add_argument("--protocol", default="all", help="Comma-separated protocol filter or 'all'")
    parser.add_argument("--combination", default="", help="Optional combination substring filter")
    parser.add_argument("--repeats", type=int, default=3, help="Interleaved repeats per combination")
    parser.add_argument("--bulk-mib", type=int, default=16, help="MiB per TCP bulk phase")
    parser.add_argument("--duration-sec", type=float, default=0.0, help="Fixed duration in seconds per TCP phase (overrides bulk-mib when > 0)")
    parser.add_argument("--streams", type=int, default=8, help="Concurrent TCP streams")
    parser.add_argument("--udp-packets", type=int, default=200, help="UDP burst packets")
    parser.add_argument("--work-dir", default="/tmp/bench-vs-mihomo", help="Scratch directory")
    parser.add_argument("--out", default="", help="Output JSON path")
    parser.add_argument("--server-agent", type=int, default=0, help="Run as WAN server agent on given TCP port")
    parser.add_argument("--wan-server", default="", help="Remote WAN server agent address host:port")
    args = parser.parse_args()

    work = Path(args.work_dir).resolve()
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    os.chmod(work, 0o700)

    if args.server_agent > 0:
        run_server_agent(args.server_agent, args.alias, args.kerlico, args.mihomo, work)
        return

    if not args.out:
        raise ValueError("--out is required unless --server-agent is used")

    machine_info = collect_machine_info(args.alias, args.kerlico, args.mihomo)
    materials = generate_materials(work / "pki", args.kerlico)
    all_cases = build_protocol_cases(materials)

    proto_filter = None if args.protocol == "all" else {p.strip() for p in args.protocol.split(",") if p.strip()}
    comb_parts = [x.strip() for x in args.combination.split(",") if x.strip()] if args.combination else []
    selected = [
        c for c in all_cases
        if (proto_filter is None or c["protocol"] in proto_filter)
        and (not comb_parts or c["combination"] in comb_parts)
    ]

    results: list[dict[str, Any]] = []
    with ExitStack() as top_stack:
        if args.wan_server:
            init_resp = wan_rpc(
                args.wan_server,
                {
                    "cmd": "init",
                    "cert_pem": materials["cert_pem"],
                    "key_pem": materials["key_pem"],
                },
            )
            t_tcp = init_resp["t_tcp"]
            t_udp = init_resp["t_udp"]
            cover_port = init_resp["cover_port"]
            machine_info["topology"] = "wan-1gbps-cross-host"
            machine_info["client_machine"] = copy.deepcopy(machine_info)
            machine_info["server_machine"] = init_resp["machine"]
        else:
            t_tcp, t_udp = top_stack.enter_context(start_echo_servers())
            cover_port = top_stack.enter_context(start_tls_cover(materials["cert"], materials["key"]))
            machine_info["topology"] = "loopback-same-host"

        for case in selected:
            proto = case["protocol"]
            combo = case["combination"]
            case_dir = work / f"{proto}-{combo}"
            case_dir.mkdir(parents=True, exist_ok=True)
            k_runs: list[dict[str, Any]] = []
            m_runs: list[dict[str, Any]] = []
            errors: dict[str, str] = {}

            for r_idx in range(args.repeats):
                # Interleave order: even rounds kerlico -> mihomo, odd rounds mihomo -> kerlico
                order = ("kerlico", "mihomo") if r_idx % 2 == 0 else ("mihomo", "kerlico")
                for eng in order:
                    if eng in errors:
                        continue
                    try:
                        res = run_single_side(
                            engine=eng,
                            case=case,
                            work_dir=case_dir / f"r{r_idx}",
                            kerlico_bin=args.kerlico,
                            mihomo_bin=args.mihomo,
                            t_tcp=t_tcp,
                            t_udp=t_udp,
                            cover_port=cover_port if case.get("needs_cover") else None,
                            bulk_mib=args.bulk_mib,
                            streams=args.streams,
                            udp_packets=args.udp_packets,
                            wan_server=args.wan_server,
                            duration_sec=args.duration_sec,
                        )
                        if eng == "kerlico":
                            k_runs.append(res)
                        else:
                            m_runs.append(res)
                    except Exception as exc:
                        errors[eng] = f"{type(exc).__name__}: {exc}"

            row = {
                "protocol": proto,
                "combination": combo,
                "mode": case["mode"],
                "udp_tested": case["udp"],
                "repeats": args.repeats,
                "status": "pass" if (k_runs and m_runs and not errors) else "error",
                "errors": errors,
                "kerlico": summarize_runs(k_runs) if k_runs else None,
                "mihomo": summarize_runs(m_runs) if m_runs else None,
                "kerlico_runs": k_runs,
                "mihomo_runs": m_runs,
            }
            results.append(row)
            print(
                json.dumps(
                    {
                        "machine": args.alias,
                        "protocol": proto,
                        "combination": combo,
                        "status": row["status"],
                        "errors": errors,
                        "k_8s_mib_s": row["kerlico"]["tcp_8stream_mib_s"] if row["kerlico"] else None,
                        "m_8s_mib_s": row["mihomo"]["tcp_8stream_mib_s"] if row["mihomo"] else None,
                        "k_peak_rss_kb": row["kerlico"]["combined"]["peak_rss_kb"] if row["kerlico"] else None,
                        "m_peak_rss_kb": row["mihomo"]["combined"]["peak_rss_kb"] if row["mihomo"] else None,
                        "k_cpu_ms_per_mib": row["kerlico"]["combined"]["tcp_cpu_ms_per_mib"] if row["kerlico"] else None,
                        "m_cpu_ms_per_mib": row["mihomo"]["combined"]["tcp_cpu_ms_per_mib"] if row["mihomo"] else None,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

    payload = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": machine_info,
        "workload": {
            "repeats_interleaved": args.repeats,
            "tcp_duration_sec": args.duration_sec if args.duration_sec > 0 else None,
            "tcp_single_stream_mib": None if args.duration_sec > 0 else args.bulk_mib,
            "tcp_multi_stream_count": args.streams,
            "tcp_multi_stream_total_mib": None if args.duration_sec > 0 else args.bulk_mib,
            "udp_burst_packets": args.udp_packets,
            "udp_packet_bytes": 1200,
        },
        "results": results,
    }
    out_text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.wan_server:
        wan_ip = args.wan_server.rsplit(":", 1)[0]
        out_text = out_text.replace(wan_ip, "<perf-03-wan-ip>")
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(out_text, encoding="utf-8")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
