import argparse
import asyncio
from config_v2 import bind_members
from contextlib import contextmanager
import ctypes
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys

if os.name == "nt":
    import msvcrt
else:
    import fcntl

PORT_LEASE = None


@contextmanager
def port_lease(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, "r+", encoding="ascii", newline="\n") as handle:
        if os.name == "nt":
            if os.fstat(handle.fileno()).st_size == 0:
                handle.write("\n")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield handle
        finally:
            handle.flush()
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def require_loopback(host):
    if not ipaddress.ip_address(host).is_loopback:
        raise RuntimeError("SSR隔离验收只允许显式回环地址")


def helpers():
    spec = importlib.util.spec_from_file_location("shadowsocks_interop", Path(__file__).with_name("interop_shadowsocks.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def port(host="127.0.0.1"):
        require_loopback(host)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        # worker 内核的临时 UDP 出口会占用 bind(0) 候选；选择临时范围之外且双协议均空闲的端口。
        try:
            upper = min(int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0]), 30000)
        except (OSError, ValueError):
            upper = 30000
        if upper <= 10240:
            raise RuntimeError("测试端口范围不足")
        # 多个对照进程共享项目租约，防止“检查空闲→启动子进程”之间再次分配同一端口。
        lease = PORT_LEASE or (Path(__file__).resolve().parents[1] / ".private" / "ssr-interop" / "ports.lock" if os.name == "nt" else Path(__file__).resolve().parents[2] / "ssr-test-ports.txt")
        with port_lease(lease) as handle:
            handle.seek(0)
            used = {int(line) for line in handle.read().splitlines() if line}
            for _ in range(128):
                number = random.SystemRandom().randrange(10240, upper)
                if number in used:
                    continue
                try:
                    with socket.socket(family, socket.SOCK_STREAM) as tcp, socket.socket(family, socket.SOCK_DGRAM) as udp:
                        if os.name == "nt":
                            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                            udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                        tcp.bind((host, number))
                        udp.bind((host, number))
                        handle.seek(0, os.SEEK_END)
                        handle.write(str(number) + "\n")
                        handle.flush()
                        return number
                except OSError:
                    pass
        raise RuntimeError("找不到同时空闲的 TCP/UDP 测试端口")
    module.port = port
    return module


h = helpers()
PROTOCOLS = ["origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"]
OBFS = ["plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"]
BASE_PASSWORD = "synthetic-ssr-base-password"
USER_PASSWORD = "synthetic-ssr-user-password"


def authenticated(protocol, obfs, udp):
    return (protocol != "origin" or obfs.startswith("tls1.2_ticket")) and (not udp or protocol.startswith("auth_aes128") or protocol.startswith("auth_chain"))


def options(method, protocol, obfs, multi):
    value = {"method": method, "password": BASE_PASSWORD, "protocol": protocol, "obfs": obfs, "allow_insecure": True}
    if multi:
        value["users"] = [{"id": 7, "password": USER_PASSWORD}, {"id": 8, "password": "synthetic-second-user-password"}]
    return value


def base():
    return {"version": 2, "inbounds": [], "nodes": [], "outbounds": [], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 5000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65000}}


def server_config(host, port, method, protocol, obfs, multi):
    config = base()
    config["outbounds"] = [{"tag": "direct", "type": "direct"}]
    key = "nodes" if authenticated(protocol, obfs, True) else "local_inbounds"
    config[key] = [{"tag": "ssr", "type": "shadowsocksr", "listen": h.endpoint(host, port), "outbound": "direct", "options": options(method, protocol, obfs, multi)}]
    if key == "nodes":
        node = config[key][0]
        password = node["options"].pop("password")
        users = node["options"].pop("users", [])
        credentials = [{"password": password, "user": user} for user in users]
        bind_members(config, node, credentials or [{"password": password}])
    return config


def client_config(local, host, port, target_host, target_port, method, protocol, obfs, multi):
    config = base()
    opts = options(method, protocol, obfs, False)
    opts["server"] = {"host": host, "port": port}
    if multi:
        opts["user"] = {"id": 7, "password": USER_PASSWORD}
    config["outbounds"] = [{"tag": "proxy", "type": "shadowsocksr", "options": opts}]
    config["inbounds"] = [{"tag": network, "type": network + "-forward", "listen": h.endpoint("127.0.0.1", local), "target": {"host": target_host, "port": target_port}, "outbound": "proxy"} for network in ["tcp", "udp"]]
    return config


def reference_config(direction, host, port, local, target_host, target_port, method, protocol, obfs, multi, kind):
    if kind == "kerlico":
        return server_config(host, port, method, protocol, obfs, multi) if direction == "server" else client_config(local, host, port, target_host, target_port, method, protocol, obfs, multi)
    method = method.replace("cfb128", "cfb")
    if kind == "python":
        return {"server": host, "server_port": port, "local_address": "127.0.0.1", "local_port": local, "password": BASE_PASSWORD, "method": method, "protocol": protocol, "obfs": obfs, "obfs_param": "", "protocol_param": ("64#7:" + USER_PASSWORD + ",8:synthetic-second-user-password" if direction == "server" else "7:" + USER_PASSWORD) if multi else "", "timeout": 5, "udp_timeout": 5, "forbidden_ip": "", "dns_ipv6": True}
    if direction == "server":
        raise RuntimeError("固定 mihomo 没有 SSR 服务端入口")
    proxy = {"name": "relay", "type": "ssr", "server": host, "port": port, "cipher": method, "password": BASE_PASSWORD, "protocol": protocol, "obfs": obfs, "udp": True}
    if multi:
        proxy["protocol-param"] = "7:" + USER_PASSWORD
    return {"mode": "rule", "log-level": "error", "external-controller": h.endpoint("127.0.0.1", h.port()), "secret": "synthetic-controller-key", "ipv6": True, "geo-auto-update": False, "tun": {"enable": False}, "port": 0, "socks-port": 0, "mixed-port": 0, "redir-port": 0, "tproxy-port": 0, "rules": ["MATCH,DIRECT"], "proxies": [proxy], "listeners": [{"name": network, "type": "tunnel", "listen": "127.0.0.1", "port": str(local), "network": [network], "target": h.endpoint(target_host, target_port), "proxy": "relay"} for network in ["tcp", "udp"]]}


async def start(args, kind, direction, config, log, host, port, work):
    require_loopback(host)
    work, config, log = Path(work).resolve(), Path(config).resolve(), Path(log).resolve()
    if config.parent != work or log.parent != work:
        raise RuntimeError("进程配置和日志必须属于本任务独立目录")
    handle = None
    readiness = None
    readiness_port = None
    process = None
    try:
        if kind == "mihomo":
            value = json.loads(config.read_text())
            forbidden = {port, int(value["external-controller"].rsplit(":", 1)[1])}
            def available():
                while True:
                    candidate = h.port()
                    if candidate not in forbidden:
                        forbidden.add(candidate)
                        return candidate
            ready_target, readiness_port = available(), available()
            async def greeting(reader, writer):
                try:
                    writer.write(b"ssr-reference-running")
                    await writer.drain()
                finally:
                    writer.close()
                    await writer.wait_closed()
            readiness = await asyncio.start_server(greeting, "127.0.0.1", ready_target)
            value["listeners"].append({"name": "reference-ready", "type": "tunnel", "listen": "127.0.0.1", "port": str(readiness_port), "network": ["tcp"], "target": h.endpoint("127.0.0.1", ready_target), "proxy": "DIRECT"})
            h.save(config.parent, config.name, value)
        if kind == "python":
            command = [sys.executable, str(Path(__file__).resolve().with_name("shadowsocksr_reference.py")), "--reference", str(Path(args.reference_source).resolve()), "--role", direction, "--config", str(config)]
        elif kind == "mihomo":
            command = [args.peer, "-d", str(work), "-f", str(config)]
        else:
            command = [args.kerlico if kind == "own" else args.peer, "run", "-c", str(config)]
        executable = shutil.which(command[0]) or str(Path(command[0]).resolve())
        command[0] = executable
        creation = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", NO_PROXY="*", no_proxy="*")
        handle = log.open("wb")
        os.chmod(log, 0o600)
        process = subprocess.Popen(command, cwd=work, stdout=handle, stderr=handle, env=environment, **creation)
        await listening(process, port, host)
        if kind == "mihomo":
            value = json.loads(config.read_text())
            await listening(process, int(value["external-controller"].rsplit(":", 1)[1]), "127.0.0.1")
            await proxy_ready(process, value)
            await listening(process, readiness_port, "127.0.0.1")
            attempts = await direct_ready(process, readiness_port)
            h.save(work, "readiness.json", {"direct_attempts": attempts, "proxy_present": True, "owned_listener": True})
    except BaseException:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                await asyncio.to_thread(process.wait, timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait)
        if handle is not None:
            handle.close()
        raise
    finally:
        if readiness is not None:
            readiness.close()
            await readiness.wait_closed()
    return process, handle, kind


def windows_listening(pid, host, port):
    """IP Helper只读核对PID、监听状态、回环地址和端口，不连接其他控制面。"""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    api = ctypes.WinDLL("iphlpapi").GetExtendedTcpTable
    word = ctypes.c_uint32
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(word), ctypes.c_int, word, word, word]
    api.restype = word
    size = word(0)
    # TCP_TABLE_OWNER_PID_LISTENER为3；仅查询监听表，不读取其他进程配置。
    result = api(None, ctypes.byref(size), False, family, 3, 0)
    if result not in (0, 122):
        raise OSError(result, "无法读取测试进程监听表")
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        result = api(buffer, ctypes.byref(size), False, family, 3, 0)
        if result == 122:
            continue
        if result:
            raise OSError(result, "无法读取测试进程监听表")
        data = buffer.raw
        count = struct.unpack_from("<I", data)[0]
        width = 56 if family == socket.AF_INET6 else 24
        if 4 + count * width > len(data):
            raise RuntimeError("测试进程监听表长度不合法")
        for index in range(count):
            row = 4 + index * width
            if family == socket.AF_INET6:
                address = socket.inet_ntop(family, data[row:row + 16])
                local_port = socket.ntohs(struct.unpack_from("<I", data, row + 20)[0] & 0xFFFF)
                state, owner = struct.unpack_from("<II", data, row + 48)
            else:
                state = struct.unpack_from("<I", data, row)[0]
                address = socket.inet_ntop(family, data[row + 4:row + 8])
                local_port = socket.ntohs(struct.unpack_from("<I", data, row + 8)[0] & 0xFFFF)
                owner = struct.unpack_from("<I", data, row + 20)[0]
            if state == 2 and owner == pid and local_port == port and ipaddress.ip_address(address) == ipaddress.ip_address(host):
                return True
        return False
    raise RuntimeError("测试进程监听表在查询期间持续变化")


def linux_listening(pid, host, port):
    inodes = set()
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            link = os.readlink(descriptor)
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
        except FileNotFoundError:
            pass
    table = "tcp6" if ":" in host else "tcp"
    for line in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
        fields = line.split()
        address, number = fields[1].rsplit(":", 1)
        raw = bytes.fromhex(address)
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
        actual = socket.inet_ntop(socket.AF_INET6 if table == "tcp6" else socket.AF_INET, raw)
        if fields[3] == "0A" and int(number, 16) == port and fields[9] in inodes and ipaddress.ip_address(actual) == ipaddress.ip_address(host):
            return True
    return False


async def listening(process, port, host="127.0.0.1"):
    """只确认本任务创建的进程拥有监听，不通过业务连接探测SSR节点。"""
    require_loopback(host)
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("参考进程启动失败")
        if os.name == "nt":
            owned = windows_listening(process.pid, host, port)
        elif sys.platform.startswith("linux"):
            owned = linux_listening(process.pid, host, port)
        else:
            raise RuntimeError("此平台尚未实现可归属的监听就绪检查")
        if owned:
            return
        await asyncio.sleep(0.03)
    raise RuntimeError("参考监听未就绪")


async def proxy_ready(process, config):
    """监听创建早于代理表发布；确认合成代理已进入只读控制面后才发送业务。"""
    host, port = config["external-controller"].rsplit(":", 1)
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("参考进程启动失败")
        writer = None
        try:
            reader, writer = await asyncio.open_connection(host, int(port))
            request = f"GET /proxies/relay HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {config['secret']}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(65536), 1)
            if response.startswith(b"HTTP/1.1 200 "):
                return
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
        await asyncio.sleep(0.03)
    raise RuntimeError("参考代理表未就绪")


async def direct_ready(process, port):
    """监听及代理表发布后仍可能处于Suspend；用独立DIRECT问候确认Running，不预热SSR路径。"""
    for attempt in range(100):
        if process.poll() is not None:
            raise RuntimeError("参考进程启动失败")
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            greeting = await asyncio.wait_for(reader.readexactly(21), 1)
            if greeting == b"ssr-reference-running":
                return attempt + 1
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
        await asyncio.sleep(0.01)
    raise RuntimeError("参考运行状态未就绪")


async def stop(item):
    process, handle, kind = item
    terminated = process.poll() is None
    if process.poll() is None:
        process.terminate()
    try:
        await asyncio.to_thread(process.wait, timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        await asyncio.to_thread(process.wait)
        raise RuntimeError("SSR 进程未按时退出")
    finally:
        handle.close()
    allowed = {0, -signal.SIGTERM} if kind in {"python", "mihomo"} else {0}
    if os.name == "nt" and terminated:
        # Windows terminate是本任务句柄的强制清理；退出1不作为优雅退出验收。
        allowed.add(1)
    if process.returncode not in allowed:
        raise RuntimeError(f"SSR 进程退出状态不符：{process.returncode}")


async def socks_tcp(local, host, target):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    raw = socket.inet_pton(family, host)
    reader, writer = await asyncio.open_connection("127.0.0.1", local)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise RuntimeError("参考 SOCKS 协商失败")
        writer.write(bytes([5, 1, 0, 4 if family == socket.AF_INET6 else 1]) + raw + target.to_bytes(2, "big"))
        await writer.drain()
        header = await reader.readexactly(4)
        if header[1] != 0:
            raise RuntimeError("参考 SOCKS 请求被拒绝")
        if header[3] == 3:
            count = (await reader.readexactly(1))[0] + 2
        else:
            count = 18 if header[3] == 4 else 6
        await reader.readexactly(count)
        payload = b"ssr-interoperability|" * 2048
        writer.write(payload)
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(len(payload)), 5) != payload:
            raise RuntimeError("SSR TCP 负载不符")
    finally:
        writer.close()
        await writer.wait_closed()


async def socks_udp(local, host, target, payload):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    address = bytes([4 if family == socket.AF_INET6 else 1]) + socket.inet_pton(family, host) + target.to_bytes(2, "big")
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        await loop.sock_sendto(sock, b"\0\0\0" + address + payload, ("127.0.0.1", local))
        response, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 5)
        if len(response) < 4 or response[:3] != b"\0\0\0":
            raise RuntimeError("参考 UDP 回包格式不符")
        offset = 22 if response[3] == 4 else 10 if response[3] == 1 else 7 + response[4]
        if response[offset:] != b"echo|" + payload:
            raise RuntimeError("SSR UDP 负载不符")


async def greeting_tcp(local):
    reader, writer = await asyncio.open_connection("127.0.0.1", local)
    try:
        if await asyncio.wait_for(reader.readexactly(19), 5) != b"ssr-target-greeting":
            raise RuntimeError("SSR 目标先发内容不符")
        payload = b"ssr-after-greeting|" * 4096
        writer.write(payload)
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(len(payload)), 5) != payload:
            raise RuntimeError("SSR TCP 负载不符")
    finally:
        writer.close()
        await writer.wait_closed()


async def main(args):
    global PORT_LEASE
    if args.peer_kind == "mihomo" and "client" in args.directions.split(","):
        raise RuntimeError("mihomo 仅可验证 kerlico 服务端方向，必须显式选择 --directions server")
    if args.peer_kind == "python" and not args.reference_source:
        raise RuntimeError("Python 对端需要固定只读源码目录")
    if args.target_greeting and args.peer_kind == "python":
        raise RuntimeError("目标先发工具模式当前用于透明转发入口")
    for host in args.node_hosts.split(",") + args.target_hosts.split(","):
        require_loopback(host)
    root = Path(args.work).resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    PORT_LEASE = root / "ports.lock" if os.name == "nt" else None
    records = []
    for protocol in args.protocols.split(","):
        multi = args.multi and (protocol.startswith("auth_aes128") or protocol.startswith("auth_chain"))
        methods = ["none" if protocol.startswith("auth_chain") else "aes-128-cfb"] if args.methods == "auto" else args.methods.split(",")
        for method in methods:
            for obfs in args.obfs.split(","):
                for host in args.node_hosts.split(","):
                    for target_host in args.target_hosts.split(","):
                        target_port = h.port(target_host)
                        async def echo(reader, writer):
                            if args.target_greeting:
                                writer.write(b"ssr-target-greeting")
                                await writer.drain()
                            await h.echo(reader, writer)
                        target_tcp = await asyncio.start_server(echo, target_host, target_port)
                        target_udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(h.UdpEcho, local_addr=(target_host, target_port))
                        try:
                            for direction in args.directions.split(","):
                                label = f"{protocol}-{obfs}-{method}-{direction}-node{'6' if ':' in host else '4'}-target{'6' if ':' in target_host else '4'}"
                                work = root / label
                                work.mkdir(mode=0o700)
                                node, local = h.port(host), h.port()
                                if direction == "client":
                                    server = reference_config("server", host, node, local, target_host, target_port, method, protocol, obfs, multi, args.peer_kind)
                                    client = client_config(local, host, node, target_host, target_port, method, protocol, obfs, multi)
                                    server_kind, client_kind = args.peer_kind, "own"
                                else:
                                    server = server_config(host, node, method, protocol, obfs, multi)
                                    client = reference_config("client", host, node, local, target_host, target_port, method, protocol, obfs, multi, args.peer_kind)
                                    server_kind, client_kind = "own", args.peer_kind
                                active = []
                                try:
                                    active.append(await start(args, server_kind, "server", h.save(work, "server.json", server), work / "server.log", host, node, work))
                                    active.append(await start(args, client_kind, "client", h.save(work, "client.json", client), work / "client.log", "127.0.0.1", local, work))
                                    checks = [None] + ([int(size) for size in args.udp_sizes.split(",")] if obfs == "plain" else [])
                                    for size in checks:
                                        record = {"protocol": protocol, "obfs": obfs if size is None else None, "method": method, "role": direction, "node_family": 6 if ":" in host else 4, "target_family": 6 if ":" in target_host else 4, "network": "tcp" if size is None else "udp", "registration": "nodes" if authenticated(protocol, obfs, True) else "local_inbounds", "multi": multi}
                                        if size is None:
                                            record["traffic_pattern"] = "target-first" if args.target_greeting else "client-first"
                                        if size is not None:
                                            record["payload_bytes"] = size
                                        try:
                                            if client_kind == "python":
                                                await (socks_tcp(local, target_host, target_port) if size is None else socks_udp(local, target_host, target_port, b"u" * size))
                                            else:
                                                await ((greeting_tcp(local) if args.target_greeting else h.tcp(local)) if size is None else h.udp(local, b"u" * size))
                                            record["pass"] = True
                                        except Exception as error:
                                            record.update({"pass": False, "error": type(error).__name__})
                                            if isinstance(error, asyncio.IncompleteReadError):
                                                record.update({"expected_bytes": error.expected, "received_bytes": len(error.partial)})
                                        records.append(record)
                                        print(json.dumps(record, ensure_ascii=False), flush=True)
                                except Exception as error:
                                    records.append({"case": label, "pass": False, "network": "startup", "error": type(error).__name__})
                                finally:
                                    for item in reversed(active):
                                        try:
                                            await stop(item)
                                        except Exception as error:
                                            records.append({"case": label, "pass": False, "network": "shutdown", "error": type(error).__name__})
                        finally:
                            target_udp.close()
                            target_tcp.close()
                            await target_tcp.wait_closed()
    summary = {"peer_kind": args.peer_kind, "platform": sys.platform, "process_cleanup": "owned-handle-forced-no-graceful-exit-claim" if os.name == "nt" else "owned-handle-sigterm", "records": records, "passed": sum(record["pass"] for record in records), "failed": sum(not record["pass"] for record in records)}
    h.save(root, "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSR 角色、protocol、obfs、cipher 与原生 UDP 分维度验收")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--peer-kind", choices=["kerlico", "python", "mihomo"], required=True)
    parser.add_argument("--reference-source")
    parser.add_argument("--work", required=True)
    parser.add_argument("--protocols", default=",".join(PROTOCOLS))
    parser.add_argument("--obfs", default=",".join(OBFS))
    parser.add_argument("--methods", default="auto")
    parser.add_argument("--directions", default="client,server")
    parser.add_argument("--node-hosts", default="127.0.0.1,::1")
    parser.add_argument("--target-hosts", default="127.0.0.1,::1")
    parser.add_argument("--udp-sizes", default="3,2000")
    parser.add_argument("--multi", action="store_true")
    parser.add_argument("--target-greeting", action="store_true", help="透明入口先读目标问候，再发送大负载，单独登记此流量模式")
    asyncio.run(main(parser.parse_args()))
