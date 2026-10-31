"""仅在 worker 验收 SSR Rust CLI；Python/mihomo 只作为独立参考对端。"""
import argparse
import asyncio
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import random
import signal
import socket
import subprocess
import sys


def helpers():
    spec = importlib.util.spec_from_file_location("shadowsocks_interop", Path(__file__).with_name("interop_shadowsocks.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def port(host="127.0.0.1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        # worker 内核的临时 UDP 出口会占用 bind(0) 候选；选择临时范围之外且双协议均空闲的端口。
        try:
            upper = min(int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0]), 30000)
        except (OSError, ValueError):
            upper = 30000
        if upper <= 10240:
            raise RuntimeError("测试端口范围不足")
        # 多个对照进程共享项目租约，防止“检查空闲→启动子进程”之间再次分配同一端口。
        lease = Path(__file__).resolve().parents[2] / "ssr-test-ports.txt"
        descriptor = os.open(lease, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.seek(0)
            used = {int(line) for line in handle.read().splitlines() if line}
            for _ in range(128):
                number = random.SystemRandom().randrange(10240, upper)
                if number in used:
                    continue
                try:
                    with socket.socket(family, socket.SOCK_STREAM) as tcp, socket.socket(family, socket.SOCK_DGRAM) as udp:
                        tcp.bind((host, number))
                        udp.bind((host, number))
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
    return {"version": 1, "inbounds": [], "nodes": [], "outbounds": [], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 5000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65000}}


def server_config(host, port, method, protocol, obfs, multi):
    config = base()
    config["outbounds"] = [{"tag": "direct", "type": "direct"}]
    key = "nodes" if authenticated(protocol, obfs, True) else "local_inbounds"
    config[key] = [{"tag": "ssr", "type": "shadowsocksr", "listen": h.endpoint(host, port), "outbound": "direct", "options": options(method, protocol, obfs, multi)}]
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
    return {"mode": "rule", "log-level": "error", "external-controller": h.endpoint("127.0.0.1", h.port()), "secret": "synthetic-controller-key", "ipv6": True, "geo-auto-update": False, "rules": ["MATCH,DIRECT"], "proxies": [proxy], "listeners": [{"name": network, "type": "tunnel", "listen": "127.0.0.1", "port": str(local), "network": [network], "target": h.endpoint(target_host, target_port), "proxy": "relay"} for network in ["tcp", "udp"]]}


async def start(args, kind, direction, config, log, host, port, work):
    handle = log.open("wb")
    os.chmod(log, 0o600)
    readiness = None
    readiness_port = None
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
        command = [sys.executable, str(Path(__file__).with_name("shadowsocksr_reference.py")), "--reference", args.reference_source, "--role", direction, "--config", str(config)]
    elif kind == "mihomo":
        command = [args.peer, "-d", str(work), "-f", str(config)]
    else:
        command = [args.kerlico if kind == "own" else args.peer, "run", "-c", str(config)]
    process = None
    try:
        process = subprocess.Popen(command, stdout=handle, stderr=handle, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        if kind == "mihomo":
            await listening(process, port)
            await proxy_ready(process, json.loads(config.read_text()))
            attempts = await direct_ready(process, readiness_port)
            h.save(work, "readiness.json", {"direct_attempts": attempts, "proxy_present": True})
        else:
            await h.ready(process, host, port)
    except BaseException:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                await asyncio.to_thread(process.wait, timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                await asyncio.to_thread(process.wait)
        handle.close()
        raise
    finally:
        if readiness is not None:
            readiness.close()
            await readiness.wait_closed()
    return process, handle, kind


async def listening(process, port):
    """worker 通过自有进程的监听 inode 就绪，避免探测连接触发参考端额外协议会话。"""
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("参考进程启动失败")
        inodes = set()
        for descriptor in Path(f"/proc/{process.pid}/fd").iterdir():
            try:
                link = os.readlink(descriptor)
                if link.startswith("socket:["):
                    inodes.add(link[8:-1])
            except FileNotFoundError:
                pass
        for table in ["tcp", "tcp6"]:
            for line in Path(f"/proc/{process.pid}/net/{table}").read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port and fields[9] in inodes:
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
    if args.peer_kind == "mihomo" and "client" in args.directions.split(","):
        raise RuntimeError("mihomo 仅可验证 kerlico 服务端方向，必须显式选择 --directions server")
    if args.peer_kind == "python" and not args.reference_source:
        raise RuntimeError("Python 对端需要固定只读源码目录")
    if args.target_greeting and args.peer_kind == "python":
        raise RuntimeError("目标先发工具模式当前用于透明转发入口")
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
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
    summary = {"peer_kind": args.peer_kind, "records": records, "passed": sum(record["pass"] for record in records), "failed": sum(not record["pass"] for record in records)}
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
