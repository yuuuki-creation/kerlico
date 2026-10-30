"""在 worker 上运行固定对端互通；配置及原始日志仅保留在调用者私有工作区。"""
import argparse
import asyncio
import base64
import json
import os
from pathlib import Path
import socket
import subprocess

METHODS = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]

def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]

def key(method, value):
    return base64.b64encode(bytes([value]) * (16 if "aes-128" in method else 32)).decode()

class Echo(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, packet, peer):
        self.transport.sendto(packet, peer)

async def echo_tcp(reader, writer):
    try:
        while packet := await reader.read(16384):
            writer.write(packet)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()

def upstream_config(core, role, method, port, ss_port, target_port, service, user, multi, target_host="127.0.0.1"):
    password = service + ":" + user if multi else user
    if core == "sing-box":
        if role == "server":
            inbound = {"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ss_port, "method": method, "password": service if multi else user}
            if multi:
                inbound["users"] = [{"name": "test-user", "password": user}]
            return {"log": {"disabled": True}, "inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}]}
        return {"log": {"disabled": True}, "inbounds": [{"type": "direct", "listen": "127.0.0.1", "listen_port": port, "override_address": target_host, "override_port": target_port}], "outbounds": [{"type": "shadowsocks", "tag": "ss", "server": "127.0.0.1", "server_port": ss_port, "method": method, "password": password}]}
    if role == "server":
        settings = {"method": method, "password": service if multi else user, "network": "tcp,udp"}
        if multi:
            settings["clients"] = [{"password": user}]
        return {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": ss_port, "protocol": "shadowsocks", "settings": settings}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": [target_host + ("/128" if ":" in target_host else "/32")], "port": str(target_port)}]}}]}
    return {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door", "settings": {"address": target_host, "port": target_port, "network": "tcp,udp"}}], "outbounds": [{"protocol": "shadowsocks", "settings": {"address": "127.0.0.1", "port": ss_port, "method": method, "password": password}}]}

async def wait_ready(port, processes):
    for _ in range(100):
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("对端进程提前退出")
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError("监听未就绪")

async def check_tcp(port, payload_size=131072):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    payload = (bytes(range(256)) * ((payload_size + 255) // 256))[:payload_size]
    writer.write(payload)
    await writer.drain()
    received = bytearray()
    deadline = asyncio.get_running_loop().time() + 5
    while len(received) < len(payload):
        try:
            chunk = await asyncio.wait_for(reader.read(len(payload) - len(received)), max(0.001, deadline - asyncio.get_running_loop().time()))
        except asyncio.TimeoutError as error:
            writer.close()
            raise RuntimeError(f"TCP 超时，已收到 {len(received)}/{len(payload)} 字节") from error
        if not chunk:
            raise RuntimeError(f"TCP 提前关闭，已收到 {len(received)}/{len(payload)} 字节")
        received.extend(chunk)
    if received != payload:
        raise RuntimeError("TCP 负载不匹配")
    writer.close()
    await writer.wait_closed()

async def check_udp(port, payload_size=8192):
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.setblocking(False)
        for payload in [b"ss2022", (bytes(range(256)) * ((payload_size + 255) // 256))[:payload_size]]:
            await loop.sock_sendto(udp, payload, ("127.0.0.1", port))
            try:
                received, _ = await asyncio.wait_for(loop.sock_recvfrom(udp, 65536), 5)
            except asyncio.TimeoutError as error:
                raise RuntimeError(f"UDP {len(payload)} 字节负载超时") from error
            if received != payload:
                raise RuntimeError("UDP 负载不匹配")

async def main(args):
    results = []
    versions = {}
    for label, binary, expected in [("sing-box", args.sing_box, "1.14.4"), ("xray", args.xray, "26.10.29")]:
        version = subprocess.check_output([binary, "version"], text=True).splitlines()[0]
        if expected not in version:
            raise RuntimeError("固定对端版本不匹配")
        versions[label] = version
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    (root / "versions.json").write_text(json.dumps(versions, ensure_ascii=False, indent=2))
    echo_port = free_port()
    tcp = await asyncio.start_server(echo_tcp, "127.0.0.1", echo_port)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=("127.0.0.1", echo_port))
    echo6_port = free_port()
    tcp6 = await asyncio.start_server(echo_tcp, "::1", echo6_port)
    transport6, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=("::1", echo6_port))
    try:
        for family, target_host, target_port in [("v4", "127.0.0.1", echo_port), ("v6", "::1", echo6_port)]:
            if args.family != "both" and family != args.family:
                continue
            for core, binary in [("sing-box", args.sing_box), ("xray", args.xray)]:
                if args.core != "both" and core != args.core:
                    continue
                for method in METHODS:
                    for multi in [False, True]:
                        if multi and "chacha" in method:
                            continue
                        for role in ["client", "server"]:
                            name = f"{core}-{family}-{method}-{'eih' if multi else 'single'}-rust-{role}"
                            work = root / name
                            work.mkdir(mode=0o700, exist_ok=True)
                            ss_port, forward_port = free_port(), free_port()
                            user, service = key(method, 11), key(method, 22)
                            rust = {"method": method, "key": user if role == "client" or not multi else service}
                            if role == "client":
                                rust.update(server="127.0.0.1", port=ss_port, identity_keys=[service] if multi else [])
                            else:
                                rust["users"] = [user] if multi else []
                            upstream = upstream_config(core, "server" if role == "client" else "client", method, forward_port, ss_port, target_port, service, user, multi, target_host)
                            if args.debug_peers:
                                upstream["log"] = {"loglevel": "debug"} if core == "xray" else {"level": "debug"}
                            rust_file, peer_file = work / "rust.json", work / "peer.json"
                            rust_file.write_text(json.dumps(rust))
                            peer_file.write_text(json.dumps(upstream))
                            os.chmod(rust_file, 0o600)
                            os.chmod(peer_file, 0o600)
                            peer_cmd = [binary, "run", "-c", str(peer_file)]
                            rust_cmd = [args.peer, role, str(rust_file), f"127.0.0.1:{forward_port if role == 'client' else ss_port}"]
                            if role == "client":
                                rust_cmd += [target_host, str(target_port)]
                            processes = []
                            logs = []
                            result = {"case": name}
                            try:
                                for index, command in enumerate([peer_cmd, rust_cmd]):
                                    log = (work / f"process-{index}.log").open("wb")
                                    logs.append(log)
                                    processes.append(subprocess.Popen(command, stdout=log, stderr=log))
                                await wait_ready(ss_port, processes)
                                await wait_ready(forward_port, processes)
                                await check_tcp(forward_port, args.tcp_size)
                                result["tcp"] = "pass"
                                await check_udp(forward_port, args.udp_size)
                                result["udp"] = "pass"
                            except Exception as error:
                                result["error"] = type(error).__name__ + ": " + str(error)
                            finally:
                                for process in processes:
                                    process.terminate()
                                for process in processes:
                                    try:
                                        process.wait(timeout=3)
                                    except subprocess.TimeoutExpired:
                                        process.kill()
                                        process.wait()
                                for log in logs:
                                    log.close()
                            results.append(result)
                            print(json.dumps(result, ensure_ascii=False), flush=True)
        (root / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    finally:
        tcp.close()
        await tcp.wait_closed()
        transport.close()
        tcp6.close()
        await tcp6.wait_closed()
        transport6.close()
    if any("error" in result for result in results):
        raise SystemExit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--xray", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--core", choices=["both", "sing-box", "xray"], default="both")
    parser.add_argument("--family", choices=["both", "v4", "v6"], default="both")
    parser.add_argument("--tcp-size", type=int, default=131072)
    parser.add_argument("--udp-size", type=int, default=8192)
    parser.add_argument("--debug-peers", action="store_true")
    asyncio.run(main(parser.parse_args()))
