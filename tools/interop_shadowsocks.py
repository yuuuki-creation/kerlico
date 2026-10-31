"""仅在 worker 项目区验证 Shadowsocks 正式 CLI 与独立参考对端。"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import signal
import socket
import subprocess


METHODS = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]


def port(host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def endpoint(host, number):
    return f"[{host}]:{number}" if ":" in host else f"{host}:{number}"


def save(root, name, value):
    path = root / name
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    os.chmod(path, 0o600)
    return path


def limits():
    return {"connect_timeout_ms": 2500, "idle_timeout_ms": 5000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65000}


def kerlico_server(host, number, method, secret):
    entry_kind = "local_inbounds" if method in {"none", "plain"} else "nodes"
    return {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], entry_kind: [{"tag": "node", "type": "shadowsocks", "listen": endpoint(host, number), "outbound": "direct", "options": {"method": method, "password": secret, "allow_insecure": True}}], "limits": limits()}


def kerlico_client(number, peer_host, peer_port, target_host, target_port, method, secret):
    return {"version": 1, "outbounds": [{"tag": "proxy", "type": "shadowsocks", "options": {"server": peer_host, "port": peer_port, "method": method, "password": secret, "allow_insecure": True}}], "inbounds": [{"tag": network, "type": network + "-forward", "listen": endpoint("127.0.0.1", number), "target": {"host": target_host, "port": target_port}, "outbound": "proxy"} for network in ["tcp", "udp"]], "nodes": [], "limits": limits()}


def peer_server(kind, host, number, method, secret, target_host, target_port):
    if kind == "xray":
        return {"log": {"loglevel": "none"}, "inbounds": [{"listen": host, "port": number, "protocol": "shadowsocks", "settings": {"method": method, "password": secret, "network": "tcp,udp"}}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": [target_host + ("/128" if ":" in target_host else "/32")], "port": str(target_port)}]}}]}
    return {"log": {"disabled": True}, "inbounds": [{"type": "shadowsocks", "tag": "in", "listen": host, "listen_port": number, "method": method, "password": secret}], "outbounds": [{"type": "direct", "tag": "direct"}]}


def peer_client(kind, number, peer_host, peer_port, target_host, target_port, method, secret):
    if kind == "xray":
        return {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": number, "protocol": "dokodemo-door", "settings": {"address": target_host, "port": target_port, "network": "tcp,udp"}}], "outbounds": [{"protocol": "shadowsocks", "settings": {"address": peer_host, "port": peer_port, "method": method, "password": secret}}]}
    return {"log": {"disabled": True}, "inbounds": [{"type": "direct", "tag": "in", "listen": "127.0.0.1", "listen_port": number, "override_address": target_host, "override_port": target_port}], "outbounds": [{"type": "shadowsocks", "tag": "proxy", "server": peer_host, "server_port": peer_port, "method": method, "password": secret}]}


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, peer):
        self.transport.sendto(b"echo|" + data, peer)


async def echo(reader, writer):
    try:
        while data := await reader.read(16384):
            writer.write(data)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        await writer.drain()
    except (OSError, ConnectionError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def ready(process, host, number):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("参考进程启动失败")
        try:
            _, writer = await asyncio.open_connection(host, number)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.03)
    raise RuntimeError("进程监听未就绪")


async def start(binary, kind, config, log, host, number):
    handle = log.open("wb")
    os.chmod(log, 0o600)
    command = [binary, "run", "-c", str(config)] if kind != "xray" else [binary, "run", "-config", str(config)]
    process = subprocess.Popen(command, stdout=handle, stderr=handle)
    try:
        await ready(process, host, number)
        return process, handle
    except BaseException:
        if process.poll() is None:
            process.terminate()
        try:
            await asyncio.to_thread(process.wait, timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            await asyncio.to_thread(process.wait)
        handle.close()
        raise


async def stop(process, handle):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        await asyncio.to_thread(process.wait, timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        await asyncio.to_thread(process.wait)
        raise RuntimeError("进程未按时退出")
    finally:
        handle.close()
    if process.returncode != 0:
        raise RuntimeError("进程退出状态非零")


async def tcp(number):
    reader, writer = await asyncio.open_connection("127.0.0.1", number)
    try:
        payload = b"shadowsocks-interoperability|" * 2048
        writer.write(payload)
        await writer.drain()
        got = await asyncio.wait_for(reader.readexactly(len(payload)), 4)
        if got != payload:
            raise RuntimeError("TCP 内容不符")
        # 半关闭能力在包级测试验证；此处允许参考对端使用其自身排空策略。
    finally:
        writer.close()
        await writer.wait_closed()


async def udp(number, payload):
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        await loop.sock_sendto(sock, payload, ("127.0.0.1", number))
        got, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 4)
        if got != b"echo|" + payload:
            raise RuntimeError("UDP 内容不符")


async def main(args):
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    records = []
    for method in args.methods.split(","):
        for node_host in args.node_hosts.split(","):
            for target_host in args.target_hosts.split(","):
                target_port = port(target_host)
                tcp_target = await asyncio.start_server(echo, target_host, target_port)
                udp_target, _ = await asyncio.get_running_loop().create_datagram_endpoint(UdpEcho, local_addr=(target_host, target_port))
                try:
                    for direction in args.directions.split(","):
                        label = f"{method}-{direction}-node{'6' if ':' in node_host else '4'}-target{'6' if ':' in target_host else '4'}"
                        node_port, forward_port = port(node_host), port()
                        secret = "synthetic-" + os.urandom(16).hex()
                        if direction == "client":
                            server = peer_server(args.peer_kind, node_host, node_port, method, secret, target_host, target_port)
                            client = kerlico_client(forward_port, node_host, node_port, target_host, target_port, method, secret)
                            server_binary, server_kind, client_binary, client_kind = args.peer, args.peer_kind, args.kerlico, "kerlico"
                        else:
                            server = kerlico_server(node_host, node_port, method, secret)
                            client = peer_client(args.peer_kind, forward_port, node_host, node_port, target_host, target_port, method, secret)
                            server_binary, server_kind, client_binary, client_kind = args.kerlico, "kerlico", args.peer, args.peer_kind
                        active = []
                        try:
                            server_file = save(root, label + "-server.json", server)
                            client_file = save(root, label + "-client.json", client)
                            active.append(await start(server_binary, server_kind, server_file, root / (label + "-server.log"), node_host, node_port))
                            active.append(await start(client_binary, client_kind, client_file, root / (label + "-client.log"), "127.0.0.1", forward_port))
                            checks = [("tcp", None)] + [("udp", b"u" * int(size)) for size in args.udp_sizes.split(",")]
                            for network, payload in checks:
                                record = {"case": label, "network": network}
                                if payload is not None:
                                    record["payload_bytes"] = len(payload)
                                try:
                                    await (tcp(forward_port) if payload is None else udp(forward_port, payload))
                                    records.append(dict(record, **{"pass": True}))
                                except Exception as error:
                                    records.append(dict(record, **{"pass": False, "error": type(error).__name__}))
                                print(json.dumps(records[-1], ensure_ascii=False), flush=True)
                        except Exception as error:
                            records.append({"case": label, "network": "startup", "pass": False, "error": type(error).__name__})
                        finally:
                            for process, handle in reversed(active):
                                try:
                                    await stop(process, handle)
                                except Exception as error:
                                    records.append({"case": label, "network": "shutdown", "pass": False, "error": type(error).__name__})
                finally:
                    udp_target.close()
                    tcp_target.close()
                    await tcp_target.wait_closed()
    summary = {"peer_kind": args.peer_kind, "records": records, "passed": sum(item["pass"] for item in records), "failed": sum(not item["pass"] for item in records)}
    save(root, "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shadowsocks 双向原生 TCP/UDP 互通矩阵")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--peer-kind", choices=["xray", "sing-box"], required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--methods", default=",".join(METHODS))
    parser.add_argument("--node-hosts", default="127.0.0.1,::1")
    parser.add_argument("--target-hosts", default="127.0.0.1,::1")
    parser.add_argument("--directions", default="client,server")
    parser.add_argument("--udp-sizes", default="3,12000,0")
    asyncio.run(main(parser.parse_args()))
