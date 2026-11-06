"""仅在 worker 验收 Hysteria2 正式 CLI 与固定参考对端的双向矩阵。"""
from config_v2 import bind_members
import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess


def helpers():
    spec = importlib.util.spec_from_file_location("shadowsocks_interop", Path(__file__).with_name("interop_shadowsocks.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = helpers()


def udp_port(host):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def material(root):
    cert, key = root / "certificate.pem", root / "private-key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth", "-keyout", str(key), "-out", str(cert)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    os.chmod(key, 0o600)
    os.chmod(cert, 0o600)
    return cert, key


BANDWIDTH = None


def options(host, port, auth, cert, obfs, congestion):
    value = {"server": {"host": host, "port": port}, "auth": auth, "tls": {"server_name": "localhost", "ca_pem": cert.read_text()}, "salamander_password": obfs, "limits": {"congestion": congestion}}
    if BANDWIDTH:
        value.update(up=f"{BANDWIDTH} Mbps", down=f"{BANDWIDTH} Mbps")
    return value


def server_options(auth, cert, key, obfs, congestion):
    value = {"auth": auth, "tls": {"certificate_file": str(cert), "private_key_file": str(key)}, "salamander_password": obfs, "limits": {"congestion": congestion}}
    if BANDWIDTH:
        value.update(up=f"{BANDWIDTH} Mbps", down=f"{BANDWIDTH} Mbps")
    return value


def kerlico_server(host, port, auth, cert, key, obfs, congestion):
    config = {"version": 2, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [{"tag": "node", "type": "hysteria2", "listen": h.endpoint(host, port), "outbound": "direct", "options": server_options(auth, cert, key, obfs, congestion)}], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 5000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65507}}
    node = config["nodes"][0]
    bind_members(config, node, [{"auth": node["options"].pop("auth")}])
    return config


def kerlico_client(forward, host, port, target_host, target_port, auth, cert, obfs, congestion):
    return {"version": 2, "outbounds": [{"tag": "proxy", "type": "hysteria2", "options": options(host, port, auth, cert, obfs, congestion)}], "nodes": [], "inbounds": [{"tag": network, "type": network + "-forward", "listen": h.endpoint("127.0.0.1", forward), "target": {"host": target_host, "port": target_port}, "outbound": "proxy"} for network in ["tcp", "udp"]], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 5000, "drain_timeout_ms": 500, "max_sessions": 128, "max_datagram_size": 65507}}


def peer_config(kind, direction, host, port, forward, target_host, target_port, auth, cert, key, obfs, congestion):
    if kind == "kerlico":
        return kerlico_server(host, port, auth, cert, key, obfs, congestion) if direction == "server" else kerlico_client(forward, host, port, target_host, target_port, auth, cert, obfs, congestion)
    if kind == "native":
        if direction == "server":
            config = {"listen": h.endpoint(host, port), "tls": {"cert": str(cert), "key": str(key)}, "auth": {"type": "password", "password": auth}, "ignoreClientBandwidth": not BANDWIDTH}
        else:
            config = {"server": h.endpoint(host, port), "auth": auth, "tls": {"sni": "localhost", "ca": str(cert)}, "tcpForwarding": [{"listen": h.endpoint("127.0.0.1", forward), "remote": h.endpoint(target_host, target_port)}], "udpForwarding": [{"listen": h.endpoint("127.0.0.1", forward), "remote": h.endpoint(target_host, target_port), "timeout": "5s"}]}
        if BANDWIDTH:
            config["bandwidth"] = {"up": f"{BANDWIDTH} mbps", "down": f"{BANDWIDTH} mbps"}
        if obfs:
            config["obfs"] = {"type": "salamander", "salamander": {"password": obfs}}
        return config
    if kind == "mihomo":
        if direction != "server":
            raise ValueError("mihomo 只作为服务端")
        listener = {"name": "hy2-in", "type": "hysteria2", "listen": host, "port": port, "users": {"user": auth}, "certificate": str(cert), "private-key": str(key), "alpn": ["h3"]}
        if BANDWIDTH:
            listener.update({"up": BANDWIDTH, "down": BANDWIDTH, "ignore-client-bandwidth": False})
        if obfs:
            listener.update({"obfs": "salamander", "obfs-password": obfs})
        return {"mode": "direct", "log-level": "error", "ipv6": True, "listeners": [listener]}
    if kind == "sing-box":
        if direction == "server":
            inbound = {"type": "hysteria2", "listen": host, "listen_port": port, "users": [{"password": auth}], "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}}
            if obfs:
                inbound["obfs"] = {"type": "salamander", "password": obfs}
            return {"log": {"disabled": True}, "inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}]}
        outbound = {"type": "hysteria2", "tag": "proxy", "server": host, "server_port": port, "password": auth, "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)}}
        if obfs:
            outbound["obfs"] = {"type": "salamander", "password": obfs}
        return {"log": {"disabled": True}, "inbounds": [{"type": "direct", "listen": "127.0.0.1", "listen_port": forward, "override_address": target_host, "override_port": target_port}], "outbounds": [outbound]}
    stream = {"network": "hysteria", "security": "tls", "hysteriaSettings": {"version": 2}}
    if obfs:
        stream["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": obfs}}]}
    if direction == "server":
        stream["tlsSettings"] = {"alpn": ["h3"], "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}
        return {"log": {"loglevel": "none"}, "inbounds": [{"listen": host, "port": port, "protocol": "hysteria", "settings": {"version": 2, "users": [{"auth": auth}]}, "streamSettings": stream}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": [target_host + ("/128" if ":" in target_host else "/32")], "port": str(target_port)}]}}]}
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    stream["tlsSettings"] = {"serverName": "localhost", "alpn": ["h3"], "pinnedPeerCertSha256": pin}
    stream["hysteriaSettings"]["auth"] = auth
    return {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": forward, "protocol": "dokodemo-door", "settings": {"address": target_host, "port": target_port, "network": "tcp,udp"}}], "outbounds": [{"protocol": "hysteria", "settings": {"version": 2, "address": host, "port": port}, "streamSettings": stream}]}


async def bulk(forward, size):
    """经转发入口回显 size 字节，返回 MiB/s；设置带宽时双方 Brutal 把速率限在协商值附近。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", forward)
    data = os.urandom(size)
    loop = asyncio.get_running_loop()
    started = loop.time()

    async def send():
        writer.write(data)
        await writer.drain()

    sender = asyncio.create_task(send())
    try:
        got = await asyncio.wait_for(reader.readexactly(size), 60)
        await sender
    finally:
        writer.close()
        await writer.wait_closed()
    if got != data:
        raise RuntimeError("TCP 内容不符")
    return round(size / 1048576 / (loop.time() - started), 2)


async def client_first(forward):
    """客户端先发短请求；Mihomo 服务端在目标回写前不发 TCP 响应，客户端不能先等响应。"""
    reader, writer = await asyncio.open_connection("127.0.0.1", forward)
    try:
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        writer.write(request)
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(len(request)), 4) != request:
            raise RuntimeError("TCP 内容不符")
    finally:
        writer.close()
        await writer.wait_closed()


async def start(binary, kind, direction, config, log, forward):
    handle = log.open("wb")
    os.chmod(log, 0o600)
    if kind == "native":
        command = [binary, direction, "--disable-update-check", "--log-level", "error", "--config", str(config)]
    elif kind == "mihomo":
        command = [binary, "-d", str(config.parent), "-f", str(config)]
    elif kind == "xray":
        command = [binary, "run", "-config", str(config)]
    else:
        command = [binary, "run", "-c", str(config)]
    process = subprocess.Popen(command, stdout=handle, stderr=handle)
    try:
        if direction == "client":
            await h.ready(process, "127.0.0.1", forward)
        else:
            await asyncio.sleep(0.15)
            if process.poll() is not None:
                raise RuntimeError("QUIC 服务进程启动失败")
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
    return process, handle


async def main(args):
    os.umask(0o077)
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    cert, key = material(root)
    records = []
    for congestion in args.congestion.split(","):
        for mode in args.modes.split(","):
            for host in args.node_hosts.split(","):
                for target_host in args.target_hosts.split(","):
                    target_port = h.port(target_host)
                    tcp = await asyncio.start_server(h.echo, target_host, target_port)
                    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(h.UdpEcho, local_addr=(target_host, target_port))
                    try:
                        for direction in args.directions.split(","):
                            label = f"{direction}-{mode}-{congestion}-node{'6' if ':' in host else '4'}-target{'6' if ':' in target_host else '4'}"
                            port, forward = udp_port(host), h.port()
                            auth = "synthetic-" + os.urandom(16).hex()
                            obfs = "synthetic-salamander-password" if mode == "salamander" else None
                            if direction == "client":
                                server = peer_config(args.peer_kind, "server", host, port, forward, target_host, target_port, auth, cert, key, obfs, congestion)
                                client = kerlico_client(forward, host, port, target_host, target_port, auth, cert, obfs, congestion)
                                server_kind, client_kind, server_binary, client_binary = args.peer_kind, "kerlico", args.peer, args.kerlico
                            else:
                                server = kerlico_server(host, port, auth, cert, key, obfs, congestion)
                                client = peer_config(args.peer_kind, "client", host, port, forward, target_host, target_port, auth, cert, key, obfs, congestion)
                                server_kind, client_kind, server_binary, client_binary = "kerlico", args.peer_kind, args.kerlico, args.peer
                            active = []
                            try:
                                active.append(await start(server_binary, server_kind, "server", h.save(root, label + "-server.json", server), root / (label + "-server.log"), forward))
                                active.append(await start(client_binary, client_kind, "client", h.save(root, label + "-client.json", client), root / (label + "-client.log"), forward))
                                for size in ["client-first", None] + [int(size) for size in args.udp_sizes.split(",")]:
                                    record = {"case": label, "network": "tcp-client-first" if size == "client-first" else "tcp" if size is None else "udp"}
                                    if isinstance(size, int):
                                        record["payload_bytes"] = size
                                    try:
                                        await (client_first(forward) if size == "client-first" else h.tcp(forward) if size is None else h.udp(forward, b"u" * size))
                                        record["pass"] = True
                                    except Exception as error:
                                        record.update({"pass": False, "error": type(error).__name__})
                                    records.append(record)
                                    print(json.dumps(record, ensure_ascii=False), flush=True)
                                if BANDWIDTH:
                                    record = {"case": label, "network": "bulk", "payload_bytes": 8 << 20, "limit_mib_s": round(BANDWIDTH * 1e6 / 8 / 1048576, 2)}
                                    try:
                                        record["mib_s"] = await bulk(forward, 8 << 20)
                                        record["pass"] = True
                                    except Exception as error:
                                        record.update({"pass": False, "error": type(error).__name__})
                                    records.append(record)
                                    print(json.dumps(record, ensure_ascii=False), flush=True)
                            except Exception as error:
                                records.append({"case": label, "network": "startup", "pass": False, "error": type(error).__name__})
                            finally:
                                for process, handle in reversed(active):
                                    try:
                                        await h.stop(process, handle)
                                    except Exception as error:
                                        records.append({"case": label, "network": "shutdown", "pass": False, "error": type(error).__name__})
                    finally:
                        udp.close()
                        tcp.close()
                        await tcp.wait_closed()
    summary = {"peer_kind": args.peer_kind, "bandwidth_mbps": BANDWIDTH, "records": records, "passed": sum(record["pass"] for record in records), "failed": sum(not record["pass"] for record in records)}
    h.save(root, "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hysteria2 双端与原生 UDP 互通矩阵")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--peer-kind", choices=["kerlico", "xray", "sing-box", "native", "mihomo"], required=True)
    parser.add_argument("--bandwidth", type=int, default=0, help="双方 up/down，Mbit/s；0 为不设（服务端忽略客户端带宽）")
    parser.add_argument("--work", required=True)
    parser.add_argument("--directions", default="client,server")
    parser.add_argument("--modes", default="native,salamander")
    parser.add_argument("--congestion", default="bbr,reno")
    parser.add_argument("--node-hosts", default="127.0.0.1,::1")
    parser.add_argument("--target-hosts", default="127.0.0.1,::1")
    parser.add_argument("--udp-sizes", default="3,2000,4000")
    arguments = parser.parse_args()
    BANDWIDTH = arguments.bandwidth
    asyncio.run(main(arguments))
