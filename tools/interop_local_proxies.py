"""仅在 worker 上验证 SOCKS/HTTP 正式 CLI 与固定 sing-box 对端。"""
import argparse
import asyncio
import json
import os
import socket
from pathlib import Path
import subprocess

from interop_shadowsocks import port, endpoint, save, limits, echo, UdpEcho, start, stop, tcp


async def udp(number, payload):
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        await loop.sock_sendto(sock, payload, ("127.0.0.1", number))
        got, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 4)
        if got != b"echo|" + payload:
            raise RuntimeError("UDP 内容不符")


async def reference_baseline(args, root):
    records = []
    for host in ["127.0.0.1", "::1"]:
        target_port, forward = port(host), port()
        target, _ = await asyncio.get_running_loop().create_datagram_endpoint(UdpEcho, local_addr=(host, target_port))
        config = {"log": {"disabled": True}, "inbounds": [{"type": "direct", "tag": "entry", "listen": "127.0.0.1", "listen_port": forward, "override_address": host, "override_port": target_port}], "outbounds": [{"type": "direct", "tag": "direct"}]}
        label = "reference-baseline-" + ("6" if ":" in host else "4")
        active = None
        try:
            active = await start(args.peer, "sing-box", save(root, label + ".json", config), root / (label + ".log"), "127.0.0.1", forward)
            for size in [3, 12000, 0]:
                try:
                    await udp(forward, b"x" * size)
                    records.append({"target": host, "size": size, "pass": True})
                except Exception as error:
                    records.append({"target": host, "size": size, "pass": False, "error": type(error).__name__})
        finally:
            if active:
                await stop(*active)
            target.close()
    return records


def kernel_server(protocol, version, host, number, username, password, tls):
    options = {}
    if protocol == "socks":
        options["version"] = version
    if protocol == "http" or version == "5":
        options["auth"] = {"username": username, "password": password}
    if tls:
        options["tls"] = {"cert_pem": tls[0].read_text(), "key_pem": tls[1].read_text()}
    field = "local_inbounds" if protocol == "socks" and version != "5" else "nodes"
    return {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], field: [{"tag": "proxy", "type": protocol, "listen": endpoint(host, number), "outbound": "direct", "options": options}], "limits": limits()}


def peer_server(protocol, version, host, number, username, password, tls):
    entry = {"type": protocol, "tag": "proxy", "listen": host, "listen_port": number}
    if protocol == "http" or version == "5":
        entry["users"] = [{"username": username, "password": password}]
    if tls:
        entry["tls"] = {"enabled": True, "certificate_path": str(tls[0]), "key_path": str(tls[1])}
    return {"log": {"disabled": True}, "inbounds": [entry], "outbounds": [{"type": "direct", "tag": "direct"}]}


def client_options(protocol, version, host, number, username, password, tls, kernel):
    if kernel:
        options = {"server": {"host": host, "port": number}}
        if protocol == "socks":
            options["version"] = version
        if protocol == "http" or version == "5":
            options["auth"] = {"username": username, "password": password}
        if tls:
            options["tls"] = {"server_name": "localhost", "ca_pem": tls[0].read_text()}
    else:
        options = {"type": protocol, "tag": "proxy", "server": host, "server_port": number}
        if protocol == "socks":
            options["version"] = version
        if protocol == "http" or version == "5":
            options.update(username=username, password=password)
        if tls:
            options["tls"] = {"enabled": True, "server_name": "localhost", "certificate_path": str(tls[0])}
    return options


def client(protocol, version, host, number, forward, target_host, target_port, username, password, tls, kernel):
    options = client_options(protocol, version, host, number, username, password, tls, kernel)
    if kernel:
        networks = ["tcp", "udp"] if protocol == "socks" and version == "5" else ["tcp"]
        return {"version": 1, "outbounds": [{"tag": "proxy", "type": protocol, "options": options}], "inbounds": [{"tag": network, "type": network + "-forward", "listen": endpoint("127.0.0.1", forward), "target": {"host": target_host, "port": target_port}, "outbound": "proxy"} for network in networks], "limits": limits()}
    return {"log": {"disabled": True}, "inbounds": [{"type": "direct", "tag": "entry", "listen": "127.0.0.1", "listen_port": forward, "override_address": target_host, "override_port": target_port}], "outbounds": [options]}


async def main(args):
    root = Path(args.work).resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    cert, key = root / "node.crt", root / "node.key"
    with (root / "certificate.log").open("wb") as log:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-days", "1"], stdout=log, stderr=log, check=True)
    for path in [cert, key, root / "certificate.log"]:
        os.chmod(path, 0o600)
    baseline = await reference_baseline(args, root)
    records = []
    for protocol, version, secure in [("socks", "4", False), ("socks", "4a", False), ("socks", "5", False), ("http", "1.1", False), ("http", "1.1", True)]:
        if protocol not in args.protocols.split(","):
            continue
        for host in ["127.0.0.1", "::1"]:
            for target_host in ["127.0.0.1", "::1"]:
                if protocol == "socks" and version != "5" and target_host == "::1":
                    continue
                target_port = port(target_host)
                tcp_target = await asyncio.start_server(echo, target_host, target_port)
                udp_target, _ = await asyncio.get_running_loop().create_datagram_endpoint(UdpEcho, local_addr=(target_host, target_port))
                try:
                    for direction in ["client", "server"]:
                        label = f"{protocol}-{version}-tls{int(secure)}-{direction}-node{'6' if ':' in host else '4'}-target{'6' if ':' in target_host else '4'}"
                        number, forward = port(host), port()
                        username, password = "proxy-test", "synthetic-" + os.urandom(16).hex()
                        tls = (cert, key) if secure else None
                        own_client = direction == "client"
                        server = peer_server(protocol, version, host, number, username, password, tls) if own_client else kernel_server(protocol, version, host, number, username, password, tls)
                        outgoing = client(protocol, version, host, number, forward, target_host, target_port, username, password, tls, own_client)
                        active = []
                        try:
                            server_file = save(root, label + "-server.json", server)
                            client_file = save(root, label + "-client.json", outgoing)
                            active.append(await start(args.peer if own_client else args.kerlico, "sing-box" if own_client else "kerlico", server_file, root / (label + "-server.log"), host, number))
                            active.append(await start(args.kerlico if own_client else args.peer, "kerlico" if own_client else "sing-box", client_file, root / (label + "-client.log"), "127.0.0.1", forward))
                            checks = [("tcp", None)]
                            if protocol == "socks" and version == "5":
                                checks.extend(("udp", size) for size in [3, 12000, 0])
                            for network, size in checks:
                                record = {"case": label, "network": network, "size": size}
                                try:
                                    if network == "tcp":
                                        await tcp(forward)
                                    else:
                                        await udp(forward, b"u" * size)
                                    records.append(dict(record, **{"pass": True}))
                                except Exception as error:
                                    control = [item for item in baseline if item["target"] == target_host]
                                    reference_drops_empty = any(item["size"] == 0 and not item["pass"] for item in control) and all(item["pass"] for item in control if item["size"] != 0)
                                    data_passed = all(any(item["case"] == label and item["network"] == "udp" and item.get("size") == count and item["pass"] is True for item in records) for count in [3, 12000])
                                    if direction == "server" and size == 0 and reference_drops_empty and data_passed and isinstance(error, TimeoutError):
                                        records.append(dict(record, **{"pass": None, "status": "reference_ingress_limited", "error": type(error).__name__}))
                                    else:
                                        records.append(dict(record, **{"pass": False, "error": type(error).__name__}))
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
    summary = {"peer_kind": "sing-box", "reference_baseline": baseline, "records": records, "passed": sum(item["pass"] is True for item in records), "failed": sum(item["pass"] is False for item in records), "reference_limited": sum(item["pass"] is None for item in records)}
    save(root, "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOCKS 与 HTTP 代理双向互通")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--protocols", default="socks,http")
    asyncio.run(main(parser.parse_args()))
