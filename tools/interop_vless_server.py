#!/usr/bin/env python3
"""用真实 Xray 客户端验证 kerlico 节点；仅在专用 worker 执行。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import time
from types import SimpleNamespace

import interop_vless as h
from interop_vless_matrix import TlsServer, material, tcp, cases

USERS = ["00000000-0000-0000-0000-000000000011", "00000000-0000-0000-0000-000000000012"]


def verify(args, root, materials=None):
    cert, key, tls_context, reality_keys, encryption_keys = materials or material(root,args.reference,args.key_kind)
    decryption = "none" if args.encryption == "none" else "mlkem768x25519plus."+args.encryption+".600s."+encryption_keys[0]
    encryption = "none" if args.encryption == "none" else "mlkem768x25519plus."+args.encryption+"."+args.rtt+"."+encryption_keys[1]
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    checks = []
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        udp = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        inner = TlsServer(("127.0.0.1", 0), h.TcpEcho)
        inner.tls = tls_context
        target_tls = stack.enter_context(h.serve(inner))
        ports = [h.free_port(), h.free_port()]
        cover = TlsServer(("127.0.0.1", 0), h.TcpEcho)
        cover.tls = tls_context
        cover_port = stack.enter_context(h.serve(cover))
        node_security = {"type": args.security}
        peer_security = {"network": "raw" if args.transport == "tcp" else args.transport, "security": args.security}
        if args.security == "tls":
            alpn = {"h1": "http/1.1", "h2": "h2", "h3": "h3"}[args.http] if args.transport == "xhttp" else "h2" if args.transport == "grpc" else "http/1.1"
            node_security.update(certificate_file=str(cert), private_key_file=str(key))
            peer_security["tlsSettings"] = {"serverName": "localhost", "pinnedPeerCertSha256": pin, "alpn": [alpn]}
        elif args.security == "reality":
            node_security.update(cover={"host": "127.0.0.1", "port": cover_port}, private_key=reality_keys[0], server_names=["localhost"], short_ids=["abcd"])
            peer_security["realitySettings"] = {"serverName": "localhost", "password": reality_keys[1], "shortId": "abcd", "fingerprint": "chrome"}
        transport = {"type": args.transport}
        if args.transport in ("ws", "httpupgrade"):
            transport["path"] = "/kerlico"
            peer_security[args.transport+"Settings"] = {"path": "/kerlico", "host": "localhost"}
        elif args.transport == "grpc":
            transport["service_name"] = "kerlico"
            peer_security["grpcSettings"] = {"serviceName": "kerlico", "multiMode": args.multi}
        elif args.transport == "xhttp":
            transport["settings"] = {"path": "/kerlico", "mode": args.mode, "http_version": args.http}
            peer_security["xhttpSettings"] = {"path": "/kerlico", "mode": args.mode}
        nodes = [{"tag": "node"+str(i), "type": "vless", "listen": ("127.0.0.1:" if i == 0 else "[::1]:")+str(ports[i]), "outbound": "direct", "max_sessions": 32, "options": {"uuid": USERS[i], "flow": "xtls-rprx-vision" if args.vision else "", "security": node_security, "transport": transport}} for i in range(2)]
        for node in nodes:
            node["options"]["decryption"] = decryption
        config = {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": nodes, "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 6000, "drain_timeout_ms": 300, "max_sessions": 64}}
        server_path = root / "kerlico-server.json"
        h.write_json(server_path, config)
        server_args = [args.kerlico, "run", "-c", str(server_path)]
        if args.control_server:
            control_stream=dict(peer_security)
            if args.security=="tls":control_stream["tlsSettings"]={"alpn":[alpn],"certificates":[{"certificateFile":str(cert),"keyFile":str(key)}]}
            elif args.security=="reality":control_stream["realitySettings"]={"target":"127.0.0.1:"+str(cover_port),"privateKey":reality_keys[0],"serverNames":["localhost"],"shortIds":["abcd"]}
            control = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1" if i == 0 else "::1", "port": ports[i], "protocol": "vless", "settings": {"clients": [{"id": USERS[i], "flow": "xtls-rprx-vision" if args.vision else ""}], "decryption": decryption}, "streamSettings": control_stream} for i in range(2)], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32", "::1/128"], "port": ",".join(map(str, [target4, target6, udp, target_tls]))}]}}]}
            control_path = root / "xray-control-server.json"
            h.write_json(control_path, control)
            server_args = [args.reference, "run", "-config", str(control_path)]
        with h.process(server_args, root, "kerlico-server") as server:
            if args.transport == "xhttp" and args.http == "h3":
                time.sleep(0.2)
                if server.poll() is not None:
                    raise RuntimeError("HTTP/3 节点未启动")
            else:
                h.wait_ready(server, ports[0])
            for i in range(2):
                for invalid in (False, True):
                    label = "node"+str(i)+("-wrong-credential" if invalid else "-valid")
                    directory = root / label
                    directory.mkdir(mode=0o700)
                    local4, local6, local_udp, local_tls = [h.free_port() for _ in range(4)]
                    rules = [("tcp4", "tcp", local4, "127.0.0.1", target4), ("tcp6", "tcp", local6, "::1", target6), ("udp", "udp", local_udp, "127.0.0.1", udp), ("tls", "tcp", local_tls, "127.0.0.1", target_tls)]
                    outbound = {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1" if i == 0 else "::1", "port": ports[i], "users": [{"id": USERS[1-i] if invalid else USERS[i], "flow": "xtls-rprx-vision" if args.vision else "", "encryption": encryption}]}]}, "streamSettings": peer_security, "mux": {"enabled": args.mux, "concurrency": -1 if args.vision or args.transport=="xhttp" else 4, "xudpConcurrency": 4 if args.vision or args.mux or args.xudp else -1}}
                    client_config = {"log": {"loglevel": "debug"}, "inbounds": [{"tag": tag, "listen": "127.0.0.1", "port": local, "protocol": "tunnel", "settings": {"address": host, "port": target, "network": network}} for tag, network, local, host, target in rules], "outbounds": [outbound]}
                    path = directory / "xray-client.json"
                    h.write_json(path, client_config)
                    check = subprocess.run([args.reference, "run", "-test", "-config", str(path)], capture_output=True, timeout=10)
                    (directory / "reference-check.log").write_bytes(check.stdout+check.stderr)
                    if check.returncode:
                        raise RuntimeError("参考客户端配置拒绝")
                    with h.process([args.reference, "run", "-config", str(path)], directory, "xray-client") as client:
                        h.wait_ready(client, local4)
                        if invalid:
                            try:
                                value = tcp(local4, b"must-not-pass-credential-boundary")
                            except (OSError, TimeoutError):
                                value = b""
                            if value:
                                raise RuntimeError("两个节点错误地互相接受了凭据")
                            checks.append(label+"：跨节点凭据被拒绝")
                            continue
                        for local in (local4, local6):
                            payload = bytes(range(256))*256
                            value=tcp(local,payload)
                            if value != payload:
                                h.write_json(directory / "mismatch.json", {"local":local,"expected":len(payload),"received":len(value),"first_mismatch":next((i for i,(a,b) in enumerate(zip(payload,value)) if a!=b),None)})
                                raise RuntimeError(label+"：目标族转发失败")
                        checks.append(label+"：IPv4 与 IPv6 目标")
                        verify_context = ssl.create_default_context(cafile=str(cert))
                        payload = bytes(range(256))*1024
                        if tcp(local_tls, payload, verify_context) != payload:
                            raise RuntimeError(label+"：业务 TLS 回写失败")
                        checks.append(label+"：业务 TLS 与 256KiB")
                        if h.udp_request(local_udp, b"datagram-roundtrip") != b"datagram-roundtrip":
                            raise RuntimeError(label+"：UDP 回写失败")
                        checks.append(label+("：XUDP" if args.vision or args.mux or args.xudp else "：普通 UDP"))
                        with ThreadPoolExecutor(max_workers=4) as pool:
                            payloads = [("peer-"+str(n)).encode()*128 for n in range(4)]
                            if list(pool.map(lambda value: tcp(local4, value), payloads)) != payloads:
                                raise RuntimeError(label+"：并发连接串流")
                        checks.append(label+"：四路并发隔离")
            server.terminate()
            if server.wait(timeout=3) != 0:
                raise RuntimeError("服务端没有按预算退出")
            checks.append("服务端有界退出")
    return checks


def main():
    parser = argparse.ArgumentParser(description="真实参考客户端到 VLESS 独立节点的互通")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--vision", action="store_true")
    parser.add_argument("--control-server", action="store_true")
    parser.add_argument("--encryption", choices=["none", "native", "xorpub", "random"], default="none")
    parser.add_argument("--rtt", choices=["1rtt", "0rtt"], default="1rtt")
    parser.add_argument("--mux", action="store_true")
    parser.add_argument("--key-kind",choices=["x25519","mlkem","hybrid"],default="x25519")
    parser.add_argument("--xudp", action="store_true")
    parser.add_argument("--transport", choices=["tcp", "ws", "httpupgrade", "grpc", "xhttp"], default="tcp")
    parser.add_argument("--security", choices=["none", "tls", "reality"], default="tls")
    parser.add_argument("--http", choices=["h1", "h2", "h3"], default="h2")
    parser.add_argument("--mode", default="auto")
    parser.add_argument("--multi", action="store_true")
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--only")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    os.umask(0o077)
    args.kerlico = str(Path(args.kerlico).resolve())
    args.reference = str(Path(args.reference).resolve())
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.matrix:
        materials = material(root,args.reference,args.key_kind)
        selected = [case for case in cases(args.full) if args.only is None or args.only in case.label()]
        results = []
        def run(pair):
            iteration,case=pair
            directory = root / (("iteration-"+str(iteration)+"-") if args.repeat!=1 else "") / case.label()
            directory.mkdir(parents=True,mode=0o700)
            options = dict(vars(args))
            options.update(transport=case.transport, security=case.security, vision=case.vision, mode=case.mode, http=case.http, multi=case.multi, encryption=case.encryption, rtt=case.rtt, xudp=case.xudp)
            try:
                return {"case": case.label(), "ok": True, "checks": verify(SimpleNamespace(**options), directory, materials)}
            except Exception as error:
                return {"case": case.label(), "ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
        from concurrent.futures import as_completed
        with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 4))) as pool:
            for future in as_completed([pool.submit(run, (iteration,case)) for iteration in range(max(1,args.repeat)) for case in selected]):
                result = future.result()
                results.append(result)
                print(json.dumps(result, ensure_ascii=False), flush=True)
                h.write_json(root / "results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "key_kind":args.key_kind,"control_server": args.control_server, "results": results})
        if not selected or not all(result["ok"] for result in results):
            raise SystemExit(1)
        return
    try:
        result = {"ok": True, "vision": args.vision, "checks": verify(args, root)}
    except Exception as error:
        result = {"ok": False, "vision": args.vision, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
    result["control_server"]=args.control_server
    result["binary_sha256"] = hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest()
    h.write_json(root / "result.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    if not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
