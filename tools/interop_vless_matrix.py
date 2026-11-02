#!/usr/bin/env python3
"""在隔离 worker 用真实 Xray 验证 VLESS 客户端组合；密钥和原始日志只留私有目录。"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import threading
import time

import interop_vless as h


@dataclass(frozen=True)
class Case:
    transport: str
    security: str
    vision: bool = False
    mode: str = "auto"
    http: str = "h2"
    multi: bool = False
    encryption: str = "none"
    rtt: str = "1rtt"
    xudp: bool = False

    def label(self):
        return "-".join([self.transport, self.security, self.http if self.transport == "xhttp" else "multi" if self.multi else "single", self.mode, "vision" if self.vision else "ordinary", self.encryption, self.rtt, "xudp" if self.xudp else "udp"])


def cases(full):
    result = []
    for transport in ("tcp", "ws", "httpupgrade", "grpc", "xhttp"):
        for security in ("none", "tls", "reality"):
            if security == "reality" and transport in ("ws", "httpupgrade"):
                continue
            versions = ("h1", "h2", "h3") if transport == "xhttp" and security == "tls" else ("h2",)
            if transport == "xhttp" and security == "none":
                versions = ("h1",)
            for http in versions:
                modes = ("packet-up", "stream-up", "stream-one") if transport == "xhttp" else ("auto",)
                for mode in modes:
                    for multi in ((False, True) if transport == "grpc" else (False,)):
                        result.append(Case(transport, security, mode=mode, http=http, multi=multi))
                        if transport == "tcp" and security != "none":
                            result.append(Case(transport, security, vision=True))
                        if full:
                            result.append(Case(transport, security, mode=mode, http=http, multi=multi, xudp=True))
                            for enc in ("native", "xorpub", "random"):
                                for rtt in ("1rtt", "0rtt"):
                                    for vision in (False, True):
                                        result.append(Case(transport, security, vision=vision, mode=mode, http=http, multi=multi, encryption=enc, rtt=rtt))
    return result


class TlsEcho(h.TcpEcho):
    def handle(self):
        self.request.settimeout(8)
        try:
            self.request = self.server.tls.wrap_socket(self.request, server_side=True)
        except (OSError, ssl.SSLError):
            return
        super().handle()


class TlsServer(h.TcpServer):
    def __init__(self, address, _handler):
        # TLS 握手在请求线程执行，接纳线程继续处理并发的 REALITY cover 连接。
        super().__init__(address, TlsEcho)


# REALITY 把自身证书填充到 cover 的证书记录长度；ML-DSA-65 证书约 3.5 KiB，cover 必须更长。
COVER_NAMES = ",".join("DNS:cover-padding-"+str(i)+".invalid" for i in range(200))


def material(root, reference=None, key_kind="x25519"):
    cert, key = root / "certificate.pem", root / "certificate-key.pem"
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,"+COVER_NAMES, "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth"], capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError("生成测试证书失败")
    def pair(label):
        path = root / (label + ".pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-out", str(path)], check=True, capture_output=True, timeout=10)
        private = subprocess.check_output(["openssl", "pkey", "-in", str(path), "-outform", "DER"])[-32:]
        public = subprocess.check_output(["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"])[-32:]
        return tuple(base64.urlsafe_b64encode(v).rstrip(b"=").decode() for v in (private, public))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.load_cert_chain(cert, key)
    def kem():
        if reference is None:raise RuntimeError("ML-KEM 测试缺少固定参考程序")
        result=subprocess.run([reference,"mlkem768"],capture_output=True,check=True,timeout=15)
        values=dict(line.split(": ",1) for line in result.stdout.decode().splitlines() if ": " in line)
        value=(values["Seed"],values["Client"])
        if len(base64.urlsafe_b64decode(value[0]+"="*((-len(value[0]))%4)))!=64 or len(base64.urlsafe_b64decode(value[1]+"="*((-len(value[1]))%4)))!=1184:raise RuntimeError("参考程序 ML-KEM 材料长度不合法")
        return value
    links={"x25519":lambda:[pair("encryption")],"mlkem":lambda:[kem()],"hybrid":lambda:[pair("encryption"),kem()],"chain":lambda:[kem(),pair("encryption"),kem(),pair("encryption2")]}[key_kind]()
    encryption=tuple(".".join(values) for values in zip(*links))
    return cert, key, context, pair("reality"), encryption


def mldsa65(reference):
    result = subprocess.run([reference, "mldsa65"], capture_output=True, check=True, timeout=15)
    values = dict(line.split(": ", 1) for line in result.stdout.decode().splitlines() if ": " in line)
    return values["Seed"], values["Verify"]


def tcp(port, payload, tls_context=None):
    raw = socket.create_connection(("127.0.0.1", port), timeout=6)
    with raw:
        sock = tls_context.wrap_socket(raw, server_hostname="localhost") if tls_context else raw
        sock.settimeout(8)
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
        if not tls_context:
            sock.shutdown(socket.SHUT_WR)
        chunks = []
        size = 0
        while size < len(payload):
            part = sock.recv(min(65536, len(payload)-size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
        return b"".join(chunks)


def verify(case, args, root, materials):
    directory = root / case.label()
    directory.mkdir(mode=0o700)
    cert, key, tls_server_context, reality_keys, encryption_keys = materials
    checks = []
    with ExitStack() as stack:
        tcp_target = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        udp_target = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        inner = TlsServer(("127.0.0.1", 0), h.TcpEcho)
        inner.tls = tls_server_context
        tls_target = stack.enter_context(h.serve(inner))
        cover = TlsServer(("127.0.0.1", 0), h.TcpEcho)
        cover.tls = tls_server_context
        cover_port = stack.enter_context(h.serve(cover))
        port = h.free_port()
        network = "raw" if case.transport == "tcp" else case.transport
        stream = {"network": network, "security": case.security}
        security = {"type": case.security}
        if case.security == "tls":
            alpn = {"h1": "http/1.1", "h2": "h2", "h3": "h3"}[case.http] if case.transport == "xhttp" else "h2" if case.transport == "grpc" else "http/1.1"
            stream["tlsSettings"] = {"alpn": [alpn], "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}
            security.update(server_name="localhost", ca_pem=cert.read_text(), alpn=[alpn])
        elif case.security == "reality":
            stream["realitySettings"] = {"target": "127.0.0.1:"+str(cover_port), "serverNames": ["localhost"], "privateKey": reality_keys[0], "shortIds": ["abcd"]}
            security.update(server_name="localhost", public_key=reality_keys[1], short_id="abcd", fingerprint="chrome")
            if args.mldsa65:
                seed, verify_key = mldsa65(args.reference)
                stream["realitySettings"]["mldsa65Seed"] = seed
                security["mldsa65_verify"] = verify_key
        transport = {"type": case.transport}
        if case.transport in ("ws", "httpupgrade"):
            stream[case.transport+"Settings"] = {"path": "/kerlico", "host": "localhost"}
            transport.update(path="/kerlico", host="localhost")
        elif case.transport == "grpc":
            stream["grpcSettings"] = {"serviceName": "kerlico", "multiMode": case.multi}
            transport.update(service_name="kerlico", multi_mode=case.multi, authority="localhost")
        elif case.transport == "xhttp":
            stream["xhttpSettings"] = {"path": "/kerlico", "mode": case.mode}
            transport["settings"] = {"path": "/kerlico", "mode": case.mode, "host": "localhost", "http_version": case.http, "padding_bytes": [100, 200]}
        flow = "xtls-rprx-vision" if case.vision else ""
        decryption = "none" if case.encryption == "none" else "mlkem768x25519plus."+case.encryption+".600s."+encryption_keys[0]
        encryption = "none" if case.encryption == "none" else "mlkem768x25519plus."+case.encryption+"."+case.rtt+"."+encryption_keys[1]
        reference = {"log": {"loglevel": "debug" if args.diagnose else "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {"clients": [{"id": h.USER_ID, "flow": flow}], "decryption": decryption}, "streamSettings": stream}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": ",".join(map(str, [tcp_target, udp_target, tls_target]))}]}}]}
        ref_path = directory / "reference.json"
        h.write_json(ref_path, reference)
        check = subprocess.run([args.reference, "run", "-test", "-config", str(ref_path)], capture_output=True, timeout=10)
        (directory / "reference-check.log").write_bytes(check.stdout+check.stderr)
        if check.returncode:
            raise RuntimeError("参考端配置拒绝")
        local_tcp, local_udp, local_tls = h.free_port(), h.free_port(), h.free_port()
        options = {"server": {"host": "127.0.0.1", "port": port}, "uuid": h.USER_ID, "flow": flow, "encryption": encryption, "security": security, "transport": transport, "packet_encoding": "xudp" if case.xudp else "udp"}
        if args.mux:
            options["mux"] = {"enabled": True, "tcp": not (case.vision or case.transport == "xhttp"), "udp": True, "concurrency": 4, "max_connections": 2}
        if args.packet_encoding:
            options["packet_encoding"] = args.packet_encoding
        config = {"version": 1, "outbounds": [{"tag": "proxy", "type": "vless", "options": options}], "inbounds": [{"tag": name, "type": kind, "listen": "127.0.0.1:"+str(local), "target": {"host": "127.0.0.1", "port": target}, "outbound": "proxy"} for name, kind, local, target in [("tcp", "tcp-forward", local_tcp, tcp_target), ("udp", "udp-forward", local_udp, udp_target), ("tls", "tcp-forward", local_tls, tls_target)]], "limits": {"connect_timeout_ms": 6000, "idle_timeout_ms": 10000, "drain_timeout_ms": 500, "max_sessions": 64}}
        path = directory / "kerlico.json"
        h.write_json(path, config)
        with h.process([args.reference, "run", "-config", str(ref_path)], directory, "reference") as backend:
            if case.transport == "xhttp" and case.http == "h3":
                time.sleep(0.2)
                if backend.poll() is not None:
                    raise RuntimeError("参考端启动失败")
            else:
                h.wait_ready(backend, port)
            with h.process([args.kerlico, "run", "-c", str(path)], directory, "kerlico") as client:
                h.wait_ready(client, local_tcp)
                def stage(name):
                    h.write_json(directory / "progress.json", {"stage": name, "passed": checks})
                stage("普通 TCP")
                for payload in (b"payload-before-response", bytes(range(256))*256, b"second-connection-for-session-reuse"):
                    if tcp(local_tcp, payload) != payload:
                        raise RuntimeError("TCP 回写不一致")
                checks.append("TCP 首包、大负载与重复连接")
                stage("数据报")
                if h.udp_request(local_udp, b"datagram-probe") != b"datagram-probe":
                    raise RuntimeError("UDP 回写不一致")
                checks.append("XUDP" if case.vision or case.xudp else "普通 UDP")
                stage("业务 TLS")
                verify_context = ssl.create_default_context(cafile=str(cert))
                payload = bytes(range(256))*1024
                value=tcp(local_tls, payload, verify_context)
                if value != payload:
                    h.write_json(directory / "mismatch.json", {"expected":len(payload),"received":len(value),"first_mismatch":next((i for i,(a,b) in enumerate(zip(payload,value)) if a!=b),None)})
                    raise RuntimeError("业务 TLS 大负载回写不一致")
                checks.append("业务 TLS 1.3 与 256KiB 负载")
                stage("并发隔离")
                with ThreadPoolExecutor(max_workers=4) as pool:
                    payloads = [("isolated-flow-"+str(i)).encode()*128 for i in range(4)]
                    if list(pool.map(lambda value: tcp(local_tcp, value), payloads)) != payloads:
                        raise RuntimeError("并发流数据混用")
                checks.append("四路并发隔离")
                client.terminate()
                if client.wait(timeout=3) != 0:
                    raise RuntimeError("有界退出失败")
                checks.append("有界退出")
            if args.mldsa65:
                security["mldsa65_verify"] = mldsa65(args.reference)[1]
                wrong = directory / "kerlico-wrong-mldsa.json"
                h.write_json(wrong, config)
                with h.process([args.kerlico, "run", "-c", str(wrong)], directory, "kerlico-wrong-mldsa") as client:
                    h.wait_ready(client, local_tcp)
                    try:
                        returned = tcp(local_tcp, b"must-not-pass-mldsa")
                    except OSError:
                        returned = b""
                    if returned:
                        raise RuntimeError("错误 ML-DSA-65 公钥未被拒绝")
                checks.append("错误 ML-DSA-65 公钥被拒绝")
    return checks


def migration(args, root):
    """kerlico 客户端经可切断中继连接 Xray：XUDP 应保留出口端口，普通 UDP 作为对照应改变端口。"""
    results = []
    with h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpPortEcho)) as target:
        for label, encoding, mux, expected in (("xudp", "xudp", False, True), ("xudp-mux", "xudp", True, True), ("udp-control", "udp", False, False)):
            directory = root / label
            directory.mkdir(mode=0o700)
            port, local = h.free_port(), h.free_port()
            reference = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": {"clients": [{"id": h.USER_ID}], "decryption": "none"}, "streamSettings": {"network": "raw", "security": "none"}}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": str(target)}]}}]}
            ref_path = directory / "reference.json"
            h.write_json(ref_path, reference)
            with h.process([args.reference, "run", "-config", str(ref_path)], directory, "reference") as backend:
                h.wait_ready(backend, port)
                relay = h.Relay(port)
                options = {"server": {"host": "127.0.0.1", "port": relay.port}, "uuid": h.USER_ID, "security": {"type": "none"}, "packet_encoding": encoding}
                if mux:
                    options["mux"] = {"enabled": True, "tcp": False, "udp": True, "concurrency": 4, "max_connections": 2}
                config = {"version": 1, "outbounds": [{"tag": "proxy", "type": "vless", "options": options}], "inbounds": [{"tag": "udp", "type": "udp-forward", "listen": "127.0.0.1:"+str(local), "target": {"host": "127.0.0.1", "port": target}, "outbound": "proxy"}], "limits": {"connect_timeout_ms": 4000, "idle_timeout_ms": 20000, "drain_timeout_ms": 300, "max_sessions": 16}}
                path = directory / "kerlico.json"
                h.write_json(path, config)
                with h.process([args.kerlico, "run", "-c", str(path)], directory, "kerlico"):
                    time.sleep(0.5)
                    before, after, moved = h.carrier_migration(local, relay)
                relay.close()
            ok = moved and (before == after) == expected
            results.append({"case": label, "ok": ok, "before": before, "after": after, "new_carrier": moved})
            print(json.dumps(results[-1], ensure_ascii=False), flush=True)
    return results


def main():
    parser = argparse.ArgumentParser(description="真实参考端 VLESS 组合验证，只在专用 worker 执行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--work-dir", default=".private/matrix")
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--only")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--mux", action="store_true")
    parser.add_argument("--key-kind",choices=["x25519","mlkem","hybrid","chain"],default="x25519")
    parser.add_argument("--packet-encoding", choices=["udp", "xudp", "packetaddr"])
    parser.add_argument("--mldsa65", action="store_true", help="REALITY 服务端签名，客户端校验正确与错误公钥")
    parser.add_argument("--xudp-migration", action="store_true", help="切断载体后验证 XUDP 出口端口不变")
    args = parser.parse_args()
    os.umask(0o077)
    args.kerlico = str(Path(args.kerlico).resolve())
    args.reference = str(Path(args.reference).resolve())
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if args.xudp_migration:
        if not all(result["ok"] for result in migration(args, root)):
            raise SystemExit(1)
        return
    materials = material(root,args.reference,args.key_kind)
    selected = [c for c in cases(args.full) if args.only is None or args.only in c.label()]
    results = []
    def run(pair):
        iteration,case=pair
        case_root=root if args.repeat==1 else root / ("iteration-"+str(iteration))
        case_root.mkdir(exist_ok=True,mode=0o700)
        try:
            return {"case": case.label(), "ok": True, "checks": verify(case, args, case_root, materials)}
        except Exception as error:
            reason = str(error) if isinstance(error, RuntimeError) else type(error).__name__+":"+str(error)
            return {"case": case.label(), "ok": False, "reason": reason}
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 4))) as pool:
        futures = {pool.submit(run, c): c for c in [(iteration,case) for iteration in range(max(1,args.repeat)) for case in selected]}
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            h.write_json(root / "results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "key_kind":args.key_kind, "mux": args.mux, "packet_encoding": args.packet_encoding, "results": results})
    if not selected or not all(r["ok"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
