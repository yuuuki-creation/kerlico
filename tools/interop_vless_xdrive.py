#!/usr/bin/env python3
"""在 worker 验证 XDRIVE 双向互通；HTTP 存储为隔离模拟服务，不使用真实云凭据。"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit, parse_qs, quote, unquote
from xml.sax.saxutils import escape

import interop_vless as h
from interop_vless_matrix import material

def tcp(port,payload):
    # Mux 的 END 终止全流；此互通场景按长度回写，不让参考端将提前 EOF 转为 END。
    with socket.create_connection(("127.0.0.1",port),timeout=8) as sock:
        sock.settimeout(10)
        sock.sendall(len(payload).to_bytes(4,"big")+payload)
        output=bytearray()
        while len(output)<len(payload):
            data=sock.recv(min(65536,len(payload)-len(output)))
            if not data:break
            output.extend(data)
        return bytes(output)


ACCESS = "kerlico-test-access"
SECRET = "kerlico-test-secret"
TOKEN = "kerlico-template-test"


class StorageServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self):
        super().__init__(("127.0.0.1", 0), StorageHandler)
        self.objects = {}
        self.lock = threading.Lock()
        self.requests = 0
        self.rejected = 0


class StorageHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_):
        pass

    def reply(self, status, data=b"", content="application/octet-stream"):
        self.send_response(status)
        self.send_header("Content-Type", content)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def signed(self, payload):
        value = self.headers.get("Authorization", "")
        if not value.startswith("AWS4-HMAC-SHA256 "):
            return False
        try:
            fields = dict(part.strip().split("=", 1) for part in value[17:].split(","))
            access, scope = fields["Credential"].split("/", 1)
            if access != ACCESS or self.headers["x-amz-content-sha256"] != hashlib.sha256(payload).hexdigest():
                return False
            date, region, service, end = scope.split("/")
            if service != "s3" or end != "aws4_request":
                return False
            parsed = urlsplit(self.path)
            query = "&".join(sorted(quote(k, safe="-_.~")+"="+quote(v, safe="-_.~") for k, values in parse_qs(parsed.query, keep_blank_values=True).items() for v in values))
            canonical_headers = "".join(name+":"+" ".join(self.headers[name].split())+"\n" for name in fields["SignedHeaders"].split(";"))
            canonical = "\n".join([self.command, parsed.path, query, canonical_headers, fields["SignedHeaders"], hashlib.sha256(payload).hexdigest()])
            text = "AWS4-HMAC-SHA256\n"+self.headers["x-amz-date"]+"\n"+scope+"\n"+hashlib.sha256(canonical.encode()).hexdigest()
            key = ("AWS4"+SECRET).encode()
            for part in (date, region, "s3", "aws4_request"):
                key = hmac.new(key, part.encode(), hashlib.sha256).digest()
            return hmac.compare_digest(fields["Signature"], hmac.new(key, text.encode(), hashlib.sha256).hexdigest())
        except (ValueError, KeyError, TypeError, AttributeError):
            return False

    def handle_request(self):
        payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        is_s3 = parsed.path.startswith("/bucket")
        authorized = self.signed(payload) if is_s3 else self.headers.get("Authorization") == "Bearer "+TOKEN
        with self.server.lock:
            self.server.requests += 1
            if not authorized:
                self.server.rejected += 1
        if not authorized:
            return self.reply(403)
        listing = is_s3 and "list-type" in query or parsed.path == "/list"
        key = unquote(parsed.path.removeprefix("/bucket/") if is_s3 else parsed.path.removeprefix("/objects/"))
        with self.server.lock:
            if listing:
                prefix = query.get("prefix", [""])[0]
                names = sorted(k for k in self.server.objects if k.startswith(prefix))
                if is_s3:
                    start = int(query.get("continuation-token", ["0"])[0])
                    page = names[start:start+16]
                    more = start+len(page) < len(names)
                    xml = '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>'+str(more).lower()+"</IsTruncated>"+"".join("<Contents><Key>"+escape(name)+"</Key></Contents>" for name in page)
                    if more:
                        xml += "<NextContinuationToken>"+str(start+len(page))+"</NextContinuationToken>"
                    return self.reply(200, (xml+"</ListBucketResult>").encode(), "application/xml")
                return self.reply(200, json.dumps(names).encode(), "application/json")
            if self.command == "PUT":
                self.server.objects[key] = payload
                return self.reply(200)
            if self.command == "DELETE":
                for name in list(self.server.objects):
                    if name == key or name.startswith(key+("/" if is_s3 else "~")):
                        del self.server.objects[name]
                return self.reply(204)
            if key not in self.server.objects:
                return self.reply(404)
            return self.reply(200, self.server.objects[key])

    do_GET = handle_request
    do_PUT = handle_request
    do_DELETE = handle_request


def settings(backend, root, port):
    common = {"service": backend, "remote_folder": str(root / "objects") if backend == "local" else "kerlico", "segment_bytes": 16384, "flush_interval_ms": 10, "poll_interval_ms": 10, "max_poll_interval_ms": 100, "concurrency": 4}
    if backend == "s3":
        common.update(secrets=[ACCESS, SECRET], s3={"endpoint": "http://127.0.0.1:"+str(port), "region": "us-east-1", "bucket": "bucket", "path_style": True})
    elif backend == "template":
        endpoint = "http://127.0.0.1:"+str(port)
        template = {"flatten": True, "concurrency": 4, "auth": {"type": "static", "header": {"Authorization": "Bearer {secret0}"}}, "put": {"method": "PUT", "url": endpoint+"/objects/{name}"}, "get": {"url": endpoint+"/objects/{name}"}, "delete": {"method": "DELETE", "url": endpoint+"/objects/{name}"}, "list": {"url": endpoint+"/list?prefix={prefix}", "namesRegex": '"([^"\\\\]+)"'}}
        common.update(secrets=[TOKEN], template=json.dumps(template))
    return common


def verify(args, root, role, backend):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    cert, key, _, _, keys = material(root,args.reference,args.key_kind)
    del cert, key
    encryption = "mlkem768x25519plus.native.1rtt."+keys[1]
    decryption = "mlkem768x25519plus.native.600s."+keys[0]
    with ExitStack() as stack:
        mock = StorageServer()
        port = stack.enter_context(h.serve(mock))
        store = settings(backend, root, port)
        xstore = {"".join([parts[0]]+[part.capitalize() for part in parts[1:]]): value for name, value in store.items() for parts in [name.split("_")]}
        if "template" in store:
            xstore["template"] = json.loads(store["template"])
        if "s3" in store:
            xstore["s3"] = {"endpoint": store["s3"]["endpoint"], "region": "us-east-1", "bucket": "bucket", "pathStyle": True}
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), h.TcpEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), h.TcpEcho)))
        udp = stack.enter_context(h.serve(h.UdpServer(("127.0.0.1", 0), h.UdpEcho)))
        locals_ = [h.free_port() for _ in range(3)]
        paths = [("tcp4", "tcp", "127.0.0.1", target4), ("tcp6", "tcp", "::1", target6), ("udp", "udp", "127.0.0.1", udp)]
        peer = {"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": 443, "users": [{"id": h.USER_ID, "encryption": encryption}]}]}, "streamSettings": {"network": "xdrive", "security": "none", "xdriveSettings": xstore}, "mux": {"enabled": True, "concurrency": 4, "xudpConcurrency": 4}}
        node = {"tag": "storage", "type": "vless", "listen": "127.0.0.1:0", "outbound": "direct", "options": {"uuid": h.USER_ID, "decryption": decryption, "security": {"type": "none"}, "transport": {"type": "xdrive", "settings": store}}}
        client = {"tag": "proxy", "type": "vless", "options": {"server": {"host": "127.0.0.1", "port": 443}, "uuid": h.USER_ID, "encryption": encryption, "security": {"type": "none"}, "transport": {"type": "xdrive", "settings": store}, "mux": {"enabled": True, "tcp": True, "udp": True, "concurrency": 4}}}
        if role == "server":
            kerlico = {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": [node], "limits": {"connect_timeout_ms": 6000, "idle_timeout_ms": 10000, "drain_timeout_ms": 200}}
            reference = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": local, "protocol": "tunnel", "settings": {"address": host, "port": target, "network": network}} for local, (_, network, host, target) in zip(locals_, paths)], "outbounds": [peer]}
        else:
            kerlico = {"version": 1, "outbounds": [client], "inbounds": [{"tag": tag, "type": network+"-forward", "listen": "127.0.0.1:"+str(local), "target": {"host": host, "port": target}, "outbound": "proxy"} for local, (tag, network, host, target) in zip(locals_, paths)], "limits": {"connect_timeout_ms": 6000, "idle_timeout_ms": 10000, "drain_timeout_ms": 200}}
            reference = {"log": {"loglevel": "debug"}, "inbounds": [{"listen": "127.0.0.1", "port": 1443, "protocol": "vless", "settings": {"clients": [{"id": h.USER_ID}], "decryption": decryption}, "streamSettings": peer["streamSettings"]}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32", "::1/128"], "port": ",".join(map(str, [target4, target6, udp]))}]}}]}
        config = root / "kerlico.json"
        ref_config = root / "reference.json"
        h.write_json(config, kerlico)
        h.write_json(ref_config, reference)
        with h.process([args.reference, "run", "-config", str(ref_config)], root, "reference") as ref, h.process([args.kerlico, "run", "-c", str(config)], root, "kerlico") as core:
            time.sleep(0.5)
            if core.poll() is not None or ref.poll() is not None:
                raise RuntimeError("XDRIVE 进程提前退出")
            checks = []
            def stage(label):
                h.write_json(root / "progress.json", {"stage": label, "passed": checks})
            payload = bytes(range(256))*512
            stage("双目标 TCP")
            for index, local in enumerate(locals_[:2]):
                value = tcp(local, payload)
                if value != payload:
                    raise RuntimeError("XDRIVE TCP 回写不一致：目标 "+str(index)+"，收到 "+str(len(value))+" 字节")
            checks.append("双目标 TCP")
            stage("UDP")
            if h.udp_request(locals_[2], b"xdrive-datagram") != b"xdrive-datagram":
                raise RuntimeError("XDRIVE UDP 回写不一致")
            checks.append("UDP")
            stage("Mux 四路并发")
            with ThreadPoolExecutor(max_workers=4) as pool:
                values = [bytes([index])*32768 for index in range(4)]
                def probe(index):
                    try:
                        value = tcp(locals_[0], values[index])
                        h.write_json(root / ("flow-"+str(index)+".json"), {"received": len(value), "expected": len(values[index]), "ok": value == values[index]})
                        return value
                    except Exception as error:
                        h.write_json(root / ("flow-"+str(index)+".json"), {"error": type(error).__name__})
                        raise
                if list(pool.map(probe, range(4))) != values:
                    raise RuntimeError("XDRIVE Mux 并发串流")
            checks.append("Mux 四路并发")
            stage("退出")
            for child in (core, ref):
                child.terminate()
                if child.wait(timeout=3) != 0:
                    raise RuntimeError("XDRIVE 退出失败")
        if backend != "local" and (mock.requests == 0 or mock.rejected):
            raise RuntimeError("存储未访问或鉴权失败")
        return ["IPv4/IPv6 TCP 128KiB", "UDP", "Mux 四路并发", "有界退出", "真实存储路径/请求鉴权"]


def main():
    parser = argparse.ArgumentParser(description="真实 Xray 与 kerlico 的 XDRIVE 双向互通")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--key-kind",choices=["x25519","mlkem","hybrid"],default="x25519")
    parser.add_argument("--backend", choices=["local", "template", "s3", "all"], default="all")
    parser.add_argument("--role", choices=["client", "server", "both"], default="both")
    args = parser.parse_args()
    args.kerlico = str(Path(args.kerlico).resolve())
    args.reference = str(Path(args.reference).resolve())
    root = Path(args.work_dir).resolve()
    os.umask(0o077)
    results = []
    for backend in (["local", "template", "s3"] if args.backend == "all" else [args.backend]):
        for role in (["client", "server"] if args.role == "both" else [args.role]):
            try:
                result = {"backend": backend, "role": role, "ok": True, "checks": verify(args, root / (backend+"-"+role), role, backend)}
            except Exception as error:
                result = {"backend": backend, "role": role, "ok": False, "reason": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            h.write_json(root / "results.json", {"binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "results": results})
    if not all(result["ok"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
