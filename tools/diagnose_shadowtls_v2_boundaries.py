#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import threading

import interop_shadowtls as s


def record(kind, payload):
    return bytes((kind, 3, 3))+len(payload).to_bytes(2, "big")+payload


def read_record(stream):
    header = s.exact(stream, 5)
    if not header:
        return None
    if len(header) != 5 or header[1] != 3:
        raise RuntimeError("诊断载体记录头被截断或版本无效")
    body = s.exact(stream, int.from_bytes(header[3:5], "big"))
    if len(body) != int.from_bytes(header[3:5], "big"):
        raise RuntimeError("诊断载体记录体被截断")
    return header+body


def records(data):
    offset = 0
    while offset < len(data):
        length = int.from_bytes(data[offset+3:offset+5], "big")+5
        if offset+5 > len(data) or offset+length > len(data):
            raise RuntimeError("TLS MemoryBIO 输出未组成完整记录")
        yield data[offset:offset+length]
        offset += length


class Transcript:
    def __init__(self, password):
        self.hash = hmac.new(password, digestmod="sha1")
        self.offset = 0
        self.last = None
        self.current = None
        self.prefixes = {}
        self.chunks = []
        self.boundaries = []

    def sent(self, chunk, stage):
        self.last = self.current
        for byte in chunk:
            self.hash.update(bytes((byte,)))
            self.offset += 1
            digest = self.hash.copy().digest()[:8]
            self.prefixes.setdefault(digest, []).append(self.offset)
        self.current = self.hash.copy().digest()[:8]
        self.chunks.append({"end": self.offset, "bytes": len(chunk), "stage": stage, "tag": self.current.hex()})

    def first_business(self, tag):
        matches = self.prefixes.get(tag, [])
        requested_ends = {chunk["end"] for chunk in self.chunks if chunk["stage"] == "post-handshake-ticket-prefix"}
        return {
            "emitted_raw_bytes": self.offset,
            "matched_prefix_bytes": matches,
            "matches_complete_record": any(offset in self.boundaries for offset in matches),
            "matches_write_chunk": any(offset in {chunk["end"] for chunk in self.chunks} for offset in matches),
            "matches_current_or_last_write": tag in (self.current, self.last),
            "matches_requested_late_cut": any(offset in requested_ends for offset in matches),
            "first_business_tag": tag.hex(),
            "chunks": list(self.chunks),
            "record_boundaries": list(self.boundaries),
        }


class ControlledOuter:
    def __init__(self, cert, key, port, backend, tls_version, tickets, boundary, hold_ms):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if tls_version == "1.2" else ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(cert), str(key))
        context.set_alpn_protocols(["http/1.1"])
        context.num_tickets = tickets
        self.context, self.backend = context, backend
        self.tls_version, self.boundary, self.hold_ms = tls_version, boundary, hold_ms
        self.observations = []
        self.lock = threading.Lock()
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                observation = {"tls_version": owner.tls_version, "boundary": owner.boundary, "tickets_configured": tickets}
                try:
                    owner.connection(self.request, observation)
                except (OSError, ssl.SSLError, RuntimeError) as error:
                    observation.update(ok=False, error=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
                finally:
                    with owner.lock:
                        if observation.get("client_tls_records", 0):
                            owner.observations.append(observation)

        self.server = s.OwnedTcpServer(("127.0.0.1", port), Handler)

    def __enter__(self):
        self.server.__enter__()
        return self

    def __exit__(self, *_):
        self.server.__exit__(*_)

    def connection(self, front, observation):
        front.settimeout(5)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        session = self.context.wrap_bio(incoming, outgoing, server_side=True)
        transcript = Transcript(b"outer-test-11")
        send_lock = threading.Lock()
        release = threading.Event()
        sender_errors = []

        def send_bytes(chunk, stage, record_end=False):
            with send_lock:
                if chunk:
                    front.sendall(chunk)
                    transcript.sent(chunk, stage)
                if record_end:
                    transcript.boundaries.append(transcript.offset)

        def send_records(data, stage, late=False):
            count = 0
            for frame in records(data):
                if late and count == 0:
                    cut = {"header": 2, "header-complete": 5, "body": min(8, len(frame)), "record": len(frame)}[self.boundary]
                    send_bytes(frame[:cut], stage+"-prefix", record_end=cut == len(frame))
                    release.wait(self.hold_ms/1000)
                    send_bytes(frame[cut:], stage+"-suffix", record_end=cut != len(frame))
                else:
                    for index, chunk in enumerate((frame[:2], frame[2:5], frame[5:])):
                        send_bytes(chunk, stage, record_end=index == 2)
                count += 1
            return count

        late = b""
        while True:
            try:
                session.do_handshake()
                pending = outgoing.read()
                if self.tls_version == "1.3":
                    late = pending
                else:
                    send_records(pending, "handshake")
                break
            except ssl.SSLWantReadError:
                send_records(outgoing.read(), "handshake")
                frame = read_record(front)
                if frame is None:
                    return
                observation["client_tls_records"] = observation.get("client_tls_records", 0)+1
                incoming.write(frame)
        observation["handshake_complete"] = True
        observation["late_record_count"] = len(list(records(late)))

        def send_late():
            try:
                send_records(late, "post-handshake-ticket", late=True)
            except (OSError, RuntimeError) as error:
                sender_errors.append(type(error).__name__)

        sender = self.server.start_worker(send_late)
        try:
            first = read_record(front)
            if first is None or first[0] != 23 or len(first) < 13:
                raise RuntimeError("真实握手后没有完整 v2 首业务记录")
            with send_lock:
                observation.update(transcript.first_business(first[5:13]))
            observation["first_shadowtls_write_bytes"] = len(first)-13
            observation["one_byte_shadowtls_first_write_covered"] = False
            if observation["first_shadowtls_write_bytes"] <= 1:
                raise RuntimeError("此AEAD内层诊断预期先写编码首部，不能仅有1字节ShadowTLS首写")
            release.set()
            sender.join(timeout=2)
            if sender.is_alive() or sender_errors:
                raise RuntimeError("晚到票据发送没有有界完成")
            if not observation["matches_current_or_last_write"]:
                raise RuntimeError("首业务摘要不匹配当前或上次写入块，未连接内层")
            with socket.create_connection(("127.0.0.1", self.backend), timeout=4) as backend:
                backend.settimeout(5)
                if not self.server.track_connection(backend):
                    raise RuntimeError("受控外层关闭期间不再接纳内层连接")
                try:
                    backend.sendall(first[13:])
                    done = threading.Event()
                    reply_errors = []

                    def reply():
                        try:
                            while not done.is_set():
                                payload = backend.recv(16384)
                                if not payload:
                                    break
                                with send_lock:
                                    front.sendall(record(23, payload))
                        except OSError as error:
                            if not done.is_set() and not self.server.closing:
                                reply_errors.append(type(error).__name__)
                        finally:
                            done.set()
                            try:
                                front.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                pass

                    reader = self.server.start_worker(reply)
                    try:
                        while not done.is_set():
                            frame = read_record(front)
                            if frame is None:
                                break
                            if frame[0] != 23:
                                raise RuntimeError("切换后的 v2 记录类型不合法")
                            backend.sendall(frame[5:])
                    finally:
                        done.set()
                        try:
                            backend.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        reader.join(timeout=2)
                        if reader.is_alive():
                            raise RuntimeError("内层回包线程未退出")
                        if reply_errors:
                            raise RuntimeError("内层回包线程提前失败："+",".join(reply_errors))
                    observation["ok"] = True
                finally:
                    self.server.release_connection(backend)
        finally:
            release.set()
            sender.join(timeout=2)
            if sender.is_alive():
                raise RuntimeError("晚到票据线程在收尾时仍未退出")
            if sender_errors:
                raise RuntimeError("晚到票据线程失败："+",".join(sender_errors))


def verify(args, directory, cert, key, tls_version, tickets, boundary):
    checks = []
    backend, outer, echo, banner = [s.h.free_port() for _ in range(4)]
    with ExitStack() as stack:
        echo_target = stack.enter_context(s.OwnedTcpServer(("127.0.0.1", echo), s.h.TcpEcho)).server_address[1]
        banner_target = stack.enter_context(s.OwnedTcpServer(("127.0.0.1", banner), s.Banner)).server_address[1]
        server = {"log": {"level": "error"}, "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": backend, "method": "aes-128-gcm", "password": s.password("aes-128-gcm", 11), "network": "tcp"}], "outbounds": [{"type": "direct"}]}
        s.h.write_json(directory/"inner.json", server)
        inner = stack.enter_context(s.process([args.sing_box, "run", "-c", str(directory/"inner.json")], directory, "inner"))
        s.wait_listener(inner, ("127.0.0.1", backend))
        fixture = stack.enter_context(ControlledOuter(cert, key, outer, backend, tls_version, tickets, boundary, args.late_hold_ms))
        s.wait_listener(fixture.server, ("127.0.0.1", outer))
        rules = [("echo", s.h.free_port(), echo_target), ("banner", s.h.free_port(), banner_target)]
        client = {"version": 1, "outbounds": [{"tag": "proxy", "type": "shadowtls", "options": s.shadow_client(2, False, tls_version, cert, "aes-128-gcm", 11, False, ("127.0.0.1", outer))}], "inbounds": [{"type": "tcp-forward", "tag": tag, "listen": "127.0.0.1:"+str(port), "target": {"host": "127.0.0.1", "port": target}, "outbound": "proxy"} for tag, port, target in rules], "limits": {"connect_timeout_ms": 5000, "idle_timeout_ms": 6000, "drain_timeout_ms": 400, "max_sessions": 32}}
        s.h.write_json(directory/"client.json", client)
        process = stack.enter_context(s.process([args.kerlico, "run", "-c", str(directory/"client.json")], directory, "client"))
        for _, port, _ in rules:
            s.wait_listener(process, ("127.0.0.1", port))
        failure = None
        try:
            for size in (1, 17, 4096):
                payload = bytes((size % 251,))*size
                if s.tcp(rules[0][1], payload) != payload:
                    raise RuntimeError("应用负载回写不一致")
                checks.append("应用负载"+str(size)+"字节，另有4字节测试长度及AEAD内层编码")
            if s.tcp(rules[1][1], b"x", True) != b"x":
                raise RuntimeError("真实内层目标先发回写失败")
            checks.append("目标先发")
            with ThreadPoolExecutor(max_workers=4) as pool:
                payloads = [bytes((index,))*17 for index in range(4)]
                if list(pool.map(lambda payload: s.tcp(rules[0][1], payload), payloads)) != payloads:
                    raise RuntimeError("四路并发回写不一致")
            checks.append("四路并发")
        except (OSError, RuntimeError) as error:
            failure = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        finally:
            cleanup = [s.stop_process(process, "本项目客户端"), s.stop_process(inner, "参考内层")]
    observations = fixture.observations
    s.h.write_json(directory/"boundaries.json", {"observations": observations, "fixture_cleanup": fixture.server.cleanup})
    complete = [sample for sample in observations if sample.get("first_business_tag")]
    if failure is None and sum(bool(sample.get("ok")) for sample in complete) < 8:
        failure = "真实业务样本缺失或受控外层尚未成功收尾"
    boundary_observed = any(sample.get("matches_requested_late_cut") for sample in complete) if tls_version == "1.3" else None
    return {"ok": failure is None, "failure": failure, "checks": checks, "cleanup": cleanup, "fixture_cleanup": fixture.server.cleanup, "observations": observations, "application_payload_sizes": [1, 17, 4096], "one_byte_shadowtls_first_write_covered": False, "requested_late_boundary_observed": boundary_observed}


def main():
    parser = argparse.ArgumentParser(description="真实 TLS 与受控 v2 原始摘要诊断，不修改系统网络")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--openssl")
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--listen-port-range")
    parser.add_argument("--late-hold-ms", type=int, default=25)
    args = parser.parse_args()
    if not 0 <= args.late_hold_ms <= 100:
        raise RuntimeError("晚到票据夹具等待必须在0至100毫秒内")
    os.umask(0o077)
    ports = s.configure_ports(None, args.listen_port_range)
    args.kerlico, args.sing_box = str(Path(args.kerlico).resolve()), str(Path(args.sing_box).resolve())
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, mode=0o700)
    cert, key = s.material(root, args.openssl)
    results = []
    for tls_version in ("1.2", "1.3"):
        for tickets in (2, 8):
            for boundary in ("header", "header-complete", "body", "record"):
                label = "tls"+tls_version+"-tickets"+str(tickets)+"-"+boundary
                directory = root/label
                directory.mkdir(mode=0o700)
                try:
                    result = verify(args, directory, cert, key, tls_version, tickets, boundary)
                except Exception as error:
                    result = {"ok": False, "failure": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
                result["case"] = label
                results.append(result)
                samples = result.get("observations", [])
                print(json.dumps({"case": label, "ok": result["ok"], "failure": result.get("failure"), "checks": result.get("checks", []), "observations": len(samples), "requested_late_boundary_observed": result.get("requested_late_boundary_observed"), "one_byte_shadowtls_first_write_covered": False, "partial_record_prefixes": sum(bool(sample.get("matched_prefix_bytes")) and not sample.get("matches_complete_record", False) for sample in samples)}, ensure_ascii=False), flush=True)
                s.h.write_json(root/"results.json", {"fixture": "受控外层，只验证当前或上次写入块摘要，不等于官方互通", "ports": ports, "tls_library": ssl.OPENSSL_VERSION, "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "kerlico_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "reference_sha256": hashlib.sha256(Path(args.sing_box).read_bytes()).hexdigest(), "results": results})
    if not all(result["ok"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
