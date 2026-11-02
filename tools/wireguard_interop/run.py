"""在海外worker运行官方WireGuard双方向回环业务矩阵，保存去秘密结果。"""

import argparse
import base64
from contextlib import ExitStack
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import queue
import select
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid


def b64(data):
    return base64.b64encode(data).decode("ascii")


def endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def target(host, port):
    return {"host": host, "port": port}


def write_private(path, value):
    with path.open("w", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream)


class Rpc:
    def __init__(self, command, directory, name):
        self.log = (directory / (name + ".stderr")).open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, cwd=directory, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.log, text=True, encoding="utf-8", bufsize=1)
        self.responses = queue.Queue()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        try:
            self.ready = self.receive(20)
            if not self.ready.get("ready"):
                raise RuntimeError("验证peer没有进入准备状态")
        except Exception:
            self.close()
            raise

    def read(self):
        for line in self.process.stdout:
            try:
                self.responses.put(json.loads(line))
            except (ValueError, TypeError):
                self.responses.put({"ok": False, "error": "验证peer输出不合法"})

    def receive(self, timeout):
        try:
            return self.responses.get(timeout=timeout)
        except queue.Empty:
            raise RuntimeError("验证peer未在期限内响应") from None

    def call(self, request, timeout=35, allow_failure=False):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        result = self.receive(timeout)
        if not allow_failure and not result.get("ok"):
            raise RuntimeError("验证peer业务失败：" + str(result.get("error", "未知错误")))
        return result

    def stop(self):
        self.process.stdin.write('{"op":"stop"}\n')
        self.process.stdin.flush()
        result = self.receive(10)
        self.process.wait(timeout=10)
        if not result.get("stopped") or not result.get("clean") or self.process.returncode:
            raise RuntimeError("验证peer未完成干净关闭")
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


class Proxy:
    def __init__(self, host, port):
        self.host, self.upstream = host, (host, port)
        self.socket = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((host, 0))
        self.port = self.socket.getsockname()[1]
        self.client = None
        self.impaired = False
        self.stopped = threading.Event()
        self.counts = {"handshake_init": 0, "keepalive": 0, "data": 0, "payload_frames": 0, "dropped": 0, "replayed": 0, "reordered": 0}
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        delayed = []
        while not self.stopped.is_set():
            readable, _, _ = select.select([self.socket], [], [], 0.01)
            now = time.monotonic()
            remaining = []
            for deadline, data, address in delayed:
                if deadline <= now:
                    self.socket.sendto(data, address)
                else:
                    remaining.append((deadline, data, address))
            delayed = remaining
            if not readable:
                continue
            data, source = self.socket.recvfrom(65536)
            if source[:2] == self.upstream:
                address = self.client
            else:
                self.client, address = source, self.upstream
            if address is None:
                continue
            kind = struct.unpack_from("<I", data)[0] if len(data) >= 4 else 0
            if kind == 1:
                self.counts["handshake_init"] += 1
            if kind == 4:
                self.counts["keepalive" if len(data) == 32 else "data"] += 1
                if self.impaired and len(data) > 160:
                    self.counts["payload_frames"] += 1
                    count = self.counts["payload_frames"]
                    if count == 13:
                        self.counts["dropped"] += 1
                        continue
                    if count in [7, 21]:
                        self.counts["reordered"] += 1
                        delayed.append((now + 0.02, data, address))
                        continue
                    if count == 17:
                        self.counts["replayed"] += 1
                        self.socket.sendto(data, address)
            self.socket.sendto(data, address)

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError("验证UDP中继未退出")


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        data = bytearray()
        while len(data) <= 16 * 1024 * 1024:
            block = self.request.recv(65536)
            if not block:
                self.request.sendall(struct.pack("!H", self.server.server_address[1]) + data)
                return
            data.extend(block)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, channel = self.request
        channel.sendto(data, self.client_address)
        if data == b"fullcone":
            with socket.socket(channel.family, socket.SOCK_DGRAM) as other:
                other.bind((self.server.server_address[0], 0))
                other.sendto(b"unsolicited", self.client_address)


def native_echo(stack, ipv6, udp):
    base = socketserver.ThreadingUDPServer if udp else socketserver.ThreadingTCPServer
    class Server(base):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
        daemon_threads = True
        allow_reuse_address = False
        max_packet_size = 65535
        def server_bind(self):
            if ipv6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()
    server = Server(("::1" if ipv6 else "127.0.0.1", 0), UdpEcho if udp else TcpEcho)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return target(server.server_address[0], server.server_address[1])


def account():
    identity = str(uuid.uuid4())
    return {"user_id":identity, "username":"interop_" + identity,
            "password_hash":"$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljLXRlc3Q$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}


def one_case(args, role, ipv6, with_psk, rows):
    host = "::1" if ipv6 else "127.0.0.1"
    name = f"{role}-outer{'6' if ipv6 else '4'}-psk{int(with_psk)}"
    directory = args.run_dir / name
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    def keypair():
        return json.loads(subprocess.check_output([str(args.go_peer), "keygen"], cwd=directory))
    server_key, client_key, other_key = keypair(), keypair(), keypair()
    psk = b64(os.urandom(32)) if with_psk else None
    def rust_tunnel(key, last):
        return {"private_key":key["private_key"], "addresses":[f"10.77.0.{last}", f"fd77::{last}"], "mtu":1280}
    def rust_peer(key, last, secret):
        value = {"public_key":key["public_key"], "allowed_ips":[f"10.77.0.{last}/32", f"fd77::{last}/128"] if last else ["0.0.0.0/0", "::/0"], "persistent_keepalive":1}
        if secret:
            value["preshared_key"] = secret
        return value
    def go_config(key, peer, last, secret, address=""):
        return {"private_key":key["private_key"], "public_key":peer["public_key"], "preshared_key":secret or "",
                "addresses":[f"10.77.0.{last}", f"fd77::{last}"], "allowed_ips":["0.0.0.0/0", "::/0"],
                "endpoint":address, "persistent_keepalive":1, "echo":[]}
    with ExitStack() as stack:
        tcp_targets, udp_targets = [], []
        if role == "outbound":
            cfg = go_config(server_key, client_key, 1, psk)
            cfg["allowed_ips"] = ["10.77.0.2/32", "fd77::2/128"]
            for ip in ["192.0.2.5", "198.51.100.7", "2001:db8::5", "2001:db8::7"]:
                cfg["addresses"].append(ip)
                tcp_targets.append(target(ip, 10080))
                udp_targets.append(target(ip, 1053))
                cfg["echo"].extend([dict(target(ip, 10080), protocol="tcp"), dict(target(ip, 1053), protocol="udp")])
            server_path = directory / "go-server.json"
            write_private(server_path, cfg)
            server = Rpc([str(args.go_peer), str(server_path)], directory, "server")
            stack.callback(server.close)
            server_port = server.ready["listen_port"]
        else:
            for family in [False, True]:
                for _ in range(2):
                    tcp_targets.append(native_echo(stack, family, False))
                    udp_targets.append(native_echo(stack, family, True))
            accounts = [account(), account()]
            members = [{"user_id":accounts[index]["user_id"], "native_credential":rust_peer(key, index + 2, psk)}
                       for index, key in enumerate([client_key, other_key])]
            cfg = {"version":2, "accounts":accounts, "outbounds":[{"tag":"native", "type":"direct"}],
                   "nodes":[{"tag":"wg", "type":"wireguard", "listen":endpoint(host, 0), "outbound":"native",
                             "options":{"tunnel":rust_tunnel(server_key, 1)}, "members":members}],
                   "limits":{"max_sessions":128,"connect_timeout_ms":5000,"idle_timeout_ms":15000,"drain_timeout_ms":3000}}
            server_path = directory / "rust-server.json"
            write_private(server_path, cfg)
            server = Rpc([str(args.rust_peer), "node", str(server_path)], directory, "server")
            stack.callback(server.close)
            server_port = int(server.ready["listeners"][0]["address"].rsplit(":", 1)[1])
        proxy = Proxy(host, server_port)
        stack.callback(proxy.close)
        if role == "outbound":
            client_cfg = {"tunnel":rust_tunnel(client_key, 2), "peer":rust_peer(server_key, None, psk),
                          "endpoint":{"host":host,"port":proxy.port}}
            path = directory / "rust-client.json"
            write_private(path, client_cfg)
            caller = Rpc([str(args.rust_peer), "client", str(path)], directory, "client")
        else:
            client_cfg = go_config(client_key, server_key, 2, psk, endpoint(host, proxy.port))
            path = directory / "go-client.json"
            write_private(path, client_cfg)
            caller = Rpc([str(args.go_peer), str(path)], directory, "client")
        stack.callback(caller.close)
        upload, download = 0, 0
        def check(request, label, expected=None):
            nonlocal upload, download
            result = caller.call(request)
            if request["op"] == "tcp":
                payload = base64.b64decode(request["payload"])
                response = base64.b64decode(result["payload"])
                if response != struct.pack("!H", request["target"]["port"]) + payload:
                    raise RuntimeError("TCP载荷或半关闭回包不一致")
                upload += len(payload)
                download += len(response)
            else:
                packets = request.get("packets") or [{"target":request["target"], "payload":body} for body in request["payloads"]]
                for sent, received in zip(packets, result["packets"]):
                    if received["payload"] != sent["payload"] or received["source"] != endpoint(sent["target"]["host"], sent["target"]["port"]):
                        raise RuntimeError("UDP载荷、原目标或来源不一致，预期来源=" + endpoint(sent["target"]["host"], sent["target"]["port"])
                                           + "，实际来源=" + received["source"] + "，载荷相同=" + str(received["payload"] == sent["payload"])
                                           + "，预期字节=" + str(len(base64.b64decode(sent["payload"]))) + "，实际字节=" + str(len(base64.b64decode(received["payload"]))))
                    upload += len(base64.b64decode(sent["payload"]))
                    download += len(base64.b64decode(received["payload"]))
                if len(result["packets"]) != len(packets) + request.get("extra_receives", 0):
                    raise RuntimeError("UDP数据报数量不一致")
                if request.get("extra_receives"):
                    extra = result["packets"][-1]
                    if base64.b64decode(extra["payload"]) != b"unsolicited" or extra["source"] == result["packets"][0]["source"]:
                        raise RuntimeError("多目标UDP未知来源未保留")
                    download += len(b"unsolicited")
            rows.append({"case":name,"check":label,"result":"passed"})
        for index, item in enumerate(tcp_targets):
            proxy.impaired = index == 0 and not args.no_impairment
            size = args.tcp_bytes if index == 0 else 65537
            check({"op":"tcp","target":item,"payload":b64(bytes(n % 251 for n in range(size)))}, f"tcp-{index}-fin-loss-reorder-replay")
        proxy.impaired = False
        for index, item in enumerate(udp_targets):
            maximum = 65527 if ":" in item["host"] else 65507
            check({"op":"fixed_udp","target":item,"payloads":[b64(bytes([size % 251]) * size) for size in [0, 1, 4096, maximum]]}, f"fixed-udp-{index}-empty-large")
        check({"op":"association_udp","packets":[{"target":item,"payload":b64(struct.pack("!I", index))} for index, item in enumerate(udp_targets)]}, "multi-target-udp")
        check({"op":"association_udp","packets":[{"target":udp_targets[0],"payload":b64(b"fullcone")}],"extra_receives":1}, "full-cone-source")
        monitor = caller if role == "inbound" else server
        before = monitor.call({"op":"snapshot"})
        start = time.monotonic()
        while time.monotonic() - start < args.rotation_seconds:
            time.sleep(1)
            check({"op":"fixed_udp","target":udp_targets[0],"payloads":[b64(b"rotation")]}, "rotation-activity")
        after = monitor.call({"op":"snapshot"})
        if args.rotation_seconds >= 130:
            old = (before.get("last_handshake_time_sec", 0), before.get("last_handshake_time_nsec", 0))
            new = (after.get("last_handshake_time_sec", 0), after.get("last_handshake_time_nsec", 0))
            if not old[0] or new <= old or proxy.counts["handshake_init"] < 2:
                raise RuntimeError("会话轮换未由官方peer确认")
            keepalive = proxy.counts["keepalive"]
            time.sleep(3)
            if proxy.counts["keepalive"] <= keepalive:
                raise RuntimeError("未观察到持久keepalive")
            rows.append({"case":name,"check":"timed-rekey-keepalive","result":"passed","quiet_keepalives":proxy.counts["keepalive"]-keepalive})
        else:
            rows.append({"case":name,"check":"timed-rekey-keepalive","result":"unverified"})
        if role == "inbound":
            usage = server.call({"op":"snapshot"})
            if usage["upload_bytes"] != upload or usage["download_bytes"] != download or usage["users"] != 1:
                raise RuntimeError("唯一业务计量或可信用户归属不一致")
            rows.append({"case":name,"check":"unique-meter","result":"passed"})
        caller.stop()
        if role == "inbound":
            before_negative = server.call({"op":"snapshot"})
            attempts = [(client_key, 4, psk, "spoofed-inner-source"), (keypair(), 2, psk, "unregistered-peer")]
            if with_psk:
                attempts.append((client_key, 2, b64(os.urandom(32)), "wrong-psk"))
            for attempt, (credential, last, secret, label) in enumerate(attempts):
                other_proxy = Proxy(host, server_port)
                stack.callback(other_proxy.close)
                bad_path = directory / f"negative-{attempt}.json"
                write_private(bad_path, go_config(credential, server_key, last, secret, endpoint(host, other_proxy.port)))
                bad = Rpc([str(args.go_peer), str(bad_path)], directory, f"negative-{attempt}")
                stack.callback(bad.close)
                response = bad.call({"op":"fixed_udp","target":udp_targets[0],"payloads":[b64(b"must-reject")]}, allow_failure=True)
                if response.get("ok"):
                    raise RuntimeError("未授权来源获得了业务回包")
                bad.stop()
                current = server.call({"op":"snapshot"})
                if current["upload_bytes"] != before_negative["upload_bytes"] or len(current["records"]) != len(before_negative["records"]):
                    raise RuntimeError("未授权来源创建了业务流")
                rows.append({"case":name,"check":label,"result":"passed"})
            second_proxy = Proxy(host, server_port)
            stack.callback(second_proxy.close)
            second_path = directory / "second-peer.json"
            write_private(second_path, go_config(other_key, server_key, 3, psk, endpoint(host, second_proxy.port)))
            second = Rpc([str(args.go_peer), str(second_path)], directory, "second-peer")
            stack.callback(second.close)
            payload = b"second-authenticated-user"
            response = second.call({"op":"tcp","target":tcp_targets[-1],"payload":b64(payload)})
            expected = struct.pack("!H", tcp_targets[-1]["port"]) + payload
            if base64.b64decode(response["payload"]) != expected:
                raise RuntimeError("第二认证peer回包不一致")
            upload += len(payload)
            download += len(expected)
            second.stop()
            usage = server.call({"op":"snapshot"})
            if usage["users"] != 2 or usage["upload_bytes"] != upload or usage["download_bytes"] != download:
                raise RuntimeError("多个认证peer的计量归属不一致")
            rows.append({"case":name,"check":"multi-peer-identity-and-meter","result":"passed"})
        stopped = server.stop()
        if role == "inbound" and stopped["snapshot"]["active_flows"]:
            raise RuntimeError("Engine关闭后仍有未完成业务流")
        if args.no_impairment:
            rows.append({"case":name,"check":"shutdown-and-actual-impairment","result":"unverified","carrier":dict(proxy.counts)})
        elif not all(proxy.counts[name] > 0 for name in ["dropped", "replayed", "reordered"]):
            raise RuntimeError("TCP扰动未真实发生")
        else:
            rows.append({"case":name,"check":"shutdown-and-actual-impairment","result":"passed","carrier":dict(proxy.counts)})
        if args.tcp_bytes != 1024 * 1024:
            rows.append({"case":name,"check":"tcp-megabyte-boundary","result":"unverified"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-peer", type=Path, required=True)
    parser.add_argument("--go-peer", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--rotation-seconds", type=int, default=135)
    parser.add_argument("--role", choices=["both", "inbound", "outbound"], default="both")
    parser.add_argument("--no-impairment", action="store_true")
    parser.add_argument("--tcp-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--jobs", type=int, default=1)
    expected_cases = {f"{role}-outer{family}-psk{psk}" for role in ["inbound", "outbound"] for family in [4, 6] for psk in [0, 1]}
    parser.add_argument("--case", choices=sorted(expected_cases), action="append", dest="cases")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("互通矩阵只能在海外Linux worker执行")
    if not 0 <= args.rotation_seconds <= 900:
        raise SystemExit("定时轮换观察窗口必须为0至900秒")
    if not 1 <= args.tcp_bytes <= 16 * 1024 * 1024:
        raise SystemExit("TCP诊断载荷必须为1字节至16MiB")
    if not 1 <= args.jobs <= 4:
        raise SystemExit("互通并发配置数必须为1至4")
    args.rust_peer, args.go_peer, args.run_dir = args.rust_peer.resolve(), args.go_peer.resolve(), args.run_dir.resolve()
    args.run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(args.run_dir, 0o700)
    rows = []
    failed = False
    executed_cases = set()
    selected = []
    for role in (["inbound", "outbound"] if args.role == "both" else [args.role]):
        for ipv6 in [False, True]:
            for psk in [False, True]:
                case = f"{role}-outer{6 if ipv6 else 4}-psk{int(psk)}"
                if args.cases and case not in args.cases:
                    continue
                executed_cases.add(case)
                selected.append((role, ipv6, psk, case))
    def execute(parameters):
        role, ipv6, psk, case = parameters
        result = []
        try:
            one_case(args, role, ipv6, psk, result)
            return result, False
        except Exception as error:
            failure = args.run_dir / (case + ".failure.log")
            with failure.open("w", encoding="utf-8") as output:
                os.chmod(failure, 0o600)
                traceback.print_exc(file=output)
            result.append({"case":case, "check":"case", "result":"failed", "error_type":type(error).__name__})
            return result, True
    with ThreadPoolExecutor(max_workers=args.jobs) as workers:
        for result, case_failed in workers.map(execute, selected):
            rows.extend(result)
            failed = failed or case_failed
    for case in sorted(expected_cases - executed_cases):
        rows.append({"case":case, "check":"case", "result":"unverified"})
    adapter = args.go_peer.with_name("netstack-adapter.json")
    report = {"peer_commit":"f333402bd9cbe0f3eeb02507bd14e23d7d639280", "netstack_adapter":json.loads(adapter.read_text(encoding="utf-8")) if adapter.exists() else None,
              "impairment":"one dropped payload frame, two 20ms delays, one replay",
              "rust_peer_sha256":hashlib.sha256(args.rust_peer.read_bytes()).hexdigest(),
              "go_peer_sha256":hashlib.sha256(args.go_peer.read_bytes()).hexdigest(), "rotation_seconds":args.rotation_seconds,"jobs":args.jobs,
              "rows":rows, "complete":not failed and all(row["result"] == "passed" for row in rows)}
    (args.run_dir / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"complete":report["complete"],"passed":sum(row["result"] == "passed" for row in rows),
                      "failed":sum(row["result"] == "failed" for row in rows),"unverified":sum(row["result"] == "unverified" for row in rows)}))
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
