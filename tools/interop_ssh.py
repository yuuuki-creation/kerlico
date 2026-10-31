"""仅在 worker 运行原生 SSH 出站与项目隔离 OpenSSH 容器的互通验证。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import uuid

import interop_vless as h


PASSWORD = "synthetic-ssh-fixture"


class RawEcho(h.TcpEcho):
    def handle(self):
        self.request.settimeout(6)
        data = bytearray()
        try:
            while chunk := self.request.recv(65536):
                data.extend(chunk)
                if len(data) > 1048576:
                    return
            self.request.sendall(data)
        except OSError:
            pass


def port(host="127.0.0.1"):
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as value:
        value.bind((host, 0))
        return value.getsockname()[1]


def execute(command, log):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
    log.write_bytes(result.stdout)
    os.chmod(log, 0o600)
    if result.returncode:
        raise RuntimeError("SSH 参考工具命令失败，详情仅保留在私有日志")
    return result.stdout


def create_key(root, label, algorithm, passphrase=""):
    path = root / label
    command = ["ssh-keygen", "-q", "-t", algorithm, "-N", passphrase, "-C", "", "-f", str(path)]
    if algorithm == "rsa":
        command.extend(["-b", "3072"])
    execute(command, root / (label + "-generate.log"))
    os.chmod(path, 0o600)
    os.chmod(Path(str(path) + ".pub"), 0o600)
    fingerprint = subprocess.check_output(["ssh-keygen", "-l", "-E", "sha256", "-f", str(path) + ".pub"], timeout=10).decode().split()[1]
    return path, fingerprint


def tcp(number, payload):
    with socket.create_connection(("127.0.0.1", number), timeout=5) as stream:
        stream.settimeout(6)
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        result = bytearray()
        while data := stream.recv(65536):
            result.extend(data)
        return bytes(result)


def options(host, number, pin, auth):
    return {"server": {"host": host, "port": number}, "username": "proxy-test", "host_key_sha256": [pin], "auth": auth}


def configure(root, method, client, targets, via_http):
    outbounds = [{"tag": "proxy", "type": "ssh", "options": client}]
    inbounds, cases, nodes = [], [], []
    gateways = [("proxy", "")]
    if via_http:
        gateways = []
        for host in ["127.0.0.1", "::1"]:
            number, tag = port(host), "gateway" + ("6" if ":" in host else "4")
            auth = {"username": "gateway-test", "password": "synthetic-" + tag}
            address = f"[{host}]:{number}" if ":" in host else f"{host}:{number}"
            nodes.append({"tag": tag, "type": "http", "listen": address, "outbound": "proxy", "options": {"auth": auth}})
            outbounds.append({"tag": tag, "type": "http", "options": {"server": {"host": host, "port": number}, "auth": auth}})
            gateways.append((tag, "-" + tag))
    for label, host, number in targets:
        for gateway, suffix in gateways:
            local, name = port(), label + suffix
            inbounds.append({"tag": name, "type": "tcp-forward", "listen": f"127.0.0.1:{local}", "target": {"host": host, "port": number}, "outbound": gateway, "require_remote_eof": True})
            cases.append((name, local))
    for label, change in [("wrong-user", {"username": "denied-test"}), ("wrong-pin", {"host_key_sha256": ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]})]:
        bad = dict(client, **change)
        outbounds.append({"tag": label, "type": "ssh", "options": bad})
        local = port()
        inbounds.append({"tag": label, "type": "tcp-forward", "listen": f"127.0.0.1:{local}", "target": {"host": targets[0][1], "port": targets[0][2]}, "outbound": label})
        cases.append((label, local))
    config = {"version": 1, "outbounds": outbounds, "inbounds": inbounds, "nodes": nodes, "limits": {"connect_timeout_ms": 3000, "idle_timeout_ms": 10000, "drain_timeout_ms": 500, "max_sessions": 64}}
    path = root / (method + ".json")
    h.write_json(path, config)
    return path, cases


def main(args):
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    image = args.image
    if not args.skip_image_build:
        execute(["docker", "build", "--label", "kerlico.task=ssh-reference", "-t", image, "tools/ssh_peer"], root / "image-build.log")
    image_id = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=10).decode().strip()
    image = image_id
    peer_version = subprocess.run(["docker", "run", "--rm", "--entrypoint", "/usr/sbin/sshd", image, "-V"], capture_output=True, timeout=15)
    if peer_version.returncode:
        raise RuntimeError("无法读取隔离 OpenSSH 对端版本")
    h.write_json(root / "reference.json", {"image_id": image_id, "version": (peer_version.stdout + peer_version.stderr).decode().strip()})
    host_keys = {algorithm: create_key(root, "host-" + algorithm, algorithm) for algorithm in ["ed25519", "rsa"]}
    user_keys = {algorithm: create_key(root, "user-" + algorithm, algorithm)[0] for algorithm in ["ed25519", "ecdsa", "rsa"]}
    user_keys["encrypted-ed25519"] = create_key(root, "user-encrypted", "ed25519", "synthetic-passphrase")[0]
    authorized = root / "authorized_keys"
    authorized.write_text("\n".join(Path(str(path) + ".pub").read_text().strip() for path in user_keys.values()) + "\n")
    os.chmod(authorized, 0o600)
    records = []
    with ExitStack() as stack:
        target4 = stack.enter_context(h.serve(h.TcpServer(("127.0.0.1", 0), RawEcho)))
        target6 = stack.enter_context(h.serve(h.TcpServer6(("::1", 0), RawEcho)))
        targets = [("target4", "127.0.0.1", target4), ("target6", "::1", target6), ("domain", "localhost", target4)]
        for host_algorithm, (host_key, pin) in host_keys.items():
            for host in ["127.0.0.1", "::1"]:
                number = port(host)
                name = "kerlico-ssh-peer-" + uuid.uuid4().hex[:12]
                peer_config = root / "sshd_config"
                peer_config.write_text(f"Port {number}\nListenAddress {host}\nHostKey /keys/{host_key.name}\nPidFile /tmp/kerlico-sshd.pid\nPasswordAuthentication yes\nPubkeyAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM no\nPermitEmptyPasswords no\nAllowUsers proxy-test\nAuthorizedKeysFile none\nAuthorizedKeysCommand /bin/cat /keys/authorized_keys\nAuthorizedKeysCommandUser root\nAllowTcpForwarding local\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\nForceCommand /bin/false\nUseDNS no\nMaxStartups 50\nMaxAuthTries 3\nPerSourcePenalties no\n")
                os.chmod(peer_config, 0o600)
                log = (root / (name + ".log")).open("wb")
                command = ["docker", "run", "--rm", "--name", name, "--label", "kerlico.task=ssh-reference", "--network", "host", "--mount", f"type=bind,src={root},dst=/keys,readonly", image]
                peer = subprocess.Popen(command, stdout=log, stderr=log)
                container_index = root / "containers.json"
                owned = json.loads(container_index.read_text()) if container_index.exists() else []
                h.write_json(container_index, owned + [name])
                try:
                    for _ in range(200):
                        if peer.poll() is not None:
                            raise RuntimeError("OpenSSH 隔离对端未启动")
                        try:
                            with socket.create_connection((host, number), timeout=0.2):
                                break
                        except OSError:
                            import time
                            time.sleep(0.03)
                    else:
                        raise RuntimeError("OpenSSH 隔离对端未就绪")
                    for method in ["password", *user_keys]:
                        case = root / (f"{host_algorithm}-{'6' if ':' in host else '4'}-{method}")
                        case.mkdir(mode=0o700)
                        auth = {"type": "password", "password": PASSWORD} if method == "password" else {"type": "publickey", "private_key_file": str(user_keys[method])}
                        if method == "encrypted-ed25519":
                            auth["passphrase"] = "synthetic-passphrase"
                        path, cases = configure(case, method, options(host, number, pin, auth), targets, args.via_http)
                        with h.process([args.kerlico, "run", "-c", str(path)], case, "kernel") as child:
                            h.wait_ready(child, cases[0][1])
                            for label, local in cases:
                                payload = b"ssh-interoperability|" * 4096
                                if label.startswith("wrong-"):
                                    try:
                                        value = tcp(local, payload)
                                    except OSError:
                                        value = b""
                                    passed = not value
                                else:
                                    passed = tcp(local, payload) == payload
                                records.append({"case": case.name, "check": label, "pass": passed})
                            with ThreadPoolExecutor(max_workers=4) as pool:
                                payloads = [bytes([index]) * 32769 for index in range(4)]
                                results = list(pool.map(lambda payload: tcp(cases[0][1], payload), payloads))
                            records.append({"case": case.name, "check": "concurrent", "pass": results == payloads})
                            child.terminate()
                            records.append({"case": case.name, "check": "bounded-shutdown", "pass": child.wait(timeout=3) == 0})
                finally:
                    try:
                        try:
                            subprocess.run(["docker", "stop", "--time", "2", name], capture_output=True, timeout=10)
                        finally:
                            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=10)
                    finally:
                        try:
                            peer.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            peer.kill()
                            peer.wait(timeout=5)
                        log.close()
    summary = {"records": records, "passed": sum(item["pass"] for item in records), "failed": sum(not item["pass"] for item in records), "binary_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "reference_image": image_id}
    h.write_json(root / "result.json", summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH 出站与隔离 OpenSSH 对端验证，仅在 worker 运行")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--image", default="kerlico-ssh-peer:local")
    parser.add_argument("--skip-image-build", action="store_true")
    parser.add_argument("--via-http", action="store_true", help="通过同程序独立 HTTP 节点的统一出口访问 SSH，需要两个 feature")
    main(parser.parse_args())
