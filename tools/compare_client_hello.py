"""仅在 worker 运行：对同一 client-fingerprint，比较 kerlico 与 mihomo Trojan 出站发出的 ClientHello。

两端各自经本地转发入口拨向回环抓包服务，抓第一条 TLS 记录，比较 JA4 与去 GREASE 后的密码套件顺序、
扩展集合（Chrome 会打乱扩展顺序，按类型排序比较）、supported_groups、signature_algorithms 与 ALPN。
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def grease(value):
    return value & 0x0F0F == 0x0A0A


def u16(data, at):
    return int.from_bytes(data[at:at + 2], "big")


def u16_list(body):
    return [u16(body, 2 + 2 * i) for i in range(u16(body, 0) // 2)]


def shape(record):
    hello = record[5:]
    if record[0] != 0x16 or hello[0] != 1:
        raise ValueError("不是 ClientHello")
    at = 4 + 2 + 32
    at += 1 + hello[at]
    ciphers = [c for c in u16_list(hello[at:]) if not grease(c)]
    at += 2 + u16(hello, at)
    at += 1 + hello[at]
    end = at + 2 + u16(hello, at)
    at += 2
    extensions, groups, sigalgs, alpn, versions = [], [], [], [], []
    while at < end:
        kind, length = u16(hello, at), u16(hello, at + 2)
        body = hello[at + 4:at + 4 + length]
        if kind == 0x000A:
            groups = [g for g in u16_list(body) if not grease(g)]
        elif kind == 0x000D:
            sigalgs = u16_list(body)
        elif kind == 0x0010:
            i, alpn = 2, []
            while i < len(body):
                alpn.append(body[i + 1:i + 1 + body[i]].decode())
                i += 1 + body[i]
        elif kind == 0x002B:
            versions = [v for v in (int.from_bytes(body[1 + 2 * i:3 + 2 * i], "big") for i in range(body[0] // 2)) if not grease(v)]
        if not grease(kind):
            extensions.append(kind)
        at += 4 + length
    version = {0x0304: "13", 0x0303: "12"}.get(max(versions) if versions else u16(hello, 4), "00")
    sorted_ciphers = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ja4_exts = ",".join(f"{e:04x}" for e in sorted(e for e in extensions if e not in (0x0000, 0x0010)))
    ja4_sig = ",".join(f"{s:04x}" for s in sigalgs)
    first_alpn = alpn[0] if alpn else ""
    ja4 = (
        f"t{version}{'d' if 0x0000 in extensions else 'i'}{len(ciphers):02d}{len(extensions):02d}"
        f"{(first_alpn[0] + first_alpn[-1]) if first_alpn else '00'}_"
        f"{hashlib.sha256(sorted_ciphers.encode()).hexdigest()[:12]}_"
        f"{hashlib.sha256((ja4_exts + '_' + ja4_sig).encode()).hexdigest()[:12]}"
    )
    return {
        "ja4": ja4,
        "ciphers": [f"{c:04x}" for c in ciphers],
        "extensions": [f"{e:04x}" for e in sorted(extensions)],
        "groups": [f"{g:04x}" for g in groups],
        "signature_algorithms": [f"{s:04x}" for s in sigalgs],
        "alpn": alpn,
    }


async def capture(port, timeout):
    got = asyncio.get_running_loop().create_future()

    async def handle(reader, writer):
        try:
            header = await reader.readexactly(5)
            body = await reader.readexactly(int.from_bytes(header[3:5], "big"))
            if not got.done():
                got.set_result(header + body)
        except Exception as error:
            if not got.done():
                got.set_exception(error)
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    try:
        return await asyncio.wait_for(got, timeout)
    finally:
        server.close()


async def run_client(command, forward, capture_port, log):
    handle = open(log, "wb")
    process = subprocess.Popen(command, stdout=handle, stderr=handle)
    try:
        record_task = asyncio.create_task(capture(capture_port, 15))
        for _ in range(100):
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", forward)
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            raise RuntimeError(f"转发入口未就绪：{command[0]}")
        try:
            return await record_task
        finally:
            writer.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
        handle.close()


def mihomo_proxy(capture_port, fingerprint):
    return {"name": "proxy", "type": "trojan", "server": "127.0.0.1", "port": capture_port, "password": "synthetic", "sni": "example.com", "client-fingerprint": fingerprint, "udp": False}


def kerlico_config(forward, capture_port, fingerprint):
    """kerlico 读同一条 Mihomo 代理（YAML），经 Mihomo 字段映射得到出站，验证的是用户实际写法。"""
    inbound = {"tag": "tcp", "type": "tcp-forward", "listen": f"127.0.0.1:{forward}", "target": {"host": "example.com", "port": 443}, "outbound": "proxy"}
    proxy = json.dumps(mihomo_proxy(capture_port, fingerprint))
    return f"proxies:\n  - {proxy}\ninbounds:\n  - {json.dumps(inbound)}\n"


def mihomo_config(forward, capture_port, fingerprint):
    proxy = mihomo_proxy(capture_port, fingerprint)
    listener = {"name": "forward", "type": "tunnel", "listen": "127.0.0.1", "port": forward, "network": ["tcp"], "target": "example.com:443", "proxy": "proxy"}
    return {"mode": "rule", "log-level": "error", "proxies": [proxy], "listeners": [listener], "rules": ["MATCH,proxy"]}


async def main(args):
    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    results, mismatches = {}, 0
    for fingerprint in args.fingerprints.split(","):
        shapes = {}
        for kind in ["kerlico", "mihomo"]:
            forward, capture_port = free_port(), free_port()
            if kind == "kerlico":
                config = work / f"kerlico-{fingerprint}.yaml"
                config.write_text(kerlico_config(forward, capture_port, fingerprint))
                command = [args.kerlico, "run", "-c", str(config)]
            else:
                home = work / f"mihomo-{fingerprint}"
                home.mkdir(exist_ok=True)
                config = home / "config.yaml"
                config.write_text(json.dumps(mihomo_config(forward, capture_port, fingerprint)))
                command = [args.mihomo, "-d", str(home), "-f", str(config)]
            try:
                record = await run_client(command, forward, capture_port, work / f"{kind}-{fingerprint}.log")
            except Exception as error:
                shapes[kind] = {"ja4": f"error: {type(error).__name__}"}
                continue
            shapes[kind] = shape(record)
        if any("ciphers" not in shapes[kind] for kind in shapes):
            mismatches += 1
            results[fingerprint] = {"ja4": {kind: shapes[kind]["ja4"] for kind in shapes}, "match": False}
            print(json.dumps({fingerprint: results[fingerprint]}, ensure_ascii=False), flush=True)
            continue
        diff = {key: {kind: shapes[kind][key] for kind in shapes} for key in shapes["kerlico"] if shapes["kerlico"][key] != shapes["mihomo"][key]}
        mismatches += bool(diff)
        results[fingerprint] = {"ja4": {kind: shapes[kind]["ja4"] for kind in shapes}, "match": not diff, "diff": diff}
        print(json.dumps({fingerprint: results[fingerprint]}, ensure_ascii=False), flush=True)
    if mismatches:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="kerlico 与 mihomo 的 uTLS ClientHello 比较")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--fingerprints", default="chrome,firefox")
    os.umask(0o077)
    asyncio.run(main(parser.parse_args()))
