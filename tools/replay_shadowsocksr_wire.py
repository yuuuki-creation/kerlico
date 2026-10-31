"""worker专用：规范化捕获时间和合成目标，确定重放原生对端的非法TLS记录前缀。"""
import argparse
import asyncio
import collections
import collections.abc
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time

import interop_shadowsocksr as t


async def hello_response(reader):
    records = []
    changed = False
    for _ in range(8):
        header = await asyncio.wait_for(reader.readexactly(5), 3)
        size = int.from_bytes(header[3:5], "big")
        if size > 16384:
            raise RuntimeError("参考握手长度异常")
        body = await asyncio.wait_for(reader.readexactly(size), 3)
        records.append(header + body)
        if header[0] == 20:
            changed = True
        elif changed and header[0] == 22:
            return b"".join(records)
    raise RuntimeError("握手记录未结束")


async def main(args):
    collections.MutableMapping = collections.abc.MutableMapping
    sys.path.insert(0, args.reference_source)
    from shadowsocks import encrypt
    captured = json.loads(Path(args.fixture).read_text())
    base_key = encrypt.encrypt_key(t.BASE_PASSWORD.encode(), "aes-128-cfb")
    hello = bytearray(captured["client_hello"])
    mac_key = base_key + bytes(hello[44:76])
    hello[11:15] = int(time.time()).to_bytes(4, "big")
    hello[33:43] = hmac.new(mac_key, bytes(hello[11:33]), hashlib.sha1).digest()[:10]
    finished = bytes(captured["client_finished"])
    if hmac.new(mac_key, finished[:-10], hashlib.sha1).digest()[:10] != finished[-10:]:
        raise RuntimeError("捕获的ClientFinished校验失败")
    first = bytes(captured["first_app_records"])
    iv = first[5:21]
    root = Path(args.work)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = []
    for kind in ["own", "python"]:
        work = root / kind
        work.mkdir(mode=0o700)
        accepted = asyncio.Event()
        async def echo(reader, writer):
            accepted.set()
            try:
                writer.write(b"wire-ready")
                await writer.drain()
                await reader.read()
            finally:
                writer.close()
        target = await asyncio.start_server(echo, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]
        node = t.h.port()
        options = t.server_config("127.0.0.1", node, "aes-128-cfb", "origin", "tls1.2_ticket_auth", False) if kind == "own" else t.reference_config("server", "127.0.0.1", node, 0, "127.0.0.1", target_port, "aes-128-cfb", "origin", "tls1.2_ticket_auth", False, "python")
        active, writer = None, None
        try:
            active = await t.start(args, kind, "server", t.h.save(work, "server.json", options), work / "server.log", "127.0.0.1", node, work)
            reader, writer = await asyncio.open_connection("127.0.0.1", node)
            writer.write(hello)
            await writer.drain()
            response = await hello_response(reader)
            valid_response = hmac.compare_digest(hmac.new(mac_key, response[11:33], hashlib.sha1).digest()[:10], response[33:43]) and hmac.compare_digest(hmac.new(mac_key, response[:-10], hashlib.sha1).digest()[:10], response[-10:])
            if not valid_response:
                raise RuntimeError("服务端握手校验失败")
            # 只将合法地址改为本次合成echo，保留原IV、record结构、Finished及非法前缀。
            address = b"\x01\x7f\0\0\x01" + target_port.to_bytes(2, "big")
            cipher = encrypt.Encryptor(t.BASE_PASSWORD.encode(), "aes-128-cfb", iv).encrypt(address)
            flight = finished + b"\x17\x03\x03\0\x10" + cipher[:16] + b"\x17\x03\x03\0\x07" + cipher[16:]
            writer.write(flight)
            await writer.drain()
            await asyncio.wait_for(accepted.wait(), 3)
            writer.write(bytes(captured["bad_record_prefix"]))
            await writer.drain()
            rejected = False
            try:
                while await asyncio.wait_for(reader.read(4096), 3):
                    pass
                rejected = True
            except (ConnectionResetError, BrokenPipeError):
                rejected = True
            result = {"server": "rust" if kind == "own" else "python", "server_handshake_verified": valid_response, "valid_finished_and_address_accepted": accepted.is_set(), "captured_bad_prefix_rejected": rejected, "pass": valid_response and accepted.is_set() and rejected}
            results.append(result)
            print(json.dumps(result), flush=True)
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
            if active is not None:
                await t.stop(active)
            target.close()
            await target.wait_closed()
    t.h.save(root, "summary.json", {"results": results, "original_peer_sha256": captured["peer_sha256"], "original_pcap_sha256": captured["pcap_sha256"]})
    if len(results) != 2 or not all(row["pass"] for row in results):
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="两种原生服务端的非法TLS记录确定性重放，不代表原生生产者每次都会出错")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--reference-source", required=True)
    parser.add_argument("--fixture", default="crates/protocol-shadowsocksr/tests/fixtures/mihomo-malformed-tls.json")
    parser.add_argument("--work", required=True)
    asyncio.run(main(parser.parse_args()))
