"""在 worker 测量参考对端的直连 UDP 入口，不经过 kerlico 或代理协议。"""
import argparse
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket


def load_helpers():
    location = Path(__file__).with_name("interop_shadowsocks.py")
    spec = importlib.util.spec_from_file_location("shadowsocks_interop", location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def main(args):
    helpers = load_helpers()
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    target_port, forward_port = helpers.port(), helpers.port()
    target, _ = await asyncio.get_running_loop().create_datagram_endpoint(helpers.UdpEcho, local_addr=("127.0.0.1", target_port))
    config = helpers.peer_client(args.peer_kind, forward_port, "127.0.0.1", 1, "127.0.0.1", target_port, "aes-128-gcm", "synthetic-control")
    config["outbounds"] = [{"type": "direct", "tag": "proxy"}] if args.peer_kind == "sing-box" else [{"protocol": "freedom"}]
    process, handle = await helpers.start(args.peer, args.peer_kind, helpers.save(root, "config.json", config), root / "control.log", "127.0.0.1", forward_port)
    records = []
    try:
        loop = asyncio.get_running_loop()
        for size in [3, 12000, 0]:
            record = {"payload_bytes": size, "expected_bytes": size + 5}
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setblocking(False)
                payload = b"u" * size
                await loop.sock_sendto(sock, payload, ("127.0.0.1", forward_port))
                try:
                    received, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 4)
                    record.update(received_bytes=len(received), matches=received == b"echo|" + payload)
                except asyncio.TimeoutError:
                    record.update(received_bytes=None, matches=False, timeout=True)
            records.append(record)
    finally:
        await helpers.stop(process, handle)
        target.close()
    summary = {"peer_kind": args.peer_kind, "direct_ingress": records}
    helpers.save(root, "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="参考入口 UDP 零包与包长对照测量")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--peer-kind", choices=["xray", "sing-box"], required=True)
    parser.add_argument("--work", required=True)
    asyncio.run(main(parser.parse_args()))
