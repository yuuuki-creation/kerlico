#!/usr/bin/env python3
import argparse
from contextlib import closing, ExitStack
import json
import os
from pathlib import Path
import socket
import ssl
import time
from interop_shadowtls import ConcurrentOrigin, configure_ports, h, process, resolve_openssl, wait_listener

def main():
    parser = argparse.ArgumentParser(description="项目隔离回环 TLS 握手站点并发对照")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--openssl", help="独立OpenSSL可执行文件")
    parser.add_argument("--listen-port-range")
    parser.add_argument("--origin-kind", choices=("openssl-serial", "concurrent"), default="openssl-serial")
    parser.add_argument("--tls-version", choices=("1.2", "1.3"), default="1.3")
    args = parser.parse_args()
    os.umask(0o077)
    ports = configure_ports(None, args.listen_port_range)
    openssl = resolve_openssl(args.openssl) if args.origin_kind == "openssl-serial" else None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(Path(args.certificate).resolve()))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if args.tls_version == "1.2" else ssl.TLSVersion.TLSv1_3
    port = h.free_port()
    def connect(timeout):
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            return context.wrap_socket(raw, server_hostname="shadowtls.example.invalid")
        except BaseException:
            raw.close()
            raise
    directory = Path(args.work_dir).resolve()
    directory.mkdir(parents=True, mode=0o700)
    result = None
    cleanup = None
    with ExitStack() as stack:
        if args.origin_kind == "concurrent":
            child = stack.enter_context(ConcurrentOrigin(Path(args.certificate).resolve(), Path(args.key).resolve(), port, args.tls_version, 2, None))
        else:
            child = stack.enter_context(process([openssl, "s_server", "-quiet", "-accept", "127.0.0.1:"+str(port), "-cert", str(Path(args.certificate).resolve()), "-key", str(Path(args.key).resolve()), "-www", "-tls1_2" if args.tls_version == "1.2" else "-tls1_3"], directory, "origin"))
        first = None
        deadline = time.monotonic()+3
        wait_listener(child, ("127.0.0.1", port), timeout=3)
        while time.monotonic() < deadline:
            try:
                first = connect(0.5)
                break
            except OSError:
                if child.poll() is not None:
                    raise RuntimeError("独立 TLS 站点提前退出") from None
                time.sleep(0.03)
        if first is None:
            raise RuntimeError("首条真实 TLS 握手失败")
        with closing(first):
            try:
                with closing(connect(0.5)):
                    concurrent = "已完成"
            except (OSError, TimeoutError) as error:
                concurrent = type(error).__name__
        with closing(connect(2)):
            recovered = True
        result = {"origin_kind": args.origin_kind, "tls_version": args.tls_version, "first_handshake": True, "second_while_first_open": concurrent, "after_first_closed": recovered, "ports": ports}
    if args.origin_kind == "concurrent":
        cleanup = {"kind": "全部handler已join且自有连接已关闭", "details": child.cleanup, "graceful_drain_verified": False}
    else:
        cleanup = json.loads((directory/"origin-cleanup.json").read_text())
    result["cleanup"] = cleanup
    print(json.dumps(result, ensure_ascii=False))
if __name__ == "__main__":
    main()
