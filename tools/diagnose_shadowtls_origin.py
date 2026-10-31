#!/usr/bin/env python3
"""在 worker 回环独立测量 OpenSSL -www 的并发握手条件，不经过代理核心。"""
import argparse
from contextlib import closing
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
from interop_shadowtls import ConcurrentOrigin

def main():
    parser = argparse.ArgumentParser(description="仅在 worker 运行的 TLS 握手站点并发对照")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--origin-kind", choices=("openssl-serial", "concurrent"), default="openssl-serial")
    parser.add_argument("--tls-version", choices=("1.2", "1.3"), default="1.3")
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(Path(args.certificate).resolve()))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2 if args.tls_version == "1.2" else ssl.TLSVersion.TLSv1_3
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    def connect(timeout):
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            return context.wrap_socket(raw, server_hostname="shadowtls.example.invalid")
        except BaseException:
            raw.close()
            raise
    with tempfile.TemporaryDirectory(prefix="shadowtls-origin-control-") as directory:
        with open(Path(directory)/"origin.log", "wb") as log:
            if args.origin_kind == "concurrent":
                child = ConcurrentOrigin(Path(args.certificate).resolve(), Path(args.key).resolve(), port, args.tls_version, 2, None)
                child.__enter__()
            else:
                child = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", "127.0.0.1:"+str(port), "-cert", str(Path(args.certificate).resolve()), "-key", str(Path(args.key).resolve()), "-www", "-tls1_2" if args.tls_version == "1.2" else "-tls1_3"], stdout=log, stderr=subprocess.STDOUT)
            try:
                first = None
                deadline = time.monotonic()+3
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
                print(json.dumps({"origin_kind": args.origin_kind, "tls_version": args.tls_version, "first_handshake": True, "second_while_first_open": concurrent, "after_first_closed": recovered}, ensure_ascii=False))
            finally:
                if args.origin_kind == "concurrent":
                    child.__exit__(None, None, None)
                else:
                    child.terminate()
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=2)
if __name__ == "__main__":
    main()
