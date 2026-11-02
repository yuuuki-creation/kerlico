#!/usr/bin/env python3
"""只用自有回环进程和线程检查ShadowTLS工具的归属、退出与回收。"""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import sys
import threading

import interop_shadowtls as s


def child(config_path):
    config = json.loads(Path(config_path).read_text())
    if config["mode"] == "exit":
        return 7
    if os.name != "nt":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    family = socket.AF_INET6 if ":" in config["host"] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        if os.name == "nt":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((config["host"], config["port"]))
        listener.listen()
        while True:
            connection, _ = listener.accept()
            with connection:
                Path(config["accepted"]).write_text("accepted", encoding="ascii")
                connection.sendall(b"owned")


def checks(args, root):
    results = []
    for index, host in enumerate(("127.0.0.1", "::1")):
        port = s.h.free_port()
        accepted = root/("accepted-"+str(index)+".txt")
        config = root/("listener-"+str(index)+".json")
        s.h.write_json(config, {"mode": "listen", "host": host, "port": port, "accepted": str(accepted)})
        with s.process([sys.executable, str(Path(__file__).resolve()), "--child-config", str(config)], root, "listener-"+str(index)) as process:
            s.wait_listener(process, (host, port))
            if not s.owned_listener(process.pid, (host, port)):
                raise RuntimeError("自有子进程监听未被识别")
            if s.owned_listener(os.getpid(), (host, port)):
                raise RuntimeError("监听被错误归属到父进程")
            if accepted.exists():
                raise RuntimeError("监听就绪检查不应建立TCP业务连接")
            with socket.create_connection((host, port), timeout=2) as stream:
                if s.exact(stream, 5) != b"owned":
                    raise RuntimeError("自有监听问候失败")
            s.stop_process(process, "平台检查监听")
        results.append({"check": "监听归属与无探针就绪", "family": "IPv6" if ":" in host else "IPv4", "ok": True})
    try:
        s.owned_listener(os.getpid(), ("192.0.2.1", 1))
    except RuntimeError:
        results.append({"check": "非回环查询拒绝", "ok": True})
    else:
        raise RuntimeError("非回环查询未拒绝")

    early = root/"early-exit.json"
    s.h.write_json(early, {"mode": "exit"})
    rejected = False
    try:
        with s.process([sys.executable, str(Path(__file__).resolve()), "--child-config", str(early)], root, "early-exit") as process:
            process.wait(timeout=3)
            try:
                s.stop_process(process, "预期提前退出样本")
            except RuntimeError as error:
                rejected = "意外退出" in str(error)
            if not rejected:
                raise RuntimeError("提前退出被误记为请求后的强制清理")
    except RuntimeError as error:
        if not rejected or "意外退出" not in str(error):
            raise
    results.append({"check": "请求停止前意外退出单列", "ok": True})

    entered = threading.Event()
    class Waiting(socketserver.BaseRequestHandler):
        def handle(self):
            entered.set()
            try:
                self.request.recv(1)
            except OSError:
                if not self.server.closing:
                    raise
    connection = None
    server = s.OwnedTcpServer(("127.0.0.1", s.h.free_port()), Waiting)
    try:
        with server:
            s.wait_listener(server, server.server_address)
            connection = socket.create_connection(server.server_address, timeout=2)
            if not entered.wait(timeout=2):
                raise RuntimeError("等待关闭的handler未启动")
    finally:
        if connection is not None:
            connection.close()
    if server.cleanup["handler_threads_started"] != 1 or server.cleanup["handler_threads_joined"] != 1:
        raise RuntimeError("未join全部等待中的handler")
    results.append({"check": "关闭自有连接后join全部handler", "ok": True, "cleanup": server.cleanup})

    failed = threading.Event()
    class Broken(socketserver.BaseRequestHandler):
        def handle(self):
            failed.set()
            raise RuntimeError("预期handler失败样本")
    server = s.OwnedTcpServer(("127.0.0.1", s.h.free_port()), Broken)
    try:
        with server:
            with socket.create_connection(server.server_address, timeout=2):
                if not failed.wait(timeout=2):
                    raise RuntimeError("错误handler未启动")
    except RuntimeError:
        if not server.cleanup or server.cleanup["errors"] != ["handler:RuntimeError"] or server.cleanup["handler_threads_alive"]:
            raise
    else:
        raise RuntimeError("handler退出错误被吞掉")
    results.append({"check": "handler退出错误使夹具失败", "ok": True})

    server = s.OwnedTcpServer(("127.0.0.1", 0), Waiting)
    worker_read, worker_write = socket.socketpair()
    worker_entered = threading.Event()
    def waiting_worker():
        worker_entered.set()
        try:
            worker_read.recv(1)
        except OSError:
            if not server.closing:
                raise
        finally:
            server.release_connection(worker_read)
            worker_read.close()
    try:
        with server:
            if not server.track_connection(worker_read):
                raise RuntimeError("辅助线程的自有连接未登记")
            server.start_worker(waiting_worker)
            if not worker_entered.wait(timeout=2):
                raise RuntimeError("等待关闭的辅助线程未启动")
    finally:
        worker_read.close()
        worker_write.close()
    if server.cleanup["auxiliary_threads_started"] != 1 or server.cleanup["auxiliary_threads_joined"] != 1:
        raise RuntimeError("未join等待自有连接关闭的辅助线程")
    results.append({"check": "关闭自有连接后join活跃辅助线程", "ok": True, "cleanup": server.cleanup})

    server = s.OwnedTcpServer(("127.0.0.1", 0), Waiting)
    worker_failed = threading.Event()
    def broken_worker():
        worker_failed.set()
        raise RuntimeError("预期辅助线程失败样本")
    try:
        with server:
            server.start_worker(broken_worker)
            if not worker_failed.wait(timeout=2):
                raise RuntimeError("错误辅助线程未启动")
    except RuntimeError:
        if not server.cleanup or server.cleanup["errors"] != ["worker:RuntimeError"] or server.cleanup["auxiliary_threads_alive"]:
            raise
    else:
        raise RuntimeError("辅助线程退出错误被吞掉")
    results.append({"check": "辅助线程退出错误使夹具失败", "ok": True})

    cert, key = s.material(root, args.openssl)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(cert))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    origin = s.ConcurrentOrigin(cert, key, s.h.free_port(), "1.3", 2, None)
    connection = None
    try:
        with origin:
            s.wait_listener(origin, origin.server_address)
            with closing(socket.create_connection(origin.server_address, timeout=2)) as raw:
                connection = context.wrap_socket(raw, server_hostname="shadowtls.example.invalid")
    finally:
        if connection is not None:
            connection.close()
    results.append({"check": "真实TLS连接未主动关闭时仍回收全部站点handler", "ok": True, "cleanup": origin.cleanup})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir")
    parser.add_argument("--openssl")
    parser.add_argument("--listen-port-range")
    parser.add_argument("--child-config", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child_config:
        raise SystemExit(child(args.child_config))
    if not args.work_dir:
        parser.error("需要项目独立--work-dir")
    os.umask(0o077)
    root = Path(args.work_dir).resolve()
    root.mkdir(parents=True, mode=0o700)
    ports = s.configure_ports(None, args.listen_port_range)
    results = checks(args, root)
    s.h.write_json(root/"results.json", {"ports": ports, "results": results})
    print(json.dumps({"ok": True, "checks": len(results)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
