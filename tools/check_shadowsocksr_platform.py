import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import interop_shadowsocksr as ssr


def child(config_path):
    value = json.loads(Path(config_path).read_text(encoding="utf-8"))
    ssr.require_loopback(value["host"])
    family = socket.AF_INET6 if ":" in value["host"] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        if os.name == "nt":
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        listener.bind((value["host"], value["port"]))
        listener.listen()
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.sendall(b"synthetic-ssr-platform-ready")


async def main(args):
    root = Path(args.work).resolve()
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    ssr.PORT_LEASE = root / "ports.lock"
    records = []
    for host in ["127.0.0.1", "::1"]:
        try:
            with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind((host, 0))
        except OSError:
            if host == "::1":
                records.append({"family": 6, "status": "unavailable"})
                continue
            raise
        port = ssr.h.port(host)
        config = root / ("listener6.json" if ":" in host else "listener4.json")
        config.write_text(json.dumps({"host": host, "port": port}), encoding="utf-8")
        os.chmod(config, 0o600)
        log = root / (config.stem + ".log")
        creation = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
        with log.open("wb") as handle:
            os.chmod(log, 0o600)
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child-config", str(config)], cwd=root, stdout=handle, stderr=handle, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"), **creation)
            try:
                await ssr.listening(process, port, host)
                owned = ssr.windows_listening if os.name == "nt" else ssr.linux_listening
                if owned(os.getpid(), host, port):
                    raise RuntimeError("监听归属错误地接受了父进程PID")
                if ssr.h.port(host) == port:
                    raise RuntimeError("端口租约重复分配了活动端口")
                reader, writer = await asyncio.open_connection(host, port)
                try:
                    greeting = await asyncio.wait_for(reader.readexactly(28), 2)
                    if greeting != b"synthetic-ssr-platform-ready":
                        raise RuntimeError("本任务子进程问候不符")
                finally:
                    writer.close()
                    await writer.wait_closed()
                records.append({"family": 6 if ":" in host else 4, "status": "passed", "owned_listener": True, "foreign_pid_rejected": True, "lease_distinct": True})
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    await asyncio.to_thread(process.wait, timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    await asyncio.to_thread(process.wait)
                    raise RuntimeError("本任务监听进程清理超时")
    rejected = False
    try:
        ssr.require_loopback("192.0.2.1")
    except RuntimeError:
        rejected = True
    if not rejected:
        raise RuntimeError("隔离工具接受了非回环地址")
    summary = {"platform": sys.platform, "records": records, "non_loopback_rejected": True, "graceful_shutdown_checked": False}
    (root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSR测试工具的自有PID监听与任务端口租约检查")
    parser.add_argument("--work")
    parser.add_argument("--child-config")
    arguments = parser.parse_args()
    if arguments.child_config:
        child(arguments.child_config)
    elif arguments.work:
        asyncio.run(main(arguments))
    else:
        parser.error("需要--work或本任务生成的--child-config")
