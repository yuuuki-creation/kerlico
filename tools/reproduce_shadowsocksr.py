"""worker专用：固定SSR失败参数，三向对照；抓包只限本任务回环节点端口，不延迟业务。"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

import interop_shadowsocksr as t

PAIRS = {"mihomo-rust": ("own", "mihomo"), "mihomo-python": ("python", "mihomo"), "rust-python": ("python", "own")}


async def capture(work, node):
    path = work / "wire.pcap"
    path.touch(mode=0o600)
    output, log = path.open("wb"), (work / "capture.log").open("wb")
    os.chmod(work / "capture.log", 0o600)
    process = subprocess.Popen(["tcpdump", "-n", "-p", "-i", "lo", "-s", "0", "-U", "-w", "-", "tcp", "port", str(node)], stdout=output, stderr=log)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("抓包进程启动失败")
            if "listening on" in (work / "capture.log").read_text():
                return process, output, log
            await asyncio.sleep(0.02)
        raise RuntimeError("抓包进程未就绪")
    except BaseException:
        if process.poll() is None:
            process.terminate()
        await asyncio.to_thread(process.wait, timeout=4)
        output.close()
        log.close()
        raise


async def stop_capture(item, work):
    process, output, log = item
    try:
        # 业务和两端进程已结束后，等内核抓包批次写出；不改变被测连接的回写时序。
        for _ in range(150):
            if (work / "wire.pcap").stat().st_size > 24:
                break
            await asyncio.sleep(0.02)
        process.send_signal(signal.SIGINT)
        await asyncio.to_thread(process.wait, timeout=4)
    finally:
        if process.poll() is None:
            process.kill()
            await asyncio.to_thread(process.wait)
        output.close()
        log.close()


async def native_client(args, config, log, local):
    handle = log.open("wb")
    os.chmod(log, 0o600)
    process = subprocess.Popen([args.kerlico, "run", "-c", str(config)], stdout=handle, stderr=handle)
    item = process, handle, "own"
    try:
        # 不用透明入口探测连接预先生成另一个SSR会话。
        await t.listening(process, local)
        return item
    except BaseException:
        await t.stop(item)
        raise


async def payload(local, target_first, size):
    if size is None:
        return await (t.greeting_tcp(local) if target_first else t.h.tcp(local))
    reader, writer = await asyncio.open_connection("127.0.0.1", local)
    try:
        if target_first and await asyncio.wait_for(reader.readexactly(19), 5) != b"ssr-target-greeting":
            raise RuntimeError("目标问候不符")
        data = b"x" * size
        writer.write(data)
        await writer.drain()
        if await asyncio.wait_for(reader.readexactly(size), 5) != data:
            raise RuntimeError("TCP内容不符")
    finally:
        writer.close()
        await writer.wait_closed()


async def main(args):
    pairs = args.pairs.split(",")
    if any(pair not in PAIRS for pair in pairs) or not 1 <= args.iterations <= 100:
        raise RuntimeError("对照角色或次数不合法")
    if args.payload_bytes is not None and not 1 <= args.payload_bytes <= 2 * 1024 * 1024:
        raise RuntimeError("合成负载须在1字节至2 MiB之间")
    root = Path(args.work)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    method = ("none" if args.protocol.startswith("auth_chain") else "aes-128-cfb") if args.method == "auto" else args.method
    args.peer = args.mihomo
    records = []
    metadata = {"rust_cli_sha256": hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(), "mihomo_sha256": hashlib.sha256(Path(args.mihomo).read_bytes()).hexdigest(), "reference_commit": "fd723a92c488d202b407323f0512987346944136"}
    for pair in pairs:
        for index in range(args.iterations):
            work = root / f"{pair}-{index}"
            work.mkdir(mode=0o700)
            server_kind, client_kind = PAIRS[pair]
            target_seen = [False, 0]
            target, node, local = t.h.port(), t.h.port(), t.h.port()
            active, trace, listener = [], None, None
            row = {"pair": pair, "iteration": index, "protocol": args.protocol, "obfs": args.obfs, "method": method, "traffic_pattern": "target-first" if args.target_greeting else "client-first", "payload_bytes": args.payload_bytes or (77824 if args.target_greeting else 59392), "node_port": node, "pass": False}
            async def echo(reader, writer):
                target_seen[0] = True
                try:
                    if args.target_greeting:
                        writer.write(b"ssr-target-greeting")
                        await writer.drain()
                    while data := await reader.read(16384):
                        target_seen[1] += len(data)
                        writer.write(data)
                        await writer.drain()
                except (OSError, ConnectionError):
                    pass
                finally:
                    writer.close()
            try:
                if args.capture:
                    trace = await capture(work, node)
                listener = await asyncio.start_server(echo, "127.0.0.1", target)
                config = t.server_config("127.0.0.1", node, method, args.protocol, args.obfs, False) if server_kind == "own" else t.reference_config("server", "127.0.0.1", node, local, "127.0.0.1", target, method, args.protocol, args.obfs, False, "python")
                active.append(await t.start(args, server_kind, "server", t.h.save(work, "server.json", config), work / "server.log", "127.0.0.1", node, work))
                config = t.client_config(local, "127.0.0.1", node, "127.0.0.1", target, method, args.protocol, args.obfs, False) if client_kind == "own" else t.reference_config("client", "127.0.0.1", node, local, "127.0.0.1", target, method, args.protocol, args.obfs, False, "mihomo")
                path = t.h.save(work, "client.json", config)
                if client_kind == "own":
                    active.append(await native_client(args, path, work / "client.log", local))
                else:
                    active.append(await t.start(args, client_kind, "client", path, work / "client.log", "127.0.0.1", local, work))
                await payload(local, args.target_greeting, args.payload_bytes)
                row["pass"] = True
            except Exception as error:
                row["error"] = type(error).__name__
                if isinstance(error, asyncio.IncompleteReadError):
                    row.update(expected_bytes=error.expected, received_bytes=len(error.partial))
            finally:
                row.update(target_accepted=target_seen[0], target_received_bytes=target_seen[1])
                if active:
                    row["server_exit_before_stop"] = active[0][0].poll()
                    row["client_exit_before_stop"] = active[-1][0].poll()
                for item in reversed(active):
                    try:
                        await t.stop(item)
                    except Exception as error:
                        row.update({"pass": False, "shutdown_error": type(error).__name__})
                if listener is not None:
                    listener.close()
                    await listener.wait_closed()
                if trace is not None:
                    await stop_capture(trace, work)
                    row["pcap_sha256"] = hashlib.sha256((work / "wire.pcap").read_bytes()).hexdigest()
            records.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)
            if not row["pass"] and args.until_failure:
                break
    summary = {"metadata": metadata, "records": records, "passed": sum(row["pass"] for row in records), "failed": sum(not row["pass"] for row in records)}
    t.h.save(root, "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="固定SSR用例的三向原生对端复现，不加入业务延迟")
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--reference-source", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--protocol", choices=t.PROTOCOLS, required=True)
    parser.add_argument("--obfs", choices=t.OBFS, required=True)
    parser.add_argument("--method", default="auto")
    parser.add_argument("--pairs", default=",".join(PAIRS))
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--target-greeting", action="store_true")
    parser.add_argument("--payload-bytes", type=int)
    parser.add_argument("--until-failure", action="store_true")
    parser.add_argument("--capture", action="store_true")
    asyncio.run(main(parser.parse_args()))
