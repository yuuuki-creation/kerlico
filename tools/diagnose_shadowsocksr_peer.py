"""worker 专用：显式延迟参考客户端的首个服务端 TCP 回写，定位即时握手兼容性；不计直接互通。"""
import argparse
import asyncio
import json
from pathlib import Path
import interop_shadowsocksr as t


async def main(args):
    root = Path(args.work)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = []
    for protocol in args.protocols.split(","):
        for obfs in args.obfs.split(","):
            method = "none" if protocol.startswith("auth_chain") else "aes-128-cfb"
            work = root / (protocol + "-" + obfs)
            work.mkdir(mode=0o700)
            backend, local, target = t.h.port(), t.h.port(), t.h.port()
            async def relay(reader, writer, backend_port=backend):
                remote_writer = None
                try:
                    remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", backend_port)
                    async def pump(source, destination, delay):
                        first = True
                        while data := await source.read(4096):
                            if first and delay:
                                await asyncio.sleep(delay)
                            first = False
                            destination.write(data)
                            await destination.drain()
                        if destination.can_write_eof():
                            destination.write_eof()
                    await asyncio.gather(pump(reader, remote_writer, 0), pump(remote_reader, writer, args.reply_delay_ms / 1000))
                except (ConnectionError, OSError):
                    pass
                finally:
                    for stream in [writer, remote_writer]:
                        if stream is not None:
                            stream.close()
            gateway = await asyncio.start_server(relay, "127.0.0.1", 0)
            front = gateway.sockets[0].getsockname()[1]
            async def echo_target(reader, writer):
                if args.target_greeting:
                    writer.write(b"ssr-target-greeting")
                    await writer.drain()
                await t.h.echo(reader, writer)
            echo = await asyncio.start_server(echo_target, "127.0.0.1", target)
            active = []
            try:
                cfg = t.server_config("127.0.0.1", backend, method, protocol, obfs, False) if args.server_kind == "kerlico" else t.reference_config("server", "127.0.0.1", backend, local, "127.0.0.1", target, method, protocol, obfs, False, "python")
                active.append(await t.start(args, "own" if args.server_kind == "kerlico" else "python", "server", t.h.save(work, "server.json", cfg), work / "server.log", "127.0.0.1", backend, work))
                cfg = t.reference_config("client", "127.0.0.1", front, local, "127.0.0.1", target, method, protocol, obfs, False, "mihomo")
                active.append(await t.start(args, "mihomo", "client", t.h.save(work, "client.json", cfg), work / "client.log", "127.0.0.1", local, work))
                record = {"protocol": protocol, "obfs": obfs, "server_kind": args.server_kind, "reply_delay_ms": args.reply_delay_ms, "traffic_pattern": "target-first" if args.target_greeting else "client-first", "pass": True}
                try:
                    await (t.greeting_tcp(local) if args.target_greeting else t.h.tcp(local))
                except Exception as error:
                    record.update({"pass": False, "error": type(error).__name__})
                records.append(record)
                print(json.dumps(record), flush=True)
            finally:
                for item in reversed(active):
                    try:
                        await t.stop(item)
                    except Exception as error:
                        records.append({"protocol": protocol, "obfs": obfs, "network": "shutdown", "pass": False, "error": type(error).__name__})
                gateway.close()
                echo.close()
                await gateway.wait_closed()
                await echo.wait_closed()
    summary = {"records": records, "passed": sum(record["pass"] for record in records), "failed": sum(not record["pass"] for record in records)}
    t.h.save(root, "summary.json", summary)
    print(json.dumps(summary), flush=True)
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--server-kind", choices=["kerlico", "python"], required=True)
    parser.add_argument("--reference-source")
    parser.add_argument("--work", required=True)
    parser.add_argument("--protocols", default=",".join(t.PROTOCOLS))
    parser.add_argument("--obfs", default=",".join(t.OBFS))
    parser.add_argument("--reply-delay-ms", type=int, default=20)
    parser.add_argument("--target-greeting", action="store_true")
    asyncio.run(main(parser.parse_args()))
