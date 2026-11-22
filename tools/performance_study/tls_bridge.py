"""TLS termination on the load side for clients without a plaintext AnyTLS transport."""
import argparse
import asyncio
import ssl


async def copy(reader, writer):
    while block := await reader.read(65536):
        writer.write(block)
        await writer.drain()
    if writer.can_write_eof():
        writer.write_eof()


async def serve(args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    async def handle(reader, writer):
        peer_reader, peer_writer = await asyncio.open_connection(args.target, args.port)
        try:
            readers = [asyncio.create_task(copy(reader, peer_writer)), asyncio.create_task(copy(peer_reader, writer))]
            try:
                await asyncio.wait(readers, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for task in readers:
                    task.cancel()
                await asyncio.gather(*readers, return_exceptions=True)
        finally:
            peer_writer.close()
            writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", args.listen, ssl=ctx)
    async with server:
        print("listening", flush=True)
        await server.serve_forever()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("listen", type=int)
    p.add_argument("target")
    p.add_argument("port", type=int)
    p.add_argument("cert")
    p.add_argument("key")
    asyncio.run(serve(p.parse_args()))
