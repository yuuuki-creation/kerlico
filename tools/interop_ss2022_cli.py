"""在 worker 验收正式 kerlico CLI 的 SS2022 装配；不修改系统配置或已有服务。"""
import argparse
import asyncio
import base64
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def key(length=16):
    return base64.b64encode(os.urandom(length)).decode()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    os.chmod(path, 0o600)
    return path


class Echo(asyncio.DatagramProtocol):
    def __init__(self, prefix, payloads):
        self.prefix, self.payloads = prefix, payloads
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, packet, peer):
        self.payloads.append(packet)
        self.transport.sendto(self.prefix + packet, peer)


async def tcp_echo(reader, writer, prefix, payloads):
    received = bytearray()
    try:
        writer.write(prefix)
        await writer.drain()
        while packet := await reader.read(16384):
            received.extend(packet)
            writer.write(packet)
            await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        await writer.drain()
    except (OSError, ConnectionError):
        pass
    finally:
        if received:
            payloads.append(bytes(received))
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def wait_ready(host, port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("正式 CLI 启动后提前退出")
        try:
            _, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.05)
            return
        except OSError:
            await asyncio.sleep(0.03)
    raise RuntimeError("正式 CLI 未就绪")


async def start(binary, config, log, host, port):
    handle = log.open("wb")
    os.chmod(log, 0o600)
    process = subprocess.Popen([binary, "run", "-c", str(config)], stdout=handle, stderr=handle)
    try:
        await wait_ready(host, port, process)
    except BaseException:
        if process.poll() is None:
            process.terminate()
        await asyncio.to_thread(process.wait, timeout=3)
        handle.close()
        raise
    return process, handle


async def stop(process, handle):
    began = time.monotonic()
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        code = await asyncio.to_thread(process.wait, timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        await asyncio.to_thread(process.wait)
        raise RuntimeError("正式 CLI 超出退出预算")
    finally:
        handle.close()
    if code != 0:
        raise RuntimeError("正式 CLI 退出状态不是零")
    if time.monotonic() - began > 2:
        raise RuntimeError("正式 CLI 未在集成退出上限内完成")


async def tcp_check(port, prefix, payload=b"cli-tcp"):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    # 先读取目标主动发送的数据，核对出站无业务早数据时也能完成握手。
    banner = await asyncio.wait_for(reader.readexactly(len(prefix)), 2)
    if banner != prefix:
        raise RuntimeError("正式 TCP 路径目标地址族不符")
    writer.write(payload)
    await writer.drain()
    received = await asyncio.wait_for(reader.readexactly(len(payload)), 2)
    if received != payload:
        raise RuntimeError("正式 TCP 路径负载不符")
    writer.write_eof()
    if await asyncio.wait_for(reader.read(), 2):
        raise RuntimeError("正式 TCP 路径出现额外数据")
    writer.close()
    await writer.wait_closed()


async def udp_check(port, prefix, payload=b"cli-udp"):
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        await loop.sock_sendto(sock, payload, ("127.0.0.1", port))
        received, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 2)
        if received != prefix + payload:
            raise RuntimeError("正式 UDP 路径目标地址族或负载不符")


async def reject_tcp(port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        try:
            writer.write(b"bad-key-tcp")
            await writer.drain()
            result = await asyncio.wait_for(reader.read(1), 1.5)
            if result:
                raise RuntimeError("错误凭据获得了目标数据")
        except (OSError, asyncio.TimeoutError):
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def reject_udp(port):
    loop = asyncio.get_running_loop()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        await loop.sock_sendto(sock, b"bad-key-udp", ("127.0.0.1", port))
        try:
            await asyncio.wait_for(loop.sock_recvfrom(sock, 65536), 0.2)
        except asyncio.TimeoutError:
            return
        raise RuntimeError("错误 UDP 凭据获得了数据")


def limits(global_sessions=128):
    return {"connect_timeout_ms": 1000, "idle_timeout_ms": 1500, "drain_timeout_ms": 500, "max_sessions": global_sessions, "udp_queue_packets": 16, "max_datagram_size": 65000}


def node(tag, host, port, secret, sessions=32):
    return {"tag": tag, "type": "ss2022", "listen": f"[{host}]:{port}" if ":" in host else f"{host}:{port}", "outbound": "direct", "max_sessions": sessions, "options": {"method": "2022-blake3-aes-128-gcm", "key": secret}}


def base(nodes, global_sessions=128):
    return {"version": 1, "outbounds": [{"tag": "direct", "type": "direct"}], "inbounds": [], "nodes": nodes, "limits": limits(global_sessions)}


def check(binary, file, expected=True, fragment=None):
    result = subprocess.run([binary, "check", "-c", str(file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
    if (result.returncode == 0) != expected:
        raise RuntimeError("CLI 配置验收状态不符")
    if fragment and fragment not in result.stdout + result.stderr:
        raise RuntimeError("CLI 配置拒绝类别不符")


async def probe(binary, file):
    process = await asyncio.create_subprocess_exec(binary, str(file), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise RuntimeError("原生探针超时")
    if process.returncode:
        raise RuntimeError("原生探针失败：" + stderr.decode(errors="replace")[-300:])
    return json.loads(stdout)


async def main(args):
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    records = []
    payloads = []
    port = free_port()
    tcp4 = await asyncio.start_server(lambda r, w: tcp_echo(r, w, b"v4|", payloads), "127.0.0.1", port)
    tcp6 = await asyncio.start_server(lambda r, w: tcp_echo(r, w, b"v6|", payloads), "::1", port)
    udp4, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Echo(b"v4|", payloads), local_addr=("127.0.0.1", port))
    udp6, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Echo(b"v6|", payloads), local_addr=("::1", port))
    active = []
    try:
        modules = subprocess.check_output([args.kerlico, "modules"], text=True).splitlines()
        if set(modules) != {"outbound/direct", "outbound/reject", "outbound/ss2022", "inbound/ss2022"}:
            raise RuntimeError("SS2022 构建的模块剪裁不符")
        bare = subprocess.check_output([args.minimal, "modules"], text=True).splitlines()
        if set(bare) != {"outbound/direct", "outbound/reject"}:
            raise RuntimeError("无协议构建的模块剪裁不符")
        records.append({"case": "feature-modules", "pass": True})

        node_port = free_port()
        a, b = key(), key()
        server = base([node("node4", "127.0.0.1", node_port, a), node("node6", "::1", node_port, b)])
        server_file = save(root / "server-only.json", server)
        check(args.minimal, server_file, False, "节点协议未注册")
        check(args.kerlico, server_file)
        direct_config = base([])
        direct_config["inbounds"] = [{"tag": "direct-forward", "type": "tcp-forward", "listen": "127.0.0.1:" + str(free_port()), "target": {"host": "127.0.0.1", "port": port}, "outbound": "direct"}]
        check(args.minimal, save(root / "minimal-direct.json", direct_config))
        records.append({"case": "minimal-config-crop", "pass": True})

        for name, mutate, fragment in [
            ("duplicate-service-key", lambda c: c["nodes"][1]["options"].update(key=a), "节点认证凭据重复"),
            ("duplicate-user-key", lambda c: [n["options"].update(users=[key_shared]) for n in c["nodes"]], "节点认证凭据重复"),
            ("mapped-listen", lambda c: c["nodes"][1].update(listen="[::ffff:127.0.0.1]:" + str(node_port)), "IPv4-mapped"),
            ("udp-listen-collision", lambda c: c["inbounds"].append({"tag": "collision", "type": "udp-forward", "listen": "127.0.0.1:" + str(node_port), "target": {"host": "127.0.0.1", "port": port}, "outbound": "direct"}), "监听地址重复"),
        ]:
            key_shared = key()
            invalid = copy.deepcopy(server)
            mutate(invalid)
            check(args.kerlico, save(root / (name + ".json"), invalid), False, fragment)
            records.append({"case": name, "pass": True})

        for method in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]:
            config = copy.deepcopy(server)
            for n in config["nodes"]:
                n["options"] = {"method": method, "key": key(16 if "aes-128" in method else 32)}
            check(args.kerlico, save(root / (method + ".json"), config))
        records.append({"case": "all-method-configs", "pass": True})

        config = copy.deepcopy(server)
        forwards = []
        for family, host, secret in [("4", "127.0.0.1", a), ("6", "::1", b)]:
            config["outbounds"].append({"tag": "ss" + family, "type": "ss2022", "options": {"server": host, "port": node_port, "method": "2022-blake3-aes-128-gcm", "key": secret}})
            config["outbounds"].append({"tag": "bad" + family, "type": "ss2022", "options": {"server": host, "port": node_port, "method": "2022-blake3-aes-128-gcm", "key": b if family == "4" else a}})
            for target_family, target_host in [("4", "127.0.0.1"), ("6", "::1")]:
                listen = free_port()
                for network in ["tcp", "udp"]:
                    config["inbounds"].append({"tag": f"f{family}{target_family}{network}", "type": network + "-forward", "listen": "127.0.0.1:" + str(listen), "target": {"host": target_host, "port": port}, "outbound": "ss" + family})
                forwards.append((listen, b"v4|" if target_family == "4" else b"v6|"))
            listen = free_port()
            for network in ["tcp", "udp"]:
                config["inbounds"].append({"tag": f"bad{family}{network}", "type": network + "-forward", "listen": "127.0.0.1:" + str(listen), "target": {"host": "127.0.0.1", "port": port}, "outbound": "bad" + family})
            forwards.append((listen, None))
        domain = free_port()
        for network in ["tcp", "udp"]:
            config["inbounds"].append({"tag": "domain" + network, "type": network + "-forward", "listen": "127.0.0.1:" + str(domain), "target": {"host": "localhost", "port": port}, "outbound": "ss6"})
        file = save(root / "dual-role.json", config)
        check(args.kerlico, file)
        check(args.minimal, file, False, "出站类型未注册")
        # 配置检查必须不占用端口：在实际 echo 已监听时也能校验相同监听配置。
        occupied = copy.deepcopy(config)
        occupied["nodes"][0]["listen"] = "127.0.0.1:" + str(port)
        check(args.kerlico, save(root / "check-with-occupied-port.json", occupied))
        records.append({"case": "check-no-bind-and-outbound-crop", "pass": True})
        process, handle = await start(args.kerlico, file, root / "dual-role.log", "127.0.0.1", node_port)
        active.append((process, handle))
        for listen, prefix in forwards:
            if prefix:
                await tcp_check(listen, prefix)
                await udp_check(listen, prefix)
            else:
                await reject_tcp(listen)
                await reject_udp(listen)
        await tcp_check(domain, b"v4|", b"client-domain-tcp")
        await udp_check(domain, b"v4|", b"client-domain-udp")
        records.append({"case": "dual-role-address-matrix", "tcp_paths": 4, "udp_paths": 4, "pass": True})
        records.append({"case": "cross-node-runtime-credentials", "node_families": 2, "pass": True})
        records.append({"case": "client-domain-ipv4-first", "tcp": True, "udp": True, "pass": True})
        for family, host, secret in [("4", "127.0.0.1", a), ("6", "::1", b)]:
            probe_config = {"mode": "udp", "server": (f"[{host}]:{node_port}" if family == "6" else f"{host}:{node_port}"), "key": secret, "targets": [f"127.0.0.1:{port}", f"[::1]:{port}"], "domain_port": port}
            result = await probe(args.probe, save(root / ("probe-" + family + ".json"), probe_config))
            records.append({"case": "formal-node-probe-" + family, "pass": True, "result": result})
        await stop(process, handle)
        active.remove((process, handle))
        if any(packet.startswith((b"bad-key", b"block-")) for packet in payloads):
            raise RuntimeError("应拒绝的数据进入了业务目标")
        if sum(packet == b"probe-first" for packet in payloads) != 2 or sum(packet == b"probe-second" for packet in payloads) != 2:
            raise RuntimeError("回放数据到达业务目标")
        records.append({"case": "authentication-and-replay-no-egress", "pass": True})

        only_port = free_port()
        only_key = key()
        only = base([node("only6", "::", only_port, only_key)])
        only_file = save(root / "v6only.json", only)
        process, handle = await start(args.kerlico, only_file, root / "v6only.log", "::1", only_port)
        active.append((process, handle))
        v6_options = {"mode": "v6only", "server": f"[::1]:{only_port}", "key": only_key, "targets": [f"127.0.0.1:{port}", f"[::1]:{port}"]}
        v6_result = await probe(args.probe, save(root / "v6only-probe.json", v6_options))
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", only_port), 0.5)
        except OSError:
            pass
        else:
            writer.close()
            await writer.wait_closed()
            raise RuntimeError("IPv6 wildcard 节点接纳了 IPv4 TCP")
        await stop(process, handle)
        active.remove((process, handle))
        records.append({"case": "ipv6-wildcard-v6only", "pass": True, "result": v6_result})

        for label, total, other_allowed in [("node-budget", 8, True), ("global-budget", 2, False)]:
            budget_port = free_port()
            ka, kb = key(), key()
            bounded = base([node("budget4", "127.0.0.1", budget_port, ka, 2), node("budget6", "::1", budget_port, kb, 2)], total)
            file = save(root / (label + ".json"), bounded)
            process, handle = await start(args.kerlico, file, root / (label + ".log"), "127.0.0.1", budget_port)
            active.append((process, handle))
            options = {"mode": "budget", "server": f"127.0.0.1:{budget_port}", "key": ka, "targets": [f"127.0.0.1:{port}", f"[::1]:{port}"], "other_server": f"[::1]:{budget_port}", "other_key": kb, "other_allowed": other_allowed}
            result = await probe(args.probe, save(root / (label + "-probe.json"), options))
            await stop(process, handle)
            active.remove((process, handle))
            # 同端口重新启动，用于核对退出后监听资源已释放。
            process, handle = await start(args.kerlico, file, root / (label + "-restart.log"), "127.0.0.1", budget_port)
            active.append((process, handle))
            await stop(process, handle)
            active.remove((process, handle))
            records.append({"case": label + "-drain-restart", "pass": True, "result": result})
        if any(packet.startswith((b"bad-key", b"block-")) for packet in payloads):
            raise RuntimeError("鉴权或预算拒绝的数据进入了业务目标")
    finally:
        for process, handle in active:
            if process.poll() is None:
                process.kill()
            await asyncio.to_thread(process.wait)
            handle.close()
        tcp4.close()
        tcp6.close()
        await tcp4.wait_closed()
        await tcp6.wait_closed()
        udp4.close()
        udp6.close()
        save(root / "results.json", records)
    for record in records:
        print(json.dumps(record, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kerlico", required=True)
    parser.add_argument("--minimal", required=True)
    parser.add_argument("--probe", required=True)
    parser.add_argument("--work", required=True)
    asyncio.run(main(parser.parse_args()))
