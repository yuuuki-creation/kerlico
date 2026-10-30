"""仅在 worker 验证 Rust 客户端两层 EIH 链与 Rust 终端；中继由固定 Xray 承担。"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
from interop_ss2022 import Echo, check_tcp, check_udp, echo_tcp, free_port, key, wait_ready

async def main(args):
    root = Path(args.work)
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    version = subprocess.check_output([args.xray, "version"], text=True).splitlines()[0]
    if "26.10.29" not in version:
        raise RuntimeError("固定 Xray 版本不匹配")
    results = []
    for family, host in [("v4", "127.0.0.1"), ("v6", "::1")]:
        echo_port = free_port()
        tcp = await asyncio.start_server(echo_tcp, host, echo_port)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Echo, local_addr=(host, echo_port))
        try:
            for method in ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"]:
                name = family + "-" + method + "-two-hop-eih"
                work = root / name
                work.mkdir(mode=0o700, exist_ok=True)
                terminal_port, relay_port, forward_port = free_port(), free_port(), free_port()
                relay, service, user = key(method, 21), key(method, 22), key(method, 23)
                configs = [
                    {"method": method, "key": service, "users": [user]},
                    {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": relay_port, "protocol": "shadowsocks", "settings": {"method": method, "password": relay, "network": "tcp,udp", "clients": [{"password": service, "address": "127.0.0.1", "port": terminal_port}]}}], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": str(terminal_port)}]}}]},
                    {"server": "127.0.0.1", "port": relay_port, "method": method, "key": user, "identity_keys": [relay, service]},
                ]
                files = []
                for index, config in enumerate(configs):
                    file = work / f"config-{index}.json"
                    file.write_text(json.dumps(config))
                    os.chmod(file, 0o600)
                    files.append(file)
                commands = [
                    [args.peer, "server", str(files[0]), f"127.0.0.1:{terminal_port}"],
                    [args.xray, "run", "-c", str(files[1])],
                    [args.peer, "client", str(files[2]), f"127.0.0.1:{forward_port}", host, str(echo_port)],
                ]
                processes, logs = [], []
                result = {"case": name}
                try:
                    for index, command in enumerate(commands):
                        log = (work / f"process-{index}.log").open("wb")
                        logs.append(log)
                        processes.append(subprocess.Popen(command, stdout=log, stderr=log))
                    for port in [terminal_port, relay_port, forward_port]:
                        await wait_ready(port, processes)
                    await check_tcp(forward_port)
                    result["tcp"] = "pass"
                    await check_udp(forward_port, 4096)
                    result["udp"] = "pass"
                except Exception as error:
                    result["error"] = type(error).__name__ + ": " + str(error)
                finally:
                    for process in processes:
                        process.terminate()
                    for process in processes:
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    for log in logs:
                        log.close()
                results.append(result)
                print(json.dumps(result, ensure_ascii=False), flush=True)
        finally:
            tcp.close()
            await tcp.wait_closed()
            transport.close()
    (root / "results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    if any("error" in result for result in results):
        raise SystemExit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", required=True)
    parser.add_argument("--xray", required=True)
    parser.add_argument("--work", required=True)
    asyncio.run(main(parser.parse_args()))
