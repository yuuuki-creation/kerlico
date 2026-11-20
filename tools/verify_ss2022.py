#!/usr/bin/env python3
"""Compare SS2022 TCP and UDP against Xray 26.10.31 on a local worker."""
import argparse
import base64
import contextlib
import json
import os
import socket
import socketserver
import subprocess
import tempfile
from pathlib import Path

import verify_mieru as fixtures
import verify_hy2 as hy2
from verify_hy2 import (ReplyAfterFin, datagram_origins, http_connect, tcp_half_close, tcp_payload,
                        udp_alternate_reply, udp_payload, udp_source_port)


METHODS = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}


def secret(length, offset):
    return base64.b64encode(bytes((i + offset) % 256 for i in range(length))).decode()


def reference_binary(paths, name):
    return paths.reference / (name + ".exe" if os.name == "nt" else name)


def server(paths, filename, port, method, identity, users, xr, landing=None, relay_to=None, listen="127.0.0.1"):
    if xr == "shadowsocks-rust":
        entry = {"server": listen, "server_port": port, "method": method,
                 "password": identity or users[0][1], "mode": "tcp_and_udp"}
        if identity:
            entry["users"] = [{"name": name, "password": key} for name, key in users]
        cfg = {"servers": [entry]}
        cmd = [reference_binary(paths, "ssserver"), "-c", filename]
    elif xr:
        settings = {"method": method, "password": identity or users[0][1], "network": "tcp,udp"}
        if identity:
            settings["users"] = [{"email": name, "password": key} for name, key in users]
        cfg = {"log": {"loglevel": "warning"}, "inbounds": [
            {"protocol": "shadowsocks", "listen": listen, "port": port, "settings": settings}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"]}]}}]}
        cmd = [paths.xray, "run", "-c", filename]
    else:
        settings = {"method": method, "users": [{"email": name, "password": key} for name, key in users]}
        if identity:
            settings["identityKey"] = identity
        inbound = {"protocol": "ss2022", "tag": "ss2022", "listen": listen, "port": port,
                   "outbound": "native-v4", "settings": settings}
        cfg = {"warp": {"secretKey": "invalid"}, "inbounds": [inbound]}
        if landing:
            inbound["rules"] = [{"geoip": ["private"], "outbound": "landing"}]
            cfg["landing"] = landing
        cmd = [paths.server, filename]
    if relay_to:
        if not xr:
            settings["relay"] = True
        for account in settings["users"]:
            account.update(address="127.0.0.1", port=relay_to)
    fixtures.write_json(filename, cfg)
    return cmd


def client(paths, filename, port, socks, http, method, password, xr, host="127.0.0.1"):
    if xr == "shadowsocks-rust":
        cfg = {"server": host, "server_port": port, "method": method,
               "password": password, "locals": [
                   {"local_address": "127.0.0.1", "local_port": socks,
                    "protocol": "socks", "mode": "tcp_and_udp"},
                   {"local_address": "127.0.0.1", "local_port": http, "protocol": "http"}]}
        cmd = [reference_binary(paths, "sslocal"), "-c", filename]
    elif xr:
        cfg = {"log": {"loglevel": "warning"}, "inbounds": [
            {"protocol": "socks", "listen": "127.0.0.1", "port": socks, "settings": {"udp": True}},
            {"protocol": "http", "listen": "127.0.0.1", "port": http}], "outbounds": [
            {"protocol": "shadowsocks", "settings": {"address": host, "port": port,
                                                      "method": method, "password": password}}]}
        cmd = [paths.xray, "run", "-c", filename]
    else:
        cfg = {"protocol": "ss2022", "peer": fixtures.authority(host, port), "settings": {
            "method": method, "password": password, "socks5Port": socks, "httpProxyPort": http}}
        cmd = [paths.client, filename]
    fixtures.write_json(filename, cfg)
    return cmd


def rejected(socks, target, origins):
    before = origins.tcp4.count
    try:
        conn, _ = fixtures.socks_connect(socks, "127.0.0.1", target)
    except (fixtures.Failure, OSError):
        return
    with conn:
        conn.settimeout(2)
        try:
            conn.sendall(b"must-not-reach-origin")
            got = conn.recv(64)
        except OSError:
            got = b""
        fixtures.require(not got, "invalid credentials received data")
    fixtures.require(origins.tcp4.count == before, "invalid credentials reached origin")


class Greeting(socketserver.BaseRequestHandler):
    payload = b"server speaks first\0"

    def handle(self):
        self.request.sendall(self.payload)
        # Keep the connection open until the client has consumed the greeting.
        self.request.settimeout(4)
        try:
            self.request.recv(1)
        except (ConnectionResetError, TimeoutError):
            pass


def server_first(paths, root, origins, count):
    folder = root / "server-first-xray"
    folder.mkdir()
    port, socks, http = fixtures.free_ports(3)
    method = "2022-blake3-aes-128-gcm"
    identity, password = secret(16, 1), secret(16, 17)
    server_file = folder / "server.json"
    command = server(paths, server_file, port, method, identity, [("alice", password)], xr=True)
    config = json.loads(server_file.read_text(encoding="utf-8"))
    config["log"]["loglevel"] = "info"
    fixtures.write_json(server_file, config)
    host, target = origins.add(fixtures.ThreadedTCP, "127.0.0.1", Greeting, "server-first").server_address
    with fixtures.managed(command, folder, "server") as peer:
        fixtures.wait_for(peer, lambda: fixtures.ports_ready([port]))
        command = client(paths, folder / "client.json", port, socks, http, method, f"{identity}:{password}", False)
        with fixtures.managed(command, folder, "client") as proxy:
            fixtures.wait_for(proxy, lambda: fixtures.ports_ready([socks]))
            for index in range(count):
                try:
                    with fixtures.socks_connect(socks, host, target)[0] as link:
                        fixtures.require(fixtures.exact(link, len(Greeting.payload)) == Greeting.payload,
                                         "server-first greeting changed")
                except (OSError, fixtures.Failure) as error:
                    raise fixtures.Failure(f"server-first request {index + 1}/{count} failed") from error
    print(f"PASS server-first-xray ({count} requests)", flush=True)


def run(paths, root, origins, name, method, multi=False, xr_client=False, xr_server=False, landing=None,
        allow_lost_half_close=False, password_override=None):
    size = METHODS[method]
    identity = secret(size, 1) if multi else None
    users = [("alice", password_override or secret(size, 17))] + ([("bob", secret(size, 65))] if multi else [])
    folder = root / name
    folder.mkdir()
    port, = fixtures.free_ports(1)
    serve = server(paths, folder / "server.json", port, method, identity, users, xr_server, landing)
    target = origins.tcp4.server_address[1]
    with fixtures.managed(serve, folder, "server") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([port]))
        for user, password in users + [("wrong", secret(size, 111))]:
            socks, http = fixtures.free_ports(2)
            password = f"{identity}:{password}" if identity else password
            open_client = client(paths, folder / f"{user}.json", port, socks, http, method, password, xr_client)
            with fixtures.managed(open_client, folder, user) as peer:
                fixtures.wait_for(peer, lambda: fixtures.ports_ready([socks, http]))
                if user == "wrong":
                    rejected(socks, target, origins)
                    continue
                tcp_payload(socks, target)
                http_connect(http, target)
                try:
                    tcp_half_close(socks, origins.after_fin.server_address[1])
                except (fixtures.Failure, OSError):
                    if not (xr_client or xr_server or allow_lost_half_close):
                        raise
                    print(f"OBSERVED {name}/{user}: peer did not preserve half-close", flush=True)
                udp_payload(socks, [origins.udp4.server_address[1], origins.udp4b.server_address[1]])
                same_port = udp_source_port(socks, origins)
                if not xr_server:
                    fixtures.require(same_port, "UDP session split across source ports")
                elif not same_port:
                    print(f"OBSERVED {name}/{user}: reference used different source ports", flush=True)
                udp_alternate_reply(socks, origins)
    print(f"PASS {name}", flush=True)


def run_relay(paths, root, origins, method, xray_relay, hops=1):
    size = METHODS[method]
    relay_keys = [secret(size, n) for n in (89, 193)[:hops]]
    server_key, user_key = (secret(size, n) for n in (17, 111))
    directory = root / f"relay-{size}-{hops}-hop" / ("xray-first" if xray_relay else "kerlico-first")
    directory.mkdir(parents=True)
    *relay_ports, target, socks, http = fixtures.free_ports(hops + 3)
    target_cmd = server(paths, directory / "target.json", target, method, server_key,
                        [("alice", user_key)], not xray_relay)
    keys = [*relay_keys, server_key, user_key]
    client_cmd = client(paths, directory / "client.json", relay_ports[0], socks, http,
                        method, ":".join(keys), not xray_relay)
    next_ports = [*relay_ports[1:], target]
    with contextlib.ExitStack() as stack:
        end = stack.enter_context(fixtures.managed(target_cmd, directory, "target"))
        fixtures.wait_for(end, lambda: fixtures.ports_ready([target]))
        for i in reversed(range(hops)):
            port = relay_ports[i]
            relay_name = f"relay-{i}"
            relay_cmd = server(paths, directory / f"{relay_name}.json", port, method, keys[i],
                               [("target", keys[i + 1])], xray_relay != bool(i % 2), relay_to=next_ports[i])
            middle = stack.enter_context(fixtures.managed(relay_cmd, directory, relay_name))
            fixtures.wait_for(middle, lambda: fixtures.ports_ready([port]))
        peer = stack.enter_context(fixtures.managed(client_cmd, directory, "client"))
        fixtures.wait_for(peer, lambda: fixtures.ports_ready([socks, http]))
        tcp_payload(socks, origins.tcp4.server_address[1])
        http_connect(http, origins.tcp4.server_address[1])
        udp_payload(socks, [origins.udp4.server_address[1], origins.udp4b.server_address[1]])
    print(f"PASS {directory.parent.name}-{directory.name}", flush=True)


def anytls_landing(paths, root, origins, stock):
    label = "mihomo" if stock else "kerlico"
    folder = root / f"anytls-peer-{label}"
    folder.mkdir()
    cert, key, pin = hy2.make_identity(folder)
    port, = fixtures.free_ports(1)
    password = "fixture-ss2022-anytls"
    config = folder / "anytls.json"
    if stock:
        fixtures.write_json(config, {"mode": "rule", "log-level": "warning", "listeners": [
            {"type": "anytls", "name": "test", "listen": "127.0.0.1", "port": port,
             "users": {"test": password}, "certificate": str(cert), "private-key": str(key)}],
            "rules": ["MATCH,DIRECT"]})
        command = [paths.mihomo, "-d", folder, "-f", config]
    else:
        fixtures.write_json(config, {"warp": {"secretKey": "invalid"}, "inbounds": [
            {"protocol": "anytls", "tag": "test", "listen": "127.0.0.1", "port": port,
             "outbound": "native-v4", "settings": {"certificate": str(cert), "private-key": str(key),
                 "users": [{"email": "test", "password": password}]}}]})
        command = [paths.server, config]
    landing = {"protocol": "anytls", "address": "127.0.0.1", "port": port,
               "settings": {"sni": "localhost", "password": password, "fingerprint": pin, "udp": True}}
    with fixtures.managed(command, folder, "anytls") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([port]))
        run(paths, root, origins, f"ss2022-landing-to-{label}-anytls", "2022-blake3-aes-128-gcm",
            landing=landing, allow_lost_half_close=True)


def mieru_landing(paths, root, origins, stock, transport):
    label = f"{'mita' if stock else 'kerlico'}-mieru-{transport.lower()}"
    folder = root / label
    folder.mkdir()
    port, = fixtures.free_ports(1, kind=socket.SOCK_DGRAM if transport == "UDP" else socket.SOCK_STREAM)
    username, password = "fixture-ss2022", "fixture-mieru-password"
    config = folder / "mieru.json"
    if stock:
        fixtures.write_json(config, {"listenIPAddress": "127.0.0.1", "loggingLevel": "INFO",
            "portBindings": [{"port": port, "protocol": transport}],
            "users": [{"name": username, "password": password, "allowLoopbackIP": True}]})
        command = [paths.mita, "run"]
        # The enclosing mkdtemp is private; mita does not need an installed service account.
        env = {**os.environ, "MITA_CONFIG_JSON_FILE": str(config), "MITA_UDS_PATH": str(folder / "mita.sock"),
               "MITA_INSECURE_UDS": "1"}
    else:
        fixtures.write_json(config, {"warp": {"secretKey": "invalid"}, "inbounds": [
            {"protocol": "mieru", "tag": "test", "listen": "127.0.0.1", "port": port,
             "outbound": "native-v4", "settings": {"transport": transport,
                 "users": [{"email": "test", "username": username, "password": password}]}}]})
        command, env = [paths.server, config], None
    landing = {"protocol": "mieru", "address": "127.0.0.1", "port": port,
               "settings": {"username": username, "password": password, "transport": transport}}
    with fixtures.managed(command, folder, "mieru", env=env) as process:
        fixtures.wait_for(process, lambda: "socks5 server is running" in process.text() if stock else
                          "mieru" in process.text().splitlines())
        run(paths, root, origins, f"ss2022-landing-to-{label}", "2022-blake3-aes-128-gcm",
            landing=landing, allow_lost_half_close=True)


def vless_landing(paths, root, origins, stock, mux):
    from verify_ss2022_chacha import udp_session_isolation

    label = f"{'xray' if stock else 'kerlico'}-vless-{'mux' if mux else 'xudp'}"
    folder = root / label
    folder.mkdir()
    port, = fixtures.free_ports(1)
    user = "b83ad2e1-a41a-435d-a352-1edc9e388153"
    config = folder / "vless.json"
    if stock:
        fixtures.write_json(config, {"log": {"loglevel": "warning"}, "inbounds": [
            {"protocol": "vless", "listen": "127.0.0.1", "port": port,
             "settings": {"decryption": "none", "clients": [{"id": user}]}}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
                {"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"]}]}}]})
        command = [paths.vless_peer, "run", "-c", config]
    else:
        fixtures.write_json(config, {"warp": {"secretKey": "invalid"}, "inbounds": [
            {"protocol": "vless", "tag": "test", "listen": "127.0.0.1", "port": port,
             "outbound": "native-v4", "settings": {"decryption": "none",
                 "users": [{"email": "test", "id": user}]}}]})
        command = [paths.server, config]
    landing = {"protocol": "vless", "address": "127.0.0.1", "port": port,
               "settings": {"network": "raw", "security": "none", "id": user,
                            "encryption": "none", "mux": mux}}
    with fixtures.managed(command, folder, "vless") as process:
        fixtures.wait_for(process, lambda: fixtures.ports_ready([port]))
        run(paths, root, origins, f"ss2022-landing-to-{label}", "2022-blake3-aes-128-gcm",
            landing=landing, allow_lost_half_close=True)
        ingress, = fixtures.free_ports(1)
        key = bytes(range(31, 63))
        serve = server(paths, folder / "isolation.json", ingress, "2022-blake3-chacha20-poly1305",
                       None, [("test", secret(32, 31))], False, landing)
        with fixtures.managed(serve, folder, "isolation") as process:
            fixtures.wait_for(process, lambda: fixtures.ports_ready([ingress]))
            udp_session_isolation(ingress, key, origins)
        print(f"PASS same outer UDP socket stays isolated through {label}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("client", "server"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).resolve(), required=True)
    for name in ("xray", "reference", "hysteria", "mihomo", "mita"):
        parser.add_argument(f"--{name}", type=lambda path: Path(path).resolve())
    parser.add_argument("--vless-peer", type=lambda path: Path(path).resolve())
    parser.add_argument("--reference-extra", action="store_true", help="Reference was built with aead-cipher-2022-extra")
    parser.add_argument("--server-first-count", type=int, default=16, help="Number of server-first requests to Xray")
    args = parser.parse_args()
    fixtures.require(args.xray or args.reference or args.hysteria or args.mihomo or args.mita or args.vless_peer,
                     "supply an independent implementation")
    for xray in {args.xray, args.vless_peer} - {None}:
        version = subprocess.check_output([xray, "version"], text=True, timeout=10)
        fixtures.require("26.10.31" in version and "a4a3dff" in version, "unexpected Xray version")
    if args.reference:
        for bin in ("sslocal", "ssserver"):
            version = subprocess.check_output([reference_binary(args, bin), "--version"], text=True, timeout=10)
            fixtures.require("1.25.0" in version, "unexpected shadowsocks-rust version")
    root = Path(tempfile.mkdtemp(prefix="kerlico-ss2022-peer-"))
    print(f"Logs: {root}", flush=True)
    with fixtures.Fixtures() as origins, datagram_origins(origins):
        origins.after_fin = origins.add(fixtures.ThreadedTCP, "127.0.0.1", ReplyAfterFin, "ss2022-after-fin")
        if args.hysteria:
            hy2.verify_peer(args.hysteria)
            identity = hy2.make_identity(root)
            port, = fixtures.free_ports(1, kind=socket.SOCK_DGRAM)
            command = hy2.official_server(args, root / "hy2-target.json", port, identity)
            landing = {"protocol": "hy2", "address": "127.0.0.1", "port": port, "settings": {
                "serverName": "localhost", "password": hy2.PASSWORD, "tls": {"pinnedPeerCertSha256": identity[2]}}}
            with fixtures.managed(command, root, "hy2-target") as peer:
                fixtures.wait_for(peer, lambda: "server up" in peer.text().lower())
                run(args, root, origins, "ss2022-landing-to-official-hy2", "2022-blake3-aes-128-gcm",
                    landing=landing, allow_lost_half_close=True)
        if args.mihomo:
            version = subprocess.check_output([args.mihomo, "-v"], text=True, timeout=10)
            fixtures.require(version.startswith(("Mihomo Meta 1.19.33 ", "Mihomo Meta v1.19.33 ")),
                             "unexpected mihomo version")
            anytls_landing(args, root, origins, stock=True)
            anytls_landing(args, root, origins, stock=False)
        if args.mita:
            version = subprocess.check_output([args.mita, "version"], text=True, timeout=10)
            fixtures.require(version.strip() == "3.39.0", "unexpected mita version")
            for transport in ("TCP", "UDP"):
                for stock in (True, False):
                    mieru_landing(args, root, origins, stock, transport)
        if args.vless_peer:
            for mux in (False, True):
                for stock in (True, False):
                    vless_landing(args, root, origins, stock, mux)
        if args.reference:
            methods = dict(METHODS)
            if args.reference_extra:
                methods["2022-blake3-chacha8-poly1305"] = 32
                METHODS.update(methods)
            for method in methods:
                suffix = method.removeprefix("2022-blake3-")
                for multi in ([False, True] if "aes" in method else [False]):
                    label = suffix + ("-multi" if multi else "")
                    run(args, root, origins, label + "-ssrust-to-kerlico", method, multi, xr_client="shadowsocks-rust")
                    run(args, root, origins, label + "-kerlico-to-ssrust", method, multi, xr_server="shadowsocks-rust")
        if not args.xray:
            return
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        canonical = secret(16, 9)
        # Go's decoder ignores CRLF and accepts the unused low bits of the final digit.
        final = alphabet[alphabet.index(canonical[-3]) | 1]
        compatible = canonical[:8] + "\r\n" + canonical[8:-3] + final + "=="
        run(args, root, origins, "migrate-xray-to-kerlico", "2022-blake3-aes-128-gcm", xr_client=True,
            password_override=compatible)
        run(args, root, origins, "migrate-kerlico-to-xray", "2022-blake3-aes-128-gcm", xr_server=True,
            password_override=compatible)
        if args.server_first_count > 0:
            server_first(args, root, origins, args.server_first_count)
        run(args, root, origins, "xray-control", "2022-blake3-aes-128-gcm", xr_client=True, xr_server=True)
        run(args, root, origins, "kerlico-half-close-control", "2022-blake3-aes-128-gcm")
        for method in METHODS:
            if "chacha8" in method:
                continue
            suffix = method.removeprefix("2022-blake3-")
            for multi in ([False, True] if "aes" in method else [False]):
                label = suffix + ("-multi" if multi else "")
                run(args, root, origins, label + "-xray-to-kerlico", method, multi, xr_client=True)
                run(args, root, origins, label + "-kerlico-to-xray", method, multi, xr_server=True)
            if "aes" in method:
                for hops in (1, 2):
                    for xray_relay in (False, True):
                        run_relay(args, root, origins, method, xray_relay, hops)
        method = "2022-blake3-aes-128-gcm"
        port, = fixtures.free_ports(1)
        password = secret(METHODS[method], 17)
        command = server(args, root / "target.json", port, method, None, [("target", password)], xr=True)
        with fixtures.managed(command, root, "landing-target") as peer:
            fixtures.wait_for(peer, lambda: fixtures.ports_ready([port]))
            landing = {"protocol": "ss2022", "address": "127.0.0.1", "port": port,
                       "settings": {"method": method, "password": password}}
            run(args, root, origins, "ss2022-landing-to-xray", method, xr_client=True, landing=landing)


if __name__ == "__main__":
    main()
