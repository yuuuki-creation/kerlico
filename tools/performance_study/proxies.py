"""Paired local protocol configurations. Both test namespaces use fixed private addresses."""
import json
from pathlib import Path
from copy import copy
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify_hy2 as hy2
import verify_mieru as mieru
import verify_socks as socks
import verify_ss2022 as ss

SERVER = "10.51.0.1"
ENDPOINT = "10.51.0.2"
PASSWORD = "study-local-password"


def config(path, value, *command):
    path.write_text(json.dumps(value, indent=2) + "\n")
    return [*command, path]


def kerlico_node(paths, protocol, settings):
    return {"warp": {"secretKey": "invalid"}, "inbounds": [{
        "protocol": protocol, "tag": "study", "listen": SERVER, "port": paths.port,
        "outbound": "native-v4", "settings": settings}]}


def kerlico_client(paths, path, protocol, settings):
    return config(path, {"protocol": protocol, "peer": f"{SERVER}:{paths.port}",
                         "settings": {**settings, "socks5Port": paths.socks, "httpProxyPort": paths.http}}, paths.client)


def landing_command(paths, folder):
    original = json.loads((folder / "client.json").read_text())
    address, port = original["peer"].rsplit(":", 1)
    endpoint = socks.native(("127.0.0.1", paths.socks), False, True)
    endpoint["inbounds"][0]["rules"] = [{"geoip": ["private"], "outbound": "landing"}]
    settings = original["settings"].copy()
    for field in ("socks5Port", "httpProxyPort", "socks5ListenLAN", "httpProxyListenLAN"):
        settings.pop(field, None)
    endpoint["landing"] = dict(protocol=original["protocol"], address=address, port=int(port), settings=settings)
    return config(folder / "landing.json", endpoint, paths.server)


def socks_pair(paths, root, variant, ks, kc):
    user = {"user": "test", "pass": "pass"}
    authenticated = variant == "password"
    node = socks.native((SERVER, paths.port), authenticated, True)
    if ks:
        server = config(root / "server.json", node, paths.server)
    else:
        entry = node["inbounds"][0]
        entry.pop("outbound")
        server = config(root / "server.json", {"inbounds": [entry], "outbounds": [{"protocol": "freedom"}],
                            "log": {"loglevel": "warning"}}, paths.xray, "run", "-c")
    if kc:
        client = kerlico_client(paths, root / "client.json", "socks", user if authenticated else {})
    else:
        peer = {"address": SERVER, "port": paths.port}
        if authenticated:
            peer["users"] = [user]
        client = config(root / "client.json", {"inbounds": [{"protocol": "socks", "listen": "127.0.0.1",
            "port": paths.socks, "settings": {"udp": True}}], "log": {"loglevel": "warning"},
            "outbounds": [{"protocol": "socks", "settings": {"servers": [peer]}}]}, paths.xray, "run", "-c")
    return server, client


def ss_pair(paths, root, variant, ks, kc):
    name, mode = variant.split("/")
    method = "2022-blake3-" + name
    size = 32 if name in ("chacha8-poly1305", "chacha12-poly1305") else ss.METHODS[method]
    if name == "chacha8-poly1305":
        paths = copy(paths)
        paths.reference = paths.peers.parent / "ss-extra/bin"
    if name == "chacha12-poly1305" and not (ks and kc):
        raise ValueError("neither pinned reference implements ChaCha12")
    key = ss.secret(size, 17)
    if mode in ("relay1", "relay2"):
        relay_keys = [ss.secret(size, n) for n in (89, 193)[:int(mode[-1])]]
        chain = [*relay_keys, ss.secret(size, 1), key]
        ports = [paths.port, paths.aux, paths.chain_port][:len(chain)-1]
        # All downstream processes and all reference relay processes are Xray. Only the selected endpoint changes.
        for i in reversed(range(len(ports))):
            last = i == len(ports)-1
            name = "terminal" if last else ("server" if i == 0 else "second-relay")
            path = root / (name + ".json")
            xray = i != 0 or not ks
            command = ss.server(paths, path, ports[i], method, chain[i], [("user", chain[i+1])], xray,
                                relay_to=None if last else ports[i+1], listen=SERVER if i == 0 else "127.0.0.1")
            if last:
                data = json.loads(path.read_text())
                data["outbounds"][0]["settings"]["finalRules"][0]["ip"] = [paths.origin_ip + "/32"]
                config(path, data)
            if i:
                paths.chain_helpers.append((name, command))
            else:
                server = command
        return server, ss.client(paths, root / "client.json", paths.port, paths.socks, paths.http,
                                 method, ":".join(chain), not kc, host=SERVER)
    identity = ss.secret(size, 1) if mode == "multi" else None
    users = [("alice", key)] + ([("bob", ss.secret(size, 65))] if identity else [])
    return (ss.server(paths, root / "server.json", paths.port, method, identity, users,
                      False if ks else "shadowsocks-rust", listen=SERVER),
            ss.client(paths, root / "client.json", paths.port, paths.socks, paths.http, method,
                      f"{identity}:{key}" if identity else key, False if kc else "shadowsocks-rust", host=SERVER))


def hysteria_pair(paths, root, variant, ks, kc):
    identity = hy2.make_identity(root)
    official, kerlico = {}, {}
    if variant in ("salamander", "gecko"):
        official["obfs"] = {"type": variant, variant: {"password": PASSWORD}}
        kerlico["obfs"] = {"type": variant, "password": PASSWORD}
    if variant == "brutal":
        official["bandwidth"] = {"up": "1250 mbps", "down": "1250 mbps"}
        kerlico.update(sendRate=156250000, receiveRate=156250000)
    s = root / "server.json"
    c = root / "client.json"
    if ks:
        server = hy2.kerlico_server(paths, s, paths.port, identity, extra=kerlico)
        data = json.loads(s.read_text())
        data["inbounds"][0]["listen"] = SERVER
        config(s, data)
    else:
        server = hy2.official_server(paths, s, paths.port, identity, extra=official, listen=SERVER)
    if kc:
        client = hy2.kerlico_client(paths, c, paths.port, paths.socks, paths.http, identity, hy2.PASSWORD, extra=kerlico, peer=SERVER)
    else:
        client = hy2.official_client(paths, c, paths.port, paths.socks, paths.http, identity, hy2.PASSWORD, extra=official)
        data = json.loads(c.read_text())
        data["server"] = f"{SERVER}:{paths.port}"
        config(c, data)
    if variant == "port-hop":
        data = json.loads(c.read_text())
        if kc:
            data["settings"].update(hopPorts=f"{paths.port},{paths.aux}", hopInterval=5)
        else:
            data["server"] = f"{SERVER}:{paths.port},{paths.aux}"
            data["transport"] = {"type": "udp", "udp": {"hopInterval": "5s"}}
        config(c, data)
    return server, client


def anytls_pair(paths, root, variant, ks, kc):
    cert, key, _ = hy2.make_identity(root)
    s = root / "server.json"
    c = root / "client.json"
    options = {"password": PASSWORD, "sni": "localhost", "skip-cert-verify": True, "udp": True}
    client_host, client_port = SERVER, paths.port
    if variant.startswith("shadowtls"):
        version = int(variant[-1])
        transport = {"shadow-tls": {"enable": True, "version": version, "password": PASSWORD,
            "users": [{"name":"outer-user","password":PASSWORD}], "handshake":{"dest":f"127.0.0.1:{paths.aux}"}}}
        options["shadow-tls-opts"] = {"version":version, "password":PASSWORD}
    elif variant.startswith("restls"):
        transport = {"res-tls": {"enable":True,"dest":f"127.0.0.1:{paths.aux}", "password":PASSWORD}}
        options["restls-opts"] = {"version-hint":"tls"+variant[-2:], "password":PASSWORD}
    elif variant == "jls":
        user = {"username":"outer-user","password":PASSWORD}
        transport = {"jls-config":{"enable":True, "dest":f"127.0.0.1:{paths.aux}", "sni":"localhost", "users":[user]}}
        options["jls-opts"] = user
    elif variant == "plaintext":
        transport = {"allow-insecure":True}
        client_host,client_port = "127.0.0.1",paths.aux
    elif variant in ("official", "tls", "ech", "chrome", "padding"):
        transport = {"certificate": cert.read_text() if ks else cert.name,
                     "private-key": key.read_text() if ks else key.name}
        if variant in ("chrome", "ech"):
            options["client-fingerprint"] = "chrome"
        if variant=="ech":
            generated = subprocess.check_output([paths.mihomo, "generate", "ech-keypair", "public.example.invalid"],text=True)
            public, private = generated.strip().removeprefix("Config: ").split("\nKey: ",1)
            options["ech-opts"] = {"enable": True, "config": public.strip()}
            (root/"ech.pem").write_text(private+"\n")
            transport["ech-key"] = private if ks else "ech.pem"
        if variant=="padding":
            transport["padding-scheme"] = "stop=5\n0=20-20\n1=150-150\n2=200-200\n3=300-300,c,90-90\n4=64-64"
    else:
        raise ValueError("unknown AnyTLS carrier: "+variant)
    if not ks and variant == "official":
        server = ["env", "LOG_LEVEL=warn", paths.peers / "anytls-server", "-l", f"{SERVER}:{paths.port}", "-p", PASSWORD]
    elif ks:
        server = config(s, kerlico_node(paths, "anytls", {**transport,
            "users": [{"email": "test", "password": PASSWORD}]}), paths.server)
    else:
        server = config(s, {"log-level": "warning", "mode": "rule", "listeners": [{"name": "study", "type": "anytls",
            "listen": SERVER, "port": paths.port, "users": {"test": PASSWORD}, **transport}],
            "rules": ["MATCH,DIRECT"]}, paths.mihomo, "-d", root, "-f")
    if not kc and variant == "official":
        client = ["env", "LOG_LEVEL=warn", paths.peers / "anytls-client", "-l", f"127.0.0.1:{paths.socks}",
                  "-s", f"{SERVER}:{paths.port}", "-sni", "localhost", "-p", PASSWORD]
    elif kc:
        client = kerlico_client(paths, c, "anytls", options)
        if variant == "plaintext":
            data = json.loads(c.read_text())
            data["peer"] = f"{client_host}:{client_port}"
            config(c, data)
    else:
        homedir = root / "mihomo-client"
        homedir.mkdir()
        client = config(c, {"log-level": "warning", "mode": "rule", "mixed-port": paths.socks, "proxies": [
            {"name": "study", "type": "anytls", "server": client_host, "port": client_port, **options}],
            "rules": ["MATCH,study"]}, paths.mihomo, "-d", homedir, "-f")
    return server, client


def mieru_pair(paths, root, variant, ks, kc):
    transport, mux, handshake, low, mtu = variant.split("/")
    row = transport.upper(), "MULTIPLEXING_" + mux.upper(), "HANDSHAKE_" + handshake.upper(), int(low), int(mtu)
    mode, multiplex, hs, entropy, mtu = row
    level = ["OFF", "32", "40", "48", "56"][entropy]
    pattern = {"lowEntropy": {"mode": "LOW_ENTROPY_MODE_" + level, "maskRotation": "LOW_ENTROPY_MASK_NO_ROTATION"}}
    bindings = [{"port": paths.port, "protocol": mode}]
    s, c = root / "server.json", root / "client.json"
    if ks:
        server = config(s, kerlico_node(paths, "mieru", {"transport": mode, "mtu": mtu, "users": [
            {"email": "test-user", "username": "test-user", "password": "test-password"}]}), paths.server)
    else:
        config(s, {"listenIPAddress": SERVER, "portBindings": bindings, "mtu": mtu,
            "users": [{"name": "test-user", "password": "test-password", "allowPrivateIP": True, "allowLoopbackIP": True}],
            "loggingLevel": "ERROR", "trafficPattern": pattern})
        server = ["env", f"MITA_CONFIG_JSON_FILE={s}", "MITA_UDS_PATH=/tmp/study-mita-" + str(root.stat().st_ino) + ".sock",
                  "MITA_INSECURE_UDS=1", paths.mita, "run"]
    if kc:
        client = kerlico_client(paths, c, "mieru", mieru.client_settings(row, paths.socks, paths.http))
    else:
        config(c, {"profiles": [{"profileName": "test", "user": {"name": "test-user", "password": "test-password"},
            "servers": [{"ipAddress": SERVER, "portBindings": bindings}], "mtu": mtu, "multiplexing": {"level": multiplex},
            "handshakeMode": hs, "trafficPattern": pattern}], "activeProfile": "test", "rpcPort": 19115,
            "socks5Port": paths.socks, "httpProxyPort": paths.http, "loggingLevel": "ERROR", "advancedSettings": {"noCheckUpdate": True}})
        client = ["env", f"MIERU_CONFIG_JSON_FILE={c}", paths.mieru, "run"]
    return server, client


def wireguard_pair(paths, root, variant, ks, kc):
    if variant!="node-landing":
        raise ValueError("expected the userspace WireGuard node/landing comparison")
    def keypair():
        key = subprocess.check_output(["wg","genkey"],text=True)
        return key.strip(), subprocess.check_output(["wg","pubkey"],input=key,text=True).strip()
    skey,spub = keypair()
    ckey,cpub = keypair()
    psk = subprocess.check_output(["wg","genpsk"],text=True).strip()
    local = "10.122.0.2"
    if ks:
        node = kerlico_node(paths,"wireguard",{"privateKey":skey,"mtu":1200,"users":[
            {"email":"study","publicKey":cpub,"presharedKey":psk,"allowedIPs":[local+"/32"]}]})
        server = config(root/"server.json",node,paths.server)
    else:
        server = config(root/"server.json",{"log":{"loglevel":"warning"},"inbounds":[
            {"protocol":"wireguard","listen":SERVER,"port":paths.port,"settings":{"secretKey":skey,
             "address":["10.122.0.1"],"mtu":1200,"noKernelTun":True,"peers":[{"publicKey":cpub,
             "preSharedKey":psk,"allowedIPs":[local+"/32"],"email":"study"}]}}],
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow",
            "network":"tcp,udp","ip":[paths.origin_ip+"/32"]}]}}]},paths.xray,"run","-c")
    if kc:
        client = kerlico_client(paths,root/"client.json","wireguard",{"secretKey":ckey,"publicKey":spub,
                                "preSharedKey":psk,"localAddresses":[local],"allowedIPs":["0.0.0.0/0"],"mtu":1200})
    else:
        client = config(root/"client.json",{"log":{"loglevel":"warning"},"inbounds":[
            {"protocol":"socks","listen":"127.0.0.1","port":paths.socks,"settings":{"udp":True}}],
            "outbounds":[{"protocol":"wireguard","settings":{"secretKey":ckey,"address":[local],
            "mtu":1200,"noKernelTun":True,"peers":[{"publicKey":spub,"preSharedKey":psk,"allowedIPs":["0.0.0.0/0"],
            "endpoint":f"{SERVER}:{paths.port}"}]}}]},paths.xray,"run","-c")
    return server,client


BUILDERS = {"socks": socks_pair, "ss2022": ss_pair, "hy2": hysteria_pair,
            "anytls": anytls_pair, "mieru": mieru_pair, "wireguard": wireguard_pair}
