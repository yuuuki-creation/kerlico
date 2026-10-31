#!/usr/bin/env python3
"""专用 worker 的 TUIC 双端矩阵；参考二进制须由任务预先固定并核验来源。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import signal
import subprocess
import time
import interop_vless as h

ID = "00000000-0000-4000-8000-000000000001"
TOKEN = "synthetic-token"
PASSWORD = "synthetic-password"

class UdpServer(h.UdpServer):
    max_packet_size = 65535

def wait_listener(child, port, protocol):
    deadline = time.monotonic()+8
    observed = False
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("代理对端在就绪前退出")
        owned = set()
        for descriptor in Path("/proc/"+str(child.pid)+"/fd").glob("*"):
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owned.add(target[8:-1])
        ready = False
        for suffix in ("", "6"):
            table = Path("/proc/net/"+protocol+suffix)
            if not table.exists():
                continue
            for line in table.read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 9 and fields[9] in owned and int(fields[1].split(":")[-1],16) == port:
                    if protocol == "udp" or fields[3] == "0A":
                        ready = True
        if ready and observed:
            return
        observed = ready
        time.sleep(0.02)
    raise RuntimeError("进程自身监听未在预算内就绪")

def wait_udp(child, port, host):
    wait_listener(child, port, "udp")

def wait_tcp(child, port):
    wait_listener(child, port, "tcp")

def tcp(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(len(payload).to_bytes(4, "big")+payload)
        result=bytearray()
        while len(result)<len(payload):
            part=sock.recv(min(65535,len(payload)-len(result)))
            if not part:
                break
            result.extend(part)
        return bytes(result)

def verify(args, root, version, mode, node_host, congestion, direction, cert, key):
    label="-".join([args.backend,"v"+str(version),mode,"node6" if ":" in node_host else "node4",congestion,direction])
    work=root/label
    work.mkdir(mode=0o700)
    with ExitStack() as stack:
        target_tcp=stack.enter_context(h.serve(h.TcpServer(("127.0.0.1",0),h.TcpEcho)))
        target_udp=stack.enter_context(h.serve(UdpServer(("127.0.0.1",0),h.UdpEcho)))
        node_port,tcp_port,udp_port=h.free_port(),h.free_port(),h.free_port()
        target_address=("[::1]:" if ":" in node_host else "127.0.0.1:")+str(node_port)
        own={"version":1,"limits":{"connect_timeout_ms":4000,"idle_timeout_ms":10000,"drain_timeout_ms":500},"outbounds":[],"inbounds":[]}
        auth={"token":TOKEN} if version==4 else {"uuid":ID,"password":PASSWORD}
        if direction=="client":
            options={"version":version,"server":{"host":node_host,"port":node_port},"tls":{"server_name":"localhost","ca_pem":cert.read_text()},"udp_relay_mode":mode,"congestion_control":congestion,**auth}
            own["outbounds"]=[{"tag":"proxy","type":"tuic","options":options}]
            own["inbounds"]=[{"tag":"tcp","type":"tcp-forward","listen":"127.0.0.1:"+str(tcp_port),"target":{"host":"127.0.0.1","port":target_tcp},"outbound":"proxy"},{"tag":"udp","type":"udp-forward","listen":"127.0.0.1:"+str(udp_port),"target":{"host":"127.0.0.1","port":target_udp},"outbound":"proxy"}]
        else:
            own["outbounds"]=[{"tag":"direct","type":"direct"}]
            own["nodes"]=[{"tag":"node","type":"tuic","listen":target_address,"outbound":"direct","options":{"version":version,"tls":{"certificate_file":str(cert),"private_key_file":str(key)},"congestion_control":congestion,**auth}}]
        if args.backend=="mihomo":
            peer={"mode":"rule","log-level":"error","ipv6":True,"rules":["MATCH,DIRECT"],"geo-auto-update":False}
            if direction=="client":
                server={"enable":True,"listen":target_address,"certificate":cert.read_text(),"private-key":key.read_text(),"congestion-controller":"cubic","authentication-timeout":4000,"alpn":["h3"]}
                if version==4:
                    server["token"]=[TOKEN]
                else:
                    server["users"]={ID:PASSWORD}
                peer["tuic-server"]=server
            else:
                fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
                peer["proxies"]=[{"name":"relay","type":"tuic","server":node_host,"port":node_port,"sni":"localhost","fingerprint":fingerprint,"udp-relay-mode":mode,"congestion-controller":"cubic","alpn":["h3"],**auth}]
                peer["listeners"]=[{"name":"tcp","type":"tunnel","listen":"127.0.0.1","port":str(tcp_port),"network":["tcp"],"target":"127.0.0.1:"+str(target_tcp),"proxy":"relay"},{"name":"udp","type":"tunnel","listen":"127.0.0.1","port":str(udp_port),"network":["udp"],"target":"127.0.0.1:"+str(target_udp),"proxy":"relay"}]
            reference_args=[args.reference,"-d",str(work),"-f",str(work/"peer.json")]
        else:
            if version!=5:
                raise RuntimeError("固定 sing-box 仅作为 TUIC v5 对端")
            peer={"log":{"level":"warn"},"inbounds":[],"outbounds":[]}
            if direction=="client":
                peer["inbounds"]=[{"type":"tuic","listen":node_host,"listen_port":node_port,"users":[{"uuid":ID,"password":PASSWORD}],"congestion_control":"cubic","tls":{"enabled":True,"certificate_path":str(cert),"key_path":str(key),"alpn":["h3"]}}]
                peer["outbounds"]=[{"type":"direct"}]
            else:
                peer["outbounds"]=[{"type":"tuic","server":node_host,"server_port":node_port,"uuid":ID,"password":PASSWORD,"udp_relay_mode":mode,"congestion_control":"cubic","tls":{"enabled":True,"server_name":"localhost","certificate":[cert.read_text()],"alpn":["h3"]}}]
                peer["inbounds"]=[{"type":"direct","listen":"127.0.0.1","listen_port":tcp_port,"network":"tcp","override_address":"127.0.0.1","override_port":target_tcp},{"type":"direct","listen":"127.0.0.1","listen_port":udp_port,"network":"udp","override_address":"127.0.0.1","override_port":target_udp}]
            reference_args=[args.reference,"run","-c",str(work/"peer.json")]
        h.write_json(work/"own.json",own)
        h.write_json(work/"peer.json",peer)
        own_args=[args.kerlico,"run","-c",str(work/"own.json")]
        first=stack.enter_context(h.process(reference_args if direction=="client" else own_args,work,"first"))
        wait_udp(first,node_port,node_host)
        second=stack.enter_context(h.process(own_args if direction=="client" else reference_args,work,"second"))
        wait_tcp(second,tcp_port)
        payload=bytes(range(251))*1024
        if tcp(tcp_port,payload)!=payload:
            raise RuntimeError(label+"：TCP 回写失败")
        checks=[label+"：TCP"]
        h.write_json(work/"progress.json",checks)
        sizes=[17,900] if version==4 and mode=="native" else [17,1200,12000]
        for size in sizes:
            payload=bytes([size%251])*size
            if h.udp_request(udp_port,payload)!=payload:
                raise RuntimeError(label+"：UDP 回写失败："+str(size))
        checks.append(label+"：UDP")
        h.write_json(work/"progress.json",checks)
        if args.lifecycle:
            own_process = second if direction == "client" else first
            own_process.send_signal(signal.SIGTERM)
            status = own_process.wait(timeout=4)
            if status != 0:
                raise RuntimeError(label+"：根程序退出状态异常："+str(status))
            if direction == "server":
                family = socket.AF_INET6 if ":" in node_host else socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as probe:
                    probe.bind((node_host,node_port))
            else:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                    probe.bind(("127.0.0.1",udp_port))
            restarted = stack.enter_context(h.process(own_args,work,"restarted"))
            if direction == "server":
                wait_udp(restarted,node_port,node_host)
            else:
                wait_tcp(restarted,tcp_port)
            restarted.send_signal(signal.SIGTERM)
            status = restarted.wait(timeout=4)
            if status != 0:
                raise RuntimeError(label+"：重启后退出状态异常："+str(status))
            checks.append(label+"：有界退出与同端口重启")
            h.write_json(work/"progress.json",checks)
        return checks

def main():
    parser=argparse.ArgumentParser(description="TUIC v4/v5 双向真实互通")
    parser.add_argument("--kerlico",required=True)
    parser.add_argument("--reference",required=True)
    parser.add_argument("--backend",choices=("mihomo","sing-box"),required=True)
    parser.add_argument("--work-dir",required=True)
    parser.add_argument("--full",action="store_true")
    parser.add_argument("--lifecycle",action="store_true")
    args=parser.parse_args()
    os.umask(0o077)
    root=Path(args.work_dir).resolve()
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    cert,key=root/"certificate.pem",root/"key.pem"
    result=subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(cert),"-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-addext","basicConstraints=critical,CA:FALSE","-addext","extendedKeyUsage=serverAuth"],capture_output=True,timeout=30)
    if result.returncode:
        raise RuntimeError("测试证书生成失败")
    checks,failures=[],[]
    for version in ([4,5] if args.backend=="mihomo" else [5]):
        for mode in ["native","quic"]:
            for host in (["127.0.0.1","::1"] if args.full else ["127.0.0.1"]):
                for congestion in (["cubic","newreno","bbr"] if args.full else ["cubic"]):
                    for direction in ["client","server"]:
                        try:
                            checks.extend(verify(args,root,version,mode,host,congestion,direction,cert,key))
                        except Exception as error:
                            failures.append({"version":version,"mode":mode,"node_family":6 if ":" in host else 4,"congestion":congestion,"direction":direction,"error":str(error) if isinstance(error,RuntimeError) else type(error).__name__})
    result={"ok":not failures,"checks":checks,"failures":failures,"binary_sha256":hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(),"reference_sha256":hashlib.sha256(Path(args.reference).read_bytes()).hexdigest()}
    h.write_json(root/"result.json",result)
    print(json.dumps(result,ensure_ascii=False),flush=True)
    if failures:
        raise SystemExit(1)

if __name__=="__main__":
    main()
