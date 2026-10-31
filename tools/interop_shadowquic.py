#!/usr/bin/env python3
"""专用 worker 的 ShadowQUIC/JLS 双端与真实上游回退矩阵。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import interop_vless as h
USERNAME = "node-user"
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

def tcp(port,payload):
    with socket.create_connection(("127.0.0.1",port),timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(len(payload).to_bytes(4,"big")+payload)
        answer=bytearray()
        while len(answer)<len(payload):
            part=sock.recv(min(65535,len(payload)-len(answer)))
            if not part:
                break
            answer.extend(part)
        return bytes(answer)

def verify(args,root,version,mode,host,congestion,direction):
    label="-".join([version,mode,"node6" if ":" in host else "node4",congestion,direction])
    work=root/label
    work.mkdir(mode=0o700)
    checks=[]
    used=set()
    def port():
        while True:
            value=h.free_port()
            if value not in used:
                used.add(value)
                return value
    with ExitStack() as stack:
        tcp_target=stack.enter_context(h.serve(h.TcpServer(("127.0.0.1",0),h.TcpEcho)))
        udp_target=stack.enter_context(h.serve(UdpServer(("127.0.0.1",0),h.UdpEcho)))
        cover_port,node_port,tcp_port,udp_port=port(),port(),port(),port()
        cover_host="127.0.0.1" if ":" in host else "::1"
        cover_address=("[::1]:" if ":" in cover_host else "127.0.0.1:")+str(cover_port)
        node_address=("[::1]:" if ":" in host else "127.0.0.1:")+str(node_port)
        cert=work/"cover.pem"
        cover=stack.enter_context(h.process([args.cover,cover_address,str(cert),version],work,"cover"))
        wait_udp(cover,cover_port,cover_host)
        own={"version":1,"limits":{"connect_timeout_ms":4000,"idle_timeout_ms":10000,"drain_timeout_ms":500},"inbounds":[],"outbounds":[]}
        peer={"mode":"rule","log-level":"error","ipv6":True,"rules":["MATCH,DIRECT"],"geo-auto-update":False}
        auth={"username":USERNAME,"password":PASSWORD}
        if direction=="client":
            options={"server":{"host":host,"port":node_port},"server_name":"cover.invalid","quic_version":version,"udp_mode":mode,"congestion_control":congestion,**auth}
            own["outbounds"]=[{"tag":"proxy","type":"shadowquic","options":options}]
            own["inbounds"]=[{"tag":"tcp","type":"tcp-forward","listen":"127.0.0.1:"+str(tcp_port),"target":{"host":"127.0.0.1","port":tcp_target},"outbound":"proxy"},{"tag":"udp","type":"udp-forward","listen":"127.0.0.1:"+str(udp_port),"target":{"host":"127.0.0.1","port":udp_target},"outbound":"proxy"}]
            peer["listeners"]=[{"name":"node","type":"shadowquic","listen":host,"port":str(node_port),"users":[auth],"jls-upstream":{"addr":cover_address,"sni":"cover.invalid"},"quic-versions":[version],"alpn":["h3"],"congestion-controller":"cubic","max-idle-time":10000}]
        else:
            own["outbounds"]=[{"tag":"direct","type":"direct"}]
            own["nodes"]=[{"tag":"node","type":"shadowquic","listen":node_address,"outbound":"direct","options":{"upstream":{"host":cover_host,"port":cover_port},"server_name":"cover.invalid","quic_versions":[version],"congestion_control":congestion,**auth}}]
            peer["proxies"]=[{"name":"relay","type":"shadowquic","server":host,"port":node_port,"sni":"cover.invalid","quic-versions":[version],"udp-over-stream":mode=="stream","congestion-controller":"cubic","alpn":["h3"],**auth}]
            peer["listeners"]=[{"name":"tcp","type":"tunnel","listen":"127.0.0.1","port":str(tcp_port),"network":["tcp"],"target":"127.0.0.1:"+str(tcp_target),"proxy":"relay"},{"name":"udp","type":"tunnel","listen":"127.0.0.1","port":str(udp_port),"network":["udp"],"target":"127.0.0.1:"+str(udp_target),"proxy":"relay"}]
        h.write_json(work/"own.json",own)
        h.write_json(work/"peer.json",peer)
        own_args=[args.kerlico,"run","-c",str(work/"own.json")]
        peer_args=[args.reference,"-d",str(work),"-f",str(work/"peer.json")]
        first=stack.enter_context(h.process(peer_args if direction=="client" else own_args,work,"first"))
        wait_udp(first,node_port,host)
        second=stack.enter_context(h.process(own_args if direction=="client" else peer_args,work,"second"))
        wait_tcp(second,tcp_port)
        (work/"stage.json").write_text("TCP")
        payload=bytes(range(251))*1024
        if tcp(tcp_port,payload)!=payload:
            raise RuntimeError(label+"：TCP 回写失败")
        checks.append(label+"：TCP")
        (work/"stage.json").write_text("UDP")
        for size in ([17,900] if mode=="datagram" else [17,1200,12000]):
            payload=bytes([size%251])*size
            if h.udp_request(udp_port,payload)!=payload:
                raise RuntimeError(label+"：UDP 回写失败："+str(size))
        checks.append(label+"：UDP")
        (work/"stage.json").write_text("回退")
        probe=subprocess.run([args.cover,"probe",node_address,str(cert),version],capture_output=True,timeout=8)
        (work/"cover-probe.log").write_bytes(probe.stdout+probe.stderr)
        if probe.returncode:
            raise RuntimeError(label+"：普通 QUIC 未真实回退到合成上游")
        checks.append(label+"：JLS 上游回退")
        h.write_json(work/"progress.json",checks)
        if args.lifecycle:
            process=second if direction=="client" else first
            process.send_signal(signal.SIGTERM)
            if process.wait(timeout=4)!=0:
                raise RuntimeError(label+"：根程序退出状态异常")
            restarted=stack.enter_context(h.process(own_args,work,"restarted"))
            if direction=="client":
                wait_tcp(restarted,tcp_port)
            else:
                wait_udp(restarted,node_port,host)
            restarted.send_signal(signal.SIGTERM)
            if restarted.wait(timeout=4)!=0:
                raise RuntimeError(label+"：重启退出状态异常")
            checks.append(label+"：有界退出与同端口重启")
        return checks

def main():
    parser=argparse.ArgumentParser(description="ShadowQUIC/JLS 双向真实互通")
    parser.add_argument("--kerlico",required=True)
    parser.add_argument("--reference",required=True)
    parser.add_argument("--cover",required=True)
    parser.add_argument("--work-dir",required=True)
    parser.add_argument("--full",action="store_true")
    parser.add_argument("--versions",nargs="+",choices=["v1","v2"],default=["v1","v2"])
    parser.add_argument("--lifecycle",action="store_true")
    args=parser.parse_args()
    os.umask(0o077)
    root=Path(args.work_dir).resolve()
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    checks,failures=[],[]
    for version in args.versions:
        for mode in ["datagram","stream"]:
            for host in (["127.0.0.1","::1"] if args.full else ["127.0.0.1"]):
                for congestion in (["cubic","newreno","bbr"] if args.full else ["cubic"]):
                    for direction in ["client","server"]:
                        try:
                            checks.extend(verify(args,root,version,mode,host,congestion,direction))
                        except Exception as error:
                            failures.append({"version":version,"mode":mode,"node_family":6 if ":" in host else 4,"congestion":congestion,"direction":direction,"error":str(error) if isinstance(error,RuntimeError) else type(error).__name__})
    result={"ok":not failures,"checks":checks,"failures":failures,"binary_sha256":hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(),"reference_sha256":hashlib.sha256(Path(args.reference).read_bytes()).hexdigest()}
    h.write_json(root/"result.json",result)
    print(json.dumps(result,ensure_ascii=False),flush=True)
    if failures:
        raise SystemExit(1)

if __name__=="__main__":
    main()
