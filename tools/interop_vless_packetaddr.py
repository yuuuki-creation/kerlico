#!/usr/bin/env python3
"""在 worker 用固定 sing-box 验证 packetaddr 双端与两类地址。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import socket
import time

import interop_vless as h
from interop_vless_matrix import material


class Udp4(h.UdpServer):
    max_packet_size=65535


class Udp6(Udp4):
    address_family=socket.AF_INET6


def verify(args,root,role,family):
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    cert,key,_,_,_=material(root)
    host="127.0.0.1" if family==4 else "::1"
    user="00000000-0000-0000-0000-00000000005"+str(family)
    with ExitStack() as stack:
        target4=stack.enter_context(h.serve(Udp4(("127.0.0.1",0),h.UdpEcho)))
        target6=stack.enter_context(h.serve(Udp6(("::1",0),h.UdpEcho)))
        node_port=h.free_port();ports=[h.free_port(),h.free_port()]
        targets=[("127.0.0.1",target4),("::1",target6)]
        if role=="client":
            reference={"log":{"level":"error"},"inbounds":[{"type":"vless","listen":host,"listen_port":node_port,"users":[{"uuid":user}],"tls":{"enabled":True,"certificate_path":str(cert),"key_path":str(key)}}],"outbounds":[{"type":"direct"}]}
            options={"server":{"host":host,"port":node_port},"uuid":user,"packet_encoding":"packetaddr","security":{"type":"tls","server_name":"localhost","ca_pem":cert.read_text()}}
            config={"version":1,"outbounds":[{"tag":"proxy","type":"vless","options":options}],"inbounds":[{"tag":"udp"+str(index),"type":"udp-forward","listen":"127.0.0.1:"+str(local),"target":{"host":address,"port":port},"outbound":"proxy"} for index,(local,(address,port)) in enumerate(zip(ports,targets))],"limits":{"connect_timeout_ms":3000,"idle_timeout_ms":6000,"drain_timeout_ms":200}}
        else:
            config={"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"node","type":"vless","listen":("["+host+"]" if family==6 else host)+":"+str(node_port),"outbound":"direct","options":{"uuid":user,"security":{"type":"tls","certificate_file":str(cert),"private_key_file":str(key)}}}],"limits":{"connect_timeout_ms":3000,"idle_timeout_ms":6000,"drain_timeout_ms":200}}
            reference={"log":{"level":"error"},"inbounds":[{"type":"direct","listen":"127.0.0.1","listen_port":local,"network":"udp","override_address":address,"override_port":port} for local,(address,port) in zip(ports,targets)],"outbounds":[{"type":"vless","server":host,"server_port":node_port,"uuid":user,"packet_encoding":"packetaddr","tls":{"enabled":True,"server_name":"localhost","certificate_path":str(cert)}}]}
        core_path=root/"kerlico.json";ref_path=root/"reference.json"
        h.write_json(core_path,config);h.write_json(ref_path,reference)
        with h.process([args.kerlico,"run","-c",str(core_path)],root,"kerlico") as core,h.process([args.reference,"run","-c",str(ref_path)],root,"reference") as peer:
            deadline=time.monotonic()+8
            listener=peer if role=="client" else core
            while True:
                if listener.poll() is not None:raise RuntimeError("packetaddr 节点启动失败")
                try:
                    with socket.create_connection((host,node_port),timeout=0.1):break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError("packetaddr 节点就绪超时")
                    time.sleep(0.03)
            time.sleep(0.15)
            if core.poll() is not None or peer.poll() is not None:raise RuntimeError("packetaddr 进程启动失败")
            checks=[]
            for index,local in enumerate(ports):
                for size in [17,4096,12000]:
                    payload=bytes(value%251 for value in range(size))
                    if h.udp_request(local,payload)!=payload:raise RuntimeError("packetaddr 地址或包边界回写不一致")
                    checks.append("target"+str(index)+"："+str(size))
            for child in (core,peer):
                child.terminate()
                if child.wait(timeout=3)!=0:raise RuntimeError("packetaddr 进程退出失败")
            checks.append("有界退出")
            return checks


def main():
    parser=argparse.ArgumentParser(description="真实 sing-box packetaddr 双向互通")
    parser.add_argument("--kerlico",required=True)
    parser.add_argument("--reference",required=True)
    parser.add_argument("--work-dir",required=True)
    args=parser.parse_args()
    args.kerlico=str(Path(args.kerlico).resolve());args.reference=str(Path(args.reference).resolve())
    root=Path(args.work_dir).resolve();os.umask(0o077);root.mkdir(parents=True,exist_ok=True,mode=0o700)
    results=[]
    for role in ["client","server"]:
        for family in [4,6]:
            try:result={"role":role,"family":family,"ok":True,"checks":verify(args,root/(role+str(family)),role,family)}
            except Exception as error:result={"role":role,"family":family,"ok":False,"reason":str(error) if isinstance(error,RuntimeError) else type(error).__name__+":"+str(error)}
            results.append(result);print(json.dumps(result,ensure_ascii=False),flush=True)
            h.write_json(root/"results.json",{"binary_sha256":hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(),"results":results})
    if not all(row["ok"] for row in results):raise SystemExit(1)


if __name__=="__main__":main()
