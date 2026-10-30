#!/usr/bin/env python3
"""在 worker 验证 XHTTP 上下行独立端点、CA、SNI、地址族及 H1/H2/H3。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack,contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import threading
import time

import interop_vless as h
from interop_vless_matrix import tcp


def cert(root,name):
    certificate,key=root/(name+".pem"),root/(name+".key")
    result=subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(key),"-out",str(certificate),"-days","1","-subj","/CN="+name+".invalid","-addext","subjectAltName=DNS:"+name+".invalid","-addext","basicConstraints=critical,CA:FALSE","-addext","extendedKeyUsage=serverAuth"],capture_output=True,timeout=30)
    if result.returncode:raise RuntimeError("分离端点测试证书生成失败")
    return certificate,key


class TcpFront(h.TcpServer):
    def __init__(self,host,identity,backend,backend_cert):
        if ":" in host:self.address_family=socket.AF_INET6
        self.backend=backend;self.names=[];self.accepted=0
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_3
        self.context.set_alpn_protocols(["h2","http/1.1"])
        self.context.load_cert_chain(*map(str,identity))
        self.context.set_servername_callback(lambda _,name,__:self.names.append(name))
        self.backend_cert=backend_cert
        super().__init__((host,0),FrontHandler)


class FrontHandler(h.TcpEcho):
    def handle(self):
        client=upstream=None
        try:
            self.request.settimeout(5)
            client=self.server.context.wrap_socket(self.request,server_side=True)
            context=ssl.create_default_context(cafile=str(self.server.backend_cert))
            context.set_alpn_protocols([client.selected_alpn_protocol() or "http/1.1"])
            upstream=context.wrap_socket(socket.create_connection(("127.0.0.1",self.server.backend),timeout=5),server_hostname="backend.invalid")
            self.server.accepted+=1
            for sock in (client,upstream):sock.setblocking(False)
            ends={client:False,upstream:False};pending={client:bytearray(),upstream:bytearray()};closed=set();writes={client:None,upstream:None};last=time.monotonic()
            # 同一线程驱动两个 SSL 对象；SSL_read/SSL_write 不跨线程并发。
            while time.monotonic()-last<12:
                read=[sock for sock in (client,upstream) if not ends[sock] and len(pending[upstream if sock is client else client])<262144]
                write=[sock for sock in (client,upstream) if pending[sock]]
                ready_read,ready_write,_=select.select(read,write,[],0.05)
                for sock in read:
                    if sock.pending()>0 and sock not in ready_read:ready_read.append(sock)
                for sock in ready_read:
                    other=upstream if sock is client else client
                    try:data=sock.recv(32768)
                    except (ssl.SSLWantReadError,ssl.SSLWantWriteError):continue
                    if data:pending[other].extend(data);last=time.monotonic()
                    else:ends[sock]=True
                for sock in ready_write:
                    if writes[sock] is None:writes[sock]=bytes(pending[sock][:32768])
                    try:count=sock.send(writes[sock])
                    except (ssl.SSLWantReadError,ssl.SSLWantWriteError):continue
                    del pending[sock][:count];writes[sock]=None;last=time.monotonic()
                for source,destination in ((client,upstream),(upstream,client)):
                    if ends[source] and not pending[destination] and destination not in closed:
                        try:socket.socket.shutdown(destination,socket.SHUT_WR)
                        except OSError:pass
                        closed.add(destination)
                if all(ends.values()) and not any(pending.values()):break
        except (OSError,ssl.SSLError):pass
        finally:
            for sock in (client,upstream):
                if sock is not None:sock.close()


class UdpFront:
    def __init__(self,host,backend):
        self.backend=("127.0.0.1",backend);self.stop=threading.Event();self.count=0
        self.listener=socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET,socket.SOCK_DGRAM)
        self.listener.bind((host,0));self.port=self.listener.getsockname()[1]
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        clients={};reverse={}
        try:
            while not self.stop.is_set():
                ready,_,_=select.select([self.listener,*reverse],[],[],0.05)
                for sock in ready:
                    if sock is self.listener:
                        data,address=sock.recvfrom(65535)
                        if address not in clients:
                            if len(clients)>=128:continue
                            output=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);output.connect(self.backend);clients[address]=output;reverse[output]=address
                        clients[address].send(data);self.count+=1
                    else:
                        self.listener.sendto(sock.recv(65535),reverse[sock])
        except OSError:pass
        finally:
            for sock in reverse:sock.close()
    def close(self):
        self.stop.set();self.thread.join(timeout=2);self.listener.close()


def verify(args,root,materials,up,down,mode,negative=None):
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    with ExitStack() as stack:
        target4=stack.enter_context(h.serve(h.TcpServer(("127.0.0.1",0),h.TcpEcho)))
        target6=stack.enter_context(h.serve(h.TcpServer6(("::1",0),h.TcpEcho)))
        backend=h.free_port();user="00000000-0000-0000-0000-000000000061"
        use_core=up=="h3" or down=="h3"
        if use_core:
            server={"version":1,"outbounds":[{"tag":"direct","type":"direct"}],"inbounds":[],"nodes":[{"tag":"logical-node","type":"vless","listen":"127.0.0.1:"+str(backend),"outbound":"direct","max_sessions":64,"options":{"uuid":user,"security":{"type":"tls","certificate_file":str(materials["backend"][0]),"private_key_file":str(materials["backend"][1])},"transport":{"type":"xhttp","settings":{"path":"/split","mode":"auto","http_version":"auto"}}}}],"limits":{"connect_timeout_ms":5000,"idle_timeout_ms":8000,"drain_timeout_ms":200,"max_sessions":128}}
            server_args=[args.kerlico,"run","-c"]
        else:
            server={"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":backend,"protocol":"vless","settings":{"clients":[{"id":user}],"decryption":"none"},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"certificates":[{"certificateFile":str(materials["backend"][0]),"keyFile":str(materials["backend"][1])}]},"xhttpSettings":{"path":"/split","mode":"auto"}}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32","::1/128"],"port":str(target4)+","+str(target6)}]}}]}
            server_args=[args.reference,"run","-config"]
        path=root/"backend.json";h.write_json(path,server)
        process=stack.enter_context(h.process(server_args+[str(path)],root,"backend"));h.wait_ready(process,backend)
        fronts=[];security=[];ports=[]
        for version,host,name in [(up,"127.0.0.1","upload"),(down,"::1","download")]:
            if version=="h3":
                front=UdpFront(host,backend);stack.callback(front.close);port=front.port;identity="backend"
            else:
                front=TcpFront(host,materials[name],backend,materials["backend"][0]);port=stack.enter_context(h.serve(front));identity=name
            fronts.append(front);ports.append(port);security.append({"type":"tls","server_name":identity+".invalid","ca_pem":materials[identity][0].read_text()})
        if negative=="ca":security[1]["ca_pem"]=materials["untrusted"][0].read_text()
        elif negative=="sni":security[1]["server_name"]="wrong.invalid"
        options={"server":{"host":"127.0.0.1","port":ports[0]},"server_family":"ipv4","uuid":user,"security":security[0],"transport":{"type":"xhttp","settings":{"path":"/split","mode":mode,"http_version":up,"download":{"server":{"host":"::1","port":ports[1]},"server_family":"ipv6","security":security[1],"xhttp":{"path":"/split","http_version":down,"mode":"auto"}}}}}
        locals_=[h.free_port(),h.free_port()]
        client={"version":1,"outbounds":[{"tag":"proxy","type":"vless","options":options}],"inbounds":[{"tag":"site"+str(index),"type":"tcp-forward","listen":"127.0.0.1:"+str(local),"target":{"host":host,"port":target},"outbound":"proxy"} for index,(local,(host,target)) in enumerate(zip(locals_,[("127.0.0.1",target4),("::1",target6)]))],"limits":{"connect_timeout_ms":5000,"idle_timeout_ms":8000,"drain_timeout_ms":200,"max_sessions":64}}
        path=root/"client.json";h.write_json(path,client)
        with h.process([args.kerlico,"run","-c",str(path)],root,"client") as process:
            h.wait_ready(process,locals_[0])
            if negative:
                try:response=tcp(locals_[0],b"must-fail-download-verification")
                except OSError:response=b""
                if response:raise RuntimeError("独立下载的错误 CA/SNI 被接受")
                return ["独立下载拒绝错误 "+negative]
            payload=bytes(range(256))*256
            for local in locals_:
                if tcp(local,payload)!=payload:raise RuntimeError("分离端点 TCP 回写不一致")
            with ThreadPoolExecutor(max_workers=4) as pool:
                values=[bytes([index])*32768 for index in range(4)]
                if list(pool.map(lambda value:tcp(locals_[0],value),values))!=values:raise RuntimeError("分离端点并发串流")
            for front,version,name in zip(fronts,[up,down],["upload","download"]):
                if version=="h3":
                    if front.count==0:raise RuntimeError("未使用配置的 QUIC 方向")
                elif front.accepted==0 or name+".invalid" not in front.names:raise RuntimeError("未使用配置的独立 TLS 方向")
            process.terminate()
            if process.wait(timeout=3)!=0:raise RuntimeError("上下行分离退出失败")
        return ["两类网站目标 64KiB","四路并发","两个前端实际访问","CA/SNI 独立","有界退出"]


def main():
    parser=argparse.ArgumentParser(description="XHTTP 上下行分离互通，只在 worker 执行")
    parser.add_argument("--kerlico",required=True);parser.add_argument("--reference",required=True);parser.add_argument("--work-dir",required=True)
    args=parser.parse_args();args.kerlico=str(Path(args.kerlico).resolve());args.reference=str(Path(args.reference).resolve())
    root=Path(args.work_dir).resolve();os.umask(0o077);root.mkdir(parents=True,exist_ok=True,mode=0o700)
    materials={name:cert(root,name) for name in ["backend","upload","download","untrusted"]}
    cases=[("h1","h1","packet-up"),("h1","h2","packet-up"),("h2","h1","stream-up"),("h2","h2","stream-up"),("h1","h3","packet-up"),("h2","h3","stream-up"),("h3","h2","packet-up"),("h3","h3","packet-up")]
    results=[]
    for up,down,mode,negative in [(*case,None) for case in cases]+[("h2","h1","stream-up","ca"),("h1","h2","packet-up","sni")]:
        label="-".join([up,down,mode,negative or "valid"])
        try:result={"case":label,"oracle":"self" if "h3" in (up,down) else "xray","ok":True,"checks":verify(args,root/label,materials,up,down,mode,negative)}
        except Exception as error:result={"case":label,"ok":False,"reason":str(error) if isinstance(error,RuntimeError) else type(error).__name__+":"+str(error)}
        results.append(result);print(json.dumps(result,ensure_ascii=False),flush=True);h.write_json(root/"results.json",{"binary_sha256":hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(),"results":results})
    if not all(row["ok"] for row in results):raise SystemExit(1)


if __name__=="__main__":main()
