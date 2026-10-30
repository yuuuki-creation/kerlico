#!/usr/bin/env python3
"""在 worker 对照业务 TLS 的实际上传字节，定位 Vision 转发差异；捕获只留私有目录。"""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import threading
from types import SimpleNamespace

import interop_vless as h
import interop_vless_matrix as matrix

CONTEXT = threading.local()
CAPTURES = {}
LOCK = threading.Lock()
ORIGINAL_TCP = matrix.tcp


def bio_client(port, payload, context=None):
    if context is None:
        return ORIGINAL_TCP(port, payload)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname="localhost")
    uploaded, received, downloaded = bytearray(), bytearray(), bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
        sock.settimeout(8)
        def flush():
            while outgoing.pending:
                data = outgoing.read()
                uploaded.extend(data)
                sock.sendall(data)
        def invoke(operation):
            while True:
                try:
                    value = operation()
                    flush()
                    return value
                except ssl.SSLWantReadError:
                    flush()
                    data = sock.recv(65536)
                    downloaded.extend(data)
                    if not data:
                        incoming.write_eof()
                    else:
                        incoming.write(data)
                except ssl.SSLWantWriteError:
                    flush()
        try:
            invoke(tls.do_handshake)
            data = len(payload).to_bytes(4,"big")+payload
            offset = 0
            while offset < len(data):
                offset += invoke(lambda: tls.write(data[offset:]))
            while len(received)<len(payload):
                data = invoke(lambda: tls.read(min(65536,len(payload)-len(received))))
                if not data:
                    break
                received.extend(data)
            return bytes(received)
        finally:
            (CONTEXT.current / "client-upload.bin").write_bytes(uploaded)
            (CONTEXT.current / "client-download.bin").write_bytes(downloaded)


def bio_server(handler):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = handler.server.tls.wrap_bio(incoming, outgoing, server_side=True)
    upload,download = bytearray(),bytearray()
    completed = False
    reason = None
    handler.request.settimeout(10)
    def flush():
        while outgoing.pending:
            data=outgoing.read()
            download.extend(data)
            handler.request.sendall(data)
    def invoke(operation):
        while True:
            try:
                value = operation()
                flush()
                return value
            except ssl.SSLWantReadError:
                flush()
                data=handler.request.recv(65536)
                if not data:
                    incoming.write_eof()
                else:
                    upload.extend(data)
                    incoming.write(data)
            except ssl.SSLWantWriteError:
                flush()
    try:
        invoke(tls.do_handshake)
        completed = True
        prefix = bytearray()
        while len(prefix)<4:
            data=invoke(lambda:tls.read(4-len(prefix)))
            if not data:return
            prefix.extend(data)
        expected=int.from_bytes(prefix,"big")
        if expected>2*1024*1024:return
        payload=bytearray()
        while len(payload)<expected:
            data=invoke(lambda:tls.read(min(65536,expected-len(payload))))
            if not data:return
            payload.extend(data)
        offset=0
        while offset<len(payload):
            offset+=invoke(lambda:tls.write(payload[offset:]))
    except (OSError,ssl.SSLError) as error:
        reason=type(error).__name__+":"+str(error)
        try:flush()
        except OSError:pass
    finally:
        if completed:
            with LOCK:
                captures=CAPTURES[handler.server.capture_root]
                index=len(captures)
                captures.append({"bytes":bytes(upload),"download":bytes(download),"error":reason})
            (handler.server.capture_root / ("server-upload-"+str(index)+".bin")).write_bytes(upload)
            (handler.server.capture_root / ("server-download-"+str(index)+".bin")).write_bytes(download)


class SocketCapture:
    def __init__(self,port,root):
        self.port,self.root=port,root
        self.packets={}
        self.stop=threading.Event()
        self.socket=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
        self.socket.bind(("lo",0))
        self.socket.settimeout(0.1)
        self.thread=threading.Thread(target=self.receive,daemon=True)
        self.thread.start()
    def receive(self):
        while not self.stop.is_set():
            try:data=self.socket.recv(65536)
            except socket.timeout:continue
            except OSError:return
            if len(data)<54 or data[12:14]!=b"\x08\x00" or data[23]!=6:continue
            offset=14+(data[14]&15)*4
            if len(data)<offset+20 or data[26:30]!=b"\x7f\x00\x00\x01" or data[30:34]!=b"\x7f\x00\x00\x01":continue
            src,dst,seq=struct.unpack("!HHI",data[offset:offset+8])
            if self.port not in (src,dst):continue
            end=14+int.from_bytes(data[16:18],"big")
            start=offset+(data[offset+12]>>4)*4
            payload=data[start:end]
            if not payload:continue
            direction="upload" if dst==self.port else "download"
            client=src if dst==self.port else dst
            self.packets.setdefault((client,direction),{})[seq]=payload
    def finish(self):
        self.stop.set();self.thread.join(timeout=1);self.socket.close()
        streams=[]
        for client in sorted({client for client,_ in self.packets}):
            row={}
            for direction in ("upload","download"):
                chunks=self.packets.get((client,direction),{});out=bytearray();end=None;gaps=0
                for seq,data in sorted(chunks.items()):
                    if end is None:end=seq
                    if seq>end:gaps+=seq-end
                    overlap=max(0,end-seq);out.extend(data[overlap:]);end=max(end,seq+len(data))
                row[direction]=bytes(out);row[direction+"_gaps"]=gaps
                (self.root/("capture-"+str(client)+"-"+direction+".bin")).write_bytes(out)
            streams.append(row)
        return streams

def main():
    parser=argparse.ArgumentParser(description="业务 TLS 字节对照，只在专用 worker 执行")
    parser.add_argument("--kerlico",required=True)
    parser.add_argument("--reference",required=True)
    parser.add_argument("--work-dir",required=True)
    parser.add_argument("--repeat",type=int,default=12)
    parser.add_argument("--workers",type=int,default=2)
    parser.add_argument("--socket-client",action="store_true")
    parser.add_argument("--socket-server",action="store_true")
    args=parser.parse_args()
    args.kerlico=str(Path(args.kerlico).resolve())
    args.reference=str(Path(args.reference).resolve())
    args.diagnose=True
    args.mux=False
    args.packet_encoding=None
    root=Path(args.work_dir).resolve()
    os.umask(0o077)
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    materials=matrix.material(root)
    if not args.socket_client:matrix.tcp=bio_client
    if not args.socket_server:matrix.TlsEcho.handle=bio_server
    original_server=matrix.TlsServer
    class CapturedServer(original_server):
        def __init__(self,*values):
            super().__init__(*values)
            self.capture_root=CONTEXT.current
            self.capture=None
            if args.socket_server and not CONTEXT.target_seen:
                CONTEXT.target_seen=True
                self.capture=SocketCapture(self.server_address[1],self.capture_root)
        def server_close(self):
            super().server_close()
            if self.capture is not None:CONTEXT.packet_streams=self.capture.finish()
    matrix.TlsServer=CapturedServer
    results=[]
    case=matrix.Case("tcp","reality",vision=True)
    def run(iteration):
        directory=root/("iteration-"+str(iteration))
        directory.mkdir(mode=0o700)
        CONTEXT.current=directory
        CONTEXT.target_seen=False
        CONTEXT.packet_streams=[]
        with LOCK:CAPTURES[directory]=[]
        try:
            matrix.verify(case,args,directory,materials)
            result={"iteration":iteration,"ok":True}
        except Exception as error:
            result={"iteration":iteration,"ok":False,"error":str(error)}
        expected=(directory/"client-upload.bin").read_bytes() if (directory/"client-upload.bin").exists() else b""
        received=(directory/"client-download.bin").read_bytes() if (directory/"client-download.bin").exists() else b""
        result["packet_comparison"]=[{"upload":len(capture["upload"]),"download":len(capture["download"]),"upload_gaps":capture["upload_gaps"],"download_gaps":capture["download_gaps"],"upload_mismatch":next((i for i,(a,b) in enumerate(zip(expected,capture["upload"])) if a!=b),None),"download_mismatch":next((i for i,(a,b) in enumerate(zip(capture["download"],received)) if a!=b),None),"client_download":len(received)} for capture in CONTEXT.packet_streams]
        result["downloads"]=[{"target":len(capture["download"]),"client":len(received),"first_mismatch":next((i for i,(a,b) in enumerate(zip(capture["download"],received)) if a!=b),None)} for capture in CAPTURES[directory]]
        result["uploads"]=[{"client":len(expected),"target":len(capture["bytes"]),"first_mismatch":next((i for i,(a,b) in enumerate(zip(expected,capture["bytes"])) if a!=b),None),"error":capture["error"]} for capture in CAPTURES[directory]]
        return result
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for future in as_completed([pool.submit(run,iteration) for iteration in range(args.repeat)]):
            result=future.result()
            results.append(result)
            print(json.dumps(result,ensure_ascii=False),flush=True)
            h.write_json(root/"results.json",{"binary_sha256":hashlib.sha256(Path(args.kerlico).read_bytes()).hexdigest(),"results":results})


if __name__=="__main__":main()
