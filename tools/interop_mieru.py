#!/usr/bin/env python3
"""专用 worker：Mieru TCP 与显式本地旧 UDP 的双角色独立对端矩阵。"""
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
USERNAME='node-user'
PASSWORD='synthetic-password'
class UdpServer(h.UdpServer):max_packet_size=65535
class UdpServer6(UdpServer):address_family=socket.AF_INET6

def address(host,port):return ('['+host+']' if ':' in host else host)+':'+str(port)
def wait_listener(child,port,protocol):
 deadline=time.monotonic()+8;observed=False
 while time.monotonic()<deadline:
  if child.poll() is not None:raise RuntimeError('对端在监听就绪前退出')
  owned=set()
  for descriptor in Path('/proc/'+str(child.pid)+'/fd').glob('*'):
   try:target=os.readlink(descriptor)
   except FileNotFoundError:continue
   if target.startswith('socket:[') and target.endswith(']'):owned.add(target[8:-1])
  ready=False
  for suffix in ['', '6']:
   table=Path('/proc/net/'+protocol+suffix)
   if not table.exists():continue
   for line in table.read_text().splitlines()[1:]:
    fields=line.split()
    if len(fields)>9 and fields[9] in owned and int(fields[1].split(':')[-1],16)==port and (protocol=='udp' or fields[3]=='0A'):ready=True
  if ready and observed:return
  observed=ready;time.sleep(0.02)
 raise RuntimeError('进程自身监听未在预算内就绪')
def tcp(port,payload):
 with socket.create_connection(('127.0.0.1',port),timeout=5) as stream:
  stream.settimeout(8);stream.sendall(len(payload).to_bytes(4,'big')+payload);reply=bytearray()
  while len(reply)<len(payload):
   chunk=stream.recv(min(65535,len(payload)-len(reply)))
   if not chunk:break
   reply.extend(chunk)
  return bytes(reply)
def packet(port,data,timeout=5):
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
  stream.settimeout(timeout);stream.sendto(data,('127.0.0.1',port));return stream.recv(65535)
def verify(args,root,transport,host,target_host,mux,no_wait,mode,rotation,role):
 label='-'.join([transport,'node6' if ':' in host else 'node4','target6' if ':' in target_host else 'target4','mux' if mux else 'single','lazy' if no_wait else 'wait','e'+str(mode)+'r'+str(rotation),role])
 work=root/label;work.mkdir(mode=0o700);checks=[];boundaries=[];used=set()
 def port():
  while True:
   value=h.free_port()
   if value in used:continue
   with ExitStack() as sockets:
    try:
     for family,ip in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
      for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
       test=sockets.enter_context(socket.socket(family,kind));test.bind((ip,value))
    except OSError:continue
   used.add(value);return value
 encoded=subprocess.run([args.pattern_encoder,'-encode-traffic','-mode',str(mode),'-rotation',str(rotation),'-padding','32'],capture_output=True,timeout=5)
 if encoded.returncode:raise RuntimeError('固定参照的 traffic pattern 编码失败')
 pattern=encoded.stdout.decode().strip()
 with ExitStack() as stack:
  tcp_server=h.TcpServer6 if ':' in target_host else h.TcpServer;udp_server=UdpServer6 if ':' in target_host else UdpServer
  tp=stack.enter_context(h.serve(tcp_server((target_host,0),h.TcpEcho)));up=stack.enter_context(h.serve(udp_server((target_host,0),h.UdpEcho)))
  np,tcp_port,udp_port=port(),port(),port()
  own={'version':1,'inbounds':[],'outbounds':[],'limits':{'connect_timeout_ms':4000,'idle_timeout_ms':10000,'drain_timeout_ms':500,'max_sessions':128,'max_datagram_size':65535}}
  reference={'mode':'rule','rules':['MATCH,DIRECT'],'log-level':'error','geo-auto-update':False,'ipv6':True}
  auth={'username':USERNAME,'password':PASSWORD};traffic={'low_entropy_mode':mode,'mask_rotation':rotation,'max_padding':32}
  if role=='client':
   own['outbounds']=[{'tag':'proxy','type':'mieru','options':{'server':{'host':host,'port':np},'transport':transport,'unsafe_udp_compatibility':transport=='udp','multiplexing':mux,'no_wait':no_wait,'traffic':traffic,**auth}}]
   own['inbounds']=[{'tag':'tcp','type':'tcp-forward','listen':address('127.0.0.1',tcp_port),'target':{'host':target_host,'port':tp},'outbound':'proxy'},{'tag':'udp','type':'udp-forward','listen':address('127.0.0.1',udp_port),'target':{'host':target_host,'port':up},'outbound':'proxy'}]
   reference['listeners']=[{'type':'mieru','name':'node','listen':host,'port':str(np),'transport':transport.upper(),'users':{USERNAME:PASSWORD},'traffic-pattern':pattern,'user-hint-is-mandatory':True}]
  else:
   own['outbounds']=[{'tag':'direct','type':'direct'}]
   own['nodes' if transport=='tcp' else 'local_inbounds']=[{'tag':'node','type':'mieru','listen':address(host,np),'outbound':'direct','options':{'transport':transport,'unsafe_udp_compatibility':transport=='udp','traffic':traffic,**auth}}]
   reference['proxies']=[{'name':'relay','type':'mieru','server':host,'port':np,'transport':transport.upper(),'udp':True,'multiplexing':'MULTIPLEXING_HIGH' if mux else 'MULTIPLEXING_OFF','handshake-mode':'HANDSHAKE_NO_WAIT' if no_wait else 'HANDSHAKE_STANDARD','traffic-pattern':pattern,**auth}]
   reference['listeners']=[{'name':'tcp','type':'tunnel','listen':'127.0.0.1','port':str(tcp_port),'network':['tcp'],'target':address(target_host,tp),'proxy':'relay'},{'name':'udp','type':'tunnel','listen':'127.0.0.1','port':str(udp_port),'network':['udp'],'target':address(target_host,up),'proxy':'relay'}]
  h.write_json(work/'own.json',own);h.write_json(work/'peer.json',reference)
  own_args=[args.kerlico,'run','-c',str(work/'own.json')];ref_args=[args.reference,'-d',str(work),'-f',str(work/'peer.json')]
  first=stack.enter_context(h.process(ref_args if role=='client' else own_args,work,'first'));wait_listener(first,np,transport)
  second=stack.enter_context(h.process(own_args if role=='client' else ref_args,work,'second'));wait_listener(second,tcp_port,'tcp')
  (work/'stage.json').write_text('TCP');data=bytes(range(251))*1024
  if tcp(tcp_port,data)!=data:raise RuntimeError(label+'：TCP 回写不符')
  checks.append(label+'：TCP')
  (work/'stage.json').write_text('UDP')
  for size in [17,1200,12000]:
   data=bytes([size%251])*size
   if packet(udp_port,data)!=data:raise RuntimeError(label+'：UDP 回写不符：'+str(size))
  checks.append(label+'：UDP')
  if mode==0 and mux and not no_wait and host=='127.0.0.1' and target_host=='127.0.0.1':
   for size in args.boundary_sizes:
    data=bytes([size%251])*size
    received=None
    try:
     reply=packet(udp_port,data,timeout=2);received=len(reply);ok=reply==data;error=None if ok else '回写长度或内容不符'
    except Exception as failure:ok=False;error=type(failure).__name__
    boundaries.append({'case':label,'size':size,'received':received,'ok':ok,'error':error})
    if packet(udp_port,b'after-boundary')!=b'after-boundary':raise RuntimeError(label+'：边界探测后小包不能恢复')
  if args.lifecycle:
   process=second if role=='client' else first;process.send_signal(signal.SIGTERM)
   if process.wait(timeout=4)!=0:raise RuntimeError(label+'：退出状态异常')
   restarted=stack.enter_context(h.process(own_args,work,'restarted'));wait_listener(restarted,tcp_port if role=='client' else np,'tcp' if role=='client' else transport)
   restarted.send_signal(signal.SIGTERM)
   if restarted.wait(timeout=4)!=0:raise RuntimeError(label+'：重绑后的退出状态异常')
   checks.append(label+'：有界退出与同端口重绑')
  h.write_json(work/'progress.json',{'checks':checks,'boundaries':boundaries});return checks,boundaries

def main():
 p=argparse.ArgumentParser();p.add_argument('--kerlico',required=True);p.add_argument('--reference',required=True);p.add_argument('--reference-kind',choices=['api','mihomo'],required=True);p.add_argument('--pattern-encoder',required=True);p.add_argument('--work-dir',required=True);p.add_argument('--full',action='store_true');p.add_argument('--entropy',action='store_true');p.add_argument('--ipv6-targets',action='store_true');p.add_argument('--lifecycle',action='store_true');p.add_argument('--boundary-sizes',nargs='+',type=int,default=[0,65507]);a=p.parse_args()
 if any(size<0 or size>65507 for size in a.boundary_sizes):raise RuntimeError('边界包长不合法')
 os.umask(0o077);root=Path(a.work_dir).resolve();root.mkdir(mode=0o700,parents=True,exist_ok=True);cases=[]
 for transport in ['tcp','udp']:
  for host in (['127.0.0.1','::1'] if a.full else ['127.0.0.1']):
   for mux in ([False,True] if a.full else [True]):
    for lazy in ([False,True] if a.full else [False]):
     for role in ['client','server']:cases.append((transport,host,'127.0.0.1',mux,lazy,0,0,role))
 if a.entropy:
  for transport in ['tcp','udp']:
   for mode in range(1,5):
    for rotation in [0,7,48]:
     for role in ['client','server']:cases.append((transport,'127.0.0.1','127.0.0.1',True,False,mode,rotation,role))
 if a.ipv6_targets:
  for transport in ['tcp','udp']:
   for host in ['127.0.0.1','::1']:
    for role in ['client','server']:cases.append((transport,host,'::1',True,False,0,0,role))
 checks=[];boundaries=[];failures=[]
 for case in cases:
  try:
   c,b=verify(a,root,*case);checks.extend(c);boundaries.extend(b)
   if a.reference_kind=='api' and any(not item['ok'] for item in b):failures.append({'case':case,'error':'官方 API 参照的声明包长边界未通过','boundary_failures':[item for item in b if not item['ok']]})
  except Exception as error:failures.append({'case':case,'error':str(error) if isinstance(error,RuntimeError) else type(error).__name__})
 result={'ok':not failures,'configurations':len(cases),'checks':checks,'boundary_probes':boundaries,'failures':failures,'reference_kind':a.reference_kind,'binary_sha256':hashlib.sha256(Path(a.kerlico).read_bytes()).hexdigest(),'reference_sha256':hashlib.sha256(Path(a.reference).read_bytes()).hexdigest(),'pattern_encoder_sha256':hashlib.sha256(Path(a.pattern_encoder).read_bytes()).hexdigest()}
 h.write_json(root/'result.json',result);print(json.dumps(result,ensure_ascii=False),flush=True)
 if failures:raise SystemExit(1)
if __name__=='__main__':main()
