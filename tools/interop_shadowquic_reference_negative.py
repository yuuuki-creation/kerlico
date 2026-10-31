#!/usr/bin/env python3
"""受控 Go 参照的 v2 缺失/伪造版本信息，双角色独立负回归。"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import subprocess
import interop_shadowquic as h

def main():
 p=argparse.ArgumentParser();p.add_argument('--kerlico',required=True);p.add_argument('--cover',required=True);p.add_argument('--reference-root',required=True);p.add_argument('--work-dir',required=True);a=p.parse_args()
 os.umask(0o077);root=Path(a.work_dir).resolve();root.mkdir(mode=0o700);bins=Path(a.reference_root).resolve();checks=[];failures=[]
 for host in ['127.0.0.1','::1']:
  for role in ['client','server']:
   for fault in ['omit','wrong']:
    label=f'node{6 if ":" in host else 4}-{role}-{fault}';work=root/label;work.mkdir(mode=0o700)
    try:
     with ExitStack() as stack:
      np,cp=h.h.free_port(),h.h.free_port();node=('[::1]:' if ':' in host else '127.0.0.1:')+str(np)
      cover_host='127.0.0.1' if ':' in host else '::1';cover=('[::1]:' if ':' in cover_host else '127.0.0.1:')+str(cp);cert=work/'cover.pem'
      c=stack.enter_context(h.h.process([a.cover,cover,str(cert),'v2'],work,'cover'));h.wait_udp(c,cp,cover_host)
      peer={'proxies':[{'server':host,'port':np,'sni':'cover.invalid','username':h.USERNAME,'password':h.PASSWORD,'quic-versions':['v2']}]}
      h.h.write_json(work/'client.json',peer)
      server={'listeners':[{'type':'shadowquic','listen':host,'port':str(np),'users':[{'username':h.USERNAME,'password':h.PASSWORD}],'jls-upstream':{'addr':cover,'sni':'cover.invalid'},'quic-versions':['v2']}]}
      h.h.write_json(work/'server.json',server)
      own={'version':1,'inbounds':[],'limits':{'connect_timeout_ms':4000,'idle_timeout_ms':10000,'drain_timeout_ms':500},'outbounds':[{'tag':'direct','type':'direct'}],'nodes':[{'tag':'node','type':'shadowquic','listen':node,'outbound':'direct','options':{'username':h.USERNAME,'password':h.PASSWORD,'server_name':'cover.invalid','upstream':{'host':cover_host,'port':cp},'quic_versions':['v2']}}]}
      h.h.write_json(work/'own.json',own)
      faulty=str(bins/('shadowquic-reference-'+fault));normal=str(bins/'shadowquic-reference')
      command=[a.cover,'probe-jls',node,str(cert),'v2']
      if role=='client':
       child=stack.enter_context(h.h.process([a.kerlico,'run','-c',str(work/'own.json')],work,'rust-node'));h.wait_udp(child,np,host)
       command=[faulty,'-probe','-f',str(work/'client.json')]
       result=subprocess.run(command,capture_output=True,timeout=8)
       control=subprocess.run([normal,'-probe','-f',str(work/'client.json')],capture_output=True,timeout=8)
      else:
       with h.h.process([faulty,'-f',str(work/'server.json')],work,'fault-node') as child:
        h.wait_udp(child,np,host);result=subprocess.run(command,capture_output=True,timeout=8)
       with h.h.process([normal,'-f',str(work/'server.json')],work,'control-node') as child:
        h.wait_udp(child,np,host);control=subprocess.run(command,capture_output=True,timeout=8)
      diagnostic=(result.stdout+result.stderr).decode(errors='replace');(work/'negative.log').write_text(diagnostic);(work/'control.log').write_bytes(control.stdout+control.stderr)
      if result.returncode==0 or not any(code in diagnostic for code in ['VERSION_NEGOTIATION_ERROR','0x11']):raise RuntimeError('未以版本协商错误拒绝负参数')
      if control.returncode!=0:raise RuntimeError('合法参照控制组握手失败')
      checks.append({'case':label,'rejected_with':'0x11','valid_control':True})
    except Exception as error:failures.append({'case':label,'error':str(error) if isinstance(error,RuntimeError) else type(error).__name__})
 result={'ok':not failures,'checks':checks,'failures':failures,'binaries':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in bins.iterdir() if path.is_file()}}
 h.h.write_json(root/'result.json',result);print(json.dumps(result,ensure_ascii=False),flush=True)
 if failures:raise SystemExit(1)
if __name__=='__main__':main()
