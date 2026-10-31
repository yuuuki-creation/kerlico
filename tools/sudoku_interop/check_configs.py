#!/usr/bin/env python3
"""用真实CLI校验注册、凭据和能力门槛；不启动监听。"""
import argparse
import copy
import json
from pathlib import Path
import subprocess
from run import KEY, METHODS, kernel_client, kernel_node, matrix, sha


def main():
    from worker import require_worker
    require_worker()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kerlico",required=True)
    parser.add_argument("--work",type=Path,required=True)
    args=parser.parse_args()
    if args.work.exists():
        raise SystemExit("必须使用新标签，保留旧日志")
    args.work.mkdir(parents=True,mode=0o700)
    binary=str(Path(args.kerlico).resolve())
    cases=[]
    base=matrix("carriers")[0]
    for aead in METHODS:
        case=dict(base,aead=aead)
        value=kernel_node(case,"127.0.0.1",10443,{})
        cases.append(("valid-"+aead,value,True))
    authenticated=kernel_node(base,"127.0.0.1",10443,{})
    duplicate=copy.deepcopy(authenticated)
    second=copy.deepcopy(duplicate["nodes"][0]);second["tag"]="node6";second["listen"]="[::1]:10443"
    duplicate["nodes"].append(second)
    cases.append(("duplicate-seed",duplicate,False))
    independent=copy.deepcopy(duplicate)
    independent["nodes"][1]["options"]["protocol"]["key"]="synthetic-sudoku-cli-node-b-secret"
    cases.append(("independent-dual-stack",independent,True))
    unsafe=kernel_node(dict(base,aead="none"),"127.0.0.1",10443,{})
    unsafe["nodes"]=unsafe.pop("local_inbounds")
    cases.append(("none-cannot-be-node",unsafe,False))
    wide=kernel_node(dict(base,aead="none"),"0.0.0.0",10443,{})
    cases.append(("none-cannot-listen-wide",wide,False))
    for name,patch in [("unknown-protocol-field",{"typo":True}),
                       ("aead-with-insecure-flag",{"allow_insecure":True}),
                       ("invalid-padding",{"padding_min":50,"padding_max":10}),
                       ("ascii-with-custom-layout",{"table_type":"prefer_ascii","custom_tables":["xpxvvpvv"]}),
                       ("invalid-custom-layout",{"custom_tables":["xxxxxxxx"]})]:
        value=copy.deepcopy(authenticated);value["nodes"][0]["options"]["protocol"].update(patch);cases.append((name,value,False))
    # WS普通流不承诺写端EOF；mux on另有真正逻辑FIN，不能用伪开关通过。
    class Target:
        host="127.0.0.1"
        port=443
    for mux,allowed in [("off",False),("on",True)]:
        value,_=kernel_client(dict(base,mode="ws",mux=mux),"127.0.0.1",10443,[Target()],[],{})
        value["inbounds"][0]["require_remote_eof"]=True
        cases.append(("ws-eof-"+mux,value,allowed))
    records=[]
    for index,(name,value,allowed) in enumerate(cases):
        path=args.work/f"{index:02d}-{name}.json";path.write_text(json.dumps(value,indent=2)+"\n")
        with (args.work/f"{index:02d}-{name}.log").open("wb") as log:
            result=subprocess.run([binary,"check","-c",str(path.resolve())],stdout=log,stderr=subprocess.STDOUT)
        records.append({"name":name,"expected_accept":allowed,"returncode":result.returncode,"pass":(result.returncode==0)==allowed})
        (args.work/"results.json").write_text(json.dumps({"kerlico_sha256":sha(binary),"records":records},indent=2)+"\n")
    print(json.dumps({"checks":len(records),"passed":sum(r["pass"] for r in records)}))
    if not all(r["pass"] for r in records):
        raise SystemExit(1)


if __name__=="__main__":
    main()
