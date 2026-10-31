#!/usr/bin/env python3
"""仅在专用 Linux worker 项目区构建受控 Go 测试对端。"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
SOURCES={
 "jls-quic-go":{"commit":"732f2fc9a34de12a58020a0ca75bf336095aed93","url":"https://codeload.github.com/metacubex/jls-quic-go/tar.gz/732f2fc9a34de12a58020a0ca75bf336095aed93","sha256":"e25f4a453645447beb43ce66c53122e02ddd9aa2b16d28dcfe105576218c7462"},
 "mihomo":{"commit":"3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8","url":"https://codeload.github.com/MetaCubeX/mihomo/tar.gz/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8","sha256":"ecda5f8c8a8a1d60bc088c2640c85d92c8f002c0686234a26bdf671735afe216"},
 "go":{"version":"go1.26.10","url":"https://go.dev/dl/go1.26.10.linux-amd64.tar.gz","sha256":"ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5"},
}
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def extract(data,target,strip):
 with tarfile.open(fileobj=io.BytesIO(data),mode="r:gz") as tar:
  for entry in tar.getmembers():
   parts=Path(entry.name).parts[strip:]
   if not parts:continue
   if ".." in parts or entry.name.startswith("/"):raise RuntimeError("来源包路径不合法")
   path=target.joinpath(*parts)
   if entry.isdir():path.mkdir(parents=True,exist_ok=True)
   elif entry.isfile():
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(tar.extractfile(entry).read());path.chmod(entry.mode&0o777)
   else:raise RuntimeError("来源包含非普通文件")
def download(spec):
 data=urllib.request.urlopen(spec["url"],timeout=60).read()
 if hashlib.sha256(data).hexdigest()!=spec["sha256"]:raise RuntimeError("官方固定来源摘要不符")
 return data
def main():
 p=argparse.ArgumentParser();p.add_argument("--work-dir",required=True);p.add_argument("--go-root");p.add_argument("--cache-dir");p.add_argument("--module-cache-dir");a=p.parse_args()
 if os.uname().sysname!="Linux" or not Path("/proc").exists():raise RuntimeError("仅允许专用 Linux worker")
 os.umask(0o077);work=Path(a.work_dir).resolve();work.mkdir(mode=0o700)
 source=Path(__file__).resolve().parent
 originals=work/"originals";originals.mkdir()
 for name in ["jls-quic-go","mihomo"]:
  data=download(SOURCES[name]);(originals/(name+".tar.gz")).write_bytes(data);extract(data,work/name,1)
 goroot=Path(a.go_root).resolve() if a.go_root else work/"go"
 if not a.go_root:extract(download(SOURCES["go"]),work,0)
 peer=work/"peer";peer.mkdir();bins=work/"bin";bins.mkdir()
 for name in ["main.go","main_test.go","go.mod","go.sum"]:
  if (source/name).exists():shutil.copyfile(source/name,peer/name)
 for name in ["version-information.patch","key-update-label.patch","fault-injection.patch"]:shutil.copyfile(source/name,work/name)
 changed=["connection.go","internal/wire/transport_parameters.go","internal/handshake/updatable_aead.go"]
 before={name:digest(work/"jls-quic-go"/name) for name in changed}
 subprocess.run(["patch","-p1","-i",str(work/"version-information.patch")],cwd=work/"jls-quic-go",check=True)
 temporary=work/"tmp";temporary.mkdir()
 env=os.environ.copy();env.update({"GOROOT":str(goroot),"GOTOOLCHAIN":"local","GOMAXPROCS":"1","GOMEMLIMIT":"768MiB","GOCACHE":str(Path(a.cache_dir).resolve() if a.cache_dir else work/"cache"),"GOMODCACHE":str(Path(a.module_cache_dir).resolve() if a.module_cache_dir else work/"mod-cache"),"GOPATH":str(work/"gopath"),"CGO_ENABLED":"0","GOTMPDIR":str(temporary),"TMPDIR":str(temporary)})
 go=str(goroot/"bin/go")
 def run(args,cwd=peer):subprocess.run(args,cwd=cwd,env=env,check=True)
 shutil.copyfile(source/"fixtures/key_update_vector_test.go",work/"jls-quic-go/internal/handshake/controlled_key_update_test.go")
 vector_args=[go,"test","-p=1","-mod=mod","-run","^TestControlledKeyUpdateVectors$","./internal/handshake"]
 gap=subprocess.run(vector_args,cwd=work/"jls-quic-go",env=env,capture_output=True)
 (work/"parameter-only-key-update.log").write_bytes(gap.stdout+gap.stderr)
 if gap.returncode==0 or "固定密钥更新向量不符" not in (gap.stdout+gap.stderr).decode(errors="replace"):raise RuntimeError("未复现固定上游 v2 密钥更新缺口")
 subprocess.run(["patch","-p1","-i",str(work/"key-update-label.patch")],cwd=work/"jls-quic-go",check=True)
 run(vector_args,work/"jls-quic-go")
 run([str(goroot/"bin/gofmt"),"-w",str(peer/"main.go"),str(peer/"main_test.go"),str(work/"jls-quic-go/internal/handshake/controlled_key_update_test.go")]+[str(work/"jls-quic-go"/name) for name in changed])
 after={name:digest(work/"jls-quic-go"/name) for name in changed}
 run([go,"test","-p=1","-mod=mod","-run","^TestControlledVersionInformation$","."])
 run([go,"build","-p=1","-mod=mod","-trimpath","-buildvcs=false","-o",str(bins/"shadowquic-reference"),"."])
 # 源补丁在格式化之前的上下文生成，因此先恢复其原文本再应用独立故障补丁。
 # 用保存的兼容版本源码建立故障副本，避免修改已冻结二进制的来源记录。
 fault=work/"fault-source";shutil.copytree(work/"jls-quic-go",fault)
 raw=work/"raw-wire";raw.mkdir();extract((originals/"jls-quic-go.tar.gz").read_bytes(),raw,1)
 shutil.copyfile(raw/"internal/wire/transport_parameters.go",fault/"internal/wire/transport_parameters.go")
 # 兼容补丁的 connection 部分已在副本中；只重建 wire 文本供独立故障补丁使用。
 patch=(work/"version-information.patch").read_text();wire_patch=patch[patch.index("--- a/internal/wire/transport_parameters.go"):patch.index("--- a/connection.go")]
 (work/"wire-only.patch").write_text(wire_patch)
 run(["patch","-p1","-i",str(work/"wire-only.patch")],fault)
 run(["patch","-p1","-i",str(work/"fault-injection.patch")],fault)
 mod=(peer/"go.mod").read_text();(peer/"go.mod").write_text(mod.replace("=> ../jls-quic-go","=> ../fault-source"))
 for mode in ["omit","wrong"]:run([go,"build","-p=1","-mod=mod","-trimpath","-buildvcs=false","-ldflags=-X github.com/metacubex/jls-quic-go/internal/wire.VersionInformationFault="+mode,"-o",str(bins/("shadowquic-reference-"+mode)),"."])
 (peer/"go.mod").write_text(mod)
 result={"sources":SOURCES,"before":before,"controlled_source":after,"patches":{name:digest(work/name) for name in ["version-information.patch","key-update-label.patch","fault-injection.patch"]},"binaries":{path.name:digest(path) for path in bins.iterdir()},"peer_sources":{name:digest(peer/name) for name in ["main.go","main_test.go","go.mod","go.sum"]},"go_mod_sha256":digest(peer/"go.mod"),"go_sum_sha256":digest(peer/"go.sum")}
 (work/"provenance.json").write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
if __name__=="__main__":main()
