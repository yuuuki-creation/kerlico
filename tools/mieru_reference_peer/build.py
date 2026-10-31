#!/usr/bin/env python3
"""在专用 worker 项目区构建未改运行源码的官方 Mieru API 参照和独立向量。"""
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
 'v3.38.1':{'commit':'a2208ee7a38fb41d843a13ecdde858e67ef2f485','url':'https://codeload.github.com/enfein/mieru/tar.gz/a2208ee7a38fb41d843a13ecdde858e67ef2f485','sha256':'fdc42f6abc8d5fdee35d510bc1c2309d1a767add23032ad8d6c479e9d2d22bce'},
 'v3.39.0':{'commit':'bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06','url':'https://codeload.github.com/enfein/mieru/tar.gz/bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06','sha256':'8853a026abf90b35036e3bc3ebf441d6123ee7e94ce490a64165342805416db7'},
}
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--work-dir',required=True);p.add_argument('--go-root',required=True);p.add_argument('--version',choices=list(SOURCES),default='v3.38.1');p.add_argument('--vectors-output',required=True);p.add_argument('--cache-dir');p.add_argument('--module-cache-dir');a=p.parse_args()
 if os.uname().sysname!='Linux' or not Path('/proc').exists():raise RuntimeError('仅允许专用 Linux worker')
 os.umask(0o077);work=Path(a.work_dir).resolve();work.mkdir(mode=0o700);tool=Path(__file__).resolve().parent;goroot=Path(a.go_root).resolve();spec=SOURCES[a.version]
 data=urllib.request.urlopen(spec['url'],timeout=60).read()
 if hashlib.sha256(data).hexdigest()!=spec['sha256']:raise RuntimeError('固定官方来源摘要不符')
 (work/'official-source.tar.gz').write_bytes(data);source=work/'mieru';source.mkdir()
 with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
  for entry in archive.getmembers():
   parts=Path(entry.name).parts[1:]
   if not parts:continue
   if '..' in parts or entry.name.startswith('/'):raise RuntimeError('来源包路径不合法')
   path=source.joinpath(*parts)
   if entry.isdir():path.mkdir(parents=True,exist_ok=True)
   elif entry.isfile():path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(archive.extractfile(entry).read())
   else:raise RuntimeError('来源包包含非普通文件')
 before={str(path.relative_to(source)):digest(path) for path in source.rglob('*.go') if not path.name.endswith('_test.go')}
 peer=work/'peer';peer.mkdir()
 for name in ['main.go','go.mod','go.sum']:
  if (tool/name).exists():shutil.copyfile(tool/name,peer/name)
 mod=(peer/'go.mod').read_text().replace('v3.38.1',a.version);(peer/'go.mod').write_text(mod)
 fixture=source/'pkg/protocol/kerlico_export_vectors_test.go';shutil.copyfile(tool/'fixtures/export_vectors_test.go',fixture)
 vectors=Path(a.vectors_output).resolve();vectors.parent.mkdir(parents=True,exist_ok=True)
 temporary=work/'tmp';temporary.mkdir();env=os.environ.copy();env.update({'GOROOT':str(goroot),'GOTOOLCHAIN':'local','GOMAXPROCS':'1','GOMEMLIMIT':'768MiB','GOCACHE':str(Path(a.cache_dir).resolve() if a.cache_dir else work/'cache'),'GOMODCACHE':str(Path(a.module_cache_dir).resolve() if a.module_cache_dir else work/'module-cache'),'GOPATH':str(work/'gopath'),'CGO_ENABLED':'0','GOTELEMETRY':'off','GOTMPDIR':str(temporary),'TMPDIR':str(temporary),'KERLICO_MIERU_VECTOR_OUTPUT':str(vectors),'KERLICO_MIERU_SOURCE_VERSION':a.version})
 go=str(goroot/'bin/go')
 def run(args,cwd):subprocess.run(args,cwd=cwd,env=env,check=True)
 run([str(goroot/'bin/gofmt'),'-w',str(peer/'main.go'),str(fixture)],peer)
 run([go,'test','-p=1','-mod=mod','-run','^TestKerlicoMieruExportVectors$','./pkg/protocol'],source)
 run([go,'build','-p=1','-mod=mod','-trimpath','-buildvcs=false','-o',str(work/'mieru-reference'),'.'],peer)
 after={str(path.relative_to(source)):digest(path) for path in source.rglob('*.go') if not path.name.endswith('_test.go')}
 if before!=after:raise RuntimeError('官方 Go 运行源码发生非预期修改')
 result={'version':a.version,'source':spec,'runtime_source_unmodified':True,'binary_sha256':digest(work/'mieru-reference'),'vectors_sha256':digest(vectors),'peer_sources':{name:digest(peer/name) for name in ['main.go','go.mod','go.sum']},'fixture_sha256':digest(fixture)}
 (work/'provenance.json').write_text(json.dumps(result,indent=2));print(json.dumps(result),flush=True)
if __name__=='__main__':main()
