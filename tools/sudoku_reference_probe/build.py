#!/usr/bin/env python3
"""仅在专用worker构建固定上游研究探针，保留来源、依赖及原始结果。"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--go-root")
    args = parser.parse_args()
    if os.uname().sysname != "Linux" or not Path("/proc").exists():
        raise RuntimeError("研究探针只允许在专用Linux worker运行")
    os.umask(0o077)
    source = Path(__file__).resolve().parent
    common_path = source.parent / "shadowquic_reference_peer" / "build.py"
    spec = importlib.util.spec_from_file_location("fixed_reference_download", common_path)
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    work = Path(args.work_dir).resolve()
    work.mkdir(mode=0o700)
    original = common.download(common.SOURCES["mihomo"])
    (work / "mihomo-original.tar.gz").write_bytes(original)
    common.extract(original, work / "mihomo", 1)
    goroot = Path(args.go_root).resolve() if args.go_root else work / "go"
    if not args.go_root:
        common.extract(common.download(common.SOURCES["go"]), work, 0)
    peer = work / "peer"
    peer.mkdir()
    for name in ["go.mod", "main.go"]:
        shutil.copyfile(source / name, peer / name)
    if (source / "go.sum").exists():
        shutil.copyfile(source / "go.sum", peer / "go.sum")
    temporary = work / "tmp"
    temporary.mkdir()
    env = os.environ.copy()
    env.update({"GOROOT": str(goroot), "GOTOOLCHAIN": "local", "GOMAXPROCS": "1", "GOMEMLIMIT": "768MiB", "GOCACHE": str(work / "cache"), "GOMODCACHE": str(work / "mod-cache"), "GOPATH": str(work / "gopath"), "CGO_ENABLED": "0", "GOTMPDIR": str(temporary), "TMPDIR": str(temporary)})
    binary = work / "sudoku-reference-probe"
    with (work / "build.log").open("wb") as log:
        mode = "-mod=readonly" if (source / "go.sum").exists() else "-mod=mod"
        subprocess.run([str(goroot / "bin" / "go"), "build", "-p=1", mode, "-trimpath", "-buildvcs=false", "-o", str(binary), "."], cwd=peer, env=env, stdout=log, stderr=log, check=True)
    with (work / "result.json").open("wb") as output:
        subprocess.run([str(binary)], cwd=peer, env=env, stdout=output, stderr=subprocess.PIPE, timeout=120, check=True)
    result = json.loads((work / "result.json").read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    provenance = {"source": common.SOURCES["mihomo"], "go": common.SOURCES["go"], "binary_sha256": digest(binary), "result_sha256": digest(work / "result.json"), "go_mod_sha256": digest(peer / "go.mod"), "go_sum_sha256": digest(peer / "go.sum"), "probe_source_sha256": digest(peer / "main.go"), "identity_records": len(result["identity_semantics"]), "vector_records": len(result["vectors"])}
    (work / "provenance.json").write_text(json.dumps(provenance, indent=2))
    print(json.dumps(provenance))


if __name__ == "__main__":
    main()
