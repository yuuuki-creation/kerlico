#!/usr/bin/env python3
"""仅在worker生成固定参考的纯向量；不会执行网络互通。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
SOURCE = json.loads((HERE / "SOURCE.json").read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest(root):
    return {p.relative_to(root).as_posix(): digest(p) for p in sorted(root.rglob("*"))
            if p.is_file() and ".git" not in p.relative_to(root).parts}


def main():
    from worker import require_worker
    require_worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--go", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    original = args.source.resolve()
    for name, expected in SOURCE["mihomo"]["files"].items():
        if digest(original / name) != expected:
            raise SystemExit("固定Mihomo源码摘要不符: " + name)
    if args.work.exists() or args.output.exists():
        raise SystemExit("工作目录和输出必须为新标签；保留旧证据")
    args.work.mkdir(parents=True, mode=0o700)
    copied = args.work / "source"
    shutil.copytree(original, copied, ignore=shutil.ignore_patterns(".git", "target", "*.log"))
    before = manifest(copied)
    destination = args.work / "vectors"
    destination.mkdir(mode=0o700)
    temporary = args.work / "tmp"
    temporary.mkdir(mode=0o700)
    bridges = {"keys_test.go": "transport/sudoku/kerlico_vectors_test.go",
               "record_test.go": "transport/sudoku/crypto/kerlico_vectors_test.go"}
    for source, target in bridges.items():
        shutil.copyfile(HERE / "vectors" / source, copied / target)
    after = manifest(copied)
    changed = sorted(name for name in before if before[name] != after.get(name))
    added = sorted(set(after) - set(before))
    if changed or added != sorted(bridges.values()):
        raise SystemExit("临时副本除了导出桥接出现其他变化")
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOMAXPROCS": "1", "GOMEMLIMIT": "768MiB",
                "GOPROXY": "off", "GOSUMDB": "off", "KERLICO_VECTOR_OUT": str(destination.resolve()),
                "GOTMPDIR": str(temporary.resolve()), "TMPDIR": str(temporary.resolve()),
                "GOPATH": str((args.work / "gopath").resolve())})
    tests = [("./transport/sudoku", "TestKerlicoExportControlVectors"),
             ("./transport/sudoku/crypto", "TestKerlicoExportRecordVectors")]
    executed = []
    for package, name in tests:
        command = [args.go, "test", "-mod=readonly", "-p=1", "-count=1", "-run", "^" + name + "$", "-v", package]
        with (args.work / (name + ".log")).open("wb") as log:
            result = subprocess.run(command, cwd=copied, env=env, stdout=log, stderr=subprocess.STDOUT)
        executed.append({"package": package, "test": name, "returncode": result.returncode})
        (args.work / "executed.json").write_text(json.dumps(executed, indent=2) + "\n")
        if result.returncode:
            raise SystemExit("Go纯向量导出失败；保留原日志，不生成成功fixture")
    final = manifest(copied)
    if final != after:
        raise SystemExit("向量执行后临时源码发生变化；不生成成功fixture")
    value = {"schema": 1, "fixed_commit": SOURCE["mihomo"]["commit"], "network_connections": 0,
             "control": json.loads((destination / "control.json").read_text()),
             "records": json.loads((destination / "records.json").read_text())}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    record = {"source_files": before, "added_export_bridges": {name: after[name] for name in added},
              "changed_production_files": changed, "executed": executed, "output_sha256": digest(args.output)}
    (args.work / "source-and-result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"tests": executed, "output_sha256": record["output_sha256"]}))


if __name__ == "__main__":
    main()
