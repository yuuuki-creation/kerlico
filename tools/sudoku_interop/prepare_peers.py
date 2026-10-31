#!/usr/bin/env python3
"""在专用worker的新目录构建原生固定参考程序；不启动互通。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
SOURCE = json.loads((HERE / "SOURCE.json").read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    from worker import require_worker
    require_worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", choices=["mihomo", "official"], required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-sha256")
    parser.add_argument("--allow-module-downloads", action="store_true")
    args = parser.parse_args()
    if args.work.exists():
        raise SystemExit("必须使用新的项目标签；不能覆盖原对端")
    args.work.mkdir(parents=True, mode=0o700)
    entry = SOURCE[args.peer]
    archive = args.archive or args.work / "original.tar.gz"
    if args.archive is None:
        urllib.request.urlretrieve(entry["archive_url"], archive)
    actual = sha(archive)
    expected = entry.get("archive_sha256") or args.archive_sha256
    if not expected:
        raise SystemExit("固定参考归档缺少预期SHA256，不构建")
    if expected != actual:
        raise SystemExit("固定参考归档摘要不符")
    unpacked = args.work / "unpacked"
    unpacked.mkdir()
    with tarfile.open(archive) as bundle:
        bundle.extractall(unpacked, filter="data")
    roots = list(unpacked.iterdir())
    if len(roots) != 1:
        raise SystemExit("上游归档顶层不唯一")
    root = roots[0]
    for name, expected in entry["files"].items():
        if sha(root / name) != expected:
            raise SystemExit("固定参考文件摘要不符: " + name)
    source_manifest = {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*")) if p.is_file()}
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOMAXPROCS": "1", "GOMEMLIMIT": "768MiB"})
    if not args.allow_module_downloads:
        env.update({"GOPROXY": "off", "GOSUMDB": "off"})
    binary = args.work / ("mihomo" if args.peer == "mihomo" else "sudoku-tunnel")
    target = "." if args.peer == "mihomo" else "./cmd/sudoku-tunnel"
    command = [args.go, "build", "-p=1", "-mod=readonly", "-trimpath", "-o", str(binary.resolve()), target]
    with (args.work / "build.log").open("wb") as log:
        result = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
    after_manifest = {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*")) if p.is_file()}
    changed = sorted(name for name in set(source_manifest) | set(after_manifest) if source_manifest.get(name) != after_manifest.get(name))
    record = {"peer": args.peer, "commit": entry["commit"], "archive_url": entry["archive_url"],
              "archive_sha256": actual, "archive_expected_sha256": expected, "source_files": source_manifest,
              "production_source_changes": len(changed), "changed_source_files": changed, "source_unchanged_after_build": not changed, "returncode": result.returncode}
    if result.returncode == 0:
        record["binary_sha256"] = sha(binary)
    (args.work / "peer-source.json").write_text(json.dumps(record, indent=2) + "\n")
    if changed:
        raise SystemExit("参考构建改变生产源码，保留清单；不登记原生未修改对端")
    if result.returncode:
        raise SystemExit("参考构建失败，保留日志；未启动测试")
    print(json.dumps({"peer": args.peer, "commit": entry["commit"], "binary_sha256": record["binary_sha256"]}))


if __name__ == "__main__":
    main()
