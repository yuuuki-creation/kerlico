#!/usr/bin/env python3
"""从 cargo metadata 生成发行二进制实际链接依赖的许可通知，写到标准输出。

在 worker 的源码根目录运行。结果随二进制上传，不提交：上游署名不进入本仓库历史。
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

LICENSE_FILE = re.compile(r"^(license|licence|copying|notice|copyright|authors)", re.IGNORECASE)
ROOT_PACKAGE = "kerlico"


def linked_packages():
    meta = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked",
         "--filter-platform", "x86_64-unknown-linux-gnu"]))
    packages = {package["id"]: package for package in meta["packages"]}
    nodes = {node["id"]: node for node in meta["resolve"]["nodes"]}
    root = next(package["id"] for package in meta["packages"] if package["name"] == ROOT_PACKAGE)
    seen = set()
    stack = [root]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for dep in nodes[current]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    return [packages[package_id] for package_id in seen]


def license_files(package):
    root = pathlib.Path(package["manifest_path"]).parent
    return sorted(path for path in root.iterdir() if path.is_file() and LICENSE_FILE.match(path.name))


def main():
    packages = sorted(linked_packages(), key=lambda package: (package["name"], package["version"]))
    third_party = [package for package in packages if not package["name"].startswith("kerlico")]
    texts = {}
    without_license = []
    print(f"kerlico 第三方许可通知 / Third-party notices ({len(third_party)} packages)\n")
    for package in third_party:
        print(f"{package['name']} {package['version']}: {package.get('license') or package.get('license_file') or 'UNKNOWN'}")
        files = license_files(package)
        if not package.get("license") and not package.get("license_file") and not files:
            without_license.append(f"{package['name']} {package['version']}")
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            key = hashlib.sha256(text.encode()).hexdigest()
            texts.setdefault(key, (text, []))[1].append(f"{package['name']} {package['version']} ({path.name})")
    for text, owners in texts.values():
        print("\n" + "=" * 72)
        print("\n".join(owners))
        print("-" * 72)
        print(text)
    if without_license:
        print("无许可声明：" + ", ".join(without_license), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
