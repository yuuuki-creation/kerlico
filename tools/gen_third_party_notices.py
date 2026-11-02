#!/usr/bin/env python3
"""从 cargo metadata 生成发行二进制实际链接依赖的许可通知，写到标准输出。

在 worker 的源码根目录运行。结果随二进制上传，不提交：上游署名不进入本仓库历史。

包内没有许可文本时，MIT、BSD-2-Clause、BSD-3-Clause、ISC 用标准模板填入作者；
其他许可复用依赖图内另一包未修改的原文。`OR` 表达式满足一个选项即可。
仍有包缺文本时退出码非零。
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT_PACKAGE = "kerlico"
LICENSE_NAME = re.compile(r"licen[cs]e|^copying", re.IGNORECASE)
LICENSE_DIRECTORY = re.compile(r"^licen[cs]es?$", re.IGNORECASE)
NOTICE_NAME = re.compile(r"^(notice|copyright|authors)", re.IGNORECASE)
NOT_TEXT = {".rs", ".py", ".c", ".h", ".cc", ".cpp", ".toml", ".json", ".yml", ".yaml", ".sh", ".js", ".ts", ".go", ".proto"}
NOT_LINKED = {"tests", "test", "benches", "examples", "target", ".git"}
MIN_CUSTOM_TEXT = 200

MIT = """MIT License

Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

BSD_DISCLAIMER = """THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""

BSD_2 = """BSD 2-Clause License

Copyright (c) {holders}

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

""" + BSD_DISCLAIMER

BSD_3 = """BSD 3-Clause License

Copyright (c) {holders}

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

""" + BSD_DISCLAIMER

ISC = """ISC License

Copyright (c) {holders}

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE."""

TEMPLATES = {"MIT": MIT, "BSD-2-Clause": BSD_2, "BSD-3-Clause": BSD_3, "ISC": ISC}


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


def is_license_name(path):
    return LICENSE_NAME.search(path.name) and path.suffix.lower() not in NOT_TEXT


def license_files(package):
    """返回 (本包许可文本, 其他通知)。深层目录的许可属于内嵌代码，不算本包的。"""
    root = pathlib.Path(package["manifest_path"]).parent
    own = []
    notices = []
    if package.get("license_file"):
        own.append(root / package["license_file"])
    for directory, children, names in os.walk(root):
        current = pathlib.Path(directory)
        children[:] = sorted(child for child in children if child not in NOT_LINKED)
        for name in sorted(names):
            path = current / name
            if current == root and is_license_name(path):
                own.append(path)
            elif current == root and NOTICE_NAME.match(name):
                notices.append(path)
            elif current != root and LICENSE_DIRECTORY.match(path.relative_to(root).parts[0]):
                own.append(path)
            elif current != root and is_license_name(path):
                notices.append(path)
    return sorted(set(own)), notices


def read(path):
    return path.read_text(encoding="utf-8", errors="replace").strip()


def identify(text):
    """按许可正文的固定措辞识别 SPDX 标识，一个文件可含多项。"""
    plain = " ".join(text.lower().split())
    found = set()
    if "apache license" in plain and "version 2.0" in plain:
        found.add("Apache-2.0")
    if "permission is hereby granted, free of charge" in plain:
        found.add("MIT" if "shall be included in all copies" in plain else "MIT-0")
    if "redistribution and use in source and binary forms" in plain:
        found.add("BSD-3-Clause" if "neither the name" in plain else "BSD-2-Clause")
    if "distribute this software for any purpose with or without fee" in plain:
        found.add("ISC" if "above copyright notice" in plain else "0BSD")
    checks = {
        "MPL-2.0": "mozilla public license",
        "Zlib": "altered source versions must be plainly marked",
        "Unlicense": "free and unencumbered software released into the public domain",
        "Unicode-3.0": "unicode, inc.",
        "CC0-1.0": "cc0 1.0",
        "BSL-1.0": "boost software license",
        "CDLA-Permissive-2.0": "community data license agreement",
        # MPL-2.0 正文也提到 LGPL，要匹配 LGPL 自身的标题行。
        "LGPL-3.0-or-later": "gnu lesser general public license version 3, 29 june 2007",
    }
    found.update(spdx for spdx, phrase in checks.items() if phrase in plain)
    return found


def parse_expression(text):
    """把 SPDX 表达式解析成嵌套的 ("or"|"and", 子项) 元组；旧写法 `/` 等同 `OR`，`WITH` 例外归入主许可。"""
    tokens = re.findall(r"[()/]|[^\s()/]+", text)
    position = 0

    def peek():
        return tokens[position] if position < len(tokens) else None

    def atom():
        nonlocal position
        token = peek()
        position += 1
        if token == "(":
            inner = either()
            position += 1
            return inner
        if peek() == "WITH":
            position += 2
        return token

    def both():
        nonlocal position
        parts = [atom()]
        while peek() == "AND":
            position += 1
            parts.append(atom())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def either():
        nonlocal position
        parts = [both()]
        while peek() in ("OR", "/"):
            position += 1
            parts.append(both())
        return parts[0] if len(parts) == 1 else ("or", parts)

    return either()


def needed_texts(expression, present, available):
    """返回还要补的标准文本列表；缺了又补不上时返回 None。"""
    if isinstance(expression, str):
        if expression in present:
            return []
        return [expression] if expression in available else None
    kind, parts = expression
    plans = [needed_texts(part, present, available) for part in parts]
    if kind == "or":
        return min((plan for plan in plans if plan is not None), key=len, default=None)
    if any(plan is None for plan in plans):
        return None
    return sorted({spdx for plan in plans for spdx in plan})


def reusable_texts(packages):
    """依赖图内只含一种许可的原文，按许可索引。Apache 优先取附录占位符未填的版本，避免带上别家署名。"""
    candidates = {}
    for package in packages:
        for path in license_files(package)[0]:
            text = read(path)
            found = identify(text)
            if len(found) == 1:
                candidates.setdefault(found.pop(), []).append(text)
    return {spdx: min(texts, key=lambda text: ("[yyyy]" not in text, text)) for spdx, texts in candidates.items()}


def holders(package):
    return ", ".join(package["authors"]) or f"The {package['name']} authors"


def main(packages=None):
    if packages is None:
        packages = linked_packages()
    packages = sorted(packages, key=lambda package: (package["name"], package["version"]))
    third_party = [package for package in packages if not package["name"].startswith("kerlico")]
    reusable = reusable_texts(third_party)
    available = set(TEMPLATES) | set(reusable)
    texts = {}
    without_text = []

    def add(text, owner):
        key = hashlib.sha256(text.encode()).hexdigest()
        texts.setdefault(key, (text, []))[1].append(owner)

    print(f"kerlico 第三方许可通知 / Third-party notices ({len(third_party)} packages)\n")
    for package in third_party:
        label = f"{package['name']} {package['version']}"
        print(f"{label}: {package.get('license') or package.get('license_file') or 'UNKNOWN'}")
        root = pathlib.Path(package["manifest_path"]).parent
        own, notices = license_files(package)
        own = [path for path in own if path.is_file()]
        for path in own + notices:
            add(read(path), f"{label} ({path.relative_to(root)})")
        contents = [read(path) for path in own]
        if package.get("license"):
            # 识别不出的长文件视为该包的定制文本，不替它补；短文件只是一句指引。
            custom = any(len(text) >= MIN_CUSTOM_TEXT and not identify(text) for text in contents)
            needed = [] if custom else needed_texts(
                parse_expression(package["license"]), set().union(*map(identify, contents)), available)
        else:
            needed = [] if own else None
        if needed is None:
            without_text.append(label)
            continue
        for spdx in needed:
            origin = package.get("repository") or "UNKNOWN"
            print(f"  authors: {holders(package)}; repository: {origin}")
            text = TEMPLATES[spdx].replace("{holders}", holders(package)) if spdx in TEMPLATES else reusable[spdx]
            add(text, f"{label} ({spdx} standard text; authors: {holders(package)}; repository: {origin})")
    for text, owners in texts.values():
        print("\n" + "=" * 72)
        print("\n".join(owners))
        print("-" * 72)
        print(text)
    if without_text:
        print("无许可文本：" + ", ".join(without_text), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
