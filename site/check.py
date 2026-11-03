#!/usr/bin/env python3
"""校验 site/：语言键齐全、协议清单与 apps/kerlico 注册一致、无外部资源、体积、配色对比度。先运行 build.py。"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DIST = ROOT / "dist"
MAIN_RS = ROOT.parent / "apps" / "kerlico" / "src" / "main.rs"
MAX_ASSET_BYTES = 400 * 1024

RESOURCE_ATTR = re.compile(r"<(script|img|iframe|audio|video|source|embed|object|track)\b[^>]*?\s(?:src|data)\s*=\s*[\"']([^\"']+)", re.I)
LINK_TAG = re.compile(r"<link\b[^>]*>", re.I)
HREF = re.compile(r"\bhref\s*=\s*[\"']([^\"']+)", re.I)
CSS_URL = re.compile(r"url\(\s*[\"']?([^\"')]+)", re.I)
CSS_IMPORT = re.compile(r"@import\s+[\"']?([^\"';\s]+)", re.I)
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.I)
# 官网写给没有背景的读者：不出现函数名、字段名和内部模块名。
JARGON = re.compile(r"`|Dispatcher|EgressRuntime|NodeId|UserId|Engine|Registry|TargetPolicy|native_credential|crate|inbound/|outbound/")
FAILURES = []


def fail(message):
    FAILURES.append(message)


def is_external(url):
    return bool(EXTERNAL.match(url)) and not url.lower().startswith("data:")


def luminance(hex_color):
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a, b):
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def registered_directions():
    """按 feature 汇总 registry() 里的 register / register_node，得到代码里的真实方向。"""
    source = MAIN_RS.read_text(encoding="utf-8")
    body = source[source.index("fn registry()") : source.index("#[tokio::main]")]
    found = {}
    blocks = re.split(r'#\[cfg\(feature = "protocol-([a-z0-9-]+)"\)\]', body)
    for name, block in zip(blocks[1::2], blocks[2::2]):
        entry = found.setdefault(name, set())
        if ".register(" in block:
            entry.add("out")
        if ".register_node(" in block:
            entry.add("in")
    return {name: ("both" if len(dirs) == 2 else next(iter(dirs))) for name, dirs in found.items()}


def check_i18n(config, protocols):
    codes = [lang["code"] for lang in config["languages"]]
    catalogs = {code: json.loads((SRC / "i18n" / f"{code}.json").read_text(encoding="utf-8")) for code in codes}
    reference = set(catalogs[codes[0]])
    for code, catalog in catalogs.items():
        if set(catalog) != reference:
            fail(f"{code} 键不一致：{sorted(set(catalog) ^ reference)}")
        for key, value in catalog.items():
            if JARGON.search(value):
                fail(f"{code}.{key} 含内部名字：{JARGON.search(value).group(0)}")
    required = {"zh-CN", "en", "ja", "ko", "ru", "es", "fa"}
    if set(codes) != required:
        fail(f"语言集合不符：{sorted(set(codes) ^ required)}")
    for protocol in protocols:
        if f"proto.{protocol['id']}" not in reference:
            fail(f"缺协议说明：{protocol['id']}")
    return codes


def check_protocols(protocols):
    if len(protocols) != 30:
        fail(f"协议数 {len(protocols)}，应为 30")
    listed = {item["id"]: item["dir"] for item in protocols}
    registered = registered_directions()
    if listed != registered:
        diff = sorted(set(listed.items()) ^ set(registered.items()))
        fail(f"protocols.json 与 main.rs 注册不一致：{diff}")


def check_pages(config, protocols):
    pages = [DIST / "index.html"] + [DIST / lang["code"] / "index.html" for lang in config["languages"]]
    for page in pages:
        if not page.exists():
            fail(f"缺页面：{page.relative_to(DIST)}")
            continue
        text = page.read_text(encoding="utf-8")
        where = page.relative_to(DIST).as_posix()
        for _, url in RESOURCE_ATTR.findall(text):
            if is_external(url):
                fail(f"{where} 外部资源：{url}")
        for tag in LINK_TAG.findall(text):
            href = HREF.search(tag)
            if href and is_external(href.group(1)):
                fail(f"{where} 外部 link：{href.group(1)}")
        for lang in config["languages"]:
            if f'hreflang="{lang["code"]}"' not in text:
                fail(f"{where} 缺 hreflang={lang['code']}")
        if 'hreflang="x-default"' not in text:
            fail(f"{where} 缺 x-default")
    for lang in config["languages"]:
        page = DIST / lang["code"] / "index.html"
        if not page.exists():
            continue
        text = page.read_text(encoding="utf-8")
        if not re.search(rf'<html lang="{re.escape(lang["code"])}" dir="{lang["dir"]}">', text):
            fail(f"{lang['code']} 页面 lang/dir 错误")
        if text.count('class="tri ') != len(protocols):
            fail(f"{lang['code']} 页面三角面数量不等于协议数")


def check_assets():
    total = 0
    for asset in (DIST / "assets").iterdir():
        total += asset.stat().st_size
        text = asset.read_text(encoding="utf-8")
        if asset.suffix == ".css":
            for url in CSS_URL.findall(text) + CSS_IMPORT.findall(text):
                if is_external(url):
                    fail(f"{asset.name} 外部资源：{url}")
        if asset.suffix == ".js" and re.search(r"(?:createElement\(['\"](?:script|link|img)|\bimport\s*\(|\bfetch\s*\(|XMLHttpRequest|importScripts|https?://(?!www\.w3\.org/))", text):
            fail(f"{asset.name} 含动态资源加载")
    if total > MAX_ASSET_BYTES:
        fail(f"assets {total} 字节，超过 {MAX_ASSET_BYTES}")
    return total


def check_contrast():
    css = (SRC / "style.css").read_text(encoding="utf-8")
    root = dict(re.findall(r"--([a-z-]+):\s*(#[0-9A-Fa-f]{6})", css[css.index(":root") : css.index("}", css.index(":root"))]))
    themes = re.findall(r"\.t-([a-z]+)\s*\{([^}]*)\}", css)
    if not themes:
        fail("style.css 没有 .t-* 主题")
    for name, body in themes:
        values = {}
        for prop, value in re.findall(r"--([a-z-]+):\s*([^;]+);", body):
            value = value.strip()
            reference = re.match(r"var\(--([a-z-]+)\)", value)
            values[prop] = root.get(reference.group(1)) if reference else value
        for fg, bg in (("fg", "bg"), ("mut", "bg"), ("code-fg", "code-bg"), ("link", "bg")):
            if fg in values and bg in values:
                ratio = contrast(values[fg], values[bg])
                if ratio < 4.5:
                    fail(f".t-{name} {fg}/{bg} 对比度 {ratio:.2f} < 4.5")


def main():
    config = json.loads((SRC / "config.json").read_text(encoding="utf-8"))
    protocols = json.loads((SRC / "protocols.json").read_text(encoding="utf-8"))
    if not DIST.exists():
        print("缺 dist/，先运行 build.py", file=sys.stderr)
        return 1
    codes = check_i18n(config, protocols)
    check_protocols(protocols)
    check_pages(config, protocols)
    total = check_assets()
    check_contrast()
    if FAILURES:
        for failure in FAILURES:
            print(f"失败：{failure}", file=sys.stderr)
        return 1
    print(f"通过：{len(codes)} 种语言，{len(protocols)} 个协议与 main.rs 一致，assets {total / 1024:.1f} KB，对比度达 AA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
