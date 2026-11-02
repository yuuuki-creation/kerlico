#!/usr/bin/env python3
"""按外观包标准（schemaVersion 1）校验本目录的外观并打包成 dist/kerlico-theme-<版本>.zip。
检查包的大小与文件名、theme.css 的禁用写法和 url()、文件头、两套配色的 WCAG AA 对比度；theme.json 的完整结构由服务端上传时校验。
用法：python package_theme.py"""
import json
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(ROOT, "dist")
MAX_ZIP, MAX_TOTAL, MAX_FILES, MAX_FILE, MAX_CSS = 2 << 20, 4 << 20, 64, 512 << 10, 64 << 10
BANNED_CSS = ("\\", "@import", "expression(", "javascript:", "vbscript:", "image-set(", "src(", "</")
ASSET = re.compile(r"^assets/[a-z0-9][a-z0-9._-]{0,63}\.(png|jpg|jpeg|webp|gif|avif|woff2|woff)$")
# 文字色/底色对，至少 4.5:1（正文）；界面元素与焦点框至少 3:1。
TEXT_PAIRS = [("foreground", "background"), ("foreground", "surface"), ("foreground", "surfaceSecondary"), ("muted", "background"), ("muted", "surface"),
              ("defaultForeground", "default"), ("accent", "background"), ("accent", "surface"), ("accentForeground", "accent")]
UI_PAIRS = [("focus", "background"), ("border", "background")]


def fail(message):
    sys.exit(f"校验失败：{message}")


def luminance(color):
    channels = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def check_contrast(manifest):
    for scheme, palette in manifest["tokens"].items():
        for pairs, minimum in ((TEXT_PAIRS, 4.5), (UI_PAIRS, 3.0)):
            for text, background in pairs:
                ratio = contrast(palette[text], palette[background])
                print(f"{scheme:5} {text}/{background}: {ratio:.2f}")
                if ratio < minimum:
                    fail(f"{scheme} 的 {text} 在 {background} 上对比度 {ratio:.2f}，低于 {minimum}")


def check_stylesheet(css, files):
    if len(css) > MAX_CSS:
        fail("theme.css 超过 64KiB")
    lower = css.decode().lower()
    for banned in BANNED_CSS:
        if banned in lower:
            fail(f"theme.css 不能包含 {banned}")
    for target in re.findall(r"url\(\s*['\"]?([^'\")\s]*)", lower):
        if not ASSET.match(target) or target not in files:
            fail(f"theme.css 的 url() 指向包外：{target}")


def check_magic(name, data):
    if name.endswith(".webp") and not (data[:4] == b"RIFF" and data[8:12] == b"WEBP"):
        fail(f"{name} 文件头不是 WEBP")
    if name.endswith(".png") and data[:8] != b"\x89PNG\r\n\x1a\n":
        fail(f"{name} 文件头不是 PNG")


def read_files():
    names = ["theme.json", "theme.css", "preview.webp"] + [f"assets/{name}" for name in os.listdir(os.path.join(ROOT, "assets"))]
    files = {}
    for name in names:
        if name.startswith("assets/") and not ASSET.match(name):
            fail(f"不允许的文件：{name}")
        with open(os.path.join(ROOT, name), "rb") as handle:
            files[name] = handle.read()
    return files


def main():
    files = read_files()
    manifest = json.loads(files["theme.json"])
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_TOTAL:
        fail("文件数或解压总大小超限")
    for name, data in files.items():
        if len(data) > MAX_FILE:
            fail(f"{name} 超过 512KiB")
        check_magic(name, data)
    if manifest.get("stylesheet") != "theme.css" or manifest.get("preview") not in files:
        fail("theme.json 没有声明 theme.css 或预览图")
    check_stylesheet(files["theme.css"], files)
    check_contrast(manifest)
    os.makedirs(DIST, exist_ok=True)
    target = os.path.join(DIST, f"kerlico-theme-{manifest['version']}.zip")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), files[name], zipfile.ZIP_DEFLATED)
    if os.path.getsize(target) > MAX_ZIP:
        fail("压缩包超过 2MiB")
    print(f"{os.path.relpath(target, ROOT)}: {os.path.getsize(target) // 1024}KiB，{len(files)} 个文件")


if __name__ == "__main__":
    main()
