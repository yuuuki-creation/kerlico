#!/usr/bin/env python3
"""把 kerlico 的 docs/ 打成 nice-wiki 能导入的 Markdown 压缩包，文档树写在清单里，由 provision.py 分批导入
（nice-wiki 的导入请求只有 10 秒委托有效期，一次导不完 70 篇）。分批后站内链接跨包解析不了，所以这里先写成占位地址
https://kerlico-wiki.invalid/doc/<路径段>，全部导入后由 provision.py 换成站内链接；指向 docs/ 之外的相对链接改成仓库地址。
产出 dist/kerlico-docs.zip 和 dist/kerlico-docs.json。用法：python prepare_docs.py"""
import json
import os
import posixpath
import re
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(ROOT))
DOCS = os.path.join(REPO, "docs")
DIST = os.path.join(ROOT, "dist")
REPO_URL = "https://github.com/yuuuki-creation/kerlico/blob/main/"
DOC_URL = "https://kerlico-wiki.invalid/doc/"
LINK = re.compile(r"(\]\()([^)\s]+)(\))")

CORE = ["core", "config", "control", "device-runtime", "node-egress", "dns", "history", "localization", "http-carrier", "tun", "ip-tunnel"]
PROXY = ["vless", "vmess", "trojan", "shadowsocks", "ss2022", "shadowsocksr", "shadowtls", "anytls", "snell", "socks", "http-proxy", "naive", "trusttunnel",
         "hysteria1", "hysteria2", "tuic", "shadowquic", "masque", "mieru", "sudoku", "ssh", "tor", "gost-relay"]
VPN = ["wireguard", "openvpn", "openconnect", "tailscale", "zerotier", "easytier"]


def interfaces(names):
    # docs/node-egress.md 占用了同名路径段，占位链接要靠路径段定位文档，所以全局唯一。
    return [{"file": f"interfaces/{name}.md", **({"slug": "node-egress-api"} if name == "node-egress" else {})} for name in names]


def releases():
    tagged = sorted((name for name in os.listdir(os.path.join(DOCS, "releases")) if re.fullmatch(r"\d+\.\d+\.\d+\.md", name)),
                    key=lambda name: [int(part) for part in name[:-3].split(".")], reverse=True)
    others = sorted(name for name in os.listdir(os.path.join(DOCS, "releases")) if name not in tagged)
    return [{"file": f"releases/{name}"} for name in tagged + others]


def decisions():
    names = sorted(name for name in os.listdir(os.path.join(DOCS, "decisions")) if name != "README.md")
    return [{"file": f"decisions/{name}"} for name in names]


# 文档树。file 是 docs/ 下的现有文件；只有 title 没有 file 的是生成的目录页，正文列出下级。
TREE = [
    {"file": "usage.md", "children": [{"file": "usage.en.md"}]},
    {"file": "architecture.md", "children": [{"file": "node-egress.md"}, {"file": "statistics-and-users.md"}]},
    {"file": "interfaces/README.md", "children": [
        {"title": "核心与运行", "slug": "runtime", "children": interfaces(CORE)},
        {"title": "代理协议", "slug": "proxy", "children": interfaces(PROXY)},
        {"title": "VPN 与组网", "slug": "vpn", "children": interfaces(VPN)},
    ]},
    {"title": "发布说明", "slug": "releases", "children": releases()},
    {"file": "decisions/README.md", "children": decisions()},
]


def read_doc(relative):
    with open(os.path.join(DOCS, relative), encoding="utf-8") as handle:
        return handle.read()


def title_of(node):
    if "title" in node:
        return node["title"]
    return re.search(r"^# +(.+?)\s*$", read_doc(node["file"]), re.M).group(1)


def slug_of(node):
    if "slug" in node:
        return node["slug"]
    stem = node["file"][:-3]
    if stem.endswith("/README"):
        return stem[:-len("/README")]
    return stem.rsplit("/", 1)[-1].replace(".", "-")


def seo_of(node):
    if "file" not in node:
        return node["title"]
    for line in read_doc(node["file"]).splitlines():
        line = line.strip()
        if len(line) >= 20 and not line.startswith(("#", "|", "```", "-", ">", "*", "<", "[")):
            return re.sub(r"[`*_\[\]]|\(http[^)]*\)", "", line)[:150]
    return title_of(node)


def walk(nodes, depth=0):
    for node in nodes:
        yield node, depth
        yield from walk(node.get("children", []), depth + 1)


def rewrite_links(relative, text, slugs):
    def repl(match):
        target = match.group(2)
        path, _, fragment = target.partition("#")
        if not path or "://" in path or path.startswith("mailto:"):
            return match.group(0)
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), path))
        if resolved in slugs:
            return f"{match.group(1)}{DOC_URL}{slugs[resolved]}{match.group(3)}"
        anchor = f"#{fragment}" if fragment else ""
        repo_path = resolved[3:] if resolved.startswith("../") else f"docs/{resolved}"
        return f"{match.group(1)}{REPO_URL}{repo_path}{anchor}{match.group(3)}"
    return LINK.sub(repl, text)


def index_page(node):
    lines = [f"# {node['title']}", ""]
    for child in node["children"]:
        lines.append(f"- [{title_of(child)}]({DOC_URL}{slug_of(child)})")
    return "\n".join(lines) + "\n"


def manifest_of(node):
    entry = {"title": title_of(node), "slug": slug_of(node), "seo": seo_of(node), "file": node.get("file", f"{slug_of(node)}.md")}
    children = [manifest_of(child) for child in node.get("children", [])]
    return {**entry, "children": children} if children else entry


def main():
    nodes = list(walk(TREE))
    slugs = {node["file"]: slug_of(node) for node, _ in nodes if "file" in node}
    for key in (title_of, slug_of):
        values = [key(node) for node, _ in nodes]
        if len(values) != len(set(values)):
            raise SystemExit(f"有重复：{sorted(v for v in values if values.count(v) > 1)}")
    missing = {f"interfaces/{name}" for name in os.listdir(os.path.join(DOCS, "interfaces"))} - set(slugs)
    if missing:
        raise SystemExit(f"接口文档没有进文档树：{sorted(missing)}")
    files = {}
    for node, _ in nodes:
        if "file" in node:
            files[node["file"]] = rewrite_links(node["file"], read_doc(node["file"]), slugs)
        else:
            files[f"{slug_of(node)}.md"] = index_page(node)
    os.makedirs(DIST, exist_ok=True)
    target = os.path.join(DIST, "kerlico-docs.zip")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(name, files[name])
    with open(os.path.join(DIST, "kerlico-docs.json"), "w", encoding="utf-8") as handle:
        json.dump([manifest_of(node) for node in TREE], handle, ensure_ascii=False, indent=1)
    print(f"{len(nodes)} 篇文档，压缩包 {os.path.getsize(target) // 1024}KiB")


if __name__ == "__main__":
    main()
