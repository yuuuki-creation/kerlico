#!/usr/bin/env python3
"""把 src/template.html 与 src/i18n/<lang>.json 生成到 dist/。缺键、多键或未解析占位符都让构建失败。"""

import hashlib
import html
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DIST = ROOT / "dist"

# 文件顺序就是依赖顺序：后面的文件使用前面定义的函数。
JS_PARTS = ["geom", "glyphs", "field", "render", "intro", "scroll", "dispatcher", "wall", "main"]
PLACEHOLDER = re.compile(r"\{\{([^{}]+)\}\}")
CODE_SPAN = re.compile(r"`([^`]+)`")
LABEL_PREFIXES = ("how.l_", "wall.both", "wall.in", "wall.out", "start.copy", "start.copied")
DIR_LABEL = {"both": "wall.both", "in": "wall.in", "out": "wall.out"}


class BuildError(Exception):
    pass


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def to_html(text):
    """反引号转 <code dir=ltr>，保证 RTL 页面里命令和标识的方向正确。"""
    parts = CODE_SPAN.split(text)
    out = []
    for index, part in enumerate(parts):
        if index % 2:
            out.append(f'<code dir="ltr">{html.escape(part)}</code>')
        else:
            out.append(html.escape(part))
    return "".join(out)


def to_plain(text):
    return html.escape(text.replace("`", ""), quote=True)


def load_catalogs(config, protocols):
    catalogs = {lang["code"]: read_json(SRC / "i18n" / f"{lang['code']}.json") for lang in config["languages"]}
    reference = catalogs[config["languages"][0]["code"]]
    wanted = set(reference)
    expected_protocols = {f"proto.{item['id']}" for item in protocols}
    missing_protocols = expected_protocols - wanted
    if missing_protocols:
        raise BuildError(f"参考语言缺协议键：{sorted(missing_protocols)}")
    for code, catalog in catalogs.items():
        missing = wanted - set(catalog)
        extra = set(catalog) - wanted
        if missing or extra:
            raise BuildError(f"{code} 缺键 {sorted(missing)}，多键 {sorted(extra)}")
        empty = [key for key, value in catalog.items() if not isinstance(value, str) or not value.strip()]
        if empty:
            raise BuildError(f"{code} 空值：{sorted(empty)}")
    return catalogs


def alternates(config):
    lines = []
    for lang in config["languages"]:
        lines.append(f'<link rel="alternate" hreflang="{lang["code"]}" href="../{lang["code"]}/">')
    lines.append('<link rel="alternate" hreflang="x-default" href="../">')
    return "\n".join(lines)


def lang_links(config, current):
    items = []
    for lang in config["languages"]:
        state = ' aria-current="true"' if lang["code"] == current else ""
        items.append(
            f'<a href="../{lang["code"]}/" hreflang="{lang["code"]}" lang="{lang["code"]}" '
            f'dir="{lang["dir"]}" data-lang="{lang["code"]}" title="{html.escape(lang["name"], quote=True)}" '
            f'aria-label="{html.escape(lang["name"], quote=True)}"{state}>{html.escape(lang["short"])}</a>'
        )
    return "".join(items)


def protocol_items(protocols, catalog):
    items = []
    for protocol in protocols:
        label_key = DIR_LABEL[protocol["dir"]]
        items.append(
            f'<li class="tri d-{protocol["dir"]}" data-id="{protocol["id"]}" data-dir="{protocol["dir"]}">'
            f'<button type="button"><span class="flipper"><span class="face front"><b dir="ltr">{html.escape(protocol["name"])}</b></span>'
            f'<span class="face back" aria-hidden="true"></span></span>'
            f'<span class="desc"><span class="dir-label">{to_html(catalog[label_key])}</span> '
            f'<span class="sentence">{to_html(catalog["proto." + protocol["id"]])}</span></span></button></li>'
        )
    return "\n".join(items)


def labels_json(catalog):
    keys = [key for key in catalog if key.startswith(LABEL_PREFIXES)]
    data = {key: catalog[key].replace("`", "") for key in keys}
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


def render_page(template, config, protocols, lang, catalog, used, asset_version):
    counts = {
        "total": len(protocols),
        "both": sum(item["dir"] == "both" for item in protocols),
        "in": sum(item["dir"] == "in" for item in protocols),
        "out": sum(item["dir"] == "out" for item in protocols),
    }

    def text_of(key):
        if key not in catalog:
            raise BuildError(f"模板引用了不存在的键：{key}")
        used.add(key)
        return catalog[key]

    def replace(match):
        token = match.group(1).strip()
        if token == "lang":
            return lang["code"]
        if token == "dir":
            return lang["dir"]
        if token == "@asset_version":
            return asset_version
        if token == "@alternates":
            return alternates(config)
        if token == "@lang_current":
            return html.escape(lang["name"])
        if token == "@lang_links":
            return lang_links(config, lang["code"])
        if token == "@protocols":
            for protocol in protocols:
                used.add(f"proto.{protocol['id']}")
            return protocol_items(protocols, catalog)
        if token == "@labels":
            used.update(key for key in catalog if key.startswith(LABEL_PREFIXES))
            return labels_json(catalog)
        if token.startswith("count:"):
            return str(counts[token[6:]])
        if token.startswith("cfg:"):
            return html.escape(config[token[4:]], quote=True)
        if token.startswith("plain:"):
            return to_plain(text_of(token[6:]))
        return to_html(text_of(token))

    page = PLACEHOLDER.sub(replace, template)
    if "{{" in page or "}}" in page:
        raise BuildError(f"{lang['code']} 页面残留占位符")
    return page


def root_page(config):
    codes = [lang["code"] for lang in config["languages"]]
    links = "".join(
        f'<li><a href="{lang["code"]}/" hreflang="{lang["code"]}" lang="{lang["code"]}" dir="{lang["dir"]}">'
        f'{html.escape(lang["name"])}</a></li>'
        for lang in config["languages"]
    )
    alternate = "\n".join(
        f'<link rel="alternate" hreflang="{code}" href="{code}/">' for code in codes
    )
    return f"""<!doctype html>
<html lang="{config['default_lang']}" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kerlico</title>
<meta name="color-scheme" content="dark">
{alternate}
<link rel="alternate" hreflang="x-default" href="./">
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#10131C;color:#EFE9DC;font:16px/1.6 system-ui,sans-serif}}ul{{list-style:none;padding:0}}a{{color:#EFE9DC}}</style>
<script>
(function () {{
  var codes = {json.dumps(codes)};
  var chosen = null;
  try {{ chosen = localStorage.getItem('kerlico.lang'); }} catch (e) {{}}
  if (codes.indexOf(chosen) < 0) {{
    chosen = null;
    var wanted = navigator.languages || [navigator.language || ''];
    for (var i = 0; i < wanted.length && !chosen; i++) {{
      var tag = String(wanted[i]).toLowerCase();
      for (var j = 0; j < codes.length && !chosen; j++) {{
        if (tag.split('-')[0] === codes[j].toLowerCase().split('-')[0]) chosen = codes[j];
      }}
    }}
  }}
  location.replace((chosen || {json.dumps(config['default_lang'])}) + '/' + location.hash);
}})();
</script>
</head>
<body>
<noscript><ul>{links}</ul></noscript>
</body>
</html>
"""


def build():
    config = read_json(SRC / "config.json")
    protocols = read_json(SRC / "protocols.json")
    catalogs = load_catalogs(config, protocols)
    template = (SRC / "template.html").read_text(encoding="utf-8")

    if DIST.exists():
        shutil.rmtree(DIST)
    (DIST / "assets").mkdir(parents=True)

    style = (SRC / "style.css").read_bytes()
    script = "\n".join((SRC / "js" / f"{name}.js").read_text(encoding="utf-8") for name in JS_PARTS)
    # CDN 和浏览器都会缓存静态资源，地址带内容哈希，更新后立刻换新。
    asset_version = hashlib.sha256(style + script.encode("utf-8")).hexdigest()[:10]

    used = set()
    for lang in config["languages"]:
        catalog = catalogs[lang["code"]]
        page = render_page(template, config, protocols, lang, catalog, used, asset_version)
        out = DIST / lang["code"] / "index.html"
        out.parent.mkdir(parents=True)
        out.write_text(page, encoding="utf-8", newline="\n")

    reference = catalogs[config["languages"][0]["code"]]
    unused = sorted(set(reference) - used)
    if unused:
        raise BuildError(f"有键未被模板使用：{unused}")

    (DIST / "index.html").write_text(root_page(config), encoding="utf-8", newline="\n")
    (DIST / "assets" / "site.css").write_bytes(style)
    (DIST / "assets" / "site.js").write_text(
        "(function () {\n'use strict';\n" + script + "\n})();\n", encoding="utf-8", newline="\n"
    )

    size = sum(path.stat().st_size for path in (DIST / "assets").iterdir())
    print(f"已生成 {len(config['languages'])} 种语言，assets {size / 1024:.1f} KB")


if __name__ == "__main__":
    try:
        build()
    except (BuildError, OSError, json.JSONDecodeError) as error:
        print(f"构建失败：{error}", file=sys.stderr)
        sys.exit(1)
