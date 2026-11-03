#!/usr/bin/env python3
"""能力总表：把 Mihomo、sing-box、Xray 的文档清单合并成一张表，并跟踪 kerlico 的实现和实测状态。

输入都在 docs/capability-matrix/：
  sources/<core>.jsonl    三家文档清单，由通读文档得到
  annotations/*.jsonl     kerlico 现状：{"key":..., "kerlico":"yes|partial|no|na", "where":..., "note":...}
  results/*.jsonl         实测结论：{"key":..., "test":"pass|fail|blocked", "evidence":..., "date":...}

用法：
  tools/capability_matrix.py build     生成 README.md 和各类别的 Markdown
  tools/capability_matrix.py check     校验注解键存在、取值合法；--strict 还要求每行都有 kerlico 现状
  tools/capability_matrix.py keys      列出规范键，可用 --category、--subject 过滤
  tools/capability_matrix.py next      列出还没测的键，可用 --category、--subject、--limit 过滤
"""
import argparse
import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "docs" / "capability-matrix"
CORES = ("mihomo", "sing-box", "xray")
CATEGORY_ORDER = (
    "inbound", "outbound", "transport", "security", "mux", "udp", "flow", "route", "ruleset", "dns", "group",
    "provider", "tun", "sniff", "dialer", "user", "stats", "api", "log", "ntp", "cert", "cache", "config", "cli",
    "experimental", "other",
)
CATEGORY_TITLE = {
    "inbound": "入站", "outbound": "出站", "transport": "传输层", "security": "安全层", "mux": "多路复用",
    "udp": "UDP 处理", "flow": "流控", "route": "路由", "ruleset": "规则集", "dns": "DNS", "group": "策略组",
    "provider": "代理提供者", "tun": "TUN 与系统接入", "sniff": "嗅探", "dialer": "拨号选项", "user": "用户与鉴权",
    "stats": "统计", "api": "API", "log": "日志", "ntp": "NTP", "cert": "证书", "cache": "缓存",
    "config": "配置格式", "cli": "命令行", "experimental": "实验性功能", "other": "其他",
}
# 同一概念在三家的不同叫法，合到一个主题下。
SUBJECT_ALIAS = {
    "freedom": "direct", "blackhole": "block", "reject": "block", "dokodemo-door": "tunnel", "shadowsocks2022": "ss2022",
    "endpoint-wireguard": "wireguard", "endpoint-tailscale": "tailscale", "endpoint-openconnect": "openconnect",
    "endpoint-openvpn-client": "openvpn", "endpoint-openvpn-server": "openvpn", "endpoint-masque-client": "masque",
    "endpoint-masque-server": "masque", "hysteria1": "hysteria", "selector": "select", "urltest": "url-test",
}
KERLICO_VALUES = ("yes", "partial", "no", "na")
TEST_VALUES = ("pass", "fail", "blocked")
KERLICO_LABEL = {"yes": "已实现", "partial": "部分", "no": "未实现", "na": "不适用", None: "待标注"}
TEST_LABEL = {"pass": "通过", "fail": "失败", "blocked": "受阻", None: "未测"}


def norm_name(name):
    return re.sub(r"[^a-z0-9]+", "-", re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", str(name)).lower()).strip("-")


def row_key(item):
    subject = norm_name(item.get("subject") or "general")
    subject = SUBJECT_ALIAS.get(subject, subject)
    name = norm_name(item.get("name") or item["id"].rsplit(".", 1)[-1])
    return f"{item['category']}/{subject}/{name}"


def read_jsonl(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def load_rows():
    rows = {}
    for core in CORES:
        for item in read_jsonl(ROOT / "sources" / f"{core}.jsonl"):
            key = row_key(item)
            row = rows.setdefault(key, {"key": key, "category": item["category"], "kind": item["kind"], "cores": {}, "summary": item.get("summary", "")})
            entry = row["cores"].setdefault(core, {"status": item["status"], "values": [], "constraints": [], "dimensions": {}, "basis": item.get("basis", "")})
            entry["values"] = sorted({*entry["values"], *map(str, item.get("values") or [])})
            entry["constraints"] = sorted({*entry["constraints"], *(item.get("constraints") or [])})
            for dimension, values in (item.get("dimensions") or {}).items():
                entry["dimensions"][dimension] = sorted({*entry["dimensions"].get(dimension, []), *map(str, values)})
    return rows


def overlay(rows, folder, field, allowed, problems):
    for path in sorted((ROOT / folder).glob("*.jsonl")):
        for record in read_jsonl(path):
            key = record.get("key")
            if key not in rows:
                problems.append(f"{path.name}: 键不存在：{key}")
            elif record.get(field) not in allowed:
                problems.append(f"{path.name}: {key} 的 {field} 取值非法：{record.get(field)}")
            elif field in rows[key]:
                problems.append(f"{path.name}: {key} 重复标注")
            else:
                rows[key].update(record)


def load():
    rows = load_rows()
    problems = []
    overlay(rows, "annotations", "kerlico", KERLICO_VALUES, problems)
    overlay(rows, "results", "test", TEST_VALUES, problems)
    return rows, problems


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def support(row, core):
    entry = row["cores"].get(core)
    if not entry:
        return ""
    mark = {"current": "有", "deprecated": "废弃", "removed": "已移除", "experimental": "实验"}[entry["status"]]
    return mark


def values_text(row):
    parts = []
    merged = sorted({value for entry in row["cores"].values() for value in entry["values"]})
    if merged:
        parts.append("取值：" + "、".join(f"`{value}`" for value in merged[:24]) + ("……" if len(merged) > 24 else ""))
    for entry in row["cores"].values():
        for dimension, values in entry["dimensions"].items():
            parts.append(f"{dimension}：" + "、".join(f"`{value}`" for value in values))
        parts.extend(f"约束：{constraint}" for constraint in entry["constraints"])
    return "<br>".join(dict.fromkeys(parts))


def state(row):
    kerlico, test = row.get("kerlico"), row.get("test")
    return KERLICO_LABEL[kerlico], TEST_LABEL[test]


def category_page(category, rows):
    out = [f"# {CATEGORY_TITLE[category]}", "", "由 `tools/capability_matrix.py build` 生成，不要手改。", ""]
    groups = collections.defaultdict(list)
    for row in rows:
        groups[row["key"].split("/")[1]].append(row)
    for subject in sorted(groups):
        out += [f"## {subject}", "", "| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for row in sorted(groups[subject], key=lambda item: (item["kind"] != "protocol", item["kind"] != "combo", item["key"])):
            kerlico, test = state(row)
            name = row["key"].split("/", 2)[2]
            out.append(
                f"| `{name}` | {cell(row['summary'])} | {support(row, 'mihomo')} | {support(row, 'sing-box')} | {support(row, 'xray')} "
                f"| {kerlico} | {test} | {cell(values_text(row))} |"
            )
        out.append("")
    return "\n".join(out)


def overview(rows):
    by_category = collections.defaultdict(list)
    for row in rows.values():
        by_category[row["category"]].append(row)
    total = len(rows)
    tested = sum(row.get("test") == "pass" for row in rows.values())
    out = [
        "# 能力总表",
        "",
        f"Mihomo、sing-box、Xray 文档写到的全部操作和组合，共 {total} 项，以及 kerlico 对每一项的实现和实测状态。由 `tools/capability_matrix.py build` 生成，不要手改。",
        "",
        "三家文档的固定提交见 [来源说明](sources/README.md)。",
        "",
        "| 类别 | 项数 | 已实现 | 部分 | 未实现 | 不适用 | 待标注 | 实测通过 | 实测失败 | 受阻 | 未测 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for category in CATEGORY_ORDER:
        group = by_category.get(category, [])
        if not group:
            continue
        kerlico = collections.Counter(row.get("kerlico") for row in group)
        test = collections.Counter(row.get("test") for row in group)
        applicable = [row for row in group if row.get("kerlico") in ("yes", "partial")]
        out.append(
            f"| [{CATEGORY_TITLE[category]}]({category}.md) | {len(group)} | {kerlico['yes']} | {kerlico['partial']} | {kerlico['no']} | {kerlico['na']} | {kerlico[None]} "
            f"| {test['pass']} | {test['fail']} | {test['blocked']} | {sum(row.get('test') is None for row in applicable)} |"
        )
    out += ["", f"实测通过合计 {tested} 项。“未测”只统计 kerlico 已实现或部分实现的项。", ""]
    return "\n".join(out)


def build(rows):
    by_category = collections.defaultdict(list)
    for row in rows.values():
        by_category[row["category"]].append(row)
    for category, group in by_category.items():
        (ROOT / f"{category}.md").write_text(category_page(category, group), encoding="utf-8", newline="\n")
    (ROOT / "README.md").write_text(overview(rows), encoding="utf-8", newline="\n")
    print(f"生成 {len(by_category)} 个类别，共 {len(rows)} 项")


def select(rows, args):
    for key in sorted(rows):
        category, subject, _ = key.split("/", 2)
        if args.category and category != args.category:
            continue
        if args.subject and subject != args.subject:
            continue
        yield rows[key]


def main():
    parser = argparse.ArgumentParser(description="能力总表")
    parser.add_argument("command", choices=["build", "check", "keys", "next"])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--category")
    parser.add_argument("--subject")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    rows, problems = load()
    if args.command in ("build", "check"):
        unknown = sorted({row["category"] for row in rows.values()} - set(CATEGORY_ORDER))
        if unknown:
            problems.append(f"未知类别：{unknown}")
        if args.command == "check" and args.strict:
            problems += [f"待标注：{key}" for key, row in rows.items() if "kerlico" not in row][:40]
        for problem in problems:
            print(problem, file=sys.stderr)
        if problems:
            return 1
    if args.command == "build":
        build(rows)
    elif args.command == "check":
        print(f"通过：{len(rows)} 项")
    else:
        count = 0
        for row in select(rows, args):
            if args.command == "next" and (row.get("test") or row.get("kerlico") in ("no", "na")):
                continue
            print(f"{row['key']}\t{'/'.join(row['cores'])}\t{row.get('kerlico', '-')}\t{row.get('test', '-')}\t{row['summary']}")
            count += 1
            if args.limit and count >= args.limit:
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
