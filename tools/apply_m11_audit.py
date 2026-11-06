#!/usr/bin/env python3
"""按 docs/testing/m11-audit/audit.jsonl 把能力总表改为审计后的真实状态。

real：保留标注；有具名测试则 results 记 pass 并写测试名，否则删除 results 行（未测）。
overclaimed：yes 降为 partial，说明改为审计结论，删除 results 行。
stub、missing：降为 no，说明改为审计结论，删除 results 行。

已在 audit.jsonl 之后单独修复的键，用 --keep 跳过（可多次传入，或传文件）。
"""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "capability-matrix"
AUDIT = ROOT / "docs" / "testing" / "m11-audit" / "audit.jsonl"
DATE = "2026-11-06"
NO_TEST = {"", "none", "null", "n/a"}
LABEL = {"overclaimed": "夸大", "stub": "空壳", "missing": "缺失"}


def load(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def dump(path, rows):
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8", newline="\n")


def named_test(value):
    text = str(value or "").strip()
    return None if text.lower() in NO_TEST or text.lower().startswith("none") else text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="append", default=[], help="跳过的键，或含键列表的文件")
    args = parser.parse_args()
    keep = set()
    for item in args.keep:
        path = Path(item)
        keep |= set(path.read_text(encoding="utf-8").split()) if path.is_file() else {item}

    audit = {row["key"]: row for row in load(AUDIT) if row["key"] not in keep}
    counts = {}
    for path in sorted((MATRIX / "annotations").glob("*.jsonl")):
        rows = load(path)
        for row in rows:
            verdict = audit.get(row["key"], {}).get("verdict")
            if verdict is None or verdict == "real":
                continue
            fix = audit[row["key"]].get("fix", "").strip()
            row["kerlico"] = "partial" if verdict == "overclaimed" and row["kerlico"] in ("yes", "partial") else "no"
            row["note"] = f"M11 审计（{LABEL[verdict]}）：{fix}" if fix else f"M11 审计（{LABEL[verdict]}）"
            counts[verdict] = counts.get(verdict, 0) + 1
        dump(path, rows)

    for path in sorted((MATRIX / "results").glob("*.jsonl")):
        out = []
        for row in load(path):
            entry = audit.get(row["key"])
            if entry is None:
                out.append(row)
                continue
            test = named_test(entry.get("test")) if entry["verdict"] == "real" else None
            if test:
                out.append({"key": row["key"], "test": "pass", "evidence": test, "date": DATE})
                counts["pass"] = counts.get("pass", 0) + 1
            else:
                counts["untested"] = counts.get("untested", 0) + 1
        dump(path, out)
    print(json.dumps(counts, ensure_ascii=False))


if __name__ == "__main__":
    main()
