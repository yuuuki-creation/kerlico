#!/usr/bin/env python3
"""kerlico 与 Mihomo / sing-box 在真实 Geo 数据与规则集上的匹配差分。

在 worker 上运行：用同一批域名与 IP，分别取 Mihomo 二进制（日志中的命中规则）、sing-box
`rule-set match` 与 kerlico CLI 的判定，逐项比较。数据文件放在 --assets 目录，缺失时从
MetaCubeX/meta-rules-dat 下载。结果写入 --out（JSON）。

用法：
  tools/geo_diff_vs_mihomo.py --kerlico target/release/kerlico --mihomo bin/mihomo \\
      --sing-box bin/sing-box --assets assets --work tmp --out geo-diff.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

RELEASE = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest"
RAW = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
ASSETS = {
    "geoip.dat": f"{RELEASE}/geoip.dat",
    "geosite.dat": f"{RELEASE}/geosite.dat",
    "country.mmdb": f"{RELEASE}/country.mmdb",
    "geoip.metadb": f"{RELEASE}/geoip.metadb",
    "GeoLite2-ASN.mmdb": f"{RELEASE}/GeoLite2-ASN.mmdb",
    "geosite-cn.mrs": f"{RAW}/meta/geo/geosite/cn.mrs",
    "geosite-nocn.mrs": f"{RAW}/meta/geo/geosite/geolocation-!cn.mrs",
    "geoip-cn.mrs": f"{RAW}/meta/geo/geoip/cn.mrs",
    "geosite-cn.srs": f"{RAW}/sing/geo/geosite/cn.srs",
    "geoip-cn.srs": f"{RAW}/sing/geo/geoip/cn.srs",
}
ASN = 4134
FIXED_DOMAINS = [
    "www.baidu.com", "baidu.com", "qq.com", "www.taobao.com", "bilibili.com",
    "www.google.com", "google.cn", "www.google.cn", "github.com", "api.github.com",
    "www.youtube.com", "twitter.com", "x.com", "telegram.org", "openai.com",
    "cloudflare.com", "example.com", "apple.com", "www.apple.com.cn", "microsoft.com",
]


def fetch_assets(assets: Path) -> None:
    assets.mkdir(parents=True, exist_ok=True)
    for name, url in ASSETS.items():
        target = assets / name
        if not target.exists():
            subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(target), url], check=True)


def mihomo_dump(mihomo: str, behavior: str, mrs: Path, out: Path) -> list[str]:
    subprocess.run([mihomo, "convert-ruleset", behavior, "mrs", str(mrs), str(out)], check=True,
                   capture_output=True)
    return [line.strip() for line in out.read_text().splitlines() if line.strip()]


def hosts_from_patterns(patterns: list[str], rng: random.Random, count: int) -> list[str]:
    out = []
    for pattern in rng.sample(patterns, min(count, len(patterns))):
        if pattern.startswith("+."):
            base = pattern[2:]
            out.append(rng.choice([base, f"www.{base}", f"a.b.{base}", f"x{base}"]))
        elif pattern.startswith("."):
            out.append(rng.choice([pattern[1:], f"sub{pattern}"]))
        elif "*" not in pattern:
            out.append(rng.choice([pattern, f"w.{pattern}"]))
    return out


def sample_domains(rng: random.Random, cn: list[str], nocn: list[str]) -> list[str]:
    domains = list(FIXED_DOMAINS)
    domains += hosts_from_patterns(cn, rng, 90)
    domains += hosts_from_patterns(nocn, rng, 90)
    return list(dict.fromkeys(d.lower() for d in domains))


def sample_ips(rng: random.Random, cn_cidrs: list[str]) -> list[str]:
    ips = ["114.114.114.114", "223.5.5.5", "1.1.1.1", "8.8.8.8", "240e::1", "2001:4860:4860::8888"]
    for cidr in rng.sample(cn_cidrs, min(100, len(cn_cidrs))):
        net = ipaddress.ip_network(cidr, strict=False)
        ips.append(str(net.network_address + rng.randrange(net.num_addresses)))
    for _ in range(70):
        ips.append(str(ipaddress.IPv4Address(rng.randrange(1 << 24, 223 << 24))))
    for _ in range(30):
        ips.append(str(ipaddress.IPv6Address((0x2 << 125) | rng.getrandbits(125))))
    return list(dict.fromkeys(ips))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def socks_connect(port: int, target: str) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(b"\x05\x01\x00")
        s.recv(2)
        try:
            ip = ipaddress.ip_address(target)
            atyp = b"\x01" if ip.version == 4 else b"\x04"
            addr = atyp + ip.packed
        except ValueError:
            addr = b"\x03" + bytes([len(target)]) + target.encode()
        s.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", 80))
        try:
            s.recv(64)
        except OSError:
            pass


def remote_address(target: str) -> str:
    try:
        ip = ipaddress.ip_address(target)
        return f"[{ip}]:80" if ip.version == 6 else f"{ip}:80"
    except ValueError:
        return f"{target}:80"


def mihomo_decisions(mihomo: str, work: Path, name: str, files: dict[str, Path], config: str,
                     targets: list[str], marker: str) -> dict[str, bool]:
    home = work / f"mihomo-{name}"
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    for dst, src in files.items():
        shutil.copy(src, home / dst)
    port = free_port()
    (home / "config.yaml").write_text(
        f"mixed-port: {port}\nmode: rule\nlog-level: info\nipv6: true\ngeo-auto-update: false\n"
        f"dns: {{enable: false}}\n{config}"
    )
    log = (home / "stdout.log").open("w")
    proc = subprocess.Popen([mihomo, "-d", str(home), "-f", str(home / "config.yaml")],
                            stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError(f"mihomo {name} 未启动：{(home / 'stdout.log').read_text()[-2000:]}")
        for target in targets:
            socks_connect(port, target)
        time.sleep(1.5)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    text = (home / "stdout.log").read_text()
    out = {}
    for target in targets:
        needle = f"--> {remote_address(target)} match "
        lines = [l for l in text.splitlines() if needle in l]
        if not lines:
            raise RuntimeError(f"mihomo {name} 日志里没有 {target}")
        out[target] = marker.lower() in lines[-1].split(needle, 1)[1].lower()
    return out


def run_json_lines(cmd: list[str]) -> list[dict]:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def kerlico_codes(kerlico: str, sub: str, db: Path, code: str, targets: list[str]) -> dict[str, bool]:
    rows = run_json_lines([kerlico, sub, "-f", str(db), "lookup", "--code", code, *targets])
    return {t: bool(r["codes"]) for t, r in zip(targets, rows)}


def kerlico_asn(kerlico: str, db: Path, targets: list[str]) -> dict[str, bool]:
    rows = run_json_lines([kerlico, "geoip", "-f", str(db), "lookup", *targets])
    return {t: r["asn"] == ASN for t, r in zip(targets, rows)}


def kerlico_match(kerlico: str, ruleset: Path, targets: list[str]) -> dict[str, bool]:
    rows = run_json_lines([kerlico, "rule-set", "match", str(ruleset), *targets])
    return {t: r["matched"] for t, r in zip(targets, rows)}


def singbox_match(singbox: str, ruleset: Path, targets: list[str]) -> dict[str, bool]:
    out = {}
    for t in targets:
        r = subprocess.run([singbox, "rule-set", "match", "-f", "binary", str(ruleset), t],
                           capture_output=True, text=True)
        out[t] = "match rules." in (r.stdout + r.stderr)
    return out


def compare(name: str, reference: dict[str, bool], ours: dict[str, bool], against: str) -> dict:
    diff = [{"target": t, against: reference[t], "kerlico": ours[t]}
            for t in reference if reference[t] != ours[t]]
    return {
        "case": name,
        "reference": against,
        "targets": len(reference),
        "reference_hits": sum(reference.values()),
        "agree": len(reference) - len(diff),
        "disagree": diff[:20],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kerlico", required=True)
    ap.add_argument("--mihomo", required=True)
    ap.add_argument("--sing-box", required=True)
    ap.add_argument("--assets", type=Path, required=True)
    ap.add_argument("--work", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=20261106)
    args = ap.parse_args()
    a = args.assets
    fetch_assets(a)
    args.work.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    cn = mihomo_dump(args.mihomo, "domain", a / "geosite-cn.mrs", args.work / "cn.txt")
    nocn = mihomo_dump(args.mihomo, "domain", a / "geosite-nocn.mrs", args.work / "nocn.txt")
    cn_cidrs = mihomo_dump(args.mihomo, "ipcidr", a / "geoip-cn.mrs", args.work / "cnip.txt")
    domains = sample_domains(rng, cn, nocn)
    ips = sample_ips(rng, cn_cidrs)
    geo_files = {"GeoSite.dat": a / "geosite.dat", "GeoIP.dat": a / "geoip.dat",
                 "Country.mmdb": a / "country.mmdb", "ASN.mmdb": a / "GeoLite2-ASN.mmdb"}
    metadb_files = dict(geo_files, **{"Country.mmdb": a / "geoip.metadb"})
    provider_files = dict(geo_files, **{"cn.mrs": a / "geosite-cn.mrs", "cnip.mrs": a / "geoip-cn.mrs"})
    k, m = args.kerlico, args.mihomo
    results = []

    def mihomo(name, files, config, targets, marker):
        return mihomo_decisions(m, args.work, name, files, config, targets, marker)

    results.append(compare("GEOSITE,cn (geosite.dat)",
                           mihomo("geosite", geo_files, "rules:\n  - GEOSITE,cn,REJECT\n  - MATCH,REJECT\n",
                                  domains, "GeoSite(cn)"),
                           kerlico_codes(k, "geosite", a / "geosite.dat", "cn", domains), "mihomo"))
    results.append(compare("GEOSITE,google@cn (attribute)",
                           mihomo("geosite-attr", geo_files,
                                  "rules:\n  - GEOSITE,google@cn,REJECT\n  - MATCH,REJECT\n",
                                  domains, "GeoSite(google@cn)"),
                           kerlico_codes(k, "geosite", a / "geosite.dat", "google@cn", domains),
                           "mihomo"))
    results.append(compare("GEOIP,CN (country.mmdb, geodata-mode false)",
                           mihomo("geoip-mmdb", geo_files,
                                  "geodata-mode: false\nrules:\n  - GEOIP,CN,REJECT,no-resolve\n  - MATCH,REJECT\n",
                                  ips, "GeoIP(CN)"),
                           kerlico_codes(k, "geoip", a / "country.mmdb", "cn", ips), "mihomo"))
    results.append(compare("GEOIP,CN (geoip.metadb, geodata-mode false)",
                           mihomo("geoip-metadb", metadb_files,
                                  "geodata-mode: false\nrules:\n  - GEOIP,CN,REJECT,no-resolve\n  - MATCH,REJECT\n",
                                  ips, "GeoIP(CN)"),
                           kerlico_codes(k, "geoip", a / "geoip.metadb", "cn", ips), "mihomo"))
    results.append(compare("GEOIP,CN (geoip.dat, geodata-mode true)",
                           mihomo("geoip-dat", geo_files,
                                  "geodata-mode: true\nrules:\n  - GEOIP,CN,REJECT,no-resolve\n  - MATCH,REJECT\n",
                                  ips, "GeoIP(CN)"),
                           kerlico_codes(k, "geoip", a / "geoip.dat", "cn", ips), "mihomo"))
    results.append(compare(f"IP-ASN,{ASN} (GeoLite2-ASN.mmdb)",
                           mihomo("asn", geo_files,
                                  f"rules:\n  - IP-ASN,{ASN},REJECT,no-resolve\n  - MATCH,REJECT\n",
                                  ips, f"IPASN({ASN})"),
                           kerlico_asn(k, a / "GeoLite2-ASN.mmdb", ips), "mihomo"))
    providers = ("rule-providers:\n"
                 "  cn: {type: file, behavior: domain, format: mrs, path: ./cn.mrs}\n"
                 "  cnip: {type: file, behavior: ipcidr, format: mrs, path: ./cnip.mrs}\n")
    results.append(compare("RULE-SET domain mrs (geosite/cn.mrs)",
                           mihomo("mrs-domain", provider_files,
                                  providers + "rules:\n  - RULE-SET,cn,REJECT\n  - MATCH,REJECT\n",
                                  domains, "RuleSet(cn)"),
                           kerlico_match(k, a / "geosite-cn.mrs", domains), "mihomo"))
    results.append(compare("RULE-SET ipcidr mrs (geoip/cn.mrs)",
                           mihomo("mrs-ip", provider_files,
                                  providers + "rules:\n  - RULE-SET,cnip,REJECT,no-resolve\n  - MATCH,REJECT\n",
                                  ips, "RuleSet(cnip)"),
                           kerlico_match(k, a / "geoip-cn.mrs", ips), "mihomo"))
    results.append(compare("sing-box srs domain (geosite/cn.srs)",
                           singbox_match(args.sing_box, a / "geosite-cn.srs", domains),
                           kerlico_match(k, a / "geosite-cn.srs", domains), "sing-box"))
    results.append(compare("sing-box srs ipcidr (geoip/cn.srs)",
                           singbox_match(args.sing_box, a / "geoip-cn.srs", ips),
                           kerlico_match(k, a / "geoip-cn.srs", ips), "sing-box"))

    w = args.work
    encoders = {}
    subprocess.run([k, "rule-set", "convert", str(a / "geosite-cn.mrs"), "-o", str(w / "k-cn.txt")], check=True)
    encoders["mrs->text equals mihomo dump"] = sorted((w / "k-cn.txt").read_text().split()) == sorted(cn)
    subprocess.run([k, "rule-set", "convert", "--behavior", "domain", str(w / "cn.txt"), "-o",
                    str(w / "k-cn.mrs")], check=True)
    subprocess.run([m, "convert-ruleset", "domain", "text", str(w / "cn.txt"), str(w / "m-cn.mrs")],
                   check=True, capture_output=True)
    dec = lambda p: subprocess.run(["zstd", "-dc", str(p)], check=True, capture_output=True).stdout
    encoders["text->mrs payload byte-equal to mihomo"] = dec(w / "k-cn.mrs") == dec(w / "m-cn.mrs")
    redump = mihomo_dump(m, "domain", w / "k-cn.mrs", w / "k-cn-redump.txt")
    encoders["kerlico mrs read back by mihomo"] = sorted(redump) == sorted(cn)
    subprocess.run([k, "rule-set", "convert", "--behavior", "ipcidr", str(w / "cnip.txt"), "-o",
                    str(w / "k-cnip.mrs")], check=True)
    subprocess.run([m, "convert-ruleset", "ipcidr", "text", str(w / "cnip.txt"), str(w / "m-cnip.mrs")],
                   check=True, capture_output=True)
    encoders["ipcidr text->mrs payload byte-equal to mihomo"] = dec(w / "k-cnip.mrs") == dec(w / "m-cnip.mrs")
    subprocess.run([k, "rule-set", "decompile", str(a / "geosite-cn.srs"), "-o", str(w / "k-cn.json")], check=True)
    subprocess.run([k, "rule-set", "compile", str(w / "k-cn.json"), "-o", str(w / "k-cn.srs")], check=True)
    sb = lambda p, o: subprocess.run([args.sing_box, "rule-set", "decompile", "-o", str(o), str(p)],
                                     check=True, capture_output=True)
    sb(a / "geosite-cn.srs", w / "sb-cn.json")
    sb(w / "k-cn.srs", w / "sb-k-cn.json")
    norm = lambda p: json.dumps(json.loads(p.read_text())["rules"], sort_keys=True)
    encoders["kerlico srs decoded by sing-box equals original"] = norm(w / "sb-cn.json") == norm(w / "sb-k-cn.json")

    summary = {
        "domains": len(domains),
        "ips": len(ips),
        "cases": results,
        "encoders": encoders,
    }
    args.out.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    for r in results:
        print(f"{r['case']}: {r['agree']}/{r['targets']} agree ({r['reference_hits']} hits by {r['reference']})")
    for name, ok in encoders.items():
        print(f"{name}: {'ok' if ok else 'MISMATCH'}")
    if any(r["disagree"] for r in results) or not all(encoders.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
