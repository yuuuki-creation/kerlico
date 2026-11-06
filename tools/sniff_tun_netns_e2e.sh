#!/usr/bin/env bash
# TUN 入站经共享嗅探阶段的端到端验证：只在临时 netns 内建 TUN 与路由，不改宿主网络。
# 用法（root）：tools/sniff_tun_netns_e2e.sh <kerlico 可执行文件>
# netns 内 kerlico 持有 TUN，客户端向文档地址发 TLS ClientHello 与 QUIC Initial；
# 出站 hit/miss 都是 reject，按连接日志里命中的规则判定是否按嗅探域名分流。
set -euo pipefail

bin="$(realpath "${1:?用法：$0 <kerlico 可执行文件>}")"
[ "$(id -u)" = 0 ] || { echo "需要 root 运行" >&2; exit 2; }
for tool in ip python3; do command -v "$tool" >/dev/null || { echo "缺少 $tool" >&2; exit 2; }; done
root="$(cd "$(dirname "$0")/.." && pwd)"

ns="ks$$"
work="$(mktemp -d)"
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  wait 2>/dev/null || true
  ip netns del "$ns" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

ip netns add "$ns"
ip -n "$ns" link set lo up

cat >"$work/config.json" <<JSON
{
  "version": 2,
  "outbounds": [{"tag":"hit","type":"reject"},{"tag":"miss","type":"reject"}],
  "local_inbounds": [{"tag":"tun-in","type":"tun","listen":"127.0.0.1:0","outbound":"miss",
    "options":{"name":"ks0","addresses":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"mtu":1500}}],
  "routes": [{"outbound":"hit","domain":["allowed.test","quic.example.com"]}],
  "sniffer": {"enable":true,"override_destination":false,
    "sniff":{"TLS":{"ports":[443]},"QUIC":{"ports":[443]}}},
  "log_level": "info"
}
JSON

ip netns exec "$ns" "$bin" run -c "$work/config.json" >"$work/kerlico.log" 2>&1 &
pid=$!
for _ in $(seq 50); do
  ip -n "$ns" link show ks0 >/dev/null 2>&1 && break
  sleep 0.2
done
ip -n "$ns" link show ks0 >/dev/null || { cat "$work/kerlico.log"; echo "TUN 未建立" >&2; exit 1; }
ip -n "$ns" link set ks0 up
ip -n "$ns" route add 198.51.100.0/24 dev ks0
ip -n "$ns" -6 route add 2001:db8::/64 dev ks0
sleep 0.5

ip netns exec "$ns" python3 - "$root" <<'PY'
import socket, struct, sys, time
root = sys.argv[1]
def hello(sni):
    host = sni.encode()
    ext = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    exts = struct.pack("!HH", 0, len(ext)) + ext
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00\x00\x02\x13\x01\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
def tcp(dst, sni):
    family = socket.AF_INET6 if ":" in dst else socket.AF_INET
    s = socket.socket(family)
    s.settimeout(3)
    s.connect((dst, 443))
    s.sendall(hello(sni))
    try:
        s.recv(1)
    except OSError:
        pass
    s.close()
quic = [bytes.fromhex(l.strip()) for l in open(f"{root}/crates/net/tests/fixtures/sniff/curl-http3-initial.hex") if l.strip() and not l.startswith("#")]
for dst in ("198.51.100.10", "2001:db8::10"):
    tcp(dst, "allowed.test")
    tcp(dst, "other.test")
    family = socket.AF_INET6 if ":" in dst else socket.AF_INET
    u = socket.socket(family, socket.SOCK_DGRAM)
    for p in quic:
        u.sendto(p, (dst, 443))
    time.sleep(0.5)
    u.close()
time.sleep(1)
PY

log="$work/kerlico.log"
fail=0
check() {
  if grep -E "$1" "$log" >/dev/null; then echo "PASS $2"; else echo "FAIL $2"; fail=1; fi
}
for dst in '198\.51\.100\.10' '\[2001:db8::10\]'; do
  fam=ipv4; [ "$dst" = '198\.51\.100\.10' ] || fam=ipv6
  check "\[TCP\] [^ ]+ --> $dst:443 match Domain\(allowed\.test,quic\.example\.com\) using hit" "tcp/$fam TLS SNI 命中"
  check "\[TCP\] [^ ]+ --> $dst:443 doesn't match any rule using miss" "tcp/$fam 其他 SNI 未命中"
  # reject 没有多目标 UDP 能力，准入失败时记 warning，出站名同样说明路由结果。
  check "\[UDP\] [^ ]+ --> $dst:443 match Domain\(allowed\.test,quic\.example\.com\) using hit|\[UDP\] dial hit [^ ]+ --> $dst:443" "udp/$fam QUIC SNI 命中"
done
[ "$fail" = 0 ] || { echo "--- kerlico 日志"; cat "$log"; }
exit "$fail"
