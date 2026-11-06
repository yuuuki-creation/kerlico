#!/usr/bin/env bash
# tproxy 入站端到端验证：只在临时 netns 内建拓扑、策略路由与 nft TPROXY 规则，不改宿主网络。
# 用法（root）：tools/tproxy_netns_e2e.sh <kerlico 可执行文件>
# 拓扑：client ns --veth-- proxy ns（kerlico tproxy + direct）--veth-- server ns（持有原始目标地址的回显服务）
set -euo pipefail

bin="$(realpath "${1:?用法：$0 <kerlico 可执行文件>}")"
[ "$(id -u)" = 0 ] || { echo "需要 root 运行" >&2; exit 2; }
for tool in ip nft python3; do command -v "$tool" >/dev/null || { echo "缺少 $tool" >&2; exit 2; }; done

tag="kt$$"
c="$tag-c" p="$tag-p" s="$tag-s"
work="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for ns in "$c" "$p" "$s"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

port=7893
dst4=198.51.100.10 dst6=2001:db8::10 echo_port=9000

for ns in "$c" "$p" "$s"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done
ip -n "$c" link add c0 type veth peer name p0 netns "$p"
ip -n "$s" link add s1 type veth peer name p1 netns "$p"

ip -n "$c" addr add 192.0.2.2/24 dev c0
ip -n "$c" addr add 2001:db8:1::2/64 dev c0 nodad
ip -n "$c" link set c0 up
ip -n "$c" route add default via 192.0.2.1
ip -n "$c" -6 route add default via 2001:db8:1::1

ip -n "$p" addr add 192.0.2.1/24 dev p0
ip -n "$p" addr add 2001:db8:1::1/64 dev p0 nodad
ip -n "$p" addr add 203.0.113.1/24 dev p1
ip -n "$p" addr add 2001:db8:2::1/64 dev p1 nodad
ip -n "$p" link set p0 up
ip -n "$p" link set p1 up
ip -n "$p" route add "$dst4/32" via 203.0.113.2
ip -n "$p" -6 route add "$dst6/128" via 2001:db8:2::2
ip netns exec "$p" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 \
  net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv4.conf.p0.rp_filter=0

ip -n "$s" addr add 203.0.113.2/24 dev s1
ip -n "$s" addr add 2001:db8:2::2/64 dev s1 nodad
ip -n "$s" addr add "$dst4/32" dev lo
ip -n "$s" addr add "$dst6/128" dev lo nodad
ip -n "$s" link set s1 up
ip -n "$s" route add default via 203.0.113.1
ip -n "$s" -6 route add default via 2001:db8:2::1

ip -n "$p" rule add fwmark 1 lookup 100
ip -n "$p" route add local 0.0.0.0/0 dev lo table 100
ip -n "$p" -6 rule add fwmark 1 lookup 100
ip -n "$p" -6 route add local ::/0 dev lo table 100
ip netns exec "$p" nft -f - <<EOF
table inet kerlico_e2e {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "p0" ip daddr $dst4 meta l4proto { tcp, udp } tproxy ip to :$port meta mark set 1 accept
    iifname "p0" ip6 daddr $dst6 meta l4proto { tcp, udp } tproxy ip6 to :$port meta mark set 1 accept
  }
}
EOF

cat >"$work/config.json" <<EOF
{
  "version": 2,
  "lan_allowed_ips": ["0.0.0.0/0", "::/0"],
  "outbounds": [{ "tag": "direct", "type": "direct" }],
  "local_inbounds": [
    { "tag": "tproxy-v4", "type": "tproxy", "listen": "0.0.0.0:$port", "outbound": "direct" },
    { "tag": "tproxy-v6", "type": "tproxy", "listen": "[::]:$port", "outbound": "direct" }
  ]
}
EOF

cat >"$work/server.py" <<'EOF'
import socket, sys, threading
log = open(sys.argv[1], "a", buffering=1)
port = int(sys.argv[2])
def udp(family, host):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        data, peer = s.recvfrom(65535)
        log.write(f"udp {s.getsockname()[0]} {peer[0]} {data.decode()}\n")
        s.sendto(data, peer)
def tcp_conn(conn):
    with conn:
        data = conn.recv(65535)
        log.write(f"tcp {conn.getsockname()[0]} {conn.getpeername()[0]} {data.decode()}\n")
        conn.sendall(data)
def tcp(family, host):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
    while True:
        conn, _ = s.accept()
        threading.Thread(target=tcp_conn, args=(conn,), daemon=True).start()
for family, host in ((socket.AF_INET, sys.argv[3]), (socket.AF_INET6, sys.argv[4])):
    for fn in (udp, tcp):
        threading.Thread(target=fn, args=(family, host), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
EOF

cat >"$work/client.py" <<'EOF'
import socket, sys
proto, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
if proto == "udp":
    sockets = [socket.socket(family, socket.SOCK_DGRAM) for _ in range(2)]
    for index, s in enumerate(sockets):
        s.settimeout(5)
        for seq in range(2):
            payload = f"udp-{host}-{index}-{seq}".encode()
            s.sendto(payload, (host, port))
            data, source = s.recvfrom(65535)
            assert data == payload, f"回显内容不符：{data!r}"
            assert (source[0], source[1]) == (host, port), f"回包源地址 {source[:2]} 不是原始目标"
else:
    with socket.create_connection((host, port), timeout=5) as s:
        payload = f"tcp-{host}".encode()
        s.sendall(payload)
        data = s.recv(65535)
        assert data == payload, f"回显内容不符：{data!r}"
print(f"client ok {proto} {host}")
EOF

ip netns exec "$s" python3 "$work/server.py" "$work/server.log" "$echo_port" "$dst4" "$dst6" >"$work/server.out" 2>&1 &
pids+=($!)
ip netns exec "$p" "$bin" run -c "$work/config.json" >"$work/kerlico.log" 2>&1 &
pids+=($!)

ready=0
for _ in $(seq 50); do
  if grep -q ready "$work/server.out" 2>/dev/null \
    && [ "$(ip netns exec "$p" ss -Hlnu "sport = :$port" | wc -l)" -ge 2 ]; then
    ready=1
    break
  fi
  python3 -c 'import time; time.sleep(0.1)'
done
if [ "$ready" != 1 ]; then
  echo "kerlico 或回显服务未就绪" >&2
  cat "$work/kerlico.log" "$work/server.out" >&2
  exit 1
fi

failed=0
for proto in udp tcp; do
  for dst in "$dst4" "$dst6"; do
    family=ipv4 egress=203.0.113.1
    [[ "$dst" == *:* ]] && family=ipv6 egress=2001:db8:2::1
    # 服务端看到的来源必须是代理出口；若是客户端地址，说明报文被直接转发而没有经过 kerlico。
    if ip netns exec "$c" python3 "$work/client.py" "$proto" "$dst" "$echo_port" \
      && grep -q "^$proto $dst $egress " "$work/server.log"; then
      echo "PASS $proto/$family"
    else
      echo "FAIL $proto/$family"
      failed=1
    fi
  done
done
if [ "$failed" != 0 ]; then
  echo "--- server.log" >&2; cat "$work/server.log" >&2 || true
  echo "--- kerlico.log" >&2; tail -n 50 "$work/kerlico.log" >&2
fi
exit "$failed"
