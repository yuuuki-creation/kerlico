#!/usr/bin/env bash
set -euo pipefail
if [[ ${1-} != --isolated ]]; then
    exec unshare --net --mount --propagation private bash "$0" --isolated "$@"
fi
shift

ip link set lo up
mkdir -p /run/netns
mount -t tmpfs tmpfs /run/netns
ip netns add socks-end
ip link add socks-proxy type veth peer name socks-peer netns socks-end
ip addr add 10.51.0.1/24 dev socks-proxy
ip -6 addr add 2001:db8:51::1/64 dev socks-proxy nodad
ip link set socks-proxy up
ip netns exec socks-end ip link set lo up
ip netns exec socks-end ip addr add 10.51.0.2/24 dev socks-peer
ip netns exec socks-end ip link set socks-peer up
ip route add default dev socks-proxy
ip -6 route add default dev socks-proxy
exec "$@"
