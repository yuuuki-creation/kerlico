#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} != --origin ]]; then
    entry=$(realpath "$0")
    exec bash "$(dirname "$entry")/../socks_bench/veth.sh" bash "$entry" --origin "$@"
fi
shift
ip netns add study-origin
ip link add origin-proxy type veth peer name origin-peer netns study-origin
ip addr add 10.52.0.1/24 dev origin-proxy
ip link set origin-proxy up
ip -n study-origin link set lo up
ip -n study-origin addr add 10.52.0.2/24 dev origin-peer
ip -n study-origin link set origin-peer up
export KERLICO_STUDY_SEPARATE_ORIGIN=1
exec "$@"
