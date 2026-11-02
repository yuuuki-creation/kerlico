#!/usr/bin/env bash
# 在 glibc 较低的 worker 上从提交构建发行二进制，下载产物并生成 SHA256SUMS。
# 用法：tools/worker_release.sh 版本 提交 输出目录 [别名=perf-02]
set -euo pipefail

version="$1"
rev="$(git rev-parse "$2")"
out="$3"
alias="${4:-perf-02}"
root="${KERLICO_WORKER_ROOT:-/srv/build/kerlico}/release-$version"
run() { ssh -F "${KERLICO_SSH_CONFIG:-.private/machines/ssh_config}" -o BatchMode=yes -o ServerAliveInterval=30 "$alias" "$@"; }

git -c core.autocrlf=false archive "$rev" | gzip | run "rm -rf '$root/src' && mkdir -p '$root/src' && tar -xz -C '$root/src' && cd '$root/src' \
  && export PATH=\"\$HOME/.cargo/bin:\$PATH\" CARGO_TARGET_DIR='$root/target' CARGO_INCREMENTAL=0 \
  && export PROTOC=\"\$(bash tools/fetch_protoc.sh '${root%/*}')\" \
  && nice -n 10 cargo build --release --locked -p kerlico \
  && python3 tools/gen_third_party_notices.py > '$root/target/release/THIRD_PARTY_NOTICES.txt' \
  && '$root/target/release/kerlico' --lang en check -c examples/config-v2-minimal.json"

mkdir -p "$out"
for name in kerlico THIRD_PARTY_NOTICES.txt; do
  run "cat '$root/target/release/$name'" > "$out/$name"
done
chmod +x "$out/kerlico"
(cd "$out" && sha256sum --binary kerlico THIRD_PARTY_NOTICES.txt | sed 's/ \*/  /' > SHA256SUMS && cat SHA256SUMS)
