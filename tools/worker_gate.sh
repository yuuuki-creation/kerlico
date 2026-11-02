#!/usr/bin/env bash
# 发行门禁：在 worker 上对一个提交执行 fmt、clippy、全量测试与 release 构建。
# 用法：tools/worker_gate.sh [别名=perf-01] [提交=HEAD]
set -euo pipefail

alias="${1:-perf-01}"
rev="$(git rev-parse "${2:-HEAD}")"
root="${KERLICO_WORKER_ROOT:-/srv/build/kerlico}/gate"
run() { ssh -F "${KERLICO_SSH_CONFIG:-.private/machines/ssh_config}" -o BatchMode=yes -o ServerAliveInterval=30 "$alias" "$@"; }

git -c core.autocrlf=false archive "$rev" | gzip | run "mkdir -p '$root' && rm -rf '$root/new' && mkdir '$root/new' \
  && tar -xz -C '$root/new' && mkdir -p '$root/src' && rsync -rc --delete '$root/new/' '$root/src/'"

run "cat > '$root/job.sh'" <<EOF
cd '$root/src'
export CARGO_TARGET_DIR='$root/target' CARGO_BUILD_JOBS=6 CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RUST_TEST_THREADS=1
export KERLICO_TEST_ASSETS_DIR='${root%/gate}/resume-test-assets' KERLICO_WORKER_ALIAS='$alias'
export PATH="\$HOME/.cargo/bin:\$PATH" PROTOC="\$(bash tools/fetch_protoc.sh '${root%/gate}')"
failed=0
step() { echo "=== \$1"; shift; "\$@"; code=\$?; echo "=== exit \$code"; [ "\$code" = 0 ] || failed=1; }
set +e
step fmt cargo fmt --all --check
step clippy cargo clippy --workspace --all-targets --locked --keep-going --no-deps -- -D warnings
step test cargo test --workspace --all-targets --locked --no-fail-fast
step test-third-party cargo test --locked -p zerotier-node
step release cargo build --release --locked -p kerlico
step notices sh -c 'python3 tools/gen_third_party_notices.py > "\$CARGO_TARGET_DIR/release/THIRD_PARTY_NOTICES.txt"'
sha256sum "\$CARGO_TARGET_DIR/release/kerlico" "\$CARGO_TARGET_DIR/release/THIRD_PARTY_NOTICES.txt"
echo "=== gate \$failed"
EOF
run "rm -f '$root/done'; cd '$root' && nohup setsid nice -n 10 sh -c 'bash job.sh > gate.log 2>&1; touch done' > /dev/null 2>&1 &"

until run "test -f '$root/done'"; do sleep 60; done

echo "gate $rev on $alias"
run "grep -E '^test .* FAILED|^test result: .*[1-9][0-9]* failed|^error(\[|:)' '$root/gate.log' | head -120"
run "grep -E '^=== |^[0-9a-f]{64} ' '$root/gate.log'"
run "grep -qx '=== gate 0' '$root/gate.log'" || { echo "gate failed" >&2; exit 1; }
