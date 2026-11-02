#!/usr/bin/env bash
# 把工作树（含未提交改动）同步到 worker，在其中运行命令。--pull 把命令改动的文件拉回本机。
# 用法：tools/worker_run.sh [--pull] 别名 命令...
set -euo pipefail

pull=0
if [ "${1:-}" = "--pull" ]; then
  pull=1
  shift
fi
alias="$1"
shift
root="${KERLICO_WORKER_ROOT:-/srv/build/kerlico}/gate"
run() { ssh -F .private/machines/ssh_config -o BatchMode=yes -o ServerAliveInterval=30 "$alias" "$@"; }

index="$(mktemp)"
trap 'rm -f "$index"' EXIT
cp "$(git rev-parse --git-dir)/index" "$index"
GIT_INDEX_FILE="$index" git add -A 2>/dev/null
tree="$(GIT_INDEX_FILE="$index" git write-tree)"

git -c core.autocrlf=false archive "$tree" | gzip | run "mkdir -p '$root' && rm -rf '$root/new' && mkdir '$root/new' \
  && tar -xz -C '$root/new' && mkdir -p '$root/src' && rsync -rc --delete '$root/new/' '$root/src/' && touch '$root/marker'"

status=0
run "cd '$root/src' && export CARGO_TARGET_DIR='$root/target' CARGO_BUILD_JOBS=6 CARGO_INCREMENTAL=0 \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 RUST_TEST_THREADS=1 \
  KERLICO_TEST_ASSETS_DIR='${root%/gate}/resume-test-assets' KERLICO_WORKER_ALIAS='$alias' \
  PATH=\"\$HOME/.cargo/bin:\$PATH\"; $*" || status=$?

if [ "$pull" = 1 ]; then
  run "cd '$root/src' && find . -type f -newer '$root/marker' -print0 | tar --null -T - -cz" | tar -xz
fi
exit "$status"
