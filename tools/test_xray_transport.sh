#!/usr/bin/env bash
# 运行 third_party/xray-transport 自带的测试。该包不在 workspace 内（带独立 dev-dependencies），
# `cargo test -p` 无法选中；这里以它的清单为根，套用根 Cargo.toml 的 [patch] 与 Cargo.lock，
# 保证测到的就是 kerlico 实际链接的 shaped-rustls、h3 与 quinn。
# 用法：tools/test_xray_transport.sh [cargo test 参数...]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
crate="$root/third_party/xray-transport"
xray='https://github.com/aimalygin/xray-rust'
rev='9b06d37466492242a1827f9a16aa91ca4c1b00be'
lock="$crate/Cargo.lock"
cleanup() { rm -f "$lock"; }
trap cleanup EXIT
cp "$root/Cargo.lock" "$lock"
cargo test --manifest-path "$crate/Cargo.toml" \
  --config "patch.crates-io.rustls.path='$root/third_party/shaped-rustls/rustls'" \
  --config "patch.crates-io.h3.path='$root/third_party/h3'" \
  --config "patch.crates-io.ml-kem.path='$root/third_party/ml-kem-legacy'" \
  --config "patch.crates-io.quinn.git='$xray'" --config "patch.crates-io.quinn.rev='$rev'" \
  --config "patch.crates-io.quinn-proto.git='$xray'" --config "patch.crates-io.quinn-proto.rev='$rev'" \
  --config "patch.crates-io.h3-quinn.git='$xray'" --config "patch.crates-io.h3-quinn.rev='$rev'" \
  --config "patch.crates-io.blake3.git='$xray'" --config "patch.crates-io.blake3.rev='$rev'" \
  --config "patch.'$xray'.xray-transport.path='$crate'" \
  "$@"
