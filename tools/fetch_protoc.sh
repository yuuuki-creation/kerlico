#!/usr/bin/env bash
# 把固定版本的 protoc 下载到指定目录并打印其路径；已存在时直接复用。上游 EasyTier 的 build.rs 需要它。
# 用法：export PROTOC="$(tools/fetch_protoc.sh 目录)"
set -euo pipefail

version=28.3
sha256=0ad949f04a6a174da83cdcbdb36dee0a4925272a5b6d83f79a6bf9852076d53f
dir="$1/protoc-$version"
bin="$dir/bin/protoc"

if [ ! -x "$bin" ]; then
  mkdir -p "$dir"
  zip="$dir/protoc.zip"
  curl -fsSL --max-time 120 -o "$zip" \
    "https://github.com/protocolbuffers/protobuf/releases/download/v$version/protoc-$version-linux-x86_64.zip"
  echo "$sha256  $zip" | sha256sum -c --quiet >&2
  python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$zip" "$dir"
  chmod +x "$bin"
  rm -f "$zip"
fi
echo "$bin"
