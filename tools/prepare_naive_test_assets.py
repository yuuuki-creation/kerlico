#!/usr/bin/env python3
"""专用worker准备固定Naive测试资产；测试自身不联网，源码仅分发元数据。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request

SOURCE_ROOT = Path(__file__).resolve().parents[1]
METADATA = SOURCE_ROOT / "crates/protocol-naive/tests/fixtures/SOURCE.json"
RELATIVE_PATH = Path("naive/blocked-intermediate.der")


def der_tlv(data, offset, tag):
    if offset + 2 > len(data) or data[offset] != tag:
        raise ValueError("固定测试资产DER结构不匹配")
    first = data[offset + 1]
    cursor = offset + 2
    if first < 128:
        length = first
    else:
        count = first & 127
        if not 1 <= count <= 4 or cursor + count > len(data) or data[cursor] == 0:
            raise ValueError("固定测试资产DER长度编码不合法")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
        if length < 128:
            raise ValueError("固定测试资产DER长度编码不规范")
    end = cursor + length
    if end > len(data):
        raise ValueError("固定测试资产DER被截断")
    return cursor, end


def spki_bytes(data):
    certificate, end = der_tlv(data, 0, 0x30)
    if end != len(data):
        raise ValueError("固定测试资产DER包含尾随数据")
    cursor, tbs_end = der_tlv(data, certificate, 0x30)
    if data[cursor] == 0xA0:
        _, cursor = der_tlv(data, cursor, 0xA0)
    for tag in [0x02, 0x30, 0x30, 0x30, 0x30]:
        _, cursor = der_tlv(data, cursor, tag)
    _, spki_end = der_tlv(data, cursor, 0x30)
    if spki_end > tbs_end:
        raise ValueError("固定测试资产SPKI超出证书主体")
    return data[cursor:spki_end]


def verify(data, metadata):
    if len(data) != metadata["byte_len"]:
        raise ValueError("Naive测试资产大小与固定元数据不匹配")
    if hashlib.sha256(data).hexdigest() != metadata["sha256_der"]:
        raise ValueError("Naive测试资产DER摘要与固定元数据不匹配")
    if hashlib.sha256(spki_bytes(data)).hexdigest() != metadata["sha256_spki"]:
        raise ValueError("Naive测试资产SPKI摘要与固定元数据不匹配")


class HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        original = urllib.parse.urlsplit(request.full_url)
        target = urllib.parse.urlsplit(new_url)
        if target.scheme != "https" or target.hostname != original.hostname:
            raise ValueError("固定资产下载拒绝非HTTPS或跨主机重定向")
        return super().redirect_request(request, response, code, message, headers, new_url)


def read_cached(path, metadata):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Naive测试资产缓存必须是普通文件")
    with path.open("rb") as source:
        data = source.read(metadata["byte_len"] + 1)
    verify(data, metadata)


def prepare(assets_dir):
    metadata = json.loads(METADATA.read_text())
    if metadata["relative_path"] != RELATIVE_PATH.as_posix() or metadata["representation"] != "x509-der":
        raise ValueError("Naive测试资产元数据格式不匹配")
    if urllib.parse.urlsplit(metadata["url"]).scheme != "https":
        raise ValueError("固定资产来源必须使用HTTPS")
    destination = assets_dir / RELATIVE_PATH
    if destination.exists() or destination.is_symlink():
        read_cached(destination, metadata)
        return {"status": "cached-verified", "byte_len": metadata["byte_len"], "sha256_der": metadata["sha256_der"], "sha256_spki": metadata["sha256_spki"]}
    report = {"status": "download-rejected"}
    try:
        opener = urllib.request.build_opener(HTTPSOnlyRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        request = urllib.request.Request(metadata["url"], headers={"User-Agent": "kerlico-test-asset-preparation", "Accept-Encoding": "identity"})
        with opener.open(request, timeout=30) as response:
            report["http_content_type"] = response.headers.get("Content-Type")
            report["http_content_length"] = response.headers.get("Content-Length")
            data = response.read(metadata["byte_len"] + 1)
            report["received_byte_len"] = len(data)
        verify(data, metadata)
    except Exception as error:
        report["error"] = type(error).__name__
        print(json.dumps(report, ensure_ascii=False), file=sys.stderr)
        raise
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".naive-asset-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            read_cached(destination, metadata)
    finally:
        temporary.unlink(missing_ok=True)
    report.update({"status": "downloaded-verified", "sha256_der": metadata["sha256_der"], "sha256_spki": metadata["sha256_spki"]})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-dir", type=Path, default=SOURCE_ROOT / ".private/test-assets")
    args = parser.parse_args()
    if os.environ.get("KERLICO_WORKER_ONLY") != "1":
        raise SystemExit("只允许在专用worker准备测试资产")
    os.umask(0o077)
    try:
        report = prepare(args.assets_dir.resolve())
    except Exception as error:
        raise SystemExit("Naive测试资产准备失败：" + str(error)) from error
    print(json.dumps(report, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
