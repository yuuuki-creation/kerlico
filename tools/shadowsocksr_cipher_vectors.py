"""仅在 worker 从原生 OpenSSL/libsodium 与固定 table 参考生成 SSR 合成 cipher 向量。"""
import argparse
import collections
import collections.abc
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def key(password, size):
    output, previous = b"", b""
    while len(output) < size:
        previous = hashlib.md5(previous + password).digest()
        output += previous
    return output[:size]


def main(args):
    sys.dont_write_bytecode = True
    collections.MutableMapping = collections.abc.MutableMapping
    sys.path.insert(0, args.reference)
    from shadowsocks.crypto.table import TableCipher
    methods = [f"{family}-{bits}-{mode}" for family in ["aes", "camellia"] for bits in [128, 192, 256] for mode in ["ctr", "cfb1", "cfb8", "cfb128", "ofb"]]
    methods += ["none", "rc4", "rc4-md5", "rc4-md5-6", "table", "chacha20", "chacha20-ietf", "xchacha20", "salsa20"]
    password = b"synthetic-cipher-vector-secret"
    plain = bytes(range(256)) * 2 + b"tail"
    records = []
    sodium = ctypes.CDLL(ctypes.util.find_library("sodium"))
    for method in methods:
        bits = int(method.split("-")[1]) if method.startswith(("aes-", "camellia-")) else 256 if method in {"chacha20", "chacha20-ietf", "xchacha20", "salsa20"} else 128
        size = 0 if method in {"none", "table", "rc4"} else 6 if method == "rc4-md5-6" else 8 if method in {"chacha20", "salsa20"} else 12 if method == "chacha20-ietf" else 24 if method == "xchacha20" else 16
        material, iv = key(password, bits // 8), bytes(range(size))
        if method == "none":
            encoded = plain
        elif method == "table":
            encoded = TableCipher("table", material, b"", 1).update(plain)
        elif method in {"chacha20", "chacha20-ietf", "xchacha20", "salsa20"}:
            name = method.replace("-ietf", "_ietf")
            function = getattr(sodium, "crypto_stream_" + name + "_xor_ic")
            function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_uint32 if method.endswith("-ietf") else ctypes.c_ulonglong, ctypes.c_char_p]
            function.restype = ctypes.c_int
            output = ctypes.create_string_buffer(len(plain))
            assert function(output, plain, len(plain), iv, 0, material) == 0
            encoded = output.raw
        else:
            name = "rc4" if method.startswith("rc4") else method.replace("cfb128", "cfb")
            actual = hashlib.md5(material + iv).digest() if method.startswith("rc4-md5") else material
            command = ["openssl", "enc", "-" + name, "-e", "-nopad", "-provider", "default", "-provider", "legacy", "-K", actual.hex()]
            if iv and not method.startswith("rc4"):
                command += ["-iv", iv.hex()]
            encoded = subprocess.run(command, input=plain, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
        records.append({"method": method, "key": list(material), "iv": list(iv), "ciphertext": list(encoded)})
    Path(args.output).write_text(json.dumps({"plain": list(plain), "records": records}, separators=(",", ":")))
    print("独立 cipher 向量已生成：", len(records))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output", required=True)
    main(parser.parse_args())
