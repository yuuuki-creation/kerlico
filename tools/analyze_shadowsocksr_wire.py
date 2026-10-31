"""worker专用：分析三向复现产生的合成回环PCAP，不接受真实凭据或业务抓包。"""
import argparse
import binascii
import collections
import collections.abc
import ctypes
import ctypes.util
import hashlib
import hmac
import json
from pathlib import Path
import struct
import sys
import time

import interop_shadowsocksr as t


def flows(path, node):
    data = path.read_bytes()
    magic = data[:4]
    if magic not in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"]:
        raise RuntimeError("需要普通PCAP格式")
    endian = "<" if magic in [b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"] else ">"
    link = struct.unpack(endian + "I", data[20:24])[0]
    position, result, current = 24, [], {}
    while position + 16 <= len(data):
        epoch, _, size, _ = struct.unpack(endian + "IIII", data[position:position + 16])
        position += 16
        packet = data[position:position + size]
        position += size
        if len(packet) != size:
            raise RuntimeError("PCAP包记录被截断")
        skip = {1: 14, 113: 16, 276: 20, 0: 4, 108: 4, 101: 0}.get(link)
        if skip is None:
            raise RuntimeError("本工具未实现该链路类型")
        packet = packet[skip:]
        if not packet or packet[0] >> 4 != 4 or packet[9] != 6:
            continue
        ip_header = (packet[0] & 15) * 4
        tcp = packet[ip_header:int.from_bytes(packet[2:4], "big")]
        if len(tcp) < 20:
            continue
        src, dst, sequence = struct.unpack("!HHI", tcp[:8])
        direction, peer = ("c", src) if dst == node else ("s", dst)
        flags, offset = tcp[13], (tcp[12] >> 4) * 4
        body = tcp[offset:]
        if direction == "c" and flags & 2:
            flow = current.get(peer)
            if flow is None or flow.get("c_base") != (sequence + 1) & 0xffffffff:
                flow = {"peer_port": peer, "capture_epoch": epoch, "c": [], "s": [], "c_base": (sequence + 1) & 0xffffffff, "s_base": None, "first_s_bytes": None}
                current[peer] = flow
                result.append(flow)
        flow = current.get(peer)
        if flow is None:
            continue
        if direction == "s" and flags & 2:
            flow["s_base"] = (sequence + 1) & 0xffffffff
        if body:
            base = flow[direction + "_base"]
            if base is None:
                raise RuntimeError("抓包缺少TCP握手")
            flow[direction].append(((sequence - base) & 0xffffffff, body))
            if direction == "s" and flow["first_s_bytes"] is None:
                flow["first_s_bytes"] = len(body)
    def assemble(parts):
        output = b""
        for relative, body in sorted(parts):
            if relative > len(output):
                raise RuntimeError("TCP抓包有序号缺口")
            output += body[max(0, len(output) - relative):]
        return output
    for flow in result:
        flow["client"] = assemble(flow["c"])
        flow["server"] = assemble(flow["s"])
    return result


def tls_records(data, client):
    position, records, app, error, ccs = 0, [], b"", None, None
    finished = None
    while position + 5 <= len(data):
        kind, version = data[position], data[position + 1:position + 3]
        length = int.from_bytes(data[position + 3:position + 5], "big")
        expected_version = b"\x03\x01" if client and position == 0 else b"\x03\x03"
        if kind not in {20, 22, 23} or version != expected_version:
            error = {"offset": position, "kind": kind, "prefix": list(data[position:position + 5])}
            break
        end = position + 5 + length
        if end > len(data):
            error = {"offset": position, "incomplete_record": True, "declared_bytes": length, "available_bytes": len(data) - position - 5}
            break
        records.append({"kind": kind, "bytes": length, "offset": position})
        if kind == 23:
            app += data[position + 5:end]
        elif kind == 20:
            ccs = position
        elif kind == 22 and ccs is not None and finished is None:
            finished = (ccs, end)
        position = end
    if error is None and position != len(data):
        error = {"offset": position, "incomplete_header": True, "available_bytes": len(data) - position}
    return records, app, error, finished


def reference_decoder(args, cipher, method, capture_epoch):
    collections.MutableMapping = collections.abc.MutableMapping
    library = ctypes.CDLL(ctypes.util.find_library("crypto"))
    if hasattr(library, "OSSL_PROVIDER_load"):
        library.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        library.OSSL_PROVIDER_load.restype = ctypes.c_void_p
        if not library.OSSL_PROVIDER_load(None, b"default") or not library.OSSL_PROVIDER_load(None, b"legacy"):
            raise RuntimeError("参考密码provider不可用")
    sys.path.insert(0, args.reference_source)
    from shadowsocks import obfs, encrypt
    # 重放捕获时钟，避免旧认证时间戳在后续审计时过期；不改写报文或校验算法。
    time.time = lambda: capture_epoch
    decryptor = encrypt.Encryptor(t.BASE_PASSWORD.encode(), method)
    plain = decryptor.decrypt(cipher)
    layer = obfs.obfs(args.protocol)
    info = obfs.server_info(layer.init_data())
    info.key = encrypt.encrypt_key(t.BASE_PASSWORD.encode(), method)
    info.key_str = t.BASE_PASSWORD.encode()
    info.iv = b"\x42" * decryptor.iv_len()
    info.recv_iv = cipher[:decryptor.iv_len()]
    info.users = {}
    info.update_user_func = lambda user: None
    info.protocol_param = "64"
    info.obfs_param = ""
    info.host, info.port, info.client, info.client_port = "127.0.0.1", 1, "127.0.0.1", 1
    info.head_len, info.tcp_mss, info.buffer_size = 30, 1460, 32768
    info.overhead = layer.get_overhead(False) + (5 if args.obfs.startswith("tls") else 0)
    layer.set_server_info(info)
    decoded, error = b"", None
    try:
        for start in range(0, len(plain), 2048):
            value, _ = layer.server_post_decrypt(plain[start:start + 2048])
            decoded += value
    except Exception as failure:
        error = type(failure).__name__
    expected = b"shadowsocks-interoperability|" * 2048
    return {"cipher_plain_bytes": len(plain), "protocol_plain_bytes": len(decoded), "protocol_error": error, "reference_raw_trans": bool(getattr(layer.obfs, "raw_trans", False)), "address_prefix_valid": decoded[:5] == b"\x01\x7f\0\0\x01", "payload_is_original_prefix": len(decoded) >= 7 and decoded[7:] == expected[:len(decoded) - 7], "received_auth_header": bool(getattr(layer.obfs, "has_recv_header", False))}


def main(args):
    path = Path(args.pcap)
    captured_flows = flows(path, args.node_port)
    if not captured_flows:
        print(json.dumps({"pcap_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "no_tcp_flows": True}))
        return
    flow = max(captured_flows, key=lambda flow: len(flow["client"]))
    client, server = flow["client"], flow["server"]
    result = {"pcap_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "client_bytes": len(client), "server_bytes": len(server), "peer_port": flow["peer_port"]}
    if not client:
        result["no_client_ssr_bytes"] = True
        print(json.dumps(result))
        return
    method = ("none" if args.protocol.startswith("auth_chain") else "aes-128-cfb") if args.method == "auto" else args.method.replace("cfb128", "cfb")
    cipher = client
    if args.obfs == "random_head":
        head = next((size for size in range(8, min(len(client), 103) + 1) if binascii.crc32(client[:size]) == 0xffffffff), None)
        result.update(random_head_crc_valid=head is not None, random_head_bytes=head, server_first_write_bytes=flow["first_s_bytes"])
        if head is None:
            print(json.dumps(result))
            return
        cipher = client[head:]
    elif args.obfs.startswith("tls"):
        records, cipher, error, finished = tls_records(client, True)
        server_records, _, server_error, server_finished = tls_records(server, False)
        key = hashlib.md5(t.BASE_PASSWORD.encode()).digest() + client[44:76]
        valid = lambda data, value: hmac.compare_digest(hmac.new(key, data, hashlib.sha1).digest()[:10], value)
        result.update(client_records=records, client_record_error=error, server_record_error=server_error, client_hello_mac=valid(client[11:33], client[33:43]), server_hello_mac=valid(server[11:33], server[33:43]))
        result["client_finished_mac"] = finished is not None and valid(client[finished[0]:finished[1] - 10], client[finished[1] - 10:finished[1]])
        result["client_app_before_finished"] = any(record["kind"] == 23 and (finished is None or record["offset"] < finished[1]) for record in records)
        result["server_finished_mac"] = server_finished is not None and valid(server[:server_finished[1] - 10], server[server_finished[1] - 10:server_finished[1]])
    else:
        raise RuntimeError("本工具仅分析固定random_head/ticket失败用例")
    result["reference_clock_epoch"] = flow["capture_epoch"]
    result["reference_decode"] = reference_decoder(args, cipher, method, flow["capture_epoch"])
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="分析合成SSR抓包及固定参考解码结果，不改写原始报文")
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--node-port", type=int, required=True)
    parser.add_argument("--reference-source", required=True)
    parser.add_argument("--protocol", choices=t.PROTOCOLS, required=True)
    parser.add_argument("--obfs", choices=["random_head", "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"], required=True)
    parser.add_argument("--method", default="auto")
    main(parser.parse_args())
