"""Read the selected TLS version and cipher suite from a captured Ethernet/IPv4 ServerHello."""
from pathlib import Path
import struct


def negotiated(path):
    if not Path(path).exists():
        return None
    raw=Path(path).read_bytes()
    if len(raw)<40:
        return None
    order={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">"}.get(raw[:4])
    if order is None or struct.unpack_from(order+"I",raw,20)[0]!=1:
        return None
    captured=struct.unpack_from(order+"I",raw,32)[0]
    packet=raw[40:40+captured]
    if len(packet)<54 or packet[12:14]!=b"\x08\x00":
        return None
    tcp=14+(packet[14]&15)*4
    if len(packet)<tcp+20:
        return None
    tls=tcp+4*(packet[tcp+12]>>4)
    hello=packet[tls+9:]
    if len(hello)<38 or packet[tls]!=22 or packet[tls+5]!=2:
        return None
    offset=35+hello[34]
    if len(hello)<offset+3:
        return None
    cipher=int.from_bytes(hello[offset:offset+2],"big")
    legacy_version=hello[:2]
    version=legacy_version
    source="legacy_version"
    at=offset+5
    terminal=min(len(hello),at+int.from_bytes(hello[offset+3:at],"big"))
    while at+4<=terminal:
        kind=int.from_bytes(hello[at:at+2],"big")
        n=int.from_bytes(hello[at+2:at+4],"big")
        if kind==43 and n==2 and at+6<=terminal:
            version=hello[at+4:at+6]
            source="supported_versions"
        at+=4+n
    names={0x1301:"TLS_AES_128_GCM_SHA256",0x1302:"TLS_AES_256_GCM_SHA384",
           0x1303:"TLS_CHACHA20_POLY1305_SHA256"}
    if cipher in names and source=="legacy_version":
        # A potentially fragmented TLS 1.3 ServerHello carries 0x0303 in its legacy field.
        version=bytes.fromhex("0304")
        source="tls13_only_cipher"
    return dict(cipher_id=f"0x{cipher:04x}",cipher=names.get(cipher),version_id="0x"+version.hex(),
                version_source=source, legacy_version="0x"+legacy_version.hex())
