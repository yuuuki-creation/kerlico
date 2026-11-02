"""等 Mihomo 真正开始处理连接。

Mihomo 的 ApplyConfig 先开监听，tunnel.OnRunning 在其后；这段窗口里到达的 TCP 被直接关闭、UDP 被丢弃，且不写日志。
只等端口可连的脚本会把这个窗口记成被测协议的提前 EOF。探针走专用入口和 DIRECT，不经过被测协议，不会掩盖被测路径上的失败。
"""
import socket
import struct
import time

PROBE = "tunnel-probe"


def add_probe(config, port):
    """在 listeners 与 rules 都写好后调用。port 由脚本的端口分配器给出，避免与它分配的其他端口相撞。"""
    config.setdefault("listeners", []).append({"name": PROBE, "type": "socks", "listen": "127.0.0.1", "port": port, "udp": False})
    config["rules"].insert(0, f"IN-NAME,{PROBE},DIRECT")
    return config


def _reaches(probe_port, sink):
    with socket.create_connection(("127.0.0.1", probe_port), .2) as stream:
        stream.settimeout(.2)
        stream.sendall(b"\x05\x01\x00")
        stream.recv(2)
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", sink.getsockname()[1]))
        sink.accept()[0].close()


def wait_running(child, config, timeout=12):
    """child 是 subprocess.Popen。Mihomo 的 SOCKS 入口先回成功再拨号，所以以目标收到连接为准。"""
    probe_port = next(row["port"] for row in config["listeners"] if row["name"] == PROBE)
    with socket.socket() as sink:
        sink.bind(("127.0.0.1", 0))
        sink.listen(8)
        sink.settimeout(.05)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("Mihomo 在进入运行状态前退出")
            try:
                _reaches(probe_port, sink)
                return
            except OSError:
                time.sleep(.005)
    raise TimeoutError("Mihomo tunnel 未进入运行状态")
