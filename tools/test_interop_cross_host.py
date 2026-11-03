#!/usr/bin/env python3
"""跨机矩阵的回显判定：慢但持续有进展的路径不能被判成停滞。"""
import socket
import threading
import time
import unittest

import interop_cross_host as tool


def throttled_echo(server, chunk, interval):
    client, _ = server.accept()
    with client:
        while data := client.recv(chunk):
            client.sendall(data)
            time.sleep(interval)


class ExchangeTest(unittest.TestCase):
    def slow_stream(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 14)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        threading.Thread(target=throttled_echo, args=(server, 1 << 14, 0.03), daemon=True).start()
        stream = socket.socket()
        self.addCleanup(stream.close)
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 14)
        stream.connect(server.getsockname())
        stream.settimeout(1.0)
        return stream

    def test_exchange_outlasting_stall_limit_passes_while_data_moves(self):
        result = tool.exchange(self.slow_stream(), 1 << 21, stall=1.0)
        self.assertTrue(result["ok"], result)

    def test_watch_reports_how_much_was_sent_when_peer_stops(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        stream = socket.socket()
        self.addCleanup(stream.close)
        stream.connect(server.getsockname())
        started = time.monotonic()
        result = tool.exchange(stream, 1 << 16, stall=0.3)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(result["error"], "stall@0 sent=65536")


if __name__ == "__main__":
    unittest.main()
