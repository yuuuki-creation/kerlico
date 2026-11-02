from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import interop_trusttunnel as tt


TARGET = ("127.0.0.1", 20000)
PIN_ERROR = "certificate fingerprints do not match"
NAME_ERROR = "x509: certificate is valid for tt.example.invalid, not wrong.example.invalid"


def dial_log(network, error, target=TARGET):
    return (f'level=warning msg="[{network.upper()}] dial proxy (match Match/) '
            f'127.0.0.1:21000 --> {tt.address(*target)} error: {error}"\n').encode()


class TlsNegativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.positive = tt.TlsProbe(tt.ProbeState.BUSINESS_SUCCESS, True, True, True)
        self.negative = tt.TlsProbe(tt.ProbeState.REQUEST_FAILED, True, True, True)

    def result(self, variant="wrong-ca", network="tcp", positive=None, negative=None):
        records = []
        tt.record_tls_negative(records, "isolated-case", variant, network, TARGET,
                               self.positive if positive is None else positive,
                               self.negative if negative is None else negative)
        return records[0]

    def test_each_expected_rejection_requires_its_own_protocol_and_error(self):
        for variant, error in [("wrong-ca", PIN_ERROR), ("wrong-name", NAME_ERROR)]:
            for network in ("tcp", "udp"):
                with self.subTest(variant=variant, network=network):
                    result = self.result(variant, network, negative=replace(self.negative, log=dial_log(network, error)))
                    self.assertEqual(result["outcome"], "pass")
                    self.assertEqual(result["tls_negative_state"], "tls-rejected")

    def test_cross_category_and_other_tls_failures_do_not_pass(self):
        for variant, error in [("wrong-ca", NAME_ERROR), ("wrong-name", PIN_ERROR),
                               ("wrong-ca", "x509: certificate signed by unknown authority"),
                               ("wrong-name", "x509: certificate has expired or is not yet valid")]:
            with self.subTest(variant=variant, error=error):
                result = self.result(variant, negative=replace(self.negative, log=dial_log("tcp", error)))
                self.assertEqual(result["outcome"], "fail")
                self.assertEqual(result["tls_negative_state"], "unrelated-failure")

    def test_crash_missing_listener_and_failed_setup_cannot_reuse_a_tls_error(self):
        with_error = replace(self.negative, log=dial_log("tcp", PIN_ERROR))
        failures = [replace(with_error, client_running=False), replace(with_error, server_running=False),
                    replace(with_error, listener_owned=False), replace(with_error, state=tt.ProbeState.SETUP_FAILED)]
        for observation in failures:
            with self.subTest(observation=observation):
                result = self.result(negative=observation)
                self.assertEqual(result["outcome"], "fail")
                self.assertEqual(result["tls_negative_state"], "unrelated-failure")

    def test_eof_timeout_and_empty_log_are_insufficient(self):
        for error_type in ("RuntimeError", "TimeoutError", "ConnectionRefusedError", None):
            with self.subTest(error_type=error_type):
                result = self.result(negative=replace(self.negative, error_type=error_type))
                self.assertEqual(result["outcome"], "fail")
                self.assertEqual(result["tls_negative_state"], "insufficient-evidence")

    def test_connected_tunnel_or_business_reply_is_never_a_rejection(self):
        for state in (tt.ProbeState.TUNNEL_ESTABLISHED, tt.ProbeState.BUSINESS_SUCCESS):
            for network in ("tcp", "udp"):
                with self.subTest(state=state, network=network):
                    result = self.result(network=network, negative=replace(self.negative, state=state, log=dial_log(network, PIN_ERROR)))
                    self.assertEqual(result["outcome"], "fail")
                    self.assertEqual(result["tls_negative_state"], "business-accepted")

    def test_missing_or_invalid_positive_control_cannot_pass(self):
        invalid_controls = [replace(self.positive, state=tt.ProbeState.REQUEST_FAILED),
                            replace(self.positive, state=tt.ProbeState.TUNNEL_ESTABLISHED),
                            replace(self.positive, client_running=False),
                            replace(self.positive, server_running=False),
                            replace(self.positive, listener_owned=False)]
        for control in invalid_controls:
            with self.subTest(control=control):
                result = self.result(positive=control, negative=replace(self.negative, log=dial_log("tcp", PIN_ERROR)))
                self.assertEqual(result["outcome"], "fail")
                self.assertEqual(result["tls_negative_state"], "insufficient-evidence")

    def test_unattributed_other_target_other_network_or_health_log_cannot_pass(self):
        for log in (dial_log("tcp", PIN_ERROR, ("127.0.0.1", 20001)), dial_log("udp", PIN_ERROR),
                    ("health check error: "+PIN_ERROR).encode(),
                    dial_log("tcp", PIN_ERROR).replace(b"dial proxy", b"dial another-proxy")):
            with self.subTest(log=log):
                result = self.result(negative=replace(self.negative, log=log))
                self.assertEqual(result["outcome"], "fail")
                self.assertEqual(result["tls_negative_state"], "insufficient-evidence")

    def test_mixed_expected_and_unrelated_dial_failures_do_not_pass(self):
        result = self.result(negative=replace(self.negative, log=dial_log("tcp", PIN_ERROR)+dial_log("tcp", "connection refused")))
        self.assertEqual(result["outcome"], "fail")
        self.assertEqual(result["tls_negative_state"], "unrelated-failure")

    def test_successful_proxy_dial_followed_by_business_timeout_cannot_pass(self):
        for network in ("tcp", "udp"):
            with self.subTest(network=network):
                success = f'[{network.upper()}] 127.0.0.1:21000 --> 127.0.0.1:20000 match Match using proxy\n'.encode()
                result = self.result(network=network, negative=replace(self.negative, log=dial_log(network, PIN_ERROR)+success,
                                                                       error_type="TimeoutError"))
                self.assertEqual(result["outcome"], "fail")
                self.assertEqual(result["tls_negative_state"], "business-accepted")

    def test_probe_ignores_pre_request_and_other_case_logs(self):
        child = SimpleNamespace(poll=lambda: None)
        args = SimpleNamespace(peer="isolated-peer", mtls=False)
        for current_log, expected in [(b"", "insufficient-evidence"), (dial_log("tcp", PIN_ERROR), "tls-rejected")]:
            with self.subTest(expected=expected), TemporaryDirectory() as temporary:
                directory = Path(temporary)/"negative"

                @contextmanager
                def fake_process(command, path, label):
                    (path/"client.log").write_bytes(dial_log("tcp", PIN_ERROR))
                    (path/"another-case.log").write_bytes(dial_log("tcp", PIN_ERROR))
                    yield child

                def failed_request(*args):
                    with (directory/"client.log").open("ab") as log:
                        log.write(current_log)
                    raise RuntimeError("SOCKS目标被拒绝")

                with patch.object(tt, "port", return_value=22000), \
                     patch.object(tt, "mihomo_client", return_value={"proxies": [{}]}), \
                     patch.object(tt, "process", side_effect=fake_process), \
                     patch.object(tt, "ready"), patch.object(tt, "socket_owned", return_value=True), \
                     patch.object(tt, "socks_open", side_effect=failed_request), \
                     patch.object(tt.time, "monotonic", side_effect=[0, 2]):
                    observed = tt.observe_tls_probe(args, directory, child, "127.0.0.1", 23000,
                                                    "isolated-test-secret", "h2", {}, TARGET, "tcp", "wrong-ca")
                self.assertEqual(observed.log, current_log)
                self.assertGreater(observed.log_start, 0)
                self.assertEqual(self.result(negative=observed)["tls_negative_state"], expected)

    def test_probe_keeps_established_tunnel_when_later_business_io_fails(self):
        child = SimpleNamespace(poll=lambda: None)
        args = SimpleNamespace(peer="isolated-peer", mtls=False)
        for network in ("tcp", "udp"):
            with self.subTest(network=network), TemporaryDirectory() as temporary:
                directory = Path(temporary)/"negative"

                @contextmanager
                def fake_process(command, path, label):
                    (path/"client.log").write_bytes(dial_log(network, PIN_ERROR))
                    yield child

                def bad_udp_reply(number, target, payload, received):
                    received()
                    raise RuntimeError("SOCKS UDP来源不符")

                with patch.object(tt, "port", return_value=22000), \
                     patch.object(tt, "mihomo_client", return_value={"proxies": [{}]}), \
                     patch.object(tt, "process", side_effect=fake_process), \
                     patch.object(tt, "ready"), patch.object(tt, "socket_owned", return_value=True), \
                     patch.object(tt, "socks_open", return_value=(MagicMock(), None)), \
                     patch.object(tt, "exact", side_effect=[b"hello|", RuntimeError("目标数据提前结束")]), \
                     patch.object(tt, "socks_udp", side_effect=bad_udp_reply):
                    observed = tt.observe_tls_probe(args, directory, child, "127.0.0.1", 23000,
                                                    "isolated-test-secret", "h2", {}, TARGET, network, "wrong-ca")
                self.assertEqual(observed.state, tt.ProbeState.TUNNEL_ESTABLISHED)
                self.assertEqual(self.result(network=network, negative=observed)["outcome"], "fail")

    def test_local_socks_success_is_not_remote_tls_handshake_success(self):
        child = SimpleNamespace(poll=lambda: None)
        args = SimpleNamespace(peer="isolated-peer", mtls=False)
        for current_log, expected in [(b"", "insufficient-evidence"), (dial_log("tcp", PIN_ERROR), "tls-rejected")]:
            with self.subTest(expected=expected), TemporaryDirectory() as temporary:
                directory = Path(temporary)/"negative"

                @contextmanager
                def fake_process(command, path, label):
                    (path/"client.log").write_bytes(b"")
                    yield child

                def ended_before_greeting(*args):
                    with (directory/"client.log").open("ab") as log:
                        log.write(current_log)
                    raise RuntimeError("目标数据提前结束")

                with patch.object(tt, "port", return_value=22000), \
                     patch.object(tt, "mihomo_client", return_value={"proxies": [{}]}), \
                     patch.object(tt, "process", side_effect=fake_process), \
                     patch.object(tt, "ready"), patch.object(tt, "socket_owned", return_value=True), \
                     patch.object(tt, "socks_open", return_value=(MagicMock(), None)), \
                     patch.object(tt, "exact", side_effect=ended_before_greeting), \
                     patch.object(tt.time, "monotonic", side_effect=[0, 2]):
                    observed = tt.observe_tls_probe(args, directory, child, "127.0.0.1", 23000,
                                                    "isolated-test-secret", "h2", {}, TARGET, "tcp", "wrong-ca")
                self.assertEqual(observed.state, tt.ProbeState.REQUEST_FAILED)
                self.assertEqual(self.result(negative=observed)["tls_negative_state"], expected)


if __name__ == "__main__":
    unittest.main()
