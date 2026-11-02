"""验证结果汇总机制，不替代真实WireGuard互通矩阵。"""

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack


module_path = Path(os.environ.get("WIREGUARD_INTEROP_MODULE", Path(__file__).with_name("run.py")))
spec = importlib.util.spec_from_file_location("wireguard_interop_run", module_path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReportTests(unittest.TestCase):
    def invoke(self, extra, operation=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        binary = root / "peer"
        binary.write_bytes(b"report-mechanism-test")
        run_dir = root / "result"
        arguments = ["run.py", "--rust-peer", str(binary), "--go-peer", str(binary), "--run-dir", str(run_dir), *extra]
        def succeeded(args, role, ipv6, psk, rows):
            rows.append({"case":f"{role}-outer{6 if ipv6 else 4}-psk{int(psk)}", "check":"observed", "result":"passed"})
        with patch.object(runner.sys, "argv", arguments), patch.object(runner, "one_case", operation or succeeded), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exited:
            runner.main()
        return exited.exception.code, json.loads((run_dir / "results.json").read_text()), run_dir

    def test_all_cases_are_required_for_complete(self):
        code, report, _ = self.invoke([])
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        self.assertEqual(len(report["rows"]), 8)

    def test_one_role_is_incomplete_and_names_missing_cases(self):
        code, report, _ = self.invoke(["--role", "inbound"])
        self.assertEqual(code, 0)
        self.assertFalse(report["complete"])
        missing = {row["case"] for row in report["rows"] if row["result"] == "unverified"}
        self.assertEqual(missing, {f"outbound-outer{family}-psk{psk}" for family in [4, 6] for psk in [0, 1]})

    def test_case_selection_cannot_claim_complete(self):
        code, report, _ = self.invoke(["--case", "inbound-outer4-psk0"])
        self.assertEqual(code, 0)
        self.assertFalse(report["complete"])
        self.assertEqual(sum(row["result"] == "unverified" for row in report["rows"]), 7)

    def test_parallel_cases_are_merged_once_each(self):
        code, report, _ = self.invoke(["--jobs", "4"])
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        self.assertEqual(len(report["rows"]), 8)
        self.assertEqual(len({row["case"] for row in report["rows"]}), 8)

    def test_failure_retains_private_diagnostic_without_public_details(self):
        def failed(*_):
            raise RuntimeError("private-diagnostic-marker")
        code, report, directory = self.invoke([], failed)
        self.assertEqual(code, 1)
        self.assertFalse(report["complete"])
        self.assertNotIn("private-diagnostic-marker", json.dumps(report))
        logs = list(directory.glob("*.failure.log"))
        self.assertEqual(len(logs), 8)
        for log in logs:
            self.assertEqual(log.stat().st_mode & 0o777, 0o600)
            self.assertIn("private-diagnostic-marker", log.read_text())


class EchoTests(unittest.TestCase):
    def test_native_udp_echo_preserves_actual_maximum_payload(self):
        with ExitStack() as resources:
            target = runner.native_echo(resources, False, True)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
                channel.settimeout(3)
                payload = bytes(index % 251 for index in range(65507))
                self.assertEqual(channel.sendto(payload, (target["host"], target["port"])), len(payload))
                reply, source = channel.recvfrom(65535)
                self.assertEqual(source, (target["host"], target["port"]))
                self.assertEqual(reply, payload)


if __name__ == "__main__":
    unittest.main()
