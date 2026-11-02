import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import worker


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("KERLICO_WORKER") == "1", "只在授权Linux worker执行")
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.output = self.base / "output"
        self.output.mkdir()
        for name in ["Cargo.toml", "Cargo.lock", "apps/kerlico/Cargo.toml", "crates/protocol-tor/src/outbound.rs",
                     "crates/protocol-tor/src/runtime.rs", "tools/tor_interop/worker.py"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"controlled-source\n")
        self.manifest = self.base / "manifest.json"
        self.rows = [{"path": path.relative_to(self.root).as_posix(), "bytes": path.stat().st_size, "sha256": worker.digest(path)}
                     for path in self.root.rglob("*") if path.is_file()]
        worker.write_json(self.manifest, self.rows)

    def test_manifest_rejects_omitted_compilation_input(self):
        worker.write_json(self.manifest, [row for row in self.rows if not row["path"].endswith("runtime.rs")])
        with self.assertRaisesRegex(ValueError, "完整快照文件集合"):
            worker.verify_manifest(self.root, self.manifest)

    def test_manifest_rejects_added_cargo_config_and_mutated_bytes(self):
        config = self.root / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text("[build]\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "完整快照文件集合"):
            worker.verify_manifest(self.root, self.manifest)
        config.unlink()
        (self.root / "Cargo.lock").write_bytes(b"changed-source\n")
        with self.assertRaisesRegex(ValueError, "固定清单"):
            worker.verify_manifest(self.root, self.manifest)

    def test_artifact_requires_current_manifest_fresh_build_and_private_target(self):
        target = self.output / "target/debug/kerlico"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"controlled-artifact")
        artifact = {"reason": "compiler-artifact", "target": {"name": "kerlico", "kind": ["bin"]},
                    "manifest_path": str(self.root / "apps/kerlico/Cargo.toml"), "fresh": False, "executable": str(target)}
        log = self.output / "build.stdout.log"
        log.write_text(json.dumps(artifact) + "\n", encoding="utf-8")
        self.assertEqual(worker.built_cli(self.root, self.output), target)
        for field, invalid in [("fresh", True), ("manifest_path", str(self.root / "Cargo.toml")),
                               ("executable", str(self.root / "Cargo.lock"))]:
            rejected = dict(artifact)
            rejected[field] = invalid
            log.write_text(json.dumps(rejected) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                worker.built_cli(self.root, self.output)

    def test_command_timeout_keeps_both_original_streams(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            worker.command_log([sys.executable, "-c",
                                "import sys,time; print('raw-out',flush=True); print('raw-err',file=sys.stderr,flush=True); time.sleep(60)"],
                               self.root, self.output, "controlled", 1)
        self.assertIn(b"raw-out", (self.output / "controlled.stdout.log").read_bytes())
        self.assertIn(b"raw-err", (self.output / "controlled.stderr.log").read_bytes())

    def arguments(self):
        return argparse.Namespace(source_root=str(self.root), source_manifest=str(self.manifest),
                                  worker_root=str(self.base), worker_alias="perf-01", cargo=sys.executable,
                                  build_timeout=30, public_tor=True, literal_ipv4=None, literal_ipv6=None)

    def test_manifest_preflight_failure_retains_known_digest_and_summary(self):
        worker.write_json(self.manifest, self.rows[:-1])
        with patch.object(worker, "__file__", str(self.root / "tools/tor_interop/worker.py")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(self.arguments()), 1)
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "source-manifest")
        self.assertEqual(summary["source_manifest_sha256"], worker.digest(self.manifest))
        self.assertEqual((directory / "source-manifest.json").read_bytes(), self.manifest.read_bytes())
        self.assertIn("ValueError", (directory / "failure.log").read_text(encoding="utf-8"))

    def test_check_failure_retains_build_binding_and_both_logs(self):
        def build(args, root, manifest, directory, summary):
            cli = directory / "controlled-cli"
            cli.write_bytes(b"controlled-only")
            summary["cli_sha256"] = worker.digest(cli)
            return cli

        def check(command, cwd, directory, name, timeout):
            self.assertEqual(name, "check")
            (directory / "check.stdout.log").write_bytes(b"original-check-output")
            (directory / "check.stderr.log").write_bytes(b"original-check-error")
            return subprocess.CompletedProcess(command, 7)

        with patch.object(worker, "__file__", str(self.root / "tools/tor_interop/worker.py")), \
             patch.object(worker, "build_cli", side_effect=build), \
             patch.object(worker, "command_log", side_effect=check), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(self.arguments()), 1)
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "config-check")
        self.assertEqual(summary["check_exit_code"], 7)
        self.assertEqual(summary["cli_sha256"], worker.digest(directory / "controlled-cli"))
        self.assertEqual((directory / "check.stdout.log").read_bytes(), b"original-check-output")
        self.assertEqual((directory / "check.stderr.log").read_bytes(), b"original-check-error")
        self.assertTrue((directory / "failure.log").is_file())

    def test_trusted_directory_rejects_writable_or_symlink_ancestor(self):
        shared = self.base / "shared"
        private = shared / "private"
        private.mkdir(parents=True, mode=0o700)
        worker.require_trusted_directory(private)
        for mode in [0o775, 0o1777]:
            shared.chmod(mode)
            with self.assertRaisesRegex(ValueError, "完整可信祖先"):
                worker.require_trusted_directory(private)
        shared.chmod(0o700)
        link = self.base / "link"
        link.symlink_to(shared, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "完整可信祖先"):
            worker.require_trusted_directory(link / "private")

    def test_source_outside_job_is_rejected_before_build(self):
        args = self.arguments()
        args.worker_root = str(self.output)
        with patch.object(worker, "build_cli") as build, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(args), 1)
        build.assert_not_called()
        directory = next(self.output.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "source-inputs")
        self.assertEqual(summary["error_class"], "ValueError")
        self.assertTrue((directory / "failure.log").is_file())

    def test_symlink_manifest_is_rejected_before_reading_its_contents(self):
        alias = self.base / "manifest-alias.json"
        alias.symlink_to(self.manifest)
        args = self.arguments()
        args.source_manifest = str(alias)
        with patch.object(worker, "build_cli") as build, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(args), 1)
        build.assert_not_called()
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "source-inputs")
        self.assertNotIn("source_manifest_sha256", summary)
        self.assertTrue((directory / "failure.log").is_file())

    def test_worker_preflight_failure_keeps_summary_and_original_exception(self):
        args = self.arguments()
        args.public_tor = False
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(args), 1)
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "worker-preflight")
        self.assertEqual(summary["error_class"], "RuntimeError")
        self.assertIn("public-tor", (directory / "failure.log").read_text(encoding="utf-8"))

    def test_build_failure_keeps_summary_binding_record_and_original_logs(self):
        def command(command, cwd, directory, name, timeout):
            (directory / (name + ".stdout.log")).write_bytes(b"original-build-stdout")
            (directory / (name + ".stderr.log")).write_bytes(b"original-build-stderr")
            return subprocess.CompletedProcess(command, 0 if name == "cargo-version" else 101)

        with patch.object(worker, "__file__", str(self.root / "tools/tor_interop/worker.py")), \
             patch.object(worker, "command_log", side_effect=command), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(self.arguments()), 1)
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        record = json.loads((directory / "build-record.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "build")
        self.assertEqual(summary["build_exit_code"], 101)
        self.assertNotIn("cli_sha256", summary)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["source_manifest_sha256"], worker.digest(self.manifest))
        self.assertEqual(record["build_exit_code"], 101)
        self.assertEqual(summary["build_record_sha256"], worker.digest(directory / "build-record.json"))
        self.assertEqual(record["build_stdout_sha256"], worker.digest(directory / "build.stdout.log"))
        self.assertEqual(record["build_stderr_sha256"], worker.digest(directory / "build.stderr.log"))
        self.assertEqual((directory / "build.stderr.log").read_bytes(), b"original-build-stderr")
        self.assertTrue((directory / "failure.log").is_file())

    def test_build_timeout_keeps_record_without_claiming_cli_success(self):
        def command(command, cwd, directory, name, timeout):
            (directory / (name + ".stdout.log")).write_bytes(b"original-timeout-stdout")
            (directory / (name + ".stderr.log")).write_bytes(b"original-timeout-stderr")
            if name == "build":
                raise subprocess.TimeoutExpired(command, timeout)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(worker, "__file__", str(self.root / "tools/tor_interop/worker.py")), \
             patch.object(worker, "command_log", side_effect=command), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(self.arguments()), 1)
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        record = json.loads((directory / "build-record.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "build")
        self.assertEqual(summary["error_class"], "TimeoutExpired")
        self.assertEqual(record["status"], "failed")
        self.assertNotIn("cli_sha256", record)
        self.assertEqual(record["build_stderr_sha256"], worker.digest(directory / "build.stderr.log"))
        self.assertTrue((directory / "failure.log").is_file())

    def test_cargo_symlink_keeps_the_explicit_proxy_entrypoint(self):
        cargo = self.base / "cargo"
        cargo.symlink_to(sys.executable)
        args = self.arguments()
        args.cargo = str(cargo)
        summary = {"source_manifest_sha256": worker.digest(self.manifest)}

        def command(command, cwd, directory, name, timeout):
            self.assertEqual(command[0], str(cargo))
            return subprocess.CompletedProcess(command, 0 if name == "cargo-version" else 101)

        with patch.object(worker, "command_log", side_effect=command), self.assertRaises(RuntimeError):
            worker.build_cli(args, self.root, self.manifest, self.output, summary)
        record = json.loads((self.output / "build-record.json").read_text(encoding="utf-8"))
        self.assertEqual(record["cargo_sha256"], worker.digest(cargo))
        self.assertEqual(record["status"], "failed")

    def test_preexisting_target_is_rejected_without_binary_binding(self):
        (self.output / "target").mkdir()
        summary = {"source_manifest_sha256": worker.digest(self.manifest)}
        with patch.object(worker, "command_log", return_value=subprocess.CompletedProcess([], 0)), \
             self.assertRaisesRegex(ValueError, "全新target"):
            worker.build_cli(self.arguments(), self.root, self.manifest, self.output, summary)
        record = json.loads((self.output / "build-record.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "failed")
        self.assertNotIn("cli_sha256", record)
        self.assertFalse((self.output / "build-command.json").exists())

    def test_network_failure_keeps_known_cli_binding_and_original_cli_log(self):
        def build(args, root, manifest, directory, summary):
            cli = directory / "controlled-cli"
            cli.write_bytes(b"controlled-only")
            summary["cli_sha256"] = worker.digest(cli)
            return cli

        def start(cli, config, directory, number):
            path = directory / ("cli-" + str(number) + ".log")
            path.write_bytes(b"original-cli-log")
            return object(), path.open("ab")

        with patch.object(worker, "__file__", str(self.root / "tools/tor_interop/worker.py")), \
             patch.object(worker, "build_cli", side_effect=build), \
             patch.object(worker, "command_log", return_value=subprocess.CompletedProcess([], 0)), \
             patch.object(worker, "start", side_effect=start), patch.object(worker, "wait_listener"), \
             patch.object(worker, "request", side_effect=ConnectionError("受控网络失败")), \
             patch.object(worker, "stop") as stopped, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(self.arguments()), 1)
        stopped.assert_called_once()
        directory = next(self.base.glob("tor-native-*"))
        summary = json.loads((directory / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["stage"], "domain-a")
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["error_class"], "ConnectionError")
        self.assertEqual(summary["cli_sha256"], worker.digest(directory / "controlled-cli"))
        self.assertEqual((directory / "cli-1.log").read_bytes(), b"original-cli-log")
        self.assertIn("受控网络失败", (directory / "failure.log").read_text(encoding="utf-8"))

    def test_http_failure_keeps_original_status_headers_and_bounded_body(self):
        class Stream:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def settimeout(self, timeout):
                pass

            def sendall(self, data):
                pass

        class Response:
            status = 503
            version = 11
            reason = "Unavailable"

            def begin(self):
                pass

            def getheaders(self):
                return [("X-Controlled", "original-header")]

            def read(self, limit):
                self.limit = limit
                return b"original-http-body"

        response = Response()
        probe = {"name": "controlled", "port": 1, "tls": False}
        with patch.object(worker.socket, "create_connection", return_value=Stream()), \
             patch.object(worker.http.client, "HTTPResponse", return_value=response), \
             self.assertRaisesRegex(ValueError, "HTTP 200"):
            worker.request(probe, self.output)
        head = json.loads((self.output / "http-controlled.head.json").read_text(encoding="utf-8"))
        self.assertEqual(head["status"], 503)
        self.assertEqual(head["headers"], [["X-Controlled", "original-header"]])
        self.assertEqual((self.output / "http-controlled.body").read_bytes(), b"original-http-body")
        self.assertEqual(response.limit, worker.MAX_RESPONSE + 1)


if __name__ == "__main__":
    unittest.main()
