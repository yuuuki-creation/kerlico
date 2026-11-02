import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import traceback


ARTI_VERSION = "0.47.0"
ARTI_COMMIT = "ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087"
ONION = "hjirlp6fu47kox4cnede4zlvaeq672bibss3oxgmsnsc5mdxygqshbqd.onion"
CHECK_HOST = "check.torproject.org"
MAX_RESPONSE = 1024 * 1024


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            result.update(data)
    return result.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def source_files(root):
    def failed_scan(error):
        raise error

    files = set()
    own_uid = os.geteuid()
    for directory, names, entries in os.walk(root, followlinks=False, onerror=failed_scan):
        current = Path(directory)
        if current == root:
            names[:] = [name for name in names if name != ".git"]
            entries = [name for name in entries if name != ".git"]
        for name in names + entries:
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                raise ValueError("冻结源码不得包含符号链接")
            metadata = candidate.stat()
            if metadata.st_uid not in {0, own_uid} or metadata.st_mode & 0o022:
                raise ValueError("冻结源码不得由不可信主体拥有或写入")
            if any(part in {".private", ".audit", "target", "__pycache__"} for part in candidate.relative_to(root).parts):
                raise ValueError("源码快照混入运行、缓存或私有目录")
            if relative == "reference/.upstream":
                raise ValueError("源码快照混入上游只读缓存")
        for name in entries:
            candidate = current / name
            if not stat.S_ISREG(candidate.stat().st_mode):
                raise ValueError("源码快照包含非常规文件")
            files.add(candidate.relative_to(root).as_posix())
    return files


def verify_manifest(root, path):
    entries = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(entries, list) or not entries:
        raise ValueError("源码清单必须是非空记录数组")
    observed = set()
    for row in entries:
        raw = row["path"]
        relative = PurePosixPath(raw)
        if not isinstance(raw, str) or not raw or "\\" in raw or ":" in raw or relative.is_absolute():
            raise ValueError("源码清单路径不合法")
        if relative.as_posix() != raw or any(part in {"..", ".private", ".audit", ".git"} for part in relative.parts):
            raise ValueError("源码清单路径不合法")
        if raw in observed:
            raise ValueError("源码清单包含重复文件")
        if not isinstance(row["bytes"], int) or row["bytes"] < 0 or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"]):
            raise ValueError("源码清单摘要或大小不合法")
        observed.add(raw)
    actual = source_files(root)
    if actual != observed:
        raise ValueError("源码清单与完整快照文件集合不相等")
    for row in entries:
        source = root / row["path"]
        if source.stat().st_size != row["bytes"] or digest(source) != row["sha256"]:
            raise ValueError("源码不符合固定清单")
    required = {"Cargo.toml", "Cargo.lock", "apps/kerlico/Cargo.toml", "crates/protocol-tor/src/outbound.rs", "tools/tor_interop/worker.py"}
    if not required.issubset(observed):
        raise ValueError("源码清单缺少本轮必要输入")
    return digest(path)


def require_trusted_directory(path):
    absolute = path.absolute()
    own_uid = os.geteuid()
    for component in [*reversed(absolute.parents), absolute]:
        metadata = component.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, own_uid} or metadata.st_mode & 0o022:
            raise ValueError("worker目录须有完整可信祖先且不能经过符号链接")


def require_trusted_file(path):
    require_trusted_directory(path.parent)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & 0o022:
        raise ValueError("worker输入须是可信目录中的不可共享写入常规文件")


def command_log(command, cwd, directory, name, timeout):
    with (directory / (name + ".stdout.log")).open("wb") as stdout, (directory / (name + ".stderr.log")).open("wb") as stderr:
        with subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True) as process:
            try:
                return subprocess.CompletedProcess(command, process.wait(timeout=timeout))
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                raise


def built_cli(root, directory):
    candidates = []
    for line in (directory / "build.stdout.log").read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact" or message.get("target", {}).get("name") != "kerlico":
            continue
        if "bin" not in message["target"]["kind"] or message.get("executable") is None:
            continue
        if Path(message["manifest_path"]).resolve() != root / "apps/kerlico/Cargo.toml" or message.get("fresh") is not False:
            raise ValueError("CLI产物没有绑定本次源码构建")
        executable = Path(message["executable"]).resolve(strict=True)
        if not executable.is_relative_to(directory / "target") or not executable.is_file():
            raise ValueError("CLI产物不在本作业新建target内")
        candidates.append(executable)
    if len(candidates) != 1:
        raise ValueError("本次构建没有产生唯一kerlico CLI")
    return candidates[0]


def build_cli(args, root, manifest, directory, summary):
    summary["stage"] = "toolchain"
    record = {
        "source_manifest_sha256": summary["source_manifest_sha256"],
        "features": ["protocol-tor"], "default_features": False, "status": "running",
    }
    try:
        record["cargo_lock_sha256"] = digest(root / "Cargo.lock")
        cargo = Path(args.cargo)
        if not cargo.is_absolute():
            raise ValueError("Cargo工具链必须显式给出worker绝对路径")
        if not cargo.is_file():
            raise ValueError("Cargo工具链入口不是可用文件")
        record["cargo_sha256"] = digest(cargo)
        version = command_log([str(cargo), "--version", "--verbose"], root, directory, "cargo-version", 20)
        record["cargo_version_exit_code"] = version.returncode
        if version.returncode != 0:
            raise RuntimeError("Cargo版本查询失败")
        target = directory / "target"
        if target.exists():
            raise ValueError("本次构建必须使用全新target")
        summary["stage"] = "build"
        command = [
            str(cargo), "build", "--locked", "--manifest-path", str(root / "Cargo.toml"),
            "--package", "kerlico", "--no-default-features", "--features", "protocol-tor",
            "--target-dir", str(target), "--message-format", "json-render-diagnostics",
        ]
        write_json(directory / "build-command.json", {"command": command, "cwd": str(root)})
        result = command_log(command, root, directory, "build", args.build_timeout)
        record["build_exit_code"] = summary["build_exit_code"] = result.returncode
        if result.returncode != 0:
            raise RuntimeError("固定源码的CLI构建失败")
        summary["stage"] = "build-input-recheck"
        if verify_manifest(root, manifest) != summary["source_manifest_sha256"]:
            raise ValueError("构建期间源码清单发生变化")
        cli = built_cli(root, directory)
        record["cli_sha256"] = summary["cli_sha256"] = digest(cli)
        record["cli_bytes"] = cli.stat().st_size
        record["status"] = "built-fixed-source"
        return cli
    except BaseException as error:
        record["status"] = "failed"
        record["error_class"] = type(error).__name__
        raise
    finally:
        record["stage"] = summary["stage"]
        for name, key in [
            ("cargo-version.stdout.log", "cargo_version_log_sha256"),
            ("cargo-version.stderr.log", "cargo_version_stderr_sha256"),
            ("build.stdout.log", "build_stdout_sha256"),
            ("build.stderr.log", "build_stderr_sha256"),
            ("build-command.json", "build_command_sha256"),
        ]:
            path = directory / name
            if path.is_file():
                record[key] = digest(path)
        write_json(directory / "build-record.json", record)
        summary["build_record_sha256"] = digest(directory / "build-record.json")


def reserve_port():
    reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reservation.bind(("127.0.0.1", 0))
    return reservation


def configure(probes):
    return {
        "version": 2,
        "outbounds": [{"tag": tag, "type": "tor", "options": {
            "data_directory": "tor-state", "bootstrap_timeout_ms": 240000,
            "carrier_timeout_ms": 30000, "shutdown_timeout_ms": 5000,
        }} for tag in ["tor-a", "tor-b"]],
        "inbounds": [{"tag": item["name"], "type": "tcp-forward", "listen": "127.0.0.1:" + str(item["port"]),
                      "target": {"host": item["target"], "port": item["target_port"]}, "outbound": item["outbound"]}
                     for item in probes],
        "limits": {"connect_timeout_ms": 295000, "idle_timeout_ms": 300000,
                   "drain_timeout_ms": 5000, "max_sessions": 16},
    }


def request(probe, directory):
    with socket.create_connection(("127.0.0.1", probe["port"]), timeout=5) as raw:
        raw.settimeout(295)
        stream = ssl.create_default_context().wrap_socket(raw, server_hostname=CHECK_HOST) if probe["tls"] else raw
        with stream:
            host = CHECK_HOST if probe["tls"] else ONION
            path = "/api/ip" if probe["tls"] else "/"
            stream.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + host
                            + "\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(stream)
            response.begin()
            write_json(directory / ("http-" + probe["name"] + ".head.json"), {
                "status": response.status, "version": response.version,
                "reason": response.reason, "headers": response.getheaders(),
            })
            with (directory / ("http-" + probe["name"] + ".body")).open("wb") as body:
                try:
                    payload = response.read(MAX_RESPONSE + 1)
                except http.client.IncompleteRead as error:
                    body.write(error.partial)
                    raise
                body.write(payload)
            if response.status != 200:
                raise ValueError("官方目标未返回HTTP 200")
            if len(payload) > MAX_RESPONSE:
                raise ValueError("官方响应超过验证上限")
            if probe["tls"]:
                if json.loads(payload).get("IsTor") is not True:
                    raise ValueError("官方检测未确认Tor出口")
            elif b"Arti" not in payload:
                raise ValueError("官方onion内容不符合预期")
            return {"name": probe["name"], "status": "passed", "http_status": 200}


def start(cli, config, directory, number):
    log = (directory / ("cli-" + str(number) + ".log")).open("wb")
    try:
        process = subprocess.Popen([str(cli), "run", "--config", str(config)],
                                   cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=log, start_new_session=True)
    except BaseException:
        log.close()
        raise
    return process, log


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise RuntimeError("所属CLI未在关闭预算内退出，已清理本工具创建的进程组")
    if process.returncode != 0:
        raise RuntimeError("所属CLI非正常退出")


def wait_listener(process, port):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("CLI在监听建立前退出")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("项目回环监听未就绪")


def main(args):
    summary = {"arti_version": ARTI_VERSION, "arti_commit": ARTI_COMMIT, "records": [],
               "unverified": ["public-network-establishment-request-cancellation"],
               "status": "running", "stage": "worker-directory"}
    directory = None
    reservations = []
    process = None
    log = None
    os.umask(0o077)
    try:
        worker_root = Path(args.worker_root).absolute()
        if sys.platform != "linux" or os.environ.get("KERLICO_WORKER") != "1":
            raise RuntimeError("只允许在显式标记的Linux worker执行")
        require_trusted_directory(worker_root)
        worker_root = worker_root.resolve(strict=True)
        summary["stage"] = "result-directory"
        directory = Path(tempfile.mkdtemp(prefix="tor-native-", dir=worker_root))
        directory.chmod(0o700)
        summary["stage"] = "worker-preflight"
        if not args.public_tor:
            raise RuntimeError("真实Tor网络验证需要命令显式选择public-tor")
        if not re.fullmatch(r"perf-[0-9]{2}", args.worker_alias):
            raise ValueError("worker记录只允许中性别名")
        if not 1 <= args.build_timeout <= 7200:
            raise ValueError("构建预算须为1至7200秒")
        summary["worker"] = args.worker_alias
        summary["stage"] = "source-inputs"
        root = Path(args.source_root).absolute()
        manifest = Path(args.source_manifest).absolute()
        if (root == worker_root or not root.is_relative_to(worker_root)
                or not manifest.is_relative_to(worker_root)):
            raise ValueError("源码快照和清单必须属于本次worker作业目录")
        if directory.is_relative_to(root) or root.is_relative_to(directory) or manifest.is_relative_to(root):
            raise ValueError("源码快照、清单和作业输出必须分开")
        require_trusted_directory(root)
        require_trusted_file(manifest)
        root = root.resolve(strict=True)
        manifest = manifest.resolve(strict=True)
        if (not root.is_relative_to(worker_root) or not manifest.is_relative_to(worker_root)
                or manifest.is_relative_to(root)):
            raise ValueError("源码快照和清单必须属于本次worker作业目录且相互分离")
        manifest_copy = directory / "source-manifest.json"
        manifest_copy.write_bytes(manifest.read_bytes())
        manifest_copy.chmod(0o600)
        manifest = manifest_copy
        summary["source_manifest_sha256"] = digest(manifest)
        if Path(__file__).resolve() != root / "tools/tor_interop/worker.py":
            raise ValueError("必须运行固定源码快照中的worker工具")
        summary["stage"] = "source-manifest"
        verify_manifest(root, manifest)
        summary["stage"] = "probe-inputs"
        probes = [
            {"name": "domain-a", "target": CHECK_HOST, "target_port": 443, "outbound": "tor-a", "tls": True},
            {"name": "domain-b", "target": CHECK_HOST, "target_port": 443, "outbound": "tor-b", "tls": True},
            {"name": "onion-v3", "target": ONION, "target_port": 80, "outbound": "tor-a", "tls": False},
        ]
        for family, address in [(4, args.literal_ipv4), (6, args.literal_ipv6)]:
            if address is None:
                summary["unverified"].append("literal-ipv" + str(family))
                continue
            parsed = ipaddress.ip_address(address)
            if parsed.version != family or not parsed.is_global:
                raise ValueError("字面测试目标必须是指定地址族的公网地址")
            probes.append({"name": "literal-ipv" + str(family), "target": str(parsed), "target_port": 443,
                           "outbound": "tor-a", "tls": True})
        cli = build_cli(args, root, manifest, directory, summary)
        summary["stage"] = "config-check"
        for probe in probes:
            reservation = reserve_port()
            reservations.append(reservation)
            probe["port"] = reservation.getsockname()[1]
        config = directory / "config.json"
        write_json(config, configure(probes))
        checked = command_log([str(cli), "check", "--config", str(config)], directory, directory, "check", 20)
        summary["check_exit_code"] = checked.returncode
        if checked.returncode != 0 or (directory / "tor-state").exists():
            raise RuntimeError("配置校验失败或提前创建了Tor运行状态")
        for reservation in reservations:
            reservation.close()
        reservations.clear()
        summary["stage"] = "cli-start"
        if digest(cli) != summary["cli_sha256"]:
            raise ValueError("CLI在构建绑定后发生变化")
        process, log = start(cli, config, directory, 1)
        wait_listener(process, probes[0]["port"])
        summary["records"].append({"name": "loopback-listener-ready", "status": "observed"})
        for probe in probes:
            summary["stage"] = probe["name"]
            summary["records"].append(request(probe, directory))
        if not all((directory / "tor-state" / tag / "state").is_dir() for tag in ["tor-a", "tor-b"]):
            raise RuntimeError("两个命名Tor实例没有独立状态目录")
        summary["stage"] = "shutdown"
        stop(process)
        process = None
        log.close()
        log = None
        summary["records"].append({"name": "shutdown", "status": "passed"})
        summary["stage"] = "restart"
        if digest(cli) != summary["cli_sha256"]:
            raise ValueError("CLI在重启前发生变化")
        process, log = start(cli, config, directory, 2)
        wait_listener(process, probes[0]["port"])
        result = request(probes[0], directory)
        result["name"] = "restart-after-real-shutdown"
        summary["records"].append(result)
        stop(process)
        process = None
        summary["stage"] = "final-input-recheck"
        if verify_manifest(root, manifest) != summary["source_manifest_sha256"] or digest(cli) != summary["cli_sha256"]:
            raise ValueError("验证期间固定输入发生变化")
        summary["status"] = "passed-selected-scope"
        summary["stage"] = "complete"
    except BaseException as error:
        summary["status"] = "failed"
        summary["error_class"] = type(error).__name__
        summary["records"].append({"name": summary["stage"], "status": "failed", "error_class": type(error).__name__})
        if directory is not None:
            (directory / "failure.log").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        for reservation in reservations:
            reservation.close()
        if process is not None:
            try:
                stop(process)
            except Exception as error:
                summary["status"] = "failed"
                summary["cleanup_error_class"] = type(error).__name__
                (directory / "cleanup.log").write_text(traceback.format_exc(), encoding="utf-8")
        if log is not None:
            log.close()
        if directory is not None:
            write_json(directory / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary["status"] == "passed-selected-scope" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Linux worker从固定源码构建并验证原生Tor出站")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-manifest", required=True)
    parser.add_argument("--worker-root", required=True)
    parser.add_argument("--worker-alias", required=True)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--build-timeout", type=int, default=3600)
    parser.add_argument("--public-tor", action="store_true")
    parser.add_argument("--literal-ipv4")
    parser.add_argument("--literal-ipv6")
    sys.exit(main(parser.parse_args()))
