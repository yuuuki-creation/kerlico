"""在海外worker的独立目录准备固定官方peer，不安装系统软件。"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("固定peer只在海外Linux worker构建")
    source = json.loads(Path(__file__).with_name("SOURCE.json").read_text(encoding="utf-8"))["wireguard_go"]
    cache = args.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(cache, 0o700)
    archive = cache / "wireguard-go.tar.gz"
    if not archive.exists():
        archive.write_bytes(urllib.request.urlopen(source["archive"], timeout=60).read())
    raw = archive.read_bytes()
    if digest(raw) != source["archive_sha256"]:
        raise SystemExit("官方源码归档摘要不匹配，停止准备")
    upstream = cache / "wireguard-go"
    if not upstream.exists():
        upstream.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as bundle:
            prefix = "wireguard-go-" + source["commit"] + "/"
            for member in bundle.getmembers():
                if not member.name.startswith(prefix):
                    if member.isdir() and member.name.rstrip("/") == prefix.rstrip("/"):
                        continue
                    raise SystemExit("官方归档目录不匹配")
                relative = Path(member.name[len(prefix):])
                if relative.is_absolute() or ".." in relative.parts or not (member.isdir() or member.isfile()):
                    raise SystemExit("官方归档含不接受的路径或链接")
                output = upstream / relative
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(bundle.extractfile(member).read())
    expected = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as bundle:
        prefix = "wireguard-go-" + source["commit"] + "/"
        for member in bundle.getmembers():
            if member.isfile():
                if not member.name.startswith(prefix):
                    raise SystemExit("官方归档文件目录不匹配")
                relative = Path(member.name[len(prefix):])
                output = upstream / relative
                expected.add(relative.as_posix())
                if output.is_symlink() or not output.is_file() or digest(output.read_bytes()) != digest(bundle.extractfile(member).read()):
                    raise SystemExit("固定官方源码缓存已变化")
    actual = {path.relative_to(upstream).as_posix() for path in upstream.rglob("*") if path.is_file()}
    if actual != expected:
        raise SystemExit("固定官方源码缓存含额外或缺失文件")
    if digest((upstream / "go.sum").read_bytes()) != source["go_sum_sha256"]:
        raise SystemExit("官方依赖摘要表不匹配")
    adapted = cache / "peer-wireguard-go"
    original_tun = (upstream / "tun/netstack/tun.go").read_bytes()
    old_factories = b"[]stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}"
    new_factories = b"[]stack.NetworkProtocolFactory{ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}), ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true})}"
    if original_tun.count(old_factories) != 1:
        raise SystemExit("固定netstack工厂定义与回环适配前提不符")
    adapted_tun = original_tun.replace(old_factories, new_factories)
    if not adapted.exists():
        shutil.copytree(upstream, adapted)
        (adapted / "tun/netstack/tun.go").write_bytes(adapted_tun)
    for name in expected:
        path = adapted / name
        contents = adapted_tun if name == "tun/netstack/tun.go" else (upstream / name).read_bytes()
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != digest(contents):
            raise SystemExit("参考peer回环适配副本与固定输入不符")
    if {path.relative_to(adapted).as_posix() for path in adapted.rglob("*") if path.is_file()} != expected:
        raise SystemExit("参考peer回环适配副本含额外或缺失文件")
    (cache / "netstack-adapter.json").write_text(json.dumps({
        "source_commit":source["commit"], "file":"tun/netstack/tun.go",
        "original_sha256":digest(original_tun), "adapted_sha256":digest(adapted_tun),
        "change":"ipv4/ipv6 NewProtocolWithOptions AllowExternalLoopbackTraffic=true",
        "scope":"test-only netstack loopback acceptance; WireGuard cryptography and protocol unchanged",
    }, indent=2) + "\n", encoding="utf-8")
    build = cache / "peer-build"
    build.mkdir(exist_ok=True)
    shutil.copyfile(Path(__file__).parent / "peer" / "main.go", build / "main.go")
    (build / "go.mod").write_text("module kerlico.invalid/wireguard-interop\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard v0.0.0\n\nreplace golang.zx2c4.com/wireguard => ../peer-wireguard-go\n", encoding="utf-8")
    shutil.copyfile(upstream / "go.sum", build / "go.sum")
    environment = os.environ.copy()
    environment.update(GOTOOLCHAIN="local", GOWORK="off", GOENV="off", GOFLAGS="", GOMAXPROCS="2",
                       GOCACHE=str(cache / "go-cache"), GOMODCACHE=str(cache / "go-mod"), GOPATH=str(cache / "go-path"))
    binary = cache / "wireguard-go-peer"
    with (cache / "build.log").open("w", encoding="utf-8") as log:
        subprocess.run([args.go, "build", "-mod=mod", "-trimpath", "-o", str(binary), "."], cwd=build,
                       env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
    closure = subprocess.check_output([args.go, "list", "-m", "-json", "all"], cwd=build, env=environment)
    (cache / "module-closure.json").write_bytes(closure)
    print(json.dumps({"binary":binary.name, "sha256":digest(binary.read_bytes()),
                      "source_commit":source["commit"], "go_mod_sha256":digest((build / "go.mod").read_bytes()),
                      "go_sum_sha256":digest((build / "go.sum").read_bytes())}))


if __name__ == "__main__":
    main()
