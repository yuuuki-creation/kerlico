"""仅在专用worker准备固定参照；不会修改系统信任库或启动服务。"""
import argparse, hashlib, io, json, os, pathlib, shutil, subprocess, tarfile, urllib.request

SING_SHA = "c005f35300ce76427dc285481ec5695f5b179cd2"
SING_ARCHIVE = "1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59"
CADDY_SHA = "72dd0fb067f6d7826c7f79907670ba4a713bfe37"
CADDY_ARCHIVE = "e86c49311c0c9f7e9b3b80527f0139e5739dfe28effeaa41c444dd743f0bbd7e"
FORWARD_SHA = "e747854e78743dba85c039b38ed185fb11d93667"
CADDY_PATCHES = {"caddy-sing-quic-bbrv1.patch": "298a057cf1640718a14157bcd22a37575538adffba5189e7a7ecd54bffe7cb8e", "caddy-read-idle-timeout.patch": "02583f364374e9461cee9b954349b87e0390d600319beafcf52ebcc5e2947eab"}
OFFICIAL_TAG = "v154.0.8037.49-5"
OFFICIAL_ARCHIVE = "80214dfea1767f6ecf63a3a79dc9f48b203460f51abc609357fff48dd5844c7d"

def download(url, digest):
    data = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "protocol-reference-preparation"})).read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("固定来源归档摘要不一致")
    return data

def extract(data, destination, strip):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for entry in archive.getmembers():
            parts = pathlib.PurePosixPath(entry.name).parts[strip:]
            if not parts or ".." in parts or pathlib.PurePosixPath(*parts).is_absolute():
                continue
            target = destination.joinpath(*parts)
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif entry.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(entry).read())
                target.chmod(entry.mode & 0o777)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=pathlib.Path)
    parser.add_argument("--go", required=True)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--official", action="store_true")
    options = parser.parse_args()
    if os.environ.get("KERLICO_WORKER_ONLY") != "1":
        raise SystemExit("只允许在专用worker执行")
    work = options.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    source = work / "helper"
    shutil.copytree(pathlib.Path(__file__).parent, source, dirs_exist_ok=True, ignore=shutil.ignore_patterns("reference", "__pycache__"))
    reference = source / "reference/sing-box"
    marker = work / "source.json"
    if reference.exists():
        if not marker.exists() or json.loads(marker.read_text()).get("sha") != SING_SHA:
            raise RuntimeError("已有参照目录未固定到所需来源")
    else:
        data = download("https://codeload.github.com/SagerNet/sing-box/tar.gz/" + SING_SHA, SING_ARCHIVE)
        extract(data, reference, 1)
        marker.write_text(json.dumps({"sha": SING_SHA, "archive_sha256": SING_ARCHIVE, "modification": "仅增加naive_export.go导出已有padding封装，未改变算法和产品源码"}, ensure_ascii=False, indent=2) + "\n")
    shutil.copyfile(source / "fixtures/naive_export.go", reference / "protocol/naive/reference_export.go")
    caddy_reference = source / "reference/caddy"
    caddy_marker = work / "caddy-source.json"
    if caddy_reference.exists():
        if not caddy_marker.exists() or json.loads(caddy_marker.read_text()).get("patches") != CADDY_PATCHES:
            raise RuntimeError("已有Caddy测试副本未固定到所需上游补丁")
    else:
        data = download("https://codeload.github.com/caddyserver/caddy/tar.gz/" + CADDY_SHA, CADDY_ARCHIVE)
        (work / "caddy-original.tar.gz").write_bytes(data)
        extract(data, caddy_reference, 1)
        patch_directory = work / "upstream-patches"
        patch_directory.mkdir(exist_ok=True)
        patches = []
        for name, digest in CADDY_PATCHES.items():
            url = "https://raw.githubusercontent.com/klzgrad/forwardproxy/" + FORWARD_SHA + "/" + name
            path = patch_directory / name
            path.write_bytes(download(url, digest))
            patches.append(str(path.resolve()))
        patch_environment = dict(os.environ, GIT_CEILING_DIRECTORIES=str(caddy_reference.parent))
        subprocess.run(["git", "apply", "--check", *patches], cwd=caddy_reference, env=patch_environment, check=True)
        subprocess.run(["git", "apply", *patches], cwd=caddy_reference, env=patch_environment, check=True)
        caddy_marker.write_text(json.dumps({"sha": CADDY_SHA, "archive_sha256": CADDY_ARCHIVE, "patches": CADDY_PATCHES, "patch_source_sha": FORWARD_SHA, "purpose": "严格复现固定上游Naive服务端发布流程；不是stock Caddy"}, ensure_ascii=False, indent=2) + "\n")
    options.output_dir.mkdir(parents=True, exist_ok=True)
    (work / "go-tmp").mkdir(exist_ok=True)
    environment = dict(os.environ, GOTMPDIR=str(work / "go-tmp"), TMPDIR=str(work / "go-tmp"), GOMEMLIMIT="768MiB", GOMAXPROCS="1", GOTOOLCHAIN="local", GOCACHE=str(work / "go-cache"), GOMODCACHE=str(work / "go-mod-cache"))
    outputs = {}
    for module, prefix, name in [(source, "naive", "naive-reference"), (source / "cmd/caddy", "caddy", "caddy-naive-reference")]:
        subprocess.run([options.go, "mod", "tidy"], cwd=module, env=environment, check=True)
        lock = module / "go.sum"
        if lock.exists() and not (work / (prefix + "-go.sum.first-resolver")).exists():
            shutil.copyfile(lock, work / (prefix + "-go.sum.first-resolver"))
            shutil.copyfile(module / "go.mod", work / (prefix + "-go.mod.first-resolver"))
        output = options.output_dir / name
        subprocess.run([options.go, "build", "-p=1", "-trimpath", "-o", str(output.resolve()), "."], cwd=module, env=environment, check=True)
        outputs[name] = {"sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "modules": subprocess.check_output([options.go, "version", "-m", str(output.resolve())], env=environment).decode()}
        (work / "binaries.json").write_text(json.dumps(outputs, ensure_ascii=False, indent=2) + "\n")
    if options.official:
        name = "naiveproxy-" + OFFICIAL_TAG + "-linux-x64.tar.xz"
        url = "https://github.com/klzgrad/naiveproxy/releases/download/" + OFFICIAL_TAG + "/" + name
        data = download(url, OFFICIAL_ARCHIVE)
        (work / name).write_bytes(data)
        extract(data, work / "official", 0)
        candidates = [p for p in (work / "official").rglob("naive") if p.is_file()]
        if len(candidates) != 1:
            raise RuntimeError("官方资产内容不符合预期")
        output = options.output_dir / "naive-official"
        shutil.copyfile(candidates[0], output)
        output.chmod(0o700)
        outputs["naive-official"] = {"url": url, "archive_sha256": OFFICIAL_ARCHIVE, "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
    (work / "binaries.json").write_text(json.dumps(outputs, ensure_ascii=False, indent=2) + "\n")
    print("固定参照已构建并保存摘要；未启动服务")

if __name__ == "__main__":
    main()
