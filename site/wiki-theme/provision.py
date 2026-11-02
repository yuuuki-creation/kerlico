#!/usr/bin/env python3
"""配置 kerlico 文档站（nice-wiki 实例）：管理员、外观、模型、索引与问答、文档、多语言。每一步都可重跑。只用标准库。
在部署机上运行，不含任何密钥：管理员账号和口令从标准输入读（两行：账号、口令），OpenRouter 密钥从 --openrouter-key 指向的文件读。

  python3 provision.py STEP... < 管理员文件
  STEP：account theme models index docs pace status

pace 长时间运行：按免费模型的限速一篇篇发布、一篇篇翻译，建议 nohup 放到后台。

安装令牌用环境变量 NW_SETUP_TOKEN 传入（只有首次注册需要）。"""
import argparse
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

PROVIDER = "openrouter"
BASE_URL = "https://openrouter.ai/api/v1"
SITE_NAME = "Kerlico"
BASE_LANGUAGE = "zh-Hans"
# 按顺序翻译：英文随发布自动翻译，其余语言等前一种翻完再逐篇申请。波斯语 fa 不在 nice-wiki 预设的 15 种语言里。
LANGUAGES = ["en", "ja", "ko", "ru", "es"]
IMPORT_BATCH = 10  # 导入请求的委托证明只有 10 秒
DOC_URL = "https://kerlico-wiki.invalid/doc/"
IN_FLIGHT = 3  # 英文之外同时申请翻译的文档数，免费模型约每分钟 20 次
RETRY_STOPPED_AFTER = 3600
BATCH_OUTPUT_TOKENS = 4000
EMBED_PREPROCESSOR = "none;tiktoken-go@v0.7.0;cl100k_base"

# 只放 /api/v1/models 里 pricing 全为 0 且本实例实测能调用的模型。
MODELS = [
    {"modelId": "gemma-4-31b", "providerModelVersion": "google/gemma-4-31b-it:free", "capabilities": ["chat", "vision"], "dimension": 0, "preprocessorVersion": "none", "maxInputTokens": 262144, "maxOutputTokens": 32768},
    {"modelId": "gemma-4-26b", "providerModelVersion": "google/gemma-4-26b-a4b-it:free", "capabilities": ["chat", "vision"], "dimension": 0, "preprocessorVersion": "none", "maxInputTokens": 262144, "maxOutputTokens": 32768},
    {"modelId": "north-mini-code", "providerModelVersion": "cohere/north-mini-code:free", "capabilities": ["chat"], "dimension": 0, "preprocessorVersion": "none", "maxInputTokens": 256000, "maxOutputTokens": 64000},
    {"modelId": "nemotron-3-5-lightning", "providerModelVersion": "nvidia/nemotron-3.5-lightning:free", "capabilities": ["chat"], "dimension": 0, "preprocessorVersion": "none", "maxInputTokens": 1000000, "maxOutputTokens": 65536},
    {"modelId": "nemotron-3-5-vl", "providerModelVersion": "nvidia/nemotron-3.5-super-vl:free", "capabilities": ["chat", "vision"], "dimension": 0, "preprocessorVersion": "none", "maxInputTokens": 1000000, "maxOutputTokens": 131072},
    # 网关要求回包的模型名与请求一致（去掉前缀后比较）；免费向量模型里目前只有这个回包带 :free。
    # maxInputTokens 是整批的预算，单段由 CHUNK_TOKENS 控制在模型的 512 词元以内。
    {"modelId": "lfm-2-5-embedding", "providerModelVersion": "liquid/lfm-2.5-embedding-350m:free", "capabilities": ["embedding"], "dimension": 1024, "preprocessorVersion": EMBED_PREPROCESSOR, "maxInputTokens": 8191, "maxOutputTokens": 0},
]
# 档位 → 模型（第一个是主模型，后面按顺序备用）。重排没有免费模型，不建档位，任务按“能力不可用”降级。
TIERS = {
    "fast": ["gemma-4-26b", "nemotron-3-5-lightning", "north-mini-code"],
    "accurate": ["gemma-4-31b", "north-mini-code", "gemma-4-26b"],
    "vision": ["gemma-4-31b", "nemotron-3-5-vl"],
    "embedding": ["lfm-2-5-embedding"],
}
COST_CLASSES = ["qa", "background", "admin-probe"]
TASKS = {
    "qa.inspect": "fast", "qa.answer": "accurate", "qa.compact": "fast",
    "knowledge.context": "fast", "knowledge.summary": "fast", "knowledge.describe": "fast",
    "knowledge.describe-visual": "vision", "knowledge.extract-attachment": "vision", "knowledge.embed": "embedding", "knowledge.rerank": "rerank",
    "localization.document": "accurate", "localization.ui": "accurate", "localization.terms": "accurate", "localization.review": "accurate", "localization.suggest": "fast",
    "memory.overview": "fast", "memory.assistant": "accurate", "content.slug": "fast", "content.seo": "fast",
}
# 向量模型上下文只有 512 词元，切块留出余量。
CHUNK_TOKENS = 400
OVERLAP_TOKENS = 40
# 网关的并发槽满了会直接拒绝而不是排队，这里给足；真正的限速靠 pace 控制在途文档数。
CONCURRENCY = 32
REQUEST_TIMEOUT_MS = 180000
GUARD_DEFAULTS = {"qaPerSubjectPerMinute": 30, "qaBurst": 5, "qaPerSitePerMinute": 600, "qaSubjectConcurrency": 1, "qaSiteConcurrency": 32, "challengeEnabled": True, "externalChallengeEnabled": False, "qaPerNetworkPerMinute": 60}


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {str(body)[:500]}")
        self.status = status
        self.body = body


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cookie = ""
        self.csrf = ""
        self.credentials = None

    def login(self):
        name, password = self.credentials
        result = self.call("POST", "/v1/sessions", {"accountName": name, "password": password})
        self.csrf = result["session"]["csrfToken"] if "session" in result else result["tokens"]["csrfToken"]

    def call(self, method, path, body=None, raw=None, content_type=None, key=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        key = key or uuid.uuid4().hex
        for attempt in range(12):
            request = urllib.request.Request(self.base + path, data=data, method=method)
            request.add_header("Origin", self.base)
            if data is not None:
                request.add_header("Content-Type", content_type or "application/json")
            if self.cookie:
                request.add_header("Cookie", self.cookie)
            if method != "GET":
                if self.csrf:
                    request.add_header("X-CSRF-Token", self.csrf)
                request.add_header("Idempotency-Key", key)
            try:
                response = urllib.request.urlopen(request, timeout=300)
            except urllib.error.HTTPError as error:
                response = error
            if response.status not in (429, 503):
                break
            response.read()
            time.sleep(10)  # 入口按客户端限流，刚启动时依赖服务也可能还没就绪。
        payload = response.read().decode()
        cookies = [cookie.split(";")[0] for cookie in response.headers.get_all("Set-Cookie") or []]
        if cookies:
            self.cookie = "; ".join(cookies)
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = payload
        if response.status == 401 and self.credentials and path != "/v1/sessions":
            self.cookie = self.csrf = ""
            self.login()
            return self.call(method, path, body, raw, content_type, key)
        if response.status >= 400:
            raise ApiError(response.status, parsed)
        return parsed

    def put(self, path, body, method="PUT"):
        key = uuid.uuid4().hex
        return self.call(method, path, {**body, "idempotencyKey": key}, key=key)


def read_admin():
    lines = [line.strip() for line in sys.stdin.read().splitlines() if line.strip()]
    if len(lines) < 2:
        sys.exit("标准输入要给两行：账号、口令")
    return lines[0], lines[1]


def account(client, name, password):
    state = client.call("GET", "/v1/registration")
    if state.get("registrationOpen"):
        token = os.environ.get("NW_SETUP_TOKEN", "").strip()
        result = client.call("POST", "/v1/registration", {"accountName": name, "password": password, "passwordConfirmation": password, "setupToken": token})
        print("已注册站主")
        client.csrf = result["session"]["csrfToken"] if "session" in result else result["tokens"]["csrfToken"]
    else:
        client.login()
    init = client.call("GET", "/v1/initialization")
    if not init.get("initialized"):
        client.call("POST", "/v1/initialization", {"name": SITE_NAME, "baseLanguage": BASE_LANGUAGE})
        print("站点已初始化")
    languages = client.call("GET", "/v1/languages?includeDisabled=true")["languages"]
    if not any(item["tag"] == BASE_LANGUAGE for item in languages):
        client.put(f"/v1/languages/{BASE_LANGUAGE}", {"expectedVersion": 0, "language": language_config(BASE_LANGUAGE, 1, True, True, False)})
        print("基准语言已启用")


def language_config(tag, version, enabled, default, automatic):
    return {"tag": tag, "version": version, "enabled": enabled, "isDefault": default, "automaticTranslation": automatic, "direction": "ltr",
            "reflectionEnabled": False, "batchOutputTokens": BATCH_OUTPUT_TOKENS, "translationMemoryMinimumCharacters": 20}


def theme(client, path):
    with open(path, "rb") as handle:
        package = handle.read()
    installed = client.call("POST", "/v1/appearance/themes", raw=package, content_type="application/octet-stream")
    print("外观包已安装", json.dumps(installed, ensure_ascii=False)[:200])
    loaded = client.call("GET", "/v1/appearance")
    entry = next(item for item in loaded["themes"] if item["manifest"]["id"] == "kerlico" and item["manifest"]["version"] == json.loads(zip_manifest(path))["version"])
    client.call("PUT", "/v1/appearance", {"themeDigest": entry["digest"], "colorScheme": "system"})
    print("外观已启用", entry["digest"][:12])


def zip_manifest(path):
    with zipfile.ZipFile(path) as archive:
        return archive.read("theme.json")


def models(client, key_path):
    catalog = client.call("GET", "/v1/admin/catalog")
    existing = next((item for item in catalog["providers"] if item["providerId"] == PROVIDER), None)
    fields = {k: v for k, v in (existing or {}).items() if k not in ("credentialConfigured", "lastProbe")}
    client.put(f"/v1/admin/providers/{PROVIDER}", {"expectedVersion": existing["version"] if existing else 0, "provider": {
        "connectTimeoutMs": 5000, "streamIdleTimeoutMs": 60000, "extraHeaderNames": [], **fields, "credentialVersion": existing["credentialVersion"] if existing else 0,
        "providerId": PROVIDER, "displayName": "OpenRouter (free models)", "adapter": "openai_chat", "baseUrl": BASE_URL, "enabled": True,
        "concurrencyLimit": CONCURRENCY, "requestTimeoutMs": REQUEST_TIMEOUT_MS, "extraHeaderSecretRefs": [], "version": (existing["version"] if existing else 0) + 1}})
    with open(key_path, encoding="utf-8") as handle:
        secret = handle.read().strip()
    if not (existing and existing.get("credentialConfigured")):
        client.put(f"/v1/admin/providers/{PROVIDER}/credentials", {"providerId": PROVIDER, "secret": secret, "expectedVersion": 0}, "POST")
    del secret
    catalog = client.call("GET", "/v1/admin/catalog")
    for model in MODELS:
        if not model["providerModelVersion"].endswith(":free"):
            sys.exit(f"只允许免费模型：{model['modelId']}")
        current = next((item for item in catalog["models"] if item["modelId"] == model["modelId"]), None)
        version = current["version"] if current else 0
        client.put(f"/v1/admin/models/{urllib.parse.quote(model['modelId'], safe='')}", {"expectedVersion": version, "model": {
            **model, "providerId": PROVIDER, "version": version + 1, "catalogOrigin": "manual", "manualOverride": True, "enabled": True}})
    for cost_class in COST_CLASSES:
        for tier, ordered in TIERS.items():
            matches = [item for item in catalog["profiles"] if item["costClass"] == cost_class and item["tier"] == tier]
            for profile in matches or [None]:
                profile_id = profile["profileId"] if profile else f"{cost_class}-{tier}"
                version = profile["version"] if profile else 0
                zero = {"currency": "USD", "micros": 0}
                client.put(f"/v1/admin/profiles/{profile_id}", {"expectedVersion": version, "profile": {
                    "profileId": profile_id, "version": version + 1, "costClass": cost_class, "tier": tier, "orderedModelIds": ordered, "concurrency": CONCURRENCY,
                    "maximumCost": zero, "dailyLimitCost": zero}})
    for task, tier in TASKS.items():
        current = next((item for item in catalog["taskAssignments"] if item["taskId"] == task), None)
        version = current["version"] if current else 0
        client.put(f"/v1/task-assignments/{task}", {"expectedVersion": version, "assignment": {"taskId": task, "tier": tier, "version": version + 1}})
    print(f"模型 {len(MODELS)} 个，档位 {len(TIERS)} 个，任务 {len(TASKS)} 个")
    for model in MODELS:
        print(model["modelId"], probe(client, model["modelId"]))


def probe(client, model_id):
    key = uuid.uuid4().hex
    created = client.call("POST", f"/v1/providers/{PROVIDER}:probe", {"providerId": PROVIDER, "modelId": model_id, "idempotencyKey": key}, key=key)
    wanted = created["invocation"]["invocationId"]
    for _ in range(30):
        time.sleep(2)
        provider = next(item for item in client.call("GET", "/v1/admin/catalog")["providers"] if item["providerId"] == PROVIDER)
        last = provider.get("lastProbe") or {}
        if last.get("invocation", {}).get("invocationId") == wanted and last["invocation"]["state"] in ("succeeded", "failed", "cancelled", "charge_unknown", "reconciled"):
            return {k: last.get(k) for k in ("latencyMs", "httpStatus", "failureCode", "providerMessage")} | {"state": last["invocation"]["state"]}
    return "60 秒没有结果"


def index(client):
    options = client.call("GET", "/v1/index-options")
    catalog = client.call("GET", "/v1/admin/catalog")
    profile_id = next(item for item in catalog["profiles"] if item["costClass"] == "background" and item["tier"] == "embedding")["profileId"]
    space = next(item for item in options["profiles"] if item["profileId"] == profile_id).get("space")
    if not space:
        sys.exit("知识索引读不到向量档位")
    try:
        current = client.call("GET", "/v1/index-config")["config"]
    except ApiError as error:
        if error.status != 404:
            raise
        current = None
    client.put("/v1/index-config", {"expectedVersion": current["version"] if current else 0, "config": {
        "configId": current["configId"] if current else uuid.uuid4().hex, "version": current["version"] if current else 0, "enabled": True, "embeddingProfileId": profile_id, "space": space,
        "chunkTokens": CHUNK_TOKENS, "overlapTokens": OVERLAP_TOKENS, "language": options["baseLanguage"]}})
    try:
        client.call("GET", "/v1/policies")
    except ApiError as error:
        if error.status != 404:
            raise
        site = client.call("GET", "/v1/self")["account"]["siteId"]
        client.call("PUT", "/v1/policies", {"siteId": site, "expectedRevision": 0, "policyJSON": GUARD_DEFAULTS})
    qa = client.call("GET", "/v1/admin/policy")
    client.put("/v1/admin/policy", {"expectedVersion": qa["version"], "policy": {**qa["policy"], "enabled": True, "retrievalSpace": space}})
    # 已发布文档补建一次索引（已是最新的直接复用），之后每次发布自动建。
    for document in options["documents"]:
        client.put("/v1/builds", {"document": document["reference"], "force": False}, "POST")
    print(f"知识索引与公开问答已开启，补建索引 {len(options['documents'])} 篇")


def flatten(nodes):
    for node in nodes:
        yield node
        yield from flatten(node.get("children", []))


def docs(client, zip_path, manifest_path):
    """分批导入并把占位链接换成站内链接。只建草稿，发布由 pace 负责。"""
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    with zipfile.ZipFile(zip_path) as archive:
        sources = {name: archive.read(name) for name in archive.namelist()}

    def import_children(parent_id, nodes):
        existing = {item["title"]: item["documentId"] for item in client.call("GET", "/v1/tree")["documents"] if item.get("parentId") == parent_id}
        pending = [node for node in nodes if node["title"] not in existing]
        for start in range(0, len(pending), IMPORT_BATCH):
            batch = pending[start:start + IMPORT_BATCH]
            package = io.BytesIO()
            with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("SUMMARY.md", "\n".join(f"* [{node['title']}]({node['file']})" for node in batch) + "\n")
                for node in batch:
                    archive.writestr(node["file"], sources[node["file"]])
            query = "?format=gitbook" + (f"&parent={parent_id}" if parent_id else "")
            result = client.call("POST", "/v1/site-import" + query, raw=package.getvalue(), content_type="application/octet-stream")
            if result.get("failures") or result.get("documents") != len(batch):
                sys.exit(f"导入失败：{result.get('documents')}/{len(batch)} {result.get('failures')}")
            for warning in result.get("warnings", []):
                print("警告", warning)
        existing = {item["title"]: item["documentId"] for item in client.call("GET", "/v1/tree")["documents"] if item.get("parentId") == parent_id}
        for node in nodes:
            if node.get("children"):
                import_children(existing[node["title"]], node["children"])

    import_children(None, manifest)
    tree = client.call("GET", "/v1/tree")["documents"]
    ids = {}
    by_title = {item["title"]: item["documentId"] for item in tree}
    for node in flatten(manifest):
        ids[node["slug"]] = by_title[node["title"]]
    fixed = 0
    for item in tree:
        fixed += replace_placeholders(client, item["documentId"], ids)
    print(f"文档 {len(tree)} 篇（清单 {len(ids)} 篇），改写站内链接 {fixed} 处")
    if len(tree) != len(ids):
        sys.exit("文档数和清单不一致")


def replace_placeholders(client, document_id, ids):
    current = client.call("GET", f"/v1/documents/{document_id}/draft")
    draft, body = current["draft"], current["body"]
    changed = 0

    def walk(value):
        nonlocal changed
        if isinstance(value, dict):
            target = value.get("target")
            if isinstance(target, dict) and str(target.get("href", "")).startswith(DOC_URL):
                value["target"] = {"kind": "internal", "documentId": ids[target["href"][len(DOC_URL):]], "blockId": None}
                changed += 1
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(body)
    if changed:
        lease = client.call("POST", f"/v1/documents/{document_id}/lock", {"tabId": uuid.uuid4().hex})["lease"]
        client.call("PUT", f"/v1/documents/{document_id}/draft", {"body": body, "expectedDraftVersion": draft["draftVersion"], "expectedDraftRevisionId": draft["revisionId"],
                    "leaseId": lease["leaseId"], "fencingToken": lease["fencingToken"], "serverBootId": lease["serverBootId"]})
        client.call("DELETE", f"/v1/documents/{document_id}/lock", {"leaseId": lease["leaseId"], "serverBootId": lease["serverBootId"]})
    return changed


def publish(client, node, entry):
    draft = client.call("GET", f"/v1/documents/{node['documentId']}/draft")["draft"]
    client.call("POST", f"/v1/documents/{node['documentId']}:publish", {"draftRevisionId": draft["revisionId"], "expectedDraftVersion": draft["draftVersion"],
                "expectedRevision": node["revision"], "manualPathSegment": entry["slug"], "manualSEO": entry["seo"]})


def ensure_language(client, tag, automatic):
    languages = {item["tag"]: item for item in client.call("GET", "/v1/languages?includeDisabled=true")["languages"]}
    current = languages.get(tag)
    version = current["version"] if current else 0
    if current and current["enabled"] and current["automaticTranslation"] == automatic and current["batchOutputTokens"] == BATCH_OUTPUT_TOKENS:
        return
    client.put(f"/v1/languages/{tag}", {"expectedVersion": version, "language": language_config(tag, version + 1, True, False, automatic)})
    print("语言已配置", tag, "自动翻译" if automatic else "按篇申请", flush=True)


def pace(client, manifest_path):
    """先逐篇发布（英文随发布自动排队翻译），英文译完后其余语言按在途上限逐篇申请，全部完成后打开自动翻译。"""
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = {node["title"]: node for node in flatten(json.load(handle))}
    ensure_language(client, "en", True)
    last_report, retried = 0, {}
    while True:
        tree = client.call("GET", "/v1/tree")["documents"]
        progress, tally = language_progress(client)
        active = len(progress.get("active", []))
        unpublished = [item for item in tree if not item.get("publishedReference")]
        references = {item["documentId"]: item["publishedReference"] for item in tree if item.get("publishedReference")}
        now = time.time()
        if now - last_report > 300:
            print(time.strftime("%H:%M:%S"), "未发布", len(unpublished), "在途", active, json.dumps(tally, ensure_ascii=False), flush=True)
            last_report = now
        if unpublished:
            # 文档树是前序，父文档先发布。基准语言不等翻译；英文译文在翻译服务里排队，队列自己按并发消化。
            node = unpublished[0]
            publish(client, node, manifest[node["title"]])
        elif active < IN_FLIGHT:
            target = next((tag for tag in LANGUAGES if tag not in tally or set(tally[tag]) != {"translated"}), None)
            if target is None:
                for tag in LANGUAGES:
                    ensure_language(client, tag, True)
                print("全部语言翻译完成", json.dumps(tally, ensure_ascii=False), flush=True)
                return
            ensure_language(client, target, target == "en")
            for row in progress["documents"]:
                key = (row["documentId"], row["language"])
                if row["language"] == target and (row["state"] == "waiting" or (row["state"] == "stopped" and now - retried.get(key, 0) > RETRY_STOPPED_AFTER)):
                    retried[key] = now
                    client.put("/v1/translations", {"document": references[row["documentId"]], "targetLanguage": target}, "POST")
                    break
        time.sleep(20)


def language_progress(client):
    progress = client.call("GET", "/v1/translations/progress")
    tally = {}
    for row in progress.get("documents", []):
        states = tally.setdefault(row["language"], {})
        states[row["state"]] = states.get(row["state"], 0) + 1
    return progress, tally


def status(client):
    progress, tally = language_progress(client)
    print("modelReady", progress.get("modelReady"), "在途", len(progress.get("active", [])))
    for tag, states in sorted(tally.items()):
        print(tag, states)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("steps", nargs="+", choices=["account", "theme", "models", "index", "docs", "pace", "status"])
    parser.add_argument("--base", default="http://127.0.0.1:18790")
    parser.add_argument("--openrouter-key", default="private/openrouter-key")
    parser.add_argument("--theme-zip", default="import/kerlico-theme-1.0.1.zip")
    parser.add_argument("--docs-zip", default="import/kerlico-docs.zip")
    parser.add_argument("--docs-manifest", default="import/kerlico-docs.json")
    args = parser.parse_args()
    client = Client(args.base)
    client.credentials = read_admin()
    account(client, *client.credentials)
    runners = {"account": lambda: None, "theme": lambda: theme(client, args.theme_zip), "models": lambda: models(client, args.openrouter_key), "index": lambda: index(client),
               "docs": lambda: docs(client, args.docs_zip, args.docs_manifest), "pace": lambda: pace(client, args.docs_manifest), "status": lambda: status(client)}
    for step in args.steps:
        runners[step]()


if __name__ == "__main__":
    main()
