# 文档站外观与部署脚本

kerlico 文档站跑在 nice-wiki 上。这里放外观包 `kerlico` 和把实例配好的脚本。脚本不含密钥。

| 文件 | 作用 |
|---|---|
| `theme.json`、`theme.css` | 外观包内容，打包后走站点后台或 `provision.py theme` 上传 |
| `gen_assets.py` | 生成 `assets/` 和 `preview.webp`（需要 Pillow，种子固定）；图片不进仓库，打包前先跑 |
| `package_theme.py` | 校验并打包到 `dist/kerlico-theme-<版本>.zip`，含 WCAG AA 对比度检查 |
| `prepare_docs.py` | 把 `docs/` 打成 `dist/kerlico-docs.zip` 和文档树清单，文档树定义在脚本开头 |
| `make_compose.py` | 把 nice-wiki 的单机编排改成只监听回环地址的独立实例 |
| `provision.py` | 配置实例：管理员、外观、模型、索引与问答、导入、限速发布与翻译 |

## 部署

镜像按 nice-wiki main 自行构建：v0.2.1 发布镜像没有外观功能，子文档的公开页也会 404（main 已修）。在部署目录放好 nice-wiki 的 `deploy/` 和 `bin/nw-keys` 后：

```sh
python3 make_compose.py --version <镜像标签> --public-url https://wiki.kerlico.com --mtu 1280
sh deploy/init-secrets.sh
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d --no-build --pull never
```

编排的项目名是 `kerlico-wiki`，网段 `10.231.98.0/24`，入口只有 `127.0.0.1:18790`，由反向代理对外。`--public-url` 让 edge 信任 Docker 网段传来的访客地址，否则所有访客算同一个地址，限流和问答额度会被共用。不带这个参数就是只能经 SSH 隧道访问的本地实例。同一台机器上的其他 nice-wiki 不受影响。OpenRouter 密钥放 `private/openrouter-key`（0600），不进任何仓库。

配置（管理员文件两行：账号、口令，只在标准输入里传）：

```sh
NW_SETUP_TOKEN=$(docker exec kerlico-wiki-account-1 cat /data/identity/control/setup-token) \
  python3 provision.py account theme models index docs < 管理员文件
python3 provision.py pace < 管理员文件     # 长时间运行，放后台
python3 provision.py status < 管理员文件   # 查翻译进度
```

## 访问

正式地址是 https://wiki.kerlico.com ，后台在 `/admin`。Cloudflare 代理到部署机的 Caddy，再到 `127.0.0.1:18790`。

公开地址在初始化时写进数据库，换域名后运行 `python3 provision.py public-url --base <新地址> --public-url <新地址> < 管理员文件`。经 Cloudflare 运行时脚本要带自己的 User-Agent，默认的 Python UA 会被拒绝（错误 1010）。

## 模型

全部是 OpenRouter 上 `pricing` 全为 0 的模型，第一个是主模型，后面按顺序备用。

| 档位 | 用途 | 模型 |
|---|---|---|
| 快速 | 检索核查、索引背景、路径名 | `google/gemma-4-26b-a4b-it:free`、`nvidia/nemotron-3.5-lightning:free`、`cohere/north-mini-code:free` |
| 精确 | 回答、翻译、术语 | `google/gemma-4-31b-it:free`、`cohere/north-mini-code:free`、`google/gemma-4-26b-a4b-it:free` |
| 视觉 | 图片与附件描述 | `google/gemma-4-31b-it:free`、`nvidia/nemotron-3.5-super-vl:free` |
| 嵌入 | 生成向量 | `liquid/lfm-2.5-embedding-350m:free`（1024 维，上下文 512 词元，切块 400） |
| 重排 | 召回重排 | 没有免费模型，关闭；检索不做重排 |

选型依据：

- 其余免费向量模型回包的模型名不带 `:free`，网关按版本不一致拒收。
- `thinkingmachines/inkling*:free` 对这个调用方返回 403，`liquid/lfm-2.5-2.6b:free` 强制推理而网关会关掉推理。
- 免费模型约每分钟 20 次、每天 1000 次（账户有余额时）。

## 语言

基准语言 `zh-Hans`（nice-wiki 的标签写法，对应宣传站的 zh-CN）。`en` 随发布自动翻译，`ja`、`ko`、`ru`、`es` 由 `pace` 逐篇申请，全部译完后再打开自动翻译。

`fa` 没有启用：nice-wiki 只接受预设的 15 种语言，其中没有波斯语。加进去要改 nice-wiki 的语言表和后台译文。

`docs/usage.en.md` 作为“使用指南”的子页单独保留；其他英文页是模型译文。

## nice-wiki 的两处限制

- 导入请求的委托证明只有 10 秒，导入几十篇会让后面的文档留成空草稿。`provision.py` 按每批 10 篇导入，站内链接先写占位地址，全部导入后再换成站内链接。
- 模型网关的并发槽满了会直接拒绝，不排队，所以并发上限给到 32。翻译服务自己排队，英文实测每分钟约 0.4 篇；`pace` 申请其余语言时把在途文档数压到 3 篇。
