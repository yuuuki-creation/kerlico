构建：`python site/build.py`，生成 `site/dist/`（不提交）。
校验：`python site/check.py`。
预览：`python -m http.server 8000 --directory site/dist`，打开 `http://127.0.0.1:8000/`。
线上：https://www.kerlico.com （`kerlico.com` 跳转到 www）。把 `site/dist/` 同步到部署机的站点目录即可，文件都是静态的。
