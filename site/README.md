构建：`python site/build.py`，生成 `site/dist/`（不提交）。
校验：`python site/check.py`。
预览：`python -m http.server 8000 --directory site/dist`，打开 `http://127.0.0.1:8000/`。
