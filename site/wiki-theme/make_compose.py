#!/usr/bin/env python3
"""把 nice-wiki 生成的单机编排改成只监听回环地址的独立实例，在部署目录（含 deploy/）里运行。
与同机其他 nice-wiki 隔离：独立项目名、网段和数据卷；没有 Caddy，入口是 edge 直接发布到 127.0.0.1。
用法：python3 make_compose.py --version <镜像标签> [--port 18790] [--subnet 10.231.98.0/24] [--project kerlico-wiki]"""
import argparse
import json
import re

SOURCE_SUBNET = "10.231.97.0/24"


def rewrite(text, project, subnet, base):
    text = text.replace("name: nice-wiki\n", f"name: {project}\n", 1)
    text = text.replace(SOURCE_SUBNET, subnet)
    text = re.sub(r"    build:\n(      .*\n)+", "", text)
    text = text.replace('NW_ALLOW_LOCAL_HTTP: "false"', 'NW_ALLOW_LOCAL_HTTP: "true"')
    text = text.replace("NW_PUBLIC_BASE_URL: https://${SITE_DOMAIN}", f"NW_PUBLIC_BASE_URL: {base}")
    text = re.sub(r"      NW_CADDY_ADMIN_URL: .*\n", "", text)
    text = re.sub(r"  caddy:\n(    .*\n|      .*\n)+\n?", "", text)
    text = re.sub(r"  caddy-(data|config):\n", "", text)
    port = base.rsplit(":", 1)[1]
    return text.replace("  edge:\n", f'  edge:\n    ports: ["127.0.0.1:{port}:8090"]\n', 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--port", default="18790")
    parser.add_argument("--subnet", default="10.231.98.0/24")
    parser.add_argument("--project", default="kerlico-wiki")
    args = parser.parse_args()
    with open("deploy/docker-compose.yml", encoding="utf-8") as handle:
        compose = rewrite(handle.read(), args.project, args.subnet, f"http://127.0.0.1:{args.port}")
    with open("deploy/docker-compose.yml", "w", encoding="utf-8") as handle:
        handle.write(compose)
    with open("deploy/config/portal.json", encoding="utf-8") as handle:
        # 没有反向代理：edge 直接收连接（来自 Docker 网关），不带 X-Forwarded-For，不能把网段当受信代理。
        portal = json.load(handle)
    portal["trustedProxyCIDRs"] = []
    with open("deploy/config/portal.json", "w", encoding="utf-8") as handle:
        json.dump(portal, handle, indent=2)
    with open("deploy/.env", "w", encoding="utf-8") as handle:
        handle.write(f"NW_VERSION={args.version}\nGOMEMLIMIT=256MiB\nSITE_DOMAIN=localhost\n")


if __name__ == "__main__":
    main()
