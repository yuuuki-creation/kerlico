#!/usr/bin/env python3
"""生成外观 kerlico 的三角面素材到 assets/ 和 preview.webp（外观包不能带 SVG，只能放位图）。
随机数种子固定，改完配色或形状重跑即可。需要 Pillow。用法：python gen_assets.py"""
import math
import os
import random
from PIL import Image, ImageDraw

THEME = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(THEME, "assets")
INK, BONE, VERMILION, COBALT, ACID, GRAPHITE = "#10131C", "#EFE9DC", "#FF4B2B", "#2D4BFF", "#D7FF3E", "#3A3F4D"
RAMP = (COBALT, GRAPHITE, VERMILION)
SUPERSAMPLE = 2  # 先画大再缩小，三角形的边才不带锯齿


def rgb(value):
    return tuple(int(value[i:i + 2], 16) for i in (1, 3, 5))


def mix(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def ramp(t):
    t = max(0.0, min(1.0, t)) * (len(RAMP) - 1)
    index = min(int(t), len(RAMP) - 2)
    return mix(rgb(RAMP[index]), rgb(RAMP[index + 1]), t - index)


def triangles(width, height, cell, jitter, seed):
    """抖动网格切成三角形，每格随机选一条对角线；外圈多铺一格，抖动后四边不缺角。返回 (三个顶点, 随机数)。"""
    rng = random.Random(seed)
    cols, rows = round(width / cell) + 2, round(height / cell) + 2
    cw, ch = width / (cols - 2), height / (rows - 2)
    offsets = {(i, j): (rng.uniform(-jitter, jitter) * cw, rng.uniform(-jitter, jitter) * ch) for i in range(cols + 1) for j in range(rows + 1)}

    def vertex(i, j):
        dx, dy = offsets[i, j]
        return ((i - 1) * cw + dx, (j - 1) * ch + dy)

    out = []
    for i in range(cols):
        for j in range(rows):
            a, b, c, d = vertex(i, j), vertex(i + 1, j), vertex(i + 1, j + 1), vertex(i, j + 1)
            pair = ((a, b, c), (a, c, d)) if rng.random() < 0.5 else ((a, b, d), (b, c, d))
            out += [(tri, rng.random()) for tri in pair]
    return out


def centroid(tri):
    return sum(p[0] for p in tri) / 3, sum(p[1] for p in tri) / 3


def render(width, height, background, paint):
    image = Image.new("RGB", (width * SUPERSAMPLE, height * SUPERSAMPLE), rgb(background))
    paint(ImageDraw.Draw(image))
    return image.resize((width, height), Image.LANCZOS)


def fill(draw, tri, color):
    scaled = [(x * SUPERSAMPLE, y * SUPERSAMPLE) for x, y in tri]
    draw.polygon(scaled, fill=color, outline=color)


def shards(background, line, lighten):
    """首页背景：三角面沿对角线从钴蓝经石墨到朱红，中间留空；一条裂缝右侧整体错开，缝上暴露一条细线。"""
    width, height = 2400, 1350
    # 裂缝：画面上沿 x=62% 到下沿 x=38%。
    crack_top, crack_bottom = 0.62 * width, 0.38 * width

    def crack_x(y):
        return crack_top + (crack_bottom - crack_top) * y / height

    def clearing(x, y):
        """到中间空地边界的距离，<1 在空地内。"""
        return math.hypot((x / width - 0.5) / 0.37, (y / height - 0.46) / 0.56)

    def paint(draw):
        rng = random.Random(97)
        for tri, r in triangles(width, height, 108, 0.38, 71):
            x, y = centroid(tri)
            distance = clearing(x, y)
            # 边界附近随机丢面，边缘才是碎开的，不是一条圆弧。
            if distance < 1 or rng.random() > (distance - 1) * 3.2 + 0.12:
                continue
            shift = (46, -30) if x > crack_x(y) else (0, 0)
            moved = [(px + shift[0], py + shift[1]) for px, py in tri]
            color = ramp(x / width * 0.86 + y / height * 0.14)
            color = mix(color, rgb(background), lighten * (0.2 + r * 0.5))
            color = mix(color, (255, 255, 255) if r > 0.5 else rgb(INK), abs(r - 0.5) * 0.3)
            if rng.random() < 0.012:
                color = rgb(ACID)
            fill(draw, moved, color)
        scale = SUPERSAMPLE
        draw.line([(crack_top * scale, 0), (crack_bottom * scale, height * scale)], fill=rgb(line), width=scale)
        for fraction in (0.12, 0.88):
            y = height * fraction
            x = crack_x(y)
            draw.line([((x - 90) * scale, y * scale), ((x + 136) * scale, (y - 30) * scale)], fill=rgb(line), width=scale)
    return render(width, height, background, paint)


def band():
    """页头、页脚挂出的切角块：横向一条完整的色阶。"""
    width, height = 1200, 56

    def paint(draw):
        for tri, r in triangles(width, height, 28, 0.32, 53):
            x, _ = centroid(tri)
            color = ramp(x / width)
            fill(draw, tri, mix(color, (255, 255, 255) if r > 0.5 else rgb(INK), abs(r - 0.5) * 0.34))
    return render(width, height, INK, paint)


def preview(light, dark):
    """后台外观卡片的预览：沿斜线拼接明暗两版，叠一条页头。"""
    width, height = 960, 600
    light = light.resize((width, height), Image.LANCZOS)
    dark = dark.resize((width, height), Image.LANCZOS)
    mask = Image.new("L", (width, height), 0)
    ImageDraw.Draw(mask).polygon([(width * 0.62, 0), (width, 0), (width, height), (width * 0.38, height)], fill=255)
    out = Image.composite(dark, light, mask)
    draw = ImageDraw.Draw(out)
    draw.rectangle([0, 0, width, 46], fill=rgb(BONE))
    draw.line([(0, 46), (width, 46)], fill=rgb(INK), width=1)
    strip = band().resize((400, 14), Image.LANCZOS)
    out.paste(strip, (0, 47))
    return out


def save(image, path, **options):
    image.save(path, "WEBP", method=6, **options)
    print(f"{os.path.relpath(path, THEME)}: {image.width}x{image.height} {os.path.getsize(path) // 1024}KiB")


def main():
    os.makedirs(ASSETS, exist_ok=True)
    light = shards(BONE, GRAPHITE, 0.0)
    dark = shards(INK, "#8A8E9A", 0.0)
    save(light, os.path.join(ASSETS, "shards-light.webp"), quality=82)
    save(dark, os.path.join(ASSETS, "shards-dark.webp"), quality=82)
    save(band(), os.path.join(ASSETS, "band.webp"), lossless=True)
    save(preview(light, dark), os.path.join(THEME, "preview.webp"), quality=80)


if __name__ == "__main__":
    main()
