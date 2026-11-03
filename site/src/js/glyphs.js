// 字形由凸多边形拼成，单元高 100。不依赖字体，所以每个三角形都能单独飞入和被切开。
const GLYPHS = {
  K: { w: 100, parts: [
    [[0, 0], [30, 0], [30, 100], [0, 100]],
    [[30, 40], [62, 0], [98, 0], [30, 74]],
    [[46, 54], [65, 34], [100, 100], [64, 100]],
  ] },
  E: { w: 90, parts: [
    [[0, 0], [30, 0], [30, 100], [0, 100]],
    [[30, 0], [86, 0], [86, 24], [30, 24]],
    [[30, 38], [74, 38], [74, 62], [30, 62]],
    [[30, 76], [90, 76], [90, 100], [30, 100]],
  ] },
  R: { w: 100, parts: [
    [[0, 0], [30, 0], [30, 100], [0, 100]],
    [[30, 0], [76, 0], [72, 24], [30, 24]],
    [[76, 0], [100, 20], [100, 42], [76, 62], [72, 38], [72, 24]],
    [[30, 38], [72, 38], [76, 62], [30, 62]],
    [[48, 62], [78, 62], [100, 100], [66, 100]],
  ] },
  L: { w: 88, parts: [
    [[0, 0], [30, 0], [30, 100], [0, 100]],
    [[30, 76], [88, 76], [88, 100], [30, 100]],
  ] },
  I: { w: 30, parts: [[[0, 0], [30, 0], [30, 100], [0, 100]]] },
  C: { w: 88, parts: [
    [[24, 0], [88, 0], [88, 24], [36, 24]],
    [[0, 24], [24, 0], [36, 24], [30, 30]],
    [[0, 24], [30, 30], [30, 70], [0, 76]],
    [[0, 76], [30, 70], [36, 76], [24, 100]],
    [[24, 100], [36, 76], [88, 76], [88, 100]],
  ] },
  O: { w: 100, parts: [
    [[24, 0], [76, 0], [64, 24], [36, 24]],
    [[76, 0], [100, 24], [70, 30], [64, 24]],
    [[100, 24], [100, 76], [70, 70], [70, 30]],
    [[100, 76], [76, 100], [64, 76], [70, 70]],
    [[24, 100], [36, 76], [64, 76], [76, 100]],
    [[0, 24], [24, 0], [36, 24], [30, 30]],
    [[0, 24], [30, 30], [30, 70], [0, 76]],
    [[0, 76], [30, 70], [36, 76], [24, 100]],
  ] },
};

function subdivide(tri, maxEdge, rand, out) {
  const [a, b, c] = tri;
  const dist = (p, q) => Math.hypot(p[0] - q[0], p[1] - q[1]);
  const ab = dist(a, b), bc = dist(b, c), ca = dist(c, a);
  const longest = Math.max(ab, bc, ca);
  if (longest <= maxEdge) {
    out.push(tri);
    return;
  }
  const t = 0.38 + rand() * 0.24;
  const cut = (p, q) => [p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t];
  if (longest === ab) {
    const m = cut(a, b);
    subdivide([a, m, c], maxEdge, rand, out);
    subdivide([m, b, c], maxEdge, rand, out);
  } else if (longest === bc) {
    const m = cut(b, c);
    subdivide([a, b, m], maxEdge, rand, out);
    subdivide([a, m, c], maxEdge, rand, out);
  } else {
    const m = cut(c, a);
    subdivide([a, b, m], maxEdge, rand, out);
    subdivide([m, b, c], maxEdge, rand, out);
  }
}

// 用切割线把三角形分到两侧；跨线的三角形被裁成一个三角形和一个四边形。
function splitByLine(tri, px, py, nx, ny, out) {
  const side = tri.map((v) => (v[0] - px) * nx + (v[1] - py) * ny);
  const positive = side.filter((s) => s >= 0).length;
  if (positive === 3 || positive === 0) {
    out.push({ tri, part: positive === 3 ? 1 : -1 });
    return;
  }
  const up = [], down = [];
  for (let i = 0; i < 3; i++) {
    const j = (i + 1) % 3;
    const p = tri[i], q = tri[j];
    (side[i] >= 0 ? up : down).push(p);
    if ((side[i] >= 0) !== (side[j] >= 0)) {
      const t = side[i] / (side[i] - side[j]);
      const m = [p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t];
      up.push(m);
      down.push(m);
    }
  }
  for (const [poly, part] of [[up, 1], [down, -1]]) {
    for (let i = 1; i < poly.length - 1; i++) out.push({ tri: [poly[0], poly[i], poly[i + 1]], part });
  }
}

function createWord(w, h, narrow, rtl) {
  const rand = rng(1307);
  const lines = ['KERLICO'];
  const gapUnits = 10;
  const widths = lines.map((line) => [...line].reduce((sum, ch, i) => sum + GLYPHS[ch].w + (i ? gapUnits : 0), 0));
  const widest = Math.max(...widths);
  const W = narrow ? w - 48 : Math.min(w * 0.68, 1120);
  const sx = W / widest;
  const lineH = Math.min(h * 0.26, sx * 132);
  const sy = lineH / 100;
  const top = Math.max(84, h * (narrow ? 0.24 : 0.18));
  const left = (w - W) / 2;
  const lineGap = lineH * 0.1;
  const totalH = lines.length * lineH + (lines.length - 1) * lineGap;

  const raw = [];
  const maxEdge = Math.max(46, W / 16);
  lines.forEach((line, row) => {
    const start = rtl ? left + W - widths[row] * sx : left;
    let cursor = start;
    const y0 = top + row * (lineH + lineGap);
    for (const ch of line) {
      const glyph = GLYPHS[ch];
      for (const poly of glyph.parts) {
        const pts = poly.map(([x, y]) => [cursor + x * sx, y0 + y * sy]);
        for (let i = 1; i < pts.length - 1; i++) subdivide([pts[0], pts[i], pts[i + 1]], maxEdge, rand, raw);
      }
      cursor += (glyph.w + gapUnits) * sx;
    }
  });

  const rise = (rtl ? 1 : -1) * totalH * 0.3;
  const angle = Math.atan2(rise, W);
  const tx = Math.cos(angle), ty = Math.sin(angle);
  const nx = -ty, ny = tx;
  const px = w / 2, py = top + totalH * 0.5;
  const pieces = [];
  for (const tri of raw) splitByLine(tri, px, py, nx, ny, pieces);

  const n = pieces.length;
  const word = {
    n,
    pos: new Float32Array(n * 6),
    part: new Int8Array(n),
    cx: new Float32Array(n),
    cy: new Float32Array(n),
    fx: new Float32Array(n),
    fy: new Float32Array(n),
    fr: new Float32Array(n),
    delay: new Float32Array(n),
    nx: new Float32Array(n),
    ny: new Float32Array(n),
    nz: new Float32Array(n),
    tone: new Float32Array(n),
    bottom: top + totalH,
    cut: { px, py, tx, ty, nx, ny, shift: W * 0.004, gap: Math.max(1.5, W * 0.0016), len: W * 0.56 },
    buf: new Float32Array((n * 2 + 2) * 15),
  };
  const diag = Math.hypot(w, h);
  pieces.forEach(({ tri, part }, i) => {
    tri.forEach((v, k) => {
      word.pos[i * 6 + k * 2] = v[0];
      word.pos[i * 6 + k * 2 + 1] = v[1];
    });
    const cx = (tri[0][0] + tri[1][0] + tri[2][0]) / 3;
    const cy = (tri[0][1] + tri[1][1] + tri[2][1]) / 3;
    word.cx[i] = cx;
    word.cy[i] = cy;
    word.part[i] = part;
    const a = rand() * Math.PI * 2;
    const reach = diag * (0.35 + rand() * 0.55);
    word.fx[i] = Math.cos(a) * reach;
    word.fy[i] = Math.sin(a) * reach;
    word.fr[i] = (rand() - 0.5) * 9;
    word.delay[i] = 0.12 + 0.34 * Math.abs(cx - w / 2) / (w / 2) * 0.5 + rand() * 0.2;
    const tiltX = (rand() - 0.5) * 0.95, tiltY = (rand() - 0.5) * 0.95;
    const len = Math.hypot(tiltX, tiltY, 1);
    word.nx[i] = tiltX / len;
    word.ny[i] = tiltY / len;
    word.nz[i] = 1 / len;
    word.tone[i] = rand();
  });
  return word;
}
