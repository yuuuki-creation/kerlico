// 每帧由这份状态决定网格和字形的全部形变与明暗，栅格化层只读结果。
function createFrameState() {
  return {
    t: 0,
    lightX: 0, lightY: 0, lightZ: 300,
    angle: -24 * RAD, crackX: 0.6, crackY: 0.5,
    gap: 10, slide: 40, burst: 0,
    rampAngle: -35 * RAD, rampOff: 0,
    intro: 1, breath: 1,
    sliceP: 1, cutFlash: 0, wordScatter: 0, scrollY: 0,
  };
}

function createField(w, h, narrow) {
  const rand = rng(20261103);
  const margin = Math.max(90, w * 0.08);
  const cell = narrow ? 62 : clamp(Math.sqrt((w * h) / 400), 54, 86);
  const pts = [];
  const x0 = -margin, y0 = -margin;
  const cols = Math.ceil((w + margin * 2) / cell);
  const rows = Math.ceil((h + margin * 2) / cell);
  for (let r = 0; r <= rows; r++) {
    for (let c = 0; c <= cols; c++) {
      const edge = r === 0 || c === 0 || r === rows || c === cols;
      const jitter = edge ? 0.12 : 0.78;
      pts.push(x0 + (c + (rand() - 0.5) * jitter) * cell, y0 + (r + (rand() - 0.5) * jitter) * cell);
    }
  }
  // 中带加密：小三角形集中在画面中部，边角留大块面，读起来是低多边形而不是噪点。
  const extra = Math.round(cols * rows * 0.42);
  for (let i = 0; i < extra; i++) {
    const u = rand(), v = rand();
    const x = lerp(w * 0.08, w * 0.92, u);
    const y = h * 0.5 + (x - w / 2) * -0.35 + (v - 0.5) * h * 0.5;
    pts.push(x + (rand() - 0.5) * cell * 0.4, y);
  }
  const tris = delaunay(Float64Array.from(pts));
  const vCount = pts.length / 2;
  const tCount = tris.length / 3;
  const f = {
    w, h, vCount, tCount, tris,
    diag: Math.hypot(w, h),
    vx: Float32Array.from(pts),
    vz: new Float32Array(vCount),
    vp: new Float32Array(vCount),
    wx: new Float32Array(vCount),
    wy: new Float32Array(vCount),
    wz: new Float32Array(vCount),
    cx: new Float32Array(tCount),
    cy: new Float32Array(tCount),
    r1: new Float32Array(tCount),
    r2: new Float32Array(tCount),
    tone: new Float32Array(tCount),
    fx: new Float32Array(tCount),
    fy: new Float32Array(tCount),
    fr: new Float32Array(tCount),
    delay: new Float32Array(tCount),
    triBuf: new Float32Array(tCount * 15),
    lineBuf: new Float32Array(tCount * 30),
  };
  for (let i = 0; i < vCount; i++) {
    const x = f.vx[i * 2], y = f.vx[i * 2 + 1];
    const low = Math.sin(x * 0.006 + 1.3) * Math.cos(y * 0.008 - 0.4) + 0.5 * Math.sin((x + y) * 0.013);
    f.vz[i] = low * cell * 0.7 + (rand() - 0.5) * cell * 0.95;
    f.vp[i] = rand() * Math.PI * 2;
  }
  const cxMid = w / 2, cyMid = h / 2;
  for (let i = 0; i < tCount; i++) {
    const a = tris[i * 3], b = tris[i * 3 + 1], c = tris[i * 3 + 2];
    const cx = (f.vx[a * 2] + f.vx[b * 2] + f.vx[c * 2]) / 3;
    const cy = (f.vx[a * 2 + 1] + f.vx[b * 2 + 1] + f.vx[c * 2 + 1]) / 3;
    f.cx[i] = cx;
    f.cy[i] = cy;
    f.r1[i] = rand();
    f.r2[i] = rand();
    f.tone[i] = (rand() - 0.5) * 0.16;
    const ang = Math.atan2(cy - cyMid, cx - cxMid) + (rand() - 0.5) * 1.3;
    const reach = f.diag * (0.3 + rand() * 0.7);
    f.fx[i] = Math.cos(ang) * reach;
    f.fy[i] = Math.sin(ang) * reach;
    f.fr[i] = (rand() - 0.5) * 7;
    f.delay[i] = 0.04 + 0.3 * (Math.hypot(cx - cxMid, cy - cyMid) / (f.diag / 2)) + rand() * 0.16;
  }
  return f;
}

function rampColor(u, out) {
  const t = clamp(u, 0, 1);
  const from = t < 0.5 ? COBALT : GRAPHITE;
  const to = t < 0.5 ? GRAPHITE : VERMILION;
  const k = t < 0.5 ? t * 2 : (t - 0.5) * 2;
  out[0] = lerp(from[0], to[0], k);
  out[1] = lerp(from[1], to[1], k);
  out[2] = lerp(from[2], to[2], k);
}

const scratch = [0, 0, 0];
const MESH_STRENGTH = 0.62;

// 把网格当前帧写入 triBuf / lineBuf，返回三角形数和线段数。
function emitField(f, S) {
  const { t, lightX, lightY, lightZ } = S;
  const breath = S.breath;
  const vx = f.vx, wx = f.wx, wy = f.wy, wz = f.wz;
  for (let i = 0; i < f.vCount; i++) {
    const p = f.vp[i];
    wx[i] = vx[i * 2] + Math.cos(t * 0.31 + p) * 2.6 * breath;
    wy[i] = vx[i * 2 + 1] + Math.sin(t * 0.27 + p * 1.7) * 2.6 * breath;
    wz[i] = f.vz[i] + Math.sin(t * 0.62 + p) * 9 * breath;
  }
  const nx = -Math.sin(S.angle), ny = Math.cos(S.angle);
  const tx = Math.cos(S.angle), ty = Math.sin(S.angle);
  const px = S.crackX * f.w, py = S.crackY * f.h;
  const rx = Math.cos(S.rampAngle), ry = Math.sin(S.rampAngle);
  const midX = f.w / 2, midY = f.h / 2;
  const halfDiag = f.diag / 2;
  const reach = S.burst * f.diag * 1.5 + 1;
  const falloff = (f.diag * 0.62) * (f.diag * 0.62);
  const introing = S.intro < 1;
  let tn = 0;
  const tb = f.triBuf, tris = f.tris;

  for (let i = 0; i < f.tCount; i++) {
    const a = tris[i * 3], b = tris[i * 3 + 1], c = tris[i * 3 + 2];
    const cx = f.cx[i], cy = f.cy[i];
    const d = (cx - px) * nx + (cy - py) * ny;
    const side = d < 0 ? -1 : 1;
    const ad = d < 0 ? -d : d;
    const hit = 1 - ad / reach;
    const bk = hit > 0 ? S.burst * hit * (0.3 + 0.7 * f.r1[i]) : 0;

    const push = S.gap * 0.5 + bk * (50 + 190 * f.r2[i]);
    const shear = side * S.slide * 0.5 + bk * (f.r1[i] - 0.5) * 240;
    let ox = nx * side * push + tx * shear;
    let oy = ny * side * push + ty * shear;
    let rot = bk * (f.r2[i] - 0.5) * 3.2;
    let scale = 1 - bk * 0.62;
    if (introing) {
      const k = easeOutExpo(clamp((S.intro - f.delay[i]) / 0.5, 0, 1));
      const left = 1 - k;
      ox += f.fx[i] * left;
      oy += f.fy[i] * left;
      rot += f.fr[i] * left;
      scale *= 0.2 + 0.8 * k;
    }
    const cos = Math.cos(rot), sin = Math.sin(rot);
    const ccx = cx + ox, ccy = cy + oy;
    const ax = wx[a] - cx, ay = wy[a] - cy;
    const bx = wx[b] - cx, by = wy[b] - cy;
    const dx = wx[c] - cx, dy = wy[c] - cy;
    const x0 = ccx + scale * (ax * cos - ay * sin), y0 = ccy + scale * (ax * sin + ay * cos);
    const x1 = ccx + scale * (bx * cos - by * sin), y1 = ccy + scale * (bx * sin + by * cos);
    const x2 = ccx + scale * (dx * cos - dy * sin), y2 = ccy + scale * (dx * sin + dy * cos);

    const e1x = wx[b] - wx[a], e1y = wy[b] - wy[a], e1z = wz[b] - wz[a];
    const e2x = wx[c] - wx[a], e2y = wy[c] - wy[a], e2z = wz[c] - wz[a];
    let nnx = e1y * e2z - e1z * e2y;
    let nny = e1z * e2x - e1x * e2z;
    let nnz = e1x * e2y - e1y * e2x;
    if (nnz < 0) { nnx = -nnx; nny = -nny; nnz = -nnz; }
    const nlen = Math.sqrt(nnx * nnx + nny * nny + nnz * nnz) || 1;
    nnx = nnx / nlen + rot * 0.9;
    nny /= nlen;
    nnz /= nlen;
    const lx = lightX - ccx, ly = lightY - ccy, lz = lightZ;
    const dist2 = lx * lx + ly * ly + lz * lz;
    const ilen = 1 / Math.sqrt(dist2);
    const att = 1 / (1 + dist2 / falloff);
    const dot = Math.max(0, (nnx * lx + nny * ly + nnz * lz) * ilen);
    const shade = 0.16 + dot * att * 1.15;
    const spec = Math.pow(dot, 12) * att * 0.22;

    const u = ((cx - midX) * rx + (cy - midY) * ry) / halfDiag * 0.62 + 0.5 + S.rampOff + f.tone[i];
    rampColor(u, scratch);
    // 网格只是氛围，向底色收一些，前面的文字才是主角。
    const cr = lerp(INK[0], scratch[0] * shade + spec * BONE[0], MESH_STRENGTH);
    const cg = lerp(INK[1], scratch[1] * shade + spec * BONE[1], MESH_STRENGTH);
    const cb = lerp(INK[2], scratch[2] * shade + spec * BONE[2], MESH_STRENGTH);
    const base = tn * 5;
    tb[base] = x0; tb[base + 1] = y0; tb[base + 2] = cr; tb[base + 3] = cg; tb[base + 4] = cb;
    tb[base + 5] = x1; tb[base + 6] = y1; tb[base + 7] = cr; tb[base + 8] = cg; tb[base + 9] = cb;
    tb[base + 10] = x2; tb[base + 11] = y2; tb[base + 12] = cr; tb[base + 13] = cg; tb[base + 14] = cb;
    tn += 3;
  }
  f.triCount = tn;
  f.lineCount = 0;
}

function emitWord(word, S, diag) {
  const buf = word.buf;
  const cut = word.cut;
  const introing = S.intro < 1;
  const scatter = S.wordScatter;
  if (scatter >= 1) {
    word.count = 0;
    return;
  }
  let n = 0;
  const yOff = -S.scrollY;
  const push = (x, y, r, g, b) => {
    const base = n * 5;
    buf[base] = x; buf[base + 1] = y; buf[base + 2] = r; buf[base + 3] = g; buf[base + 4] = b;
    n++;
  };
  const falloff = (diag * 0.6) * (diag * 0.6);
  for (let pass = 0; pass < 2; pass++) {
    for (let i = 0; i < word.n; i++) {
      const part = word.part[i];
      const shift = cut.shift * S.sliceP * (part > 0 ? 1 : -0.45);
      const gap = cut.gap * S.sliceP * part;
      let ox = cut.tx * shift + cut.nx * gap;
      let oy = cut.ty * shift + cut.ny * gap + yOff;
      let rot = 0, scale = 1;
      if (scatter > 0) {
        // 往下滚时大字重新碎开，碎片飞向开场时来的方向。
        const k = sstep(word.delay[i] * 0.5, 0.5 + word.delay[i] * 0.5, scatter);
        ox += word.fx[i] * k * 0.8;
        oy += word.fy[i] * k * 0.8;
        rot = word.fr[i] * k;
        scale = 1 - k;
      }
      if (introing) {
        const k = easeOutExpo(clamp((S.intro - word.delay[i]) / 0.36, 0, 1));
        const left = 1 - k;
        ox += word.fx[i] * left;
        oy += word.fy[i] * left;
        rot = word.fr[i] * left;
        scale = 0.3 + 0.7 * k;
      }
      const cx = word.cx[i], cy = word.cy[i];
      const ccx = cx + ox, ccy = cy + oy;
      if (ccy < -220 || ccy > S.vh + 220) continue;
      let r, g, b;
      if (pass === 0) {
        r = INK[0]; g = INK[1]; b = INK[2];
      } else {
        const lx = S.lightX - ccx, ly = S.lightY - ccy, lz = S.lightZ;
        const d2 = lx * lx + ly * ly + lz * lz;
        const il = 1 / Math.sqrt(d2);
        const att = 1 / (1 + d2 / falloff);
        const dot = Math.max(0, (word.nx[i] * lx + word.ny[i] * ly + word.nz[i] * lz) * il);
        const lum = 0.66 + word.tone[i] * 0.08 + dot * att * 0.58;
        r = BONE[0] * lum; g = BONE[1] * lum; b = BONE[2] * lum;
      }
      const sh = pass === 0 ? 3 : 0;
      const cos = Math.cos(rot), sin = Math.sin(rot);
      for (let k = 0; k < 3; k++) {
        const vx = word.pos[i * 6 + k * 2] - cx, vy = word.pos[i * 6 + k * 2 + 1] - cy;
        push(ccx + sh + scale * (vx * cos - vy * sin), ccy + sh + scale * (vx * sin + vy * cos), r, g, b);
      }
    }
  }
  if (S.cutFlash > 0) {
    const reach = cut.len * S.cutFlash;
    const hw = 1.6;
    const ax = cut.px - cut.tx * cut.len, ay = cut.py - cut.ty * cut.len + yOff;
    const bx = ax + cut.tx * reach * 2, by = ay + cut.ty * reach * 2;
    const qx = cut.nx * hw, qy = cut.ny * hw;
    push(ax - qx, ay - qy, BONE[0], BONE[1], BONE[2]);
    push(ax + qx, ay + qy, BONE[0], BONE[1], BONE[2]);
    push(bx + qx, by + qy, BONE[0], BONE[1], BONE[2]);
    push(ax - qx, ay - qy, BONE[0], BONE[1], BONE[2]);
    push(bx + qx, by + qy, BONE[0], BONE[1], BONE[2]);
    push(bx - qx, by - qy, BONE[0], BONE[1], BONE[2]);
  }
  word.count = n;
}
