const clamp = (v, a, b) => (v < a ? a : v > b ? b : v);
const lerp = (a, b, t) => a + (b - a) * t;
const sstep = (a, b, v) => {
  const t = clamp((v - a) / (b - a), 0, 1);
  return t * t * (3 - 2 * t);
};
const easeOutExpo = (t) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t));
const easeOutBack = (t) => {
  const u = t - 1;
  return 1 + 2.4 * u * u * u + 1.4 * u * u;
};
const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
const RAD = Math.PI / 180;

const INK = hex('#10131C');
const BONE = hex('#EFE9DC');
const VERMILION = hex('#FF4B2B');
const COBALT = hex('#2D4BFF');
const ACID = hex('#D7FF3E');
const GRAPHITE = hex('#3A3F4D');

function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function circumcircle(p, a, b, c) {
  const ax = p[a * 2], ay = p[a * 2 + 1];
  const bx = p[b * 2], by = p[b * 2 + 1];
  const cx = p[c * 2], cy = p[c * 2 + 1];
  const d = 2 * (ax * (by - cy) + bx * (cy - ay) + cx * (ay - by)) || 1e-9;
  const a2 = ax * ax + ay * ay, b2 = bx * bx + by * by, c2 = cx * cx + cy * cy;
  const x = (a2 * (by - cy) + b2 * (cy - ay) + c2 * (ay - by)) / d;
  const y = (a2 * (cx - bx) + b2 * (ax - cx) + c2 * (bx - ax)) / d;
  const dx = ax - x, dy = ay - y;
  return { a, b, c, x, y, r: dx * dx + dy * dy };
}

// Bowyer-Watson：按 x 排序扫描，圆已被扫过的三角形移出活动表，点数少时接近线性。
function delaunay(points) {
  const n = points.length / 2;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (let i = 0; i < n; i++) {
    const x = points[i * 2], y = points[i * 2 + 1];
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  }
  const span = Math.max(maxX - minX, maxY - minY) || 1;
  const midX = (minX + maxX) / 2, midY = (minY + maxY) / 2;
  const p = new Float64Array(n * 2 + 6);
  p.set(points);
  p.set([midX - 20 * span, midY - span, midX, midY + 20 * span, midX + 20 * span, midY - span], n * 2);

  const order = Array.from({ length: n }, (_, i) => i).sort((a, b) => points[a * 2] - points[b * 2]);
  let open = [circumcircle(p, n, n + 1, n + 2)];
  const closed = [];
  for (const i of order) {
    const x = p[i * 2], y = p[i * 2 + 1];
    const edges = [];
    const kept = [];
    for (const t of open) {
      const dx = x - t.x;
      if (dx > 0 && dx * dx > t.r) {
        closed.push(t);
        continue;
      }
      const dy = y - t.y;
      if (dx * dx + dy * dy - t.r > 1e-9) {
        kept.push(t);
        continue;
      }
      edges.push(t.a, t.b, t.b, t.c, t.c, t.a);
    }
    for (let e = edges.length - 2; e >= 0; e -= 2) {
      const a = edges[e], b = edges[e + 1];
      if (a < 0) continue;
      for (let f = e - 2; f >= 0; f -= 2) {
        const c = edges[f], d = edges[f + 1];
        if ((a === c && b === d) || (a === d && b === c)) {
          edges[e] = edges[e + 1] = edges[f] = edges[f + 1] = -1;
          break;
        }
      }
    }
    for (let e = 0; e < edges.length; e += 2) {
      if (edges[e] >= 0) kept.push(circumcircle(p, edges[e], edges[e + 1], i));
    }
    open = kept;
  }
  const out = [];
  for (const t of closed.concat(open)) {
    if (t.a < n && t.b < n && t.c < n) out.push(t.a, t.b, t.c);
  }
  return new Uint32Array(out);
}
