const DIAGRAM_NODES = {
  in4: { kind: 'in', label: 'disp.l_in4' },
  in6: { kind: 'in', label: 'disp.l_in6' },
  loc: { kind: 'in', label: 'disp.l_loc' },
  disp: { kind: 'hub', text: 'Dispatcher' },
  local: { kind: 'fork', text: 'Local' },
  remote: { kind: 'fork', text: 'Remote' },
  resolve: { kind: 'step', label: 'disp.l_resolve' },
  n4: { kind: 'exit', text: 'IPv4' },
  n6: { kind: 'exit', text: 'IPv6' },
  warp: { kind: 'exit', label: 'disp.l_warp' },
  target: { kind: 'end', label: 'disp.l_target' },
  pa: { kind: 'proxy', text: 'proxy-a' },
  pb: { kind: 'proxy', text: 'proxy-b' },
  pc: { kind: 'proxy', text: 'proxy-c' },
};

// stage 是这条边开始点亮的讲解步骤。
const DIAGRAM_EDGES = [
  ['in4', 'disp', 0], ['in6', 'disp', 0], ['loc', 'disp', 0],
  ['disp', 'local', 1], ['disp', 'remote', 1],
  ['local', 'resolve', 2], ['resolve', 'n4', 2], ['resolve', 'n6', 2], ['resolve', 'warp', 2, true],
  ['n4', 'target', 2], ['n6', 'target', 2], ['warp', 'target', 2, true],
  ['remote', 'pa', 3], ['remote', 'pb', 3], ['remote', 'pc', 3],
];

const DIAGRAM_LAYOUTS = {
  wide: {
    w: 1000, h: 640, hub: 74, node: 15,
    at: {
      in4: [74, 84], in6: [122, 318], loc: [52, 552], disp: [356, 300],
      local: [566, 168], remote: [590, 462], resolve: [690, 92],
      n4: [842, 40], n6: [872, 150], warp: [822, 268], target: [966, 138],
      pa: [832, 382], pb: [884, 482], pc: [820, 590],
    },
    notes: { proxy: [920, 398], keep: [628, 560] },
  },
  tall: {
    w: 360, h: 620, hub: 46, node: 11,
    at: {
      in4: [52, 34], in6: [180, 22], loc: [308, 40], disp: [180, 142],
      local: [86, 262], remote: [276, 262], resolve: [60, 346],
      n4: [26, 440], n6: [94, 452], warp: [164, 424], target: [84, 556],
      pa: [226, 372], pb: [282, 424], pc: [334, 366],
    },
    notes: { proxy: [282, 492], keep: [268, 318] },
  },
};

const PACKET_COLORS = { in4: '#2D4BFF', in6: '#FF4B2B', loc: '#EFE9DC' };
const CHIP_LOCAL = {
  n4: '203.0.113.7:443',
  n6: '[2001:db8::7]:443',
  warp: 'Warp6 [2001:db8::7]:443',
};
const CHIP_DOMAIN = 'example.com:443';

function createDispatcher(host, steps, labels, rtl, reduced) {
  const NS = 'http://www.w3.org/2000/svg';
  const make = (parent, name, attrs, text) => {
    const el = document.createElementNS(NS, name);
    for (const key in attrs) el.setAttribute(key, attrs[key]);
    if (text !== undefined) el.textContent = text;
    parent.appendChild(el);
    return el;
  };
  const rand = rng(42);
  let layout, at, svg, hubEl, edgeEls = [], nodeEls = [];
  let packets = [];
  let chips = {};
  let stage = reduced ? 3 : 0;
  let spawn = 0;
  let pulse = 0;
  const api = { visible: false };

  const triPoints = (r) => `0,${-r} ${r * 0.866},${r * 0.5} ${-r * 0.866},${r * 0.5}`;

  const applyStage = () => {
    edgeEls.forEach(({ el, stage: s }) => el.classList.toggle('on', stage >= s));
    nodeEls.forEach(({ el, stage: s }) => el.classList.toggle('on', stage >= s));
    steps.forEach((li, i) => {
      li.classList.toggle('active', i === stage);
      li.setAttribute('aria-current', i === stage ? 'step' : 'false');
    });
  };

  const nodeStage = (id) => {
    let least = 3;
    for (const edge of DIAGRAM_EDGES) {
      if (edge[0] === id || edge[1] === id) least = Math.min(least, edge[2]);
    }
    return least;
  };

  const placeText = (el, x, y, anchor) => {
    el.setAttribute('x', x);
    el.setAttribute('y', y);
    el.setAttribute('text-anchor', anchor);
  };

  const build = (narrow) => {
    host.textContent = '';
    layout = DIAGRAM_LAYOUTS[narrow ? 'tall' : 'wide'];
    at = {};
    for (const id in layout.at) {
      const [x, y] = layout.at[id];
      at[id] = [rtl ? layout.w - x : x, y];
    }
    const W = layout.w, H = layout.h;
    svg = make(host, 'svg', { viewBox: `0 0 ${W} ${H}`, class: narrow ? 'tall' : 'wide', 'aria-hidden': 'true' });

    // 外露的结构线：过枢纽的两条不对齐基准线和外接圆。
    const [hx, hy] = at.disp;
    make(svg, 'line', { x1: 0, y1: hy + 34, x2: W, y2: hy - 26, class: 'construct' });
    make(svg, 'line', { x1: hx - 30, y1: 0, x2: hx + 22, y2: H, class: 'construct' });
    make(svg, 'circle', { cx: hx, cy: hy, r: layout.hub * 1.32, class: 'construct dash' });
    make(svg, 'text', { x: hx + layout.hub * 1.1 * (rtl ? -1 : 1), y: hy - layout.hub * 1.18, class: 'coordtext', 'text-anchor': rtl ? 'end' : 'start', dir: 'ltr' }, `(${hx},${hy})`);

    edgeEls = DIAGRAM_EDGES.map(([a, b, s, dash]) => {
      const el = make(svg, 'line', {
        x1: at[a][0], y1: at[a][1], x2: at[b][0], y2: at[b][1],
        class: `edge${dash ? ' dash' : ''}`,
      });
      return { el, stage: s };
    });

    nodeEls = [];
    for (const id in DIAGRAM_NODES) {
      const node = DIAGRAM_NODES[id];
      const [x, y] = at[id];
      const g = make(svg, 'g', { class: `node k-${node.kind}`, transform: `translate(${x},${y})` });
      const r = node.kind === 'hub' ? layout.hub : node.kind === 'fork' ? layout.node * 1.5 : layout.node;
      const shape = make(g, 'polygon', { points: triPoints(r) });
      if (node.kind === 'hub') hubEl = shape;
      const text = node.text || labels[node.label];
      const below = node.kind === 'in' && narrow ? -r - 6 : r + (narrow ? 13 : 19);
      const label = make(g, 'text', { y: below, 'text-anchor': 'middle' }, text);
      if (node.text) label.setAttribute('direction', 'ltr');
      if (node.kind === 'hub') {
        make(g, 'text', { y: r * 0.34, 'text-anchor': 'middle', class: 'hubmark', direction: 'ltr' }, '×1');
      }
      nodeEls.push({ el: g, stage: nodeStage(id) });
    }

    const proxy = make(svg, 'text', { class: 'dnote', 'text-anchor': 'middle' }, labels['disp.l_proxy']);
    placeText(proxy, rtl ? W - layout.notes.proxy[0] : layout.notes.proxy[0], layout.notes.proxy[1], 'middle');
    const keep = make(svg, 'text', { class: 'dnote acid', 'text-anchor': 'middle' }, labels['disp.l_keep']);
    placeText(keep, rtl ? W - layout.notes.keep[0] : layout.notes.keep[0], layout.notes.keep[1], 'middle');
    nodeEls.push({ el: proxy, stage: 3 }, { el: keep, stage: 3 });

    packets = [];
    const count = narrow ? 18 : 28;
    const size = narrow ? 7 : 11;
    for (let i = 0; i < count; i++) {
      const el = make(svg, 'polygon', { points: triPoints(size), class: 'packet', visibility: 'hidden' });
      packets.push({ el, active: false, pts: null, lens: null, total: 0, s: 0, speed: 0, exit: null, chip: null, resolveAt: 0, src: '' });
    }

    const makeChip = (cls) => {
      const g = make(svg, 'g', { class: `chip ${cls}`, visibility: 'hidden' });
      const rect = make(g, 'rect', { rx: 0, ry: 0 });
      const text = make(g, 'text', { 'text-anchor': 'middle', y: 4, direction: 'ltr' }, CHIP_DOMAIN);
      return { g, rect, text, packet: null, shown: '' };
    };
    chips = { local: makeChip('c-local'), remote: makeChip('c-remote') };
    applyStage();
  };

  const setChipText = (chip, value) => {
    if (chip.shown === value) return;
    chip.shown = value;
    chip.text.textContent = value;
    const width = Math.max(40, chip.text.getComputedTextLength() + 12);
    chip.rect.setAttribute('x', -width / 2);
    chip.rect.setAttribute('width', width);
    chip.rect.setAttribute('y', -9);
    chip.rect.setAttribute('height', 18);
    chip.width = width;
  };

  const pickRoute = () => {
    const srcs = ['in4', 'in6', 'loc'];
    const src = srcs[Math.floor(rand() * 3)];
    if (stage === 0) return { src, ids: [src, 'disp'] };
    const branch = stage === 2 || rand() < 0.5 ? 'local' : 'remote';
    if (branch === 'local') {
      if (stage === 1) return { src, ids: [src, 'disp', 'local'] };
      const roll = rand();
      const exit = roll < 0.45 ? 'n4' : roll < 0.8 ? 'n6' : 'warp';
      return { src, ids: [src, 'disp', 'local', 'resolve', exit, 'target'], exit, branch };
    }
    if (stage === 1) return { src, ids: [src, 'disp', 'remote'] };
    const proxy = ['pa', 'pb', 'pc'][Math.floor(rand() * 3)];
    return { src, ids: [src, 'disp', 'remote', proxy], branch };
  };

  const launch = (packet, route) => {
    const pts = route.ids.map((id) => at[id]);
    const lens = [];
    let total = 0;
    for (let i = 1; i < pts.length; i++) {
      total += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
      lens.push(total);
    }
    packet.active = true;
    packet.pts = pts;
    packet.lens = lens;
    packet.total = total;
    packet.s = 0;
    packet.speed = (layout.w > 500 ? 300 : 150) * (0.85 + rand() * 0.3);
    packet.src = route.src;
    packet.exit = route.exit || null;
    packet.hubAt = lens[0];
    packet.hubbed = false;
    packet.resolveAt = route.exit ? lens[2] : Infinity;
    packet.chip = null;
    packet.el.setAttribute('fill', PACKET_COLORS[route.src]);
    packet.el.setAttribute('visibility', 'visible');
    if (route.branch === 'local' && !chips.local.packet) {
      chips.local.packet = packet;
      packet.chip = chips.local;
      setChipText(chips.local, CHIP_DOMAIN);
      chips.local.g.setAttribute('visibility', 'visible');
    } else if (route.branch === 'remote' && !chips.remote.packet) {
      chips.remote.packet = packet;
      packet.chip = chips.remote;
      setChipText(chips.remote, CHIP_DOMAIN);
      chips.remote.g.setAttribute('visibility', 'visible');
    }
  };

  const place = (packet) => {
    const { pts, lens } = packet;
    let i = 0;
    while (i < lens.length - 1 && packet.s > lens[i]) i++;
    const prev = i === 0 ? 0 : lens[i - 1];
    const t = clamp((packet.s - prev) / (lens[i] - prev), 0, 1);
    const x = lerp(pts[i][0], pts[i + 1][0], t);
    const y = lerp(pts[i][1], pts[i + 1][1], t);
    const deg = Math.atan2(pts[i + 1][1] - pts[i][1], pts[i + 1][0] - pts[i][0]) / RAD + 90;
    packet.el.setAttribute('transform', `translate(${x.toFixed(1)},${y.toFixed(1)}) rotate(${deg.toFixed(0)})`);
    if (packet.chip) {
      if (packet.exit && packet.s >= packet.resolveAt) setChipText(packet.chip, CHIP_LOCAL[packet.exit]);
      const half = (packet.chip.width || 80) / 2;
      const cx = clamp(x, half + 2, layout.w - half - 2);
      packet.chip.g.setAttribute('transform', `translate(${cx.toFixed(1)},${(y - 20).toFixed(1)})`);
    }
  };

  api.setStage = (next) => {
    if (next === stage) return;
    stage = next;
    applyStage();
  };

  api.tick = (dt) => {
    if (!api.visible) return;
    spawn -= dt;
    if (spawn <= 0) {
      const free = packets.find((p) => !p.active);
      if (free) launch(free, pickRoute());
      spawn = layout.w > 500 ? 0.11 + rand() * 0.12 : 0.17 + rand() * 0.16;
    }
    for (const packet of packets) {
      if (!packet.active) continue;
      packet.s += packet.speed * dt;
      if (!packet.hubbed && packet.s >= packet.hubAt) {
        packet.hubbed = true;
        pulse = 1;
      }
      if (packet.s >= packet.total) {
        packet.active = false;
        packet.el.setAttribute('visibility', 'hidden');
        if (packet.chip) {
          packet.chip.packet = null;
          packet.chip.g.setAttribute('visibility', 'hidden');
          packet.chip = null;
        }
        continue;
      }
      place(packet);
    }
    pulse = Math.max(0, pulse - dt * 5);
    if (hubEl) hubEl.setAttribute('transform', `scale(${(1 + pulse * 0.07).toFixed(3)})`);
  };

  // 减少动态时把若干数据包定格在各条路线中段，图仍然讲清分流关系。
  const freeze = () => {
    const frozen = [
      { src: 'in4', ids: ['in4', 'disp'], at: 0.55 },
      { src: 'in6', ids: ['in6', 'disp'], at: 0.5 },
      { src: 'loc', ids: ['loc', 'disp'], at: 0.62 },
      { src: 'in4', ids: ['in4', 'disp', 'local', 'resolve', 'n4', 'target'], exit: 'n4', branch: 'local', at: 0.78 },
      { src: 'in6', ids: ['in6', 'disp', 'local', 'resolve', 'n6', 'target'], exit: 'n6', at: 0.9 },
      { src: 'loc', ids: ['loc', 'disp', 'local', 'resolve', 'warp', 'target'], exit: 'warp', at: 0.86 },
      { src: 'in4', ids: ['in4', 'disp', 'remote', 'pa'], branch: 'remote', at: 0.82 },
      { src: 'in6', ids: ['in6', 'disp', 'remote', 'pb'], at: 0.9 },
      { src: 'loc', ids: ['loc', 'disp', 'remote', 'pc'], at: 0.88 },
    ];
    frozen.forEach((route, i) => {
      const packet = packets[i];
      launch(packet, route);
      packet.s = packet.total * route.at;
      place(packet);
    });
  };

  api.rebuild = (narrow) => {
    build(narrow);
    if (reduced) freeze();
  };
  return api;
}
