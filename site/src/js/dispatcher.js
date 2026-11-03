const DIAGRAM_NODES = {
  phone: { kind: 'in', label: 'how.l_phone' },
  laptop: { kind: 'in', label: 'how.l_laptop' },
  friend: { kind: 'in', label: 'how.l_friend' },
  hub: { kind: 'hub', text: 'Kerlico' },
  direct: { kind: 'fork', label: 'how.l_direct' },
  remote: { kind: 'fork', label: 'how.l_remote' },
  server: { kind: 'step', label: 'how.l_server' },
  site: { kind: 'end', label: 'how.l_site' },
};

// 第三项是这条边开始点亮的讲解步骤。
const DIAGRAM_EDGES = [
  ['phone', 'hub', 0], ['laptop', 'hub', 0], ['friend', 'hub', 0],
  ['hub', 'direct', 1], ['hub', 'remote', 1],
  ['direct', 'site', 2], ['remote', 'server', 2], ['server', 'site', 2],
];

const DIAGRAM_LAYOUTS = {
  wide: {
    w: 1000, h: 620, hub: 70, node: 17, speed: 260,
    at: {
      phone: [80, 110], laptop: [50, 310], friend: [80, 510], hub: [340, 310],
      direct: [610, 150], remote: [610, 470], server: [790, 470], site: [930, 300],
    },
  },
  tall: {
    w: 360, h: 560, hub: 44, node: 12, speed: 130,
    at: {
      phone: [50, 42], laptop: [180, 30], friend: [310, 42], hub: [180, 165],
      direct: [80, 310], remote: [280, 310], server: [280, 410], site: [180, 515],
    },
  },
};

const PACKET_COLORS = { phone: '#EFE9DC', laptop: '#8FA2FF', friend: '#FF6A4D' };
const SOURCES = ['phone', 'laptop', 'friend'];

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
  let layout, at, hubEl, edgeEls = [], nodeEls = [];
  let packets = [];
  let stage = reduced ? 2 : 0;
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
    let least = 2;
    for (const edge of DIAGRAM_EDGES) {
      if (edge[0] === id || edge[1] === id) least = Math.min(least, edge[2]);
    }
    return least;
  };

  const build = (narrow) => {
    host.textContent = '';
    layout = DIAGRAM_LAYOUTS[narrow ? 'tall' : 'wide'];
    at = {};
    for (const id in layout.at) {
      const [x, y] = layout.at[id];
      at[id] = [rtl ? layout.w - x : x, y];
    }
    const svg = make(host, 'svg', { viewBox: `0 0 ${layout.w} ${layout.h}`, class: narrow ? 'tall' : 'wide', 'aria-hidden': 'true' });

    edgeEls = DIAGRAM_EDGES.map(([a, b, s]) => ({
      el: make(svg, 'line', { x1: at[a][0], y1: at[a][1], x2: at[b][0], y2: at[b][1], class: 'edge' }),
      stage: s,
    }));

    nodeEls = [];
    for (const id in DIAGRAM_NODES) {
      const node = DIAGRAM_NODES[id];
      const [x, y] = at[id];
      const g = make(svg, 'g', { class: `node k-${node.kind}`, transform: `translate(${x},${y})` });
      const r = node.kind === 'hub' ? layout.hub : node.kind === 'fork' ? layout.node * 1.3 : layout.node;
      const shape = make(g, 'polygon', { points: triPoints(r) });
      if (node.kind === 'hub') hubEl = shape;
      const above = narrow && node.kind === 'in';
      const label = make(g, 'text', { y: above ? r + 15 : r + (narrow ? 16 : 26), 'text-anchor': 'middle' }, node.text || labels[node.label]);
      if (node.text) label.setAttribute('direction', 'ltr');
      nodeEls.push({ el: g, stage: nodeStage(id) });
    }

    packets = [];
    const size = narrow ? 6 : 9;
    for (let i = 0; i < (narrow ? 18 : 30); i++) {
      const el = make(svg, 'polygon', { points: triPoints(size), visibility: 'hidden' });
      packets.push({ el, active: false, pts: null, lens: null, total: 0, s: 0, speed: 0, hubAt: 0, hubbed: false });
    }
    applyStage();
  };

  const pickRoute = () => {
    const src = SOURCES[Math.floor(rand() * 3)];
    if (stage === 0) return [src, 'hub'];
    const direct = rand() < 0.5;
    if (stage === 1) return [src, 'hub', direct ? 'direct' : 'remote'];
    return direct ? [src, 'hub', 'direct', 'site'] : [src, 'hub', 'remote', 'server', 'site'];
  };

  const launch = (packet, ids) => {
    const pts = ids.map((id) => at[id]);
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
    packet.speed = layout.speed * (0.85 + rand() * 0.3);
    packet.hubAt = lens[0];
    packet.hubbed = false;
    packet.el.setAttribute('fill', PACKET_COLORS[ids[0]]);
    packet.el.setAttribute('visibility', 'visible');
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
      spawn = layout.w > 500 ? 0.13 + rand() * 0.14 : 0.2 + rand() * 0.18;
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
        continue;
      }
      place(packet);
    }
    pulse = Math.max(0, pulse - dt * 5);
    if (hubEl) hubEl.setAttribute('transform', `scale(${(1 + pulse * 0.06).toFixed(3)})`);
  };

  // 减少动态时把数据包定格在各条路线中段，图仍然讲清走向。
  const freeze = () => {
    const frozen = [
      { ids: ['phone', 'hub'], at: 0.55 },
      { ids: ['laptop', 'hub'], at: 0.5 },
      { ids: ['friend', 'hub'], at: 0.62 },
      { ids: ['phone', 'hub', 'direct', 'site'], at: 0.72 },
      { ids: ['friend', 'hub', 'remote', 'server', 'site'], at: 0.66 },
    ];
    frozen.forEach((route, i) => {
      launch(packets[i], route.ids);
      packets[i].s = packets[i].total * route.at;
      place(packets[i]);
    });
  };

  api.rebuild = (narrow) => {
    build(narrow);
    if (reduced) freeze();
  };
  return api;
}
