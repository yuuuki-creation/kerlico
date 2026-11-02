// 每段的网格姿态。段落交界处两组参数之间插值，并在交界中点叠加 burst（裂开再重组）。
const PROFILES = {
  top: { a: -24, x: 0.6, y: 0.52, gap: 10, slide: 46, ra: -35, ro: 0.04, wire: 0, wa: 60 },
  roles: { a: 38, x: 0.72, y: 0.42, gap: 22, slide: -70, ra: 18, ro: -0.1, wire: 0.26, wa: 104 },
  dispatcher: { a: -64, x: 0.2, y: 0.55, gap: 30, slide: 34, ra: 118, ro: -0.26, wire: 0, wa: 40 },
  protocols: { a: 12, x: 0.5, y: 0.14, gap: 16, slide: 130, ra: -72, ro: 0.2, wire: 0.2, wa: 92 },
  tunnels: { a: -38, x: 0.82, y: 0.7, gap: 26, slide: -90, ra: 160, ro: 0.08, wire: 0.3, wa: -30 },
  users: { a: 58, x: 0.3, y: 0.3, gap: 18, slide: 60, ra: 40, ro: -0.18, wire: 0, wa: 10 },
  start: { a: -14, x: 0.46, y: 0.82, gap: 34, slide: -120, ra: -120, ro: -0.04, wire: 0.22, wa: 74 },
  license: { a: 28, x: 0.62, y: 0.3, gap: 12, slide: 80, ra: -18, ro: 0.22, wire: 0, wa: 30 },
};

function shortestArc(from, to, t) {
  let d = to - from;
  while (d > 90) d -= 180;
  while (d < -90) d += 180;
  return from + d * t;
}

function createScroll(rtl, reduced) {
  const nodes = [...document.querySelectorAll('[data-sec]')];
  const sections = nodes.map((el) => ({ el, id: el.id, top: 0, height: 0, p: -1, coord: el.querySelector('.coord') }));
  const scroller = { sections, y: 0, smooth: 0, vh: 1, vw: 1 };

  scroller.measure = () => {
    scroller.vh = window.innerHeight;
    scroller.vw = window.innerWidth;
    const y = window.scrollY;
    sections.forEach((sec, index) => {
      const rect = sec.el.getBoundingClientRect();
      sec.top = rect.top + y;
      sec.height = rect.height;
      if (sec.coord) sec.coord.textContent = `S${String(index).padStart(2, '0')} y=${Math.round(sec.top)} h=${Math.round(sec.height)}`;
    });
  };

  // 把滚动位置映射到两组姿态和过渡进度。
  const applyProfile = (S, y, scale) => {
    const center = y + scroller.vh / 2;
    let index = 0;
    for (let i = 0; i < sections.length; i++) {
      if (center >= sections[i].top) index = i;
    }
    const current = sections[index];
    const boundaryNext = current.top + current.height;
    const span = scroller.vh * 0.42;
    let from = current, to = current, q = 0;
    if (index < sections.length - 1 && center > boundaryNext - span) {
      to = sections[index + 1];
      q = (center - (boundaryNext - span)) / (span * 2);
    } else if (index > 0 && center < current.top + span) {
      from = sections[index - 1];
      q = (center - (current.top - span)) / (span * 2);
    }
    const a = PROFILES[from.id], b = PROFILES[to.id];
    const e = sstep(0.18, 0.82, q);
    const flip = rtl ? -1 : 1;
    S.angle = shortestArc(a.a, b.a, e) * flip * RAD;
    S.crackX = rtl ? 1 - lerp(a.x, b.x, e) : lerp(a.x, b.x, e);
    S.crackY = lerp(a.y, b.y, e);
    S.gap = lerp(a.gap, b.gap, e) * scale;
    S.slide = lerp(a.slide, b.slide, e) * scale * flip;
    const ra = shortestArc(a.ra, b.ra, e);
    S.rampAngle = (rtl ? 180 - ra : ra) * RAD;
    S.rampOff = lerp(a.ro, b.ro, e);
    S.wireW = lerp(a.wire, b.wire, e) * Math.hypot(scroller.vw, scroller.vh);
    S.wireAngle = shortestArc(a.wa, b.wa, e) * flip * RAD;
    const pulse = Math.sin(Math.PI * clamp(q, 0, 1));
    S.burst = pulse * pulse * 0.9;
  };

  scroller.tick = (dt, S) => {
    scroller.y = window.scrollY;
    if (reduced) {
      scroller.smooth = scroller.y;
    } else {
      scroller.smooth += (scroller.y - scroller.smooth) * (1 - Math.exp(-dt * 9));
      if (Math.abs(scroller.y - scroller.smooth) < 0.05) scroller.smooth = scroller.y;
    }
    S.scrollY = scroller.y;
    S.vh = scroller.vh;
    applyProfile(S, scroller.smooth, scroller.vw < 820 ? 0.6 : 1);
    if (reduced) S.burst = 0;
    S.wordDrift = reduced ? 0 : Math.min(scroller.y * 0.16, 220);

    if (reduced) return;
    for (const sec of sections) {
      const near = scroller.smooth + scroller.vh * 1.4 > sec.top && scroller.smooth - scroller.vh * 0.4 < sec.top + sec.height;
      if (!near) continue;
      const p = sec.id === 'top' ? 1 : clamp((scroller.smooth + scroller.vh * 0.95 - sec.top) / (scroller.vh * 0.62), 0, 1);
      const eased = Math.round(easeOutExpo(p) * 1000) / 1000;
      if (eased !== sec.p) {
        sec.p = eased;
        sec.el.style.setProperty('--p', eased);
      }
    }
  };
  return scroller;
}

// 把真实的切割线、光源位置和网格规模画在最上层，这些标注都是当前帧的实际值。
function createAnno(svg, field) {
  const NS = 'http://www.w3.org/2000/svg';
  const make = (name, cls) => {
    const el = document.createElementNS(NS, name);
    if (cls) el.setAttribute('class', cls);
    svg.appendChild(el);
    return el;
  };
  const crack = make('line', 'a-crack');
  const crackText = make('text', 'a-text');
  const lh = make('line', 'a-light');
  const lv = make('line', 'a-light');
  const lightText = make('text', 'a-text');
  const stats = make('text', 'a-text a-stats');
  let lastText = 0;
  const anno = { field };

  anno.tick = (S, vw, vh, now, kind, dpr) => {
    const px = S.crackX * vw, py = S.crackY * vh;
    const tx = Math.cos(S.angle), ty = Math.sin(S.angle);
    const reach = Math.hypot(vw, vh);
    crack.setAttribute('x1', px - tx * reach);
    crack.setAttribute('y1', py - ty * reach);
    crack.setAttribute('x2', px + tx * reach);
    crack.setAttribute('y2', py + ty * reach);
    const lx = S.lightX, ly = S.lightY;
    lh.setAttribute('x1', lx - 16); lh.setAttribute('x2', lx + 16); lh.setAttribute('y1', ly); lh.setAttribute('y2', ly);
    lv.setAttribute('y1', ly - 16); lv.setAttribute('y2', ly + 16); lv.setAttribute('x1', lx); lv.setAttribute('x2', lx);
    lightText.setAttribute('x', clamp(lx + 20, 8, vw - 120));
    lightText.setAttribute('y', clamp(ly - 10, 66, vh - 12));
    crackText.setAttribute('x', clamp(px + tx * 90, 10, vw - 170));
    crackText.setAttribute('y', clamp(py + ty * 90 - 8, 76, vh - 30));
    stats.setAttribute('x', 12);
    stats.setAttribute('y', vh - 10);
    if (now - lastText > 120) {
      lastText = now;
      lightText.textContent = `L ${Math.round(lx)},${Math.round(ly)},${Math.round(S.lightZ)}`;
      crackText.textContent = `CRACK ${(S.angle / RAD).toFixed(1)}° GAP ${S.gap.toFixed(0)}`;
      stats.textContent = `V${anno.field.vCount} T${anno.field.tCount} ${kind} DPR${dpr.toFixed(2)} S${Math.round(S.scrollY)}`;
    }
  };
  return anno;
}
