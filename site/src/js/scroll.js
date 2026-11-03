// 每段的网格姿态。段落交界处两组参数之间插值，并在交界中点叠加 burst（裂开再重组）。
const PROFILES = {
  top: { a: -24, x: 0.6, y: 0.52, gap: 2, slide: 6, ra: -35, ro: 0.04 },
  uses: { a: 34, x: 0.7, y: 0.42, gap: 3, slide: -10, ra: 18, ro: -0.1 },
  how: { a: -52, x: 0.3, y: 0.55, gap: 3, slide: 8, ra: 118, ro: -0.24 },
  protocols: { a: 12, x: 0.5, y: 0.2, gap: 2, slide: 12, ra: -72, ro: 0.18 },
  networks: { a: -38, x: 0.78, y: 0.66, gap: 4, slide: -12, ra: 160, ro: 0.06 },
  usage: { a: 48, x: 0.3, y: 0.34, gap: 3, slide: 10, ra: 40, ro: -0.16 },
  start: { a: -14, x: 0.46, y: 0.78, gap: 2, slide: -8, ra: -120, ro: 0.1 },
};

function shortestArc(from, to, t) {
  let d = to - from;
  while (d > 90) d -= 180;
  while (d < -90) d += 180;
  return from + d * t;
}

function createScroll(rtl, reduced) {
  const nodes = [...document.querySelectorAll('[data-sec]')];
  const sections = nodes.map((el) => ({ el, id: el.id, top: 0, height: 0, p: -1 }));
  const scroller = { sections, y: 0, smooth: 0, vh: 1, vw: 1 };

  scroller.measure = () => {
    scroller.vh = window.innerHeight;
    scroller.vw = window.innerWidth;
    const y = window.scrollY;
    sections.forEach((sec) => {
      const rect = sec.el.getBoundingClientRect();
      sec.top = rect.top + y;
      sec.height = rect.height;
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
    const pulse = Math.sin(Math.PI * clamp(q, 0, 1));
    S.burst = pulse * pulse * 0.42;
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
    const off = clamp(scroller.y / (scroller.vh * 0.75), 0, 1);
    S.wordScatter = reduced ? 0 : off;
    if (off !== scroller.off) {
      scroller.off = off;
      document.documentElement.style.setProperty('--scroll-off', reduced ? 0 : off.toFixed(3));
    }

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
