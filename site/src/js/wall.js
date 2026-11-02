// 三角面排在交错的三角格上：相邻面共用一条斜边，奇偶位朝向相反。
function createWall(root, card, filters, labels, rtl, reduced) {
  const items = [...root.querySelectorAll('.tri')].map((el, index) => {
    const button = el.querySelector('button');
    return {
      el, button, index,
      id: el.dataset.id,
      dir: el.dataset.dir,
      modules: el.dataset.modules,
      front: el.querySelector('.front'),
      name: el.querySelector('.front b').textContent,
      sentence: el.querySelector('.sentence').innerHTML,
      x: 0, y: 0, base: 0, up: true, shown: true,
    };
  });
  const box = root.parentElement;
  const api = { visible: false };
  let filter = 'all';
  let current = null;
  let closeTimer = 0;

  const SHADE_FROM = { both: COBALT, out: VERMILION, in: ACID };
  const SHADE_TO = { both: INK, out: BONE, in: BONE };
  const SHADE_MAX = { both: 0.36, out: 0.26, in: 0.24 };

  const pickGrid = (count, width) => {
    const target = width < 620 ? 128 : 178;
    const biggest = width < 620 ? width * 0.8 : 420;
    let cols = 1;
    while (cols < count) {
      const base = (width * 2) / (cols + 1);
      if (base <= target) break;
      cols++;
    }
    let base = Math.min((width * 2) / (cols + 1), biggest);
    if (cols === count && count > 1) base = Math.min(base, target * 1.5);
    return { cols, base };
  };

  const layout = () => {
    const width = box.clientWidth;
    const active = items.filter((item) => filter === 'all' || item.dir === filter);
    const { cols, base } = pickGrid(active.length, width);
    const h = base * 0.866;
    const pitch = base / 2;
    const gap = Math.max(2, base * 0.018);
    const rows = Math.ceil(active.length / cols);
    active.forEach((item, i) => {
      const r = Math.floor(i / cols), c = i % cols;
      item.up = (r + c) % 2 === 0;
      const x = c * pitch;
      item.x = rtl ? width - base - x : x;
      item.y = r * (h + gap);
      item.base = base;
    });
    root.style.height = `${rows * (h + gap)}px`;
    items.forEach((item) => {
      const on = active.includes(item);
      item.shown = on;
      item.el.classList.toggle('off', !on);
      item.el.classList.toggle('up', item.up);
      item.el.classList.toggle('down', !item.up);
      item.button.tabIndex = on ? 0 : -1;
      item.button.setAttribute('aria-hidden', on ? 'false' : 'true');
      item.el.style.setProperty('--base', `${item.base || base}px`);
      item.el.style.setProperty('--fs', `${Math.max(10.5, Math.min(26, (item.base || base) * 0.082))}px`);
      if (on) {
        item.el.style.setProperty('--x', `${item.x}px`);
        item.el.style.setProperty('--y', `${item.y}px`);
      }
      if (!reduced) item.el.style.transitionDelay = `${(item.index % 12) * 16}ms`;
    });
    hide();
  };

  const show = (item) => {
    clearTimeout(closeTimer);
    if (current && current !== item) current.el.classList.remove('flip');
    current = item;
    item.el.classList.add('flip');
    const dirLabel = labels[`wall.${item.dir}`];
    card.querySelector('b').textContent = item.name;
    card.querySelector('.pd').textContent = dirLabel;
    card.querySelector('.pm').textContent = item.modules.replace(' ', '  ');
    card.querySelector('p').innerHTML = item.sentence;
    card.className = `pcard d-${item.dir} ${item.up ? 'up' : 'down'}`;
    const width = box.clientWidth;
    const cardW = Math.min(width, 380);
    card.style.width = `${cardW}px`;
    const cardH = card.offsetHeight;
    const centerX = item.x + item.base / 2;
    const left = clamp(centerX - cardW / 2, 0, width - cardW);
    const preferred = item.y + item.base * 0.866 + 6;
    const fitsBelow = preferred + cardH <= box.clientHeight + 40;
    const top = fitsBelow ? preferred : Math.max(0, item.y - cardH - 6);
    card.style.left = `${left}px`;
    card.style.top = `${top}px`;
    card.style.transformOrigin = `${clamp(centerX - left, 0, cardW)}px ${fitsBelow ? 0 : cardH}px`;
    card.classList.add('on');
  };

  const hide = () => {
    if (current) current.el.classList.remove('flip');
    current = null;
    card.classList.remove('on');
  };

  for (const item of items) {
    const { button } = item;
    button.addEventListener('pointerenter', (event) => {
      if (event.pointerType === 'mouse') show(item);
    });
    button.addEventListener('pointerleave', (event) => {
      if (event.pointerType === 'mouse' && document.activeElement !== button) {
        closeTimer = setTimeout(hide, 80);
      }
    });
    button.addEventListener('focus', () => show(item));
    button.addEventListener('blur', () => { closeTimer = setTimeout(hide, 80); });
    button.addEventListener('click', () => show(item));
  }
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') hide();
  });
  for (const control of filters) {
    control.addEventListener('click', () => {
      filter = control.dataset.filter;
      filters.forEach((b) => b.setAttribute('aria-pressed', b === control ? 'true' : 'false'));
      layout();
    });
  }

  // 面的明暗跟同一个光源走，只往提高文字对比度的方向混色，保证 AA。
  const light = (S, boxRect) => {
    for (const item of items) {
      if (!item.shown) continue;
      const cx = boxRect.left + item.x + item.base / 2;
      const cy = boxRect.top + item.y + item.base * 0.45;
      const d = Math.hypot(S.lightX - cx, S.lightY - cy);
      const lit = clamp(1 - d / 520, 0, 1);
      const from = SHADE_FROM[item.dir], to = SHADE_TO[item.dir], max = SHADE_MAX[item.dir];
      const tone = ((item.index * 37) % 11) / 10;
      const amount = max * (item.dir === 'both' ? clamp(tone * 0.7 + (1 - lit) * 0.5, 0, 1) : clamp(tone * 0.35 + lit * 0.65, 0, 1));
      const r = lerp(from[0], to[0], amount) * 255;
      const g = lerp(from[1], to[1], amount) * 255;
      const b = lerp(from[2], to[2], amount) * 255;
      item.front.style.backgroundColor = `rgb(${r | 0},${g | 0},${b | 0})`;
    }
  };

  api.layout = layout;
  api.tick = (S) => {
    if (api.visible) light(S, box.getBoundingClientRect());
  };
  return api;
}
