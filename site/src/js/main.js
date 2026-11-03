function initChrome(labels) {
  for (const link of document.querySelectorAll('[data-lang]')) {
    link.addEventListener('click', () => {
      try { localStorage.setItem('kerlico.lang', link.dataset.lang); } catch (e) { /* 存储不可用时只影响下次跳转 */ }
    });
  }
  const menu = document.querySelector('.langs');
  document.addEventListener('click', (event) => {
    if (menu.open && !menu.contains(event.target)) menu.open = false;
  });
  for (const cmd of document.querySelectorAll('.cmd')) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy';
    button.textContent = labels['start.copy'];
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(cmd.textContent);
        button.textContent = labels['start.copied'];
        setTimeout(() => { button.textContent = labels['start.copy']; }, 1400);
      } catch (e) {
        window.getSelection().selectAllChildren(cmd);
      }
    });
    cmd.after(button);
  }
}

function main() {
  const root = document.documentElement;
  const rtl = root.dir === 'rtl';
  const reduced = root.classList.contains('rm');
  const labels = JSON.parse(document.getElementById('labels').textContent);
  initChrome(labels);

  const canvas = document.getElementById('mesh');
  const renderer = createRenderer(canvas);
  const S = createFrameState();
  const scroller = createScroll(rtl, reduced);
  const intro = createIntro(() => scroller.measure());
  const dispatcher = createDispatcher(
    document.getElementById('diagram'),
    [...document.querySelectorAll('.steps li')],
    labels, rtl, reduced,
  );
  const wall = createWall(
    document.getElementById('wall'),
    document.getElementById('pcard'),
    [...document.querySelectorAll('[data-filter]')],
    labels, rtl, reduced,
  );
  const track = document.querySelector('.disp-track');

  let field, word;
  let vw = 0, vh = 0, dpr = 1;
  let narrow = false;
  const light = { x: 0, y: 0, tx: 0, ty: 0, lastInput: -1e9 };

  const rebuild = () => {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    vw = w;
    vh = h;
    narrow = window.innerWidth < 820;
    const coarse = window.matchMedia('(pointer: coarse)').matches;
    const cap = renderer.kind === '2D' ? 1 : coarse || narrow ? 1.5 : 2;
    dpr = Math.min(window.devicePixelRatio || 1, cap);
    renderer.resize(w, h, dpr);
    field = createField(w, h, narrow);
    word = createWord(w, h, narrow, rtl);
    root.style.setProperty('--word-bottom', `${Math.round(word.bottom)}px`);
    dispatcher.rebuild(narrow);
    wall.layout();
    scroller.measure();
    light.tx = light.x = w * (rtl ? 0.32 : 0.68);
    light.ty = light.y = h * 0.28;
  };

  const syncStage = () => {
    if (reduced) return;
    const span = track.offsetHeight - window.innerHeight;
    const rect = track.getBoundingClientRect();
    const progress = clamp(-rect.top / (span || 1), 0, 0.999);
    dispatcher.setStage(Math.floor(progress * 3));
  };

  const draw = () => {
    emitField(field, S);
    emitWord(word, S, field.diag);
    renderer.draw(field, word);
    wall.tick(S);
  };

  const updateLight = (dt, now) => {
    const idle = now - light.lastInput > 3500;
    if (idle) {
      const t = now / 1000;
      light.tx = vw * (0.5 + 0.34 * Math.sin(t * 0.19));
      light.ty = vh * (0.42 + 0.3 * Math.cos(t * 0.27));
    }
    const k = 1 - Math.exp(-dt * 6);
    light.x += (light.tx - light.x) * k;
    light.y += (light.ty - light.y) * k;
    S.lightX = light.x;
    S.lightY = light.y;
    S.lightZ = field.diag * 0.2;
  };

  rebuild();

  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.target === track) dispatcher.visible = entry.isIntersecting;
      else wall.visible = entry.isIntersecting;
    }
  }, { rootMargin: '10% 0px' });
  io.observe(track);
  io.observe(document.getElementById('wall'));

  const staticFrame = () => {
    S.breath = 0;
    scroller.tick(0, S);
    S.lightX = light.x;
    S.lightY = light.y;
    S.lightZ = field.diag * 0.2;
    draw();
  };

  let resizeTimer = 0;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      // 手机地址栏伸缩只改高度，不值得重建网格。
      if (canvas.clientWidth !== vw || Math.abs(canvas.clientHeight - vh) > vh * 0.2) rebuild();
      scroller.measure();
      if (reduced) staticFrame();
    }, 140);
  });
  if (window.ResizeObserver) new ResizeObserver(() => scroller.measure()).observe(document.body);

  if (reduced) {
    let queued = false;
    window.addEventListener('scroll', () => {
      if (queued) return;
      queued = true;
      requestAnimationFrame(() => {
        queued = false;
        staticFrame();
      });
    }, { passive: true });
    staticFrame();
    return;
  }

  window.addEventListener('pointermove', (event) => {
    light.tx = event.clientX;
    light.ty = event.clientY;
    light.lastInput = performance.now();
  }, { passive: true });

  let raf = 0, last = 0, slow = 0, frames = 0;
  const frame = (now) => {
    raf = requestAnimationFrame(frame);
    const elapsed = now - last;
    // rAF 时间戳可能略早于 start() 记录的 performance.now()，负 dt 会让所有弹簧发散。
    const dt = clamp(elapsed / 1000, 0, 0.05);
    last = now;
    S.t += dt;
    intro.tick(dt, S);
    scroller.tick(dt, S);
    updateLight(dt, now);
    syncStage();
    dispatcher.tick(dt);
    draw();
    frames++;
    if (elapsed > 26) slow++;
    if (frames >= 90) {
      if (slow > 45 && dpr > 1) {
        dpr = Math.max(1, dpr * 0.8);
        renderer.resize(vw, vh, dpr);
      }
      frames = 0;
      slow = 0;
    }
  };
  const start = () => {
    if (raf) return;
    last = performance.now();
    raf = requestAnimationFrame(frame);
  };
  const stop = () => {
    cancelAnimationFrame(raf);
    raf = 0;
  };
  document.addEventListener('visibilitychange', () => {
    root.classList.toggle('paused', document.hidden);
    if (document.hidden) stop();
    else start();
  });
  if (!document.hidden) start();
}

main();
