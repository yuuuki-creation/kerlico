// 开场时间线（秒），总长 2.35。
const INTRO = { assemble: 1.45, cut: 1.55, cutEnd: 1.8, end: 2.35, reveal: 1.9 };
const SKIP_EVENTS = ['scroll', 'wheel', 'keydown', 'pointerdown'];

function createIntro(onReveal) {
  const root = document.documentElement;
  const state = { active: root.classList.contains('intro'), time: 0, revealed: false };

  const reveal = () => {
    if (state.revealed) return;
    state.revealed = true;
    root.classList.remove('intro');
    onReveal();
  };
  const finish = () => {
    if (!state.active) return;
    state.active = false;
    state.time = INTRO.end;
    reveal();
    removeListeners();
  };
  const removeListeners = () => {
    for (const name of SKIP_EVENTS) window.removeEventListener(name, finish);
  };

  if (state.active) {
    try { sessionStorage.setItem('kerlico.intro', '1'); } catch (e) { /* 存储不可用时下次重播，不影响页面 */ }
    for (const name of SKIP_EVENTS) window.addEventListener(name, finish, { passive: true });
  } else {
    state.revealed = true;
  }

  state.tick = (dt, S) => {
    if (!state.active) {
      S.intro = 1;
      S.sliceP = 1;
      S.cutFlash = 0;
      return;
    }
    state.time += dt;
    const time = state.time;
    if (time >= INTRO.reveal) reveal();
    S.intro = clamp(time / INTRO.assemble, 0, 1);
    S.cutFlash = time < INTRO.cut ? 0 : clamp((time - INTRO.cut) / (INTRO.cutEnd - INTRO.cut), 0, 1) * (1 - sstep(INTRO.end - 0.2, INTRO.end, time));
    S.sliceP = time < INTRO.cutEnd ? 0 : easeOutBack(clamp((time - INTRO.cutEnd) / (INTRO.end - INTRO.cutEnd), 0, 1));
    if (time >= INTRO.end) finish();
  };
  return state;
}
