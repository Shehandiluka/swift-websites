// Shared behaviour: menu, config links, and the SCROLL CINEMA engine.
(function () {
  const cfg = window.SITE || {};
  const root = document.documentElement;
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const ease = t => t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; // easeInOutCubic
  const easeOut = t => 1 - Math.pow(1 - t, 3);
  const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) root.classList.add('no-motion');

  // ---------- menu ----------
  const nav = document.querySelector('.nav');
  const btn = document.querySelector('.menu-btn');
  if (btn && nav) {
    btn.addEventListener('click', () => nav.classList.toggle('open'));
    nav.querySelectorAll('.nav-links a').forEach(a => a.addEventListener('click', () => nav.classList.remove('open')));
  }

  // ---------- config-driven links ----------
  document.querySelectorAll('[data-cfg]').forEach(el => {
    const v = cfg[el.dataset.cfg];
    if (v) { el.setAttribute('href', v); return; }
    if (el.hasAttribute('data-hide-empty')) { el.remove(); return; }
    if (el.dataset.fallback) el.setAttribute('href', el.dataset.fallback);
    if (el.dataset.fallbackText) { const t = el.querySelector('.t') || el; t.textContent = el.dataset.fallbackText; }
  });
  document.querySelectorAll('[data-cfg-text]').forEach(el => { const v = cfg[el.dataset.cfgText]; if (v) el.textContent = v; });
  document.querySelectorAll('img[data-fallback-hide]').forEach(img => {
    img.addEventListener('error', () => img.remove());
    if (img.complete && !img.naturalWidth) img.remove();
  });
  document.querySelectorAll('[data-year]').forEach(el => el.textContent = new Date().getFullYear());

  // ---------- scroll progress bar ----------
  const bar = document.createElement('div'); bar.className = 'scroll-bar'; document.body.appendChild(bar);

  // ---------- scenes ----------
  const SCENES = {
    // Hero: headline lifts away, product window rises, flattens and grows.
    hero(sec, p) {
      const copy = sec.querySelector('.hero-copy');
      const dev = sec.querySelector('.hero-device');
      const hint = sec.querySelector('.scroll-hint');
      const e = ease(clamp(p / .55));
      const mobile = innerWidth < 760;
      if (copy) { copy.style.transform = `translate3d(0, ${-e * (mobile ? 22 : 30)}vh, 0) scale(${1 - e * .08})`; copy.style.opacity = clamp(1 - e * 1.35); }
      if (hint) hint.style.opacity = clamp(1 - p * 6);
      if (dev) {
        const tilt = dev.querySelector('.tilt');
        const vh = innerHeight, dh = dev.offsetHeight || vh * .5;
        const startY = vh * (mobile ? .74 : .76);                 // peeking below the headline
        const endY = Math.max(76, (vh - dh) / 2 + 24);            // centred in the screen
        const d = ease(clamp(p / .7));
        dev.style.top = '0px';
        dev.style.transform = `translate3d(-50%, ${startY + (endY - startY) * d}px, 0)`;
        if (tilt) tilt.style.transform = `rotateX(${(1 - d) * 32}deg) scale(${.84 + d * .16})`;
        const fan = dev.querySelectorAll('.fan .window');
        fan.forEach((w, i) => {
          const k = i - (fan.length - 1) / 2; // -1, 0, 1
          const s = easeOut(clamp((p - .05) / .8));
          w.style.transform = `translate3d(calc(-50% + ${k * s * 50}%), ${Math.abs(k) * s * 8}%, ${-Math.abs(k) * 60}px) rotate(${k * s * 7}deg)`;
          w.style.zIndex = 10 - Math.abs(k);
        });
      }
    },

    // Story: one pinned stage, N products play one after another like video chapters.
    story(sec, p) {
      const texts = [...sec.querySelectorAll('.story-text')];
      const imgs = [...sec.querySelectorAll('.story-img')];
      const dots = [...sec.querySelectorAll('.story-dots button')];
      const win = sec.querySelector('.story-visual .window');
      const n = texts.length;
      const seg = clamp(p, 0, .9999) * n;
      const active = Math.floor(seg);
      texts.forEach((t, j) => {
        const d = seg - (j + .5);
        let op = clamp((.5 - Math.abs(d)) / .14);
        if (j === 0 && d < 0) op = 1;
        if (j === n - 1 && d > 0) op = 1;
        const dy = (j === 0 && d < 0) || (j === n - 1 && d > 0) ? 0 : -d * 70;
        t.style.opacity = op;
        t.style.transform = `translate3d(0, ${dy}px, 0)`;
        t.style.pointerEvents = op > .5 ? 'auto' : 'none';
        const local = clamp(seg - j);
        t.querySelectorAll('.ticks li').forEach((li, k) => {
          const v = j < active ? 1 : j > active ? 0 : easeOut(clamp((local - .06 - k * .09) / .1));
          li.style.opacity = v; li.style.transform = `translate3d(${(1 - v) * 30}px, 0, 0)`;
        });
        const img = imgs[j];
        if (img) {
          img.style.opacity = op;
          img.style.transform = `scale(${1.08 - .08 * easeOut(local)}) translate3d(0, ${(1 - local) * -2}%, 0)`;
        }
      });
      if (win) {
        const local = seg - active;
        win.style.transform = `rotateY(${(.5 - local) * -8}deg) rotateX(${4 - local * 4}deg)`;
      }
      dots.forEach((b, j) => {
        b.classList.toggle('on', j === active);
        b.querySelector('span').style.transform = `scaleX(${clamp(seg - j)})`;
      });
      const glows = (sec.dataset.glows || '').split('|');
      if (glows[active]) sec.style.setProperty('--glow', glows[active]);
      sec.style.setProperty('--gx', (active % 2 ? 25 : 75) + '%');
    },
  };

  // ---------- engine ----------
  const pins = [...document.querySelectorAll('[data-pin]')];
  const scrubs = [...document.querySelectorAll('[data-scrub]')];
  // auto-stagger grid children
  scrubs.forEach(el => {
    if (el.dataset.delay) return;
    const sib = [...el.parentElement.children].filter(c => c.hasAttribute('data-scrub'));
    if (sib.length > 1) el.dataset.delay = (sib.indexOf(el) % 4) * 0.12;
  });
  let layout = [];

  function measure() {
    if (reduce) return;
    pins.forEach(sec => { sec.style.height = (+sec.dataset.pin || 200) + 'vh'; });
    layout = pins.map(sec => ({ sec, top: sec.offsetTop, h: sec.offsetHeight }));
    // anchors inside stories (so #swiftpaypos etc. land on the right chapter)
    layout.forEach(({ sec, h }) => {
      const a = [...sec.querySelectorAll('.story-anchor')];
      a.forEach((el, j) => { el.style.top = ((j + .5) / a.length * (h - innerHeight)) + 'px'; });
    });
  }

  function frame() {
    ticking = false;
    const y = scrollY, vh = innerHeight;
    const max = document.documentElement.scrollHeight - vh;
    bar.style.transform = `scaleX(${max > 0 ? y / max : 0})`;
    if (reduce) return;
    for (const { sec, top, h } of layout) {
      if (y + vh < top - vh || y > top + h + vh) continue;
      const p = clamp((y - top) / Math.max(1, h - vh));
      const fn = SCENES[sec.dataset.scene];
      if (fn) fn(sec, p);
    }
    document.querySelectorAll('[data-count]').forEach(el => {
      const r = el.getBoundingClientRect(); if (r.top > vh || r.bottom < 0) return;
      const v = easeOut(clamp((vh - r.top) / (vh * .45)));
      el.textContent = Math.round(+el.dataset.count * v) + (el.dataset.suffix || '');
    });
    for (const el of scrubs) {
      const r = el.getBoundingClientRect();
      if (r.top > vh * 1.2 || r.bottom < -vh * .2) { if (r.top > vh) el.style.setProperty('--sp', 0); continue; }
      const v = clamp((vh * .98 - r.top) / (vh * .42) - (+el.dataset.delay || 0));
      el.style.setProperty('--sp', easeOut(v).toFixed(3));
    }
  }
  let ticking = false;
  const onScroll = () => { if (!ticking) { ticking = true; requestAnimationFrame(frame); } };

  // story chapter buttons
  document.querySelectorAll('.story').forEach(sec => {
    sec.querySelectorAll('.story-dots button').forEach((b, j, all) => b.addEventListener('click', () => {
      const L = layout.find(l => l.sec === sec); if (!L) return;
      scrollTo({ top: L.top + (j + .5) / all.length * (L.h - innerHeight), behavior: 'smooth' });
    }));
  });

  measure(); frame();
  addEventListener('scroll', onScroll, { passive: true });
  addEventListener('resize', () => { measure(); frame(); });
  addEventListener('load', () => { measure(); frame(); });
})();
