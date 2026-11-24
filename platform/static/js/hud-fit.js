/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Keeps the top bar on one row on wide screens (figures strip layout, >= 1440px wide).
   When the buttons do not fit beside the name (more buttons for admins, browser zoom), the least
   important labels collapse to their icons step by step (the tooltip still names each button). */
(() => {
  const hud = document.querySelector(".hud");
  if (!hud) return;
  const left = hud.querySelector(".hud-left"), right = hud.querySelector(".hud-right");
  if (!left || !right) return;
  const STEPS = ["hud-fit-1", "hud-fit-2", "hud-fit-3"];
  const root = document.documentElement;
  const wrapped = () => right.offsetTop > left.offsetTop + 4;
  function fit() {
    hud.classList.remove(...STEPS, "hud-fit-wrap");
    root.style.removeProperty("--hud-h");
    if (innerWidth < 1440) return;            // narrower layouts wrap by design
    for (const s of STEPS) {
      if (!wrapped()) return;
      hud.classList.add(s);
    }
    // still two rows (a long name, every button, browser zoom): the bar grows to hold them, the figures strip stays
    // inside it with its background, and everything placed under the bar (--hud-h) moves down by the real height
    // (the user, 2026-11-23: the figures had dropped out of the bar onto the map)
    if (wrapped()) {
      hud.classList.add("hud-fit-wrap");
      root.style.setProperty("--hud-h", `${hud.offsetHeight}px`);
    }
  }
  let t;
  const later = () => { clearTimeout(t); t = setTimeout(fit, 80); };
  addEventListener("resize", later);
  // the name, subtitle and clocks change width after loading; fit() ends at the same size, so no loop
  if (window.ResizeObserver) { const ro = new ResizeObserver(later); ro.observe(left); ro.observe(right); }
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(fit);
  fit();
})();
