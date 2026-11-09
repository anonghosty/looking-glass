/* Keeps the top bar on one row on wide screens (figures strip layout, >= 1440px wide).
   When the buttons do not fit beside the name (more buttons for admins, browser zoom), the least
   important labels collapse to their icons step by step (the tooltip still names each button). */
(() => {
  const hud = document.querySelector(".hud");
  if (!hud) return;
  const left = hud.querySelector(".hud-left"), right = hud.querySelector(".hud-right");
  if (!left || !right) return;
  const STEPS = ["hud-fit-1", "hud-fit-2", "hud-fit-3"];
  const wrapped = () => right.offsetTop > left.offsetTop + 4;
  function fit() {
    hud.classList.remove(...STEPS);
    if (innerWidth < 1440) return;            // narrower layouts wrap by design
    for (const s of STEPS) {
      if (!wrapped()) return;
      hud.classList.add(s);
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
