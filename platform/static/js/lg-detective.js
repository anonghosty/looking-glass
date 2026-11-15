/* Looking Glass is thinking (the user, 2026-11-15): while Looking Glass compares the reports, a detective walks along
   the report sheets looking through his magnifying glass, a thought bubble over his head. If he finds something, a
   light bulb lights up; if not, he stops and shrugs. Line art in the platform's colours, drawn here (no image files).
   With reduced motion asked for, he stands still and only the bulb or the shrug changes.

     const d = window.LGDetective.mount(host, "Comparing every indicator across names and reports");
     await d.found();          // the bulb, then remove() it yourself (or leave it)
     d.nothing("No matches");  // he shrugs and the caption says why; he stays
     d.remove();
*/
(() => {
  const NS = "http://www.w3.org/2000/svg";
  const calm = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const s = (tag, attrs, parent) => {
    const e = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    if (parent) parent.append(e);
    return e;
  };

  function drawing() {
    const svg = s("svg", { viewBox: "0 0 360 120", class: "dt-svg", "aria-hidden": "true", focusable: "false" });
    s("line", { x1: 8, y1: 108, x2: 352, y2: 108, class: "dt-ground" }, svg);
    // the reports pinned on his evidence board at eye level, joined by a red string; he walks in front of them
    const sheets = s("g", { class: "dt-sheets" }, svg);
    const at = [[40, 30], [112, 22], [188, 32], [262, 24]];
    s("polyline", { points: at.map(([x, y]) => `${x + 18},${y + 3}`).join(" "), class: "dt-string" }, sheets);
    at.forEach(([x, y], i) => {
      const g = s("g", { class: `dt-sheet dt-sheet-${i}` }, sheets);
      s("rect", { x, y, width: 36, height: 32, rx: 2.5 }, g);
      for (const dy of [9, 15, 21, 27]) s("line", { x1: x + 6, y1: y + dy, x2: x + (dy === 27 ? 20 : 30), y2: y + dy }, g);
      s("circle", { cx: x + 18, cy: y + 3, r: 2.2, class: "dt-pin" }, g);
    });
    // the detective: walking (outer), facing the way he walks (flip), his body
    const walk = s("g", { class: "dt-walk" }, svg);
    const flip = s("g", { class: "dt-flip" }, walk);
    const man = s("g", { class: "dt-man" }, flip);
    // an African detective (the user, 2026-11-15), flat colours: tan trench coat, fedora, light shirt and red tie, dark
    // trousers, black gloves, a magnifying glass. He faces right; the flip turns him round.
    const leg = (cls, d, shoe) => { const g = s("g", { class: `dt-leg ${cls}` }, man); s("path", { d, class: "dt-trouser" }, g);
      s("ellipse", { cx: shoe, cy: 106.6, rx: 4.8, ry: 2, class: "dt-shoe" }, g); };
    leg("dt-leg-a", "M-6.5 80 L-1 80 L-2 105.5 L-7 105.5 Z", -4);
    leg("dt-leg-b", "M1 80 L6.5 80 L7 105.5 L2 105.5 Z", 5.5);
    const arm = (d, g, hand) => { s("path", { d, class: "dt-sleeve" }, g); s("circle", { cx: hand[0], cy: hand[1], r: 2.5, class: "dt-glove" }, g); };
    arm("M-7 55 L-12 64 L-9 71.5", s("g", { class: "dt-arm-back" }, man), [-9, 72]);  // the other hand on his hip
    s("path", { d: "M-9.5 52 L9.5 52 L13.5 87 L-13.5 87 Z", class: "dt-coat" }, man);    // the trench coat
    s("path", { d: "M-3.6 52 L3.6 52 L2 66 L-2 66 Z", class: "dt-shirt" }, man);
    s("path", { d: "M-1 53 L1 53 L1.7 63.5 L0 66.5 L-1.7 63.5 Z", class: "dt-tie" }, man);
    s("path", { d: "M-3.6 52 L-6.5 52 L-2 65 Z M3.6 52 L6.5 52 L2 65 Z", class: "dt-lapel" }, man);
    s("rect", { x: -11.6, y: 71, width: 23.2, height: 2.4, class: "dt-belt" }, man);
    s("line", { x1: 0, y1: 73.5, x2: 0, y2: 87, class: "dt-split" }, man);
    const top = s("g", { class: "dt-top" }, man);                                          // head and hat tilt together
    s("rect", { x: -2.2, y: 47.5, width: 4.4, height: 5, class: "dt-skin" }, top);         // neck
    s("ellipse", { cx: 0, cy: 42.5, rx: 6.3, ry: 7, class: "dt-skin" }, top);              // head
    s("circle", { cx: -5.6, cy: 43, r: 1.5, class: "dt-skin dt-ear" }, top);
    s("path", { d: "M-6.3 41 Q-6 34.5 0 34.2 Q6 34.5 6.3 40 L4 38.6 L-4.5 39 Z", class: "dt-hair" }, top);
    s("circle", { cx: 3, cy: 42, r: 0.9, class: "dt-eye" }, top);
    s("path", { d: "M1.4 46 Q3.2 47.4 5 45.8", class: "dt-smile" }, top);
    s("ellipse", { cx: 0, cy: 36.4, rx: 11.5, ry: 2.3, class: "dt-brim" }, top);           // the fedora
    s("path", { d: "M-6.6 36 L-5.6 28.6 Q0 25.6 5.6 28.6 L6.6 36 Z", class: "dt-crown" }, top);
    s("rect", { x: -6.5, y: 33.2, width: 13, height: 2.1, class: "dt-band" }, top);
    // the arm holding the magnifying glass up to the reports
    const glass = s("g", { class: "dt-glass" }, man);
    s("line", { x1: 18.8, y1: 48.6, x2: 21.2, y2: 43.6, class: "dt-handle" }, glass);
    s("circle", { cx: 23.6, cy: 38.6, r: 5.4, class: "dt-lens" }, glass);
    arm("M7 55 L14 61 L18.2 51", glass, [18.6, 50]);
    // shrugging: both hands out and up (shown instead of the glass)
    const shrug = s("g", { class: "dt-shrug" }, man);
    arm("M-7.5 55.5 L-16.5 62 L-21 53.5", shrug, [-21.3, 52.6]);
    arm("M7.5 55.5 L16.5 62 L21 53.5", shrug, [21.3, 52.6]);
    const q = s("text", { x: 13, y: 27, class: "dt-q" }, shrug); q.textContent = "?";
    // thinking: a bubble of dots over his head
    const think = s("g", { class: "dt-think" }, man);
    s("circle", { cx: 9, cy: 25, r: 1.5 }, think);
    s("circle", { cx: 13, cy: 20, r: 2.2 }, think);
    s("ellipse", { cx: 22, cy: 11, rx: 10, ry: 7 }, think);
    for (const [i, x] of [17, 22, 27].entries()) s("circle", { cx: x, cy: 11, r: 1.4, class: `dt-dot dt-dot-${i}` }, think);
    // found it: a light bulb over his hat
    const bulb = s("g", { class: "dt-bulb" }, man);
    for (const [x1, y1, x2, y2] of [[0, -1, 0, -7], [-10, 3, -14, -1], [10, 3, 14, -1], [-12, 12, -18, 12], [12, 12, 18, 12]])
      s("line", { x1, y1, x2, y2, class: "dt-ray" }, bulb);
    s("path", { d: "M-6 12 a6 6 0 1 1 12 0 c0 3 -2.5 4 -2.5 7 h-7 c0 -3 -2.5 -4 -2.5 -7 z", class: "dt-glass-bulb" }, bulb);
    s("line", { x1: -3, y1: 22, x2: 3, y2: 22, class: "dt-base" }, bulb);
    return svg;
  }

  function mount(host, label) {
    const box = document.createElement("div");
    box.className = "dt-stage" + (calm() ? " dt-calm" : "");
    box.setAttribute("role", "img");
    box.setAttribute("aria-label", "Looking Glass is thinking");
    const cap = document.createElement("p");
    cap.className = "dt-cap"; cap.setAttribute("aria-live", "polite");
    cap.textContent = `Looking Glass is thinking: ${label || "looking through the reports"}…`;
    box.append(drawing(), cap);
    host.append(box);
    // he is only seen once the page's own loading logo has gone (2026-11-15: on lg-test the whole act ran under it): the
    // time he must walk counts from then, so the reader always sees him look before the bulb or the shrug
    const covered = () => !!document.querySelector("#lgTransition.on");
    let started = covered() ? null : Date.now();
    const shown = new Promise((resolve) => {
      if (started) return resolve();
      const t0 = Date.now();
      const tick = () => { if (!covered() || Date.now() - t0 > 20000) { started = Date.now(); resolve(); } else setTimeout(tick, 120); };
      tick();
    });
    const atLeast = async (ms) => { await shown; await new Promise((r) => setTimeout(r, calm() ? 0 : Math.max(0, ms - (Date.now() - started)))); };
    return {
      el: box,
      /** he found something: the bulb lights; resolves when it has been seen (about a second) */
      async found(text) {
        await atLeast(1600);                       // never just a flicker: he walks a moment first
        box.classList.add("is-found");
        box.setAttribute("aria-label", "Looking Glass found something");
        cap.textContent = text || "Looking Glass found something.";
        await new Promise((r) => setTimeout(r, calm() ? 300 : 1100));
      },
      /** nothing found: he stops and shrugs; the caption says it */
      async nothing(text) {
        await atLeast(1600);
        box.classList.add("is-shrug");
        box.setAttribute("aria-label", "Looking Glass found nothing");
        cap.textContent = text || "Looking Glass has nothing to ask.";
      },
      remove() { box.remove(); },
    };
  }

  window.LGDetective = { mount };
})();
