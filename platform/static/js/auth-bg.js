/* Looking Glass · sign-in scene (decorative; no real data before sign-in)
   * Globe of dots in the shape of the continents (world-atlas land-110m, CC0, pinned with an integrity hash).
     Interactive: drag (mouse or finger) to spin, with inertia; scroll or pinch to zoom; hover lights up the land
     under the pointer; click or tap launches a burst of attacks from that spot. Keyboard / TV remote: focus the globe
     (Tab or the remote's arrows), then arrows turn it, + / - or channel keys zoom, OK launches a burst.
     Auto-rotates when left alone.
   * Attacks arc in from around the world with impact rings.
   Still frame for "reduce motion"; pauses when the tab is hidden. */
(() => {
  "use strict";
  const cv = document.getElementById("authBg");
  if (!cv || !cv.getContext) return;
  const ctx = cv.getContext("2d");
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const TAU = Math.PI * 2, rad = Math.PI / 180;
  const LAND_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/land-110m.json";
  const LAND_SRI = "sha384-5oFOGoMd0tkagYW08lVco4uAi7XDEDBwBxOdeKx+SA1ihbsHiR/aFAJGretluTzG";
  let W = 0, H = 0, dpr = 1;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = innerWidth; H = innerHeight;
    cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  addEventListener("resize", resize); resize();

  // ------------------------------------------------------------------ globe geometry
  const ll = (lat, lon) => [Math.cos(lat * rad) * Math.sin(lon * rad), Math.sin(lat * rad), Math.cos(lat * rad) * Math.cos(lon * rad)];
  const fib = (n) => { const out = []; for (let i = 0; i < n; i++) { const y = 1 - (i / (n - 1)) * 2, r = Math.sqrt(1 - y * y), th = i * 2.399963229728653; out.push([Math.cos(th) * r, y, Math.sin(th) * r]); } return out; };
  let ocean = fib(900), land = [], landAlpha = 0;
  // land: decode the TopoJSON and keep the dots that fall on land
  (async () => {
    try {
      const topo = await (await fetch(LAND_URL, { integrity: LAND_SRI, mode: "cors", credentials: "omit" })).json();
      const [sx, sy] = topo.transform.scale, [tx0, ty0] = topo.transform.translate;
      const arcs = topo.arcs.map((a) => { let x = 0, y = 0; return a.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx0, y * sy + ty0]; }); });
      const ring = (ids) => { const pts = []; for (const i of ids) { const a = i < 0 ? arcs[~i].slice().reverse() : arcs[i]; pts.push(...(pts.length ? a.slice(1) : a)); } return pts; };
      const polys = [];
      for (const g of topo.objects.land.geometries) {
        const P = g.type === "Polygon" ? [g.arcs] : g.type === "MultiPolygon" ? g.arcs : [];
        for (const p of P) {
          const rings = p.map(ring), o = rings[0];
          let x0 = 180, x1 = -180, y0 = 90, y1 = -90; for (const [x, y] of o) { x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y); }
          polys.push({ rings, b: [x0, y0, x1, y1] });
        }
      }
      const inRing = (x, y, r) => { let c = false; for (let i = 0, j = r.length - 1; i < r.length; j = i++) { const [xi, yi] = r[i], [xj, yj] = r[j]; if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) c = !c; } return c; };
      const onLand = (lon, lat) => polys.some(({ rings, b }) => lon >= b[0] && lon <= b[2] && lat >= b[1] && lat <= b[3] && inRing(lon, lat, rings[0]) && !rings.slice(1).some((h) => inRing(lon, lat, h)));
      const cand = fib(14000), keep = [];
      for (const v of cand) {
        const lat = Math.asin(v[1]) / rad, lon = Math.atan2(v[0], v[2]) / rad;
        if (lat > -58 && onLand(lon, lat)) keep.push(v);
      }
      land = keep;
    } catch { land = []; }                                  // offline or blocked: the plain dotted sphere stays
  })();

  // view: yaw / pitch / zoom, dragged with inertia, auto-rotation when idle
  let yaw = 0.35, pitch = 0.28, zoom = 1, vYaw = 0, vPitch = 0, drag = null, lastInput = -1e9;
  let hoverV = null, hoverAt = 0;
  function rot(v) {
    const [x, y, z] = v, c = Math.cos(yaw), s = Math.sin(yaw);
    const x1 = x * c + z * s, z1 = -x * s + z * c, cp = Math.cos(pitch), sp = Math.sin(pitch);
    return [x1, y * cp - z1 * sp, y * sp + z1 * cp];
  }
  function unrot(v) {                                      // screen-space unit vector -> world
    const [x, y, z] = v, cp = Math.cos(pitch), sp = Math.sin(pitch);
    const y1 = y * cp + z * sp, z1 = -y * sp + z * cp, c = Math.cos(yaw), s = Math.sin(yaw);
    return [x * c - z1 * s, y1, x * s + z1 * c];
  }
  const geo = () => { const wide = W >= 960; const R = Math.min(W, H) * (wide ? 0.34 : 0.38) * zoom; return { cx: W * 0.5, cy: H * (wide ? 0.48 : 0.4), R }; };
  function pick(e) {
    const { cx, cy, R } = geo(), x = (e.clientX - cx) / R, y = -(e.clientY - cy) / R, d = x * x + y * y;
    return d > 1 ? null : unrot([x, y, Math.sqrt(1 - d)]);
  }
  // Input: mouse, touch and pen (pointer events), and keyboard / TV remote. The page's content sits above the canvas:
  // listen on the window and ignore the sign-in card itself.
  const onCard = (e) => e.target.closest && e.target.closest(".auth-card, a, button, input, select, textarea, summary, label");
  const pts = new Map();                                   // pointers down on the globe (two = pinch to zoom)
  let pinch = null;
  const spread = () => { const [a, b] = [...pts.values()]; return Math.hypot(a.x - b.x, a.y - b.y); };
  const endDrag = () => { drag = null; pinch = null; pts.clear(); document.body.classList.remove("globe-drag"); };
  addEventListener("pointerdown", (e) => {
    if (onCard(e) || (!pick(e) && !pts.size)) return;
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    try { cv.setPointerCapture(e.pointerId); } catch { /* not over the canvas */ }
    if (document.activeElement !== cv) cv.focus({ preventScroll: true });   // keys and the remote then act on the globe
    if (pts.size === 2) { pinch = { d: spread(), zoom }; drag = null; return; }
    drag = { x: e.clientX, y: e.clientY, t: performance.now(), moved: 0, id: e.pointerId }; lastInput = performance.now();
    document.body.classList.add("globe-drag");
  });
  addEventListener("pointermove", (e) => {
    if (pts.has(e.pointerId)) pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch && pts.size === 2) {                         // two fingers: zoom
      zoom = Math.max(0.75, Math.min(1.45, pinch.zoom * spread() / Math.max(1, pinch.d))); lastInput = performance.now();
      return;
    }
    const p = e.pointerType === "mouse" && !onCard(e) ? pick(e) : null;
    document.body.classList.toggle("globe-hover", !!p && !drag);
    if (drag && e.pointerId === drag.id) {
      const { R } = geo(), dx = e.clientX - drag.x, dy = e.clientY - drag.y, now = performance.now(), dt = Math.max(1, now - drag.t);
      yaw += dx / R; pitch = Math.max(-1.25, Math.min(1.25, pitch + dy / R));
      vYaw = (dx / R) / dt * 16; vPitch = (dy / R) / dt * 16;
      drag.moved += Math.abs(dx) + Math.abs(dy); drag.x = e.clientX; drag.y = e.clientY; drag.t = now; lastInput = now;
    }
    if (e.pointerType === "mouse") { hoverV = p; hoverAt = performance.now(); }
  }, { passive: true });
  addEventListener("pointerup", (e) => {
    const tap = drag && e.pointerId === drag.id && drag.moved < (e.pointerType === "mouse" ? 6 : 12) && !pinch;
    if (tap) { const v = pick(e); if (v) { burst(v); hoverV = v; hoverAt = performance.now(); } }
    pts.delete(e.pointerId);
    if (!pts.size) endDrag(); else if (pinch && pts.size < 2) pinch = null;
  });
  addEventListener("pointercancel", endDrag);              // the browser took the gesture (e.g. a system swipe)
  addEventListener("blur", endDrag);
  addEventListener("wheel", (e) => {
    if (onCard(e) || !pick(e)) return;
    zoom = Math.max(0.75, Math.min(1.45, zoom * (e.deltaY > 0 ? 0.94 : 1.06))); lastInput = performance.now();
  }, { passive: true });
  // Keyboard and TV remote: the globe takes focus like a button (Tab, or the remote's arrows from the page). With focus,
  // arrows turn it, + / - (or Page Up / Down, the remote's channel keys) zoom, OK / Enter / Space launches an attack
  // burst from the point facing you. Typing in the form is never affected: these keys act only when the globe has focus.
  cv.addEventListener("keydown", (e) => {
    const step = e.shiftKey ? 0.35 : 0.14;
    const k = e.key;
    if (k === "ArrowLeft") vYaw -= step * 0.25;
    else if (k === "ArrowRight") vYaw += step * 0.25;
    else if (k === "ArrowUp") vPitch -= step * 0.2;
    else if (k === "ArrowDown") vPitch += step * 0.2;
    else if (k === "+" || k === "=" || k === "PageUp" || k === "ChannelUp") zoom = Math.min(1.45, zoom * 1.08);
    else if (k === "-" || k === "_" || k === "PageDown" || k === "ChannelDown") zoom = Math.max(0.75, zoom / 1.08);
    else if (k === "Enter" || k === " " || k === "Select" || k === "Accept") { const v = unrot([0, 0, 1]); burst(v); hoverV = v; hoverAt = performance.now(); }
    else if (k === "Escape" || k === "GoBack" || k === "BrowserBack" || k === "Backspace") {   // remote Back: to the card
      const first = document.querySelector(".auth-view:not([hidden]) .auth-btn, .auth-card .auth-btn, .auth-card input, .auth-card button");
      if (first) { e.preventDefault(); first.focus(); }
      return;
    }
    else if (k === "Tab") return;                          // leave the globe as usual
    else return;
    e.preventDefault(); lastInput = performance.now();
  });
  // the hint shows for keyboard / remote focus only (not after a mouse click or a tap)
  cv.addEventListener("focus", () => { let kb = true; try { kb = cv.matches(":focus-visible"); } catch { /* old browser */ } document.body.classList.toggle("globe-focus", kb); });
  cv.addEventListener("blur", () => document.body.classList.remove("globe-focus"));

  // ------------------------------------------------------------------ attacks
  const SOURCES = [[40.7, -74], [51.5, -0.1], [55.7, 37.6], [39.9, 116.4], [35.7, 139.7], [1.35, 103.8], [-23.5, -46.6], [19.4, -99.1],
    [28.6, 77.2], [52.5, 13.4], [37.6, 127], [-33.9, 151.2], [30, 31.2], [6.5, 3.4], [-1.3, 36.8], [33.6, -7.6], [25.2, 55.3], [48.9, 2.35], [37.8, -122.4], [-26.2, 28]].map(([a, b]) => ll(a, b));
  const HUB = ll(7.9, -1.0);
  const COLORS = ["#e5484d", "#f5b54a", "#5b8def", "#e5484d", "#8e7cf0"];
  const arcs = [], rings = [];
  const pickColor = () => COLORS[(Math.random() * COLORS.length) | 0];
  // attacks run only between points on the side facing the viewer, so every arc starts and lands on the visible globe
  const facing = (v, min = 0.18) => rot(v)[2] > min;
  function spawn(from) {
    const vis = SOURCES.filter((v) => facing(v));
    const a = from || vis[(Math.random() * vis.length) | 0];
    if (!a) return;
    const b = facing(HUB, 0.1) && (from || Math.random() < 0.72) ? HUB : vis[(Math.random() * vis.length) | 0];
    if (!b || a === b) return;
    arcs.push({ a, b, t: 0, speed: 0.0065 + Math.random() * 0.006, color: pickColor(), w: 1 + Math.random() * 1.3 });
  }
  function burst(v) { rings.push({ v, r: 0, color: "#ffffff", max: 34 }); for (let i = 0; i < 5; i++) setTimeout(() => spawn(v), i * 120); }
  function slerp(a, b, t) {
    const d = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2])), om = Math.acos(d);
    if (om < 1e-4) return a;
    const s = Math.sin(om), k1 = Math.sin((1 - t) * om) / s, k2 = Math.sin(t * om) / s;
    return [a[0] * k1 + b[0] * k2, a[1] * k1 + b[1] * k2, a[2] * k1 + b[2] * k2];
  }

  // ------------------------------------------------------------------ frame
  const stars = Array.from({ length: 150 }, () => ({ x: Math.random(), y: Math.random(), z: 0.2 + Math.random() * 0.8, tw: Math.random() * TAU }));
  let last = performance.now(), spawnClock = 0;
  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000); last = now;
    // inertia, then gentle auto-rotation after 2.5 s without input
    if (!drag) {
      yaw += vYaw; pitch = Math.max(-1.25, Math.min(1.25, pitch + vPitch)); vYaw *= 0.94; vPitch *= 0.9;
      if (now - lastInput > 2500) { yaw += dt * 0.12; pitch += (0.28 - pitch) * Math.min(1, dt * 0.6); }
    }
    ctx.clearRect(0, 0, W, H);
    const bg = ctx.createRadialGradient(W * 0.5, H * 0.42, 0, W * 0.5, H * 0.42, Math.max(W, H) * 0.75);
    bg.addColorStop(0, "#0d1324"); bg.addColorStop(1, "#05060a"); ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);
    for (const s of stars) {
      s.tw += dt * (0.6 + s.z);
      const x = ((s.x * W - yaw * 40 * s.z) % W + W) % W, y = ((s.y * H + pitch * 30 * s.z) % H + H) % H;
      ctx.fillStyle = `rgba(190,205,255,${0.12 + 0.35 * s.z * (0.6 + 0.4 * Math.sin(s.tw))})`; ctx.fillRect(x, y, s.z * 1.5, s.z * 1.5);
    }
    const { cx, cy, R } = geo();
    const halo = ctx.createRadialGradient(cx, cy, R * 0.9, cx, cy, R * 1.4);
    halo.addColorStop(0, "rgba(91,141,239,.18)"); halo.addColorStop(1, "rgba(91,141,239,0)"); ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(cx, cy, R * 1.4, 0, TAU); ctx.fill();
    const body = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, R);
    body.addColorStop(0, "rgba(28,40,80,.75)"); body.addColorStop(1, "rgba(8,12,26,.85)"); ctx.fillStyle = body; ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();
    ctx.strokeStyle = "rgba(120,150,255,.28)"; ctx.lineWidth = 1; ctx.stroke();
    // dots: ocean faint, land bright; dots near the pointer light up
    if (land.length && landAlpha < 1) landAlpha = Math.min(1, landAlpha + dt * 1.5);
    const hv = hoverV && now - hoverAt < 1500 ? hoverV : null;
    for (const d of ocean) {
      const [x, y, z] = rot(d); if (z < 0) continue;
      ctx.fillStyle = `rgba(110,135,210,${(0.08 + z * 0.25) * (1 - landAlpha * 0.6)})`; ctx.fillRect(cx + x * R - 0.6, cy - y * R - 0.6, 1.2, 1.2);
    }
    for (const d of land) {
      const [x, y, z] = rot(d); if (z < -0.02) continue;
      let a = (0.25 + z * 0.75) * landAlpha, s = 1 + z * 1.1, col = "160,185,255";
      if (hv) { const dd = (d[0] - hv[0]) ** 2 + (d[1] - hv[1]) ** 2 + (d[2] - hv[2]) ** 2; if (dd < 0.018) { const k = 1 - dd / 0.018; a = Math.min(1, a + k * 0.8); s += k * 1.4; col = "255,200,120"; } }
      ctx.fillStyle = `rgba(${col},${a})`; ctx.fillRect(cx + x * R - s / 2, cy - y * R - s / 2, s, s);
    }
    // the constituency
    const hub = rot(HUB);
    if (hub[2] > 0) { const hx = cx + hub[0] * R, hy = cy - hub[1] * R, pulse = Math.sin(now / 300);
      ctx.fillStyle = "#e5484d"; ctx.beginPath(); ctx.arc(hx, hy, 3.4, 0, TAU); ctx.fill();
      ctx.strokeStyle = `rgba(229,72,77,${0.45 + 0.3 * pulse})`; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(hx, hy, 8 + 2.5 * pulse, 0, TAU); ctx.stroke(); }
    // attacks
    spawnClock += dt;
    if (!reduce && spawnClock > 0.3 && arcs.length < 28) { spawnClock = 0; spawn(); }
    for (let i = arcs.length - 1; i >= 0; i--) {
      const a = arcs[i]; a.t += a.speed * dt * 60;
      const head = Math.min(1, a.t), tail = Math.max(0, head - 0.38);
      // fade out when an end turns away (the globe was dragged); never draw the hidden part
      const ends = Math.min(rot(a.a)[2], rot(a.b)[2]);
      const fade = Math.max(0, Math.min(1, (ends - 0.02) / 0.15));
      ctx.beginPath(); let started = false, vis = 0;
      for (let k = 0; k <= 26; k++) {
        const f = tail + (head - tail) * (k / 26), p = slerp(a.a, a.b, f), lift = 1 + 0.12 * Math.sin(Math.PI * f);
        const [x, y, z] = rot([p[0] * lift, p[1] * lift, p[2] * lift]);
        if (z < 0.02 || x * x + y * y > 1.02) { started = false; continue; }      // behind the globe or past its outline
        vis++; const X = cx + x * R, Y = cy - y * R; started ? ctx.lineTo(X, Y) : ctx.moveTo(X, Y); started = true;
      }
      if (vis && fade > 0) { ctx.strokeStyle = a.color; ctx.globalAlpha = 0.9 * fade; ctx.lineWidth = a.w; ctx.shadowColor = a.color; ctx.shadowBlur = 9; ctx.stroke(); ctx.shadowBlur = 0; ctx.globalAlpha = 1; }
      if (a.t >= 1 && !a.hit) { a.hit = true; rings.push({ v: a.b, r: 0, color: a.color, max: 24 }); }
      if (a.t > 1.38) arcs.splice(i, 1);
    }
    for (let i = rings.length - 1; i >= 0; i--) {
      const g = rings[i]; g.r += dt * 28;
      const [x, y, z] = rot(g.v);
      if (z > 0) { ctx.strokeStyle = g.color; ctx.globalAlpha = Math.max(0, 1 - g.r / g.max); ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(cx + x * R, cy - y * R, g.r, 0, TAU); ctx.stroke(); ctx.globalAlpha = 1; }
      if (g.r > g.max) rings.splice(i, 1);
    }
  }
  if (reduce) {
    for (let i = 0; i < 18; i++) spawn();
    arcs.forEach((a) => { a.t = Math.random(); });
    const still = () => frame(performance.now()); still(); addEventListener("resize", still); setTimeout(still, 1500);   // after the land loads
    return;
  }
  function loop(now) { if (!document.hidden) frame(now); requestAnimationFrame(loop); }
  requestAnimationFrame(loop);
})();
