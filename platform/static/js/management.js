/* Looking Glass · Executive (management portal): aggregated figures only, two platforms, filters that every chart
   follows (click any bar, slice or region to focus on it), explanations of infections and vulnerabilities, and an
   executive PDF report of exactly what is on screen. Charts are plain SVG: no external libraries. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const NS = "http://www.w3.org/2000/svg";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const sv = (t, a = {}) => { const e = document.createElementNS(NS, t); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pct = (x, d = 0) => `${(100 * (x || 0)).toFixed(d)}%`;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SEV_COLOURS = { critical: "#ef4444", high: "#f97316", medium: "#f5b54a", low: "#38bdf8", info: "#94a3b8", unrated: "#64748b" };
  const PALETTE = ["#5b8def", "#8b5cf6", "#22c3a6", "#f5b54a", "#ef6f8a", "#38bdf8", "#a3e635", "#f97316", "#c084fc", "#94a3b8"];
  const FILTERS = {
    comms: [["attack", "Attack type"], ["infection", "Infection"], ["report", "Report"], ["region", "Region"], ["sector", "Sector"], ["network", "Network"], ["severity", "Severity"],
            ["icombo", "Infections on the same device"], ["rcombo", "Reports seeing the same device"], ["code", "Combination code"]],
    services: [["family", "Report family"], ["service", "Service"], ["issue", "Issue"], ["region", "Region"], ["sector", "Sector"], ["network", "Network"], ["severity", "Severity"],
               ["icombo", "Issues on the same host"], ["scombo", "Services on the same host"], ["code", "Combination code"]],
  };
  const state = { plat: "comms", day: "", demo: false, filters: { comms: {}, services: {} }, data: null, shapes: null, shapesFor: "",
    explained: { comms: {}, services: {} }, open: { comms: new Set(), services: new Set() } };
  try { const s = JSON.parse(localStorage.getItem("lg.mgmt") || "{}"); if (s.plat) state.plat = s.plat; } catch { /* private window */ }

  // ---------------- data
  const query = () => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(state.filters[state.plat])) if (v) p.set(k, v);
    if (state.day) p.set("day", state.day);
    if (state.demo) p.set("demo", "1");
    return p;
  };
  // loading: the full logo animation on opening and on switching view; the searching logo badge on refreshes
  const PLAT_LABEL = { comms: "Preparing reported network communications", services: "Preparing publicly accessible / vulnerable services" };
  let busyTimer = null;
  // refreshing: every card keeps its size and shows the searching logo with "Loading data…" until the figures arrive
  function cardsBusy(on) {
    for (const c of document.querySelectorAll(".mg-card, .mg-kpi")) {
      if (on) {
        c.style.minHeight = `${c.offsetHeight}px`;
        let o = c.querySelector(":scope > .mg-card-load");
        if (!o) {
          o = el("div", "mg-card-load"); o.setAttribute("aria-hidden", "true");
          const w = el("span", "lg-logo-wrap searching"); w.innerHTML = window.LGLoader ? window.LGLoader.svg(c.classList.contains("mg-kpi") ? 22 : 34) : "";
          o.append(w, el("span", null, "Loading data…")); c.append(o);
        }
        o.classList.add("on");
      } else {
        c.querySelector(":scope > .mg-card-load")?.classList.remove("on");
        c.style.minHeight = "";
      }
    }
  }
  // only the newest load draws and clears the loaders; what an older one turned on is cleared by the newest (review 2026-11-13)
  let loadSeq = 0, fullOn = false, cardsOn = false;
  async function load(big, quiet = false) {
    const seq = ++loadSeq;
    // quiet: the 7-day baseline finished more days in the background; refresh the figures without the loaders
    if (!quiet) clearTimeout(baseTimer);
    document.body.classList.add("is-loading");
    const full = !quiet && (big || !state.data) && window.LGLoader;
    if (full) { window.LGLoader.busy(typeof big === "string" ? big : PLAT_LABEL[state.plat]); fullOn = true; }
    else if (!quiet) { clearTimeout(busyTimer); cardsBusy(true); cardsOn = true; }
    try {
      const r = await fetch(`/api/mgmt/${state.plat}?${query()}`, { cache: "no-store", credentials: "same-origin" });
      const d = await r.json();
      if (seq !== loadSeq) return;        // a newer load started: it draws
      if (!r.ok) throw new Error(d.error || r.statusText);
      state.data = d;
      render();
    } catch (e) { if (seq === loadSeq) toast(`Could not load: ${e.message}`, "bad"); }
    finally {
      if (seq === loadSeq) {
        document.body.classList.remove("is-loading");
        clearTimeout(busyTimer); if (cardsOn) { cardsOn = false; requestAnimationFrame(() => cardsBusy(false)); }
        if (fullOn) { fullOn = false; window.LGLoader.ready(); }
      }
    }
  }

  // ---------------- small pieces
  function countUp(node, to, fmtFn = fmt) {
    if (reduced) { node.textContent = fmtFn(to); return; }
    const from = Number(node.dataset.v || 0), t0 = performance.now(), dur = 700;
    node.dataset.v = to;
    const step = (t) => { const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3); node.textContent = fmtFn(k < 1 ? Math.round(from + (to - from) * e) : to); if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
  function toast(text, kind) {
    const t = $("mgToast"); t.textContent = text; t.className = `mg-toast ${kind || ""}`; t.hidden = false;
    clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 3500);
  }
  function setFilter(k, v) {
    const f = state.filters[state.plat];
    if (f[k] === v || !v) delete f[k]; else f[k] = v;
    load();
  }
  const empty = (box, text = "Nothing for this selection.") => box.replaceChildren(el("p", "mg-empty", text));

  // ---------------- charts
  function areaChart(box, hours, peak) {
    box.replaceChildren();
    const W = 760, H = 210, L = 38, B = 26, T = 14, max = Math.max(1, ...hours);
    const x = (i) => L + (i * (W - L - 8)) / 23, y = (v) => T + (H - T - B) * (1 - v / max);
    const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, class: "mg-area", role: "img", "aria-label": "Events per hour" });
    const defs = sv("defs"), g = sv("linearGradient", { id: "mgAreaG", x1: 0, x2: 0, y1: 0, y2: 1 });
    g.append(sv("stop", { offset: "0%", "stop-color": "#5b8def", "stop-opacity": ".55" }), sv("stop", { offset: "100%", "stop-color": "#5b8def", "stop-opacity": "0" }));
    defs.append(g); svg.append(defs);
    const steps = Math.min(4, max);          // small peaks: whole-number ticks only (never "2, 2, 1, 1, 0")
    for (let k = 0; k <= steps; k++) {
      const v = (max * k) / steps, yy = y(v);
      svg.append(sv("line", { x1: L, x2: W - 8, y1: yy, y2: yy, class: "grid" }));
      const t = sv("text", { x: L - 6, y: yy + 3, class: "ax", "text-anchor": "end" }); t.textContent = fmt(Math.round(v)); svg.append(t);
    }
    const pts = hours.map((v, i) => [x(i), y(v)]);
    const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join("");
    svg.append(sv("path", { d: `${line}L${x(23)} ${y(0)}L${x(0)} ${y(0)}Z`, fill: "url(#mgAreaG)" }));
    const stroke = sv("path", { d: line, class: "stroke" }); svg.append(stroke);
    for (let i = 0; i < 24; i += 3) { const t = sv("text", { x: x(i), y: H - 8, class: "ax", "text-anchor": "middle" }); t.textContent = `${String(i).padStart(2, "0")}:00`; svg.append(t); }
    if (peak != null) {
      const [px, py] = pts[peak];
      svg.append(sv("line", { x1: px, x2: px, y1: py, y2: y(0), class: "peakline" }), sv("circle", { cx: px, cy: py, r: 5, class: "peak" }));
      // the label stays inside the chart, also when the peak is at the first or last hour
      const anchor = px < L + 70 ? "start" : px > W - 80 ? "end" : "middle";
      const t = sv("text", { x: anchor === "start" ? px + 8 : anchor === "end" ? px - 8 : px, y: Math.max(py - 10, 12), class: "peaktxt", "text-anchor": anchor });
      t.textContent = `Peak ${String(peak).padStart(2, "0")}:00 · ${fmt(hours[peak])}`; svg.append(t);
    }
    // the UTC hours of the day, as Shadowserver's; the same hour in the CSIRT's time zone beside it (localtime.js)
    const d0 = state.data ? Date.parse(`${state.data.day}T00:00:00Z`) : NaN, LT = window.LGTime;
    pts.forEach((p, i) => { const c = sv("circle", { cx: p[0], cy: p[1], r: 9, class: "hit" }); const tt = sv("title");
      tt.textContent = `${String(i).padStart(2, "0")}:00–${String((i + 1) % 24).padStart(2, "0")}:00 UTC${LT && Number.isFinite(d0) ? LT.slot(d0 + i * 3600000, d0 + (i + 1) * 3600000) : ""}: ${fmt(hours[i])}`;
      c.append(tt); svg.append(c); });
    box.append(svg);
    if (!reduced) { const len = stroke.getTotalLength(); stroke.style.strokeDasharray = len; stroke.style.strokeDashoffset = len; requestAnimationFrame(() => { stroke.style.transition = "stroke-dashoffset 1.1s ease"; stroke.style.strokeDashoffset = 0; }); }
  }

  function donut(box, rows, filterKey, unit) {
    box.replaceChildren();
    rows = rows.filter((r) => r.count);
    if (!rows.length) return empty(box);
    if (filterKey === "severity") rows = rows.slice().sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.value) - ["critical", "high", "medium", "low", "info"].indexOf(b.value));
    const top = rows.slice(0, 7), rest = rows.slice(7).reduce((a, r) => a + r.count, 0);
    const parts = rest ? [...top, { label: "Other", value: "", count: rest }] : top;
    const tot = parts.reduce((a, r) => a + r.count, 0), R = 64, r0 = 42, C = 80;
    const svg = sv("svg", { viewBox: "0 0 160 160", class: "mg-donut-svg", role: "img" });
    let a0 = -Math.PI / 2;
    parts.forEach((p, i) => {
      const a1 = a0 + (2 * Math.PI * p.count) / tot, large = a1 - a0 > Math.PI ? 1 : 0;
      const P = (a, r) => [C + r * Math.cos(a), C + r * Math.sin(a)];
      const [x0, y0] = P(a0, R), [x1, y1] = P(a1 - 0.0001, R), [x2, y2] = P(a1 - 0.0001, r0), [x3, y3] = P(a0, r0);
      const colour = filterKey === "severity" ? SEV_COLOURS[p.value] || "#64748b" : p.value === "" && p.label === "Other" ? "#3a3f4d" : PALETTE[i % PALETTE.length];
      p.colour = colour;
      const path = sv("path", { d: `M${x0} ${y0}A${R} ${R} 0 ${large} 1 ${x1} ${y1}L${x2} ${y2}A${r0} ${r0} 0 ${large} 0 ${x3} ${y3}Z`, fill: colour, class: "slice" });
      const t = sv("title"); t.textContent = `${p.label}: ${fmt(p.count)} (${pct(p.count / tot, 1)})`; path.append(t);
      if (filterKey && p.value) { path.style.cursor = "pointer"; path.addEventListener("click", () => setFilter(filterKey, p.value)); }
      svg.append(path); a0 = a1;
    });
    const big = sv("text", { x: C, y: C - 2, class: "dc-big", "text-anchor": "middle" }); big.textContent = fmt(tot);
    const small = sv("text", { x: C, y: C + 15, class: "dc-small", "text-anchor": "middle" }); small.textContent = unit || "events";
    svg.append(big, small);
    const legend = el("ul", "mg-legend");
    parts.forEach((p, i) => {
      const li = el("li"); const b = el("button"); b.type = "button";
      b.append(el("i", null, ""), el("span", null, p.label), el("b", null, pct(p.count / tot)));
      b.querySelector("i").style.background = p.colour || (p.label === "Other" && !p.value ? "#3a3f4d" : PALETTE[i % PALETTE.length]);
      if (filterKey && p.value) b.addEventListener("click", () => setFilter(filterKey, p.value)); else b.disabled = true;
      if (state.filters[state.plat][filterKey] === p.value) b.classList.add("on");
      li.append(b); legend.append(li);
    });
    box.append(svg, legend);
  }

  function bars(box, rows, { key, metric = "hosts", unit = "devices", n = 8, labelOf, stack } = {}) {
    box.replaceChildren(); box.classList.toggle("stack", !!stack);   // stack: long names on their own line
    rows = rows.filter((r) => r[metric] ?? r.count).slice(0, n);
    if (!rows.length) return empty(box);
    const max = Math.max(...rows.map((r) => r[metric] ?? r.count), 1);
    for (const r of rows) {
      const v = r[metric] ?? r.count;
      const b = el("button", `mg-bar${state.filters[state.plat][key] === r.value ? " on" : ""}`); b.type = "button";
      const lbl = el("span", "l", labelOf ? labelOf(r) : r.label);
      const track = el("span", "t"), fill = el("i"); track.append(fill);
      b.append(lbl, track, el("b", null, `${fmt(v)}`));
      b.title = `${labelOf ? labelOf(r) : r.label}: ${fmt(v)} ${unit} (${pct(r.share, 1)} of the ${state.plat === "comms" ? "events" : "records"})${key ? " · click to focus on it" : ""}`;
      if (key) b.addEventListener("click", () => setFilter(key, r.value)); else b.disabled = true;
      box.append(b);
      requestAnimationFrame(() => { fill.style.width = `${(100 * v) / max}%`; });
    }
  }

  // the ranked list of infections / issues, with explanations
  function ranking(box, rows, plat) {
    box.replaceChildren();
    if (!rows.length) return empty(box);
    const max = Math.max(...rows.map((r) => r.hosts || r.count), 1);
    rows.slice(0, 12).forEach((r, i) => {
      const item = el("div", "mg-rank-item"), row = el("div", "mg-rank-row"), inline = el("div", "mg-inline");
      const kind = plat === "comms" || r.infection ? "infection" : "issue";      // a services host's infection explains as one
      const n = el("span", "n", String(i + 1));
      const main = el("div", "m");
      const name = el("button", "nm"); name.type = "button";
      name.append(el("b", null, plat === "comms" ? (r.title || r.value) : r.value));
      if (plat === "comms" && r.title && r.title !== r.value) name.append(el("small", "mono", r.value));
      if (plat === "services" && r.title) name.append(el("small", null, r.title));
      // the whole name and description on hover, in case the description had to be shortened
      name.title = `${plat === "comms" ? (r.title || r.value) : r.value}${r.title && r.title !== r.value ? ` — ${plat === "comms" ? r.value : r.title}` : ""}\nWhat is it? Click to explain`;
      const tags = el("span", "tags");
      if (plat === "services") {
        if (r.exploited) tags.append(el("span", "mg-tag bad", "Actively exploited"));
        if (r.cvss != null) tags.append(el("span", `mg-tag ${r.cvss >= 9 ? "bad" : r.cvss >= 7 ? "warn" : ""}`, `CVSS ${r.cvss}`));
        if (r.epss != null && r.epss >= 0.1) tags.append(el("span", "mg-tag warn", `EPSS ${pct(r.epss)}`));
        if (r.infection) tags.append(el("span", "mg-tag bad", "Infection / category · calling botnet sinkholes"));
        else if (!r.cve) tags.append(el("span", "mg-tag", "Configuration / exposure"));
      } else if (r.family) tags.append(el("span", "mg-tag info", r.family.startsWith("actor:") ? "Threat actor" : "Malpedia"));
      else if (r.title) tags.append(el("span", "mg-tag ok", "Looking Glass definition"));
      const bar = el("span", "t"), fill = el("i"); bar.append(fill);
      main.append(name, tags, bar);
      // its own 7-day trend: the line, and how today compares (new this week, rising, falling, steady)
      const b = state.data && state.data.baseline, vals = b && b.items[r.value];
      if (vals) {
        const today = r.hosts || r.count, g = bReady(b) ? b.assess.items[r.value] : null, a = bAvg(vals);
        const tw = el("div", "mg-rank-trend");
        tw.append(spark(vals, today, { w: 120, h: 26 }), gradePill(g, b),
          el("small", null, a != null ? `7-day avg ${fmt(Math.round(a))} ${plat === "comms" ? "devices" : "hosts"}` : ""));
        tw.title = `Last 7 days: ${vals.map((x) => (x == null ? "–" : fmt(x))).join(", ")} · report day ${fmt(today)}`;
        main.append(tw);
        // words under it for anything that is more than day-to-day variation
        if (g && g.level !== "normal") main.append(el("p", `mg-rank-note lv-${g.level}`, g.note));
      }
      const v = el("div", "v"); v.append(el("b", null, fmt(r.hosts || r.count)), el("small", null, plat === "comms" ? "devices" : "hosts"));
      const f = el("button", "mg-mini", "Focus"); f.type = "button"; f.title = "Show only this in every chart";
      f.addEventListener("click", () => setFilter(kind, r.value));
      const x = el("button", "mg-mini mg-explain-btn"); x.type = "button";
      const acts = el("div", "acts"); acts.append(x);
      if (!(plat === "services" && r.infection)) acts.append(f);           // no infection filter on the services platform
      // the explanation opens under this row (and stays open while the selection changes)
      const openSet = state.open[plat], cache = state.explained[plat];
      const show = async (on) => {
        on ? openSet.add(r.value) : openSet.delete(r.value);
        x.textContent = on ? "Hide" : "Explain"; x.setAttribute("aria-expanded", String(on)); item.classList.toggle("open", on);
        if (!on) { inline.replaceChildren(); return; }
        if (!cache[r.value]) {
          inline.replaceChildren(el("div", "mg-skel"), el("div", "mg-skel short"));
          try {
            const res = await fetch(`/api/mgmt/explain?kind=${kind}&name=${encodeURIComponent(r.value)}`, { credentials: "same-origin" });
            const j = await res.json(); if (!res.ok) throw new Error(j.error || res.statusText);
            cache[r.value] = j;
          } catch (e) { inline.replaceChildren(el("p", "mg-empty", `Could not explain it: ${e.message}`)); return; }
        }
        if (openSet.has(r.value)) inline.replaceChildren(card(cache[r.value], r.value, r));
      };
      x.addEventListener("click", () => show(!openSet.has(r.value)));
      name.addEventListener("click", () => show(!openSet.has(r.value)));
      row.append(n, main, v, acts); item.append(row, inline); box.append(item);
      show(openSet.has(r.value));
      requestAnimationFrame(() => { fill.style.width = `${(100 * (r.hosts || r.count)) / max}%`; });
    });
  }

  // each region's total, with its cities beneath (click a region to focus every chart on it)
  function regionTree(box, d) {
    box.replaceChildren();
    const comms = d.platform === "comms", unit = comms ? "devices" : "hosts";
    const rows = d.regions.filter((r) => r.value !== "Unknown region");
    if (!rows.length) return empty(box);
    const max = Math.max(1, ...rows.map((r) => r.hosts || r.count));
    box.append(el("p", "mg-tree-head", `${comms ? "Devices" : "Hosts"} per region and city`));
    for (const r of rows) {
      const v = r.hosts || r.count, det = (d.region_details || {})[r.value] || {};
      const g = el("div", `mg-tree-reg${state.filters[state.plat].region === r.value ? " on" : ""}`);
      const head = el("button", "mg-tree-row"); head.type = "button"; head.title = `Focus every chart on ${r.label}`;
      const track = el("span", "t"), fill = el("i"); track.append(fill);
      head.append(el("b", "l", r.label), track, el("b", "v", fmt(v)));
      head.addEventListener("click", () => setFilter("region", r.value));
      g.append(head);
      const cities = (det.city_devices || []).filter(([n, c]) => c && (n.toLowerCase() !== r.value.toLowerCase() || (det.city_devices || []).length === 1)).slice(0, 4);
      for (const [n, c] of cities) {
        const li = el("div", "mg-tree-city"); li.append(el("span", null, n), el("small", null, `${fmt(c)} ${unit}`)); g.append(li);
      }
      box.append(g);
      requestAnimationFrame(() => { fill.style.width = `${(100 * v) / max}%`; });
    }
  }

  // regions on the country's map (shapes from geoBoundaries, the same as Settings)
  async function regionMap(svg, rows, country) {
    state.drawN = (state.drawN || 0) + 1; svg.dataset.draw = String(state.drawN);
    svg.replaceChildren();
    state.mapMismatch = null;
    if (!country) { if ($("mgMapNote")) $("mgMapNote").hidden = true; return; }
    if (state.shapesFor !== country) {           // load once; every map drawn meanwhile waits for the same download
      state.shapesFor = country;
      state.shapesP = fetch(`/static/data/adm1/${country}.json`).then((r) => r.json()).catch(() => null);
    }
    const shapes = state.shapes = await state.shapesP;
    if (svg.dataset.draw && svg.dataset.draw !== String(state.drawN)) return;     // a newer selection is being drawn
    const note = $("mgMapNote");
    if (!shapes || !window.LGRegions) { svg.closest(".mg-mapwrap").classList.add("nomap"); if (note) note.hidden = true; return; }
    svg.closest(".mg-mapwrap").classList.remove("nomap");
    const resolve = window.LGRegions.index(shapes);
    const known = rows.filter((r) => r.value && r.value !== "Unknown region");
    const byKey = new Map(); for (const r of known) { const k = resolve(r.value); if (k) byKey.set(k, r); }
    // reports that do not fit this country's map (as on the services platform): the map stays, with a note to
    // choose the right country in Settings; the region list beside it still shows every region
    state.mapMismatch = known.length && !byKey.size ? { n: known.length, country: shapes.country || "this country" } : null;
    if (note) {
      note.hidden = !(known.length && !byKey.size);
      if (!note.hidden) {
        const canSet = document.body.dataset.settings === "1";
        note.querySelector("span").textContent = `None of the ${known.length} regions in these reports are on ${shapes.country || "this country"}'s map. `
          + (canSet ? "Kindly select the right country in Settings to populate the regions."
            : "Please contact your administrator to troubleshoot this: the country chosen in Settings does not match these reports.");
        note.querySelector("a").hidden = !canSet;
      }
    }
    const max = Math.max(1, ...[...byKey.values()].map((r) => r.hosts || r.count));
    const [x0, y0, x1, y1] = shapes.bbox, W = 520, H = 420;
    const kx = Math.cos((((y0 + y1) / 2) * Math.PI) / 180), s = Math.min((W - 20) / ((x1 - x0) * kx), (H - 20) / (y1 - y0));
    const ox = (W - (x1 - x0) * kx * s) / 2, oy = (H - (y1 - y0) * s) / 2, P = (lo, la) => [ox + (lo - x0) * kx * s, oy + (y1 - la) * s];
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const details = state.data.region_details || {}, comms = state.plat === "comms", labels = [];
    const tip = $("mgMapTip"), wrap = svg.closest(".mg-mapwrap");
    const showTip = (ev, reg, r) => {
      const d = r ? details[r.value] || {} : null;
      tip.replaceChildren(el("b", null, window.LGRegions.shortName(reg.name)));
      if (!r) tip.append(el("p", "muted", "Nothing reported in this region."));
      else {
        tip.append(el("p", "big", `${fmt(d.devices ?? r.hosts)} ${comms ? "devices" : "hosts"} · ${fmt(d.events ?? r.count)} ${comms ? "events" : "records"} · ${pct(r.share, 1)}`));
        const list = (label, rows, unit) => { if (!rows?.length) return; tip.append(el("h5", null, label)); const ul = el("ul"); for (const [n, c] of rows) { const li = el("li"); li.append(el("span", null, n), el("b", null, fmt(c))); ul.append(li); } tip.append(ul); };
        list("Cities", d.cities); list(comms ? "Top infections" : "Top issues", d.top); if (!comms) list("Services", d.services); list("Networks", d.networks);
        tip.append(el("p", "muted", "Click to focus every chart on this region"));
      }
      tip.hidden = false;
      const box = wrap.getBoundingClientRect(), tw = tip.offsetWidth, th = tip.offsetHeight;
      let x = ev.clientX - box.left + 16, y = ev.clientY - box.top + 12;
      if (x + tw > box.width) x = ev.clientX - box.left - tw - 16;
      if (y + th > box.height) y = Math.max(0, box.height - th);
      tip.style.left = `${x}px`; tip.style.top = `${y}px`;
    };
    svg.onmouseleave = () => { tip.hidden = true; };
    for (const [k, reg] of Object.entries(shapes.regions)) {
      let d = "";
      for (const poly of reg.polys) for (const ring of poly) d += ring.map(([a, b], i) => { const [x, y] = P(a, b); return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`; }).join("") + "Z";
      const r = byKey.get(k), v = r ? r.hosts || r.count : 0, t = v / max;
      const p = sv("path", { d, class: `rg${r ? "" : " none"}${r && state.filters[state.plat].region === r.value ? " on" : ""}` });
      p.style.fill = r ? `rgba(${Math.round(91 + 148 * t)}, ${Math.round(141 - 70 * t)}, ${Math.round(239 - 162 * t)}, ${0.28 + 0.65 * t})` : "";
      p.addEventListener("mousemove", (ev) => showTip(ev, reg, r));
      p.addEventListener("mouseleave", () => { tip.hidden = true; });
      if (r) p.addEventListener("click", () => setFilter("region", r.value));
      p.setAttribute("aria-label", `${window.LGRegions.shortName(reg.name)}: ${r ? `${fmt(v)} ${comms ? "devices" : "hosts"}` : "nothing reported"}`);
      svg.append(p);
      const bb = p.getBBox(), lab = reg.label ? P(reg.label[0], reg.label[1]) : [bb.x + bb.width / 2, bb.y + bb.height / 2];
      labels.push({ x: lab[0], y: lab[1], lines: [window.LGRegions.shortName(reg.name)], size: Object.keys(shapes.regions).length > 12 ? 9 : 10.5,
        prio: (r ? 1e9 + v : 0) + bb.width * bb.height, n: r ? v : null });
    }
    // every region named where it fits (the busiest first); the rest on hover
    const placed = window.LGRegions.placeLabels ? window.LGRegions.placeLabels(labels, { x0: 0, x1: W, y0: 0, y1: H }) : labels;
    for (const it of placed) {
      const t = sv("text", { x: it.x, y: it.y + it.size * 0.35, class: "rl", "text-anchor": "middle" }); t.style.fontSize = `${it.size}px`; t.textContent = it.lines[0];
      svg.append(t);
      if (it.n != null) { const c = sv("text", { x: it.x, y: it.y + it.size * 1.5, class: "rn", "text-anchor": "middle" }); c.style.fontSize = `${it.size - 0.5}px`; c.textContent = fmt(it.n); svg.append(c); }
    }
  }

  // ---------------- explain an infection or an issue
  async function explain(kind, name, row) {
    $("mgDrawerKind").textContent = kind === "issue" ? (/^CVE-/i.test(name) ? "Vulnerability" : "Issue") : "Infection / category";
    $("mgDrawerTitle").textContent = name;
    const body = $("mgDrawerBody"); body.replaceChildren(el("div", "mg-skel"), el("div", "mg-skel short"), el("div", "mg-skel"));
    $("mgDrawer").classList.add("open"); $("mgDrawer").setAttribute("aria-hidden", "false"); $("mgScrim").hidden = false;
    let x;
    try { const r = await fetch(`/api/mgmt/explain?kind=${kind}&name=${encodeURIComponent(name)}`, { credentials: "same-origin" }); x = await r.json(); if (!r.ok) throw new Error(x.error || r.statusText); }
    catch (e) { body.replaceChildren(el("p", "mg-empty", `Could not explain it: ${e.message}`)); return; }
    body.replaceChildren(card(x, name, row));
  }
  const link = (u) => { let ok = false; try { ok = ["http:", "https:"].includes(new URL(u).protocol); } catch { ok = false; } if (!ok) return el("span", null, u); const a = el("a", null, u.replace(/^https?:\/\//, "").slice(0, 70)); a.href = u; a.target = "_blank"; a.rel = "noopener noreferrer"; return a; };
  function card(x, name, row) {
    const c = el("div", "mg-explain");
    const badge = (t, k) => el("span", `mg-tag ${k || ""}`, t);
    const head = el("div", "mg-ex-badges");
    if (x.kind === "cve") {
      if (x.exploited) head.append(badge("Actively exploited · CISA KEV", "bad"));
      if (x.cvss) head.append(badge(`CVSS ${x.cvss.score} ${String(x.cvss.severity || "").toLowerCase()}`, x.cvss.score >= 9 ? "bad" : x.cvss.score >= 7 ? "warn" : ""));
      if (x.epss != null) head.append(badge(`EPSS ${pct(x.epss, 1)} in 30 days`, x.epss >= 0.1 ? "warn" : ""));
    } else if (x.found && x.kind === "actor") head.append(badge("Threat actor · Malpedia", "warn"));
    else if (x.found) head.append(badge("Malware family · Malpedia", "info"));
    else if (x.curated) head.append(badge("Looking Glass definition", "ok"));
    else head.append(badge(x.title || "Not in Malpedia", ""));
    c.append(head);
    const title = x.kind === "cve" ? (x.kev?.name || "") : (x.name || x.title || "");
    if (title && title !== name) c.append(el("h3", null, title));
    if (row) c.append(el("p", "mg-ex-impact", state.plat === "comms" ? `${fmt(row.hosts)} devices · ${fmt(row.count)} events in this selection` : `${fmt(row.hosts)} hosts · ${fmt(row.count)} records in this selection`));
    const desc = x.description || x.text || x.reason;
    if (desc) c.append(el("p", "mg-ex-desc", desc));
    if (x.kind === "cve" && x.kev) {
      const box = el("div", "mg-ex-alert");
      box.append(el("b", null, "Attackers are exploiting this vulnerability."), el("p", null, `In CISA's Known Exploited Vulnerabilities catalog since ${x.kev.date_added}${x.kev.ransomware === "Known" ? "; used in ransomware campaigns" : ""}.`));
      if (x.kev.action) box.append(el("p", null, `Required action: ${x.kev.action}`));
      c.append(box);
    }
    const facts = [];
    if (x.type) facts.push(["Type", x.type]);
    if (x.alt_names?.length) facts.push(["Also known as", x.alt_names.slice(0, 6).join(", ")]);
    if (x.attribution?.length) facts.push(["Attributed to", x.attribution.join(", ")]);
    if (x.country) facts.push(["Suspected origin", x.country]);
    if (x.families?.length && x.kind === "actor") facts.push(["Malware it uses", x.families.slice(0, 8).join(", ")]);
    if (x.published) facts.push(["Published", x.published]);
    if (x.cwes?.length) facts.push(["Weakness", x.cwes.join(", ")]);
    if (x.seen_in?.length) facts.push(["Seen in", x.seen_in.join(", ")]);
    if (facts.length) { const dl = el("dl", "mg-ex-facts"); for (const [k, v] of facts) dl.append(el("dt", null, k), el("dd", null, v)); c.append(dl); }
    for (const n of x.notes || []) {               // researchers' notes on the name (notes.py)
      const p = el("p", "mg-ex-desc mp-note"); p.append(el("b", null, `Notes shared by ${n.role || "Researcher"}: ${n.by || "a researcher"}${n.date ? ` (${n.date})` : ""}: `), document.createTextNode(n.text));
      c.append(p);
      if (n.codes?.length) c.append(window.LGCodes ? window.LGCodes.line(n.codes) : el("p", "mg-ex-desc mp-note", `Combinations: ${n.codes.map((x) => x.code).join(", ")}`));
    }
    const refs = [x.url, x.kev_url, ...(x.references || []), ...(x.curated_references || [])].filter(Boolean);
    if (refs.length) { const ul = el("ul", "mg-ex-refs"); for (const u of [...new Set(refs)].slice(0, 8)) { const li = el("li"); li.append(link(u)); ul.append(li); } c.append(el("h4", null, "References"), ul); }
    return c;
  }
  function closeDrawer() { $("mgDrawer").classList.remove("open"); $("mgDrawer").setAttribute("aria-hidden", "true"); $("mgScrim").hidden = true; }
  $("mgDrawerClose").addEventListener("click", closeDrawer); $("mgScrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // ---------------- 7-day baseline
  // b.kpis[key] / b.items[name]: values of the 7 days before the report day (null = no report that day)
  const bAvg = (vals) => { const v = (vals || []).filter((x) => x != null); return v.length ? v.reduce((a, c) => a + c, 0) / v.length : null; };
  const bReady = (b) => b && b.available >= 3;
  // the server grades every change (management.py assess): normal (grey), info (blue), good (green),
  // watch (amber: look into it) and high (red: investigate now); the words say what it may mean
  function gradePill(g, b) {
    if (!g) return el("span", "mg-delta lv-normal", b && b.building ? "baseline…" : "too few days");
    const up = g.change != null && g.change > 0, txt = g.label;
    const p = el("span", `mg-delta lv-${g.level}`, `${g.level === "normal" ? "" : up ? "▲ " : g.change != null && g.change < 0 ? "▼ " : ""}${txt}`);
    p.title = g.note || "";
    return p;
  }
  function spark(vals, today, { w = 120, h = 30, avgLine = true } = {}) {
    const pts = [...vals, today];
    const nums = pts.filter((x) => x != null);
    const svg = sv("svg", { viewBox: `0 0 ${w} ${h}`, width: w, height: h, class: "mg-spark", "aria-hidden": "true" });
    if (nums.length < 2) return svg;
    const lo = Math.min(...nums, 0), hi = Math.max(...nums, 1), X = (i) => 3 + (i * (w - 6)) / (pts.length - 1), Y = (v) => h - 4 - ((v - lo) / (hi - lo || 1)) * (h - 8);
    const a = bAvg(vals);
    if (avgLine && a != null) svg.append(sv("line", { x1: 2, x2: w - 2, y1: Y(a), y2: Y(a), class: "avg" }));
    let d = "", area = "";
    pts.forEach((v, i) => { if (v == null) return; d += `${d ? "L" : "M"}${X(i).toFixed(1)} ${Y(v).toFixed(1)}`; });
    area = `${d}L${X(pts.length - 1).toFixed(1)} ${h}L${X(pts.findIndex((v) => v != null)).toFixed(1)} ${h}Z`;
    svg.append(sv("path", { d: area, class: "area" }), sv("path", { d, class: "line" }));
    svg.append(sv("circle", { cx: X(pts.length - 1), cy: Y(today), r: 3, class: "today" }));
    return svg;
  }
  const BASE_FIGS = {
    comms: [["devices", "Affected devices"], ["multi_infected", "Several infections"], ["infections", "Infections"],
            ["cross_report", "In several reports"], ["critical", "Critical events"], ["regions", "Regions affected"], ["events", "Events"]],
    services: [["hosts", "Internet-facing hosts"], ["vulnerable_hosts", "Hosts with an issue"], ["kev_hosts", "Actively exploited"], ["critical_cves", "Critical CVEs"],
               ["multi_issue", "Several issues"], ["cross_report", "In several reports"], ["issues", "Kinds of issue"], ["records", "Records"]],
  };
  function baselineCard(d) {
    const b = d.baseline, box = $("chBase"), st = $("mgBaseStatus");
    box.replaceChildren();
    st.textContent = b && b.building && b.progress ? `Building the baseline… ${b.progress.done}/${b.progress.total} days` : b && b.building ? "Building the baseline…" : b ? `${b.available} of 7 days with reports` : "";
    st.classList.toggle("busy", !!(b && b.building));
    if (!b) return empty(box, "No baseline for this selection.");
    const label = (iso) => new Date(`${iso}T00:00:00Z`).toLocaleDateString("en-GB", { weekday: "short", day: "numeric", timeZone: "UTC" });
    for (const [key, name] of BASE_FIGS[d.platform]) {
      const vals = b.kpis[key] || [], today = d.kpis[key] ?? 0, g = bReady(b) ? b.assess.kpis[key] : null, a = bAvg(vals);
      const cell = el("div", `mg-base-cell${g ? ` lv-${g.level}` : ""}`);
      const head = el("div", "mg-base-head"); head.append(el("span", null, name), el("b", null, fmt(today)));
      const foot = el("div", "mg-base-foot");
      foot.append(gradePill(g, b), el("small", null, a != null ? `avg ${fmt(Math.round(a))}` : ""));
      const ch = spark(vals, today, { w: 260, h: 70 });
      ch.setAttribute("aria-label", `${name}: ${b.days.map((x, i) => `${label(x)} ${vals[i] == null ? "no report" : fmt(vals[i])}`).join(", ")}, report day ${fmt(today)}`);
      const axis = el("div", "mg-base-axis"); axis.append(el("span", null, label(b.days[0])), el("span", null, "report day"));
      cell.append(head, ch, axis, foot);
      if (g && g.level !== "normal") cell.append(el("p", `mg-base-note lv-${g.level}`, g.note));
      box.append(cell);
    }
    // how the changes are graded (the thresholds), stated on the page
    const sc = $("mgScale"); sc.replaceChildren();
    if (b.scale) {
      sc.append(el("h3", null, "How changes are graded"),
        el("p", "mg-scale-lead", "Every figure is compared with its own average over the 7 days before the report day: "
          + "(today − 7-day average) ÷ 7-day average. The percentage decides the grade:"));
      const list = el("div", "mg-scale-list");
      for (const s of b.scale) {
        const row = el("div", "mg-scale-row");
        row.append(el("span", `mg-delta lv-${s.level}`, s.name), el("b", null, s.range), el("span", "m", s.meaning));
        list.append(row);
      }
      sc.append(list);
    }
  }
  let baseTimer;
  function pollBaseline(d) {
    clearTimeout(baseTimer);
    if (d.baseline && d.baseline.building) baseTimer = setTimeout(() => { if (state.data === d) load(false, true); }, 6000);
  }

  // ---------------- render everything
  function kpiTiles(d) {
    const k = d.kpis, box = $("mgKpis");
    const tiles = d.platform === "comms" ? [
      ["devices", k.devices, "Affected devices", "infected or attacking", "blue"],
      ["infections", k.infections, "Infections", "malware families and categories", "violet"],
      ["multi_infected", k.multi_infected, "Several infections", "devices to clean up first", "amber"],
      ["cross_report", k.cross_report, "In several reports", "devices seen by more than one report", "red"],
      ["regions", k.regions, "Regions affected", `${fmt(k.networks)} networks`, "teal"],
      ["events", k.events, "Events", `${pct(k.share_of_day, 1)} of the day`, "slate"],
    ] : [
      ["hosts", k.hosts, "Internet-facing hosts", `${fmt(k.services)} services exposed`, "blue"],
      ["vulnerable_hosts", k.vulnerable_hosts, "Hosts with an issue", `${pct(k.vulnerable_hosts / Math.max(1, k.hosts))} of the hosts`, "amber"],
      ["kev_hosts", k.kev_hosts, "Actively exploited", `${fmt(k.kev_cves)} CVEs in CISA KEV`, "red"],
      ["critical_cves", k.critical_cves, "Critical CVEs", "CVSS 9 or more", "violet"],
      ["multi_issue", k.multi_issue, "Several issues", "largest attack surface", "teal"],
      ["records", k.records, "Records", `${pct(k.share_of_day, 1)} of the day`, "slate"],
    ];
    if (box.dataset.plat !== d.platform) { box.replaceChildren(); box.dataset.plat = d.platform; }
    const b = d.baseline;
    tiles.forEach(([id, v, label, sub, tone], i) => {
      let t = box.children[i];
      if (!t) { t = el("div", `mg-kpi ${tone}`); t.append(el("span", "mg-kpi-label"), el("b", "mg-kpi-v", "0"), el("span", "mg-kpi-sub"), el("div", "mg-kpi-trend")); box.append(t); }
      t.className = `mg-kpi ${tone}`; t.querySelector(".mg-kpi-label").textContent = label; t.querySelector(".mg-kpi-sub").textContent = sub;
      countUp(t.querySelector(".mg-kpi-v"), v);
      // against the 7-day baseline: a small trend line (7 days and the report day) and the change on the average
      const tr = t.querySelector(".mg-kpi-trend"); tr.replaceChildren();
      const vals = b && b.kpis[id];
      if (vals) {
        const g = bReady(b) ? b.assess.kpis[id] : null, a = bAvg(vals);
        const ln = spark(vals, v, { w: 200, h: 26 }); ln.setAttribute("preserveAspectRatio", "none");
        // the average first, on its own line (the full number), then the grade under it
        const avgLine = el("div", "mg-kpi-avg"); avgLine.append(el("span", null, "7-day average"), el("b", null, a != null ? fmt(Math.round(a)) : "–"));
        tr.append(ln, avgLine, gradePill(g, b));
        if (g && (g.level === "watch" || g.level === "high")) tr.append(el("p", `mg-kpi-note lv-${g.level}`, g.note));
        tr.title = `${g ? g.note + " " : ""}Last 7 days: ${vals.map((x) => (x == null ? "–" : fmt(x))).join(", ")} · report day ${fmt(v)}`;
      }
    });
  }
  function filterBar(d) {
    const row = $("mgFilters"); row.replaceChildren();
    const f = state.filters[state.plat];
    for (const [k, label] of FILTERS[state.plat]) {
      const opts = d.facets[k] || []; if (!opts.length) continue;
      const s = el("select", "lg-enhance mg-dd"); s.setAttribute("aria-label", label); s.dataset.caption = label;
      s.append(new Option(`All ${label === "Severity" ? "severities" : "of them"}`, ""));
      for (const o of opts) { const v = typeof o === "object" ? o.value : o, l = typeof o === "object" ? o.label : o; s.append(new Option(l, v)); }
      s.value = f[k] || ""; s.addEventListener("change", () => { if (s.value) f[k] = s.value; else delete f[k]; load(); });
      row.append(s); window.LGSelect?.enhance(s);
    }
    const act = $("mgActive"); act.replaceChildren();
    const keys = Object.keys(f).filter((k) => f[k]);
    if (keys.length) {
      act.append(el("span", "mg-active-lbl", "Focused on"));
      for (const k of keys) {
        const lbl = (FILTERS[state.plat].find((x) => x[0] === k) || [k, k])[1];
        const facet = (d.facets[k] || []).find((o) => (typeof o === "object" ? o.value : o) === f[k]);
        const chip = el("button", "mg-chip"); chip.type = "button"; chip.append(el("span", null, `${lbl}: ${typeof facet === "object" ? facet.label : f[k]}`), el("b", null, "×"));
        chip.title = "Remove this filter"; chip.addEventListener("click", () => { delete f[k]; load(); }); act.append(chip);
      }
      const reset = el("button", "mg-reset", "Reset all"); reset.type = "button"; reset.addEventListener("click", () => { state.filters[state.plat] = {}; load(); }); act.append(reset);
    }
  }
  function render() {
    const d = state.data, comms = d.platform === "comms";
    window.LGTime?.set(d.tz);              // the CSIRT's time zone that day (Settings > Country)
    document.body.dataset.plat = d.platform;
    for (const b of document.querySelectorAll("[data-plat]")) b.setAttribute("aria-selected", String(b.dataset.plat === d.platform));
    $("mgScope").textContent = `${d.scope}${d.demo ? " · Demo mode" : ""}`;
    // rebuilt whenever the days differ, not only their number: at midnight the window moves by a day and keeps its length
    // (review 2026-11-13: the list went stale)
    const sel = $("mgDay"); if ([...sel.options].map((o) => o.value).join() !== d.days.slice().reverse().join()) { sel.replaceChildren(...d.days.slice().reverse().map((x) => new Option(new Date(`${x}T00:00:00Z`).toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }), x))); }
    sel.value = d.day; window.LGSelect?.sync(sel);
    $("mgEyebrow").textContent = `${comms ? "Infections & attacks" : "Exposure & vulnerabilities"} · ${new Date(`${d.day}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" })}`;
    $("mgHeadline").textContent = d.findings[0] || "Nothing was reported for this selection.";
    filterBar(d); kpiTiles(d);
    const findings = $("mgFindings"); findings.replaceChildren(...d.findings.slice(1).map((t) => el("li", null, t)));
    if (!findings.children.length) findings.append(el("li", null, "No further findings for this selection."));
    areaChart($("chTrend"), d.hours, d.peak_hour);
    baselineCard(d); pollBaseline(d);
    const pk = d.peak_hour != null ? Date.parse(`${d.day}T00:00:00Z`) + d.peak_hour * 3600000 : null;
    $("tTrend").textContent = `${comms ? "Events" : "Records"} per hour (UTC)${d.peak_hour != null ? ` · peak ${String(d.peak_hour).padStart(2, "0")}:00 UTC${window.LGTime ? window.LGTime.also(pk, false) : ""}` : ""}`;
    regionMap($("chMap"), d.regions, d.country);
    regionTree($("chRegions"), d);
    donut($("chSectors"), d.sectors, "sector", comms ? "events" : "records");
    $("tTopTitle").textContent = comms ? "Top infections" : "Top issues";
    $("tTop").textContent = comms ? "Devices per infection · Explain shows what each one is, right under it" : "Hosts per issue, most hosts first · Explain shows what each one is";
    ranking($("chTop"), comms ? d.infections : d.issues.concat(d.infections_on || []).sort((a, b) => b.hosts - a.hosts || Number(b.exploited) - Number(a.exploited) || (b.cvss || 0) - (a.cvss || 0)), d.platform);
    $("tMixTitle").textContent = comms ? "Attack types" : "Report families";
    donut($("chMix"), comms ? d.attack : d.families, comms ? "attack" : "family", comms ? "events" : "records");
    bars($("chNets"), d.networks.filter((r) => r.value !== "Unknown network"), { key: "network", unit: comms ? "devices" : "hosts" });
    // every report of the selection, ranked by devices (hosts), none left out; a click focuses the page on it
    const reps = d.reports || [];
    bars($("chReports"), reps, { key: comms ? "report" : "service", unit: comms ? "devices" : "hosts", n: Infinity });
    $("tReports").textContent = `All ${fmt(reps.length)} report${reps.length === 1 ? "" : "s"} with data in this selection, ranked by ${comms ? "devices" : "hosts"} · click one to focus on it`;
    if (comms) {
      $("tX1Title").textContent = "Devices in two reports"; $("tX1").textContent = "The same device seen by different sensors";
      bars($("chX1"), d.report_pairs, { metric: "count", unit: "devices", stack: true });
      $("tX2Title").textContent = "Where infected devices connect to"; $("tX2").textContent = "Countries of the servers contacted";
      bars($("chX2"), d.destinations, { metric: "count", unit: "events", labelOf: (r) => countryName(r.label) });
    } else {
      $("tX1Title").textContent = "Exposed services"; $("tX1").textContent = "Hosts per service · click to focus";
      bars($("chX1"), d.services, { key: "service", unit: "hosts" });
      $("tX2Title").textContent = "Industries"; $("tX2").textContent = "Sector of the organisations (Shadowserver)";
      bars($("chX2"), d.industries, { metric: "count", unit: "records" });
    }
    insight(d);
    level();
    $("mgTook").textContent = `Data of ${d.day} · prepared in ${d.took} s.`;
    try { localStorage.setItem("lg.mgmt", JSON.stringify({ plat: state.plat })); } catch { /* private window */ }
  }
  // ---------------- deeper insight: the analyst figures, aggregated
  function hero(box, items) {
    box.replaceChildren(...items.map(([v, l, tone]) => { const d = el("div", `mg-hero-stat ${tone || ""}`); const b = el("b", null, "0"); d.append(b, el("span", null, l)); countUp(b, v); return d; }));
  }
  function steps(box, rows, unit) {
    box.replaceChildren();
    const max = Math.max(1, ...rows.map((r) => r.count));
    for (const r of rows) {
      const s = el("div", "mg-step"), col = el("i"); s.append(el("b", null, fmt(r.count)), el("span", "col"), el("small", null, r.label));
      s.querySelector(".col").append(col); s.title = `${fmt(r.count)} ${unit} with ${r.label}`;
      requestAnimationFrame(() => { col.style.height = `${Math.max(4, (100 * r.count) / max)}%`; });
      box.append(s);
    }
  }
  // the top findings: the most common combinations (the executive report brings every one as CSV)
  // key: the filter a row sets (icombo / rcombo / scombo): click = focus every chart on the devices or hosts with exactly
  // this combination; clicking the active row again removes the focus
  function comboList(box, rows, total, unit, key) {
    box.replaceChildren();
    if (!rows.length) return empty(box, "No combinations in this selection.");
    const max = Math.max(1, ...rows.map((r) => r.count));
    const list = el("div", "mg-combo-list");
    rows.slice(0, 10).forEach((r, i) => {
      const on = key && state.filters[state.plat][key] === r.label;
      const row = el(key ? "button" : "div", `mg-combo${on ? " on" : ""}`), parts = el("div", "parts");
      for (const p of r.label.split(" + ")) parts.append(el("span", "mg-combo-part", p));
      const bar = el("span", "t"), fill = el("i"); bar.append(fill);
      row.append(el("span", "n", String(i + 1)), parts, el("b", null, fmt(r.count)), bar);
      row.title = `${r.label}: ${fmt(r.count)} ${unit} with exactly this combination`
        + (key ? (on ? " · click again to show everything" : ` · click to see a breakdown of these ${unit}`) : "");
      if (key) { row.type = "button"; row.setAttribute("aria-pressed", String(!!on)); row.addEventListener("click", () => setFilter(key, r.label)); }
      list.append(row);
      requestAnimationFrame(() => { fill.style.width = `${(100 * r.count) / max}%`; });
    });
    box.append(list, el("p", "mg-combo-note", total > 10
      ? `Top 10 of ${fmt(total)} combinations${key ? " · click one for a breakdown" : ""}. The executive report includes every one as a CSV file.`
      : `All ${fmt(total)} combination${total === 1 ? "" : "s"}${key ? " · click one for a breakdown" : ""}.`));
  }
  // the cards with several infections/issues and the cross-report analysis end level with the stacked column;
  // their top-findings lists scroll inside (wide screens only, where they sit in one row with the column)
  let levelObs = null;
  function level() {
    const grid = document.querySelector(".mg-grid-insight"), stack = grid?.querySelector(".mg-stack");
    if (!stack) return;
    const apply = () => {
      if (innerWidth <= 1180) { grid.classList.remove("levelled"); return; }
      grid.style.setProperty("--mg-level", `${stack.offsetHeight}px`); grid.classList.add("levelled");
    };
    if (!levelObs && window.ResizeObserver) { levelObs = new ResizeObserver(apply); levelObs.observe(stack); addEventListener("resize", apply); }
    apply();
  }
  function insight(d) {
    const comms = d.platform === "comms";
    if (comms) {
      $("tMultiTitle").textContent = "Devices with several infections"; $("tMulti").textContent = "The clean-up priority: one device, more than one infection";
      hero($("sMulti"), [[d.multi.devices, "devices", "amber"], [Math.round(100 * d.multi.share), "% of the affected devices", ""]]);
      steps($("chMultiCount"), d.multi.by_count, "devices");
      $("tCombos").textContent = "Top findings: infections on the same device";
      comboList($("chCombos"), d.multi.combos, d.multi.combinations, "devices", "icombo");
      $("tCross").textContent = "The same device seen by different sensors";
      hero($("sCross"), [[d.cross.devices, "devices in several reports", "blue"], [Math.round(100 * d.cross.share), "% of the devices", ""]]);
      steps($("chCrossCount"), d.cross.by_count, "devices");
      $("tPairs").textContent = "Top findings: reports seeing the same device";
      comboList($("chPairs"), d.cross.combos, d.cross.combinations, "devices", "rcombo");
      $("tX3Title").textContent = "Repeat behaviour"; $("tX3").textContent = "Devices that call home again and again (beaconing)";
      hero($("sX3"), [[d.beacon.repeating, "seen three times or more", "violet"], [d.beacon.regular, "at a regular rhythm", "amber"]]);
      $("chX3").replaceChildren(el("p", "mg-note", d.beacon.typical ? `Typical repeat interval: ${d.beacon.typical}. A regular rhythm points to automated malware check-ins.` : "Not enough repeated contacts to measure a rhythm."));
      $("tX4Title").textContent = "C2 / sinkhole domains"; $("tX4").textContent = `${fmt(d.c2.domains)} domains and ${fmt(d.c2.destinations)} destination servers contacted · devices per domain`;
      bars($("chX4"), d.c2.top, { metric: "hosts", unit: "devices", n: 8 });
    } else {
      $("tMultiTitle").textContent = "Hosts with several issues"; $("tMulti").textContent = "The largest attack surface: one host, more than one issue";
      hero($("sMulti"), [[d.multi.hosts, "hosts", "amber"], [Math.round(100 * d.multi.share), "% of the hosts with an issue", ""]]);
      steps($("chMultiCount"), d.multi.by_count, "hosts");
      $("tCombos").textContent = "Top findings: issues on the same host";
      comboList($("chCombos"), d.multi.combos, d.multi.combinations, "hosts", "icombo");
      $("tCross").textContent = "The same host in several reports";
      hero($("sCross"), [[d.cross.hosts, "hosts in several reports", "blue"], [Math.round(100 * d.cross.share), "% of the hosts", ""]]);
      steps($("chCrossCount"), d.cross.by_count, "hosts");
      $("tPairs").textContent = "Top findings: services (reports) on the same host";
      comboList($("chPairs"), d.cross.combos, d.cross.combinations, "hosts", "scombo");
      $("tX3Title").textContent = "Kinds of issue"; $("tX3").textContent = "Vulnerabilities versus configuration and exposure";
      hero($("sX3"), [[d.kpis.cves, "different CVEs", "violet"], [d.kpis.issues - d.kpis.cves, "other issues", ""]]);
      bars($("chX3"), d.issue_kinds, { metric: "count", unit: "records" });
      $("tX4Title").textContent = "Devices"; $("tX4").textContent = "Vendor and type of the internet-facing devices identified";
      bars($("chX4"), d.devices, { metric: "count", unit: "hosts", n: 8 });
    }
    donut($("chSev"), d.severity, "severity", comms ? "events" : "records");
  }
  const countryName = (c) => { try { return new Intl.DisplayNames(["en"], { type: "region" }).of(c) || c; } catch { return c; } };

  // ---------------- controls
  for (const b of document.querySelectorAll("[data-plat]")) b.addEventListener("click", () => { if (state.plat !== b.dataset.plat) { state.plat = b.dataset.plat; load(true); } });
  $("mgDay").addEventListener("change", () => { state.day = $("mgDay").value; load(); });
  // back on the page after midnight (UTC): the days have moved on, so the list and the figures are fetched again,
  // quietly (review 2026-11-13: the day picker stayed on the old days until the page was reloaded)
  let openedOn = new Date().toISOString().slice(0, 10);
  document.addEventListener("visibilitychange", () => {
    const today = new Date().toISOString().slice(0, 10);
    if (document.visibilityState === "visible" && today !== openedOn && state.data) { openedOn = today; load(false, true); }
  });
  $("mgDemo").addEventListener("click", () => { state.demo = !state.demo; $("mgDemo").setAttribute("aria-pressed", String(state.demo)); state.filters[state.plat] = {}; load(state.demo ? "Opening the demonstration data" : true); });
  // the reports' regions are on none of the selected country's regions: ask before the report (without the map,
  // or fix the country first: admins in Settings, management users through their administrator)
  function mapWarning() {
    return new Promise((done) => {
      const canSet = document.body.dataset.settings === "1", mm = state.mapMismatch;
      const back = el("div", "mg-dlg-back"), dlg = el("div", "mg-dlg");
      dlg.setAttribute("role", "alertdialog"); dlg.setAttribute("aria-modal", "true"); dlg.setAttribute("aria-labelledby", "mgDlgT");
      const t = el("h3", null, "The data does not match the map"); t.id = "mgDlgT";
      const p1 = el("p", null, `None of the ${mm.n} regions in these reports are on ${mm.country}'s map, so the report's map would be empty.`);
      const p2 = el("p", "muted", canSet
        ? "You can generate the report without the map (the regions and their cities are still listed), or select the right country in Settings first."
        : "Please contact your administrator to troubleshoot this (the country chosen in Settings does not match these reports). Meanwhile you can generate the report without the map; the regions and their cities are still listed.");
      const acts = el("div", "mg-dlg-acts");
      const close = (v) => { back.remove(); document.removeEventListener("keydown", key); done(v); };
      const key = (e) => { if (e.key === "Escape") close(null); };
      const bt = (label, cls, v) => { const x = el("button", cls, label); x.type = "button"; x.addEventListener("click", () => close(v)); return x; };
      acts.append(bt("Cancel", "mg-link", null),
        canSet ? bt("Select the right map", "mg-link", "settings") : bt("Contact the administrator", "mg-link", "admin"),
        bt("Generate without the map", "mg-dlg-go", "nomap"));
      dlg.append(t, p1, p2, acts); back.append(dlg);
      back.addEventListener("click", (e) => { if (e.target === back) close(null); });
      document.addEventListener("keydown", key);
      document.body.append(back); acts.lastChild.focus();
    });
  }
  $("mgReport").addEventListener("click", async () => {
    const b = $("mgReport"); if (b.disabled) return;
    const p = query(); p.set("platform", state.plat);
    if (state.mapMismatch) {
      const v = await mapWarning();
      if (!v) return;
      if (v === "settings") { location.href = "/settings"; return; }
      if (v === "admin") { toast(`Please contact your administrator to troubleshoot this: Settings has ${state.mapMismatch.country}, which does not match these reports.`, "ok"); return; }
      p.set("map", "0");
    }
    b.disabled = true; b.classList.add("busy"); b.querySelector("b").textContent = "Preparing the report…";
    try {
      const r = await fetch(`/api/mgmt/report?${p}`, { credentials: "same-origin", cache: "no-store" });
      if (!r.ok) { let m = r.statusText; try { m = (await r.json()).error || m; } catch { /* not JSON */ } throw new Error(m); }
      const blob = await r.blob(), a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = ((r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/) || [])[1] || "looking-glass-executive.zip";
      document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      toast("Executive report downloaded", "ok");
    } catch (e) { toast(`The report failed: ${e.message}`, "bad"); }
    finally { b.disabled = false; b.classList.remove("busy"); b.querySelector("b").textContent = "Executive report"; }
  });
  $("mgExplainAll").addEventListener("click", async () => {
    if (!state.data) return;      // clicked before the first load: nothing to explain yet (review 2026-11-13)
    const d = state.data, comms = d.platform === "comms", b = $("mgExplainAll");
    const names = (comms ? d.infections : d.issues).slice(0, 25).map((r) => r.value);
    b.disabled = true;
    try {
      const res = await window.LGLookup.run({ kind: comms ? "malpedia" : "issues", values: names, title: comms ? "Explaining the top infections" : "Explaining the top issues",
        intro: comms ? "Each infection is looked up once in Malpedia (malware families and threat actors) or in the Looking Glass definitions."
          : "CVEs: CISA's Known Exploited Vulnerabilities catalog, EPSS and the official CVE records; other issues: their definitions.",
        doneText: "Each explanation is now shown under its name in the list on the dashboard. You can close this window." });
      Object.assign(state.explained[d.platform], res);
      for (const n of names.slice(0, 12)) state.open[d.platform].add(n);
      ranking($("chTop"), comms ? d.infections : d.issues.concat(d.infections_on || []).sort((a, c) => c.hosts - a.hosts || Number(c.exploited) - Number(a.exploited) || (c.cvss || 0) - (a.cvss || 0)), d.platform);
      $("cTop").scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
      toast(`${Object.keys(res).length} explained: shown under each name`, "ok");
    } catch (e) { toast(e.message, "bad"); }
    finally { b.disabled = false; }
  });
  // opened from a finding (/management?code=LG-C-…): the portal shows exactly that combination, on its platform
  (async () => {
    const qs = new URLSearchParams(location.search);
    const code = (qs.get("code") || "").trim().toUpperCase();
    // embedded in a review page (review.html): the portal's own figures, without its header
    if (qs.get("embed") === "1") document.documentElement.classList.add("mg-embed");
    const many = code.split(",").map((x) => x.trim()).filter((x) => /^LG-[CXA]-[0-9A-F]{8}$/.test(x));
    if (many.length > 1) {                     // several codes (a review's views): their devices together, on the platform given
      state.plat = qs.get("plat") === "services" ? "services" : "comms";
      for (const b of document.querySelectorAll("[data-plat]")) b.setAttribute("aria-pressed", String(b.dataset.plat === state.plat));
      state.filters[state.plat] = { code: many.join(",") };
      if (qs.get("embed") !== "1") toast(`Showing ${many.length} combinations together`);
    } else if (/^LG-[CXA]-[0-9A-F]{8}$/.test(code)) {
      try {
        const r = await fetch(`/api/combo-codes/${code}`, { cache: "no-store" });
        const x = await r.json();
        if (r.ok) {
          state.plat = x.section === "issues" || x.section === "services" ? "services" : "comms";
          if (x.kind === "a" && x.day) state.day = x.day;      // an analyst's selection is of one day: open that day
          for (const b of document.querySelectorAll("[data-plat]")) b.setAttribute("aria-pressed", String(b.dataset.plat === state.plat));
          state.filters[state.plat] = { code };
          toast(`Showing combination ${code}: ${x.text}`);
        } else toast(x.error || `Unknown combination code ${code}`, "bad");
      } catch { /* the portal still opens unfiltered */ }
    }
    load(true);
  })();
})();
