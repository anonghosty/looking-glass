/* Looking Glass · the analyst's combination search (/combinations, combos.py).
   Paste a researcher's combination code, see what it stands for (with the researchers' notes), search the days in memory
   or a date range of the stored history, follow the progress, download the PDF + CSV. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const MAX = +document.body.dataset.maxDays || 31;
  const CODE_RX = /^LG-[CXA]-[0-9A-F]{8}$/;
  let entry = null, job = null, timer = null, autoDownload = false, lookSeq = 0, drawSeq = 0;

  function say(node, text, kind) { node.textContent = text; node.className = `cb-msg ${kind || ""}`; }
  const iso = (d) => d.toISOString().slice(0, 10);

  async function look(code) {
    // a new code: a search still running for the previous one is left behind (its results would be drawn under this
    // code), and only the latest look-up's answer is shown (review 2026-11-13)
    const seq = ++lookSeq;
    clearTimeout(timer); job = null; done();
    code = code.trim().toUpperCase(); $("cbCode").value = code;
    $("cbEntry").hidden = true; $("cbStep2Box").hidden = true; $("cbStep3Box").hidden = true; entry = null;
    if (!CODE_RX.test(code)) { say($("cbCodeMsg"), "A code looks like LG-C-1A2B3C4D (one report), LG-X-1A2B3C4D (across reports) or LG-A-1A2B3C4D (an analyst's selection).", "bad"); return; }
    say($("cbCodeMsg"), `Looking up ${code}…`); $("cbCodeMsg").classList.add("lg-loading");     // the searching logo meanwhile
    let r, d;
    try {
      r = await fetch(`/api/combo-codes/${code}`, { cache: "no-store" });
      d = await r.json().catch(() => ({}));
    } catch {
      if (seq !== lookSeq) return;
      $("cbCodeMsg").classList.remove("lg-loading"); $("cbCodeMsg").querySelector(".lg-logo-wrap")?.remove();
      say($("cbCodeMsg"), "The connection was interrupted. Try again.", "bad"); return;
    }
    if (seq !== lookSeq) return;                  // another code was looked up meanwhile
    $("cbCodeMsg").classList.remove("lg-loading"); $("cbCodeMsg").querySelector(".lg-logo-wrap")?.remove();
    if (!r.ok) { say($("cbCodeMsg"), d.error || `Not found (HTTP ${r.status})`, "bad"); return; }
    say($("cbCodeMsg"), ""); entry = d;
    try { history.replaceState(null, "", `?code=${code}`); } catch { /* */ }
    drawEntry(d);
    $("cbStep2Box").hidden = false;
    // an analyst code is its selection on its own day: no choice of days
    const isA = d.kind === "a";
    document.querySelector('input[name="cbWhere"][value="history"]').closest(".cb-opt").hidden = isA;
    if (isA) { document.querySelector('input[name="cbWhere"][value="memory"]').checked = true; $("cbDates").hidden = true; }
    document.querySelector('input[name="cbWhere"][value="memory"]').nextElementSibling.querySelector("b").textContent = isA ? `The selection on ${d.day}` : "The days in memory";
    $("cbMemDays").textContent = isA ? "exactly the records the analysis window showed, read again from that day"
      : d.memory_days?.length ? `${d.memory_days.join(", ")}: exactly the counts the researcher saw` : "no day in memory yet";
  }

  function chips(items) {
    const s = el("div", "cb-set");
    if (!items.length) s.append(el("span", "cb-none", "the name only (no other indicator)"));
    items.forEach((x, i) => { if (i) s.append(el("span", "cb-plus", "+")); s.append(el("span", "cb-chip", x)); });
    return s;
  }
  function drawEntry(d) {
    const box = $("cbEntry"); box.replaceChildren(); box.hidden = false;
    if (d.kind === "a") {                         // an analyst's selection
      const h = el("div", "cb-entry-h");
      h.append(el("code", "cb-code", d.code), el("span", "cb-kind a", "Analyst selection"),
        el("span", "cb-sec", `${d.platform === "services" ? "Publicly accessible services" : "Network communications"} · ${d.day}`));
      box.append(h, el("div", "cb-name cb-name-a", d.label || "Whole day"));
      const facts = [];
      if (d.records != null) facts.push(`${fmt(d.records)} records on ${fmt(d.hosts)} host${d.hosts === 1 ? "" : "s"} when it was made`);
      if (d.names?.length) facts.push(`names in it: ${d.names.join(", ")}`);
      if (facts.length) box.append(el("p", "cb-hint", facts.join(" · ")));
      return;
    }
    const h = el("div", "cb-entry-h");
    h.append(el("code", "cb-code", d.code), el("span", `cb-kind ${d.kind}`, d.kind === "x" ? "Across reports" : "One report"),
      el("span", "cb-sec", d.section === "issues" ? "Publicly accessible services · issue" : "Network communications · infection / category"));
    box.append(h, el("div", "cb-name", d.name));
    if (d.kind === "r") {
      const p = el("div", "cb-part"); p.append(el("span", "cb-rep", d.report), chips(d.items)); box.append(p);
    } else for (const [rep, items] of d.parts) { const p = el("div", "cb-part"); p.append(el("span", "cb-rep", rep), chips(items)); box.append(p); }
    box.append(el("p", "cb-hint", "Exactly: " + (d.section === "issues" ? "the record carries these associated tags and CVEs and no other."
      : "the record carries these indicators and no other C2 domain, DNS lookup, TLS name, user agent or tag.")
      + (d.kind === "x" ? " Across reports: the device carried, in each of these reports, exactly what is listed." : "")
      + (d.first ? ` First shown to a researcher on ${d.first}.` : "")));
    if (d.notes?.length) {
      const n = el("div", "cb-notes"); n.append(el("h3", null, `Researchers' notes on ${d.name}`));
      for (const x of d.notes.slice(0, 6)) {
        const li = el("div", `cb-note${x.codes?.some((c) => c.code === d.code) ? " this" : ""}`);
        li.append(el("b", null, `${x.role}: ${x.by}${x.date ? ` (${x.date})` : ""}`), el("p", null, x.text));
        if (x.codes?.some((c) => c.code === d.code)) li.append(el("span", "cb-tag", "points at this combination"));
        n.append(li);
      }
      box.append(n);
    }
  }

  // ---------------- where to look
  function where() { return document.querySelector('input[name="cbWhere"]:checked').value; }
  function span() {
    const f = $("cbFrom").value, t = $("cbTo").value;
    if (!f || !t) { $("cbSpan").textContent = ""; return 0; }
    const n = Math.round((new Date(t) - new Date(f)) / 864e5) + 1;
    $("cbSpan").textContent = n < 1 ? "The end is before the start." : n > MAX ? `${n} days: at most ${MAX} at a time.` : `${n} day${n === 1 ? "" : "s"}`;
    $("cbSpan").className = `cb-hint${n < 1 || n > MAX ? " bad" : ""}`; return n;
  }
  for (const r of document.querySelectorAll('input[name="cbWhere"]')) r.addEventListener("change", () => { $("cbDates").hidden = where() !== "history"; });
  const today = new Date(); const from = new Date(today - 13 * 864e5);
  $("cbTo").value = iso(today); $("cbFrom").value = iso(from); $("cbTo").max = iso(today); $("cbFrom").max = iso(today);
  $("cbFrom").addEventListener("change", span); $("cbTo").addEventListener("change", span); span();

  // ---------------- the search
  async function start() {
    if (!entry || $("cbSearch").disabled) return;   // never two searches at once (a double click, a re-run on download)
    const body = { code: entry.code };
    if (where() === "history") {
      const n = span(); if (n < 1 || n > MAX) return;
      body.from = $("cbFrom").value; body.to = $("cbTo").value;
    }
    $("cbSearch").disabled = true; $("cbStop").hidden = false; $("cbStep3Box").hidden = true;
    $("cbProgress").hidden = false; $("cbLog").replaceChildren(); $("cbBar").style.width = "2%";
    let r;
    try {
      r = await fetch("/api/combos/search", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
    } catch { $("cbLog").append(el("li", "bad", "The connection was interrupted. Try again.")); failed(); return; }
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { $("cbLog").append(el("li", "bad", d.error || `Refused (HTTP ${r.status})`)); failed(); return; }
    job = d.id; poll();
  }
  function done() { $("cbSearch").disabled = false; $("cbStop").hidden = true; clearTimeout(timer); }
  // a re-run for an expired download that does not finish leaves no download waiting: a later search would otherwise
  // download a ZIP on its own (external review, 2026-11-12)
  function failed() { autoDownload = false; $("cbDownload").textContent = "Download PDF + CSV (ZIP)"; done(); }
  async function poll() {
    const mine = job;                             // a poll for a search that was left behind stops here
    let r, d;
    try {
      r = await fetch(`/api/combos/search/${mine}`, { cache: "no-store" });
      d = await r.json().catch(() => ({}));
    } catch {
      if (mine !== job) return;
      $("cbLog").append(el("li", "bad", "The connection was interrupted. Search again.")); failed(); return;
    }
    if (mine !== job) return;
    if (!r.ok) { $("cbLog").append(el("li", "bad", d.error || "The search was lost.")); failed(); return; }
    $("cbBar").style.width = `${Math.max(2, Math.round((d.done / Math.max(1, d.total)) * 100))}%`;
    const log = $("cbLog"); log.replaceChildren(); for (const l of d.log.slice(-12)) log.append(el("li", null, l));
    if (d.state === "running") { timer = setTimeout(poll, 700); return; }
    done();
    if (d.state === "failed") { log.append(el("li", "bad", d.error)); failed(); return; }
    show(d);
  }
  // ---------------- the filter at the top: the whole search, or one network (organisation) of it; the figures, map,
  // devices and Across reports below follow it (the request to management and the analysis stay on the whole search)
  let full = null;
  function filterBar(s) {
    let bar = $("cbFilter");
    if (!bar) { bar = el("div", "cb-filter"); bar.id = "cbFilter"; $("cbTiles").before(bar); }
    bar.replaceChildren();
    const sel = el("select", "cb-filter-sel"); sel.setAttribute("aria-label", "Show the devices of");
    sel.append(new Option(`All networks · ${fmt(s.devices)} device${s.devices === 1 ? "" : "s"} on ${fmt((s.networks_all || []).length)} network${(s.networks_all || []).length === 1 ? "" : "s"}`, ""));
    for (const n of s.networks_all || []) sel.append(new Option(`${n.label || "Unknown"}${n.asn ? ` (AS${n.asn})` : ""} · ${fmt(n.devices)} device${n.devices === 1 ? "" : "s"}, ${fmt(n.records)} records`, n.label || "Unknown"));
    const note = el("span", "cb-filter-note", "The whole search.");
    bar.append(el("b", null, "Showing"), sel, note);
    sel.addEventListener("change", async () => {
      const n = sel.value;
      const ns = $("cbNet"); if (ns && [...ns.options].some((o) => o.value === n)) { ns.value = n; ns.onchange && ns.onchange(); }
      if (!n) { figures(full); note.textContent = "The whole search."; bar.classList.remove("on"); return; }
      note.textContent = `Reading ${n}'s devices…`; note.classList.add("lg-loading"); sel.disabled = true;
      try {
        const r = await fetch(`/api/combos/search/${job}/summary?network=${encodeURIComponent(n)}`, { cache: "no-store" });
        const x = await r.json().catch(() => ({}));
        if (!r.ok) { note.textContent = x.error || `Could not filter (HTTP ${r.status})`; return; }
        const xs = x.summary || {};
        figures(xs); bar.classList.add("on");
        note.textContent = `${fmt(xs.devices)} of ${fmt(full.devices)} devices, ${fmt(xs.records)} of ${fmt(full.records)} records: everything below is ${n} only.`;
      } catch { note.textContent = "The connection was interrupted. Pick the network again.";
      } finally { sel.disabled = false; note.classList.remove("lg-loading"); note.querySelector(".lg-logo-wrap")?.remove(); }
    });
  }
  function show(d) {
    const s = d.summary || {};
    full = s;
    $("cbStep3Box").hidden = false;
    filterBar(s);
    figures(s);
    const days = $("cbDays");
    let host = $("cbEnrichHost");
    if (!host) { host = el("div"); host.id = "cbEnrichHost"; days.after(host); }
    host.replaceChildren();
    // the analysis across every category, added to this report, and the request to management (combos-enrich.js)
    if (s.devices && window.LGEnrich) host.append(window.LGEnrich.box(job, s, entry));
    afterShow(s);
  }
  function figures(s) {
    const tiles = $("cbTiles"); tiles.replaceChildren();
    const known = (s.regions || []).filter((r) => r.value !== "Unknown region");
    for (const [v, l, sub] of [[s.devices, "devices", "carry exactly this"], [s.records, "records", s.devices ? `${(s.records / s.devices).toFixed(1)} per device` : ""],
      [s.repeat, "repeating it", s.devices ? `${Math.round((100 * s.repeat) / s.devices)}% of the devices` : ""], [s.multi_day, "on several days", ""],
      [(s.across || {}).multi, "also in other reports", "see Across reports"], [s.networks, "networks", ""], [known.length, "regions", `${fmt(s.cities)} cities`],
      [s.peak_hour == null ? "–" : `${String(s.peak_hour).padStart(2, "0")}:00`, "peak hour (UTC)", ""]]) {
      const t = el("div", "cb-tile"); t.append(el("b", null, typeof v === "number" ? fmt(v) : v ?? "–"), el("span", null, l));
      if (sub) t.append(el("small", null, sub)); tiles.append(t);
    }
    drawGeo(s);
    drawGrid(s);
    const days = $("cbDays"); days.replaceChildren();
    const per = s.per_day || [], max = Math.max(1, ...per.map(([, n]) => n));
    if (per.length > 1) {
      const ch = el("div", "cb-chart"); ch.setAttribute("aria-label", "Records per day");
      for (const [day, n] of per) { const c = el("div", "cb-col"); c.title = `${day}: ${fmt(n)} records`; const b = el("i"); b.style.height = `${Math.max(n ? 4 : 1, (n / max) * 100)}%`; c.append(b, el("small", null, day.slice(5))); ch.append(c); }
      days.append(el("h3", null, "Records per day"), ch);
    }
    // across reports: what the devices found carried in the name's other reports, each pattern with its own code
    const x = s.across || {};
    if (x.patterns?.length) {
      days.append(el("h3", null, `Across reports: ${fmt(x.multi)} of these devices ${x.multi === 1 ? "was" : "were"} also seen in other reports`));
      const ul = el("ul", "cb-x");
      for (const p of x.patterns) {
        const li = el("li"); const parts = el("div", "cb-x-parts");
        for (const part of p.parts) { const b = el("div", "cb-part"); b.append(el("span", "cb-rep", part.report), chips(part.items)); parts.append(b); }
        const side = el("div", "cb-x-side"); side.append(el("b", null, fmt(p.devices)), el("span", null, p.devices === 1 ? "device" : "devices"));
        const a = el("a", "cb-x-code", p.code); a.href = `/combinations?code=${p.code}`; a.title = "Search exactly this cross-report pattern";
        side.append(a); li.append(parts, side); ul.append(li);
      }
      days.append(ul);
      if (x.patterns_total > x.patterns.length) days.append(el("p", "cb-hint", `The ${x.patterns.length} most frequent of ${fmt(x.patterns_total)} patterns; the devices CSV gives each device's pattern code.`));
    } else if (s.devices && entry?.kind === "r") days.append(el("p", "cb-hint", "Across reports: none of these devices was seen in another report of this name in this period."));
    if (!s.devices) days.append(el("p", "cb-hint", "No device carried exactly this combination in this period. Try the stored history over a longer range."));
  }
  function afterShow(s) {
    // the report for one network provider (to attach to the advisory sent to that operator), or for all of them
    const ns = $("cbNet"), keep = ns.value;
    ns.replaceChildren(new Option("All networks", ""));
    for (const n of s.networks_all || []) ns.append(new Option(`${n.label}${n.asn ? ` (AS${n.asn})` : ""} · ${fmt(n.devices)} device${n.devices === 1 ? "" : "s"}`, n.label));
    ns.value = [...ns.options].some((o) => o.value === keep) ? keep : "";
    const setHref = () => {
      $("cbDownload").href = `/api/combos/search/${job}/download${ns.value ? `?network=${encodeURIComponent(ns.value)}` : ""}`;
      $("cbDownload").textContent = ns.value ? `Download the report for ${ns.value} (PDF + CSV)` : "Download PDF + CSV (ZIP)";
    };
    ns.onchange = setHref; setHref();
    $("cbDownload").hidden = !s.devices && !s.records;
    if (autoDownload) { autoDownload = false; $("cbDownload").click(); return; }
    $("cbStep3Box").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  // ---------------- where: the country's regions coloured by devices; hover a region for its devices, cities, networks and
  // the addresses (this page is for analysts); beside it, each region with its cities
  const SVG = "http://www.w3.org/2000/svg";
  const sv = (t, a) => { const n = document.createElementNS(SVG, t); for (const [k, v] of Object.entries(a || {})) n.setAttribute(k, v); return n; };
  let shapesP = null, shapesFor = null;
  async function drawGeo(s) {
    const box = $("cbGeo"), svg = $("cbMap"), tip = $("cbTip"), tree = $("cbTree");
    const rows = (s.regions || []).filter((r) => r.value !== "Unknown region");
    box.hidden = !s.devices; if (!s.devices) return;
    const det = s.region_details || {};
    // the list beside the map
    tree.replaceChildren(el("h3", null, "Devices per region"));
    const mx = Math.max(1, ...(s.regions || []).map((r) => r.devices));
    for (const r of s.regions || []) {
      const g = el("div", "cb-tree-reg"); const head = el("div", "cb-tree-row"); const tr = el("span", "t"), f = el("i"); tr.append(f);
      f.style.width = `${(100 * r.devices) / mx}%`; head.append(el("b", "l", r.label), tr, el("b", "v", fmt(r.devices))); g.append(head);
      for (const [n, c] of ((det[r.value] || {}).cities || []).slice(0, 4)) { const li = el("div", "cb-tree-city"); li.append(el("span", null, n), el("small", null, `${fmt(c)} device${c === 1 ? "" : "s"}`)); g.append(li); }
      tree.append(g);
    }
    // the map (only the latest draw: one that waited for the shapes while a network was picked stops, or both would
    // add their regions, review 2026-11-13)
    const seq = ++drawSeq;
    svg.replaceChildren();
    const country = s.country;
    if (!country || !window.LGRegions) { box.classList.add("nomap"); return; }
    if (shapesFor !== country) { shapesFor = country; shapesP = fetch(`/static/data/adm1/${country}.json`).then((r) => (r.ok ? r.json() : null)).catch(() => null); }
    const shapes = await shapesP;
    if (seq !== drawSeq) return;
    if (!shapes) { box.classList.add("nomap"); return; }
    box.classList.remove("nomap");
    const resolve = window.LGRegions.index(shapes), byKey = new Map();
    for (const r of rows) { const k = resolve(r.value); if (k) byKey.set(k, r); }
    const max = Math.max(1, ...[...byKey.values()].map((r) => r.devices));
    const [x0, y0, x1, y1] = shapes.bbox, W = 520, H = 440;
    const kx = Math.cos((((y0 + y1) / 2) * Math.PI) / 180), sc = Math.min((W - 20) / ((x1 - x0) * kx), (H - 20) / (y1 - y0));
    const ox = (W - (x1 - x0) * kx * sc) / 2, oy = (H - (y1 - y0) * sc) / 2, P = (lo, la) => [ox + (lo - x0) * kx * sc, oy + (y1 - la) * sc];
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    const wrap = svg.parentElement, labels = [];
    const showTip = (ev, reg, r) => {
      const d = r ? det[r.value] || {} : null;
      tip.replaceChildren(el("b", null, window.LGRegions.shortName(reg.name)));
      if (!r) tip.append(el("p", "muted", "No device with this combination here."));
      else {
        tip.append(el("p", "big", `${fmt(d.devices)} device${d.devices === 1 ? "" : "s"} · ${fmt(d.records)} records · ${Math.round(r.share * 1000) / 10}%`));
        const list = (label, items, mono) => { if (!items?.length) return; tip.append(el("h5", null, label)); const ul = el("ul"); for (const [n, c] of items) { const li = el("li"); li.append(el(mono ? "code" : "span", null, n), el("b", null, fmt(c))); ul.append(li); } tip.append(ul); };
        list("Cities", d.cities); list("Networks", d.networks);
        list(`IP addresses${d.devices > (d.ips || []).length ? ` (the first ${d.ips.length} of ${fmt(d.devices)})` : ""}`, d.ips, true);
      }
      tip.hidden = false;
      const b = wrap.getBoundingClientRect(), tw = tip.offsetWidth, th = tip.offsetHeight;
      let x = ev.clientX - b.left + 16, y = ev.clientY - b.top + 12;
      if (x + tw > b.width) x = ev.clientX - b.left - tw - 16;
      if (y + th > b.height) y = Math.max(0, b.height - th);
      tip.style.left = `${Math.max(0, x)}px`; tip.style.top = `${y}px`;
    };
    svg.onmouseleave = () => { tip.hidden = true; };
    for (const [k, reg] of Object.entries(shapes.regions)) {
      let dd = "";
      for (const poly of reg.polys) for (const ring of poly) dd += ring.map(([a, b], i) => { const [x, y] = P(a, b); return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`; }).join("") + "Z";
      const r = byKey.get(k), v = r ? r.devices : 0, t = v / max;
      const p = sv("path", { d: dd, class: `rg${r ? "" : " none"}` });
      if (r) p.style.fill = `rgba(${Math.round(91 + 148 * t)}, ${Math.round(141 - 70 * t)}, ${Math.round(239 - 162 * t)}, ${0.28 + 0.65 * t})`;
      p.addEventListener("mousemove", (ev) => showTip(ev, reg, r)); p.addEventListener("mouseleave", () => { tip.hidden = true; });
      p.setAttribute("aria-label", `${window.LGRegions.shortName(reg.name)}: ${r ? `${fmt(v)} devices` : "none"}`);
      svg.append(p);
      const bb = p.getBBox(), lab = reg.label ? P(reg.label[0], reg.label[1]) : [bb.x + bb.width / 2, bb.y + bb.height / 2];
      labels.push({ x: lab[0], y: lab[1], lines: [window.LGRegions.shortName(reg.name)], size: Object.keys(shapes.regions).length > 12 ? 9 : 10.5,
        prio: (r ? 1e9 + v : 0) + bb.width * bb.height, n: r ? v : null });
    }
    const placed = window.LGRegions.placeLabels ? window.LGRegions.placeLabels(labels, { x0: 0, x1: W, y0: 0, y1: H }) : labels;
    for (const it of placed) {
      const tx = sv("text", { x: it.x, y: it.y + it.size * 0.35, class: "rl", "text-anchor": "middle" }); tx.style.fontSize = `${it.size}px`; tx.textContent = it.lines[0]; svg.append(tx);
      if (it.n != null) { const c = sv("text", { x: it.x, y: it.y + it.size * 1.5, class: "rn", "text-anchor": "middle" }); c.style.fontSize = `${it.size - 0.5}px`; c.textContent = fmt(it.n); svg.append(c); }
    }
  }

  // ---------------- the key breakdowns: networks, cities, activity by hour, what the devices are, ports, the busiest devices
  function drawGrid(s) {
    const g = $("cbGrid"); g.replaceChildren();
    if (!s.devices) return;
    const card = (title, sub) => { const c = el("article", "cb-mini"); c.append(el("h3", null, title)); if (sub) c.append(el("p", "cb-hint", sub)); g.append(c); return c; };
    const bars = (c, items, val, lab, extra) => {
      const mx = Math.max(1, ...items.map(val));
      for (const it of items) {
        const r = el("div", "cb-bar-r"); const tr = el("span", "t"), f = el("i"); tr.append(f); f.style.width = `${(100 * val(it)) / mx}%`;
        const name = el("span", "n", lab(it)); name.title = lab(it); r.append(name, tr, el("b", null, fmt(val(it))));
        if (extra) r.title = extra(it); c.append(r);
      }
    };
    if (s.top_networks?.length) {
      const c = card("Networks", "devices per network · click one for its own report");
      bars(c, s.top_networks, (x) => x.devices, (x) => x.label, (x) => `AS${x.asn} · ${fmt(x.devices)} devices, ${fmt(x.records)} records · click for this network's report`);
      // a network row chooses the report for that provider (the selector by the download button)
      [...c.querySelectorAll(".cb-bar-r")].forEach((row, i) => {
        const n = s.top_networks[i]; row.classList.add("pick"); row.tabIndex = 0; row.setAttribute("role", "button");
        const go = () => { $("cbNet").value = n.label; $("cbNet").dispatchEvent(new Event("change")); $("cbDownload").scrollIntoView({ behavior: "smooth", block: "center" }); $("cbDownload").classList.add("pulse"); setTimeout(() => $("cbDownload").classList.remove("pulse"), 1400); };
        row.addEventListener("click", go); row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
      });
    }
    if (s.top_cities?.length) bars(card("Cities", "devices per city"), s.top_cities, (x) => x.devices, (x) => `${x.label}${x.region ? ` · ${x.region}` : ""}`);
    if (s.hours?.some((n) => n)) {
      const c = card("Activity by hour (UTC)", s.peak_hour == null ? "" : `busiest at ${String(s.peak_hour).padStart(2, "0")}:00`);
      const ch = el("div", "cb-hours"), mx = Math.max(1, ...s.hours);
      s.hours.forEach((n, h) => { const col = el("div", `cb-hcol${h === s.peak_hour ? " peak" : ""}`); col.title = `${String(h).padStart(2, "0")}:00 · ${fmt(n)} records`;
        const b = el("i"); b.style.height = `${Math.max(n ? 4 : 1, (100 * n) / mx)}%`; col.append(b); if (h % 6 === 0) col.append(el("small", null, String(h).padStart(2, "0"))); ch.append(col); });
      c.append(ch);
    }
    if (s.kinds?.length) bars(card("What the devices are", "as the reports name them, per record"), s.kinds, (x) => x.records, (x) => x.label);
    if (s.ports?.length) bars(card("Ports", "port / protocol, per record"), s.ports, (x) => x.records, (x) => x.label);
    if (s.top_devices?.length) {
      const c = card("The busiest devices", `the ${s.top_devices.length} with the most records; all ${fmt(s.devices)} are in the CSV`); c.classList.add("wide");
      const t = el("table", "cb-table"); const hd = el("tr");
      for (const h of ["IP address", "Network", "Region", "City", "Records", "Days", "Last seen", "Also seen in"]) hd.append(el("th", null, h));
      t.append(hd);
      for (const x of s.top_devices) {
        const tr = el("tr");
        for (const [v, cls] of [[x.ip, "mono"], [x.network], [x.region], [x.city], [fmt(x.records), "num"], [fmt(x.days), "num"], [x.last, "mono"], [x.also.join(", ") || "–"]]) tr.append(el("td", cls || null, v));
        t.append(tr);
      }
      const sc = el("div", "cb-table-wrap"); sc.append(t); c.append(sc);
    }
  }

  // the download goes through the page: the file keeps its name, and an expired search says so instead of a broken file
  $("cbDownload").addEventListener("click", async (e) => {
    e.preventDefault();
    const a = $("cbDownload");
    if (a.dataset.busy) return;                   // a double click: one download (and at most one re-run)
    a.dataset.busy = "1";
    const label = a.textContent; a.textContent = "Preparing the download…";
    try {
      let r = await fetch(a.href, { cache: "no-store" });
      if (r.status === 404 && entry) {
        // the search has expired (kept an hour): run it again with the same settings, then download
        a.textContent = "Running the search again…";
        autoDownload = true; start(); return;
      }
      if (r.status === 409) {                // across-report data: management decides first (combo_review.py)
        const d = await r.json().catch(() => ({}));
        const box = document.querySelector(".ce-review");
        if (box) { box.scrollIntoView({ behavior: "smooth", block: "start" }); box.classList.add("pulse"); setTimeout(() => box.classList.remove("pulse"), 1600); }
        const st = box?.querySelector(".ce-state"); if (st && d.error) { st.className = "ce-state todo"; st.textContent = d.error; } else alert(d.error || "Management decides first.");
        return;
      }
      if (!r.ok) { const d = await r.json().catch(() => ({})); alert(d.error || `Download failed (HTTP ${r.status})`); return; }
      const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "looking-glass_combination.zip";
      const url = URL.createObjectURL(await r.blob());
      const tmp = el("a"); tmp.href = url; tmp.download = name; document.body.append(tmp); tmp.click(); tmp.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
    } catch { alert("Download failed: the connection was interrupted. Try again."); }
    finally { delete a.dataset.busy; if (!autoDownload) a.textContent = label; }
  });
  // ---------------- the analysts' codes: a searchable drop-down list to revisit one and report on it again
  let acodes = [];
  async function loadAcodes() {
    try {
      const r = await fetch("/api/analyst-codes", { cache: "no-store" });
      if (!r.ok) return;
      acodes = (await r.json()).codes || [];
      $("cbAc").hidden = !acodes.length;
    } catch { /* the list is a convenience */ }
    finally { window.LGLoader?.ready(); }
  }
  function acList(show) {
    const ul = $("cbAcList"), q = $("cbAcQ").value.trim().toLowerCase();
    ul.replaceChildren();
    const hits = acodes.filter((x) => !q || [x.code, x.day, x.label, x.platform, ...(x.names || []), x.finding?.title, x.finding?.number, x.finding?.by].join(" ").toLowerCase().includes(q)).slice(0, 40);
    for (const x of hits) {
      const li = el("li", "cb-ac-item"); li.setAttribute("role", "option"); li.tabIndex = -1;
      const top = el("div", "cb-ac-top");
      top.append(el("code", null, x.code), el("b", null, x.finding ? `${x.finding.number} ${x.finding.title}` : "No finding"),
        el("span", `cb-ac-st s-${x.finding?.status || "none"}`, x.finding?.status || ""));
      li.append(top, el("div", "cb-ac-sel", x.label),
        el("div", "cb-ac-meta", `${x.day} · ${x.platform === "services" ? "services" : "network communications"} · ${fmt(x.records)} records on ${fmt(x.hosts)} host${x.hosts === 1 ? "" : "s"}`
          + (x.names?.length ? ` · ${x.names.join(", ")}` : "") + (x.finding?.by ? ` · by ${x.finding.by}` : "")));
      const pick = () => { $("cbAcQ").value = ""; ul.hidden = true; $("cbAcQ").setAttribute("aria-expanded", "false"); look(x.code); };
      li.addEventListener("mousedown", (e) => { e.preventDefault(); pick(); });
      li.addEventListener("keydown", (e) => { if (e.key === "Enter") pick(); });
      ul.append(li);
    }
    if (!hits.length) ul.append(el("li", "cb-ac-none", "No analyst code matches."));
    ul.hidden = !show; $("cbAcQ").setAttribute("aria-expanded", String(!!show));
  }
  $("cbAcQ").addEventListener("focus", () => acList(true));
  $("cbAcQ").addEventListener("input", () => acList(true));
  $("cbAcQ").addEventListener("blur", () => setTimeout(() => { $("cbAcList").hidden = true; $("cbAcQ").setAttribute("aria-expanded", "false"); }, 120));
  $("cbAcQ").addEventListener("keydown", (e) => {
    const items = [...$("cbAcList").querySelectorAll(".cb-ac-item")];
    if (e.key === "ArrowDown" && items.length) { e.preventDefault(); items[0].focus(); }
    if (e.key === "Escape") { $("cbAcList").hidden = true; }
  });
  $("cbAcList").addEventListener("keydown", (e) => {
    const items = [...$("cbAcList").querySelectorAll(".cb-ac-item")], i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown" && i < items.length - 1) { e.preventDefault(); items[i + 1].focus(); }
    if (e.key === "ArrowUp") { e.preventDefault(); (i > 0 ? items[i - 1] : $("cbAcQ")).focus(); }
  });
  loadAcodes();
  $("cbCodeForm").addEventListener("submit", (e) => { e.preventDefault(); look($("cbCode").value); });
  $("cbSearch").addEventListener("click", () => { autoDownload = false; start(); });   // a search the analyst starts never downloads on its own
  $("cbStop").addEventListener("click", async () => {
    const b = $("cbStop");
    if (!job || b.disabled) return;
    b.disabled = true;                            // one stop request; the search's own poll then ends it
    try { await fetch(`/api/combos/search/${job}/stop`, { method: "POST", headers: { "X-CSRF-Token": csrf() } }); }
    catch { $("cbLog").append(el("li", "bad", "The stop request did not reach the server. Try again.")); }
    finally { b.disabled = false; }
  });
  const q = new URLSearchParams(location.search).get("code");
  if (q) look(q);
})();
