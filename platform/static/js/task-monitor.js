/* Looking Glass · Settings → Task monitor (task_monitor.py): the server right now, like a task manager, refreshed every
   five seconds while the tab is open and the page is in view. Two actions: forget the kept answers, and how long heavy
   answers are kept (response_cache.py). Everything is built as text, never as HTML. */
(() => {
  "use strict";
  const pane = document.getElementById("tabMonitor");
  if (!pane) return;
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const dur = (s) => { s = Math.max(0, Math.round(s || 0)); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : m ? `${m} min` : `${s} s`; };
  const gb = (mb) => mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${fmt(mb)} MB`;
  const PERIOD = 5000;
  let timer = null, paused = false, first = true, D = null;

  async function api(url, body) {
    const r = await fetch(url, body === undefined ? { cache: "no-store" } : { method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  }
  const say = (t, bad) => { const m = $("tmMsg"); m.textContent = t || ""; m.classList.toggle("bad", !!bad); };

  // ---------------- drawing
  function tile(label, value, sub, level) {
    const t = el("div", `tm-tile${level ? " tm-" + level : ""}`);
    t.append(el("span", "tm-label", label), el("b", "tm-value", value));
    if (sub) t.append(el("small", "muted", sub));
    return t;
  }
  function card(title, ...kids) { const c = el("section", "tm-card"); c.append(el("h3", null, title), ...kids); return c; }
  function bars(per) {                                   // requests per minute over the last hour, newest on the right
    const max = Math.max(1, ...per), ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 120 32"); svg.setAttribute("class", "tm-bars"); svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", `Requests per minute over the last hour, at most ${max}`);
    per.forEach((v, i) => { const r = document.createElementNS(ns, "rect"); const h = Math.max(v ? 1.5 : 0, 30 * v / max);
      r.setAttribute("x", String(i * 2)); r.setAttribute("y", String(31 - h)); r.setAttribute("width", "1.4"); r.setAttribute("height", String(h)); svg.append(r); });
    return svg;
  }
  function meter(used, total) {
    const m = el("div", "tm-meter"), i = el("i"); const p = total ? Math.min(100, 100 * used / total) : 0;
    i.style.width = `${p}%`; if (p > 85) m.classList.add("tm-high"); m.append(i); return m;
  }

  function draw(d) {
    const s = d.service || {}, rq = d.requests || {}, mg = d.mongodb || {}, mc = d.machine || {}, c = d.cache || {};
    const load1 = (mc.load || [0])[0], cpus = mc.cpus || 1;
    const top = el("div", "tm-tiles");
    top.append(
      tile("Web service", s.memory_mb ? gb(s.memory_mb) : "?", `up ${dur(s.uptime_s)} · ${fmt(s.threads)} threads${s.cpu_percent != null ? ` · CPU ${s.cpu_percent}%` : ""}`),
      tile("Requests", `${fmt(rq.running)} running`, `${fmt(rq.last_minute)} in the last minute · ${fmt(rq.total)} since start`),
      tile("MongoDB", mg.running ? gb(mg.memory_mb) : "not running", mg.running ? `up ${dur(mg.uptime_s)}` : "the reports cannot be read", mg.running ? "" : "bad"),
      tile("Computer", `load ${load1}`, `${cpus} CPUs · ${load1 > cpus ? "busier than its CPUs" : "within its CPUs"}`, load1 > cpus ? "warn" : ""),
      tile("Memory free", mc.memory_available_mb != null ? gb(mc.memory_available_mb) : "?", mc.memory_total_mb ? `of ${gb(mc.memory_total_mb)} · swap ${fmt(mc.swap_used_mb)} MB used` : "",
        mc.memory_total_mb && mc.memory_available_mb < mc.memory_total_mb * 0.1 ? "warn" : ""),
      tile("Disk free", mc.disk_free_gb != null ? `${mc.disk_free_gb} GB` : "?", mc.disk_total_gb ? `of ${mc.disk_total_gb} GB` : "", mc.disk_free_gb != null && mc.disk_free_gb < 5 ? "bad" : ""));
    const mem = el("div", "tm-memrow");
    if (mc.memory_total_mb) { mem.append(el("span", "muted", "Memory in use"), meter(mc.memory_total_mb - mc.memory_available_mb, mc.memory_total_mb)); }

    const reqs = card("Requests per minute, last hour", bars(rq.per_minute || []),
      el("p", "muted tm-note", `${fmt(rq.this_minute)} so far this minute. A request slower than ${d.slow_limit_s} s is recorded below.`));

    const jobs = el("ul", "tm-jobs");
    for (const j of d.jobs || []) {
      const li = el("li", j.running ? "tm-ok" : j.once ? "tm-done" : "tm-bad");
      li.append(el("span", "tm-dot"), el("span", null, j.name), el("small", "muted", j.running ? "running" : j.once ? "finished (runs once at start)" : "not running: restart the service"));
      jobs.append(li);
    }

    const slow = el("div", "table-wrap");
    if ((d.slow || []).length) {
      const t = el("table", "hosts tm-slow"), th = el("tr");
      ["Request", "Times", "Typical", "Slowest", "Most at once", "Roles"].forEach((h) => th.append(el("th", null, h)));
      const thead = el("thead"); thead.append(th); const tb = el("tbody");
      for (const r of d.slow) {
        const tr = el("tr");
        tr.append(el("td", "mono", r.route), el("td", null, fmt(r.count)), el("td", null, `${r.median.toFixed(1)} s`),
          el("td", null, `${r.slowest.toFixed(1)} s`), el("td", null, fmt(r.running_max)), el("td", "muted", (r.roles || []).join(", ") || "–"));
        tb.append(tr);
      }
      t.append(thead, tb); slow.append(t);
    } else slow.append(el("p", "muted", `No request took longer than ${d.slow_limit_s} s in the last day.`));

    const p = d.pipeline || {}, last = p.last;
    const pipe = el("div", "tm-pipe");
    if (!p.found) pipe.append(el("p", "muted", "The report pipeline is not on this computer."));
    else {
      pipe.append(last ? el("p", last.ok ? "tm-okline" : "tm-badline",
        `Last run ${new Date(last.finished * 1000).toISOString().replace("T", " ").slice(0, 16)} UTC: ${last.ok ? "went well" : "had problems"}`
        + ` · ${fmt(last.rows_inserted)} new rows${last.file_errors ? ` · ${last.file_errors} file errors` : ""}${last.email_failed ? " · mailbox not read" : ""}`
        + (last.pruned_files ? ` · ${last.pruned_files} old copies removed (${last.pruned_mb} MB)` : ""))
        : el("p", "muted", "No run recorded yet (written after the next run)."));
      const sch = el("ul", "tm-plain");
      for (const x of p.schedule || []) sch.append(el("li", null, `${x.what}: ${x.when}`));
      if (p.schedule_readable === false) {
        // the service's sandbox blocks crontab: that is not "no schedule"; the last run's time tells whether it runs
        const age = last ? (Date.now() / 1000 - last.finished) / 3600 : null;
        sch.append(el("li", age != null && age > 26 ? "tm-badline" : "muted",
          "The schedule cannot be read from inside the service (its security sandbox). "
          + (age == null ? "No run is recorded yet." : age > 26 ? `The last run was ${Math.round(age)} hours ago: check the schedule on the server (crontab -l).`
            : `The last run was ${age < 1 ? "less than an hour" : Math.round(age) + " hours"} ago, so it is running.`)));
      } else if (!(p.schedule || []).length) sch.append(el("li", "tm-badline", "No schedule found for this account: the reports are not fetched by themselves."));
      pipe.append(el("small", "muted", "Schedule (cron):"), sch);
    }

    const misc = el("div", "tm-misc");
    misc.append(el("p", null, (d.restarts || []).length ? `Started: ${d.restarts.join(" · ")}` : "No start recorded yet."));
    const locks = el("p"); locks.append(document.createTextNode(`Locked sign-ins now: ${fmt(d.locks)} `));
    if (d.locks) { const a = el("a", null, "see and lift them"); a.href = "/admin#locks"; locks.append(a); }
    misc.append(locks);
    const al = el("ul", "tm-plain");
    for (const a of d.alerts || []) al.append(el("li", a.problem ? "tm-badline" : null, a.title));
    misc.append(el("small", "muted", (d.alerts || []).length ? "In the admins' bell:" : "Nothing in the admins' bell."), al);

    const grid = el("div", "tm-grid");
    grid.append(card("Background jobs", jobs), reqs, card("Report pipeline", pipe), card("Starts, locks and alerts", misc));
    $("tmBody").replaceChildren(top, mem, grid, card("Slowest requests, last day", slow));
    drawCache(c);
    $("tmAt").textContent = `Read at ${d.at}${paused ? " · paused" : ""}`;
  }

  // ---------------- kept answers: the time, with what it means, and clearing them
  let cacheDrawn = false;
  function drawCache(c) {
    const box = $("tmCache");
    const stats = `${fmt(c.entries)} answers kept · ${fmt(c.hit)} given from memory · ${fmt(c.stale)} given while one was being computed · ${fmt(c.miss)} computed`;
    if (cacheDrawn) { $("tmCacheStats").textContent = stats; $("tmCacheNow").textContent = now(c); return; }
    cacheDrawn = true;
    const sel = el("select", "lg-enhance"); sel.id = "tmTtl";
    for (const [v, t] of [[0, "Off: always compute"], [30, "30 seconds"], [60, "1 minute"], [180, "3 minutes (default)"], [600, "10 minutes"], [1800, "30 minutes"]]) {
      const o = el("option", null, t); o.value = String(v); if (v === c.ttl_s) o.selected = true; sel.append(o);
    }
    if (![0, 30, 60, 180, 600, 1800].includes(c.ttl_s)) { const o = el("option", null, `${c.ttl_s} seconds`); o.value = String(c.ttl_s); o.selected = true; sel.append(o); }
    const save = el("button", "intro-cta", "Save"); save.type = "button";
    const clear = el("button", "pill-btn", "Clear kept answers now"); clear.type = "button";
    save.addEventListener("click", async () => {
      save.disabled = true;
      try { const r = await api("/api/admin/monitor/cache", { ttl: Number(sel.value) }); say(r.ttl_s ? `Heavy answers are now kept ${r.ttl_s} seconds.` : "The cache is off: every answer is computed."); refresh(); }
      catch (e) { say(e.message, true); } finally { save.disabled = false; }
    });
    clear.addEventListener("click", async () => {
      clear.disabled = true;
      try { const r = await api("/api/admin/monitor/cache", { action: "clear" }); say(`${r.cleared} kept answer(s) forgotten: the next visit computes afresh.`); refresh(); }
      catch (e) { say(e.message, true); } finally { clear.disabled = false; }
    });
    const row = el("div", "st-row st-tools tm-cache-row");
    const lab = el("label", "st-field"); lab.append(el("span", null, "Keep heavy answers for"), sel);
    row.append(lab, save, clear);
    box.replaceChildren(card("Kept answers (speed and freshness)",
      el("p", "st-hint", "The Definitions lists, Intel summary and leads and the ATT&CK panel take seconds to compute with a lot of data. "
        + "Looking Glass keeps each answer for a while and computes it for one person at a time, so nobody waits behind someone else. "
        + "A kept answer is exactly what was computed: it is always correct. Only how recent it is changes: new reports show "
        + "within the time chosen. Anyone's change (a definition, a note, a mapping) shows at once. Shorter is fresher, longer is faster."),
      row, el("p", "muted", now(c)), el("p", "muted", stats)));
    box.querySelectorAll("p.muted")[0].id = "tmCacheNow"; box.querySelectorAll("p.muted")[1].id = "tmCacheStats";
    try { window.LGSelect?.enhance?.(sel); } catch { /* the plain list still works */ }
  }
  const now = (c) => `Now: ${c.ttl_s ? `${c.ttl_s} seconds` : "off"} (${c.ttl_from_settings ? "chosen here" : `from the installation's .env, ${c.ttl_env_s} s`}).`;

  // ---------------- the inner tabs, like Task Manager: Overview (above), Processes, Performance, Users
  let TAB = "overview", PERF_SEL = "cpu";
  const tmTabs = [...pane.querySelectorAll("[data-tm]")];
  function showTm(which) {
    TAB = which;
    for (const b of tmTabs) b.setAttribute("aria-selected", String(b.dataset.tm === which));
    for (const p of pane.querySelectorAll("[data-tm-pane]")) p.hidden = p.dataset.tmPane !== which;
    if (D) drawTab(D);
  }
  for (const b of tmTabs) b.addEventListener("click", () => showTm(b.dataset.tm));
  function drawTab(d) {
    if (TAB === "processes") drawProcesses(d);
    else if (TAB === "performance") drawPerformance(d);
    else if (TAB === "users") drawUsers(d);
  }

  // a sortable table: rows of {key: value}; cols [{key, label, fmt?, cls?}]
  const SORT = {};
  function table(id, rows, cols, defKey, empty) {
    const st = SORT[id] || (SORT[id] = { key: defKey, desc: true });
    const sorted = [...rows].sort((a, b) => { const x = a[st.key], y = b[st.key];
      const c = typeof x === "number" && typeof y === "number" ? x - y : String(x ?? "").localeCompare(String(y ?? "")); return st.desc ? -c : c; });
    const wrap = el("div", "table-wrap"), t = el("table", "hosts tm-tm"), tr = el("tr");
    for (const c of cols) {
      const th = el("th", c.cls || null); const b = el("button", "tm-sort", c.label + (st.key === c.key ? (st.desc ? " ▾" : " ▴") : ""));
      b.type = "button"; b.addEventListener("click", () => { if (st.key === c.key) st.desc = !st.desc; else { st.key = c.key; st.desc = true; } drawTab(D); });
      th.append(b); tr.append(th);
    }
    const thead = el("thead"); thead.append(tr); const tb = el("tbody");
    if (!sorted.length) { const r = el("tr"); const td = el("td", "muted", empty); td.colSpan = cols.length; r.append(td); tb.append(r); }
    for (const row of sorted) {
      const r = el("tr", row._cls || null);
      for (const c of cols) { const v = c.fmt ? c.fmt(row) : row[c.key]; const td = el("td", c.cls || null); if (v instanceof Node) td.append(v); else td.textContent = v ?? "–"; r.append(td); }
      tb.append(r);
    }
    t.append(thead, tb); wrap.append(t); return wrap;
  }

  // ---------------- Processes: what the server is doing now (requests being answered, background jobs)
  function drawProcesses(d) {
    const rows = (d.processes || []).map((p) => ({ name: `${p.method} ${p.route}`, kind: "Request", user: p.user, role: p.role || "–", seconds: p.seconds,
      status: p.seconds > 10 ? "Slow" : "Running", _cls: p.seconds > 10 ? "tm-row-warn" : null }));
    for (const j of d.jobs || []) rows.push({ name: j.name, kind: "Background job", user: "Looking Glass", role: "–", seconds: -1,
      status: j.running ? "Running" : j.once ? "Finished" : "Stopped", _cls: !j.running && !j.once ? "tm-row-bad" : null });
    const s = d.service || {}, rq = d.requests || {};
    const head = el("div", "tm-proc-head");
    head.append(tile("Requests running", fmt(rq.running), `${fmt(rq.last_minute)} in the last minute`),
      tile("Web service", s.memory_mb ? gb(s.memory_mb) : "?", `CPU ${s.cpu_percent ?? "–"}% · ${fmt(s.threads)} threads`),
      tile("Background jobs", `${(d.jobs || []).filter((j) => j.running).length} running`, `${(d.jobs || []).length} in all`));
    $("tmProc").replaceChildren(head, table("proc", rows, [
      { key: "name", label: "Name", cls: "tm-wrap", fmt: (r) => el("span", r.kind === "Request" ? "mono" : null, r.name) }, { key: "kind", label: "Type" }, { key: "user", label: "User" }, { key: "role", label: "Role" },
      { key: "status", label: "Status" }, { key: "seconds", label: "Running for", fmt: (r) => (r.seconds < 0 ? "–" : `${r.seconds.toFixed(1)} s`) }],
      "seconds", "Nothing is running."),
      el("p", "muted tm-note", "Each request the server is answering right now, longest first, with the account it is for. A request over 10 s is marked slow; "
        + "the Users tab shows who used the most server time."));
  }

  // ---------------- Users: who is using the service, and how much of it
  function drawUsers(d) {
    const rows = (d.users || []).map((u) => ({ ...u, last: u.last_ago == null ? "" : `${u.last_route} · ${dur(u.last_ago)} ago`,
      _cls: u.share >= 50 && (d.users || []).length > 1 ? "tm-row-warn" : null }));
    const top = rows[0];
    const lead = el("p", "tm-note");
    lead.textContent = !rows.length ? "Nobody has used the service in the last " + d.users_window_min + " minutes."
      : top && top.share >= 50 && rows.length > 1 ? `${top.user} used ${top.share}% of the server's time in the last ${d.users_window_min} minutes, mostly on ${top.slowest_route || top.last_route}.`
      : `Server time in the last ${d.users_window_min} minutes, heaviest first.`;
    const bar = (r) => { const w = el("span", "tm-share"); const i = el("i"); i.style.width = `${r.share}%`; w.append(i, el("small", null, `${r.share}%`)); return w; };
    $("tmUsers").replaceChildren(lead, table("users", rows, [
      { key: "user", label: "User" }, { key: "role", label: "Role" }, { key: "running", label: "Running now" },
      { key: "requests", label: "Requests" }, { key: "seconds", label: "Server time", fmt: (r) => `${r.seconds} s` },
      { key: "cpu_seconds", label: "CPU time", fmt: (r) => `${r.cpu_seconds} s` }, { key: "share", label: "Share", fmt: bar },
      { key: "slowest", label: "Slowest", fmt: (r) => (r.slowest ? `${r.slowest} s · ${r.slowest_route}` : "–"), cls: "tm-wrap" },
      { key: "last_ago", label: "Last", fmt: (r) => r.last || "–", cls: "tm-wrap" }], "seconds", "Nobody yet."),
      el("p", "muted tm-note", "Server time is how long the server spent answering that person's requests; CPU time is the computing part of it. "
        + "Account names as on the Admin page; no address is shown."));
  }

  // ---------------- Performance: graphs like Task Manager's (the last two minutes, a reading every two seconds)
  const kb = (v) => (v >= 1024 ? `${(v / 1024).toFixed(1)} MB/s` : `${Math.round(v)} KB/s`);
  const PERF = {
    cpu: { name: "CPU", series: [["cpu", "All programs"], ["service_cpu", "Looking Glass"]], max: () => 100, val: (p) => `${p.cpu ?? 0}%`, unit: "%" },
    memory: { name: "Memory", series: [["memory_used_mb", "In use"]], max: (h) => (h.at(-1) || {}).memory_total_mb || 1, val: (p) => `${gb(p.memory_used_mb || 0)}`, unit: "MB" },
    disk: { name: "Disk", series: [["disk_read_kbs", "Read"], ["disk_write_kbs", "Write"]], max: null, val: (p) => kb((p.disk_read_kbs || 0) + (p.disk_write_kbs || 0)), unit: "KB/s" },
    network: { name: "Network", series: [["net_rx_kbs", "Received"], ["net_tx_kbs", "Sent"]], max: null, val: (p) => kb((p.net_rx_kbs || 0) + (p.net_tx_kbs || 0)), unit: "KB/s" },
    service: { name: "Looking Glass", series: [["service_mb", "Memory"]], max: null, val: (p) => gb(p.service_mb || 0), unit: "MB" },
    mongodb: { name: "MongoDB", series: [["mongodb_mb", "Memory"]], max: null, val: (p) => (p.mongodb_mb ? gb(p.mongodb_mb) : "–"), unit: "MB" },
  };
  function chart(hist, def, big) {
    const ns = "http://www.w3.org/2000/svg", W = big ? 600 : 120, H = big ? 220 : 36, n = 60;
    const svg = document.createElementNS(ns, "svg"); svg.setAttribute("viewBox", `0 0 ${W} ${H}`); svg.setAttribute("class", big ? "tm-chart" : "tm-spark");
    svg.setAttribute("preserveAspectRatio", "none"); svg.setAttribute("role", "img");
    const vals = hist.flatMap((p) => def.series.map(([k]) => p[k] || 0));
    const max = (def.max && def.max(hist)) || Math.max(1, ...vals) * 1.15;
    if (big) for (let i = 1; i < 4; i++) { const l = document.createElementNS(ns, "line"); l.setAttribute("x1", "0"); l.setAttribute("x2", String(W));
      l.setAttribute("y1", String(H * i / 4)); l.setAttribute("y2", String(H * i / 4)); l.setAttribute("class", "tm-grid-line"); svg.append(l); }
    def.series.forEach(([k], si) => {
      const pts = hist.map((p, i) => [W - (hist.length - 1 - i) * (W / (n - 1)), H - Math.min(H, (p[k] || 0) / max * H)]);
      if (!pts.length) return;
      const line = pts.map((q) => q.join(",")).join(" ");
      const area = document.createElementNS(ns, "polygon"); area.setAttribute("points", `${pts[0][0]},${H} ${line} ${pts.at(-1)[0]},${H}`);
      area.setAttribute("class", `tm-area s${si}`); svg.append(area);
      const pl = document.createElementNS(ns, "polyline"); pl.setAttribute("points", line); pl.setAttribute("class", `tm-line s${si}`); svg.append(pl);
    });
    svg.setAttribute("aria-label", `${def.name}, the last two minutes`);
    return svg;
  }
  function drawPerformance(d) {
    const hist = d.performance || [], last = hist.at(-1) || {};
    const list = el("div", "tm-perf-list");
    for (const [key, def] of Object.entries(PERF)) {
      const b = el("button", `tm-perf-item${key === PERF_SEL ? " on" : ""}`); b.type = "button";
      const txt = el("span", "tm-perf-txt"); txt.append(el("b", null, def.name), el("small", "muted", hist.length ? def.val(last) : "…"));
      b.append(chart(hist, def, false), txt);
      b.addEventListener("click", () => { PERF_SEL = key; drawPerformance(D); });
      list.append(b);
    }
    const def = PERF[PERF_SEL], mc = d.machine || {}, s = d.service || {}, mg = d.mongodb || {};
    const main = el("div", "tm-perf-main");
    const top = el("div", "tm-perf-top"); top.append(el("h3", null, def.name), el("b", "tm-perf-now", hist.length ? def.val(last) : "Collecting…"));
    const legend = el("div", "tm-legend");
    def.series.forEach(([k, label], si) => { const x = el("span", `tm-key s${si}`); x.append(el("i"), document.createTextNode(` ${label}: ${last[k] ?? "–"}${k.endsWith("kbs") ? " KB/s" : k.endsWith("mb") ? " MB" : "%"}`)); legend.append(x); });
    const facts = el("dl", "tm-facts");
    const add = (k, v) => { const f = el("div", "tm-fact"); f.append(el("dt", null, k), el("dd", null, v)); facts.append(f); };
    if (PERF_SEL === "cpu") { add("Load (1, 5, 15 min)", (mc.load || []).join(" · ")); add("CPUs", fmt(mc.cpus)); add("Looking Glass", `${last.service_cpu ?? "–"}% · ${fmt(s.threads)} threads`); add("Up", dur(s.uptime_s)); }
    if (PERF_SEL === "memory") { add("In use", gb(last.memory_used_mb || 0)); add("Available", gb(mc.memory_available_mb || 0)); add("Total", gb(mc.memory_total_mb || 0)); add("Swap in use", `${fmt(mc.swap_used_mb)} MB`); }
    if (PERF_SEL === "disk") { add("Free", `${mc.disk_free_gb} GB of ${mc.disk_total_gb} GB`); add("Read now", kb(last.disk_read_kbs || 0)); add("Write now", kb(last.disk_write_kbs || 0)); }
    if (PERF_SEL === "network") { add("Received now", kb(last.net_rx_kbs || 0)); add("Sent now", kb(last.net_tx_kbs || 0)); }
    if (PERF_SEL === "service") { add("Memory", gb(s.memory_mb || 0)); add("CPU", `${s.cpu_percent ?? "–"}%`); add("Threads", fmt(s.threads)); add("Up", dur(s.uptime_s)); add("Requests running", fmt((d.requests || {}).running)); }
    if (PERF_SEL === "mongodb") { add("Running", mg.running ? "yes" : "no"); add("Memory", mg.running ? gb(mg.memory_mb) : "–"); add("Up", mg.running ? dur(mg.uptime_s) : "–"); }
    main.append(top, chart(hist, def, true), legend, el("small", "muted", `The last two minutes, a reading every ${d.sample_s} seconds${hist.length < 3 ? " (collecting: readings start when this tab opens)" : ""}.`), facts);
    const wrap = el("div", "tm-perf"); wrap.append(list, main); $("tmPerf").replaceChildren(wrap);
  }

  // ---------------- refreshing while the tab shows (Performance more often, like Task Manager)
  async function refresh() {
    try { D = await api("/api/admin/monitor"); draw(D); drawTab(D); }
    catch (e) { if (first) $("tmBody").replaceChildren(el("p", "fd-empty", e.message)); else say(`Could not read the figures: ${e.message}`, true); }
    finally { if (first) { first = false; window.LGLoader?.ready(); } }
  }
  let tick = 0;                                    // every 2 s on Performance (its graphs), every 5 s elsewhere
  function start() { stop(); refresh(); timer = setInterval(() => { tick += 1;
    if (!paused && !document.hidden && (TAB === "performance" || tick % Math.round(PERIOD / 2000) === 0)) refresh(); }, 2000); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  document.addEventListener("lg:settings-tab", (e) => (e.detail === "monitor" ? start() : stop()));
  $("tmPause").addEventListener("click", () => {
    paused = !paused; $("tmPause").setAttribute("aria-pressed", String(paused)); $("tmPause").textContent = paused ? "Resume" : "Pause";
    if (!paused) refresh(); else if (D) $("tmAt").textContent = `Read at ${D.at} · paused`;
  });
  if (!pane.hidden) start();                      // opened straight on #monitor
})();
