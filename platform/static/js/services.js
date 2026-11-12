/* Looking Glass · Publicly accessible / vulnerable services.
   Same look and the same patterns as the network communications platform (app.js / app.css): top bar figures,
   Filters and Intel panels, a record stream, record details and an analysis dialog whose figures open the lists
   behind them (hosts to follow up, hosts with several issues, hosts in several reports...). Instead of the map the
   stage shows a services constellation (one bubble per service) or a Ghana regions heatmap. */
(() => {
  "use strict";
  // ------------------------------------------------------------------ basics (same helpers as app.js)
  const $ = (id) => document.getElementById(id);
  const mq = (q) => window.matchMedia(q).matches;
  // local times beside UTC (static/js/localtime.js, Settings > Country > Time zone); without it, UTC only
  const LT = () => window.LGTime || { on: () => false, also: () => "", slot: () => "", tag: () => "UTC", place: () => "UTC" };
  const reducedMotion = mq("(prefers-reduced-motion: reduce)");
  // Display quality chosen on any page (Auto / Full / Lite; static/js/display.js): Lite = fewer stars and particles, no glow
  const LITE = window.LGDisplay ? window.LGDisplay.lite
    : /SMART-TV|SmartTV|Tizen|Web0S|webOS|BRAVIA|AFT[A-Z]|CrKey|HbbTV|NetCast/i.test(navigator.userAgent) || (navigator.hardwareConcurrency || 8) <= 2;
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const fmt = (n) => Math.round(n || 0).toLocaleString("en-US");
  const titleCase = (s) => (s || "").toLowerCase().replace(/(^|[\s-])\w/g, (c) => c.toUpperCase());
  const flagUrl = (cc) => (cc && /^[a-z]{2}$/i.test(cc) && cc !== "EU" ? `https://flagcdn.com/w40/${cc.toLowerCase()}.png` : "");
  const flagImg = (cc) => { const i = el("img", "flag"); i.alt = ""; const u = flagUrl(cc); if (u) { i.src = u; i.loading = "lazy"; } else i.style.visibility = "hidden"; return i; };
  const SEV = { critical: "#e5484d", high: "#f76b15", medium: "#ffc53d", low: "#3e8ef7", info: "#8b8d98" };
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const sevColor = (s) => SEV[s] || SEV.info;
  const ACCENT = "#5b8def";
  const FAMC = { "Exposed service": "#5b8def", "Identified device": "#12a594", "Service population": "#8e7cf0", Compromised: "#e5484d", Blocklisted: "#e2a336", Other: "#8b8d98" };
  const famColor = (f) => FAMC[f] || FAMC.Other;
  const PAL = ["#5b8def", "#12a594", "#e2a336", "#8e7cf0", "#d6409f", "#46a758", "#00a2c7", "#c98a5e"];
  const ls = { get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } } };
  const pct = (n, total) => {
    const f = n / Math.max(1, total);
    if (f > 0 && f < 0.001) return "<0.1%";
    if (f > 0.995 && f < 1) return `${(Math.floor(f * 1000) / 10).toFixed(1)}%`;
    return `${(f * 100).toFixed(f < 0.1 ? 1 : 0)}%`;
  };
  const hhmm = (m) => `${String(Math.floor(m / 60) % 25).padStart(2, "0")}:${String(Math.floor(m) % 60).padStart(2, "0")}`;
  // the country comes from Settings (both platforms); Shadowserver writes the country name when only it is known
  const COUNTRY = { code: "GH", name: "Ghana", hasRegions: true, restricted: false, networks: 0, cidrs: 0 };
  const SUFFIXES = [" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT", " WILAYA", " ATOLL"];
  const normRegion = window.LGRegions ? window.LGRegions.norm
    : (n) => { let s = String(n || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toUpperCase().trim(); for (const x of SUFFIXES) if (s.endsWith(x)) s = s.slice(0, -x.length).trim(); return s; };
  const regionUnknown = (r) => !r || normRegion(r) === normRegion(COUNTRY.name);
  const regionLabel = (r) => (regionUnknown(r) ? "Region unknown" : titleCase(r));
  const POLL_MS = 1500, LOOKAHEAD_MS = 6000, MAX_ROWS = 150;

  const qs = new URLSearchParams(location.search);
  const state = {
    demo: qs.has("demo") ? qs.get("demo") === "1" : ls.get("lg.svc.demo", false),
    speed: 1, paused: false, autoPaused: false, pauseReplay: 0, anchorReplay: Date.now() - 86400000, anchorWall: Date.now(),
    dayStart: 0, dayEnd: 0, sched: null, schedState: null, replayDay: null, waiting: false, behind: false,
    filters: { family: new Set(), service: new Set(), severity: new Set(), issue: new Set(), region: "", city: "", asn: "", port: "", vendor: "", device_type: "", ip: "",
      vulnerable: false, multi: false, cross: false },
    cursor: null, pending: [], generation: 0, events: new Map(), recent: [],
    stats: null, facets: null, svcFamily: new Map(), defs: new Map(), glossary: null,
    dataVersion: null, sourcesVersion: null, view: ls.get("lg.svc.view", "sky"), modalEv: null,
  };
  const replayNow = () => {
    if (state.paused) return state.pauseReplay;
    if (state.waiting) return state.anchorReplay;
    let r = state.anchorReplay + (Date.now() - state.anchorWall) * state.speed;
    if (state.dayEnd && r >= state.dayEnd) r = state.speed === 1 ? state.dayEnd - 1 : state.dayStart + ((r - state.dayStart) % 86400000);
    return r;
  };
  const wallFor = (replayMs) => state.anchorWall + (replayMs - state.anchorReplay) / state.speed;
  const atParam = () => new Date(replayNow()).toISOString();

  // ------------------------------------------------------------------ tooltips (same behaviour as app.js)
  const tipEl = $("tip");
  let lastPointer = "mouse";
  document.addEventListener("pointerdown", (e) => { lastPointer = e.pointerType || "mouse"; }, true);
  document.addEventListener("touchstart", () => { lastPointer = "touch"; hideTip(); }, { capture: true, passive: true });
  const isTouchLike = () => lastPointer === "touch" || lastPointer === "pen" || mq("(hover: none)");
  function showTip(evt, nodes) {
    tipEl.replaceChildren(...nodes); tipEl.hidden = false;
    const pad = 14, w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    let x = evt.clientX + pad, y = evt.clientY + pad;
    if (x + w > innerWidth - 8) x = evt.clientX - w - pad;
    if (y + h > innerHeight - 8) y = evt.clientY - h - pad;
    tipEl.style.left = `${Math.max(8, x)}px`; tipEl.style.top = `${Math.max(8, y)}px`;
    clearTimeout(hideTip._t); if (isTouchLike()) hideTip._t = setTimeout(hideTip, 3500);
  }
  function hideTip() { tipEl.hidden = true; clearTimeout(hideTip._t); }
  window.addEventListener("blur", hideTip);
  const tipLine = (b, rest) => { const d = el("div"); if (b) d.append(el("b", null, b)); if (rest) d.append(document.createTextNode(rest)); return d; };
  function attachTip(node, fn) {
    node.addEventListener("mousemove", (e) => { const c = fn(e); if (c) showTip(e, c); else hideTip(); });
    node.addEventListener("mouseleave", hideTip);
  }
  const TERMS = {
    exposures: ["Records yesterday", "Every record of every publicly accessible / vulnerable services report for the replayed day (yesterday). One record = one host and service seen by Shadowserver's scans or feeds. The figure is the whole day; it does not change while the replay runs."],
    replayed: ["Replayed so far", "Records whose time (extracted_date) is at or before the replay position, counted exactly by the server."],
    exposed_host: ["Exposed host", "A distinct IP address in your constituency with at least one internet-reachable service or finding in the reports."],
    vulnerable_host: ["Hosts with issues", "Hosts with a concrete problem: a CVE, POODLE or FREAK, an expired certificate, an exposed admin panel, an implant or a compromise. Follow these up first."],
    issue: ["Issue", "A concrete problem found on a host: a known vulnerability (CVE), weak encryption (POODLE, FREAK), an expired certificate, an exposed admin panel, a device implant or a compromise."],
    severity: ["Severity", "Shadowserver's rating of each record: critical, high, medium, low or info. Each report also has an overall rating on Shadowserver's site."],
    service: ["Service report", "What was found reachable, named after the Shadowserver report: for example HTTP, SSL/TLS, SSH, RDP or MikroTik service (IPv6 reports are marked)."],
    family: ["Report family", "Exposed service (scans), Service population (counts of hosts running a protocol), Identified device (fingerprints), Compromised and Blocklisted."],
    network: ["Network (ASN)", "The company operating the connection (ISP, university, bank, hosting provider), shown by name instead of AS number."],
    region: ["Region", "The region of the country (chosen in Settings) the host is in, from Shadowserver's geolocation. 'Region unknown' means the location is only known at country level."],
    city: ["City", "Where the host is, from Shadowserver's geolocation of its IP address."],
    vendor: ["Vendor", "The device maker identified by the scan (for example Huawei, MikroTik, Cisco), where Shadowserver could fingerprint it."],
    device_type: ["Device type", "What kind of device the scan identified: router, firewall, camera, VPN and so on."],
    port: ["Port", "The network port the service answered on, for example 443 (HTTPS), 22 (SSH) or 3389 (RDP)."],
    product: ["Product", "Software or device model announced by the service (server banner, SSH software, device model)."],
    replay_time: ["Replay time (UTC)", "The time (extracted_date) of the records being played now: normally yesterday. The same replay as the network communications platform."],
    current_time: ["Current time (UTC)", "The real time now, separate from the replay time."],
    activity: ["Activity", "Records in the last 5 replay minutes compared with the day's average per minute."],
    timeline: ["Activity yesterday", "Records per 15 minutes over the whole day. Click a bar to analyse those 15 minutes."],
    stream: ["Record stream", "Records as they replay, newest first. Click one for all its fields, the report's definition and analysis links."],
    constellation: ["Services constellation", "One bubble per service, sized by its records for the day (with the active filters). A dot flies into a bubble each time one of its records replays, coloured by severity. Click a bubble to analyse that service."],
    ghana: ["Regions map", "The regions of the country chosen in Settings (any African country). Each region is coloured by its records for the day (with the active filters). Regions flash when one of their records replays. Hover to see which reports and issues make up a region; click to analyse it."],
    cross: ["Hosts in several reports", "Hosts that appear in more than one Shadowserver report on the same day, for example an exposed admin panel and an outdated SSH server on the same address."],
    multi: ["Hosts with multiple issues", "Hosts carrying more than one issue across all their reports of the day (several CVEs, or a CVE plus an exposed admin panel...). These have the largest attack surface. As a filter it shows these hosts with all their reports."],
    share: ["Share of all records", "This selection's records as a share of all the day's records."],
    cve: ["CVE", "Common Vulnerabilities and Exposures: the public ID of a known security flaw, for example CVE-2023-48795 (Terrapin, in SSH)."],
    scan: ["Scan", "Shadowserver connects to every IPv4 address (and many IPv6 ones) every day and records which services answer. Being in a scan report means the service is reachable from the whole internet."],
    amplification: ["Amplification", "Some UDP services answer a small request with a much larger reply. Attackers spoof the victim's address to turn them into DDoS weapons."],
  };
  function explain(node, key) {
    const t = TERMS[key]; if (!t || !node || node.dataset.tipped) return;
    node.dataset.tipped = "1"; node.classList.add("term");
    attachTip(node, () => [tipLine(t[0]), tipLine(null, t[1]), ...(node.closest(".kpi.click, .i-kpi.click") ? [el("div", "tt-hint", "Click to analyse")] : []), el("div", "tip-more", "Full list: Glossary")]);
  }
  function explainAll(root = document) { for (const n of root.querySelectorAll("[data-term]")) explain(n, n.dataset.term); }
  const defOf = (label) => state.defs.get(label);

  // ------------------------------------------------------------------ data
  async function getJSON(url) {
    if (state.demo) url += (url.includes("?") ? "&" : "?") + "demo=1";
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  }
  const SETS = ["family", "service", "severity", "issue"], SINGLES = ["region", "city", "asn", "port", "vendor", "device_type", "ip"];
  // "Hosts in several reports" (cross): the filters set when it was switched on CHOOSE the hosts (the seed); filters added
  // afterwards narrow the hosts' widened records. The seed travels in the value: cross=seed:<filters>, so the server
  // can tell them apart (e.g. Blocklisted + several reports + Accessible HTTP = the Accessible HTTP records of
  // blocklisted hosts that are in several reports, exactly what the Accessible HTTP bubble counted).
  // The same holds for "Hosts with multiple issues" (multi): both compare the chosen hosts against all their reports
  // of the day and show those hosts with all their reports; the seed travels on whichever of the two is set.
  const WIDEN = ["cross", "multi"];
  const seedable = ([k]) => !WIDEN.includes(k) && k !== "time";
  const encSeed = (pairs) => `seed:${new URLSearchParams(pairs.filter(seedable)).toString()}`;
  const decSeed = (v) => (String(v || "").startsWith("seed:") ? [...new URLSearchParams(String(v).slice(5))] : null);
  const widening = () => WIDEN.some((k) => state.filters[k]);
  /** pairs with a plain cross=1 / multi=1 get their seed: every filter before them */
  function seal(pairs) {
    if (!pairs.some(([k, v]) => WIDEN.includes(k) && !decSeed(v))) return pairs;   // nothing to do: the same array
    return pairs.map(([k, v], i) => (WIDEN.includes(k) && !decSeed(v) ? [k, encSeed(pairs.slice(0, i))] : [k, v]));
  }
  function filterPairs() {
    const p = [];
    for (const k of SETS) for (const v of state.filters[k]) p.push([k, v]);
    for (const k of SINGLES) if (state.filters[k]) p.push([k, state.filters[k]]);
    for (const k of FLAGS) if (state.filters[k] && !WIDEN.includes(k)) p.push([k, "1"]);
    if (!widening()) return p;
    const has = (a, b) => a[0] === b[0] && String(a[1]) === String(b[1]);
    const seed = (state.crossSeed || p.filter(seedable)).filter((s) => p.some((x) => has(x, s)));
    return [...seed, ...WIDEN.filter((k) => state.filters[k]).map((k) => [k, encSeed(seed)]), ...p.filter((x) => !seed.some((s) => has(x, s)))];
  }
  /** the seed of the current view (the filters that chose the hosts) */
  const currentSeed = () => (widening() ? decSeed((filterPairs().find(([k]) => WIDEN.includes(k)) || [])[1]) || [] : []);
  const FLAGS = ["vulnerable", "multi", "cross"];   // card filters: hosts with issues / multiple issues / several reports
  const filterParams = () => new URLSearchParams(filterPairs());
  const NAMES = { family: "Report family", service: "Service report", severity: "Severity", issue: "Issue", region: "Region", city: "City", asn: "Network", port: "Port",
    vendor: "Vendor", device_type: "Device type", ip: "Host", vulnerable: "Hosts with issues", multi: "Hosts with multiple issues", cross: "Hosts in several reports",
    tag: "Tag", product: "Product", sector: "Sector", protocol: "Protocol", time: "Time", version: "Version" };
  const FLAG_TITLE = { vulnerable: "Hosts with issues", multi: "Hosts with multiple issues", cross: "Hosts in several reports" };
  const refLabels = new Map();
  function valueLabel(k, v) {
    if (k === "time") {
      const [a, m] = String(v).split("+").map(Number), a0 = (state.dayStart || 0) + a * 60000;
      return `${hhmm(a)} to ${hhmm(a + m)} UTC${state.dayStart ? LT().slot(a0, a0 + m * 60000) : ""}`;
    }
    if (k === "ip") return refLabels.get(v) || v;
    if (WIDEN.includes(k)) return "yes, with all their reports";
    if (FLAGS.includes(k)) return "yes";
    if (k === "city" || k === "severity") return titleCase(v);
    if (k === "region") return regionLabel(v);
    if (k === "port") return `Port ${v}`;
    return v;
  }

  // ------------------------------------------------------------------ toast
  let toastTimer = null;
  function toast(msg) { const t = $("toast"); t.textContent = msg; t.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, msg.length > 120 ? 12000 : 7000); }

  // ------------------------------------------------------------------ clock + schedule (shared with the map platform)
  const hm = (iso) => (iso ? iso.slice(11, 16) : "");
  async function syncClock() {
    const c = await getJSON("/api/svc/clock");
    const switched = state.schedState !== null && (c.replay_day !== state.replayDay || c.state !== state.schedState);
    state.sched = c; state.replayDay = c.replay_day; state.schedState = c.state;
    state.dayStart = Date.parse(c.day_start); state.dayEnd = Date.parse(c.day_end);
    window.LGTime?.set(c.tz);              // the CSIRT's time zone (Settings > Country): local times beside UTC
    const sth = document.getElementById("streamTimeHead");
    if (sth) sth.textContent = `Replay time (${LT().on() ? LT().tag() : "UTC"})`;
    state.waiting = c.state !== "playing";
    if (switched) {
      setPaused(false); state.behind = false; $("btnCatchUp").hidden = true;
      state.anchorReplay = Date.parse(c.replay_now); state.anchorWall = Date.now();
      resetStream(); refreshAll();
      if (c.state === "playing") toast(`Replay of ${c.replay_day} has started from 00:00.`);
    } else {
      if (state.speed === 1 && !state.paused && !state.behind) { state.anchorReplay = Date.parse(c.replay_now); state.anchorWall = Date.now(); }
      if ((state.dataVersion != null && c.data_version !== state.dataVersion) || (state.sourcesVersion != null && c.sources_version !== state.sourcesVersion)) refreshAll();
    }
    announce(c);
    state.dataVersion = c.data_version; state.sourcesVersion = c.sources_version;
    $("collectionName").textContent = `Shadowserver · ${c.sources} reports`;
    const w = $("waiting"); w.hidden = !state.waiting;
    if (state.waiting) w.textContent = c.state === "waiting"
      ? `Waiting for Shadowserver's reports for ${c.replay_day}. The replay starts from 00:00 once they arrive (checked every 15 seconds).`
      : `Reports for ${c.replay_day} are arriving (${fmt(c.day_total)} records so far). The replay starts at about ${hm(c.settle_until)} UTC${LT().also(c.settle_until, false)}.`;
  }
  const announced = new Set(); let primed = false;
  function announce(c) {
    const fresh = [], types = [];
    for (const r of c.report_changes || []) { const k = `${c.replay_day}|${r.source}|${r.rows}`; if (announced.has(k)) continue; announced.add(k); if (primed) fresh.push(r); }
    for (const s of c.new_sources || []) { const k = `t|${s.name}`; if (announced.has(k)) continue; announced.add(k); if (primed) types.push(s); }
    primed = true;
    let msg = "";
    if (fresh.length) msg += `New report data for ${c.replay_day}: ${fresh.map((r) => `${r.label} (${r.new ? "" : "+"}${fmt(r.added)} records${r.arrived_at ? `, received ${hm(r.arrived_at)} UTC${LT().also(r.arrived_at, false)}` : ""})`).join(", ")}. Totals and analysis now include it. `;
    for (const s of types) {
      const score = s.required_total ? ` (${s.required_ok}/${s.required_total} required fields)` : "";
      msg += s.compatible === false
        ? `Report type ${s.label} was discovered but cannot be processed yet${score}: missing ${s.missing.join(", ")}. It is listed under Filters and on the overview page. `
        : `New report type detected: ${s.label}. Compatibility check passed${score}${(s.warnings || []).length ? `; not in this report: ${s.warnings.join(", ").toLowerCase()}` : ""}. Its records are loaded. `;
    }
    if (!msg) return;
    toast(msg.trim());
    // like the map platform: the notice also stays at the top of the stream until dismissed (or 10 minutes)
    const note = el("div", "stream-notice"); note.setAttribute("role", "status");
    note.append(el("span", null, msg.trim()));
    const x = el("button", null, "×"); x.type = "button"; x.setAttribute("aria-label", "Dismiss"); x.addEventListener("click", () => note.remove());
    note.append(x); $("rows").before(note);
    setTimeout(() => note.remove(), 10 * 60000);
  }

  // ------------------------------------------------------------------ pause / speed / catch up
  function setPaused(on, auto = false) {
    if (on === state.paused) return;
    if (on) { state.pauseReplay = replayNow(); state.paused = true; state.autoPaused = auto; }
    else { state.anchorReplay = state.pauseReplay; state.anchorWall = Date.now(); state.paused = false; state.autoPaused = false; state.behind = true; state.cursor = replayNow(); }
    $("btnPause").textContent = on ? "Resume" : "Pause"; $("btnPause").setAttribute("aria-pressed", String(on));
    $("btnCatchUp").hidden = !(state.behind || on) || state.speed !== 1;
  }
  $("btnPause").addEventListener("click", () => setPaused(!state.paused));
  $("btnCatchUp").addEventListener("click", async () => {
    setPaused(false); state.behind = false; $("btnCatchUp").hidden = true;
    await syncClock().catch(() => {}); if (state.sched) { state.anchorReplay = Date.parse(state.sched.replay_now); state.anchorWall = Date.now(); }
    resetStream(); backfill(); refreshReplayed();
  });
  $("speed").addEventListener("change", () => {
    const r = replayNow(); state.speed = Number($("speed").value); state.anchorReplay = r; state.anchorWall = Date.now();
    state.pending = []; state.cursor = r; state.behind = state.speed !== 1;
    $("btnCatchUp").hidden = true;
    if (state.speed === 1) { state.behind = false; syncClock().catch(() => {}); }
  });
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (!state.sched) return;   // not synced with the server yet: nothing to pause
    if (document.hidden && !state.paused) setPaused(true, true);
    else if (!document.hidden && state.autoPaused) {
      const away = Date.now() - hiddenAt;
      setPaused(false); $("btnCatchUp").hidden = false;
      if (away > 5000) toast(`The replay paused while this tab was in the background (${Math.round(away / 60000) || "<1"} min) and has continued from where it stopped. Press Catch up to jump to the current replay time.`);
    }
    if (document.hidden) hiddenAt = Date.now();
  });

  // ------------------------------------------------------------------ stream (same rows as the communications stream)
  const rowsEl = $("rows"), streamBody = $("streamBody");
  function resetStream() { state.generation++; state.pending = []; rowsEl.replaceChildren(); state.events.clear(); state.cursor = replayNow(); $("streamEmpty").hidden = false; }
  function buildRow(ev, flash) {
    const li = el("li", "row" + (flash && !reducedMotion ? " flash" : "")); li.dataset.id = ev.id; li.tabIndex = -1;
    li.style.setProperty("--sevc", sevColor(ev.severity));
    const t = (ev.extracted_date || "").replace("T", " ");
    const lt = LT().on() ? LT().dateTime(t) : "";          // the CSIRT's time zone when it is not UTC
    const time = el("span", "r-time mono"); time.append(el("span", "r-clock", (lt || t).slice(11, 19)), el("span", "r-date", (lt || t).slice(0, 10)));
    time.title = `Replay time: the record is from ${t.slice(0, 19)} UTC${LT().also(t)} (extracted_date)`;
    const sev = el("span", "r-sev"); const sb = el("span", "sev", ev.severity || "n/a"); sb.style.setProperty("--sevc", sevColor(ev.severity)); sev.append(sb);
    const inf = el("span", "r-inf"); const sw = el("span", "swatch"); sw.style.background = famColor(ev.family);
    const txt = el("span", "r-inf-txt"); const b = el("b", null, ev.service); b.title = defOf(ev.service)?.def || ev.service;
    const srcl = el("span", "r-src-label"); const cd = el("i"); cd.style.background = famColor(ev.family); srcl.append(cd, document.createTextNode(ev.family));
    txt.append(b, srcl); inf.append(sw, txt);
    const host = el("span", "r-ep r-src"); const top = el("span", "top"); top.append(flagImg(ev.geo), el("span", "ip", `${ev.ip}${ev.port ? ":" + ev.port : ""}`));
    const place = [titleCase(ev.city), regionLabel(ev.region)].filter(Boolean).join(", ");
    const pl = el("span", "place", place); pl.title = place; host.append(top, pl); if (ev.network) host.append(el("span", "sub", ev.network));
    const arrow = el("span", "r-arrow", "·");
    const dev = el("span", "r-ep r-dst"); const dt = el("span", "top"); dt.append(el("span", "ip", [ev.vendor, ev.product].filter(Boolean).join(" · ") || ev.device_type || "not identified"));
    const dv = el("span", "place", [ev.device_type, ev.version].filter(Boolean).join(" · ")); dev.append(dt, dv); if (ev.hostname) dev.append(el("span", "sub", ev.hostname));
    const proto = el("span", "r-proto", [ev.protocol, ev.port].filter(Boolean).join("/"));
    const req = el("span", "r-req");
    const iss = el("span", "host" + (ev.issues.length ? " iss" : ""), ev.issues.length ? ev.issues.join(", ") : "no issue"); iss.title = iss.textContent;
    const tg = el("span", "url", ev.tags.join(", ")); tg.title = tg.textContent; req.append(iss, tg);
    li.append(time, sev, inf, host, arrow, dev, proto, req, el("span"));
    li.addEventListener("click", () => openModal(ev));
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); li.click(); }
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); const n = e.key === "ArrowDown" ? li.nextElementSibling : li.previousElementSibling; if (n) n.focus(); }
    });
    return li;
  }
  function addRow(ev, flash) {
    if (state.events.has(ev.id)) return;
    state.events.set(ev.id, ev);
    rowsEl.prepend(buildRow(ev, flash));
    $("streamEmpty").hidden = true;
    while (rowsEl.children.length > MAX_ROWS) { const last = rowsEl.lastChild; state.events.delete(last.dataset.id); last.remove(); }
  }
  streamBody.addEventListener("keydown", (e) => { if (e.target === streamBody && (e.key === "ArrowDown" || e.key === "Enter")) { const f = rowsEl.firstElementChild; if (f) { e.preventDefault(); f.focus(); } } });
  function setStreamCollapsed(on, remember = true) {
    const s = $("stream"); s.classList.toggle("collapsed", on);
    $("btnStreamMin").textContent = on ? "Show list" : "Hide list"; $("btnStreamMin").setAttribute("aria-expanded", String(!on));
    const root = document.documentElement.style;
    if (on) root.setProperty("--stream-h", `${Math.ceil(s.querySelector(".stream-head").getBoundingClientRect().height + 14)}px`);
    else { const saved = ls.get("lg.svc.streamH", null); if (saved && !mq("(max-width: 700px)")) root.setProperty("--stream-h", `${innerHeight <= 820 ? Math.min(saved, innerHeight * 0.4) : saved}px`); else root.removeProperty("--stream-h"); }
    if (remember) ls.set("lg.svc.collapsed", on);
    setTimeout(() => stage.resize(), 60);
  }
  $("btnStreamMin").addEventListener("click", () => setStreamCollapsed(!$("stream").classList.contains("collapsed")));
  (() => {   // drag the top edge of the stream to resize it (as on the map platform)
    let startY = 0, startH = 0;
    const move = (e) => { const h = Math.max(120, Math.min(innerHeight * 0.7, startH + (startY - e.clientY))); document.documentElement.style.setProperty("--stream-h", `${h}px`); stage.resize(); };
    const up = () => { removeEventListener("pointermove", move); removeEventListener("pointerup", up); ls.set("lg.svc.streamH", parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--stream-h"))); };
    $("streamResize").addEventListener("pointerdown", (e) => { startY = e.clientY; startH = $("stream").getBoundingClientRect().height; addEventListener("pointermove", move); addEventListener("pointerup", up); });
  })();
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea")) return;
    if (e.key === "Escape") { closeInsight(); closeModal(); closeGlossary(); setDrawer(false); }
    else if (e.key.toLowerCase() === "l") setStreamCollapsed(!$("stream").classList.contains("collapsed"));
  });

  let polling = false;
  async function poll() {
    if (polling || state.paused || state.waiting) return;
    polling = true;
    const gen = state.generation;
    try {
      const to = replayNow() + LOOKAHEAD_MS * state.speed, from = state.cursor ?? replayNow();
      if (to - from < 500) return;
      const p = filterParams(); p.set("from", new Date(from).toISOString()); p.set("to", new Date(to).toISOString()); p.set("limit", "400");
      const d = await getJSON(`/api/svc/events?${p}`);
      if (gen !== state.generation) return;
      state.cursor = to;
      const weight = d.returned ? d.total / d.returned : 1;
      for (const ev of d.events) state.pending.push({ ev, weight, wall: wallFor(Date.parse(ev.extracted_date)) });
      state.pending.sort((a, b) => a.wall - b.wall);
      $("streamInfo").textContent = d.sampled ? `sampled ${d.returned} of ${d.total}` : "";
    } catch (err) { toast(`Data feed error: ${err.message}. Retrying…`); }
    finally { polling = false; }
  }
  async function backfill() {
    if (state.waiting) return;
    const gen = state.generation, to = replayNow();
    // the latest (matching) records of the day up to the replay time, however long ago: Shadowserver's service reports
    // arrive in bursts, so the last few minutes are often empty and the stream would sit on "Waiting for records"
    // (filtered or not; Block List, for example, only has records at 01:00-03:00)
    const p = filterParams();
    p.set("from", new Date(Math.max(to - 3 * 60000, state.dayStart || 0)).toISOString()); p.set("to", new Date(to).toISOString()); p.set("limit", "60");
    p.set("latest", "1");
    try {
      const d = await getJSON(`/api/svc/events?${p}`);
      if (gen !== state.generation) return;
      for (const ev of d.events) { addRow(ev, false); state.recent.push([Date.parse(ev.extracted_date), 1]); }
      state.cursor = to;
    } catch { state.cursor = to; }
  }
  function release() {
    const now = Date.now(); let n = 0;
    while (state.pending.length && state.pending[0].wall <= now) {
      const { ev, wall, weight } = state.pending.shift();
      state.recent.push([Date.parse(ev.extracted_date), weight]);
      if (now - wall > 4000) continue;
      addRow(ev, true); stage.hit(ev); if (++n > 40) break;
    }
  }

  // ------------------------------------------------------------------ top bar figures
  // Every refresh carries a sequence number; a slower, older reply never overwrites a newer one (filters changed).
  const seq = { stats: 0, replayed: 0, regions: 0 };
  async function refreshReplayed() {
    const my = ++seq.replayed;
    try {
      const p = filterParams(); p.set("at", atParam());
      const r = await getJSON(`/api/svc/replayed?${p}`);
      if (my !== seq.replayed) return;
      $("kReplayed").textContent = fmt(r.replayed);
      $("kReplayed").parentElement.title = `${fmt(r.replayed)} of ${fmt(r.total)} records of ${r.day} replayed so far (${pct(r.replayed, r.total)})`;
      updateStreamEmpty(r, replayNow());
    } catch { /* keep */ }
  }
  // What the empty stream says. The stream only shows what has been replayed so far, while the figures, charts and
  // lists cover the whole day: a filter whose records all come later in the day must say so, and when.
  function waitText(ms) {
    const m = Math.round(ms / 60000);
    if (ms < 60000) return "less than a minute";
    if (m < 60) return `about ${m} minute${m === 1 ? "" : "s"}`;
    const h = Math.floor(m / 60), rest = m % 60;
    return `about ${h} hour${h === 1 ? "" : "s"}${rest ? ` ${rest} minute${rest === 1 ? "" : "s"}` : ""}`;
  }
  function updateStreamEmpty(r, at) {
    const filtered = [...filterParams().keys()].length > 0;
    let msg = "Waiting for records in the replay window…";
    if (filtered && r.total === 0) {
      msg = `No records of ${r.day} match these filters.`;
    } else if (r.replayed === 0 && r.total > 0 && r.next_at) {
      const head = !filtered ? `No record of ${r.day} has been replayed yet: the first`
        : r.total === 1 ? `The only matching record of ${r.day} has not been replayed yet: it`
          : `None of the ${fmt(r.total)} matching records of ${r.day} has been replayed yet: the first`;
      msg = `${head} is at ${r.next_at.slice(11, 19)} UTC${LT().also(r.next_at)} and the replay is at ${new Date(at).toISOString().slice(11, 19)} UTC`
        + (state.paused ? " (paused)." : `, so it appears in ${waitText((Date.parse(r.next_at) - at) / Math.max(1, state.speed))}.`)
        + (!filtered || !r.hosts ? ""
          : r.hosts === 1 ? " Its host (IP address) is already in the charts and statistics: click them to analyse it."
            : ` Their ${fmt(r.hosts)} hosts (IP addresses) are already in the charts and statistics: click them to analyse them.`);
    }
    $("streamEmpty").textContent = msg;
  }
  // Hide whole figures, least important first, until the rest fit the top bar (never cut one off), as on the map.
  // dropped in this order when the top bar is too narrow (a card is hidden whole, never cut off)
  const KPI_DROP = ["kServices", "kReplayed", "kHosts", "kCrit", "kVuln"];
  function fitKpis() {
    const box = $("kpis"); if (!box) return;
    for (const k of box.children) k.classList.remove("kpi-off");
    const fits = () => box.scrollWidth <= box.clientWidth + 1 &&
      [...box.children].every((k) => k.classList.contains("kpi-off") || getComputedStyle(k).display === "none" || k.getBoundingClientRect().right <= box.getBoundingClientRect().right + 1);
    for (const id of KPI_DROP) { if (fits()) break; $(id)?.parentElement.classList.add("kpi-off"); }
  }
  addEventListener("resize", () => { clearTimeout(fitKpis._t); fitKpis._t = setTimeout(fitKpis, 120); });
  // the room for the cards also changes when the clocks, subtitle or constituency label change: refit then too
  if (window.ResizeObserver) {
    const ro = new ResizeObserver(() => { clearTimeout(fitKpis._t); fitKpis._t = setTimeout(fitKpis, 120); });
    for (const s of [".hud-left", ".hud-right"]) { const n = document.querySelector(s); if (n) ro.observe(n); }
  }
  function tickHud() {
    const box = $("kpis");
    if (box && box.scrollWidth > box.clientWidth + 1) fitKpis();
    else if (box && box.querySelector(".kpi-off") && Date.now() - (fitKpis._last || 0) > 2000) { fitKpis._last = Date.now(); fitKpis(); }
    const r = new Date(replayNow()).toISOString(), n = new Date().toISOString();
    // in the CSIRT's time zone when it is not UTC (Settings > Country); the tooltips keep the UTC time
    const loc = LT().on(), zone = loc ? LT().tag() : "UTC";
    $("replayDate").textContent = state.waiting ? (state.replayDay || r.slice(0, 10)) : loc ? LT().dateTime(r) : `${r.slice(0, 10)} ${r.slice(11, 19)}`;
    if (!state.waiting) $("replayDate").title = `${r.slice(0, 10)} ${r.slice(11, 19)} UTC${LT().also(r)}`;
    $("nowClock").textContent = loc ? LT().dateTime(n) : `${n.slice(0, 10)} ${n.slice(11, 19)}`;
    $("nowClock").title = `${n.slice(0, 10)} ${n.slice(11, 19)} UTC${LT().also(n)}`;
    const nl = document.querySelector(".now-clock"); if (nl) nl.textContent = `Current time (${zone})`;
    $("clockDate").textContent = state.schedState === "waiting" ? "Waiting for the reports of" : state.schedState === "settling" ? "Reports arriving · replay starts soon" : state.paused ? `Replay time (${zone}) · paused` : `Replay time (${zone})`;
    const cut = replayNow() - 5 * 60000;
    state.recent = state.recent.filter((x) => x[0] >= cut - 60000);
    const recent = state.recent.filter((x) => x[0] >= cut).reduce((a, x) => a + x[1], 0) / 5;
    const avg = state.stats ? state.stats.total / 1440 : recent;
    const ratio = avg ? recent / avg : 0;
    const lvl = ratio < 0.5 ? 1 : ratio < 0.9 ? 2 : ratio < 1.4 ? 3 : ratio < 2.2 ? 4 : 5;
    [...$("levelBar").children].forEach((i, k) => i.classList.toggle("on", k < lvl));
    $("levelBar").style.setProperty("--lc", ["#30a46c", "#30a46c", "#ffc53d", "#f76b15", "#e5484d"][lvl - 1]);
    $("levelBar").title = `Activity level ${lvl} of 5 (last 5 replay minutes compared with the day's average)`;
  }
  for (const k of document.querySelectorAll(".kpi[data-open]")) {
    const go = () => {
      const base = filterPairs(), what = k.dataset.open;
      if (what === "replayed") return openInsight([...base, ["time", `0+${((replayNow() - state.dayStart) / 60000).toFixed(4)}`]], { drill: "events" });
      if (what === "vulnerable") return openInsight(base, { drill: "vulnerable" });
      if (what === "critical") return openInsight(narrow(base, "severity", "critical"), { drill: "hosts" });
      if (what === "hosts") return openInsight(base, { drill: "hosts" });
      if (what === "services") return openInsight(base, { drill: "services" });
      openInsight(base);
    };
    k.addEventListener("click", go);
    k.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  }

  // ================================================================== charts (the same ones as app.js)
  function donutChart(svg, legend, rows, opts = {}) {
    svg.replaceChildren(); legend.replaceChildren();
    const NS = "http://www.w3.org/2000/svg", cx = 60, cy = 60, R = 54, r0 = 36;
    const sum = rows.reduce((a, r) => a + r.count, 0) || 1, color = opts.color || (() => ACCENT);
    let a0 = -Math.PI / 2;
    const arc = (a1, a2) => { const large = a2 - a1 > Math.PI ? 1 : 0, p = (r, a) => `${cx + r * Math.cos(a)} ${cy + r * Math.sin(a)}`;
      return `M${p(R, a1)} A${R} ${R} 0 ${large} 1 ${p(R, a2)} L${p(r0, a2)} A${r0} ${r0} 0 ${large} 0 ${p(r0, a1)} Z`; };
    for (const r of rows) {
      const frac = r.count / sum, a1 = a0, a2 = a0 + Math.max(frac * Math.PI * 2, 0.02); a0 = a1 + frac * Math.PI * 2;
      const path = document.createElementNS(NS, "path");
      path.setAttribute("d", frac >= 0.9999 ? arc(-Math.PI / 2, Math.PI * 1.5 - 0.0001) : arc(a1, a2));
      path.setAttribute("fill", color(r.value)); path.setAttribute("stroke", "#141417"); path.setAttribute("stroke-width", "1"); svg.append(path);
      const li = el("li"); const sw = el("span", "swatch"); sw.style.background = color(r.value);
      const name = el("span", null, r.label || r.value); name.title = r.label || r.value;
      li.append(sw, name, el("span", "n", pct(r.count, sum))); legend.append(li);
      const on = () => { svg.classList.add("hovering"); path.classList.add("hot"); li.classList.add("hot"); };
      const off = () => { svg.classList.remove("hovering"); path.classList.remove("hot"); li.classList.remove("hot"); hideTip(); };
      const tip = () => [tipLine(r.label || r.value), tipLine(null, `${fmt(r.count)} ${opts.unit || "records"} · ${pct(r.count, sum)}`),
        ...(opts.describe && opts.describe(r.value) ? [tipLine(null, opts.describe(r.value))] : []), ...(opts.onClick ? [tipLine(null, "Click for analysis")] : [])];
      for (const n of [path, li]) {
        n.addEventListener("mouseenter", on); n.addEventListener("mouseleave", off); n.addEventListener("mousemove", (e) => showTip(e, tip()));
        if (opts.onClick) { n.addEventListener("click", () => opts.onClick(r.value)); n.style.cursor = "pointer"; } else n.style.cursor = "default";
      }
    }
    const t = (y, cls, txt) => { const n = document.createElementNS(NS, "text"); n.setAttribute("x", cx); n.setAttribute("y", y); n.setAttribute("text-anchor", "middle"); n.setAttribute("class", cls); n.textContent = txt; return n; };
    svg.append(t(cy + 2, "d-total", fmt(rows.length ? sum : 0)), t(cy + 15, "d-sub", opts.center || "records"));
    if (!rows.length) legend.append(el("li", "muted", "No data yet"));
  }
  function chartClick(canvas, slots, minutes) {
    if (canvas._click) return; canvas._click = true; canvas.style.cursor = "pointer";
    canvas.addEventListener("click", (e) => {
      const rect = canvas.getBoundingClientRect();
      const i = Math.min(slots - 1, Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * slots)));
      if (typeof canvas._pick !== "function") return;
      const d = canvas._data;
      const v = Array.isArray(d) ? d[i] : d && d.byFam ? Object.values(d.byFam).reduce((a, arr) => a + (arr[i] || 0), 0) : 1;
      if (v) canvas._pick(i * minutes, minutes);
    });
  }
  function stackedHours(canvas, byFam, curHour, info, pick) {
    if (!canvas || !canvas.offsetWidth) return;
    canvas._data = { byFam, curHour }; canvas._pick = pick; chartClick(canvas, 24, 60);
    const dpr = devicePixelRatio || 1, w = canvas.offsetWidth, h = canvas.offsetHeight || 80;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const g = canvas.getContext("2d"); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
    const fams = Object.keys(byFam), totals = Array.from({ length: 24 }, (_, i) => fams.reduce((a, k) => a + byFam[k][i], 0));
    const max = Math.max(1, ...totals), bw = w / 24;
    g.strokeStyle = "rgba(255,255,255,0.06)";
    for (const f of [0.5, 1]) { const y = Math.round(h - f * (h - 4)) + 0.5; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke(); }
    for (let i = 0; i < 24; i++) { let y = h; for (const k of fams) { const v = byFam[k][i]; if (!v) continue; const bh = Math.max(1, (v / max) * (h - 4));
      g.fillStyle = famColor(k); g.globalAlpha = curHour == null || i === curHour ? 1 : 0.7; g.fillRect(i * bw + 1, y - bh, bw - 2, bh); y -= bh; } }
    g.globalAlpha = 1;
    if (info) info.textContent = `peak ${fmt(Math.max(...totals))} / hour`;
    if (!canvas._tip) {
      canvas._tip = true;
      attachTip(canvas, (e) => {
        const d = canvas._data; if (!d) return null;
        const rect = canvas.getBoundingClientRect(), i = Math.min(23, Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * 24)));
        const rows = Object.entries(d.byFam).map(([k, v]) => [k, v[i]]).filter(([, v]) => v), tot = rows.reduce((a, [, v]) => a + v, 0);
        const h0 = (state.dayStart || 0) + i * 3600000;
        return [tipLine(`${String(i).padStart(2, "0")}:00 to ${String((i + 1) % 24).padStart(2, "0")}:00 UTC${state.dayStart ? LT().slot(h0, h0 + 3600000) : ""}`), tipLine(null, `${fmt(tot)} records${i === d.curHour ? " · the replay is in this hour" : ""}`),
          ...rows.map(([k, v]) => { const dv = el("div"); const sw = el("span", "swatch"); sw.style.cssText = `background:${famColor(k)};margin-right:6px`; dv.append(sw, document.createTextNode(`${k}: ${fmt(v)} (${pct(v, tot)})`)); return dv; }),
          ...(tot ? [tipLine(null, "Click to analyse this hour")] : [])];
      });
    }
  }
  function barChart(canvas, values, opts = {}) {
    if (!canvas || !canvas.offsetWidth) return 0;
    const dpr = devicePixelRatio || 1, w = canvas.offsetWidth, h = canvas.offsetHeight || 64;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const g = canvas.getContext("2d"); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
    const vals = values.map((v) => v ?? 0), max = Math.max(1, ...vals), n = values.length, gap = n > 48 ? 1 : 2, bw = w / n;
    g.strokeStyle = "rgba(255,255,255,0.06)"; g.lineWidth = 1;
    for (const f of [0.5, 1]) { const y = Math.round(h - f * (h - 4)) + 0.5; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke(); }
    for (let i = 0; i < n; i++) {
      const x = i * bw + gap / 2, bwid = Math.max(1, bw - gap), bh = Math.max(vals[i] ? 1 : 0, (vals[i] / max) * (h - 4));
      g.fillStyle = i === opts.highlight ? "#ededef" : opts.color || ACCENT; g.globalAlpha = i === opts.highlight ? 1 : opts.past != null && i > opts.past ? 0.35 : 0.85;
      g.fillRect(x, h - bh, bwid, bh);
    }
    g.globalAlpha = 1; return max;
  }
  function quarterHours(canvas, buckets, info, color, mark, scope) {
    canvas._data = buckets; canvas._mark = mark; canvas._pick = scope; chartClick(canvas, 96, 15);
    const max = barChart(canvas, buckets, { highlight: mark, color, past: mark });
    if (info && max) info.textContent = `peak ${fmt(max)} per 15 min`;
    if (!canvas._tip) {
      canvas._tip = true;
      attachTip(canvas, (e) => {
        const b = canvas._data; if (!b || !b.length) return null;
        const rect = canvas.getBoundingClientRect(), i = Math.min(95, Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * 96)));
        const v = b[i], peak = Math.max(...b);
        const q0 = (state.dayStart || 0) + i * 900000;
        return [tipLine(`${hhmm(i * 15)} to ${hhmm(i * 15 + 15)} UTC${state.dayStart ? LT().slot(q0, q0 + 900000) : ""}`), tipLine(null, `${fmt(v)} records${v === peak && v ? " · busiest 15 minutes of the day" : ""}${i === canvas._mark ? " · the replay is here" : ""}`),
          ...(v ? [tipLine(null, "Click to analyse these 15 minutes")] : [])];
      });
    }
  }
  function severityMix(bar, leg, rows, opts = {}) {
    bar.replaceChildren(); leg.replaceChildren();
    const sum = rows.reduce((a, r) => a + r.count, 0) || 1;
    for (const r of [...rows].sort((a, b) => SEV_ORDER.indexOf(a.value) - SEV_ORDER.indexOf(b.value))) {
      const seg = el("i"); seg.style.width = `${(r.count / sum) * 100}%`; seg.style.background = sevColor(r.value);
      const tip = () => [tipLine(titleCase(r.value)), tipLine(null, `${fmt(r.count)} records · ${pct(r.count, sum)}`), ...(opts.onClick ? [tipLine(null, "Click to analyse")] : [])];
      attachTip(seg, tip);
      if (opts.onClick) seg.addEventListener("click", () => opts.onClick(r.value)); else seg.style.cursor = "default";
      bar.append(seg);
      const s = el("span"); const d = el("span", "sevdot"); d.style.background = sevColor(r.value);
      s.append(d, document.createTextNode(r.value), el("b", null, pct(r.count, sum))); leg.append(s);
      if (opts.onClick) { s.classList.add("click"); s.style.cursor = "pointer"; attachTip(s, tip); s.addEventListener("click", () => opts.onClick(r.value)); }
    }
    if (!rows.length) leg.append(el("span", null, "No data yet"));
  }
  function topList(id, rows, key, labelFn, colorFn, total) {
    const ol = $(id); if (!ol) return; ol.replaceChildren();
    const max = Math.max(1, ...rows.map((r) => r.count)), sum = total || rows.reduce((a, r) => a + r.count, 0);
    for (const r of rows.slice(0, 6)) {
      const li = el("li"); li.tabIndex = 0; li.setAttribute("role", "button");
      const bar = el("span", "bar"); bar.style.width = `calc(${(r.count / max) * 100}% - 16px)`; if (colorFn) bar.style.setProperty("--bc", colorFn(r.value));
      const lbl = el("span", "lbl"); lbl.append(...labelFn(r));
      li.append(bar, lbl, el("span", "num", fmt(r.count)));
      attachTip(li, () => [tipLine(lbl.textContent), tipLine(null, `${fmt(r.count)} records · ${fmt(r.hosts)} hosts · ${pct(r.count, sum)} of all records`),
        ...(key === "service" && defOf(r.value) ? [tipLine(null, defOf(r.value).def)] : []), tipLine(null, "Click for analysis")]);
      const open = () => openInsight(narrow(filterPairs(), key, r.value));
      li.addEventListener("click", open);
      li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
      ol.append(li);
    }
    if (!rows.length) ol.append(el("li", "muted", "No data yet"));
  }
  const swatchLabel = (color) => (r) => { const sw = el("span", "swatch"); sw.style.background = color; return [sw, el("span", null, r.label || r.value)]; };

  // ------------------------------------------------------------------ Intel
  async function refreshStats() {
    const my = ++seq.stats;
    try {
      const p = filterParams(); p.set("at", atParam()); p.set("n", "80");
      const s = await getJSON(`/api/svc/stats?${p}`);
      if (my !== seq.stats) return;   // the filters changed while this was loading
      state.stats = s;
      window.LGLoader?.ready();   // arriving from another page: the logo hands over once the figures are in
      $("kTotal").textContent = fmt(s.total); $("kHosts").textContent = fmt(s.hosts); $("kVuln").textContent = fmt(s.vulnerable_hosts);
      $("kCrit").textContent = fmt(s.critical); $("kServices").textContent = fmt(s.services);
      renderIntel(s); stage.setData(s); loadRegions();
    } catch (err) { toast(`Could not load figures: ${err.message}`); }
  }
  function renderIntel(s) {
    const b = s.breakdowns, total = Math.max(1, s.total);
    const curQ = state.dayStart ? Math.floor((replayNow() - state.dayStart) / 900000) : null;
    quarterHours($("timeline"), s.quarters, $("tlInfo"), ACCENT, curQ, (st, m) => openInsight(narrow(filterPairs(), "time", `${st}+${m}`)));
    donutChart($("donut"), $("topFamily"), b.family, { color: famColor, unit: "records", onClick: (v) => openInsight(narrow(filterPairs(), "family", v)),
      describe: (v) => (state.glossary?.families.find((f) => f.name === v) || {}).def });
    stackedHours($("hourClass"), s.hours_by_family || {}, curQ != null ? Math.floor(curQ / 4) : null, $("hbcInfo"), (st, m) => openInsight(narrow(filterPairs(), "time", `${st}+${m}`)));
    severityMix($("sevBar"), $("sevLegend"), s.severity || [], { onClick: (v) => openInsight(narrow(filterPairs(), "severity", v)) });
    topList("topIssue", b.issue, "issue", swatchLabel("#f5b54a"), () => "#f5b54a", total);
    topList("topService", b.service, "service", (r) => { const sw = el("span", "swatch"); sw.style.background = famColor(state.svcFamily.get(r.value)); return [sw, el("span", null, r.label)]; }, (v) => famColor(state.svcFamily.get(v)), total);
    topList("topNet", b.network, "asn", swatchLabel("#7c7c85"), null, total);
    topList("topRegion", b.region, "region", (r) => [flagImg(COUNTRY.code), el("span", null, r.label)], null, total);
    topList("topCity", b.city, "city", (r) => [flagImg(COUNTRY.code), el("span", null, r.label)], null, total);
    topList("topVendor", b.vendor, "vendor", swatchLabel("#12a594"), () => "#12a594", total);
    topList("topProduct", b.product, "product", (r) => [el("span", "mono", r.label)], null, total);
    topList("topPort", b.port, "port", (r) => [el("span", "mono", `Port ${r.label}`)], null, total);
  }

  // ================================================================== the stage: constellation or Ghana regions
  const css = (v) => parseFloat(getComputedStyle(document.documentElement).getPropertyValue(v)) || 0;
  function freeArea(top = 64, bottom = 24) {
    const g = css("--gutter") || 12, W = innerWidth, H = innerHeight;
    const a = { x0: css("--left-w") + g * 2, x1: W - css("--right-w") - g * 2, y0: css("--hud-h") + g * 2 + top, y1: H - css("--stream-h") - g * 2 - bottom };
    if (a.x1 - a.x0 < 200) { a.x0 = 10; a.x1 = W - 10; }
    if (a.y1 - a.y0 < 120) { a.y0 = css("--hud-h") + 50; a.y1 = H - 40; }
    return a;
  }
  // Ghana regions heatmap (SVG): coloured by records with the active filters; flashes as records replay
  const ghana = (() => {
    const svg = $("ghana"), NS = "http://www.w3.org/2000/svg";
    let shapes = null, data = null, paths = new Map();
    let bbox = null, loadedFor = null, file = null;
    // report region name -> map region key, through the names, ISO names and aliases in the map file (static/js/regions.js)
    let resolve = (n) => { const k = normRegion(n); return shapes && shapes[k] ? k : null; };
    async function load() {
      if (shapes && loadedFor === COUNTRY.code) return shapes;
      try {
        file = await (await fetch(`/static/data/adm1/${COUNTRY.code}.json`)).json();
        shapes = Object.fromEntries(Object.entries(file.regions).map(([k, v]) => [k, v.polys])); bbox = file.bbox;
        if (window.LGRegions) resolve = window.LGRegions.index(file);
      } catch { shapes = {}; bbox = null; file = null; }
      loadedFor = COUNTRY.code;
      return shapes;
    }
    const nameOf = (key) => (file && file.regions[key] ? (window.LGRegions ? window.LGRegions.shortName(file.regions[key].name) : file.regions[key].name) : titleCase(key));
    // several report names can fall on one map region (e.g. a newer province drawn inside the one it was carved from): add them up
    function mergeRegion(a, b) {
      if (!a) return { ...b, raws: [b.raw] };
      const add = (x, y) => { const m = new Map(x); for (const [k, n] of y) m.set(k, (m.get(k) || 0) + n); return [...m].sort((p, q) => q[1] - p[1]).slice(0, 6); };
      return { ...a, events: a.events + b.events, hosts: a.hosts + b.hosts, vulnerable_hosts: a.vulnerable_hosts + b.vulnerable_hosts, critical: a.critical + b.critical,
        services: add(a.services, b.services), issues: add(a.issues, b.issues), cities: add(a.cities, b.cities), networks: add(a.networks, b.networks),
        raw: a.events >= b.events ? a.raw : b.raw, raws: [...a.raws, b.raw] };
    }
    const RAMP = ["#1d2a4a", "#1f6f8b", "#2bb07f", "#f5b54a", "#e5484d"];   // never passes through grey
    function rampColor(f) {
      const x = Math.max(0, Math.min(1, f)) * (RAMP.length - 1), i = Math.min(RAMP.length - 2, Math.floor(x)), t = x - i;
      const a = parseInt(RAMP[i].slice(1), 16), b = parseInt(RAMP[i + 1].slice(1), 16);
      const c = (s) => Math.round(((a >> s) & 255) * (1 - t) + ((b >> s) & 255) * t);
      return `rgb(${c(16)},${c(8)},${c(0)})`;
    }
    async function draw() {
      await load(); svg.replaceChildren(); paths = new Map();
      if (!shapes || !Object.keys(shapes).length || !bbox) return;
      const { x0, x1, y0, y1 } = freeArea(76, 30);
      // the chosen country's bounding box, equirectangular with a cos(latitude) correction
      const [lon0, lat0, lon1, lat1] = bbox, kx = Math.cos((((lat0 + lat1) / 2) * Math.PI) / 180);
      const s = Math.min((x1 - x0) / ((lon1 - lon0) * kx), (y1 - y0) / (lat1 - lat0));
      const ox = x0 + ((x1 - x0) - (lon1 - lon0) * kx * s) / 2, oy = y0 + ((y1 - y0) - (lat1 - lat0) * s) / 2;
      const P = (lon, lat) => [ox + (lon - lon0) * kx * s, oy + (lat1 - lat) * s];
      // the reports' region names (e.g. GREATER ACCRA, Alger, Al Qāhirah) matched to the map's regions through its aliases;
      // names that are on no region of this map stay in `off` (they still count in the region list and the analysis)
      const regs = {}, off = [], raw = (data && data.regions) || {};
      let unknownRegion = null;
      for (const [k, v] of Object.entries(raw)) {
        if (!k || regionUnknown(k)) { unknownRegion = mergeRegion(unknownRegion, { ...v, raw: k }); continue; }
        const key = resolve(k);
        if (key) regs[key] = mergeRegion(regs[key], { ...v, raw: k }); else off.push(k);
      }
      const max = Math.max(1, ...Object.values(regs).map((v) => v.events));
      const selKey = state.filters.region ? resolve(state.filters.region) : null;
      const labels = [], n = Object.keys(shapes).length, size = n > 30 ? 10.5 : 12;
      for (const [name, polys] of Object.entries(shapes)) {
        let d = "";
        for (const poly of polys) for (const ring of poly) d += ring.map(([lo, la], i) => { const [x, y] = P(lo, la); return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`; }).join("") + "Z";
        const meta = file && file.regions[name];
        // label point well inside the region (computed by manage/region_aliases.py); centre of the bounding box as a fallback
        let lab = meta && meta.label ? P(meta.label[0], meta.label[1]) : null;
        const r = regs[name], v = r ? r.events : 0;
        const path = document.createElementNS(NS, "path"); path.setAttribute("d", d); path.setAttribute("class", "rg" + (selKey === name ? " sel" : ""));
        path.setAttribute("fill", v ? rampColor(Math.log1p(v) / Math.log1p(max)) : "#16181f");
        path.addEventListener("mousemove", (e) => showTip(e, tipFor(name, r)));
        path.addEventListener("mouseleave", hideTip);
        path.addEventListener("click", () => openInsight(narrow(filterPairs(), "region", r ? r.raw : nameOf(name))));
        svg.append(path);
        if (!lab) { const b = path.getBBox(); lab = [b.x + b.width / 2, b.y + b.height / 2]; }
        paths.set(name, { path, lab });
        // regions with records get their labels first; the rest by size of the region on screen
        const bb = path.getBBox();
        labels.push({ key: name, x: lab[0], y: lab[1] + 3, lines: [nameOf(name), v ? fmt(v) : "–"], size, prio: (v ? 1e9 + v : 0) + bb.width * bb.height });
      }
      const L = window.LGRegions ? window.LGRegions.placeLabels(labels, { x0: 0, x1: innerWidth, y0: 0, y1: innerHeight }) : labels;
      for (const it of L) {
        const t = document.createElementNS(NS, "text"); t.setAttribute("x", it.x); t.setAttribute("y", it.y - size * 0.35); t.setAttribute("text-anchor", "middle"); t.style.fontSize = `${size}px`; t.textContent = it.lines[0]; svg.append(t);
        const c = document.createElementNS(NS, "text"); c.setAttribute("x", it.x); c.setAttribute("y", it.y + size * 0.85); c.setAttribute("text-anchor", "middle"); c.setAttribute("class", "n"); c.style.fontSize = `${size - 1}px`; c.textContent = it.lines[1]; svg.append(c);
      }
      // reports that do not fit this country's map: the map stays, with a note to choose the right country
      const known = [...Object.keys(regs), ...off], onMap = Object.keys(regs);
      const note = $("regionNotice");
      note.hidden = !(known.length && !onMap.length);
      if (!note.hidden) note.querySelector("span").textContent =
        `None of the ${known.length} regions in these reports are on ${COUNTRY.name}'s map. Kindly select the right country in Settings to populate the regions.`;
      const notes = [];
      if (unknownRegion) notes.push(`Region unknown: ${fmt(unknownRegion.events)} records`);
      if (off.length && onMap.length) notes.push(`Not on this map: ${off.slice(0, 4).map(titleCase).join(", ")}${off.length > 4 ? ` and ${off.length - 4} more` : ""}`);
      notes.forEach((s, i) => { const t = document.createElementNS(NS, "text"); t.setAttribute("x", x0 + 4); t.setAttribute("y", y1 - (notes.length - 1 - i) * 15); t.setAttribute("class", "n"); t.textContent = s; svg.append(t); });
    }
    function tipFor(name, r) {
      const iso = (file && file.regions[name] && file.regions[name].iso) || [];
      const lines = [tipLine(nameOf(name), iso.length ? ` · ${iso.join(", ")}` : "")];
      if (r && r.raws && r.raws.length > 1) lines.push(tipLine("In the reports as: ", r.raws.map(titleCase).join(", ")));
      if (!r) return [...lines, tipLine(null, "No records with the active filters.")];
      lines.push(tipLine(null, `${fmt(r.events)} records · ${fmt(r.hosts)} hosts · ${fmt(r.vulnerable_hosts)} with issues · ${fmt(r.critical)} critical`));
      if (r.services.length) lines.push(tipLine("Reports: ", r.services.map(([k, n]) => `${k} ${fmt(n)}`).join(", ")));
      if (r.issues.length) lines.push(tipLine("Issues: ", r.issues.map(([k, n]) => `${k} ${fmt(n)}`).join(", ")));
      if (r.cities.length) lines.push(tipLine("Cities: ", r.cities.map(([k, n]) => `${k} ${fmt(n)}`).join(", ")));
      if (r.networks.length) lines.push(tipLine("Networks: ", r.networks.map(([k, n]) => `${k} ${fmt(n)}`).join(", ")));
      lines.push(el("div", "tt-hint", "Click to analyse this region"));
      return lines;
    }
    function hit(ev) {
      const p = paths.get(resolve(ev.region)); if (!p) return;
      p.path.classList.remove("pulse"); void p.path.getBBox(); p.path.classList.add("pulse");
      if (p.lab && !reducedMotion && svg.childElementCount < 400) {
        const c = document.createElementNS(NS, "circle"); c.setAttribute("cx", p.lab[0] + (Math.random() - 0.5) * 30); c.setAttribute("cy", p.lab[1] + (Math.random() - 0.5) * 30);
        c.setAttribute("r", "3"); c.setAttribute("class", "ping"); c.style.stroke = sevColor(ev.severity); svg.append(c);
        c.animate([{ r: "3px", opacity: 1 }, { r: "22px", opacity: 0 }], { duration: 1100, easing: "ease-out" }).onfinish = () => c.remove();
      }
    }
    function setData(d) { data = d; if (state.view === "ghana") draw(); }
    return { draw, hit, setData };
  })();

  const stage = (() => {
    const cv = $("sky"), ctx = cv.getContext("2d");
    let W = 0, H = 0, dpr = 1, area = { x0: 0, y0: 0, x1: 0, y1: 0 }, bubbles = [], byLabel = new Map(), parts = [], rings = [], stars = [], hover = null;
    function resize() {
      dpr = Math.min(2, devicePixelRatio || 1); W = innerWidth; H = innerHeight;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      area = freeArea();
      stars = Array.from({ length: LITE ? 50 : 160 }, () => ({ x: Math.random() * W, y: Math.random() * H, r: Math.random() * 1.2 + 0.2, a: Math.random() * 0.5 + 0.1, t: Math.random() * 6 }));
      layout(); if (state.view === "ghana") ghana.draw();
    }
    function setData(s) {
      const rows = s.breakdowns.service;
      const keep = new Map(bubbles.map((b) => [b.label, b]));
      bubbles = rows.filter((r) => r.count > 0).map((r) => {
        const o = keep.get(r.value);
        return { label: r.value, count: r.count, hosts: r.hosts, family: state.svcFamily.get(r.value) || (o && o.family) || "Other",
          x: o ? o.x : (area.x0 + area.x1) / 2, y: o ? o.y : (area.y0 + area.y1) / 2, r: o ? o.r : 4, heat: o ? o.heat : 0, tr: o ? o.tr : 12, fresh: !o };
      });
      byLabel = new Map(bubbles.map((b) => [b.label, b]));
      layout(); legend();
    }
    function legend() {
      const lg = $("legend"); lg.replaceChildren();
      if (state.view === "ghana") { lg.append(document.createTextNode("fewer records"), el("span", "ramp"), document.createTextNode("more records · flashes as records replay")); return; }
      for (const f of [...new Set(bubbles.map((b) => b.family))]) { const s = el("span"); const i = el("i"); i.style.background = famColor(f); s.append(i, document.createTextNode(f)); lg.append(s); }
    }
    function layout() {
      if (!bubbles.length || !W) return;
      const aw = area.x1 - area.x0, ah = area.y1 - area.y0, sum = bubbles.reduce((a, b) => a + b.count, 0);
      const k = Math.sqrt((aw * ah * 0.42) / (Math.PI * Math.max(1, sum))), rmax = Math.min(aw, ah) * 0.32;
      for (const b of bubbles) b.tr = Math.max(9, Math.min(rmax, k * Math.sqrt(b.count)));
      bubbles.sort((a, b) => b.count - a.count);
      bubbles.forEach((b, i) => { if (b.fresh) { b.fresh = false; const a = i * 2.4, d = 36 * Math.sqrt(i); b.x = (area.x0 + area.x1) / 2 + Math.cos(a) * d; b.y = (area.y0 + area.y1) / 2 + Math.sin(a) * d; } });
      for (let it = 0; it < 260; it++) relax(1);
    }
    function relax(k) {
      const cx = (area.x0 + area.x1) / 2, cy = (area.y0 + area.y1) / 2;
      for (const b of bubbles) {
        if (!Number.isFinite(b.tr)) b.tr = 12;
        if (!Number.isFinite(b.x) || !Number.isFinite(b.y) || !Number.isFinite(b.r)) { b.x = cx; b.y = cy; b.r = 4; }
        b.r += (b.tr - b.r) * 0.2 * k; b.x += (cx - b.x) * 0.012 * k; b.y += (cy - b.y) * 0.018 * k;
      }
      for (let i = 0; i < bubbles.length; i++) for (let j = i + 1; j < bubbles.length; j++) {
        const a = bubbles[i], b = bubbles[j], dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 0.01, min = a.r + b.r + 6;
        if (d < min) { const push = (min - d) / 2, ux = dx / d, uy = dy / d; a.x -= ux * push; a.y -= uy * push; b.x += ux * push; b.y += uy * push; }
      }
      for (const b of bubbles) { b.x = Math.max(area.x0 + b.r, Math.min(area.x1 - b.r, b.x)); b.y = Math.max(area.y0 + b.r, Math.min(area.y1 - b.r, b.y)); }
    }
    function hit(ev) {
      if (document.hidden) return;
      if (state.view === "ghana") return ghana.hit(ev);
      const b = byLabel.get(ev.service); if (!b) return;
      if (parts.length > (LITE ? 30 : 160)) parts.shift();
      const ang = Math.random() * Math.PI * 2, R = Math.hypot(W, H) * 0.55;
      parts.push({ b, sx: W / 2 + Math.cos(ang) * R, sy: H / 2 + Math.sin(ang) * R, t0: performance.now(), dur: reducedMotion ? 1 : 900 + Math.random() * 500,
        c: sevColor(ev.severity), crit: ev.severity === "critical" || ev.issues.length > 0 });
    }
    const hexA = (hex, a) => { const n = parseInt(hex.slice(1), 16); return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${Math.max(0, Math.min(1, a)).toFixed(3)})`; };
    const fit = (t, w, fs) => { if (t.length * fs * 0.55 <= w) return t; const n = Math.max(3, Math.floor(w / (fs * 0.55)) - 1); return t.slice(0, n) + "…"; };
    function draw(now) {
      if (!W || !H) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H);
      for (const s of stars) { const a = s.a * (0.6 + 0.4 * Math.sin(now / 1400 + s.t)); ctx.fillStyle = `rgba(200,210,255,${a})`; ctx.fillRect(s.x, s.y, s.r, s.r); }
      if (state.view !== "sky") return;
      const cx = (area.x0 + area.x1) / 2, cy = (area.y0 + area.y1) / 2;
      ctx.strokeStyle = "rgba(91,141,239,.06)"; ctx.lineWidth = 1;
      for (let i = 1; i <= 3; i++) { ctx.beginPath(); ctx.arc(cx, cy, Math.min(area.x1 - area.x0, area.y1 - area.y0) * 0.17 * i, 0, Math.PI * 2); ctx.stroke(); }
      if (!LITE) relax(0.15);
      const seedServices = new Set(widening() ? currentSeed().filter(([k]) => k === "service").map(([, v]) => v) : []);
      for (const b of bubbles) {
        const col = famColor(b.family); b.heat *= 0.965; const glow = b.heat;
        if (!LITE) { const g = ctx.createRadialGradient(b.x, b.y, b.r * 0.2, b.x, b.y, b.r * (1.15 + glow * 0.5));
          g.addColorStop(0, hexA(col, 0.32 + glow * 0.3)); g.addColorStop(1, hexA(col, 0)); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(b.x, b.y, b.r * (1.15 + glow * 0.5), 0, Math.PI * 2); ctx.fill(); }
        ctx.fillStyle = hexA(col, 0.14 + glow * 0.2); ctx.strokeStyle = hexA(col, hover === b ? 1 : 0.55 + glow * 0.4); ctx.lineWidth = hover === b ? 2.2 : 1.2;
        ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
        // cross-report view: the report(s) the selection started from are outlined
        if (seedServices.has(b.label)) {
          ctx.save(); ctx.setLineDash([5, 4]); ctx.strokeStyle = "#ffc53d"; ctx.lineWidth = 2;
          ctx.beginPath(); ctx.arc(b.x, b.y, b.r + 6, 0, Math.PI * 2); ctx.stroke(); ctx.restore();
        }
        if (b.r >= 20) {
          ctx.fillStyle = "#ededef"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
          const fs = Math.max(10, Math.min(15, b.r / 3.6)); ctx.font = `600 ${fs}px Inter, system-ui, sans-serif`;
          ctx.fillText(fit(b.label, b.r * 1.8, fs), b.x, b.y - (b.r > 30 ? fs * 0.45 : 0));
          if (b.r > 30) { ctx.fillStyle = "#b4b4bb"; ctx.font = `500 ${fs * 0.8}px "Geist Mono", monospace`; ctx.fillText(fmt(b.count), b.x, b.y + fs * 0.75); }
        }
      }
      const keep = [];
      for (const p of parts) {
        const k = Math.min(1, (now - p.t0) / p.dur), e = 1 - Math.pow(1 - k, 3), x = p.sx + (p.b.x - p.sx) * e, y = p.sy + (p.b.y - p.sy) * e;
        if (k < 1) {
          const k2 = Math.max(0, e - 0.08); ctx.strokeStyle = hexA(p.c, 0.35); ctx.lineWidth = 1; ctx.beginPath();
          ctx.moveTo(p.sx + (p.b.x - p.sx) * k2, p.sy + (p.b.y - p.sy) * k2); ctx.lineTo(x, y); ctx.stroke();
          ctx.fillStyle = p.c; ctx.beginPath(); ctx.arc(x, y, p.crit ? 3 : 2, 0, Math.PI * 2); ctx.fill(); keep.push(p);
        } else { p.b.heat = Math.min(1, p.b.heat + 0.35); rings.push({ b: p.b, t0: now, c: p.c, big: p.crit }); }
      }
      parts = keep; rings = rings.filter((r) => now - r.t0 < 900);
      for (const r of rings) { const k = (now - r.t0) / 900; ctx.strokeStyle = hexA(r.c, (1 - k) * 0.8); ctx.lineWidth = r.big ? 2 : 1.2; ctx.beginPath(); ctx.arc(r.b.x, r.b.y, r.b.r + 3 + k * (r.big ? 26 : 14), 0, Math.PI * 2); ctx.stroke(); }
    }
    function frame(now) { try { draw(now); } catch (err) { if (!frame.w) { frame.w = 1; console.warn("stage frame skipped:", err); } } requestAnimationFrame(frame); }
    function pick(e) { return bubbles.find((b) => Math.hypot(b.x - e.clientX, b.y - e.clientY) <= b.r + 2) || null; }
    cv.addEventListener("mousemove", (e) => {
      if (state.view !== "sky") return;
      hover = pick(e); cv.style.cursor = hover ? "pointer" : "default";
      if (!hover) return hideTip();
      const b = hover, d = defOf(b.label), tot = state.stats ? state.stats.total : 0;
      showTip(e, [tipLine(b.label, ` · ${b.family}`), tipLine(null, `${fmt(b.count)} records · ${fmt(b.hosts)} hosts · ${pct(b.count, tot)}`),
        ...(d ? [tipLine(null, d.def)] : []), ...(d && d.rating ? [tipLine(null, `Shadowserver rating: ${d.rating}`)] : []), el("div", "tt-hint", "Click to analyse")]);
    });
    cv.addEventListener("mouseleave", () => { hover = null; hideTip(); });
    cv.addEventListener("click", (e) => { const b = pick(e); if (b) openInsight(narrow(filterPairs(), "service", b.label)); });
    addEventListener("resize", () => resize());
    requestAnimationFrame(frame);
    return { resize, setData, hit, legend };
  })();
  async function loadRegions() {
    const my = ++seq.regions;
    try { const p = filterParams(); p.set("at", atParam()); const d = await getJSON(`/api/svc/regions?${p}`); if (my === seq.regions) ghana.setData(d); } catch { /* keep */ }
  }
  function setView(v) {
    state.view = v; ls.set("lg.svc.view", v);
    for (const b of $("viewSeg").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.view === v));
    $("ghana").toggleAttribute("hidden", v !== "ghana");   // an <svg> has no .hidden property: use the attribute
    if (v !== "ghana") $("regionNotice").hidden = true;
    $("stageHint").textContent = stageHint();
    if (v === "ghana") ghana.draw();
    stage.legend();
  }
  for (const b of $("viewSeg").querySelectorAll("button")) b.addEventListener("click", () => setView(b.dataset.view));
  explain($("viewSeg").querySelector('[data-view="sky"]'), "constellation");
  explain($("viewSeg").querySelector('[data-view="ghana"]'), "ghana");

  // ------------------------------------------------------------------ filters (drawer)
  async function loadFacets() {
    try {
      const f = await getJSON(`/api/svc/facets?at=${encodeURIComponent(atParam())}`);
      state.facets = f; state.svcFamily = new Map(f.reports.map((r) => [r.label, r.family]));
      if (state.stats) { stage.setData(state.stats); renderIntel(state.stats); }
      buildFilters();
      const ub = $("unsupportedBox"); ub.hidden = !f.unsupported.length;
      if (f.unsupported.length) ub.replaceChildren(el("h3", null, `${f.unsupported.length} report type(s) not processed yet`), el("p", "fg-hint", f.unsupported.map((u) => `${u.label}: missing ${u.missing.join(", ")}`).join(" · ")));
    } catch (err) { toast(`Could not load filters: ${err.message}`); }
  }
  function chips(box, key, rows, color, label = (r) => r.label) {
    box.replaceChildren();
    for (const r of rows) {
      const b = el("button", "chip"); b.type = "button"; b.setAttribute("aria-pressed", String(state.filters[key].has(r.value)));
      const d = el("span", "dot"); d.style.background = color(r.value); b.append(d, document.createTextNode(label(r)), el("span", "chip-n", fmt(r.count)));
      b.addEventListener("click", () => { const s = state.filters[key]; s.has(r.value) ? s.delete(r.value) : s.add(r.value); filtersChanged(); });
      box.append(b);
    }
  }
  function checklist(box, key, rows, q, color) {
    box.replaceChildren();
    for (const r of rows.filter((x) => !q || x.label.toLowerCase().includes(q))) {
      const li = el("li"); const lab = el("label"); const cb = el("input"); cb.type = "checkbox"; cb.checked = state.filters[key].has(r.value);
      const sw = el("span", "swatch"); sw.style.background = color ? color(r.value) : "#7c7c85";
      lab.append(cb, sw, el("span", "nm", r.label), el("span", "n", fmt(r.count))); li.append(lab);
      if (key === "service") attachTip(li, () => { const d = defOf(r.value); return [tipLine(r.label), ...(d ? [tipLine(null, d.def)] : [])]; });
      cb.addEventListener("change", () => { const s = state.filters[key]; cb.checked ? s.add(r.value) : s.delete(r.value); filtersChanged(); });
      box.append(li);
    }
    if (!box.children.length) box.append(el("li", "muted", "No match"));
  }
  function select(sel, key, rows, all, labelFn = (r) => r.label) {
    sel.replaceChildren(); const o0 = el("option", null, all); o0.value = ""; sel.append(o0);
    for (const r of rows) { const o = el("option", null, `${labelFn(r)} (${fmt(r.count)})`); o.value = r.value; sel.append(o); }
    if (state.filters[key] && !rows.some((r) => String(r.value) === String(state.filters[key]))) { const o = el("option", null, valueLabel(key, state.filters[key])); o.value = state.filters[key]; sel.append(o); }
    sel.value = state.filters[key] || "";
  }
  function buildFilters() {
    const f = state.facets; if (!f) return;
    const b = f.facets;
    chips($("fFamily"), "family", b.family, famColor);
    chips($("fSeverity"), "severity", b.severity, sevColor, (r) => titleCase(r.label));
    const svc = f.reports.filter((r) => r.rows).map((r) => ({ value: r.label, label: r.label, count: r.rows }));
    $("srcCount").textContent = `(${svc.length} with data yesterday, of ${f.reports.length})`;
    checklist($("fService"), "service", svc, $("svcSearch").value.trim().toLowerCase(), (v) => famColor(state.svcFamily.get(v)));
    $("issCount").textContent = `(${b.issue.length})`;
    checklist($("fIssue"), "issue", b.issue, $("issSearch").value.trim().toLowerCase(), () => "#f5b54a");
    select($("fRegion"), "region", b.region, "All regions");
    select($("fCity"), "city", b.city, "All cities");
    select($("fAsn"), "asn", b.network, "All networks");
    select($("fPort"), "port", b.port, "All ports");
    select($("fVendor"), "vendor", b.vendor, "All vendors");
    select($("fDevice"), "device_type", b.device_type, "All device types");
    $("fVuln").checked = state.filters.vulnerable; $("fMulti").checked = state.filters.multi; $("fCross").checked = state.filters.cross;
  }
  $("svcSearch").addEventListener("input", buildFilters);
  $("issSearch").addEventListener("input", buildFilters);
  for (const [id, key] of [["fRegion", "region"], ["fCity", "city"], ["fAsn", "asn"], ["fPort", "port"], ["fVendor", "vendor"], ["fDevice", "device_type"]])
    $(id).addEventListener("change", () => { state.filters[key] = $(id).value; filtersChanged(); });
  for (const [id, key] of [["fVuln", "vulnerable"], ["fMulti", "multi"], ["fCross", "cross"]]) $(id).addEventListener("change", () => {
    // switching "several reports" / "multiple issues" on: the filters set now choose the hosts; filters added later
    // narrow their reports (the seed is kept while either of the two stays on)
    if (WIDEN.includes(key)) {
      if ($(id).checked && !widening()) state.crossSeed = filterPairs().filter(seedable);
      state.filters[key] = $(id).checked;
      if (!widening()) state.crossSeed = null;
    } else state.filters[key] = $(id).checked;
    filtersChanged();
  });
  $("btnReset").addEventListener("click", () => { clearFilters(); filtersChanged(); });
  function clearFilters() { for (const k of SETS) state.filters[k].clear(); for (const k of SINGLES) state.filters[k] = ""; for (const k of FLAGS) state.filters[k] = false; state.crossSeed = null; }
  function renderFilterBar() {
    const bar = $("filterBar"); bar.replaceChildren();
    const pairs = filterPairs(); bar.hidden = !pairs.length; if (!pairs.length) return;
    bar.append(el("span", null, "Filtered by"));
    for (const [k, v] of pairs) {
      const c = el("span", "fchip"); c.append(el("b", null, `${NAMES[k] || k}:`), el("span", "mono", valueLabel(k, v)));
      const x = el("button", null, "×"); x.type = "button"; x.setAttribute("aria-label", `Remove ${NAMES[k] || k} filter`);
      x.addEventListener("click", () => { if (state.filters[k] instanceof Set) state.filters[k].delete(v); else if (FLAGS.includes(k)) state.filters[k] = false; else state.filters[k] = ""; if (!widening()) state.crossSeed = null; filtersChanged(); });
      c.append(x); bar.append(c);
    }
    const clear = el("button", "link-btn", "Clear all"); clear.type = "button"; clear.addEventListener("click", () => { clearFilters(); filtersChanged(); }); bar.append(clear);
  }
  function stageHint() {
    const f = state.filters;
    const seed = currentSeed().filter(([k]) => ["service", "family", "issue", "severity"].includes(k));
    if (widening() && seed.length) {
      const fp = filterPairs(), last = Math.max(...WIDEN.map((k) => fp.findIndex(([pk]) => pk === k)));
      const from = seed.map(([, v]) => v).join(", "), then = fp.slice(last + 1).filter(([k]) => !FLAGS.includes(k));
      const which = [f.cross ? "are in several reports" : "", f.multi ? "carry several issues" : ""].filter(Boolean).join(" and ");
      return `hosts of ${from} that ${which} · showing ${then.length ? `their ${then.map(([, v]) => v).join(", ")} records` : "all their reports"}`
        + `${state.view === "sky" && seed.some(([k]) => k === "service") ? " · the starting report is outlined" : ""}`;
    }
    return state.view === "ghana" ? "regions coloured by records · hover for what makes them up · click to analyse" : "one bubble per service · click to analyse";
  }
  function filtersChanged() {
    buildFilters(); renderFilterBar(); resetStream(); backfill(); refreshStats(); refreshReplayed(); $("stageHint").textContent = stageHint();
    // keep the filters in the address, so a refresh (or a minimised tab reloaded by the browser) returns to the same view
    const u = new URL(location.href), keep = u.searchParams.get("demo");
    u.search = new URLSearchParams(filterPairs().filter(([k]) => k !== "ip")).toString();
    if (keep) u.searchParams.set("demo", keep);
    history.replaceState(null, "", u.pathname + (u.search || ""));
  }
  function applyPairs(pairs) {
    clearFilters();
    pairs = seal(pairs);
    for (const [k, v] of pairs) { if (SETS.includes(k)) state.filters[k].add(v); else if (SINGLES.includes(k)) state.filters[k] = v; else if (FLAGS.includes(k)) state.filters[k] = true; }
    const cp = pairs.find(([k]) => WIDEN.includes(k)); state.crossSeed = cp ? decSeed(cp[1]) : null;
    const skipped = pairs.filter(([k]) => !SETS.includes(k) && !SINGLES.includes(k) && !FLAGS.includes(k));
    filtersChanged();
    toast(`View filtered to ${pairs.filter((p) => !skipped.includes(p)).map(([k, v]) => `${NAMES[k] || k} ${valueLabel(k, v)}`).join(" · ") || "everything"}.`
      + (skipped.length ? ` Not applied (use the analysis for those): ${skipped.map(([k, v]) => `${NAMES[k] || k} ${valueLabel(k, v)}`).join(", ")}.` : "") + " Use Clear all above the stream to remove it.");
  }

  // ------------------------------------------------------------------ drawer (tablet / phone): same as the map platform
  function setDrawer(open) { $("drawer").classList.toggle("open", open); $("scrim").hidden = !open || !mq("(max-width: 1099px)"); $("btnDrawer").setAttribute("aria-expanded", String(open)); }
  $("btnDrawer").addEventListener("click", () => setDrawer(true));
  $("btnCloseDrawer").addEventListener("click", () => setDrawer(false));
  $("scrim").addEventListener("click", () => setDrawer(false));
  for (const tab of document.querySelectorAll(".drawer-tabs [role=tab]")) tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".drawer-tabs [role=tab]")) t.setAttribute("aria-selected", String(t === tab));
    for (const b of document.querySelectorAll(".tab-body")) b.hidden = b.dataset.body !== tab.dataset.tab;
    if (tab.dataset.tab === "intel" && state.stats) setTimeout(() => renderIntel(state.stats), 0);
  });
  function placeIntel() {   // narrower screens: Intel moves into the drawer's second tab
    const narrowScreen = mq("(max-width: 1439px)"), intel = $("intel");
    if (narrowScreen && intel.parentElement !== $("intelSlot")) $("intelSlot").append(intel);
    else if (!narrowScreen && intel.parentElement !== $("intelCol")) $("intelCol").append(intel);
  }
  addEventListener("resize", () => { placeIntel(); if (state.stats) renderIntel(state.stats); });

  // ================================================================== record details (same dialog as the map platform)
  function section(title, rows, wide) {
    const s = el("section", "m-sec" + (wide ? " wide" : "")); s.append(el("h3", null, title));
    const dl = el("dl");
    for (const [k, v, pair] of rows) {
      dl.append(el("dt", null, k));
      const dd = el("dd", v ? null : "empty", v || "Not recorded");
      if (v && pair) { dd.title = "Click to analyse"; dd.style.cursor = "pointer"; dd.style.color = "var(--accent)"; dd.addEventListener("click", () => openInsight([pair])); }
      dl.append(dd);
    }
    s.append(dl); return s;
  }
  function defBox(box, label) {
    box.replaceChildren();
    const d = defOf(label); if (!d) return;
    box.append(el("b", null, `${d.title}${d.ipv6 ? " (IPv6)" : ""}`), document.createTextNode(` · Shadowserver rating: ${d.rating || "n/a"}. `), document.createTextNode(d.def));
    if (d.why) box.append(el("div", null, `Why it matters: ${d.why}`));
    if (d.url) { const a = el("a", null, "Shadowserver report page ↗"); a.href = d.url; a.target = "_blank"; a.rel = "noopener"; box.append(el("div"), a); }
  }
  async function openModal(ev) {
    hideTip();
    let d;
    try { d = await getJSON(`/api/svc/detail?id=${encodeURIComponent(ev.id)}&at=${encodeURIComponent(ev.extracted_date)}`); }
    catch (err) { toast(`Could not load the record: ${err.message}`); return; }
    const e = d.event; state.modalEv = e; refLabels.set(e.ip_ref, e.ip);
    $("modal").style.setProperty("--mc", famColor(e.family));
    const sw = el("span", "swatch"); sw.style.background = famColor(e.family);
    $("mTitle").replaceChildren(sw, document.createTextNode(e.service));
    const sev = $("mSev"); sev.textContent = e.severity || "n/a"; sev.style.setProperty("--sevc", sevColor(e.severity));
    $("mTag").textContent = `tag: ${e.tag || "n/a"}`;
    $("mTime").textContent = `Record time ${(e.extracted_date || "").replace("T", " ").slice(0, 19)} UTC${LT().also(e.extracted_date)}`;
    defBox($("mKb"), e.service);
    $("mPlace").replaceChildren(flagImg(e.geo), el("span", null, [titleCase(e.city), regionUnknown(e.region) ? "" : titleCase(e.region), COUNTRY.name].filter(Boolean).join(", ")));
    $("mIp").textContent = `${e.ip}${e.port ? ":" + e.port : ""}`;
    $("mProto").textContent = e.protocol || "";
    $("mSvc").replaceChildren(el("span", null, `${e.service} · port ${e.port || "n/a"}`));
    $("mProduct").textContent = [e.vendor, e.product, e.version].filter(Boolean).join(" · ") || "product not identified";
    const body = $("mBody"); body.replaceChildren();
    if (e.issues.length) body.append(section("Issues found", e.issues.map((i) => ["Issue", i, ["issue", i]]), true));
    const net = e.network ? e.network.replace(/ \(AS\d+\)$/, "") : "";
    body.append(
      section("Host", [["IP", e.ip, ["ip", e.ip_ref]], ["Port", e.port, e.port ? ["port", e.port] : null], ["Protocol", e.protocol], ["Hostname", e.hostname],
        [state.demo ? "Network" : "Network (ASN)", e.network, net ? ["asn", net] : null], ["Sector", e.sector, e.sector ? ["sector", e.sector] : null]]),
      section("Location", [["City", titleCase(e.city), e.city ? ["city", e.city] : null], ["Region", regionLabel(e.region), e.region ? ["region", e.region] : null], ["Country", e.geo && `${e.geo === COUNTRY.code ? COUNTRY.name : e.geo} (${e.geo})`]]),
      section("Service and device", [["Report", `${e.service} (${e.report})`, ["service", e.service]], ["Report family", e.family, ["family", e.family]], ["Severity", e.severity, ["severity", e.severity]],
        ["Vendor", e.vendor, e.vendor ? ["vendor", e.vendor] : null], ["Device type", e.device_type, e.device_type ? ["device_type", e.device_type] : null],
        ["Product", e.product, e.product ? ["product", e.product] : null], ["Version", e.version], ["Tags", e.tags.join(", ")]]),
      section("This host yesterday", [["Records", fmt(d.host_records)], ["Reports / services", d.host_services.join(", ")]]),
    );
    const ex = Object.entries(e.extras || {});
    const hid = e.extras_hidden ? ` (${e.extras_hidden} identifying or unlisted field${e.extras_hidden === 1 ? "" : "s"} hidden in the masked view)` : "";
    if (ex.length || hid) body.append(section(`${e.service} specific fields${hid}`, ex.map(([k, v]) => [k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase()), v]), true));
    $("modal").hidden = false; $("modalScrim").hidden = false; $("btnModalClose").focus();
  }
  function closeModal() { $("modal").hidden = true; if ($("insight").hidden && $("glossary").hidden) $("modalScrim").hidden = true; state.modalEv = null; }
  $("btnModalClose").addEventListener("click", closeModal);
  $("modalScrim").addEventListener("click", () => { if (!$("glossary").hidden) closeGlossary(); else if (!$("insight").hidden) closeInsight(); else closeModal(); });
  $("mHost").addEventListener("click", () => { const e = state.modalEv; if (e) openInsight([["ip", e.ip_ref]]); });
  $("mService").addEventListener("click", () => { const e = state.modalEv; if (e) openInsight([["service", e.service]]); });
  $("mShow").addEventListener("click", () => { const e = state.modalEv; if (!e) return; closeModal(); applyPairs([["service", e.service]]); });
  $("mCopy").addEventListener("click", async () => {
    if (!state.modalEv) return;
    try { await navigator.clipboard.writeText(JSON.stringify(state.modalEv, null, 2)); $("mCopy").textContent = "Copied"; setTimeout(() => { $("mCopy").textContent = "Copy JSON"; }, 1500); } catch { toast("Clipboard not available"); }
  });

  // ================================================================== analysis (same dialog, figures and drill-downs as the map platform)
  const stack = [];
  function narrow(pairs, k, v) {
    const multi = ["issue", "tag"].includes(k);
    pairs = seal(pairs);
    // after "several reports", a new filter narrows the widened records: the filters that chose the hosts (before it) stay
    const ci = WIDEN.includes(k) ? -1 : Math.max(-1, ...pairs.map(([pk], i) => (WIDEN.includes(pk) ? i : -1)));
    const keep = ci >= 0 ? pairs.slice(0, ci + 1) : [], rest = ci >= 0 ? pairs.slice(ci + 1) : pairs;
    return seal([...keep, ...rest.filter(([pk, pv]) => (multi ? !(pk === k && pv === v) : pk !== k)), [k, v]]);
  }
  function selTitle(pairs) {
    if (!pairs.length) return "The whole day";
    return pairs.map(([k, v]) => (k === "ip" ? `Host ${valueLabel(k, v)}` : FLAG_TITLE[k] || valueLabel(k, v))).join(" · ");
  }
  function kindLabel(pairs) {
    if (!pairs.length) return "Whole day · all reports";
    if (pairs.length > 1) return "Combined selection";
    const k = pairs[0][0];
    return { service: "Service report", ip: "Host", issue: "Issue", region: "Region", city: "City", asn: "Network", family: "Report family", severity: "Severity",
      port: "Port", vendor: "Vendor", product: "Product", time: "Time window", vulnerable: "Hosts with issues", multi: "Hosts with multiple issues", cross: "Hosts in several reports",
      device_type: "Device type", tag: "Tag", sector: "Sector" }[k] || NAMES[k] || "Analysis";
  }
  async function openInsight(pairs, opts = {}) {
    hideTip();
    pairs = seal(pairs);
    if (opts.push !== false) stack.push(pairs);
    $("iBack").hidden = stack.length < 2;
    $("iKind").textContent = kindLabel(pairs); $("iTitle").textContent = selTitle(pairs); $("iRange").textContent = "";
    $("iBody").replaceChildren(el("div", "i-loading", "Analysing…"));
    $("insight").hidden = false; $("modalScrim").hidden = false; $("btnInsightClose").focus();
    const p = new URLSearchParams(pairs); p.set("at", atParam());
    window.LGAnalysis = { platform: "services", query: p.toString(), at: p.get("at"), title: selTitle(pairs) };   // acode-make.js
    let d;
    try { d = await getJSON(`/api/svc/insight?${p}`); } catch (err) { $("iBody").replaceChildren(el("div", "i-loading", `Could not load analysis: ${err.message}`)); return; }
    if (stack[stack.length - 1] !== pairs) return;
    renderInsight(pairs, d, opts.drill);
  }
  function renderParts(pairs) {
    const box = $("iParts"); box.replaceChildren();
    if (pairs.length < 2) { box.hidden = true; return; }
    box.hidden = false; box.append(el("span", "i-parts-lbl", "Selection:"));
    pairs.forEach(([k, v], i) => {
      const chip = el("span", "fchip part");
      const open = el("button", "part-open"); open.type = "button"; open.append(el("b", null, `${NAMES[k] || k}:`), el("span", "mono", valueLabel(k, v)));
      open.title = "Open this part on its own"; open.addEventListener("click", () => openInsight([[k, v]]));
      const x = el("button", null, "×"); x.type = "button"; x.title = "Remove this part (widen the selection)"; x.addEventListener("click", () => openInsight(pairs.filter((_, j) => j !== i)));
      chip.append(open, x); box.append(chip);
    });
  }
  function card(title, kind) {
    const sec = el("section", "m-sec chart-card"); sec.append(el("h3", null, title)); const out = { sec };
    if (kind === "donut") { const wrap = el("div", "donut-wrap"); out.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg"); out.svg.setAttribute("viewBox", "0 0 120 120"); out.svg.classList.add("donut"); out.legend = el("ol", "legend"); wrap.append(out.svg, out.legend); sec.append(wrap); }
    else if (kind === "canvas") { out.canvas = el("canvas", "i-chart"); sec.append(out.canvas); }
    else if (kind === "sev") { out.bar = el("div", "sevbar"); out.legend = el("div", "sevlegend"); sec.append(out.bar, out.legend); }
    return out;
  }
  const BREAK_TITLES = { service: "Services (reports)", issue: "Issues", region: "Regions", city: "Cities", network: "Networks", vendor: "Device vendors", product: "Products",
    port: "Ports", tag: "Tags", sector: "Sectors", device_type: "Device types", family: "Report families", protocol: "Protocols" };
  const KEY_OF = { service: "service", issue: "issue", region: "region", city: "city", network: "asn", vendor: "vendor", product: "product", port: "port", tag: "tag",
    sector: "sector", device_type: "device_type", family: "family", protocol: "protocol", severity: "severity" };
  function renderInsight(pairs, d, autoDrill) {
    $("iKind").textContent = kindLabel(pairs);
    const title = $("iTitle"); title.replaceChildren();
    const svcPair = pairs.length === 1 && pairs[0][0] === "service" ? pairs[0][1] : null;
    if (svcPair) { const sw = el("span", "swatch"); sw.style.background = famColor(state.svcFamily.get(svcPair)); title.append(sw); }
    if (pairs.length === 1 && pairs[0][0] === "family") { const sw = el("span", "swatch"); sw.style.background = famColor(pairs[0][1]); title.append(sw); }
    title.append(document.createTextNode(selTitle(pairs)));
    $("iRange").textContent = d.total ? `Records reported by Shadowserver as of ${d.day}` : `No records reported by Shadowserver for ${d.day}`;
    renderParts(pairs);
    if (svcPair) defBox($("iKb"), svcPair); else $("iKb").replaceChildren();
    $("iFilter").hidden = !pairs.length;

    const body = $("iBody"); body.replaceChildren();
    const kpis = el("div", "i-kpis"), drill = el("section", "m-sec i-drill"); drill.hidden = true;
    const isHost = pairs.some(([k]) => k === "ip");
    const kpi = (v, k, metric, term) => {
      const b = el("div", "i-kpi"); const kk = el("div", "k", k); if (term) kk.dataset.term = term; b.append(el("div", "v", v), kk); kpis.append(b);
      if (!metric || !d.total) return;
      b.classList.add("click"); b.tabIndex = 0; b.setAttribute("role", "button"); b.dataset.metric = metric; b.append(el("div", "go", "Details ›"));
      const open = () => toggleDrill(pairs, d, metric, b, drill, kpis);
      b.addEventListener("click", open); b.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
    };
    kpi(fmt(d.total), "Records", "events", "exposures");
    kpi(pct(d.total, d.day_total), "Share of all records", "share", "share");
    if (!isHost) kpi(fmt(d.hosts), "Exposed hosts", "hosts", "exposed_host");
    kpi(fmt(d.vulnerable_hosts), "Hosts with issues", "vulnerable", "vulnerable_host");
    kpi(fmt(d.issues), "Issues", "issues", "issue");
    if (!isHost) kpi(fmt(d.multi_issue_hosts), "Hosts with multiple issues", "multi", "multi");
    kpi(fmt(d.services), "Reports", "services", "service");
    if (!isHost) kpi(fmt(d.cross_report_hosts), "Hosts in several reports", "cross", "cross");
    kpi(fmt(d.networks), "Networks", "networks", "network");
    kpi(fmt(d.regions), "Regions", "regions", "region");
    body.append(kpis);
    if (d.total) body.append(el("div", "i-kpi-hint", "Click any figure for the list behind it, such as the hosts that need follow-up."));
    body.append(drill);

    const grid = el("div", "i-grid");
    const f = el("section", "m-sec"); f.append(el("h3", null, "Key findings"));
    const ul = el("ul", "i-findings"); for (const s of d.findings.length ? d.findings : ["No records have been reported for this selection."]) ul.append(el("li", null, s)); f.append(ul);
    const B = d.breakdowns;
    const mix = B.family.length > 1 ? { title: "Share by report family", rows: B.family, color: famColor, key: "family" }
      : { title: "Share by service report", rows: B.service, color: (v) => PAL[Math.max(0, B.service.findIndex((r) => r.value === v)) % PAL.length], key: "service" };
    const mixCard = card(mix.title, "donut");
    const second = B.issue.length ? { title: "Issues", rows: B.issue, key: "issue" } : { title: "Networks", rows: B.network, key: "asn" };
    const netCard = card(second.title, "donut");
    const side = el("div", "i-side"); side.append(mixCard.sec, netCard.sec); grid.append(f, side); body.append(grid);
    const axis = () => { const ax = el("div", "tl-axis mono"); for (const l of ["00", "06", "12", "18", "24"]) ax.append(el("span", null, l)); return ax; };
    const row1 = el("div", "i-charts");
    const cHour = card(d.peak_hour != null ? `Records by hour and family · peak ${String(d.peak_hour).padStart(2, "0")}:00` : "Records by hour and family", "canvas"); cHour.sec.append(axis());
    const cQuarter = card("Activity by 15 minutes", "canvas"); cQuarter.sec.append(axis());
    const cSev = card("Severity mix", "sev");
    row1.append(cHour.sec, cQuarter.sec, cSev.sec); body.append(row1);
    setTimeout(() => {
      donutChart(mixCard.svg, mixCard.legend, mix.rows, { color: mix.color, unit: "records", center: "records", onClick: (v) => openInsight(narrow(pairs, mix.key, v)) });
      donutChart(netCard.svg, netCard.legend, second.rows, { color: (v) => PAL[Math.max(0, second.rows.findIndex((r) => r.value === v)) % PAL.length], unit: "records", center: "records", onClick: (v) => openInsight(narrow(pairs, second.key, v)) });
      const scope = (st, m) => openInsight(narrow(pairs, "time", `${st}+${m}`));
      stackedHours(cHour.canvas, d.hours_by_family || {}, null, null, scope);
      quarterHours(cQuarter.canvas, d.quarters || [], null, svcPair ? famColor(state.svcFamily.get(svcPair)) : ACCENT, null, scope);
      severityMix(cSev.bar, cSev.legend, d.severity || [], { onClick: (v) => openInsight(narrow(pairs, "severity", v)) });
    }, 0);
    const breaks = el("div", "i-breaks");
    for (const key of ["service", "issue", "region", "city", "network", "vendor", "product", "port", "device_type", "sector", "tag", "family"]) {
      const rows = B[key] || []; if (!rows.length) continue;
      const sec = el("section", "m-sec"); sec.append(el("h3", null, BREAK_TITLES[key]));
      const list = el("ul", "brk");
      for (const r of rows) {
        const li = el("li"); const bl = el("span", "bl");
        const kc = key === "service" ? famColor(state.svcFamily.get(r.value)) : key === "family" ? famColor(r.value) : key === "issue" ? "#f5b54a" : null;
        if (kc) { const sw = el("span", "swatch"); sw.style.background = kc; bl.append(sw); }
        if (key === "region" || key === "city") bl.append(flagImg(COUNTRY.code));
        const lab = el("span", ["product", "port", "tag"].includes(key) ? "mono" : null, key === "port" ? `Port ${r.label}` : r.label); lab.title = r.label; bl.append(lab);
        const bs = el("span", "bs"); const bi = el("i"); bi.style.width = `${Math.max(2, r.share * 100)}%`; if (kc) bi.style.setProperty("--bc", kc); bs.append(bi);
        li.append(bl, bs, el("span", "bv", pct(r.share, 1)));
        // a value that is already the selection (e.g. Device Identification inside its own analysis) is not a link
        const current = pairs.some(([pk, pv]) => pk === KEY_OF[key] && String(pv) === String(r.value));
        if (!current) li.classList.add("click");
        attachTip(li, () => [tipLine(lab.textContent), tipLine(null, `${fmt(r.count)} records · ${fmt(r.hosts)} hosts · ${pct(r.count, d.total)} of this selection`),
          ...(key === "service" && defOf(r.value) ? [tipLine(null, defOf(r.value).def)] : []), tipLine(null, current ? "This is the current selection" : "Click to analyse")]);
        if (!current) li.addEventListener("click", () => openInsight(narrow(pairs, KEY_OF[key], r.value)));
        list.append(li);
      }
      sec.append(list); breaks.append(sec);
    }
    body.append(breaks);
    if (d.host_rows.length && !isHost) {
      const sec = el("section", "m-sec wide"); sec.append(el("h3", null, "Hosts to follow up first"));
      const wrap = el("div", "table-wrap"); const tbl = el("table", "hosts");
      const thead = el("thead"); const hr = el("tr");
      for (const h of ["Host IP", "Issues", "Reports / services", "Records", "City", "Network", "Device / product", "Last seen"]) hr.append(el("th", null, h));
      thead.append(hr); tbl.append(thead);
      const tb = el("tbody");
      for (const h of d.host_rows) {
        refLabels.set(h.ref, h.ip);
        const tr = el("tr", "click");
        tr.append(el("td", "mono", h.ip), el("td", null, h.issues.join(", ") || "–"), el("td", null, h.services.join(", ")), el("td", "mono", fmt(h.events)), el("td", null, h.city),
          el("td", null, h.network || "n/a"), el("td", null, [h.vendor, h.product].filter(Boolean).join(" · ")), el("td", "mono", (h.last || "").slice(11, 19)));
        tr.addEventListener("click", () => openInsight([["ip", h.ref]]));
        tb.append(tr);
      }
      tbl.append(tb); wrap.append(tbl); sec.append(wrap); body.append(sec);
    }
    explainAll(body);
    if (autoDrill) { const tile = kpis.querySelector(`.i-kpi[data-metric="${autoDrill}"]`); if (tile) tile.click(); }
  }
  async function toggleDrill(pairs, d, metric, tile, box, kpis) {
    const same = box.dataset.metric === metric && !box.hidden;
    for (const k of kpis.querySelectorAll(".i-kpi")) { k.classList.remove("active"); k.setAttribute("aria-expanded", "false"); }
    if (same) { box.hidden = true; box.dataset.metric = ""; return; }
    tile.classList.add("active"); tile.setAttribute("aria-expanded", "true");
    box.dataset.metric = metric; box.hidden = false;
    box.replaceChildren(el("div", "i-loading", "Loading the details…"));
    box.scrollIntoView({ block: "nearest", behavior: reducedMotion ? "auto" : "smooth" });
    const p = new URLSearchParams(pairs); p.set("at", atParam()); p.set("metric", metric);
    let r;
    try { r = await getJSON(`/api/svc/drill?${p}`); } catch (err) { box.replaceChildren(el("div", "i-loading", `Could not load the details: ${err.message}`)); return; }
    if (box.dataset.metric !== metric) return;
    renderDrill(box, r, pairs, d);
  }
  const drillCell = (v) => (Array.isArray(v) ? v.join(", ") : typeof v === "number" ? fmt(v) : v ?? "");
  function renderDrill(box, r, pairs, d) {
    box.replaceChildren();
    const head = el("div", "drill-head"); head.append(el("h3", null, r.title));
    const acts = el("div", "drill-actions");
    if (r.rows.length) {
      const canExport = document.body.dataset.export === "1";     // external viewers get no downloads
      const dl = el("button", "pill-btn", "Download CSV"); dl.type = "button"; dl.title = "Save this list as a spreadsheet file (CSV)"; dl.addEventListener("click", () => downloadDrill(r, pairs, d)); if (canExport) acts.append(dl);
      const p = new URLSearchParams(pairs); p.set("at", atParam()); p.set("metric", r.metric); p.set("all", "1"); p.set("label", selTitle(pairs));
      const pdf = el("button", "pill-btn pdf-btn", "Download report (PDF + CSV)"); pdf.type = "button";
      pdf.title = "A ZIP file with a detailed PDF report of this figure (executive summary, key figures, priorities, the issues explained: CVEs with NVD, CISA KEV and EPSS, breakdowns, report definitions) and the complete list as a CSV file";
      pdf.addEventListener("click", () => window.LGPdf.download(pdf, `/api/svc/report?${p}`));
      if (canExport) acts.append(pdf);
      const hasIssues = r.columns.some(([k]) => k === "issues") || r.row_kind === "issue";
      if (LOOKUPS && hasIssues) {
        const ib = el("button", "pill-btn mp-btn", r.iss ? "Issues explained ✓" : "Explain issues"); ib.type = "button";
        ib.title = "Explain every issue in this list: CVEs from NVD (description, CVSS), CISA's Known Exploited Vulnerabilities catalog (actively exploited?) and EPSS; other issues from their definitions";
        ib.disabled = !!r.iss;
        ib.addEventListener("click", async () => {
          ib.disabled = true; ib.textContent = "Looking up the issues…";
          try {
            let all = r;
            if (r.total > r.rows.length) { try { const q = new URLSearchParams(pairs); q.set("at", atParam()); q.set("metric", r.metric); q.set("all", "1"); all = await getJSON(`/api/svc/drill?${q}`); } catch { all = r; } }
            const names = [...new Set(all.rows.flatMap((row) => (r.row_kind === "issue" ? [row.name] : row.issues || [])).filter(Boolean))];
            const nCve = names.filter((n) => /^CVE-\d{4}-\d{4,7}$/i.test(n)).length;
            r.iss = await window.LGLookup.run({ kind: "issues", values: names, title: "Explaining the issues",
              intro: `${names.length} issue${names.length === 1 ? "" : "s"}: ${nCve} CVE${nCve === 1 ? "" : "s"}, looked up in batches (CISA's exploited-vulnerabilities catalog once a day, EPSS 100 at a time, ` +
                `the official CVE.org records four at a time; NVD's own analysis is added in the background at NVD's pace), and ${names.length - nCve} other issue${names.length - nCve === 1 ? "" : "s"}, explained from their definitions.` });
            renderDrill(box, r, pairs, d);
          } catch (err) { ib.disabled = false; ib.textContent = `Look-up failed: ${err.message} (retry)`; }
        });
        acts.append(ib);
      }
    }
    const x = el("button", "pill-btn", "Close"); x.type = "button";
    x.addEventListener("click", () => { box.hidden = true; box.dataset.metric = ""; box.parentElement?.querySelectorAll(".i-kpi.active").forEach((k) => k.classList.remove("active")); });
    acts.append(x); head.append(acts); box.append(head);
    if (r.intro) box.append(el("p", "drill-intro", r.intro));
    if (r.iss) {                                    // every issue of the list, explained
      const v = Object.values(r.iss), kev = v.filter((x) => x.exploited).length, cve = v.filter((x) => x.kind === "cve").length;
      const det = el("details", "mp-batch");
      det.append(el("summary", null, `${v.length} issue${v.length === 1 ? "" : "s"}: ${cve} CVE${cve === 1 ? "" : "s"}${kev ? `, ${kev} actively exploited (CISA KEV)` : ""}. Show each one`));
      const list = el("div", "mp-cards");
      for (const [n, x] of Object.entries(r.iss).sort((a, b) => Number(!!b[1].exploited) - Number(!!a[1].exploited) || ((b[1].cvss || {}).score || 0) - ((a[1].cvss || {}).score || 0))) list.append(issueCard(x, n));
      det.append(list); box.append(det);
    }
    if (!r.rows.length) { box.append(el("p", "drill-empty", r.empty)); return; }
    const wrap = el("div", "table-wrap drill-wrap"); const tbl = el("table", "hosts drill-table");
    const cols = r.iss ? [...r.columns, ["_issues", "What the issues are"]] : r.columns;
    const thead = el("thead"); const hr = el("tr"); for (const [, label] of cols) hr.append(el("th", null, label)); thead.append(hr); tbl.append(thead);
    const tb = el("tbody");
    for (const row of r.rows) {
      const tr = el("tr");
      for (const [key] of cols) {
        const v = row[key];
        if (key === "_issues") {
          const td = el("td", "mp-cell");
          for (const n of (r.row_kind === "issue" ? [row.name] : row.issues || [])) {
            const x = r.iss[n]; if (!x) continue;
            const det = el("details", `mp-mini ${x.exploited ? "kev" : x.found || x.curated ? "ok" : "no"}`);
            const sum = el("summary"); sum.append(el("b", "mono", n), document.createTextNode(` → ${issueShort(x)}`));
            det.append(sum, issueCard(x, n)); det.addEventListener("click", (ev) => ev.stopPropagation());
            td.append(det);
          }
          tr.append(td); continue;
        }
        if (key === "followup") {
          const td = el("td", "fu");
          if (!v.length) td.append(el("span", "muted", "Monitor"));
          for (const reason of v) td.append(el("span", `fu-chip${/issues|reports|critical/i.test(reason) ? " hi" : ""}`, reason));
          td.title = v.join(" · ") || "No strong signs beyond this selection"; tr.append(td); continue;
        }
        const txt = String(drillCell(v));
        const td = el("td", ["ip", "first", "last"].includes(key) || typeof v === "number" ? "mono" : null, ["first", "last"].includes(key) ? txt.replace("T", " ").slice(11, 19) : txt);
        if (txt.length > 24) td.title = txt; tr.append(td);
      }
      const target = r.row_kind === "ip" ? row.ref : row.value;
      if (target) {
        tr.classList.add("click"); tr.title = r.row_kind === "ip" ? "Open this host's analysis" : "Open the analysis for this entry";
        if (r.row_kind === "ip") refLabels.set(row.ref, row.ip);
        tr.addEventListener("click", () => openInsight(r.row_kind === "ip" ? [["ip", target]] : narrow(pairs, r.row_kind, target)));
      }
      tb.append(tr);
    }
    tbl.append(tb); wrap.append(tbl); box.append(wrap);
    if (r.total > r.rows.length) box.append(el("p", "drill-more", `Showing the first ${fmt(r.rows.length)} of ${fmt(r.total)}.${document.body.dataset.export === "1" ? ` Download CSV saves all ${fmt(r.total)}.` : ""}`));
    else box.append(el("p", "drill-more", `${fmt(r.total)} ${r.total === 1 ? "entry" : "entries"}. Click a row to analyse it.`));
  }
  async function downloadDrill(r, pairs, d) {
    const iss = r.iss, kind = r.row_kind;
    if (r.total > r.rows.length) { try { const p = new URLSearchParams(pairs); p.set("at", atParam()); p.set("metric", r.metric); p.set("all", "1"); r = await getJSON(`/api/svc/drill?${p}`); } catch { /* the rows shown */ } }
    // quoted, and spreadsheet-safe: a cell starting with = + - @ (not a plain number) would run as a formula
    const q = (s) => { s = String(s); if (/^[=+\-@\t\r\n＝＋－＠]/.test(s) && !/^([+-]?\d+([.,]\d+)*%?|-+)$/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
    const lines = [[...r.columns.map(([, l]) => q(l)), ...(iss ? [q("What the issues are (CVE: NVD / CISA KEV / EPSS; others: definition)")] : [])].join(",")];
    for (const row of r.rows) {
      const cells = r.columns.map(([k]) => q(k === "followup" ? (row[k] || []).join("; ") : drillCell(row[k])));
      if (iss) cells.push(q((kind === "issue" ? [row.name] : row.issues || []).filter((n) => iss[n]).map((n) => `${n}: ${issueShort(iss[n])}`).join(" | ")));
      lines.push(cells.join(","));
    }
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a"), name = selTitle(pairs).replace(/[^\w.-]+/g, "-").slice(0, 40);
    a.href = URL.createObjectURL(blob); a.download = `looking-glass-services_${d.day}_${name}_${r.metric}.csv`;
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  // ---------------- issues explained: CVEs (NVD, CISA KEV, EPSS) and the others (definitions written by researchers)
  const LOOKUPS = !!(window.SVC_CONFIG || {}).lookups;
  const extLink = (href, text) => {
    let ok = false; try { ok = ["http:", "https:"].includes(new URL(href).protocol); } catch { ok = false; }
    if (!ok) return el("span", null, text);
    const a = el("a", null, text); a.href = href; a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
  };
  function refList(card, refs, label) {
    refs = [...new Set((refs || []).filter(Boolean))]; if (!refs.length) return;
    const ul = el("ul", "mp-refs");
    for (const u of refs.slice(0, 10)) { const li = el("li"); li.append(extLink(u, u.replace(/^https?:\/\//, "").slice(0, 90))); ul.append(li); }
    card.append(el("p", "mp-meta", label), ul);
  }
  function issueShort(x) {
    if (x.kind === "cve") {
      const bits = [];
      if (x.exploited) bits.push("ACTIVELY EXPLOITED");
      if (x.cvss) bits.push(`CVSS ${x.cvss.score}`);
      if (x.epss != null) bits.push(`EPSS ${(x.epss * 100).toFixed(1)}%`);
      if (x.pending) bits.push("not looked up yet"); else if (!x.found) bits.push("no public record");
      return `${x.kev?.name || (x.description || "").slice(0, 70)}${bits.length ? ` (${bits.join(", ")})` : ""}`;
    }
    return x.curated ? x.title : "no definition yet";
  }
  function issueCard(x, name) {
    const card = el("div", "mp-card"), head = el("div", "mp-head");
    if (x.kind === "cve") {
      card.classList.add(x.exploited ? "mp-kev" : "mp-cve");
      head.append(el("span", `badge mp-badge ${x.exploited ? "mp-badge-kev" : x.found ? "mp-badge-cve" : "mp-badge-no"}`,
        x.exploited ? "Actively exploited · CISA KEV" : x.found ? "CVE" : x.pending ? "Not looked up yet" : "No public record"));
      const t = el("b"); t.append(extLink(x.url, x.kev?.name ? `${name}: ${x.kev.name}` : name)); head.append(t); card.append(head);
      const facts = [];
      if (x.cvss) facts.push(`CVSS ${x.cvss.version} score ${x.cvss.score} (${String(x.cvss.severity || "").toLowerCase()}${x.cvss.source ? `, ${x.cvss.source}` : ""})`);
      if (x.epss != null) facts.push(`EPSS ${(x.epss * 100).toFixed(1)}% chance of exploitation in the next 30 days`);
      if (x.published) facts.push(`published ${x.published}`);
      if (facts.length) card.append(el("p", "mp-meta", facts.join(" · ")));
      if (x.description) card.append(el("p", "mp-desc", x.description));
      if (x.kev) {
        card.append(el("p", "mp-kev-line", `Actively exploited: in CISA's Known Exploited Vulnerabilities catalog since ${x.kev.date_added}${x.kev.ransomware === "Known" ? ", and used in ransomware campaigns" : ""}.`));
        if (x.kev.action) card.append(el("p", "mp-meta", `CISA's required action: ${x.kev.action}`));
      } else if (x.found) card.append(el("p", "mp-meta", "Not in CISA's Known Exploited Vulnerabilities catalog: no confirmed active exploitation reported to CISA (this does not mean it is safe)."));
      if (x.sources?.length) card.append(el("p", "mp-meta", `Sources: ${[...x.sources, "CISA KEV", "EPSS"].join(", ")}${x.nvd ? "" : " (NVD's own analysis is added within minutes)"}`));
      if (x.pending) card.append(el("p", "mp-meta", "Not looked up yet: try again in a minute."));
      if (x.cwes?.length) card.append(el("p", "mp-meta", `Weakness: ${x.cwes.join(", ")}`));
      if (x.note) card.append(el("p", "mp-meta", `Note by ${x.note_by || "a researcher"}: ${x.note}`));
      refList(card, [x.kev_url, x.nvd ? "" : x.cveorg_url, ...(x.references || []).slice(0, 6), ...(x.curated_references || [])], "References:");
    } else if (x.curated) {
      card.classList.add("mp-curated");
      head.append(el("span", "badge mp-badge mp-badge-kb", "Looking Glass definition"), el("b", null, `${name}: ${x.title}`)); card.append(head);
      if (x.type) card.append(el("p", "mp-meta", x.type));
      if (x.description) card.append(el("p", "mp-desc", x.description));
      refList(card, x.references, `Evidence (${(x.references || []).length} reference${(x.references || []).length === 1 ? "" : "s"}):`);
      card.append(el("p", "mp-meta", `Defined${x.by ? ` by ${x.by}` : ""}${x.updated ? ` on ${x.updated}` : ""}.`));
    } else {
      head.append(el("span", "badge mp-badge mp-badge-no", "No definition yet"), el("b", null, name)); card.append(head);
      if (x.text) card.append(el("p", "mp-desc", x.text));
    }
    for (const n of x.notes || []) {               // researchers' notes on the issue (notes.py), newest first
      const p = el("p", "mp-note"); p.append(el("b", null, `Notes shared by ${n.role || "Researcher"}: ${n.by || "a researcher"}${n.date ? ` (${n.date})` : ""}: `), document.createTextNode(n.text));
      card.append(p);
      if (n.codes?.length) card.append(window.LGCodes ? window.LGCodes.line(n.codes) : el("p", "mp-note", `Combinations: ${n.codes.map((c) => c.code).join(", ")}`));
    }
    return card;
  }
  function closeInsight() { $("insight").hidden = true; stack.length = 0; if ($("modal").hidden && $("glossary").hidden) $("modalScrim").hidden = true; }
  $("btnInsightClose").addEventListener("click", closeInsight);
  $("iBack").addEventListener("click", () => { stack.pop(); const p = stack[stack.length - 1]; if (p) openInsight(p, { push: false }); });
  // "Filter the view" applies the selection AND the card (figure) that is open: with "Hosts in several reports" open
  // on Device Identification, the view shows exactly those hosts, not all of Device Identification.
  const CARD_FILTER = { vulnerable: "vulnerable", multi: "multi", cross: "cross" };
  const openCard = () => { const box = document.querySelector("#iBody .i-drill"); return box && !box.hidden ? box.dataset.metric : ""; };
  function updateFilterButton() {
    const card = CARD_FILTER[openCard()];
    $("iFilter").textContent = card ? `Filter the view · ${FLAG_TITLE[card]}` : "Filter the view";
    $("iFilter").title = card ? `Show this selection on the page, limited to ${FLAG_TITLE[card].toLowerCase()} (the open card)` : "Show this selection on the page (open a card such as Hosts with issues to filter by it too)";
  }
  $("iFilter").addEventListener("click", () => {
    const cur = stack[stack.length - 1]; if (!cur) return;
    const card = CARD_FILTER[openCard()];
    const pairs = card && !cur.some(([k]) => k === card) ? [...cur, [card, "1"]] : cur;
    closeInsight(); closeModal(); applyPairs(pairs);
  });
  new MutationObserver(updateFilterButton).observe($("iBody"), { subtree: true, childList: true, attributes: true, attributeFilter: ["hidden", "data-metric"] });

  // ------------------------------------------------------------------ glossary
  async function loadGlossary() {
    try {
      const g = await getJSON("/api/svc/glossary");
      state.glossary = g;
      state.defs = new Map(g.reports.map((r) => [r.label, { title: r.title, rating: r.rating, def: r.def, why: r.why, url: r.url, ipv6: r.ipv6 }]));
    } catch { /* tooltips without definitions */ }
  }
  function renderGlossary() {
    const q = $("gSearch").value.trim().toLowerCase(), box = $("gBody"); box.replaceChildren();
    const g = state.glossary || { reports: [], families: [] };
    const groups = [
      { group: "Figures and terms", items: Object.values(TERMS).map(([t, d]) => ({ term: t, def: d })) },
      { group: "Report families", items: g.families.map((f) => ({ term: f.name, def: f.def[0].toUpperCase() + f.def.slice(1) + "." })) },
      { group: `Reports (${g.reports.length}), defined from Shadowserver's report pages`, items: g.reports.slice().sort((a, b) => b.rows - a.rows || a.label.localeCompare(b.label))
        .map((r) => ({ term: `${r.label}${r.title ? ` · ${r.title}` : ""}`, def: `${r.def || "No definition yet."}${r.why ? ` Why it matters: ${r.why}` : ""}${r.rating ? ` Shadowserver rating: ${r.rating}.` : ""} ${r.rows ? `${fmt(r.rows)} records on the replayed day.` : "No records on the replayed day."}`, url: r.url })) },
    ];
    let n = 0;
    for (const gr of groups) {
      const items = gr.items.filter((it) => !q || it.term.toLowerCase().includes(q) || it.def.toLowerCase().includes(q)); if (!items.length) continue;
      const sec = el("section", "gl-group"); sec.append(el("h3", null, gr.group)); const dl = el("dl");
      for (const it of items) { const dd = el("dd", null, it.def + " "); if (it.url) { const a = el("a", null, "Report page ↗"); a.href = it.url; a.target = "_blank"; a.rel = "noopener"; dd.append(a); } dl.append(el("dt", null, it.term), dd); n++; }
      sec.append(dl); box.append(sec);
    }
    if (!n) box.append(el("p", "muted", "No matching terms."));
    $("gCount").textContent = `${n} entries`;
  }
  function closeGlossary() { $("glossary").hidden = true; if ($("modal").hidden && $("insight").hidden) $("modalScrim").hidden = true; }
  $("btnGlossary").addEventListener("click", () => { renderGlossary(); $("glossary").hidden = false; $("modalScrim").hidden = false; $("gSearch").focus(); });
  $("btnGlossaryClose").addEventListener("click", closeGlossary);
  $("gSearch").addEventListener("input", renderGlossary);

  // ------------------------------------------------------------------ demo mode
  function setDemo(on) {
    state.demo = on; ls.set("lg.svc.demo", on);
    $("btnDemo").setAttribute("aria-pressed", String(on)); $("demoPill").hidden = !on;
    const u = new URL(location.href); if (on) u.searchParams.set("demo", "1"); else u.searchParams.delete("demo"); history.replaceState(null, "", u);
    // host references and network aliases differ between the two modes (the server accepts only aliases when masked)
    for (const k of ["ip", "asn"]) if (state.filters[k]) state.filters[k] = "";
    resetStream(); refreshAll(); backfill();
  }
  $("btnDemo").addEventListener("click", () => setDemo(!state.demo));

  // ------------------------------------------------------------------ settings (constituency label, changes)
  // Applied at start and whenever Settings change (checked every 10 s): country, regions map, labels, constituency
  let scopeVersion = null;
  function applySettings(st, announce = true) {
    const changed = scopeVersion != null && st.version !== scopeVersion;
    scopeVersion = st.version;
    const countryChanged = COUNTRY.code !== st.country;
    Object.assign(COUNTRY, { code: st.country, name: st.country_name, hasRegions: st.has_regions, restricted: st.restricted, networks: st.networks, cidrs: st.cidrs });
    document.querySelector('[data-view="ghana"]').textContent = `${st.country_name} regions`;
    $("ghana").setAttribute("aria-label", `${st.country_name} regions heatmap`);
    const pill = $("scopePill"); pill.hidden = !st.restricted;
    pill.textContent = `Constituency: ${st.networks} network${st.networks === 1 ? "" : "s"}${st.cidrs ? ` + ${st.cidrs} range${st.cidrs === 1 ? "" : "s"}` : ""}`;
    pill.title = "Only the networks of your constituency are shown on both platforms (Settings)";
    if (!changed) return;
    // new settings: everything reloads (the server has already reloaded the day with the new constituency)
    resetStream(); refreshAll(); backfill(); loadRegions();
    if (countryChanged && state.view === "ghana") ghana.draw();
    $("stageHint").textContent = stageHint();
    if (announce) toast(`Settings updated: ${st.country_name}${st.restricted ? ` · constituency of ${st.networks} AS number${st.networks === 1 ? "" : "s"}${st.cidrs ? ` and ${st.cidrs} address range${st.cidrs === 1 ? "" : "s"}` : ""}` : " · whole country"}. The view has been refreshed.`);
  }
  setInterval(async () => { try { applySettings(await (await fetch("/api/settings/public", { cache: "no-store" })).json()); } catch { /* keep */ } }, 10000);

  // ------------------------------------------------------------------ boot
  function refreshAll() { loadFacets(); refreshStats(); refreshReplayed(); loadGlossary(); }
  function loop() { release(); requestAnimationFrame(loop); }
  (async function start() {
    $("btnDemo").setAttribute("aria-pressed", String(state.demo)); $("demoPill").hidden = !state.demo;
    // country and constituency from Settings
    try { applySettings(await (await fetch("/api/settings/public", { cache: "no-store" })).json(), false); } catch { /* defaults: Ghana */ }
    // leaving for the overview fades out (and the page faded in on arrival), like the intro into the map
    // leaving: the logo animates ("Opening …") and the next page appears from it (static/js/loader.js); plain fade as a fallback
    const leave = (url) => {
      if (window.LGLoader) { window.LGLoader.go(url); return; }
      const f = $("pageFade"); f.classList.remove("in"); void f.offsetWidth; f.classList.add("out");
      setTimeout(() => { location.href = url; }, reducedMotion ? 0 : 420);
    };
    for (const a of document.querySelectorAll('a[href^="/?intro"]')) a.addEventListener("click", (e) => { e.preventDefault(); leave(a.getAttribute("href")); });
    setTimeout(() => $("pageFade").classList.remove("in"), 800);
    // Settings buttons (top bar, constituency label, region notice); from here Settings shows both parts: the country (regions map) and the constituency
    for (const id of ["btnSettings", "scopePill", "regionNoticeBtn"]) $(id).addEventListener("click", () => leave("/settings?for=services"));
    // opened with filters in the address (e.g. from the intro page's report list: /services?service=DNS%20Open%20Resolvers)
    for (const k of SETS) for (const v of qs.getAll(k)) state.filters[k].add(v);
    for (const k of SINGLES) if (qs.get(k)) state.filters[k] = qs.get(k);
    for (const k of FLAGS) if (qs.get(k) === "1" || (WIDEN.includes(k) && decSeed(qs.get(k)))) state.filters[k] = true;
    state.crossSeed = decSeed(qs.get("cross")) || decSeed(qs.get("multi"));
    placeIntel(); explainAll();
    if (ls.get("lg.svc.collapsed", false)) setStreamCollapsed(true, false);
    stage.resize(); setView(state.view);
    await loadGlossary();
    try { await syncClock(); } catch (err) { toast(`Could not reach the server: ${err.message}`); }
    if (state.sched) { state.anchorReplay = Date.parse(state.sched.replay_now); state.anchorWall = Date.now(); }
    state.cursor = replayNow();
    await Promise.all([loadFacets(), refreshStats()]);
    renderFilterBar(); refreshReplayed(); backfill();
    setInterval(poll, POLL_MS); setInterval(refreshReplayed, 3000); setInterval(refreshStats, 30000);
    setInterval(() => syncClock().catch(() => {}), 15000); setInterval(tickHud, 250);
    setInterval(() => { if (state.stats) renderIntel(state.stats); }, 60000);
    requestAnimationFrame(loop);
  })();
})();
