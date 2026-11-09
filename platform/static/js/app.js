/* Threat Map front end: Mapbox satellite + deck.gl 3D arcs, live replay of the previous day. */
(() => {
  "use strict";

  const CFG = window.TM_CONFIG || {};
  // Malpedia look-ups; without a Malpedia token the Looking Glass definitions (written by researchers) answer instead
  const MP_ON = !!(CFG.malpedia || CFG.enrich);
  const MP_NAME = CFG.malpedia ? "Malpedia" : "definitions";
  const MP_SRC = CFG.malpedia ? "on Malpedia" : "in the Looking Glass definitions";
  const mq = (q) => window.matchMedia(q).matches;
  const isPhone = () => mq("(max-width: 700px)");
  const reducedMotion = mq("(prefers-reduced-motion: reduce)");
  if (window.LG_UNSUPPORTED) return;   // the page already explains that this browser is too old

  // ------------------------------------------------------------------ performance profile
  // Full: everything (3D tilt, glow, trails, camera drift, blur). Lite: for smart TVs and older computers:
  // flat map, sharp (not blurred) panels, fewer simultaneous arcs and popups, half the redraw rate.
  // Auto (default) picks Lite for TV browsers and very weak devices, and switches to Lite by itself if the
  // map keeps running below ~22 frames per second. Choice: Filters > Display, or ?perf=auto|full|lite.
  // The choice (Auto / Full / Lite) is shared with the intro page and the services platform: static/js/display.js.
  const D = window.LGDisplay;
  const PERF_AUTO_KEY = D.AUTO_KEY;
  const lsGet = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
  const lsSet = (k, v) => { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { /* private mode */ } };
  const perfChoice = D.choice;
  const IS_TV = D.isTV;
  const autoReason = D.reason;
  const LITE = D.lite;
  const P = LITE
    ? { frameMs: 66, maxActive: 40, popups: 4, arcPoints: 24, rows: 120, glow: false, trails: false, srcPulse: false, pitch: 0, fog: false, pixelRatio: 1, antialias: false }
    : { frameMs: 33, maxActive: 180, popups: 10, arcPoints: 64, rows: 250, glow: true, trails: true, srcPulse: true, pitch: 48, fog: true, pixelRatio: Math.min(window.devicePixelRatio || 1, 2), antialias: true };

  // ------------------------------------------------------------------ tuning
  const POLL_MS = 4000;            // ask the server for the next replay window this often
  const LOOKAHEAD_MS = 6000;       // fetch a bit ahead so arcs launch on time
  const BACKFILL_MIN = 15;         // on load, show the last N replay-minutes in the stream
  const ACTIVE_REPLAY_MS = 75000;  // an attack stays "active" on the map for this much replay time…
  const ACTIVE_MIN_WALL = 9000;    // …but never less than this on screen
  const TRAVEL_MS = 1600;          // first flight of the packet along the arc
  const LOOP_MS = 2800;            // then it re-fires along the arc every LOOP_MS
  const ARC_POINTS = P.arcPoints;
  const POPUP_MS = 6500;
  const MAX_POPUPS = P.popups;
  const MAX_ROWS = P.rows;
  const maxActive = () => Math.min(P.maxActive, isPhone() ? 60 : 180);

  // Severity colors are reserved for severity; infections use a separate categorical palette with no red.
  const SEV = { critical: "#e5484d", high: "#f76b15", medium: "#ffc53d", low: "#3e8ef7", info: "#8b8d98" };
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const PALETTE = ["#5b8def", "#12a594", "#e2a336", "#8e7cf0", "#d6409f", "#46a758", "#00a2c7", "#c98a5e", "#a1c45a", "#7ce2fe", "#e796f3", "#b0b4ba"];
  const ACCENT = "#5b8def";
  const SET_KEYS = ["source", "attack_class", "infection", "severity", "protocol"];   // multi-select filters
  // single-value filters; the last ones are set from an analysis ("Filter map") and shown as chips
  const SINGLE_KEYS = ["src_city", "dst_geo", "tag", "dst_port", "http_host", "src_ip",
    "src_asn", "dst_asn", "dst_ip", "dst_city", "src_geo", "http_agent", "request"];
  const labelCache = new Map();   // "key\u0000value" -> readable label (for references and names)
  const cacheLabel = (k, v, label) => { if (label) labelCache.set(`${k}\u0000${v}`, String(label)); };
  // attack types get fixed, distinct colors (used for chips, intel bars and popups)
  const CLASS_COLOR = { "Botnet C2": "#5b8def", "Brute force": "#e2a336", "Scanning": "#12a594", "DDoS": "#d6409f",
    "Initial access": "#8e7cf0", "IP spoofing": "#c98a5e", "Spam": "#a1c45a", "Other": "#b0b4ba" };
  const classColor = (c) => CLASS_COLOR[c] || CLASS_COLOR.Other;
  // what the two ends of a communication are, per attack type
  const ROLES = {
    "Botnet C2": { src: "Infected host", dst: "Destination (C2 / sinkhole)" },
    "Brute force": { src: "Attacking host", dst: "Target (honeypot sensor)" },
    "Scanning": { src: "Scanning host", dst: "Target (honeypot sensor)" },
    "DDoS": { src: "Source", dst: "Attack target" },
    "Initial access": { src: "Compromised host", dst: "Destination" },
    "Spam": { src: "Spam sender", dst: "Hosted URL" },
    default: { src: "Source host", dst: "Destination" },
  };
  const srcLabel = (name) => state.facets?.source_labels?.[name] || name;

  // Short, factual notes for well-known families (shown in the detail view).
  const INFECTION_NOTES = {
    "android.badbox2": "BADBOX 2.0: backdoored, low-cost Android devices (TV boxes, tablets, projectors) enrolled in a botnet used for residential proxying and ad fraud.",
    "android.vo1d": "Vo1d: a botnet of compromised Android TV boxes with a backdoor that can download and run additional payloads.",
    "avalanche": "Avalanche: malware families tied to the Avalanche crimeware hosting network, dismantled in 2016. Its domains are sinkholed.",
    "bondat": "Bondat: a worm that spreads through removable drives and has been used for cryptocurrency mining.",
    "residential-proxy": "Residential proxy software: the device is relaying third-party traffic as a proxy exit node.",
    "netnut": "NetNut: a residential proxy network. The device is acting as a proxy exit node.",
    "android.vo1d2": "Vo1d: a botnet of compromised Android TV boxes with a backdoor that can download and run additional payloads.",
    "ssh-brute-force": "SSH brute force: this host repeatedly tried to log in to an SSH honeypot with guessed usernames and passwords.",
    "telnet-brute-force": "Telnet brute force: this host repeatedly tried to log in to a Telnet honeypot, typical of IoT botnets such as Mirai.",
    "http-scan": "HTTP scan: this host probed a web honeypot for vulnerable paths, a sign of automated exploitation tooling.",
    "smb-scan": "SMB scan: this host probed a honeypot over SMB (port 445), a technique used by worms and ransomware for lateral spread.",
    "rdp-scan": "RDP scan: this host probed a honeypot for Remote Desktop, often a precursor to credential attacks.",
    "ddos-participant": "DDoS participant: this host took part in a denial-of-service attack observed by a DDoS protection provider.",
    "ddos-amplification": "DDoS amplification: this host answered spoofed requests and amplified traffic toward a victim.",
  };

  // Knowledge base (data/infections.json via /api/infections) with the built-in notes above as fallback.
  let KB = {};
  async function loadKb() {
    try { const r = await fetch("/api/infections", { cache: "no-store" }); if (r.ok) KB = await r.json(); } catch { /* fallback only */ }
  }
  function kbEntry(...names) {
    for (const n of names) {
      if (!n) continue;
      const k = String(n).toLowerCase();
      if (KB[k]) return KB[k];
      if (INFECTION_NOTES[k]) return { description: INFECTION_NOTES[k], confidence: "medium", status: "reviewed" };
    }
    return null;
  }
  function renderKb(box, ...names) {
    box.replaceChildren();
    const e = kbEntry(...names);
    if (!e) {
      box.append(el("p", "kb-missing", "Not in the Looking Glass knowledge base yet. It will be listed by manage/infections_missing.py for definition."));
      kbLookups(box, names);
      return;
    }
    const head = el("div", "kb-head");
    if (e.title) head.append(el("b", null, e.title));
    if (e.type) head.append(el("span", "badge", e.type));
    if (e.confidence === "low" || e.status === "needs-review") head.append(el("span", "badge warn", "Unverified"));
    if (head.childNodes.length) box.append(head);
    if (e.description) box.append(el("p", "kb-desc", e.description));
    if (e.action) { const a = el("p", "kb-action"); a.append(el("b", null, "Recommended action: "), document.createTextNode(e.action)); box.append(a); }
    kbLookups(box, names);
  }
  // the infection name, and the report's tag when it names something else
  function kbLookups(box, names) {
    const [inf, tag] = names;
    malpediaButton(box, "infection", inf, inf ? `Look up ${inf} ${MP_SRC}` : undefined);
    if (tag && tag !== inf && !/^untagged$/i.test(tag)) malpediaButton(box, "tag", tag, `Look up tag ${tag} ${MP_SRC}`);
  }

  // ------------------------------------------------------------------ Malpedia: many names at once (each unique name once)
  async function mpBatch(names) {
    const uniq = [...new Set(names.filter(Boolean).map(String))], out = {};
    for (let i = 0; i < uniq.length; i += 80) {
      const r = await getJSON(`/api/malpedia/batch?values=${encodeURIComponent(uniq.slice(i, i + 80).join(","))}`);
      Object.assign(out, r.results || {});
    }
    return out;
  }
  function mpSummary(res) {           // e.g. "3 of 4 names found in Malpedia"
    const v = Object.values(res), f = v.filter((x) => x.found).length, c = v.filter((x) => x.curated).length;
    return `${f} of ${v.length} name${v.length === 1 ? "" : "s"} found in Malpedia${c ? `, ${c} defined by Looking Glass` : ""}${v.some((x) => x.pending) ? " (some not checked yet: try again in a minute)" : ""}`;
  }
  // references (evidence) written by an administrator in Settings
  function kbRefs(card, refs, label) {
    if (!refs?.length) return;
    const ul = el("ul", "mp-refs");
    for (const u of refs) { const li = el("li"); li.append(extLink(u, u.replace(/^https?:\/\//, "").slice(0, 90))); ul.append(li); }
    card.append(el("p", "mp-meta", label), ul);
  }
  function mpCard(x, name) {
    const card = el("div", "mp-card");
    const head = el("div", "mp-head");
    if (x.curated) {                                 // Malpedia has nothing, an administrator defined it (Settings)
      card.classList.add("mp-curated");
      head.append(el("span", "badge mp-badge mp-badge-kb", "Looking Glass definition"));
      head.append(el("b", null, name && name.toLowerCase() !== String(x.title).toLowerCase() ? `${name}: ${x.title}` : x.title)); card.append(head);
      if (x.type) card.append(el("p", "mp-meta", x.type));
      if (x.description) card.append(el("p", "mp-desc", x.description));
      if (x.seen_in?.length) card.append(el("p", "mp-meta", `Seen in: ${x.seen_in.join(", ")}`));
      kbRefs(card, x.references, `Evidence (${x.references.length} reference${x.references.length === 1 ? "" : "s"}):`);
      card.append(el("p", "mp-meta", `Not in Malpedia; defined${x.by ? ` by ${x.by}` : ""}${x.updated ? ` on ${x.updated}` : ""}.`));
      return card;
    }
    if (x.found && x.kind === "actor") {               // a threat actor (group), not a malware family
      card.classList.add("mp-actor");
      head.append(el("span", "badge mp-badge mp-badge-actor", "Malpedia · threat actor"));
      const t = el("b"); t.append(extLink(x.url, x.name)); head.append(t); card.append(head);
      card.append(el("p", "mp-meta", `"${name || x.name}" is the name of a threat actor (a group of attackers), not of a malware program.`
        + (x.matched_by ? ` Matched by ${x.matched_by}.` : "")));
      if (x.description) card.append(el("p", "mp-desc", x.description));
      if (x.alt_names?.length) card.append(el("p", "mp-meta", `Also known as: ${x.alt_names.join(", ")}`));
      const where = [x.country && `Suspected origin: ${x.country}`, x.sponsor && `suspected sponsor: ${x.sponsor}`].filter(Boolean).join(" · ");
      if (where) card.append(el("p", "mp-meta", where));
      if (x.targets?.length) card.append(el("p", "mp-meta", `Targets: ${x.targets.join(", ")}`));
      if (x.sectors?.length) card.append(el("p", "mp-meta", `Sectors: ${x.sectors.join(", ")}`));
      if (x.families?.length) card.append(el("p", "mp-meta", `Malware it uses: ${x.families.join(", ")}`));
      if (x.references?.length) kbRefs(card, x.references, `References (${fmt(x.reference_count || x.references.length)}):`);
      kbRefs(card, x.curated_references, "Looking Glass references:");
      return card;
    }
    if (x.found) {
      head.append(el("span", "badge mp-badge", "Malpedia"));
      const t = el("b"); t.append(extLink(x.url, `${x.name} (${x.family})`)); head.append(t); card.append(head);
      if (name && name.toLowerCase() !== String(x.name).toLowerCase()) card.append(el("p", "mp-meta", `Reported by Shadowserver as "${name}".`));
      if (x.matched_by) card.append(el("p", "mp-meta", `Matched by ${x.matched_by}.`));
      if (x.description) card.append(el("p", "mp-desc", x.description));
      if (x.alt_names?.length) card.append(el("p", "mp-meta", `Also known as: ${x.alt_names.join(", ")}`));
      if (x.attribution?.length) card.append(el("p", "mp-meta", `Attributed to: ${x.attribution.join(", ")}`));
      if (x.updated) card.append(el("p", "mp-meta", `Updated ${x.updated}`));
      if (x.references?.length) {
        const ul = el("ul", "mp-refs");
        for (const u of x.references) { const li = el("li"); li.append(extLink(u, u.replace(/^https?:\/\//, "").slice(0, 90))); ul.append(li); }
        card.append(el("p", "mp-meta", `References (${fmt(x.reference_count || x.references.length)}):`), ul);
      }
      kbRefs(card, x.curated_references, "Looking Glass references:");
    } else {
      head.append(el("span", "badge mp-badge mp-badge-no", x.offline ? "No definition yet" : "Not in Malpedia"));
      head.append(el("b", null, name ? `${name}: ${x.title || "not found"}` : x.title || "Not found")); card.append(head);
      if (x.text) card.append(el("p", "mp-desc", x.text));
      if (x.seen_in?.length) card.append(el("p", "mp-meta", `Seen in: ${x.seen_in.join(", ")}`));
      if (x.pending) card.append(el("p", "mp-meta", "Not checked yet (Malpedia allows a limited number of look-ups per minute): try again in a minute."));
      if (x.near?.length) card.append(el("p", "mp-meta", `Similar names in Malpedia: ${x.near.join(", ")}`));
    }
    return card;
  }
  function mpShort(x) { return x.found && x.kind === "actor" ? `${x.name} (threat actor)` : x.found ? `${x.name} (${x.family})` : x.curated ? `${x.title} (Looking Glass definition)` : (x.title || "not in Malpedia"); }
  function renderMpList(box, res) {
    const list = el("div", "mp-cards");
    for (const [name, x] of Object.entries(res).sort((a, b) => Number(b[1].found) - Number(a[1].found) || a[0].localeCompare(b[0]))) list.append(mpCard(x, name));
    box.append(list);
  }
  // a host (clicked IP): all of its infections / categories at once
  function renderHostMalpedia(box, names) {
    box.replaceChildren();
    if (!MP_ON || !names.length) return;
    const wrap = el("div", "mp-host");
    const btn = el("button", "pill-btn mp-btn", `Look up this host's ${names.length} infection${names.length === 1 ? "" : "s"} / categor${names.length === 1 ? "y" : "ies"} ${MP_SRC}`);
    btn.type = "button";
    btn.addEventListener("click", async () => {
      btn.disabled = true; btn.textContent = "Looking up on Malpedia…";
      try {
        const res = names.length > 3 ? await window.LGLookup.run({ kind: "malpedia", values: names, title: `Looking up this host's ${names.length} infections`,
          intro: CFG.malpedia ? "Each name is looked up on Malpedia once (answers kept a week)." : "Answered from the Looking Glass definitions." })
          : await mpBatch(names);
        wrap.replaceChildren(el("div", "mp-head", mpSummary(res))); renderMpList(wrap, res);
      } catch (err) { btn.disabled = false; btn.textContent = `Malpedia lookup failed: ${err.message} (click to retry)`; }
    });
    wrap.append(btn); box.append(wrap);
  }

  // ------------------------------------------------------------------ Malpedia lookups (server side, token never in the page)
  function malpediaButton(box, field, value, label) {
    if (!value || !MP_ON) return null;
    const wrap = el("div", "mp");
    const btn = el("button", "pill-btn mp-btn", label || "Look up on Malpedia");
    btn.type = "button";
    btn.title = `Search Malpedia, the malware encyclopedia, for "${value}"`;
    btn.addEventListener("click", (ev) => { ev.stopPropagation(); loadMalpedia(wrap, field, value); });
    wrap.append(btn); box.append(wrap);
    return wrap;
  }
  async function loadMalpedia(wrap, field, value) {
    wrap.replaceChildren(el("div", "mp-loading", "Looking up on Malpedia…"));
    let r;
    try { r = await getJSON(`/api/malpedia?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`); }
    catch (err) { wrap.replaceChildren(el("p", "mp-err", `Malpedia lookup failed: ${err.message}`)); return; }
    renderMalpedia(wrap, r, value);
  }
  // links from Malpedia (third-party data): only http(s) becomes a link, anything else (javascript:, data:...) is plain text
  const extLink = (href, text) => {
    let ok = false; try { ok = ["http:", "https:"].includes(new URL(href).protocol); } catch { ok = false; }
    if (!ok) return el("span", null, text);
    const a = el("a", null, text); a.href = href; a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
  };
  function renderMalpedia(wrap, r, value) {
    wrap.replaceChildren();
    const card = el("div", "mp-card");
    const head = el("div", "mp-head"); head.append(el("span", "badge mp-badge", "Malpedia"));
    if (r.kind === "sample") {
      head.append(el("b", null, r.found ? "Sample known to Malpedia" : "Sample not in Malpedia"));
      card.append(head, el("p", "mp-desc mono", r.hash));
      if (r.found && r.info) {
        const info = r.info, fam = info.family || info.families || "";
        if (fam) card.append(el("p", "mp-meta", `Family: ${Array.isArray(fam) ? fam.join(", ") : fam}`));
        if (info.status) card.append(el("p", "mp-meta", `Status: ${info.status}`));
      }
      wrap.append(card); return;
    }
    const f = r.family;
    if (!f && r.curated) { wrap.append(mpCard(r.curated, value)); return; }
    if (!f && r.actor_card) { wrap.append(mpCard(r.actor_card, value)); return; }
    if (!f && r.explain) {                         // not malware, or not listed: say what it is, plainly
      wrap.append(mpCard({ found: false, ...r.explain, near: (r.matches || []).slice(0, 3).map((m) => m.id) }, value));
      return;
    }
    if (!f) {
      head.append(el("b", null, `No Malpedia family found for "${value}"`));
      card.append(head);
    } else {
      const t = el("b"); t.append(extLink(f.url, `${f.name} (${f.id})`)); head.append(t);
      card.append(head);
      const m = (r.matches || [])[0];
      if (m && m.matched_by && m.matched_by !== "chosen") card.append(el("p", "mp-meta", `Matched by ${m.matched_by}.`));
      if (f.description) card.append(el("p", "mp-desc", f.description));
      const meta = [];
      if (f.alt_names.length) meta.push(`Also known as: ${f.alt_names.join(", ")}`);
      if (f.attribution.length) meta.push(`Attributed to: ${f.attribution.join(", ")}`);
      const yr = Object.entries(f.yara || {}).map(([k, v]) => `${v} ${k}`).join(", ");
      if (yr) meta.push(`YARA rules: ${yr}`);
      if (f.updated) meta.push(`Updated ${f.updated}`);
      for (const line of meta) card.append(el("p", "mp-meta", line));
      if (f.references.length) {
        const ul = el("ul", "mp-refs");
        for (const u of f.references.slice(0, 6)) { const li = el("li"); li.append(extLink(u, u.replace(/^https?:\/\//, "").slice(0, 90))); ul.append(li); }
        card.append(el("p", "mp-meta", `References (${fmt(f.reference_count)}):`), ul);
      }
      kbRefs(card, r.curated_references, "Looking Glass references:");
    }
    const others = (r.matches || []).filter((m) => !f || m.id !== f.id);
    if (others.length) {
      const row = el("div", "mp-others"); row.append(el("span", "mp-meta", f ? "Other possible matches:" : "Possible matches:"));
      for (const m of others) {
        const b = el("button", "pill-btn", m.id); b.type = "button"; b.title = `Matched by ${m.matched_by}`;
        b.addEventListener("click", (ev) => { ev.stopPropagation(); loadMalpedia(wrap, "family", m.id); });
        row.append(b);
      }
      card.append(row);
    }
    wrap.append(card);
  }

  // ------------------------------------------------------------------ helpers
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
  const fmt = (n) => Math.round(n).toLocaleString("en-US");
  const titleCase = (s) => (s || "").toLowerCase().replace(/(^|[\s-])\w/g, (c) => c.toUpperCase());
  const regionNames = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch { return null; } })();
  const countryName = (cc) => { if (!cc) return "Unknown"; if (cc === "EU") return "Europe"; try { return regionNames ? regionNames.of(cc.toUpperCase()) : cc; } catch { return cc; } };
  const flagUrl = (cc) => (cc && /^[a-z]{2}$/i.test(cc) && cc !== "EU" ? `https://flagcdn.com/w40/${cc.toLowerCase()}.png` : "");
  const flagImg = (cc) => { const i = el("img", "flag"); i.alt = ""; const u = flagUrl(cc); if (u) { i.src = u; i.loading = "lazy"; } else i.style.visibility = "hidden"; return i; };
  const hexRgb = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
  const sevColor = (s) => SEV[s] || SEV.info;
  const infName = (ev) => ev.infection || ev.family || ev.tag || "unknown";
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
  };

  // ------------------------------------------------------------------ state
  const state = {
    anchorWall: Date.now(), anchorReplay: Date.now(), speed: 1,
    cursor: null, generation: 0,
    pending: [], active: [], popups: [],
    events: new Map(),                 // id -> event (recent, for lookups)
    rowsById: new Map(),               // id -> <li>
    pins: new Map(store.get("tm.pins", []).map((e) => [e.id, e])),
    infColors: new Map(),
    facets: null, stats: null,
    filters: { source: new Set(), attack_class: new Set(), infection: new Set(), severity: new Set(), protocol: new Set(),
      src_city: "", dst_geo: "", tag: "", dst_port: "", http_host: "", src_ip: "",
      src_asn: "", dst_asn: "", dst_ip: "", dst_city: "", src_geo: "", http_agent: "", request: "" },
    liveAdded: 0, liveCritical: 0, recentRate: [],   // [replayMs, weight]
    buffer: [], paused: false, pauseAt: 0, pauseReplay: 0, behind: false, autoPaused: false,
    // replay schedule from the server: playing | waiting (report not in yet) | settling (report arriving)
    schedState: null, replayDay: null, dayStart: 0, dayEnd: 0, waiting: false, sched: null, lastSync: 0,
    hoverId: null, flashId: null, flashUntil: 0,
    cinema: !reducedMotion && !LITE, interacting: false, lite: LITE,
    demo: store.get("tm.demo", false), demoForced: false,
    modalEv: null,
  };
  // while paused the replay clock stands still at the moment Pause was pressed
  // while waiting for a report the replay holds at 00:00; at Speed 1x it never runs past the end of its day
  const replayNow = () => {
    if (state.paused) return state.pauseReplay;
    if (state.waiting) return state.anchorReplay;
    const r = state.anchorReplay + (Date.now() - state.anchorWall) * state.speed;
    return state.speed === 1 && state.dayEnd ? Math.min(r, state.dayEnd - 1) : r;
  };
  const wallFor = (replayMs) => state.anchorWall + (replayMs - state.anchorReplay) / state.speed;

  function infColor(name) {
    const k = name || "unknown";
    if (!state.infColors.has(k)) state.infColors.set(k, PALETTE[state.infColors.size % PALETTE.length]);
    return state.infColors.get(k);
  }

  // ------------------------------------------------------------------ geo
  const toRad = (d) => (d * Math.PI) / 180, toDeg = (r) => (r * 180) / Math.PI;
  function arcPath(a, b, n = ARC_POINTS) {
    const [l1, p1, l2, p2] = [toRad(a[0]), toRad(a[1]), toRad(b[0]), toRad(b[1])];
    const d = 2 * Math.asin(Math.sqrt(Math.sin((p2 - p1) / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin((l2 - l1) / 2) ** 2));
    if (!d) return [[...a, 0], [...b, 0]];
    const height = Math.min(1600000, d * 6371000 * 0.22);
    const pts = [];
    let prev = null;
    for (let i = 0; i <= n; i++) {
      const f = i / n, A = Math.sin((1 - f) * d) / Math.sin(d), B = Math.sin(f * d) / Math.sin(d);
      const x = A * Math.cos(p1) * Math.cos(l1) + B * Math.cos(p2) * Math.cos(l2);
      const y = A * Math.cos(p1) * Math.sin(l1) + B * Math.cos(p2) * Math.sin(l2);
      const z = A * Math.sin(p1) + B * Math.sin(p2);
      let lon = toDeg(Math.atan2(y, x));
      if (prev !== null) { while (lon - prev > 180) lon -= 360; while (lon - prev < -180) lon += 360; }
      prev = lon;
      pts.push([lon, toDeg(Math.atan2(z, Math.sqrt(x * x + y * y))), Math.sin(Math.PI * f) * height]);
    }
    return pts;
  }
  const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2);

  // ------------------------------------------------------------------ map + deck
  if (!window.mapboxgl || !window.deck) { toast("Map libraries failed to load. Check the network connection."); return; }
  mapboxgl.accessToken = CFG.mapboxToken;
  const map = new mapboxgl.Map({
    container: "map",
    style: "mapbox://styles/mapbox/satellite-streets-v12",
    projection: "mercator",
    center: [-30, 30], zoom: isPhone() ? 1.1 : 2.1, pitch: LITE ? 0 : isPhone() ? 30 : 48, bearing: LITE ? 0 : -8,
    antialias: P.antialias, attributionControl: true, maxPitch: 70,
    // Lite: draw at 1 pixel per CSS pixel (a 4K TV otherwise renders four times the pixels) and skip fades
    pixelRatio: P.pixelRatio, fadeDuration: LITE ? 0 : 300,
  });
  map.addControl(new mapboxgl.NavigationControl({ visualizePitch: true }), "bottom-right");
  const overlay = new deck.MapboxOverlay({
    interleaved: false,
    useDevicePixels: LITE ? 1 : true,
    layers: [],
    pickingRadius: isPhone() ? 12 : 6,
    onClick: (info) => {
      const id = info.layer && info.layer.id;
      // whole-day layer: a source place opens its city analysis, a destination its country analysis
      const o = info.object;
      // the map shows the filtered day, so these open within the active filters too
      if (id === "all-src" && o && o.key) return openScoped("src_city", o.key);
      if (id === "all-dst" && o) return o.key ? openScoped("dst_place", `${o.key}|${o.cc}`) : o.cc ? openScoped("dst_geo", o.cc) : null;
      if (id === "all-flows" && o) return openScoped("route", `${o.src_name.key}|${o.src_name.cc}>${o.dst_name.key}|${o.dst_name.cc}`);
      const ev = info.object && (info.object.ev || info.object); if (ev && ev.id) openModal(state.events.get(ev.id) || ev);
    },
    getCursor: ({ isHovering, isDragging }) => (isDragging ? "grabbing" : isHovering ? "pointer" : "grab"),
  });
  map.addControl(overlay);
  if (new URLSearchParams(location.search).has("debug")) window.__lg = { map, overlay };   // for testing only

  // Map hover: deck.gl only starts its own hover handling after the map has been dragged once, so tooltips
  // were missing on a fresh page. We pick under the pointer ourselves on every mouse move (at most ~30
  // times a second) and show the shared tooltip, so hover works straight away.
  let mapPt = null, mapEvt = null, pickTimer = null;
  function mapHoverPick() {
    pickTimer = null;
    if (!mapPt) return;
    let p = null;
    try { p = overlay.pickObject({ x: mapPt.x, y: mapPt.y, radius: isPhone() ? 12 : 6 }); } catch { p = null; }
    const o = p && p.object;
    const ev = o && (o.ev || o);
    state.hoverId = ev && ev.id ? ev.id : null;
    const t = p && geoTooltip(o, p.layer);
    if (t) { const box = el("div", "map-tip"); box.innerHTML = t.html; showTip(mapEvt, [box]); } else hideTip();
    map.getCanvas().style.cursor = t ? "pointer" : "";
  }
  map.on("mousemove", (e) => { mapPt = e.point; mapEvt = e.originalEvent; if (!pickTimer) pickTimer = setTimeout(mapHoverPick, 33); });
  map.on("mouseout", () => { mapPt = null; state.hoverId = null; hideTip(); map.getCanvas().style.cursor = ""; });
  map.on("movestart", () => { if (state.interacting) hideTip(); });

  map.on("style.load", () => {
    try {
      map.setPaintProperty("satellite", "raster-brightness-max", 0.55);
      map.setPaintProperty("satellite", "raster-saturation", -0.55);
      map.setPaintProperty("satellite", "raster-contrast", 0.08);
    } catch { /* layer names differ */ }
    if (P.fog) map.setFog({ color: "rgb(8,14,24)", "high-color": "rgb(14,40,80)", "horizon-blend": 0.08, "space-color": "rgb(2,4,8)", "star-intensity": 0.5 });
    fitDefault(false);
    requestAnimationFrame(frame);
  });
  function fitDefault(animate = true) {
    const css = getComputedStyle(document.documentElement);
    const px = (v) => parseFloat(css.getPropertyValue(v)) || 0;
    const g = px("--gutter");
    const pad = { top: px("--hud-h") + g * 3, bottom: px("--stream-h") + g * 3, left: px("--left-w") + g * 3, right: px("--right-w") + g * 3 };
    const vw = window.innerWidth, vh = window.innerHeight;
    if (vw - pad.left - pad.right < 160 || vh - pad.top - pad.bottom < 120) { pad.left = pad.right = 10; pad.top = 40; pad.bottom = 40; }
    // the Americas to Europe (where most sinkholes and attackers are), widened to take in the country set in Settings
    const c = state.countryBox, w = Math.min(-125, c ? c[0] : -125), s = Math.min(-2, c ? c[1] : -2), e = Math.max(32, c ? c[2] : 32);
    map.fitBounds([[w, s], [e, 60]], { padding: pad, pitch: state.lite ? 0 : isPhone() ? 30 : 48, bearing: state.lite ? 0 : -8, duration: animate && !state.lite ? 1800 : 0 });
  }
  function markInteract() { state.interacting = true; clearTimeout(map._tmI); map._tmI = setTimeout(() => { state.interacting = false; }, 6000); }
  for (const e of ["mousedown", "touchstart", "wheel", "dragstart"]) map.on(e, markInteract);
  // the zoom / compass buttons are not part of the map canvas, so map events don't see them
  map.getContainer().addEventListener("pointerdown", (e) => { if (e.target.closest(".mapboxgl-ctrl")) markInteract(); }, true);

  // ------------------------------------------------------------------ automatic Lite switch
  // In Auto, if the map keeps running below ~22 frames per second (two 5-second checks in a row, after the
  // first 10 seconds of loading), switch to Lite and remember it for this device.
  let pwStart = 0, pwFrames = 0, pwSlow = 0;
  const pwBegin = performance.now() + 10000;
  function perfWatch(ts) {
    if (state.lite || perfChoice !== "auto" || document.hidden || state.paused) { pwStart = 0; return; }
    if (ts < pwBegin) return;
    if (!pwStart) { pwStart = ts; pwFrames = 0; return; }
    pwFrames++;
    if (ts - pwStart < 5000) return;
    const fps = (pwFrames * 1000) / (ts - pwStart);
    pwSlow = fps < 22 ? pwSlow + 1 : 0;
    pwStart = ts; pwFrames = 0;
    if (pwSlow >= 2) {
      lsSet(PERF_AUTO_KEY, "1");
      applyLite();
      toast(`This screen was drawing slowly (${Math.round(fps)} frames per second), so Looking Glass switched to Lite display for smoother playback. You can change it under Filters > Display.`);
    }
  }
  function applyLite() {
    // switch now; the lower pixel density for the map also applies from the next page load
    state.lite = true; document.documentElement.classList.add("lite");
    Object.assign(P, { frameMs: 66, maxActive: 40, glow: false, trails: false, srcPulse: false, fog: false });
    state.cinema = false; $("btnCinema").setAttribute("aria-pressed", "false");
    try { map.setFog(null); } catch { /* style not ready */ }
    map.easeTo({ pitch: 0, bearing: 0, duration: 0 });
    state.active = state.active.slice(-P.maxActive);
    renderPerfUi();
  }
  function renderPerfUi() { D.render(state.lite); }   // every Display switch on the page (map drawer and intro)

  // ------------------------------------------------------------------ animation loop
  let lastPaint = 0, cinemaT = 0, lastTs = performance.now(), baseBearing = LITE ? 0 : -8;
  function frame(ts) {
    const dt = Math.min(100, ts - lastTs); lastTs = ts;
    perfWatch(ts);
    // paused: time stands still, so arcs freeze in place and nothing new is launched
    const now = state.paused ? state.pauseAt : Date.now();
    while (!state.paused && state.pending.length && state.pending[0].wall <= now) {
      const p = state.pending.shift();
      if (p.gen !== state.generation) continue;
      // late (for example after the browser throttled the page): still list it in the stream, just don't animate it
      if (now - p.wall > 15000) { remember(p.ev); countEvent(p.ev, p.weight); addRow(p.ev, true); continue; }
      launch(p.ev, p.weight, now);
    }
    // the slow cinema rotation must never fight a camera animation (zoom buttons, fly-to), or it cancels it
    const cameraBusy = map.isEasing() || map.isZooming() || map.isRotating() || map.isMoving();
    if (state.cinema && !state.interacting && !state.paused && !cameraBusy) {
      cinemaT += dt / 1000;
      map.setBearing(baseBearing + Math.sin(cinemaT / 14) * 10);
    } else if (!state.cinema) baseBearing = map.getBearing();
    if (ts - lastPaint > P.frameMs) { paint(now); lastPaint = ts; if (state.lite) positionPopups(now); }
    if (!state.lite) positionPopups(now);
    requestAnimationFrame(frame);
  }

  function activeWallMs() { return Math.max(ACTIVE_MIN_WALL, ACTIVE_REPLAY_MS / state.speed); }

  function launch(ev, weight, now, opts = {}) {
    remember(ev);
    countEvent(ev, weight);
    const color = infColor(infName(ev));
    if (state.active.length < maxActive()) {
      const path = ev.src_coords && ev.dst_coords ? arcPath(ev.src_coords, ev.dst_coords) : null;
      const start = opts.start ?? now;
      state.active.push({ ev, rgb: hexRgb(color), path, start, life: activeWallMs(), phase: Math.random() * 0.25 });
      const row = state.rowsById.get(ev.id); if (row) row.classList.add("live");
    }
    // no popups on the map any more: hovering any drawing explains it, and clicking analyses it
    if (!opts.silent) addRow(ev, true);
  }

  function paint(now) {
    const arcs = [], tails = [], heads = [], rings = [], srcDots = [], dstDots = [];
    const keep = [];
    for (const a of state.active) {
      const age = now - a.start;
      if (age > a.life) { const r = state.rowsById.get(a.ev.id); if (r) r.classList.remove("live"); continue; }
      keep.push(a);
      const fadeIn = Math.min(1, age / 400), fadeOut = Math.min(1, (a.life - age) / 2500), alpha = fadeIn * fadeOut;
      const hot = a.ev.id === state.hoverId || (a.ev.id === state.flashId && now < state.flashUntil);
      if (a.path) {
        const n = a.path.length - 1;
        // packet position: first flight eased, then periodic re-fires
        let t, fired;
        if (age < TRAVEL_MS) { t = ease(age / TRAVEL_MS); fired = false; }
        else { const k = ((age - TRAVEL_MS) / LOOP_MS + a.phase) % 1; t = Math.min(1, k * 1.6); fired = true; }
        const drawn = fired ? n : Math.max(1, Math.round(t * n));
        arcs.push({ ev: a.ev, path: drawn >= n ? a.path : a.path.slice(0, drawn + 1), color: [...a.rgb, (hot ? 235 : P.glow ? 105 : 150) * alpha], w: hot ? 2.6 : P.glow ? 1.2 : 1.6 });
        if (t < 1 && !P.trails) {
          const hi = Math.max(1, Math.round(t * n));
          heads.push({ ev: a.ev, path: a.path.slice(Math.max(0, hi - 2), hi + 1), color: [245, 247, 250, 230 * alpha] });
        } else if (t < 1) {
          const hi = Math.max(1, Math.round(t * n));
          tails.push({ ev: a.ev, path: a.path.slice(Math.max(0, hi - 12), hi + 1), color: [...a.rgb, 210 * alpha] });
          heads.push({ ev: a.ev, path: a.path.slice(Math.max(0, hi - 2), hi + 1), color: [245, 247, 250, 230 * alpha] });
        } else {
          // impact ring right after each arrival
          const since = fired ? (((age - TRAVEL_MS) / LOOP_MS + a.phase) % 1 - 1 / 1.6) / (1 - 1 / 1.6) : 0;
          if (since >= 0 && since <= 1) rings.push({ ev: a.ev, pos: a.ev.dst_coords, r: 3 + 22 * since, color: [...a.rgb, 255 * (1 - since) * alpha] });
        }
        if (P.glow && age >= TRAVEL_MS && age < TRAVEL_MS + 900) { const s = (age - TRAVEL_MS) / 900; rings.push({ ev: a.ev, pos: a.ev.dst_coords, r: 4 + 34 * s, color: [255, 255, 255, 200 * (1 - s) * alpha] }); }
        dstDots.push({ ev: a.ev, pos: a.ev.dst_coords, color: [...a.rgb, 255 * alpha], r: hot ? 6 : 3.5 });
      }
      const sp = a.ev.src_coords || a.ev.dst_coords;
      if (sp) {
        const pulse = (age % 1800) / 1800;
        srcDots.push({ ev: a.ev, pos: sp, color: [...a.rgb, 255 * alpha], r: hot ? 6 : 3.5 });
        if (P.srcPulse) rings.push({ ev: a.ev, pos: sp, r: 4 + 12 * pulse, color: [...a.rgb, 170 * (1 - pulse) * alpha] });
      }
    }
    state.active = keep;

    // pinned communications stay drawn
    const pinned = [];
    if (!state.demo) for (const ev of state.pins.values()) if (ev.src_coords && ev.dst_coords && matchesFilters(ev)) pinned.push({ ev, path: ev._path || (ev._path = arcPath(ev.src_coords, ev.dst_coords)) });

    overlay.setProps({ layers: [
      ...geoLayers(),
      new deck.PathLayer({ id: "pinned", data: pinned, getPath: (d) => d.path, getColor: [158, 140, 252, 210], getWidth: 2.2, widthUnits: "pixels", capRounded: true, jointRounded: true, pickable: true,
        getDashArray: [6, 4], dashJustified: true, extensions: deck.PathStyleExtension ? [new deck.PathStyleExtension({ dash: true })] : [] }),
      // Lite: no glow halo (it doubles the line work); trails are skipped above
      new deck.PathLayer({ id: "arcs-glow", data: P.glow ? arcs : [], visible: P.glow, getPath: (d) => d.path, getColor: (d) => [d.color[0], d.color[1], d.color[2], d.color[3] * 0.18], getWidth: (d) => d.w * 3.5, widthUnits: "pixels", capRounded: true, jointRounded: true }),
      new deck.PathLayer({ id: "arcs", data: arcs, getPath: (d) => d.path, getColor: (d) => d.color, getWidth: (d) => d.w, widthUnits: "pixels", capRounded: true, jointRounded: true, pickable: true }),
      new deck.PathLayer({ id: "tails", data: tails, getPath: (d) => d.path, getColor: (d) => d.color, getWidth: 3, widthUnits: "pixels", capRounded: true, jointRounded: true }),
      new deck.PathLayer({ id: "heads", data: heads, getPath: (d) => d.path, getColor: (d) => d.color, getWidth: 4.5, widthUnits: "pixels", capRounded: true, jointRounded: true }),
      new deck.ScatterplotLayer({ id: "rings", data: rings, getPosition: (d) => d.pos, getRadius: (d) => d.r, radiusUnits: "pixels", stroked: true, filled: false, getLineColor: (d) => d.color, getLineWidth: 1.5, lineWidthUnits: "pixels" }),
      new deck.ScatterplotLayer({ id: "dst", data: dstDots, getPosition: (d) => d.pos, getRadius: (d) => d.r, radiusUnits: "pixels", getFillColor: (d) => d.color, pickable: true }),
      new deck.ScatterplotLayer({ id: "src", data: srcDots, getPosition: (d) => d.pos, getRadius: (d) => d.r, radiusUnits: "pixels", getFillColor: (d) => d.color, stroked: true, getLineColor: [11, 11, 13, 200], getLineWidth: 1, lineWidthUnits: "pixels", pickable: true }),
    ] });
  }

  // ------------------------------------------------------------------ whole-day connections layer
  // The animated arcs only show what is playing right now. Underneath, every source place, destination and
  // source -> destination connection of the whole day (with the active filters) stays drawn, sized by count,
  // so the map always shows everything and a filter narrows it instead of moving it elsewhere.
  let geoCache = null;           // the layers, rebuilt only when the data changes
  const flowPaths = new Map();   // "lon,lat>lon,lat" -> arc path
  state.showAll = lsGet("lg.allFlows") !== "0";
  function geoLayers() { return state.showAll && geoCache ? geoCache : []; }
  function buildGeoLayers(g) {
    if (!g) { geoCache = null; return; }
    const maxF = Math.max(1, ...g.flows.map((f) => f.count));
    const maxS = Math.max(1, ...g.sources.map((s) => s.count));
    const maxD = Math.max(1, ...g.destinations.map((d) => d.count));
    const lw = (c, m) => 0.6 + 2.4 * (Math.log10(c + 1) / Math.log10(m + 1));
    for (const f of g.flows) {
      const k = `${f.src}>${f.dst}`;
      if (!flowPaths.has(k)) flowPaths.set(k, arcPath(f.src, f.dst, Math.max(16, Math.round(ARC_POINTS / 2))));
      f.path = flowPaths.get(k); f.rgb = hexRgb(classColor(f.class)); f.w = lw(f.count, maxF);
    }
    for (const s of g.sources) { s.rgb = hexRgb(classColor(s.class)); s.r = 3 + 9 * Math.sqrt(s.count / maxS); }
    for (const d of g.destinations) d.r = 2.5 + 8 * Math.sqrt(d.count / maxD);
    const a = state.lite ? 80 : 60;
    geoCache = [
      new deck.PathLayer({ id: "all-flows", data: g.flows, getPath: (f) => f.path, getColor: (f) => [...f.rgb, a], getWidth: (f) => f.w,
        widthUnits: "pixels", capRounded: true, pickable: true, autoHighlight: true, highlightColor: [255, 255, 255, 120] }),
      new deck.ScatterplotLayer({ id: "all-dst", data: g.destinations, getPosition: (d) => d.pos, getRadius: (d) => d.r, radiusUnits: "pixels",
        getFillColor: [237, 237, 239, 40], stroked: true, getLineColor: [237, 237, 239, 150], getLineWidth: 1, lineWidthUnits: "pixels",
        pickable: true, autoHighlight: true, highlightColor: [255, 255, 255, 90] }),
      new deck.ScatterplotLayer({ id: "all-src", data: g.sources, getPosition: (s) => s.pos, getRadius: (s) => s.r, radiusUnits: "pixels",
        getFillColor: (s) => [...s.rgb, 90], stroked: true, getLineColor: (s) => [...s.rgb, 220], getLineWidth: 1, lineWidthUnits: "pixels",
        pickable: true, autoHighlight: true, highlightColor: [255, 255, 255, 90] }),
    ];
  }
  const placeName = (p) => [p.city, p.region, countryName(p.cc)].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(", ") || "Unknown place";
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const CLICK_HINT = '<div class="tt-hint">Click to analyse</div>';
  // hover text for everything drawn on the map; every drawing can be clicked
  function geoTooltip(o, layer) {
    if (!o || !layer) return null;
    const id = String(layer.id), day = state.geo ? state.geo.day : "";
    let html = null;
    const n = (v, w) => `${fmt(v)} ${w}${v === 1 ? "" : "s"}`;
    if (id === "all-flows") html = `<b>${esc(placeName(o.src_name))} → ${esc(placeName(o.dst_name))}</b><br>${n(o.count, "event")} on ${day} · mostly ${esc(o.class)}${CLICK_HINT}`;
    else if (id === "all-src") html = `<b>${esc(placeName(o))}</b> · source<br>${n(o.count, "event")} from ${n(o.hosts, "host")} on ${day} · mostly ${esc(o.class)}${CLICK_HINT}`;
    else if (id === "all-dst") html = `<b>${esc(placeName(o))}</b> · destination<br>${n(o.count, "event")} on ${day} · mostly ${esc(o.class)}${CLICK_HINT}`;
    else if (o.ev && ["arcs", "src", "dst", "pinned"].includes(id)) {
      // a live (or pinned) event: replaces the old popups
      const ev = o.ev, t = (ev.extracted_date || "").replace("T", " ").slice(0, 19);
      const from = [titleCase(ev.src_city), countryName(ev.src_geo)].filter(Boolean).join(", ");
      const to = [titleCase(ev.dst_city), ev.dst_geo ? countryName(ev.dst_geo) : ""].filter(Boolean).join(", ") || "unknown destination";
      const fromTxt = ev.src_ip || from ? `${esc(ev.src_ip || "")}${from ? ` (${esc(from)})` : ""}` : "source not reported";
      html = `<b>${esc(infName(ev))}</b> · ${esc(ev.attack_class || "")}<br>${fromTxt} → ${ev.dst_ip && !ev.src_ip ? esc(ev.dst_ip) + " " : ""}${esc(to)}${ev.dst_port ? ":" + esc(ev.dst_port) : ""}<br>${t} UTC`
        + '<div class="tt-hint">Click for the full details and analysis</div>';
    }
    return html ? { html } : null;
  }
  let geoBusy = false;
  async function loadGeo(fit) {
    // never skip a load (a filter change during a load used to keep the old map for up to a minute);
    // instead the newest request wins and older replies are dropped
    const my = loadGeo.seq = (loadGeo.seq || 0) + 1;
    geoBusy = true;
    try {
      const p = filterParams(); p.set("at", new Date(replayNow()).toISOString());
      const g = await getJSON(`/api/geo?${p}`);
      if (my !== loadGeo.seq) return;
      state.geo = g; buildGeoLayers(g);
      if (fit) fitToGeo(g);
    } catch { /* keep the previous layer */ }
    finally { geoBusy = false; }
  }
  // after a filter change, bring every matching place into view if some are off screen
  function fitToGeo(g) {
    const pts = [...g.sources, ...g.destinations].map((x) => x.pos);
    if (!pts.length) return;
    const b = map.getBounds();
    if (pts.every((p) => b.contains(p))) return;
    const lons = pts.map((p) => p[0]), lats = pts.map((p) => p[1]);
    const css = getComputedStyle(document.documentElement), px = (v) => parseFloat(css.getPropertyValue(v)) || 0, gt = px("--gutter");
    const pad = { top: px("--hud-h") + gt * 4, bottom: px("--stream-h") + gt * 4, left: px("--left-w") + gt * 4, right: px("--right-w") + gt * 4 };
    if (window.innerWidth - pad.left - pad.right < 160 || window.innerHeight - pad.top - pad.bottom < 120) { pad.left = pad.right = 20; pad.top = pad.bottom = 60; }
    try { map.fitBounds([[Math.min(...lons), Math.min(...lats)], [Math.max(...lons), Math.max(...lats)]], { padding: pad, maxZoom: 6, duration: state.lite ? 0 : 1200 }); } catch { /* bounds too small */ }
  }

  // ------------------------------------------------------------------ popups on the map
  function maybePopup(ev, color, now) {
    if (document.hidden) return;
    const pos = ev.src_coords || ev.dst_coords;
    if (!pos) return;
    while (state.popups.length >= MAX_POPUPS) dropPopup(state.popups[0]);
    const node = el("div", "popup");
    node.style.setProperty("--pc", color);
    const top = el("div", "p-inf"); const dot = el("span", "sevdot"); dot.style.background = sevColor(ev.severity);
    top.append(dot, el("span", null, infName(ev)));
    const sub = el("div", "p-sub", `${ev.attack_class} · ${ev.src_ip || ev.src_geo} → ${ev.dst_geo || "?"}${ev.dst_port ? ":" + ev.dst_port : ""}`);
    node.append(top, sub);
    node.addEventListener("click", () => openModal(ev));
    $("popups").append(node);
    // fan popups out so concurrent ones around the same city don't stack
    const slot = state.popups.length;
    const ang = (slot / MAX_POPUPS) * Math.PI * 2 + Math.random() * 0.6;
    const rad = isPhone() ? 26 + (slot % 3) * 16 : 30 + (slot % 3) * 28;
    state.popups.push({ node, pos, born: now, dx: Math.cos(ang) * rad * 1.6, dy: Math.sin(ang) * rad - 10 });
  }
  function dropPopup(p) {
    state.popups = state.popups.filter((x) => x !== p);
    p.node.classList.add("out");
    setTimeout(() => p.node.remove(), 500);
  }
  function positionPopups(now) {
    for (const p of [...state.popups]) {
      if (now - p.born > POPUP_MS) { dropPopup(p); continue; }
      const pt = map.project(p.pos);
      p.node.style.left = `${pt.x + p.dx}px`;
      p.node.style.top = `${pt.y + p.dy}px`;
    }
  }

  // ------------------------------------------------------------------ data
  function filterParams() {
    const p = new URLSearchParams();
    for (const k of SET_KEYS) for (const v of state.filters[k]) p.append(k, v);
    for (const k of SINGLE_KEYS) if (state.filters[k]) p.append(k, state.filters[k]);
    return p;
  }
  // Client-side copy of the server's filter logic, used for pinned items and as a safety net on incoming events.
  const EMPTY_LABEL = { infection: "unknown", tag: "untagged", severity: "unrated" };
  function matchesFilters(ev) {
    const f = state.filters;
    const norm = (k) => ev[k] || EMPTY_LABEL[k] || "";
    for (const k of SET_KEYS) if (f[k].size && !f[k].has(norm(k))) return false;
    for (const k of ["src_city", "dst_geo", "tag", "dst_port", "dst_city", "src_geo"]) if (f[k] && String(norm(k)) !== String(f[k])) return false;
    // concealed (demo) and company-name filters are applied by the server only
    if (!state.demo) for (const k of ["http_host", "dst_ip", "http_agent", "request"]) if (f[k] && norm(k) !== f[k]) return false;
    if (f.src_ip && ev.src_ref !== f.src_ip && ev.src_ip !== f.src_ip) return false;   // host filters use the opaque reference
    return true;
  }
  const FILTER_NAMES = { source: "Report", attack_class: "Attack type", infection: "Infection / category", severity: "Severity", protocol: "Protocol",
    src_city: "Affected city", dst_geo: "Target country", tag: "Tag", dst_port: "Port", http_host: "C2 domain", src_ip: "Host",
    src_asn: "Source network", dst_asn: "Destination network", dst_ip: "Destination IP", dst_city: "Destination city", src_geo: "Source country",
    http_agent: "User agent", request: "Request path", time: "Time" };
  // readable value for a filter chip or a selection title
  function filterValueLabel(k, v) {
    const cached = labelCache.get(`${k}\u0000${v}`);
    if (cached) return cached;
    if (k === "source") return srcLabel(v);
    if (k === "src_city" || k === "dst_city") return titleCase(v);
    if (k === "dst_geo" || k === "src_geo") return countryName(v);
    if (k === "time") return entityLabel("time", v);
    if (k === "severity") return titleCase(v);
    if (/^[0-9a-f]{12}$/.test(v) && ["src_ip", "dst_ip", "http_host", "http_agent", "request"].includes(k)) return "selected (concealed)";
    return v;
  }
  function renderFilterBar() {
    const bar = $("filterBar"); bar.replaceChildren();
    const f = state.filters, chips = [];
    const add = (key, value, label) => {
      const c = el("span", "fchip"); c.append(el("b", null, `${FILTER_NAMES[key]}:`), el("span", "mono", label));
      const x = el("button", null, "×"); x.type = "button"; x.setAttribute("aria-label", `Remove ${FILTER_NAMES[key]} filter`);
      x.addEventListener("click", () => { if (f[key] instanceof Set) f[key].delete(value); else f[key] = ""; buildFilters(); filtersChanged(); });
      c.append(x); chips.push(c);
    };
    for (const k of SET_KEYS) for (const v of f[k]) add(k, v, filterValueLabel(k, v));
    for (const k of SINGLE_KEYS) if (f[k]) add(k, f[k], filterValueLabel(k, f[k]));
    if (!chips.length) { bar.hidden = true; return; }
    bar.append(el("span", null, "Filtered by"), ...chips);
    const clear = el("button", "link-btn", "Clear all"); clear.type = "button";
    clear.addEventListener("click", () => $("btnReset").click());
    bar.append(clear);
    bar.hidden = false;
  }

  async function getJSON(url) {
    // demo mode is applied by the server, so concealed values never reach the browser
    if (state.demo) url += (url.includes("?") ? "&" : "?") + "demo=1";
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  }
  async function syncClock() {
    const c = await getJSON("/api/clock");
    state.lastSync = Date.now();
    const switched = state.schedState !== null && (c.replay_day !== state.replayDay || c.state !== state.schedState);
    state.sched = c; state.replayDay = c.replay_day; state.schedState = c.state;
    state.dayStart = Date.parse(c.day_start); state.dayEnd = Date.parse(c.day_end);
    state.waiting = c.state !== "playing";
    if (switched) {
      // a new day started (or its report arrived): everyone jumps to the server's position, from 00:00
      state.autoPaused = false; setPaused(false); state.behind = false; $("btnCatchUp").hidden = true;
      state.anchorReplay = Date.parse(c.replay_now); state.anchorWall = Date.now();
      resetStream(); state.cursor = replayNow();
      loadFacets(); refreshStats(); refreshReplayed(); loadGeo(false); poll();
      if (!$("intro").hidden) loadIntro(false);
      if (c.state === "playing") toast(`Replay of ${c.replay_day} has started from 00:00.`);
    } else if ((state.dataVersion != null && c.data_version !== state.dataVersion)
      || (state.sourcesVersion != null && c.sources_version !== state.sourcesVersion)) {
      // a report for this day was added (or grew) in MongoDB: refresh every figure, list and the map now
      loadFacets(); refreshStats(); refreshReplayed(); loadGeo(false);
      if (!$("intro").hidden) loadIntro(false);
    }
    if (!switched && state.speed === 1 && !state.paused && !state.behind) {
      // after a pause the replay deliberately runs behind; only "Catch up" or a speed change jumps it forward
      state.anchorReplay = Date.parse(c.replay_now); state.anchorWall = Date.now();
    }
    announceReports(c);
    state.dataVersion = c.data_version; state.sourcesVersion = c.sources_version;
    renderWaiting();
    if (c.sources) $("collectionName").textContent = `Shadowserver · ${c.sources} reports`;
    if (c.demo_forced && !state.demoForced) { state.demoForced = true; setDemo(true, false); }
  }
  const hhmmUtc = (iso) => (iso ? iso.slice(11, 16) : "");
  // Reports arrive in MongoDB at different times. The server notices a new (or grown) report within
  // 15 seconds and lists it in /api/clock; announce each one once, in the toast and at the top of the stream.
  const announced = new Set();
  let announcePrimed = false;
  function announceReports(c) {
    const fresh = [], newTypes = [];
    for (const r of c.report_changes || []) {
      const key = `${c.replay_day}|${r.source}|${r.rows}`;
      if (announced.has(key)) continue;
      announced.add(key);
      if (announcePrimed) fresh.push(r);   // changes from before this page was opened are not news
    }
    // a report type (MongoDB collection) that did not exist before: announce it even without data for this day
    for (const s of c.new_sources || []) {
      const key = `type|${s.name}`;
      if (announced.has(key)) continue;
      announced.add(key);
      if (announcePrimed && !fresh.some((r) => r.source === s.name)) newTypes.push(s);
    }
    announcePrimed = true;
    if (!fresh.length && !newTypes.length) return;
    let msg = "";
    if (fresh.length) {
      const parts = fresh.map((r) => `${r.label} (${r.new ? "" : "+"}${fmt(r.added)} event${r.added === 1 ? "" : "s"})`);
      const when = fresh[fresh.length - 1].arrived_at;
      msg = `New report data for ${c.replay_day}: ${parts.join(", ")}${when ? `, received ${hhmmUtc(when)} UTC` : ""}. `
        + (c.state === "playing" ? "Totals, analysis and the map now include it. " : "It will be part of the replay. ");
    }
    const ok = newTypes.filter((s) => s.compatible !== false), bad = newTypes.filter((s) => s.compatible === false);
    if (ok.length) {
      msg += `New report type${ok.length > 1 ? "s" : ""} detected: ${ok.map((s) => s.label).join(", ")}. `
        + `Compatibility check passed (${ok[0].required_ok}/${ok[0].required_total} required fields), so ${ok.length > 1 ? "their" : "its"} data is loaded onto the map. `
        + `Now monitoring ${c.sources} reports${fresh.length ? "" : `; no data for ${c.replay_day} yet`}. `;
    }
    if (bad.length) {
      msg += bad.map((s) => `Report type ${s.label} was discovered but cannot be shown yet: missing ${s.missing.join(", ")}. `).join("")
        + "It is listed on the overview page; support will be added in a future update.";
    }
    msg = msg.trim();
    toast(msg);
    if (c.state === "playing") {
      const note = el("div", "stream-notice"); note.setAttribute("role", "status");
      note.append(el("span", null, msg));
      const x = el("button", null, "×"); x.type = "button"; x.setAttribute("aria-label", "Dismiss");
      x.addEventListener("click", () => note.remove());
      note.append(x);
      $("rows").before(note);
      setTimeout(() => note.remove(), 10 * 60000);
    }
  }
  function clockLabel() {
    if (state.schedState === "waiting") return "Waiting for the report of";
    if (state.schedState === "settling") return "Report arriving · replay starts soon";
    return state.paused ? "Replay time (UTC) · paused" : "Replay time (UTC)";
  }
  function renderWaiting() {
    const c = state.sched; if (!c) return;
    document.body.classList.toggle("is-waiting", state.waiting);
    const msg = c.state === "waiting"
      ? `Waiting for Shadowserver's reports for ${c.replay_day}. MongoDB is checked every 15 seconds, and the replay starts from 00:00 once they arrive.`
      : c.state === "settling"
        ? `Reports for ${c.replay_day} are arriving: ${(c.reports || []).length} so far with ${fmt(c.day_total || 0)} events`
          + `${(c.reports || []).length ? ` (${c.reports.map((r) => `${r.label} ${fmt(r.rows)}`).join(", ")})` : ""}. `
          + `The replay starts from 00:00 at about ${hhmmUtc(c.settle_until)} UTC, ${Math.round((c.settle_seconds || 600) / 60)} minutes after the last report arrived; later reports are still added.`
        : (state.emptyMsg || "Waiting for attacks in the replay window…");
    $("streamEmpty").textContent = msg;
    if (state.waiting) $("streamEmpty").hidden = false;
  }
  function remember(ev) {
    state.events.set(ev.id, ev);
    if (state.events.size > 1500) state.events.delete(state.events.keys().next().value);
  }
  function countEvent(ev, weight) {
    // only feeds the activity level; the totals are whole-day figures from the server
    state.recentRate.push([Date.parse(ev.extracted_date), weight]);
  }

  let polling = false;
  async function poll() {
    if (polling || state.paused || state.waiting) return;
    polling = true;
    const gen = state.generation;
    try {
      const to = replayNow() + LOOKAHEAD_MS * state.speed;
      const from = state.cursor ?? replayNow();
      if (to - from < 500) return;
      const p = filterParams();
      p.set("from", new Date(from).toISOString()); p.set("to", new Date(to).toISOString());
      const data = await getJSON(`/api/events?${p}`);
      if (gen !== state.generation) return;
      state.cursor = to;
      const weight = data.returned ? data.total / data.returned : 1;
      for (const ev of data.events) if (matchesFilters(ev)) state.pending.push({ ev, gen, weight, wall: wallFor(Date.parse(ev.extracted_date)) });
      state.pending.sort((a, b) => a.wall - b.wall);
      $("streamInfo").textContent = data.sampled ? `sampled ${data.returned} of ${data.total}` : "";
      if (toastIsError) hideToast();   // the feed is back: clear a feed error, but keep normal messages
    } catch (err) { toast(`Data feed error: ${err.message}. Retrying…`); }
    finally { polling = false; }
  }

  // Fill the stream with the last few replay-minutes and put the most recent ones on the map.
  async function backfill() {
    const gen = state.generation;
    const to = replayNow();
    if (state.waiting) { state.cursor = to; renderWaiting(); return; }   // nothing to show before the report arrives
    const p = filterParams();
    // Unfiltered: the last few minutes. Filtered: the latest matching attacks of the day, however long ago,
    // so a rare infection or quiet city never shows an empty stream.
    const filtered = [...filterParams().keys()].length > 0;
    // never reach back into the previous day: each day's replay starts clean at 00:00
    p.set("from", new Date(Math.max(to - BACKFILL_MIN * 60000, state.dayStart || 0)).toISOString()); p.set("to", new Date(to).toISOString());
    p.set("limit", filtered ? "60" : "300");
    if (filtered) p.set("latest", "1");
    try {
      const data = await getJSON(`/api/events?${p}`);
      if (gen !== state.generation) return;
      const now = Date.now();
      const evs = data.events.filter(matchesFilters);
      evs.forEach((ev, i) => {
        remember(ev);
        addRow(ev, false);
        const ageReplay = to - Date.parse(ev.extracted_date);
        let ageWall = ageReplay / state.speed;
        // filtered view: always put the latest 10 matches on the map, staggered, even if they are older
        if (filtered && i >= evs.length - 10) ageWall = Math.min(ageWall, (evs.length - 1 - i) * 1200);
        if (ageWall < activeWallMs() - 1500 && state.active.length < maxActive()) {
          const color = infColor(infName(ev));
          const path = ev.src_coords && ev.dst_coords ? arcPath(ev.src_coords, ev.dst_coords) : null;
          state.active.push({ ev, rgb: hexRgb(color), path, start: now - ageWall, life: activeWallMs(), phase: Math.random() });
          state.rowsById.get(ev.id)?.classList.add("live");
        }
        state.recentRate.push([Date.parse(ev.extracted_date), 1]);
      });
      state.cursor = to;
    } catch (err) { toast(`Could not load recent attacks: ${err.message}`); state.cursor = to; }
  }

  // "Replayed so far": the exact number of the day's records (with the active filters) whose event time is
  // at or before the replay position, counted by the server. Stands still while paused.
  let replayedBusy = false, replayedAt = null;
  async function refreshReplayed() {
    const at = replayNow();
    if (state.paused && replayedAt === at) return;
    const my = refreshReplayed.seq = (refreshReplayed.seq || 0) + 1;
    replayedBusy = true;
    try {
      const p = filterParams(); p.set("at", new Date(at).toISOString());
      const r = await getJSON(`/api/replayed?${p}`);
      if (my !== refreshReplayed.seq) return;
      replayedAt = at;
      animateKpi("kpiReplayed", r.replayed, true);
      $("kpiReplayed").parentElement.title = `${fmt(r.replayed)} of ${fmt(r.total)} events of ${r.day} replayed so far (${pct(r.replayed, r.total)})`;
      updateStreamEmpty(r, at);
    } catch { /* keep the last value */ }
    finally { replayedBusy = false; }
  }
  // What the empty stream says. The stream only shows what has been replayed so far, while the map, charts and
  // figures cover the whole day: a filter whose events all come later in the day must say so, and when.
  function waitText(ms) {
    const m = Math.round(ms / 60000);
    if (ms < 60000) return "less than a minute";
    if (m < 60) return `about ${m} minute${m === 1 ? "" : "s"}`;
    const h = Math.floor(m / 60), r = m % 60;
    return `about ${h} hour${h === 1 ? "" : "s"}${r ? ` ${r} minute${r === 1 ? "" : "s"}` : ""}`;
  }
  function updateStreamEmpty(r, at) {
    const filtered = [...filterParams().keys()].length > 0;
    let msg = null;
    if (filtered && r.total === 0) {
      msg = `No events of ${r.day} match these filters.`;
    } else if (r.replayed === 0 && r.total > 0 && r.next_at) {
      const first = r.next_at.slice(11, 19), now = new Date(at).toISOString().slice(11, 19);
      const head = !filtered ? `No event of ${r.day} has been replayed yet: the first`
        : r.total === 1 ? `The only matching event of ${r.day} has not been replayed yet: it`
          : `None of the ${fmt(r.total)} matching events of ${r.day} has been replayed yet: the first`;
      msg = `${head} is at ${first} UTC and the replay is at ${now} UTC`
        + (state.paused ? " (paused)." : `, so it appears in ${waitText((Date.parse(r.next_at) - at) / Math.max(1, state.speed))}.`)
        + (!filtered || !r.hosts ? ""
          : r.hosts === 1 ? " Its IP address is already in the charts and statistics: click them to analyse it, or find it on the map."
            : ` Their ${fmt(r.hosts)} IP addresses are already in the charts and statistics: click them to analyse them, or find them on the map.`);
    }
    state.emptyMsg = msg;
    if (!state.waiting) $("streamEmpty").textContent = msg || "Waiting for attacks in the replay window…";
  }
  async function refreshStats() {
    const day = new Date(replayNow()).toISOString().slice(0, 10);
    if (state.facets && state.facets.day !== day) loadFacets();
    const my = refreshStats.seq = (refreshStats.seq || 0) + 1;
    try {
      const p = filterParams(); p.set("at", new Date(replayNow()).toISOString());
      const s = await getJSON(`/api/stats?${p}`);
      if (my !== refreshStats.seq) return;   // filters changed meanwhile: a newer reply is on its way
      state.stats = s; state.liveAdded = 0; state.liveCritical = 0;
      window.LGLoader?.ready();
      setTimeout(fitKpis, 1000);   // after the figures have counted up to their new width
      renderIntel(s);
    } catch { /* keep previous */ }
  }
  async function loadFacets() {
    try {
      state.facets = await getJSON(`/api/facets?at=${encodeURIComponent(new Date(replayNow()).toISOString())}`);
      for (const r of state.facets.infection || []) infColor(r.value);
      buildFilters();
      renderPins();   // pinned rows can now show report labels
    } catch (err) { toast(`Could not load filters: ${err.message}`); }
  }

  // ------------------------------------------------------------------ HUD
  const tweens = new Map();
  function animateKpi(id, value, instant) {
    const node = $(id); if (!node) return;
    const prev = tweens.get(id) ?? 0;
    if (instant || reducedMotion) { node.textContent = fmt(value); tweens.set(id, value); return; }
    if (prev === value) return;
    const start = performance.now(), from = prev;
    tweens.set(id, value);
    const step = (t) => { const k = Math.min(1, (t - start) / 700); node.textContent = fmt(from + (value - from) * ease(k)); if (k < 1 && tweens.get(id) === value) requestAnimationFrame(step); };
    requestAnimationFrame(step);
    // animation frames stop in background tabs; make sure the exact figure is always shown
    setTimeout(() => { if (tweens.get(id) === value) node.textContent = fmt(value); }, 900);
  }
  const LEVELS = ["LOW", "GUARDED", "ELEVATED", "HIGH", "SEVERE"];
  // "Yesterday" when an ISO time falls on yesterday's UTC date (the normal replay), otherwise the plain date
  function dayWord(iso) {
    const y = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const d = String(iso || "").slice(0, 10);
    return d === y ? "Yesterday" : d === new Date().toISOString().slice(0, 10) ? "Today" : d;
  }
  // ---- top-bar figures open the analysis of the whole day (with the active filters) at the matching list
  function openGlobal(drill, extra = []) {
    const base = [...filterParams()];
    const pairs = [...base.filter(([k]) => !extra.some(([ek]) => ek === k)), ...extra];
    if (!pairs.length) return openInsight("filters", "", true, { drill });
    if (pairs.length === 1) return openInsight(pairs[0][0], pairs[0][1], true, { drill });
    openInsight("filters", new URLSearchParams(pairs).toString(), true, { drill });
  }
  const KPI_OPEN = {
    kpiTotal: () => openGlobal("events"),
    // from 00:00 up to the replay position: what has been replayed so far
    kpiReplayed: () => {
      // to the exact second of the replay position, so the count equals the figure in the top bar
      const start = state.dayStart || Date.parse(new Date(replayNow()).toISOString().slice(0, 10) + "T00:00:00Z");
      const secs = Math.max(1, Math.min(86400, Math.floor((replayNow() - start) / 1000) + 1));
      openGlobal("events", [["time", `0+${(secs / 60).toFixed(4)}`]]);
    },
    kpiHosts: () => openGlobal("hosts"),
    kpiReports: () => openGlobal("reports"),
    kpiCross: () => openGlobal("cross"),
    kpiCritical: () => openGlobal("hosts", [["severity", "critical"]]),
  };
  for (const [id, open] of Object.entries(KPI_OPEN)) {
    const k = $(id) && $(id).parentElement; if (!k) continue;
    k.classList.add("click"); k.tabIndex = 0; k.setAttribute("role", "button");
    k.setAttribute("aria-label", `${k.querySelector(".kpi-label").textContent}: open the analysis`);
    k.addEventListener("click", (e) => { e.preventDefault(); open(); });
    k.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
  }

  // Hide whole figures, least important first, until the rest fit the top bar (never squeeze them).
  const KPI_DROP = ["kpiCross", "kpiReports", "kpiHosts", "kpiCritical", "kpiReplayed"];
  function fitKpis() {
    const box = $("kpis"); if (!box) return;
    for (const k of box.children) k.classList.remove("kpi-off");
    // also counts a figure cut off at the edge, not only one pushed outside the box
    const fits = () => box.scrollWidth <= box.clientWidth + 1 &&
      [...box.children].every((k) => k.classList.contains("kpi-off") || getComputedStyle(k).display === "none" || k.getBoundingClientRect().right <= box.getBoundingClientRect().right + 1);
    for (const id of KPI_DROP) {
      if (fits()) break;
      $(id)?.parentElement.classList.add("kpi-off");
    }
  }
  window.addEventListener("resize", () => { clearTimeout(fitKpis._t); fitKpis._t = setTimeout(fitKpis, 120); });
  function tickHud() {
    {
      // numbers grew: hide more; something hidden: every ~2 s see whether it fits again (window grew)
      const box = $("kpis");
      if (box && box.scrollWidth > box.clientWidth + 1) fitKpis();
      else if (box && box.querySelector(".kpi-off") && Date.now() - (fitKpis._last || 0) > 2000) { fitKpis._last = Date.now(); fitKpis(); }
    }
    const r = new Date(replayNow());
    // the replayed day (yesterday) and the real current time are shown separately
    const rIso = r.toISOString();
    // replay time = the extracted_date of the events being played now; current time = the real clock.
    // They differ by at least a day (more when a report arrived late), so both show their full date.
    $("replayDate").textContent = state.waiting ? (state.replayDay || rIso.slice(0, 10)) : `${rIso.slice(0, 10)} ${rIso.slice(11, 19)}`;
    const c = state.sched;
    $("replayDate").title = state.waiting
      ? `${$("streamEmpty").textContent}`
      : `The event time (extracted_date) being replayed now: ${dayWord(rIso).toLowerCase() === "yesterday" ? "yesterday, " : ""}${rIso.slice(0, 10)} ${rIso.slice(11, 19)} UTC`
        + (c && c.delay_seconds > 300 ? `. This day's replay started at ${hhmmUtc(c.started_at)} UTC when its report arrived.` : "");
    $("clockDate").textContent = clockLabel();
    // faster speeds (demos) loop the day instead of running past its end
    if (state.speed > 1 && state.dayEnd && !state.paused && state.anchorReplay + (Date.now() - state.anchorWall) * state.speed >= state.dayEnd) {
      state.anchorReplay = state.dayStart; state.anchorWall = Date.now();
      state.generation++; state.pending = []; state.cursor = state.dayStart;
    }
    // Speed 1x reached the end of the day: ask the server what comes next
    if (state.speed === 1 && state.dayEnd && r.getTime() >= state.dayEnd - 1000 && Date.now() - state.lastSync > 10000) syncClock().catch(() => {});
    const nIso = new Date().toISOString();
    $("nowClock").textContent = `${nIso.slice(0, 10)} ${nIso.slice(11, 19)}`;
    const s = state.stats;
    if (s) {
      // whole-day totals from the server; the replayed stream never changes them
      animateKpi("kpiTotal", s.total);
      animateKpi("kpiCritical", s.critical);
      animateKpi("kpiHosts", s.unique_src_ip);
      animateKpi("kpiReports", s.unique_sources);
      animateKpi("kpiCross", s.multi_source_hosts);
    }
    // activity: last 5 replay-minutes vs today's average per minute
    const cut = replayNow() - 5 * 60000;
    state.recentRate = state.recentRate.filter((x) => x[0] >= cut - 60000);
    const recent = state.recentRate.filter((x) => x[0] >= cut).reduce((a, x) => a + x[1], 0) / 5;
    const mins = Math.max(1, (replayNow() - Date.parse(r.toISOString().slice(0, 10) + "T00:00:00Z")) / 60000);
    const avg = s ? s.total / 1440 : recent;   // the replayed day's average per minute
    const ratio = avg ? recent / avg : 0;
    const lvl = ratio < 0.5 ? 1 : ratio < 0.9 ? 2 : ratio < 1.4 ? 3 : ratio < 2.2 ? 4 : 5;
    [...$("levelBar").children].forEach((i, k) => i.classList.toggle("on", k < lvl));
    $("levelBar").style.setProperty("--lc", ["#30a46c", "#30a46c", "#ffc53d", "#f76b15", "#e5484d"][lvl - 1]);
    $("levelBar").title = `Activity level ${lvl} of 5 (last 5 replay minutes compared with the day's average)`;
  }

  // ------------------------------------------------------------------ live stream
  const streamBody = $("streamBody");
  // the list itself takes focus (Tab / remote); Down then steps into the rows
  streamBody.addEventListener("keydown", (e) => {
    if (e.target !== streamBody) return;
    if (e.key === "ArrowDown" || e.key === "Enter") { const first = streamBody.querySelector(".row"); if (first) { e.preventDefault(); first.focus(); } }
  });
  function buildRow(ev) {
    const li = el("li", "row");
    li.dataset.id = ev.id;
    li.style.setProperty("--sevc", sevColor(ev.severity));
    // replay time: the report's own extracted_date (when the event happened), never the wall clock
    const t = (ev.extracted_date || ev.timestamp || "").replace("T", " ");
    const time = el("span", "r-time mono");
    time.append(el("span", "r-clock", t.slice(11, 19)), el("span", "r-date", t.slice(0, 10)));
    time.title = `Replay time: the event happened at ${t.slice(0, 19)} UTC (extracted_date)`;
    const sev = el("span", "r-sev"); const sb = el("span", "sev", ev.severity || "n/a"); sev.append(sb);
    const inf = el("span", "r-inf"); const sw = el("span", "swatch"); sw.style.background = infColor(infName(ev)); sw.style.color = infColor(infName(ev));
    const ib = el("b", null, infName(ev)); ib.title = `${infName(ev)}${ev.tag && ev.tag !== ev.infection ? ` · tag: ${ev.tag}` : ""}`;
    const txt = el("span", "r-inf-txt"); txt.append(ib);
    const srcl = el("span", "r-src-label"); const cd = el("i"); cd.style.background = classColor(ev.attack_class);
    srcl.append(cd, document.createTextNode(ev.source_label || srcLabel(ev.source || ev.category) || "")); srcl.title = `${ev.attack_class || ""} · ${ev.source || ev.category || ""}`;
    txt.append(srcl); inf.append(sw, txt);
    const src = endpoint("r-ep r-src", ev.src_geo, ev.src_ip, ev.src_port, [titleCase(ev.src_city), titleCase(ev.src_region)].filter(Boolean).join(", "), ev.src_asn_name || (ev.src_asn && `AS${ev.src_asn}`));
    const arrow = el("span", "r-arrow", "→");
    const dst = endpoint("r-ep r-dst", ev.dst_geo, ev.dst_ip, ev.dst_port, [titleCase(ev.dst_city), countryName(ev.dst_geo)].filter(Boolean).join(", "), ev.dst_asn_name || (ev.dst_asn && `AS${ev.dst_asn}`));
    const proto = el("span", "r-proto", [ev.protocol, ev.dst_port].filter(Boolean).join("/"));
    const req = el("span", "r-req");
    const host = el("span", "host", ev.http_host || ev.ssl_servername || ev.dst_hostname || "n/a"); host.title = host.textContent;
    const url = el("span", "url", ev.http_url || ev.http_agent || ""); url.title = url.textContent;
    req.append(host, url);
    const pin = el("button", "pin"); pin.type = "button"; pin.setAttribute("aria-label", "Pin this attack");
    pin.innerHTML = '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path fill="currentColor" d="M16 3l5 5-3 1-4 4 1 5-2 2-4-4-5 5-1-1 5-5-4-4 2-2 5 1 4-4z"/></svg>';
    pin.setAttribute("aria-pressed", String(state.pins.has(ev.id)));
    pin.addEventListener("click", (e) => { e.stopPropagation(); togglePin(ev); });
    li.append(time, sev, inf, src, arrow, dst, proto, req, pin);
    li.classList.toggle("pinned", state.pins.has(ev.id));
    li.addEventListener("click", () => openModal(state.events.get(ev.id) || ev));
    // keyboard / TV remote: rows can be focused, arrows move between them (scrolling the list), Enter opens
    li.tabIndex = -1;
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); li.click(); }
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const rows = [...streamBody.querySelectorAll(".row")];
        const next = rows[rows.indexOf(li) + (e.key === "ArrowDown" ? 1 : -1)];
        if (next) next.focus();
      }
    });
    li.addEventListener("mouseenter", () => { state.hoverId = ev.id; });
    li.addEventListener("mouseleave", () => { if (state.hoverId === ev.id) state.hoverId = null; });
    return li;
  }
  function endpoint(cls, cc, ip, port, place, asn) {
    const box = el("span", cls);
    // a side the report does not have at all (source-only or destination-only reports) says so
    const none = !ip && !cc && !place;
    const top = el("span", "top"); top.append(flagImg(cc), el("span", "ip", none ? "not reported" : `${ip || "n/a"}${port ? ":" + port : ""}`));
    if (none) top.title = "This report does not include this side of the connection";
    const pl = el("span", "place", place); pl.title = place;
    box.append(top, pl);
    if (asn) box.append(el("span", "sub", asn));
    return box;
  }
  const atTop = () => streamBody.scrollTop < 8;
  function addRow(ev, flash) {
    if (state.rowsById.has(ev.id)) return;
    if (flash && (state.paused || !atTop())) {
      state.buffer.push(ev);
      $("newCount").textContent = state.buffer.length; $("btnNew").hidden = false;
      return;
    }
    insertRow(ev, flash);
  }
  function insertRow(ev, flash) {
    const li = buildRow(ev);
    if (flash) li.classList.add("flash");
    if (state.active.some((a) => a.ev.id === ev.id)) li.classList.add("live");
    $("rows").prepend(li);
    state.rowsById.set(ev.id, li);
    $("streamEmpty").hidden = true;
    const rows = $("rows");
    while (rows.children.length > MAX_ROWS) { const last = rows.lastChild; state.rowsById.delete(last.dataset.id); last.remove(); }
  }
  function flushBuffer() {
    for (const ev of state.buffer) insertRow(ev, true);
    state.buffer = [];
    $("btnNew").hidden = true;
  }
  $("btnNew").addEventListener("click", () => { flushBuffer(); streamBody.scrollTo({ top: 0, behavior: "smooth" }); });
  streamBody.addEventListener("scroll", () => { if (atTop() && !state.paused && state.buffer.length) flushBuffer(); }, { passive: true });
  // Pause freezes the whole replay: clock, map animations, popups and the stream. Resume carries on from
  // the same moment, so nothing is skipped; the replay then runs behind until "Catch up" is pressed.
  function setPaused(p) {
    if (p === state.paused) return;
    if (p) {
      state.pauseReplay = replayNow(); state.pauseAt = Date.now(); state.paused = true;
    } else {
      const d = Date.now() - state.pauseAt;
      state.anchorWall += d;
      state.paused = false;
      for (const x of state.pending) x.wall += d;
      for (const a of state.active) a.start += d;
      for (const x of state.popups) x.born += d;
      if (state.flashUntil) state.flashUntil += d;
      if (d > 1000) state.behind = true;
      if (atTop()) flushBuffer();
    }
    $("btnPause").setAttribute("aria-pressed", String(p));
    $("btnPause").textContent = p ? "Resume" : "Pause";
    $("btnPause").title = p ? "Continue the replay from where it stopped" : "Freeze the replay: map, stream and clock";
    $("clockDate").textContent = clockLabel();
    document.body.classList.toggle("is-paused", p);
    $("btnCatchUp").hidden = p || !state.behind;
  }
  $("btnPause").addEventListener("click", () => { state.autoPaused = false; setPaused(!state.paused); });
  $("btnCatchUp").addEventListener("click", async () => {
    state.behind = false;
    $("btnCatchUp").hidden = true;
    try { await syncClock(); } catch { /* keep */ }
    state.generation++; state.pending = []; state.cursor = replayNow();
    poll(); refreshStats();
  });

  // pins
  function togglePin(ev) {
    if (state.pins.has(ev.id)) state.pins.delete(ev.id);
    else { const { _path, ...clean } = ev; state.pins.set(ev.id, clean); }
    store.set("tm.pins", [...state.pins.values()].slice(-50).map(({ _path, ...e }) => e));
    renderPins();
    const row = state.rowsById.get(ev.id);
    if (row) { row.classList.toggle("pinned", state.pins.has(ev.id)); row.querySelector(".pin").setAttribute("aria-pressed", String(state.pins.has(ev.id))); }
    if (state.modalEv && state.modalEv.id === ev.id) $("mPin").textContent = state.pins.has(ev.id) ? "Unpin" : "Pin";
  }
  function renderPins() {
    const ul = $("pinnedRows"); ul.replaceChildren();
    // pins are stored with full detail in this browser, so they are never shown in demo mode
    if (state.demo) { $("pinnedWrap").hidden = true; return; }
    const all = [...state.pins.values()].reverse();
    const shown = all.filter(matchesFilters);
    for (const ev of shown) { const li = buildRow(ev); li.classList.add("pinned"); ul.append(li); }
    $("pinnedWrap").hidden = shown.length === 0;
    const hidden = all.length - shown.length;
    $("pinCount").textContent = shown.length ? `(${shown.length}${hidden ? `, ${hidden} hidden by filters` : ""})` : "";
  }

  // phone bottom sheet + desktop resize
  function setStreamExpanded(on) { $("stream").classList.toggle("expanded", on); $("btnStreamToggle").setAttribute("aria-expanded", String(on)); }
  $("btnStreamToggle").addEventListener("click", () => setStreamExpanded(!$("stream").classList.contains("expanded")));
  // Hide / show the list: collapsed, the stream is just its title bar and the map gets the screen.
  // Smart TVs start collapsed (their browsers use small screen sizes); everyone else starts open. Remembered.
  function setStreamCollapsed(on, remember = true) {
    const s = $("stream");
    s.classList.toggle("collapsed", on);
    $("btnStreamMin").textContent = on ? "Show list" : "Hide list";
    $("btnStreamMin").setAttribute("aria-expanded", String(!on));
    const root = document.documentElement.style;
    if (on) root.setProperty("--stream-h", `${Math.ceil(s.querySelector(".stream-head").getBoundingClientRect().height + 14)}px`);
    else {
      const saved = store.get("tm.streamH", null);
      if (saved && !isPhone()) root.setProperty("--stream-h", `${window.innerHeight <= 820 ? Math.min(saved, window.innerHeight * 0.4) : saved}px`);
      else root.removeProperty("--stream-h");
    }
    if (remember) lsSet("lg.streamCollapsed", on ? "1" : "0");
    setTimeout(() => { try { map.resize(); } catch { /* not ready */ } }, 50);
  }
  $("btnStreamMin").addEventListener("click", () => setStreamCollapsed(!$("stream").classList.contains("collapsed")));
  // keyboard / TV remote: L toggles the list (not while typing)
  document.addEventListener("keydown", (e) => {
    if ((e.key === "l" || e.key === "L") && !e.ctrlKey && !e.metaKey && !e.altKey && !/input|textarea|select/i.test(e.target.tagName)) {
      setStreamCollapsed(!$("stream").classList.contains("collapsed"));
    }
  });
  (() => {
    const saved = store.get("tm.streamH", null);
    // short screens (TVs, small laptops): a remembered height never takes more than 40% of the screen
    if (saved && !isPhone()) document.documentElement.style.setProperty("--stream-h", `${window.innerHeight <= 820 ? Math.min(saved, window.innerHeight * 0.4) : saved}px`);
    const pref = lsGet("lg.streamCollapsed");
    if (!isPhone() && (pref === "1" || (pref === null && IS_TV))) requestAnimationFrame(() => setStreamCollapsed(true, false));
    let startY = 0, startH = 0;
    const move = (e) => {
      const h = Math.max(150, Math.min(window.innerHeight * 0.65, startH + (startY - e.clientY)));
      document.documentElement.style.setProperty("--stream-h", `${h}px`);
    };
    const up = () => {
      window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up);
      store.set("tm.streamH", parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--stream-h")));
    };
    $("streamResize").addEventListener("pointerdown", (e) => {
      startY = e.clientY; startH = $("stream").getBoundingClientRect().height;
      window.addEventListener("pointermove", move); window.addEventListener("pointerup", up);
    });
  })();

  // ------------------------------------------------------------------ detail modal
  async function openModal(ev) {
    hideTip();
    state.modalEv = ev;
    const color = infColor(infName(ev));
    const modal = $("modal");
    modal.style.setProperty("--mc", color);
    const sw = el("span", "swatch"); sw.style.background = color;
    $("mInfection").replaceChildren(sw, document.createTextNode(infName(ev)));
    $("mHost").hidden = !ev.src_ip;
    const sev = $("mSev"); sev.textContent = ev.severity || "n/a"; sev.style.setProperty("--sevc", sevColor(ev.severity));
    $("mTag").textContent = `tag: ${ev.tag || "n/a"}`;
    $("mTime").textContent = `Event time ${(ev.extracted_date || ev.timestamp || "").replace("T", " ").slice(0, 19)} UTC`;
    renderKb($("mKb"), ev.infection, ev.tag);
    setPlace("mSrcPlace", ev.src_geo, [titleCase(ev.src_city), titleCase(ev.src_region), countryName(ev.src_geo)]);
    setPlace("mDstPlace", ev.dst_geo, [titleCase(ev.dst_city), titleCase(ev.dst_region), countryName(ev.dst_geo)]);
    $("mSrcIp").textContent = `${ev.src_ip || "n/a"}${ev.src_port ? ":" + ev.src_port : ""}`;
    $("mDstIp").textContent = `${ev.dst_ip || "n/a"}${ev.dst_port ? ":" + ev.dst_port : ""}`;
    $("mProto").textContent = [ev.protocol, ev.http_url ? "http" : ev.ssl_cipher ? "tls" : ""].filter(Boolean).join(" · ");
    $("mPin").textContent = state.pins.has(ev.id) ? "Unpin" : "Pin";

    const roles = ROLES[ev.attack_class] || ROLES.default;
    document.querySelectorAll("#modal .m-route .ep-k")[0].textContent = roles.src;
    document.querySelectorAll("#modal .m-route .ep-k")[1].textContent = roles.dst;
    const body = $("mBody"); body.replaceChildren();
    const req = [ev.http_url || "", ev.http_host && `Host: ${ev.http_host}`, ev.http_agent && `User-Agent: ${ev.http_agent}`, ev.http_referer && `Referer: ${ev.http_referer}`].filter(Boolean).join("\n");
    if (req) body.append(section("HTTP request (as seen by the sinkhole)", null, true, req));
    body.append(
      section(roles.src, [["IP", ev.src_ip], ["Port", ev.src_port], ["Hostname", ev.src_hostname], [state.demo ? "Network" : "Network (ASN)", ev.src_asn_name || (ev.src_asn && `AS${ev.src_asn}`)], ["City", titleCase(ev.src_city)], ["Region", titleCase(ev.src_region)], ["Country", ev.src_geo && `${countryName(ev.src_geo)} (${ev.src_geo})`], ["Sector", ev.src_sector], ["NAICS", ev.src_naics]]),
      section(roles.dst, [["IP", ev.dst_ip], ["Port", ev.dst_port], ["Hostname", ev.dst_hostname], [state.demo ? "Network" : "Network (ASN)", ev.dst_asn_name || (ev.dst_asn && `AS${ev.dst_asn}`)], ["City", titleCase(ev.dst_city)], ["Region", titleCase(ev.dst_region)], ["Country", ev.dst_geo && `${countryName(ev.dst_geo)} (${ev.dst_geo})`], ["Sector", ev.dst_sector], ["NAICS", ev.dst_naics]]),
      section("Threat", [["Attack type", ev.attack_class], ["Report", ev.source_label && `${ev.source_label} (${ev.source})`], ["Infection / category", ev.infection], ["Family", ev.family], ["Tag", ev.tag], ["Severity", ev.severity], ["Protocol", ev.protocol], ["Application", ev.application], ["Version", ev.version], ["Reported by", ev.public_source]]),
      section("TLS / device", [["SSL server name", ev.ssl_servername], ["SSL cipher", ev.ssl_cipher], ["Device vendor", ev.device_vendor], ["Device type", ev.device_type], ["Device model", ev.device_model], ["Machine name", ev.machine_name]]),
    );
    const extras = Object.entries(ev.extras || {});
    if (extras.length) {
      const pretty = (k) => k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
      const xs = section(`${ev.source_label || "Report"} specific fields`, extras.map(([k, v]) => [pretty(k), v]), true);
      // report fields holding a malware family or a sample hash can be looked up on Malpedia
      for (const [k, v] of extras) {
        const val = String(v ?? "");
        if (/^(md5|sha1|sha256|.*_hash|hash)$/i.test(k) || /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i.test(val)) {
          if (/^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i.test(val)) malpediaButton(xs, "hash", val, `Look up ${pretty(k)} ${MP_SRC}`);
        } else if (/^(family|malware|malware_family|threat|botnet)$/i.test(k) && val) malpediaButton(xs, "infection", val, `Look up ${pretty(k)} "${val}" ${MP_SRC}`);
      }
      body.append(xs);
    }
    const related = section("This host yesterday", [["Status", "Loading…"]]);
    body.append(related);
    body.append(section("Provenance", [["Timestamp", ev.timestamp], ["Logged", ev.logged_date], ["Extracted", ev.extracted_date], ["Report file", ev.filename], ["Line hash", ev.line_hash], ["Public source", ev.public_source], ["Forwarded by", ev.forwarded_by], ["Event ID", ev.event_id], ["Detail", ev.detail]], true));

    $("modal").hidden = false; $("modalScrim").hidden = false;
    $("btnModalClose").focus();

    if (ev.src_ip) {
      try {
        const r = await getJSON(`/api/related?ref=${encodeURIComponent(ev.src_ref || ev.src_ip)}&at=${encodeURIComponent(new Date(replayNow()).toISOString())}`);
        if (state.modalEv !== ev) return;
        related.replaceWith(section("This host yesterday", [
          ["Events", fmt(r.count)], ["First seen", r.first && `${r.first.replace("T", " ").slice(0, 19)} UTC`], ["Last seen", r.last && `${r.last.replace("T", " ").slice(0, 19)} UTC`],
          ["Seen in reports", (r.sources || []).map((s) => `${s.label} (${fmt(s.count)}, ${Math.round((s.count / Math.max(1, r.count)) * 100)}%)`).join(", ")],
          ["Infections / categories", r.infections.join(", ")], ["Contacted hosts", r.hosts.join(", ")], ["Destinations", r.dst_ips.join(", ")],
        ]));
      } catch { /* leave placeholder */ }
    }
  }
  function setPlace(id, cc, parts) {
    const node = $(id); node.replaceChildren(flagImg(cc), el("span", null, parts.filter(Boolean).join(", ")));
  }
  function section(title, rows, wide, pre) {
    const s = el("section", "m-sec" + (wide ? " wide" : ""));
    s.append(el("h3", null, title));
    if (pre) { s.append(el("pre", null, pre)); return s; }
    const dl = el("dl");
    for (const [k, v] of rows) { dl.append(el("dt", null, k)); dl.append(el("dd", v ? null : "empty", v || "Not recorded")); }
    s.append(dl);
    return s;
  }
  function closeModal() { $("modal").hidden = true; $("modalScrim").hidden = true; state.modalEv = null; }
  $("btnModalClose").addEventListener("click", closeModal);
  $("modalScrim").addEventListener("click", () => { if (!$("insight").hidden) closeInsight(); else closeModal(); });
  $("mHost").addEventListener("click", () => { if (state.modalEv) openInsight("src_ip", state.modalEv.src_ref || state.modalEv.src_ip); });
  $("mPin").addEventListener("click", () => state.modalEv && togglePin(state.modalEv));
  $("mCopy").addEventListener("click", async () => {
    if (!state.modalEv) return;
    const { _path, ...clean } = state.modalEv;
    try { await navigator.clipboard.writeText(JSON.stringify(clean, null, 2)); $("mCopy").textContent = "Copied"; setTimeout(() => { $("mCopy").textContent = "Copy JSON"; }, 1500); } catch { toast("Clipboard not available"); }
  });
  $("mFly").addEventListener("click", () => {
    const ev = state.modalEv; if (!ev) return;
    closeModal();
    const a = ev.src_coords || ev.dst_coords, b = ev.dst_coords || a;   // destination-only events fly to the target
    if (!a) return;
    state.flashId = ev.id; state.flashUntil = Date.now() + 9000;
    if (!state.active.some((x) => x.ev.id === ev.id)) launch(ev, 0, Date.now(), { silent: true });
    state.interacting = true; clearTimeout(map._tmI); map._tmI = setTimeout(() => { state.interacting = false; }, 10000);
    const bounds = new mapboxgl.LngLatBounds(a, a).extend(b);
    map.fitBounds(bounds, { padding: 120, maxZoom: 5, pitch: 50, duration: 1800 });
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") { if (!$("insight").hidden) closeInsight(); else if (!$("modal").hidden) closeModal(); else setDrawer(false); } });

  // ------------------------------------------------------------------ filters
  function buildFilters() {
    const f = state.facets || {};
    const cBox = $("fClass"); cBox.replaceChildren();
    for (const r of f.attack_class || []) cBox.append(chip(r.value, "attack_class", classColor(r.value), fmt(r.count)));
    const sl = $("fSource"); sl.replaceChildren();
    for (const r of f.source || []) {
      const li = el("li"), label = el("label"), cb = el("input");
      cb.type = "checkbox"; cb.checked = state.filters.source.has(r.value);
      cb.addEventListener("change", () => { cb.checked ? state.filters.source.add(r.value) : state.filters.source.delete(r.value); filtersChanged(); });
      const sw = el("span", "swatch"); sw.style.background = classColor(f.source_class?.[r.value]);
      const name = el("span", "name", srcLabel(r.value)); name.title = `${r.value} · ${f.source_class?.[r.value] || ""}`; name.style.fontFamily = "var(--font)";
      label.append(cb, sw, name, el("span", "count", fmt(r.count)));
      li.append(label); sl.append(li);
    }
    $("srcCount").textContent = f.source ? `(${f.source.length} with data yesterday)` : "";
    const sevBox = $("fSeverity"); sevBox.replaceChildren();
    for (const s of (f.severity || []).map((x) => x.value).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))) sevBox.append(chip(s, "severity", sevColor(s)));
    const pBox = $("fProtocol"); pBox.replaceChildren();
    for (const p of f.protocol || []) pBox.append(chip(p.value, "protocol"));
    renderInfectionList();
    $("infCount").textContent = f.infection ? `(${f.infection.length})` : "";
    fillSelect($("fSrcCity"), "All cities", f.src_city || [], (v) => titleCase(v), "src_city");
    fillSelect($("fDst"), "All countries", f.dst_geo || [], countryName, "dst_geo");
    fillSelect($("fTag"), "All tags", f.tag || [], (v) => v, "tag");
    fillSelect($("fPort"), "All ports", f.dst_port || [], (v) => v, "dst_port");
    fillSelect($("fSrcAsn"), "All networks", f.src_asn || [], (v) => v, "src_asn");
    fillSelect($("fDstAsn"), "All networks", f.dst_asn || [], (v) => v, "dst_asn");
  }
  function chip(value, key, dotColor, count) {
    const b = el("button", "chip"); b.type = "button";
    b.setAttribute("aria-pressed", String(state.filters[key].has(value)));
    if (dotColor) { const d = el("span", "dot"); d.style.background = dotColor; b.append(d); }
    b.append(document.createTextNode(value));
    if (count) b.append(el("span", "chip-n", count));
    b.addEventListener("click", () => { const s = state.filters[key]; s.has(value) ? s.delete(value) : s.add(value); b.setAttribute("aria-pressed", String(s.has(value))); filtersChanged(); });
    return b;
  }
  function renderInfectionList() {
    const q = $("infSearch").value.trim().toLowerCase();
    const ul = $("fInfection"); ul.replaceChildren();
    const sevOf = state.facets?.infection_severity || {};
    for (const r of state.facets?.infection || []) {
      if (q && !r.value.toLowerCase().includes(q)) continue;
      const li = el("li"), label = el("label"), cb = el("input");
      cb.type = "checkbox"; cb.checked = state.filters.infection.has(r.value);
      cb.addEventListener("change", () => { cb.checked ? state.filters.infection.add(r.value) : state.filters.infection.delete(r.value); filtersChanged(); });
      const sw = el("span", "swatch"); sw.style.background = infColor(r.value); sw.style.color = infColor(r.value);
      const name = el("span", "name", r.value); name.title = `${r.value} · ${sevOf[r.value] || ""}`;
      const sd = el("span", "sevdot"); sd.style.background = sevColor(sevOf[r.value]); sd.title = sevOf[r.value] || "";
      label.append(cb, sw, name, sd, el("span", "count", fmt(r.count)));
      li.append(label); ul.append(li);
    }
  }
  $("infSearch").addEventListener("input", renderInfectionList);
  function fillSelect(sel, allLabel, rows, labelFn, key) {
    sel.replaceChildren(new Option(allLabel, ""));
    for (const r of rows) sel.append(new Option(`${labelFn(r.value)} (${fmt(r.count)})`, r.value));
    sel.value = state.filters[key] || "";
    sel.onchange = () => { state.filters[key] = sel.value; filtersChanged(); };
  }
  $("btnReset").addEventListener("click", () => {
    for (const k of SET_KEYS) state.filters[k].clear();
    for (const k of SINGLE_KEYS) state.filters[k] = "";
    $("infSearch").value = "";
    buildFilters(); filtersChanged();
  });
  let filterTimer = null;
  function filtersChanged() {
    clearTimeout(filterTimer);
    renderFilterBar(); renderPins();
    filterTimer = setTimeout(() => { resetStream(); refreshStats(); refreshReplayed(); loadGeo(true); }, 250);
  }
  function resetStream() {
    state.generation++;
    state.pending = []; state.active = []; state.buffer = []; state.recentRate = [];
    $("btnNew").hidden = true;
    $("rows").replaceChildren(); state.rowsById.clear(); $("streamEmpty").hidden = false;
    for (const p of [...state.popups]) dropPopup(p);
    backfill().then(poll);
  }

  // ------------------------------------------------------------------ intel
  // ---- tooltip shared by all charts and lists
  const tipEl = $("tip");
  function showTip(evt, html) {
    tipEl.replaceChildren(...html);
    tipEl.hidden = false;
    const pad = 14, w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    let x = evt.clientX + pad, y = evt.clientY + pad;
    if (x + w > window.innerWidth - 8) x = evt.clientX - w - pad;
    if (y + h > window.innerHeight - 8) y = evt.clientY - h - pad;
    tipEl.style.left = `${Math.max(8, x)}px`; tipEl.style.top = `${Math.max(8, y)}px`;
    clearTimeout(hideTip._t);
    if (isTouchLike()) hideTip._t = setTimeout(hideTip, 3500);   // touch: close by itself
  }
  function hideTip() { tipEl.hidden = true; clearTimeout(hideTip._t); }
  // Touch screens have no mouse to "leave", so a tapped tooltip used to stay up until another tap or two.
  // After a touch, a tooltip now closes by itself after a few seconds, and any new tap, scroll or opened
  // panel closes it straight away.
  let lastPointer = "mouse";
  document.addEventListener("pointerdown", (e) => { lastPointer = e.pointerType || "mouse"; }, true);
  document.addEventListener("touchstart", () => { lastPointer = "touch"; hideTip(); }, { capture: true, passive: true });
  document.addEventListener("scroll", () => { if (lastPointer !== "mouse") hideTip(); }, { capture: true, passive: true });
  window.addEventListener("blur", hideTip);
  const isTouchLike = () => lastPointer === "touch" || lastPointer === "pen" || mq("(hover: none)");
  const tipLine = (b, rest) => { const d = el("div"); if (b) d.append(el("b", null, b)); if (rest) d.append(document.createTextNode(rest)); return d; };
  const pct = (n, total) => {
    const f = n / Math.max(1, total);
    if (f > 0 && f < 0.001) return "<0.1%";
    if (f > 0.995 && f < 1) return `${(Math.floor(f * 1000) / 10).toFixed(1)}%`;
    return `${(f * 100).toFixed(f < 0.1 ? 1 : 0)}%`;
  };
  function attachTip(node, fn) {
    node.addEventListener("mousemove", (e) => { const c = fn(e); if (c) showTip(e, c); else hideTip(); });
    node.addEventListener("mouseleave", hideTip);
  }

  function renderIntel(s) {
    const sevOf = state.facets?.infection_severity || {};
    const total = Math.max(1, s.total);
    drawDonut(s.attack_class || [], total);
    drawHourClass(s.hours_by_class || {}, s.current_hour);
    drawSeverity(s.severity || [], total);
    const netLabel = (r) => { const sw = el("span", "swatch"); sw.style.background = "#7c7c85"; return [sw, el("span", null, r.label)]; };
    top("topSrcNet", s.src_network || [], "src_asn", (v, r) => netLabel(r), null, total,
      (r) => (state.demo || !r.asns?.length ? "" : `AS${r.asns.join(", AS")}`));
    top("topDstNet", s.dst_network || [], "dst_asn", (v, r) => netLabel(r), null, total,
      (r) => (state.demo || !r.asns?.length ? "" : `AS${r.asns.join(", AS")}`));
    top("topSource", s.source || [], "source", (v) => { const sw = el("span", "swatch"); sw.style.background = classColor(state.facets?.source_class?.[v]); return [sw, el("span", null, srcLabel(v))]; }, (v) => classColor(state.facets?.source_class?.[v]));
    top("topInfection", s.infection, "infection", (v) => { const sw = el("span", "swatch"); sw.style.background = infColor(v); const d = el("span", "sevdot"); d.style.background = sevColor(sevOf[v]); d.title = sevOf[v] || ""; return [sw, el("span", "mono", v), d]; }, (v) => infColor(v));
    top("topCity", s.src_city, "src_city", (v) => [flagImg((s.src_geo[0] || {}).value), el("span", null, titleCase(v))]);
    top("topHost", s.http_host, "http_host", (v, r) => [el("span", "mono", r.label || v)]);
    top("topDst", s.dst_geo, "dst_geo", (v) => [flagImg(v), el("span", null, countryName(v))]);
    drawTimeline(s.timeline || []);
  }
  function top(id, rows, kind, labelFn, colorFn, total, extraFn) {
    const ol = $(id); ol.replaceChildren();
    const max = Math.max(1, ...rows.map((r) => r.count));
    const sum = total || rows.reduce((a, r) => a + r.count, 0);
    for (const r of rows.slice(0, 6)) {
      const li = el("li"); li.tabIndex = 0; li.setAttribute("role", "button");
      const bar = el("span", "bar"); bar.style.width = `calc(${(r.count / max) * 100}% - 16px)`;
      if (colorFn) bar.style.setProperty("--bc", colorFn(r.value));
      const lbl = el("span", "lbl"); lbl.append(...labelFn(r.value, r));
      li.append(bar, lbl, el("span", "num", fmt(r.count)));
      attachTip(li, () => {
        const name = lbl.textContent;
        const lines = [tipLine(name), tipLine(null, `${fmt(r.count)} events · ${pct(r.count, sum)} of all events`)];
        const extra = extraFn && extraFn(r);
        if (extra) lines.push(tipLine(null, extra));
        lines.push(tipLine(null, "Click for analysis"));
        return lines;
      });
      const open = () => openScoped(kind, r.value);
      li.addEventListener("click", open);
      li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
      ol.append(li);
    }
    if (!rows.length) ol.append(el("li", "muted", "No data yet"));
  }
  function barChart(canvas, values, opts = {}) {
    if (!canvas || !canvas.offsetWidth) return;
    const dpr = window.devicePixelRatio || 1, w = canvas.offsetWidth, h = canvas.offsetHeight || 64;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const g = canvas.getContext("2d"); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
    const vals = values.map((v) => v ?? 0), max = Math.max(1, ...vals), n = values.length, gap = n > 48 ? 1 : 2, bw = w / n;
    g.strokeStyle = "rgba(255,255,255,0.06)"; g.lineWidth = 1;
    for (const f of [0.5, 1]) { const y = Math.round(h - f * (h - 4)) + 0.5; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke(); }
    for (let i = 0; i < n; i++) {
      const x = i * bw + gap / 2, bwid = Math.max(1, bw - gap);
      if (values[i] === null || values[i] === undefined) { g.fillStyle = "rgba(255,255,255,0.04)"; g.fillRect(x, h - 2, bwid, 2); continue; }
      const bh = Math.max(1, (values[i] / max) * (h - 4));
      g.fillStyle = i === opts.highlight ? "#ededef" : opts.color || ACCENT;
      g.globalAlpha = i === opts.highlight ? 1 : 0.85;
      g.fillRect(x, h - bh, bwid, bh);
    }
    g.globalAlpha = 1;
    return max;
  }
  // ================================================================== reusable charts (Intel + analysis)
  const CLASS_INFO = {
    "Botnet C2": "Infected devices calling sinkholed botnet servers", "Brute force": "Password-guessing attempts against honeypots",
    "Scanning": "Hosts probing honeypots for vulnerable services", "DDoS": "Hosts taking part in, or targeted by, denial-of-service attacks",
    "Initial access": "Malware payloads executed on users' machines", "IP spoofing": "Networks that let forged source addresses out",
    "Spam": "Spam campaigns linked to local hosts",
  };
  const hhmm = (m) => `${String(Math.floor(m / 60) % 24).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;

  /* Donut with legend. rows: [{value, label?, count}]; opts: {color(v), describe(v), onClick(v), center, unit} */
  function donutChart(svg, legend, rows, opts = {}) {
    svg.replaceChildren(); svg.classList.remove("hovering"); legend.replaceChildren();
    const NS = "http://www.w3.org/2000/svg", cx = 60, cy = 60, R = 54, r0 = 36;
    const sum = rows.reduce((a, r) => a + r.count, 0) || 1;
    const color = opts.color || (() => ACCENT);
    let a0 = -Math.PI / 2;
    const arc = (a1, a2) => {
      const large = a2 - a1 > Math.PI ? 1 : 0, p = (r, a) => `${cx + r * Math.cos(a)} ${cy + r * Math.sin(a)}`;
      return `M${p(R, a1)} A${R} ${R} 0 ${large} 1 ${p(R, a2)} L${p(r0, a2)} A${r0} ${r0} 0 ${large} 0 ${p(r0, a1)} Z`;
    };
    for (const r of rows) {
      const frac = r.count / sum, a1 = a0, a2 = a0 + Math.max(frac * Math.PI * 2, 0.02);
      a0 = a1 + frac * Math.PI * 2;
      const path = document.createElementNS(NS, "path");
      path.setAttribute("d", frac >= 0.9999 ? arc(-Math.PI / 2, Math.PI * 1.5 - 0.0001) : arc(a1, a2));
      path.setAttribute("fill", color(r.value)); path.setAttribute("stroke", "#141417"); path.setAttribute("stroke-width", "1");
      svg.append(path);
      const li = el("li"); const sw = el("span", "swatch"); sw.style.background = color(r.value);
      const name = el("span", null, r.label || r.value); name.title = r.label || r.value;
      li.append(sw, name, el("span", "n", pct(r.count, sum)));
      legend.append(li);
      const on = () => { svg.classList.add("hovering"); path.classList.add("hot"); li.classList.add("hot"); };
      const off = () => { svg.classList.remove("hovering"); path.classList.remove("hot"); li.classList.remove("hot"); hideTip(); };
      const tip = () => [tipLine(r.label || r.value), tipLine(null, `${fmt(r.count)} ${opts.unit || "events"} · ${pct(r.count, sum)}`),
        ...(opts.describe && opts.describe(r.value) ? [tipLine(null, opts.describe(r.value))] : []),
        ...(opts.onClick ? [tipLine(null, "Click for analysis")] : [])];
      for (const n of [path, li]) {
        n.addEventListener("mouseenter", on); n.addEventListener("mouseleave", off);
        n.addEventListener("mousemove", (e) => showTip(e, tip()));
        if (opts.onClick) { n.addEventListener("click", () => opts.onClick(r.value)); n.style.cursor = "pointer"; } else n.style.cursor = "default";
      }
    }
    const t = (y, cls, txt) => { const n = document.createElementNS(NS, "text"); n.setAttribute("x", cx); n.setAttribute("y", y); n.setAttribute("text-anchor", "middle"); n.setAttribute("class", cls); n.textContent = txt; return n; };
    svg.append(t(cy + 2, "d-total", fmt(rows.length ? sum : 0)), t(cy + 15, "d-sub", opts.center || "events"));
    if (!rows.length) legend.append(el("li", "muted", "No data yet"));
  }

  /* Events per hour stacked by attack type, with hover breakdown. */
  // Clicking a bar analyses that hour / 15 minutes. `pick` (start minute, minutes) decides within what:
  // inside an analysis that same selection, in Intel the active filters.
  function chartClick(canvas, slots, minutes) {
    if (canvas._click) return;
    canvas._click = true;
    canvas.style.cursor = "pointer";
    canvas.addEventListener("click", (e) => {
      const rect = canvas.getBoundingClientRect();
      const i = Math.min(slots - 1, Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * slots)));
      if (typeof canvas._pick !== "function") return;
      const d = canvas._data;
      const v = Array.isArray(d) ? d[i] : d && d.byClass ? Object.values(d.byClass).reduce((a, arr) => a + (arr[i] || 0), 0) : 1;
      if (!v) return;   // nothing happened in that window
      canvas._pick(i * minutes, minutes);
    });
  }
  function stackedHours(canvas, byClass, curHour, info, pick) {
    if (!canvas || !canvas.offsetWidth) return;
    canvas._data = { byClass, curHour }; canvas._pick = pick;
    chartClick(canvas, 24, 60);
    const dpr = window.devicePixelRatio || 1, w = canvas.offsetWidth, h = canvas.offsetHeight || 80;
    canvas.width = w * dpr; canvas.height = h * dpr;
    const g = canvas.getContext("2d"); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
    const classes = Object.keys(byClass);
    const totals = Array.from({ length: 24 }, (_, i) => classes.reduce((a, k) => a + byClass[k][i], 0));
    const max = Math.max(1, ...totals), bw = w / 24;
    g.strokeStyle = "rgba(255,255,255,0.06)";
    for (const f of [0.5, 1]) { const y = Math.round(h - f * (h - 4)) + 0.5; g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke(); }
    // whole day is drawn; the replay's current hour is only highlighted
    for (let i = 0; i < 24; i++) {
      let y = h;
      for (const k of classes) {
        const v = byClass[k][i]; if (!v) continue;
        const bh = Math.max(1, (v / max) * (h - 4));
        g.fillStyle = classColor(k); g.globalAlpha = curHour == null || i === curHour ? 1 : 0.7;
        g.fillRect(i * bw + 1, y - bh, bw - 2, bh); y -= bh;
      }
    }
    g.globalAlpha = 1;
    if (info) info.textContent = `peak ${fmt(Math.max(...totals))} / hour`;
    if (!canvas._tip) {
      canvas._tip = true;
      attachTip(canvas, (e) => {
        const d = canvas._data; if (!d) return null;
        const rect = canvas.getBoundingClientRect();
        const i = Math.min(23, Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * 24)));
        const rows = Object.entries(d.byClass).map(([k, v]) => [k, v[i]]).filter(([, v]) => v);
        const tot = rows.reduce((a, [, v]) => a + v, 0);
        return [tipLine(`${String(i).padStart(2, "0")}:00 to ${String((i + 1) % 24).padStart(2, "0")}:00 UTC`), tipLine(null, `${fmt(tot)} events${i === d.curHour ? " · the replay is in this hour" : ""}`),
          ...rows.map(([k, v]) => { const dv = el("div"); const sw = el("span", "swatch"); sw.style.cssText = `background:${classColor(k)};margin-right:6px`; dv.append(sw, document.createTextNode(`${k}: ${fmt(v)} (${pct(v, tot)})`)); return dv; }),
          ...(tot ? [tipLine(null, "Click to analyse this hour")] : [])];
      });
    }
  }

  /* 96 x 15-minute activity bars with hover. */
  // whole-day bars; `mark` (optional) highlights the 15 minutes the replay is in
  function quarterHours(canvas, buckets, info, color, mark, scope, clickable = true) {
    canvas._data = buckets; canvas._mark = mark; canvas._pick = clickable ? scope : null;
    canvas._clickable = clickable;
    if (clickable) chartClick(canvas, 96, 15);
    const max = barChart(canvas, buckets, { highlight: mark, color });
    if (info && max) info.textContent = `peak ${fmt(max)} per 15 min`;
    if (!canvas._tip) {
      canvas._tip = true;
      attachTip(canvas, (e) => {
        const b = canvas._data; if (!b || !b.length) return null;
        const rect = canvas.getBoundingClientRect();
        const i = Math.min(95, Math.max(0, Math.floor(((e.clientX - rect.left) / rect.width) * 96)));
        const v = b[i], peak = Math.max(...b.map((x) => x ?? 0));
        return [tipLine(`${hhmm(i * 15)} to ${hhmm(i * 15 + 15)} UTC`),
          tipLine(null, `${fmt(v ?? 0)} events${v === peak && v ? " · busiest 15 minutes of the day" : ""}${i === canvas._mark ? " · the replay is here" : ""}`),
          ...(canvas._clickable && v ? [tipLine(null, "Click to analyse these 15 minutes")] : [])];
      });
    }
  }

  /* Severity stacked bar + legend. */
  function severityMix(bar, leg, rows, opts = {}) {
    bar.replaceChildren(); leg.replaceChildren();
    const sum = rows.reduce((a, r) => a + r.count, 0) || 1;
    const order = [...rows].sort((a, b) => SEV_ORDER.indexOf(a.value) - SEV_ORDER.indexOf(b.value));
    for (const r of order) {
      const seg = el("i"); seg.style.width = `${(r.count / sum) * 100}%`; seg.style.background = sevColor(r.value);
      const tip = () => [tipLine(titleCase(r.value)), tipLine(null, `${fmt(r.count)} events · ${pct(r.count, sum)}`), ...(opts.onClick ? [tipLine(null, "Click to analyse")] : [])];
      attachTip(seg, tip);
      if (opts.onClick) seg.addEventListener("click", () => opts.onClick(r.value)); else seg.style.cursor = "default";
      bar.append(seg);
      const s = el("span"); const d = el("span", "sevdot"); d.style.background = sevColor(r.value);
      s.append(d, document.createTextNode(r.value), el("b", null, pct(r.count, sum))); leg.append(s);
      if (opts.onClick) { s.classList.add("click"); s.style.cursor = "pointer"; attachTip(s, tip); s.addEventListener("click", () => opts.onClick(r.value)); }
    }
    if (!rows.length) leg.append(el("span", null, "No data yet"));
  }

  /* Labelled histogram (horizontal bars), e.g. events per host. rows: [{label, count}] */
  function histogram(box, rows, opts = {}) {
    box.replaceChildren();
    const sum = rows.reduce((a, r) => a + r.count, 0) || 1, max = Math.max(1, ...rows.map((r) => r.count));
    for (const r of rows) {
      const li = el("li"); const bs = el("span", "bs"); const bi = el("i");
      bi.style.width = `${(r.count / max) * 100}%`; if (opts.color) bi.style.setProperty("--bc", opts.color);
      bs.append(bi);
      li.append(el("span", "hl", r.label), bs, el("span", "bv", fmt(r.count)));
      attachTip(li, () => [tipLine(r.label), tipLine(null, `${fmt(r.count)} ${opts.unit || "hosts"} · ${pct(r.count, sum)}`), ...(opts.note ? [tipLine(null, opts.note(r))] : [])]);
      box.append(li);
    }
    if (!rows.some((r) => r.count)) { box.replaceChildren(el("li", "muted", opts.empty || "Not enough data yet")); }
  }

  // ---- Intel panel wrappers
  function drawDonut(rows) {
    donutChart($("donut"), $("topClass"), rows, { color: classColor, describe: (v) => CLASS_INFO[v], onClick: (v) => openScoped("attack_class", v) });
  }
  // "Attack type: Scanning · Affected city: Accra" for a filtered selection
  function filtersLabel(qs) {
    const parts = [];
    for (const [k, v] of new URLSearchParams(qs)) parts.push(k === "time" ? filterValueLabel(k, v) : `${FILTER_NAMES[k] || k}: ${filterValueLabel(k, v)}`);
    return parts.join(" · ") || "All events";
  }

  // ---- one model for selections: a list of [field, value] pairs
  // The analysis being shown, as pairs (so it can be narrowed further or applied to the map).
  function scopePairs(kind, value) {
    if (!kind) return [];
    if (kind === "filters") return [...new URLSearchParams(value)];
    if (kind === "time") {
      const [span, sk, ...rest] = String(value).split("|");
      return [["time", span], ...(sk ? scopePairs(sk, rest.join("|")) : [])];
    }
    if (kind === "route") {
      const [s, d] = String(value).split(">"); const [sc, sg] = s.split("|"); const [dc, dg] = (d || "").split("|");
      return [["src_city", sc], ["src_geo", sg], ["dst_city", dc], ["dst_geo", dg]].filter(([, v]) => v);
    }
    if (kind === "dst_place") { const [dc, dg] = String(value).split("|"); return [["dst_city", dc], ["dst_geo", dg]].filter(([, v]) => v); }
    return [[kind, value]];
  }
  // Open the narrowest analysis for a list of pairs: one entity on its own, otherwise a filtered selection.
  // `base` may hold several values of a multi-select field (e.g. two attack types); a field in `extra`
  // replaces it (narrowing a deep dive).
  function openPairs(base, extra = []) {
    const replaced = new Set(extra.map(([k]) => k));
    const flatAll = [...base.filter(([k]) => !replaced.has(k)), ...extra];
    const seen = new Map();
    for (const [k, v] of flatAll) seen.set(k, v);
    const multi = flatAll.length !== seen.size;   // a multi-select field with several values
    if (multi) return openInsight("filters", new URLSearchParams(flatAll).toString());
    const flat = [...seen];
    if (flat.length === 1) return openInsight(flat[0][0], flat[0][1]);
    const has = (...ks) => ks.every((k) => seen.has(k));
    // keep the dedicated analyses when they fit exactly
    if (flat.length === 2 && has("dst_city", "dst_geo")) return openInsight("dst_place", `${seen.get("dst_city")}|${seen.get("dst_geo")}`);
    if (flat.length === 4 && has("src_city", "src_geo", "dst_city", "dst_geo"))
      return openInsight("route", `${seen.get("src_city")}|${seen.get("src_geo")}>${seen.get("dst_city")}|${seen.get("dst_geo")}`);
    if (flat.length === 2 && seen.has("time")) {
      const [ok, ov] = flat.find(([k]) => k !== "time");
      return openInsight("time", `${seen.get("time")}|${ok}|${ov}`);
    }
    openInsight("filters", new URLSearchParams(flat).toString());
  }
  // The parts of a combined selection, as chips under the analysis title: click a part to open it on its
  // own (for example a host with all its reports), or × to remove it and widen the selection again.
  function renderParts(d) {
    let box = $("iParts");
    if (!box) { box = el("div", "i-parts"); box.id = "iParts"; $("iRange").after(box); }
    box.replaceChildren();
    const pairs = scopePairs(d.kind, d.value);
    if (pairs.length < 2) { box.hidden = true; return; }
    box.hidden = false;
    box.append(el("span", "i-parts-lbl", "Selection:"));
    pairs.forEach(([k, v], i) => {
      const chip = el("span", "fchip part");
      const open = el("button", "part-open"); open.type = "button";
      open.append(el("b", null, k === "time" ? "Time:" : `${FILTER_NAMES[k] || k}:`), el("span", "mono", filterValueLabel(k, v)));
      open.title = "Open this part on its own";
      open.addEventListener("click", () => openPairs([[k, v]]));
      const x = el("button", null, "×"); x.type = "button"; x.title = "Remove this part (widen the selection)";
      x.setAttribute("aria-label", `Remove ${FILTER_NAMES[k] || k}`);
      x.addEventListener("click", () => openPairs(pairs.filter((_, j) => j !== i)));
      chip.append(open, x); box.append(chip);
    });
  }
  // Inside an analysis: narrow it by one more field (deep dive)
  function drillTo(d, key, value, label) {
    cacheLabel(key, value, label);
    openPairs(scopePairs(d.kind, d.value), [[key, value]]);
  }
  // Intel entries and map drawings reflect the active filters, so their analysis does too: clicking
  // a network while Scanning is selected analyses "Scanning + that network", not all of the network.
  function openScoped(kind, value, label) {
    cacheLabel(kind, value, label);
    const base = [...filterParams()];
    if (!base.length) return openInsight(kind, value);
    openPairs(base, scopePairs(kind, value));
  }
  const intelPick = (start, minutes) => openScoped("time", `${start}+${minutes}`);
  function drawHourClass(byClass, curHour) { stackedHours($("hourClass"), byClass, curHour, $("hbcInfo"), intelPick); }
  function drawSeverity(rows) {
    severityMix($("sevBar"), $("sevLegend"), rows, { onClick: (v) => openScoped("severity", v) });
  }
  function drawTimeline(buckets) { quarterHours($("timeline"), buckets, $("tlInfo"), null, state.stats?.current_quarter, intelPick); }

  // ------------------------------------------------------------------ analytics (insight dialog)
  const KIND_FIELD = { source: "source", attack_class: "attack_class", infection: "infection", src_city: "src_city", http_host: "http_host", dst_geo: "dst_geo", src_ip: "src_ip", src_asn: null, dst_ip: null,
    dst_port: "dst_port", severity: "severity", tag: "tag", protocol: "protocol" };
  const BREAK_TITLES = {
    source: "Share by source report", attack_class: "Share by attack type",
    infection: "Infections / categories", src_city: "Affected cities", src_asn: "Source networks", dst_asn: "Destination networks", http_host: "C2 / sinkhole domains",
    dst_ip: "Destination IPs", dst_geo: "Target countries", dst_port: "Target ports",
    http_agent: "User agents", request: "Request paths", severity: "Severity", tag: "Tags",
  };
  // every breakdown in the analysis view can be analysed further. In demo mode concealed values
  // (destination IPs, domains, user agents, paths) arrive as opaque references the server resolves.
  const PIVOT_KEYS = ["source", "attack_class", "infection", "src_city", "src_asn", "dst_asn", "http_host", "dst_ip", "dst_geo",
    "dst_port", "http_agent", "request", "severity", "tag", "protocol", "route", "dst_place", "filters", "time"];
  const PIVOTS = { has: (k) => PIVOT_KEYS.includes(k) };
  const insightStack = [];
  function entityLabel(kind, v) {
    if (kind === "src_city") return titleCase(v);
    if (kind === "dst_geo") return countryName(v);
    if (kind === "src_asn" || kind === "dst_asn") return /^\d+$/.test(v) ? `AS${v}` : v;
    if (kind === "source") return srcLabel(v);
    if (kind === "dst_port") return `Port ${v}`;
    if (kind === "filters") return filtersLabel(v);
    if (kind === "src_geo") return countryName(v);
    if (kind === "dst_city") return titleCase(v);
    if (kind === "time") {
      const [s, m] = String(v).split("|")[0].split("+").map(Number);
      // minutes may carry seconds (a window ending exactly at the replay position)
      const hms = (x) => { if (x >= 1440) return "24:00"; const tot = Math.round(x * 60), h = Math.floor(tot / 3600), mi = Math.floor(tot / 60) % 60, se = tot % 60;
        return `${String(h).padStart(2, "0")}:${String(mi).padStart(2, "0")}${se ? ":" + String(se).padStart(2, "0") : ""}`; };
      return `${hms(s || 0)} to ${hms((s || 0) + (m || 60))} UTC`;
    }
    if (kind === "severity") return titleCase(v);
    if (kind === "route" || kind === "dst_place") {
      const nice = (p) => { const [c, cc] = String(p).split("|"); return [titleCase(c || ""), cc ? countryName(cc) : ""].filter(Boolean).join(", ") || "Unknown place"; };
      if (kind === "route") { const [s, d] = String(v).split(">"); return `${nice(s)} → ${nice(d)}`; }
      return nice(v);
    }
    return v;
  }
  // opts.drill: open this figure's list straight away (e.g. "hosts" from the top bar's Source hosts)
  async function openInsight(kind, value, push = true, opts = {}) {
    hideTip();
    state.pendingDrill = opts.drill || null;
    if (push) insightStack.push([kind, value]);
    $("iBack").hidden = insightStack.length < 2;
    $("iKind").textContent = "Analysis";
    $("iTitle").textContent = entityLabel(kind, value);
    $("iRange").textContent = "";
    $("iBody").replaceChildren(el("div", "i-loading", "Analysing…"));
    // every analysis can filter the map, except a bare time window (the replay itself is the time axis)
    $("iFilter").hidden = scopePairs(kind, value).every(([k]) => k === "time");
    $("insight").hidden = false; $("modalScrim").hidden = false;
    $("btnInsightClose").focus();
    let d;
    try {
      d = await getJSON(`/api/insight?kind=${encodeURIComponent(kind)}&value=${encodeURIComponent(value)}&at=${encodeURIComponent(new Date(replayNow()).toISOString())}`);
    } catch (err) { $("iBody").replaceChildren(el("div", "i-loading", `Could not load analysis: ${err.message}`)); return; }
    const cur = insightStack[insightStack.length - 1];
    if (!cur || cur[0] !== kind || cur[1] !== value) return;
    renderInsight(d);
  }
  function renderInsight(d) {
    $("iKind").textContent = d.kind === "filters" && !d.value ? "Whole day · all reports" : d.kind_label;
    if (d.value_label && !["filters", "time", "route", "dst_place"].includes(d.kind)) cacheLabel(d.kind, d.value, d.value_label);
    const title = $("iTitle"); title.replaceChildren();
    if (d.kind === "infection") { const sw = el("span", "swatch"); sw.style.background = infColor(d.value); title.append(sw); }
    if (d.kind === "attack_class" || d.kind === "source") { const sw = el("span", "swatch"); sw.style.background = classColor(d.kind === "source" ? state.facets?.source_class?.[d.value] : d.value); title.append(sw); }
    if (d.kind === "dst_geo") title.append(flagImg(d.value));
    let titleText = d.value_label || entityLabel(d.kind, d.value);
    if (d.kind === "time" && d.scope && d.scope.kind) titleText += ` · ${d.scope_label || entityLabel(d.scope.kind, d.scope.value)}`;
    title.append(document.createTextNode(titleText));
    const t = (s) => (s ? s.replace("T", " ").slice(11, 19) : "n/a");
    const day = String(d.as_of || d.first || new Date(replayNow()).toISOString()).slice(0, 10);
    const dw = dayWord(day);
    $("iRange").textContent = d.total ? `Attacks reported by Shadowserver as of ${day}` : `No attacks reported by Shadowserver yet for ${day}`;
    $("iRange").title = `${dw === day ? "" : `${dw}, `}${day} (UTC), the day being replayed`;
    renderParts(d);
    if (d.kind === "infection") renderKb($("iKb"), d.value);
    else if (d.kind === "src_ip" && d.breakdowns?.infection?.length) renderHostMalpedia($("iKb"), d.breakdowns.infection.map((r) => r.value));
    else $("iKb").replaceChildren();

    const body = $("iBody"); body.replaceChildren();
    const kpis = el("div", "i-kpis");
    const drill = el("section", "m-sec i-drill"); drill.hidden = true;
    // every figure opens the list behind it (hosts to follow up, domains, destinations, reports)
    const kpi = (v, k, metric) => {
      const b = el("div", "i-kpi"); b.append(el("div", "v", v), el("div", "k", k)); kpis.append(b);
      if (!metric || !d.total) return;
      b.classList.add("click"); b.tabIndex = 0; b.setAttribute("role", "button"); b.dataset.metric = metric;
      b.setAttribute("aria-label", `${k}: ${v}. Show the details`);
      b.append(el("div", "go", "Details ›"));
      const open = () => toggleDrill(d, metric, b, drill, kpis);
      b.addEventListener("click", open);
      b.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
    };
    kpi(fmt(d.total), "Events", "events");
    kpi(d.all_total ? pct(d.total, d.all_total) : `${(d.share * 100).toFixed(1)}%`, "Share of all events", "share");
    if (d.kind !== "src_ip") kpi(fmt(d.hosts), "Source hosts", "hosts");
    kpi(fmt(d.c2_hosts), "C2 domains", "c2");
    kpi(fmt(d.dst_ips), "Destination IPs", "dst_ips");
    kpi(d.beacon_median_label || "n/a", "Median repeat interval", d.kind !== "src_ip" ? "interval" : null);
    if (d.kind !== "src_ip") kpi(fmt(d.multi_infected), "Hosts with multiple threats", "multi");
    kpi(fmt(d.reports), "Reports", "reports");
    if (d.kind !== "src_ip") kpi(fmt(d.cross_report_hosts), "Cross-report hosts", "cross");
    body.append(kpis);
    if (d.total) body.append(el("div", "i-kpi-hint", "Click any figure for the list behind it, such as the hosts that need follow-up."));
    body.append(drill);

    const grid = el("div", "i-grid");
    const f = el("section", "m-sec"); f.append(el("h3", null, "Key findings"));
    const ul = el("ul", "i-findings");
    for (const s of d.insights.length ? d.insights : ["No events have been reported for this selection yet."]) ul.append(el("li", null, s));
    f.append(ul);
    // composition donut: attack types when mixed, otherwise infections / categories, otherwise reports
    const B = d.breakdowns;
    // first breakdown that actually splits this selection into more than one part
    const PAL = ["#5b8def", "#12a594", "#e2a336", "#8e7cf0", "#d6409f", "#46a758", "#00a2c7", "#c98a5e"];
    const byIndex = (rows) => (v) => PAL[Math.max(0, rows.findIndex((r) => r.value === v)) % PAL.length];
    const candidates = [
      B.attack_class && { title: "Share by attack type", rows: B.attack_class, color: classColor, kind: "attack_class", describe: (v) => CLASS_INFO[v] },
      B.infection && { title: "Share by infection / category", rows: B.infection, color: infColor, kind: "infection", describe: (v) => kbEntry(v)?.title },
      B.source && { title: "Share by source report", rows: B.source, color: (v) => classColor(state.facets?.source_class?.[v]), kind: "source" },
      B.dst_geo && { title: "Share by target country", rows: B.dst_geo.map((r) => ({ ...r, label: countryName(r.value) })), color: byIndex(B.dst_geo), kind: "dst_geo" },
      B.src_city && { title: "Share by affected city", rows: B.src_city.map((r) => ({ ...r, label: titleCase(r.label) })), color: byIndex(B.src_city), kind: "src_city" },
    ].filter(Boolean);
    const mix = candidates.find((c) => c.rows.length > 1) || candidates.find((c) => c.rows.length) || { title: "Share", rows: [], color: () => ACCENT, kind: "" };
    const mixCard = card(mix.title, "donut");
    // right column: composition donut + networks donut, so the space next to the findings is used
    const netRows = (d.kind === "src_asn" ? B.dst_asn : B.src_asn) || [];
    const netKind = d.kind === "src_asn" ? "dst_asn" : "src_asn";
    const cNet = card(d.kind === "src_asn" ? "Destination networks" : "Source networks", "donut");
    const side = el("div", "i-side"); side.append(mixCard.sec, cNet.sec);
    grid.append(f, side);
    body.append(grid);

    const axis = () => { const ax = el("div", "tl-axis mono"); for (const l of ["00", "06", "12", "18", "24"]) ax.append(el("span", null, l)); return ax; };
    const row1 = el("div", "i-charts");
    const cHour = card(d.peak_hour !== null ? `Events by hour and type · peak ${String(d.peak_hour).padStart(2, "0")}:00` : "Events by hour and type", "canvas");
    cHour.sec.append(axis());
    const cQuarter = card("Activity by 15 minutes", "canvas");
    cQuarter.sec.append(axis());
    const cSev = card("Severity mix", "sev");
    row1.append(cHour.sec, cQuarter.sec, cSev.sec);
    body.append(row1);

    // draw after layout so canvases have a size (setTimeout also runs when the tab is in the background)
    setTimeout(() => {
      donutChart(mixCard.svg, mixCard.legend, mix.rows, { color: mix.color, describe: mix.describe, center: "events", onClick: mix.kind === d.kind ? null : (v) => drillTo(d, mix.kind, v) });
      // clicking a bar analyses that time window within this same selection
      const scope = (start, minutes) => drillTo(d, "time", `${start}+${minutes}`);   // within this selection
      stackedHours(cHour.canvas, d.hours_by_class || {}, d.current_hour, null, scope);
      const q = d.as_of ? Math.floor((Date.parse(d.as_of) - Date.parse(d.as_of.slice(0, 10) + "T00:00:00Z")) / 900000) : null;
      quarterHours(cQuarter.canvas, d.timeline || [], null, d.kind === "infection" ? infColor(d.value) : ACCENT, q, scope);
      severityMix(cSev.bar, cSev.legend, d.severity || [], d.kind === "severity" ? {} : { onClick: (v) => drillTo(d, "severity", v) });
      const palette = ["#5b8def", "#12a594", "#e2a336", "#8e7cf0", "#d6409f", "#46a758", "#00a2c7", "#c98a5e"];
      const netColor = (v) => palette[Math.max(0, netRows.findIndex((r) => r.value === v)) % palette.length];
      donutChart(cNet.svg, cNet.legend, netRows, { color: netColor, center: "events", onClick: (v) => drillTo(d, netKind, v) });
    }, 0);

    const breaks = el("div", "i-breaks");
    for (const [key, rows] of Object.entries(d.breakdowns)) {
      const sec = el("section", "m-sec"); sec.append(el("h3", null, BREAK_TITLES[key] || key));
      const list = el("ul", "brk");
      for (const r of rows) {
        const li = el("li"); const bl = el("span", "bl");
        const kc = key === "infection" ? infColor(r.value) : key === "attack_class" ? classColor(r.value) : key === "source" ? classColor(state.facets?.source_class?.[r.value]) : key === "severity" ? sevColor(r.value) : null;
        if (kc) { const sw = el("span", "swatch"); sw.style.background = kc; bl.append(sw); }
        if (key === "dst_geo") bl.append(flagImg(r.value));
        const label = key === "src_city" ? titleCase(r.label) : key === "dst_geo" ? countryName(r.value) : r.label;
        const lab = el("span", ["http_host", "dst_ip", "request", "http_agent", "infection"].includes(key) ? "mono" : null, label); lab.title = r.label;
        bl.append(lab);
        const bs = el("span", "bs"); const bi = el("i"); bi.style.width = `${Math.max(2, r.share * 100)}%`;
        if (kc) bi.style.setProperty("--bc", kc);
        bs.append(bi);
        li.append(bl, bs, el("span", "bv", pct(r.share, 1)));
        attachTip(li, () => [tipLine(lab.textContent), tipLine(null, `${fmt(r.count)} events · ${pct(r.count, d.total)} of this selection`),
          ...(PIVOTS.has(key) ? [tipLine(null, "Click to analyse")] : [])]);
        if (PIVOTS.has(key)) { li.classList.add("click"); li.addEventListener("click", () => drillTo(d, key, r.value, label)); }
        list.append(li);
      }
      sec.append(list); breaks.append(sec);
    }
    body.append(breaks);

    if (d.top_hosts.length && d.kind !== "src_ip") {
      const sec = el("section", "m-sec wide"); sec.append(el("h3", null, "Most active source hosts"));
      const wrap = el("div", "table-wrap"); const tbl = el("table", "hosts");
      const thead = el("thead"); const hr = el("tr");
      for (const h of ["Host IP", "Events", "Infections / categories", "City", "ASN", "First seen", "Last seen"]) hr.append(el("th", null, h));
      thead.append(hr); tbl.append(thead);
      const tb = el("tbody");
      for (const h of d.top_hosts) {
        const tr = el("tr", "click");
        tr.append(el("td", "mono", h.ip), el("td", "mono", fmt(h.count)), el("td", "mono", h.infections.join(", ")), el("td", null, titleCase(h.city)),
          el("td", null, h.asn || "n/a"), el("td", "mono", t(h.first)), el("td", "mono", t(h.last)));
        tr.addEventListener("click", () => drillTo(d, "src_ip", h.ref || h.ip, h.ip));
        tb.append(tr);
      }
      tbl.append(tb); wrap.append(tbl); sec.append(wrap); body.append(sec);
    }
    autoExplain(body);   // hover explanations for the KPI labels and chart titles
    // opened from a top-bar figure: show that figure's list straight away
    if (state.pendingDrill) {
      const tile = kpis.querySelector(`.i-kpi[data-metric="${state.pendingDrill}"]`);
      state.pendingDrill = null;
      if (tile) tile.click();
    }
  }

  // ------------------------------------------------------------------ figure drill-down
  async function toggleDrill(d, metric, tile, box, kpis) {
    const same = box.dataset.metric === metric && !box.hidden;
    for (const k of kpis.querySelectorAll(".i-kpi")) { k.classList.remove("active"); k.setAttribute("aria-expanded", "false"); }
    if (same) { box.hidden = true; box.dataset.metric = ""; return; }
    tile.classList.add("active"); tile.setAttribute("aria-expanded", "true");
    box.dataset.metric = metric; box.hidden = false;
    box.replaceChildren(el("div", "i-loading", "Loading the details…"));
    box.scrollIntoView({ block: "nearest", behavior: reducedMotion ? "auto" : "smooth" });
    let r;
    try {
      r = await getJSON(`/api/insight/drill?kind=${encodeURIComponent(d.kind)}&value=${encodeURIComponent(d.value)}&metric=${metric}&at=${encodeURIComponent(d.as_of)}`);
    } catch (err) { box.replaceChildren(el("div", "i-loading", `Could not load the details: ${err.message}`)); return; }
    if (box.dataset.metric !== metric) return;
    renderDrill(box, r, d);
  }
  function drillCell(key, v) {
    if (Array.isArray(v)) return v.join(", ");
    if (typeof v === "number") return fmt(v);
    if (key === "city") return titleCase(v || "");
    if (key === "country") return v ? countryName(v) : "";
    return v ?? "";
  }
  function renderDrill(box, r, d) {
    box.replaceChildren();
    const head = el("div", "drill-head");
    head.append(el("h3", null, r.title));
    const acts = el("div", "drill-actions");
    if (r.rows.length) {
      // only roles with the export permission get the downloads (external viewers do not)
      if (document.body.dataset.export === "1") {
      const dl = el("button", "pill-btn", "Download CSV"); dl.type = "button";
      dl.title = "Save this list as a spreadsheet file (CSV)";
      dl.addEventListener("click", () => downloadDrill(r, d));
      acts.append(dl);
      const label = `${d.kind_label || ""}: ${d.value_label || d.value}${d.scope_label ? ` (${d.scope_label})` : ""}`;
      acts.append(pdfButton(`/api/insight/report?kind=${encodeURIComponent(d.kind)}&value=${encodeURIComponent(d.value)}&metric=${r.metric}&at=${encodeURIComponent(d.as_of)}&all=1&label=${encodeURIComponent(label)}`));
      }
      if (MP_ON && r.columns.some(([k]) => k === "infections" || k === "infection")) {
        const mp = el("button", "pill-btn mp-btn", r.mp ? `${MP_NAME} ✓` : `Enrich with ${MP_NAME}`); mp.type = "button";
        mp.title = "Look up every infection / category in this list on Malpedia (each name once) and add the result to the table and the CSV";
        mp.disabled = !!r.mp;
        mp.addEventListener("click", async () => {
          mp.disabled = true; mp.textContent = `Looking up ${MP_SRC}…`;
          try {
            let all = r;
            if (r.total > r.rows.length) { try { all = await getJSON(`/api/insight/drill?kind=${encodeURIComponent(d.kind)}&value=${encodeURIComponent(d.value)}&metric=${r.metric}&at=${encodeURIComponent(d.as_of)}&all=1`); } catch { all = r; } }
            const names = [...new Set(all.rows.flatMap((row) => [].concat(row.infections || row.infection || [])).filter(Boolean))];
            r.mp = await window.LGLookup.run({ kind: "malpedia", values: names, title: CFG.malpedia ? "Looking up on Malpedia" : "Looking up the definitions",
              intro: `${names.length} infection${names.length === 1 ? "" : "s"} / categor${names.length === 1 ? "y" : "ies"} in this list, each looked up once. ` +
                (CFG.malpedia ? "Malpedia's answers are kept for a week, so names seen before come back at once; new names are asked at most 30 a minute." :
                  "Malpedia is not set up here: the Looking Glass definitions answer.") });
            renderDrill(box, r, d);
          } catch (err) { mp.disabled = false; mp.textContent = `Malpedia failed: ${err.message} (retry)`; }
        });
        acts.append(mp);
      }
    }
    const x = el("button", "pill-btn", "Close"); x.type = "button";
    x.addEventListener("click", () => { box.hidden = true; box.dataset.metric = ""; box.parentElement?.querySelectorAll(".i-kpi.active").forEach((k) => { k.classList.remove("active"); k.setAttribute("aria-expanded", "false"); }); });
    acts.append(x); head.append(acts); box.append(head);
    if (r.intro) box.append(el("p", "drill-intro", r.intro));
    if (r.mp) {                                      // the Malpedia answer for every name in the list
      const det = el("details", "mp-batch"); det.append(el("summary", null, `Malpedia: ${mpSummary(r.mp)}. Show each name and why`));
      renderMpList(det, r.mp); box.append(det);
    }
    if (!r.rows.length) { box.append(el("p", "drill-empty", r.empty)); return; }

    const hostRows = r.row_kind === "src_ip";
    const canOpen = hostRows || PIVOTS.has(r.row_kind);
    const wrap = el("div", "table-wrap drill-wrap"); const tbl = el("table", "hosts drill-table");
    const thead = el("thead"); const hr = el("tr");
    const cols = r.mp ? [...r.columns, ["_malpedia", "Malpedia"]] : r.columns;
    for (const [, label] of cols) hr.append(el("th", null, label));
    thead.append(hr); tbl.append(thead);
    const tb = el("tbody");
    for (const row of r.rows) {
      const tr = el("tr");
      for (const [key] of cols) {
        const v = row[key];
        if (key === "_malpedia") {
          const td = el("td", "mp-cell");
          for (const n of [].concat(row.infections || row.infection || [])) {
            const x = r.mp?.[n]; if (!x) continue;
            const det = el("details", `mp-mini ${x.found ? "ok" : "no"}`);
            const sum = el("summary"); sum.append(el("b", "mono", n), document.createTextNode(` → ${mpShort(x)}`));
            det.append(sum, mpCard(x, n));
            det.addEventListener("click", (ev) => ev.stopPropagation());   // opening it does not open the host
            td.append(det);
          }
          tr.append(td); continue;
        }
        if (key === "followup") {
          const td = el("td", "fu");
          if (!v.length) td.append(el("span", "muted", "Monitor"));
          for (const reason of v) td.append(el("span", `fu-chip${/kinds|reports/i.test(reason) ? " hi" : ""}`, reason));
          td.title = v.join(" · ") || "No strong signs beyond this selection";
          tr.append(td); continue;
        }
        const txt = String(drillCell(key, v));
        const td = el("td", ["ip", "dst", "domain", "interval", "first", "last", "ports"].includes(key) || typeof v === "number" ? "mono" : null, txt);
        if (txt.length > 24) td.title = txt;
        if (key === "rhythm" && v === "Regular") td.classList.add("regular");
        tr.append(td);
      }
      const target = hostRows ? row.ref : row.value;
      if (canOpen && target) {
        tr.classList.add("click");
        tr.title = hostRows ? "Open this host's analysis" : "Open the analysis for this entry";
        const rowLabel = row.ip || row.domain || row.dst || row.report || row.infection || "";
        tr.addEventListener("click", () => drillTo(d, r.row_kind, target, rowLabel));
      }
      tb.append(tr);
    }
    tbl.append(tb); wrap.append(tbl); box.append(wrap);
    if (r.total > r.rows.length) box.append(el("p", "drill-more", `Showing the first ${fmt(r.rows.length)} of ${fmt(r.total)}.${document.body.dataset.export === "1" ? ` Download CSV saves all ${fmt(r.total)}.` : ""}`));
    else if (canOpen) box.append(el("p", "drill-more", `${fmt(r.total)} ${r.total === 1 ? "entry" : "entries"}. Click a row to analyse it.`));
  }
  // Malpedia result for one row: the families found, and why the others are not there
  function mpForRow(mp, row) {
    const names = [].concat(row.infections || row.infection || []);
    const fams = [], descs = [], notes = [];
    for (const n of names) {
      const x = mp?.[n]; if (!x) continue;
      if (x.found) { fams.push(`${n} = ${x.name} (${x.kind === "actor" ? "threat actor" : x.family}) ${x.url || ""}`.trim()); if (x.description) descs.push(`${x.name}: ${x.description}`); }
      else if (x.curated) notes.push(`${n}: ${x.title} (Looking Glass definition). ${x.description || ""} References: ${(x.references || []).join(" ")}`.trim());
      else notes.push(`${n}: ${x.title}. ${x.text || ""}`.trim());
    }
    return { families: fams.join("; "), descriptions: descs.join(" | "), notes: notes.join(" | ") };
  }
  // PDF report of a figure: executive summary, key figures, infections explained, breakdowns, the complete list
  function pdfButton(url) {
    const b = el("button", "pill-btn pdf-btn", "Download report (PDF + CSV)"); b.type = "button";
    b.title = "A ZIP file with a detailed PDF report of this figure (executive summary, key figures, priorities, the infections / categories explained with Malpedia or the definitions, breakdowns, report definitions) and the complete list as a CSV file";
    b.addEventListener("click", () => window.LGPdf.download(b, url));
    return b;
  }
  async function downloadDrill(r, d) {
    const mp = r.mp;
    if (r.total > r.rows.length) {   // the table shows the first rows; the file gets all of them
      try { r = await getJSON(`/api/insight/drill?kind=${encodeURIComponent(d.kind)}&value=${encodeURIComponent(d.value)}&metric=${r.metric}&at=${encodeURIComponent(d.as_of)}&all=1`); } catch { /* fall back to the rows shown */ }
    }
    const q = (s) => `"${String(s).replace(/"/g, '""')}"`;
    const lines = [[...r.columns.map(([, l]) => q(l)), ...(mp ? [q("Malpedia families"), q("Malpedia descriptions"), q("Not in Malpedia: what it is and why")] : [])].join(",")];
    for (const row of r.rows) {
      const cells = r.columns.map(([k]) => q(k === "followup" ? (row[k] || []).join("; ") : drillCell(k, row[k])));
      if (mp) { const m = mpForRow(mp, row); cells.push(q(m.families), q(m.descriptions), q(m.notes)); }
      lines.push(cells.join(","));
    }
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    const day = String(d.as_of || "").slice(0, 10);
    const name = String(d.value_label || d.value).replace(/[^\w.-]+/g, "-").slice(0, 40);
    a.href = URL.createObjectURL(blob); a.download = `looking-glass_${day}_${name}_${r.metric}.csv`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  /* A titled card holding one chart: kind = donut | canvas | sev | hist */
  function card(title, kind, sub) {
    const sec = el("section", "m-sec chart-card");
    sec.append(el("h3", null, title));
    if (sub) sec.append(el("div", "card-sub", sub));
    const out = { sec };
    if (kind === "donut") {
      const wrap = el("div", "donut-wrap");
      out.svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      out.svg.setAttribute("viewBox", "0 0 120 120"); out.svg.classList.add("donut");
      out.legend = el("ol", "legend");
      wrap.append(out.svg, out.legend); sec.append(wrap);
    } else if (kind === "canvas") {
      out.canvas = el("canvas", "i-chart"); sec.append(out.canvas);
    } else if (kind === "sev") {
      out.bar = el("div", "sevbar"); out.legend = el("div", "sevlegend"); sec.append(out.bar, out.legend);
    } else if (kind === "hist") {
      out.list = el("ul", "hist"); sec.append(out.list);
    }
    return out;
  }
  function closeInsight() { $("insight").hidden = true; insightStack.length = 0; if ($("modal").hidden) $("modalScrim").hidden = true; }
  $("btnInsightClose").addEventListener("click", closeInsight);
  $("iBack").addEventListener("click", () => { insightStack.pop(); const p = insightStack[insightStack.length - 1]; if (p) openInsight(p[0], p[1], false); });
  $("iFilter").addEventListener("click", () => {
    const cur = insightStack[insightStack.length - 1]; if (!cur) return;
    // the map, stream and Intel are set to exactly this analysis' selection (every part of it)
    const pairs = scopePairs(cur[0], cur[1]);
    const mapPairs = pairs.filter(([k]) => k !== "time" && k in state.filters);
    if (!mapPairs.length) return;
    for (const k of SET_KEYS) state.filters[k].clear();
    for (const k of SINGLE_KEYS) state.filters[k] = "";
    for (const [k, v] of mapPairs) { if (state.filters[k] instanceof Set) state.filters[k].add(v); else state.filters[k] = v; }
    closeInsight(); closeModal(); buildFilters(); filtersChanged();
    const timeNote = pairs.some(([k]) => k === "time") ? " The time window is not applied: the map and stream replay the whole day for this selection." : "";
    toast(`Map filtered to ${filtersLabel(new URLSearchParams(mapPairs).toString())}.${timeNote} Use Clear all above the stream to remove it.`);
  });

  // ------------------------------------------------------------------ drawer / layout
  function setDrawer(open) {
    $("drawer").classList.toggle("open", open);
    $("scrim").hidden = !open || !mq("(max-width: 1099px)");
    $("btnDrawer").setAttribute("aria-expanded", String(open));
  }
  $("btnDrawer").addEventListener("click", () => setDrawer(true));
  $("btnCloseDrawer").addEventListener("click", () => setDrawer(false));
  $("scrim").addEventListener("click", () => setDrawer(false));
  for (const tab of document.querySelectorAll(".drawer-tabs [role=tab]")) {
    tab.addEventListener("click", () => {
      for (const t of document.querySelectorAll(".drawer-tabs [role=tab]")) t.setAttribute("aria-selected", String(t === tab));
      for (const b of document.querySelectorAll(".tab-body")) b.hidden = b.dataset.body !== tab.dataset.tab;
      if (tab.dataset.tab === "intel" && state.stats) setTimeout(() => renderIntel(state.stats), 0);
    });
  }
  const wide = window.matchMedia("(min-width: 1440px)");
  function placeIntel() {
    const intel = $("intel");
    if (wide.matches) {
      $("intelCol").append(intel);
      document.querySelector('[data-tab="filters"]').click();
    } else $("intelSlot").append(intel);
    if (state.stats) setTimeout(() => renderIntel(state.stats), 0);
  }
  wide.addEventListener("change", placeIntel);
  placeIntel();
  let resizeTimer = null;
  window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (state.stats) { drawTimeline(state.stats.timeline || []); drawHourClass(state.stats.hours_by_class || {}, state.stats.current_hour); } }, 200); });

  // demo mode: the server masks network names, AS numbers, IPs and hostnames; this only switches the view
  function setDemo(on, reload = true) {
    state.demo = on;
    if (!state.demoForced) store.set("tm.demo", on);
    document.body.classList.toggle("demo", on);
    $("btnDemo").setAttribute("aria-pressed", String(on));
    $("btnDemo").disabled = state.demoForced;
    $("btnDemo").title = state.demoForced ? "Demo mode is enforced by the server (PUBLIC_DEMO=1)"
      : on ? "Demo mode on: network names, AS numbers and IP addresses are concealed. Click to show them."
        : "Demo mode: conceal network names, AS numbers and IP addresses for public presentations";
    $("demoPill").hidden = !on;
    requestAnimationFrame(fitKpis); setTimeout(fitKpis, 300);
    if (!reload) return;
    closeInsight(); closeModal();
    // concealed references and network aliases differ between the two modes, so those filters are cleared
    for (const k of ["src_ip", "http_host", "dst_ip", "http_agent", "request", "src_asn", "dst_asn"]) state.filters[k] = "";
    renderFilterBar(); renderPins();
    resetStream(); refreshStats();
  }
  $("btnDemo").addEventListener("click", () => { if (!state.demoForced) setDemo(!state.demo); });
  setDemo(state.demo, false);

  // speed + cinema
  $("speed").addEventListener("change", async (e) => {
    setPaused(false);
    state.behind = false; $("btnCatchUp").hidden = true;
    const r = replayNow();
    state.speed = Number(e.target.value) || 1;
    state.anchorReplay = r; state.anchorWall = Date.now();
    if (state.speed === 1) { try { await syncClock(); } catch { /* keep */ } }
    state.generation++; state.pending = []; state.cursor = replayNow();
    poll(); refreshStats();
  });
  // display quality: Auto / Full / Lite buttons are handled by display.js (shared with the intro and services pages)
  renderPerfUi();
  // whole-day connections layer on / off
  $("fAllFlows").checked = state.showAll;
  $("fAllFlows").addEventListener("change", (e) => { state.showAll = e.target.checked; lsSet("lg.allFlows", state.showAll ? null : "0"); });
  $("btnCinema").setAttribute("aria-pressed", String(state.cinema));
  $("btnCinema").addEventListener("click", () => {
    state.cinema = !state.cinema; baseBearing = map.getBearing() - Math.sin(cinemaT / 14) * 10;
    $("btnCinema").setAttribute("aria-pressed", String(state.cinema));
  });

  // toast
  let toastTimer = null;
  let toastIsError = false;
  function toast(msg) {
    const t = $("toast"); t.textContent = msg; t.hidden = false;
    toastIsError = /error|could not|cannot/i.test(msg);
    clearTimeout(toastTimer); toastTimer = setTimeout(hideToast, msg.length > 120 ? 12000 : 8000);
  }
  function hideToast() { $("toast").hidden = true; }

  // ------------------------------------------------------------------ intro page
  // Everything here is live: the number of reports comes from the server's collection registry
  // (new collections are discovered automatically), and the page refreshes every minute while open.
  let introTimer = null, introSvcTimer = null, introSvcVersion = null;
  function countUp(node, value, suffix = "") {
    if (reducedMotion) { node.textContent = fmt(value) + suffix; return; }
    const start = performance.now(), dur = 1100;
    const step = (t) => { const k = Math.min(1, (t - start) / dur); node.textContent = fmt(value * (1 - Math.pow(1 - k, 3))) + suffix; if (k < 1) requestAnimationFrame(step); else node.textContent = fmt(value) + suffix; };
    requestAnimationFrame(step);
    setTimeout(() => { node.textContent = fmt(value) + suffix; }, dur + 300);   // in case animation frames are paused
  }
  async function loadIntro(first) {
    let o;
    try { o = await getJSON("/api/overview"); } catch { return; }
    window.__lgIntroData = o;
    window.LGLoader?.ready();   // arriving from another page: the logo hands over once the overview has its figures
    const dayTxt = new Date(o.day + "T00:00:00Z").toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
    const sst = o.schedule && o.schedule.state;
    $("introKicker").textContent = sst === "waiting" ? `Shadowserver threat intelligence · waiting for the report of ${dayTxt}`
      : sst === "settling" ? `Shadowserver threat intelligence · the report of ${dayTxt} is arriving`
        : `Shadowserver threat intelligence · replaying ${dayTxt}`;
    $("introDayTitle").textContent = `${dayTxt} at a glance`;
    // stats
    const stats = [
      [o.total, "events observed"],
      [o.reports_active, `reports with data, of ${fmt(o.reports_total)} monitored`],
      [o.source_hosts, "source hosts"],
      [o.infections, "infections / categories"],
      [o.cities, "affected cities"],
      [o.cross_report_hosts, "hosts seen in several reports"],
    ];
    const box = $("introStats");
    if (first || !box.children.length) {
      box.replaceChildren();
      for (const [v, k] of stats) {
        const s = el("div", "intro-stat"); const vv = el("div", "v", "0"); s.append(vv, el("div", "k", k)); box.append(s);
        countUp(vv, v);
      }
    } else {
      [...box.children].forEach((s, i) => { s.querySelector(".v").textContent = fmt(stats[i][0]); s.querySelector(".k").textContent = stats[i][1]; });
    }
    // full-day activity + attack type mix
    setTimeout(() => {
      quarterHours($("introTimeline"), o.timeline, null, undefined, undefined, undefined, false);
      if (o.peak_quarter !== null) $("introPeak").textContent = `busiest: ${hhmm(o.peak_quarter * 15)} UTC`;
    }, 0);
    const bar = $("introClassBar"), leg = $("introClassLegend"); bar.replaceChildren(); leg.replaceChildren();
    for (const c of o.classes) {
      const seg = el("i"); seg.style.width = `${(c.count / Math.max(1, o.total)) * 100}%`; seg.style.background = classColor(c.value); seg.style.cursor = "default";
      attachTip(seg, () => [tipLine(c.value), tipLine(null, `${fmt(c.count)} events · ${pct(c.count, o.total)}`), tipLine(null, CLASS_INFO[c.value] || "")]);
      bar.append(seg);
      const s = el("span"); const d = el("span", "sevdot"); d.style.background = classColor(c.value);
      s.append(d, document.createTextNode(c.value), el("b", null, pct(c.count, o.total))); leg.append(s);
    }
    // the two tracks under the overview
    // each track says whether it has data; without reports for the day it is "Currently unavailable"
    const setBadge = (id, ok) => { const b = $(id); b.textContent = ok ? "Available" : "Currently unavailable"; b.classList.toggle("on", ok); b.classList.toggle("dev", !ok); };
    setBadge("trackCommsBadge", o.total > 0);
    $("trackCommsMeta").textContent = o.total
      ? `${fmt(o.reports_total)} reports monitored · ${fmt(o.total)} events on ${o.day}`
      : `${fmt(o.reports_total)} reports monitored · waiting for reports from Shadowserver for ${o.day}`;
    // no ?at=: the server uses its own replay position (the browser's clock may not be synced yet on a fresh load)
    getJSON("/api/svc/facets").then(async (f) => {
      const ok = f.total > 0;
      setBadge("trackServicesBadge", ok);
      const withData = f.reports.filter((r) => r.rows);
      $("trackServicesMeta").textContent = ok
        ? `${fmt(f.reports.length)} reports monitored · ${fmt(f.total)} records from ${fmt(withData.length)} reports on ${f.day}`
        : `${fmt(f.reports.length)} reports monitored · waiting for reports from Shadowserver for ${f.day}`;
      // every services report with its official name and Shadowserver's definition (hover)
      let defs = new Map();
      try { const g = await getJSON("/api/svc/glossary"); defs = new Map(g.reports.map((r) => [r.label, r])); } catch { /* names only */ }
      $("introSvcTitle").textContent = `${fmt(f.reports.length)} publicly accessible / vulnerable services reports monitored`;
      $("introSvcSub").textContent = ok ? `${fmt(withData.length)} with data for this day` : "waiting for reports from Shadowserver";
      const famColor = { "Exposed service": "#5b8def", "Identified device": "#12a594", "Service population": "#8e7cf0", Compromised: "#e5484d", Blocklisted: "#e2a336" };
      const ul = $("introSvcReports"); ul.replaceChildren();
      for (const r of f.reports) {
        const li = el("li", r.rows ? "on" : "off"); const sw = el("span", "swatch"); sw.style.background = famColor[r.family] || "#8b8d98";
        li.append(sw, el("span", "nm", r.label), el("span", "ct", r.rows ? fmt(r.rows) : "no data"));
        const d = defs.get(r.label) || {};
        attachTip(li, () => [tipLine(r.label), ...(d.def ? [tipLine(null, d.def)] : []), ...(d.why ? [tipLine(null, `Why it matters: ${d.why}`)] : []),
          tipLine(null, `${r.family}${d.rating ? ` · Shadowserver rating: ${d.rating}` : ""} · collection ${r.name}`), tipLine(null, r.rows ? `${fmt(r.rows)} records on this day` : "No records on this day")]);
        ul.append(li);
      }
      // services report types that were discovered but fail the field check (same box as for communications)
      const ub = $("introSvcUnsupported"), bad = f.unsupported || [];
      ub.replaceChildren(); ub.hidden = !bad.length;
      if (bad.length) {
        ub.append(el("h3", null, `${bad.length} more services report type${bad.length > 1 ? "s" : ""} discovered, not supported yet`),
          el("p", "muted", "They have a host address (ip) but lack fields the platform needs. Support will be added in a future update."));
        const list = el("ul");
        for (const r of bad) { const li = el("li"); li.append(el("span", "nm", r.label), el("span", "why", `missing ${r.missing.join(", ")}`)); list.append(li); }
        ub.append(list);
      }
    }).catch(() => {});
    // every monitored report, active ones first
    $("introReportsTitle").textContent = `${fmt(o.reports_total)} reports monitored`;
    $("introReportsSub").textContent = `${fmt(o.reports_active)} with data for this day`;
    const ul = $("introReports"); ul.replaceChildren();
    for (const r of o.reports) {
      const li = el("li", r.rows ? "on" : "off"); const sw = el("span", "swatch"); sw.style.background = classColor(r.class);
      const nm = el("span", "nm", r.label);
      li.append(sw, nm, el("span", "ct", r.rows ? fmt(r.rows) : "no data"));
      attachTip(li, () => [tipLine(r.title ? `${r.label} · ${r.title}` : r.label), ...(r.def ? [tipLine(null, r.def)] : []),
        ...(r.why ? [tipLine(null, `Why it matters: ${r.why}`)] : []),
        tipLine(null, `${r.class}${r.rating ? ` · Shadowserver rating: ${r.rating}` : ""} · collection ${r.name}`), tipLine(null, r.rows ? `${fmt(r.rows)} events on this day` : "No events on this day"),
        ...((r.warnings || []).length ? [tipLine(null, `Not in this report: ${r.warnings.join(", ").toLowerCase()}`)] : [])]);
      ul.append(li);
    }
    // discovered report types whose fields the platform cannot process yet
    const un = $("introUnsupported"), bad = o.unsupported || [];
    un.replaceChildren(); un.hidden = !bad.length;
    if (bad.length) {
      un.append(el("h3", null, `${bad.length} more report type${bad.length > 1 ? "s" : ""} discovered, not supported yet`),
        el("p", "muted", "They match the discovery rules (source / destination fields), but lack fields the platform needs to put them on the map. Support will be added in a future update."));
      const list = el("ul");
      for (const r of bad) {
        const li = el("li"); li.append(el("span", "nm", r.label), el("span", "why", `missing ${r.missing.join(", ")}`));
        attachTip(li, () => [tipLine(r.label), tipLine(null, `collection ${r.name} · layout ${r.layout}`),
          tipLine(null, `${r.required_ok} of ${r.required_total} required fields present`),
          tipLine(null, `Missing: ${r.missing.join("; ")}`), tipLine(null, "Will be supported in a future update")]);
        list.append(li);
      }
      un.append(list);
    }
    autoExplain($("intro"));
  }
  function setIntroInUrl(on) {
    const u = new URL(location.href);
    if (on) u.searchParams.set("intro", "1"); else u.searchParams.delete("intro");
    history.replaceState(null, "", u.pathname + (u.search || "") + u.hash);
  }
  function openIntro() {
    setIntroInUrl(true);
    const intro = $("intro");
    intro.hidden = false; intro.classList.remove("leaving");
    showIntroTab("overview");
    loadIntro(true);
    clearInterval(introTimer); introTimer = setInterval(() => loadIntro(false), 60000);
    // the services card follows the services platform's own clock: new collections, late records or a field-check
    // result show on the intro within ~15 s (the map's clock already refreshes the intro for communications)
    clearInterval(introSvcTimer); introSvcVersion = null;
    introSvcTimer = setInterval(async () => {
      if ($("intro").hidden) return;
      try {
        const c = await getJSON("/api/svc/clock");
        const v = `${c.data_version}|${c.sources_version}|${c.sources}|${c.unsupported}`;
        if (introSvcVersion != null && v !== introSvcVersion) loadIntro(false);
        introSvcVersion = v;
      } catch { /* next time */ }
    }, 15000);
    setTimeout(() => $("btnExplore").focus(), 50);
  }
  function closeIntro(demo) {
    clearInterval(introTimer); clearInterval(introSvcTimer);
    setIntroInUrl(false);
    try { sessionStorage.setItem("lg.introSeen", "1"); } catch { /* private mode: intro shows again on refresh */ }
    if (demo !== undefined && demo !== state.demo && !state.demoForced) setDemo(demo);
    const intro = $("intro"); intro.classList.add("leaving");
    setTimeout(() => { intro.hidden = true; }, 520);
    hideTip();
  }
  // Explore: the logo animates over the intro ("Opening …"), then the map appears
  $("btnExplore").addEventListener("click", () => { window.LGLoader?.flash("Opening reported network communications"); setTimeout(() => closeIntro(), state.lite || reducedMotion ? 0 : 350); });
  $("btnExploreDemo").addEventListener("click", () => { window.LGLoader?.flash("Opening reported network communications · demo mode"); setTimeout(() => closeIntro(true), state.lite || reducedMotion ? 0 : 350); });
  // publicly accessible / vulnerable services: its own page (/services); the buttons are plain links
  // ------------------------------------------------------------------ glossary + hover explanations
  const GLOSSARY = window.LG_GLOSSARY || [];
  const TERMS = {};
  for (const g of GLOSSARY) for (const it of g.items) TERMS[it.key] = it;
  // label text (lower case, prefix match, longest wins) -> glossary key
  const LABEL_TERMS = {
    "events yesterday": "attacks_today", "replayed so far": "replayed", "source hosts": "source_host", "source host": "source_host",
    "reports": "reports_count", "reports with data": "report", "report": "report", "cross-report hosts": "cross_report", "critical": "critical",
    "activity": "activity", "activity yesterday": "timeline", "activity by 15 minutes": "timeline", "target ports": "target_port", "target port": "target_port",
    "user agents": "user_agent", "request paths": "request_path", "replaying events": "replay", "replaying events of": "replay_date", "replay time (utc)": "replay_date", "display": "display", "replay time": "replay_date", "current time (utc)": "current_time", "event time": "event_time", "severity": "severity",
    "severity mix": "severity", "infection / category": "infection", "infections / categories": "infection", "top infections": "infection",
    "destination": "destination", "destination ips": "destination_ips", "destination networks": "network", "source networks": "network",
    "network": "network", "affected city": "affected_city", "affected cities": "affected_city", "most affected cities": "affected_city",
    "target country": "target_country", "target countries": "target_country", "tag": "tag", "attack type": "attack_type",
    "attack types": "attack_type", "share by attack type": "attack_type", "source report": "report", "source reports": "report",
    "share by source report": "report", "share by infection": "infection", "share by target country": "target_country",
    "share by affected city": "affected_city", "events by hour": "attack_type", "key findings": "key_findings", "events": "event",
    "events observed": "event", "share of all events": "share", "c2 domains": "c2_domains", "contacted c2": "c2_domains",
    "c2 / sinkhole domains": "c2_domains", "median repeat interval": "median_interval", "hosts with multiple threats": "multi_threat",
    "hosts seen in several": "cross_report", "event stream": "stream", "filters": "filters", "intel": "intel",
    "most active source hosts": "source_host",
  };
  const LABEL_KEYS = Object.keys(LABEL_TERMS).sort((a, b) => b.length - a.length);
  function termFor(text) {
    const t = (text || "").trim().toLowerCase();
    if (!t) return null;
    if (LABEL_TERMS[t]) return LABEL_TERMS[t];
    const k = LABEL_KEYS.find((p) => t.startsWith(p));
    return k ? LABEL_TERMS[k] : null;
  }
  function explain(node, key) {
    const it = TERMS[key];
    if (!it || node.dataset.term) return;
    node.dataset.term = key;
    node.classList.add("term");
    attachTip(node, () => [tipLine(it.term), tipLine(null, it.def),
      ...(node.closest(".kpi.click, .i-kpi.click") ? [el("div", "tt-hint", "Click to analyse")] : []),
      el("div", "tip-more", "Full list: Overview, then Glossary")]);
  }
  function autoExplain(root) {
    const sel = "h2, h3, .kpi-label, .stream-cols span, .grid2 label > span, .i-kpi .k, .intro-stat .k";
    for (const n of root.querySelectorAll(sel)) {
      if (n.dataset.term || n.closest(".intro-reports, .legend, #glGroups")) continue;
      // only the label's own text (headings may contain a count span)
      const own = [...n.childNodes].filter((c) => c.nodeType === 3).map((c) => c.textContent).join(" ").trim() || n.textContent;
      const key = termFor(own);
      if (key) explain(n, key);
    }
  }
  // draws glossary groups into a box; reports carry a link to their page on shadowserver.org
  function drawGlossary(box, groups, q) {
    box.replaceChildren();
    let shown = 0;
    for (const g of groups) {
      const items = g.items.filter((it) => !q || it.term.toLowerCase().includes(q) || it.def.toLowerCase().includes(q));
      if (!items.length) continue;
      const sec = el("section", "gl-group"); sec.append(el("h3", null, g.group));
      const dl = el("dl");
      for (const it of items) {
        const dd = el("dd", null, it.def);
        if (it.url) { const a = el("a", "gl-link", "Shadowserver report page ↗"); a.href = it.url; a.target = "_blank"; a.rel = "noopener"; dd.append(" ", a); }
        dl.append(el("dt", null, it.term), dd); shown++;
      }
      sec.append(dl); box.append(sec);
    }
    if (!shown) box.append(el("p", "muted", "No matching terms."));
    return shown;
  }
  const SVC_GROUP = "Publicly accessible / vulnerable services";
  // intro page: everything, both platforms
  function renderGlossary() {
    const shown = drawGlossary($("glGroups"), [...GLOSSARY, ...reportGroups], $("glSearch").value.trim().toLowerCase());
    $("glCount").textContent = `${shown} term${shown === 1 ? "" : "s"}`;
  }
  $("glSearch").addEventListener("input", renderGlossary);
  // every report the platforms detected, defined from Shadowserver's report pages (data/service_reports.json)
  let reportGroups = [];
  async function loadReportGlossary() {
    try {
      const [a, b] = await Promise.all([getJSON("/api/report_glossary"), getJSON("/api/svc/glossary")]);
      const item = (r) => ({ term: `${r.label}${r.title && r.title !== r.label ? ` (${r.title})` : ""}`, url: r.url,
        def: `${r.def || "No definition yet."}${r.why ? ` Why it matters: ${r.why}` : ""}${r.rating ? ` Shadowserver rating: ${r.rating}.` : ""} ${r.rows ? `${fmt(r.rows)} records on the replayed day.` : "No records on the replayed day."}` });
      const byRows = (x, y) => (y.rows || 0) - (x.rows || 0) || x.label.localeCompare(y.label);
      reportGroups = [
        { group: `Network communication reports (${a.communications.length}), defined from Shadowserver's report pages`, comms: true, items: a.communications.slice().sort(byRows).map(item) },
        { group: `Publicly accessible / vulnerable services reports (${b.reports.length})`, items: b.reports.map(item) },
        { group: "Publicly accessible / vulnerable services: report families", items: b.families.map((f) => ({ term: f.name, def: f.def[0].toUpperCase() + f.def.slice(1) + "." })) },
      ];
      if (!$("introGlossary").hidden) renderGlossary();
    } catch { /* the static glossary still works */ }
  }
  loadReportGlossary();

  // ---- Glossary button in the top bar: only this platform (network communications terms and reports, with links
  // to Shadowserver); the services platform has its own, and the intro page's Glossary tab has both
  function renderGlossaryDlg() {
    const groups = [...GLOSSARY.filter((g) => g.group !== SVC_GROUP), ...reportGroups.filter((g) => g.comms)];
    const n = drawGlossary($("gdBody"), groups, $("gdSearch").value.trim().toLowerCase());
    $("gdCount").textContent = `${n} entries`;
  }
  function closeGlossaryDlg() { $("glossaryDlg").hidden = true; if ($("modal").hidden && $("insight").hidden) $("modalScrim").hidden = true; }
  $("btnGlossary").addEventListener("click", async () => {
    if (!reportGroups.length) await loadReportGlossary();
    renderGlossaryDlg(); $("glossaryDlg").hidden = false; $("modalScrim").hidden = false; $("gdSearch").focus();
  });
  $("btnGlossaryClose").addEventListener("click", closeGlossaryDlg);
  $("gdSearch").addEventListener("input", renderGlossaryDlg);
  $("modalScrim").addEventListener("click", () => { if (!$("glossaryDlg").hidden) closeGlossaryDlg(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("glossaryDlg").hidden) closeGlossaryDlg(); });

  // ---- Settings: constituency label in the top bar and on the intro page (both platforms share the settings)
  async function loadScope() {
    try {
      const st = await getJSON("/api/settings/public");
      const box = Array.isArray(st.bbox) && st.bbox.length === 4 ? st.bbox : null;
      if (JSON.stringify(box) !== JSON.stringify(state.countryBox || null)) {
        const first = state.countryBox === undefined; state.countryBox = box;
        if (typeof fitDefault === "function" && !state.interacting) try { fitDefault(!first); } catch { /* map not ready yet */ }
      }
      const pill = $("scopePill");
      pill.hidden = !st.restricted;
      pill.textContent = `Constituency: ${st.networks} network${st.networks === 1 ? "" : "s"}${st.cidrs ? ` + ${st.cidrs} range${st.cidrs === 1 ? "" : "s"}` : ""}`;
      pill.title = "Only the networks of your constituency are shown on both platforms (Settings)";
      $("introScope").textContent = st.restricted
        ? `Showing your constituency: ${st.networks} AS number${st.networks === 1 ? "" : "s"}${st.cidrs ? `, ${st.cidrs} address range${st.cidrs === 1 ? "" : "s"}` : ""} · country ${st.country_name}`
        : `Showing the whole country (${st.country_name})`;
      $("introSettings").title = `Settings · ${$("introScope").textContent}`;
      if (state.scopeVersion != null && st.version !== state.scopeVersion) {
        // new constituency: the server has reloaded the day; everything on screen reloads too
        resetStream(); loadFacets(); refreshStats(); refreshReplayed(); loadGeo(false);
        if (!$("intro").hidden) loadIntro(false);
        toast(`Settings updated: ${st.restricted ? `constituency of ${st.networks} AS number${st.networks === 1 ? "" : "s"}${st.cidrs ? ` and ${st.cidrs} address range${st.cidrs === 1 ? "" : "s"}` : ""}` : "whole country"}. The view has been refreshed.`);
      }
      state.scopeVersion = st.version;
    } catch { /* keep */ }
  }
  loadScope(); setInterval(loadScope, 10000);

  // ---- smooth hand-over to the services platform (the intro fades out like it does into the map)
  // the logo animates ("Opening …") and the next page appears from it (static/js/loader.js); plain fade as a fallback
  function goTo(url) {
    if (window.LGLoader) { window.LGLoader.go(url); return; }
    const fade = $("pageFade");
    $("intro").classList.add("leaving");
    void fade.offsetWidth; fade.classList.add("out");   // apply at once (an animation frame can be delayed)
    setTimeout(() => { location.href = url; }, reducedMotion ? 0 : 450);
  }
  for (const a of document.querySelectorAll('a[href^="/services"]')) a.addEventListener("click", (e) => { e.preventDefault(); goTo(a.getAttribute("href")); });
  window.__lgGoTo = goTo;
  // Settings: buttons (top bar, constituency label, intro page), all with the same fade
  // from the map the Settings page shows only the constituency (the map does not use a country); the intro shows both
  for (const id of ["btnSettings", "scopePill"]) $(id)?.addEventListener("click", () => goTo("/settings?for=comms"));
  $("introSettings")?.addEventListener("click", () => goTo("/settings"));
  function showIntroTab(tab) {
    for (const b of document.querySelectorAll(".intro-tabs [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.itab === tab));
    $("introOverview").hidden = tab !== "overview";
    $("introGlossary").hidden = tab !== "glossary";
    if (tab === "glossary") { renderGlossary(); }
    else if (window.__lgIntroData) setTimeout(() => quarterHours($("introTimeline"), window.__lgIntroData.timeline, null, undefined, undefined, undefined, false), 0);
  }
  for (const b of document.querySelectorAll(".intro-tabs [role=tab]")) b.addEventListener("click", () => showIntroTab(b.dataset.itab));
  renderGlossary();
  // static labels on the platform (top bar, filters, intel, stream)
  autoExplain(document);
  explain($("speed"), "speed");
  explain($("levelBar"), "activity");

  $("btnIntro").addEventListener("click", openIntro);
  $("btnOverview").addEventListener("click", openIntro);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("intro").hidden) closeIntro(); });
  // shown once per browser session; refreshes go straight to the map (use Overview to come back)
  const introSeen = (() => { try { return sessionStorage.getItem("lg.introSeen") === "1"; } catch { return false; } })();
  // "/?intro=1" (the services platform's Overview button) always opens the intro page
  // the address says whether the intro is open (?intro=1), so a refresh (e.g. after the tab sat minimised) stays there
  const wantIntro = new URLSearchParams(location.search).get("intro") === "1";
  if (introSeen && !wantIntro) $("intro").hidden = true; else openIntro();

  // ------------------------------------------------------------------ boot
  (async () => {
    renderPins();
    try { await syncClock(); } catch (err) { toast(`Cannot reach server: ${err.message}`); }
    await loadKb();
    setInterval(loadKb, 10 * 60000);   // pick up new definitions without a reload
    await loadFacets();
    await refreshStats();
    await backfill();
    poll();
    setInterval(poll, POLL_MS);
    setInterval(refreshStats, 30000);
    loadGeo(false); setInterval(() => loadGeo(false), 60000);   // whole-day connections (late rows included)
    refreshReplayed(); setInterval(refreshReplayed, 2000);
    setInterval(loadFacets, 15 * 60000);
    // the server decides which day plays (each day from 00:00 once its report is in); check it often
    setInterval(() => syncClock().catch(() => {}), 15000);   // also how new reports are noticed
    setInterval(tickHud, 250);
    // Browsers stop animations in a hidden or minimised tab, which used to leave a hole in the stream.
    // Instead, the replay pauses itself while the tab is hidden and resumes from the same moment on return
    // (no event skipped); "Catch up" then jumps to the current replay time if wanted.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        if (!state.paused) { state.autoPaused = true; setPaused(true); }
      } else if (state.autoPaused) {
        state.autoPaused = false;
        const away = Date.now() - state.pauseAt;
        setPaused(false);
        // the notice is about the platform's replay: not shown over the intro page (the replay still resumed)
        if (away > 60000 && $("intro").hidden) toast(`The replay paused while this tab was in the background (${Math.round(away / 60000)} min) and has continued from where it stopped. Press Catch up to jump to the current replay time.`);
      }
    });
  })();
})();
