/* Looking Glass · Settings (both platforms): country and constituency.
   /settings?for=comms      opened from network communications: only the constituency (the map does not use a country)
   /settings?for=services   opened from publicly accessible / vulnerable services: country and constituency
   /settings                from the intro page: both */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Math.round(n || 0).toLocaleString("en-US");
  const titleCase = (s) => (s || "").toLowerCase().replace(/(^|[\s-])\w/g, (c) => c.toUpperCase());
  const TYPE_NAMES = { isp: "Telco / ISP", bank: "Bank", finance: "Bank", education: "University / research", government: "Government", enterprise: "Enterprise",
    cloud: "Cloud / CDN", hosting: "Hosting", datacentre: "Data centre", ixp: "Exchange", unknown: "Other", private: "Other" };
  const SUFFIXES = [" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT", " WILAYA", " ATOLL"];
  const norm = (n) => { let s = String(n || "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toUpperCase().trim(); for (const x of SUFFIXES) if (s.endsWith(x)) s = s.slice(0, -x.length).trim(); return s; };
  const FOR = new URLSearchParams(location.search).get("for") || "";
  // the constituency (the user's design, 2026-11-21: one picker, in Network names & types): chosen = whole networks
  // (AS numbers), someNets + picks = networks with some of their address blocks ticked, the "Other address ranges" box
  // (#cidrs) = the rest. Saved as before: AS numbers and address ranges (CIDRs), with Apply settings.
  let data = null, chosen = new Set(), someNets = new Set(), picks = new Map(), mode = "all", shapes = null, saved = null;
  let blockInfo = { counts: null, owners: {} };      // address_blocks.py: blocks per network; saved range -> its network
  const plural = (n, one, many) => `${fmt(n)} ${n === 1 ? one : (many || `${one}s`)}`;
  const uniqSorted = (list) => [...new Set(list.map(String))].sort();
  try { sessionStorage.removeItem("lg.settingsToken"); } catch { /* the settings token is gone (2026-11-11) */ }

  // ---------------- which settings this page shows
  if (FOR === "comms") {
    $("cardCountry").hidden = true;
    $("stScope").textContent = "Settings · network communications (constituency)";
    document.title = "Looking Glass · Settings · network communications";
  } else if (FOR === "services") {
    $("stScope").textContent = "Settings · publicly accessible / vulnerable services (country and constituency)";
  }

  async function load() {
    data = await (await fetch("/api/settings", { cache: "no-store" })).json();
    Object.assign(TYPE_NAMES, data.type_labels || {});          // every network type, the ones this site added included
    const s = data.settings;
    saved = { country: s.country, timezone: s.timezone || "", networks: [...s.networks].map(String).sort(), cidrs: uniqSorted(s.cidrs) };
    // which saved ranges are a network's address blocks, and how many blocks each network has (administrators only)
    if (data.writable && window.LGBlocks) {
      try { const b = await window.LGBlocks.summary(); blockInfo = { counts: b.counts || {}, owners: b.owners || {} }; }
      catch (e) { console.warn("The address blocks could not be read:", e); }
    }
    mode = s.restricted ? "some" : "all";
    applySaved(saved.networks, saved.cidrs);
    // continent first, then its countries (2026-11-15: every country in the world)
    const conts = (data.continents && data.continents.length) ? data.continents : [...new Set(data.countries.map((c) => c.continent).filter(Boolean))];
    const cs = $("continent"); cs.replaceChildren();
    for (const k of conts) { const o = el("option", null, k); o.value = k; cs.append(o); }
    cs.closest("label").hidden = !conts.length;          // an older region-map index without continents: one list
    const mine = data.countries.find((c) => c.iso2 === s.country);
    cs.value = (mine && mine.continent) || conts[0] || "";
    fillCountries(s.country);
    fillZones(s.timezone);
    access();
    setMode(mode); await renderCountry(); refresh();
    const unknown = data.networks.filter((n) => /^AS\d+$/.test(n.name)).length;
    $("unknownCount").textContent = unknown ? `· ${unknown} unidentified` : "";
  }

  function countryLabel(c) {
    return `${c.country} · ${c.regions ? `${c.regions} regions` : c.kind === "whole" ? "the whole country as one area" : "no region map"}`;
  }
  function fillCountries(pick) {
    const cont = $("continent").value, sel = $("country"); sel.replaceChildren();
    const list = data.countries.filter((c) => !cont || !c.continent || c.continent === cont);
    for (const c of list) { const o = el("option", null, countryLabel(c)); o.value = c.iso2; sel.append(o); }
    sel.value = list.some((c) => c.iso2 === pick) ? pick : (list[0] || {}).iso2 || "";
  }

  // ---------------- Identify networks: background look-up with a progress window
  let idTimer = null;
  function idShow(on) { $("idModal").hidden = !on; $("idBack").hidden = !on; if (on) $("idClose").focus(); }
  function idRender(st) {
    const pct = st.total ? Math.round((100 * st.done) / st.total) : (st.state === "done" ? 100 : 0);
    $("idBar").style.width = `${pct}%`; $("idBar").parentElement.setAttribute("aria-valuenow", String(pct));
    for (const [id, k] of [["idDone", "done"], ["idTotal", "total"], ["idAdded", "added"], ["idKnown", "known"], ["idFailed", "failed"]]) $(id).textContent = fmt(st[k]);
    $("idNow").textContent = st.state === "running" ? (st.current ? `Now: ${st.current}` : "Starting…") : "";
    const log = $("idLog"); log.replaceChildren(...(st.log || []).map((l) => el("li", null, l))); log.scrollTop = log.scrollHeight;
    $("idMsg").textContent = st.message || "";
    $("idMsg").className = "id-msg" + (st.state === "failed" ? " bad" : st.state === "done" ? " good" : "");
    $("idTitle").textContent = st.state === "running" ? "Identifying networks…" : st.state === "failed" ? "Identifying networks: stopped" : "Networks identified";
  }
  async function idPoll() {
    clearTimeout(idTimer);
    let st; try { st = await (await fetch("/api/asns/identify", { cache: "no-store" })).json(); } catch { idTimer = setTimeout(idPoll, 2000); $("btnIdentify").disabled = false; return; }
    idRender(st);
    $("btnIdentify").disabled = false;         // polling (a click shows the progress again) or over (a click starts a new job)
    if (st.state === "running") idTimer = setTimeout(idPoll, 1000);
    else {
      idTimer = null;                          // done, failed or stopped: no job to resume (review 2026-11-13)
      if (st.state === "done" || st.state === "stopped") {
        // the choices not applied yet stay as they were
        const keep = { c: new Set(chosen), s: new Set(someNets), p: new Map([...picks].map(([a, v]) => [a, new Set(v)])), o: $("cidrs").value, m: mode };
        await load();
        chosen = keep.c; someNets = keep.s; picks = keep.p; $("cidrs").value = keep.o; setMode(keep.m);
      }
    }
  }
  $("btnIdentify").addEventListener("click", async () => {
    // a job already running: show its progress window again (closing it never stopped the polling), never a second start (review 2026-11-13)
    if (idTimer) { idShow(true); return; }
    const btn = $("btnIdentify"); btn.disabled = true;      // until the job is polled or has failed
    idShow(true); idRender({ state: "running", total: 0, done: 0, added: 0, known: 0, failed: 0, current: "", log: [], message: "" });
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
    try {
      const r = await fetch("/api/asns/identify", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: "{}" });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { btn.disabled = false; idRender({ state: "failed", total: 0, done: 0, added: 0, known: 0, failed: 0, log: [], message: j.error || `Refused (${r.status}).` }); return; }
    } catch (e) { btn.disabled = false; idRender({ state: "failed", total: 0, done: 0, added: 0, known: 0, failed: 0, log: [], message: `Could not start: ${e.message}` }); return; }
    idPoll();
  });
  $("idClose").addEventListener("click", () => idShow(false));
  $("idBack").addEventListener("click", () => idShow(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("idModal").hidden) idShow(false); });
  function access() {
    const box = $("access");
    $("cidrs").readOnly = !data.writable;         // read only: the other address ranges are shown, not changed
    if (data.writable) { box.hidden = true; return; }
    box.hidden = false; box.replaceChildren();
    box.append(document.createTextNode("Read only: changing settings needs an account with the Settings permission (administrators)."));
  }

  // ---------------- region names as Shadowserver spells them: the administrator's matches (region_matches.py)
  async function setMatch(iso, name, target, btn) {
    if (btn) btn.disabled = true;
    try {
      const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
      const r = await fetch("/api/settings/region-matches", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ country: iso, name, target }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      await renderCountry();
    } catch (e) {
      const h = $("matchHint"); h.textContent = `Not saved: ${e.message}`; h.classList.add("bad");
      if (btn) btn.disabled = false;
    }
  }
  function matchCell(x, iso, regionName, rm) {
    const td = el("td", "st-matchcell");
    if (!data.writable || !rm || !x.r) { td.textContent = x.status === "chosen" ? "your choice" : ""; return td; }
    if (x.status === "map") { td.append(el("span", "muted", "the map's own name")); return td; }
    if (x.status === "country") { td.append(el("span", "muted", "the country's name")); return td; }
    if (x.status === "chosen") {
      td.append(el("span", null, "your choice "));
      const undo = el("button", "pill-btn", "Undo"); undo.type = "button";
      undo.title = `Forget that "${x.r}" means ${regionName(x.hit || "__country__")}`;
      undo.addEventListener("click", () => setMatch(iso, x.r, "", undo)); td.append(undo); return td;
    }
    // not matched: the suggestion, or a choice of region, or "the country itself"
    if (x.suggestion) {
      const use = el("button", "lg-btn primary st-use", `Use ${regionName(x.suggestion)}`); use.type = "button";
      use.title = `Count "${x.r}" as ${regionName(x.suggestion)} (similarity ${Math.round((x.score || 0) * 100)}%)`;
      use.addEventListener("click", () => setMatch(iso, x.r, x.suggestion, use)); td.append(use);
    }
    const pick = el("select", "st-pick lg-enhance"); pick.setAttribute("aria-label", `Choose the region for ${x.r}`);
    pick.append(el("option", null, x.suggestion ? "or choose…" : "Choose the region…"));
    const c = el("option", null, "The country itself (region unknown)"); c.value = "__country__"; pick.append(c);
    for (const r of rm.regions || []) { const o = el("option", null, window.LGRegions ? window.LGRegions.shortName(r.name) : r.name); o.value = r.key; pick.append(o); }
    pick.addEventListener("change", () => { if (pick.value) setMatch(iso, x.r, pick.value, pick); });
    td.append(pick);
    return td;
  }

  // ---------------- country
  let countrySeq = 0;
  async function renderCountry() {
    const mine = ++countrySeq;
    const iso = $("country").value, info = data.countries.find((c) => c.iso2 === iso) || {};
    const hasMap = !!(info.regions || info.kind);
    $("countryMeta").textContent = info.regions ? `${info.regions} first-level regions · ${info.continent || ""}`.replace(/ · $/, "")
      : info.kind === "whole" ? "Drawn as one area: the open data has no first-level regions for it, so every record counts for the whole country"
      : "No map available for this country: its records are still counted";
    const svg = $("preview"); svg.replaceChildren(); shapes = null;
    // the map's place shows the loading line until its regions are in (2026-11-15: an empty map showed)
    document.getElementById("previewWait")?.remove();
    let wait = null;
    if (hasMap) {
      wait = el("p", "lg-loading", `Loading the map of ${info.country || iso}…`); wait.id = "previewWait";
      svg.before(wait); svg.style.visibility = "hidden";
    }
    let got = null;
    if (hasMap) { try { got = await (await fetch(`/static/data/adm1/${iso}.json`)).json(); } catch { got = null; } }
    if (mine !== countrySeq) return;           // another country was picked meanwhile: its own call draws the map (review 2026-11-13)
    wait?.remove(); svg.style.visibility = "";
    shapes = got;
    const keys = shapes ? Object.keys(shapes.regions) : [];
    const country = norm(info.country || "");
    // report region names -> map regions through the map's names, ISO names and aliases (static/js/regions.js)
    const resolve = shapes && window.LGRegions ? window.LGRegions.index(shapes)
      : (r) => { const k = norm(r); return keys.find((x) => x === k) || keys.find((x) => x.replace(/[^A-Z]/g, "") === k.replace(/[^A-Z]/g, "")) || null; };
    const shortName = (k) => (window.LGRegions ? window.LGRegions.shortName(shapes.regions[k].name) : shapes.regions[k].name);
    const whole = !!(shapes && shapes.whole);
    // what each report name matched, from the server (region_matches.py): the map's own names, the administrator's
    // choices, the country itself, or nothing yet with the closest region suggested (2026-11-15)
    let rm = null;
    try { rm = await (await fetch(`/api/settings/region-matches?country=${encodeURIComponent(iso)}`, { cache: "no-store" })).json(); } catch { rm = null; }
    if (mine !== countrySeq) return;
    const rows = rm && Array.isArray(rm.rows) ? rm.rows.map((x) => ({ r: x.name, n: x.records, status: x.status, suggestion: x.suggestion, score: x.score,
        unknown: !whole && x.target === "__country__", hit: x.target && x.target !== "__country__" ? x.target : (whole && shapes ? Object.keys(shapes.regions)[0] : null) }))
      : data.data_regions.map(([r, n]) => {
        const unknown = !whole && (window.LGRegions ? window.LGRegions.isCountry(r, { ...info, regionNames: window.LGRegions.regionNames(shapes) }) : (!r || norm(r) === country));
        return { r, n, unknown, hit: unknown || !shapes ? null : resolve(r), status: "map" };
      });
    const perRegion = new Map(); for (const x of rows) if (x.hit) perRegion.set(x.hit, (perRegion.get(x.hit) || 0) + x.n);
    const tb = $("matchTable").querySelector("tbody"); tb.replaceChildren();
    const regionName = (k) => (k === "__country__" ? "the country itself (region unknown)" : shapes && shapes.regions[k] ? shortName(k) : k);
    for (const x of rows) {
      const tr = el("tr");
      tr.append(el("td", null, x.r ? titleCase(x.r) : "(empty)"), el("td", "mono", fmt(x.n)),
        el("td", x.unknown ? "" : x.hit ? "ok" : "no", x.unknown ? "Region unknown (country only)" : x.hit ? shortName(x.hit) : "not on this map"));
      tr.append(matchCell(x, iso, regionName, rm));
      tb.append(tr);
    }
    const known = rows.filter((x) => !x.unknown), matched = known.filter((x) => x.hit).length;
    $("matchHint").classList.remove("bad");
    $("matchHint").textContent = !data.data_regions.length ? "No records loaded yet for yesterday."
      : matched === 0 && known.length
        ? `None of the ${known.length} regions in yesterday's reports are on ${info.country}'s map: the reports seem to be for another country. The map will still be shown, with a note asking to select the right country.`
        : `${matched} of ${known.length} regions in yesterday's reports are drawn on this country's map${known.length - matched ? `; ${known.length - matched} are not (their records still count in the region list)` : ""}.`;
    if (!shapes) return;
    const [x0, y0, x1, y1] = shapes.bbox, W = svg.clientWidth || 400, H = svg.clientHeight || 340;
    const kx = Math.cos((((y0 + y1) / 2) * Math.PI) / 180), s = Math.min((W - 20) / ((x1 - x0) * kx), (H - 20) / (y1 - y0));
    const ox = (W - (x1 - x0) * kx * s) / 2, oy = (H - (y1 - y0) * s) / 2, P = (lo, la) => [ox + (lo - x0) * kx * s, oy + (y1 - la) * s];
    const NS = "http://www.w3.org/2000/svg", hits = new Set(rows.map((x) => x.hit).filter(Boolean));
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    // every region is named: a label where it fits (regions with records first, then the largest), otherwise on hover
    const n = keys.length, size = n > 30 ? 8.5 : n > 15 ? 9.5 : 10.5, labels = [];
    for (const [k, reg] of Object.entries(shapes.regions)) {
      let d = "";
      for (const poly of reg.polys) for (const ring of poly) d += ring.map(([a, b], i) => { const [x, y] = P(a, b); return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`; }).join("") + "Z";
      const p = document.createElementNS(NS, "path"); p.setAttribute("d", d); p.setAttribute("class", hits.has(k) ? "hit" : "miss");
      const recs = perRegion.get(k) || 0;
      const t = document.createElementNS(NS, "title");
      t.textContent = `${shortName(k)}${reg.iso && reg.iso.length ? ` (${reg.iso.join(", ")})` : ""}${recs ? ` · ${fmt(recs)} records yesterday` : " · no records yesterday"}`;
      p.append(t); svg.append(p);
      const bb = p.getBBox(), lab = reg.label ? P(reg.label[0], reg.label[1]) : [bb.x + bb.width / 2, bb.y + bb.height / 2];
      labels.push({ x: lab[0], y: lab[1], lines: [shortName(k)], size, prio: (recs ? 1e9 + recs : 0) + bb.width * bb.height });
    }
    const L = window.LGRegions ? window.LGRegions.placeLabels(labels, { x0: 0, x1: W, y0: 0, y1: H }) : labels;
    for (const it of L) {
      const tx = document.createElementNS(NS, "text"); tx.setAttribute("x", it.x); tx.setAttribute("y", it.y + it.size * 0.35); tx.setAttribute("text-anchor", "middle");
      tx.style.fontSize = `${it.size}px`; tx.textContent = it.lines[0]; svg.append(tx);
    }
    $("countryMeta").textContent = `${keys.length} first-level regions · geoBoundaries ADM1 · ${L.length} labelled here, hover a region for any name`;
  }
  $("country").addEventListener("change", () => { fillZones(""); renderCountry(); refresh(); });
  $("continent").addEventListener("change", () => { fillCountries(""); fillZones(""); renderCountry(); refresh(); });
  // ---------------- time zone: the country's own zones (DR Congo has two), then UTC; a new country takes its usual zone
  function fillZones(pick) {
    const zs = (data.zones || {})[$("country").value] || [];
    const sel = $("tzone"); sel.replaceChildren();
    for (const z of zs) { const o = el("option", null, z.label); o.value = z.zone; sel.append(o); }
    sel.value = zs.some((z) => z.zone === pick) ? pick : (zs[0] || {}).zone || "UTC";
    window.LGSelect?.sync(sel);
    zoneMeta();
  }
  function zoneMeta() {
    const z = ((data.zones || {})[$("country").value] || []).find((x) => x.zone === $("tzone").value);
    $("tzoneMeta").textContent = !z ? "" : z.same_as_utc ? "Same as UTC today: times are shown in UTC only"
      : `Today ${z.offset}: 12:00 UTC is shown as ${String((12 + Math.floor(z.offset_minutes / 60) + 24) % 24).padStart(2, "0")}:${String(((z.offset_minutes % 60) + 60) % 60).padStart(2, "0")}, beside the UTC time`;
  }
  $("tzone").addEventListener("change", () => { zoneMeta(); refresh(); });

  // ---------------- constituency
  function setMode(m) {
    mode = m;
    for (const b of document.querySelectorAll(".st-mode button")) b.setAttribute("aria-pressed", String(b.dataset.mode === m));
    refresh();
  }
  for (const b of document.querySelectorAll(".st-mode button")) b.addEventListener("click", () => setMode(b.dataset.mode));
  const pickSet = (asn) => { if (!picks.has(asn)) picks.set(asn, new Set()); return picks.get(asn); };
  /** the saved AS numbers and ranges as the picker shows them: a range that is one of a network's address blocks is
      that network's chosen block (Some address blocks); any other range goes to Other address ranges */
  function applySaved(nets, cidrs) {
    chosen = new Set(nets.map(String)); someNets = new Set(); picks = new Map();
    const other = [];
    for (const c of cidrs) {
      const a = blockInfo.owners[c];
      if (a && !chosen.has(String(a))) { someNets.add(String(a)); pickSet(String(a)).add(c); } else other.push(c);
    }
    $("cidrs").value = other.join("\n");
  }
  // the network list (Network names & types, net-editor.js) is where the constituency is chosen: its Constituent
  // column (Not in / The whole network / Some address blocks). Choosing there switches this card to "Only selected".
  window.LGConstituency = {
    _l: [],
    state(asn) {
      const a = String(asn);
      if (mode !== "some") return "out";
      return chosen.has(a) ? "whole" : someNets.has(a) ? "some" : "out";
    },
    has: (asn) => mode === "some" && chosen.has(String(asn)),
    isSome: () => mode === "some",
    writable: () => !!(data && data.writable),
    picked: (asn) => new Set(picks.get(String(asn)) || []),
    blockCount: (asn) => (blockInfo.counts ? blockInfo.counts[String(asn)] || 0 : null),
    count: () => chosen.size,
    key: () => [mode, [...chosen].sort().join(","), [...someNets].sort().map((a) => `${a}:${(picks.get(a) || new Set()).size}`).join(","),
      blockInfo.counts ? "1" : "0", data && data.writable ? "w" : "r"].join("|"),
    setState(asn, s) {
      if (!data) return;
      const a = String(asn);
      chosen.delete(a); someNets.delete(a);
      if (s === "whole") chosen.add(a); else if (s === "some") someNets.add(a);
      if (mode !== "some" && s !== "out") setMode("some"); else refresh();
    },
    set(asn, on) { this.setState(asn, on ? "whole" : "out"); },
    toggleBlock(asn, blk, on) {
      if (!data) return;
      const a = String(asn), set = pickSet(a);
      if (on) { set.add(blk); blockInfo.owners[blk] = a; } else set.delete(blk);
      refresh();
    },
    onChange(fn) { this._l.push(fn); },
  };
  function tell() { for (const f of (window.LGConstituency && window.LGConstituency._l) || []) { try { f(); } catch { /* the other card */ } } }
  // typing an other address range chooses "Only selected networks and address ranges", like a choice in the list
  $("cidrs").addEventListener("input", () => { if (mode !== "some" && cidrList().length) setMode("some"); else refresh(); });
  const cidrList = () => $("cidrs").value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const blockList = () => [...someNets].flatMap((a) => [...(picks.get(a) || [])]);

  // ---------------- what would be applied, and whether it differs from what is in force
  function wanted() {
    return { country: $("country").value, timezone: $("tzone").value, networks: mode === "some" ? [...chosen].sort() : [],
      cidrs: mode === "some" ? uniqSorted([...blockList(), ...cidrList()]) : [] };
  }
  /** N networks, M address blocks, K other ranges (a range that is a block of a network chosen whole counts as other) */
  function counts(w) {
    const blocks = w.cidrs.filter((c) => blockInfo.owners[c] && !w.networks.includes(String(blockInfo.owners[c]))).length;
    return { nets: w.networks.length, blocks, other: w.cidrs.length - blocks };
  }
  const countsText = (k) => `${plural(k.nets, "network")}, ${plural(k.blocks, "address block")}, ${plural(k.other, "other range")}`;
  function describe(w) {
    const nets = data.networks.filter((n) => n.asns.some((a) => w.networks.includes(String(a))));
    const c = (data.countries.find((x) => x.iso2 === w.country) || {}).country || w.country;
    const names = nets.length ? ` (${nets.slice(0, 3).map((n) => n.name).join(", ")}${nets.length > 3 ? ` and ${nets.length - 3} more` : ""})` : "";
    const scope = w.networks.length || w.cidrs.length ? `constituency of ${countsText(counts(w))}${names}` : "whole country";
    const z = (((data.zones || {})[w.country] || []).find((x) => x.zone === w.timezone) || {}).label || w.timezone || "UTC";
    return FOR === "comms" ? scope : `${c} · times also in ${z} · ${scope}`;
  }
  function refresh() {
    if (!data) return;
    const w = wanted();
    // the live summary line (the choice itself is made in Network names & types, below)
    const box = $("scopeSummary"), go = el("a", null, "Network names & types"); go.href = "#cardNets";
    if (mode === "all") {
      box.replaceChildren(document.createTextNode(`Whole country: both platforms show everything in the reports (yesterday: ${fmt(data.totals.communications)} communication events, ${fmt(data.totals.services)} services records). ` +
        "To choose networks or address blocks instead, use the Constituent column of "), go, document.createTextNode(", below."));
    } else {
      const k = counts(w);
      box.replaceChildren(el("b", null, countsText(k)), document.createTextNode(k.nets || k.blocks || k.other
        ? ". Change them in the Constituent column of "
        : ". Nothing chosen yet (applying with nothing chosen means the whole country): choose networks or address blocks in the Constituent column of "),
      go, document.createTextNode(", below."));
    }
    $("envLines").textContent = `COUNTRY=${w.country}\nTIMEZONE=${w.timezone}\nCONSTITUENT_ASNS=${w.networks.join(",")}\nCONSTITUENT_CIDRS=${w.cidrs.join(",")}`;
    tell();                                       // the network list further down shows the same ticks
    // apply bar
    const dirty = JSON.stringify(w) !== JSON.stringify(saved);
    const bar = $("applyBar"); bar.classList.toggle("dirty", dirty);
    if (dirty) { bar.classList.remove("done"); $("applyState").textContent = "Unsaved changes"; $("applyDetail").textContent = `Apply to use: ${describe(w)}`; }
    else if (!bar.classList.contains("done")) { $("applyState").textContent = "No changes"; $("applyDetail").textContent = `In force: ${describe(saved)}`; }
    $("save").disabled = !dirty || !data.writable;
    $("revert").hidden = !dirty;
  }
  $("revert").addEventListener("click", () => {
    applySaved(saved.networks, saved.cidrs);
    const sc = data.countries.find((c) => c.iso2 === saved.country);
    if (sc && sc.continent) $("continent").value = sc.continent;
    fillCountries(saved.country); fillZones(saved.timezone);
    setMode(saved.networks.length || saved.cidrs.length ? "some" : "all"); renderCountry();
  });

  // ---------------- apply, then confirm once both platforms have the new settings
  $("save").addEventListener("click", async () => {
    const w = wanted();
    const bar = $("applyBar"), banner = $("banner");
    $("save").disabled = true; $("applyState").textContent = "Applying…"; $("applyDetail").textContent = describe(w);
    try {
      // the session's CSRF token (from the page) proves the change comes from this page (auth.py)
      const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
      const r = await fetch("/api/settings", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(w) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error || r.statusText);
      saved = { country: j.settings.country, timezone: j.settings.timezone || "", networks: [...j.settings.networks].map(String).sort(), cidrs: uniqSorted(j.settings.cidrs) };
      applySaved(saved.networks, saved.cidrs);   // the ranges as the server keeps them (written the standard way)
      // wait until both platforms have reloaded their data with the new settings
      $("applyState").textContent = "Applied · both platforms are reloading…";
      let ok = false;
      for (let i = 0; i < 40 && !ok; i++) {
        await new Promise((x) => setTimeout(x, 750));
        try {
          const [c, s] = await Promise.all([fetch("/api/clock").then((x) => x.json()), fetch("/api/svc/clock").then((x) => x.json())]);
          ok = c.data_version !== "0" && s.data_version !== "0";
        } catch { /* keep waiting */ }
      }
      const time = new Date().toISOString().slice(11, 16);
      bar.classList.remove("dirty"); bar.classList.add("done");
      $("applyState").textContent = `Settings applied at ${time} UTC`;
      $("applyDetail").textContent = `In force: ${describe(saved)}`;
      banner.className = "st-banner"; banner.hidden = false;
      banner.textContent = `Settings updated (${time} UTC): ${describe(saved)}. ${ok ? "Both platforms have reloaded their data;" : "Both platforms are reloading their data;"} open pages refresh by themselves within about 10 seconds.`;
      banner.scrollIntoView({ behavior: "smooth", block: "start" });
      refresh();
    } catch (err) {
      banner.className = "st-banner err"; banner.hidden = false; banner.textContent = `Settings were not applied: ${err.message}`;
      $("applyState").textContent = "Not applied"; refresh();
    }
  });
  for (const b of document.querySelectorAll("[data-go]")) b.addEventListener("click", () => {
    if (!$("save").disabled && !confirm("You have changes that are not applied yet. Leave without applying them?")) return;
    if (window.LGLoader) window.LGLoader.go(b.dataset.go); else location.href = b.dataset.go;
  });
  const loaded = () => { $("stLoading")?.remove(); $("stMain")?.classList.remove("st-pending"); window.LGLoader?.ready(); };
  load().then(loaded, (err) => { loaded(); throw err; }).catch((err) => { const b = $("banner"); b.className = "st-banner err"; b.hidden = false; b.textContent = `Could not load settings: ${err.message}`; });
})();
