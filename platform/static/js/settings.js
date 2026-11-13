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
  let data = null, chosen = new Set(), mode = "all", typeFilter = "", shapes = null, saved = null;
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
    saved = { country: s.country, timezone: s.timezone || "", networks: [...s.networks].map(String).sort(), cidrs: [...s.cidrs] };
    chosen = new Set(s.networks.map(String));
    mode = s.restricted ? "some" : "all";
    $("cidrs").value = s.cidrs.join("\n");
    const sel = $("country"); sel.replaceChildren();
    for (const c of data.countries) { const o = el("option", null, `${c.country}${c.regions ? ` · ${c.regions} regions` : " · no region map"}`); o.value = c.iso2; sel.append(o); }
    sel.value = s.country;
    fillZones(s.timezone);
    access();
    setMode(mode); buildTypes(); renderNets(); await renderCountry(); refresh();
    const unknown = data.networks.filter((n) => /^AS\d+$/.test(n.name)).length;
    $("unknownCount").textContent = unknown ? `· ${unknown} unidentified` : "";
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
      if (st.state === "done" || st.state === "stopped") { const keep = new Set(chosen); await load(); chosen = keep; renderNets(); refresh(); }
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
    if (data.writable) { box.hidden = true; return; }
    box.hidden = false; box.replaceChildren();
    box.append(document.createTextNode("Read only: changing settings needs an account with the Settings permission (administrators)."));
  }

  // ---------------- country
  let countrySeq = 0;
  async function renderCountry() {
    const mine = ++countrySeq;
    const iso = $("country").value, info = data.countries.find((c) => c.iso2 === iso) || {};
    $("countryMeta").textContent = info.regions ? `${info.regions} first-level regions · geoBoundaries ADM1` : "No region boundaries available for this country";
    const svg = $("preview"); svg.replaceChildren(); shapes = null;
    let got = null;
    if (info.regions) { try { got = await (await fetch(`/static/data/adm1/${iso}.json`)).json(); } catch { got = null; } }
    if (mine !== countrySeq) return;           // another country was picked meanwhile: its own call draws the map (review 2026-11-13)
    shapes = got;
    const keys = shapes ? Object.keys(shapes.regions) : [];
    const country = norm(info.country || "");
    // report region names -> map regions through the map's names, ISO names and aliases (static/js/regions.js)
    const resolve = shapes && window.LGRegions ? window.LGRegions.index(shapes)
      : (r) => { const k = norm(r); return keys.find((x) => x === k) || keys.find((x) => x.replace(/[^A-Z]/g, "") === k.replace(/[^A-Z]/g, "")) || null; };
    const shortName = (k) => (window.LGRegions ? window.LGRegions.shortName(shapes.regions[k].name) : shapes.regions[k].name);
    const rows = data.data_regions.map(([r, n]) => {
      const k = norm(r), unknown = !r || k === country;
      const hit = unknown || !shapes ? null : resolve(r);
      return { r, n, unknown, hit };
    });
    const perRegion = new Map(); for (const x of rows) if (x.hit) perRegion.set(x.hit, (perRegion.get(x.hit) || 0) + x.n);
    const tb = $("matchTable").querySelector("tbody"); tb.replaceChildren();
    for (const x of rows) {
      const tr = el("tr");
      tr.append(el("td", null, x.r ? titleCase(x.r) : "(empty)"), el("td", "mono", fmt(x.n)),
        el("td", x.unknown ? "" : x.hit ? "ok" : "no", x.unknown ? "Region unknown (country only)" : x.hit ? shortName(x.hit) : "not on this map"));
      tb.append(tr);
    }
    const known = rows.filter((x) => !x.unknown), matched = known.filter((x) => x.hit).length;
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
    $("someBox").hidden = m !== "some"; refresh();
  }
  for (const b of document.querySelectorAll(".st-mode button")) b.addEventListener("click", () => setMode(b.dataset.mode));
  function buildTypes() {
    const box = $("typeChips"); box.replaceChildren();
    const types = [...new Set(data.networks.map((n) => TYPE_NAMES[n.type] || "Other"))].sort();
    for (const t of ["All types", ...types]) {
      const b = el("button", "chip", t); b.type = "button"; b.setAttribute("aria-pressed", String((t === "All types" && !typeFilter) || t === typeFilter));
      b.addEventListener("click", () => { typeFilter = t === "All types" ? "" : t; buildTypes(); renderNets(); });
      box.append(b);
    }
  }
  const shown = () => {
    const q = $("netSearch").value.trim().toLowerCase();
    return data.networks.filter((n) => (!typeFilter || (TYPE_NAMES[n.type] || "Other") === typeFilter)
      && (!q || n.name.toLowerCase().includes(q) || n.asns.some((a) => String(a).includes(q.replace(/^as/, "")))));
  };
  const isOn = (n) => n.asns.every((a) => chosen.has(String(a)));
  function renderNets() {
    const tb = $("netTable").querySelector("tbody"); tb.replaceChildren();
    for (const n of shown()) {
      const tr = el("tr", isOn(n) ? "sel" : ""); const cb = el("input"); cb.type = "checkbox"; cb.checked = isOn(n);
      cb.addEventListener("change", () => { for (const a of n.asns) cb.checked ? chosen.add(String(a)) : chosen.delete(String(a)); tr.classList.toggle("sel", cb.checked); refresh(); });
      const td = el("td"); td.append(cb);
      tr.append(td, el("td", null, n.name), el("td", null, TYPE_NAMES[n.type] || "Other"), el("td", "mono", n.asns.map((a) => `AS${a}`).join(", ")), el("td", "mono", fmt(n.records)));
      tr.addEventListener("click", (e) => { if (e.target !== cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event("change")); } });
      tb.append(tr);
    }
    refresh();
  }
  // the network list further down (Network names & types, net-editor.js) picks constituents too: the same selection and
  // the same Apply settings. Ticking a network there switches this card to "Only selected networks".
  window.LGConstituency = {
    _l: [],
    has: (asn) => mode === "some" && chosen.has(String(asn)),
    isSome: () => mode === "some",
    count: () => chosen.size,
    key: () => `${mode}|${[...chosen].sort().join(",")}`,
    set(asn, on) {
      if (!data) return;
      if (mode !== "some") setMode("some");
      if (on) chosen.add(String(asn)); else chosen.delete(String(asn));
      renderNets();
    },
    onChange(fn) { this._l.push(fn); },
  };
  function tell() { for (const f of (window.LGConstituency && window.LGConstituency._l) || []) { try { f(); } catch { /* the other card */ } } }
  $("netSearch").addEventListener("input", renderNets);
  $("selShown").addEventListener("click", () => { for (const n of shown()) for (const a of n.asns) chosen.add(String(a)); renderNets(); });
  $("clearShown").addEventListener("click", () => { for (const n of shown()) for (const a of n.asns) chosen.delete(String(a)); renderNets(); });
  $("cidrs").addEventListener("input", refresh);
  const cidrList = () => $("cidrs").value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

  // ---------------- what would be applied, and whether it differs from what is in force
  function wanted() {
    return { country: $("country").value, timezone: $("tzone").value, networks: mode === "some" ? [...chosen].sort() : [], cidrs: mode === "some" ? cidrList() : [] };
  }
  function describe(w) {
    const nets = data.networks.filter((n) => n.asns.some((a) => w.networks.includes(String(a))));
    const c = (data.countries.find((x) => x.iso2 === w.country) || {}).country || w.country;
    const scope = w.networks.length || w.cidrs.length
      ? `constituency of ${nets.length} network${nets.length === 1 ? "" : "s"}${nets.length ? ` (${nets.slice(0, 3).map((n) => n.name).join(", ")}${nets.length > 3 ? ", …" : ""})` : ""}${w.cidrs.length ? ` and ${w.cidrs.length} address range${w.cidrs.length > 1 ? "s" : ""}` : ""}`
      : "whole country";
    const z = (((data.zones || {})[w.country] || []).find((x) => x.zone === w.timezone) || {}).label || w.timezone || "UTC";
    return FOR === "comms" ? scope : `${c} · times also in ${z} · ${scope}`;
  }
  function refresh() {
    if (!data) return;
    const sel = $("selCount"); const comp = data.networks.filter(isOn).length;
    sel.textContent = `${comp} network${comp === 1 ? "" : "s"} selected (${chosen.size} AS number${chosen.size === 1 ? "" : "s"})`;
    const w = wanted();
    // preview
    const box = $("preview2");
    if (mode === "all") box.textContent = `Whole country: both platforms show everything in the reports (yesterday: ${fmt(data.totals.communications)} communication events, ${fmt(data.totals.services)} services records).`;
    else {
      const recs = data.networks.filter((n) => n.asns.some((a) => chosen.has(String(a)))).reduce((a, n) => a + n.records, 0);
      box.textContent = chosen.size || w.cidrs.length
        ? `Selected networks account for about ${fmt(recs)} of yesterday's records on both platforms together${w.cidrs.length ? `, plus the records in ${w.cidrs.length} address range${w.cidrs.length > 1 ? "s" : ""}` : ""}.`
        : "Nothing selected yet: choose networks or enter address ranges (applying with nothing selected means the whole country).";
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
    chosen = new Set(saved.networks); $("cidrs").value = saved.cidrs.join("\n"); $("country").value = saved.country; fillZones(saved.timezone);
    setMode(saved.networks.length || saved.cidrs.length ? "some" : "all"); renderNets(); renderCountry();
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
      saved = { country: j.settings.country, timezone: j.settings.timezone || "", networks: [...j.settings.networks].map(String).sort(), cidrs: [...j.settings.cidrs] };
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
