/* Looking Glass · Intel gathered (researchers; the Definitions page).
   * window.LGIntel.open(name, section, report): the indicators behind an infection / category or an issue, per report
     (C2 domains, DNS lookups, URLs, user agents, credentials tried, fingerprints, certificates…), from /api/intel.
     A rail of reports, the combinations as a set matrix (which values travel together), indicator cards with share bars,
     hosts and repeating hosts. Interactions: focus a value (everything else dims to where it occurs), search, sort,
     copy (per value, per combination, per card as lines or one line), keyboard ([ ] or ← → reports, / search, Esc).
   * "Seen in" report cards on the Definitions tables, and the "Looking Glass asks" card (/api/intel/leads).
   Server side: intel.py. Researchers never see host addresses. Styles: static/css/intel.css. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const get = async (u) => { const r = await fetch(u, { cache: "no-store" }); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); };
  const svg = (d, s = 18, w = 1.8) => { const n = document.createElementNS("http://www.w3.org/2000/svg", "svg"); n.setAttribute("viewBox", "0 0 24 24"); n.setAttribute("width", s); n.setAttribute("height", s); n.setAttribute("aria-hidden", "true");
    const p = document.createElementNS("http://www.w3.org/2000/svg", "path"); p.setAttribute("d", d); p.setAttribute("fill", "none"); p.setAttribute("stroke", "currentColor"); p.setAttribute("stroke-width", w); p.setAttribute("stroke-linecap", "round"); p.setAttribute("stroke-linejoin", "round"); n.append(p); return n; };
  const ICON = {
    intel: "M10.5 18a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15zM21 21l-4.3-4.3M7.5 10.5h6M10.5 7.5v6",
    ask: "M12 21a9 9 0 1 0-9-9c0 1.6.4 3.1 1.1 4.4L3 21l4.6-1.1A9 9 0 0 0 12 21zM9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6M12 16.5v.01",
    copy: "M9 9h10v11H9zM5 15V4h10", check: "M5 12.5l4.5 4.5L19 7", close: "M6 6l12 12M18 6 6 18", search: "M10.5 18a7.5 7.5 0 1 1 0-15 7.5 7.5 0 0 1 0 15zM21 21l-4.3-4.3",
    focus: "M12 3v3M12 18v3M3 12h3M18 12h3M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z", host: "M4 6h16v9H4zM9 19h6M12 15v4", rep: "M4 12a8 8 0 0 1 13.7-5.7L20 8M20 4v4h-4M20 12a8 8 0 0 1-13.7 5.7L4 16M4 20v-4h4",
  };
  // what each kind of indicator is, in the order a researcher reads them
  const GROUP = { "C2 domain": "net", "DNS lookup": "net", "TLS server name (SNI)": "net", "Certificate name": "net", "URL": "web", "Request pattern": "web",
    "User agent": "web", "SSH client": "web", "Brute-force username": "cred", "Brute-force password": "cred",
    "Other CVEs on the same hosts": "cve", "Associated tags": "tag", "SSH fingerprint (HASSH)": "fp",
    "TLS fingerprint (JARM)": "fp", "Certificate SHA-256": "fp", "Web page hash": "fp", "Server software": "sw", "SSH software": "sw", "Product": "sw",
    "Certificate issuer": "sw", "Family named by the report": "meta", "Application": "meta" };
  const ORDER = ["C2 domain", "DNS lookup", "TLS server name (SNI)", "URL", "User agent", "Request pattern", "SSH client", "Brute-force username",
    "Brute-force password", "Other CVEs on the same hosts", "Associated tags", "Product", "Certificate name", "Server software", "SSH software",
    "TLS fingerprint (JARM)", "SSH fingerprint (HASSH)", "Certificate SHA-256", "Web page hash", "Certificate issuer", "Family named by the report", "Application"];
  const SHOW = 6, MATRIX_MAX = 14;
  const pct = (s) => (s == null ? "" : s >= 0.995 ? "100%" : s >= 0.1 ? `${Math.round(s * 100)}%` : s >= 0.001 ? `${(s * 100).toFixed(1)}%` : "<0.1%");
  const plural = (n, w) => `${fmt(n)} ${w}${n === 1 ? "" : /(s|ch|sh|x)$/.test(w) ? "es" : "s"}`;
  // what people read for a report: its title (services reports), never the collection name
  const rn = (x) => (st?.d?.labels || {})[x] || x;
  const SEC = { issues: "issue", services: "services report", infections: "infection / category" };

  // ---------------- copying: one value per line (files, tools) or one line with commas (search boxes, messages)
  async function writeClip(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch { /* not a secure page, or refused */ }
    const ta = document.createElement("textarea"); ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
    document.body.append(ta); ta.select(); let ok = false; try { ok = document.execCommand("copy"); } catch { /* */ } ta.remove(); return ok;
  }
  let toastT;
  function toast(text) {
    let t = $("igToast"); if (!t) { t = el("div", "ig-toast"); t.id = "igToast"; t.setAttribute("role", "status"); box.append(t); }
    t.replaceChildren(svg(ICON.check, 14, 2.2), document.createTextNode(text)); t.classList.add("on");
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("on"), 1600);
  }
  async function copy(text, what) { toast((await writeClip(text)) ? `Copied ${what}` : "Copy failed: select the text instead"); }
  function iconBtn(icon, tip, fn, cls = "") {
    const b = el("button", `ig-ibtn ${cls}`); b.type = "button"; b.title = tip; b.setAttribute("aria-label", tip); b.append(svg(icon, 14));
    b.addEventListener("click", (e) => { e.stopPropagation(); fn(); }); return b;
  }
  // the combination code: what a researcher puts in a note, and an analyst pastes on the Combinations page
  function codeChip(code, what) {
    const b = el("button", "ig-code"); b.type = "button";
    b.title = `Combination code ${code}: copy it into your note. An analyst pastes it on the Combinations page to get exactly these devices.`;
    b.setAttribute("aria-label", `Copy the combination code ${code}`);
    b.append(el("span", "ig-code-k", "Code"), el("code", null, code), svg(ICON.copy, 11));
    b.addEventListener("click", (e) => { e.stopPropagation(); copy(`${code} (${what})`, `the code ${code}`); });
    return b;
  }
  // "Move to notes": a pattern of interest goes to a new note with its code attached (the note says why it matters;
  // nothing is saved until the researcher adds the note)
  function noteBtn(code, text) {
    const b = el("button", "ig-tonote"); b.type = "button"; b.hidden = !window.LGNotes;
    b.title = `Open a new note on ${st?.d?.title || st?.d?.name} with ${code} attached`;
    b.append(svg("M5 4h11l3 3v13H5zM9 9h6M9 13h6M9 17h3", 13), el("span", null, "Move to notes"));
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      const d = st.d; close();
      window.LGNotes?.open(d.name, d.section || "infections", d.title, [{ code, text }]);
    });
    return b;
  }
  function copySeg(getValues, what) {
    const seg = el("div", "ig-seg"); seg.setAttribute("role", "group"); seg.setAttribute("aria-label", `Copy ${what}`);
    const ic = el("span", "ig-seg-ic"); ic.append(svg(ICON.copy, 13)); seg.append(ic);
    for (const [label, join, tip] of [["Lines", "\n", "one per line, for files and tools"], ["One line", ", ", "on one line with commas, for search boxes and messages"]]) {
      const b = el("button", null, label); b.type = "button"; b.title = `Copy ${what} ${tip}`;
      b.addEventListener("click", () => { const v = getValues(); copy(v.join(join), `${plural(v.length, "value")}${join === "\n" ? ", one per line" : " on one line"}`); });
      seg.append(b);
    }
    return seg;
  }

  // ---------------- the window: header, tools, rail of reports, content
  let back, box, body, st = null;
  function shell() {
    if (box) return;
    back = el("div", "ig-back"); back.hidden = true;
    box = el("section", "ig-modal"); box.hidden = true; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "igName");
    const head = el("header", "ig-head");
    const icon = el("div", "ig-icon"); icon.append(svg(ICON.intel, 20));
    const titles = el("div", "ig-titles");
    const eyebrow = el("div", "ig-eyebrow"); eyebrow.append(el("span", null, "Intel gathered"), el("span", "ig-dot", "·"), el("span", "ig-sec")); eyebrow.lastChild.id = "igSec";
    const name = el("h2", "ig-name"); name.id = "igName";
    const meta = el("div", "ig-meta"); meta.id = "igMeta";
    titles.append(eyebrow, name, meta);
    const tools = el("div", "ig-tools");
    const sw = el("label", "ig-search"); sw.append(svg(ICON.search, 14));
    const q = el("input"); q.id = "igQ"; q.type = "text"; q.spellcheck = false; q.placeholder = "Search values"; q.setAttribute("aria-label", "Search the values (press / )"); q.autocomplete = "off";
    sw.append(q, el("kbd", null, "/"));
    const x = iconBtn(ICON.close, "Close (Esc)", close, "ig-close");
    tools.append(sw, x);                           // values are listed by records, most first
    head.append(icon, titles, tools);
    body = el("div", "ig-body");
    box.append(head, body);
    back.addEventListener("click", close);
    q.addEventListener("input", () => { if (st) { st.q = q.value.trim().toLowerCase(); paint(); } });
    document.addEventListener("keydown", (e) => {
      if (box.hidden) return;
      const typing = e.target === q || /INPUT|TEXTAREA|SELECT/.test(e.target.tagName);
      // Esc peels one layer at a time: the search, then the focus, then the window
      if (e.key === "Escape") {
        if (e.target === q && (q.value || st?.q)) { q.value = ""; if (st) { st.q = ""; paint(); } q.blur(); }
        else if (e.target === q) q.blur();
        else if (st?.focus) { st.focus = null; paint(); }
        else close();
        e.preventDefault(); return;
      }
      if (typing) return;
      if (e.key === "/") { q.focus(); e.preventDefault(); }
      else if ((e.key === "]" || e.key === "ArrowRight" || e.key === "ArrowDown") && st) { pick(Math.min(st.d.reports.length - 1, st.i + 1)); e.preventDefault(); }
      else if ((e.key === "[" || e.key === "ArrowLeft" || e.key === "ArrowUp") && st) { pick(Math.max(st.min, st.i - 1)); e.preventDefault(); }
    });
    document.body.append(back, box);
  }
  function close() { back.hidden = true; box.hidden = true; document.documentElement.classList.remove("ig-open"); st = null; }

  // ---------------- "Looking Glass asks": one analysis box per match
  const KIND_OF = { 1: "Both platforms", 2: "Undefined name", 3: "Two names", 4: "Two reports" };
  function leadItem(x, current) {
    const li = el("li", `ig-lead p${x.priority}`);
    // header: what kind of match, what Looking Glass concludes, how much evidence
    const h = el("div", "ig-lead-h");
    h.append(el("span", "ig-lead-tag", KIND_OF[x.priority] || "Match"), el("b", "ig-lead-v", x.verdict || ""), el("span", "ig-lead-n", plural(x.count, "record")));
    // the indicator itself
    const ind = el("div", "ig-lead-ind");
    ind.append(el("span", "ig-lead-k", x.kind === "domain" ? "Domain" : x.kind), el("code", null, x.value),
      iconBtn(ICON.copy, `Copy ${x.value}`, () => copy(x.value, "the indicator")));
    li.append(h, ind);
    // the evidence: where Looking Glass saw it
    if (x.where?.length) {
      const tb = el("div", "ig-where"); tb.append(el("div", "ig-where-h", "Where Looking Glass saw it"));
      const max = Math.max(1, ...x.where.map((w) => w.records));
      for (const w of x.where) {
        const row = el("div", "ig-where-r");
        const nm = el("button", `ig-where-name${current && w.name === current ? " cur" : ""}`, w.name); nm.type = "button";
        nm.title = current && w.name === current ? "This name" : `Intel gathered for ${w.name}`;
        if (!(current && w.name === current)) nm.addEventListener("click", () => open(w.name, w.section, w.report));
        const st_ = el("span", `ig-def ${w.defined ? "yes" : "no"}`, w.defined ? "defined" : "no definition");
        const rep = el("span", "ig-where-rep", w.report);
        const bar = el("span", "ig-where-bar"); const f = el("i"); f.style.width = `${Math.max(4, (w.records / max) * 100)}%`; bar.append(f);
        row.append(nm, st_, rep, bar, el("b", "ig-where-c", fmt(w.records)));
        tb.append(row);
      }
      li.append(tb);
    }
    // what Looking Glass saw, in words
    const say = el("div", "ig-lead-say");
    say.append(el("p", null, x.text));
    li.append(say);
    return li;
  }

  // ---------------- one value row: thin share bar, aligned figures, focus and copy
  function figures(v) {
    const f = el("div", "ig-fig");
    const rec = el("span", "ig-f-rec"); rec.append(el("b", null, fmt(v.count)), el("small", null, pct(v.share)));
    const h = el("span", "ig-f-host"); h.append(svg(ICON.host, 12), document.createTextNode(fmt(v.hosts || 0)));
    h.title = `${plural(v.hosts || 0, "device")} carry it (counted, never shown)`;
    f.append(rec, h);
    const r = el("span", `ig-f-rep${v.repeat_hosts ? "" : " none"}`, v.repeat_hosts ? fmt(v.repeat_hosts) : "");   // the number only, empty when none
    r.title = v.repeat_hosts ? `${plural(v.repeat_hosts, "device")} repeat it (more than one record each): a pattern, not a one-off` : "No device repeats it";
    f.append(r);
    f.title = `${plural(v.count, "record")} (${pct(v.share)} of this report's)`;
    return f;
  }
  function valueRow(v, kind) {
    const li = el("li", "ig-v"); li.dataset.value = v.value;
    li.style.setProperty("--w", String(Math.max(1.5, v.share * 100)));   // a number: the CSS multiplies it
    const main = el("div", "ig-v-main");
    const code = el("code", null, v.value); code.title = `${v.value}\nClick to focus: dim everything that does not carry it`;
    main.append(code);
    li.append(main, figures(v), iconBtn(ICON.copy, `Copy ${v.value}`, () => copy(v.value, kind === "Other CVEs on the same hosts" ? v.value : "the value"), "ig-v-copy"));
    li.addEventListener("click", () => { st.focus = st.focus === v.value ? null : v.value; paint(); });
    return li;
  }

  function kindCard(k) {
    const card = el("article", `ig-card g-${GROUP[k.kind] || "meta"}`);
    const head = el("header", "ig-card-h");
    const t = el("div", "ig-card-t"); t.append(el("i"), el("b", null, k.kind), el("span", null, `${fmt(k.distinct)} distinct`));
    head.append(t, copySeg(() => [...card.querySelectorAll("li.ig-v:not(.out)")].map((li) => li.dataset.value), k.kind.toLowerCase()));
    const cols = el("div", "ig-cols"); cols.append(el("span", null, "Value"), el("span", null, "Records"), el("span", null, "Devices"), el("span", null, "Repeating"));
    cols.title = "Devices: how many distinct devices carry the value (counted, never shown). Repeating: how many of them carry it in more than one record";
    const ul = el("ul", "ig-vals");
    const vals = [...k.values].sort((a, b) => b.count - a.count);   // most records first
    let shown = 0;
    for (const v of vals) {
      const li = valueRow(v, k.kind);
      const hit = !st.q || v.value.toLowerCase().includes(st.q);
      if (!hit) li.classList.add("out");
      if (st.focus && v.value === st.focus) li.classList.add("focused");
      if (hit && !st.q && ++shown > SHOW && !card.dataset.all && !(st.open || {})[k.kind]) li.classList.add("more");
      ul.append(li);
    }
    card.append(head, cols, ul);
    const hidden = ul.querySelectorAll(".more").length;
    if (hidden) {
      const more = el("button", "ig-more", `Show ${hidden} more`); more.type = "button";
      more.addEventListener("click", () => { st.open = { ...(st.open || {}), [k.kind]: true }; paint(); });
      card.append(more);
    }
    if (st.q && !ul.querySelector("li:not(.out)")) card.classList.add("empty");
    if (k.distinct > k.values.length) card.append(el("p", "ig-foot", `The ${k.values.length} most frequent of ${fmt(k.distinct)}.`));
    // services: values fewer than 5 hosts share are not shown (they could point at one host)
    if (k.hidden) card.append(el("p", "ig-foot", `${fmt(k.hidden)} other value${k.hidden === 1 ? "" : "s"}, each on fewer than 5 hosts: not shown, to keep hosts unidentifiable.`));
    return card;
  }

  // ---------------- combinations: a set matrix (values as columns, combinations as rows), or chips when too many
  function comboCard(r) {
    const card = el("article", "ig-card ig-combos");
    const head = el("header", "ig-card-h");
    const t = el("div", "ig-card-t"); t.append(el("i"), el("b", null, "Combinations"),
      el("span", null, `${plural(r.combinations_total, "exact set")} of ${r.combo_of || "associated tags and CVEs"} on the same record · which values travel together`));
    const weight = new Map();
    for (const c of r.combinations) for (const x of c.items) weight.set(x, (weight.get(x) || 0) + c.count);
    const items = [...weight.keys()].sort((a, b) => weight.get(b) - weight.get(a) || a.localeCompare(b));
    // two views: the list of sets (default: every value readable) and the set matrix (which values travel together)
    head.append(t);
    if (items.length && items.length <= MATRIX_MAX) {
      const view = el("div", "ig-view"); view.setAttribute("role", "group"); view.setAttribute("aria-label", "Show the combinations as");
      for (const [k, l, tip] of [["list", "List", "Each set as its values, joined with +"], ["matrix", "Matrix", "Values as columns, sets as rows: which values travel together"]]) {
        const b = el("button", null, l); b.type = "button"; b.title = tip; b.setAttribute("aria-pressed", String((st.comboView || "list") === k));
        b.addEventListener("click", () => { st.comboView = k; paint(); }); view.append(b);
      }
      head.append(view);
    }
    card.append(head);
    const max = Math.max(1, ...r.combinations.map((c) => c.count));
    const qHit = (c) => !st.q || c.items.some((x) => x.toLowerCase().includes(st.q));
    const fHit = (c) => !st.focus || c.items.includes(st.focus);
    const bar = (c) => {
      const b = el("div", "ig-mbar"); const fill = el("i"); fill.style.width = `${Math.max(2, (c.count / max) * 100)}%`; b.append(fill);
      const n = el("span"); n.append(el("b", null, fmt(c.count)), el("small", null, pct(c.share))); b.append(n); return b;
    };
    if (st.comboView === "matrix" && items.length && items.length <= MATRIX_MAX) {
      const m = el("div", "ig-matrix"); m.style.setProperty("--cols", items.length);
      const hd = el("div", "ig-mrow ig-mhead");
      for (const x of items) {
        const h = el("button", `ig-mcol${st.focus === x ? " on" : ""}`); h.type = "button"; h.title = `${x}: ${plural(weight.get(x), "record")}. Click to focus`;
        h.append(el("span", null, x)); h.addEventListener("click", () => { st.focus = st.focus === x ? null : x; paint(); }); hd.append(h);
      }
      hd.append(el("span", "ig-mlab", "Records"), el("span", "ig-mlab", "Devices"), el("span", "ig-mlab", "Repeating"), el("span"));
      m.append(hd);
      for (const c of r.combinations) {
        const row = el("div", `ig-mrow${qHit(c) && fHit(c) ? "" : " dim"}`);
        const idx = items.map((x) => c.items.includes(x));
        const first = idx.indexOf(true), last = idx.lastIndexOf(true);
        items.forEach((x, i) => {
          const cell = el("span", `ig-mcell${idx[i] ? " in" : ""}${i > first && i < last ? " link" : ""}${i === first && first !== last ? " start" : ""}${i === last && first !== last ? " end" : ""}${st.focus === x ? " col" : ""}`);
          cell.append(el("i")); cell.title = idx[i] ? x : ""; row.append(cell);
        });
        if (!c.items.length) row.classList.add("nothing");
        const hosts = el("span", "ig-f-host"); hosts.append(svg(ICON.host, 12), document.createTextNode(fmt(c.hosts || 0)));
        const rep = el("span", `ig-f-rep${c.repeat_hosts ? "" : " none"}`, c.repeat_hosts ? fmt(c.repeat_hosts) : "");
        rep.title = c.repeat_hosts ? `${plural(c.repeat_hosts, "device")} repeat this exact set` : "No device repeats it";
        row.append(bar(c), hosts, rep, iconBtn(ICON.copy, `Copy this set with its code ${c.code || ""}: ${c.items.join(", ") || "nothing else"}`, () => copy((c.code ? `${c.code}: ` : "") + c.items.join(", "), "this set and its code")));
        row.title = c.items.join(" + ") || "nothing else";
        m.append(row);
      }
      card.append(m);
    } else {
      // the same design as the combinations across reports: share ring and records, the set, devices on the side
      const ul = el("ul", "ig-xc ig-cmb");
      for (const c of r.combinations) {
        const li = el("li", qHit(c) && fHit(c) ? "" : "dim");
        const stat = el("div", "ig-xc-stat");
        const ring = el("span", "ig-ring"); ring.style.setProperty("--p", String(Math.round(c.share * 100))); ring.append(el("em", null, pct(c.share)));
        const num = el("div", "ig-xc-num"); num.append(el("b", null, fmt(c.count)), el("span", null, c.count === 1 ? "record" : "records"));
        stat.append(ring, num); stat.title = `${plural(c.count, "record")}: ${pct(c.share)} of this report's records`;
        const blk = el("div", "ig-xc-part");
        const set = el("div", "ig-set");
        if (!c.items.length) set.append(el("span", "ig-none", "nothing else"));
        c.items.forEach((x, i) => {
          if (i) set.append(el("span", "ig-plus", " + "));
          const chip = el("button", `ig-chip${st.focus === x ? " on" : ""}`, x); chip.type = "button";
          chip.addEventListener("click", () => { st.focus = st.focus === x ? null : x; paint(); }); set.append(chip);
        });
        blk.append(set);
        if (c.code) {
          const what = `${st.d.title || st.d.name} in ${rn(r.report)}: ${c.items.join(" + ") || "the name only"}`;
          const codes = el("div", "ig-code-row"); codes.append(codeChip(c.code, what), noteBtn(c.code, `${rn(r.report)}: ${c.items.join(" + ") || "the name only"}`));
          blk.append(codes);
        }
        const meta = el("div", "ig-cmb-meta");
        const dv = el("div"); dv.append(el("b", null, fmt(c.hosts || 0)), el("span", null, (c.hosts || 0) === 1 ? "device" : "devices"));
        dv.title = `${plural(c.hosts || 0, "device")} carry this set (counted, never shown)`;
        const rp = el("div", c.repeat_hosts ? "rep" : "none"); rp.append(el("b", null, c.repeat_hosts ? fmt(c.repeat_hosts) : "–"), el("span", null, "repeating"));
        rp.title = c.repeat_hosts ? `${plural(c.repeat_hosts, "device")} carry it in more than one record` : "No device carries it in more than one record";
        meta.append(dv, rp);
        li.append(stat, blk, meta, iconBtn(ICON.copy, "Copy this set on one line (with its code)", () => copy((c.code ? `${c.code}: ` : "") + c.items.join(", "), "this set on one line")));
        ul.append(li);
      }
      card.append(ul);
    }
    card.append(el("p", "ig-foot", `Each row is one exact set, counted per record (of ${fmt(r.records)}).` +
      (r.combinations_total > r.combinations.length ? ` The ${r.combinations.length} most frequent of ${fmt(r.combinations_total)} are shown.` : "") +
      (r.combinations_small ? ` ${plural(r.combinations_small, "other set")} on fewer than ${st.d.min_hosts || 5} devices: not shown, to keep hosts unidentifiable.` : "") +
      " Click a value to highlight every set that carries it."));
    return card;
  }

  // ---------------- across reports: which reports see the same devices, and which indicators turn up in several
  function acrossView(pane) {
    const d = st.d, a = d.across || {};
    const path = el("div", "ig-path");
    path.append(el("code", null, d.title || d.name), el("span", "ig-sep", "›"), el("b", null, "Across reports"), el("span", "ig-sep", "›"),
      el("span", null, `${plural(a.devices || 0, "device")} · ${fmt(a.multi_devices || 0)} seen in more than one report`));
    pane.append(path);
    if (d.section === "services") pane.append(sinkCard(d));   // the hosts that also call botnet sinkholes, first
    if (d.cross) pane.append(everyCard(d));                  // the same hosts in every other category
    // 0. combinations across reports: for devices in two or more reports, exactly what each carried in each report
    const c0 = el("article", "ig-card ig-xcombos");
    const h0 = el("header", "ig-card-h"), t0 = el("div", "ig-card-t");
    t0.append(el("i"), el("b", null, "Combinations across reports"),
      el("span", null, `${plural(a.cross_combos_total || 0, "exact pattern")} among the ${plural(a.multi_devices || 0, "device")} seen in more than one report: what each device carried in each report`));
    h0.append(t0); c0.append(h0);
    const xs = (a.cross_combos || []).filter((x) => !st.q || x.parts.some((p) => p.items.some((v) => v.toLowerCase().includes(st.q))));
    if (!xs.length) {
      if (st.q) c0.append(el("p", "ig-empty", `Nothing matches “${st.q}”.`));
      else if (d.section === "services") c0.append(el("p", "ig-empty", (a.multi_devices || 0)
        ? `${plural(a.multi_devices, "device")} of this report ${a.multi_devices === 1 ? "is" : "are"} in other services reports too, but no exact pattern is shared by ${d.min_hosts || 5} or more: smaller groups are not shown, to keep hosts unidentifiable.`
        : "None of this report's devices is in another services report in the days in memory."));
      else if (a.multi_devices || 0) c0.append(el("p", "ig-empty", "No exact pattern to show."));
      else c0.append(noOverlap(st.d.reports.map((r) => r.report)));
    }
    const ulx = el("ul", "ig-xc"), maxx = Math.max(1, ...xs.map((x) => x.devices));
    const chipSet = (items) => {
      const set = el("div", "ig-set");
      if (!items.length) { const n = el("span", "ig-none", "no indicator: this report carries only the name"); n.title = "The records of this report name the infection but carry no domain, lookup, user agent or tag for it"; set.append(n); }
      items.forEach((v, j) => {
        if (j) set.append(el("span", "ig-plus", " + "));
        const chip = el("button", `ig-chip${st.focus === v ? " on" : ""}`, v); chip.type = "button";
        chip.addEventListener("click", () => { st.focus = st.focus === v ? null : v; paint(); }); set.append(chip);
      });
      return set;
    };
    for (const x of xs) {
      const li = el("li");
      // the figure: a ring for the share of multi-report devices, the device count large
      const stat = el("div", "ig-xc-stat");
      const ring = el("span", "ig-ring"); ring.style.setProperty("--p", String(Math.round(x.share * 100))); ring.append(el("em", null, pct(x.share)));
      const num = el("div", "ig-xc-num"); num.append(el("b", null, fmt(x.devices)), el("span", null, x.devices === 1 ? "device" : "devices"));
      stat.append(ring, num);
      stat.title = `${plural(x.devices, "device")}: ${pct(x.share)} of the devices seen in more than one report`;
      // the reports: one block per report, or one block when the set is the same in every report
      const parts = el("div", "ig-xc-parts");
      const same = x.parts.every((p) => p.items.join("\u0001") === x.parts[0].items.join("\u0001"));
      if (same && x.parts.length > 1) {
        const blk = el("div", "ig-xc-part same");
        const hd = el("div", "ig-xc-reps"); hd.append(el("span", "ig-xc-rep", x.parts.length === 2 ? "Same in both reports" : `Same in all ${x.parts.length} reports`));
        for (const p of x.parts) hd.append(el("span", "ig-xc-rname", rn(p.report)));
        blk.append(hd, chipSet(x.parts[0].items)); parts.append(blk);
      } else {
        for (const p of x.parts) { const blk = el("div", `ig-xc-part${p.report === d.name ? " cur" : ""}`); blk.append(el("span", "ig-xc-rep", rn(p.report)), chipSet(p.items)); parts.append(blk); }
      }
      if (st.focus && !x.parts.some((p) => p.items.includes(st.focus))) li.classList.add("dim");
      const pat = x.parts.map((p) => `${rn(p.report)}: ${p.items.join(", ") || "-"}`).join(" | ");
      if (x.code) { const cr = el("div", "ig-code-row"); cr.append(codeChip(x.code, `${d.title || d.name} across ${pat}`), noteBtn(x.code, `Across ${pat}`)); parts.append(cr); }
      li.append(stat, parts, iconBtn(ICON.copy, "Copy this pattern on one line (with its code)", () => copy((x.code ? `${x.code}: ` : "") + pat, "this pattern")));
      li.title = `${plural(x.devices, "device")} carried exactly this, report by report`;
      ulx.append(li);
    }
    void maxx;
    c0.append(ulx, el("p", "ig-foot", "Each row is one exact pattern: the reports a device was seen in and, for each, everything it carried there. Devices counted, never shown."));
    pane.append(c0);
    // 1. the sets of reports the devices were seen in
    const c1 = el("article", "ig-card ig-combos");
    const h1 = el("header", "ig-card-h"), t1 = el("div", "ig-card-t");
    t1.append(el("i"), el("b", null, "Reports seeing the same devices"),
      el("span", null, `${plural(a.report_sets_total || 0, "exact set")} of reports per device · devices counted, never shown`));
    h1.append(t1); c1.append(h1);
    const ul1 = el("ul", "ig-sets"), max1 = Math.max(1, ...(a.report_sets || []).map((s) => s.devices));
    for (const s of a.report_sets || []) {
      const li = el("li", s.reports.length > 1 ? "multi" : "");
      const set = el("div", "ig-set");
      s.reports.forEach((x, i) => { if (i) set.append(el("span", "ig-plus", " + ")); set.append(el("span", "ig-rchip", rn(x))); });
      if (s.reports.length > 1) set.append(el("span", "ig-xtag", `${s.reports.length} reports`));
      const bar = el("div", "ig-mbar"); const f = el("i"); f.style.width = `${Math.max(2, (s.devices / max1) * 100)}%`; bar.append(f);
      const n = el("span"); n.append(el("b", null, fmt(s.devices)), el("small", null, pct(s.share))); bar.append(n);
      const dv = el("span", "ig-f-host"); dv.append(svg(ICON.host, 12), document.createTextNode("devices"));
      li.append(set, bar, dv, el("span"), el("span"));
      ul1.append(li);
    }
    if (!(a.report_sets || []).length) c1.append(el("p", "ig-empty", d.section === "services"
      ? `No set of reports is shared by ${d.min_hosts || 5} or more devices.` : "No set of reports to show."));
    c1.append(ul1, el("p", "ig-foot", "Each row is one exact set of reports a device was seen in for this name, in the days held in memory."));
    pane.append(c1);
    if (d.section === "services") return;             // services: the sinkhole card is at the top
    // 2. indicators seen in more than one report
    const c2 = el("article", "ig-card g-net");
    const h2 = el("header", "ig-card-h"), t2 = el("div", "ig-card-t");
    t2.append(el("i"), el("b", null, "Indicators in more than one report"),
      el("span", null, `${plural(a.shared_total || 0, "value")} that different reports both carry for this name`));
    const rows = (a.shared || []).filter((x) => !st.q || x.value.toLowerCase().includes(st.q));
    h2.append(t2, copySeg(() => rows.map((x) => x.value), "these indicators")); c2.append(h2);
    if (!rows.length) c2.append(el("p", "ig-empty", st.q ? `Nothing matches “${st.q}”.` : "No indicator turns up in more than one report for this name."));
    const ul2 = el("ul", "ig-xlist");
    for (const x of rows) {
      const li = el("li");
      const main = el("div", "ig-x-main"); main.append(el("code", null, x.value), el("small", null, x.kinds.join(" · ")));
      const where = el("div", "ig-x-where");
      for (const [rep, n] of Object.entries(x.where)) { const c = el("span", "ig-rchip"); c.append(document.createTextNode(rep), el("b", null, fmt(n))); where.append(c); }
      li.append(main, where, iconBtn(ICON.copy, `Copy ${x.value}`, () => copy(x.value, "the indicator")));
      ul2.append(li);
    }
    c2.append(ul2);
    if ((a.shared_total || 0) > (a.shared || []).length) c2.append(el("p", "ig-foot", `The ${(a.shared || []).length} seen in the most reports and records, of ${fmt(a.shared_total)}.`));
    pane.append(c2);
  }

  // every report that led to a finding, grouped by kind: "Sinkhole reports 1: Sinkhole DNS (1)", "Services reports 3: …"
  function seenIn(groups) {
    const w = el("div", "ig-seenin");
    for (const g of groups || []) {
      const r = el("div", "ig-seenin-r");
      r.append(el("span", "ig-seenin-k", `${g.kind} ${g.reports.length}`),
        el("span", "ig-seenin-l", g.reports.map((x) => `${x.title} (${fmt(x.hosts)})`).join(" · ")));
      w.append(r);
    }
    return w;
  }
  // services: the report's devices that the network communications reports show calling botnet sinkholes, per infection,
  // each with its code (an analyst gets exactly those devices of this report)
  function sinkCard(d) {
    const s = d.sinkholes || { hosts: 0, share: 0, names: [] };
    const c = el("article", `ig-card g-cred ig-sink${s.hosts ? " on" : ""}`);
    const h = el("header", "ig-card-h"), t = el("div", "ig-card-t");
    t.append(el("i"), el("b", null, "Also calling botnet sinkholes"),
      el("span", null, s.hosts ? `${plural(s.hosts, "device")} (${pct(s.share)} of this report's) are in the network communications reports too: an exposed service on a device that is already infected`
        : "None of this report's devices is in the network communications reports of the days in memory"));
    h.append(t); c.append(h);
    if ((s.reports || []).length) {                // which sinkhole reports these hosts are in
      const reps = el("div", "ig-set ig-sink-reps");
      reps.append(el("span", "ig-sink-k", "In the sinkhole reports"));
      for (const r of s.reports) { const c2 = el("span", "ig-rchip"); c2.append(document.createTextNode(r.report), el("b", null, fmt(r.hosts))); reps.append(c2); }
      c.append(reps);
    }
    const rows = (s.names || []).filter((x) => !st.q || x.name.toLowerCase().includes(st.q));
    if (rows.length) {
      const cols = el("div", "ig-cols"); cols.append(el("span", null, "Infection / category"), el("span", null, ""), el("span", null, "Devices"), el("span", null, "")); c.append(cols);
      const ul = el("ul", "ig-vals"), max = Math.max(1, ...rows.map((x) => x.hosts));
      for (const x of rows) {
        const li = el("li", "ig-v ig-sink-r"); li.style.setProperty("--w", String(Math.max(1.5, (x.hosts / max) * 100)));
        const main = el("div", "ig-v-main");
        const nm = el("button", "ig-where-name", x.name); nm.type = "button"; nm.title = `Intel gathered for ${x.name}`;
        nm.addEventListener("click", (e) => { e.stopPropagation(); open(x.name, "infections"); });
        main.append(nm);
        if (x.seen_in?.length) main.append(seenIn(x.seen_in));
        else if (x.reports?.length) main.append(el("span", "ig-sink-in", `in ${x.reports.map((r) => r.report).join(", ")}`));
        if (x.code) main.append(codeChip(x.code, `${d.title || d.name}: devices also calling botnet sinkholes as ${x.name}`),
          noteBtn(x.code, `${d.title || d.name}: hosts also calling botnet sinkholes as ${x.name}`));
        const f = el("div", "ig-fig"), hh = el("span", "ig-f-host"); hh.append(svg(ICON.host, 12), document.createTextNode(fmt(x.hosts)));
        hh.title = `${plural(x.hosts, "device")} of this report call a sinkhole as ${x.name} (counted, never shown)`;
        f.append(el("span"), hh, el("span", "ig-f-rep none", ""));
        li.append(main, f, iconBtn(ICON.copy, `Copy ${x.name}`, () => copy(x.name, "the name"), "ig-v-copy"));
        ul.append(li);
      }
      c.append(ul, el("p", "ig-foot", "Threat names, not hosts. A code gives an analyst exactly the devices of this report that call a sinkhole as that infection."));
    }
    return c;
  }
  // infections and issues: the same hosts in every other category (services_intel.for_hosts): the services reports they
  // are in with their pattern combinations, the CVEs and issues on them, the infections they call sinkholes as; codes
  // with "Move to notes"; values clickable like everywhere in this window
  function everyCard(d) {
    const x = d.cross, me = String(d.name).toLowerCase();
    const c = el("article", "ig-card ig-every");
    const h = el("header", "ig-card-h"), t = el("div", "ig-card-t");
    t.append(el("i"), el("b", null, "In every other category"),
      el("span", null, `the same ${d.section === "issues" ? "hosts" : "devices"} in the services reports, with the CVEs, issues and infections on them · counts and codes only`));
    h.append(t); c.append(h);
    // where these hosts were seen: every report, grouped by kind (sinkhole, vulnerability, services, other categories)
    if ((x.sources || []).length) {
      const w = el("div", "ig-src");
      w.append(el("b", "ig-src-h", `Where these ${d.section === "issues" ? "hosts" : "devices"} were seen`));
      for (const s of x.sources) {
        const r = el("div", "ig-src-r");
        r.append(el("span", "ig-src-k", `${s.reports.length} ${s.kind.replace(/ reports$/, "").toLowerCase()} report${s.reports.length === 1 ? "" : "s"}`));
        const list = el("div", "ig-src-l");
        for (const x2 of s.reports) { const ch = el("span", "ig-rchip"); ch.append(document.createTextNode(x2.title), el("b", null, fmt(x2.hosts))); list.append(ch); }
        r.append(list); w.append(r);
      }
      c.append(w);
    }
    const qOk = (s) => !st.q || s.toLowerCase().includes(st.q);
    const chipOf = (v) => { const b = el("button", `ig-chip${st.focus === v ? " on" : ""}`, v); b.type = "button";
      b.addEventListener("click", (e) => { e.stopPropagation(); st.focus = st.focus === v ? null : v; paint(); }); return b; };
    const block = (title, n, cls) => { const b = el("section", `ig-every-b ${cls}`); const hh = el("div", "ig-every-h"); hh.append(el("b", null, title), el("span", null, n)); b.append(hh); c.append(b); return b; };
    // infections (other than this one; a services report shows its sinkholes in the card above)
    const svcSec = d.section === "services";
    const infs = svcSec ? [] : (x.infections || []).filter((i) => i.name.toLowerCase() !== me && qOk(i.name));
    const bi = svcSec ? el("div") : block(d.section === "issues" ? "Infections" : "Other infections", !infs.length ? "none"
      : d.section === "issues" ? `${plural(x.infections_hosts, "host")} calling botnet sinkholes` : `${plural(infs.length, "other infection")} on these devices`, "inf");
    if (!infs.length && !svcSec) bi.append(el("p", "ig-empty", d.section === "issues" ? "None of these hosts calls a botnet sinkhole in the days in memory." : "These devices call no other infection's sinkhole in the days in memory."));
    for (const i of infs) {
      const row = el("div", `ig-every-r${st.focus && st.focus !== i.name ? " dim" : ""}`);
      const nm = el("button", "ig-where-name", i.name); nm.type = "button"; nm.title = `Intel gathered for ${i.name}`;
      nm.addEventListener("click", (e) => { e.stopPropagation(); open(i.name, "infections"); });
      row.append(nm, el("span", "ig-every-n", plural(i.hosts, "host")));
      for (const r of i.reports.slice(0, 3)) {
        const cr = el("div", "ig-code-row"); cr.append(el("span", "ig-every-in", r.title),
          codeChip(r.code, `${r.title}: hosts also calling botnet sinkholes as ${i.name}`), noteBtn(r.code, `${r.title}: hosts also calling botnet sinkholes as ${i.name}`));
        row.append(cr);
      }
      bi.append(row);
    }
    // CVEs and issues (other than this one)
    const iss = (x.issues || []).filter((i) => i.name !== d.name && qOk(i.name));
    const bc = block("CVEs and issues", iss.length ? `${fmt(x.issues_total)} on these hosts` : "none", "cve");
    if (!iss.length) bc.append(el("p", "ig-empty", "No CVE or other issue on these hosts in the services reports of the days in memory."));
    else {
      // each CVE or issue with the services reports it was found in (what a researcher is about to send)
      const ul = el("div", "ig-every-iss"), openI = (st.open || {}).iss;
      iss.forEach((i, n) => {
        const row = el("div", `ig-every-ir${st.focus && st.focus !== i.name ? " dim" : ""}`); if (n >= 12 && !openI) row.hidden = true;
        const b = chipOf(i.name); b.classList.add(/^CVE-/i.test(i.name) ? "cve" : "iss"); b.append(el("em", null, fmt(i.hosts)));
        const w = i.seen_in?.length ? seenIn(i.seen_in) : el("span", "ig-every-in", `in ${(i.reports || []).map((r) => `${r.title} (${fmt(r.hosts)})`).join(", ") || "the services reports"}`);
        row.append(b, w); ul.append(row);
      });
      bc.append(ul);
      if (iss.length > 12 && !openI) {
        const more = el("button", "ig-more", `Show all ${iss.length}`); more.type = "button";
        more.addEventListener("click", () => { st.open = { ...(st.open || {}), iss: true }; paint(); }); bc.append(more);
      }
    }
    // services, with their pattern combinations
    const svc = (x.services || []).filter((s) => s.report !== d.name && (qOk(s.title) || s.combinations.some((k) => k.items.some(qOk))));
    const bs = block(svcSec ? "Other services reports" : "Services", svc.length ? plural(svc.length, "report") : "none", "svc");
    if (!svc.length) bs.append(el("p", "ig-empty", "None of these hosts is in the services reports of the days in memory."));
    const open_ = (st.open || {}).every;
    // grouped by kind of report, each kind with its count and names: vulnerability, services, other categories
    const KORD = ["Vulnerability reports", "Services reports"];
    const kinds = [...new Set(svc.map((s) => s.kind || "Services reports"))].sort((a, b) => ((KORD.indexOf(a) + 1) || 9) - ((KORD.indexOf(b) + 1) || 9));
    svc.sort((a, b) => kinds.indexOf(a.kind || "Services reports") - kinds.indexOf(b.kind || "Services reports") || b.hosts - a.hosts);
    if (svc.length) {
      const sum = el("div", "ig-seenin ig-svc-kinds");
      for (const k of kinds) {
        const of = svc.filter((s) => (s.kind || "Services reports") === k);
        const r = el("div", "ig-seenin-r"); r.append(el("span", "ig-seenin-k", `${k} ${of.length}`), el("span", "ig-seenin-l", of.map((s) => `${s.title} (${fmt(s.hosts)})`).join(" · ")));
        sum.append(r);
      }
      bs.append(sum);
    }
    let lastKind = null;
    svc.forEach((s, n) => {
      const kind = s.kind || "Services reports";
      if (kind !== lastKind) { lastKind = kind; const kh = el("div", "ig-every-kh", `${kind} · ${svc.filter((x) => (x.kind || "Services reports") === kind).length}`); if (n >= 6 && !open_) kh.hidden = true; bs.append(kh); }
      const r = el("div", "ig-every-s"); if (n >= 6 && !open_) r.hidden = true;
      const hh = el("div", "ig-every-r"); hh.append(el("b", null, s.title), el("span", "ig-every-n", plural(s.hosts, "host"))); r.append(hh);
      for (const k of s.combinations.filter((k) => k.items.length).slice(0, 3)) {
        const row = el("div", `ig-every-k${st.focus && !k.items.includes(st.focus) ? " dim" : ""}`);
        const set = el("div", "ig-set"); k.items.forEach((v, j) => { if (j) set.append(el("span", "ig-plus", " + ")); set.append(chipOf(v)); });
        const cr = el("div", "ig-code-row"); cr.append(el("span", "ig-every-n", plural(k.hosts, "host")));
        // fewer than 5 devices: the pattern is shown, without a lasting code (small_codes.py); an analyst drills into it
        if (k.code) cr.append(codeChip(k.code, `${s.title}: ${k.items.join(" + ")}`), noteBtn(k.code, `${s.title}: ${k.items.join(" + ")}`));
        else cr.append(el("span", "ig-held", `Fewer than 5 devices: no lasting code. An analyst can drill into it.`));
        row.append(set, cr); r.append(row);
      }
      bs.append(r);
    });
    if (svc.length > 6 && !open_) {
      const more = el("button", "ig-more", `Show all ${svc.length} reports`); more.type = "button";
      more.addEventListener("click", () => { st.open = { ...(st.open || {}), every: true }; paint(); }); bs.append(more);
    }
    c.append(el("p", "ig-foot", `In the days in memory (${(x.days || []).join(", ")}). A pattern value is shown only when 5 or more hosts share it; hosts are counted, never shown.`));
    return c;
  }
  // services: the report's overview (kb-services.js) and its pattern fields (kb-services-patterns.js) in the same window
  function servicePane(kind) {
    const pane = st.pane; pane.replaceChildren();
    const path = el("div", "ig-path");
    path.append(el("code", null, st.d.title || st.d.name), el("span", "ig-sep", "›"), el("b", null, kind === -3 ? "About this report" : "Pattern fields"));
    const inner = el("div", "ig-svc-pane"); pane.append(path, inner);
    if (kind === -3) window.LGServices?.overview(inner, st.d.name);
    else window.LGServicePatterns?.fields(inner, st.d.name, () => { const n = st.d.name; open(n, "services", "*fields*"); window.LGServices?.reload(); });
  }

  // ---------------- painting the chosen report (on focus, search and sort changes too)
  // the empty "across" answer: say that the addresses are there, and why the reports can still not share one
  function noOverlap(reps) {
    const box = el("div", "ig-empty ig-why");
    box.append(el("p", null, "No device was seen in more than one report for this name. Every record carries its IP address; each IP address simply turned up in one report only."));
    const why = [], v6 = reps.filter((r) => /ipv6/i.test(r)), v4 = reps.filter((r) => !/ipv6/i.test(r));
    if (v6.length && v4.length)
      why.push(`${v6.join(", ")} records a different IP address for a machine than the other reports do, so its IP addresses never match theirs, even when it is the same machine.`);
    if (reps.some((r) => /dns/i.test(r)) && reps.some((r) => !/dns/i.test(r)))
      why.push("In a DNS report the IP address is often the DNS server that looked the name up on the machine's behalf (an ISP's or company's resolver), while other reports see the infected machine's own IP address, so the two rarely match.");
    if (why.length) {
      const ul = el("ul", "ig-why-list");
      why.forEach((t) => ul.append(el("li", null, t)));
      box.append(ul);
    }
    return box;
  }
  function pick(i) { if (!st || i === st.i || i < st.min || i >= st.d.reports.length) return; st.i = i; st.focus = null; st.open = {}; paint(true); }
  // services: the extra rail entries (-2 pattern fields, -3 about this report) are not in the [ ] cycle
  function pickExtra(i) { if (!st) return; st.i = i; st.focus = null; paint(true); }
  function paint(scrollTop) {
    const d = st.d;
    st.rail.querySelectorAll(".ig-rep-btn").forEach((b) => { const on = +b.dataset.i === st.i; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
    if (st.i === -1) { st.pane.replaceChildren(); acrossView(st.pane); if (scrollTop) keepPlace(); return; }
    if (st.i < -1) { if (scrollTop) servicePane(st.i); if (scrollTop) keepPlace(); return; }    // drawn once (forms keep their state)
    const r = d.reports[st.i];
    const pane = st.pane; pane.replaceChildren();
    const path = el("div", "ig-path");
    path.append(el("code", null, d.title || d.name), el("span", "ig-sep", "›"), el("b", null, rn(r.report)), el("span", "ig-sep", "›"),
      el("span", null, `${plural(r.records, "record")} · what comes with it here`));
    if (st.focus) {
      const f = el("button", "ig-focus"); f.type = "button"; f.title = "Clear the focus (Esc)";
      f.append(svg(ICON.focus, 13), el("span", null, "Focus"), el("code", null, st.focus), svg(ICON.close, 12, 2.2));
      f.addEventListener("click", () => { st.focus = null; paint(); }); path.append(f);
    }
    pane.append(path);
    const ks = [...r.indicators].sort((a, b) => (ORDER.indexOf(a.kind) + 1 || 99) - (ORDER.indexOf(b.kind) + 1 || 99));
    if (!ks.length) { pane.append(el("p", "ig-empty", "This report carries nothing more for it than the name.")); return; }
    if (r.combinations?.length) pane.append(comboCard(r));
    else if (r.single?.code) {
      // one combination only: no card, but its code, so an analyst can still pull exactly these devices
      const one = el("div", "ig-one-code");
      one.append(el("span", null, `Every record here carries the same set${r.single.items.length ? `: ${r.single.items.join(" + ")}` : ""}`),
        codeChip(r.single.code, `${d.name} in ${r.report}: ${r.single.items.join(" + ") || "the name only"}`),
        noteBtn(r.single.code, `${rn(r.report)}: ${r.single.items.join(" + ") || "the name only"}`));
      pane.append(one);
    }
    const grid = el("div", "ig-grid");
    for (const k of ks) grid.append(kindCard(k));
    pane.append(grid);
    if (st.q && !pane.querySelector(".ig-card:not(.empty) li.ig-v:not(.out), .ig-mrow:not(.dim):not(.ig-mhead), .ig-sets li:not(.dim)"))
      pane.append(el("p", "ig-empty", `Nothing in ${rn(r.report)} matches “${st.q}”.`));
    if (scrollTop) keepPlace();
  }
  // switching report: stay where the reader is; only when they are below the start of the report content, bring that
  // start into view (never back up to "Looking Glass asks" above it)
  function keepPlace() {
    const layout = st.pane.closest(".ig-layout"); if (!layout) return;
    const top = layout.offsetTop - 12;
    if (body.scrollTop > top) body.scrollTo({ top, behavior: "instant" });
  }

  async function open(name, section, report) {
    shell();
    $("igName").textContent = name; $("igSec").textContent = SEC[section] || SEC.infections; $("igMeta").replaceChildren();
    $("igQ").value = "";
    body.replaceChildren(el("div", "ig-loading lg-loading", "Gathering the indicators from the reports…"));   // the searching logo (loader.js)
    back.hidden = false; box.hidden = false; document.documentElement.classList.add("ig-open");
    let d; try { d = await get(`/api/intel?section=${encodeURIComponent(section || "infections")}&name=${encodeURIComponent(name)}`); }
    catch (e) { body.replaceChildren(el("p", "ig-empty", `Could not gather the intel: ${e.message}`)); return; }
    const svc = d.section === "services";
    if (d.title) $("igName").textContent = d.title;            // a services report: its title, the collection names small
    const records = d.reports.reduce((s, r) => s + r.records, 0), kinds = new Set(d.reports.flatMap((r) => r.indicators.map((k) => k.kind)));
    const meta = $("igMeta");
    const facts = svc ? [[plural(d.reports[0]?.hosts || 0, "device"), ""], [plural(records, "record"), ""], [plural(kinds.size, "pattern field"), " with values"],
                         [d.days.map((x) => x.slice(5)).join(" · "), " in memory"], [d.name, ""]]
      : [[plural(d.reports.length, "report"), ""], [plural(records, "record"), ""], [plural(kinds.size, "kind"), " of indicator"], [d.days.map((x) => x.slice(5)).join(" · "), " in memory"]];
    for (const [n, l] of facts)
      { const s = el("span"); s.append(el("b", null, n), document.createTextNode(l)); meta.append(s); }
    if (svc) meta.lastChild.classList.add("ig-meta-id");
    body.replaceChildren();
    if (d.asks?.length) {                         // services: Looking Glass's question about the pattern fields
      const ask = el("div", "ig-svc-ask"); ask.append(svg(ICON.ask, 16), el("b", null, "Looking Glass asks:"), el("span", null, d.asks.join(" ")));
      const go = el("button", "ig-more", "Open the pattern fields"); go.type = "button"; go.addEventListener("click", () => pickExtra(-2)); ask.append(go);
      body.append(ask);
    }
    if (d.leads?.length) {
      const asks = el("section", "ig-asks");
      const ah = el("div", "ig-asks-h"); ah.append(svg(ICON.ask, 16), el("b", null, "Looking Glass asks: can you look into this?"), el("span", null, plural(d.leads.length, "match")));
      const ul = el("ul", "ig-leads"); d.leads.forEach((x, i) => { const li = leadItem(x, d.name); if (i >= 2) li.hidden = true; ul.append(li); });
      asks.append(ah, ul);
      if (d.leads.length > 2) {           // the first two; the rest on request, so the intel stays in view
        const more = el("button", "ig-more", `Show ${d.leads.length - 2} more`); more.type = "button";
        more.addEventListener("click", () => { const o = more.dataset.open !== "1"; ul.querySelectorAll("li").forEach((li, i) => { if (i >= 2) li.hidden = !o; }); more.dataset.open = o ? "1" : ""; more.textContent = o ? "Show fewer" : `Show ${d.leads.length - 2} more`; });
        asks.append(more);
      }
      body.append(asks);
    }
    if (!d.reports.length) { body.append(el("p", "ig-empty", `${d.name} is not in the reports held in memory (${d.days.join(", ")}), so there is nothing to gather right now. The Definitions list shows where and when it was last seen.`)); return; }
    const layout = el("div", "ig-layout");
    const rail = el("nav", "ig-rail"); rail.setAttribute("role", "tablist"); rail.setAttribute("aria-label", "Reports");
    rail.append(el("div", "ig-rail-h", svc ? "This report" : `Seen in ${plural(d.reports.length, "report")}`));
    const maxRec = Math.max(1, ...d.reports.map((r) => r.records));
    const crossAny = d.cross && ((d.cross.services || []).length || (d.cross.issues || []).length || (d.cross.infections || []).length);
    const cross = d.reports.length > 1 || !!d.across_always || !!crossAny;
    if (cross) {                                   // the view across the reports, first in the rail
      const a = d.across || {};
      const b = el("button", "ig-rep-btn ig-rep-x"); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.i = -1;
      b.append(el("span", "ig-rep-n", "Across reports"), el("span", "ig-rep-m", svc
        ? `${fmt(a.multi_devices || 0)} in other reports · ${fmt(d.sinkholes?.hosts || 0)} calling sinkholes`
        : `${fmt(a.multi_devices || 0)} devices in 2+ · ${fmt(a.shared_total || 0)} shared`));
      if (svc && d.sinkholes?.hosts) b.classList.add("alert");
      b.addEventListener("click", () => pick(-1)); rail.append(b);
    }
    d.reports.forEach((r, i) => {
      const b = el("button", "ig-rep-btn"); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.i = i;
      const kinds = r.indicators.length;
      b.append(el("span", "ig-rep-n", svc ? "Patterns and combinations" : rn(r.report)),
        el("span", "ig-rep-m", `${fmt(r.records)} · ${kinds ? plural(kinds, svc ? "field" : "kind") : svc ? "tags only" : "name only"}`));
      const bar = el("i", "ig-rep-bar"); bar.style.width = `${Math.max(3, (r.records / maxRec) * 100)}%`; b.append(bar);
      if (!kinds) b.classList.add("bare");
      b.addEventListener("click", () => pick(i)); rail.append(b);
    });
    if (svc) {                                     // services: the pattern fields and what the report is, in the same window
      rail.append(el("div", "ig-rail-h", "The report"));
      for (const [i, l, m] of [[-2, "Pattern fields", d.asks?.length ? "Looking Glass asks" : "what is compared"], [-3, "About this report", "definitions, issues, products"]]) {
        const b = el("button", `ig-rep-btn ig-rep-s${i === -2 && d.asks?.length ? " ask" : ""}`); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.i = i;
        b.append(el("span", "ig-rep-n", l), el("span", "ig-rep-m", m)); b.addEventListener("click", () => pickExtra(i)); rail.append(b);
      }
    }
    rail.append(el("p", "ig-keys", "[ ]  switch report · /  search · Esc  close"));
    const pane = el("div", "ig-pane");
    layout.append(rail, pane); body.append(layout, el("p", "ig-note", "Indicators only: the hosts themselves are never shown here. Addresses inside URLs and banners are masked."));
    st = { d, i: report === "*across*" && cross ? -1 : report === "*fields*" && svc ? -2 : Math.max(0, report ? d.reports.findIndex((r) => r.report === report) : 0), q: "", sort: "count", focus: null, open: {}, rail, pane,
      min: cross ? -1 : 0 };
    paint(true);
  }

  // ---------------- "Seen in" as report cards: intel found there, or the name only (one click opens that report)
  let summary = null;
  const summaryReady = get("/api/intel/summary").then((s) => { summary = s; decorate(document); return s; }).catch(() => null);
  function decorate(root) {
    if (!summary) return;
    for (const cell of (root || document).querySelectorAll("[data-intel-name]")) {
      const section = cell.dataset.intelSection || "infections", name = cell.dataset.intelName;
      const reps = (summary[section] || {})[section === "issues" ? name : name.toLowerCase()];
      if (!reps) continue;
      const list = el("div", "ig-seen-list");
      for (const [rep, s] of Object.entries(reps).sort((a, b) => b[1].records - a[1].records)) {
        const b = el("button", `ig-seen ${s.kinds ? "on" : "off"}`); b.type = "button";
        b.append(el("span", "ig-seen-r", rep), el("span", "ig-seen-k", s.kinds ? `intel · ${plural(s.kinds, "kind")}` : "name only"));
        b.title = s.kinds ? `${fmt(s.records)} records in ${rep} carry indicators (${plural(s.kinds, "kind")}): open Intel gathered on this report`
          : `${fmt(s.records)} records in ${rep} carry the name only, no indicators`;
        b.addEventListener("click", (e) => { e.stopPropagation(); open(name, section, rep); });
        list.append(b);
      }
      if (cell.dataset.intelMode === "append") { cell.querySelector(".ig-seen-list")?.remove(); cell.append(list); }
      else cell.replaceChildren(list);
    }
  }

  // ---------------- the "Looking Glass asks" card on the page
  // the card on the Definitions page: a summary of what Looking Glass found, filters by kind, then the analysis boxes
  async function leads() {
    const card = $("cardLeads"); if (!card) return;
    let d; try { d = await get("/api/intel/leads"); } catch { return; }
    const ul = $("leadList"); ul.replaceChildren();
    $("leadSub").textContent = d.leads.length
      ? `Looking Glass compared every indicator across names and reports of ${d.days.join(", ")} and found ${plural(d.leads.length, "match")} worth a researcher's eye.`
      : `No matches between names and reports in ${d.days.join(", ") || "the days in memory"}.`;
    let bar = $("leadBar"); if (bar) bar.remove();
    bar = el("div", "ig-lead-bar"); bar.id = "leadBar";
    const names = new Set(d.leads.flatMap((x) => x.names.map((n) => n.name)));
    const undef = new Set(d.leads.flatMap((x) => x.names.filter((n) => !n.defined).map((n) => n.name)));
    const sum = el("div", "ig-lead-sum");
    for (const [n, l] of [[d.leads.length, "matches"], [names.size, "names involved"], [undef.size, "without a definition"]]) { const s = el("div"); s.append(el("b", null, fmt(n)), el("span", null, l)); sum.append(s); }
    const chips = el("div", "ig-lead-chips"); chips.setAttribute("role", "group"); chips.setAttribute("aria-label", "Show matches of one kind");
    let filter = 0, opened = false;
    const draw = () => {
      ul.replaceChildren();
      const list = d.leads.filter((x) => !filter || x.priority === filter);
      list.forEach((x, i) => { const li = leadItem(x); if (!opened && i >= 4) li.hidden = true; ul.append(li); });
      more.hidden = list.length <= 4; more.textContent = opened ? "Show fewer" : `Show all ${list.length}`;
      chips.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(+b.dataset.p === filter)));
    };
    for (const p of [0, 1, 2, 3, 4]) {
      const n = p ? d.leads.filter((x) => x.priority === p).length : d.leads.length;
      if (p && !n) continue;
      const b = el("button", `ig-lchip p${p}`); b.type = "button"; b.dataset.p = p;
      b.append(el("i"), document.createTextNode(p ? KIND_OF[p] : "All"), el("em", null, fmt(n)));
      b.addEventListener("click", () => { filter = p; opened = false; draw(); }); chips.append(b);
    }
    bar.append(sum, chips); ul.before(bar);
    let more = $("leadMore"); if (more) more.remove();
    more = el("button", "ig-more", ""); more.id = "leadMore"; more.type = "button";
    more.addEventListener("click", () => { opened = !opened; draw(); });
    ul.after(more);
    draw();
    card.hidden = !d.leads.length;
  }

  // per name: the devices seen in two or more of its reports (the Definitions tables' "Across reports" column)
  const acrossOf = (section, name) => ((summary || {}).across?.[section] || {})[section === "issues" ? name : String(name).toLowerCase()] || null;
  const recordsOf = (section, name) => Object.values(((summary || {})[section] || {})[section === "issues" ? name : String(name).toLowerCase()] || {}).reduce((s, r) => s + (r.records || 0), 0);
  window.LGIntel = { open, leads, decorate, summaryReady, acrossOf, recordsOf };
  leads();
})();
