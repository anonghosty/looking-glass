/* Looking Glass · Services on the researchers' page (services_kb.py): every publicly accessible / vulnerable services
   report, grouped by what the exposure means; what Shadowserver says, what Looking Glass says, what the reports show here
   (counts only: researchers never see a host), the issues on those hosts (linked to the Issues card), notes, and
   "Looking Glass asks" for new or changed report types. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  if (!$("cardSvc")) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pill = (text, kind) => el("span", `dz-pill ${kind || ""}`, text);
  const SEV = { critical: "bad", high: "warn", medium: "info", low: "", info: "" };
  const SHORT = { "Known vulnerability": "Known vulnerability", "Should not be open to the internet (remote access, databases, management)": "Should not be open",
    "Can be abused for attacks (amplification, tunnels)": "Can be abused for attacks", "Inventory: what is visible (informational)": "Inventory" };
  const SUB = { "Known vulnerability": "named flaws, CVEs", "Should not be open to the internet (remote access, databases, management)": "remote access, databases, management",
    "Can be abused for attacks (amplification, tunnels)": "amplification, tunnels", "Inventory: what is visible (informational)": "what is visible" };
  let data = null, tab = "";

  async function load() {
    const r = await fetch("/api/kb/services", { cache: "no-store" });
    if (!r.ok) { $("cardSvc").hidden = true; return; }
    data = await r.json();
    $("cardSvc").hidden = false;
    const groups = data.groups.filter((g) => data.reports.some((x) => x.group === g));
    if (!tab || !groups.includes(tab)) tab = groups.find((g) => data.reports.some((x) => x.group === g && x.hosts)) || groups[0] || "";
    const tabs = $("svcTabs"); tabs.replaceChildren();
    for (const g of groups) {
      const all = data.reports.filter((x) => x.group === g), seen = all.filter((x) => x.hosts);
      const b = el("button", `dz-stat${g === "Known vulnerability" ? " bad" : g.startsWith("Should") ? " warn" : ""}`); b.type = "button"; b.setAttribute("role", "tab");
      b.append(el("b", null, fmt(seen.length)), el("span", null, SHORT[g] || g), el("em", null, `${SUB[g] || ""} · of ${all.length} reports`));
      b.addEventListener("click", () => { tab = g; render(); });
      b.dataset.g = g; tabs.append(b);
    }
    asks();
    const s = data.status || {};
    const stat = $("svcStatus");
    stat.className = `dz-status ${s.feed_error ? "warn" : "ok"}`;
    stat.textContent = s.feed_error ? `Report feed not read (last good copy in use): ${s.feed_error}`
      : s.source === "updated here" ? `Report feed read ${String(s.feed_checked).replace("T", " ").replace("Z", " UTC")} · Shadowserver schema ${s.schema_commit}`
      : `Using the report map shipped with Looking Glass (schema ${s.schema_commit}); the daily report feed has not been read yet.`;
    render();
  }

  function asks() {
    const ev = data.events || [], box = $("svcAsks"), ul = $("svcAskList");
    box.hidden = !ev.length; ul.replaceChildren();
    for (const e of ev.slice(0, 8)) {
      const li = el("li", `svc-ask k-${e.kind}`);
      li.append(el("span", "svc-ask-k", e.kind === "new_report" ? "New report type" : e.kind === "description_changed" ? "Description updated" : "Changed"),
        el("span", "svc-ask-t", e.text), el("span", "svc-ask-d", String(e.at || "").slice(0, 10)));
      const r = data.reports.find((x) => x.names.includes(e.report) || (e.url && x.url === e.url));
      if (r) { const b = el("button", "lg-btn sm", "Open"); b.type = "button"; b.addEventListener("click", () => openDetail(r.name)); li.append(b); }
      ul.append(li);
    }
  }

  function rows() {
    const q = $("svcSearch").value.trim().toLowerCase(), only = $("svcSeen").checked;
    return data.reports.filter((x) => (q ? true : x.group === tab) && (!only || x.hosts || q)
      && (!q || [x.title, x.name, x.names.join(" "), x.products.join(" "), x.ports.join(" "), x.issues.map((i) => i.name).join(" "), x.def].join(" ").toLowerCase().includes(q)));
  }
  function render() {
    for (const b of $("svcTabs").children) b.setAttribute("aria-selected", String(b.dataset.g === tab && !$("svcSearch").value.trim()));
    const tb = $("svcTable").querySelector("tbody"); tb.replaceChildren();
    const list = rows();
    if (!list.length) {
      const tr = el("tr", "dz-empty"), td = el("td", null, $("svcSearch").value.trim() ? "Nothing matches the search." :
        "No report of this group was seen in the days in memory. Untick “Only reports seen here” to see them all.");
      td.colSpan = 6; tr.append(td); tb.append(tr); return;
    }
    for (const x of list) {
      const tr = el("tr");
      const name = el("td", "svc-name");
      const t = el("b", null, x.title); name.append(t);
      const meta = el("small", "mono", x.names.join(" · "));
      name.append(meta);
      if (x.new) name.append(pill("New report type", "warn"));
      if (x.pattern_asks?.length && x.hosts) {
        const p = pill("Check pattern fields", "warn"); p.title = x.pattern_asks.join("\n"); name.append(p);
      }
      const seen = el("td", "dz-seen");
      if (x.hosts) {
        seen.append(el("b", null, `${fmt(x.hosts)} hosts`), el("small", null, `${fmt(x.records)} records`));
        if (x.products.length) seen.append(el("small", "muted svc-prod", x.products.join(" · ")));
      } else seen.append(el("span", "muted", x.received ? "Received, not in the days in memory" : "Not received here"));
      const sev = el("td"); sev.append(pill(x.severity ? x.severity[0].toUpperCase() + x.severity.slice(1) : "–", SEV[x.severity] ?? ""));
      const iss = el("td", "dz-pills svc-iss");
      if (!x.issues.length) iss.append(el("span", "muted", x.hosts ? "none found" : "–"));
      for (const i of x.issues.slice(0, 4)) {
        const b = el("button", `dz-pill svc-ip ${i.exploited ? "bad" : i.cve ? "info" : i.defined ? "ok" : "warn"}`, i.name); b.type = "button";
        b.title = `${fmt(i.hosts)} host${i.hosts === 1 ? "" : "s"}${i.exploited ? " · actively exploited (CISA KEV)" : ""}${i.cvss != null ? ` · CVSS ${i.cvss}` : ""} — show it in Issues`;
        if (i.exploited) b.prepend(el("i", "svc-kev", "KEV"));
        b.addEventListener("click", () => toIssue(i.name)); iss.append(b);
      }
      if (x.issues_total > 4) iss.append(el("span", "muted", `+${x.issues_total - 4} more`));
      const what = el("td", "dz-def svc-def");
      what.append(el("span", null, x.def || "—"));
      const src = el("small", "svc-src");
      if (x.url) { const a = el("a", null, "Shadowserver's page ↗"); a.href = x.url; a.target = "_blank"; a.rel = "noopener"; src.append(a); }
      if (x.page?.last_updated) src.append(document.createTextNode(` · updated ${x.page.last_updated}`));
      if (x.notes) src.append(document.createTextNode(` · ${x.notes} note${x.notes === 1 ? "" : "s"}`));
      what.append(src);
      const act = el("td", "dz-act");
      const det = el("button", "lg-btn sm primary", "Details"); det.type = "button"; det.addEventListener("click", () => openDetail(x.name));
      const nb = el("button", "lg-btn sm ghost", "Notes"); nb.type = "button"; nb.hidden = !window.LGNotes;
      nb.addEventListener("click", () => window.LGNotes?.open(x.name, "services", x.title));
      act.append(det, nb);
      tr.append(name, seen, sev, iss, what, act); tb.append(tr);
    }
  }
  // an issue pill: the Issues card, filtered to it
  function toIssue(name) {
    const s = $("issSearch"); if (!s) return;
    const all = document.querySelector('[data-iss="cves"]'), def = document.querySelector('[data-iss="defined"]'), need = document.querySelector('[data-iss="needs"]');
    (/^CVE-/i.test(name) ? all : def || need)?.click();
    s.value = name; s.dispatchEvent(new Event("input"));
    $("cardIss").scrollIntoView({ behavior: "smooth", block: "start" });
  }
  $("svcSearch").addEventListener("input", render);
  $("svcSeen").addEventListener("change", render);

  // ---------------- the Details window
  const back = el("div", "kbn-back"); back.hidden = true;
  const box = el("section", "svc-modal"); box.hidden = true; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true");
  document.body.append(back, box);
  let opener = null;
  function shut() { box.hidden = true; back.hidden = true; document.body.classList.remove("kbn-open"); opener?.focus?.(); }
  back.addEventListener("click", shut);
  box.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); shut(); } });
  function bars(title, items, unit) {
    const s = el("section", "svc-block"); s.append(el("h4", null, title));
    if (!items?.length) { s.append(el("p", "muted", "Nothing in the reports.")); return s; }
    const max = Math.max(...items.map(([, n]) => n));
    const ul = el("ul", "svc-bars");
    for (const [k, n] of items) {
      const li = el("li"); const bar = el("i"); bar.style.width = `${Math.max(3, (n / max) * 100)}%`;
      li.append(el("span", "svc-bk", k), el("span", "svc-bar"), el("b", null, `${fmt(n)}${unit ? ` ${unit}` : ""}`)); li.children[1].append(bar); ul.append(li);
    }
    s.append(ul); return s;
  }
  async function openDetail(name) {
    opener = document.activeElement;
    box.replaceChildren(el("p", "svc-loading", "Reading what the reports show for this service…"));
    box.hidden = false; back.hidden = false; document.body.classList.add("kbn-open");
    const r = await fetch(`/api/kb/service?name=${encodeURIComponent(name)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { box.replaceChildren(el("p", "svc-loading", d.error || `Could not open (HTTP ${r.status})`)); return; }
    box.replaceChildren();
    const head = el("header", "svc-mhead"), t = el("div");
    t.append(el("div", "kbn-eyebrow", `Services report · ${SHORT[d.group] || d.group}`), el("h2", null, d.title), el("div", "mono svc-names", d.names.join(" · ")));
    const pills = el("div", "dz-pills");
    pills.append(pill(`Shadowserver: ${d.severity || "unrated"}`, SEV[d.severity] ?? ""), pill(d.classification, ""));
    t.append(pills);
    const x = el("button", "icon-btn kbn-close", "✕"); x.type = "button"; x.setAttribute("aria-label", "Close"); x.addEventListener("click", shut);
    head.append(t, x);
    const body = el("div", "svc-mbody"), left = el("div", "svc-col"), right = el("div", "svc-col");
    // what Looking Glass says
    const lg = el("section", "svc-block"); lg.append(el("h4", null, "What Looking Glass says"));
    lg.append(el("p", null, d.definition.def || "No definition yet."));
    if (d.definition.why) lg.append(el("p", "svc-why", d.definition.why));
    left.append(lg);
    // what Shadowserver says
    const ss = el("section", "svc-block"); ss.append(el("h4", null, "What Shadowserver says"));
    const p = d.shadowserver || {};
    if (p.blocks?.length) {
      for (const b of p.blocks) ss.append(el(b.kind === "h" ? "h5" : b.kind === "li" ? "li" : "p", null, b.text));
      ss.append(el("p", "svc-attr", "Description: The Shadowserver Foundation."));
    } else {
      ss.append(el("p", "muted", "Shadowserver describes this report on its own page" + (p.last_updated ? ` (last updated ${p.last_updated})` : "") + "."));
    }
    if (d.url) { const a = el("a", "lg-btn sm", "Read it on shadowserver.org ↗"); a.href = d.url; a.target = "_blank"; a.rel = "noopener"; ss.append(a); }
    if (p.field_names?.length) {
      const f = el("div", "svc-fields"); f.append(el("span", "muted", `Its fields (${p.field_names.length}): `));
      for (const n of p.field_names) { const c = el("code", null, n); if (p.fields?.[n]) c.title = p.fields[n]; f.append(c); }
      ss.append(f);
    }
    left.append(ss);
    // notes
    const nt = el("section", "svc-block"); nt.append(el("h4", null, `Researchers' notes${d.notes.length ? ` (${d.notes.length})` : ""}`));
    for (const n of d.notes.slice(0, 5)) { const q = el("blockquote", "svc-note"); q.append(el("p", null, n.text), el("small", null, `${n.role}: ${n.by} · ${n.date}`)); nt.append(q); }
    const nb = el("button", "lg-btn sm", d.notes.length ? "All notes / add one" : "Add a note"); nb.type = "button";
    nb.addEventListener("click", () => { shut(); window.LGNotes?.open(d.name, "services", d.title); }); nt.append(nb);
    left.append(nt);
    // what the reports show here
    const fig = el("section", "svc-block svc-figs"); fig.append(el("h4", null, "Seen here (the days in memory)"));
    const nums = el("div", "svc-nums"); nums.append(el("div", null, ""), el("div", null, ""));
    nums.children[0].append(el("b", null, fmt(d.hosts)), el("span", null, "hosts")); nums.children[1].append(el("b", null, fmt(d.records)), el("span", null, "records"));
    fig.append(nums, el("p", "muted svc-privacy", "Counts only: researchers never see a host's address."));
    right.append(fig);
    const issS = el("section", "svc-block"); issS.append(el("h4", null, `Issues found on these hosts${d.issues_total ? ` (${d.issues_total})` : ""}`));
    if (!d.issues.length) issS.append(el("p", "muted", "None in the reports."));
    else {
      const tbl = el("table", "svc-itab"), tb = el("tbody");
      for (const i of d.issues.slice(0, 25)) {
        const tr = el("tr"), n = el("td"); const b = el("button", "svc-ilink mono", i.name); b.type = "button";
        b.addEventListener("click", () => { shut(); toIssue(i.name); }); n.append(b);
        const fl = el("td", "dz-pills");
        if (i.exploited) fl.append(pill("Actively exploited", "bad"));
        if (i.cvss != null) fl.append(pill(`CVSS ${i.cvss}`, i.cvss >= 9 ? "bad" : i.cvss >= 7 ? "warn" : "info"));
        if (i.epss != null) fl.append(pill(`EPSS ${(i.epss * 100).toFixed(1)}%`, i.epss >= 0.1 ? "warn" : ""));
        if (!i.cve) fl.append(pill(i.defined ? "Defined" : "Needs a definition", i.defined ? "ok" : "warn"));
        tr.append(n, el("td", "svc-num", `${fmt(i.hosts)} host${i.hosts === 1 ? "" : "s"}`), fl); tb.append(tr);
      }
      tbl.append(tb); issS.append(tbl);
    }
    right.append(issS, bars("Products", d.products), bars("Devices (vendor and type)", d.devices), bars("Versions", d.versions),
      bars("Ports", d.ports), bars("Tags (not CVEs)", d.tags));
    body.append(left, right);
    // tabs: Overview, and the patterns (kb-services-patterns.js): Patterns, Across reports, Pattern fields
    if (d.pattern_asks?.length) {
      const ask = el("div", "svp-ask"); ask.append(el("b", null, "Looking Glass asks: "), document.createTextNode(d.pattern_asks.join(" ")));
      t.append(ask);
    }
    const titleOf = (n) => (data?.reports || []).find((r) => r.name === n || r.names.includes(n))?.title || n;
    const extra = window.LGServicePatterns ? window.LGServicePatterns.panes(d.name, titleOf, () => load()) : [];
    const tabs = el("div", "svp-tabs"); tabs.setAttribute("role", "tablist");
    const panes = [["Overview", null], ...extra].map(([label, fill]) => {
      const b = el("button", null, label); b.type = "button"; b.setAttribute("role", "tab");
      const pane = label === "Overview" ? body : el("div", "svc-mbody svp-pane");
      return { label, fill, b, pane, done: !fill };
    });
    const show = (p) => {
      for (const q of panes) { q.b.setAttribute("aria-selected", String(q === p)); q.pane.hidden = q !== p; }
      if (!p.done) { p.done = true; p.fill(p.pane); }
    };
    for (const p of panes) { p.b.addEventListener("click", () => show(p)); tabs.append(p.b); }
    box.append(head, tabs, ...panes.map((p) => p.pane));
    show(panes[0]);
    x.focus();
  }

  load().catch((e) => { $("svcStatus").textContent = `Could not load the services: ${e.message}`; });
})();
