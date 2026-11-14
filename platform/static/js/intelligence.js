/* Looking Glass · the Intelligence portal (/intelligence, intelligence.py): Shadowserver's Intelligence reports for
   analysts and admins. Group tiles (today against the median of the 7 days before, "still arriving"), one card per
   report in plain words, a report's view on its own fields (filters, free text, CSV export, leaked accounts masked
   until asked), each host's cross-view, an analyst code and finding from a filtered view, and the reports never
   received with why. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pl = (n, w, ws) => `${fmt(n)} ${n === 1 ? w : (ws || `${w}s`)}`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const main = $("itMain");
  const dayLabel = (iso) => { const d = new Date(`${iso}T00:00:00Z`); return d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" }); };
  let S = null;                       // the summary
  const view = { name: "", day: "", filters: {}, q: "", reveal: false };

  function bars(perDay, today) {      // the 8 days as small bars, today last and marked
    const max = Math.max(1, ...perDay.map((p) => p.rows));
    const w = el("div", "it-bars"); w.setAttribute("aria-hidden", "true");
    for (const p of perDay) {
      const b = el("i", p.day === today ? "now" : ""); b.style.height = `${Math.max(p.rows ? 8 : 2, Math.round((p.rows / max) * 100))}%`;
      b.title = `${dayLabel(p.day)}: ${fmt(p.rows)}`; w.append(b);
    }
    return w;
  }

  function versus(today, median) {    // today against the usual, in words
    if (!median && !today) return ["none", "nothing this week"];
    // the day's files are still coming in: a low figure is not a fall (never "100% below" before the reports arrive)
    if (S?.arriving?.still && today < median) return ["wait", `still arriving · usually ${fmt(median)}`];
    if (!median) return ["up", "new this week"];
    const r = today / median;
    if (r >= 1.5) return ["up", `${Math.round((r - 1) * 100)}% above the usual ${fmt(median)}`];
    if (r <= 0.5) return ["down", `${Math.round((1 - r) * 100)}% below the usual ${fmt(median)}`];
    return ["same", `about the usual ${fmt(median)}`];
  }

  // ------------------------------------------------------------------ the summary
  async function load() {
    let r;
    try { r = await fetch("/api/intelligence", { cache: "no-store" }); }
    catch (e) { $("itLoading")?.remove(); window.LGLoader?.ready(); main.append(el("p", "fd-empty", `Could not open it: ${e.message}`)); return; }
    const d = await r.json().catch(() => ({}));
    $("itLoading")?.remove(); window.LGLoader?.ready();
    if (!r.ok) { main.append(el("p", "fd-empty", d.error || `Could not open the Intelligence portal (HTTP ${r.status})`)); return; }
    S = d; draw();
  }

  function draw() {
    main.replaceChildren();
    const hero = el("section", "it-hero");
    hero.append(el("div", "fd-eyebrow", "Shadowserver · Intelligence reports"), el("h1", null, "Intelligence"),
      el("p", "it-sub", "What Shadowserver's Intelligence reports say about the constituency: compromised systems and victims, malicious content hosted here, addresses listed or targeted, leaked accounts and attacker infrastructure. Today is compared with the median of the 7 days before. Only hosts inside the constituency are counted."));
    const a = S.arriving;
    const line = el("p", `it-arrive ${a.still ? "still" : "in"}`);
    line.textContent = a.still ? `Today's reports are still arriving: ${a.in} of the usual ${a.usual} in so far (${dayLabel(S.today)}). Today's figures will grow during the day.`
      : `Today's reports are in: ${a.in} report${a.in === 1 ? "" : "s"} (usually ${a.usual}), ${dayLabel(S.today)}.`;
    hero.append(line);
    main.append(hero);
    // group tiles
    const tiles = el("section", "it-tiles");
    for (const gr of S.groups) {
      const [k, words] = versus(gr.today, gr.median);
      const t = el("button", `it-tile ${k}`); t.type = "button";
      t.append(el("small", null, gr.group), el("b", null, fmt(gr.today)), el("span", "it-vs", words),
        el("span", "it-rc", `${gr.received} of ${pl(gr.reports.length, "report")} received this week`), bars(gr.per_day, S.today));
      t.addEventListener("click", () => document.getElementById(`it-g-${slug(gr.group)}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
      tiles.append(t);
    }
    main.append(tiles);
    // the report view (filled when a card is opened)
    const pane = el("section", "it-view"); pane.id = "itView"; pane.hidden = true; main.append(pane);
    // per group: the reports received, as cards
    for (const gr of S.groups) {
      const rec = gr.reports.filter((x) => x.received);
      const sec = el("section", "it-group"); sec.id = `it-g-${slug(gr.group)}`;
      sec.append(el("h2", null, gr.group));
      if (!rec.length) { sec.append(el("p", "fd-empty", "No report of this group received this week (see below).")); main.append(sec); continue; }
      const cards = el("div", "it-cards");
      for (const x of rec) cards.append(card(x));
      sec.append(cards); main.append(sec);
    }
    // never received
    if (S.not_received.length) {
      const nr = el("section", "it-group it-nr");
      nr.append(el("h2", null, `Not received this week (${S.not_received.length})`),
        el("p", "it-sub", "These Intelligence reports exist, but no file of them reached Looking Glass in the last 8 days."));
      const ul = el("ul", "it-nr-list");
      for (const x of S.not_received) {
        const li = el("li");
        li.append(el("b", null, x.title), el("small", null, x.group + (x.kept ? " · older records kept" : "")), el("p", null, x.why));
        ul.append(li);
      }
      nr.append(ul); main.append(nr);
    }
    main.append(el("p", "it-foot", `Figures of ${new Date(S.generated).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}; they are kept two minutes.`));
  }

  const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-");

  function card(x) {
    const [k, words] = versus(x.today, x.median);
    const c = el("article", "it-card");
    const h = el("header");
    h.append(el("h3", null, x.title));
    if (x.no_ip) h.append(el("span", "it-tag", "no IP address"));
    if (x.severity) h.append(el("span", `it-sev ${x.severity}`, x.severity));
    c.append(h, el("p", "it-meaning", x.meaning || `Affected: ${x.affected}`));
    const n = el("div", "it-n");
    n.append(el("b", null, fmt(x.today)), el("span", `it-vs ${k}`, `today · ${words}`));
    c.append(n, bars(x.per_day, S.today));
    const row = el("div", "it-acts");
    const open = el("button", "lg-btn primary sm", "Open the records"); open.type = "button";
    const last = [...x.per_day].reverse().find((p) => p.rows);
    open.addEventListener("click", () => openView(x.name, (x.today ? S.today : last?.day) || S.today));
    row.append(open);
    if (x.url) { const a = el("a", "it-link", "Shadowserver's description"); a.href = x.url; a.target = "_blank"; a.rel = "noopener noreferrer"; row.append(a); }
    c.append(row);
    return c;
  }

  // ------------------------------------------------------------------ a report's view
  function qs(extra) {
    const p = new URLSearchParams({ name: view.name, day: view.day });
    for (const [k, vs] of Object.entries(view.filters)) for (const v of vs) p.append(k, v);
    if (view.q) p.set("q", view.q);
    if (view.reveal) p.set("reveal", "1");
    for (const [k, v] of Object.entries(extra || {})) p.set(k, v);
    return p.toString();
  }

  function openView(name, day) {
    Object.assign(view, { name, day, filters: {}, q: "", reveal: false });
    fetchView(true);
  }

  async function fetchView(scroll) {
    const pane = $("itView"); pane.hidden = false;
    pane.replaceChildren(el("div", "st-loading", "Reading the report's records…"));
    if (scroll) pane.scrollIntoView({ behavior: "smooth", block: "start" });
    let r, d;
    try { r = await fetch(`/api/intelligence/report?${qs()}`, { cache: "no-store" }); d = await r.json().catch(() => ({})); }
    catch (e) { pane.replaceChildren(el("p", "fd-empty", `Could not read it: ${e.message}`)); return; }
    if (!r.ok) { pane.replaceChildren(el("p", "fd-empty", d.error || `Could not read it (HTTP ${r.status})`)); return; }
    drawView(pane, d);
  }

  function drawView(pane, d) {
    pane.replaceChildren();
    const h = el("header", "it-vh");
    const t = el("div");
    t.append(el("div", "fd-eyebrow", "Report"), el("h2", null, d.title), el("p", "it-sub", d.meaning));
    const close = el("button", "lg-btn sm", "Close"); close.type = "button";
    close.addEventListener("click", () => { pane.hidden = true; pane.replaceChildren(); });
    h.append(t, close); pane.append(h);
    // the days
    const days = el("div", "it-days"); days.setAttribute("role", "tablist");
    for (const dd of d.days) {
      const b = el("button", "it-day", dayLabel(dd)); b.type = "button"; b.setAttribute("role", "tab");
      b.setAttribute("aria-selected", String(dd === d.day));
      b.addEventListener("click", () => { view.day = dd; fetchView(false); }); days.append(b);
    }
    pane.append(days);
    // filters: its own fields' values, then a free text
    const fl = el("div", "it-facets");
    for (const f of d.facets) {
      const g = el("div", "it-facet"); g.append(el("b", null, f.label));
      const chips = el("div", "it-chips");
      for (const v of f.values) {
        const on = (view.filters[f.key] || []).includes(v.value);
        const c = el("button", `it-chip${on ? " on" : ""}`); c.type = "button";
        c.append(el("span", null, v.value), el("small", null, fmt(v.rows)));
        c.title = v.value; c.setAttribute("aria-pressed", String(on));
        c.addEventListener("click", () => {
          const cur = new Set(view.filters[f.key] || []);
          if (cur.has(v.value)) cur.delete(v.value); else cur.add(v.value);
          if (cur.size) view.filters[f.key] = [...cur]; else delete view.filters[f.key];
          fetchView(false);
        });
        chips.append(c);
      }
      if (f.more) chips.append(el("small", "it-more", `and ${pl(f.more, "other value")}: use the search`));
      g.append(chips); fl.append(g);
    }
    const sf = el("form", "it-search");
    const inp = el("input", "fd-in"); inp.type = "search"; inp.placeholder = "Search every field (an address, a domain, a word)"; inp.value = d.q || ""; inp.maxLength = 120;
    inp.setAttribute("aria-label", "Search the records");
    const go = el("button", "lg-btn sm", "Search"); go.type = "submit";
    sf.append(inp, go);
    sf.addEventListener("submit", (e) => { e.preventDefault(); view.q = inp.value.trim(); fetchView(false); });
    fl.append(sf);
    pane.append(fl);
    // what this view holds, and what can be done with it
    const bar = el("div", "it-vbar");
    const nf = Object.values(view.filters).reduce((s, v) => s + v.length, 0) + (view.q ? 1 : 0);
    bar.append(el("span", "it-count", `${pl(d.total, "record")}${d.no_ip ? "" : ` · ${pl(d.hosts, "host")}`}${nf ? ` · ${pl(nf, "filter")}` : ""}${d.total > d.shown ? ` · the first ${fmt(d.shown)} shown (the export carries all)` : ""}`));
    if (nf) { const c = el("button", "lg-btn sm", "Clear the filters"); c.type = "button"; c.addEventListener("click", () => { view.filters = {}; view.q = ""; fetchView(false); }); bar.append(c); }
    if (d.can_reveal) {
      const rv = el("button", "lg-btn sm", view.reveal ? "Mask the accounts again" : "Show the accounts"); rv.type = "button";
      rv.title = view.reveal ? "" : "Leaked accounts are masked. Showing them is written to the audit log.";
      rv.addEventListener("click", () => { view.reveal = !view.reveal; fetchView(false); }); bar.append(rv);
    }
    if (d.total) { const ex = el("a", "lg-btn sm", "Export CSV"); ex.href = `/api/intelligence/export.csv?${qs()}`; ex.title = "Every record of this view. The export is written to the audit log."; bar.append(ex); }
    pane.append(bar);
    if (d.masked) pane.append(el("p", "it-note", "Accounts are masked (first letter and domain). “Show the accounts” shows them in full; that is written to the audit log."));
    // the records
    if (!d.rows.length) pane.append(el("p", "fd-empty", "No record on this day with these filters."));
    else pane.append(table(d));
    // an analyst code and finding from this view
    if (d.code) pane.append(codeBox(d));
    else if (!d.no_ip && d.total) pane.append(el("p", "it-note", "An analyst code is made from the services platform's records: this report is not among them."));
  }

  function table(d) {
    const wrap = el("div", "it-tablewrap");
    const tb = el("table", "it-table");
    const cols = d.columns;
    const thead = el("thead"), tr = el("tr");
    for (const c of cols) tr.append(el("th", null, c.label));
    if (d.extra.length) tr.append(el("th", null, "More"));
    thead.append(tr); tb.append(thead);
    const body = el("tbody");
    for (const r of d.rows) {
      const row = el("tr");
      for (const c of cols) {
        const td = el("td", `c-${c.key}`);
        const v = r[c.key] || "";
        if (c.key === "ip" && v) {
          const b = el("button", "it-ip", v); b.type = "button"; b.title = "What else this host carries";
          b.addEventListener("click", () => hostView(v, b)); td.append(b);
        } else td.textContent = v;
        row.append(td);
      }
      if (d.extra.length) {
        const td = el("td", "c-more");
        const more = d.extra.filter((k) => r[k]);
        if (more.length) {
          const det = el("details"); det.append(el("summary", null, pl(more.length, "field")));
          const dl = el("dl");
          for (const k of more) dl.append(el("dt", null, k.replace(/_/g, " ")), el("dd", null, r[k]));
          det.append(dl); td.append(det);
        }
        row.append(td);
      }
      body.append(row);
    }
    tb.append(body); wrap.append(tb);
    return wrap;
  }

  // ------------------------------------------------------------------ a host's cross-view
  async function hostView(ip, from) {
    let box = document.querySelector(".it-host");
    if (box) box.remove();
    box = el("aside", "it-host"); box.setAttribute("role", "dialog"); box.setAttribute("aria-label", `What ${ip} carries`);
    const head = el("header"); head.append(el("b", null, ip));
    const x = el("button", "lg-btn sm", "Close"); x.type = "button"; x.addEventListener("click", () => { box.remove(); from?.focus(); });
    head.append(x); box.append(head, el("div", "st-loading", "Following this host through the week's reports…"));
    document.body.append(box); x.focus();
    const onKey = (e) => { if (e.key === "Escape") { box.remove(); from?.focus(); document.removeEventListener("keydown", onKey); } };
    document.addEventListener("keydown", onKey);
    let r, d;
    try { r = await fetch(`/api/intelligence/host?ip=${encodeURIComponent(ip)}`, { cache: "no-store" }); d = await r.json().catch(() => ({})); }
    catch (e) { box.lastChild.replaceWith(el("p", "fd-empty", `Could not read it: ${e.message}`)); return; }
    if (!r.ok) { box.lastChild.replaceWith(el("p", "fd-empty", d.error || `HTTP ${r.status}`)); return; }
    const body = el("div", "it-hbody");
    body.append(el("h4", null, "In the Intelligence reports this week"));
    if (!d.intelligence.length) body.append(el("p", "fd-empty", "In none (inside the constituency)."));
    for (const s of d.intelligence) {
      const c = el("div", "it-hrep");
      c.append(el("b", null, s.title), el("small", null, `${pl(s.rows, "record")} · ${s.days.map(dayLabel).join(", ")}`));
      for (const [k, vs] of Object.entries(s.facts || {})) { const p = el("p"); p.append(el("span", null, `${k}: `), document.createTextNode(vs.join(", "))); c.append(p); }
      body.append(c);
    }
    body.append(el("h4", null, "On the services platform (the days in memory)"));
    const svc = d.services || [];
    if (!svc.length && !(d.issues || []).length && !(d.infections || []).length) body.append(el("p", "fd-empty", "Nothing else known for this host on those days."));
    if (svc.length) body.append(el("p", null, `Services reports: ${svc.map((s) => s.title || s.report).join(", ")}`));
    if ((d.issues || []).length) body.append(el("p", null, `CVEs and issues: ${d.issues.map((i) => i.name).join(", ")}`));
    if ((d.infections || []).length) body.append(el("p", null, `Calling sinkholes as: ${d.infections.map((i) => i.name).join(", ")}`));
    box.lastChild.replaceWith(body);
  }

  // ------------------------------------------------------------------ an analyst code and finding from the view
  function codeBox(d) {
    const c = d.code;
    const box = el("div", "it-code");
    box.append(el("h3", null, "Make an analyst code and finding from this view"));
    if (!c.possible) {
      box.append(el("p", "it-note", `This view holds ${pl(c.hosts, "host")}; a code is made of ${fmt(c.max)} at most. Narrow it with the filters first.`));
      return box;
    }
    box.append(el("p", "it-sub", `Exactly these ${pl(c.hosts, "host")}' records in this report, on the day they were seen, go to the researcher you choose as an analyst code (no address leaves for them: a host is "1 host").`));
    const ti = el("input", "fd-in"); ti.maxLength = 140; ti.placeholder = "A short title for the finding"; ti.setAttribute("aria-label", "Title");
    const ta = el("textarea", "fd-in"); ta.rows = 3; ta.maxLength = 2000; ta.placeholder = "Your note for the researcher: what you see and what you ask"; ta.setAttribute("aria-label", "Note");
    const to = window.LGPeople ? window.LGPeople.picker("researcher") : null;
    const go = el("button", "lg-btn primary", "Make the code and send it"); go.type = "button";
    const m = el("span", "fd-msg");
    go.addEventListener("click", async () => {
      if (!ti.value.trim()) { m.textContent = "Give the finding a short title."; m.className = "fd-msg bad"; ti.focus(); return; }
      if (to && !to.check()) { m.textContent = "Choose the researcher it goes to."; m.className = "fd-msg bad"; return; }
      go.disabled = true; m.textContent = "Making the code…"; m.className = "fd-msg lg-loading";
      try {
        const r = await fetch("/api/analyst-codes", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
          body: JSON.stringify({ platform: "services", query: c.query, at: c.at, title: ti.value.trim(), text: ta.value.trim(), to: to ? to.value() : "" }) });
        const x = await r.json().catch(() => ({}));
        if (!r.ok) { m.textContent = x.error || `Not made (HTTP ${r.status})`; m.className = "fd-msg bad"; return; }
        box.replaceChildren(el("h3", null, "Analyst code made"));
        const p = el("p"); const a = el("a", null, x.code); a.href = `/intel/${encodeURIComponent(x.code)}`;
        p.append(a, document.createTextNode(` · finding ${x.finding} to ${x.to} · ${pl(x.records, "record")}, ${pl(x.hosts, "host")}.`));
        box.append(p);
      } catch { m.textContent = "The connection was interrupted. Try again."; m.className = "fd-msg bad"; }
      finally { go.disabled = false; }
    });
    const row = el("div", "it-acts"); row.append(m, go);
    box.append(ti, ta, ...(to ? [to.el] : []), row);
    return box;
  }

  load();
})();
