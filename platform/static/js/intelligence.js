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
    if (!r.ok) { main.append(el("p", "fd-empty", d.error || `Could not open Abused or Compromised (HTTP ${r.status})`)); return; }
    S = d; draw();
  }

  function draw() {
    main.replaceChildren();
    const hero = el("section", "it-hero");
    hero.append(el("div", "fd-eyebrow", "Shadowserver · Intelligence reports"), el("h1", null, "Abused or Compromised"),
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

  // a report's records, laid out as the platforms' analysis window (app.css: i-kpis, m-sec, brk, fchip, hosts, pill-btn)
  function drawView(pane, d) {
    pane.replaceChildren();
    // the head: what it is, the day, the selection
    const head = el("header", "it-vh");
    const t = el("div");
    t.append(el("div", "fd-eyebrow", "Report · Abused or Compromised"), el("h2", null, d.title), el("p", "it-sub", d.meaning));
    const right = el("div", "it-vh-acts");
    const sel = el("select", "it-dayselect"); sel.setAttribute("aria-label", "Day");
    for (const dd of [...d.days].reverse()) { const o = new Option(dayLabel(dd), dd); if (dd === d.day) o.selected = true; sel.append(o); }
    sel.addEventListener("change", () => { view.day = sel.value; fetchView(false); });
    const close = el("button", "pill-btn", "Close"); close.type = "button";
    close.addEventListener("click", () => { pane.hidden = true; pane.replaceChildren(); });
    right.append(sel, close); head.append(t, right); pane.append(head);
    pane.append(el("p", "it-range", d.total ? `Records reported by Shadowserver on ${dayLabel(d.day)}, inside the constituency` : `No records for ${dayLabel(d.day)} with this selection`));
    // the selection, as chips (each removable), and a free text
    const parts = el("div", "i-parts it-parts");
    const nf = Object.values(view.filters).reduce((s, v) => s + v.length, 0) + (view.q ? 1 : 0);
    if (nf) {
      parts.append(el("span", "i-parts-lbl", "Selection:"));
      const label = (k, v) => { const f = d.facets.find((x) => x.key === k); const hit = f?.values.find((x) => x.value === v); return [f?.label || k, hit?.label || v]; };
      for (const [k, vs] of Object.entries(view.filters)) for (const v of vs) {
        const [kl, vl] = label(k, v);
        const chip = el("span", "fchip part"); const b = el("b", null, `${kl}:`); const s = el("span", "mono", vl);
        const x = el("button", null, "×"); x.type = "button"; x.title = "Remove this part (widen the selection)";
        x.addEventListener("click", () => { const rest = (view.filters[k] || []).filter((y) => y !== v); if (rest.length) view.filters[k] = rest; else delete view.filters[k]; fetchView(false); });
        chip.append(b, s, x); parts.append(chip);
      }
      if (view.q) { const chip = el("span", "fchip part"); const x = el("button", null, "×"); x.type = "button"; x.addEventListener("click", () => { view.q = ""; fetchView(false); }); chip.append(el("b", null, "Search:"), el("span", "mono", view.q), x); parts.append(chip); }
      const clr = el("button", "pill-btn", "Clear"); clr.type = "button"; clr.addEventListener("click", () => { view.filters = {}; view.q = ""; fetchView(false); }); parts.append(clr);
    }
    const sf = el("form", "it-search");
    const inp = el("input", "fd-in"); inp.type = "search"; inp.placeholder = "Search every field (an address, a domain, a word)"; inp.value = d.q || ""; inp.maxLength = 120;
    inp.setAttribute("aria-label", "Search the records");
    const go = el("button", "pill-btn", "Search"); go.type = "submit";
    sf.append(inp, go); sf.addEventListener("submit", (e) => { e.preventDefault(); view.q = inp.value.trim(); fetchView(false); });
    pane.append(parts, sf);
    // the figures
    const st = d.stats || {};
    const kpis = el("div", "i-kpis");
    const kpi = (v, k, go) => {
      const b = el("div", "i-kpi"); b.append(el("div", "v", v), el("div", "k", k));
      if (go) { b.classList.add("click"); b.tabIndex = 0; b.setAttribute("role", "button"); b.append(el("div", "go", "Details ›"));
        b.addEventListener("click", go); b.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } }); }
      kpis.append(b);
    };
    const toRecords = () => pane.querySelector(".it-records")?.scrollIntoView({ behavior: "smooth", block: "start" });
    kpi(fmt(st.records ?? d.total), "Records", d.total ? toRecords : null);
    if (!d.no_ip) { kpi(fmt(st.hosts ?? d.hosts), "Hosts", d.total ? toRecords : null); kpi(fmt(st.networks || 0), "Networks"); kpi(fmt(st.regions || 0), "Regions"); }
    for (const f of (st.fields || []).filter((x) => x.values)) kpi(fmt(f.values), `${f.label}${f.values === 1 ? "" : "s"}`.replace(/ss$/, "s"));
    pane.append(kpis);
    if (d.total) pane.append(el("div", "i-kpi-hint", "Click a value below to narrow the records to it; click Records or Hosts for the list."));
    // key findings, in words, from the breakdowns
    if (d.total) {
      const f = el("section", "m-sec"); f.append(el("h3", null, "Key findings"));
      const ul = el("ul", "i-findings");
      ul.append(el("li", null, `${pl(d.total, "record")}${d.no_ip ? "" : ` from ${pl(st.hosts ?? d.hosts, "host")} in ${pl(st.networks || 0, "network")}`} on ${dayLabel(d.day)}.`));
      for (const fc of d.facets.slice(0, 4)) {
        const top = fc.values[0]; if (!top) continue;
        ul.append(el("li", null, `Most common ${fc.label.toLowerCase()}: ${top.label || top.value} (${pl(top.rows, "record")}, ${Math.round((top.rows / d.total) * 100)}%).`));
      }
      f.append(ul); pane.append(f);
    }
    // the breakdowns: each field's values with their share; a click narrows to that value
    if (d.facets.length) {
      const breaks = el("div", "i-breaks");
      for (const fc of d.facets) {
        const sec = el("section", "m-sec"); sec.append(el("h3", null, fc.label));
        const list = el("ul", "brk");
        for (const v of fc.values) {
          const li = el("li"); const bl = el("span", "bl"); const lab = el("span", ["url", "request", "email", "username", "beacon_host"].includes(fc.key) ? "mono" : null, v.label || v.value);
          lab.title = `${v.label || v.value}: ${pl(v.rows, "record")}`; bl.append(lab);
          const share = d.total ? v.rows / d.total : 0;
          const bs = el("span", "bs"); const bi = el("i"); bi.style.width = `${Math.max(2, share * 100)}%`; bs.append(bi);
          li.append(bl, bs, el("span", "bv", `${Math.round(share * 100)}%`));
          const on = (view.filters[fc.key] || []).includes(v.value);
          if (!on) {
            li.classList.add("click"); li.tabIndex = 0; li.setAttribute("role", "button");
            const add = () => { view.filters[fc.key] = [...(view.filters[fc.key] || []), v.value]; fetchView(false); };
            li.addEventListener("click", add); li.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
          } else li.classList.add("on");
          list.append(li);
        }
        sec.append(list);
        if (fc.more) sec.append(el("p", "drill-more", `and ${pl(fc.more, "other value")}: use the search`));
        breaks.append(sec);
      }
      pane.append(breaks);
    }
    // the records: the platforms' host table, with its downloads
    const rec = el("section", "m-sec wide it-records");
    const rh = el("div", "drill-head"); rh.append(el("h3", null, `Records${d.total > d.shown ? ` · the first ${fmt(d.shown)} of ${fmt(d.total)} (the CSV carries all)` : ""}`));
    const acts = el("div", "drill-actions");
    if (d.can_reveal) {
      const rv = el("button", "pill-btn", view.reveal ? "Mask the accounts again" : "Show the accounts"); rv.type = "button";
      rv.title = view.reveal ? "" : "Leaked accounts are masked. Showing them is written to the audit log.";
      rv.addEventListener("click", () => { view.reveal = !view.reveal; fetchView(false); }); acts.append(rv);
    }
    if (d.total) { const ex = el("a", "pill-btn", "Download CSV"); ex.href = `/api/intelligence/export.csv?${qs()}`; ex.title = "Every record of this view, as a spreadsheet file. The download is written to the audit log."; acts.append(ex); }
    rh.append(acts); rec.append(rh);
    if (d.masked) rec.append(el("p", "drill-intro", "Accounts are masked (first letter and domain). “Show the accounts” shows them in full; that is written to the audit log."));
    if (!d.rows.length) rec.append(el("p", "drill-empty", "No record on this day with this selection."));
    else rec.append(table(d));
    pane.append(rec);
    // an analyst code and finding from this view
    if (d.code) pane.append(codeBox(d));
    else if (!d.no_ip && d.total) pane.append(el("p", "it-note", "An analyst code is made from the services platform's records: this report is not among them."));
  }

  function table(d) {
    const wrap = el("div", "drill-wrap it-tablewrap");
    const tb = el("table", "hosts drill-table it-table");
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
          const b = el("button", "it-ip mono", v); b.type = "button"; b.title = "What else this host carries";
          b.addEventListener("click", () => hostView(v, b)); td.append(b);
        } else td.textContent = v;
        row.append(td);
      }
      let extraRow = null;
      if (d.extra.length) {
        // the record's other fields open in a full-width row under it (in the narrow column they wrapped letter by letter)
        const td = el("td", "c-more");
        const more = d.extra.filter((k) => r[k]);
        if (more.length) {
          const b = el("button", "it-more-btn", `▸ ${pl(more.length, "field")}`); b.type = "button"; b.setAttribute("aria-expanded", "false");
          extraRow = el("tr", "it-extra"); extraRow.hidden = true;
          const cell = el("td"); cell.colSpan = cols.length + 1;
          const dl = el("dl", "it-extra-dl");
          for (const k of more) { const item = el("div"); item.append(el("dt", null, k.replace(/_/g, " ")), el("dd", null, r[k])); dl.append(item); }
          cell.append(dl); extraRow.append(cell);
          b.addEventListener("click", () => {
            const open = extraRow.hidden; extraRow.hidden = !open;
            b.setAttribute("aria-expanded", String(open)); b.textContent = `${open ? "▾" : "▸"} ${pl(more.length, "field")}`;
          });
          td.append(b);
        }
        row.append(td);
      }
      body.append(row);
      if (extraRow) body.append(extraRow);
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
