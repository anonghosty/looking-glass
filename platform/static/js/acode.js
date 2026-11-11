/* Looking Glass · an analyst code seen by the researchers (/intel/LG-A-…, acodes.py): the analyst's finding and note,
   the selection in words (never an address), then one section per category for exactly those hosts:
     Infections · CVEs and issues · Services (their patterns) · Across reports (every name's cross-report patterns,
     the ones that run through every report marked),
   each with its codes (LG-C, LG-X) to tick. Every chip is clickable: it highlights where that value turns up across the
   whole page and dims what does not carry it (a quick analysis). Answer the analyst with a reply on the finding, or
   "No combination of interest found", which closes the request. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? "" : "s"}`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const code = document.body.dataset.code, main = $("axMain");
  const picked = new Map();          // code -> what it is
  const ACROSS_SHOWN = 30;           // across-report patterns shown before "Show all"

  // ---------------- quick analysis: click a value, see everywhere it turns up
  let focus = null, focusBar = null;
  function chip(text, cls = "") {
    const b = el("button", `ax-chip ax-f ${cls}`.trim(), text); b.type = "button"; b.dataset.v = text;
    b.title = `${text}: click to highlight everywhere it turns up on this page`;
    return b;
  }
  function chips(items, every) {
    const s = el("div", "ax-set");
    if (!items.length) s.append(el("span", "ax-none", "the name only"));
    items.forEach((x, i) => { if (i) s.append(el("span", "ax-plus", "+")); s.append(chip(x, every?.has(x) ? "every" : "")); });
    return s;
  }
  function applyFocus() {
    for (const c of main.querySelectorAll(".ax-f")) c.classList.toggle("on", !!focus && c.dataset.v === focus);
    let hits = 0;
    // a focus opens the hidden rows, so every row with the value is in view
    if (focus) for (const li of main.querySelectorAll(".ax-list > li[hidden]")) li.hidden = false;
    if (focus) main.querySelectorAll(".ax-more").forEach((b) => b.remove());
    for (const li of main.querySelectorAll(".ax-list > li, .ax-issues > .ax-f")) {
      const has = !focus || (li.classList.contains("ax-f") ? li.dataset.v === focus : !!li.querySelector(`.ax-f[data-v="${CSS.escape(focus)}"]`));
      li.classList.toggle("ax-dim", !has);
      if (focus && has) hits++;
    }
    for (const sec of main.querySelectorAll(".ax-sec")) {
      const n = focus ? sec.querySelectorAll(".ax-list > li:not(.ax-dim), .ax-issues > .ax-f:not(.ax-dim)").length : null;
      const t = sec.querySelector(".ax-sec-hits"); if (t) t.textContent = n == null ? "" : n ? `${fmt(n)} with it` : "not here";
    }
    focusBar.hidden = !focus;
    if (focus) focusBar.querySelector("code").textContent = focus, focusBar.querySelector(".ax-fb-n").textContent = `in ${pl(hits, "row")} across the sections`;
  }
  main.addEventListener("click", (e) => {
    const c = e.target.closest(".ax-f"); if (!c || !main.contains(c)) return;
    focus = focus === c.dataset.v ? null : c.dataset.v; applyFocus();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && focus) { focus = null; applyFocus(); } });

  function pick(cb, c, text) {
    cb.addEventListener("change", () => { if (cb.checked) picked.set(c, text); else picked.delete(c); drawPicked(); });
  }
  let pickedBox, replyBtn;
  function drawPicked() {
    if (!pickedBox) return;
    pickedBox.replaceChildren();
    if (!picked.size) pickedBox.append(el("span", "ax-none", "No code ticked: tick combinations above to send them with the reply."));
    for (const [c, t] of picked) { const s = el("span", "ax-pick"); s.append(el("code", null, c), el("span", null, t)); pickedBox.append(s); }
  }
  // one row with a code to tick
  function codeRow(codeText, pickText, what, fig, cross) {
    const li = el("li"), lab = el("label", "ax-tick"), cb = el("input"); cb.type = "checkbox";
    lab.append(cb, el("code", `ax-code${cross ? " x" : ""}`, codeText)); pick(cb, codeText, pickText);
    li.append(lab, what, el("span", "ax-fig", fig)); return li;
  }
  // a section: one category, with its heading
  function section(key, title, sub, parent) {
    const s = el("section", `ax-sec ax-sec-${key}`);
    const h = el("header", "ax-sec-h"); h.append(el("i"), el("h2", null, title), el("span", "ax-sec-hits"));
    s.append(h); if (sub) s.append(el("p", "ax-hint ax-sec-sub", sub));
    (parent || main).append(s); return s;
  }
  const empty = (t) => el("p", "ax-none ax-xnone", t);

  // the names in exactly the analyst's records (infections, or CVEs and issues), with their combinations
  function nameCards(sec, d) {
    const w = d.section === "issues" ? "host" : "device";
    for (const n of d.names) {
      const c = el("article", "ax-card");
      const hd = el("header", "ax-card-h");
      const t = el("div", "ax-card-t"); t.append(chip(n.name, "ax-name"), el("span", `ax-def${n.defined ? " ok" : ""}`, n.defined ? n.defined : "No definition yet"));
      hd.append(t, el("span", "ax-fig", `${pl(n.records, "record")} · ${pl(n.devices, w)}`));
      c.append(hd, el("div", "ax-reps", n.reports.map((r) => `${r.report} (${fmt(r.records)})`).join(" · ")));
      if (n.combinations.length) {
        c.append(el("h3", null, `Combinations in these records${n.combinations_total > n.combinations.length ? ` (the ${n.combinations.length} most frequent of ${fmt(n.combinations_total)})` : ""}`));
        const ul = el("ul", "ax-list");
        for (const x of n.combinations) {
          const what = el("div", "ax-what"); what.append(el("span", "ax-rep", x.report), chips(x.items));
          ul.append(codeRow(x.code, `${n.name} in ${x.report}: ${x.items.join(" + ") || "the name only"}`, what,
            `${pl(x.records, "record")} · ${pl(x.devices, w)}${x.repeat ? ` · ${fmt(x.repeat)} repeating` : ""}`));
        }
        c.append(ul);
      }
      sec.append(c);
    }
  }
  // infections from the services side: the hosts calling botnet sinkholes, with the sinkhole code per services report
  function sinkholeRows(sec, x) {
    if (!x.infections.length) { sec.append(empty("None of these hosts is in the network communications reports of the days in memory.")); return; }
    sec.append(el("p", "ax-xsum", `${pl(x.infections_hosts, "host")} of the selection call botnet sinkholes:`));
    const ul = el("ul", "ax-list");
    for (const i of x.infections) for (const r of i.reports) {
      const what = el("div", "ax-what"); what.append(el("span", "ax-rep", r.title), chips([i.name]));
      ul.append(codeRow(r.code, `${r.title}: hosts also calling botnet sinkholes as ${i.name}`, what, `${pl(r.hosts, "host")} · ${pl(i.hosts, "host")} in all`, true));
    }
    sec.append(ul);
  }
  // CVEs and issues from the services side, on the hosts of a network communications code
  function issueChips(sec, x) {
    if (!x.issues.length) { sec.append(empty("No CVE or issue on these hosts in the services reports of the days in memory.")); return; }
    // each CVE or issue with the services reports it was found in
    const ul = el("ul", "ax-list ax-iss-list");
    for (const i of x.issues) {
      const li = el("li"), b = chip(i.name, `ax-issue${/^CVE-/i.test(i.name) ? " cve" : ""}`); b.append(el("em", null, fmt(i.hosts))); b.dataset.v = i.name;
      const w = el("div", "ax-seenin");
      for (const g of i.seen_in || []) { const r = el("div"); r.append(el("b", null, `${g.kind} ${g.reports.length}`), el("span", null, g.reports.map((y) => `${y.title} (${fmt(y.hosts)})`).join(" · "))); w.append(r); }
      if (!w.children.length) w.append(el("span", null, `in ${(i.reports || []).map((r) => `${r.title} (${fmt(r.hosts)})`).join(", ") || "the services reports"}`));
      li.append(b, w);
      ul.append(li);
    }
    sec.append(ul);
    if (x.issues_total > x.issues.length) sec.append(el("p", "ax-hint", `The ${x.issues.length} on most hosts, of ${fmt(x.issues_total)}.`));
  }
  // the services reports these hosts are in, with their pattern combinations
  function serviceRows(sec, x) {
    if (!x.services.length) { sec.append(empty("None of these hosts is in the services reports of the days in memory.")); return; }
    for (const s of x.services) {
      const c = el("article", "ax-card");
      const hd = el("header", "ax-card-h"); hd.append(el("div", "ax-card-t"), el("span", "ax-fig", pl(s.hosts, "host")));
      hd.firstChild.append(el("b", "ax-catname", s.title)); c.append(hd);
      const ul = el("ul", "ax-list");
      const bare = s.combinations.filter((k) => !k.items.length).reduce((n, k) => n + k.hosts, 0);
      for (const k of s.combinations) {
        if (!k.items.length) continue;          // no value 5+ hosts share: nothing to show or code
        const what = el("div", "ax-what"); what.append(chips(k.items));
        ul.append(codeRow(k.code, `${s.title}: ${k.items.join(" + ")}`, what, `${pl(k.records, "record")} · ${pl(k.hosts, "host")}${k.repeat ? ` · ${fmt(k.repeat)} repeating` : ""}`));
      }
      if (ul.children.length) c.append(ul);
      if (bare) c.append(empty(`${pl(bare, "host")} carry no pattern value that 5 or more hosts share here: counted, not shown.`));
      if (s.combinations_total > s.combinations.length) c.append(el("p", "ax-hint", `The ${s.combinations.length} most frequent of ${fmt(s.combinations_total)} sets.`));
      sec.append(c);
    }
    if (x.services_total > x.services.length) sec.append(el("p", "ax-hint", `The ${x.services.length} reports with most of these hosts, of ${fmt(x.services_total)}.`));
  }
  // every name's cross-report patterns in one list; those that run through every report of the name marked, and the
  // values carried in every report of a pattern outlined
  function acrossRows(sec, d) {
    const w = d.section === "issues" ? "host" : "device";
    const rows = [];
    for (const n of d.names) {
      const all = new Set([...n.reports.map((r) => r.report), ...(n.other_reports || [])]);
      for (const x of n.across) rows.push({ n, x, everyRep: all.size > 1 && x.parts.length === all.size, all: [...all] });
    }
    const multi = d.names.reduce((s, n) => s + (n.multi_devices || 0), 0);
    const spanning = rows.filter((r) => r.everyRep).length;
    if (!rows.length) {
      sec.append(empty(`None of these ${w}s was seen in another report of its name on ${d.day}: each turns up in ${[...new Set(d.names.flatMap((n) => n.reports.map((r) => r.report)))].join(", ")} only.`));
      return;
    }
    sec.append(el("p", "ax-xsum", `${pl(multi, w)} of the selection ${multi === 1 ? "is" : "are"} also in other reports of their name · ${pl(rows.length, "exact pattern")}` +
      (spanning ? `, ${spanning} of them through every report the name was seen in` : "") + ". Values outlined are carried in every report of that pattern."));
    rows.sort((a, b) => (b.everyRep - a.everyRep) || b.x.devices - a.x.devices);
    const ul = el("ul", "ax-list");
    for (const { n, x, everyRep, all } of rows) {
      const every = new Set(x.parts.length > 1 ? x.parts[0].items.filter((v) => x.parts.every((p) => p.items.includes(v))) : []);
      const what = el("div", "ax-what ax-parts");
      const tag = el("div", "ax-xname"); tag.append(chip(n.name, "ax-name sm"));
      if (everyRep) {                                    // name the reports, not only how many
        const b = el("span", "ax-every", `${all.length === 2 ? "In both reports" : `In all ${all.length} reports`}: ${x.parts.map((p) => p.report).join(" + ")}`);
        b.title = `Every report ${n.name} was seen in on this day: these devices are in all of them`;
        tag.append(b);
      }
      what.append(tag);
      for (const p of x.parts) { const b = el("div", "ax-part"); b.append(el("span", "ax-rep", p.report), chips(p.items, every)); what.append(b); }
      const li = codeRow(x.code, `${n.name} across ${x.parts.map((p) => p.report).join(" + ")}`, what, pl(x.devices, w), true);
      if (everyRep) li.classList.add("ax-span");
      if (ul.children.length >= ACROSS_SHOWN) li.hidden = true;     // the rest on request, so the page stays readable
      ul.append(li);
    }
    sec.append(ul);
    if (rows.length > ACROSS_SHOWN) {
      const more = el("button", "lg-btn sm ax-more", `Show all ${fmt(rows.length)} patterns`); more.type = "button";
      more.addEventListener("click", () => { for (const li of ul.children) li.hidden = false; more.remove(); applyFocus(); });
      sec.append(more);
    }
    const quiet = d.names.filter((n) => !n.across.length && n.devices);
    if (quiet.length) sec.append(el("p", "ax-hint", `In one report only: ${quiet.map((n) => n.name).join(", ")}.`));
  }

  async function load() {
    const r = await fetch(`/api/intel/acode/${encodeURIComponent(code)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    $("axLoading")?.remove();
    if (!r.ok) { main.append(el("p", "ax-empty", d.error || `Could not open ${code} (HTTP ${r.status})`)); return; }
    // the analyst's side
    const hero = el("section", "ax-hero");
    hero.append(el("div", "ax-eyebrow", `Analyst code · ${d.platform === "services" ? "publicly accessible services" : "network communications"} · ${d.day}`));
    const h = el("h1"); h.append(el("code", null, d.code), document.createTextNode(d.finding ? ` ${d.finding.title}` : "")); hero.append(h);
    hero.append(el("p", "ax-sel", d.label));
    if (d.finding?.text) { const q = el("blockquote", "ax-note"); q.append(el("b", null, "The analyst's note"), el("p", null, d.finding.text)); hero.append(q); }
    const k = el("div", "ax-kpis");
    for (const [v, l] of [[d.records, "records"], [d.devices, d.section === "issues" ? "hosts" : "devices"], [d.reports, "reports"], [d.names.length, d.section === "issues" ? "issues" : "infections / categories"]]) {
      const t = el("div", "ax-kpi"); t.append(el("b", null, fmt(v)), el("span", null, l)); k.append(t);
    }
    hero.append(k, el("p", "ax-hint", "Indicators only: the addresses of the hosts are never shown here. Click any value to see where else it turns up; tick the combinations that answer the analyst and send them with your reply."));
    if (d.finding) { const a = el("a", "lg-btn sm", `Finding ${d.finding.number} on the Findings page`); a.href = `/findings#f${d.finding.id}`; hero.append(a); }
    main.append(hero);
    focusBar = el("div", "ax-focusbar"); focusBar.hidden = true;
    const clr = el("button", "lg-btn sm", "Clear"); clr.type = "button"; clr.addEventListener("click", () => { focus = null; applyFocus(); });
    focusBar.append(el("span", null, "Highlighting"), el("code"), el("span", "ax-fb-n"), clr);
    main.append(focusBar);
    if (!d.records) { main.append(el("p", "ax-empty", `The selection has no records on ${d.day} any more (the day may no longer be in the database).`)); return; }
    const x = d.cross || { infections: [], issues: [], services: [], days: [] };
    const mem = (x.days || []).length ? ` (the days in memory: ${x.days.join(", ")})` : "";
    // where these hosts were seen: every report, grouped by kind
    if ((x.sources || []).length) {
      const w = el("section", "ax-src");
      w.append(el("h2", null, "Where these hosts were seen"));
      for (const s of x.sources) {
        const r = el("div", "ax-src-r");
        r.append(el("b", null, `${s.reports.length} ${s.kind.replace(/ reports$/, "").toLowerCase()} report${s.reports.length === 1 ? "" : "s"}`));
        const l = el("div", "ax-set"); for (const y of s.reports) { const c2 = el("span", "ax-issue"); c2.append(document.createTextNode(y.title), el("em", null, fmt(y.hosts))); l.append(c2); }
        r.append(l); w.append(r);
      }
      main.append(w);
    }
    // the analyst asked about the combinations across reports only: those first, the other categories folded below
    const acrossOnly = d.focus === "across";
    if (acrossOnly) {
      const ab = el("div", "ax-askfocus"); ab.append(el("b", null, "The analyst asks about the combinations across reports"),
        el("span", null, "what these hosts carry in each report they turn up in. The other categories are folded below, for context."));
      hero.append(ab);
      acrossRows(section("x", "Across reports", "Every name's hosts followed into its other reports that day: what each carried in each report. Patterns that run through every report come first."), d);
    }
    const rest = acrossOnly ? el("details", "ax-rest") : null;
    if (rest) { rest.append(el("summary", null, "Other categories: infections, CVEs and issues, services")); main.append(rest); }
    // 1. infections
    const inf = section("inf", "Infections", d.section === "issues" ? `These hosts in the network communications reports${mem}: the infections they call botnet sinkholes as.` : "The infections and categories in exactly the analyst's records, with their combinations.", rest);
    if (d.section === "issues") sinkholeRows(inf, x); else nameCards(inf, d);
    // 2. CVEs and issues
    const cve = section("cve", "CVEs and issues", d.section === "issues" ? "The CVEs and issues in exactly the analyst's records, with their combinations." : `What the services scans found on these hosts${mem}.`, rest);
    if (d.section === "issues") nameCards(cve, d); else issueChips(cve, x);
    // 3. services
    serviceRows(section("svc", "Services", `The services reports these hosts are in${mem}, with their pattern combinations. A value is shown only when 5 or more hosts share it.`, rest), x);
    // 4. across reports
    if (!acrossOnly) acrossRows(section("x", "Across reports", "Every name's hosts followed into its other reports that day: what each carried in each report. Patterns that run through every report come first."), d);
    // the reply to the analyst, on the finding
    if (d.finding) {
      const rp = el("section", "ax-reply");
      rp.append(el("h2", null, `Reply on finding ${d.finding.number}`),
        el("p", "ax-hint", "Your answer goes into the finding's history, with the ticked codes, and the finding goes back to the analyst who asked: they pull exactly those devices on the Combinations page."));
      pickedBox = el("div", "ax-picked"); rp.append(pickedBox); drawPicked();
      const ta = el("textarea", "ax-in"); ta.rows = 4; ta.maxLength = 1000; ta.placeholder = "What did you find? e.g. both infections share one C2 domain; the user agent is new; definition added";
      // "nothing of interest": answers the request and closes it, so open requests do not pile up
      const nf = el("label", "ax-nonefound"), nfc = el("input"); nfc.type = "checkbox";
      nf.append(nfc, el("b", null, "No combination of interest found"),
        el("small", null, "I looked into these records and nothing here needs following up: send this answer and close the request"));
      const row = el("div", "ax-row"), msg = el("span", "ax-msg"); replyBtn = el("button", "lg-btn primary", "Send the reply"); replyBtn.type = "button";
      const closed = d.finding.status === "closed";
      nfc.disabled = closed; if (closed) nf.title = "This request is already closed.";
      nfc.addEventListener("change", () => {
        if (nfc.checked && picked.size) { picked.clear(); for (const cb of main.querySelectorAll(".ax-tick input")) cb.checked = false; drawPicked(); }
        for (const cb of main.querySelectorAll(".ax-tick input")) cb.disabled = nfc.checked;
        replyBtn.textContent = nfc.checked ? "Send and close the request" : "Send the reply";
        ta.placeholder = nfc.checked ? "Optional: what you checked, e.g. only the name in every record; nothing shared with other reports"
          : "What did you find? e.g. both infections share one C2 domain; the user agent is new; definition added";
      });
      row.append(msg, replyBtn); rp.append(ta, nf, row);
      replyBtn.addEventListener("click", async () => {
        if (!nfc.checked && !ta.value.trim() && !picked.size) { msg.textContent = "Write a reply, tick a code, or tick “No combination of interest found”."; msg.className = "ax-msg bad"; return; }
        replyBtn.disabled = true;
        try {
          const r2 = await fetch(`/api/findings/${d.finding.id}/reply`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ text: ta.value.trim(), codes: nfc.checked ? [] : [...picked.keys()], none_found: nfc.checked }) });
          const x2 = await r2.json().catch(() => ({}));
          if (!r2.ok) { msg.textContent = x2.error || `Not sent (HTTP ${r2.status})`; msg.className = "ax-msg bad"; return; }
          msg.textContent = nfc.checked ? `Answered and closed: finding ${d.finding.number} says no combination of interest was found.`
            : `Reply sent on finding ${d.finding.number}${picked.size ? ` with ${pl(picked.size, "code")}` : ""}.`;
          msg.className = "ax-msg ok";
          if (nfc.checked) { nfc.checked = false; nfc.disabled = true; nfc.dispatchEvent(new Event("change")); }
          ta.value = ""; picked.clear(); for (const cb of main.querySelectorAll(".ax-tick input")) cb.checked = false; drawPicked();
        } finally { replyBtn.disabled = false; }
      });
      main.append(rp);
    }
  }
  load();
})();
