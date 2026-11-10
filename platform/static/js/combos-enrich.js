/* Looking Glass · the Combinations page (analysts): after a search, "Add the analysis across every category" puts what
   the devices show in the other categories into this search's report (services reports with their pattern codes, the
   CVEs and issues on them, the infections they call sinkholes as: combos.py /enrich), and "Send to management as a
   finding" makes an analyst code of exactly these devices with the request (everything, or across reports only) for
   the researchers; management accepts it with a directive for the report, or rejects it (findings.py).
   combos.js calls window.LGEnrich.box(job, summary, entry). */
(() => {
  "use strict";
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? "" : "s"}`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const post = (u, b) => fetch(u, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(b || {}) });

  function chips(items, cls) {
    const s = el("div", "ce-set");
    for (const x of items) s.append(el("span", `ce-chip ${cls || ""}`, x));
    return s;
  }
  function draw(out, e) {
    out.replaceChildren();
    if ((e.sources || []).length) {                    // where these devices were seen, every report by kind
      const w = el("article", "ce-src"); w.append(el("b", null, "Where these devices were seen"));
      for (const s of e.sources) {
        const r = el("div", "ce-row"); r.append(el("span", "ce-srck", `${s.reports.length} ${s.kind.replace(/ reports$/, "").toLowerCase()} report${s.reports.length === 1 ? "" : "s"}:`));
        r.append(el("span", "ce-sub2", s.reports.map((y) => `${y.title} (${fmt(y.hosts)})`).join(" · "))); w.append(r);
      }
      out.append(w);
    }
    const sec =(title, n, cls) => { const c = el("article", `ce-sec ${cls}`); const h = el("header"); h.append(el("i"), el("b", null, title), el("span", null, n)); c.append(h); out.append(c); return c; };
    // infections
    const inf = sec("Infections", e.infections.length ? `${pl(e.infections_hosts, "device")} calling botnet sinkholes` : "none", "inf");
    if (!e.infections.length) inf.append(el("p", "cb-hint", "None of these devices calls a botnet sinkhole in the days in memory."));
    for (const i of e.infections) {
      const r = el("div", "ce-row"); r.append(el("code", "ce-name", i.name), el("span", "ce-n", pl(i.hosts, "device")));
      if (i.reports.length) r.append(el("span", "ce-sub", `in ${i.reports.map((x) => `${x.title} (${fmt(x.hosts)})`).join(", ")}`));
      inf.append(r);
    }
    // CVEs and issues
    const cve = sec("CVEs and issues", e.issues_total ? `${fmt(e.issues_total)} on these devices` : "none", "cve");
    if (!e.issues.length) cve.append(el("p", "cb-hint", "No CVE or issue on these devices in the services reports of the days in memory."));
    else for (const i of e.issues) {                  // each with the services reports it was found in
      const r = el("div", "ce-row"), c = el("span", `ce-chip${/^CVE-/i.test(i.name) ? " cve" : ""}`, i.name); c.append(el("em", null, fmt(i.hosts)));
      r.append(c);
      if ((i.seen_in || []).length) for (const g of i.seen_in) r.append(el("span", "ce-sub", `${g.kind} ${g.reports.length}: ${g.reports.map((x) => `${x.title} (${fmt(x.hosts)})`).join(" · ")}`));
      else r.append(el("span", "ce-sub", `in ${(i.reports || []).map((x) => `${x.title} (${fmt(x.hosts)})`).join(", ") || "the services reports"}`));
      cve.append(r);
    }
    // across reports: each exact pattern of these devices over every report they are in (LG-X)
    const xs = e.cross || [];
    const svc = sec("Across reports", xs.length ? `${pl(e.multi_hosts || 0, "device")} in 2+ reports · ${pl(e.cross_total || xs.length, "exact pattern")}` : "none", "svc");
    if (!xs.length) svc.append(el("p", "cb-hint", "None of these devices is in more than one report in the days in memory."));
    xs.forEach((x, idx) => {
      const r = el("div", "ce-svc"); if (idx >= 6) r.hidden = true;     // the six patterns with most devices; the rest on request
      for (const p of x.parts) {
        const row = el("div", "ce-xpart"); row.append(el("b", null, p.title));
        row.append(p.items.length ? chips(p.items) : el("span", "ce-n", "the report only")); r.append(row);
      }
      const foot = el("div", "ce-combo"); const a = el("a", "cb-x-code", x.code); a.href = `/combinations?code=${x.code}`; a.title = "Search exactly this cross-report pattern";
      foot.append(el("span"), el("span", "ce-n", pl(x.hosts, "device")), a); r.append(foot);
      svc.append(r);
    });
    if (xs.length > 6) {
      const more = el("button", "lg-btn sm ce-more", `Show all ${xs.length} patterns`); more.type = "button";
      more.addEventListener("click", () => { svc.querySelectorAll(".ce-svc[hidden]").forEach((x) => { x.hidden = false; }); more.remove(); });
      svc.append(more);
    }
    out.append(el("p", "cb-hint", `In the days in memory (${(e.days || []).join(", ")}). Added to this search's report: summary points in the PDF and ${"…_other_categories.csv"} in the ZIP.`));
  }

  function box(job, s, entry) {
    const c = el("section", "ce-box");
    c.append(el("h3", null, "Across every category"),
      el("p", "cb-hint", `What these ${pl(s.devices, "device")} show in the other categories: the services reports they are in (with their pattern codes), the CVEs and issues on them, the infections they call sinkholes as. Added to this report for its generation.`));
    const out = el("div", "ce-out");
    const go = el("button", "lg-btn primary", "Add the analysis across every category to this report"); go.type = "button";
    const msg = el("span", "cb-hint");
    const row = el("div", "ce-actions"); row.append(go, msg);
    c.append(row, out);
    if (s.enrich) { draw(out, s.enrich); go.textContent = "Analysis added: refresh it"; }
    go.addEventListener("click", async () => {
      go.disabled = true; msg.textContent = "Looking at every category for these devices…";
      try {
        const r = await post(`/api/combos/search/${job}/enrich`);
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { msg.textContent = d.error || `Failed (HTTP ${r.status})`; return; }
        draw(out, d.enrich); s.enrich = d.enrich; go.textContent = "Analysis added: refresh it";
        msg.textContent = "Added to the report: download it below.";
      } finally { go.disabled = false; }
    });
    // the request to management: an analyst code of exactly these devices, as a finding
    const req = el("details", "ce-req");
    req.append(el("summary", null, "Send to management as a finding, for the researchers' analysis"));
    const ask = el("div", "ac-ask"); let focus = "";
    for (const [k, l, t] of [["", "Everything", "every category: infections, CVEs and issues, services, across reports"],
                             ["across", "Just across-report combinations", "what these devices carry in each report they turn up in"]]) {
      const b = el("button", "ac-opt"); b.type = "button"; b.dataset.k = k; b.setAttribute("role", "radio"); b.setAttribute("aria-checked", String(k === ""));
      b.append(el("b", null, l), el("small", null, t));
      b.addEventListener("click", () => { focus = k; for (const o of ask.children) o.setAttribute("aria-checked", String(o.dataset.k === focus)); });
      ask.append(b);
    }
    const t = el("input", "ac-in"); t.maxLength = 140; t.placeholder = `Title, e.g. ${entry?.code || "this code"}'s devices: what else are they?`;
    const n = el("textarea", "ac-in"); n.rows = 3; n.maxLength = 2000; n.placeholder = "What should the researchers look at, and what report do you need?";
    const send = el("button", "lg-btn primary", "Send to management"); send.type = "button";
    const rmsg = el("div", "cb-hint");
    const toM = window.LGPeople ? window.LGPeople.picker("management") : null;     // the manager it goes to
    req.append(ask, ...(toM ? [toM.el] : []), t, n, send, rmsg);
    send.addEventListener("click", async () => {
      if (toM && !toM.check()) { rmsg.textContent = "Choose the manager it goes to."; return; }
      if (!t.value.trim()) { rmsg.textContent = "Give the finding a short title."; return; }
      send.disabled = true; rmsg.textContent = "Making the analyst code and the finding…";
      try {
        const r = await post(`/api/combos/search/${job}/acode`, { title: t.value.trim(), text: n.value.trim(), focus, to: toM ? toM.value() : "" });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { rmsg.textContent = d.error || `Refused (HTTP ${r.status})`; send.disabled = false; return; }
        rmsg.replaceChildren(document.createTextNode(`Finding ${d.finding} sent to ${d.to || "management"} with ${d.code} (${pl(d.hosts, "device")}, ${d.days.join(", ")}). `));
        const a = el("a", null, "Open it on the Findings page"); a.href = `/findings#f${d.finding.slice(1)}`; rmsg.append(a);
        send.hidden = true;
      } catch { rmsg.textContent = "The connection was interrupted. Try again."; send.disabled = false; }
    });
    c.append(req);
    return c;
  }
  window.LGEnrich = { box };
})();
