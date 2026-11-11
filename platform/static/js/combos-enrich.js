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
  function draw(out, e, tick) {
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
      // the figure management weighs: how many hosts share exactly this infrastructure
      const fig = el("span", "ce-n", `${pl(x.hosts, "host")} share this exact pattern`);
      if (tick) {
        const lab = el("label", "ce-tick"), cb = el("input"); cb.type = "checkbox"; cb.value = x.code; cb.checked = ticked.has(x.code);
        cb.addEventListener("change", () => { cb.checked ? ticked.add(x.code) : ticked.delete(x.code); r.classList.toggle("on", cb.checked); });
        lab.append(cb, el("span", null, "Send this one")); foot.append(lab, fig, a);
      } else foot.append(el("span"), fig, a);
      r.append(foot);
      svc.append(r);
    });
    if (xs.length > 6) {
      const more = el("button", "lg-btn sm ce-more", `Show all ${xs.length} patterns`); more.type = "button";
      more.addEventListener("click", () => { svc.querySelectorAll(".ce-svc[hidden]").forEach((x) => { x.hidden = false; }); more.remove(); });
      svc.append(more);
    }
    out.append(el("p", "cb-hint", `In the days in memory (${(e.days || []).join(", ")}).` + (tick === undefined ? " Added to this search's report: summary points in the PDF and …_other_categories.csv in the ZIP." : "")));
  }

  // ---------------- across-report data: tick the patterns, send them to a manager, the report follows the decision
  const ticked = new Set();
  // the analyst's view: where these devices were seen (report names), and each exact pattern across reports with its
  // devices' IP addresses and networks (the researcher's infections and CVE views are not part of it)
  const IPS_SHOWN = 12;
  function analystDraw(out, e, tick) {
    out.replaceChildren();
    if ((e.sources || []).length) {
      const w = el("article", "ce-src"); w.append(el("b", null, "Where these devices were seen"));
      for (const s of e.sources) {
        const r = el("div", "ce-row"); r.append(el("span", "ce-srck", `${s.reports.length} ${s.kind.replace(/ reports$/, "").toLowerCase()} report${s.reports.length === 1 ? "" : "s"}:`));
        r.append(el("span", "ce-sub2", s.reports.map((y) => `${y.title} (${fmt(y.hosts)})`).join(" · "))); w.append(r);
      }
      out.append(w);
    }
    const xs = e.cross || [];
    const sec = el("article", "ce-sec svc ce-x");
    const h = el("header"); h.append(el("i"), el("b", null, "Across reports, by IP address"), el("span", null, `${fmt(e.multi_hosts || 0)} IP address${(e.multi_hosts || 0) === 1 ? "" : "es"} in 2+ reports`));
    sec.append(h); out.append(sec);
    // by IP address: the patterns over the same reports are one row (the reports, then the addresses found in all of
    // them); the pattern values are the researcher's view and stay out of it
    const groups = new Map();
    for (const x of xs) {
      const key = x.parts.map((p) => p.title).join(" → ");
      const g = groups.get(key) || { titles: x.parts.map((p) => p.title), codes: [], devices: [], hosts: 0 };
      g.codes.push(x.code); g.devices.push(...(x.devices || [])); g.hosts += x.hosts; groups.set(key, g);
    }
    [...groups.values()].sort((a, b) => b.hosts - a.hosts).forEach((x, idx) => {
      const r = el("div", "ce-svc ce-xrow"); if (idx >= 6) r.hidden = true;
      const rep = el("div", "ce-xreps"); rep.append(el("span", "ce-n", `In ${x.titles.length} reports:`));
      x.titles.forEach((t, i) => { if (i) rep.append(el("span", "ce-arrow", "+")); rep.append(el("b", null, t)); });
      r.append(rep);
      // the devices: IP address and network, the first few, the rest on request, all copyable
      const devs = x.devices;
      const dv = el("div", "ce-ips");
      const list = el("div", "ce-iplist");
      const draw = (all) => {
        list.replaceChildren();
        for (const d of all ? devs : devs.slice(0, IPS_SHOWN)) { const s = el("span", "ce-ip"); s.append(el("code", null, d.ip)); if (d.network) s.append(el("small", null, d.network)); s.title = d.asn ? `AS${d.asn}` : ""; list.append(s); }
      };
      draw(false);
      const tools = el("div", "ce-iptools");
      if (devs.length > IPS_SHOWN) { const m = el("button", "lg-btn sm ghost", `All ${fmt(devs.length)} addresses`); m.type = "button"; m.addEventListener("click", () => { draw(true); m.remove(); }); tools.append(m); }
      const cp = el("button", "lg-btn sm ghost", "Copy the addresses"); cp.type = "button";
      cp.addEventListener("click", async () => { try { await navigator.clipboard.writeText(devs.map((d) => d.ip).join("\n")); cp.textContent = "Copied"; } catch { cp.textContent = "Copy failed"; } setTimeout(() => { cp.textContent = "Copy the addresses"; }, 1400); });
      tools.append(cp);
      dv.append(list, tools); r.append(dv);
      const foot = el("div", "ce-combo");
      const codes = el("span", "ce-codes");
      for (const cd of x.codes) { const a = el("a", "cb-x-code", cd); a.href = `/combinations?code=${cd}`; a.title = "Search exactly this cross-report pattern"; codes.append(a); }
      const fig = el("span", "ce-n", `${fmt(x.hosts)} IP address${x.hosts === 1 ? "" : "es"} in all ${x.titles.length} reports`);
      if (tick) {
        const lab = el("label", "ce-tick"), cb = el("input"); cb.type = "checkbox"; cb.checked = x.codes.every((cd) => ticked.has(cd));
        cb.addEventListener("change", () => { for (const cd of x.codes) cb.checked ? ticked.add(cd) : ticked.delete(cd); r.classList.toggle("on", cb.checked); });
        lab.append(cb, el("span", null, "Send these")); foot.append(lab, fig, codes);
      } else foot.append(el("span"), fig, codes);
      r.append(foot); sec.append(r);
    });
    if (groups.size > 6) {
      const more = el("button", "lg-btn sm ce-more", `Show all ${groups.size} report sets`); more.type = "button";
      more.addEventListener("click", () => { sec.querySelectorAll(".ce-xrow[hidden]").forEach((y) => { y.hidden = false; }); more.remove(); });
      sec.append(more);
    }
    out.append(el("p", "cb-hint", `In the days in memory (${(e.days || []).join(", ")}).`));
  }
  function reviewBox(job, st, entry, c) {
    const pv = st.preview || {}, rv = st.review;
    c.classList.add("ce-review");
    // no download here: before the decision it is locked, after it the advisor management chose generates the report
    const dl = document.querySelector(".cb-dl");
    if (dl) dl.hidden = true;
    c.append(el("h3", null, "Across reports: management decides what the report carries"),
      el("p", rv && rv.decision ? "cb-hint ce-intro hide" : "cb-hint", `These devices also turn up in other reports (${pl(pv.multi_hosts || 0, "device")} in 2+ reports, ${pl(pv.cross_total || 0, "exact pattern")}). ` +
        "The researcher's view is the combination above; the analyst's view is the patterns you tick below. Send them to a manager: they decide whether the report adds your views or uses the researcher's only, and send it to an advisor, who writes the advisory and generates the report."));
    const state = el("div", `ce-state ${rv ? (rv.decision ? "ok" : "wait") : "todo"}`);
    if (!rv) state.append(el("b", null, "Download locked"), document.createTextNode(" until management decides: tick the patterns that matter and send them."));
    else if (!rv.decision) { state.append(el("b", null, `Waiting for management's decision on finding ${rv.finding}`), document.createTextNode(" · the report follows it. ")); const a = el("a", null, "Open it"); a.href = `/findings#f${rv.finding.slice(1)}`; state.append(a); }
    else state.append(el("b", null, rv.decision === "both" ? "Management added your views" : "Management chose the researcher's view only"),
      document.createTextNode(` (finding ${rv.finding}): ${rv.advisor || "the advisor management chose"} writes the advisory and generates the report from exactly what you sent, below.`));
    c.append(state);
    // decided: exactly what was sent to management, nothing looked up again; the report carries this
    if (rv && rv.decision) {
      const out = el("div", "ce-out"); c.append(out);
      if (rv.decision === "both" && (rv.sent || []).length) {
        c.querySelector("h3").textContent = "Across reports: what management added to the report";
        analystDraw(out, { cross: rv.sent, sources: [], days: rv.days || [], multi_hosts: rv.sent.reduce((s, x) => s + x.hosts, 0) }, false);
        out.append(el("p", "cb-hint", `Exactly what was sent to management on finding ${rv.finding}: these patterns and their devices are in the report (summary points in the PDF, and …_other_categories.csv with every device).`));
      } else {
        c.querySelector("h3").textContent = "Across reports: not in this report";
        out.append(el("p", "cb-hint", `Management chose the researcher's view only (finding ${rv.finding}): the report is the combination above, without the across-report patterns.`));
      }
      return;
    }
    const out = el("div", "ce-out"); c.append(out);
    // where they were seen, the infections and the CVEs (as before), then Across reports with each pattern's addresses
    draw(out, pv);
    out.querySelector(".ce-sec.svc")?.remove();
    if (out.lastElementChild?.matches("p.cb-hint")) out.lastElementChild.remove();
    const tmp = el("div"); analystDraw(tmp, pv, !rv);
    for (const n of [...tmp.children]) if (!n.classList.contains("ce-src")) out.append(n);
    if (rv) return;
    // the request: tick, whom, why
    const req = el("div", "ce-req ce-req-open");
    const toM = window.LGPeople ? window.LGPeople.picker("management") : null;
    const t = el("input", "ac-in"); t.maxLength = 140; t.placeholder = `Title, e.g. ${entry?.code || "this code"}: the same devices across reports`;
    const n = el("textarea", "ac-in"); n.rows = 3; n.maxLength = 2000; n.placeholder = "Why these patterns matter for the report (e.g. the same hosts expose CWMP and call the same sinkhole)";
    const cnt = el("span", "cb-hint", "No pattern ticked yet.");
    const send = el("button", "lg-btn primary", "Send the ticked patterns to management"); send.type = "button";
    const rmsg = el("div", "cb-hint");
    req.append(el("b", null, "Send to management"), cnt, ...(toM ? [toM.el] : []), t, n, send, rmsg);
    c.append(req);
    out.addEventListener("change", () => { cnt.textContent = ticked.size ? `${pl(ticked.size, "pattern")} ticked.` : "Nothing ticked yet."; });
    send.addEventListener("click", async () => {
      if (!ticked.size) { rmsg.textContent = "Tick at least one pattern."; return; }
      if (toM && !toM.check()) { rmsg.textContent = "Choose the manager it goes to."; return; }
      if (!t.value.trim()) { rmsg.textContent = "Give the finding a short title."; return; }
      send.disabled = true; rmsg.textContent = "Sending…";
      try {
        const r = await post(`/api/combos/search/${job}/review`, { codes: [...ticked], title: t.value.trim(), text: n.value.trim(), to: toM ? toM.value() : "" });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { rmsg.textContent = d.error || `Refused (HTTP ${r.status})`; send.disabled = false; return; }
        rmsg.replaceChildren(document.createTextNode(`Finding ${d.finding} sent to ${d.to} with ${pl(d.codes.length, "pattern")}. The report unlocks once they decide. `));
        const a = el("a", null, "Open it on the Findings page"); a.href = `/findings#f${d.finding.slice(1)}`; rmsg.append(a);
        send.hidden = true; state.className = "ce-state wait"; state.replaceChildren(el("b", null, `Waiting for management's decision on finding ${d.finding}`));
        out.querySelectorAll("input[type=checkbox]").forEach((x) => { x.disabled = true; });
      } catch { rmsg.textContent = "The connection was interrupted. Try again."; send.disabled = false; }
    });
  }

  function box(job, s, entry) {
    const c = el("section", "ce-box");
    // the search's own state: across-report data (needs management's decision) or not
    const dl0 = document.querySelector(".cb-dl"); if (dl0) dl0.hidden = false;
    fetch(`/api/combos/search/${job}`, { cache: "no-store" }).then((r) => r.json()).then((st) => {
      if (st.needs_review) { c.replaceChildren(); reviewBox(job, st, entry, c); }
    }).catch(() => {});
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
