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
  // a tick box for an infection or a CVE/issue, sent to management with the patterns (2026-11-14: they could be seen but
  // not put in the report); only on the analyst's own search before it is sent
  function nameTick(set, name, row) {
    const lab = el("label", "ce-tick ce-ntick"), cb = el("input"); cb.type = "checkbox"; cb.value = name; cb.checked = set.has(name);
    cb.addEventListener("change", () => { cb.checked ? set.add(name) : set.delete(name); row.classList.toggle("on", cb.checked); });
    lab.append(cb, el("span", null, "Send this one")); return lab;
  }
  function draw(out, e, tick, names) {
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
      if (names) r.append(nameTick(tickedInf, i.name, r));
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
      if (names) r.append(nameTick(tickedIss, i.name, r));
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
  const ticked = new Set(), tickedInf = new Set(), tickedIss = new Set();
  const tickCount = () => {
    const parts = [ticked.size && pl(ticked.size, "pattern"), tickedInf.size && pl(tickedInf.size, "infection"), tickedIss.size && `${fmt(tickedIss.size)} CVE${tickedIss.size === 1 ? "" : "s"}/issue${tickedIss.size === 1 ? "" : "s"}`].filter(Boolean);
    return parts.length ? `${parts.join(", ")} ticked.` : "Nothing ticked yet.";
  };
  const anyTicked = () => ticked.size + tickedInf.size + tickedIss.size > 0;
  // after management's decision: the infections and CVEs/issues it added to the report, as they were sent
  function addedNames(out, rv) {
    const inf = rv.sent_infections || [], iss = rv.sent_issues || [];
    if (!inf.length && !iss.length) return;
    const w = el("article", "ce-sec cve"); const h = el("header"); h.append(el("i"), el("b", null, "Infections and CVEs/issues added"), el("span", null, `${inf.length + iss.length} ticked`)); w.append(h);
    for (const x of inf) { const r = el("div", "ce-row"); r.append(el("code", "ce-name", x.name), el("span", "ce-n", pl(x.hosts, "device")), el("span", "ce-sub", "infection (calling botnet sinkholes)")); w.append(r); }
    for (const x of iss) { const r = el("div", "ce-row"); const c = el("span", `ce-chip${/^CVE-/i.test(x.name) ? " cve" : ""}`, x.name); r.append(c, el("span", "ce-n", pl(x.hosts, "device"))); w.append(r); }
    out.append(w);
  }
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
    if (dl) dl.hidden = !(rv && rv.decision === "rejected");      // rejected: no advisory, the download is the analyst's again
    if (rv && rv.decision === "rejected") {
      c.append(el("h3", null, "Across reports"), el("div", "ce-state todo", `Management rejected finding ${rv.finding}: no advisory. The download is yours again.`));
      return;
    }
    c.append(el("h3", null, "Across reports: management decides what the report carries"),
      el("p", rv && rv.decision ? "cb-hint ce-intro hide" : "cb-hint", `These devices also turn up in other reports (${pl(pv.multi_hosts || 0, "device")} in 2+ reports, ${pl(pv.cross_total || 0, "exact pattern")}). ` +
        "The researcher's view is the whole combination above; your view is exactly what you tick below (the devices behind the ticked patterns, infections and CVEs/issues). Send it to a manager: whichever view they choose, the report covers exactly the devices you drilled down to; an advisor writes the advisory and generates it."));
    const state = el("div", `ce-state ${rv ? (rv.decision ? "ok" : "wait") : "todo"}`);
    if (!rv) state.append(el("b", null, "Download locked"), document.createTextNode(" until management decides: tick the patterns that matter and send them."));
    else if (!rv.decision) { state.append(el("b", null, `Waiting for management's decision on finding ${rv.finding}`), document.createTextNode(" · the report follows it. ")); const a = el("a", null, "Open it"); a.href = `/findings#f${rv.finding.slice(1)}`; state.append(a); }
    else state.append(el("b", null, rv.decision === "both" ? "Management added your views" : rv.decision === "analyst" ? "Management chose your view, of exactly the devices you drilled down to" : rv.drilled ? "Management chose the researcher's view, of exactly the devices you drilled down to" : "Management chose the researcher's view"),
      document.createTextNode(` (finding ${rv.finding}): ${rv.advisor || "the advisor management chose"} writes the advisory and generates the report from exactly what you sent, below.`));
    c.append(state);
    // decided: exactly what was sent to management, nothing looked up again; the report carries this
    if (rv && rv.decision) {
      const out = el("div", "ce-out"); c.append(out);
      if ((rv.decision === "both" || rv.decision === "analyst") && ((rv.sent || []).length || (rv.sent_infections || []).length || (rv.sent_issues || []).length)) {
        c.querySelector("h3").textContent = rv.decision === "analyst" ? "What the report carries: the devices you drilled down to" : "Across every category: what management added to the report";
        if ((rv.sent || []).length) analystDraw(out, { cross: rv.sent, sources: [], days: rv.days || [], multi_hosts: rv.sent.reduce((s, x) => s + x.hosts, 0) }, false);
        addedNames(out, rv);
        out.append(el("p", "cb-hint", `Exactly what was sent to management on finding ${rv.finding}: these and their devices are in the report (summary points in the PDF, and …_other_categories.csv with every device).`));
      } else {
        c.querySelector("h3").textContent = "Across reports: not in this report";
        out.append(el("p", "cb-hint", rv.drilled
          ? `Management chose the researcher's view (finding ${rv.finding}): the report covers exactly the devices you drilled down to, with the combination's own analysis and nothing added.`
          : `Management chose the researcher's view (finding ${rv.finding}): the report is the combination above, without the across-report patterns.`));
      }
      return;
    }
    const out = el("div", "ce-out"); c.append(out);
    // where they were seen, the infections and the CVEs (each to tick, until it is sent), then Across reports with each
    // pattern's addresses
    draw(out, pv, undefined, !rv);
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
    const cnt = el("span", "cb-hint", "Nothing ticked yet.");
    const send = el("button", "lg-btn primary", "Send the ticked views to management"); send.type = "button";
    const np = netPicker(st, () => { send.textContent = sendLabel(np.values(), "Send the ticked views to management"); });
    const rmsg = el("div", "cb-hint");
    req.append(el("b", null, "Send to management"), cnt, np.el, ...(toM ? [toM.el] : []), t, n, send, rmsg);
    c.append(req);
    out.addEventListener("change", () => { cnt.textContent = tickCount(); np.refresh(); });
    send.addEventListener("click", async () => {
      if (!anyTicked()) { rmsg.textContent = "Tick at least one pattern, infection or CVE/issue."; return; }
      if (toM && !toM.check()) { rmsg.textContent = "Choose the manager it goes to."; return; }
      if (!t.value.trim()) { rmsg.textContent = "Give the finding a short title."; return; }
      send.disabled = true; rmsg.textContent = "Sending…";
      try {
        const r = await post(`/api/combos/search/${job}/review`, { codes: [...ticked], infections: [...tickedInf], issues: [...tickedIss],
          networks: np.values(), title: t.value.trim(), text: n.value.trim(), to: toM ? toM.value() : "" });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { rmsg.textContent = d.error || `Refused (HTTP ${r.status})`; send.disabled = false; return; }
        rmsg.replaceChildren(document.createTextNode(`${sentText(d)}With ${tickCount().replace(/ ticked\.$/, "")}. Once management decides, the advisor they name generates the report. `));
        const a = el("a", null, "Open it on the Findings page"); a.href = `/findings#f${d.finding.slice(1)}`; rmsg.append(a);
        send.hidden = true; state.className = "ce-state wait"; state.replaceChildren(el("b", null, `Waiting for management's decision on finding ${d.finding}`));
        out.querySelectorAll("input[type=checkbox]").forEach((x) => { x.disabled = true; });
      } catch { rmsg.textContent = "The connection was interrupted. Try again."; send.disabled = false; }
    });
  }

  // the organisations (networks) it is sent for: none ticked = the whole combination (one overview finding); one = a
  // finding for that organisation; several = a case with one sub-finding per organisation, each decided on its own
  // where each infection, CVE/issue and across-report pattern was seen, by organisation: {network: {kind:name -> devices}}
  // (2026-11-14: the analyst saw the organisations but not which of them carry what they ticked)
  function seenByNetwork(pv) {
    const by = new Map();
    const add = (kind, name, devs) => {
      const per = new Map();
      for (const d of devs || []) { const n = d.network || "Unknown"; per.set(n, (per.get(n) || 0) + 1); }
      for (const [n, k] of per) { if (!by.has(n)) by.set(n, new Map()); by.get(n).set(`${kind}:${name}`, { kind, name, devices: k }); }
    };
    for (const x of pv.infections || []) add("inf", x.name, x.devices);
    for (const x of pv.issues || []) add("iss", x.name, x.devices);
    for (const x of pv.cross || []) add("pat", x.code, x.devices);
    return by;
  }
  const isTicked = (x) => (x.kind === "inf" ? tickedInf : x.kind === "iss" ? tickedIss : ticked).has(x.name);

  function netPicker(st, onChange) {
    const nets = st.networks || [];
    const seen = seenByNetwork(st.preview || {});
    const w = el("div", "ce-nets");
    const head = el("div", "ce-nets-head");
    head.append(el("b", null, "The organisations (networks) it is for"),
      el("span", "cb-hint", "Tick one to send it for that organisation, several to open a case with one sub-finding each (management reviews each one), or none for the whole combination. Under each: the infections and CVEs/issues its own devices carry; what you ticked is highlighted."));
    const tools = el("div", "ce-nets-tools");
    const all = el("button", "lg-btn sm ghost", "Tick all"); all.type = "button";
    const carrying = el("button", "lg-btn sm ghost", "Tick those carrying the ticked items"); carrying.type = "button";
    const none = el("button", "lg-btn sm ghost", "Clear"); none.type = "button";
    const find = el("input", "ac-in ce-nets-find"); find.placeholder = "Find a network"; find.type = "search";
    tools.append(find, all, carrying, none);
    const list = el("div", "ce-nets-list");
    const boxes = [];
    for (const n of nets) {
      const lab = el("label", "ce-net"), cb = el("input"); cb.type = "checkbox"; cb.value = n.network;
      const what = el("span", "ce-net-seen");
      lab.append(cb, el("span", null, n.network), el("small", null, `${fmt(n.devices)} IP · ${fmt(n.records)} records`), what);
      cb.addEventListener("change", () => { lab.classList.toggle("on", cb.checked); onChange(); });
      boxes.push([cb, lab, what, n.network]); list.append(lab);
    }
    // what each organisation's devices carry: the ticked items first (highlighted), then the rest, a few at most
    const refresh = () => {
      for (const [, lab, what, net] of boxes) {
        const items = [...((seen.get(net) || new Map()).values())].filter((x) => x.kind !== "pat" || isTicked(x));
        items.sort((a, b) => Number(isTicked(b)) - Number(isTicked(a)) || b.devices - a.devices);
        const hit = items.some(isTicked);
        lab.classList.toggle("has", hit);
        what.replaceChildren();
        for (const x of items.slice(0, 5)) {
          const c = el("span", `ce-net-item ${x.kind}${isTicked(x) ? " ticked" : ""}`, x.kind === "pat" ? "pattern" : x.name);
          c.title = `${x.kind === "inf" ? "Infection" : x.kind === "iss" ? (/^CVE-/i.test(x.name) ? "CVE" : "Issue") : `Across-report pattern ${x.name}`}: ${pl(x.devices, "device")} of this organisation`;
          c.append(el("em", null, fmt(x.devices))); what.append(c);
        }
        if (items.length > 5) what.append(el("span", "ce-net-more", `+${items.length - 5}`));
      }
      carrying.disabled = !anyTicked();
    };
    refresh();
    carrying.addEventListener("click", () => { for (const [cb, lab] of boxes) { cb.checked = lab.classList.contains("has"); lab.classList.toggle("on", cb.checked); } onChange(); });
    all.addEventListener("click", () => { for (const [cb, lab] of boxes) if (!lab.hidden) { cb.checked = true; lab.classList.add("on"); } onChange(); });
    none.addEventListener("click", () => { for (const [cb, lab] of boxes) { cb.checked = false; lab.classList.remove("on"); } onChange(); });
    find.addEventListener("input", () => { const t = find.value.trim().toLowerCase(); for (const [cb, lab] of boxes) lab.hidden = !!t && !cb.value.toLowerCase().includes(t); });
    w.append(head, tools, list);
    return { el: w, refresh, values: () => boxes.filter(([cb]) => cb.checked).map(([cb]) => cb.value) };
  }
  const sendLabel = (nets, base) => (nets.length > 1 ? `Submit ${nets.length} networks (a case, one sub-finding each)` : nets.length === 1 ? `Send for ${nets[0]}` : base);
  const sentText = (d) => (d.case ? `Case ${d.finding} sent to ${d.to}, with ${d.subs.length} sub-findings: ${d.subs.map((s) => `${s.finding} ${s.network}`).join(", ")}. Management reviews each one. `
    : `Finding ${d.finding}${d.network ? ` (${d.network})` : ""} sent to ${d.to}. `);

  // no across-report data: the combination still goes to management for the advisory; once sent, the report is the
  // advisor's (management decides and names them), so the download closes, unless management rejects it
  function plainSend(job, st, entry, c) {
    const rv = st.review;
    const dl = document.querySelector(".cb-dl");
    const w = el("div", "ce-req ce-req-open ce-plain");
    w.append(el("b", null, "Send to management for the advisory"));
    if (rv) {
      const rejected = rv.decision === "rejected";
      if (dl) dl.hidden = !rejected;
      const s = el("div", `ce-state ${rv.decision ? (rejected ? "todo" : "ok") : "wait"}`);
      if (!rv.decision) { s.append(el("b", null, `Waiting for management's decision on finding ${rv.finding}`), document.createTextNode(" · ")); const a = el("a", null, "Open it"); a.href = `/findings#f${rv.finding.slice(1)}`; s.append(a); }
      else if (rejected) s.append(el("b", null, `Management rejected finding ${rv.finding}`), document.createTextNode(": no advisory; the download is yours again."));
      else s.append(el("b", null, "Management approved it"), document.createTextNode(` (finding ${rv.finding}): ${rv.advisor || "the advisor management chose"} writes the advisory and generates the report from exactly this search.`));
      w.append(s);
      if (rv.decision === "both" || rv.decision === "analyst") { const added = el("div", "ce-out"); addedNames(added, rv); w.append(added); }
      c.append(w); return;
    }
    w.append(el("p", "cb-hint", "These devices turn up in no other report, so there are no across-report views to tick. Send the combination to a manager: they approve it and name the advisor who writes the advisory and generates the report from exactly this search, or reject it."));
    // the infections and CVEs/issues on these devices: tick those the report should carry (management decides)
    const pv = st.preview || {};
    if ((pv.infections || []).length || (pv.issues || []).length) {
      const box2 = el("div", "ce-out ce-plain-ticks");
      draw(box2, Object.assign({}, pv, { cross: [], sources: [] }), undefined, true);
      box2.querySelector(".ce-sec.svc")?.remove();
      if (box2.lastElementChild?.matches("p.cb-hint")) box2.lastElementChild.remove();
      w.append(el("p", "cb-hint", "Tick the infections and CVEs/issues the report should carry: management decides whether they are added."), box2);
    }
    const toM = window.LGPeople ? window.LGPeople.picker("management") : null;
    const t = el("input", "ac-in"); t.maxLength = 140; t.placeholder = `Title, e.g. ${entry?.code || "this code"}: exposed devices for an advisory`;
    const n = el("textarea", "ac-in"); n.rows = 3; n.maxLength = 2000; n.placeholder = "Your final comments: why this needs an advisory";
    const send = el("button", "lg-btn primary", "Send to management"); send.type = "button";
    const np = netPicker(st, () => { send.textContent = sendLabel(np.values(), "Send to management (the whole combination)"); });
    send.textContent = sendLabel([], "Send to management (the whole combination)");
    w.addEventListener("change", (ev) => { if (ev.target.closest(".ce-plain-ticks")) np.refresh(); });
    const msg = el("div", "cb-hint");
    w.append(np.el, ...(toM ? [toM.el] : []), t, n, send, msg);
    c.append(w);
    send.addEventListener("click", async () => {
      if (toM && !toM.check()) { msg.textContent = "Choose the manager it goes to."; return; }
      if (!t.value.trim()) { msg.textContent = "Give the finding a short title."; return; }
      send.disabled = true; msg.textContent = "Sending…";
      try {
        const r = await post(`/api/combos/search/${job}/review`, { codes: [], infections: [...tickedInf], issues: [...tickedIss],
          networks: np.values(), title: t.value.trim(), text: n.value.trim(), to: toM ? toM.value() : "" });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { msg.textContent = d.error || `Refused (HTTP ${r.status})`; send.disabled = false; return; }
        msg.replaceChildren(document.createTextNode(`${sentText(d)}${anyTicked() ? `With ${tickCount().replace(/ ticked\.$/, "")}. ` : ""}Once management approves, the advisor they name generates the report. `));
        w.querySelectorAll("input[type=checkbox]").forEach((x) => { x.disabled = true; });
        const a = el("a", null, "Open it on the Findings page"); a.href = `/findings#f${d.finding.slice(1)}`; msg.append(a);
        send.hidden = true; if (dl) dl.hidden = true;
      } catch { msg.textContent = "The connection was interrupted. Try again."; send.disabled = false; }
    });
  }

  function box(job, s, entry) {
    const c = el("section", "ce-box");
    // the search's own state: across-report data (needs management's decision) or not
    const dl0 = document.querySelector(".cb-dl"); if (dl0) dl0.hidden = false;
    fetch(`/api/combos/search/${job}`, { cache: "no-store" }).then((r) => r.json()).then((st) => {
      if (st.needs_review) { c.replaceChildren(); reviewBox(job, st, entry, c); }
      else if (!entry || !String(entry.code || "").startsWith("LG-A-")) plainSend(job, st, entry, c);
    }).catch(() => { c.append(el("p", "cb-hint", "Could not read this search's state: reload the page to send it to management.")); });   // (review 2026-11-13)
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
      } catch { msg.textContent = "The connection was interrupted. Try again."; }
      finally { go.disabled = false; }
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
