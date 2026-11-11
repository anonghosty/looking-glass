/* Looking Glass · the Findings page (/findings, findings.py): researchers' notes the team follows up.
   One card per finding: its number, title, name, the note, the combination codes (analysts: Search opens them on the
   Combinations page), the status with its history, and "Move it on" (a status and a short comment). */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  let state = "open", data = { findings: [], statuses: [] };

  async function load() {
    const r = await fetch(`/api/findings?state=${state}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { $("fdList").replaceChildren(el("p", "fd-empty", d.error || `Could not load (HTTP ${r.status})`)); return; }
    data = d; draw();
    const want = location.hash.match(/^#f(\d+)$/);
    if (want) { const c = $(`f${want[1]}`); if (c) { c.classList.add("flash"); c.scrollIntoView({ block: "center" }); } }
  }
  function draw() {
    const q = $("fdQ").value.trim().toLowerCase();
    const items = data.findings.filter((f) => !q || [f.number, f.title, f.name, f.text, ...f.codes.map((c) => `${c.code} ${c.text}`)].join(" ").toLowerCase().includes(q));
    const counts = {}; for (const f of data.findings) counts[f.status] = (counts[f.status] || 0) + 1;
    const cb = $("fdCounts"); cb.replaceChildren();
    for (const s of data.statuses) if (counts[s.key]) { const p = el("span", `fd-pill s-${s.key}`); p.append(el("b", null, String(counts[s.key])), document.createTextNode(` ${s.label}`)); cb.append(p); }
    const list = $("fdList"); list.replaceChildren();
    if (!items.length) {
      list.append(el("p", "fd-empty", q ? "Nothing matches the search." : state === "open"
        ? "No open finding. A researcher starts one from a name's Notes window on the Definitions page: “Track as a finding”." : "No finding yet."));
      return;
    }
    for (const f of items) list.append(card(f));
  }
  const pl = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  // a code and what each role can do with it: researchers open an analyst's selection, management filters the
  // Executive portal (counts only), analysts search or report on it (with the addresses)
  function codesBox(codes) {
    const cs = el("div", "fd-codes");
    for (const x of codes) {
      const isA = x.code.startsWith("LG-A-");
      const row = el("div", `fd-code${isA ? " a" : ""}`);
      row.append(el("code", null, x.code), el("span", null, x.text || ""));
      const acts = el("div", "fd-code-acts");
      const link = (label, href, title) => { const a = el("a", "lg-btn sm", label); a.href = href; a.title = title; acts.append(a); };
      if (isA && data.can_research) link("Open as researcher", `/intel/${x.code}`, "The names, definitions and intel of exactly these records, never an address; pick codes for your reply");
      if (data.can_portal) link("Show in Executive", `/management?code=${x.code}`, "Filter the Executive portal to exactly this (aggregated figures, no addresses)");
      if (data.can_search) link(isA ? "Report (PDF + CSV)" : "Search", `/combinations?code=${x.code}`, "The devices behind it with their addresses, as PDF + CSV (Combinations page)");
      if (acts.children.length) row.append(acts);
      cs.append(row);
    }
    return cs;
  }
  // ---------------- an analyst's across-report views: the researcher's view and the analyst's, side by side, with the
  // figures management weighs (counts only), and management's decision; then the analyst generates the report
  function bars(items, key) {
    const w = el("div", "fd-bars"), mx = Math.max(1, ...items.map((x) => x[key]));
    for (const x of items) {
      const r = el("div", "fd-hbar"), t = el("span", "t"), i = el("i"); i.style.width = `${(100 * x[key]) / mx}%`; t.append(i);
      r.append(el("span", "l", x.label), t, el("b", null, Number(x[key]).toLocaleString("en-US"))); w.append(r);
    }
    return w;
  }
  function reviewPanel(f, c) {
    const rv = f.review, R = rv.researcher || {}, A = rv.analyst || {};
    const p = el("section", "fd-review");
    p.append(el("h3", null, "Which views does the report carry?"));
    const cols = el("div", "fd-views");
    // the researcher's view
    const rc = el("article", "fd-view r");
    rc.append(el("div", "fd-view-k", "The researcher's view"), el("code", "fd-view-code", R.code || rv.source), el("p", "fd-view-what", R.what || ""));
    const k = el("div", "fd-kpis");
    for (const [v, l] of [[R.devices, "devices"], [R.records, "records"], [R.networks, "networks"], [R.repeat, "repeating"], [R.multi_day, "on several days"]]) {
      const t = el("div"); t.append(el("b", null, Number(v || 0).toLocaleString("en-US")), el("span", null, l)); k.append(t);
    }
    rc.append(k);
    if ((R.top_networks || []).length) rc.append(el("h4", null, "Devices per network"), bars(R.top_networks, "devices"));
    if ((R.regions || []).length) rc.append(el("h4", null, "Devices per region"), bars(R.regions, "devices"));
    if ((R.per_day || []).length) rc.append(el("h4", null, "Records per day"), bars(R.per_day.map(([d, n]) => ({ label: d, n })), "n"));
    // the analyst's view
    const ac = el("article", "fd-view a");
    ac.append(el("div", "fd-view-k", "The analyst's view: the same devices across reports"));
    const k2 = el("div", "fd-kpis");
    for (const [v, l] of [[A.multi_hosts, "devices in 2+ reports"], [(A.patterns || []).length, "patterns sent"], [A.patterns_total, "patterns in all"]]) {
      const t = el("div"); t.append(el("b", null, Number(v || 0).toLocaleString("en-US")), el("span", null, l)); k2.append(t);
    }
    ac.append(k2);
    for (const x of A.patterns || []) {
      const b = el("div", "fd-pat");
      b.append(el("div", "fd-pat-h", `${Number(x.hosts).toLocaleString("en-US")} host${x.hosts === 1 ? " shares" : "s share"} this exact infrastructure · across ${x.parts.length} reports`));
      for (const pt of x.parts) { const r = el("div", "fd-pat-r"); r.append(el("b", null, pt.title), el("span", null, pt.items.join(" + ") || "the report only")); b.append(r); }
      b.append(el("code", "fd-view-code", x.code)); ac.append(b);
    }
    if ((A.sources || []).length) {
      ac.append(el("h4", null, "Where these devices were seen"));
      for (const s of A.sources) ac.append(el("p", "fd-src", `${s.kind} ${s.reports.length}: ${s.reports.map((y) => `${y.title} (${y.hosts})`).join(" · ")}`));
    }
    cols.append(rc, ac); p.append(cols);
    // the decision
    if (rv.decision) {
      p.append(el("p", `fd-rv-done ${rv.decision}`, `${rv.decision === "both" ? "Added the analyst's views" : "The researcher's view only"} · ${rv.by}${rv.comment ? `: ${rv.comment}` : ""}`));
      if (data.can_search) { const a = el("a", "lg-btn sm primary", "Generate the report"); a.href = `/combinations?code=${encodeURIComponent(rv.source)}`; a.title = "Open the code again: the report follows management's decision"; p.append(a); }
    } else if (data.can_decide && f.open) {
      const ta = el("textarea", "fd-in"); ta.rows = 2; ta.maxLength = 1000; ta.placeholder = "Your comment: the directive for the report";
      const both = el("button", "lg-btn sm primary", "Add the analyst's views"); both.type = "button";
      const only = el("button", "lg-btn sm", "Use the researcher's view only"); only.type = "button";
      const m = el("span", "fd-msg");
      const go = async (choice) => {
        if (!ta.value.trim()) { m.textContent = "Write your comment (the directive) first."; m.className = "fd-msg bad"; ta.focus(); return; }
        both.disabled = only.disabled = true;
        try {
          const r = await fetch(`/api/findings/${f.id}/review-decision`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ choice, text: ta.value.trim() }) });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) { m.textContent = d.error || `Not saved (HTTP ${r.status})`; m.className = "fd-msg bad"; return; }
          Object.assign(f, d.finding); const n = card(f); c.replaceWith(n); n.classList.add("flash");
        } finally { both.disabled = only.disabled = false; }
      };
      both.addEventListener("click", () => go("both")); only.addEventListener("click", () => go("researcher"));
      const row = el("div", "fd-decide-row"); row.append(m, only, both);
      p.append(el("small", "fd-rv-hint", "Your decision goes back to the analyst who asked; they then generate the report with the views you chose."), ta, row);
    } else p.append(el("p", "fd-rv-done wait", "Waiting for management's decision."));
    return p;
  }
  function card(f) {
    const c = el("article", `fd-card s-${f.status}`); c.id = `f${f.id}`;
    const h = el("header", "fd-h");
    const t = el("div", "fd-t");
    t.append(el("span", "fd-no", f.number), el("h2", null, f.title));
    h.append(t, el("span", `fd-pill s-${f.status}`, f.status_label));
    const meta = el("div", "fd-meta");
    meta.append(el(f.section === "services" ? "b" : "code", "fd-name", f.display_name || f.name),
      el("span", null, f.section === "issues" ? "issue" : f.section === "services" ? "services report" : "infection / category"),
      el("span", null, `${f.role}: ${f.by} · ${f.created}`), el("span", null, `updated ${f.updated}`));
    // the channel: who holds it now, and everyone in it (only they see this finding)
    if (f.assignee) meta.append(el("span", "fd-with", `With ${f.assignee}`));
    if (f.channel?.length) { const ch = el("span", "fd-channel", `Channel: ${f.channel.join(", ")}`); ch.title = "Only these people see this finding and its trail"; meta.append(ch); }
    c.append(h, meta, el("p", "fd-text", f.text));
    if (f.origin === "analyst") meta.prepend(el("span", "fd-origin", "From an analyst"));
    if (f.review) {
      // a review: one global look, not a list of codes (the patterns are summed up in the panel below)
      const rv = f.review, g = el("div", "fd-global");
      g.append(el("span", null, `The researcher's combination ${rv.source} and ${(rv.codes || []).length} across-report pattern${(rv.codes || []).length === 1 ? "" : "s"} the analyst ticked.`));
      g.append(el("b", `fd-rv-state ${rv.decision || "wait"}`, rv.decision ? (rv.decision === "both" ? "Decided: the analyst's views added" : "Decided: the researcher's view only") : "Waiting for management's decision"));
      if (rv.decision && data.can_advise && f.open) {
        // the advisor writes the advisory and generates the report on a page of its own
        const p = el("a", "lg-btn sm primary", "Write the advisory"); p.href = `/advisory/${f.id}`;
        p.title = "The advisory (title, affected items, impact, recommended actions) over the full report from exactly what was sent"; g.append(p);
      }
      if (data.can_decide) { const a = el("a", "lg-btn sm primary", "Open the review"); a.href = `/review/${f.id}`;    // management only
        a.title = "The final look: what the researcher is saying, and the researcher's and the analyst's views as the Executive portal shows them"; g.append(a); }
      c.append(g);
    } else if (f.codes.length) c.append(el("h3", null, f.origin === "analyst" ? "The analyst's code" : "Combinations"), codesBox(f.codes));
    // the reply box: text and codes (researchers answer an analyst's code with combination codes, and the other way round)
    const rp = el("details", "fd-replybox"); rp.append(el("summary", null, f.origin === "analyst" ? "Reply to the analyst" : "Reply"));
    const rta = el("textarea", "fd-in"); rta.rows = 3; rta.maxLength = 1000; rta.placeholder = "Your reply";
    const rcodes = el("input", "fd-in"); rcodes.placeholder = "Codes to send with it (LG-C-…, LG-X-…, LG-A-…), separated by commas"; rcodes.spellcheck = false;
    const rgo = el("button", "lg-btn sm primary", "Send the reply"); rgo.type = "button"; const rmsg = el("span", "fd-msg");
    if (f.origin === "analyst" && data.can_research) {
      const a = el("a", "lg-btn sm", "Open the selection's intel to pick codes"); a.href = `/intel/${f.codes[0]?.code || ""}`; rp.append(a);
    }
    rp.append(rta, rcodes, rgo, rmsg);
    rgo.addEventListener("click", async () => {
      const codes = rcodes.value.split(/[\s,]+/).map((x) => x.trim().toUpperCase()).filter(Boolean);
      rgo.disabled = true;
      try {
        const r = await fetch(`/api/findings/${f.id}/reply`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
          body: JSON.stringify({ text: rta.value.trim(), codes }) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { rmsg.textContent = d.error || `Not sent (HTTP ${r.status})`; rmsg.className = "fd-msg bad"; return; }
        Object.assign(f, d.finding); const n = card(f); c.replaceWith(n); n.classList.add("flash"); n.querySelector(".fd-more").open = true;
      } finally { rgo.disabled = false; }
    });
    // the history: who moved it, when, with what comment
    const tl = el("ol", "fd-hist");
    for (const x of f.history) {
      const li = el("li", `s-${x.status}${x.kind === "reply" ? " reply" : ""}`);
      if (x.kind === "decision") li.classList.add("decision", x.decision);
      li.append(el("b", null, x.kind === "reply" ? "Reply" : x.kind === "decision" ? (x.decision === "accepted" ? "Accepted by management · directive" : "Rejected by management") : x.status_label),
        el("span", null, `${x.role}: ${x.by} · ${x.at}${x.to ? ` → ${x.to}` : ""}`));
      if (x.comment) li.append(el("p", null, x.comment));
      if (x.codes?.length) li.append(codesBox(x.codes));
      tl.append(li);
    }
    const det = el("details", "fd-more"); det.append(el("summary", null, `History (${f.history.length})${f.replies ? ` · ${pl(f.replies, "reply", "replies")}` : ""}`), tl);
    if (f.replies) det.open = true;
    c.append(det, rp);
    // management decides first: approve with a comment (the directive) → "Approved"; reject with the reason → closed.
    // Who it goes to next is asked when it is moved on.
    // a review: the views and the decision are on the review page (/review/<id>); the card says where it stands
    if (data.can_decide && f.open && f.status !== "approved" && !f.review) {
      const dec = el("div", "fd-decide");
      dec.append(el("b", null, "Decide"),
        el("small", null, "Approve with your comment (the directive for the report), or reject with the reason (it is closed). After approving, move it on: Looking Glass asks to whom."));
      const dta = el("textarea", "fd-in"); dta.rows = 2; dta.maxLength = 1000;
      dta.placeholder = "Comment: the directive (e.g. generate the advisory for the three operators), or the reason for rejecting";
      const acc = el("button", "lg-btn sm primary", "Approve with this comment"); acc.type = "button";
      const rej = el("button", "lg-btn sm fd-reject", "Reject and close"); rej.type = "button";
      const dmsg = el("span", "fd-msg");
      const send = async (decision) => {
        if (!dta.value.trim()) { dmsg.textContent = decision === "accept" ? "Write your comment (the directive) first." : "Write the reason first."; dmsg.className = "fd-msg bad"; dta.focus(); return; }
        acc.disabled = rej.disabled = true;
        try {
          const r = await fetch(`/api/findings/${f.id}/decision`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ decision, text: dta.value.trim() }) });
          const d = await r.json().catch(() => ({}));
          if (!r.ok) { dmsg.textContent = d.error || `Not saved (HTTP ${r.status})`; dmsg.className = "fd-msg bad"; return; }
          Object.assign(f, d.finding); const n = card(f); c.replaceWith(n); n.classList.add("flash");
        } finally { acc.disabled = rej.disabled = false; }
      };
      acc.addEventListener("click", () => send("accept")); rej.addEventListener("click", () => send("reject"));
      const row = el("div", "fd-decide-row"); row.append(dmsg, rej, acc);
      dec.append(dta, row);
      c.append(dec);
    }
    // move it on
    const mv = el("div", "fd-move");
    const sel = el("select", "fd-sel"); sel.setAttribute("aria-label", "New status");
    for (const s of data.statuses) { const o = el("option", null, s.label); o.value = s.key; if (s.key === f.status) o.selected = true; sel.append(o); }
    const com = el("input", "fd-in"); com.maxLength = 1000; com.placeholder = "Comment (for example: look at the rising trend in the Northern region)"; com.setAttribute("aria-label", "Comment");
    const go = el("button", "lg-btn sm primary", "Move it on"); go.type = "button";
    const msg = el("span", "fd-msg");
    // a hand-over (to management, a researcher, an analyst) names the person it goes to (people-pick.js)
    const KIND = { management: "management", researcher: "researcher", analyst: "analyst", advisor: "advisor" };
    // "Move it on" to a person (management, a researcher, an analyst): Looking Glass asks to whom, then it is sent
    const toBox = el("div", "fd-to"); toBox.hidden = true; let toP = null;
    const send = async (to) => {
      go.disabled = true;
      try {
        const r = await fetch(`/api/findings/${f.id}/status`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
          body: JSON.stringify({ status: sel.value, comment: com.value.trim(), to: to || "" }) });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { msg.textContent = d.error || `Not saved (HTTP ${r.status})`; msg.className = "fd-msg bad"; return; }
        Object.assign(f, d.finding); const n = card(f); c.replaceWith(n); n.classList.add("flash");
      } finally { go.disabled = false; }
    };
    const ask = () => {
      const k = KIND[sel.value];
      toBox.replaceChildren(); toP = window.LGPeople.picker(k);
      const h = el("div", "fd-ask"); h.append(el("b", null, "Looking Glass asks:"), document.createTextNode(` to whom does it go? (${window.LGPeople.label(k)})`));
      const ok = el("button", "lg-btn sm primary", "Send it"); ok.type = "button";
      const cancel = el("button", "lg-btn sm ghost", "Cancel"); cancel.type = "button";
      ok.addEventListener("click", () => { if (!toP.check()) { msg.textContent = `Choose ${window.LGPeople.label(k)}.`; msg.className = "fd-msg bad"; return; } send(toP.value()); });
      cancel.addEventListener("click", () => { toBox.hidden = true; toP = null; });
      const row = el("div", "fd-decide-row"); row.append(cancel, ok);
      toBox.append(h, toP.el, row); toBox.hidden = false; toP.el.querySelector("select")?.focus();
    };
    sel.addEventListener("change", () => { toBox.hidden = true; toP = null; });
    go.addEventListener("click", () => {
      msg.textContent = "";
      if (KIND[sel.value] && window.LGPeople) ask();       // a hand-over: ask first
      else send("");
    });
    mv.append(sel, com, go, msg);
    c.append(mv, toBox);
    return c;
  }
  for (const b of document.querySelectorAll(".fd-tabs button")) b.addEventListener("click", () => {
    state = b.dataset.state; for (const x of document.querySelectorAll(".fd-tabs button")) x.setAttribute("aria-selected", String(x === b)); load();
  });
  $("fdQ").addEventListener("input", draw);
  load();
})();
