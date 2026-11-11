/* Looking Glass · the review page (/review/<id>, combo_review.py): management's final look at an analyst's request.
   What the researcher is saying (their notes and finding on the combination), then the views, each the Executive portal
   itself (embedded, counts only): the researcher's view (the combination), the analyst's view (the across-report
   patterns they ticked), and both together when they lie on one platform; then the decision, which goes back to the
   analyst who asked. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fid = document.body.dataset.fid, main = $("rvMain");

  function portal(codes, plat) {
    const u = `/management?embed=1&plat=${plat}&code=${encodeURIComponent(codes.join(","))}`;
    const f = el("iframe", "rv-frame"); f.src = u; f.title = "The Executive portal for this view"; f.setAttribute("scrolling", "no");
    // the portal at its full height, so the page scrolls as one (no scroll bar inside, nothing cut off)
    f.addEventListener("load", () => {
      const fit = () => {
        try {
          const h = Math.min(9000, f.contentDocument.documentElement.scrollHeight);        // capped: never runs away
          if (h > 200 && Math.abs(h - f.offsetHeight) > 4) f.style.height = `${h}px`;
        } catch { /* not readable: keep the set height */ }
      };
      fit();
      try { new ResizeObserver(fit).observe(f.contentDocument.body); } catch { /* */ }
      const t = setInterval(() => { if (!document.body.contains(f)) clearInterval(t); else fit(); }, 1500);
    });
    return f;
  }

  async function load() {
    const r = await fetch(`/api/review/${encodeURIComponent(fid)}`, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    $("rvLoading")?.remove();
    if (!r.ok) { main.append(el("p", "fd-empty", d.error || `Could not open the review (HTTP ${r.status})`)); return; }
    const f = d.finding, rv = f.review, A = rv.analyst || {};
    // the request
    const hero = el("section", "rv-hero");
    hero.append(el("div", "fd-eyebrow", `Review · finding ${f.number} · ${f.status_label}`), el("h1", null, f.title));
    const meta = el("div", "rv-meta");
    meta.append(el("span", null, f.created));            // the date and the channel only
    if (f.channel?.length) meta.append(el("span", "fd-channel", `Channel: ${f.channel.join(", ")}`));
    hero.append(meta);
    if (f.text) { const q = el("blockquote", "rv-quote"); q.append(el("b", null, `Final comments by the analyst, ${f.by}`), el("p", null, f.text)); hero.append(q); }
    main.append(hero);
    // what the researcher is saying
    const rs = el("section", "rv-card rv-researcher");
    rs.append(el("h2", null, "What the researcher is saying"), el("p", "rv-what", d.researcher.what || rv.source));
    if (d.researcher.finding) {
      const x = d.researcher.finding, q = el("blockquote", "rv-quote r");
      q.append(el("b", null, `Their finding ${x.number}: ${x.title}`), el("p", null, x.text || ""), el("small", null, `Researcher: ${x.by}`));
      rs.append(q);
    }
    for (const n of d.researcher.notes || []) {
      const q = el("blockquote", "rv-quote r");
      q.append(el("b", null, `${n.role}: ${n.by} · ${n.date || ""}`), el("p", null, n.text));
      rs.append(q);
    }
    if (!d.researcher.finding && !(d.researcher.notes || []).length) rs.append(el("p", "fd-empty", "No note from the researchers on this combination yet."));
    main.append(rs);
    // the views: the Executive portal itself, filtered to each
    const vs = el("section", "rv-card rv-views");
    vs.append(el("h2", null, "The views, as the Executive portal shows them"));
    const both = d.plat_researcher === d.plat_analyst;
    const plain = !rv.codes.length;        // sent without across-report data: the researcher's view only
    const views = [
      ["r", "The researcher's view", `the combination ${rv.source}`, [rv.source], d.plat_researcher],
      ...(plain ? [] : [
        ["a", "The analyst's view", `${rv.codes.length} across-report pattern${rv.codes.length === 1 ? "" : "s"}: ${fmt((A.patterns || []).reduce((s, x) => s + x.hosts, 0))} devices`, rv.codes, d.plat_analyst],
        ...(both ? [["b", "Both together", "the combination and the patterns", [rv.source, ...rv.codes], d.plat_researcher]] : [])]),
    ];
    if (plain) vs.append(el("p", "rv-what", "These devices turn up in no other report: the analyst sends the combination as it is, for the advisory."));
    const tabs = el("div", "rv-tabs"); tabs.setAttribute("role", "tablist");
    const pane = el("div", "rv-pane");
    const frames = {};
    const show = (k) => {
      for (const b of tabs.children) b.setAttribute("aria-selected", String(b.dataset.k === k));
      for (const [kk, fr] of Object.entries(frames)) fr.hidden = kk !== k;
      if (!frames[k]) { const v = views.find((x) => x[0] === k); frames[k] = portal(v[3], v[4]); pane.append(frames[k]); }
    };
    for (const [k, l, sub] of views) {
      const b = el("button", `rv-tab ${k}`); b.type = "button"; b.setAttribute("role", "tab"); b.dataset.k = k;
      b.append(el("b", null, l), el("small", null, sub)); b.addEventListener("click", () => show(k)); tabs.append(b);
    }
    vs.append(tabs);
    // the analyst's patterns, in words: how many hosts share each exact infrastructure, across which reports
    const pats = el("div", "rv-pats");
    for (const x of A.patterns || []) {
      const p = el("div", "rv-pat");
      p.append(el("b", null, `${fmt(x.hosts)} host${x.hosts === 1 ? " shares" : "s share"} this exact infrastructure`),
        el("span", null, x.parts.map((y) => y.title).join(" + ")), el("code", null, x.code));
      pats.append(p);
    }
    vs.append(pats, pane);
    main.append(vs);
    show("r");
    // the decision
    const dc = el("section", "rv-card rv-decide");
    dc.append(el("h2", null, "The decision"));
    if (rv.decision) {
      const said = { both: "Added the analyst's views", researcher: plain ? "Approved" : "The researcher's view only", rejected: "Rejected and closed" }[rv.decision] || rv.decision;
      dc.append(el("p", `fd-rv-done ${rv.decision}`, `${said} · ${rv.by}${rv.comment ? `: ${rv.comment}` : ""}`));
    } else if (d.can_decide && f.open) {
      const ta = el("textarea", "fd-in"); ta.rows = 3; ta.maxLength = 1000; ta.placeholder = "Your comment: the directive for the report, or the reason for rejecting";
      const toV = window.LGPeople ? window.LGPeople.picker("advisor") : null;      // the advisor who writes the advisory
      const add = el("button", "lg-btn primary", "Add the analyst's views"); add.type = "button";
      const only = el("button", plain ? "lg-btn primary" : "lg-btn", plain ? "Approve and send to the advisor" : "Use the researcher's view only"); only.type = "button";
      const rej = el("button", "lg-btn fd-reject", "Reject and close"); rej.type = "button";
      const m = el("span", "fd-msg");
      const go = async (choice) => {
        if (!ta.value.trim()) { m.textContent = choice === "reject" ? "Write the reason first." : "Write your comment (the directive) first."; m.className = "fd-msg bad"; ta.focus(); return; }
        if (choice !== "reject" && toV && !toV.check()) { m.textContent = "Choose the advisor who writes the advisory."; m.className = "fd-msg bad"; return; }
        add.disabled = only.disabled = rej.disabled = true;
        try {
          const rr = await fetch(`/api/findings/${f.id}/review-decision`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ choice, text: ta.value.trim(), to: choice !== "reject" && toV ? toV.value() : "" }) });
          const x = await rr.json().catch(() => ({}));
          if (!rr.ok) { m.textContent = x.error || `Not saved (HTTP ${rr.status})`; m.className = "fd-msg bad"; return; }
          main.replaceChildren(el("p", "fd-empty", choice === "reject" ? "Rejected: the finding is closed." : "Saved: it goes to the advisor.")); setTimeout(() => location.reload(), 900);
        } finally { add.disabled = only.disabled = rej.disabled = false; }
      };
      add.addEventListener("click", () => go("both")); only.addEventListener("click", () => go("researcher")); rej.addEventListener("click", () => go("reject"));
      const row = el("div", "fd-decide-row"); row.append(m, rej, only, ...(plain ? [] : [add]));
      dc.append(el("p", "fd-rv-hint", plain ? "Approve and it goes to the advisor you choose, who writes the advisory and generates the report; or reject it with the reason (it is closed)."
                                            : "It goes to the advisor you choose: they write the advisory and generate the report with the views you chose. Or reject it with the reason (it is closed)."),
        ta, ...(toV ? [toV.el] : []), row);
    } else dc.append(el("p", "fd-rv-done wait", "Waiting for management's decision."));
    const back = el("a", `lg-btn ${rv.decision ? "primary" : "sm"}`, "Back to the Findings page"); back.href = `/findings#f${f.id}`; dc.append(back);
    main.append(dc);
  }
  load();
})();
