/* Looking Glass · an analyst code seen by the researchers (/intel/LG-A-…, acodes.py): the analyst's finding and note,
   the selection in words (never an address), and for each name in exactly those records its definition and Intel
   gathered: the combinations (LG-C) and cross-report patterns (LG-X) with their codes. Tick codes and answer the analyst
   with a reply on the finding. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const pl = (n, w) => `${fmt(n)} ${w}${n === 1 ? "" : "s"}`;
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const code = document.body.dataset.code, main = $("axMain");
  const picked = new Map();          // code -> what it is

  function chips(items) {
    const s = el("div", "ax-set");
    if (!items.length) s.append(el("span", "ax-none", "the name only"));
    items.forEach((x, i) => { if (i) s.append(el("span", "ax-plus", "+")); s.append(el("span", "ax-chip", x)); });
    return s;
  }
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
    hero.append(k, el("p", "ax-hint", "Indicators only: the addresses of the hosts are never shown here. Tick the combinations that answer the analyst and send them with your reply."));
    if (d.finding) { const a = el("a", "lg-btn sm", `Finding ${d.finding.number} on the Findings page`); a.href = `/findings#f${d.finding.id}`; hero.append(a); }
    main.append(hero);
    if (!d.records) { main.append(el("p", "ax-empty", `The selection has no records on ${d.day} any more (the day may no longer be in the database).`)); return; }
    // each name: definition, reports, combinations and cross-report patterns
    for (const n of d.names) {
      const c = el("article", "ax-card");
      const hd = el("header", "ax-card-h");
      const t = el("div", "ax-card-t"); t.append(el("code", "ax-name", n.name), el("span", `ax-def${n.defined ? " ok" : ""}`, n.defined ? n.defined : "No definition yet"));
      hd.append(t, el("span", "ax-fig", `${pl(n.records, "record")} · ${pl(n.devices, d.section === "issues" ? "host" : "device")}`));
      c.append(hd, el("div", "ax-reps", n.reports.map((r) => `${r.report} (${fmt(r.records)})`).join(" · ")));
      if (n.combinations.length) {
        c.append(el("h3", null, `Combinations in these records${n.combinations_total > n.combinations.length ? ` (the ${n.combinations.length} most frequent of ${fmt(n.combinations_total)})` : ""}`));
        const ul = el("ul", "ax-list");
        for (const x of n.combinations) {
          const li = el("li"), lab = el("label", "ax-tick"), cb = el("input"); cb.type = "checkbox";
          lab.append(cb, el("code", "ax-code", x.code)); pick(cb, x.code, `${n.name} in ${x.report}: ${x.items.join(" + ") || "the name only"}`);
          const what = el("div", "ax-what"); what.append(el("span", "ax-rep", x.report), chips(x.items));
          li.append(lab, what, el("span", "ax-fig", `${pl(x.records, "record")} · ${pl(x.devices, d.section === "issues" ? "host" : "device")}${x.repeat ? ` · ${fmt(x.repeat)} repeating` : ""}`));
          ul.append(li);
        }
        c.append(ul);
      }
      if (n.across.length) {
        c.append(el("h3", null, "Across reports: the same devices in several reports"));
        const ul = el("ul", "ax-list");
        for (const x of n.across) {
          const li = el("li"), lab = el("label", "ax-tick"), cb = el("input"); cb.type = "checkbox";
          lab.append(cb, el("code", "ax-code x", x.code)); pick(cb, x.code, `${n.name} across ${x.parts.map((p) => p.report).join(" + ")}`);
          const what = el("div", "ax-what ax-parts");
          for (const p of x.parts) { const b = el("div", "ax-part"); b.append(el("span", "ax-rep", p.report), chips(p.items)); what.append(b); }
          li.append(lab, what, el("span", "ax-fig", pl(x.devices, d.section === "issues" ? "host" : "device")));
          ul.append(li);
        }
        c.append(ul);
      }
      main.append(c);
    }
    // the reply to the analyst, on the finding
    if (d.finding) {
      const rp = el("section", "ax-reply");
      rp.append(el("h2", null, `Reply on finding ${d.finding.number}`),
        el("p", "ax-hint", "Your answer goes into the finding's history, with the ticked codes: the analyst pulls exactly those devices, management follows both sides."));
      pickedBox = el("div", "ax-picked"); rp.append(pickedBox); drawPicked();
      const ta = el("textarea", "ax-in"); ta.rows = 4; ta.maxLength = 1000; ta.placeholder = "What did you find? e.g. both infections share one C2 domain; the user agent is new; definition added";
      const row = el("div", "ax-row"), msg = el("span", "ax-msg"); replyBtn = el("button", "lg-btn primary", "Send the reply"); replyBtn.type = "button";
      row.append(msg, replyBtn); rp.append(ta, row);
      replyBtn.addEventListener("click", async () => {
        if (!ta.value.trim() && !picked.size) { msg.textContent = "Write a reply or tick a code."; msg.className = "ax-msg bad"; return; }
        replyBtn.disabled = true;
        try {
          const r2 = await fetch(`/api/findings/${d.finding.id}/reply`, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
            body: JSON.stringify({ text: ta.value.trim(), codes: [...picked.keys()] }) });
          const x = await r2.json().catch(() => ({}));
          if (!r2.ok) { msg.textContent = x.error || `Not sent (HTTP ${r2.status})`; msg.className = "ax-msg bad"; return; }
          msg.textContent = `Reply sent on finding ${d.finding.number}${picked.size ? ` with ${pl(picked.size, "code")}` : ""}.`; msg.className = "ax-msg ok";
          ta.value = ""; picked.clear(); for (const cb of main.querySelectorAll(".ax-tick input")) cb.checked = false; drawPicked();
        } finally { replyBtn.disabled = false; }
      });
      main.append(rp);
    }
  }
  load();
})();
