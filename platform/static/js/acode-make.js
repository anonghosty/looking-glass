/* Looking Glass · "Make analyst code" in the analysis window (map and services platform), for analysts.
   The analysis's current selection (window.LGAnalysis, set by app.js / services.js when an analysis opens) becomes an
   analyst code (LG-A-…, acodes.py) and a finding on the Findings page, with a title and a note. Researchers open the
   code without any address and answer on the finding; management filters the Executive portal by it. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  // analysts only: roles that see addresses and may export
  if (document.body.dataset.masked === "1" || document.body.dataset.export !== "1") return;
  const actions = document.querySelector("#insight .i-actions"), filterBtn = $("iFilter");
  if (!actions || !filterBtn) return;
  const btn = el("button", "pill-btn ac-btn", "Make analyst code"); btn.type = "button"; btn.id = "iAcode";
  btn.title = "Pass this selection to the researchers and management as an analyst code (LG-A-…) and a finding: they see it without any address";
  actions.insertBefore(btn, filterBtn);
  let source = () => window.LGAnalysis, opener = btn;

  const back = el("div", "ac-back"); back.hidden = true;
  const box = el("section", "ac-modal"); box.hidden = true; box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "acTitle");
  const h = el("h2", null, "Make an analyst code"); h.id = "acTitle";
  const sel = el("p", "ac-sel");
  const lead = el("p", "ac-lead", "The code stands for exactly this selection on this day. It becomes a finding on the Findings page: the researchers open it "
    + "with the names, definitions and intel of exactly these records (never an address) and answer with their own codes; management filters the Executive portal by it.");
  const t = el("input", "ac-in"); t.maxLength = 140; t.placeholder = "Title, e.g. one host beaconing to two sinkholes"; t.setAttribute("aria-label", "Finding title");
  const n = el("textarea", "ac-in"); n.rows = 4; n.maxLength = 2000; n.placeholder = "What should the researchers look at? e.g. which infections these hosts share, whether the C2 is new";
  n.setAttribute("aria-label", "Note for the researchers");
  // what the analyst asks for: everything, or just the combinations across reports (the researchers' page leads with them)
  const ask = el("div", "ac-ask"); ask.setAttribute("role", "radiogroup"); ask.setAttribute("aria-label", "What the researchers should look at");
  let focus = "";
  for (const [k, l, s] of [["", "Everything", "every category: infections, CVEs and issues, services, across reports"],
                           ["across", "Just across-report combinations", "what these hosts carry in each report they turn up in, with the LG-X codes"]]) {
    const b = el("button", "ac-opt"); b.type = "button"; b.dataset.k = k; b.setAttribute("role", "radio");
    b.append(el("b", null, l), el("small", null, s));
    b.addEventListener("click", () => { focus = k; for (const o of ask.children) o.setAttribute("aria-checked", String(o.dataset.k === focus)); });
    ask.append(b);
  }
  const msg = el("div", "ac-msg"); msg.setAttribute("role", "status");
  const row = el("div", "ac-row"); const cancel = el("button", "pill-btn", "Cancel"); cancel.type = "button";
  const go = el("button", "pill-btn ac-go", "Make the code and the finding"); go.type = "button";
  row.append(cancel, go);
  // the researcher it goes to: a channel, only the two of you see it (people-pick.js)
  const toR = window.LGPeople ? window.LGPeople.picker("researcher") : null;
  box.append(h, sel, lead, ask, ...(toR ? [toR.el] : []), t, n, msg, row);
  document.body.append(back, box);
  const close = () => { box.hidden = true; back.hidden = true; opener.focus(); };
  cancel.addEventListener("click", close); back.addEventListener("click", close);
  box.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.stopPropagation(); close(); } });

  let chosen = null;                  // the selection, fixed when the window opens (the replay clock moves on)
  function show() {
    const a = source(); if (!a) return; chosen = a;
    sel.textContent = `Selection: ${a.title || "this analysis"} · ${String(a.at || "").slice(0, 10)}`;
    t.value = ""; n.value = ""; msg.replaceChildren(); msg.className = "ac-msg"; go.disabled = false; go.hidden = false;
    focus = ""; for (const o of ask.children) o.setAttribute("aria-checked", String(o.dataset.k === ""));
    toR?.reset();
    box.hidden = false; back.hidden = false; setTimeout(() => t.focus(), 30);
  }
  btn.addEventListener("click", () => { source = () => window.LGAnalysis; opener = btn; show(); });
  go.addEventListener("click", async () => {
    const a = chosen; if (!a) return;
    if (toR && !toR.check()) { msg.textContent = "Choose the researcher it goes to."; msg.className = "ac-msg bad"; return; }
    if (!t.value.trim()) { msg.textContent = "Give the finding a short title."; msg.className = "ac-msg bad"; return; }
    go.disabled = true; msg.textContent = "Making the code…"; msg.className = "ac-msg";
    try {
      const r = await fetch("/api/analyst-codes", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
        body: JSON.stringify({ ...a, title: t.value.trim(), text: n.value.trim(), focus, to: toR ? toR.value() : "" }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { msg.textContent = d.error || `Refused (HTTP ${r.status})`; msg.className = "ac-msg bad"; go.disabled = false; return; }
      msg.className = "ac-msg ok"; msg.replaceChildren();
      const code = el("code", "ac-code", d.code);
      const copy = el("button", "pill-btn", "Copy the code"); copy.type = "button";
      copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(d.code); copy.textContent = "Copied"; } catch { copy.textContent = "Select and copy"; } });
      const open = el("a", "pill-btn", `Open finding ${d.finding}`); open.href = `/findings#f${d.finding.slice(1)}`;
      msg.append(el("div", null, `Finding ${d.finding} sent to ${d.to || "the researcher"}: ${fmt(d.records)} records on ${fmt(d.hosts)} host${d.hosts === 1 ? "" : "s"}.`), code,
        el("div", "ac-sub", `Researchers and management see it as: ${d.label}`), copy, open);
      go.hidden = true;
    } catch { msg.textContent = "The connection was interrupted. Try again."; msg.className = "ac-msg bad"; go.disabled = false; }
  });
})();
