/* SPDX-License-Identifier: AGPL-3.0-only
   SPDX-FileCopyrightText: the Looking Glass contributors */
/* Looking Glass · the severity map on the Definitions page (severity_map.py): every infection and issue the reports
   carried, with its criticality and where it comes from. Researchers and administrators only. Shadowserver's ratings are
   shown, never changed; a name no record rates can be rated by a researcher (audited), and the PDFs flag that rating
   "Researcher's rating". Built from the page's own parts: st-card dz, dz-stats tabs, dz-toolbar search, dz-table,
   dz-pill. Text from the server is always set as text. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  if (!$("cardSev")) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-US");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const get = async (u) => { const r = await fetch(u, { cache: "no-store" }); const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j; };
  const post = async (u, b) => {
    const r = await fetch(u, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify(b) });
    const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `Refused (${r.status})`); return j;
  };
  const WORD = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", "": "Not rated" };
  const PILL = { critical: "bad", high: "warn", medium: "info", low: "", info: "", "": "warn" };
  const PAGE = 60;
  let data = null, tab = "not_rated", shown = PAGE;

  async function load(first) {
    if (first && window.LGLoader?.wait && !load.waiting) {   // the page's logo stays until this card has its data
      load.waiting = true; return window.LGLoader.wait(load(first), "Opening definitions and intel");
    }
    try { data = await get("/api/kb/severity-map"); }
    catch (e) { if (first) { $("cardSev").hidden = true; return; } $("sevStatus").textContent = `Could not load: ${window.LGLoader.errorText(e)}`; return; }
    $("cardSev").hidden = false;
    if (first) tab = data.counts.not_rated ? "not_rated" : "all";
    render();
  }

  function list() {
    const q = $("sevSearch").value.trim().toLowerCase();
    let r = data.rows;
    if (q) return r.filter((x) => [x.name, x.kind, WORD[x.level] || "", x.rated_by || ""].join(" ").toLowerCase().includes(q));
    if (tab === "not_rated") r = r.filter((x) => !x.source);
    else if (tab === "shadowserver") r = r.filter((x) => x.source === "shadowserver");
    else if (tab === "researcher") r = r.filter((x) => x.rated_level);
    return r;
  }

  function source(x) {
    const td = el("td");
    if (x.source === "shadowserver") {
      td.append(el("span", null, "Shadowserver"), el("span", "dz-by", "the highest severity of the records that carry it"));
      if (x.replaced) td.append(el("span", "dz-by", `Replaces ${x.rated_by || "a researcher"}'s rating (${WORD[x.rated_level]}, ${String(x.rated_at).slice(0, 10)})`));
    } else if (x.source === "researcher") {
      td.append(el("span", null, `Researcher: ${x.rated_by || "unknown"}`), el("span", "dz-by", `rated on ${String(x.rated_at).slice(0, 10)}; no record rates it`));
    } else {
      td.append(el("span", null, "No record rates it"), el("span", "dz-by", "a researcher can rate it"));
    }
    return td;
  }

  function action(x) {
    const td = el("td", "dz-act");
    if (x.source === "shadowserver") return td;            // Shadowserver's ratings are never changed here
    const sel = el("select", "dz-input sev-pick lg-enhance");
    sel.setAttribute("aria-label", `Severity for ${x.name}`);
    sel.append(new Option(x.source ? "Change the rating" : "Rate this name", ""));
    for (const lv of data.levels) sel.append(new Option(WORD[lv], lv));
    if (x.source) sel.append(new Option("Take my rating back (not rated)", "-"));
    sel.addEventListener("change", async () => {
      const v = sel.value; if (!v) return;
      sel.disabled = true;
      $("sevStatus").textContent = "Saving…";
      try {
        data = await post("/api/kb/severity-map/rate", { name: x.name, level: v === "-" ? "" : v });
        $("sevStatus").textContent = v === "-" ? `${x.name}: not rated again.` : `${x.name}: rated ${WORD[v]}. The PDFs show it as a researcher's rating.`;
        render(false);
      } catch (e) { $("sevStatus").textContent = `Not saved: ${window.LGLoader.errorText(e, true)}`; sel.disabled = false; sel.value = ""; }
    });
    td.append(sel);
    return td;
  }

  function render(resetStatus = true) {
    const c = data.counts || {};
    $("sevN1").textContent = fmt(c.not_rated); $("sevN2").textContent = fmt(c.shadowserver);
    $("sevN3").textContent = fmt(c.researcher + (c.replaced || 0)); $("sevN4").textContent = fmt(c.all);
    const q = $("sevSearch").value.trim();
    for (const b of document.querySelectorAll("[data-sev]")) b.setAttribute("aria-selected", String(!q && b.dataset.sev === tab));
    if (resetStatus) $("sevStatus").textContent = "";
    const body = $("sevTable").tBodies[0]; body.replaceChildren();
    const r = list();
    if (!r.length) {
      const tr = el("tr", "dz-empty"), td = el("td", null, q ? "Nothing matches the search."
        : tab === "not_rated" ? "Every name the reports carried has a rating." : tab === "researcher" ? "No researcher has rated a name yet." : "No names yet: they appear as report days load.");
      td.colSpan = 5; tr.append(td); body.append(tr); return;
    }
    for (const x of r.slice(0, shown)) {
      const tr = el("tr");
      const n = el("td"); n.append(el("b", "mono", x.name)); tr.append(n);
      tr.append(el("td", null, x.kind || "–"));
      const lv = el("td"); lv.append(el("span", `dz-pill ${PILL[x.level] || ""}`.trim(), WORD[x.level] || "Not rated")); tr.append(lv);
      tr.append(source(x), action(x));
      body.append(tr);
    }
    $("sevMore").replaceChildren();
    if (r.length > shown) {
      const left = r.length - shown;
      const more = el("button", "lg-btn sm ghost", left <= PAGE ? `Show the other ${fmt(left)}` : `Show ${PAGE} more of ${fmt(left)}`); more.type = "button";
      more.addEventListener("click", () => { shown += PAGE; render(false); });
      $("sevMore").append(more);
    }
  }

  for (const b of document.querySelectorAll("[data-sev]")) b.addEventListener("click", () => { tab = b.dataset.sev; shown = PAGE; $("sevSearch").value = ""; render(); });
  $("sevSearch").addEventListener("input", () => { shown = PAGE; if (data) render(); });
  load(true);
})();
