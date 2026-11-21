/* Looking Glass · the quarterly reports (quarterly.py): every kept quarter with its downloads, on
   - the Executive portal (management: the management PDF and summary CSV),
   - the advisory portal (advisors: the advisor PDF and their three CSVs),
   - Settings → Quarterly (administrators: everything, the purge CSV, each accuracy check, the purge's status and
     "Make it again").
   The card is #lgQuarterly or #tabQuarterly with data-scope="management|advisor|admin". It shows its loading line
   (LGLoader.card / LGLoader.pane) while it reads. Texts are set as text, never as HTML. Every download is sealed,
   stamped and in the audit log on the server (insider.py, quarterly.py). */
(() => {
  "use strict";
  const box = document.getElementById("lgQuarterly") || document.getElementById("tabQuarterly");
  if (!box) return;
  const scope = box.dataset.scope;
  const API = { management: "/api/mgmt/quarterly", advisor: "/api/advisory/quarterly", admin: "/api/admin/quarterly" }[scope];
  if (!API) return;
  const body = box.querySelector(".q-body") || box;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
  const kb = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round((n || 0) / 1024))} KB`);
  const day = (iso) => {
    if (!iso) return "";
    const d = new Date(`${String(iso).slice(0, 10)}T00:00:00Z`);
    return isNaN(d) ? String(iso) : d.toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
  };
  let timer = null, confirmQ = null;

  function fileLinks(files) {
    const w = el("div", "q-files");
    for (const f of files) {
      const a = el("a", "pill-btn", f.label); a.href = f.url; a.setAttribute("download", f.name);
      a.title = `${f.name} · downloading it is recorded under your name`;
      a.append(el("small", null, kb(f.bytes)));
      w.append(a);
    }
    return w;
  }

  function row(q, admin) {
    const r = el("div", "q-row");
    const h = el("div", "q-head");
    h.append(el("b", null, q.quarter), el("span", `q-tag ${q.valid ? "valid" : "invalid"}`, q.valid ? "VALID" : "NOT VALID"));
    h.append(el("span", "q-meta", `${q.made ? q.made[0].toUpperCase() + q.made.slice(1) : "Made"} · ${String(q.generated_at || "").replace("T", " ").slice(0, 16)} UTC`));
    r.append(h);
    if (!q.valid) r.append(el("p", "q-why", `Not valid: ${q.why}. Do not rely on these figures until the report is made again and says VALID.`));
    if (q.permit) {
      r.append(el("p", "q-meta", `Download before the end of ${day(q.download_before)}. The raw report rows dated before ${day(q.cutoff)} are deleted on ${day(q.purge_day)}; these reports stay here.`));
    } else if (admin && q.no_permit_why) {
      r.append(el("p", "q-meta", `No purge for this quarter: ${q.no_permit_why}.`));
    }
    r.append(q.files.length ? fileLinks(q.files) : el("p", "q-meta", "No file of this quarter is kept for you."));
    if (admin) {
      const pr = q.purge_result;
      if (pr && pr.outcome === "done") {
        r.append(el("p", "q-meta", `Purged on ${String(pr.at || "").slice(0, 10)}: ${Number(pr.rows_deleted || 0).toLocaleString("en-US")} rows dated before ${day(pr.cutoff)} deleted from ${pr.collections_touched || 0} report collections.`));
      } else if (q.permit) {
        r.append(el("p", "q-meta", `Purge permit written. Rows the purge would delete, counted when it was made: ${Number(q.rows_purge_deletes || 0).toLocaleString("en-US")}.`));
      }
      const g = el("details", "q-guards");
      const bad = (q.guards || []).filter((x) => !x.ok).length;
      g.append(el("summary", null, bad ? `Accuracy checks: ${bad} failed` : `Accuracy checks: all ${(q.guards || []).length} passed`));
      const ul = el("ul");
      for (const x of q.guards || []) ul.append(el("li", x.ok ? "" : "bad", `${x.ok ? "passed" : "FAILED"} · ${x.name}${x.detail ? ` · ${x.detail}` : ""}`));
      for (const c of q.failed_collections || []) ul.append(el("li", "bad", `could not be read: ${c}`));
      g.append(ul); r.append(g);
    }
    return r;
  }

  function adminTools(d) {
    const w = el("div", "q-row");
    w.append(el("b", null, "Make it again"));
    w.append(el("p", "q-hint", `Counts an ended quarter again and replaces its kept report, for example once its last day's reports `
      + `are loaded, or after a NOT VALID run. A VALID report made before its purge day writes the purge permit again; a NOT VALID one `
      + `removes it, so nothing is deleted. A quarter whose raw rows were purged cannot be counted again. The timing cannot be changed: `
      + `${d.rules.working_days} working days (Monday to Friday) after the quarter, the purge on the next working day, always keeping the last ${d.rules.keep_days} days.`));
    const t = el("div", "q-tools");
    const sel = el("select", "lg-enhance"); sel.setAttribute("aria-label", "Quarter to make again");
    for (const q of d.can_make || []) { const o = el("option", null, q); o.value = q; sel.append(o); }
    const btn = el("button", "pill-btn", "Make it again"); btn.type = "button";
    const msg = el("span", "q-msg"); msg.setAttribute("role", "status");
    if (d.making) { btn.disabled = true; msg.textContent = `${d.making} is being made…`; msg.classList.add("lg-loading"); }
    else if (d.error) { msg.textContent = d.error; msg.classList.add("bad"); }
    if (!(d.can_make || []).length) { btn.disabled = true; sel.disabled = true; }
    btn.addEventListener("click", async () => {
      const q = sel.value;
      if (confirmQ !== q) { confirmQ = q; btn.textContent = `Make ${q} again: click to confirm`; return; }
      confirmQ = null; btn.disabled = true; msg.className = "q-msg lg-loading"; msg.textContent = `Making ${q}…`;
      try {
        const r = await fetch("/api/admin/quarterly/make", { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify({ quarter: q }) });
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
        poll();
      } catch (e) { msg.className = "q-msg bad"; msg.textContent = e.message; btn.disabled = false; btn.textContent = "Make it again"; }
    });
    t.append(sel, btn, msg); w.append(t);
    const p = d.pipeline || {};
    const last = p.last || {};
    w.append(el("p", "q-meta", p.found
      ? `The database pipeline's last purge check${last.at ? ` (${String(last.at).replace("T", " ").slice(0, 16)} UTC)` : ""}: `
        + `${last.outcome ? `${last.quarter || ""} ${last.outcome}${last.why ? `: ${last.why}` : ""}` : "none yet"}.`
        + (p.purged_before ? ` Rows dated before ${day(p.purged_before)} have been purged.` : "")
      : "The database pipeline has not checked for a purge yet (or it runs on another computer)."));
    return w;
  }

  function draw(d) {
    body.replaceChildren();
    const admin = scope === "admin";
    if (admin) body.append(adminTools(d));
    const list = el("div", "q-list");
    for (const q of d.quarters || []) list.append(row(q, admin));
    if (!(d.quarters || []).length) list.append(el("p", "q-empty", "No quarterly report yet: the first is made once this quarter has ended."));
    body.append(list);
  }

  async function load() {
    const r = await fetch(API, { cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { body.replaceChildren(el("p", "q-empty", d.error || `Could not open the quarterly reports (HTTP ${r.status})`)); return true; }
    draw(d);
    clearTimeout(timer);
    if (d.making) timer = setTimeout(poll, 5000);
    return true;
  }
  const poll = () => load().catch(() => {});

  if (scope === "admin") {
    let opened = false;
    document.addEventListener("lg:settings-tab", (e) => {
      if (e.detail !== "quarterly" || opened) return;
      opened = true;
      window.LGLoader?.pane ? window.LGLoader.pane(box, "Opening the quarterly reports…", () => load().catch((x) => body.replaceChildren(el("p", "q-empty", x.message)))) : poll();
    });
  } else {
    const work = () => load().catch((x) => { body.replaceChildren(el("p", "q-empty", `Could not open the quarterly reports: ${x.message}`)); return true; });
    (window.LGLoader?.card ? window.LGLoader.card(box, "Opening the quarterly reports…", work) : work()).then(() => {
      if (location.hash === "#quarterly") box.scrollIntoView({ block: "start" });
    });
  }
})();
