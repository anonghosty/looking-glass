/* Looking Glass · Trace a leak, in the Audit portal (insider.py): text or a file found outside is sent once to
   POST /api/audit/trace, fingerprinted there in memory and thrown away; the answer is the copies and downloads it
   matches. Auditors and administrators only (checked on the server). Every value is inserted as text. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  if (!$("trForm")) return;
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
  const fmt = (n) => Number(n || 0).toLocaleString("en-GB");
  const fmtT = (t) => (t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "–");
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

  function how(m) {
    if (m.exact) return m.kind === "download" ? "The exact file, or its exact text" : "The exact text copied";
    return `${fmt(m.matched)} of the ${fmt(m.given)} lines and addresses given (it holds ${fmt(m.of)})${m.cut ? " (only the first lines were sealed)" : ""}`;
  }
  // how a trace compares (insider.py, external review 2026-11-19): said with every answer, so a "no match" is read right
  function rules(d) {
    const share = Math.round((d.min_share || .5) * 100);
    return d.exact_only
      ? `More than ${fmt(d.max_items)} lines or addresses were given: only copies and downloads of exactly this text or file were looked for. To find partial matches, trace the part that leaked (at most ${fmt(d.max_items)} lines).`
      : `A copy or download is shown when it is exactly this text or file, or holds at least ${share}% of the lines and addresses given.`;
  }
  function show(d) {
    const out = $("trOut"); out.replaceChildren();
    if (!d.matches.length) {
      out.append(el("p", "au-vf ok", "No match: nothing copied with a copy button or downloaded from Looking Glass, among the seals kept, matches what you gave."),
        el("p", "st-hint", rules(d)));
      return;
    }
    out.append(el("p", "au-vf bad", `${fmt(d.total)} match${d.total === 1 ? "" : "es"}, the closest first${d.total > d.matches.length ? ` (the first ${fmt(d.matches.length)} shown)` : ""}.`));
    const t = el("table", "hosts adm-table au-table"), h = el("tr");
    for (const c of ["When (UTC)", "Who", "How", "What", "Page", "Match", "Seal"]) h.append(el("th", null, c));
    const th = el("thead"); th.append(h); t.append(th);
    const tb = el("tbody");
    for (const m of d.matches) {
      const tr = el("tr", m.exact ? "adm-alert" : "");
      tr.append(el("td", "mono", fmtT(m.t)), el("td", null, m.who === m.user || !m.user ? m.who : `${m.who} (${m.user})`),
        el("td", null, m.kind === "download" ? "Downloaded" : "Copied"), el("td", "adm-detail", m.what || "–"), el("td", null, m.page || "–"),
        el("td", null, how(m)), el("td", "mono", m.id || "–"));
      tb.append(tr);
    }
    t.append(tb); const w = el("div", "table-wrap"); w.append(t); out.append(w);
    out.append(el("p", "st-hint", rules(d)));
    if (d.common_left_out) out.append(el("p", "st-hint", `${fmt(d.common_left_out)} line(s) found in many people's copies and downloads (a CSV's header, for example) were not counted as matches.`));
  }
  $("trForm").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const file = $("trFile").files[0], text = $("trText").value;
    if (!file && !text.trim()) { $("trMsg").textContent = "Paste the text or choose the file to trace."; return; }
    $("trGo").disabled = true; $("trMsg").textContent = "Tracing…"; window.LGLoader?.busy("Tracing the leak");
    try {
      let r;
      if (file) {
        const fd = new FormData(); fd.append("file", file);
        r = await fetch("/api/audit/trace", { method: "POST", headers: { "X-CSRF-Token": csrf() }, body: fd });
      } else {
        r = await fetch("/api/audit/trace", { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() }, body: JSON.stringify({ text }) });
      }
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || r.statusText);
      $("trMsg").textContent = "Done: what you gave was not kept.";
      show(d);
    } catch (e) { $("trMsg").textContent = `Not traced: ${window.LGLoader.errorText(e)}`; }
    finally { $("trGo").disabled = false; window.LGLoader?.ready(); }
  });
  window.LGTrace = { ready: () => {} };
})();
